//! Tailscale-aware address policy.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};

/// Tailscale assigns node addresses from 100.64.0.0/10 and fd7a:115c:a1e0::/48.
pub fn is_tailscale(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 100 && (o[1] & 0xc0) == 64
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_tailscale(IpAddr::V4(v4)),
            None => {
                let s = v6.segments();
                s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0
            }
        },
    }
}

/// The last address `tailscale_ipv4` turned down, so that it says why once, not every poll.
static REFUSED: AtomicU32 = AtomicU32::new(0);

/// This machine's Tailscale IPv4 address, if Tailscale is up.
///
/// "Connecting" a UDP socket sends nothing; it only asks the routing table which local
/// address would be used to reach Tailscale's in-tailnet resolver. While Tailscale is down that
/// is the address of whatever interface has the default route, and 100.64.0.0/10 is also
/// carrier-grade NAT space (WWAN modems, bridged mobile and satellite gateways) and taken by
/// other overlays: the range alone proves nothing. So the address must also be on Tailscale's
/// own interface, or Tailscale must report it as this device's.
pub fn tailscale_ipv4() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    s.connect((Ipv4Addr::new(100, 100, 100, 100), 53)).ok()?;
    let ip = match s.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if is_tailscale(IpAddr::V4(ip)) => ip,
        _ => return None,
    };
    // The interface first: it needs no Tailscale CLI and works for the SYSTEM agent too.
    if on_tailscale_interface(ip) || crate::tailscale::status().is_ok_and(|st| st.is_own_address(IpAddr::V4(ip))) {
        return Some(ip);
    }
    if REFUSED.swap(ip.to_bits(), Ordering::Relaxed) != ip.to_bits() {
        crate::log!("{ip} is in 100.64.0.0/10 but does not belong to Tailscale (carrier-grade NAT or another VPN?); not listening on it");
    }
    None
}

/// Tailscale's Wintun adapter: the GUID Tailscale asks for when creating it, and the
/// description Wintun gives it ("Tailscale Tunnel", " #2" and so on when Windows numbers it).
#[cfg(windows)]
const TAILSCALE_ADAPTER_GUID: &str = "{37217669-42DA-4657-A55B-0D995D328250}";
#[cfg(windows)]
const TAILSCALE_ADAPTER_DESCRIPTION: &str = "Tailscale Tunnel";

#[cfg(windows)]
fn is_tailscale_adapter(guid: &str, description: &str) -> bool {
    let numbered = |n: &str| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit());
    guid.eq_ignore_ascii_case(TAILSCALE_ADAPTER_GUID)
        || description == TAILSCALE_ADAPTER_DESCRIPTION
        || description.strip_prefix(TAILSCALE_ADAPTER_DESCRIPTION).and_then(|s| s.strip_prefix(" #")).is_some_and(numbered)
}

/// Whether `ip` is assigned to Tailscale's network adapter.
#[cfg(windows)]
fn on_tailscale_interface(ip: Ipv4Addr) -> bool {
    adapters_holding(ip).iter().any(|(guid, description)| is_tailscale_adapter(guid, description))
}

/// The adapters `ip` is assigned to: their names (a GUID) and descriptions.
#[cfg(windows)]
fn adapters_holding(ip: Ipv4Addr) -> Vec<(String, String)> {
    use std::ptr::null;
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME;
    // u64 elements: the list is made of 8-byte aligned structures.
    let mut buf: Vec<u64> = Vec::new();
    let mut size: u32 = 16 << 10;
    let mut listed = false;
    // The list can grow between the call that sizes it and the next.
    for _ in 0..4 {
        buf.resize((size as usize).div_ceil(8), 0);
        size = (buf.len() * 8) as u32;
        match unsafe { GetAdaptersAddresses(AF_INET as u32, flags, null(), buf.as_mut_ptr().cast(), &mut size) } {
            NO_ERROR => {
                listed = true;
                break;
            }
            ERROR_BUFFER_OVERFLOW => continue,
            _ => break, // ERROR_NO_DATA (no adapters) among others
        }
    }
    let mut found = Vec::new();
    if !listed {
        return found;
    }
    let mut a = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !a.is_null() {
        let adapter = unsafe { &*a };
        let mut u = adapter.FirstUnicastAddress.cast_const();
        while !u.is_null() {
            let unicast = unsafe { &*u };
            let sa = unicast.Address.lpSockaddr;
            let len = usize::try_from(unicast.Address.iSockaddrLength).unwrap_or(0);
            if !sa.is_null() && len >= size_of::<SOCKADDR_IN>() && unsafe { (*sa).sa_family } == AF_INET {
                // S_addr holds the address in network byte order, as it is in memory.
                let sin = unsafe { &*sa.cast::<SOCKADDR_IN>() };
                if Ipv4Addr::from(unsafe { sin.sin_addr.S_un.S_addr }.to_ne_bytes()) == ip {
                    let guid = if adapter.AdapterName.is_null() {
                        String::new()
                    } else {
                        unsafe { std::ffi::CStr::from_ptr(adapter.AdapterName.cast()) }.to_string_lossy().into_owned()
                    };
                    found.push((guid, wide_ptr(adapter.Description)));
                }
            }
            u = unicast.Next.cast_const();
        }
        a = adapter.Next.cast_const();
    }
    found
}

/// A NUL-terminated UTF-16 string owned by the system, as a `String` ("" for null).
#[cfg(windows)]
fn wide_ptr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    // Terminated by contract and at most 256 characters; the cap only bounds the scan.
    let len = (0..1024).take_while(|&i| unsafe { *p.add(i) } != 0).count();
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

/// The interface tailscaled creates unless told otherwise (`--tun`).
#[cfg(not(windows))]
const TAILSCALE_INTERFACE: &str = "tailscale0";

/// Whether `ip` is assigned to Tailscale's network interface.
#[cfg(not(windows))]
fn on_tailscale_interface(ip: Ipv4Addr) -> bool {
    interfaces_holding(ip).iter().any(|name| name == TAILSCALE_INTERFACE)
}

/// The names of the interfaces `ip` is assigned to.
#[cfg(not(windows))]
fn interfaces_holding(ip: Ipv4Addr) -> Vec<String> {
    use std::ffi::{CStr, c_char, c_int, c_uint, c_void};

    /// `struct ifaddrs` (<ifaddrs.h>).
    #[repr(C)]
    struct IfAddrs {
        next: *mut IfAddrs,
        name: *const c_char,
        flags: c_uint,
        addr: *const c_void,
        netmask: *const c_void,
        broadaddr_or_dstaddr: *const c_void,
        data: *mut c_void,
    }
    /// `struct sockaddr_in` (<netinet/in.h>); the address in network byte order.
    #[repr(C)]
    struct SockaddrIn {
        family: u16,
        port: u16,
        addr: [u8; 4],
        zero: [u8; 8],
    }
    unsafe extern "C" {
        fn getifaddrs(ifap: *mut *mut IfAddrs) -> c_int;
        fn freeifaddrs(ifa: *mut IfAddrs);
    }
    const AF_INET: u16 = 2;

    let mut list: *mut IfAddrs = std::ptr::null_mut();
    if unsafe { getifaddrs(&mut list) } != 0 {
        return Vec::new();
    }
    let mut found = Vec::new();
    let mut p = list.cast_const();
    while !p.is_null() {
        let ifa = unsafe { &*p };
        // Only the family is common to all address types; read the rest for AF_INET only.
        if !ifa.addr.is_null() && !ifa.name.is_null() && unsafe { ifa.addr.cast::<u16>().read() } == AF_INET {
            let sin = unsafe { &*ifa.addr.cast::<SockaddrIn>() };
            if Ipv4Addr::from(sin.addr) == ip {
                found.push(unsafe { CStr::from_ptr(ifa.name) }.to_string_lossy().into_owned());
            }
        }
        p = ifa.next.cast_const();
    }
    unsafe { freeifaddrs(list) };
    found
}

/// `ip`, with an IPv4 address written as IPv6 (`::ffff:a.b.c.d`, as a dual-stack socket reports
/// IPv4 peers) turned back into IPv4, so that both spellings compare equal.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

pub struct PeerPolicy {
    pub allow: Vec<IpAddr>,
    pub allow_non_tailscale: bool,
    pub loopback_ok: bool,
}

impl PeerPolicy {
    pub fn allows(&self, peer: IpAddr) -> bool {
        let peer = canonical_ip(peer);
        if !self.allow.is_empty() {
            return self.allow.contains(&peer);
        }
        is_tailscale(peer) || self.allow_non_tailscale || (self.loopback_ok && peer.is_loopback())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tailscale_ranges() {
        assert!(is_tailscale("100.64.0.1".parse().unwrap()));
        assert!(is_tailscale("100.127.255.254".parse().unwrap()));
        assert!(!is_tailscale("100.128.0.1".parse().unwrap()));
        assert!(!is_tailscale("100.63.255.255".parse().unwrap()));
        assert!(!is_tailscale("192.168.0.10".parse().unwrap()));
        assert!(is_tailscale("fd7a:115c:a1e0::1".parse().unwrap()));
        assert!(!is_tailscale("fd7a:115c:a1e1::1".parse().unwrap()));
        assert!(is_tailscale("::ffff:100.100.1.1".parse().unwrap()));
    }

    #[test]
    #[ignore = "depends on the local Tailscale state"]
    fn detects_local_tailscale_ip() {
        let ip = tailscale_ipv4().expect("Tailscale not up");
        println!("tailscale ip: {ip}");
        assert!(is_tailscale(IpAddr::V4(ip)));
        assert!(on_tailscale_interface(ip), "Tailscale's own interface was not recognised");
    }

    #[test]
    fn interface_lookup() {
        let lo = Ipv4Addr::LOCALHOST;
        #[cfg(windows)]
        assert!(!adapters_holding(lo).is_empty(), "the loopback adapter holds 127.0.0.1");
        #[cfg(not(windows))]
        assert_eq!(interfaces_holding(lo), ["lo"]);
        assert!(!on_tailscale_interface(lo));
        // TEST-NET-1 (RFC 5737) is on no interface.
        let nowhere = Ipv4Addr::new(192, 0, 2, 1);
        #[cfg(windows)]
        assert!(adapters_holding(nowhere).is_empty());
        #[cfg(not(windows))]
        assert!(interfaces_holding(nowhere).is_empty());
        assert!(!on_tailscale_interface(nowhere));
    }

    #[test]
    #[cfg(windows)]
    fn tailscale_adapter_identity() {
        assert!(is_tailscale_adapter("{37217669-42da-4657-a55b-0d995d328250}", ""));
        assert!(is_tailscale_adapter("{00000000-0000-0000-0000-000000000001}", "Tailscale Tunnel"));
        assert!(is_tailscale_adapter("", "Tailscale Tunnel #2"));
        assert!(is_tailscale_adapter("", "Tailscale Tunnel #12"));
        // A WWAN modem, another VPN, look-alikes.
        assert!(!is_tailscale_adapter("{00000000-0000-0000-0000-000000000002}", "Generic Mobile Broadband Adapter"));
        assert!(!is_tailscale_adapter("", "WireGuard Tunnel"));
        assert!(!is_tailscale_adapter("", "Tailscale Tunnel #"));
        assert!(!is_tailscale_adapter("", "Tailscale Tunnel #2 (copy)"));
        assert!(!is_tailscale_adapter("", "Not Tailscale Tunnel"));
        assert!(!is_tailscale_adapter("{37217669-42da-4657-a55b-0d995d328251}", ""));
    }

    #[test]
    fn policy() {
        let p = PeerPolicy { allow: vec![], allow_non_tailscale: false, loopback_ok: false };
        assert!(p.allows("100.100.1.2".parse().unwrap()));
        assert!(!p.allows("10.0.0.2".parse().unwrap()));
        assert!(!p.allows("127.0.0.1".parse().unwrap()));
        let p = PeerPolicy { allow: vec!["100.100.1.2".parse().unwrap()], allow_non_tailscale: false, loopback_ok: true };
        assert!(p.allows("::ffff:100.100.1.2".parse().unwrap()));
        assert!(!p.allows("100.100.1.3".parse().unwrap()));
        // The list holds canonical addresses (`main` writes them so); peers of either spelling match.
        let p = PeerPolicy { allow: vec![canonical_ip("::ffff:100.100.1.2".parse().unwrap())], allow_non_tailscale: false, loopback_ok: false };
        assert!(p.allows("100.100.1.2".parse().unwrap()));
        assert!(p.allows("::ffff:100.100.1.2".parse().unwrap()));
        assert_eq!(canonical_ip("fd7a:115c:a1e0::1".parse().unwrap()), "fd7a:115c:a1e0::1".parse::<IpAddr>().unwrap());
    }
}
