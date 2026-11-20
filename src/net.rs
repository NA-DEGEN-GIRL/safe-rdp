//! Tailscale-aware address policy.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};

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

/// This machine's Tailscale IPv4 address, if Tailscale is up.
///
/// "Connecting" a UDP socket sends nothing; it only asks the routing table which local
/// address would be used to reach Tailscale's in-tailnet resolver.
pub fn tailscale_ipv4() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    s.connect((Ipv4Addr::new(100, 100, 100, 100), 53)).ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if is_tailscale(IpAddr::V4(ip)) => Some(ip),
        _ => None,
    }
}

pub struct PeerPolicy {
    pub allow: Vec<IpAddr>,
    pub allow_non_tailscale: bool,
    pub loopback_ok: bool,
}

impl PeerPolicy {
    pub fn allows(&self, peer: IpAddr) -> bool {
        let peer = match peer {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(peer),
            v4 => v4,
        };
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
    fn policy() {
        let p = PeerPolicy { allow: vec![], allow_non_tailscale: false, loopback_ok: false };
        assert!(p.allows("100.100.1.2".parse().unwrap()));
        assert!(!p.allows("10.0.0.2".parse().unwrap()));
        assert!(!p.allows("127.0.0.1".parse().unwrap()));
        let p = PeerPolicy { allow: vec!["100.100.1.2".parse().unwrap()], allow_non_tailscale: false, loopback_ok: true };
        assert!(p.allows("::ffff:100.100.1.2".parse().unwrap()));
        assert!(!p.allows("100.100.1.3".parse().unwrap()));
    }
}
