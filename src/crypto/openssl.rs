//! Linux backend: the system OpenSSL 3 libcrypto, loaded at run time with `dlopen`.
//!
//! Nothing is linked at build time. The first crypto call loads `libcrypto.so.3`, resolves every
//! function used here into a table and fetches the algorithms once. Every OpenSSL object is owned
//! by a wrapper that frees it (OpenSSL wipes key material on free). Only the non-deprecated
//! OpenSSL 3 interfaces are used: EVP_PKEY for ECDH, EVP_MAC for HMAC, EVP_CIPHER for AES-GCM.

use super::{NONCE_LEN, PUBKEY_LEN, TAG_LEN};
use crate::bail;
use crate::util::{Error, Result, Secret};
use std::ffi::{CStr, c_char, c_int, c_uint, c_ulong, c_void};
use std::marker::PhantomData;
use std::ptr::{null, null_mut};
use std::sync::OnceLock;

// glibc >= 2.34 exports these from libc itself.
unsafe extern "C" {
    fn dlopen(file: *const c_char, mode: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
    fn dlerror() -> *mut c_char;
}

const RTLD_NOW: c_int = 2;
const LIBRARIES: [&CStr; 2] = [c"libcrypto.so.3", c"libcrypto.so"];
const NOT_FOUND: &str = "libcrypto (OpenSSL 3) not found; install libssl3";

// openssl/crypto.h: keep OpenSSL from tearing itself down in an atexit handler while other
// threads may still be using it; the OS reclaims everything at exit anyway.
const OPENSSL_INIT_NO_ATEXIT: u64 = 0x0008_0000;
// openssl/evp.h
const EVP_CTRL_AEAD_GET_TAG: c_int = 0x10;
const EVP_CTRL_AEAD_SET_TAG: c_int = 0x11;
// openssl/core_dispatch.h selections: domain + other parameters (0x84), public key (0x02).
const EVP_PKEY_PUBLIC_KEY: c_int = 0x86;
#[cfg(test)]
const EVP_PKEY_KEYPAIR: c_int = 0x87;
// openssl/core.h
#[cfg(test)]
const OSSL_PARAM_UNSIGNED_INTEGER: c_uint = 2;
const OSSL_PARAM_UTF8_STRING: c_uint = 4;
const OSSL_PARAM_OCTET_STRING: c_uint = 5;
const OSSL_PARAM_UNMODIFIED: usize = usize::MAX;

const EC_GROUP: &CStr = c"P-256";
/// Largest slice handed to an `int`-length OpenSSL call at once.
const MAX_CHUNK: usize = 1 << 30;

macro_rules! opaque {
    ($($name:ident),*) => {$(
        #[repr(C)]
        struct $name {
            _data: [u8; 0],
            _marker: PhantomData<(*mut u8, std::marker::PhantomPinned)>,
        }
    )*};
}

opaque!(EvpMd, EvpMdCtx, EvpMac, EvpMacCtx, EvpCipher, EvpCipherCtx, EvpPkey, EvpPkeyCtx);

/// `OSSL_PARAM` (openssl/core.h); the lifetime ties it to the data it points at.
#[repr(C)]
struct OsslParam<'a> {
    key: *const c_char,
    data_type: c_uint,
    data: *mut c_void,
    data_size: usize,
    return_size: usize,
    _data: PhantomData<&'a [u8]>,
}

impl<'a> OsslParam<'a> {
    fn new(key: &'static CStr, data_type: c_uint, data: *const u8, data_size: usize) -> Self {
        OsslParam {
            key: key.as_ptr(),
            data_type,
            data: data as *mut c_void,
            data_size,
            return_size: OSSL_PARAM_UNMODIFIED,
            _data: PhantomData,
        }
    }

    /// UTF-8 string parameter; providers may read the value as a C string, so it stays NUL-terminated.
    fn utf8(key: &'static CStr, value: &'a CStr) -> Self {
        Self::new(key, OSSL_PARAM_UTF8_STRING, value.as_ptr().cast(), value.count_bytes())
    }

    fn octets(key: &'static CStr, value: &'a [u8]) -> Self {
        Self::new(key, OSSL_PARAM_OCTET_STRING, value.as_ptr(), value.len())
    }

    /// Unsigned big number; OpenSSL expects it in native byte order.
    #[cfg(test)]
    fn unsigned_native(key: &'static CStr, value: &'a [u8]) -> Self {
        Self::new(key, OSSL_PARAM_UNSIGNED_INTEGER, value.as_ptr(), value.len())
    }

    fn end() -> Self {
        OsslParam { key: null(), data_type: 0, data: null_mut(), data_size: 0, return_size: 0, _data: PhantomData }
    }
}

/// Declares the libcrypto function table and its resolver.
macro_rules! libcrypto {
    ($($name:ident: fn($($arg:ty),*) $(-> $ret:ty)?;)*) => {
        #[allow(non_snake_case)]
        struct Fns {
            $($name: unsafe extern "C" fn($($arg),*) $(-> $ret)?,)*
        }

        impl Fns {
            /// Resolves every entry; `handle` must come from `dlopen`.
            unsafe fn resolve(handle: *mut c_void) -> std::result::Result<Fns, String> {
                Ok(Fns {
                    $($name: unsafe {
                        std::mem::transmute::<*mut c_void, unsafe extern "C" fn($($arg),*) $(-> $ret)?>(
                            symbol(handle, concat!(stringify!($name), "\0"))?,
                        )
                    },)*
                })
            }
        }
    };
}

libcrypto! {
    OPENSSL_init_crypto: fn(u64, *const c_void) -> c_int;
    ERR_get_error: fn() -> c_ulong;
    ERR_error_string_n: fn(c_ulong, *mut c_char, usize);
    RAND_bytes: fn(*mut u8, c_int) -> c_int;

    EVP_MD_fetch: fn(*mut c_void, *const c_char, *const c_char) -> *mut EvpMd;
    EVP_MD_free: fn(*mut EvpMd);
    EVP_MD_CTX_new: fn() -> *mut EvpMdCtx;
    EVP_MD_CTX_free: fn(*mut EvpMdCtx);
    EVP_DigestInit_ex2: fn(*mut EvpMdCtx, *const EvpMd, *const OsslParam<'_>) -> c_int;
    EVP_DigestUpdate: fn(*mut EvpMdCtx, *const c_void, usize) -> c_int;
    EVP_DigestFinal_ex: fn(*mut EvpMdCtx, *mut u8, *mut c_uint) -> c_int;

    EVP_MAC_fetch: fn(*mut c_void, *const c_char, *const c_char) -> *mut EvpMac;
    EVP_MAC_free: fn(*mut EvpMac);
    EVP_MAC_CTX_new: fn(*mut EvpMac) -> *mut EvpMacCtx;
    EVP_MAC_CTX_free: fn(*mut EvpMacCtx);
    EVP_MAC_init: fn(*mut EvpMacCtx, *const u8, usize, *const OsslParam<'_>) -> c_int;
    EVP_MAC_update: fn(*mut EvpMacCtx, *const u8, usize) -> c_int;
    EVP_MAC_final: fn(*mut EvpMacCtx, *mut u8, *mut usize, usize) -> c_int;

    EVP_CIPHER_fetch: fn(*mut c_void, *const c_char, *const c_char) -> *mut EvpCipher;
    EVP_CIPHER_free: fn(*mut EvpCipher);
    EVP_CIPHER_CTX_new: fn() -> *mut EvpCipherCtx;
    EVP_CIPHER_CTX_free: fn(*mut EvpCipherCtx);
    EVP_CipherInit_ex2: fn(*mut EvpCipherCtx, *const EvpCipher, *const u8, *const u8, c_int, *const OsslParam<'_>) -> c_int;
    EVP_CipherUpdate: fn(*mut EvpCipherCtx, *mut u8, *mut c_int, *const u8, c_int) -> c_int;
    EVP_CipherFinal_ex: fn(*mut EvpCipherCtx, *mut u8, *mut c_int) -> c_int;
    EVP_CIPHER_CTX_ctrl: fn(*mut EvpCipherCtx, c_int, c_int, *mut c_void) -> c_int;

    EVP_PKEY_CTX_new_from_name: fn(*mut c_void, *const c_char, *const c_char) -> *mut EvpPkeyCtx;
    EVP_PKEY_CTX_new_from_pkey: fn(*mut c_void, *mut EvpPkey, *const c_char) -> *mut EvpPkeyCtx;
    EVP_PKEY_CTX_free: fn(*mut EvpPkeyCtx);
    EVP_PKEY_keygen_init: fn(*mut EvpPkeyCtx) -> c_int;
    EVP_PKEY_CTX_set_group_name: fn(*mut EvpPkeyCtx, *const c_char) -> c_int;
    EVP_PKEY_generate: fn(*mut EvpPkeyCtx, *mut *mut EvpPkey) -> c_int;
    EVP_PKEY_fromdata_init: fn(*mut EvpPkeyCtx) -> c_int;
    EVP_PKEY_fromdata: fn(*mut EvpPkeyCtx, *mut *mut EvpPkey, c_int, *mut OsslParam<'_>) -> c_int;
    EVP_PKEY_get_octet_string_param: fn(*const EvpPkey, *const c_char, *mut u8, usize, *mut usize) -> c_int;
    EVP_PKEY_derive_init: fn(*mut EvpPkeyCtx) -> c_int;
    EVP_PKEY_derive_set_peer_ex: fn(*mut EvpPkeyCtx, *mut EvpPkey, c_int) -> c_int;
    EVP_PKEY_derive: fn(*mut EvpPkeyCtx, *mut u8, *mut usize) -> c_int;
    EVP_PKEY_free: fn(*mut EvpPkey);
}

/// Looks up `name` (NUL-terminated) in the library `handle`.
unsafe fn symbol(handle: *mut c_void, name: &str) -> std::result::Result<*mut c_void, String> {
    debug_assert!(name.ends_with('\0'));
    let p = unsafe { dlsym(handle, name.as_ptr().cast()) };
    if p.is_null() {
        return Err(format!("it lacks {}", name.trim_end_matches('\0')));
    }
    Ok(p)
}

fn dl_error() -> String {
    let e = unsafe { dlerror() };
    if e.is_null() {
        return "unknown dlopen error".into();
    }
    unsafe { CStr::from_ptr(e) }.to_string_lossy().into_owned()
}

/// Drains this thread's OpenSSL error queue and returns its oldest entry (the root cause) as text.
fn drain_errors(f: &Fns) -> Option<String> {
    let mut first = 0;
    loop {
        let e = unsafe { (f.ERR_get_error)() };
        if e == 0 {
            break;
        }
        if first == 0 {
            first = e;
        }
    }
    if first == 0 {
        return None;
    }
    let mut buf = [0u8; 256];
    unsafe { (f.ERR_error_string_n)(first, buf.as_mut_ptr().cast(), buf.len()) };
    CStr::from_bytes_until_nul(&buf).ok().map(|s| s.to_string_lossy().into_owned())
}

/// The loaded library: function table plus the algorithms, fetched once for the process lifetime.
struct Lib {
    f: Fns,
    sha256: *mut EvpMd,
    hmac: *mut EvpMac,
    aes_gcm: *mut EvpCipher,
}

// The table is immutable once loaded, and fetched OpenSSL algorithm objects are reference-counted
// and documented as shareable between threads.
unsafe impl Send for Lib {}
unsafe impl Sync for Lib {}

static LIB: OnceLock<std::result::Result<Lib, String>> = OnceLock::new();

fn lib() -> Result<&'static Lib> {
    LIB.get_or_init(|| load(&LIBRARIES)).as_ref().map_err(|e| Error::msg(e.clone()))
}

/// Loads the first of `names` that is OpenSSL 3 or newer.
fn load(names: &[&CStr]) -> std::result::Result<Lib, String> {
    let mut why = Vec::new();
    for &name in names {
        let handle = unsafe { dlopen(name.as_ptr(), RTLD_NOW) };
        if handle.is_null() {
            why.push(dl_error());
            continue;
        }
        match unsafe { resolve(handle) } {
            // OpenSSL 3 is present; any failure from here on is reported as such.
            Ok(f) => return start(f),
            Err(e) => {
                unsafe { dlclose(handle) };
                why.push(format!("{}: {e}", name.to_string_lossy()));
            }
        }
    }
    Err(format!("{NOT_FOUND} ({})", why.join("; ")))
}

/// Checks the version, then resolves the whole table. Runs no OpenSSL code besides the version query.
unsafe fn resolve(handle: *mut c_void) -> std::result::Result<Fns, String> {
    let version = unsafe { symbol(handle, "OpenSSL_version_num\0")? };
    let version = unsafe { std::mem::transmute::<*mut c_void, unsafe extern "C" fn() -> c_ulong>(version) };
    // 0xMNN00PP0 since 3.0; the major and minor nibbles sit at the same place in 1.x.
    let v = unsafe { version() };
    if v >> 28 < 3 {
        return Err(format!("it is OpenSSL {}.{}", v >> 28, (v >> 20) & 0xff));
    }
    unsafe { Fns::resolve(handle) }
}

fn start(f: Fns) -> std::result::Result<Lib, String> {
    let fail = |f: &Fns, what: &str| match drain_errors(f) {
        Some(reason) => format!("{what} ({reason})"),
        None => what.to_string(),
    };
    unsafe {
        if (f.OPENSSL_init_crypto)(OPENSSL_INIT_NO_ATEXIT, null()) != 1 {
            return Err(fail(&f, "OpenSSL initialization failed"));
        }
        let sha256 = (f.EVP_MD_fetch)(null_mut(), c"SHA256".as_ptr(), null());
        let hmac = (f.EVP_MAC_fetch)(null_mut(), c"HMAC".as_ptr(), null());
        let aes_gcm = (f.EVP_CIPHER_fetch)(null_mut(), c"AES-256-GCM".as_ptr(), null());
        if sha256.is_null() || hmac.is_null() || aes_gcm.is_null() {
            let e = fail(&f, "libcrypto does not provide SHA-256, HMAC and AES-256-GCM");
            (f.EVP_MD_free)(sha256);
            (f.EVP_MAC_free)(hmac);
            (f.EVP_CIPHER_free)(aes_gcm);
            return Err(e);
        }
        Ok(Lib { f, sha256, hmac, aes_gcm })
    }
}

/// An owned OpenSSL object, freed on drop.
struct Owned<T> {
    ptr: *mut T,
    free: unsafe extern "C" fn(*mut T),
}

impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        unsafe { (self.free)(self.ptr) };
    }
}

impl Lib {
    /// Error for a failed `what`, with OpenSSL's reason when it queued one.
    fn error(&self, what: &str) -> Error {
        match drain_errors(&self.f) {
            Some(reason) => Error::msg(format!("{what} failed ({reason})")),
            None => Error::msg(format!("{what} failed")),
        }
    }

    /// OpenSSL convention: 1 (or another positive value) is success, 0 or negative is failure.
    fn check(&self, rc: c_int, what: &str) -> Result<()> {
        if rc > 0 { Ok(()) } else { Err(self.error(what)) }
    }

    fn own<T>(&self, ptr: *mut T, free: unsafe extern "C" fn(*mut T), what: &str) -> Result<Owned<T>> {
        if ptr.is_null() {
            return Err(self.error(what));
        }
        Ok(Owned { ptr, free })
    }

    /// Takes the key a constructor stored in `key`, also freeing it if the call reported failure.
    fn own_pkey(&self, rc: c_int, key: *mut EvpPkey, what: &str) -> Result<Owned<EvpPkey>> {
        let owned = (!key.is_null()).then(|| Owned { ptr: key, free: self.f.EVP_PKEY_free });
        self.check(rc, what)?;
        owned.ok_or_else(|| self.error(what))
    }

    fn ec_ctx(&self) -> Result<Owned<EvpPkeyCtx>> {
        let ctx = unsafe { (self.f.EVP_PKEY_CTX_new_from_name)(null_mut(), c"EC".as_ptr(), null()) };
        self.own(ctx, self.f.EVP_PKEY_CTX_free, "EVP_PKEY_CTX_new_from_name(EC)")
    }

    /// Builds a P-256 key from parameters; OpenSSL decodes and range/curve-checks any point given.
    fn ec_import(&self, selection: c_int, params: &mut [OsslParam<'_>], what: &str) -> Result<Owned<EvpPkey>> {
        // OpenSSL walks the array up to the terminator.
        assert!(params.last().is_some_and(|p| p.key.is_null()), "unterminated OSSL_PARAM array");
        let ctx = self.ec_ctx()?;
        self.check(unsafe { (self.f.EVP_PKEY_fromdata_init)(ctx.ptr) }, what)?;
        let mut key = null_mut();
        let rc = unsafe { (self.f.EVP_PKEY_fromdata)(ctx.ptr, &mut key, selection, params.as_mut_ptr()) };
        self.own_pkey(rc, key, what)
    }
}

pub fn random(buf: &mut [u8]) -> Result<()> {
    let l = lib()?;
    for chunk in buf.chunks_mut(MAX_CHUNK) {
        if unsafe { (l.f.RAND_bytes)(chunk.as_mut_ptr(), chunk.len() as c_int) } != 1 {
            return Err(l.error("RAND_bytes"));
        }
    }
    Ok(())
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finish()
}

pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    try_hmac_sha256(key, parts).unwrap_or_else(|e| panic!("HMAC-SHA256: {e}"))
}

fn try_hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 32]> {
    let l = lib()?;
    let ctx = l.own(unsafe { (l.f.EVP_MAC_CTX_new)(l.hmac) }, l.f.EVP_MAC_CTX_free, "EVP_MAC_CTX_new")?;
    let params = [OsslParam::utf8(c"digest", c"SHA256"), OsslParam::end()];
    // A NULL key would mean "keep the previous key", so an empty key still needs a valid pointer.
    static EMPTY: [u8; 1] = [0];
    let key_ptr = if key.is_empty() { EMPTY.as_ptr() } else { key.as_ptr() };
    l.check(unsafe { (l.f.EVP_MAC_init)(ctx.ptr, key_ptr, key.len(), params.as_ptr()) }, "EVP_MAC_init")?;
    for p in parts.iter().filter(|p| !p.is_empty()) {
        l.check(unsafe { (l.f.EVP_MAC_update)(ctx.ptr, p.as_ptr(), p.len()) }, "EVP_MAC_update")?;
    }
    let mut out = [0u8; 32];
    let mut n = 0usize;
    l.check(unsafe { (l.f.EVP_MAC_final)(ctx.ptr, out.as_mut_ptr(), &mut n, out.len()) }, "EVP_MAC_final")?;
    if n != out.len() {
        bail!("unexpected HMAC length {n}");
    }
    Ok(out)
}

/// Incremental SHA-256 (for file transfers).
pub struct Sha256 {
    l: &'static Lib,
    ctx: Owned<EvpMdCtx>,
}

// An EVP_MD_CTX is not tied to a thread; each Sha256 is only used by one thread at a time.
unsafe impl Send for Sha256 {}

impl Sha256 {
    pub fn new() -> Self {
        Self::try_new().unwrap_or_else(|e| panic!("SHA-256: {e}"))
    }

    fn try_new() -> Result<Self> {
        let l = lib()?;
        let ctx = l.own(unsafe { (l.f.EVP_MD_CTX_new)() }, l.f.EVP_MD_CTX_free, "EVP_MD_CTX_new")?;
        l.check(unsafe { (l.f.EVP_DigestInit_ex2)(ctx.ptr, l.sha256, null()) }, "EVP_DigestInit_ex2")?;
        Ok(Sha256 { l, ctx })
    }

    pub fn update(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let rc = unsafe { (self.l.f.EVP_DigestUpdate)(self.ctx.ptr, data.as_ptr().cast(), data.len()) };
        assert!(rc == 1, "{}", self.l.error("EVP_DigestUpdate"));
    }

    pub fn finish(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut n: c_uint = 0;
        let rc = unsafe { (self.l.f.EVP_DigestFinal_ex)(self.ctx.ptr, out.as_mut_ptr(), &mut n) };
        assert!(rc == 1 && n == 32, "{}", self.l.error("EVP_DigestFinal_ex"));
        out
    }
}

/// Ephemeral ECDH P-256 key pair.
pub struct EcdhKey {
    l: &'static Lib,
    key: Owned<EvpPkey>,
}

fn encode_point(q: &[u8; PUBKEY_LEN]) -> [u8; 1 + PUBKEY_LEN] {
    let mut point = [0u8; 1 + PUBKEY_LEN];
    point[0] = 0x04; // uncompressed (SEC 1, 2.3.3)
    point[1..].copy_from_slice(q);
    point
}

impl EcdhKey {
    pub fn generate() -> Result<Self> {
        let l = lib()?;
        let ctx = l.ec_ctx()?;
        l.check(unsafe { (l.f.EVP_PKEY_keygen_init)(ctx.ptr) }, "EVP_PKEY_keygen_init")?;
        l.check(unsafe { (l.f.EVP_PKEY_CTX_set_group_name)(ctx.ptr, EC_GROUP.as_ptr()) }, "selecting P-256")?;
        let mut key = null_mut();
        let rc = unsafe { (l.f.EVP_PKEY_generate)(ctx.ptr, &mut key) };
        Ok(EcdhKey { l, key: l.own_pkey(rc, key, "EVP_PKEY_generate")? })
    }

    /// Imports a known key pair (private scalar `d`, public point `q`); used by known-answer tests.
    #[cfg(test)]
    pub fn from_private(d: &[u8; 32], q: &[u8; PUBKEY_LEN]) -> Result<Self> {
        let l = lib()?;
        let mut d_native = Secret(*d);
        if cfg!(target_endian = "little") {
            d_native.0.reverse();
        }
        let point = encode_point(q);
        let mut params = [
            OsslParam::utf8(c"group", EC_GROUP),
            OsslParam::octets(c"pub", &point),
            OsslParam::unsigned_native(c"priv", &d_native.0),
            OsslParam::end(),
        ];
        let key = l.ec_import(EVP_PKEY_KEYPAIR, &mut params, "importing private key")?;
        Ok(EcdhKey { l, key })
    }

    /// Uncompressed public point, X || Y (big-endian coordinates).
    pub fn public_bytes(&self) -> Result<[u8; PUBKEY_LEN]> {
        let mut point = [0u8; 1 + PUBKEY_LEN];
        let mut n = 0usize;
        let rc = unsafe {
            (self.l.f.EVP_PKEY_get_octet_string_param)(
                self.key.ptr,
                c"encoded-pub-key".as_ptr(),
                point.as_mut_ptr(),
                point.len(),
                &mut n,
            )
        };
        self.l.check(rc, "exporting the public key")?;
        if n != point.len() || point[0] != 0x04 {
            bail!("unexpected EC public key encoding");
        }
        let mut out = [0u8; PUBKEY_LEN];
        out.copy_from_slice(&point[1..]);
        Ok(out)
    }

    /// ECDH shared secret with `peer`: the X coordinate, big-endian (SEC 1).
    /// The peer point gets full public-key validation (field range, on the curve, not infinity).
    pub fn agree(&self, peer: &[u8; PUBKEY_LEN]) -> Result<Secret<32>> {
        let l = self.l;
        let point = encode_point(peer);
        let mut params = [OsslParam::utf8(c"group", EC_GROUP), OsslParam::octets(c"pub", &point), OsslParam::end()];
        let peer_key = l.ec_import(EVP_PKEY_PUBLIC_KEY, &mut params, "importing peer public key")?;
        let ctx = unsafe { (l.f.EVP_PKEY_CTX_new_from_pkey)(null_mut(), self.key.ptr, null()) };
        let ctx = l.own(ctx, l.f.EVP_PKEY_CTX_free, "EVP_PKEY_CTX_new_from_pkey")?;
        l.check(unsafe { (l.f.EVP_PKEY_derive_init)(ctx.ptr) }, "EVP_PKEY_derive_init")?;
        l.check(unsafe { (l.f.EVP_PKEY_derive_set_peer_ex)(ctx.ptr, peer_key.ptr, 1) }, "validating peer public key")?;
        let mut out = Secret::<32>::zero();
        let mut n = out.0.len();
        l.check(unsafe { (l.f.EVP_PKEY_derive)(ctx.ptr, out.0.as_mut_ptr(), &mut n) }, "EVP_PKEY_derive")?;
        if n != 32 {
            bail!("unexpected ECDH secret length {n}");
        }
        if out.0.iter().all(|&b| b == 0) {
            bail!("degenerate ECDH secret");
        }
        Ok(out)
    }
}

/// AES-256-GCM key.
///
/// The cipher context keeps the expanded key; each message only re-arms it with a new nonce.
pub struct Aead {
    l: &'static Lib,
    ctx: Owned<EvpCipherCtx>,
}

// An EVP_CIPHER_CTX may move between threads; each Aead is only ever used by one thread at a time
// (it is not Sync, so `&self` methods can never race on the context).
unsafe impl Send for Aead {}

impl Aead {
    pub fn new(key: &[u8; 32]) -> Result<Self> {
        let l = lib()?;
        let ctx = l.own(unsafe { (l.f.EVP_CIPHER_CTX_new)() }, l.f.EVP_CIPHER_CTX_free, "EVP_CIPHER_CTX_new")?;
        let rc = unsafe { (l.f.EVP_CipherInit_ex2)(ctx.ptr, l.aes_gcm, key.as_ptr(), null(), 1, null()) };
        l.check(rc, "AES-GCM key setup")?;
        Ok(Aead { l, ctx })
    }

    /// Starts a message under `nonce` (the default GCM IV length is 96 bits); `enc` 1 seals, 0 opens.
    fn begin(&self, nonce: &[u8; NONCE_LEN], enc: c_int) -> Result<()> {
        let rc = unsafe { (self.l.f.EVP_CipherInit_ex2)(self.ctx.ptr, null(), null(), nonce.as_ptr(), enc, null()) };
        self.l.check(rc, "AES-GCM nonce setup")
    }

    fn authenticate(&self, aad: &[u8]) -> Result<()> {
        for chunk in aad.chunks(MAX_CHUNK) {
            let mut n: c_int = 0;
            let rc = unsafe { (self.l.f.EVP_CipherUpdate)(self.ctx.ptr, null_mut(), &mut n, chunk.as_ptr(), chunk.len() as c_int) };
            self.l.check(rc, "AES-GCM AAD")?;
        }
        Ok(())
    }

    /// Encrypts or decrypts `data` in place (GCM is a stream mode: output length = input length).
    fn crypt(&self, data: &mut [u8]) -> Result<()> {
        for chunk in data.chunks_mut(MAX_CHUNK) {
            let (p, len) = (chunk.as_mut_ptr(), chunk.len() as c_int);
            let mut n: c_int = 0;
            self.l.check(unsafe { (self.l.f.EVP_CipherUpdate)(self.ctx.ptr, p, &mut n, p, len) }, "AES-GCM")?;
            if n != len {
                bail!("AES-GCM processed {n} of {len} bytes");
            }
        }
        Ok(())
    }

    /// Completes the message; when opening, this is where the tag is checked.
    fn finish(&self) -> Result<()> {
        let mut scratch = [0u8; 16];
        let mut n: c_int = 0;
        let rc = unsafe { (self.l.f.EVP_CipherFinal_ex)(self.ctx.ptr, scratch.as_mut_ptr(), &mut n) };
        self.l.check(rc, "AES-GCM final")?;
        if n != 0 {
            bail!("AES-GCM produced unexpected trailing output");
        }
        Ok(())
    }

    /// Encrypts `data` in place and returns the authentication tag.
    pub fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], data: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        self.begin(nonce, 1)?;
        self.authenticate(aad)?;
        self.crypt(data)?;
        self.finish()?;
        let mut tag = [0u8; TAG_LEN];
        let rc = unsafe {
            (self.l.f.EVP_CIPHER_CTX_ctrl)(self.ctx.ptr, EVP_CTRL_AEAD_GET_TAG, TAG_LEN as c_int, tag.as_mut_ptr().cast())
        };
        self.l.check(rc, "reading the AES-GCM tag")?;
        Ok(tag)
    }

    /// Decrypts `data` in place; fails (and wipes `data`) if the tag does not verify.
    pub fn open(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], data: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<()> {
        if self.try_open(nonce, aad, data, tag).is_err() {
            // Decryption streams plaintext out before the tag is checked: never leave it behind.
            crate::util::wipe(data);
            let _ = drain_errors(&self.l.f);
            bail!("record authentication failed");
        }
        Ok(())
    }

    fn try_open(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], data: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<()> {
        self.begin(nonce, 0)?;
        // SET_TAG only reads through the pointer; pass a copy so no const pointer becomes mutable.
        let mut expected = *tag;
        let rc = unsafe {
            (self.l.f.EVP_CIPHER_CTX_ctrl)(self.ctx.ptr, EVP_CTRL_AEAD_SET_TAG, TAG_LEN as c_int, expected.as_mut_ptr().cast())
        };
        self.l.check(rc, "setting the AES-GCM tag")?;
        self.authenticate(aad)?;
        self.crypt(data)?;
        self.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_openssl_3() {
        let l = lib().unwrap();
        assert!(!l.sha256.is_null() && !l.hmac.is_null() && !l.aes_gcm.is_null());
    }

    #[test]
    fn param_layout_matches_c() {
        // struct ossl_param_st { const char *; unsigned int; void *; size_t; size_t; } on LP64.
        assert_eq!(size_of::<OsslParam<'_>>(), 40);
        assert_eq!(std::mem::offset_of!(OsslParam<'_>, data), 16);
        assert_eq!(std::mem::offset_of!(OsslParam<'_>, return_size), 32);
        assert_eq!(OsslParam::utf8(c"digest", c"SHA256").data_size, 6);
    }

    #[test]
    fn objects_are_send() {
        fn send<T: Send>() {}
        send::<Sha256>();
        send::<Aead>();
        let mut h = Sha256::new();
        h.update(b"abc");
        let digest = std::thread::spawn(move || h.finish()).join().unwrap();
        assert_eq!(digest, sha256(&[b"abc"]));
    }

    #[test]
    fn failures_leave_error_queue_empty() {
        let l = lib().unwrap();
        let a = EcdhKey::generate().unwrap();
        let mut off_curve = a.public_bytes().unwrap();
        off_curve[0] ^= 0x80;
        let Err(e) = a.agree(&off_curve) else { panic!("off-curve point accepted") };
        let e = e.to_string();
        assert!(e.starts_with("importing peer public key failed"), "{e}");
        assert_eq!(unsafe { (l.f.ERR_get_error)() }, 0);

        let aead = Aead::new(&[3u8; 32]).unwrap();
        let mut data = [1u8; 40];
        assert!(aead.open(&[0u8; 12], b"", &mut data, &[0u8; 16]).is_err());
        assert_eq!(data, [0u8; 40], "plaintext must be wiped on failure");
        assert_eq!(unsafe { (l.f.ERR_get_error)() }, 0);
    }

    #[test]
    fn loader_reports_missing_or_unsuitable_libraries() {
        let Err(e) = load(&[c"libcrypto-not-installed.so.3"]) else { panic!("loaded a missing library") };
        assert!(e.starts_with(NOT_FOUND) && e.contains("libcrypto-not-installed.so.3"), "{e}");
        // libc loads fine but is not libcrypto.
        let Err(e) = load(&[c"libc.so.6"]) else { panic!("accepted libc as libcrypto") };
        assert!(e.starts_with(NOT_FOUND) && e.contains("libc.so.6: it lacks OpenSSL_version_num"), "{e}");
    }

    /// One handshake's worth of objects plus a sealed and opened record, with every failure path.
    fn churn(i: u32) {
        let a = EcdhKey::generate().unwrap();
        let b = EcdhKey::generate().unwrap();
        let s = a.agree(&b.public_bytes().unwrap()).unwrap();
        assert!(a.agree(&[0u8; 64]).is_err());
        let aead = Aead::new(&s.0).unwrap();
        let mut nonce = [0u8; 12];
        nonce[4..8].copy_from_slice(&i.to_le_bytes());
        let mut data = i.to_le_bytes().repeat(9);
        let tag = aead.seal(&nonce, &nonce, &mut data).unwrap();
        let mut bad = data.clone();
        bad[0] ^= 1;
        assert!(aead.open(&nonce, &nonce, &mut bad, &tag).is_err());
        aead.open(&nonce, &nonce, &mut data, &tag).unwrap();
        assert_eq!(data, i.to_le_bytes().repeat(9));
        hmac_sha256(&s.0, &[&data]);
        sha256(&[&data]);
    }

    #[test]
    fn many_keys_and_messages() {
        for i in 0..200 {
            churn(i);
        }
    }

    fn rss_kib() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let line = status.lines().find(|l| l.starts_with("VmRSS:")).unwrap();
        line.split_whitespace().nth(1).unwrap().parse().unwrap()
    }

    /// Leak check without valgrind: a leaked key, context or error entry per iteration would grow
    /// the resident set by tens of MiB. Run alone, since other tests allocate concurrently:
    /// `cargo test openssl::tests::no_leaks -- --ignored --test-threads=1`.
    #[test]
    #[ignore = "slow; run alone"]
    fn no_leaks() {
        for i in 0..2_000 {
            churn(i);
        }
        let before = rss_kib();
        for i in 0..30_000 {
            churn(i);
        }
        let grown = rss_kib().saturating_sub(before);
        assert!(grown < 1024, "resident set grew by {grown} KiB over 30000 iterations");
    }
}
