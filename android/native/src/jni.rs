//! The JNI this library uses, declared by hand from <jni.h>: the function tables are arrays of
//! pointers, and only the entries called here are named, by their index in the table.
//!
//! Calls from Java (`Native`'s methods, registered in `JNI_OnLoad`) get their `Env` as an
//! argument. Calls into Java happen on this library's own threads too (the session's crypto runs
//! on its network threads): `env()` attaches such a thread once, as a daemon, and it is detached
//! when the thread ends. Local references made on those threads are deleted as they go (`Local`),
//! since an attached thread never returns to Java to have them freed.

use crate::util::{Error, Result};
use std::cell::Cell;
use std::ffi::{c_char, c_void};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicPtr, Ordering};

pub type JObject = *mut c_void;
type JMethod = *mut c_void;

#[repr(C)]
#[derive(Clone, Copy)]
pub union JValue {
    pub z: u8,
    pub i: i32,
    pub j: i64,
    pub f: f32,
    pub l: JObject,
}

pub fn obj(l: JObject) -> JValue {
    JValue { l }
}

const JNI_OK: i32 = 0;
pub const JNI_VERSION_1_6: i32 = 0x0001_0006;

/// Indexes into `JNINativeInterface` (<jni.h>; the first four entries are reserved).
mod ix {
    pub const FIND_CLASS: usize = 6;
    pub const THROW: usize = 13;
    pub const THROW_NEW: usize = 14;
    pub const EXCEPTION_OCCURRED: usize = 15;
    pub const EXCEPTION_CLEAR: usize = 17;
    pub const NEW_GLOBAL_REF: usize = 21;
    pub const DELETE_GLOBAL_REF: usize = 22;
    pub const DELETE_LOCAL_REF: usize = 23;
    pub const GET_STATIC_METHOD_ID: usize = 113;
    pub const CALL_STATIC_OBJECT_METHOD_A: usize = 116;
    pub const CALL_STATIC_BOOLEAN_METHOD_A: usize = 119;
    pub const CALL_STATIC_VOID_METHOD_A: usize = 143;
    pub const GET_ARRAY_LENGTH: usize = 171;
    pub const NEW_BYTE_ARRAY: usize = 176;
    pub const GET_BYTE_ARRAY_REGION: usize = 200;
    pub const SET_BYTE_ARRAY_REGION: usize = 208;
    pub const REGISTER_NATIVES: usize = 215;
    pub const EXCEPTION_CHECK: usize = 228;
    pub const NEW_DIRECT_BYTE_BUFFER: usize = 229;
    pub const GET_DIRECT_BUFFER_ADDRESS: usize = 230;
    pub const GET_DIRECT_BUFFER_CAPACITY: usize = 231;
}

/// Indexes into `JNIInvokeInterface` (the JavaVM's table).
const VM_DETACH_CURRENT_THREAD: usize = 5;
const VM_GET_ENV: usize = 6;
const VM_ATTACH_CURRENT_THREAD_AS_DAEMON: usize = 7;

/// `JNINativeMethod`.
#[repr(C)]
pub struct NativeMethod {
    pub name: *const c_char,
    pub signature: *const c_char,
    pub f: *const c_void,
}

/// A `JNIEnv*`: valid on its own thread only.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Env(*mut *const *const c_void);

/// Calls entry `$i` of the table behind `$p` (a `JNIEnv*` or `JavaVM*`) as a function of the
/// given type, with the table's owner as the first argument.
macro_rules! call {
    ($p:expr, $i:expr, fn($($t:ty),*) -> $r:ty $(, $a:expr)*) => {{
        let p = $p;
        let f: unsafe extern "C" fn(*mut c_void $(, $t)*) -> $r = std::mem::transmute(*(*p).add($i));
        f(p.cast() $(, $a)*)
    }};
}

static VM: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Detaches a thread `env()` attached when it ends.
struct Attached(Cell<bool>);

impl Drop for Attached {
    fn drop(&mut self) {
        let vm = VM.load(Ordering::Acquire) as *mut *const *const c_void;
        if self.0.get() && !vm.is_null() {
            unsafe { call!(vm, VM_DETACH_CURRENT_THREAD, fn() -> i32) };
        }
    }
}

thread_local! {
    static ATTACHED: Attached = const { Attached(Cell::new(false)) };
}

pub fn set_vm(vm: *mut c_void) {
    VM.store(vm, Ordering::Release);
}

/// This thread's `Env`, attaching the thread to the VM if it is not yet.
pub fn env() -> Result<Env> {
    let vm = VM.load(Ordering::Acquire) as *mut *const *const c_void;
    if vm.is_null() {
        return Err(Error::msg("the Java VM is not available"));
    }
    let mut e: *mut c_void = std::ptr::null_mut();
    if unsafe { call!(vm, VM_GET_ENV, fn(*mut *mut c_void, i32) -> i32, &mut e, JNI_VERSION_1_6) } == JNI_OK {
        return Ok(Env(e.cast()));
    }
    let r = unsafe { call!(vm, VM_ATTACH_CURRENT_THREAD_AS_DAEMON, fn(*mut *mut c_void, *mut c_void) -> i32, &mut e, std::ptr::null_mut()) };
    if r != JNI_OK || e.is_null() {
        return Err(Error::msg(format!("cannot attach a thread to the Java VM ({r})")));
    }
    // A thread past its thread-locals' end (in a destructor) stays attached until it exits,
    // which the VM tolerates for daemon threads.
    let _ = ATTACHED.try_with(|a| a.0.set(true));
    Ok(Env(e.cast()))
}

/// A local reference, deleted when dropped.
pub struct Local {
    env: Env,
    pub obj: JObject,
}

impl Local {
    /// The reference, no longer deleted here: for a native method to return it to Java.
    pub fn into_raw(self) -> JObject {
        let o = self.obj;
        std::mem::forget(self);
        o
    }
}

impl Drop for Local {
    fn drop(&mut self) {
        if !self.obj.is_null() {
            unsafe { call!(self.env.0, ix::DELETE_LOCAL_REF, fn(JObject) -> (), self.obj) };
        }
    }
}

/// A global reference, usable on any thread; deleted when dropped.
pub struct Global(JObject);

unsafe impl Send for Global {}
unsafe impl Sync for Global {}

impl Global {
    pub fn obj(&self) -> JObject {
        self.0
    }
}

impl Drop for Global {
    fn drop(&mut self) {
        let vm = VM.load(Ordering::Acquire) as *mut *const *const c_void;
        if vm.is_null() {
            return;
        }
        // On a thread not attached (one whose thread-locals are already being torn down
        // included) it is attached just for this, and detached again.
        let mut e: *mut c_void = std::ptr::null_mut();
        unsafe {
            let attached = call!(vm, VM_GET_ENV, fn(*mut *mut c_void, i32) -> i32, &mut e, JNI_VERSION_1_6) == JNI_OK;
            if !attached && call!(vm, VM_ATTACH_CURRENT_THREAD_AS_DAEMON, fn(*mut *mut c_void, *mut c_void) -> i32, &mut e, std::ptr::null_mut()) != JNI_OK {
                return;
            }
            let env = e as *mut *const *const c_void;
            call!(env, ix::DELETE_GLOBAL_REF, fn(JObject) -> (), self.0);
            if !attached {
                call!(vm, VM_DETACH_CURRENT_THREAD, fn() -> i32);
            }
        }
    }
}

/// An argument array for a `Call...MethodA` (null for none, not an empty slice's dangling pointer).
fn ptr(args: &[JValue]) -> *const JValue {
    if args.is_empty() { std::ptr::null() } else { args.as_ptr() }
}

/// A static method: its class and ID (valid while the class is loaded, that is for good).
#[derive(Clone, Copy)]
pub struct Method {
    class: JObject,
    id: JMethod,
}

unsafe impl Send for Method {}
unsafe impl Sync for Method {}

impl Env {
    pub fn from_raw(p: *mut c_void) -> Env {
        Env(p.cast())
    }

    fn local(self, obj: JObject) -> Local {
        Local { env: self, obj }
    }

    fn pending(self) -> bool {
        unsafe { call!(self.0, ix::EXCEPTION_CHECK, fn() -> u8) != 0 }
    }

    fn clear(self) {
        unsafe { call!(self.0, ix::EXCEPTION_CLEAR, fn() -> ()) };
    }

    /// `byte[]` `a`'s contents, read without raising anything (None if that fails).
    fn quiet_bytes(self, a: JObject) -> Option<Vec<u8>> {
        let n = self.array_len(a);
        let mut v = vec![0u8; n];
        if n > 0 {
            unsafe { call!(self.0, ix::GET_BYTE_ARRAY_REGION, fn(JObject, i32, i32, *mut u8) -> (), a, 0, n as i32, v.as_mut_ptr()) };
        }
        if self.pending() {
            self.clear();
            return None;
        }
        Some(v)
    }

    /// A new `byte[]` holding `data`, made without raising anything.
    fn quiet_array(self, data: &[u8]) -> Option<Local> {
        let n = i32::try_from(data.len()).ok()?;
        let a = self.local(unsafe { call!(self.0, ix::NEW_BYTE_ARRAY, fn(i32) -> JObject, n) });
        if !a.obj.is_null() && n > 0 {
            unsafe { call!(self.0, ix::SET_BYTE_ARRAY_REGION, fn(JObject, i32, i32, *const u8) -> (), a.obj, 0, n, data.as_ptr()) };
        }
        if self.pending() || a.obj.is_null() {
            self.clear();
            return None;
        }
        Some(a)
    }

    /// The pending Java exception, cleared, as an error (its `toString()`). Describing it runs
    /// no check of its own: a failure there (out of memory, say) cannot recurse.
    fn check(self) -> Result<()> {
        if !self.pending() {
            return Ok(());
        }
        let t = self.local(unsafe { call!(self.0, ix::EXCEPTION_OCCURRED, fn() -> JObject) });
        self.clear();
        let mut text = None;
        if let Ok(u) = up() {
            let args = [obj(t.obj)];
            let m = u.describe;
            let s = self.local(unsafe { call!(self.0, ix::CALL_STATIC_OBJECT_METHOD_A, fn(JObject, JMethod, *const JValue) -> JObject, m.class, m.id, ptr(&args)) });
            if self.pending() {
                self.clear();
            } else if !s.obj.is_null() {
                text = self.quiet_bytes(s.obj).map(|b| String::from_utf8_lossy(&b).into_owned());
            }
        }
        Err(Error::msg(text.unwrap_or_else(|| "a Java exception".into())))
    }

    pub fn find_class(self, name: &std::ffi::CStr) -> Result<Global> {
        let c = self.local(unsafe { call!(self.0, ix::FIND_CLASS, fn(*const c_char) -> JObject, name.as_ptr()) });
        self.check()?;
        self.global(&c)
    }

    /// Raises a `java.lang.IllegalStateException` with `msg` for when the native method returns.
    /// The text goes to Java as UTF-8 bytes (`Crypto.failure`): `ThrowNew` takes JNI's modified
    /// UTF-8, which text from a host (an emoji in a notice) need not be.
    pub fn throw(self, msg: &str) {
        self.clear();
        if let Ok(u) = up()
            && let Some(text) = self.quiet_array(msg.as_bytes())
        {
            let args = [obj(text.obj)];
            let m = u.failure;
            let t = self.local(unsafe { call!(self.0, ix::CALL_STATIC_OBJECT_METHOD_A, fn(JObject, JMethod, *const JValue) -> JObject, m.class, m.id, ptr(&args)) });
            if !self.pending() && !t.obj.is_null() && unsafe { call!(self.0, ix::THROW, fn(JObject) -> i32, t.obj) } == JNI_OK {
                return;
            }
            self.clear();
        }
        // Without the Java side (or its memory): ASCII, which modified UTF-8 shares.
        let ascii: String = msg.chars().map(|c| if c.is_ascii() && c != '\0' { c } else { '?' }).collect();
        let text = std::ffi::CString::new(ascii).unwrap_or_default();
        let c = self.local(unsafe { call!(self.0, ix::FIND_CLASS, fn(*const c_char) -> JObject, c"java/lang/IllegalStateException".as_ptr()) });
        if self.pending() || c.obj.is_null() {
            self.clear();
            return;
        }
        unsafe { call!(self.0, ix::THROW_NEW, fn(JObject, *const c_char) -> i32, c.obj, text.as_ptr()) };
    }

    pub fn global(self, l: &Local) -> Result<Global> {
        let g = unsafe { call!(self.0, ix::NEW_GLOBAL_REF, fn(JObject) -> JObject, l.obj) };
        if g.is_null() {
            return Err(Error::msg("NewGlobalRef failed"));
        }
        Ok(Global(g))
    }

    pub fn static_method(self, class: &Global, name: &std::ffi::CStr, sig: &std::ffi::CStr) -> Result<Method> {
        let id = unsafe { call!(self.0, ix::GET_STATIC_METHOD_ID, fn(JObject, *const c_char, *const c_char) -> JMethod, class.0, name.as_ptr(), sig.as_ptr()) };
        self.check()?;
        Ok(Method { class: class.0, id })
    }

    pub fn register_natives(self, class: &Global, methods: &[NativeMethod]) -> Result<()> {
        let r = unsafe { call!(self.0, ix::REGISTER_NATIVES, fn(JObject, *const NativeMethod, i32) -> i32, class.0, methods.as_ptr(), methods.len() as i32) };
        self.check()?;
        if r != JNI_OK {
            return Err(Error::msg(format!("RegisterNatives failed ({r})")));
        }
        Ok(())
    }

    pub fn call_object(self, m: Method, args: &[JValue]) -> Result<Local> {
        let r = unsafe { call!(self.0, ix::CALL_STATIC_OBJECT_METHOD_A, fn(JObject, JMethod, *const JValue) -> JObject, m.class, m.id, ptr(args)) };
        let r = self.local(r);
        self.check()?;
        Ok(r)
    }

    pub fn call_bool(self, m: Method, args: &[JValue]) -> Result<bool> {
        let r = unsafe { call!(self.0, ix::CALL_STATIC_BOOLEAN_METHOD_A, fn(JObject, JMethod, *const JValue) -> u8, m.class, m.id, ptr(args)) };
        self.check()?;
        Ok(r != 0)
    }

    pub fn call_void(self, m: Method, args: &[JValue]) -> Result<()> {
        unsafe { call!(self.0, ix::CALL_STATIC_VOID_METHOD_A, fn(JObject, JMethod, *const JValue) -> (), m.class, m.id, ptr(args)) };
        self.check()
    }

    /// A new `byte[]` holding `data`.
    pub fn byte_array(self, data: &[u8]) -> Result<Local> {
        let n = i32::try_from(data.len()).map_err(|_| Error::msg("too much data for a Java array"))?;
        let a = self.local(unsafe { call!(self.0, ix::NEW_BYTE_ARRAY, fn(i32) -> JObject, n) });
        self.check()?;
        if a.obj.is_null() {
            return Err(Error::msg("NewByteArray failed"));
        }
        if n > 0 {
            unsafe { call!(self.0, ix::SET_BYTE_ARRAY_REGION, fn(JObject, i32, i32, *const u8) -> (), a.obj, 0, n, data.as_ptr()) };
            self.check()?;
        }
        Ok(a)
    }

    pub fn array_len(self, a: JObject) -> usize {
        if a.is_null() {
            return 0;
        }
        unsafe { call!(self.0, ix::GET_ARRAY_LENGTH, fn(JObject) -> i32, a) }.max(0) as usize
    }

    /// Copies `byte[]` `a` into `out`, which must be as long.
    pub fn read_bytes(self, a: JObject, out: &mut [u8]) -> Result<()> {
        if self.array_len(a) != out.len() {
            return Err(Error::msg(format!("expected {} bytes from Java, got {}", out.len(), self.array_len(a))));
        }
        if out.is_empty() {
            return Ok(());
        }
        unsafe { call!(self.0, ix::GET_BYTE_ARRAY_REGION, fn(JObject, i32, i32, *mut u8) -> (), a, 0, out.len() as i32, out.as_mut_ptr()) };
        self.check()
    }

    pub fn bytes_raw(self, a: JObject) -> Result<Vec<u8>> {
        let mut v = vec![0; self.array_len(a)];
        if !v.is_empty() {
            self.read_bytes(a, &mut v)?;
        }
        Ok(v)
    }

    /// Overwrites `byte[]` `a` with zeros: for secrets that passed through the Java heap.
    pub fn zero(self, a: JObject) {
        let n = self.array_len(a);
        if n > 0 {
            let z = vec![0u8; n];
            unsafe { call!(self.0, ix::SET_BYTE_ARRAY_REGION, fn(JObject, i32, i32, *const u8) -> (), a, 0, n as i32, z.as_ptr()) };
            let _ = self.check();
        }
    }

    /// A direct `ByteBuffer` over `len` bytes at `p`, which must outlive every use Java makes of it.
    pub fn direct(self, p: *mut u8, len: usize) -> Result<Local> {
        // A zero-length buffer at a dangling pointer (an empty slice's) is fine for Java; null is not.
        if p.is_null() || i64::try_from(len).is_err() {
            return Err(Error::msg("no memory for a direct buffer"));
        }
        let b = self.local(unsafe { call!(self.0, ix::NEW_DIRECT_BYTE_BUFFER, fn(*mut c_void, i64) -> JObject, p.cast(), len as i64) });
        self.check()?;
        if b.obj.is_null() {
            return Err(Error::msg("NewDirectByteBuffer failed"));
        }
        Ok(b)
    }

    /// The memory of direct `ByteBuffer` `b`.
    pub fn direct_slice<'a>(self, b: JObject) -> Option<&'a [u8]> {
        if b.is_null() {
            return None;
        }
        let p = unsafe { call!(self.0, ix::GET_DIRECT_BUFFER_ADDRESS, fn(JObject) -> *mut u8, b) };
        let n = unsafe { call!(self.0, ix::GET_DIRECT_BUFFER_CAPACITY, fn(JObject) -> i64, b) };
        (!p.is_null() && n >= 0).then(|| unsafe { std::slice::from_raw_parts(p, n as usize) })
    }
}

/// The Java methods this library calls, looked up once in `JNI_OnLoad` (on a Java thread, whose
/// class loader knows the app's classes; this library's own threads only see the system's).
pub struct Up {
    pub describe: Method,
    pub failure: Method,
    pub random: Method,
    pub digest: Method,
    pub digest_update: Method,
    pub digest_finish: Method,
    pub hmac: Method,
    pub hmac_update: Method,
    pub hmac_finish: Method,
    pub ecdh_generate: Method,
    pub ecdh_from_private: Method,
    pub ecdh_public: Method,
    pub ecdh_agree: Method,
    pub aead: Method,
    pub aead_seal: Method,
    pub aead_open: Method,
    pub vault_hmac: Method,
    _classes: Vec<Global>,
}

static UP: OnceLock<Up> = OnceLock::new();

pub fn up() -> Result<&'static Up> {
    UP.get().ok_or_else(|| Error::msg("the Java side of the app is not loaded"))
}

/// Where the app's Java classes live.
pub const PACKAGE: &str = "io/github/na_degen_girl/saferdp/";

fn class(env: Env, name: &str) -> Result<Global> {
    let full = std::ffi::CString::new(format!("{PACKAGE}{name}")).unwrap();
    env.find_class(&full)
}

pub fn init(env: Env) -> Result<()> {
    let crypto = class(env, "Crypto")?;
    let vault = class(env, "KeyVault")?;
    let m = |c: &Global, name: &std::ffi::CStr, sig: &std::ffi::CStr| env.static_method(c, name, sig);
    let up = Up {
        describe: m(&crypto, c"describe", c"(Ljava/lang/Throwable;)[B")?,
        failure: m(&crypto, c"failure", c"([B)Ljava/lang/Throwable;")?,
        random: m(&crypto, c"random", c"([B)V")?,
        digest: m(&crypto, c"digest", c"()Ljava/lang/Object;")?,
        digest_update: m(&crypto, c"digestUpdate", c"(Ljava/lang/Object;Ljava/nio/ByteBuffer;)V")?,
        digest_finish: m(&crypto, c"digestFinish", c"(Ljava/lang/Object;)[B")?,
        hmac: m(&crypto, c"hmac", c"([B)Ljava/lang/Object;")?,
        hmac_update: m(&crypto, c"hmacUpdate", c"(Ljava/lang/Object;Ljava/nio/ByteBuffer;)V")?,
        hmac_finish: m(&crypto, c"hmacFinish", c"(Ljava/lang/Object;)[B")?,
        ecdh_generate: m(&crypto, c"ecdhGenerate", c"()Ljava/lang/Object;")?,
        ecdh_from_private: m(&crypto, c"ecdhFromPrivate", c"([B[B)Ljava/lang/Object;")?,
        ecdh_public: m(&crypto, c"ecdhPublic", c"(Ljava/lang/Object;)[B")?,
        ecdh_agree: m(&crypto, c"ecdhAgree", c"(Ljava/lang/Object;[B)[B")?,
        aead: m(&crypto, c"aead", c"([B)Ljava/lang/Object;")?,
        aead_seal: m(&crypto, c"aeadSeal", c"(Ljava/lang/Object;[B[BLjava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)V")?,
        aead_open: m(&crypto, c"aeadOpen", c"(Ljava/lang/Object;[B[BLjava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)Z")?,
        vault_hmac: m(&vault, c"hmac", c"([B[B)[B")?,
        _classes: vec![crypto, vault],
    };
    let _ = UP.set(up);
    Ok(())
}

pub fn native_class(env: Env) -> Result<Global> {
    class(env, "Native")
}
