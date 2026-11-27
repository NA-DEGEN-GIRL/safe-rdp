//! The `native` methods of the Java class `Native`, registered in `JNI_OnLoad`.
//!
//! Every method catches failures and panics alike and raises them in Java as an
//! `IllegalStateException`: nothing unwinds into the VM.

use crate::channel::Psk;
use crate::jni::{self, Env, JObject, NativeMethod, obj};
use crate::session::{Key, Session};
use crate::touch::Mode;
use crate::util::{Result, Secret};
use crate::viewer::ViewerOptions;
use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

/// Runs `f` for a native method: an error or a panic becomes a Java exception and `fallback`.
fn guard<T>(env: Env, fallback: T, f: impl FnOnce() -> Result<T>) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            env.throw(&e.to_string());
            fallback
        }
        Err(p) => {
            let what = p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()));
            env.throw(&format!("internal error: {}", what.unwrap_or_default()));
            fallback
        }
    }
}

/// A `byte[]` for Java (null if it cannot be made; an exception is then pending).
fn bytes_out(env: Env, data: &[u8]) -> Result<JObject> {
    Ok(env.byte_array(data)?.into_raw())
}

/// The pre-shared key held by the Android Keystore under `alias` (see the app's `KeyVault`): the
/// handshake asks it for HMACs and never sees the key.
pub struct VaultKey {
    pub alias: Vec<u8>,
}

impl Psk for VaultKey {
    fn extract(&self, ikm: &[u8]) -> Result<Secret<32>> {
        let env = jni::env()?;
        let alias = env.byte_array(&self.alias)?;
        let data = env.byte_array(ikm)?;
        let r = env.call_object(jni::up()?.vault_hmac, &[obj(alias.obj), obj(data.obj)]);
        env.zero(data.obj);
        let r = r?;
        let mut out = Secret::<32>::zero();
        let got = env.read_bytes(r.obj, &mut out.0);
        env.zero(r.obj);
        got?;
        Ok(out)
    }
}

extern "C" fn self_test(env: *mut c_void, _: JObject) -> JObject {
    let env = Env::from_raw(env);
    guard(env, std::ptr::null_mut(), || bytes_out(env, crate::selftest::run().as_bytes()))
}

/// `srdp1-...` text (UTF-8) to the key's 32 bytes, for `KeyVault` to import.
extern "C" fn parse_key(env: *mut c_void, _: JObject, text: JObject) -> JObject {
    let env = Env::from_raw(env);
    guard(env, std::ptr::null_mut(), || {
        let mut t = env.bytes_raw(text)?;
        let k = std::str::from_utf8(&t).map_err(|_| "not a safe-rdp key".into()).and_then(crate::keys::parse_key);
        crate::util::wipe(&mut t);
        bytes_out(env, &k?.0)
    })
}

/// A QR code's text in a camera frame's luminance plane (a direct buffer), or null.
extern "C" fn qr_decode(env: *mut c_void, _: JObject, luma: JObject, w: i32, h: i32, stride: i32) -> JObject {
    let env = Env::from_raw(env);
    guard(env, std::ptr::null_mut(), || {
        let Some(pixels) = env.direct_slice(luma) else { return Ok(std::ptr::null_mut()) };
        let dims = (usize::try_from(w), usize::try_from(h), usize::try_from(stride));
        let (Ok(w), Ok(h), Ok(stride)) = dims else { return Ok(std::ptr::null_mut()) };
        match crate::qr::decode(pixels, w, h, stride) {
            Some(mut text) => {
                let r = bytes_out(env, &text);
                crate::util::wipe(&mut text);
                r
            }
            None => Ok(std::ptr::null_mut()),
        }
    })
}

/// The app's kept log lines.
extern "C" fn log_text(env: *mut c_void, _: JObject) -> JObject {
    let env = Env::from_raw(env);
    guard(env, std::ptr::null_mut(), || bytes_out(env, crate::platform::log_text().as_bytes()))
}

/// Connects to `target`, authenticates with the Keystore key `alias` (or, for tests, the key
/// text `key`) and returns what the host's hello said. Blocks: not on the UI thread.
extern "C" fn probe(env: *mut c_void, _: JObject, target: JObject, alias: JObject, key: JObject) -> JObject {
    let env = Env::from_raw(env);
    guard(env, std::ptr::null_mut(), || {
        let target = String::from_utf8(env.bytes_raw(target)?).map_err(|_| "bad host name")?;
        let opts = crate::viewer::ViewerOptions::default();
        let c = if key.is_null() {
            crate::viewer::connect(&target, &opts, &VaultKey { alias: env.bytes_raw(alias)? })?
        } else {
            let mut t = env.bytes_raw(key)?;
            let k = std::str::from_utf8(&t).map_err(|_| "not a safe-rdp key".into()).and_then(crate::keys::parse_key);
            crate::util::wipe(&mut t);
            crate::viewer::connect(&target, &opts, &k?)?
        };
        let text = format!("{} {}x{} flags {:#x} monitors {} via {}", c.host_name, c.width, c.height, c.flags, c.monitors.len(), c.addr);
        bytes_out(env, text.as_bytes())
    })
}

/// `Native.open`'s option bits.
const OPT_VIEW_ONLY: i32 = 1;
const OPT_CLIPBOARD: i32 = 2;
const OPT_AUDIO: i32 = 4;
const OPT_PRIVACY: i32 = 8;

/// A session handle as Java holds it: a leaked `Box<Arc<Session>>`, freed by `free` only, after
/// which Java never passes it again.
fn session<'a>(h: i64) -> Option<&'a Arc<Session>> {
    (h != 0).then(|| unsafe { &*(h as *const Arc<Session>) })
}

fn text_arg(env: Env, a: JObject) -> Result<String> {
    String::from_utf8(env.bytes_raw(a)?).map_err(|_| "text is not UTF-8".into())
}

/// Starts a session to `target` with the Keystore key `alias`, or with key text `key` (tests).
#[allow(clippy::too_many_arguments)]
extern "C" fn open(
    env: *mut c_void,
    _: JObject,
    target: JObject,
    alias: JObject,
    key: JObject,
    options: i32,
    downscale: i32,
    quality: i32,
    monitor: i32,
    trackpad: u8,
    density: f32,
) -> i64 {
    let env = Env::from_raw(env);
    guard(env, 0, || {
        let target = text_arg(env, target)?;
        let key: Key = if key.is_null() {
            Box::new(VaultKey { alias: env.bytes_raw(alias)? })
        } else {
            let mut t = env.bytes_raw(key)?;
            let k = std::str::from_utf8(&t).map_err(|_| "not a safe-rdp key".into()).and_then(crate::keys::parse_key);
            crate::util::wipe(&mut t);
            Box::new(k?)
        };
        let opts = ViewerOptions {
            view_only: options & OPT_VIEW_ONLY != 0,
            clipboard: options & OPT_CLIPBOARD != 0,
            audio: options & OPT_AUDIO != 0,
            privacy: options & OPT_PRIVACY != 0,
            allow_capture: false,
            downscale: downscale.clamp(1, 4) as u8,
            quality: quality.clamp(0, 255) as u8,
            monitor: monitor.clamp(0, 255) as u8,
            instance: crate::viewer::new_instance()?,
            ..ViewerOptions::default()
        };
        let mode = if trackpad != 0 { Mode::Trackpad } else { Mode::Direct };
        let s = Session::start(target, key, opts, mode, density)?;
        Ok(Box::into_raw(Box::new(s)) as i64)
    })
}

extern "C" fn surface(env: *mut c_void, _: JObject, h: i64, surface: JObject) {
    let Some(s) = session(h) else { return };
    if surface.is_null() {
        s.renderer.detach();
    } else {
        let w = crate::render::window_from_surface(env, surface);
        if !w.is_null() {
            s.renderer.attach(w);
        }
    }
}

extern "C" fn surface_size(_: *mut c_void, _: JObject, h: i64, w: i32, ht: i32) {
    if let Some(s) = session(h) {
        s.surface_size(w, ht);
    }
}

extern "C" fn touch(_: *mut c_void, _: JObject, h: i64, kind: i32, id: i32, x: f32, y: f32, t: i64) {
    if let Some(s) = session(h) {
        s.touch(kind, id, x, y, t.max(0) as u64);
    }
}

extern "C" fn tick(_: *mut c_void, _: JObject, h: i64, t: i64) {
    if let Some(s) = session(h) {
        s.tick(t.max(0) as u64);
    }
}

extern "C" fn mouse(_: *mut c_void, _: JObject, h: i64, kind: i32, x: f32, y: f32, buttons: i32, v: f32, hs: f32) {
    if let Some(s) = session(h) {
        s.mouse(kind, x, y, buttons, v, hs);
    }
}

extern "C" fn key(_: *mut c_void, _: JObject, h: i64, evdev: i32, down: u8) {
    if let Some(s) = session(h) {
        s.key(evdev, down != 0);
    }
}

extern "C" fn set(_: *mut c_void, _: JObject, h: i64, key: i32, value: i32) {
    if let Some(s) = session(h) {
        s.set(key.clamp(0, 255) as u8, value as u32);
    }
}

extern "C" fn command(_: *mut c_void, _: JObject, h: i64, cmd: i32) {
    if let Some(s) = session(h) {
        s.command(cmd);
    }
}

extern "C" fn clipboard(env: *mut c_void, _: JObject, h: i64, text: JObject) {
    let env = Env::from_raw(env);
    if let Some(s) = session(h) {
        guard(env, (), || {
            s.clipboard(text_arg(env, text)?);
            Ok(())
        });
    }
}

/// The next event (session.rs `Event::encode`), waiting for one; null once the session is over.
extern "C" fn next_event(env: *mut c_void, _: JObject, h: i64) -> JObject {
    let env = Env::from_raw(env);
    let Some(s) = session(h) else { return std::ptr::null_mut() };
    guard(env, std::ptr::null_mut(), || match s.next_event() {
        Some(e) => bytes_out(env, &e.encode()),
        None => Ok(std::ptr::null_mut()),
    })
}

extern "C" fn close(_: *mut c_void, _: JObject, h: i64) {
    if let Some(s) = session(h) {
        s.close();
    }
}

extern "C" fn free(_: *mut c_void, _: JObject, h: i64) {
    if h != 0 {
        drop(unsafe { Box::from_raw(h as *mut Arc<Session>) });
    }
}

macro_rules! native {
    ($name:literal, $sig:literal, $f:expr) => {
        NativeMethod { name: concat!($name, "\0").as_ptr().cast(), signature: concat!($sig, "\0").as_ptr().cast(), f: $f as *const c_void }
    };
}

#[unsafe(no_mangle)]
pub extern "C" fn JNI_OnLoad(vm: *mut c_void, _reserved: *mut c_void) -> i32 {
    jni::set_vm(vm);
    let methods = [
        native!("selfTest", "()[B", self_test as extern "C" fn(_, _) -> _),
        native!("parseKey", "([B)[B", parse_key as extern "C" fn(_, _, _) -> _),
        native!("log", "()[B", log_text as extern "C" fn(_, _) -> _),
        native!("qrDecode", "(Ljava/nio/ByteBuffer;III)[B", qr_decode as extern "C" fn(_, _, _, _, _, _) -> _),
        native!("probe", "([B[B[B)[B", probe as extern "C" fn(_, _, _, _, _) -> _),
        native!("open", "([B[B[BIIIIZF)J", open as extern "C" fn(_, _, _, _, _, _, _, _, _, _, _) -> _),
        native!("surface", "(JLandroid/view/Surface;)V", surface as extern "C" fn(_, _, _, _)),
        native!("surfaceSize", "(JII)V", surface_size as extern "C" fn(_, _, _, _, _)),
        native!("touch", "(JIIFFJ)V", touch as extern "C" fn(_, _, _, _, _, _, _, _)),
        native!("tick", "(JJ)V", tick as extern "C" fn(_, _, _, _)),
        native!("mouse", "(JIFFIFF)V", mouse as extern "C" fn(_, _, _, _, _, _, _, _, _)),
        native!("key", "(JIZ)V", key as extern "C" fn(_, _, _, _, _)),
        native!("set", "(JII)V", set as extern "C" fn(_, _, _, _, _)),
        native!("command", "(JI)V", command as extern "C" fn(_, _, _, _)),
        native!("clipboard", "(J[B)V", clipboard as extern "C" fn(_, _, _, _)),
        native!("nextEvent", "(J)[B", next_event as extern "C" fn(_, _, _) -> _),
        native!("close", "(J)V", close as extern "C" fn(_, _, _)),
        native!("free", "(J)V", free as extern "C" fn(_, _, _)),
    ];
    let r = (|| -> Result<()> {
        let env = jni::env()?;
        jni::init(env)?;
        env.register_natives(&jni::native_class(env)?, &methods)
    })();
    match r {
        Ok(()) => jni::JNI_VERSION_1_6,
        Err(e) => {
            crate::log!("cannot load: {e}");
            -1
        }
    }
}
