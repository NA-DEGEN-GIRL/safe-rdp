//! Draws the remote screen on the session's `SurfaceView` with OpenGL ES 3.0, on a thread of its
//! own that owns the EGL context.
//!
//! The framebuffer (BGRA, as decoded) is one texture; only the regions that changed are uploaded,
//! and the swap from BGRA happens in the shader. Zooming and panning only move a rectangle, so
//! they never wait for the host. The picture is drawn when something changed: a frame completed,
//! the view moved, the pointer moved, the surface changed.
//!
//! When the surface goes (the app is left, the screen turns off) the texture is overwritten with
//! zeros and deleted, as the framebuffer is when the session ends: what the GPU driver does with
//! that memory afterwards is out of reach.

use crate::cursor::{Sprite, sprite_for};
use crate::gl::*;
use crate::log;
use crate::platform::mem::LockedBuf;
use crate::proto::Cursor;
use crate::util::Result;
use crate::view::View;
use crate::viewer::{FrameLock, ResizePacer};
use crate::codec::Rect;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The remote screen as last decoded.
pub struct Framebuffer {
    pub w: usize,
    pub h: usize,
    pub px: LockedBuf,
    pub dirty: Option<Rect>,
    pub resizes: ResizePacer,
}

pub fn union(a: Option<Rect>, b: Rect) -> Rect {
    match a {
        None => b,
        Some(d) => {
            let (x0, y0) = (d.x.min(b.x), d.y.min(b.y));
            let (x1, y1) = ((d.x + d.w).max(b.x + b.w), (d.y + d.h).max(b.y + b.h));
            Rect { x: x0, y: y0, w: x1 - x0, h: y1 - y0 }
        }
    }
}

/// The pointer the app draws.
pub struct Pointer {
    pub shape: Cursor,
    /// Remote pixels.
    pub at: (f32, f32),
    /// Off while a mouse is used: the system draws its own pointer then.
    pub drawn: bool,
}

/// What the session and the renderer share.
pub struct Screen {
    pub fb: FrameLock<Framebuffer>,
    pub view: Mutex<View>,
    pub pointer: Mutex<Pointer>,
    /// GL_MAX_TEXTURE_SIZE once known (0 before).
    pub max_texture: AtomicI32,
    /// Surface pixels per dp, for the pointer's size.
    pub density: f32,
}

impl Screen {
    pub fn new(density: f32) -> Screen {
        let fb = Framebuffer { w: 0, h: 0, px: LockedBuf::new(0), dirty: None, resizes: ResizePacer::new(Instant::now()) };
        Screen {
            fb: FrameLock::new(fb),
            view: Mutex::new(View::new(1.0, 1.0, 1.0, 1.0)),
            pointer: Mutex::new(Pointer { shape: Cursor::Arrow, at: (0.0, 0.0), drawn: true }),
            max_texture: AtomicI32::new(0),
            density,
        }
    }

    /// Wipes the remote screen's contents.
    pub fn wipe(&self) {
        let mut fb = self.fb.ui().unwrap_or_else(PoisonError::into_inner);
        fb.px = LockedBuf::new(0);
        (fb.w, fb.h, fb.dirty) = (0, 0, None);
    }
}

enum Command {
    Attach(*mut ANativeWindow),
    Detach,
}

unsafe impl Send for Command {}

struct State {
    command: Option<Command>,
    /// A `Detach` was carried out.
    detached: bool,
    redraw: bool,
    stop: bool,
}

/// The render thread's controls.
pub struct Renderer {
    state: Mutex<State>,
    cv: Condvar,
    running: AtomicBool,
}

impl Renderer {
    pub fn new() -> Arc<Renderer> {
        Arc::new(Renderer {
            state: Mutex::new(State { command: None, detached: false, redraw: false, stop: false }),
            cv: Condvar::new(),
            running: AtomicBool::new(false),
        })
    }

    pub fn start(self: &Arc<Self>, screen: Arc<Screen>) -> Result<()> {
        let me = self.clone();
        self.running.store(true, Ordering::SeqCst);
        std::thread::Builder::new().name("render".into()).spawn(move || {
            if let Err(e) = me.run(&screen) {
                log!("drawing failed: {e}");
            }
            me.running.store(false, Ordering::SeqCst);
            // Whoever waits for a detach must not wait for a thread that is gone.
            lock(&me.state).detached = true;
            me.cv.notify_all();
        })?;
        Ok(())
    }

    pub fn redraw(&self) {
        lock(&self.state).redraw = true;
        self.cv.notify_all();
    }

    /// Draws into `window` from now on (an `ANativeWindow` this call takes over).
    pub fn attach(&self, window: *mut ANativeWindow) {
        let mut s = lock(&self.state);
        if let Some(Command::Attach(old)) = s.command.replace(Command::Attach(window)) {
            unsafe { ANativeWindow_release(old) };
        }
        s.redraw = true;
        self.cv.notify_all();
    }

    /// Stops drawing into the window and lets go of it; returns once done, as Android requires
    /// before `surfaceDestroyed` returns.
    pub fn detach(&self) {
        let mut s = lock(&self.state);
        if let Some(Command::Attach(w)) = s.command.take() {
            unsafe { ANativeWindow_release(w) };
        }
        if !self.running.load(Ordering::SeqCst) {
            return;
        }
        s.command = Some(Command::Detach);
        s.detached = false;
        self.cv.notify_all();
        while !s.detached && self.running.load(Ordering::SeqCst) {
            s = self.cv.wait(s).unwrap_or_else(PoisonError::into_inner);
        }
    }

    pub fn stop(&self) {
        lock(&self.state).stop = true;
        self.cv.notify_all();
    }

    fn run(&self, screen: &Screen) -> Result<()> {
        let mut gl = Gl::new()?;
        loop {
            let (command, stop) = {
                let mut s = lock(&self.state);
                while s.command.is_none() && !s.stop && !(s.redraw && gl.surface.is_some()) {
                    s = self.cv.wait(s).unwrap_or_else(PoisonError::into_inner);
                }
                s.redraw = false;
                (s.command.take(), s.stop)
            };
            match command {
                Some(Command::Attach(w)) => {
                    if let Err(e) = gl.attach(w) {
                        log!("cannot draw on the window: {e}");
                    }
                    if let Some(max) = gl.max_texture {
                        screen.max_texture.store(max, Ordering::SeqCst);
                    }
                }
                Some(Command::Detach) => {
                    gl.detach();
                    lock(&self.state).detached = true;
                    self.cv.notify_all();
                }
                None => {}
            }
            if stop {
                gl.detach();
                return Ok(());
            }
            if gl.surface.is_some() {
                gl.draw(screen);
            }
        }
    }
}

const VERTEX: &str = "#version 300 es
uniform vec4 u_rect;
out vec2 v_uv;
void main() {
    vec2 c = vec2(float(gl_VertexID & 1), float(gl_VertexID >> 1));
    gl_Position = vec4(mix(u_rect.xy, u_rect.zw, c), 0.0, 1.0);
    v_uv = c;
}
\0";

/// `u_bgra`: the screen texture holds BGRA bytes uploaded as RGBA; the pointer's is RGBA.
const FRAGMENT: &str = "#version 300 es
precision mediump float;
uniform sampler2D u_tex;
uniform int u_bgra;
in vec2 v_uv;
out vec4 o;
void main() {
    vec4 c = texture(u_tex, v_uv);
    o = u_bgra == 1 ? vec4(c.b, c.g, c.r, 1.0) : c;
}
\0";

struct Gl {
    display: EGLDisplay,
    config: EGLConfig,
    context: EGLContext,
    surface: Option<(EGLSurface, *mut ANativeWindow)>,
    program: u32,
    u_rect: i32,
    u_bgra: i32,
    /// The screen texture and its size.
    tex: u32,
    tex_size: (usize, usize),
    mipmapped: bool,
    pointer_tex: u32,
    pointer: Option<(Cursor, Sprite)>,
    max_texture: Option<i32>,
    too_large: Option<(usize, usize)>,
}

impl Gl {
    fn new() -> Result<Gl> {
        unsafe {
            let display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
            if display == EGL_NO_DISPLAY || eglInitialize(display, std::ptr::null_mut(), std::ptr::null_mut()) != EGL_TRUE {
                crate::bail!("no EGL display ({:#x})", eglGetError());
            }
            let attrs = [
                EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT, EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
                EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 0, EGL_NONE,
            ];
            let mut config: EGLConfig = std::ptr::null_mut();
            let mut n = 0;
            if eglChooseConfig(display, attrs.as_ptr(), &mut config, 1, &mut n) != EGL_TRUE || n < 1 {
                eglTerminate(display);
                crate::bail!("no suitable EGL configuration ({:#x})", eglGetError());
            }
            let ctx_attrs = [EGL_CONTEXT_CLIENT_VERSION, 3, EGL_NONE];
            let context = eglCreateContext(display, config, EGL_NO_CONTEXT, ctx_attrs.as_ptr());
            if context == EGL_NO_CONTEXT {
                eglTerminate(display);
                crate::bail!("cannot create an OpenGL ES 3 context ({:#x})", eglGetError());
            }
            Ok(Gl {
                display,
                config,
                context,
                surface: None,
                program: 0,
                u_rect: -1,
                u_bgra: -1,
                tex: 0,
                tex_size: (0, 0),
                mipmapped: false,
                pointer_tex: 0,
                pointer: None,
                max_texture: None,
                too_large: None,
            })
        }
    }

    fn attach(&mut self, window: *mut ANativeWindow) -> Result<()> {
        self.detach();
        unsafe {
            let s = eglCreateWindowSurface(self.display, self.config, window, std::ptr::null());
            if s == EGL_NO_SURFACE {
                ANativeWindow_release(window);
                crate::bail!("eglCreateWindowSurface failed ({:#x})", eglGetError());
            }
            if eglMakeCurrent(self.display, s, s, self.context) != EGL_TRUE {
                eglDestroySurface(self.display, s);
                ANativeWindow_release(window);
                crate::bail!("eglMakeCurrent failed ({:#x})", eglGetError());
            }
            self.surface = Some((s, window));
            if self.program == 0 {
                self.program = program()?;
                self.u_rect = glGetUniformLocation(self.program, c"u_rect".as_ptr());
                self.u_bgra = glGetUniformLocation(self.program, c"u_bgra".as_ptr());
                let mut max = 0;
                glGetIntegerv(GL_MAX_TEXTURE_SIZE, &mut max);
                self.max_texture = Some(max);
            }
        }
        Ok(())
    }

    /// Wipes and deletes the screen texture, then lets go of the window.
    fn detach(&mut self) {
        let Some((s, w)) = self.surface.take() else { return };
        unsafe {
            if self.tex != 0 {
                let (tw, th) = self.tex_size;
                let zeros = vec![0u8; tw * th * 4];
                glBindTexture(GL_TEXTURE_2D, self.tex);
                glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
                glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, tw as i32, th as i32, GL_RGBA, GL_UNSIGNED_BYTE, zeros.as_ptr().cast());
                glDeleteTextures(1, &self.tex);
                glFinish();
                self.tex = 0;
                self.tex_size = (0, 0);
            }
            eglMakeCurrent(self.display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
            eglDestroySurface(self.display, s);
            ANativeWindow_release(w);
        }
        // Without a current context the other objects cannot be deleted; they go with it.
        self.program = 0;
        self.pointer_tex = 0;
        self.pointer = None;
        unsafe {
            eglDestroyContext(self.display, self.context);
            let ctx_attrs = [EGL_CONTEXT_CLIENT_VERSION, 3, EGL_NONE];
            self.context = eglCreateContext(self.display, self.config, EGL_NO_CONTEXT, ctx_attrs.as_ptr());
        }
    }

    fn draw(&mut self, screen: &Screen) {
        let Some((surface, _)) = self.surface else { return };
        let (mut sw, mut sh) = (0, 0);
        unsafe {
            eglQuerySurface(self.display, surface, EGL_WIDTH, &mut sw);
            eglQuerySurface(self.display, surface, EGL_HEIGHT, &mut sh);
            glViewport(0, 0, sw, sh);
            glClearColor(0.0, 0.0, 0.0, 1.0);
            glClear(GL_COLOR_BUFFER_BIT);
        }
        let view = {
            let mut v = lock(&screen.view);
            if (v.sw, v.sh) != (sw as f32, sh as f32) {
                v.set_surface(sw as f32, sh as f32);
            }
            v.clone()
        };
        if self.upload(screen, view.scale()) {
            let (l, t, w, h) = view.rect();
            self.quad(self.tex, true, (l, t, w, h), (sw as f32, sh as f32));
            let p = lock(&screen.pointer);
            let (shape, at, drawn) = (p.shape, p.at, p.drawn);
            drop(p);
            if drawn {
                self.draw_pointer(shape, view.to_surface(at.0 + 0.5, at.1 + 0.5), screen.density, (sw as f32, sh as f32));
            }
        }
        unsafe { eglSwapBuffers(self.display, surface) };
    }

    /// Brings the texture up to date with the framebuffer; false if there is nothing to show.
    fn upload(&mut self, screen: &Screen, scale: f32) -> bool {
        let mut fb = screen.fb.ui().unwrap_or_else(PoisonError::into_inner);
        let (w, h) = (fb.w, fb.h);
        if w == 0 || h == 0 || fb.px.len() != w * h * 4 {
            return false;
        }
        let max = self.max_texture.unwrap_or(0).max(0) as usize;
        if w > max || h > max {
            if self.too_large != Some((w, h)) {
                log!("the remote screen ({w}x{h}) is larger than this GPU's textures ({max})");
                self.too_large = Some((w, h));
            }
            return false;
        }
        unsafe {
            if self.tex == 0 || self.tex_size != (w, h) {
                if self.tex == 0 {
                    glGenTextures(1, &mut self.tex);
                }
                glBindTexture(GL_TEXTURE_2D, self.tex);
                glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, w as i32, h as i32, 0, GL_RGBA, GL_UNSIGNED_BYTE, std::ptr::null());
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
                self.tex_size = (w, h);
                self.mipmapped = false;
                fb.dirty = Some(Rect { x: 0, y: 0, w, h });
            }
            glBindTexture(GL_TEXTURE_2D, self.tex);
            let changed = fb.dirty.take();
            if let Some(r) = changed {
                glPixelStorei(GL_UNPACK_ALIGNMENT, 4);
                glPixelStorei(GL_UNPACK_ROW_LENGTH, w as i32);
                let at = fb.px.as_slice()[(r.y * w + r.x) * 4..].as_ptr();
                glTexSubImage2D(GL_TEXTURE_2D, 0, r.x as i32, r.y as i32, r.w as i32, r.h as i32, GL_RGBA, GL_UNSIGNED_BYTE, at.cast());
                glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
            }
            drop(fb);
            // Shrunk, plain bilinear sampling shimmers on text: mipmaps then. Magnified by a
            // whole number, sharp pixels; otherwise bilinear.
            let shrunk = scale < 0.9;
            if shrunk && (changed.is_some() || !self.mipmapped) {
                glGenerateMipmap(GL_TEXTURE_2D);
                self.mipmapped = true;
            }
            let whole = scale >= 1.0 && (scale - scale.round()).abs() < 0.01;
            let (min, mag) = match (shrunk, whole) {
                (true, _) => (GL_LINEAR_MIPMAP_LINEAR, GL_LINEAR),
                (false, true) => (GL_NEAREST, GL_NEAREST),
                (false, false) => (GL_LINEAR, GL_LINEAR),
            };
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, min);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, mag);
        }
        true
    }

    /// Draws texture `tex` into surface rectangle (left, top, width, height).
    fn quad(&self, tex: u32, bgra: bool, (l, t, w, h): (f32, f32, f32, f32), (sw, sh): (f32, f32)) {
        let ndc = |x: f32, y: f32| (x / sw * 2.0 - 1.0, 1.0 - y / sh * 2.0);
        let (x0, y0) = ndc(l, t);
        let (x1, y1) = ndc(l + w, t + h);
        unsafe {
            glUseProgram(self.program);
            glActiveTexture(GL_TEXTURE0);
            glBindTexture(GL_TEXTURE_2D, tex);
            glUniform4f(self.u_rect, x0, y0, x1, y1);
            glUniform1i(self.u_bgra, bgra as i32);
            glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
        }
    }

    fn draw_pointer(&mut self, shape: Cursor, (x, y): (f32, f32), density: f32, surface: (f32, f32)) {
        if self.pointer.as_ref().is_none_or(|(c, _)| *c != shape) {
            self.pointer = sprite_for(shape).map(|s| (shape, s));
            if let Some((_, s)) = &self.pointer {
                unsafe {
                    if self.pointer_tex == 0 {
                        glGenTextures(1, &mut self.pointer_tex);
                    }
                    glBindTexture(GL_TEXTURE_2D, self.pointer_tex);
                    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
                    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, s.w as i32, s.h as i32, 0, GL_RGBA, GL_UNSIGNED_BYTE, s.rgba.as_ptr().cast());
                    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
                    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
                    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
                    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
                }
            }
        }
        let Some((_, s)) = &self.pointer else { return };
        // About 20 dp tall, in whole multiples of the sprite's pixels.
        let k = (density * 20.0 / s.h as f32).round().max(1.0);
        let rect = (x - s.hot.0 as f32 * k, y - s.hot.1 as f32 * k, s.w as f32 * k, s.h as f32 * k);
        unsafe {
            glEnable(GL_BLEND);
            glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
        }
        self.quad(self.pointer_tex, false, rect, surface);
        unsafe { glDisable(GL_BLEND) };
    }
}

impl Drop for Gl {
    fn drop(&mut self) {
        self.detach();
        unsafe {
            eglDestroyContext(self.display, self.context);
            eglTerminate(self.display);
        }
    }
}

fn shader(kind: u32, src: &str) -> Result<u32> {
    unsafe {
        let s = glCreateShader(kind);
        let p = src.as_ptr().cast::<std::ffi::c_char>();
        glShaderSource(s, 1, &p, std::ptr::null());
        glCompileShader(s);
        let mut ok = 0;
        glGetShaderiv(s, GL_COMPILE_STATUS, &mut ok);
        if ok == 0 {
            let mut buf = [0u8; 512];
            let mut n = 0;
            glGetShaderInfoLog(s, buf.len() as i32, &mut n, buf.as_mut_ptr().cast());
            glDeleteShader(s);
            crate::bail!("shader: {}", String::from_utf8_lossy(&buf[..n.clamp(0, 512) as usize]));
        }
        Ok(s)
    }
}

fn program() -> Result<u32> {
    let (v, f) = (shader(GL_VERTEX_SHADER, VERTEX)?, shader(GL_FRAGMENT_SHADER, FRAGMENT)?);
    unsafe {
        let p = glCreateProgram();
        glAttachShader(p, v);
        glAttachShader(p, f);
        glLinkProgram(p);
        glDeleteShader(v);
        glDeleteShader(f);
        let mut ok = 0;
        glGetProgramiv(p, GL_LINK_STATUS, &mut ok);
        if ok == 0 {
            glDeleteProgram(p);
            crate::bail!("cannot link the shaders");
        }
        Ok(p)
    }
}

/// An `ANativeWindow` for a Java `Surface`.
pub fn window_from_surface(env: *mut c_void, surface: *mut c_void) -> *mut ANativeWindow {
    unsafe { ANativeWindow_fromSurface(env, surface) }
}
