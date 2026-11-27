//! The EGL, OpenGL ES 3.0 and native-window calls the renderer makes, declared by hand from the
//! NDK's headers (EGL/egl.h, GLES3/gl3.h, android/native_window*.h).

#![allow(non_snake_case, clippy::upper_case_acronyms)]

use std::ffi::{c_char, c_void};

pub type EGLDisplay = *mut c_void;
pub type EGLConfig = *mut c_void;
pub type EGLContext = *mut c_void;
pub type EGLSurface = *mut c_void;
pub type ANativeWindow = c_void;

pub const EGL_NO_DISPLAY: EGLDisplay = std::ptr::null_mut();
pub const EGL_NO_CONTEXT: EGLContext = std::ptr::null_mut();
pub const EGL_NO_SURFACE: EGLSurface = std::ptr::null_mut();
pub const EGL_DEFAULT_DISPLAY: *mut c_void = std::ptr::null_mut();
pub const EGL_TRUE: u32 = 1;
pub const EGL_NONE: i32 = 0x3038;
pub const EGL_RED_SIZE: i32 = 0x3024;
pub const EGL_GREEN_SIZE: i32 = 0x3023;
pub const EGL_BLUE_SIZE: i32 = 0x3022;
pub const EGL_ALPHA_SIZE: i32 = 0x3021;
pub const EGL_SURFACE_TYPE: i32 = 0x3033;
pub const EGL_WINDOW_BIT: i32 = 0x0004;
pub const EGL_RENDERABLE_TYPE: i32 = 0x3040;
pub const EGL_OPENGL_ES3_BIT: i32 = 0x0040;
pub const EGL_CONTEXT_CLIENT_VERSION: i32 = 0x3098;
pub const EGL_WIDTH: i32 = 0x3057;
pub const EGL_HEIGHT: i32 = 0x3056;

#[link(name = "EGL")]
unsafe extern "C" {
    pub fn eglGetDisplay(id: *mut c_void) -> EGLDisplay;
    pub fn eglInitialize(d: EGLDisplay, major: *mut i32, minor: *mut i32) -> u32;
    pub fn eglTerminate(d: EGLDisplay) -> u32;
    pub fn eglChooseConfig(d: EGLDisplay, attrs: *const i32, configs: *mut EGLConfig, size: i32, n: *mut i32) -> u32;
    pub fn eglCreateContext(d: EGLDisplay, c: EGLConfig, share: EGLContext, attrs: *const i32) -> EGLContext;
    pub fn eglDestroyContext(d: EGLDisplay, ctx: EGLContext) -> u32;
    pub fn eglCreateWindowSurface(d: EGLDisplay, c: EGLConfig, win: *mut ANativeWindow, attrs: *const i32) -> EGLSurface;
    pub fn eglDestroySurface(d: EGLDisplay, s: EGLSurface) -> u32;
    pub fn eglMakeCurrent(d: EGLDisplay, draw: EGLSurface, read: EGLSurface, ctx: EGLContext) -> u32;
    pub fn eglSwapBuffers(d: EGLDisplay, s: EGLSurface) -> u32;
    pub fn eglQuerySurface(d: EGLDisplay, s: EGLSurface, attr: i32, value: *mut i32) -> u32;
    pub fn eglGetError() -> i32;
}

#[link(name = "android")]
unsafe extern "C" {
    pub fn ANativeWindow_fromSurface(env: *mut c_void, surface: *mut c_void) -> *mut ANativeWindow;
    pub fn ANativeWindow_release(w: *mut ANativeWindow);
}

pub type GLuint = u32;
pub type GLint = i32;
pub type GLenum = u32;

pub const GL_TEXTURE_2D: GLenum = 0x0DE1;
pub const GL_TEXTURE0: GLenum = 0x84C0;
pub const GL_TEXTURE_MIN_FILTER: GLenum = 0x2801;
pub const GL_TEXTURE_MAG_FILTER: GLenum = 0x2800;
pub const GL_TEXTURE_WRAP_S: GLenum = 0x2802;
pub const GL_TEXTURE_WRAP_T: GLenum = 0x2803;
pub const GL_CLAMP_TO_EDGE: GLint = 0x812F;
pub const GL_LINEAR: GLint = 0x2601;
pub const GL_NEAREST: GLint = 0x2600;
pub const GL_LINEAR_MIPMAP_LINEAR: GLint = 0x2703;
pub const GL_RGBA: GLenum = 0x1908;
pub const GL_RGBA8: GLint = 0x8058;
pub const GL_UNSIGNED_BYTE: GLenum = 0x1401;
pub const GL_UNPACK_ROW_LENGTH: GLenum = 0x0CF2;
pub const GL_UNPACK_ALIGNMENT: GLenum = 0x0CF5;
pub const GL_MAX_TEXTURE_SIZE: GLenum = 0x0D33;
pub const GL_COLOR_BUFFER_BIT: GLenum = 0x4000;
pub const GL_TRIANGLE_STRIP: GLenum = 0x0005;
pub const GL_VERTEX_SHADER: GLenum = 0x8B31;
pub const GL_FRAGMENT_SHADER: GLenum = 0x8B30;
pub const GL_COMPILE_STATUS: GLenum = 0x8B81;
pub const GL_LINK_STATUS: GLenum = 0x8B82;
pub const GL_BLEND: GLenum = 0x0BE2;
pub const GL_SRC_ALPHA: GLenum = 0x0302;
pub const GL_ONE_MINUS_SRC_ALPHA: GLenum = 0x0303;

#[link(name = "GLESv3")]
unsafe extern "C" {
    pub fn glGetIntegerv(name: GLenum, out: *mut GLint);
    pub fn glGenTextures(n: i32, out: *mut GLuint);
    pub fn glDeleteTextures(n: i32, t: *const GLuint);
    pub fn glBindTexture(target: GLenum, t: GLuint);
    pub fn glActiveTexture(unit: GLenum);
    pub fn glTexParameteri(target: GLenum, name: GLenum, v: GLint);
    pub fn glTexImage2D(target: GLenum, level: GLint, internal: GLint, w: i32, h: i32, border: GLint, format: GLenum, ty: GLenum, data: *const c_void);
    pub fn glTexSubImage2D(target: GLenum, level: GLint, x: GLint, y: GLint, w: i32, h: i32, format: GLenum, ty: GLenum, data: *const c_void);
    pub fn glGenerateMipmap(target: GLenum);
    pub fn glPixelStorei(name: GLenum, v: GLint);
    pub fn glCreateShader(ty: GLenum) -> GLuint;
    pub fn glShaderSource(s: GLuint, n: i32, src: *const *const c_char, len: *const GLint);
    pub fn glCompileShader(s: GLuint);
    pub fn glGetShaderiv(s: GLuint, name: GLenum, out: *mut GLint);
    pub fn glGetShaderInfoLog(s: GLuint, size: i32, len: *mut i32, out: *mut c_char);
    pub fn glDeleteShader(s: GLuint);
    pub fn glCreateProgram() -> GLuint;
    pub fn glAttachShader(p: GLuint, s: GLuint);
    pub fn glLinkProgram(p: GLuint);
    pub fn glGetProgramiv(p: GLuint, name: GLenum, out: *mut GLint);
    pub fn glUseProgram(p: GLuint);
    pub fn glDeleteProgram(p: GLuint);
    pub fn glGetUniformLocation(p: GLuint, name: *const c_char) -> GLint;
    pub fn glUniform4f(loc: GLint, a: f32, b: f32, c: f32, d: f32);
    pub fn glUniform1i(loc: GLint, v: GLint);
    pub fn glViewport(x: GLint, y: GLint, w: i32, h: i32);
    pub fn glClearColor(r: f32, g: f32, b: f32, a: f32);
    pub fn glClear(mask: GLenum);
    pub fn glDrawArrays(mode: GLenum, first: GLint, count: i32);
    pub fn glEnable(cap: GLenum);
    pub fn glDisable(cap: GLenum);
    pub fn glBlendFunc(s: GLenum, d: GLenum);
    pub fn glFinish();
}
