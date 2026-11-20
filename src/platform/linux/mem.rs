//! Page-locked buffers for screen pixels (Linux).
//!
//! Anonymous mappings that are `mlock`ed (kept out of swap when RLIMIT_MEMLOCK allows),
//! excluded from core dumps with MADV_DONTDUMP, and wiped before being unmapped.

use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicBool, Ordering};

unsafe extern "C" {
    fn mmap(addr: *mut c_void, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> c_int;
    fn mlock(addr: *const c_void, len: usize) -> c_int;
    fn munlock(addr: *const c_void, len: usize) -> c_int;
    fn madvise(addr: *mut c_void, len: usize, advice: c_int) -> c_int;
}

const PROT_READ: c_int = 1;
const PROT_WRITE: c_int = 2;
const MAP_PRIVATE: c_int = 2;
const MAP_ANONYMOUS: c_int = 0x20;
const MADV_DONTDUMP: c_int = 16;

static WARNED: AtomicBool = AtomicBool::new(false);

/// Best effort: pin `len` bytes at `ptr` in RAM.
pub fn lock_pages(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    if unsafe { mlock(ptr.cast(), len) } == 0 {
        return true;
    }
    if !WARNED.swap(true, Ordering::Relaxed) {
        crate::log!("warning: could not mlock frame buffer (raise RLIMIT_MEMLOCK); it may be swapped out");
    }
    false
}

pub struct LockedBuf {
    ptr: *mut u8,
    len: usize,
    locked: bool,
}

unsafe impl Send for LockedBuf {}
unsafe impl Sync for LockedBuf {}

impl LockedBuf {
    pub fn new(len: usize) -> LockedBuf {
        if len == 0 {
            return LockedBuf { ptr: std::ptr::NonNull::dangling().as_ptr(), len: 0, locked: false };
        }
        let p = unsafe { mmap(std::ptr::null_mut(), len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
        assert!(p as isize != -1 && !p.is_null(), "mmap of {len} bytes failed");
        unsafe { madvise(p, len, MADV_DONTDUMP) };
        let ptr = p as *mut u8;
        let locked = lock_pages(ptr, len);
        LockedBuf { ptr, len, locked }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for LockedBuf {
    fn drop(&mut self) {
        if self.len == 0 {
            return;
        }
        crate::util::wipe(self.as_mut_slice());
        unsafe {
            if self.locked {
                munlock(self.ptr.cast(), self.len);
            }
            munmap(self.ptr.cast(), self.len);
        }
    }
}
