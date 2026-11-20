//! Page-locked buffers for screen pixels.
//!
//! The stock RDP client persists bitmap-cache tiles to disk. We never write pixels to disk
//! ourselves, and the large pixel buffers are additionally `VirtualLock`ed so the memory
//! manager does not page them out to pagefile.sys. Buffers are wiped before being freed.

use std::sync::atomic::{AtomicBool, Ordering};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree, VirtualLock, VirtualUnlock};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessWorkingSetSize, SetProcessWorkingSetSize};

static WARNED: AtomicBool = AtomicBool::new(false);

pub struct LockedBuf {
    ptr: *mut u8,
    len: usize,
    locked: bool,
}

unsafe impl Send for LockedBuf {}
unsafe impl Sync for LockedBuf {}

/// Best effort: pin `len` bytes at `ptr` in RAM, growing the working-set quota if needed.
pub fn lock_pages(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    unsafe {
        if VirtualLock(ptr.cast(), len) != 0 {
            return true;
        }
        let (mut min, mut max) = (0usize, 0usize);
        let proc = GetCurrentProcess();
        if GetProcessWorkingSetSize(proc, &mut min, &mut max) != 0 {
            let extra = len + (1 << 20);
            SetProcessWorkingSetSize(proc, min + extra, max.max(min + extra) + extra);
        }
        if VirtualLock(ptr.cast(), len) != 0 {
            return true;
        }
    }
    if !WARNED.swap(true, Ordering::Relaxed) {
        crate::log!("warning: could not lock frame buffer in RAM; it may be paged to disk");
    }
    false
}

impl LockedBuf {
    pub fn new(len: usize) -> LockedBuf {
        if len == 0 {
            return LockedBuf { ptr: std::ptr::NonNull::dangling().as_ptr(), len: 0, locked: false };
        }
        let ptr = unsafe { VirtualAlloc(std::ptr::null(), len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) } as *mut u8;
        assert!(!ptr.is_null(), "VirtualAlloc of {len} bytes failed");
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
                VirtualUnlock(self.ptr.cast(), self.len);
            }
            VirtualFree(self.ptr.cast(), 0, MEM_RELEASE);
        }
    }
}
