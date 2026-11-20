//! Lossless back end for tile data: LZ77+Huffman ("XPRESS Huffman", [MS-XCA] section 2).
//!
//! Windows uses the OS implementation in cabinet.dll. Other platforms use the pure-Rust
//! implementation in `xpress.rs`, which produces and accepts the same bit stream.

#[cfg(windows)]
pub use native::{Compressor, Decompressor};

#[cfg(not(windows))]
pub use portable::{Compressor, Decompressor};

#[cfg(windows)]
mod native {
    use crate::bail;
    use crate::util::{Error, Result};
    use windows_sys::Win32::Storage::Compression::*;

    pub struct Compressor(COMPRESSOR_HANDLE);
    unsafe impl Send for Compressor {}

    impl Compressor {
        pub fn new() -> Result<Self> {
            let mut h = std::ptr::null_mut();
            if unsafe { CreateCompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, std::ptr::null(), &mut h) } == 0 {
                return Err(Error::last_os("CreateCompressor"));
            }
            Ok(Compressor(h))
        }

        /// Compresses `src` into `dst`; returns false if the output would not be smaller.
        pub fn compress(&mut self, src: &[u8], dst: &mut Vec<u8>) -> bool {
            dst.clear();
            dst.reserve(src.len());
            let mut n = 0usize;
            let ok = unsafe {
                Compress(self.0, src.as_ptr().cast(), src.len(), dst.as_mut_ptr().cast(), dst.capacity(), &mut n)
            };
            if ok == 0 || n == 0 || n >= src.len() {
                return false;
            }
            unsafe { dst.set_len(n) };
            true
        }
    }

    impl Drop for Compressor {
        fn drop(&mut self) {
            unsafe { CloseCompressor(self.0) };
        }
    }

    pub struct Decompressor(DECOMPRESSOR_HANDLE);
    unsafe impl Send for Decompressor {}

    impl Decompressor {
        pub fn new() -> Result<Self> {
            let mut h = std::ptr::null_mut();
            if unsafe { CreateDecompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, std::ptr::null(), &mut h) } == 0 {
                return Err(Error::last_os("CreateDecompressor"));
            }
            Ok(Decompressor(h))
        }

        /// Decompresses `src` into exactly `dst.len()` bytes.
        pub fn decompress(&mut self, src: &[u8], dst: &mut [u8]) -> Result<()> {
            let mut n = 0usize;
            let ok = unsafe { Decompress(self.0, src.as_ptr().cast(), src.len(), dst.as_mut_ptr().cast(), dst.len(), &mut n) };
            if ok == 0 || n != dst.len() {
                bail!("corrupt tile data");
            }
            Ok(())
        }
    }

    impl Drop for Decompressor {
        fn drop(&mut self) {
            unsafe { CloseDecompressor(self.0) };
        }
    }
}

#[cfg(not(windows))]
mod portable {
    use crate::bail;
    use crate::util::Result;

    pub struct Compressor;

    impl Compressor {
        pub fn new() -> Result<Self> {
            Ok(Compressor)
        }

        /// Placeholder until the portable XPRESS encoder lands: tiles go out uncompressed.
        pub fn compress(&mut self, _src: &[u8], _dst: &mut Vec<u8>) -> bool {
            false
        }
    }

    pub struct Decompressor;

    impl Decompressor {
        pub fn new() -> Result<Self> {
            Ok(Decompressor)
        }

        pub fn decompress(&mut self, _src: &[u8], _dst: &mut [u8]) -> Result<()> {
            bail!("XPRESS decoding is not available on this platform yet")
        }
    }
}

