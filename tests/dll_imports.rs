//! The built safe-rdp.exe never takes a DLL from its own folder (build.rs, main()): what it
//! imports at start-up is a KnownDLL, which Windows maps together with its imports from its own
//! copies; everything else is delay-loaded, after main() has limited DLL loading to System32.
//! This reads the executable's import tables and checks that on this Windows: a new import that
//! is not a KnownDLL would be looked for beside the executable, together with its own imports,
//! before main() runs.
#![cfg(all(windows, target_env = "msvc"))]

use std::ffi::c_void;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW};

const EXE: &str = env!("CARGO_BIN_EXE_safe-rdp");

/// The parts of a PE32+ image this test reads.
struct Image {
    data: Vec<u8>,
    /// (virtual address, size, file offset) of each section.
    sections: Vec<(usize, usize, usize)>,
    dirs: usize,
}

impl Image {
    fn read(path: &str) -> Image {
        let data = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let u16_at = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]) as usize;
        let pe = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
        assert_eq!(&data[pe..pe + 4], b"PE\0\0");
        let opt = pe + 24;
        assert_eq!(u16_at(opt), 0x20b, "not a PE32+ image");
        let first = opt + u16_at(pe + 20);
        let mut img = Image { data: Vec::new(), sections: Vec::new(), dirs: opt + 112 };
        for i in 0..u16_at(pe + 6) {
            let s = first + 40 * i;
            let at = |k: usize| u32::from_le_bytes(data[s + k..s + k + 4].try_into().unwrap()) as usize;
            img.sections.push((at(12), at(8).max(at(16)), at(20)));
        }
        img.data = data;
        img
    }

    fn u16(&self, o: usize) -> u16 {
        u16::from_le_bytes(self.data[o..o + 2].try_into().unwrap())
    }

    fn u32(&self, o: usize) -> usize {
        u32::from_le_bytes(self.data[o..o + 4].try_into().unwrap()) as usize
    }

    fn u64(&self, o: usize) -> u64 {
        u64::from_le_bytes(self.data[o..o + 8].try_into().unwrap())
    }

    /// File offset of a relative virtual address.
    fn at(&self, rva: usize) -> usize {
        let &(va, _, raw) = self.sections.iter().find(|(va, size, _)| (*va..va + size).contains(&rva)).expect("RVA outside every section");
        rva - va + raw
    }

    fn cstr(&self, rva: usize) -> String {
        let o = self.at(rva);
        let end = self.data[o..].iter().position(|&b| b == 0).expect("unterminated name");
        String::from_utf8(self.data[o..o + end].to_vec()).expect("name not ASCII")
    }

    /// (RVA, size) of data directory `i`.
    fn dir(&self, i: usize) -> (usize, usize) {
        (self.u32(self.dirs + 8 * i), self.u32(self.dirs + 8 * i + 4))
    }

    /// The DLLs imported at start-up.
    fn imports(&self) -> Vec<String> {
        let (rva, _) = self.dir(1);
        let mut out = Vec::new();
        let mut o = self.at(rva);
        while self.u32(o + 12) != 0 {
            out.push(self.cstr(self.u32(o + 12)));
            o += 20;
        }
        out
    }

    /// The delay-loaded DLLs, each with its functions: Ok(name) or Err(ordinal).
    fn delay_imports(&self) -> Vec<(String, Vec<Result<String, u16>>)> {
        let (rva, _) = self.dir(13);
        let mut out = Vec::new();
        if rva == 0 {
            return out;
        }
        let mut o = self.at(rva);
        while self.u32(o + 4) != 0 {
            assert_eq!(self.u32(o) & 1, 1, "delay-load descriptor without RVAs");
            let mut funcs = Vec::new();
            let mut t = self.at(self.u32(o + 16));
            loop {
                let e = self.u64(t);
                if e == 0 {
                    break;
                }
                funcs.push(if e >> 63 == 1 { Err(e as u16) } else { Ok(self.cstr(e as usize + 2)) });
                t += 8;
            }
            out.push((self.cstr(self.u32(o + 4)), funcs));
            o += 32;
        }
        out
    }

    /// DependentLoadFlags from the load configuration directory.
    fn dependent_load_flags(&self) -> Option<u16> {
        let (rva, _) = self.dir(10);
        if rva == 0 {
            return None;
        }
        let o = self.at(rva);
        (self.u32(o) >= 0x50).then(|| self.u16(o + 0x4e))
    }
}

#[repr(C)]
struct UnicodeString {
    len: u16,
    max: u16,
    buf: *const u16,
}

#[repr(C)]
struct ObjectAttributes {
    len: u32,
    root: HANDLE,
    name: *const UnicodeString,
    attributes: u32,
    security: *const c_void,
    qos: *const c_void,
}

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn NtOpenDirectoryObject(dir: *mut HANDLE, access: u32, attributes: *const ObjectAttributes) -> i32;
    fn NtQueryDirectoryObject(dir: HANDLE, buf: *mut c_void, len: u32, single: u8, restart: u8, context: *mut u32, returned: *mut u32) -> i32;
    fn NtClose(h: HANDLE) -> i32;
}

/// The KnownDLLs of this boot, lowercase: the `\KnownDlls` object directory, which also holds
/// what the registry's KnownDLLs import.
fn known_dlls() -> Vec<String> {
    let path: Vec<u16> = r"\KnownDlls".encode_utf16().collect();
    let name = UnicodeString { len: (path.len() * 2) as u16, max: (path.len() * 2) as u16, buf: path.as_ptr() };
    let attributes = ObjectAttributes {
        len: size_of::<ObjectAttributes>() as u32,
        root: std::ptr::null_mut(),
        name: &name,
        attributes: 0x40, // OBJ_CASE_INSENSITIVE
        security: std::ptr::null(),
        qos: std::ptr::null(),
    };
    let mut dir: HANDLE = std::ptr::null_mut();
    // DIRECTORY_QUERY
    let status = unsafe { NtOpenDirectoryObject(&mut dir, 1, &attributes) };
    assert_eq!(status, 0, "NtOpenDirectoryObject(\\KnownDlls): {status:#x}");
    let mut names = Vec::new();
    let mut buf = vec![0u64; 512];
    let (mut context, mut returned) = (0u32, 0u32);
    let mut restart = 1;
    // One entry (name, type name) per call, until STATUS_NO_MORE_ENTRIES.
    while unsafe { NtQueryDirectoryObject(dir, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, 1, restart, &mut context, &mut returned) } == 0 {
        restart = 0;
        let entry = unsafe { &*buf.as_ptr().cast::<UnicodeString>() };
        let s = unsafe { std::slice::from_raw_parts(entry.buf, entry.len as usize / 2) };
        names.push(String::from_utf16_lossy(s).to_ascii_lowercase());
    }
    unsafe { NtClose(dir) };
    assert!(names.iter().any(|n| n == "kernel32.dll"), "\\KnownDlls listing looks wrong: {names:?}");
    names
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Loads `dll` from System32 only; None if it is not there.
fn load_system32(dll: &str) -> Option<*mut c_void> {
    let h = unsafe { LoadLibraryExW(wide(dll).as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    (!h.is_null()).then_some(h)
}

fn file_name(module: *mut c_void) -> String {
    let mut buf = [0u16; 1024];
    let n = unsafe { GetModuleFileNameW(module, buf.as_mut_ptr(), buf.len() as u32) } as usize;
    let path = String::from_utf16_lossy(&buf[..n]);
    path.rsplit('\\').next().unwrap_or_default().to_ascii_lowercase()
}

#[test]
fn imports_at_start_up_are_known_dlls() {
    let img = Image::read(EXE);
    let flags = img.dependent_load_flags().expect("no DependentLoadFlags in the load configuration");
    assert_eq!(flags & 0x800, 0x800, "DependentLoadFlags {flags:#x} lack LOAD_LIBRARY_SEARCH_SYSTEM32 (build.rs)");
    let known = known_dlls();
    let mut unsafe_imports = Vec::new();
    for dll in img.imports() {
        let lower = dll.to_ascii_lowercase();
        // An API set is resolved by Windows to the DLL that implements it: that one counts.
        let actual = if lower.starts_with("api-ms-") || lower.starts_with("ext-ms-") {
            file_name(load_system32(&dll).unwrap_or_else(|| panic!("API set {dll} does not resolve")))
        } else {
            lower
        };
        if !known.contains(&actual) {
            unsafe_imports.push(dll);
        }
    }
    assert!(
        unsafe_imports.is_empty(),
        "safe-rdp.exe imports {unsafe_imports:?} at start-up, before main() can keep DLLs out of its own folder, and \
         these are not KnownDLLs: add them to DELAY_LOADED in build.rs"
    );
}

#[test]
fn delay_loaded_functions_resolve_from_system32() {
    let img = Image::read(EXE);
    let delayed = img.delay_imports();
    let names: Vec<String> = delayed.iter().map(|(dll, _)| dll.to_ascii_lowercase()).collect();
    // The two that brought DLLs from beside the executable at start-up (sspicli, umpdc).
    for dll in ["wtsapi32.dll", "dxgi.dll"] {
        assert!(names.iter().any(|n| n == dll), "{dll} is not delay-loaded (build.rs): {names:?}");
    }
    // What the delay-load helper does on the first call: a missing function would end the
    // process right there.
    let mut missing = Vec::new();
    for (dll, funcs) in &delayed {
        let Some(module) = load_system32(dll) else {
            missing.push(format!("{dll} (not in System32)"));
            continue;
        };
        for f in funcs {
            let proc = match f {
                Ok(name) => {
                    let c = std::ffi::CString::new(name.as_str()).unwrap();
                    unsafe { GetProcAddress(module, c.as_ptr().cast()) }
                }
                Err(ordinal) => unsafe { GetProcAddress(module, *ordinal as usize as *const u8) },
            };
            if proc.is_none() {
                missing.push(format!("{dll}!{f:?}"));
            }
        }
    }
    assert!(missing.is_empty(), "delay-loaded imports this Windows does not have: {missing:?}");
}
