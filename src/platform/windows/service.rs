//! Windows service mode.
//!
//! A LocalSystem service (session 0) supervises an *agent*: the same executable started with
//! a SYSTEM token inside the active console session. Running as SYSTEM in the user's session
//! is what allows the agent to follow the input desktop onto the lock screen, the sign-in
//! screen and UAC prompts, and to drive elevated windows. The agent is tied to the service
//! with a kill-on-close job object and is restarted whenever the console session changes.
//! To stop it, the service closes the agent's stdin: the agent then releases the keys and
//! buttons a viewer holds and ends privacy mode, and is killed only if it takes too long.
//!
//! Ctrl+Alt+Del cannot be synthesised with SendInput; the agent signals a SYSTEM-only event
//! and the service calls SendSAS (requires the SoftwareSASGeneration policy, `--enable-sas`).

use super::keystore;
use crate::util::{Error, Result, wide};
use crate::{bail, log};
use std::ffi::c_void;
use std::io::PipeWriter;
use std::os::windows::io::AsRawHandle;
use std::ptr::{null, null_mut};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authentication::Identity::SendSAS;
use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::JobObjects::*;
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, REG_DWORD, RegSetKeyValueW};
use windows_sys::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
use windows_sys::Win32::System::Services::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

pub const SERVICE_NAME: &str = "SafeRdpHost";
const DISPLAY_NAME: &str = "safe-rdp host";
const SAS_EVENT: &str = r"Global\SafeRdpSas";
const FIREWALL_RULE: &str = "safe-rdp";
/// How long a stopping agent may take to end its session before it is killed.
const AGENT_STOP_WAIT: Duration = Duration::from_secs(5);

static AGENT_ARGS: OnceLock<Vec<String>> = OnceLock::new();
static STATUS: AtomicUsize = AtomicUsize::new(0);
static STOP_EVENT: AtomicUsize = AtomicUsize::new(0);
static SESSION_EVENT: AtomicUsize = AtomicUsize::new(0);

/// Called by the agent: asks the service to generate Ctrl+Alt+Del.
pub fn request_sas() -> bool {
    unsafe {
        let h = OpenEventW(EVENT_MODIFY_STATE, 0, wide(SAS_EVENT).as_ptr());
        if h.is_null() {
            return false;
        }
        SetEvent(h);
        CloseHandle(h);
        true
    }
}

/// Quotes one argument the way CommandLineToArgvW and the MSVC/Rust argument parsers undo it:
/// backslashes are literal except in front of a quote, where they are escapes.
fn quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\x0b', '"']) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', 2 * backslashes + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    // The closing quote must not be escaped by trailing backslashes.
    out.extend(std::iter::repeat_n('\\', 2 * backslashes));
    out.push('"');
    out
}

/// Splits a command line the way Windows does for a new process.
fn split_command_line(cmd: &str) -> Vec<String> {
    let w = wide(cmd);
    let mut n = 0;
    unsafe {
        let argv = CommandLineToArgvW(w.as_ptr(), &mut n);
        if argv.is_null() {
            return Vec::new();
        }
        let args = (0..n.max(0) as usize)
            .map(|i| {
                let p = *argv.add(i);
                let len = (0..).take_while(|&j| *p.add(j) != 0).count();
                String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
            })
            .collect();
        LocalFree(argv as HLOCAL);
        args
    }
}

/// Joins a program and its arguments into a command line that Windows splits back into
/// exactly these arguments, or fails.
fn command_line(parts: &[String]) -> Result<String> {
    let cmd = parts.iter().map(|p| quote(p)).collect::<Vec<_>>().join(" ");
    if split_command_line(&cmd) != parts {
        bail!("these arguments cannot be passed on a command line unchanged: {parts:?}");
    }
    Ok(cmd)
}

struct Sc(SC_HANDLE);

impl Drop for Sc {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0) };
    }
}

fn open_scm() -> Result<Sc> {
    let h = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_ALL_ACCESS) };
    if h.is_null() {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
            bail!("administrator rights required: run this from an elevated terminal");
        }
        bail!("OpenSCManager failed: {e}");
    }
    Ok(Sc(h))
}

fn open_service(scm: &Sc) -> Option<Sc> {
    let h = unsafe { OpenServiceW(scm.0, wide(SERVICE_NAME).as_ptr(), SERVICE_ALL_ACCESS) };
    (!h.is_null()).then_some(Sc(h))
}

fn stop_and_wait(svc: &Sc) {
    unsafe {
        let mut st: SERVICE_STATUS = std::mem::zeroed();
        ControlService(svc.0, SERVICE_CONTROL_STOP, &mut st);
        let t = Instant::now();
        while QueryServiceStatus(svc.0, &mut st) != 0 && st.dwCurrentState != SERVICE_STOPPED && t.elapsed() < Duration::from_secs(20) {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

fn netsh(args: &[&str]) -> bool {
    std::process::Command::new("netsh")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

pub fn install(host_args: &[String], port: u16, enable_sas: bool) -> Result<()> {
    let scm = open_scm()?;
    let key = keystore::load_user_key().map_err(|e| format!("{e}\nThe service uses the key stored for the installing user."))?;

    if let Some(svc) = open_service(&scm) {
        log!("stopping the existing service...");
        stop_and_wait(&svc);
    }

    let key_path = keystore::save_service_key(&key)?;
    log!("service key stored in {} (SYSTEM/Administrators only)", key_path.display());

    // Run from Program Files so that only administrators can replace the SYSTEM binary.
    let pf = std::env::var_os("ProgramFiles").ok_or("%ProgramFiles% is not set")?;
    let dir = std::path::Path::new(&pf).join("safe-rdp");
    std::fs::create_dir_all(&dir)?;
    let exe = dir.join("safe-rdp.exe");
    let me = std::env::current_exe()?;
    if !same_file(&me, &exe) {
        std::fs::copy(&me, &exe).map_err(|e| format!("cannot copy to {}: {e}", exe.display()))?;
    }
    keystore::restrict_to_admins(&dir).ok();
    let exe_str = exe.to_string_lossy().to_string();

    let mut parts = vec![exe_str.clone(), "service".to_string(), "run".to_string()];
    parts.extend(host_args.iter().cloned());
    let wcmd = wide(&command_line(&parts)?);
    unsafe {
        let svc = match open_service(&scm) {
            Some(svc) => {
                if ChangeServiceConfigW(svc.0, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, wcmd.as_ptr(), null(), null_mut(), null(), null(), null(), wide(DISPLAY_NAME).as_ptr()) == 0 {
                    return Err(Error::last_os("ChangeServiceConfigW"));
                }
                svc
            }
            None => {
                let h = CreateServiceW(
                    scm.0,
                    wide(SERVICE_NAME).as_ptr(),
                    wide(DISPLAY_NAME).as_ptr(),
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    wcmd.as_ptr(),
                    null(),
                    null_mut(),
                    null(),
                    null(),
                    null(),
                );
                if h.is_null() {
                    return Err(Error::last_os("CreateServiceW"));
                }
                Sc(h)
            }
        };
        let mut desc = wide("Remote desktop host for Tailscale peers (safe-rdp).");
        let d = SERVICE_DESCRIPTIONW { lpDescription: desc.as_mut_ptr() };
        ChangeServiceConfig2W(svc.0, SERVICE_CONFIG_DESCRIPTION, &d as *const _ as *const c_void);
        let mut actions = [SC_ACTION { Type: SC_ACTION_RESTART, Delay: 5000 }; 3];
        let fa = SERVICE_FAILURE_ACTIONSW { dwResetPeriod: 86400, lpRebootMsg: null_mut(), lpCommand: null_mut(), cActions: 3, lpsaActions: actions.as_mut_ptr() };
        ChangeServiceConfig2W(svc.0, SERVICE_CONFIG_FAILURE_ACTIONS, &fa as *const _ as *const c_void);

        netsh(&["advfirewall", "firewall", "delete", "rule", &format!("name={FIREWALL_RULE}")]);
        let ok = netsh(&[
            "advfirewall", "firewall", "add", "rule",
            &format!("name={FIREWALL_RULE}"),
            "dir=in", "action=allow", "protocol=TCP",
            &format!("localport={port}"),
            &format!("program={exe_str}"),
            "remoteip=100.64.0.0/10,fd7a:115c:a1e0::/48",
            "profile=any", "enable=yes",
        ]);
        if ok {
            log!("firewall: allowed TCP {port} from Tailscale addresses only");
        } else {
            log!("warning: could not add the firewall rule; allow TCP {port} inbound manually");
        }

        if enable_sas {
            let one = 1u32;
            let r = RegSetKeyValueW(
                HKEY_LOCAL_MACHINE,
                wide(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").as_ptr(),
                wide("SoftwareSASGeneration").as_ptr(),
                REG_DWORD,
                &one as *const u32 as *const c_void,
                4,
            );
            if r == 0 {
                log!("policy: services may now generate Ctrl+Alt+Del (SoftwareSASGeneration=1)");
            } else {
                log!("warning: could not set SoftwareSASGeneration (error {r})");
            }
        }

        if StartServiceW(svc.0, 0, null()) == 0 {
            return Err(Error::last_os("StartServiceW"));
        }
    }
    log!("service '{SERVICE_NAME}' installed and started; logs: {}", keystore::service_dir().display());
    Ok(())
}

fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

pub fn uninstall() -> Result<()> {
    let scm = open_scm()?;
    match open_service(&scm) {
        Some(svc) => {
            stop_and_wait(&svc);
            if unsafe { DeleteService(svc.0) } == 0 {
                return Err(Error::last_os("DeleteService"));
            }
            log!("service removed");
        }
        None => log!("service is not installed"),
    }
    netsh(&["advfirewall", "firewall", "delete", "rule", &format!("name={FIREWALL_RULE}")]);
    let key = keystore::service_key_path();
    if key.exists() {
        std::fs::remove_file(&key)?;
        log!("removed {}", key.display());
    }
    log!("note: the SoftwareSASGeneration policy (if you enabled it) is left unchanged");
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Runtime (inside the service process)

pub fn run_dispatcher(agent_args: Vec<String>) -> Result<()> {
    let _ = AGENT_ARGS.set(agent_args);
    let mut name = wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW { lpServiceName: name.as_mut_ptr(), lpServiceProc: Some(service_main) },
        SERVICE_TABLE_ENTRYW { lpServiceName: null_mut(), lpServiceProc: None },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        bail!("`service run` must be started by the Service Control Manager (use `service install`)");
    }
    Ok(())
}

fn set_state(state: u32, exit_code: u32) {
    let st = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE
        } else {
            0
        },
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: if state == SERVICE_STOP_PENDING { 10_000 } else { 0 },
    };
    unsafe { SetServiceStatus(STATUS.load(Ordering::SeqCst) as SERVICE_STATUS_HANDLE, &st) };
}

unsafe extern "system" fn handler(control: u32, _event: u32, _data: *mut c_void, _ctx: *mut c_void) -> u32 {
    unsafe {
        match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                set_state(SERVICE_STOP_PENDING, 0);
                SetEvent(STOP_EVENT.load(Ordering::SeqCst) as HANDLE);
                NO_ERROR
            }
            SERVICE_CONTROL_SESSIONCHANGE => {
                SetEvent(SESSION_EVENT.load(Ordering::SeqCst) as HANDLE);
                NO_ERROR
            }
            SERVICE_CONTROL_INTERROGATE => NO_ERROR,
            _ => ERROR_CALL_NOT_IMPLEMENTED,
        }
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    unsafe {
        let h = RegisterServiceCtrlHandlerExW(wide(SERVICE_NAME).as_ptr(), Some(handler), null());
        if h.is_null() {
            return;
        }
        STATUS.store(h as usize, Ordering::SeqCst);
        STOP_EVENT.store(CreateEventW(null(), 1, 0, null()) as usize, Ordering::SeqCst);
        SESSION_EVENT.store(CreateEventW(null(), 0, 0, null()) as usize, Ordering::SeqCst);
        // Log only into a directory that is provably the administrators' (see keystore); the
        // agent refuses to start without one as well.
        let code = match keystore::check_service_dir() {
            Ok(dir) => {
                let _ = crate::util::set_log_file(&dir.join("service.log"));
                set_state(SERVICE_RUNNING, 0);
                match supervise() {
                    Ok(()) => 0,
                    Err(e) => {
                        log!("service failed: {e}");
                        1
                    }
                }
            }
            Err(e) => {
                log!("service failed: {e}");
                ERROR_ACCESS_DENIED
            }
        };
        set_state(SERVICE_STOPPED, code);
    }
}

/// Event that only SYSTEM can open, used by the agent to request Ctrl+Alt+Del.
fn create_sas_event() -> Result<HANDLE> {
    unsafe {
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(wide("D:P(A;;GA;;;SY)").as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) == 0 {
            return Err(Error::last_os("security descriptor"));
        }
        let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 };
        let h = CreateEventW(&sa, 0, 0, wide(SAS_EVENT).as_ptr());
        LocalFree(sd as HLOCAL);
        if h.is_null() {
            return Err(Error::last_os("CreateEventW(SAS)"));
        }
        Ok(h)
    }
}

fn kill_on_close_job() -> Result<HANDLE> {
    unsafe {
        let job = CreateJobObjectW(null(), null());
        if job.is_null() {
            return Err(Error::last_os("CreateJobObjectW"));
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info as *const _ as *const c_void, size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32);
        Ok(job)
    }
}

/// A running agent.
struct Agent {
    process: HANDLE,
    /// The write end of the agent's stdin; closing it asks the agent to stop.
    stdin: Option<PipeWriter>,
    session: u32,
    started: Instant,
}

impl Agent {
    /// Closes the agent's stdin so that it shuts down cleanly (releasing held keys and buttons,
    /// ending privacy mode), and kills it if it is still running after `wait`. True if it
    /// ended by itself.
    fn stop(mut self, wait: Duration) -> bool {
        drop(self.stdin.take());
        let ms = wait.as_millis().min(u32::MAX as u128 - 1) as u32;
        if unsafe { WaitForSingleObject(self.process, ms) } == WAIT_OBJECT_0 {
            return true;
        }
        log!("agent did not stop within {ms} ms; terminating it");
        unsafe { TerminateProcess(self.process, 1) };
        false
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.process) };
    }
}

/// Starts `cmd` (program `exe`) with `token`, on `desktop` if given, inside `job`. The read end
/// of a new pipe becomes its stdin and the only handle it inherits; the write end is returned.
fn spawn(token: HANDLE, exe: &str, cmd: &str, desktop: Option<&str>, job: HANDLE) -> Result<(HANDLE, PipeWriter)> {
    let (child_stdin, stdin) = std::io::pipe()?;
    let inherit = [child_stdin.as_raw_handle() as HANDLE];
    unsafe {
        if SetHandleInformation(inherit[0], HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == 0 {
            return Err(Error::last_os("SetHandleInformation"));
        }
        let mut size = 0usize;
        InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size);
        let mut buf = vec![0usize; size.div_ceil(size_of::<usize>())];
        let list = buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
        if InitializeProcThreadAttributeList(list, 1, 0, &mut size) == 0 {
            return Err(Error::last_os("InitializeProcThreadAttributeList"));
        }
        let attr = PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize;
        if UpdateProcThreadAttribute(list, 0, attr, inherit.as_ptr() as *const c_void, size_of_val(&inherit), null_mut(), null()) == 0 {
            let e = Error::last_os("UpdateProcThreadAttribute");
            DeleteProcThreadAttributeList(list);
            return Err(e);
        }
        let mut desktop = desktop.map(wide);
        let mut si: STARTUPINFOEXW = std::mem::zeroed();
        si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = inherit[0];
        if let Some(d) = &mut desktop {
            si.StartupInfo.lpDesktop = d.as_mut_ptr();
        }
        si.lpAttributeList = list;
        let mut wcmd = wide(cmd);
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let flags = CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT;
        let si = &si.StartupInfo;
        let ok = CreateProcessAsUserW(token, wide(exe).as_ptr(), wcmd.as_mut_ptr(), null(), null(), 1, flags, null(), null(), si, &mut pi);
        let failed = (ok == 0).then(|| Error::last_os("CreateProcessAsUserW"));
        DeleteProcThreadAttributeList(list);
        if let Some(e) = failed {
            return Err(e);
        }
        AssignProcessToJobObject(job, pi.hProcess);
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        Ok((pi.hProcess, stdin))
    }
}

/// Starts `safe-rdp agent ...` as SYSTEM in `session` on the interactive window station.
fn launch_agent(session: u32, job: HANDLE) -> Result<Agent> {
    let exe = std::env::current_exe()?.to_string_lossy().to_string();
    let mut parts = vec![exe.clone(), "agent".to_string()];
    parts.extend(AGENT_ARGS.get().into_iter().flatten().cloned());
    let cmd = command_line(&parts)?;
    unsafe {
        let mut tok: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, &mut tok) == 0 {
            return Err(Error::last_os("OpenProcessToken"));
        }
        let mut dup: HANDLE = null_mut();
        let ok = DuplicateTokenEx(tok, TOKEN_ALL_ACCESS, null(), SecurityIdentification, TokenPrimary, &mut dup);
        CloseHandle(tok);
        if ok == 0 {
            return Err(Error::last_os("DuplicateTokenEx"));
        }
        if SetTokenInformation(dup, TokenSessionId, &session as *const u32 as *const c_void, 4) == 0 {
            CloseHandle(dup);
            return Err(Error::last_os("SetTokenInformation(TokenSessionId)"));
        }
        let r = spawn(dup, &exe, &cmd, Some(r"winsta0\default"), job);
        CloseHandle(dup);
        let (process, stdin) = r?;
        Ok(Agent { process, stdin: Some(stdin), session, started: Instant::now() })
    }
}

fn supervise() -> Result<()> {
    let stop = STOP_EVENT.load(Ordering::SeqCst) as HANDLE;
    let session_evt = SESSION_EVENT.load(Ordering::SeqCst) as HANDLE;
    let sas = create_sas_event()?;
    let job = kill_on_close_job()?;
    log!("service started");

    let mut agent: Option<Agent> = None;
    let mut next_launch = Instant::now();
    let mut backoff = Duration::from_secs(2);
    loop {
        let session = unsafe { WTSGetActiveConsoleSessionId() };
        if let Some(a) = agent.take_if(|a| a.session != session) {
            log!("console session changed ({} -> {session}); restarting agent", a.session);
            a.stop(AGENT_STOP_WAIT);
            next_launch = Instant::now();
        }
        if agent.is_none() && session != u32::MAX && Instant::now() >= next_launch {
            match launch_agent(session, job) {
                Ok(a) => {
                    log!("agent started in session {session}");
                    agent = Some(a);
                }
                Err(e) => {
                    log!("cannot start agent: {e}");
                    next_launch = Instant::now() + backoff;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }

        let mut handles = vec![stop, sas, session_evt];
        if let Some(a) = &agent {
            handles.push(a.process);
        }
        let r = unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, 2000) };
        match r.wrapping_sub(WAIT_OBJECT_0) {
            0 => break,
            1 => {
                log!("generating Ctrl+Alt+Del");
                unsafe { SendSAS(0) };
            }
            2 => {}
            3 => {
                let Some(a) = agent.take() else { continue };
                let mut code = 0u32;
                unsafe { GetExitCodeProcess(a.process, &mut code) };
                log!("agent exited with code {code}");
                if a.started.elapsed() > Duration::from_secs(60) {
                    backoff = Duration::from_secs(2);
                }
                next_launch = Instant::now() + backoff;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
            _ => {}
        }
    }

    if let Some(a) = agent {
        a.stop(AGENT_STOP_WAIT);
    }
    unsafe {
        CloseHandle(job);
        CloseHandle(sas);
    }
    log!("service stopped");
    Ok(())
}

/// For `safe-rdp service status`.
pub fn status() -> Result<String> {
    unsafe {
        let scm = OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return Err(Error::last_os("OpenSCManagerW"));
        }
        let scm = Sc(scm);
        let svc = OpenServiceW(scm.0, wide(SERVICE_NAME).as_ptr(), SERVICE_QUERY_STATUS);
        if svc.is_null() {
            return Ok("not installed".into());
        }
        let svc = Sc(svc);
        let mut st: SERVICE_STATUS = std::mem::zeroed();
        if QueryServiceStatus(svc.0, &mut st) == 0 {
            return Err(Error::last_os("QueryServiceStatus"));
        }
        Ok(match st.dwCurrentState {
            SERVICE_RUNNING => "running",
            SERVICE_STOPPED => "stopped",
            SERVICE_START_PENDING => "starting",
            SERVICE_STOP_PENDING => "stopping",
            _ => "unknown",
        }
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXE: &str = r"C:\Program Files\safe-rdp\safe-rdp.exe";

    #[test]
    fn arguments_survive_the_command_line() {
        let tricky = [
            r"D:\Remote Uploads\",
            r"D:\Uploads\",
            r"C:\a b\\",
            r"\server\share\with space\",
            "",
            " ",
            r"\",
            r"\\",
            "\"",
            r#"a"b"#,
            r#"a\"b"#,
            r#"a\\"b c"#,
            r#"\"""#,
            r#""lead"#,
            r#"end\\\"#,
            "tab\there",
            "new\nline",
            "v\u{b}t",
            "100.101.102.103",
            "한글 ünï",
        ];
        for a in tricky {
            let parts = [EXE, "service", "run", "--transfer-dir", a, "--allow", "100.101.102.103", "--view-only"].map(String::from);
            let cmd = command_line(&parts).unwrap_or_else(|e| panic!("{a:?}: {e}"));
            assert_eq!(split_command_line(&cmd), parts, "{cmd}");
        }
        let mut all = vec![EXE.to_string(), "agent".to_string()];
        all.extend(tricky.map(String::from));
        assert_eq!(split_command_line(&command_line(&all).unwrap()), all);
        // The directory that used to swallow every later flag, and plain arguments.
        assert_eq!(quote(r"D:\Remote Uploads\"), r#""D:\Remote Uploads\\""#);
        assert_eq!(quote(r#"a\"b"#), r#""a\\\"b""#);
        assert_eq!(quote(r"D:\Uploads\"), r"D:\Uploads\");
        assert_eq!(quote("--view-only"), "--view-only");
    }

    fn own_token() -> HANDLE {
        unsafe {
            let mut tok: HANDLE = null_mut();
            assert!(OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &mut tok) != 0);
            let mut dup: HANDLE = null_mut();
            assert!(DuplicateTokenEx(tok, TOKEN_ALL_ACCESS, null(), SecurityIdentification, TokenPrimary, &mut dup) != 0);
            CloseHandle(tok);
            dup
        }
    }

    /// Starts a console tool from System32 the way the service starts its agent; also returns a
    /// second handle to the process for watching it.
    fn start(tool: &str, args: &[&str], job: HANDLE) -> (Agent, HANDLE) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let exe = format!(r"{root}\System32\{tool}");
        let mut parts = vec![exe.clone()];
        parts.extend(args.iter().map(|a| a.to_string()));
        let token = own_token();
        let r = spawn(token, &exe, &command_line(&parts).unwrap(), None, job);
        unsafe { CloseHandle(token) };
        let (process, stdin) = r.unwrap();
        let mut watch: HANDLE = null_mut();
        let me = unsafe { GetCurrentProcess() };
        assert!(unsafe { DuplicateHandle(me, process, me, &mut watch, 0, 0, DUPLICATE_SAME_ACCESS) } != 0);
        (Agent { process, stdin: Some(stdin), session: 0, started: Instant::now() }, watch)
    }

    #[test]
    fn agents_stop_when_stdin_closes_and_are_killed_otherwise() {
        let job = kill_on_close_job().unwrap();
        unsafe {
            // sort reads its stdin to the end before it does anything else.
            let (agent, watch) = start("sort.exe", &[], job);
            assert_eq!(WaitForSingleObject(watch, 300), WAIT_TIMEOUT, "ended before its stdin was closed");
            let t = Instant::now();
            assert!(agent.stop(Duration::from_secs(10)), "did not end when its stdin was closed");
            assert!(t.elapsed() < Duration::from_secs(5));
            CloseHandle(watch);

            // ping ignores stdin, so it is terminated once the wait is over.
            let (agent, watch) = start("ping.exe", &["-n", "30", "127.0.0.1"], job);
            let t = Instant::now();
            assert!(!agent.stop(Duration::from_millis(300)));
            assert!(t.elapsed() < Duration::from_secs(3));
            assert_eq!(WaitForSingleObject(watch, 5000), WAIT_OBJECT_0);
            let mut code = 0u32;
            GetExitCodeProcess(watch, &mut code);
            assert_eq!(code, 1);
            CloseHandle(watch);
            CloseHandle(job);
        }
    }
}
