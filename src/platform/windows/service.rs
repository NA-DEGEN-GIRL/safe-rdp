//! Windows service mode.
//!
//! A LocalSystem service (session 0) supervises an *agent*: the same executable started with
//! a SYSTEM token inside the active console session. Running as SYSTEM in the user's session
//! is what allows the agent to follow the input desktop onto the lock screen, the sign-in
//! screen and UAC prompts, and to drive elevated windows. The agent is tied to the service
//! with a kill-on-close job object and is restarted whenever the console session changes.
//! To stop it, the service signals a SYSTEM-only event whose name it passes on the agent's
//! command line (handles cannot be inherited across sessions): the agent then releases the keys
//! and buttons a viewer holds and ends privacy mode, and is killed only if it takes too long.
//!
//! Ctrl+Alt+Del cannot be synthesised with SendInput; the agent signals a SYSTEM-only event
//! and the service calls SendSAS (requires the SoftwareSASGeneration policy, `--enable-sas`).

use super::keystore;
use crate::util::{Error, Result, wide};
use crate::{bail, log};
use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
/// Followed by a random suffix: the event the service signals to stop one agent.
const AGENT_STOP_EVENT: &str = r"Global\SafeRdpAgentStop-";
/// The agent's first argument, followed by the name of its stop event.
const STOP_EVENT_ARG: &str = "--stop-event";
/// Only SYSTEM (the service and its agent) may use the service's events.
const SYSTEM_ONLY: &str = "D:P(A;;GA;;;SY)";
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

/// Called by the agent: splits the name of its stop event, which the service puts first, off
/// its arguments.
pub fn agent_stop_event(args: &[String]) -> (Option<&str>, &[String]) {
    match args {
        [flag, name, rest @ ..] if flag == STOP_EVENT_ARG => (Some(name), rest),
        _ => (None, args),
    }
}

/// Called by the agent: sets `stop` once the service signals the event `name`. An event that
/// cannot be opened or waited on is never taken for a stop request; the service then
/// terminates the agent instead.
pub fn watch_stop_event(name: &str, stop: &'static AtomicBool) -> Result<()> {
    let h = unsafe { OpenEventW(SYNCHRONIZATION_SYNCHRONIZE, 0, wide(name).as_ptr()) };
    if h.is_null() {
        return Err(Error::last_os(&format!("OpenEventW({name})")));
    }
    let event = unsafe { OwnedHandle::from_raw_handle(h) };
    std::thread::Builder::new().name("stop-event".into()).spawn(move || {
        if unsafe { WaitForSingleObject(event.as_raw_handle() as HANDLE, INFINITE) } == WAIT_OBJECT_0 {
            stop.store(true, Ordering::SeqCst);
        } else {
            log!("cannot wait for the service's stop request: {}", std::io::Error::last_os_error());
        }
    })?;
    Ok(())
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

/// Creates the event `name` with security descriptor `sddl`. A name that is already taken is
/// refused: whoever created that event would control it.
fn create_event(name: &str, sddl: &str, manual_reset: bool) -> Result<OwnedHandle> {
    unsafe {
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(sddl).as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) == 0 {
            return Err(Error::last_os("security descriptor"));
        }
        let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 };
        SetLastError(0);
        let h = CreateEventW(&sa, manual_reset as i32, 0, wide(name).as_ptr());
        let e = std::io::Error::last_os_error();
        LocalFree(sd as HLOCAL);
        if h.is_null() {
            bail!("CreateEventW({name}) failed: {e}");
        }
        let h = OwnedHandle::from_raw_handle(h);
        if e.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) {
            bail!("event {name} already exists");
        }
        Ok(h)
    }
}

/// A new manual-reset event with security descriptor `sddl` and a random name, for stopping one
/// agent. Manual reset: the agent sees the request even if it opens the event only afterwards.
fn new_stop_event(sddl: &str) -> Result<(OwnedHandle, String)> {
    let mut r = [0u8; 8];
    crate::crypto::random(&mut r)?;
    let name = format!("{AGENT_STOP_EVENT}{:016x}", u64::from_ne_bytes(r));
    Ok((create_event(&name, sddl, true)?, name))
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
    /// Signalled to ask the agent to stop.
    stop_event: OwnedHandle,
    session: u32,
    started: Instant,
}

impl Agent {
    /// Signals the agent's stop event so that it shuts down cleanly (releasing held keys and
    /// buttons, ending privacy mode), and kills it if it is still running after `wait`. True if
    /// it ended by itself.
    fn stop(self, wait: Duration) -> bool {
        unsafe { SetEvent(self.stop_event.as_raw_handle() as HANDLE) };
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

/// Starts `cmd` (program `exe`) with `token`, on `desktop` if given, inside `job`. It inherits
/// no handles: they cannot be passed into another session.
fn spawn(token: HANDLE, exe: &str, cmd: &str, desktop: Option<&str>, job: HANDLE) -> Result<HANDLE> {
    unsafe {
        let mut desktop = desktop.map(wide);
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = size_of::<STARTUPINFOW>() as u32;
        if let Some(d) = &mut desktop {
            si.lpDesktop = d.as_mut_ptr();
        }
        let mut wcmd = wide(cmd);
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let flags = CREATE_NO_WINDOW | CREATE_SUSPENDED;
        if CreateProcessAsUserW(token, wide(exe).as_ptr(), wcmd.as_mut_ptr(), null(), null(), 0, flags, null(), null(), &si, &mut pi) == 0 {
            return Err(Error::last_os("CreateProcessAsUserW"));
        }
        AssignProcessToJobObject(job, pi.hProcess);
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        Ok(pi.hProcess)
    }
}

/// The agent's command line: the name of its stop event first, then the host options.
fn agent_command(exe: &str, stop_event: &str, host_args: &[String]) -> Vec<String> {
    let mut parts = vec![exe.to_string(), "agent".to_string(), STOP_EVENT_ARG.to_string(), stop_event.to_string()];
    parts.extend_from_slice(host_args);
    parts
}

/// Starts `safe-rdp agent ...` as SYSTEM in `session` on the interactive window station.
fn launch_agent(session: u32, job: HANDLE) -> Result<Agent> {
    let exe = std::env::current_exe()?.to_string_lossy().to_string();
    let (stop_event, name) = new_stop_event(SYSTEM_ONLY)?;
    let cmd = command_line(&agent_command(&exe, &name, AGENT_ARGS.get().map_or(&[], Vec::as_slice)))?;
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
        Ok(Agent { process: r?, stop_event, session, started: Instant::now() })
    }
}

fn supervise() -> Result<()> {
    let stop = STOP_EVENT.load(Ordering::SeqCst) as HANDLE;
    let session_evt = SESSION_EVENT.load(Ordering::SeqCst) as HANDLE;
    let sas = create_event(SAS_EVENT, SYSTEM_ONLY, false)?;
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

        let mut handles = vec![stop, sas.as_raw_handle() as HANDLE, session_evt];
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
    unsafe { CloseHandle(job) };
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
            SERVICE_RUNNING => "running".into(),
            // The service could not log why (it only logs into a folder it trusts): say it here.
            SERVICE_STOPPED if st.dwWin32ExitCode == ERROR_ACCESS_DENIED => refused_folder(),
            SERVICE_STOPPED => "stopped".into(),
            SERVICE_START_PENDING => "starting".into(),
            SERVICE_STOP_PENDING => "stopping".into(),
            _ => "unknown".into(),
        })
    }
}

fn refused_folder() -> String {
    let dir = keystore::service_dir();
    let detail = match keystore::check_service_dir() {
        // Unreadable without elevation; anything else is the actual reason.
        Err(e) if !e.to_string().starts_with("cannot open") => format!(" ({e})"),
        _ => String::new(),
    };
    format!(
        "stopped: it refused to use {} because its permissions changed{detail}; \
         run `safe-rdp service install` again from an elevated terminal",
        dir.display()
    )
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

    #[test]
    fn the_agent_finds_its_stop_event_in_front_of_the_host_options() {
        let host = ["--port", "1234", "--transfer-dir", "--stop-event", "--view-only"].map(String::from);
        let parts = agent_command(EXE, r"Global\SafeRdpAgentStop-0123456789abcdef", &host);
        let args = split_command_line(&command_line(&parts).unwrap());
        assert_eq!(args[..2], [EXE, "agent"]);
        let (name, rest) = agent_stop_event(&args[2..]);
        assert_eq!(name, Some(r"Global\SafeRdpAgentStop-0123456789abcdef"));
        assert_eq!(rest, host);
        // Only in front: elsewhere it is an ordinary (here: the transfer directory's) value.
        let (name, rest) = agent_stop_event(rest);
        assert_eq!((name, rest.len()), (None, 5));
        assert_eq!(agent_stop_event(&["--stop-event".to_string()]).0, None);
    }

    /// What the stand-in agent of `start_agent` may open: SYSTEM and the owner (this test).
    const TEST_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;OW)";
    static CHILD_STOP: AtomicBool = AtomicBool::new(false);

    /// The stand-in agent: watches the stop event named on its command line like the agent does,
    /// and returns once it is signalled.
    #[test]
    #[ignore = "started by agents_stop_when_signalled_and_are_killed_otherwise in a process of its own"]
    fn stand_in_agent() {
        let Some(name) = std::env::args().find(|a| a.starts_with(AGENT_STOP_EVENT)) else { return };
        // Like the agent, keep running when the event cannot be opened.
        let _ = watch_stop_event(&name, &CHILD_STOP);
        let t = Instant::now();
        while !CHILD_STOP.load(Ordering::SeqCst) {
            assert!(t.elapsed() < Duration::from_secs(60));
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Starts this test binary as a stand-in agent watching `stop_event` (named `name`) the way the
    /// service starts its agent; also returns a second handle to the process for watching it.
    fn start_agent(stop_event: OwnedHandle, name: &str, job: HANDLE) -> (Agent, HANDLE) {
        let exe = std::env::current_exe().unwrap().to_string_lossy().to_string();
        let test = format!("{}::stand_in_agent", module_path!().split_once("::").unwrap().1);
        // The event name is a second filter that matches no test.
        let parts = [exe.as_str(), "--ignored", "--exact", "-q", test.as_str(), name].map(String::from);
        let token = own_token();
        let r = spawn(token, &exe, &command_line(&parts).unwrap(), None, job);
        unsafe { CloseHandle(token) };
        let process = r.unwrap();
        let mut watch: HANDLE = null_mut();
        let me = unsafe { GetCurrentProcess() };
        assert!(unsafe { DuplicateHandle(me, process, me, &mut watch, 0, 0, DUPLICATE_SAME_ACCESS) } != 0);
        (Agent { process, stop_event, session: 0, started: Instant::now() }, watch)
    }

    #[test]
    fn agents_stop_when_signalled_and_are_killed_otherwise() {
        let job = kill_on_close_job().unwrap();
        unsafe {
            let (event, name) = new_stop_event(TEST_SDDL).unwrap();
            assert!(name.starts_with(AGENT_STOP_EVENT) && name.len() == AGENT_STOP_EVENT.len() + 16, "{name}");
            // Nobody can take over the name while it is in use.
            assert!(create_event(&name, TEST_SDDL, true).is_err());
            let (agent, watch) = start_agent(event, &name, job);
            assert_eq!(WaitForSingleObject(watch, 2000), WAIT_TIMEOUT, "ended before it was asked to");
            let t = Instant::now();
            assert!(agent.stop(Duration::from_secs(10)), "did not end when its stop event was signalled");
            assert!(t.elapsed() < Duration::from_secs(5));
            let mut code = 1u32;
            GetExitCodeProcess(watch, &mut code);
            assert_eq!(code, 0, "the stand-in agent failed");
            CloseHandle(watch);

            // The real event admits SYSTEM alone. A stand-in that cannot open it keeps running
            // and is terminated once the wait is over.
            let (event, name) = new_stop_event(SYSTEM_ONLY).unwrap();
            assert!(OpenEventW(SYNCHRONIZATION_SYNCHRONIZE, 0, wide(&name).as_ptr()).is_null());
            assert_eq!(GetLastError(), ERROR_ACCESS_DENIED);
            let (agent, watch) = start_agent(event, &name, job);
            assert_eq!(WaitForSingleObject(watch, 2000), WAIT_TIMEOUT, "an event it cannot open was taken for a stop request");
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
