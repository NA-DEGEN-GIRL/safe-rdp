//! Windows service mode.
//!
//! A LocalSystem service (session 0) supervises an *agent*: the same executable started with
//! a SYSTEM token inside the active console session. Running as SYSTEM in the user's session
//! is what allows the agent to follow the input desktop onto the lock screen, the sign-in
//! screen and UAC prompts, and to drive elevated windows. The agent is tied to the service
//! with a kill-on-close job object and is restarted whenever the console session changes.
//!
//! Ctrl+Alt+Del cannot be synthesised with SendInput; the agent signals a SYSTEM-only event
//! and the service calls SendSAS (requires the SoftwareSASGeneration policy, `--enable-sas`).

use crate::keystore;
use crate::util::{Error, Result, wide};
use crate::{bail, log};
use std::ffi::c_void;
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

pub const SERVICE_NAME: &str = "SafeRdpHost";
const DISPLAY_NAME: &str = "safe-rdp host";
const SAS_EVENT: &str = r"Global\SafeRdpSas";
const FIREWALL_RULE: &str = "safe-rdp";

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

fn quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }
    format!("\"{}\"", arg.replace('"', "\\\""))
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

    let mut cmd = format!("{} service run", quote(&exe_str));
    for a in host_args {
        cmd.push(' ');
        cmd.push_str(&quote(a));
    }
    let wcmd = wide(&cmd);
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
        let _ = crate::util::set_log_file(&keystore::service_dir().join("service.log"));
        set_state(SERVICE_RUNNING, 0);
        let code = match supervise() {
            Ok(()) => 0,
            Err(e) => {
                log!("service failed: {e}");
                1
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

/// Starts `safe-rdp agent ...` as SYSTEM in `session` on the interactive window station.
fn launch_agent(session: u32, job: HANDLE) -> Result<HANDLE> {
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
        let exe = std::env::current_exe()?.to_string_lossy().to_string();
        let mut cmd = format!("{} agent", quote(&exe));
        for a in AGENT_ARGS.get().map(|v| v.as_slice()).unwrap_or(&[]) {
            cmd.push(' ');
            cmd.push_str(&quote(a));
        }
        let mut wcmd = wide(&cmd);
        let mut desktop = wide(r"winsta0\default");
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = size_of::<STARTUPINFOW>() as u32;
        si.lpDesktop = desktop.as_mut_ptr();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let ok = CreateProcessAsUserW(
            dup,
            wide(&exe).as_ptr(),
            wcmd.as_mut_ptr(),
            null(),
            null(),
            0,
            CREATE_NO_WINDOW | CREATE_SUSPENDED,
            null(),
            null(),
            &si,
            &mut pi,
        );
        CloseHandle(dup);
        if ok == 0 {
            return Err(Error::last_os("CreateProcessAsUserW"));
        }
        AssignProcessToJobObject(job, pi.hProcess);
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        Ok(pi.hProcess)
    }
}

fn supervise() -> Result<()> {
    let stop = STOP_EVENT.load(Ordering::SeqCst) as HANDLE;
    let session_evt = SESSION_EVENT.load(Ordering::SeqCst) as HANDLE;
    let sas = create_sas_event()?;
    let job = kill_on_close_job()?;
    log!("service started");

    let mut agent: Option<(HANDLE, u32, Instant)> = None;
    let mut next_launch = Instant::now();
    let mut backoff = Duration::from_secs(2);
    loop {
        let session = unsafe { WTSGetActiveConsoleSessionId() };
        if let Some((h, s, _)) = agent {
            if s != session {
                log!("console session changed ({s} -> {session}); restarting agent");
                unsafe {
                    TerminateProcess(h, 0);
                    CloseHandle(h);
                }
                agent = None;
                next_launch = Instant::now();
            }
        }
        if agent.is_none() && session != u32::MAX && Instant::now() >= next_launch {
            match launch_agent(session, job) {
                Ok(h) => {
                    log!("agent started in session {session}");
                    agent = Some((h, session, Instant::now()));
                }
                Err(e) => {
                    log!("cannot start agent: {e}");
                    next_launch = Instant::now() + backoff;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }

        let mut handles = vec![stop, sas, session_evt];
        if let Some((h, _, _)) = agent {
            handles.push(h);
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
                let (h, _, started) = agent.take().unwrap();
                let mut code = 0u32;
                unsafe {
                    GetExitCodeProcess(h, &mut code);
                    CloseHandle(h);
                }
                log!("agent exited with code {code}");
                if started.elapsed() > Duration::from_secs(60) {
                    backoff = Duration::from_secs(2);
                }
                next_launch = Instant::now() + backoff;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
            _ => {}
        }
    }

    if let Some((h, _, _)) = agent {
        unsafe {
            TerminateProcess(h, 0);
            CloseHandle(h);
        }
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
