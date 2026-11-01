//! Tracks the running session, so `lagrelay off` can stop it from another terminal.
//!
//! Stopping works through a file the session watches. Windows can't send Ctrl+C
//! to a process in another console, and a clean exit is what restores the PC
//! settings a session changed.
use crate::config::home;
use anyhow::{bail, Result};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessesToUpdate, System};

const STOP_WAIT: Duration = Duration::from_secs(12);

fn pid_path() -> PathBuf {
    home().join("session.pid")
}

fn stop_path() -> PathBuf {
    home().join("stop")
}

pub fn parse_pid(s: &str) -> Option<u32> {
    s.trim().parse().ok().filter(|p| *p != 0)
}

/// True only if that PID is a LagRelay client, since PIDs get reused after a crash.
pub fn is_client_name(name: &str) -> bool {
    matches!(name.to_ascii_lowercase().as_str(), "lagrelay" | "lagrelay.exe")
}

fn alive_client(pid: u32) -> bool {
    let mut s = System::new();
    let p = Pid::from_u32(pid);
    s.refresh_processes(ProcessesToUpdate::Some(&[p]), true);
    s.process(p).is_some_and(|x| is_client_name(&x.name().to_string_lossy()))
}

fn running_session() -> Option<u32> {
    let pid = parse_pid(&std::fs::read_to_string(pid_path()).ok()?)?;
    (pid != std::process::id() && alive_client(pid)).then_some(pid)
}

/// Held for the whole of a session. Removes its PID file on exit.
pub struct SessionGuard;

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(pid_path());
    }
}

/// Registers this process as the session. Refuses to run two at once, because
/// their capture and routing rules would interfere.
pub fn begin_session() -> Result<SessionGuard> {
    if let Some(pid) = running_session() {
        bail!("LagRelay is already running (PID {pid}). Stop it with: lagrelay off");
    }
    std::fs::create_dir_all(home())?;
    let _ = std::fs::remove_file(stop_path());
    std::fs::write(pid_path(), std::process::id().to_string())?;
    Ok(SessionGuard)
}

pub fn stop_requested() -> bool {
    stop_path().exists()
}

pub struct OffResult {
    pub was_running: bool,
    pub forced: bool,
}

/// Asks the session to exit cleanly, and force-stops it only if it doesn't.
pub fn stop_session() -> Result<OffResult> {
    let Some(pid) = running_session() else {
        let _ = std::fs::remove_file(pid_path());
        let _ = std::fs::remove_file(stop_path());
        return Ok(OffResult { was_running: false, forced: false });
    };
    std::fs::write(stop_path(), "")?;
    let start = Instant::now();
    while start.elapsed() < STOP_WAIT {
        if !alive_client(pid) {
            let _ = std::fs::remove_file(stop_path());
            return Ok(OffResult { was_running: true, forced: false });
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let mut s = System::new();
    let p = Pid::from_u32(pid);
    s.refresh_processes(ProcessesToUpdate::Some(&[p]), true);
    let killed = s.process(p).is_some_and(|x| x.kill());
    let _ = std::fs::remove_file(stop_path());
    if !killed {
        bail!("could not stop LagRelay (PID {pid}). Run this as Administrator or with sudo");
    }
    std::thread::sleep(Duration::from_millis(300));
    let _ = std::fs::remove_file(pid_path());
    Ok(OffResult { was_running: true, forced: true })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_file_parsing() {
        assert_eq!(parse_pid("123\n"), Some(123));
        assert_eq!(parse_pid(""), None);
        assert_eq!(parse_pid("abc"), None);
        assert_eq!(parse_pid("0"), None);
    }

    #[test]
    fn only_the_client_counts_as_a_session() {
        assert!(is_client_name("lagrelay"));
        assert!(is_client_name("LagRelay.exe"));
        assert!(!is_client_name("lagrelayd"), "the relay daemon is a different program");
        assert!(!is_client_name("chrome.exe"), "a reused PID must not be killed");
    }
}
