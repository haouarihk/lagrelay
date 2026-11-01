//! RAM cleaner: asks Windows to page out idle memory from background processes.
use anyhow::Result;

/// Never touched: system processes, anything that looks like anti-cheat, and
/// known games. The caller adds the games in the user's profiles through `allow`.
/// Opening a handle to these could be seen as tampering.
const PROTECTED: &[&str] = &[
    "system", "idle", "registry", "smss", "csrss", "wininit", "winlogon", "lsass", "services", "svchost", "dwm", "memcompression", "lagrelay",
    "cs2", "faceit", "vgc", "vgtray", "valorant", "riot", "easyanticheat", "eaanticheat", "eac", "battleye", "beservice", "steam",
];

#[cfg_attr(not(windows), allow(dead_code))]
pub fn is_protected(exe: &str, allow: &[String]) -> bool {
    let n = exe.to_ascii_lowercase();
    PROTECTED.iter().any(|p| n.starts_with(p)) || allow.iter().any(|a| a.eq_ignore_ascii_case(&n))
}

#[cfg(windows)]
pub fn clean(allow: &[String]) -> Result<()> {
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE};
    use windows_sys::Win32::System::ProcessStatus::K32EmptyWorkingSet;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA};
    let before = super::monitor::available_ram();
    let (mut done, mut skipped, mut failed) = (0, 0, 0);
    for (pid, name) in crate::capture::windows::snapshot_processes() {
        if pid == 0 || is_protected(&name, allow) {
            skipped += 1;
            continue;
        }
        // SAFETY: the handle is checked, used once and closed.
        unsafe {
            let h = OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if h.is_null() {
                failed += 1;
                continue;
            }
            if K32EmptyWorkingSet(h) != 0 {
                done += 1;
            } else {
                failed += 1;
            }
            CloseHandle(h);
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    let freed = super::monitor::available_ram().saturating_sub(before);
    println!("trimmed {done} processes ({skipped} protected, {failed} denied); {} more RAM available", crate::ui::fmt_bytes(freed));
    Ok(())
}

#[cfg(not(windows))]
pub fn clean(_: &[String]) -> Result<()> {
    anyhow::bail!("the RAM cleaner is Windows only; Linux reclaims this memory on demand")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_list() {
        assert!(is_protected("cs2.exe", &[]));
        assert!(is_protected("FACEITClient.exe", &[]));
        assert!(is_protected("faceitservice.exe", &[]));
        assert!(is_protected("lsass.exe", &[]));
        assert!(is_protected("EasyAntiCheat_EOS.exe", &[]));
        assert!(!is_protected("chrome.exe", &[]));
        assert!(is_protected("chrome.exe", &["chrome.exe".to_string()]));
    }
}
