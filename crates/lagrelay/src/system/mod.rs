pub mod boost;
pub mod monitor;
pub mod ram;
pub mod shaper;

use anyhow::{bail, Context, Result};

/// Runs a program with discrete arguments (no shell) and returns its stdout.
pub fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let o = std::process::Command::new(cmd).args(args).output().with_context(|| format!("run {cmd}"))?;
    if !o.status.success() {
        let (e, out) = (String::from_utf8_lossy(&o.stderr), String::from_utf8_lossy(&o.stdout));
        bail!("{cmd} {}: {}", args.first().unwrap_or(&""), if e.trim().is_empty() { out.trim() } else { e.trim() });
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Whether this process has administrator (Windows) or root (Linux) rights.
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        // `net session` only succeeds in an elevated process.
        run("net", &["session"]).is_ok()
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}

/// Executable names go into PowerShell command strings, so restrict them.
pub fn is_safe_exe_name(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('-') && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exe_name_validation() {
        assert!(is_safe_exe_name("cs2.exe"));
        assert!(!is_safe_exe_name("a b.exe"));
        assert!(!is_safe_exe_name("x;calc"));
        assert!(!is_safe_exe_name("$(calc)"));
        assert!(!is_safe_exe_name("-Force"));
        assert!(!is_safe_exe_name(""));
    }
}
