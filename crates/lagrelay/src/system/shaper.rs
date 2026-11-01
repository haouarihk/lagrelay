//! Traffic shaper: limits bulk traffic so a game's packets don't queue behind it.
//!
//! Windows: per-application upload limits through NetQos policies; Windows has
//! no built-in way to limit downloads per application.
//! Linux: CAKE on the upload side of the default interface.
use super::{is_safe_exe_name, run};
use anyhow::{bail, Result};

/// Apps that commonly saturate an uplink during a match.
pub const DEFAULT_APPS: &[&str] = &["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "qbittorrent.exe", "utorrent.exe", "onedrive.exe", "dropbox.exe", "steamwebhelper.exe", "epicgameslauncher.exe"];

/// Parses "20mbit", "500kbit" or a plain number of Mbit/s into bits per second.
pub fn parse_rate(s: &str) -> Result<u64> {
    let t = s.trim().to_ascii_lowercase();
    let (num, mult) = if let Some(n) = t.strip_suffix("mbit") {
        (n, 1_000_000.0)
    } else if let Some(n) = t.strip_suffix("kbit") {
        (n, 1_000.0)
    } else {
        (t.as_str(), 1_000_000.0)
    };
    let v: f64 = num.trim().parse().map_err(|_| anyhow::anyhow!("bad rate '{s}'; use e.g. 20mbit"))?;
    if !(v.is_finite() && v > 0.0) {
        bail!("bad rate '{s}'");
    }
    Ok((v * mult) as u64)
}

pub fn on(bps: u64, apps: &[String]) -> Result<()> {
    if cfg!(windows) {
        let defaults: Vec<String> = DEFAULT_APPS.iter().map(|s| s.to_string()).collect();
        let list = if apps.is_empty() { &defaults } else { apps };
        for a in list {
            if !is_safe_exe_name(a) {
                bail!("unsafe executable name: {a}");
            }
            let name = format!("LagRelayShape-{a}");
            let cmd = format!("Remove-NetQosPolicy -Name '{name}' -Confirm:$false -ErrorAction SilentlyContinue; New-NetQosPolicy -Name '{name}' -AppPathNameMatchesCondition '{a}' -ThrottleRateActionBitsPerSecond {bps} -NetworkProfile All | Out-Null");
            run("powershell", &["-NoProfile", "-Command", &cmd])?;
        }
        println!("limited upload of {} apps to {} kbit/s each", list.len(), bps / 1000);
    } else {
        let i = crate::dns::active_iface()?;
        run("tc", &["qdisc", "replace", "dev", &i, "root", "cake", "bandwidth", &format!("{}kbit", bps / 1000), "diffserv4"])?;
        println!("CAKE active on {i} at {} kbit/s", bps / 1000);
    }
    Ok(())
}

pub fn off() -> Result<()> {
    if cfg!(windows) {
        run("powershell", &["-NoProfile", "-Command", "Get-NetQosPolicy | Where-Object Name -like 'LagRelayShape-*' | Remove-NetQosPolicy -Confirm:$false"])?;
    } else {
        let i = crate::dns::active_iface()?;
        run("tc", &["qdisc", "del", "dev", &i, "root"])?;
    }
    println!("traffic shaper off");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates() {
        assert_eq!(parse_rate("20mbit").unwrap(), 20_000_000);
        assert_eq!(parse_rate("500kbit").unwrap(), 500_000);
        assert_eq!(parse_rate("1.5").unwrap(), 1_500_000);
        assert!(parse_rate("fast").is_err());
        assert!(parse_rate("-1").is_err());
        assert!(parse_rate("0").is_err());
        assert!(parse_rate("inf").is_err());
    }

    #[test]
    fn default_apps_are_safe() {
        assert!(DEFAULT_APPS.iter().all(|a| is_safe_exe_name(a)));
    }
}
