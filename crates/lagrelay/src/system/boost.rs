//! Reversible system tweaks. Every tweak records exactly how to undo itself in a
//! state file before the change is made, so a crash can still be undone with
//! `lagrelay boost revert`.
use super::{is_safe_exe_name, run};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const ULTIMATE: &str = "e9a42b02-d5df-448d-aa00-03f14749eb61";
const HIGH_PERF: &str = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";
const IFEO: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
const GPU_PREFS: &str = r"HKCU\Software\Microsoft\DirectX\UserGpuPreferences";

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum Undo {
    SetActiveScheme(String),
    DeleteScheme(String),
    PowerValue { sub: String, setting: String, value: String },
    RegSet { key: String, name: String, kind: String, data: String },
    RegDelete { key: String, name: String },
    RegDeleteKey { key: String },
    ServiceStart { name: String, start: String, was_running: bool },
    DnsRestore { iface: String, servers: Vec<String> },
    RemoveQosPolicy(String),
    Governor { path: String, value: String },
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct State {
    /// (tweak name, undo steps, run in order). Newest last.
    pub applied: Vec<(String, Vec<Undo>)>,
}

fn state_path() -> PathBuf {
    crate::config::home().join("boost-state.json")
}

pub fn load_state() -> State {
    std::fs::read_to_string(state_path()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save_state(s: &State) -> Result<()> {
    std::fs::create_dir_all(crate::config::home())?;
    let tmp = state_path().with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(s)?)?;
    std::fs::rename(tmp, state_path())?;
    Ok(())
}

/// `powercfg /getactivescheme` prints "... GUID: <guid>  (Name)".
pub fn parse_guid(s: &str) -> Option<String> {
    s.split_whitespace().find(|t| t.len() == 36 && t.matches('-').count() == 4 && t.chars().all(|c| c.is_ascii_hexdigit() || c == '-')).map(str::to_string)
}

/// Finds a value in `powercfg /query`: the line "Current AC Power Setting Index: 0x...".
/// Windows localises the label, so this takes the first of the two index lines.
pub fn parse_powercfg_index(s: &str) -> Option<String> {
    s.lines().rev().filter_map(|l| l.rsplit(' ').next().filter(|v| v.starts_with("0x") && v.len() == 10)).nth(1).map(str::to_string)
}

/// Parses one value from `reg query KEY /v NAME` as (type, data).
pub fn parse_reg_value(s: &str, name: &str) -> Option<(String, String)> {
    for l in s.lines() {
        let t = l.trim_start();
        // Registry value names are case-insensitive. Missing an existing value
        // here would make the undo delete it instead of restoring it.
        if t.len() >= name.len() && t.is_char_boundary(name.len()) && t[..name.len()].eq_ignore_ascii_case(name) {
            let rest = t[name.len()..].trim_start();
            let (kind, data) = rest.split_once(char::is_whitespace)?;
            if kind.starts_with("REG_") {
                return Some((kind.to_string(), data.trim().to_string()));
            }
        }
    }
    None
}

/// The `sc config start=` word for a service's registry Start and DelayedAutoStart
/// values. `sc qc` isn't used, because Windows localises its field labels.
pub fn start_mode(start: &str, delayed: Option<&str>) -> Option<&'static str> {
    let is_on = |v: &str| v.trim_start_matches("0x").trim_start_matches('0') == "1";
    Some(match start.trim_start_matches("0x").trim_start_matches('0') {
        "2" if delayed.is_some_and(is_on) => "delayed-auto",
        "2" => "auto",
        "3" => "demand",
        "4" => "disabled",
        _ => return None,
    })
}

fn reg_get(key: &str, name: &str) -> Option<(String, String)> {
    parse_reg_value(&run("reg", &["query", key, "/v", name]).ok()?, name)
}

fn reg_set(undo: &mut Vec<Undo>, key: &str, name: &str, kind: &str, data: &str) -> Result<()> {
    undo.push(match reg_get(key, name) {
        Some((k, d)) => Undo::RegSet { key: key.into(), name: name.into(), kind: k, data: d },
        None => Undo::RegDelete { key: key.into(), name: name.into() },
    });
    run("reg", &["add", key, "/v", name, "/t", kind, "/d", data, "/f"])?;
    Ok(())
}

fn tweak_power(u: &mut Vec<Undo>) -> Result<String> {
    if !cfg!(windows) {
        return tweak_governor(u);
    }
    let old = parse_guid(&run("powercfg", &["/getactivescheme"])?).context("cannot read the active power plan")?;
    // Undo steps run last to first, so the old plan is reactivated before the
    // private copy is deleted: Windows refuses to delete the active plan.
    match run("powercfg", &["-duplicatescheme", ULTIMATE]).ok().and_then(|o| parse_guid(&o)) {
        Some(g) => {
            u.push(Undo::DeleteScheme(g.clone()));
            u.push(Undo::SetActiveScheme(old));
            run("powercfg", &["/setactive", &g])?;
            Ok("Ultimate Performance plan active".into())
        }
        None => {
            u.push(Undo::SetActiveScheme(old));
            run("powercfg", &["/setactive", HIGH_PERF])?;
            Ok("High Performance plan active (Ultimate is not available on this edition)".into())
        }
    }
}

fn tweak_governor(u: &mut Vec<Undo>) -> Result<String> {
    let mut n = 0;
    for e in std::fs::read_dir("/sys/devices/system/cpu").context("read cpu list")?.flatten() {
        let p = e.path().join("cpufreq/scaling_governor");
        let Ok(old) = std::fs::read_to_string(&p) else { continue };
        std::fs::write(&p, "performance").with_context(|| format!("write {}", p.display()))?;
        u.push(Undo::Governor { path: p.display().to_string(), value: old.trim().to_string() });
        n += 1;
    }
    if n == 0 {
        bail!("this system exposes no CPU frequency governor");
    }
    Ok(format!("performance governor on {n} CPUs"))
}

fn tweak_parking(u: &mut Vec<Undo>) -> Result<String> {
    windows_only()?;
    // /qh also lists hidden settings, and this one is hidden by default.
    let q = run("powercfg", &["/qh", "scheme_current", "sub_processor", "CPMINCORES"])?;
    let old = parse_powercfg_index(&q).context("cannot read the core parking setting")?;
    u.push(Undo::PowerValue { sub: "sub_processor".into(), setting: "CPMINCORES".into(), value: old });
    run("powercfg", &["-setacvalueindex", "scheme_current", "sub_processor", "CPMINCORES", "100"])?;
    run("powercfg", &["/setactive", "scheme_current"])?;
    Ok("core parking off while on AC power".into())
}

fn tweak_gamebar(u: &mut Vec<Undo>) -> Result<String> {
    windows_only()?;
    reg_set(u, r"HKCU\System\GameConfigStore", "GameDVR_Enabled", "REG_DWORD", "0")?;
    reg_set(u, r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled", "REG_DWORD", "0")?;
    Ok("Game Bar capture off".into())
}

fn tweak_sysmain(u: &mut Vec<Undo>) -> Result<String> {
    windows_only()?;
    let key = r"HKLM\SYSTEM\CurrentControlSet\Services\SysMain";
    let (_, start) = reg_get(key, "Start").context("cannot read SysMain's start type")?;
    let delayed = reg_get(key, "DelayedAutoStart").map(|(_, d)| d);
    let mode = start_mode(&start, delayed.as_deref()).context("unknown SysMain start type")?;
    let was_running = run("powershell", &["-NoProfile", "-Command", "(Get-Service SysMain).Status"]).is_ok_and(|s| s.trim() == "Running");
    u.push(Undo::ServiceStart { name: "SysMain".into(), start: mode.into(), was_running });
    run("sc", &["config", "SysMain", "start=", "disabled"])?;
    let _ = run("sc", &["stop", "SysMain"]);
    Ok("SysMain (SuperFetch) off".into())
}

fn tweak_qos(u: &mut Vec<Undo>, exes: &[String]) -> Result<String> {
    windows_only()?;
    // The tunnel itself carries the game's traffic, so it must be marked as well.
    let mut all: Vec<&str> = exes.iter().map(String::as_str).collect();
    all.push("lagrelay.exe");
    for e in all {
        if !is_safe_exe_name(e) {
            bail!("unsafe executable name: {e}");
        }
        let name = format!("LagRelay-{e}");
        u.push(Undo::RemoveQosPolicy(name.clone()));
        let _ = run("powershell", &["-NoProfile", "-Command", &format!("Remove-NetQosPolicy -Name '{name}' -Confirm:$false -ErrorAction SilentlyContinue")]);
        run("powershell", &["-NoProfile", "-Command", &format!("New-NetQosPolicy -Name '{name}' -AppPathNameMatchesCondition '{e}' -DSCPAction 46 -NetworkProfile All | Out-Null")])?;
    }
    Ok("traffic marked high priority (DSCP 46)".into())
}

/// Sets CPU priority through the OS's per-executable setting, so nothing ever
/// needs to open a handle to the running game.
fn tweak_priority(u: &mut Vec<Undo>, exes: &[String]) -> Result<String> {
    windows_only()?;
    if exes.is_empty() {
        bail!("no game executable given");
    }
    for e in exes {
        if !is_safe_exe_name(e) {
            bail!("unsafe executable name: {e}");
        }
        let key = format!(r"{IFEO}\{e}\PerfOptions");
        let existed = run("reg", &["query", &key]).is_ok();
        if !existed {
            u.push(Undo::RegDeleteKey { key: key.clone() });
        }
        let mut inner = vec![];
        reg_set(&mut inner, &key, "CpuPriorityClass", "REG_DWORD", "3")?;
        if existed {
            u.extend(inner);
        }
    }
    Ok(format!("high CPU priority at launch for {} (restart the game to apply)", exes.join(", ")))
}

fn tweak_gpu(u: &mut Vec<Undo>, paths: &[String]) -> Result<String> {
    windows_only()?;
    if paths.is_empty() {
        bail!("game executable path not found");
    }
    for p in paths {
        reg_set(u, GPU_PREFS, p, "REG_SZ", "GpuPreference=2;")?;
    }
    Ok("high-performance GPU selected for the game".into())
}

fn windows_only() -> Result<()> {
    if !cfg!(windows) {
        bail!("Windows only");
    }
    Ok(())
}

fn run_undo(u: &Undo) -> Result<()> {
    match u {
        Undo::SetActiveScheme(g) => drop(run("powercfg", &["/setactive", g])?),
        Undo::DeleteScheme(g) => drop(run("powercfg", &["/delete", g])?),
        Undo::PowerValue { sub, setting, value } => {
            run("powercfg", &["-setacvalueindex", "scheme_current", sub, setting, value])?;
            run("powercfg", &["/setactive", "scheme_current"])?;
        }
        Undo::RegSet { key, name, kind, data } => drop(run("reg", &["add", key, "/v", name, "/t", kind, "/d", data, "/f"])?),
        Undo::RegDelete { key, name } => {
            // Already absent is the state we wanted.
            let _ = run("reg", &["delete", key, "/v", name, "/f"]);
        }
        Undo::RegDeleteKey { key } => {
            let _ = run("reg", &["delete", key, "/f"]);
        }
        Undo::ServiceStart { name, start, was_running } => {
            run("sc", &["config", name, "start=", start])?;
            if *was_running {
                let _ = run("sc", &["start", name]);
            }
        }
        Undo::RemoveQosPolicy(n) => {
            if !is_safe_exe_name(n) {
                bail!("unsafe policy name in state file: {n}");
            }
            let _ = run("powershell", &["-NoProfile", "-Command", &format!("Remove-NetQosPolicy -Name '{n}' -Confirm:$false -ErrorAction SilentlyContinue")]);
        }
        Undo::Governor { path, value } => {
            // The state file is user-writable, so only ever touch governor files.
            if !(path.starts_with("/sys/devices/system/cpu/") && path.ends_with("/cpufreq/scaling_governor")) {
                bail!("unexpected path in state file: {path}");
            }
            std::fs::write(path, value)?;
        }
        Undo::DnsRestore { iface, servers } => crate::dns::set_servers(iface, servers)?,
    }
    Ok(())
}

pub struct Tweak {
    pub name: &'static str,
    pub desc: &'static str,
}

pub const TWEAKS: &[Tweak] = &[
    Tweak { name: "power", desc: "Ultimate Performance power plan (Linux: performance governor)" },
    Tweak { name: "parking", desc: "Disable CPU core parking on AC power" },
    Tweak { name: "gamebar", desc: "Disable Game Bar background capture" },
    Tweak { name: "sysmain", desc: "Stop SysMain/SuperFetch to free RAM" },
    Tweak { name: "qos", desc: "Mark game and tunnel traffic high priority" },
    Tweak { name: "priority", desc: "Launch the game at high CPU priority" },
    Tweak { name: "gpu", desc: "Prefer the high-performance GPU for the game" },
];

pub struct GameInfo {
    pub exes: Vec<String>,
    pub paths: Vec<String>,
}

fn apply_one(name: &str, u: &mut Vec<Undo>, g: &GameInfo) -> Result<String> {
    match name {
        "power" => tweak_power(u),
        "parking" => tweak_parking(u),
        "gamebar" => tweak_gamebar(u),
        "sysmain" => tweak_sysmain(u),
        "qos" => tweak_qos(u, &g.exes),
        "priority" => tweak_priority(u, &g.exes),
        "gpu" => tweak_gpu(u, &g.paths),
        o => Err(anyhow!("unknown tweak '{o}'")),
    }
}

/// Applies tweaks, printing each result. One failure doesn't stop the others.
/// Returns how many succeeded.
pub fn apply(names: &[&str], g: &GameInfo) -> Result<usize> {
    let mut state = load_state();
    let mut ok = 0;
    for &name in names {
        // Per-game tweaks are tracked per game, so a second game still gets its own.
        let key = match name {
            "qos" | "priority" => format!("{name}:{}", g.exes.join(",")),
            "gpu" => format!("{name}:{}", g.paths.join(",")),
            _ => name.to_string(),
        };
        if state.applied.iter().any(|(n, _)| *n == key) {
            println!("  = {name}: already applied");
            ok += 1;
            continue;
        }
        let mut undo = vec![];
        let result = apply_one(name, &mut undo, g);
        // Save whatever was recorded even on failure: part of it may have applied.
        if !undo.is_empty() {
            state.applied.push((key, undo));
            save_state(&state)?;
        }
        match result {
            Ok(m) => {
                println!("  + {name}: {m}");
                ok += 1;
            }
            Err(e) => println!("  ! {name}: {e:#}"),
        }
    }
    Ok(ok)
}

/// Records an undo step for a change made outside this module.
pub fn record(name: &str, undo: Undo) -> Result<()> {
    let mut s = load_state();
    if !s.applied.iter().any(|(n, _)| n == name) {
        s.applied.push((name.to_string(), vec![undo]));
        save_state(&s)?;
    }
    Ok(())
}

/// Undoes every applied tweak, newest first, each with its steps in reverse.
pub fn revert_all() -> Result<()> {
    let mut state = load_state();
    if state.applied.is_empty() {
        println!("nothing to revert");
        return Ok(());
    }
    let mut failed = vec![];
    while let Some((name, steps)) = state.applied.pop() {
        let mut remaining = vec![];
        for u in steps.iter().rev() {
            if let Err(e) = run_undo(u) {
                println!("  ! {name}: {e:#}");
                remaining.insert(0, u.clone());
            }
        }
        if remaining.is_empty() {
            println!("  - {name}: restored");
        } else {
            failed.push((name, remaining));
        }
    }
    state.applied = failed;
    save_state(&state)?;
    if !state.applied.is_empty() {
        bail!("{} tweak(s) could not be fully restored; rerun as Administrator: lagrelay boost revert", state.applied.len());
    }
    Ok(())
}

/// Holds 0.5 ms timer resolution until dropped. The OS also resets it if the
/// process dies, so this needs no undo record.
pub struct TimerGuard {
    #[cfg(windows)]
    set: unsafe extern "system" fn(u32, u8, *mut u32) -> i32,
    #[cfg(windows)]
    _lib: libloading::Library,
}

#[cfg(windows)]
impl Drop for TimerGuard {
    fn drop(&mut self) {
        let mut cur = 0u32;
        // SAFETY: the library is still loaded, and cur outlives the call.
        unsafe { (self.set)(5000, 0, &mut cur) };
    }
}

#[cfg(windows)]
pub fn hold_timer_resolution() -> Result<TimerGuard> {
    type F = unsafe extern "system" fn(u32, u8, *mut u32) -> i32;
    // SAFETY: ntdll is always present, and the signature matches NtSetTimerResolution.
    unsafe {
        let lib = libloading::Library::new("ntdll.dll")?;
        let f = *lib.get::<F>(b"NtSetTimerResolution\0")?;
        let mut cur = 0u32;
        let rc = f(5000, 1, &mut cur);
        if rc != 0 {
            bail!("NtSetTimerResolution returned {rc:#x}");
        }
        Ok(TimerGuard { set: f, _lib: lib })
    }
}

#[cfg(not(windows))]
pub fn hold_timer_resolution() -> Result<TimerGuard> {
    bail!("Windows only")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_parsing() {
        let s = "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)";
        assert_eq!(parse_guid(s).as_deref(), Some("381b4222-f694-41f0-9685-ff5bb260df2e"));
        assert_eq!(parse_guid("nothing here"), None);
    }

    #[test]
    fn powercfg_index_parsing_including_localised() {
        let s = "  Possible Setting Increment: 0x00000001\n  Current AC Power Setting Index: 0x00000005\n  Current DC Power Setting Index: 0x0000000a\n\n";
        assert_eq!(parse_powercfg_index(s).as_deref(), Some("0x00000005"));
        let de = "    Aktueller Wechselstromindex: 0x00000064\n    Aktueller Gleichstromindex: 0x00000001\n";
        assert_eq!(parse_powercfg_index(de).as_deref(), Some("0x00000064"));
        assert_eq!(parse_powercfg_index("none"), None);
    }

    #[test]
    fn reg_value_parsing() {
        let s = "\r\nHKEY_CURRENT_USER\\System\\GameConfigStore\r\n    GameDVR_Enabled    REG_DWORD    0x1\r\n\r\n";
        assert_eq!(parse_reg_value(s, "GameDVR_Enabled"), Some(("REG_DWORD".into(), "0x1".into())));
        assert_eq!(parse_reg_value(s, "Missing"), None);
        assert!(parse_reg_value(s, "gamedvr_enabled").is_some(), "names are case-insensitive");
        let p = "    C:\\Games\\cs2.exe    REG_SZ    GpuPreference=2;\r\n";
        assert_eq!(parse_reg_value(p, "C:\\Games\\cs2.exe"), Some(("REG_SZ".into(), "GpuPreference=2;".into())));
    }

    #[test]
    fn service_start_modes() {
        assert_eq!(start_mode("0x2", None), Some("auto"));
        assert_eq!(start_mode("0x2", Some("0x0")), Some("auto"));
        assert_eq!(start_mode("0x2", Some("0x1")), Some("delayed-auto"));
        assert_eq!(start_mode("0x3", None), Some("demand"));
        assert_eq!(start_mode("0x4", None), Some("disabled"));
        assert_eq!(start_mode("0x0", None), None);
    }

    #[test]
    fn state_roundtrip() {
        let s = State { applied: vec![("a".into(), vec![Undo::DnsRestore { iface: "3".into(), servers: vec![] }, Undo::RegDelete { key: "k".into(), name: "n".into() }])] };
        let t: State = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(t.applied, s.applied);
    }

    #[test]
    fn tampered_state_cannot_write_arbitrary_files() {
        let u = Undo::Governor { path: "/etc/passwd".into(), value: "x".into() };
        assert!(run_undo(&u).is_err());
        let q = Undo::RemoveQosPolicy("x'; calc; '".into());
        assert!(run_undo(&q).is_err());
    }
}
