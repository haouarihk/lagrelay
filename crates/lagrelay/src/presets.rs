//! Built-in one-word game presets for `lagrelay optimize`.
use crate::config::Game;
use anyhow::{bail, Result};

pub struct Preset {
    pub key: &'static str,
    pub title: &'static str,
    pub processes: &'static [&'static str],
    /// Tweaks applied by `lagrelay optimize`. SysMain is left out because it
    /// slows the rest of the PC down; `lagrelay boost apply sysmain` adds it.
    pub tweaks: &'static [&'static str],
    pub notes: &'static [&'static str],
}

const STD: &[&str] = &["power", "parking", "gamebar", "qos", "priority", "gpu"];

pub const PRESETS: &[Preset] = &[
    Preset {
        key: "cs2",
        title: "Counter-Strike 2 (Valve servers)",
        processes: &["cs2.exe"],
        tweaks: STD,
        notes: &[
            "Valve matchmaking already routes through Steam Datagram Relay, so a relay gains most on poor ISP routes; expect less here than on FACEIT.",
            "LagRelay never opens or injects into cs2.exe, and never edits its files.",
        ],
    },
    Preset {
        key: "faceit",
        title: "CS2 on FACEIT",
        // Only the game's traffic is relayed. The FACEIT client and anti-cheat
        // stay on the direct connection and are never touched.
        processes: &["cs2.exe"],
        tweaks: STD,
        notes: &[
            "FACEIT Anti-Cheat decides which drivers may load, and it isn't known to allow WinDivert. If it refuses, LagRelay reports that and keeps only the tweaks. There is no workaround by design.",
            "The game server will see your relay's IP, not your own. Check FACEIT's current rules if you are unsure this is acceptable for your account.",
            "FACEIT's own system requirements for its anti-cheat still apply; LagRelay doesn't change them.",
        ],
    },
];

pub fn find(key: &str) -> Result<&'static Preset> {
    let k = key.to_ascii_lowercase();
    match PRESETS.iter().find(|p| p.key == k) {
        Some(p) => Ok(p),
        None => bail!("no preset '{key}'. Presets: {}", PRESETS.iter().map(|p| p.key).collect::<Vec<_>>().join(", ")),
    }
}

impl Preset {
    pub fn to_game(&self) -> Game {
        Game { name: self.key.to_string(), processes: self.processes.iter().map(|s| s.to_string()).collect(), ..Default::default() }
    }
}

/// Library paths from Steam's libraryfolders.vdf ("path" lines, `\\` escaped).
pub fn parse_library_folders(vdf: &str) -> Vec<String> {
    vdf.lines()
        .filter_map(|l| {
            let mut parts = l.split('"').skip(1).step_by(2);
            (parts.next()? == "path").then(|| parts.next().map(|p| p.replace("\\\\", "\\")))?
        })
        .collect()
}

/// Full path of cs2.exe across Steam libraries, needed by the GPU preference.
pub fn find_cs2() -> Option<String> {
    let q = crate::system::run("reg", &["query", r"HKCU\Software\Valve\Steam", "/v", "SteamPath"]).ok()?;
    let (_, steam) = crate::system::boost::parse_reg_value(&q, "SteamPath")?;
    let vdf = std::fs::read_to_string(format!("{steam}/steamapps/libraryfolders.vdf")).ok()?;
    parse_library_folders(&vdf).into_iter().find_map(|lib| {
        let p = format!(r"{lib}\steamapps\common\Counter-Strike Global Offensive\game\bin\win64\cs2.exe");
        std::path::Path::new(&p).exists().then_some(p)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Matcher;

    #[test]
    fn presets_are_valid_and_only_relay_the_game() {
        for p in PRESETS {
            let m = Matcher::from_game(&p.to_game()).unwrap();
            assert!(m.wants_process("CS2.EXE"));
            assert!(!m.wants_process("faceitclient.exe"), "anti-cheat client must stay direct");
            assert!(!m.wants_process("faceitservice.exe"));
            assert!(p.processes.iter().all(|e| crate::system::is_safe_exe_name(e)));
            for t in p.tweaks {
                assert!(crate::system::boost::TWEAKS.iter().any(|d| d.name == *t), "{t}");
            }
        }
    }

    #[test]
    fn lookup() {
        assert_eq!(find("CS2").unwrap().key, "cs2");
        assert_eq!(find("faceit").unwrap().key, "faceit");
        assert!(find("nope").is_err());
    }

    #[test]
    fn vdf_library_paths() {
        let v = "\"libraryfolders\"\n{\n\t\"0\"\n\t{\n\t\t\"path\"\t\t\"C:\\\\Program Files (x86)\\\\Steam\"\n\t\t\"label\"\t\t\"\"\n\t}\n\t\"1\"\n\t{\n\t\t\"path\"\t\t\"D:\\\\SteamLibrary\"\n\t}\n}\n";
        assert_eq!(parse_library_folders(v), vec!["C:\\Program Files (x86)\\Steam", "D:\\SteamLibrary"]);
    }
}
