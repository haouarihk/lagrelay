use anyhow::{anyhow, bail, Context, Result};
use lagcore::session::{decode_key, decode_token, encode_key, generate_keypair};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Bridge,
    Exit,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Relay {
    pub name: String,
    pub addr: String,
    pub public_key: String,
    pub role: Role,
    /// The relay's access token, from its link.
    pub token: String,
}

impl Relay {
    /// Parses `lagrelay://KEY@host:port?name=x&role=exit&token=lrt_...`.
    pub fn from_link(link: &str) -> Result<Relay> {
        let rest = link.trim().strip_prefix("lagrelay://").ok_or_else(|| anyhow!("link must start with lagrelay://"))?;
        let (key, rest) = rest.split_once('@').ok_or_else(|| anyhow!("link has no key"))?;
        let (addr, query) = rest.split_once('?').unwrap_or((rest, ""));
        decode_key(key).context("link key")?;
        if addr.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()).is_none() {
            bail!("link address must be host:port");
        }
        let (mut name, mut role, mut token) = (None, Role::Exit, None);
        for kv in query.split('&') {
            match kv.split_once('=') {
                Some(("name", v)) => name = Some(v.to_string()),
                Some(("token", v)) => token = Some(v.to_string()),
                Some(("role", "bridge")) => role = Role::Bridge,
                Some(("role", "exit")) => role = Role::Exit,
                Some(("role", v)) => bail!("unknown role {v}"),
                _ => {}
            }
        }
        let token = token.ok_or_else(|| anyhow!("link has no access token; get a current one with `lagrelayd link`"))?;
        decode_token(&token).context("link token")?;
        Ok(Relay { name: name.unwrap_or_else(|| addr.to_string()), addr: addr.to_string(), public_key: key.to_string(), role, token })
    }

    pub fn token_bytes(&self) -> Result<[u8; 32]> {
        decode_token(&self.token).with_context(|| format!("relay {} token", self.name))
    }

    pub fn key(&self) -> Result<[u8; 32]> {
        decode_key(&self.public_key).with_context(|| format!("relay {} key", self.name))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Game {
    pub name: String,
    /// Executable names matched case-insensitively, e.g. "cs2.exe". Windows only.
    #[serde(default)]
    pub processes: Vec<String>,
    /// Destination networks to tunnel. Empty means any public address.
    #[serde(default)]
    pub cidrs: Vec<String>,
    /// Destination ports as "27015" or "27000-27100". Empty means all.
    #[serde(default)]
    pub ports: Vec<String>,
    /// Exit relay to use; unset selects automatically.
    pub exit: Option<String>,
    /// Game server "ip:port" used to compare exits; unset compares relay latency only.
    pub ping_target: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Settings {
    /// How many routes carry a copy of each packet.
    #[serde(default = "default_routes")]
    pub routes: usize,
    /// Most bridges allowed in one route.
    #[serde(default = "default_hops")]
    pub max_bridges: usize,
    /// UDP flows (source ports) to try. Some ISPs route each flow differently,
    /// so trying several finds the fastest path. 1 turns this off.
    #[serde(default = "default_flows")]
    pub flows: usize,
    /// Treat the plain internet route as an option: use it per server when it's fastest,
    /// and as a backup in either direction.
    #[serde(default = "default_true")]
    pub auto_direct: bool,
    /// How many milliseconds a relay must beat direct by to be used.
    #[serde(default = "default_margin")]
    pub direct_margin_ms: f64,
    /// Also move live connections when the other route stays better. This changes
    /// the IP the game server sees, which may drop you from the match.
    #[serde(default)]
    pub live_switch: bool,
    /// Send over several network interfaces at once.
    #[serde(default)]
    pub multi_internet: bool,
    /// Interfaces for multi-internet; empty means all usable ones.
    #[serde(default)]
    pub interfaces: Vec<String>,
    /// Drop a matched game's IPv6 traffic so it falls back to the IPv4 tunnel.
    #[serde(default = "default_true")]
    pub block_ipv6: bool,
}

fn default_routes() -> usize {
    2
}
fn default_hops() -> usize {
    1
}
fn default_margin() -> f64 {
    3.0
}
fn default_flows() -> usize {
    crate::engine::DEFAULT_FLOWS
}
fn default_true() -> bool {
    true
}

impl Default for Settings {
    fn default() -> Self {
        Settings { routes: 2, max_bridges: 1, flows: default_flows(), auto_direct: true, direct_margin_ms: default_margin(), live_switch: false, multi_internet: false, interfaces: vec![], block_ipv6: true }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub private_key: String,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub relays: Vec<Relay>,
    #[serde(default)]
    pub games: Vec<Game>,
}

/// Config directory: `LAGRELAY_HOME`, else `%APPDATA%\LagRelay`, else `~/.config/lagrelay`.
pub fn home() -> PathBuf {
    if let Some(h) = std::env::var_os("LAGRELAY_HOME") {
        return PathBuf::from(h);
    }
    if cfg!(windows) {
        if let Some(a) = std::env::var_os("APPDATA") {
            return PathBuf::from(a).join("LagRelay");
        }
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("lagrelay")
}

impl Config {
    pub fn path() -> PathBuf {
        home().join("config.toml")
    }

    /// Loads the config, creating one with a new key pair on first use.
    pub fn load_or_create() -> Result<Config> {
        Self::load_or_create_at(&Self::path())
    }

    pub fn load_or_create_at(p: &Path) -> Result<Config> {
        match std::fs::read_to_string(p) {
            Ok(s) => toml::from_str(&s).with_context(|| format!("parse {}", p.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let k = generate_keypair()?;
                let c = Config { private_key: encode_key(&k.private), settings: Settings::default(), relays: vec![], games: vec![] };
                c.save_at(p)?;
                Ok(c)
            }
            Err(e) => Err(e).with_context(|| format!("read {}", p.display())),
        }
    }

    pub fn save(&self) -> Result<()> {
        self.save_at(&Self::path())
    }

    pub fn save_at(&self, p: &Path) -> Result<()> {
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        let tmp = p.with_extension("toml.tmp");
        write_private(&tmp, &toml::to_string_pretty(self)?)?;
        std::fs::rename(&tmp, p)?;
        Ok(())
    }

    pub fn private(&self) -> Result<[u8; 32]> {
        decode_key(&self.private_key).context("private_key")
    }

    pub fn relay(&self, name: &str) -> Result<&Relay> {
        self.relays.iter().find(|r| r.name == name).ok_or_else(|| anyhow!("no relay named '{name}'"))
    }

    pub fn game(&self, name: &str) -> Result<&Game> {
        self.games.iter().find(|g| g.name.eq_ignore_ascii_case(name)).ok_or_else(|| anyhow!("no game named '{name}'; add it with `lagrelay game add`"))
    }
}

#[cfg(unix)]
fn write_private(p: &Path, s: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(p)?;
    f.write_all(s.as_bytes())?;
    Ok(())
}

// %APPDATA% is already restricted to the user by its default ACL.
#[cfg(not(unix))]
fn write_private(p: &Path, s: &str) -> Result<()> {
    std::fs::write(p, s)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const TOK: &str = "lrt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn parses_share_links() {
        let r = Relay::from_link(&format!("lagrelay://{KEY}@1.2.3.4:41820?name=tokyo&role=bridge&token={TOK}")).unwrap();
        assert_eq!(r.token_bytes().unwrap(), [0; 32]);
        assert_eq!((r.name.as_str(), r.addr.as_str(), r.role), ("tokyo", "1.2.3.4:41820", Role::Bridge));
        let r = Relay::from_link(&format!("lagrelay://{KEY}@relay.example.com:1?token={TOK}")).unwrap();
        assert_eq!(r.role, Role::Exit);
        assert_eq!(r.name, "relay.example.com:1");
    }

    #[test]
    fn rejects_bad_links() {
        assert!(Relay::from_link("http://x").is_err());
        assert!(Relay::from_link("lagrelay://nokey").is_err());
        assert!(Relay::from_link(&format!("lagrelay://{KEY}@noport")).is_err());
        assert!(Relay::from_link("lagrelay://short@1.2.3.4:1").is_err());
        assert!(Relay::from_link(&format!("lagrelay://{KEY}@1.2.3.4:1?role=weird&token={TOK}")).is_err());
        assert!(Relay::from_link(&format!("lagrelay://{KEY}@1.2.3.4:1")).is_err(), "token is mandatory");
        assert!(Relay::from_link(&format!("lagrelay://{KEY}@1.2.3.4:1?token=bad")).is_err());
    }

    #[test]
    fn creates_then_reloads_same_key() {
        let d = std::env::temp_dir().join(format!("lagrelay-test-{}", rand::random::<u32>()));
        let p = d.join("config.toml");
        let a = Config::load_or_create_at(&p).unwrap();
        let b = Config::load_or_create_at(&p).unwrap();
        assert_eq!(a.private_key, b.private_key);
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn minimal_toml_gets_defaults() {
        let c: Config = toml::from_str(&format!("private_key = \"{KEY}\"")).unwrap();
        assert_eq!(c.settings.routes, 2);
        assert_eq!(c.settings.flows, crate::engine::DEFAULT_FLOWS, "default for a config without [settings]");
        assert!(c.settings.block_ipv6);
    }
}
