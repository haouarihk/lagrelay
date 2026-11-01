use anyhow::{bail, Context, Result};
use lagcore::session::{decode_key, decode_token, encode_key, generate_keypair, generate_token, public_from_private};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub name: String,
    /// Address clients should use. Only used to print share links.
    pub public_addr: String,
    pub private_key: String,
    /// Clients must hold this token as well as an authorized key. Treat it like a password.
    pub access_token: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Extra listen ports, for networks that shape or block the default port.
    #[serde(default)]
    pub extra_ports: Vec<u16>,
    /// Bridge forwarding destinations as "ip:port". "*" allows any destination,
    /// and forwarding is only ever available to authenticated clients.
    #[serde(default = "default_forward")]
    pub allow_forward: Vec<String>,
    /// Lets clients reach private, loopback and link-local addresses through this
    /// relay. Off by default, so a leaked credential can't reach the relay's own
    /// local services, its containers, or a cloud metadata service.
    #[serde(default)]
    pub allow_private_destinations: bool,
    /// Present when this relay is also an exit to the internet.
    pub exit: Option<ExitConfig>,
    #[serde(default)]
    pub clients: Vec<Client>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExitConfig {
    #[serde(default = "default_tun")]
    pub tun: String,
    /// Tunnel subnet. The relay takes the .1 address.
    #[serde(default = "default_subnet")]
    pub subnet: String,
    /// Internet-facing interface for NAT. Detected from the default route if unset.
    pub wan_interface: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Client {
    pub name: String,
    pub public_key: String,
    pub vip: Ipv4Addr,
}

fn default_port() -> u16 {
    lagcore::DEFAULT_PORT
}
fn default_forward() -> Vec<String> {
    vec!["*".into()]
}
fn default_tun() -> String {
    "lagrelay0".into()
}
fn default_subnet() -> String {
    "10.77.0.0/16".into()
}

impl Config {
    pub fn load(p: &Path) -> Result<Config> {
        let s = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
        let c: Config = toml::from_str(&s).with_context(|| format!("parse {}", p.display()))?;
        c.private_key()?;
        c.token()?;
        Ok(c)
    }

    pub fn save(&self, p: &Path) -> Result<()> {
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        write_private(p, &toml::to_string_pretty(self)?)
    }

    pub fn private_key(&self) -> Result<[u8; 32]> {
        decode_key(&self.private_key).context("private_key")
    }

    pub fn token(&self) -> Result<[u8; 32]> {
        decode_token(&self.access_token).context("access_token")
    }

    pub fn share_link(&self) -> Result<String> {
        let pk = public_from_private(&self.private_key()?)?;
        let role = if self.exit.is_some() { "exit" } else { "bridge" };
        Ok(format!("lagrelay://{}@{}:{}?name={}&role={}&token={}", encode_key(&pk), self.public_addr, self.port, self.name, role, self.access_token))
    }

    pub fn new(name: String, public_addr: String, port: u16, exit: bool) -> Result<Config> {
        let k = generate_keypair()?;
        Ok(Config {
            name,
            public_addr,
            private_key: encode_key(&k.private),
            access_token: generate_token(),
            port,
            extra_ports: vec![],
            allow_forward: default_forward(),
            allow_private_destinations: false,
            exit: exit.then(|| ExitConfig { tun: default_tun(), subnet: default_subnet(), wan_interface: None }),
            clients: vec![],
        })
    }

    /// Picks the first free tunnel address after the relay's own .1 address.
    pub fn next_vip(&self) -> Result<Ipv4Addr> {
        let subnet = self.exit.as_ref().map(|e| e.subnet.as_str()).unwrap_or("10.77.0.0/16");
        let (net, len) = lagcore::ip::parse_cidr(subnet).context("bad subnet")?;
        if len > 30 {
            bail!("subnet {subnet} is too small");
        }
        let base = u32::from(net);
        let span = 1u64 << (32 - len as u32);
        for off in 2..span - 1 {
            let c = Ipv4Addr::from(base + off as u32);
            if !self.clients.iter().any(|x| x.vip == c) {
                return Ok(c);
            }
        }
        bail!("no free tunnel addresses in {subnet}")
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

#[cfg(not(unix))]
fn write_private(p: &Path, s: &str) -> Result<()> {
    std::fs::write(p, s)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vip_allocation_skips_used_and_gateway() {
        let mut c = Config::new("r".into(), "1.2.3.4".into(), 1, true).unwrap();
        assert_eq!(c.next_vip().unwrap(), Ipv4Addr::new(10, 77, 0, 2));
        c.clients.push(Client { name: "a".into(), public_key: "x".into(), vip: Ipv4Addr::new(10, 77, 0, 2) });
        assert_eq!(c.next_vip().unwrap(), Ipv4Addr::new(10, 77, 0, 3));
    }

    #[test]
    fn vip_allocation_reports_exhaustion() {
        let mut c = Config::new("r".into(), "1.2.3.4".into(), 1, true).unwrap();
        c.exit.as_mut().unwrap().subnet = "10.0.0.0/30".into();
        c.clients.push(Client { name: "a".into(), public_key: "x".into(), vip: Ipv4Addr::new(10, 0, 0, 2) });
        assert!(c.next_vip().is_err());
    }

    #[test]
    fn toml_roundtrip_and_share_link() {
        let c = Config::new("tokyo".into(), "1.2.3.4".into(), 41820, false).unwrap();
        let c2: Config = toml::from_str(&toml::to_string_pretty(&c).unwrap()).unwrap();
        assert_eq!(c2.private_key().unwrap(), c.private_key().unwrap());
        let l = c.share_link().unwrap();
        assert!(l.starts_with("lagrelay://") && l.contains("@1.2.3.4:41820?name=tokyo&role=bridge&token=lrt_"), "{l}");
        assert_eq!(c2.token().unwrap(), c.token().unwrap());
    }
}
