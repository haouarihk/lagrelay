//! Decides which captured packets belong to the selected game.
use crate::config::Game;
use anyhow::{anyhow, Result};
use lagcore::ip::{cidr_contains, is_local_scope, parse_cidr};
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct Matcher {
    pub processes: Vec<String>,
    pub cidrs: Vec<(Ipv4Addr, u8)>,
    /// Applied by the Windows backend; Linux selects by route, so by CIDR only.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub ports: Vec<(u16, u16)>,
}

pub fn parse_port_range(s: &str) -> Result<(u16, u16)> {
    let bad = || anyhow!("bad port range '{s}'");
    let (a, b) = match s.split_once('-') {
        Some((a, b)) => (a.trim().parse().map_err(|_| bad())?, b.trim().parse().map_err(|_| bad())?),
        None => {
            let p: u16 = s.trim().parse().map_err(|_| bad())?;
            (p, p)
        }
    };
    if a > b {
        return Err(bad());
    }
    Ok((a, b))
}

impl Matcher {
    pub fn from_game(g: &Game) -> Result<Matcher> {
        let cidrs = g.cidrs.iter().map(|c| parse_cidr(c).ok_or_else(|| anyhow!("bad CIDR '{c}'"))).collect::<Result<Vec<_>>>()?;
        let ports = g.ports.iter().map(|p| parse_port_range(p)).collect::<Result<Vec<_>>>()?;
        let processes: Vec<String> = g.processes.iter().map(|p| p.to_ascii_lowercase()).collect();
        if processes.is_empty() && cidrs.is_empty() && ports.is_empty() {
            return Err(anyhow!("game '{}' has no processes, CIDRs or ports, so it would match nothing", g.name));
        }
        Ok(Matcher { processes, cidrs, ports })
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn wants_process(&self, name: &str) -> bool {
        self.processes.is_empty() || self.processes.iter().any(|p| p.eq_ignore_ascii_case(name))
    }

    /// Destination part of the rule. Local-scope addresses (LAN, multicast and
    /// so on) only match when a CIDR names them explicitly.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn wants_dest(&self, dst: Ipv4Addr, port: u16, is_fragment: bool) -> bool {
        let explicit = self.cidrs.iter().any(|(n, l)| cidr_contains(*n, *l, dst));
        if !self.cidrs.is_empty() && !explicit {
            return false;
        }
        if is_local_scope(dst) && !explicit {
            return false;
        }
        // Non-first fragments carry no port; the flow table has already decided.
        is_fragment || self.ports.is_empty() || self.ports.iter().any(|(a, b)| (*a..=*b).contains(&port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn game(p: &[&str], c: &[&str], o: &[&str]) -> Game {
        Game {
            name: "g".into(),
            processes: p.iter().map(|s| s.to_string()).collect(),
            cidrs: c.iter().map(|s| s.to_string()).collect(),
            ports: o.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn port_ranges() {
        assert_eq!(parse_port_range("80").unwrap(), (80, 80));
        assert_eq!(parse_port_range("10-20").unwrap(), (10, 20));
        assert!(parse_port_range("20-10").is_err());
        assert!(parse_port_range("x").is_err());
        assert!(parse_port_range("70000").is_err());
    }

    #[test]
    fn empty_rule_is_rejected() {
        assert!(Matcher::from_game(&game(&[], &[], &[])).is_err());
        assert!(Matcher::from_game(&game(&["a.exe"], &["bad"], &[])).is_err());
    }

    #[test]
    fn process_match_is_case_insensitive() {
        let m = Matcher::from_game(&game(&["CS2.exe"], &[], &[])).unwrap();
        assert!(m.wants_process("cs2.EXE"));
        assert!(!m.wants_process("chrome.exe"));
    }

    #[test]
    fn dest_rules() {
        let pubip: Ipv4Addr = "8.8.8.8".parse().unwrap();
        let lan: Ipv4Addr = "192.168.1.9".parse().unwrap();
        let m = Matcher::from_game(&game(&["g.exe"], &[], &[])).unwrap();
        assert!(m.wants_dest(pubip, 1, false));
        assert!(!m.wants_dest(lan, 1, false), "LAN stays direct");
        let m = Matcher::from_game(&game(&[], &["192.168.1.0/24"], &["27000-27100"])).unwrap();
        assert!(m.wants_dest(lan, 27015, false), "explicit CIDR overrides local scope");
        assert!(!m.wants_dest(lan, 80, false));
        assert!(m.wants_dest(lan, 0, true), "fragment has no port");
        assert!(!m.wants_dest(pubip, 27015, false));
    }
}
