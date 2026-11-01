//! DNS optimizer: benchmarks public resolvers, then applies or resets the choice.
use anyhow::{bail, Context, Result};
use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

pub const SERVERS: &[(&str, &str, &str)] = &[
    ("Cloudflare", "1.1.1.1", "1.0.0.1"),
    ("Google", "8.8.8.8", "8.8.4.4"),
    ("Quad9", "9.9.9.9", "149.112.112.112"),
    ("OpenDNS", "208.67.222.222", "208.67.220.220"),
    ("AdGuard", "94.140.14.14", "94.140.15.15"),
    ("Control D", "76.76.2.0", "76.76.10.0"),
    ("Level3", "4.2.2.1", "4.2.2.2"),
];

/// An A-record query for `name`.
pub fn build_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

/// True when `r` answers query `id` with no error.
pub fn is_good_reply(r: &[u8], id: u16) -> bool {
    r.len() >= 12 && r[..2] == id.to_be_bytes() && r[2] & 0x80 != 0 && r[3] & 0x0F == 0
}

const NAMES: [&str; 4] = ["steamcommunity.com", "riotgames.com", "ea.com", "epicgames.com"];

async fn query(server: Ipv4Addr, name: &str) -> Option<Duration> {
    let s = UdpSocket::bind(("0.0.0.0", 0)).await.ok()?;
    s.connect(SocketAddr::from((server, 53))).await.ok()?;
    let id: u16 = rand::random();
    let t = Instant::now();
    s.send(&build_query(id, name)).await.ok()?;
    let mut b = [0u8; 1500];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(2), s.recv(&mut b)).await.ok()?.ok()?;
        if is_good_reply(&b[..n], id) {
            return Some(t.elapsed());
        }
    }
}

pub struct DnsResult {
    pub name: &'static str,
    pub primary: &'static str,
    pub secondary: &'static str,
    pub avg_ms: Option<f64>,
    pub failures: usize,
}

pub async fn benchmark() -> Vec<DnsResult> {
    let mut set = tokio::task::JoinSet::new();
    for &(name, a, b) in SERVERS {
        set.spawn(async move {
            let ip: Ipv4Addr = a.parse().expect("built-in address");
            let (mut times, mut failures) = (vec![], 0);
            for _ in 0..3 {
                for n in NAMES {
                    match query(ip, n).await {
                        Some(d) => times.push(d.as_secs_f64() * 1000.0),
                        None => failures += 1,
                    }
                }
            }
            // The fastest answers are cache hits, which match what a game sees
            // once the resolver has warmed up; the average includes both.
            let avg_ms = (!times.is_empty()).then(|| times.iter().sum::<f64>() / times.len() as f64);
            DnsResult { name, primary: a, secondary: b, avg_ms, failures }
        });
    }
    let mut out = vec![];
    while let Some(Ok(r)) = set.join_next().await {
        out.push(r);
    }
    sort_results(&mut out);
    out
}

/// Reliable servers first, fastest first; a server that dropped queries or never
/// answered is ranked below any that answered them all.
pub fn sort_results(v: &mut [DnsResult]) {
    v.sort_by(|a, b| (a.failures > 0, a.avg_ms.unwrap_or(f64::MAX)).partial_cmp(&(b.failures > 0, b.avg_ms.unwrap_or(f64::MAX))).unwrap_or(std::cmp::Ordering::Equal));
}

fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let o = Command::new(cmd).args(args).output().with_context(|| format!("run {cmd}"))?;
    if !o.status.success() {
        bail!("{cmd} failed: {}{}", String::from_utf8_lossy(&o.stderr).trim(), String::from_utf8_lossy(&o.stdout).trim());
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// The interface with the default route: its index on Windows (names can be
/// localised, and PowerShell's console encoding garbles them), its name on Linux.
pub fn active_iface() -> Result<String> {
    if cfg!(windows) {
        let o = run("powershell", &["-NoProfile", "-Command", "(Find-NetRoute -RemoteIPAddress 1.1.1.1 | Select-Object -First 1).InterfaceIndex"])?;
        let n = o.trim();
        if n.is_empty() || !n.chars().all(|c| c.is_ascii_digit()) {
            bail!("no active network adapter found");
        }
        Ok(n.to_string())
    } else {
        let o = run("ip", &["-4", "route", "show", "default"])?;
        let mut it = o.split_whitespace();
        while let Some(t) = it.next() {
            if t == "dev" {
                if let Some(d) = it.next() {
                    return Ok(d.to_string());
                }
            }
        }
        bail!("no default route found")
    }
}

/// Parses the registry NameServer value, "1.1.1.1,8.8.8.8" or sometimes space-separated.
pub fn parse_name_servers(s: &str) -> Vec<String> {
    s.split([',', ' ', '\r', '\n']).map(str::trim).filter(|a| a.parse::<Ipv4Addr>().is_ok()).map(str::to_string).collect()
}

/// Static servers set on the interface. Empty means they come from the network
/// automatically, which is the state an undo must return to.
fn configured_servers(iface: &str) -> Vec<String> {
    if !cfg!(windows) {
        return vec![];
    }
    let cmd = format!(
        "(Get-ItemProperty \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$((Get-NetAdapter -InterfaceIndex {iface}).InterfaceGuid)\").NameServer"
    );
    run("powershell", &["-NoProfile", "-Command", &cmd]).map(|o| parse_name_servers(&o)).unwrap_or_default()
}

/// Sets the interface's servers; an empty list returns to automatic. The values
/// may come from the user-writable state file, so they are always validated.
pub fn set_servers(iface: &str, servers: &[String]) -> Result<()> {
    if servers.iter().any(|a| a.parse::<Ipv4Addr>().is_err()) {
        bail!("invalid DNS server address");
    }
    if cfg!(windows) {
        if iface.is_empty() || !iface.chars().all(|c| c.is_ascii_digit()) {
            bail!("invalid interface index '{iface}'");
        }
        let action = if servers.is_empty() {
            "-ResetServerAddresses".to_string()
        } else {
            format!("-ServerAddresses {}", servers.iter().map(|a| format!("'{a}'")).collect::<Vec<_>>().join(","))
        };
        run("powershell", &["-NoProfile", "-Command", &format!("Set-DnsClientServerAddress -InterfaceIndex {iface} {action}")])?;
    } else if servers.is_empty() {
        run("resolvectl", &["revert", iface])?;
    } else {
        let mut args = vec!["dns", iface];
        args.extend(servers.iter().map(String::as_str));
        run("resolvectl", &args).context("this needs systemd-resolved and root")?;
    }
    flush()
}

/// Applies servers and returns what's needed to undo the change.
pub fn apply(primary: Ipv4Addr, secondary: Option<Ipv4Addr>) -> Result<(String, Vec<String>)> {
    let i = active_iface()?;
    let previous = configured_servers(&i);
    let mut list = vec![primary.to_string()];
    list.extend(secondary.map(|s| s.to_string()));
    set_servers(&i, &list)?;
    println!("DNS now {}", list.join(", "));
    Ok((i, previous))
}

pub fn reset() -> Result<()> {
    set_servers(&active_iface()?, &[])?;
    println!("DNS reset to the network default");
    Ok(())
}

pub fn flush() -> Result<()> {
    if cfg!(windows) {
        run("ipconfig", &["/flushdns"])?;
    } else {
        // Not every distribution runs systemd-resolved; there is nothing to flush then.
        let _ = run("resolvectl", &["flush-caches"]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_encoding() {
        let q = build_query(0x1234, "a.bc");
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(&q[12..], &[1, b'a', 2, b'b', b'c', 0, 0, 1, 0, 1]);
    }

    #[test]
    fn reply_validation() {
        let mut r = vec![0x12, 0x34, 0x81, 0x80];
        r.resize(12, 0);
        assert!(is_good_reply(&r, 0x1234));
        assert!(!is_good_reply(&r, 0x9999), "wrong id");
        assert!(!is_good_reply(&r[..5], 0x1234), "short");
        r[3] = 0x83; // NXDOMAIN
        assert!(!is_good_reply(&r, 0x1234));
        r[3] = 0x80;
        r[2] = 0x01; // not a response
        assert!(!is_good_reply(&r, 0x1234));
    }

    #[test]
    fn ranking_prefers_reliable_then_fast() {
        let mk = |name, avg, failures| DnsResult { name, primary: "", secondary: "", avg_ms: avg, failures };
        let mut v = vec![mk("flaky", Some(1.0), 1), mk("slow", Some(50.0), 0), mk("fast", Some(5.0), 0), mk("dead", None, 12)];
        sort_results(&mut v);
        assert_eq!(v.iter().map(|r| r.name).collect::<Vec<_>>(), ["fast", "slow", "flaky", "dead"]);
    }

    #[test]
    fn name_server_parsing() {
        assert_eq!(parse_name_servers("1.1.1.1,8.8.8.8\r\n"), ["1.1.1.1", "8.8.8.8"]);
        assert_eq!(parse_name_servers("9.9.9.9 149.112.112.112"), ["9.9.9.9", "149.112.112.112"]);
        assert!(parse_name_servers("\r\n").is_empty());
        assert!(parse_name_servers("not;an;ip").is_empty());
    }

    #[test]
    fn set_servers_rejects_tampered_values() {
        assert!(set_servers("eth0", &["1.1.1.1'; calc; '".to_string()]).is_err());
    }

    #[test]
    fn builtin_addresses_parse() {
        for (_, a, b) in SERVERS {
            a.parse::<Ipv4Addr>().unwrap();
            b.parse::<Ipv4Addr>().unwrap();
        }
    }
}
