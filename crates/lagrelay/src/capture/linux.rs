//! Linux capture: a TUN device plus policy routing for the game's CIDRs.
//!
//! Selection is by destination address. Per-process selection is not available
//! on Linux yet, so a Linux game profile needs at least one CIDR. Game routes live
//! in their own table, so the main table is never edited, and a server that should
//! go direct only needs a rule sending it back to the main table.
use super::{Applier, Book, Capture, CaptureParams, Seen};
use anyhow::{bail, Context, Result};
use lagcore::ip::parse_ipv4;
use lagcore::tun::Tun;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

const DEV: &str = "lagrelay-c0";
const TABLE: &str = "7700";
const PREF_EXEMPT: &str = "7500";
const PREF_DIRECT: &str = "7600";
const PREF_GAME: &str = "7700";
/// Marks LagRelay's own direct pings, so they skip the game routes.
pub const DIRECT_MARK: &str = "7700";
const ZONE: &str = "7700";

fn ip(args: &[&str]) -> Result<String> {
    let o = Command::new("ip").args(args).output().context("run ip (is iproute2 installed?)")?;
    if !o.status.success() {
        bail!("ip {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Rules that let one open socket move between the tunnel and the direct route.
///
/// The kernel records each connection's address translation on its first packet.
/// Tunnel traffic gets its own tracking zone, so a move to direct starts a new
/// record that does get translated. The two MASQUERADE rules cover each direction:
/// a socket opened on one route keeps its address when it moves to the other.
fn move_rules(vip: Ipv4Addr) -> Vec<Vec<String>> {
    let v = vip.to_string();
    let rule = |t: &[&str]| t.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    vec![
        rule(&["raw", "OUTPUT", "-o", DEV, "-j", "CT", "--zone", ZONE]),
        rule(&["raw", "PREROUTING", "-i", DEV, "-j", "CT", "--zone", ZONE]),
        rule(&["nat", "POSTROUTING", "-s", &v, "!", "-o", DEV, "-j", "MASQUERADE"]),
        rule(&["nat", "POSTROUTING", "!", "-s", &v, "-o", DEV, "-j", "MASQUERADE"]),
    ]
}

fn iptables(op: &str, r: &[String]) -> Result<()> {
    let mut args = vec!["-t", r[0].as_str(), op, r[1].as_str()];
    args.extend(r[2..].iter().map(String::as_str));
    let o = Command::new("iptables").args(&args).output().context("run iptables")?;
    if !o.status.success() {
        bail!("iptables {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(())
}

fn delete_rules(pref: &str) -> usize {
    // `ip rule del` removes one match at a time; stop as soon as none are left.
    let mut n = 0;
    while n < 4096 && ip(&["rule", "del", "pref", pref]).is_ok() {
        n += 1;
    }
    n
}

/// Turns a line of `iptables -S` into the arguments that delete it, if it's ours.
pub fn delete_args(line: &str) -> Option<Vec<String>> {
    let rest = line.strip_prefix("-A ")?;
    if !rest.split_whitespace().any(|w| w == DEV) {
        return None;
    }
    Some(std::iter::once("-D".to_string()).chain(rest.split_whitespace().map(str::to_string)).collect())
}

fn delete_iptables_rules() -> usize {
    let mut n = 0;
    for table in ["raw", "nat", "mangle", "filter"] {
        let Ok(o) = Command::new("iptables").args(["-t", table, "-S"]).output() else { continue };
        for line in String::from_utf8_lossy(&o.stdout).lines() {
            if let Some(args) = delete_args(line) {
                let mut cmd = Command::new("iptables");
                cmd.args(["-t", table]).args(&args);
                if cmd.output().is_ok_and(|x| x.status.success()) {
                    n += 1;
                }
            }
        }
    }
    n
}

/// Removes every trace of the tunnel's routing, including what a crash left behind.
/// Returns how many items were removed.
pub fn cleanup_all() -> usize {
    let mut n = 0;
    for p in [PREF_EXEMPT, PREF_DIRECT, PREF_GAME] {
        n += delete_rules(p);
    }
    let _ = ip(&["route", "flush", "table", TABLE]);
    // Deleting the device also removes anything still pointing at it.
    n += ip(&["link", "del", DEV]).is_ok() as usize;
    n + delete_iptables_rules()
}

struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        cleanup_all();
    }
}

fn set_direct_rule(dst: Ipv4Addr, on: bool) {
    let d = format!("{dst}/32");
    let _ = ip(&["rule", "del", "to", &d, "pref", PREF_DIRECT]);
    if on {
        let _ = ip(&["rule", "add", "to", &d, "lookup", "main", "pref", PREF_DIRECT]);
    }
    let _ = ip(&["route", "flush", "cache"]);
}

/// Sends a packet that was already read from the tunnel out through normal routing.
fn raw_socket() -> Result<socket2::Socket> {
    Ok(socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::RAW, Some(socket2::Protocol::from(libc::IPPROTO_RAW)))?)
}

pub async fn start(p: CaptureParams) -> Result<Capture> {
    if !p.matcher.processes.is_empty() {
        eprintln!("note: per-process matching is Windows-only for now; on Linux this game is selected by CIDR");
    }
    if p.matcher.cidrs.is_empty() {
        bail!("on Linux a game profile needs at least one CIDR (lagrelay game add NAME --cidr 1.2.3.0/24)");
    }
    cleanup_all();
    let tun = Arc::new(Tun::create(DEV)?);
    let cleanup = Cleanup;
    ip(&["addr", "add", &format!("{}/32", p.vip), "dev", DEV])?;
    ip(&["link", "set", DEV, "up", "mtu", &lagcore::TUNNEL_MTU.to_string()])?;
    ip(&["route", "replace", "default", "dev", DEV, "table", TABLE])?;
    // Relay traffic must never enter the tunnel, even under a broad game CIDR.
    for r in &p.relay_ips {
        ip(&["rule", "add", "to", &format!("{r}/32"), "lookup", "main", "pref", PREF_EXEMPT])?;
    }
    ip(&["rule", "add", "fwmark", DIRECT_MARK, "lookup", "main", "pref", PREF_EXEMPT])?;
    for (n, l) in &p.matcher.cidrs {
        ip(&["rule", "add", "to", &format!("{n}/{l}"), "lookup", TABLE, "pref", PREF_GAME])?;
    }
    if p.auto_direct {
        for r in move_rules(p.vip) {
            iptables("-A", &r)?;
        }
    }
    let raw = Arc::new(raw_socket().context("open raw socket")?);
    let book: Arc<Mutex<Book<Vec<u8>>>> = Arc::default();
    let (out_tx, out_rx) = mpsc::channel(4096);
    let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(4096);
    let (t1, t2) = (tun.clone(), tun);
    let send_raw = |raw: &socket2::Socket, pkt: &[u8], dst: Ipv4Addr| {
        let _ = raw.send_to(pkt, &SocketAddr::from((dst, 0)).into());
    };

    let (reader_out, reader_book, reader_raw, auto, decide) = (out_tx.clone(), book.clone(), raw.clone(), p.auto_direct, p.decide.clone());
    tokio::spawn(async move {
        let mut b = vec![0u8; 2048];
        while let Ok(n) = t1.read(&mut b).await {
            // Only IPv4 routes point here; anything else is ignored.
            if b[0] >> 4 != 4 {
                continue;
            }
            let pkt = b[..n].to_vec();
            if !auto {
                if reader_out.send(pkt).await.is_err() {
                    break;
                }
                continue;
            }
            let Some(i) = parse_ipv4(&pkt) else { continue };
            let seen = reader_book.lock().unwrap().see(i.dst, pkt);
            match seen {
                Seen::Relay(pkt) => {
                    if reader_out.send(pkt).await.is_err() {
                        break;
                    }
                }
                // Sent just before its direct rule took effect.
                Seen::Direct(pkt) => send_raw(&reader_raw, &pkt, i.dst),
                Seen::HeldNew => {
                    let _ = decide.send(i.dst);
                }
                Seen::Held => {}
            }
        }
    });
    tokio::spawn(async move {
        while let Some(pkt) = in_rx.recv().await {
            let _ = t2.write(&pkt).await;
        }
    });
    let apply: Applier = Arc::new(move |dst, direct, force| {
        // One rule covers all traffic to a server here, including live
        // connections, so a preference alone must not change anything.
        let mut bk = book.lock().unwrap();
        if !force && !bk.is_pending(dst) {
            return;
        }
        let held = bk.resolve(dst, direct);
        drop(bk);
        set_direct_rule(dst, direct);
        for pkt in held {
            if direct {
                send_raw(&raw, &pkt, dst);
            } else {
                let _ = out_tx.try_send(pkt);
            }
        }
    });
    Ok(Capture { outbound: out_rx, inbound: in_tx, guard: Box::new(cleanup), apply, description: format!("TUN {DEV}, routes by CIDR") })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_our_firewall_rules_are_deleted() {
        let a = delete_args("-A POSTROUTING -s 10.77.0.2/32 ! -o lagrelay-c0 -j MASQUERADE").unwrap();
        assert_eq!(a.join(" "), "-D POSTROUTING -s 10.77.0.2/32 ! -o lagrelay-c0 -j MASQUERADE");
        assert!(delete_args("-A POSTROUTING -s 10.0.1.0/24 ! -o docker0 -j MASQUERADE").is_none());
        assert!(delete_args("-A POSTROUTING -o lagrelay-c0x -j MASQUERADE").is_none(), "a similar name isn't ours");
        assert!(delete_args("-P POSTROUTING ACCEPT").is_none());
        assert!(delete_args("-N lagrelay-c0").is_none(), "only rules, never chains");
    }
}
