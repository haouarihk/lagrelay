//! Diagnostics: relay scan, speed test, bufferbloat grading, and ping/traceroute.
use crate::config::{Config, Relay};
use crate::engine::{Engine, RouteSpec};
use crate::ui::fmt_rate;
use anyhow::{bail, Result};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const SCAN_FLOWS: usize = 8;

fn direct(r: &Relay) -> RouteSpec {
    RouteSpec { bridges: vec![], exit: r.clone(), iface: None }
}

/// Measures every configured relay directly. Bridges only report reachability:
/// latency pings end at an exit, so a bridge is timed by its handshake.
pub async fn scan(cfg: &Config) -> Result<()> {
    if cfg.relays.is_empty() {
        bail!("no relays configured; add one with `lagrelay relay add LINK`");
    }
    let private = cfg.private()?;
    println!("{:<16} {:<8} {:>8} {:>8} {:>8} {:>7}  status", "relay", "role", "best", "typical", "worst", "loss");
    for r in &cfg.relays {
        let (tx, _rx) = mpsc::channel(16);
        let t = Instant::now();
        // Several flows, because some ISPs route each one differently.
        match Engine::connect(private, vec![direct(r)], 1, false, SCAN_FLOWS, tx).await {
            Ok(e) => {
                e.settle(Duration::from_millis(2000)).await;
                let s = e.snapshot();
                let mut rtts: Vec<f64> = s.paths.iter().filter(|p| p.alive).map(|p| p.rtt_ms).collect();
                rtts.sort_by(f64::total_cmp);
                let loss = s.paths.iter().filter(|p| p.alive).map(|p| p.loss_pct).fold(0.0, f64::max);
                match (rtts.first(), rtts.get(rtts.len() / 2), rtts.last()) {
                    (Some(a), Some(m), Some(z)) => println!("{:<16} {:<8} {:>5.0} ms {:>5.0} ms {:>5.0} ms {:>6.0}%  ok", r.name, role(r), a, m, z, loss),
                    _ => println!("{:<16} {:<8} {:>8} {:>8} {:>8} {:>7}  connected, but no replies", r.name, role(r), "-", "-", "-", "-"),
                }
                e.close().await;
            }
            Err(e) => {
                let msg = format!("{e:#}");
                if msg.contains("not configured as an exit") {
                    println!("{:<16} {:<8} {:>5.0} ms {:>8} {:>8} {:>7}  ok (bridge, handshake time)", r.name, role(r), t.elapsed().as_secs_f64() * 500.0, "-", "-", "-");
                } else {
                    println!("{:<16} {:<8} {:>8} {:>8} {:>8} {:>7}  {}", r.name, role(r), "-", "-", "-", "-", msg.lines().last().unwrap_or("failed").trim());
                }
            }
        }
    }
    Ok(())
}

fn role(r: &Relay) -> &'static str {
    match r.role {
        crate::config::Role::Bridge => "bridge",
        crate::config::Role::Exit => "exit",
    }
}

async fn connect_exit(cfg: &Config, name: Option<&str>, flows: usize) -> Result<std::sync::Arc<Engine>> {
    let r = match name {
        Some(n) => cfg.relay(n)?.clone(),
        None => cfg
            .relays
            .iter()
            .find(|r| r.role == crate::config::Role::Exit)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no exit relays configured"))?,
    };
    let (tx, _rx) = mpsc::channel(1);
    let e = Engine::connect(cfg.private()?, vec![direct(&r)], 1, false, flows, tx).await?;
    e.settle(Duration::from_millis(500)).await;
    Ok(e)
}

pub struct SpeedResult {
    pub down_bps: f64,
    pub up_bps: f64,
}

/// Throughput against your own relay. Ramps the offered rate until the delivered
/// rate stops keeping up, since UDP has no congestion control to discover it.
pub async fn speedtest(cfg: &Config, relay: Option<&str>, secs: u64) -> Result<SpeedResult> {
    let e = connect_exit(cfg, relay, 1).await?;
    let probe = Duration::from_secs(secs.max(1));
    let ramp = async |up: bool| -> Result<f64> {
        let mut rate = 5_000u32; // kbit/s
        let mut best = 0.0f64;
        // Doubling from 5 Mbit/s stops at about 2.5 Gbit/s, well past any game's needs.
        for _ in 0..10 {
            let (got, el) = if up { e.speed_up(rate, probe).await? } else { e.speed_down(rate, probe).await? };
            let bps = got as f64 / el.as_secs_f64().max(0.001);
            best = best.max(bps);
            let offered = rate as f64 * 125.0;
            println!("  {} offered {:>12}  delivered {:>12}", if up { "up  " } else { "down" }, fmt_rate(offered), fmt_rate(bps));
            if bps < offered * 0.85 {
                break;
            }
            rate = rate.saturating_mul(2);
        }
        Ok(best)
    };
    let down_bps = ramp(false).await?;
    let up_bps = ramp(true).await?;
    e.close().await;
    println!("download {}   upload {}", fmt_rate(down_bps), fmt_rate(up_bps));
    Ok(SpeedResult { down_bps, up_bps })
}

/// Grade from added latency under load; thresholds as commonly used by
/// bufferbloat tests (A < 30 ms extra, down to F at 400 ms or more).
pub fn bufferbloat_grade(added_ms: f64) -> char {
    match added_ms {
        x if x < 5.0 => 'S',
        x if x < 30.0 => 'A',
        x if x < 60.0 => 'B',
        x if x < 200.0 => 'C',
        x if x < 400.0 => 'D',
        _ => 'F',
    }
}

/// Worse than a B is worth fixing. Letters don't sort by quality: S is the best.
pub fn needs_shaping(grade: char) -> bool {
    matches!(grade, 'C' | 'D' | 'F')
}

async fn latency_during(e: &Engine, dur: Duration) -> f64 {
    let end = Instant::now() + dur;
    let mut samples = vec![];
    while Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(100)).await;
        e.send_pings(true).await;
        if let Some(p) = e.snapshot().paths.first() {
            samples.push(p.rtt_ms);
        }
    }
    samples.sort_by(f64::total_cmp);
    samples.get(samples.len() / 2).copied().unwrap_or(0.0)
}

pub async fn bufferbloat(cfg: &Config, relay: Option<&str>) -> Result<()> {
    println!("measuring capacity...");
    let sp = speedtest(cfg, relay, 2).await?;
    let e = connect_exit(cfg, relay, 1).await?;
    let base = latency_during(&e, Duration::from_secs(4)).await;
    println!("idle latency: {base:.1} ms");
    let dur = Duration::from_secs(8);
    let rate_d = (sp.down_bps * 8.0 / 1000.0) as u32;
    let rate_u = (sp.up_bps * 8.0 / 1000.0) as u32;
    let (load, lat) = tokio::join!(e.speed_down(rate_d, dur), latency_during(&e, dur));
    load?;
    println!("under download load: {lat:.1} ms (+{:.1} ms) grade {}", lat - base, bufferbloat_grade(lat - base));
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (load, lat2) = tokio::join!(e.speed_up(rate_u, dur), latency_during(&e, dur));
    load?;
    println!("under upload load:   {lat2:.1} ms (+{:.1} ms) grade {}", lat2 - base, bufferbloat_grade(lat2 - base));
    if needs_shaping(bufferbloat_grade((lat - base).max(lat2 - base))) {
        println!("tip: `lagrelay shape on` limits other traffic to reduce this.");
    }
    e.close().await;
    Ok(())
}

/// Compares a direct path to a game server against each exit's path to it.
pub async fn compare(cfg: &Config, target: SocketAddr) -> Result<()> {
    let SocketAddr::V4(t) = target else { bail!("only IPv4 targets are supported") };
    let timed = async {
        let s = Instant::now();
        tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(target)).await.ok()?.ok()?;
        Some(s.elapsed().as_secs_f64() * 1000.0)
    };
    match timed.await {
        Some(d) => println!("direct (TCP connect): {d:.0} ms"),
        None => println!("direct (TCP connect): no answer on that port"),
    }
    for r in cfg.relays.iter().filter(|r| r.role == crate::config::Role::Exit) {
        let e = match connect_exit(cfg, Some(&r.name), SCAN_FLOWS).await {
            Ok(e) => e,
            Err(err) => {
                println!("{}: unreachable ({err:#})", r.name);
                continue;
            }
        };
        let client = e.snapshot().best_rtt_ms.unwrap_or(0.0);
        let mut p = e.probe(*t.ip(), t.port(), true).await.ok().flatten();
        if p.is_none() {
            p = e.probe(*t.ip(), 0, false).await.ok().flatten();
        }
        match p {
            Some(d) => {
                let via = d.as_secs_f64() * 1000.0;
                println!("via {:<14} {:.0} ms  (you to relay {client:.0} + relay to game {via:.0})", r.name, client + via);
            }
            None => println!("via {:<14} relay cannot reach the target", r.name),
        }
        e.close().await;
    }
    Ok(())
}

/// Runs the OS ping or traceroute tool with a validated target.
pub fn system_trace(target: &str, trace: bool) -> Result<()> {
    if target.is_empty() || !target.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':')) || target.starts_with('-') {
        bail!("invalid host: {target}");
    }
    let (cmd, args): (&str, Vec<&str>) = match (cfg!(windows), trace) {
        (true, true) => ("tracert", vec!["-d", target]),
        (true, false) => ("ping", vec!["-n", "20", target]),
        (false, true) => ("tracepath", vec!["-n", target]),
        (false, false) => ("ping", vec!["-c", "20", target]),
    };
    let st = std::process::Command::new(cmd).args(&args).status().map_err(|e| anyhow::anyhow!("run {cmd}: {e}"))?;
    if !st.success() {
        bail!("{cmd} exited with {st}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grades() {
        assert_eq!(bufferbloat_grade(1.0), 'S');
        assert_eq!(bufferbloat_grade(29.0), 'A');
        assert_eq!(bufferbloat_grade(59.0), 'B');
        assert_eq!(bufferbloat_grade(199.0), 'C');
        assert_eq!(bufferbloat_grade(399.0), 'D');
        assert_eq!(bufferbloat_grade(1000.0), 'F');
    }

    #[test]
    fn shaping_advice_only_for_bad_grades() {
        for g in ['S', 'A', 'B'] {
            assert!(!needs_shaping(g));
        }
        for g in ['C', 'D', 'F'] {
            assert!(needs_shaping(g));
        }
    }

    #[test]
    fn rejects_injection_in_trace_target() {
        assert!(system_trace("1.1.1.1 & calc", false).is_err());
        assert!(system_trace("-c", false).is_err());
        assert!(system_trace("", true).is_err());
    }
}
