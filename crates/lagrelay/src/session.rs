//! Runs a connection: picks an exit, builds routes, pumps packets, and
//! reconnects automatically until the user quits.
use crate::capture::{self, Applier, CaptureParams};
use crate::config::{Config, Game, Relay, Role};
use crate::direct::{ping_direct, Action, Track};
use crate::engine::{enumerate_routes, list_interfaces, resolve, Engine, Iface, RouteSpec, Snapshot};
use crate::rules::Matcher;
use anyhow::{anyhow, bail, Context, Result};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

pub struct ConnectOpts {
    pub exit: Option<String>,
    pub routes: Option<usize>,
    pub multi_internet: bool,
    pub max_bridges: Option<usize>,
    pub flows: Option<usize>,
    pub no_direct: bool,
    pub live_switch: bool,
}

/// One game server's route, for display.
#[derive(Debug, Clone)]
pub struct ServerView {
    pub ip: Ipv4Addr,
    pub live_direct: bool,
    pub prefer_direct: bool,
    pub direct_ms: Option<f64>,
    pub relay_ms: Option<f64>,
}

const DIRECT_PROBE_LIMIT: Duration = Duration::from_millis(1500);
/// How long a new server's first packets wait for the tunnel before going direct.
const TUNNEL_WAIT: Duration = Duration::from_secs(10);
const REVIEW_EVERY_TICKS: u32 = 5;
const REVIEW_TICK: Duration = Duration::from_secs(2);
/// Only the most recently contacted servers are re-measured.
const MAX_TRACKED: usize = 12;

/// Measures one server both ways. The relay figure is you to relay plus relay to server.
async fn measure(ip: Ipv4Addr, engine: Option<Arc<Engine>>) -> (Option<f64>, Option<f64>) {
    let relay = async {
        let e = engine?;
        let to_relay = e.snapshot().best_rtt_ms?;
        let onward = tokio::time::timeout(DIRECT_PROBE_LIMIT, e.probe(ip, 0, false)).await.ok()?.ok()??;
        Some(to_relay + onward.as_secs_f64() * 1000.0)
    };
    let direct = async { tokio::time::timeout(DIRECT_PROBE_LIMIT, ping_direct(ip)).await.ok().flatten() };
    tokio::join!(direct, relay)
}

fn apply_actions(apply: &Applier, ip: Ipv4Addr, actions: Vec<Action>) {
    for a in actions {
        match a {
            Action::Prefer { direct } => apply(ip, direct, false),
            Action::Move { direct } => apply(ip, direct, true),
        }
    }
}

/// Decides each new server's route, then keeps both routes under review.
async fn route_chooser(
    mut requests: mpsc::UnboundedReceiver<Ipv4Addr>,
    current: Arc<tokio::sync::RwLock<Option<Arc<Engine>>>>,
    apply: Applier,
    margin: f64,
    live_switch: bool,
    view: Arc<Mutex<Vec<ServerView>>>,
) {
    let mut tracks: Vec<Track> = vec![];
    let mut tick = tokio::time::interval(REVIEW_TICK);
    let mut n = 0u32;
    let publish = |tracks: &[Track]| {
        *view.lock().unwrap() = tracks
            .iter()
            .rev()
            .map(|t| ServerView { ip: t.ip, live_direct: t.live_direct, prefer_direct: t.prefer_direct, direct_ms: t.direct_ms, relay_ms: t.relay_ms })
            .collect();
    };
    // New servers report back here, so measuring one never delays another.
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<(Ipv4Addr, Option<f64>, Option<f64>)>();
    loop {
        tokio::select! {
            r = requests.recv() => {
                let Some(ip) = r else { return };
                let (cur, done) = (current.clone(), done_tx.clone());
                tokio::spawn(async move {
                    // The game can start talking before the tunnel is up. Wait for
                    // it, because the relay can't be compared until then.
                    let until = tokio::time::Instant::now() + TUNNEL_WAIT;
                    let engine = loop {
                        let e = cur.read().await.clone();
                        if e.is_some() || tokio::time::Instant::now() >= until {
                            break e;
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    };
                    let (d, r) = measure(ip, engine).await;
                    let _ = done.send((ip, d, r));
                });
            }
            Some((ip, d, r)) = done_rx.recv() => {
                let t = Track::new(ip, d, r, margin);
                apply(ip, t.live_direct, false);
                tracks.retain(|x| x.ip != ip);
                tracks.push(t);
                if tracks.len() > MAX_TRACKED {
                    tracks.remove(0);
                }
                publish(&tracks);
            }
            _ = tick.tick() => {
                n += 1;
                let engine = current.read().await.clone();
                if engine.is_none() {
                    for t in tracks.iter_mut() {
                        let a = t.relays_down();
                        apply_actions(&apply, t.ip, a);
                    }
                    publish(&tracks);
                }
                if n % REVIEW_EVERY_TICKS == 0 && !tracks.is_empty() {
                    let ips: Vec<Ipv4Addr> = tracks.iter().map(|t| t.ip).collect();
                    let mut set = tokio::task::JoinSet::new();
                    for ip in ips {
                        let e = engine.clone();
                        set.spawn(async move { (ip, measure(ip, e).await) });
                    }
                    while let Some(Ok((ip, (d, r)))) = set.join_next().await {
                        if let Some(t) = tracks.iter_mut().find(|t| t.ip == ip) {
                            let a = t.review(d, r, margin, live_switch);
                            apply_actions(&apply, ip, a);
                        }
                    }
                    publish(&tracks);
                }
            }
        }
    }
}

/// Which interfaces routes should be built on. `None` means the system default.
pub fn route_ifaces(cfg: &Config, multi: bool) -> Result<Vec<Option<Iface>>> {
    if !multi {
        return Ok(vec![None]);
    }
    let mut ifs = list_interfaces();
    if !cfg.settings.interfaces.is_empty() {
        ifs.retain(|i| cfg.settings.interfaces.contains(&i.name));
    }
    if ifs.len() < 2 {
        bail!(
            "Multi Internet needs at least two active networks; found: {}",
            if ifs.is_empty() { "none".to_string() } else { ifs.iter().map(|i| i.name.clone()).collect::<Vec<_>>().join(", ") }
        );
    }
    Ok(ifs.into_iter().map(Some).collect())
}

fn parse_target(s: &str) -> Result<SocketAddr> {
    s.parse().map_err(|_| anyhow!("ping_target '{s}' must be ip:port"))
}

/// Compares exits. The score is the relay's latency to the client plus, when
/// the game has a ping target, the relay's own latency to the game server.
async fn choose_exit(cfg: &Config, game: &Game, specs_for: impl Fn(&Relay) -> Vec<RouteSpec>) -> Result<Relay> {
    let exits: Vec<Relay> = cfg.relays.iter().filter(|r| r.role == Role::Exit).cloned().collect();
    if exits.is_empty() {
        bail!("no exit relays configured; add one with `lagrelay relay add LINK`");
    }
    if exits.len() == 1 {
        return Ok(exits[0].clone());
    }
    let private = cfg.private()?;
    let target = game.ping_target.as_deref().map(parse_target).transpose()?;
    let mut set = tokio::task::JoinSet::new();
    for r in exits {
        let specs = specs_for(&r);
        set.spawn(async move {
            let (tx, _rx) = mpsc::channel(1);
            let run = async {
                // Several flows, so one unlucky path doesn't rule out a good exit.
                let e = Engine::connect(private, specs, 1, false, 6, tx).await?;
                e.settle(Duration::from_millis(800)).await;
                let client = e.snapshot().best_rtt_ms.context("no live route")?;
                let mut server = 0.0;
                if let Some(SocketAddr::V4(t)) = target {
                    let d = e.probe(*t.ip(), t.port(), true).await.ok().flatten();
                    let d = match d {
                        Some(d) => Some(d),
                        None => e.probe(*t.ip(), 0, false).await.ok().flatten(),
                    };
                    server = d.context("exit could not reach the game server")?.as_secs_f64() * 1000.0;
                }
                e.close().await;
                anyhow::Ok(client + server)
            }
            .await;
            (r, run)
        });
    }
    let mut best: Option<(Relay, f64)> = None;
    let mut errs = vec![];
    while let Some(j) = set.join_next().await {
        let (r, res) = j?;
        match res {
            Ok(v) => {
                println!("  exit {}: {v:.0} ms", r.name);
                if best.as_ref().is_none_or(|(_, b)| v < *b) {
                    best = Some((r, v));
                }
            }
            Err(e) => errs.push(format!("{}: {e:#}", r.name)),
        }
    }
    best.map(|(r, _)| r).ok_or_else(|| anyhow!("no exit reachable:\n  {}", errs.join("\n  ")))
}

pub struct Live {
    pub snapshot: Arc<Mutex<Snapshot>>,
    pub status: Arc<Mutex<String>>,
    pub want_routes: Arc<std::sync::atomic::AtomicU32>,
    pub stop: watch::Sender<bool>,
    pub servers: Arc<Mutex<Vec<ServerView>>>,
    pub capture_desc: String,
    pub started: Instant,
    pub game: String,
}

/// Starts the connection in background tasks and returns a live status handle.
/// The returned join handle finishes after the client has shut down cleanly.
pub async fn start(cfg: Config, game: Game, opts: ConnectOpts) -> Result<(Live, tokio::task::JoinHandle<Result<Report>>)> {
    let private = cfg.private()?;
    let matcher = Matcher::from_game(&game)?;
    let multi = opts.multi_internet || cfg.settings.multi_internet;
    let ifaces = route_ifaces(&cfg, multi)?;
    let max_bridges = opts.max_bridges.unwrap_or(cfg.settings.max_bridges);
    let routes = opts.routes.unwrap_or(cfg.settings.routes).max(1);
    let flows = opts.flows.unwrap_or(cfg.settings.flows).max(1);
    let bridges: Vec<Relay> = cfg.relays.clone();
    let ifaces2 = ifaces.clone();
    let specs_for = move |exit: &Relay| enumerate_routes(&bridges, exit, max_bridges, &ifaces2);
    let exit_name = opts.exit.clone().or_else(|| game.exit.clone());
    let exit = match exit_name {
        Some(n) => {
            let r = cfg.relay(&n)?.clone();
            if r.role != Role::Exit {
                bail!("relay {n} is a bridge, not an exit");
            }
            r
        }
        None => {
            println!("comparing exits...");
            choose_exit(&cfg, &game, &specs_for).await?
        }
    };
    let specs = specs_for(&exit);
    let mut relay_ips: Vec<Ipv4Addr> = Vec::new();
    for r in &cfg.relays {
        if let Ok(SocketAddr::V4(a)) = resolve(&r.addr).await {
            relay_ips.push(*a.ip());
        }
    }
    println!("connecting to {} through {} candidate routes...", exit.name, specs.len());
    let (in_probe_tx, _) = mpsc::channel(1);
    // The tunnel address is needed before capture can start, so open a short
    // session first. Addresses are fixed per client, so it won't change.
    let first = Engine::connect(private, specs.clone(), routes, multi, 1, in_probe_tx).await?;
    let vip = first.vip;
    first.close().await;
    drop(first);
    let tunnel_up = Arc::new(AtomicBool::new(false));
    let auto_direct = cfg.settings.auto_direct && !opts.no_direct;
    let live_switch = cfg.settings.live_switch || opts.live_switch;
    let margin = cfg.settings.direct_margin_ms;
    let (decide, requests) = mpsc::unbounded_channel();
    let cap = capture::start(CaptureParams { matcher, vip, relay_ips, block_ipv6: cfg.settings.block_ipv6, tunnel_up: tunnel_up.clone(), auto_direct, decide }).await?;
    let servers: Arc<Mutex<Vec<ServerView>>> = Arc::default();
    let capture_desc = cap.description.clone();

    let snapshot = Arc::new(Mutex::new(Snapshot::default()));
    let status = Arc::new(Mutex::new("connecting".to_string()));
    let want_routes = Arc::new(std::sync::atomic::AtomicU32::new(routes as u32));
    let (stop_tx, stop_rx) = watch::channel(false);
    let live = Live {
        snapshot: snapshot.clone(),
        status: status.clone(),
        want_routes: want_routes.clone(),
        servers: servers.clone(),
        stop: stop_tx,
        capture_desc,
        started: Instant::now(),
        game: game.name.clone(),
    };
    let handle = tokio::spawn(run(private, specs, multi, flows, want_routes, cap, snapshot, status, tunnel_up, stop_rx, exit.name.clone(), game.name.clone(), (requests, margin, live_switch, servers)));
    Ok((live, handle))
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct Report {
    pub game: String,
    pub exit: String,
    pub started_unix: u64,
    pub seconds: u64,
    pub avg_rtt_ms: f64,
    pub min_rtt_ms: f64,
    pub max_rtt_ms: f64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub recovered: u64,
    pub lost: u64,
    pub route_switches: u64,
    pub reconnects: u32,
}

#[allow(clippy::too_many_arguments)]
async fn run(
    private: [u8; 32],
    specs: Vec<RouteSpec>,
    multi: bool,
    flows: usize,
    want_routes: Arc<std::sync::atomic::AtomicU32>,
    cap: capture::Capture,
    snapshot: Arc<Mutex<Snapshot>>,
    status: Arc<Mutex<String>>,
    tunnel_up: Arc<AtomicBool>,
    mut stop: watch::Receiver<bool>,
    exit: String,
    game: String,
    chooser: (mpsc::UnboundedReceiver<Ipv4Addr>, f64, bool, Arc<Mutex<Vec<ServerView>>>),
) -> Result<Report> {
    let capture::Capture { mut outbound, inbound, guard, apply, .. } = cap;
    let start = Instant::now();
    let started_unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let current: Arc<tokio::sync::RwLock<Option<Arc<Engine>>>> = Arc::new(tokio::sync::RwLock::new(None));
    // Persistent pump: survives reconnects so capture never has to restart.
    let c2 = current.clone();
    let pump = tokio::spawn(async move {
        while let Some(pkt) = outbound.recv().await {
            if let Some(e) = c2.read().await.as_ref() {
                e.send_ip(&pkt).await;
            }
        }
    });
    let (requests, margin, live_switch, servers) = chooser;
    let route_task = tokio::spawn(route_chooser(requests, current.clone(), apply, margin, live_switch, servers));
    let mut rep = Report {
        game,
        exit,
        started_unix,
        seconds: 0,
        avg_rtt_ms: 0.0,
        min_rtt_ms: f64::MAX,
        max_rtt_ms: 0.0,
        bytes_up: 0,
        bytes_down: 0,
        recovered: 0,
        lost: 0,
        route_switches: 0,
        reconnects: 0,
    };
    let (mut rtt_sum, mut rtt_n) = (0.0f64, 0u64);
    let mut backoff = Duration::from_millis(500);
    let mut first_round = true;
    'outer: while !*stop.borrow() {
        *status.lock().unwrap() = if first_round { "connecting".into() } else { "reconnecting".into() };
        let want = want_routes.load(Ordering::Relaxed) as usize;
        let engine = tokio::select! {
            r = Engine::connect(private, specs.clone(), want, multi, flows, inbound.clone()) => r,
            _ = stop.changed() => break 'outer,
        };
        let engine = match engine {
            Ok(e) => e,
            Err(e) => {
                *status.lock().unwrap() = format!("reconnecting: {}", e.to_string().lines().next().unwrap_or(""));
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = stop.changed() => break 'outer,
                }
                backoff = (backoff * 2).min(Duration::from_secs(10));
                continue;
            }
        };
        backoff = Duration::from_millis(500);
        if !first_round {
            rep.reconnects += 1;
        }
        first_round = false;
        engine.settle(Duration::from_millis(600)).await;
        engine.prune();
        *current.write().await = Some(engine.clone());
        tunnel_up.store(true, Ordering::Relaxed);
        *status.lock().unwrap() = "connected".into();
        let e2 = engine.clone();
        let mut maint = tokio::spawn(async move { e2.run_maintenance().await });
        let mut ui = tokio::time::interval(Duration::from_millis(250));
        let mut last = Snapshot::default();
        loop {
            tokio::select! {
                _ = ui.tick() => {
                    engine.want_routes.store(want_routes.load(Ordering::Relaxed), Ordering::Relaxed);
                    let s = engine.snapshot();
                    if let Some(r) = s.best_rtt_ms {
                        rtt_sum += r; rtt_n += 1;
                        rep.min_rtt_ms = rep.min_rtt_ms.min(r);
                        rep.max_rtt_ms = rep.max_rtt_ms.max(r);
                    }
                    last = s.clone();
                    *snapshot.lock().unwrap() = s;
                }
                _ = &mut maint => break,
                _ = stop.changed() => {
                    maint.abort();
                    engine.close().await;
                    add_totals(&mut rep, &last);
                    break 'outer;
                }
            }
        }
        // All routes died. Stop tunnelling new flows until a new session is up.
        tunnel_up.store(false, Ordering::Relaxed);
        *current.write().await = None;
        add_totals(&mut rep, &last);
    }
    pump.abort();
    route_task.abort();
    drop(guard); // Stops capture and removes routes.
    *current.write().await = None;
    drop(inbound); // Lets the inject thread finish, so the capture handle closes.
    rep.seconds = start.elapsed().as_secs();
    rep.avg_rtt_ms = if rtt_n > 0 { rtt_sum / rtt_n as f64 } else { 0.0 };
    if rep.min_rtt_ms == f64::MAX {
        rep.min_rtt_ms = 0.0;
    }
    Ok(rep)
}

fn add_totals(r: &mut Report, s: &Snapshot) {
    r.bytes_up += s.bytes_up;
    r.bytes_down += s.bytes_down;
    r.recovered += s.recovered;
    r.lost += s.lost;
    r.route_switches += s.switches;
}

fn history_path() -> std::path::PathBuf {
    crate::config::home().join("history.jsonl")
}

pub fn save_report(r: &Report) -> Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(crate::config::home())?;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(history_path())?;
    writeln!(f, "{}", serde_json::to_string(r)?)?;
    Ok(())
}

pub fn load_reports() -> Result<Vec<Report>> {
    let s = match std::fs::read_to_string(history_path()) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };
    // Skip damaged lines, such as one cut short by a crash mid-write.
    Ok(s.lines().filter_map(|l| serde_json::from_str(l).ok()).collect())
}
