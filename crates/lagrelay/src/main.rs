//! LagRelay: route game traffic through relays you host yourself.
mod capture;
mod config;
mod diag;
mod direct;
mod dns;
mod engine;
mod instance;
mod presets;
mod rules;
mod session;
mod system;
mod ui;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use config::{Config, Game, Relay, Role};
use lagcore::session::{encode_key, public_from_private};
use session::{ConnectOpts, Live};
use std::io::IsTerminal;
use std::time::Duration;
use system::boost::{self, GameInfo};

#[derive(Parser)]
#[command(name = "lagrelay", version, about = "Route game traffic through relays you host yourself")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// One command to tune the PC and connect: `lagrelay optimize cs2` or `faceit`
    Optimize {
        /// cs2 or faceit
        preset: Option<String>,
        /// Use this exit relay instead of choosing automatically
        #[arg(long)]
        exit: Option<String>,
        /// Only apply PC tweaks; don't relay any traffic
        #[arg(long)]
        tweaks_only: bool,
        /// Also switch to the fastest DNS server
        #[arg(long)]
        dns: bool,
        /// Leave tweaks applied after quitting
        #[arg(long)]
        keep: bool,
        /// Undo everything an earlier run left applied
        #[arg(long)]
        revert: bool,
        /// Print status lines instead of the dashboard
        #[arg(long)]
        plain: bool,
    },
    /// Stop routing through relays. Traffic goes back to your normal connection
    #[command(visible_alias = "stop", visible_alias = "disable")]
    Off,
    /// Print this client's public key, to authorize it on your relays
    Key,
    /// Manage relays
    Relay {
        #[command(subcommand)]
        cmd: RelayCmd,
    },
    /// Manage game profiles
    Game {
        #[command(subcommand)]
        cmd: GameCmd,
    },
    /// Connect a game profile through your relays
    Connect {
        game: String,
        #[arg(long)]
        exit: Option<String>,
        /// Routes carrying a copy of each packet
        #[arg(long)]
        routes: Option<usize>,
        /// Use every network interface at once
        #[arg(long)]
        multi_internet: bool,
        /// Most bridges allowed in one route (0-2)
        #[arg(long)]
        max_bridges: Option<usize>,
        /// UDP flows to try when looking for the fastest path; 1 turns this off
        #[arg(long)]
        flows: Option<usize>,
        /// Always use the relay, even for servers where direct is faster
        #[arg(long)]
        no_direct: bool,
        /// Also move live connections when the other route stays better; may drop you from a match
        #[arg(long)]
        live_switch: bool,
        #[arg(long)]
        plain: bool,
    },
    /// Test latency to every relay
    Scan,
    /// Network diagnostics
    Diag {
        #[command(subcommand)]
        cmd: DiagCmd,
    },
    /// DNS optimizer
    Dns {
        #[command(subcommand)]
        cmd: DnsCmd,
    },
    /// Individual reversible PC tweaks
    Boost {
        #[command(subcommand)]
        cmd: BoostCmd,
    },
    /// Trim idle memory from background apps (Windows)
    Ram {
        /// Executables to leave alone
        #[arg(long)]
        allow: Vec<String>,
    },
    /// Limit bulk traffic to keep latency low
    Shape {
        #[command(subcommand)]
        cmd: ShapeCmd,
    },
    /// Show CPU, RAM, GPU and networks
    Sys,
    /// Show past connections
    History,
    /// Check that this PC is ready
    Doctor,
}

#[derive(Subcommand)]
enum RelayCmd {
    /// Add a relay from its lagrelay:// link
    Add { link: String },
    List,
    Rm { name: String },
}

#[derive(Subcommand)]
enum GameCmd {
    Add {
        name: String,
        /// Executable name, e.g. game.exe (repeatable, Windows)
        #[arg(long = "process")]
        processes: Vec<String>,
        /// Destination network (repeatable; required on Linux)
        #[arg(long = "cidr")]
        cidrs: Vec<String>,
        /// Destination port or range (repeatable)
        #[arg(long = "port")]
        ports: Vec<String>,
        #[arg(long)]
        exit: Option<String>,
        /// Game server ip:port used to compare exits
        #[arg(long)]
        ping_target: Option<String>,
    },
    List,
    Rm { name: String },
}

#[derive(Subcommand)]
enum DiagCmd {
    /// Throughput to a relay
    Speed {
        #[arg(long)]
        relay: Option<String>,
        #[arg(long, default_value_t = 2)]
        secs: u64,
    },
    /// Latency under load, graded
    Bufferbloat {
        #[arg(long)]
        relay: Option<String>,
    },
    /// Direct path vs each exit, for one game server ip:port
    Compare { target: std::net::SocketAddr },
    Ping { host: String },
    Trace { host: String },
}

#[derive(Subcommand)]
enum DnsCmd {
    /// Rank public DNS servers from this network
    Test,
    /// Apply a server: an IP address, or "fastest"
    Apply { server: String, secondary: Option<std::net::Ipv4Addr> },
    /// Return to the network's default DNS
    Reset,
    Flush,
}

#[derive(Subcommand)]
enum BoostCmd {
    List,
    /// Apply tweaks by name, or "all"
    Apply {
        names: Vec<String>,
        /// Executable for the qos and priority tweaks (repeatable)
        #[arg(long = "exe")]
        exes: Vec<String>,
        /// Full executable path for the gpu tweak (repeatable)
        #[arg(long = "path")]
        paths: Vec<String>,
    },
    /// Undo every applied tweak
    Revert,
}

#[derive(Subcommand)]
enum ShapeCmd {
    /// Limit traffic. Without --rate, measures your relay and uses half the uplink
    On {
        #[arg(long)]
        rate: Option<String>,
        /// Executables to limit (Windows; default: common browsers and sync apps)
        #[arg(long = "app")]
        apps: Vec<String>,
    },
    Off,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Optimize { preset, exit, tweaks_only, dns, keep, revert, plain } => {
            if revert {
                return boost::revert_all();
            }
            let Some(preset) = preset else { bail!("say which: lagrelay optimize cs2  or  lagrelay optimize faceit") };
            optimize(&preset, exit, tweaks_only, dns, keep, plain).await
        }
        Cmd::Off => off(),
        Cmd::Key => {
            let c = Config::load_or_create()?;
            println!("{}", encode_key(&public_from_private(&c.private()?)?));
            eprintln!("authorize it on each relay: lagrelayd add-client MY-PC <this key>");
            Ok(())
        }
        Cmd::Relay { cmd } => relay_cmd(cmd),
        Cmd::Game { cmd } => game_cmd(cmd),
        Cmd::Connect { game, exit, routes, multi_internet, max_bridges, flows, no_direct, live_switch, plain } => {
            let _session = instance::begin_session()?;
            let c = Config::load_or_create()?;
            let g = c.game(&game)?.clone();
            let live = session::start(c, g, ConnectOpts { exit, routes, multi_internet, max_bridges, flows, no_direct, live_switch }).await?;
            supervise(live, plain).await
        }
        Cmd::Scan => diag::scan(&Config::load_or_create()?).await,
        Cmd::Diag { cmd } => {
            let c = Config::load_or_create()?;
            match cmd {
                DiagCmd::Speed { relay, secs } => diag::speedtest(&c, relay.as_deref(), secs).await.map(|_| ()),
                DiagCmd::Bufferbloat { relay } => diag::bufferbloat(&c, relay.as_deref()).await,
                DiagCmd::Compare { target } => diag::compare(&c, target).await,
                DiagCmd::Ping { host } => diag::system_trace(&host, false),
                DiagCmd::Trace { host } => diag::system_trace(&host, true),
            }
        }
        Cmd::Dns { cmd } => dns_cmd(cmd).await,
        Cmd::Boost { cmd } => match cmd {
            BoostCmd::List => {
                let st = boost::load_state();
                for t in boost::TWEAKS {
                    let on = st.applied.iter().any(|(n, _)| n == t.name || n.starts_with(&format!("{}:", t.name)));
                    println!("{} {:<10} {}", if on { "*" } else { " " }, t.name, t.desc);
                }
                Ok(())
            }
            BoostCmd::Apply { names, exes, paths } => {
                let all: Vec<&str> = boost::TWEAKS.iter().map(|t| t.name).collect();
                let sel: Vec<&str> = if names.iter().any(|n| n == "all") { all } else { names.iter().map(String::as_str).collect() };
                if sel.is_empty() {
                    bail!("name at least one tweak, or \"all\"; see `lagrelay boost list`");
                }
                boost::apply(&sel, &GameInfo { exes, paths }).map(|_| ())
            }
            BoostCmd::Revert => boost::revert_all(),
        },
        Cmd::Ram { mut allow } => {
            // Your games are left alone along with anything you name.
            allow.extend(Config::load_or_create()?.games.into_iter().flat_map(|g| g.processes));
            system::ram::clean(&allow)
        }
        Cmd::Shape { cmd } => match cmd {
            ShapeCmd::On { rate, apps } => {
                let bps = match rate {
                    Some(r) => system::shaper::parse_rate(&r)?,
                    None => {
                        let c = Config::load_or_create()?;
                        (diag::speedtest(&c, None, 2).await?.up_bps * 8.0 * 0.5) as u64
                    }
                };
                system::shaper::on(bps.max(64_000), &apps)
            }
            ShapeCmd::Off => system::shaper::off(),
        },
        Cmd::Sys => {
            system::monitor::print();
            Ok(())
        }
        Cmd::History => {
            println!("{:<12} {:<12} {:>8} {:>7} {:>7} {:>10} {:>10} {:>9}", "game", "exit", "time", "avg ms", "max ms", "sent", "received", "recovered");
            for r in session::load_reports()? {
                println!("{:<12} {:<12} {:>8} {:>7.0} {:>7.0} {:>10} {:>10} {:>9}", r.game, r.exit, ui::fmt_uptime(r.seconds), r.avg_rtt_ms, r.max_rtt_ms, ui::fmt_bytes(r.bytes_up), ui::fmt_bytes(r.bytes_down), r.recovered);
            }
            Ok(())
        }
        Cmd::Doctor => doctor(),
    }
}

/// `lagrelay optimize`: tune the PC, connect, show the dashboard, restore on quit.
async fn optimize(preset: &str, exit: Option<String>, tweaks_only: bool, use_dns: bool, keep: bool, plain: bool) -> Result<()> {
    let p = presets::find(preset)?;
    let _session = instance::begin_session()?;
    println!("Optimizing for {}", p.title);
    for n in p.notes {
        println!("note: {n}");
    }
    if !system::is_elevated() {
        println!("warning: not running as Administrator, so most tweaks and the tunnel will fail.");
    }
    let mut cfg = Config::load_or_create()?;
    // Keep the user's own edits to the profile, if there are any.
    if !cfg.games.iter().any(|g| g.name.eq_ignore_ascii_case(p.key)) {
        cfg.games.push(p.to_game());
        cfg.save()?;
    }
    let game = cfg.game(p.key)?.clone();

    println!("\nPC tweaks:");
    let paths = if cfg!(windows) { presets::find_cs2().into_iter().collect() } else { vec![] };
    boost::apply(p.tweaks, &GameInfo { exes: game.processes.clone(), paths })?;
    let timer = boost::hold_timer_resolution();
    match &timer {
        Ok(_) => println!("  + timer: 0.5 ms resolution held while running"),
        Err(e) => println!("  ! timer: {e:#}"),
    }
    if use_dns {
        let best = dns::benchmark().await.into_iter().find(|r| r.avg_ms.is_some() && r.failures == 0);
        match best {
            Some(b) => {
                match dns::apply(b.primary.parse()?, b.secondary.parse().ok()) {
                    Ok((iface, servers)) => {
                        boost::record("dns", boost::Undo::DnsRestore { iface, servers })?;
                        println!("  + dns: {} ({:.0} ms)", b.name, b.avg_ms.unwrap_or(0.0));
                    }
                    Err(e) => println!("  ! dns: {e:#}"),
                }
            }
            None => println!("  ! dns: no public DNS server answered reliably"),
        }
    }

    let has_exit = cfg.relays.iter().any(|r| r.role == Role::Exit);
    let mut connected = false;
    if tweaks_only {
        println!("\nTweaks only: no traffic is being relayed.");
    } else if !has_exit {
        println!("\nNo relay configured, so only tweaks are active.\nTo relay traffic, set one up (see README) and run: lagrelay relay add LINK");
    } else {
        println!();
        match session::start(cfg, game, ConnectOpts { exit, routes: None, multi_internet: false, max_bridges: None, flows: None, no_direct: false, live_switch: false }).await {
            Ok(live) => {
                connected = true;
                if let Err(e) = supervise(live, plain).await {
                    println!("connection ended with an error: {e:#}");
                }
            }
            Err(e) => println!("Could not start the tunnel, so traffic stays direct and only tweaks are active.\nReason: {e:#}"),
        }
    }
    if !connected {
        println!("\nPress Ctrl+C when you've finished playing, or run: lagrelay off");
        wait_for_shutdown_signal().await?;
    }
    drop(timer);
    if keep {
        println!("Tweaks left applied. Undo them with: lagrelay optimize --revert");
    } else {
        println!("Restoring PC settings:");
        boost::revert_all()?;
    }
    Ok(())
}

async fn supervise(started: (Live, tokio::task::JoinHandle<Result<session::Report>>), plain: bool) -> Result<()> {
    let (live, handle) = started;
    let live = std::sync::Arc::new(live);
    if plain || !std::io::stdout().is_terminal() {
        let l2 = live.clone();
        let printer = tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(2));
            loop {
                t.tick().await;
                let s = l2.snapshot.lock().unwrap().clone();
                let st = l2.status.lock().unwrap().clone();
                let routes: Vec<String> = s.paths.iter().filter(|p| p.active).map(|p| format!("{} {:.0}ms", p.label, p.rtt_ms)).collect();
                let servers: Vec<String> = l2.servers.lock().unwrap().iter().map(|v| format!("{} {}", v.ip, ui::route_name(v.live_direct))).collect();
                println!("[{st}] exit={} routes=[{}] servers=[{}] up={} down={} recovered={} lost={} switches={}", s.exit, routes.join(", "), servers.join(", "), ui::fmt_bytes(s.bytes_up), ui::fmt_bytes(s.bytes_down), s.recovered, s.lost, s.switches);
            }
        });
        wait_for_shutdown_signal().await?;
        printer.abort();
    } else {
        let l2 = live.clone();
        // Set by `lagrelay off` or a signal: raw mode means no Ctrl+C reaches us here.
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (s2, s3) = (stop.clone(), stop.clone());
        let watcher = tokio::spawn(async move {
            let _ = wait_for_shutdown_signal().await;
            s2.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        tokio::task::spawn_blocking(move || ui::dashboard(&l2, &s3)).await??;
        watcher.abort();
    }
    let _ = live.stop.send(true);
    let report = handle.await??;
    println!(
        "session: {} on {} for {}, average ping {:.0} ms, {} packets recovered, {} route switches, {} reconnects",
        report.game,
        report.exit,
        ui::fmt_uptime(report.seconds),
        report.avg_rtt_ms,
        report.recovered,
        report.route_switches,
        report.reconnects
    );
    session::save_report(&report)
}

/// Returns on Ctrl+C, a termination signal, or a request from `lagrelay off`.
async fn wait_for_shutdown_signal() -> Result<()> {
    let off = async {
        let mut t = tokio::time::interval(Duration::from_millis(300));
        loop {
            t.tick().await;
            if instance::stop_requested() {
                return;
            }
        }
    };
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => r?,
            _ = term.recv() => {}
            _ = off => {}
        }
    }
    #[cfg(not(unix))]
    tokio::select! {
        r = tokio::signal::ctrl_c() => r?,
        _ = off => {}
    }
    Ok(())
}

/// `lagrelay off`: stops the session, and clears anything a crash left behind.
fn off() -> Result<()> {
    if cfg!(target_os = "linux") && !system::is_elevated() {
        bail!("this needs root: sudo lagrelay off");
    }
    let r = instance::stop_session()?;
    let leftovers = capture::cleanup_leftovers();
    match (r.was_running, r.forced) {
        (true, false) => println!("LagRelay stopped. Your traffic is back on your normal connection."),
        (true, true) => println!("LagRelay didn't respond, so it was force-stopped. Your traffic is back on your normal connection."),
        (false, _) if leftovers > 0 => println!("LagRelay wasn't running, but a previous session left routing behind. It's cleared, and your traffic is back on your normal connection."),
        (false, _) => println!("LagRelay isn't running. Your traffic is already on your normal connection."),
    }
    // A clean exit restored these. A crash or a force-stop can't have.
    if !boost::load_state().applied.is_empty() {
        println!("PC tweaks are still applied. To undo them: lagrelay optimize --revert");
    }
    Ok(())
}

fn relay_cmd(cmd: RelayCmd) -> Result<()> {
    let mut c = Config::load_or_create()?;
    match cmd {
        RelayCmd::Add { link } => {
            let r = Relay::from_link(&link)?;
            if c.relays.iter().any(|x| x.name == r.name) {
                bail!("a relay named {} already exists", r.name);
            }
            println!("added {} ({}) as {:?}", r.name, r.addr, r.role);
            c.relays.push(r);
            c.save()?;
        }
        RelayCmd::List => {
            println!("{:<16} {:<8} used per server when it's fastest, and as a backup", "direct", "built-in");
            for r in &c.relays {
                println!("{:<16} {:<8?} {}", r.name, r.role, r.addr);
            }
        }
        RelayCmd::Rm { name } => {
            let n = c.relays.len();
            c.relays.retain(|r| r.name != name);
            if c.relays.len() == n {
                bail!("no relay named {name}");
            }
            c.save()?;
        }
    }
    Ok(())
}

fn game_cmd(cmd: GameCmd) -> Result<()> {
    let mut c = Config::load_or_create()?;
    match cmd {
        GameCmd::Add { name, processes, cidrs, ports, exit, ping_target } => {
            if c.games.iter().any(|g| g.name.eq_ignore_ascii_case(&name)) {
                bail!("a game named {name} already exists");
            }
            let g = Game { name, processes, cidrs, ports, exit, ping_target };
            rules::Matcher::from_game(&g)?;
            c.games.push(g);
            c.save()?;
        }
        GameCmd::List => {
            for g in &c.games {
                println!("{:<14} processes={:?} cidrs={:?} ports={:?} exit={}", g.name, g.processes, g.cidrs, g.ports, g.exit.as_deref().unwrap_or("auto"));
            }
        }
        GameCmd::Rm { name } => {
            let n = c.games.len();
            c.games.retain(|g| !g.name.eq_ignore_ascii_case(&name));
            if c.games.len() == n {
                bail!("no game named {name}");
            }
            c.save()?;
        }
    }
    Ok(())
}

async fn dns_cmd(cmd: DnsCmd) -> Result<()> {
    match cmd {
        DnsCmd::Test => {
            println!("testing...");
            for r in dns::benchmark().await {
                let t = r.avg_ms.map_or("no answer".to_string(), |m| format!("{m:.1} ms"));
                println!("{:<12} {:<16} {:>10}  failed {}", r.name, r.primary, t, r.failures);
            }
            Ok(())
        }
        DnsCmd::Apply { server, secondary } => {
            if server == "fastest" {
                let best = dns::benchmark().await.into_iter().find(|r| r.avg_ms.is_some() && r.failures == 0).context("no server answered reliably")?;
                println!("fastest: {}", best.name);
                return dns::apply(best.primary.parse()?, best.secondary.parse().ok()).map(|_| ());
            }
            dns::apply(server.parse().context("server must be an IPv4 address or \"fastest\"")?, secondary).map(|_| ())
        }
        DnsCmd::Reset => dns::reset(),
        DnsCmd::Flush => dns::flush(),
    }
}

fn doctor() -> Result<()> {
    let check = |ok: bool, label: &str, fix: &str| println!("[{}] {label}{}", if ok { " ok " } else { "FAIL" }, if ok { String::new() } else { format!(" - {fix}") });
    let c = Config::load_or_create()?;
    check(system::is_elevated(), "running elevated", "open the terminal as Administrator/root");
    check(c.relays.iter().any(|r| r.role == Role::Exit), "exit relay configured", "lagrelay relay add LINK");
    #[cfg(windows)]
    {
        let dir = std::env::current_exe()?.parent().map(|d| d.to_path_buf()).context("locate executable")?;
        check(dir.join("WinDivert.dll").exists(), "WinDivert.dll present", "keep it next to lagrelay.exe");
        check(dir.join("WinDivert64.sys").exists(), "WinDivert64.sys present", "keep it next to lagrelay.exe");
        let sample = capture::windows::filter_string(&["1.2.3.4".parse()?], &[(27000, 27100)], false);
        match capture::windivert::validate_filter(&sample) {
            Ok(()) => check(true, "WinDivert accepts the capture filter", ""),
            Err(e) => check(false, "WinDivert accepts the capture filter", &format!("{e:#}")),
        }
        let procs = capture::windows::snapshot_processes();
        // ExitLag's client warns about the same class of conflict.
        let clash: Vec<&str> = ["goodbyedpi.exe", "winws.exe", "exitlag.exe"].into_iter().filter(|n| procs.iter().any(|(_, p)| p == n)).collect();
        check(clash.is_empty(), "no conflicting packet tools running", &format!("close {}", clash.join(", ")));
        if procs.iter().any(|(_, p)| p.starts_with("faceit")) {
            println!("[note] FACEIT is running. Its anti-cheat may refuse the WinDivert driver; `optimize faceit` then keeps tweaks only.");
        }
    }
    #[cfg(target_os = "linux")]
    {
        check(std::path::Path::new("/dev/net/tun").exists(), "/dev/net/tun present", "load the tun kernel module");
        check(system::run("ip", &["-V"]).is_ok(), "iproute2 installed", "install iproute2");
    }
    println!("{} network interface(s) usable for Multi Internet", engine::list_interfaces().len());
    Ok(())
}
