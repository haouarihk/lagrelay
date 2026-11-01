//! The relay event loop: sessions, bridge forwarding, exit NAT over TUN,
//! keep-alives, speed tests and latency probes.
use crate::config::Config;
use anyhow::{Context, Result};
use lagcore::ip::parse_ipv4;
use lagcore::reliab::{RxTracker, TxRing};
use lagcore::session::{accept, decode_key, receiver_idx, HandshakeReplayGuard, Session, KIND_DATA, KIND_HS_INIT, MAX_DGRAM};
use lagcore::wire::{Frame, SPEED_PKT_MAX};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[cfg(target_os = "linux")]
use lagcore::tun::Tun;

/// Exit mode is Linux-only. On other systems this keeps the event loop compiling
/// for bridge mode, and `setup_exit` refuses to start an exit.
#[cfg(not(target_os = "linux"))]
struct Tun;

#[cfg(not(target_os = "linux"))]
impl Tun {
    async fn read(&self, _: &mut [u8]) -> std::io::Result<usize> {
        std::future::pending().await
    }
    async fn write(&self, b: &[u8]) -> std::io::Result<usize> {
        Ok(b.len())
    }
}

const SESSION_IDLE: Duration = Duration::from_secs(120);
const PATH_ACTIVE_WINDOW: Duration = Duration::from_secs(3);
const MAX_PATHS: usize = 16;
const MAX_ROUTES_PER_SESSION: usize = 64;
const HS_LIMIT_PER_IP: u32 = 30;
const HS_LIMIT_GLOBAL: u32 = 300;

/// Handshakes cost CPU before a bad token can be detected, so unauthenticated
/// senders are limited per second, per source address and overall.
pub struct HandshakeLimiter {
    window: Instant,
    total: u32,
    per_ip: HashMap<IpAddr, u32>,
}

impl HandshakeLimiter {
    pub fn new() -> Self {
        HandshakeLimiter { window: Instant::now(), total: 0, per_ip: HashMap::new() }
    }

    pub fn allow(&mut self, ip: IpAddr) -> bool {
        if self.window.elapsed() >= Duration::from_secs(1) {
            self.window = Instant::now();
            self.total = 0;
            self.per_ip.clear();
        }
        if self.total >= HS_LIMIT_GLOBAL {
            return false;
        }
        let n = self.per_ip.entry(ip).or_insert(0);
        if *n >= HS_LIMIT_PER_IP {
            return false;
        }
        *n += 1;
        self.total += 1;
        true
    }
}

/// Hard cap on one speed test, so a client bug cannot flood the uplink forever.
const SPEED_MAX_BYTES: u64 = 2 << 30;

enum Ev {
    Udp { sock: usize, from: SocketAddr, data: Vec<u8> },
    Tun(Vec<u8>),
    FwdIn { session: u32, route: u32, data: Vec<u8> },
    Probe { session: u32, id: u32, rtt_us: u32 },
    FwdOpened { session: u32, route: u32, result: Option<(Arc<UdpSocket>, JoinHandle<()>)> },
}

struct RouteState {
    sock: Arc<UdpSocket>,
    reader: JoinHandle<()>,
}

#[derive(Clone, Copy)]
struct PathState {
    addr: SocketAddr,
    sock: usize,
    last_active: Option<Instant>,
}

struct Sess {
    session: Arc<Session>,
    client: String,
    vip: Ipv4Addr,
    addr: SocketAddr,
    sock: usize,
    last_rx: Instant,
    routes: HashMap<u32, RouteState>,
    paths: [Option<PathState>; MAX_PATHS],
    rx: RxTracker,
    tx: TxRing,
    tx_seq: u64,
    speed_rx: HashMap<u32, (u64, u32)>,
    speed_tx: Option<JoinHandle<()>>,
}

impl Drop for Sess {
    fn drop(&mut self) {
        for r in self.routes.values() {
            r.reader.abort();
        }
        if let Some(t) = &self.speed_tx {
            t.abort();
        }
    }
}

pub struct Server {
    cfg: Config,
    private: [u8; 32],
    token: [u8; 32],
    limiter: HandshakeLimiter,
    clients: HashMap<[u8; 32], (String, Ipv4Addr)>,
    replay: HashMap<[u8; 32], HandshakeReplayGuard>,
    socks: Vec<Arc<UdpSocket>>,
    sessions: HashMap<u32, Sess>,
    by_vip: HashMap<Ipv4Addr, u32>,
    tun: Option<Arc<Tun>>,
    tx: mpsc::Sender<Ev>,
    gateway: Ipv4Addr,
}

fn bind_udp(port: u16) -> Result<UdpSocket> {
    let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    s.set_reuse_address(true)?;
    let _ = s.set_recv_buffer_size(4 << 20);
    let _ = s.set_send_buffer_size(4 << 20);
    // DSCP EF: routers that honour it queue game traffic ahead of bulk traffic.
    let _ = s.set_tos(0xB8);
    s.set_nonblocking(true)?;
    s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
    Ok(UdpSocket::from_std(s.into())?)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn run_cmd(cmd: &str, args: &[&str]) -> Result<String> {
    let o = std::process::Command::new(cmd).args(args).output().with_context(|| format!("run {cmd}"))?;
    if !o.status.success() {
        anyhow::bail!("{cmd} {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// The interface of the default route, from `ip -4 route show default`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_default_iface(s: &str) -> Option<String> {
    let mut it = s.split_whitespace();
    while let Some(t) = it.next() {
        if t == "dev" {
            return it.next().map(str::to_string);
        }
    }
    None
}

/// Whether clients may send traffic to this address through the relay.
pub fn destination_allowed(dst: Ipv4Addr, allow_private: bool) -> bool {
    allow_private || !lagcore::ip::is_local_scope(dst)
}

/// Whether `target` is permitted by the allow_forward list.
pub fn forward_allowed(allow: &[String], target: &SocketAddr) -> bool {
    allow.iter().any(|a| a == "*" || a.parse::<SocketAddr>().is_ok_and(|x| x == *target))
}

#[cfg(not(target_os = "linux"))]
fn setup_exit(_: &Config) -> Result<(Arc<Tun>, Ipv4Addr)> {
    anyhow::bail!("exit relays need Linux (TUN and iptables). On this system, run a bridge: remove [exit] from the config")
}

#[cfg(target_os = "linux")]
fn setup_exit(cfg: &Config) -> Result<(Arc<Tun>, Ipv4Addr)> {
    let e = cfg.exit.as_ref().context("exit config")?;
    let (net, len) = lagcore::ip::parse_cidr(&e.subnet).context("bad subnet")?;
    let gw = Ipv4Addr::from(u32::from(net) + 1);
    let tun = Tun::create(&e.tun)?;
    let mtu = lagcore::TUNNEL_MTU.to_string();
    run_cmd("ip", &["addr", "replace", &format!("{gw}/{len}"), "dev", &e.tun])?;
    run_cmd("ip", &["link", "set", &e.tun, "up", "mtu", &mtu])?;
    // In a container /proc/sys is read-only; the value may already be set with
    // `--sysctl net.ipv4.ip_forward=1`, so only write when it needs changing.
    const FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
    if std::fs::read_to_string(FORWARD).map(|v| v.trim() != "1").unwrap_or(true) {
        std::fs::write(FORWARD, "1").context("enable IP forwarding (in Docker, use --sysctl net.ipv4.ip_forward=1)")?;
    }
    let wan = match &e.wan_interface {
        Some(w) => w.clone(),
        None => parse_default_iface(&run_cmd("ip", &["-4", "route", "show", "default"])?)
            .context("no default route; set exit.wan_interface")?,
    };
    let subnet = format!("{net}/{len}");
    let rules: [Vec<&str>; 4] = [
        vec!["-t", "nat", "-C", "POSTROUTING", "-s", &subnet, "-o", &wan, "-j", "MASQUERADE"],
        // Only between the tunnel and the internet: not to containers or other
        // local networks that also happen to be routable from this host.
        vec!["-C", "FORWARD", "-i", &e.tun, "-o", &wan, "-j", "ACCEPT"],
        vec!["-C", "FORWARD", "-i", &wan, "-o", &e.tun, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        vec!["-t", "mangle", "-C", "FORWARD", "-o", &e.tun, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
    ];
    for r in &rules {
        if run_cmd("iptables", r).is_err() {
            let add: Vec<&str> = r.iter().map(|a| if *a == "-C" { "-I" } else { *a }).collect();
            run_cmd("iptables", &add)?;
        }
    }
    println!("exit: {} {gw}/{len}, NAT via {wan}", e.tun);
    Ok((Arc::new(tun), gw))
}

// `ping` output is localised on Windows, so bridges there only offer TCP timing.
#[cfg(not(target_os = "linux"))]
async fn icmp_ping(_: Ipv4Addr) -> Option<u32> {
    None
}

#[cfg(target_os = "linux")]
async fn icmp_ping(ip: Ipv4Addr) -> Option<u32> {
    let out = tokio::process::Command::new("ping")
        .args(["-n", "-c", "1", "-W", "2", &ip.to_string()])
        .output()
        .await
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let t = s.split("time=").nth(1)?.split_whitespace().next()?;
    Some((t.parse::<f64>().ok()? * 1000.0) as u32)
}

async fn tcp_ping(addr: SocketAddr) -> Option<u32> {
    let t = Instant::now();
    tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr)).await.ok()?.ok()?;
    Some(t.elapsed().as_micros() as u32)
}

impl Server {
    pub async fn run(cfg: Config) -> Result<()> {
        let private = cfg.private_key()?;
        let token = cfg.token()?;
        let mut clients = HashMap::new();
        for c in &cfg.clients {
            let k = decode_key(&c.public_key).with_context(|| format!("client {} public key", c.name))?;
            clients.insert(k, (c.name.clone(), c.vip));
        }
        if clients.is_empty() {
            println!("warning: no clients configured; add one with `lagrelayd add-client`");
        }
        let (tx, mut rx) = mpsc::channel::<Ev>(8192);
        let mut socks = Vec::new();
        for (i, port) in std::iter::once(cfg.port).chain(cfg.extra_ports.iter().copied()).enumerate() {
            let s = Arc::new(bind_udp(port).with_context(|| format!("bind UDP port {port}"))?);
            println!("listening on udp/{port}");
            let (s2, tx2) = (s.clone(), tx.clone());
            tokio::spawn(async move {
                let mut b = vec![0u8; MAX_DGRAM];
                loop {
                    match s2.recv_from(&mut b).await {
                        Ok((n, from)) => {
                            if tx2.send(Ev::Udp { sock: i, from, data: b[..n].to_vec() }).await.is_err() {
                                break;
                            }
                        }
                        // Windows and Linux can surface ICMP errors here; they
                        // are not fatal for an unconnected socket.
                        Err(_) => tokio::task::yield_now().await,
                    }
                }
            });
            socks.push(s);
        }
        let (tun, gateway) = if cfg.exit.is_some() {
            let (t, gw) = setup_exit(&cfg)?;
            let (t2, tx2) = (t.clone(), tx.clone());
            tokio::spawn(async move {
                let mut b = vec![0u8; MAX_DGRAM];
                while let Ok(n) = t2.read(&mut b).await {
                    if tx2.send(Ev::Tun(b[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
            });
            (Some(t), gw)
        } else {
            (None, Ipv4Addr::UNSPECIFIED)
        };
        // The link holds the access token, so it must never go into the logs.
        println!("ready; run `lagrelayd link` to get the client link");
        let mut srv = Server { cfg, private, token, limiter: HandshakeLimiter::new(), clients, replay: HashMap::new(), socks, sessions: HashMap::new(), by_vip: HashMap::new(), tun, tx, gateway };
        let mut tick = tokio::time::interval(Duration::from_millis(20));
        let mut reap = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                ev = rx.recv() => {
                    let Some(ev) = ev else { break };
                    srv.handle(ev).await;
                }
                _ = tick.tick() => srv.send_nacks().await,
                _ = reap.tick() => srv.reap(),
                _ = tokio::signal::ctrl_c() => { println!("shutting down"); break; }
            }
        }
        Ok(())
    }

    async fn handle(&mut self, ev: Ev) {
        match ev {
            Ev::Udp { sock, from, data } => self.on_udp(sock, from, data).await,
            Ev::Tun(p) => self.on_tun(p).await,
            Ev::FwdIn { session, route, data } => {
                if let Some(s) = self.sessions.get(&session) {
                    if let Ok(d) = s.session.seal(&Frame::Fwd { route, datagram: &data }.to_vec()) {
                        let _ = self.socks[s.sock].send_to(&d, s.addr).await;
                    }
                }
            }
            Ev::Probe { session, id, rtt_us } => {
                if let Some(s) = self.sessions.get(&session) {
                    if let Ok(d) = s.session.seal(&Frame::ProbeResult { id, rtt_us }.to_vec()) {
                        let _ = self.socks[s.sock].send_to(&d, s.addr).await;
                    }
                }
            }
            Ev::FwdOpened { session, route, result } => {
                let Some(s) = self.sessions.get_mut(&session) else {
                    if let Some((_, h)) = result {
                        h.abort();
                    }
                    return;
                };
                let ok = result.is_some();
                if let Some((sock, reader)) = result {
                    if let Some(old) = s.routes.insert(route, RouteState { sock, reader }) {
                        old.reader.abort();
                    }
                }
                if let Ok(d) = s.session.seal(&Frame::FwdOk { route, ok }.to_vec()) {
                    let _ = self.socks[s.sock].send_to(&d, s.addr).await;
                }
            }
        }
    }

    async fn on_udp(&mut self, sock: usize, from: SocketAddr, data: Vec<u8>) {
        match data.first() {
            Some(&KIND_HS_INIT) => self.on_handshake(sock, from, &data).await,
            Some(&KIND_DATA) => {
                let Some(idx) = receiver_idx(&data) else { return };
                let Some(s) = self.sessions.get_mut(&idx) else { return };
                let Ok(plain) = s.session.open(&data) else { return };
                s.last_rx = Instant::now();
                s.addr = from;
                s.sock = sock;
                let Ok(frame) = Frame::decode(&plain) else { return };
                self.on_frame(idx, sock, from, frame).await;
            }
            _ => {}
        }
    }

    async fn on_handshake(&mut self, sock: usize, from: SocketAddr, data: &[u8]) {
        // Every rejected attempt is dropped without a reply, so scanners can't
        // tell that a relay is listening here.
        if !self.limiter.allow(from.ip()) {
            return;
        }
        let (clients, replay) = (&self.clients, &mut self.replay);
        let acc = accept(&self.private, &self.token, data, |peer, ts| clients.contains_key(peer) && replay.entry(*peer).or_default().admit(ts));
        let Ok(acc) = acc else { return };
        let (client, vip) = self.clients[&acc.peer].clone();
        let idx = acc.session.local_idx;
        println!("session {idx:08x}: client '{client}' from {from}");
        let _ = self.socks[sock].send_to(&acc.response, from).await;
        self.sessions.insert(
            idx,
            Sess {
                session: Arc::new(acc.session),
                client,
                vip,
                addr: from,
                sock,
                last_rx: Instant::now(),
                routes: HashMap::new(),
                paths: [None; MAX_PATHS],
                rx: RxTracker::new(Duration::from_millis(30), 3, Duration::from_millis(500)),
                tx: TxRing::new(4096, Duration::from_millis(400)),
                tx_seq: 0,
                speed_rx: HashMap::new(),
                speed_tx: None,
            },
        );
    }

    async fn on_frame(&mut self, idx: u32, sock: usize, from: SocketAddr, frame: Frame<'_>) {
        match frame {
            Frame::Hello => {
                let is_exit = self.tun.is_some();
                let name = self.cfg.name.clone();
                let s = &self.sessions[&idx];
                if is_exit {
                    // A client reconnecting replaces its previous session's address.
                    self.by_vip.insert(s.vip, idx);
                }
                let ack = Frame::HelloAck { vip: s.vip.octets(), exit: is_exit, mtu: lagcore::TUNNEL_MTU, name };
                if let Ok(d) = s.session.seal(&ack.to_vec()) {
                    let _ = self.socks[sock].send_to(&d, from).await;
                }
            }
            Frame::Ping { id, t_ns, path, active } => {
                let Some(s) = self.sessions.get_mut(&idx) else { return };
                if let Some(slot) = s.paths.get_mut(path as usize) {
                    let prev = slot.and_then(|p| p.last_active);
                    *slot = Some(PathState { addr: from, sock, last_active: if active { Some(Instant::now()) } else { prev } });
                }
                if let Ok(d) = s.session.seal(&Frame::Pong { id, t_ns, path }.to_vec()) {
                    let _ = self.socks[sock].send_to(&d, from).await;
                }
            }
            Frame::Ip { seq, path, packet } => {
                let allow_private = self.cfg.allow_private_destinations;
                let Some(s) = self.sessions.get_mut(&idx) else { return };
                if let Some(slot) = s.paths.get_mut(path as usize) {
                    *slot = Some(PathState { addr: from, sock, last_active: Some(Instant::now()) });
                }
                if !s.rx.accept(seq) {
                    return;
                }
                // Only the client's own tunnel address may be used as a source,
                // or one client could spoof traffic as another.
                let valid = parse_ipv4(packet).is_some_and(|i| i.src == s.vip && destination_allowed(i.dst, allow_private));
                if valid {
                    if let Some(t) = &self.tun {
                        let _ = t.write(packet).await;
                    }
                }
            }
            Frame::Nack { ranges } => {
                let Some(s) = self.sessions.get(&idx) else { return };
                for (start, count) in ranges.into_iter().take(64) {
                    for q in start..start.saturating_add(count.min(256) as u64) {
                        if let Some(p) = s.tx.get(q) {
                            Self::send_ip_on_paths(&self.socks, s, q, p).await;
                        }
                    }
                }
            }
            Frame::FwdOpen { route, target } => self.open_route(idx, route, target, sock, from).await,
            Frame::Fwd { route, datagram } => {
                let Some(s) = self.sessions.get(&idx) else { return };
                if let Some(r) = s.routes.get(&route) {
                    let _ = r.sock.send(datagram).await;
                }
            }
            Frame::SpeedStart { id, down, bytes, rate_kbps, pkt } => {
                let Some(s) = self.sessions.get_mut(&idx) else { return };
                if !down {
                    s.speed_rx.insert(id, (0, 0));
                    return;
                }
                if let Some(t) = s.speed_tx.take() {
                    t.abort();
                }
                let (session, socket) = (s.session.clone(), self.socks[sock].clone());
                let bytes = bytes.min(SPEED_MAX_BYTES);
                let pkt = pkt.clamp(64, SPEED_PKT_MAX) as usize;
                s.speed_tx = Some(tokio::spawn(speed_send(session, socket, from, id, bytes, rate_kbps, pkt)));
            }
            Frame::SpeedData { id, filler, .. } => {
                let Some(s) = self.sessions.get_mut(&idx) else { return };
                if let Some(e) = s.speed_rx.get_mut(&id) {
                    e.0 += filler.len() as u64;
                    e.1 += 1;
                }
            }
            Frame::SpeedEnd { id } => {
                let Some(s) = self.sessions.get_mut(&idx) else { return };
                let (bytes, packets) = s.speed_rx.remove(&id).unwrap_or((0, 0));
                if let Ok(d) = s.session.seal(&Frame::SpeedResult { id, bytes, packets }.to_vec()) {
                    let _ = self.socks[sock].send_to(&d, from).await;
                }
            }
            Frame::Probe { id, target, port, tcp } => {
                let (ip, tx) = (Ipv4Addr::from(target), self.tx.clone());
                let permitted = destination_allowed(ip, self.cfg.allow_private_destinations);
                tokio::spawn(async move {
                    if !permitted {
                        let _ = tx.send(Ev::Probe { session: idx, id, rtt_us: u32::MAX }).await;
                        return;
                    }
                    let rtt = if tcp { tcp_ping(SocketAddr::from((ip, port))).await } else { icmp_ping(ip).await };
                    let _ = tx.send(Ev::Probe { session: idx, id, rtt_us: rtt.unwrap_or(u32::MAX) }).await;
                });
            }
            Frame::Close => {
                if let Some(s) = self.sessions.remove(&idx) {
                    println!("session {idx:08x}: client '{}' closed", s.client);
                    if self.by_vip.get(&s.vip) == Some(&idx) {
                        self.by_vip.remove(&s.vip);
                    }
                }
            }
            _ => {}
        }
    }

    async fn open_route(&mut self, idx: u32, route: u32, target: String, sock: usize, from: SocketAddr) {
        let Some(s) = self.sessions.get(&idx) else { return };
        let session = s.session.clone();
        let too_many = s.routes.len() >= MAX_ROUTES_PER_SESSION && !s.routes.contains_key(&route);
        let parsed: Option<SocketAddr> = target.parse().ok();
        let private_ok = |t: &SocketAddr| matches!(t.ip(), IpAddr::V4(a) if destination_allowed(a, self.cfg.allow_private_destinations));
        let allowed = parsed.is_some_and(|t| forward_allowed(&self.cfg.allow_forward, &t) && !refers_to_self(&t, self.cfg.port) && private_ok(&t));
        if too_many || !allowed {
            println!("session {idx:08x}: refused forward to {target}");
            if let Ok(d) = session.seal(&Frame::FwdOk { route, ok: false }.to_vec()) {
                let _ = self.socks[sock].send_to(&d, from).await;
            }
            return;
        }
        let tx = self.tx.clone();
        let target = parsed.expect("checked by `allowed`");
        tokio::spawn(async move {
            let result = async {
                let u = Arc::new(bind_udp(0).ok()?);
                u.connect(target).await.ok()?;
                let (u2, tx2) = (u.clone(), tx.clone());
                let reader = tokio::spawn(async move {
                    let mut b = vec![0u8; MAX_DGRAM];
                    loop {
                        match u2.recv(&mut b).await {
                            Ok(n) => {
                                if tx2.send(Ev::FwdIn { session: idx, route, data: b[..n].to_vec() }).await.is_err() {
                                    break;
                                }
                            }
                            // ICMP port-unreachable while the next hop restarts.
                            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                        }
                    }
                });
                Some((u, reader))
            }
            .await;
            let _ = tx.send(Ev::FwdOpened { session: idx, route, result }).await;
        });
    }

    async fn on_tun(&mut self, packet: Vec<u8>) {
        let Some(i) = parse_ipv4(&packet) else { return };
        if i.dst == self.gateway {
            return;
        }
        let Some(&idx) = self.by_vip.get(&i.dst) else { return };
        let Some(s) = self.sessions.get_mut(&idx) else { return };
        let seq = s.tx_seq;
        s.tx_seq += 1;
        s.tx.push(seq, &packet);
        let s = &self.sessions[&idx];
        Self::send_ip_on_paths(&self.socks, s, seq, &packet).await;
    }

    /// Downlink multipath: one copy per path the client marked active. If none
    /// has been marked recently, fall back to whichever address spoke last.
    async fn send_ip_on_paths(socks: &[Arc<UdpSocket>], s: &Sess, seq: u64, packet: &[u8]) {
        let mut sent = false;
        for (i, p) in s.paths.iter().enumerate() {
            let Some(p) = p else { continue };
            if !p.last_active.is_some_and(|t| t.elapsed() < PATH_ACTIVE_WINDOW) {
                continue;
            }
            if let Ok(d) = s.session.seal(&Frame::Ip { seq, path: i as u8, packet }.to_vec()) {
                let _ = socks[p.sock].send_to(&d, p.addr).await;
                sent = true;
            }
        }
        if !sent {
            if let Ok(d) = s.session.seal(&Frame::Ip { seq, path: 0, packet }.to_vec()) {
                let _ = socks[s.sock].send_to(&d, s.addr).await;
            }
        }
    }

    async fn send_nacks(&mut self) {
        for s in self.sessions.values_mut() {
            let ranges = s.rx.due_nacks();
            if ranges.is_empty() {
                continue;
            }
            if let Ok(d) = s.session.seal(&Frame::Nack { ranges }.to_vec()) {
                let _ = self.socks[s.sock].send_to(&d, s.addr).await;
            }
        }
    }

    fn reap(&mut self) {
        let by_vip = &mut self.by_vip;
        self.sessions.retain(|idx, s| {
            let keep = s.last_rx.elapsed() < SESSION_IDLE;
            if !keep {
                println!("session {idx:08x}: client '{}' idle, removed", s.client);
                if by_vip.get(&s.vip) == Some(idx) {
                    by_vip.remove(&s.vip);
                }
            }
            keep
        });
    }
}

/// Blocks a client from pointing a bridge route back at this relay's own port,
/// which could otherwise create a forwarding loop.
fn refers_to_self(t: &SocketAddr, port: u16) -> bool {
    t.port() == port && matches!(t.ip(), IpAddr::V4(a) if a.is_loopback() || a.is_unspecified())
}

async fn speed_send(session: Arc<Session>, sock: Arc<UdpSocket>, to: SocketAddr, id: u32, bytes: u64, rate_kbps: u32, pkt: usize) {
    let filler = vec![0x5Au8; pkt];
    let start = Instant::now();
    let bytes_per_sec = rate_kbps as f64 * 1000.0 / 8.0;
    let (mut sent, mut seq) = (0u64, 0u32);
    while sent < bytes {
        let f = Frame::SpeedData { id, seq, sent_ns: start.elapsed().as_nanos() as u64, filler: &filler };
        if let Ok(d) = session.seal(&f.to_vec()) {
            let _ = sock.send_to(&d, to).await;
        }
        sent += pkt as u64;
        seq += 1;
        if rate_kbps > 0 {
            let due = Duration::from_secs_f64(sent as f64 / bytes_per_sec);
            if let Some(w) = due.checked_sub(start.elapsed()) {
                if w > Duration::from_millis(1) {
                    tokio::time::sleep(w).await;
                }
            }
        }
    }
    // Sent a few times: the end marker must survive the congestion we just caused.
    for _ in 0..5 {
        if let Ok(d) = session.seal(&Frame::SpeedEnd { id }.to_vec()) {
            let _ = sock.send_to(&d, to).await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_limiter_caps_each_source_and_the_total() {
        let mut l = HandshakeLimiter::new();
        let a: IpAddr = "1.1.1.1".parse().unwrap();
        for _ in 0..HS_LIMIT_PER_IP {
            assert!(l.allow(a));
        }
        assert!(!l.allow(a), "per-source cap");
        assert!(l.allow("2.2.2.2".parse().unwrap()), "others unaffected");
        let mut l = HandshakeLimiter::new();
        for i in 0..HS_LIMIT_GLOBAL {
            assert!(l.allow(IpAddr::from(i.to_be_bytes())));
        }
        assert!(!l.allow("9.9.9.9".parse().unwrap()), "global cap");
        l.window = Instant::now() - Duration::from_secs(2);
        assert!(l.allow("9.9.9.9".parse().unwrap()), "resets every second");
    }

    #[test]
    fn private_destinations_are_refused_by_default() {
        for a in ["10.0.1.5", "172.17.0.2", "192.168.1.1", "127.0.0.1", "169.254.169.254", "100.64.0.1"] {
            let ip: Ipv4Addr = a.parse().unwrap();
            assert!(!destination_allowed(ip, false), "{a}");
            assert!(destination_allowed(ip, true), "{a}");
        }
        assert!(destination_allowed("185.25.182.18".parse().unwrap(), false));
    }

    #[test]
    fn default_iface_parsing() {
        assert_eq!(parse_default_iface("default via 1.1.1.1 dev eth0 proto dhcp").as_deref(), Some("eth0"));
        assert_eq!(parse_default_iface(""), None);
    }

    #[test]
    fn forward_policy() {
        let t: SocketAddr = "1.2.3.4:5".parse().unwrap();
        assert!(forward_allowed(&["*".into()], &t));
        assert!(forward_allowed(&["1.2.3.4:5".into()], &t));
        assert!(!forward_allowed(&["1.2.3.4:6".into()], &t));
        assert!(!forward_allowed(&[], &t));
    }

    #[test]
    fn loop_guard() {
        assert!(refers_to_self(&"127.0.0.1:41820".parse().unwrap(), 41820));
        assert!(refers_to_self(&"0.0.0.0:41820".parse().unwrap(), 41820));
        assert!(!refers_to_self(&"8.8.8.8:41820".parse().unwrap(), 41820));
        assert!(!refers_to_self(&"127.0.0.1:1".parse().unwrap(), 41820));
    }
}
