//! Client tunnel engine: builds routes through bridges to one exit, sends each
//! packet over the active routes, measures every route, and fails over.
use crate::config::Relay;
use anyhow::{anyhow, bail, Context, Result};
use lagcore::reliab::{RxTracker, TxRing};
use lagcore::route::{paths_to_keep, select_active, Candidate, ExplorePolicy, Optimizer, PathStats};
use lagcore::session::{Initiator, Session, KIND_HS_RESP, MAX_DGRAM};
use lagcore::wire::Frame;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

const PATH_DEAD_AFTER: Duration = Duration::from_millis(1500);
const ALL_DEAD_RECONNECT: Duration = Duration::from_secs(8);
const STEP_TIMEOUT: Duration = Duration::from_millis(800);
const STEP_TRIES: u32 = 3;
/// The relay tracks at most this many path slots per session.
pub const MAX_PATHS: usize = 16;
/// Default number of UDP flows to try. An ISP that load-balances per flow pins
/// each source port to one path, so the same relay can be 20 ms apart by port.
pub const DEFAULT_FLOWS: usize = 16;
/// Path choices can go stale when one path congests, so keep sampling new ones.
const EXPLORE_EVERY: Duration = Duration::from_secs(30);
/// How often to search while the current routes are clearly degraded. Long enough
/// for each batch to be measured before the next prune.
const EXPLORE_BURST_EVERY: Duration = Duration::from_secs(5);
/// Stop bursting after this long: the slowdown is probably on every path.
const EXPLORE_GIVE_UP: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct Iface {
    pub name: String,
    pub ip: Ipv4Addr,
    #[cfg_attr(not(windows), allow(dead_code))]
    pub index: u32,
}

/// Non-virtual interfaces with a usable IPv4 address.
pub fn list_interfaces() -> Vec<Iface> {
    let Ok(all) = if_addrs::get_if_addrs() else { return vec![] };
    all.into_iter()
        .filter_map(|i| {
            let IpAddr::V4(ip) = i.ip() else { return None };
            if ip.is_loopback() || ip.is_link_local() || is_virtual_iface(&i.name) {
                return None;
            }
            Some(Iface { index: i.index.unwrap_or(0), name: i.name, ip })
        })
        .collect()
}

fn is_virtual_iface(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["lagrelay", "docker", "veth", "br-", "virbr", "vmnet", "vethernet", "virtualbox", "tailscale", "wireguard", "wg", "zerotier", "loopback"]
        .iter()
        .any(|p| n.starts_with(p))
}

fn bind_socket(iface: Option<&Iface>) -> Result<UdpSocket> {
    let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    let _ = s.set_recv_buffer_size(1 << 20);
    let _ = s.set_send_buffer_size(1 << 20);
    // DSCP EF. Windows ignores this unless a QoS policy allows it, which
    // `lagrelay boost apply qos` sets up.
    let _ = s.set_tos(0xB8);
    s.set_nonblocking(true)?;
    let mut bind_ip = Ipv4Addr::UNSPECIFIED;
    if let Some(i) = iface {
        bind_ip = i.ip;
        pin_to_interface(&s, i);
    }
    s.bind(&SocketAddr::from((bind_ip, 0)).into())?;
    Ok(UdpSocket::from_std(s.into())?)
}

#[cfg(target_os = "linux")]
fn pin_to_interface(s: &socket2::Socket, i: &Iface) {
    // Needs CAP_NET_RAW; binding to the source address still applies without it.
    let _ = s.bind_device(Some(i.name.as_bytes()));
}

#[cfg(windows)]
fn pin_to_interface(s: &socket2::Socket, i: &Iface) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, IP_UNICAST_IF};
    // IP_UNICAST_IF takes the interface index in network byte order. Binding
    // alone does not stop Windows routing via the lowest-metric interface.
    let v = i.index.to_be();
    // SAFETY: v outlives the call and its length is passed correctly.
    unsafe {
        setsockopt(s.as_raw_socket() as _, IPPROTO_IP, IP_UNICAST_IF, (&v as *const u32).cast(), 4);
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
fn pin_to_interface(_: &socket2::Socket, _: &Iface) {}

struct Hop {
    session: Arc<Session>,
    route: u32,
}

/// The stack of bridge sessions on one UDP socket. Bridges only see the next
/// hop's encrypted datagrams, never the traffic inside.
struct Link {
    sock: Arc<UdpSocket>,
    hops: Vec<Hop>,
}

impl Link {
    fn wrap(&self, mut d: Vec<u8>) -> Result<Vec<u8>> {
        for h in self.hops.iter().rev() {
            d = h.session.seal(&Frame::Fwd { route: h.route, datagram: &d }.to_vec())?;
        }
        Ok(d)
    }

    /// Removes the bridge layers. `None` means this is not forwarded data,
    /// such as a late control reply, and should be ignored.
    fn unwrap_all(&self, d: &[u8]) -> Option<Vec<u8>> {
        let mut cur = d.to_vec();
        for h in &self.hops {
            let plain = h.session.open(&cur).ok()?;
            match Frame::decode(&plain).ok()? {
                Frame::Fwd { datagram, .. } => cur = datagram.to_vec(),
                _ => return None,
            }
        }
        Some(cur)
    }

    /// Sends and waits for the first reply `accept` recognises, with retries.
    /// A retry resends the same bytes, which each receiver treats as a replay
    /// or duplicate, so callers supply a closure to re-create the request.
    async fn exchange<T>(&self, mut make: impl FnMut() -> Result<Vec<u8>>, mut accept: impl FnMut(&[u8]) -> Option<T>) -> Result<T> {
        let mut buf = vec![0u8; MAX_DGRAM];
        for _ in 0..STEP_TRIES {
            let out = self.wrap(make()?)?;
            let _ = self.sock.send(&out).await;
            let deadline = Instant::now() + STEP_TIMEOUT;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                let Ok(r) = tokio::time::timeout(left, self.sock.recv(&mut buf)).await else { break };
                let Ok(n) = r else { continue };
                if let Some(inner) = self.unwrap_all(&buf[..n]) {
                    if let Some(t) = accept(&inner) {
                        return Ok(t);
                    }
                }
            }
        }
        // A relay deliberately ignores anyone it doesn't accept, so this covers
        // a wrong token or an unauthorized key as well as a network failure.
        bail!("no reply (check the address, firewall, access token, and that this client is authorized)")
    }

    async fn handshake(&self, private: &[u8; 32], relay: &Relay) -> Result<Arc<Session>> {
        let init: Arc<Mutex<Option<Initiator>>> = Arc::new(Mutex::new(None));
        let (i2, private, public, token) = (init.clone(), *private, relay.key()?, relay.token_bytes()?);
        // Every retry is a new handshake, because the relay refuses replays.
        let session = self
            .exchange(
                move || {
                    let (i, msg) = Initiator::new(&private, &public, &token)?;
                    *i2.lock().unwrap() = Some(i);
                    Ok(msg)
                },
                |d| {
                    if d.first() != Some(&KIND_HS_RESP) {
                        return None;
                    }
                    init.lock().unwrap().take()?.finish(d).ok()
                },
            )
            .await?;
        Ok(Arc::new(session))
    }

    async fn open_route(&mut self, session: Arc<Session>, target: SocketAddr) -> Result<()> {
        let route: u32 = rand::random();
        let s2 = session.clone();
        let target_s = target.to_string();
        let ok = self
            .exchange(
                move || s2.seal(&Frame::FwdOpen { route, target: target_s.clone() }.to_vec()),
                |d| {
                    let plain = session.open(d).ok()?;
                    match Frame::decode(&plain).ok()? {
                        Frame::FwdOk { route: r, ok } if r == route => Some(ok),
                        _ => None,
                    }
                },
            )
            .await?;
        if !ok {
            bail!("bridge refused forwarding to {target}");
        }
        self.hops.push(Hop { session, route });
        Ok(())
    }
}

pub async fn resolve(addr: &str) -> Result<SocketAddr> {
    tokio::net::lookup_host(addr)
        .await
        .with_context(|| format!("resolve {addr}"))?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| anyhow!("{addr} has no IPv4 address"))
}

#[derive(Debug, Clone)]
pub struct RouteSpec {
    pub bridges: Vec<Relay>,
    pub exit: Relay,
    pub iface: Option<Iface>,
}

impl RouteSpec {
    pub fn label(&self) -> String {
        let mut s = String::new();
        if let Some(i) = &self.iface {
            s += &format!("[{}] ", i.name);
        }
        for b in &self.bridges {
            s += &b.name;
            s += " > ";
        }
        s + &self.exit.name
    }

    fn first_hop(&self) -> String {
        self.bridges.first().unwrap_or(&self.exit).name.clone()
    }

    fn iface_key(&self) -> String {
        self.iface.as_ref().map(|i| i.name.clone()).unwrap_or_default()
    }
}

/// All routes to `exit` with up to `max_bridges` bridges, on every interface.
pub fn enumerate_routes(bridges: &[Relay], exit: &Relay, max_bridges: usize, ifaces: &[Option<Iface>]) -> Vec<RouteSpec> {
    let mut chains: Vec<Vec<Relay>> = vec![vec![]];
    let usable: Vec<&Relay> = bridges.iter().filter(|b| b.name != exit.name).collect();
    if max_bridges >= 1 {
        chains.extend(usable.iter().map(|b| vec![(*b).clone()]));
    }
    if max_bridges >= 2 {
        for a in &usable {
            for b in &usable {
                if a.name != b.name {
                    chains.push(vec![(*a).clone(), (*b).clone()]);
                }
            }
        }
    }
    let mut out = Vec::new();
    for iface in ifaces {
        for c in &chains {
            out.push(RouteSpec { bridges: c.clone(), exit: exit.clone(), iface: iface.clone() });
        }
    }
    out
}

/// Shares `flows` sockets out across the routes, one round at a time, so a route
/// that turns out to be dead (such as an unreachable exit) can't use them all up.
pub fn expand_flows(specs: &[RouteSpec], flows: usize) -> Vec<RouteSpec> {
    if specs.is_empty() {
        return vec![];
    }
    let total = flows.clamp(1, MAX_PATHS).max(specs.len().min(MAX_PATHS));
    (0..total).map(|i| specs[i % specs.len()].clone()).collect()
}

/// How many paths to retain: the routes in use, plus spares to fail over to.
fn keep_count(want: usize) -> usize {
    (want + 2).max(4).min(MAX_PATHS)
}

pub struct Path {
    pub id: u8,
    pub label: String,
    pub first_hop: String,
    pub iface: String,
    link: Link,
    pub active: AtomicBool,
    pub stats: Mutex<PathStats>,
    rx_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Drop for Path {
    fn drop(&mut self) {
        if let Some(t) = self.rx_task.lock().unwrap().take() {
            t.abort();
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PathView {
    pub label: String,
    pub active: bool,
    pub alive: bool,
    pub rtt_ms: f64,
    pub jitter_ms: f64,
    pub loss_pct: f64,
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub exit: String,
    pub paths: Vec<PathView>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub recovered: u64,
    pub lost: u64,
    pub switches: u64,
    pub best_rtt_ms: Option<f64>,
}

#[derive(Default)]
struct Waiters {
    probes: HashMap<u32, oneshot::Sender<u32>>,
    speed_results: HashMap<u32, oneshot::Sender<(u64, u32)>>,
    speed_end: HashMap<u32, oneshot::Sender<()>>,
    speed_rx: HashMap<u32, (u64, u32)>,
}

pub struct Engine {
    pub exit_name: String,
    pub vip: Ipv4Addr,
    exit: Arc<Session>,
    start: Instant,
    paths: RwLock<Vec<Arc<Path>>>,
    tx_seq: AtomicU64,
    ring: Mutex<TxRing>,
    rx: Mutex<RxTracker>,
    inbound: mpsc::Sender<Vec<u8>>,
    waiters: Mutex<Waiters>,
    ping_id: AtomicU32,
    pub want_routes: AtomicU32,
    pub multi_internet: bool,
    private: [u8; 32],
    specs: Vec<RouteSpec>,
    flows: usize,
    explore_cursor: AtomicUsize,
    exploring: AtomicBool,
    optimizer: Mutex<Optimizer>,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    switches: AtomicU64,
}

async fn build_link(spec: &RouteSpec, private: &[u8; 32]) -> Result<Link> {
    let sock = bind_socket(spec.iface.as_ref())?;
    let first = spec.bridges.first().unwrap_or(&spec.exit);
    sock.connect(resolve(&first.addr).await?).await.with_context(|| format!("connect to {}", first.name))?;
    let mut link = Link { sock: Arc::new(sock), hops: vec![] };
    for (i, b) in spec.bridges.iter().enumerate() {
        let session = link.handshake(private, b).await.with_context(|| format!("handshake with bridge {}", b.name))?;
        let next = spec.bridges.get(i + 1).unwrap_or(&spec.exit);
        link.open_route(session, resolve(&next.addr).await?).await.with_context(|| format!("open route through {}", b.name))?;
    }
    Ok(link)
}

/// Opens the end-to-end session with the exit over `link`.
async fn exit_hello(link: &Link, private: &[u8; 32], exit: &Relay) -> Result<(Arc<Session>, Ipv4Addr, String)> {
    let session = link.handshake(private, exit).await.with_context(|| format!("handshake with {}", exit.name))?;
    let s2 = session.clone();
    let (vip, is_exit, name) = link
        .exchange(
            move || s2.seal(&Frame::Hello.to_vec()),
            |d| {
                let plain = session.open(d).ok()?;
                match Frame::decode(&plain).ok()? {
                    Frame::HelloAck { vip, exit, name, .. } => Some((Ipv4Addr::from(vip), exit, name)),
                    _ => None,
                }
            },
        )
        .await?;
    if !is_exit {
        bail!("relay {} is not configured as an exit", exit.name);
    }
    Ok((session, vip, name))
}

impl Engine {
    /// Connects to the exit via the given routes, trying `flows` UDP flows across
    /// them. Flows that fail are skipped; it is an error only if none can be built.
    pub async fn connect(private: [u8; 32], specs: Vec<RouteSpec>, want_routes: usize, multi_internet: bool, flows: usize, inbound: mpsc::Sender<Vec<u8>>) -> Result<Arc<Engine>> {
        let exit_relay = specs.first().context("no routes to try")?.exit.clone();
        let mut set = tokio::task::JoinSet::new();
        for (i, spec) in expand_flows(&specs, flows).into_iter().enumerate() {
            set.spawn(async move {
                let link = build_link(&spec, &private).await;
                (i, spec, link)
            });
        }
        let mut built = Vec::new();
        let mut errors = Vec::new();
        while let Some(r) = set.join_next().await {
            let (i, spec, link) = r?;
            match link {
                Ok(l) => built.push((i, spec, l)),
                Err(e) => errors.push(format!("{}: {e:#}", spec.label())),
            }
        }
        built.sort_by_key(|(i, _, _)| *i);
        built.truncate(MAX_PATHS);
        // The exit session is shared by all routes; open it over the first that works.
        let mut hello = None;
        for (_, spec, link) in &built {
            match exit_hello(link, &private, &exit_relay).await {
                Ok(h) => {
                    hello = Some(h);
                    break;
                }
                Err(e) => errors.push(format!("{}: {e:#}", spec.label())),
            }
        }
        let Some((exit, vip, name)) = hello else {
            bail!("could not reach exit {}:\n  {}", exit_relay.name, errors.join("\n  "));
        };
        let engine = Arc::new(Engine {
            exit_name: name,
            vip,
            exit,
            start: Instant::now(),
            paths: RwLock::new(vec![]),
            tx_seq: AtomicU64::new(0),
            ring: Mutex::new(TxRing::new(4096, Duration::from_millis(400))),
            rx: Mutex::new(RxTracker::new(Duration::from_millis(30), 3, Duration::from_millis(500))),
            inbound,
            waiters: Mutex::new(Waiters::default()),
            ping_id: AtomicU32::new(0),
            want_routes: AtomicU32::new(want_routes.max(1) as u32),
            multi_internet,
            private,
            specs,
            flows,
            explore_cursor: AtomicUsize::new(0),
            exploring: AtomicBool::new(false),
            optimizer: Mutex::new(Optimizer::new(Duration::from_secs(5), Duration::from_secs(300))),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            switches: AtomicU64::new(0),
        });
        for (_, spec, link) in built {
            engine.add_path(&spec, link);
        }
        engine.send_pings(true).await;
        Ok(engine)
    }

    /// Starts using a built link, in a free path slot. False if all are taken.
    fn add_path(self: &Arc<Self>, spec: &RouteSpec, link: Link) -> bool {
        let mut paths = self.paths.write().unwrap();
        let Some(id) = (0..MAX_PATHS as u8).find(|i| !paths.iter().any(|p| p.id == *i)) else { return false };
        let port = link.sock.local_addr().map(|a| a.port()).unwrap_or(0);
        let path = Arc::new(Path {
            id,
            label: format!("{} :{port}", spec.label()),
            first_hop: spec.first_hop(),
            iface: spec.iface_key(),
            link,
            active: AtomicBool::new(false),
            stats: Mutex::new(PathStats::default()),
            rx_task: Mutex::new(None),
        });
        let sock = path.link.sock.clone();
        *path.rx_task.lock().unwrap() = Some(tokio::spawn(path_rx(Arc::downgrade(self), Arc::downgrade(&path), sock)));
        paths.push(path);
        true
    }

    /// Closes all but the routes in use and the best spares.
    pub fn prune(&self) {
        if self.flows <= 1 {
            return;
        }
        let mut paths = self.paths.write().unwrap();
        let cands = Self::candidates(&paths);
        let active: Vec<usize> = paths.iter().enumerate().filter(|(_, p)| p.active.load(Ordering::Relaxed)).map(|(i, _)| i).collect();
        let keep = keep_count(self.want_routes.load(Ordering::Relaxed) as usize);
        let keep = paths_to_keep(&cands, &active, keep, self.multi_internet);
        let mut i = 0;
        paths.retain(|_| {
            let k = keep.contains(&i);
            i += 1;
            k
        });
    }

    /// Opens a few new flows in the background, so a path that has become faster
    /// (or a bridge that has come back) is found while playing.
    fn explore(self: &Arc<Self>, count: usize) {
        if self.flows <= 1 || self.exploring.swap(true, Ordering::Relaxed) {
            return;
        }
        let live = self.live_specs();
        let e = self.clone();
        tokio::spawn(async move {
            let mut set = tokio::task::JoinSet::new();
            for i in 0..count {
                let n = e.explore_cursor.fetch_add(1, Ordering::Relaxed);
                // Mostly routes known to work; one per round from the full list,
                // so a bridge that comes back gets noticed.
                let spec = if i + 1 == count || live.is_empty() { e.specs[n % e.specs.len()].clone() } else { live[n % live.len()].clone() };
                let private = e.private;
                set.spawn(async move {
                    let link = build_link(&spec, &private).await;
                    (spec, link)
                });
            }
            while let Some(Ok((spec, link))) = set.join_next().await {
                if let Ok(l) = link {
                    e.add_path(&spec, l);
                }
            }
            e.exploring.store(false, Ordering::Relaxed);
        });
    }

    /// Routes that currently have at least one working flow.
    fn live_specs(&self) -> Vec<RouteSpec> {
        let paths = self.snapshot_paths();
        let up: Vec<(String, String)> =
            paths.iter().filter(|p| p.stats.lock().unwrap().is_alive(PATH_DEAD_AFTER)).map(|p| (p.first_hop.clone(), p.iface.clone())).collect();
        self.specs.iter().filter(|s| up.contains(&(s.first_hop(), s.iface_key()))).cloned().collect()
    }

    /// The score of the best route currently carrying traffic.
    fn best_active_score(&self) -> Option<f64> {
        self.snapshot_paths()
            .iter()
            .filter(|p| p.active.load(Ordering::Relaxed))
            .filter_map(|p| {
                let s = p.stats.lock().unwrap();
                s.is_alive(PATH_DEAD_AFTER).then(|| s.score())
            })
            .reduce(f64::min)
    }

    fn candidates(paths: &[Arc<Path>]) -> Vec<Candidate> {
        paths
            .iter()
            .enumerate()
            .map(|(idx, p)| {
                let s = p.stats.lock().unwrap();
                Candidate { idx, iface: p.iface.clone(), first_hop: p.first_hop.clone(), score: s.score(), alive: s.is_alive(PATH_DEAD_AFTER) }
            })
            .collect()
    }

    fn now_ns(&self) -> u64 {
        self.start.elapsed().as_nanos() as u64
    }

    async fn send_exit_frame(&self, p: &Path, frame: &Frame<'_>) -> Result<()> {
        let d = self.exit.seal(&frame.to_vec())?;
        let d = p.link.wrap(d)?;
        // Errors here are normal while a route is failing: ICMP unreachable can
        // surface on a connected socket. The liveness check handles the outcome.
        let _ = p.link.sock.send(&d).await;
        Ok(())
    }

    fn snapshot_paths(&self) -> Vec<Arc<Path>> {
        self.paths.read().unwrap().clone()
    }

    pub async fn send_pings(&self, all: bool) {
        for p in self.snapshot_paths() {
            let active = p.active.load(Ordering::Relaxed);
            if !all && !active {
                continue;
            }
            let id = self.ping_id.fetch_add(1, Ordering::Relaxed);
            p.stats.lock().unwrap().on_sent();
            let _ = self.send_exit_frame(&p, &Frame::Ping { id, t_ns: self.now_ns(), path: p.id, active }).await;
        }
    }

    /// Tunnels one captured packet: one encrypted copy per active route.
    pub async fn send_ip(&self, packet: &[u8]) {
        let seq = self.tx_seq.fetch_add(1, Ordering::Relaxed);
        self.ring.lock().unwrap().push(seq, packet);
        self.bytes_up.fetch_add(packet.len() as u64, Ordering::Relaxed);
        self.send_seq(seq, packet).await;
    }

    async fn send_seq(&self, seq: u64, packet: &[u8]) {
        for p in self.snapshot_paths() {
            if p.active.load(Ordering::Relaxed) {
                let _ = self.send_exit_frame(&p, &Frame::Ip { seq, path: p.id, packet }).await;
            }
        }
    }

    async fn on_frame(&self, path: &Path, frame: Frame<'_>) {
        match frame {
            Frame::Ip { seq, packet, .. } => {
                if self.rx.lock().unwrap().accept(seq) {
                    self.bytes_down.fetch_add(packet.len() as u64, Ordering::Relaxed);
                    let _ = self.inbound.try_send(packet.to_vec());
                }
            }
            Frame::Pong { t_ns, .. } => {
                let rtt = self.now_ns().saturating_sub(t_ns) as f64 / 1e6;
                path.stats.lock().unwrap().on_rtt(rtt);
            }
            Frame::Nack { ranges } => {
                for (start, count) in ranges.into_iter().take(64) {
                    for seq in start..start.saturating_add(count.min(256) as u64) {
                        let pkt = self.ring.lock().unwrap().get(seq).map(<[u8]>::to_vec);
                        if let Some(pkt) = pkt {
                            self.send_seq(seq, &pkt).await;
                        }
                    }
                }
            }
            Frame::ProbeResult { id, rtt_us } => {
                if let Some(t) = self.waiters.lock().unwrap().probes.remove(&id) {
                    let _ = t.send(rtt_us);
                }
            }
            Frame::SpeedData { id, filler, .. } => {
                let mut w = self.waiters.lock().unwrap();
                let e = w.speed_rx.entry(id).or_insert((0, 0));
                e.0 += filler.len() as u64;
                e.1 += 1;
            }
            Frame::SpeedEnd { id } => {
                if let Some(t) = self.waiters.lock().unwrap().speed_end.remove(&id) {
                    let _ = t.send(());
                }
            }
            Frame::SpeedResult { id, bytes, packets } => {
                if let Some(t) = self.waiters.lock().unwrap().speed_results.remove(&id) {
                    let _ = t.send((bytes, packets));
                }
            }
            _ => {}
        }
    }

    /// Re-evaluates which routes carry traffic. Returns false if every route
    /// has been dead long enough that the session should be rebuilt.
    pub fn reselect(&self) -> bool {
        let paths = self.snapshot_paths();
        let want = self.want_routes.load(Ordering::Relaxed) as usize;
        let cands = Self::candidates(&paths);
        let chosen = select_active(&cands, want, self.multi_internet);
        let current: Vec<usize> = paths.iter().enumerate().filter(|(_, p)| p.active.load(Ordering::Relaxed)).map(|(i, _)| i).collect();
        let live_current: Vec<usize> = current.iter().copied().filter(|i| cands[*i].alive).collect();
        let apply = if live_current.len() != current.len() || live_current.len() != chosen.len().min(want) {
            // A route died, or the requested count changed: act immediately.
            true
        } else if let Some(&best_new) = chosen.iter().find(|i| !current.contains(i)) {
            // Both healthy: only move if clearly better, sustained (no flapping).
            let worst = live_current.iter().map(|i| cands[*i].score).fold(f64::MIN, f64::max);
            // Identified by path ID: list positions shift when paths are pruned.
            self.optimizer.lock().unwrap().evaluate(worst, paths[best_new].id as usize, cands[best_new].score)
        } else {
            false
        };
        let mut sorted = chosen.clone();
        sorted.sort_unstable();
        if apply && sorted != current {
            for (i, p) in paths.iter().enumerate() {
                p.active.store(chosen.contains(&i), Ordering::Relaxed);
            }
            if !current.is_empty() {
                self.switches.fetch_add(1, Ordering::Relaxed);
            }
        }
        if chosen.is_empty() {
            let newest = paths.iter().filter_map(|p| p.stats.lock().unwrap().last_rx).max();
            return newest.is_some_and(|t| t.elapsed() < ALL_DEAD_RECONNECT) || self.start.elapsed() < ALL_DEAD_RECONNECT;
        }
        true
    }

    pub async fn flush_nacks(&self) {
        let ranges = self.rx.lock().unwrap().due_nacks();
        if ranges.is_empty() {
            return;
        }
        let f = Frame::Nack { ranges };
        for p in self.snapshot_paths() {
            if p.active.load(Ordering::Relaxed) {
                let _ = self.send_exit_frame(&p, &f).await;
            }
        }
    }

    /// Scales the retransmit wait to the current path so a NACK is not sent for
    /// a packet that is merely reordered across routes of different latency.
    pub fn tune_nack_delay(&self) {
        let rtts: Vec<f64> = self
            .snapshot_paths()
            .iter()
            .filter(|p| p.active.load(Ordering::Relaxed))
            .map(|p| p.stats.lock().unwrap().rtt_ms)
            .collect();
        let (Some(min), Some(max)) = (rtts.iter().copied().reduce(f64::min), rtts.iter().copied().reduce(f64::max)) else { return };
        let spread = (max - min) / 2.0 + 10.0;
        self.rx.lock().unwrap().set_nack_delay(Duration::from_secs_f64(spread.clamp(10.0, 120.0) / 1000.0));
    }

    /// Runs pings, route selection and NACKs until the session should be rebuilt.
    pub async fn run_maintenance(self: &Arc<Self>) {
        let mut fast = tokio::time::interval(Duration::from_millis(200));
        let mut nack = tokio::time::interval(Duration::from_millis(10));
        let mut policy = ExplorePolicy::new(EXPLORE_EVERY, EXPLORE_BURST_EVERY, EXPLORE_GIVE_UP);
        let mut slow_tick = 0u32;
        loop {
            tokio::select! {
                _ = fast.tick() => {
                    slow_tick += 1;
                    // Standby routes need fewer pings, but enough to fail over to.
                    self.send_pings(slow_tick % 3 == 0).await;
                    if !self.reselect() {
                        return;
                    }
                    self.tune_nack_delay();
                    if let Some(count) = policy.tick(self.best_active_score()) {
                        // Last round's flows have had time to be measured.
                        self.prune();
                        self.explore(count);
                    }
                }
                _ = nack.tick() => self.flush_nacks().await,
            }
        }
    }

    /// Waits for measurements, then activates the initial routes.
    pub async fn settle(&self, d: Duration) {
        let end = Instant::now() + d;
        while Instant::now() < end {
            tokio::time::sleep(Duration::from_millis(100)).await;
            self.send_pings(true).await;
        }
        self.reselect();
    }

    pub fn snapshot(&self) -> Snapshot {
        let rx = self.rx.lock().unwrap();
        let paths: Vec<PathView> = self
            .snapshot_paths()
            .iter()
            .map(|p| {
                let s = p.stats.lock().unwrap();
                PathView {
                    label: p.label.clone(),
                    active: p.active.load(Ordering::Relaxed),
                    alive: s.is_alive(PATH_DEAD_AFTER),
                    rtt_ms: s.rtt_ms,
                    jitter_ms: s.jitter_ms,
                    loss_pct: s.loss_pct,
                }
            })
            .collect();
        let best_rtt_ms = paths.iter().filter(|p| p.active && p.alive).map(|p| p.rtt_ms).reduce(f64::min);
        Snapshot {
            exit: self.exit_name.clone(),
            paths,
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
            recovered: rx.recovered,
            lost: rx.lost,
            switches: self.switches.load(Ordering::Relaxed),
            best_rtt_ms,
        }
    }

    /// Asks the exit for its latency to a game server.
    pub async fn probe(&self, target: Ipv4Addr, port: u16, tcp: bool) -> Result<Option<Duration>> {
        let id = self.ping_id.fetch_add(1, Ordering::Relaxed);
        let (t, r) = oneshot::channel();
        self.waiters.lock().unwrap().probes.insert(id, t);
        let p = self.snapshot_paths().into_iter().next().context("no routes")?;
        self.send_exit_frame(&p, &Frame::Probe { id, target: target.octets(), port, tcp }).await?;
        let v = tokio::time::timeout(Duration::from_secs(4), r).await.context("probe timed out")??;
        Ok((v != u32::MAX).then(|| Duration::from_micros(v as u64)))
    }

    /// Downlink: relay sends paced data for `dur`; returns bytes received.
    pub async fn speed_down(&self, rate_kbps: u32, dur: Duration) -> Result<(u64, Duration)> {
        let id = rand::random::<u32>();
        let (t, r) = oneshot::channel();
        self.waiters.lock().unwrap().speed_end.insert(id, t);
        let bytes = if rate_kbps == 0 { 1u64 << 30 } else { (rate_kbps as u64 * 125).saturating_mul(dur.as_millis() as u64) / 1000 };
        let p = self.snapshot_paths().into_iter().next().context("no routes")?;
        let start = Instant::now();
        self.send_exit_frame(&p, &Frame::SpeedStart { id, down: true, bytes, rate_kbps, pkt: lagcore::wire::SPEED_PKT_MAX }).await?;
        let _ = tokio::time::timeout(dur + Duration::from_secs(2), r).await;
        let mut w = self.waiters.lock().unwrap();
        w.speed_end.remove(&id);
        let (got, _) = w.speed_rx.remove(&id).unwrap_or((0, 0));
        Ok((got, start.elapsed()))
    }

    /// Uplink: sends paced data for `dur`, then asks the relay how much arrived.
    pub async fn speed_up(&self, rate_kbps: u32, dur: Duration) -> Result<(u64, Duration)> {
        let id = rand::random::<u32>();
        let (t, r) = oneshot::channel();
        self.waiters.lock().unwrap().speed_results.insert(id, t);
        let p = self.snapshot_paths().into_iter().next().context("no routes")?;
        self.send_exit_frame(&p, &Frame::SpeedStart { id, down: false, bytes: 0, rate_kbps, pkt: 0 }).await?;
        let filler = vec![0x5Au8; lagcore::wire::SPEED_PKT_MAX as usize];
        let start = Instant::now();
        let bps = rate_kbps as f64 * 125.0;
        let (mut sent, mut seq) = (0u64, 0u32);
        while start.elapsed() < dur {
            self.send_exit_frame(&p, &Frame::SpeedData { id, seq, sent_ns: 0, filler: &filler }).await?;
            sent += filler.len() as u64;
            seq += 1;
            if rate_kbps > 0 {
                let due = Duration::from_secs_f64(sent as f64 / bps);
                if let Some(w) = due.checked_sub(start.elapsed()) {
                    if w > Duration::from_millis(1) {
                        tokio::time::sleep(w).await;
                    }
                }
            } else if seq % 64 == 0 {
                tokio::task::yield_now().await;
            }
        }
        let elapsed = start.elapsed();
        tokio::time::sleep(Duration::from_millis(300)).await;
        for _ in 0..5 {
            self.send_exit_frame(&p, &Frame::SpeedEnd { id }).await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
            if self.waiters.lock().unwrap().speed_results.get(&id).is_none_or(|t| t.is_closed()) {
                break;
            }
        }
        let (got, _) = tokio::time::timeout(Duration::from_secs(3), r).await.context("no speed result from relay")??;
        Ok((got, elapsed))
    }

    pub async fn close(&self) {
        for p in self.snapshot_paths() {
            let _ = self.send_exit_frame(&p, &Frame::Close).await;
        }
    }
}

async fn path_rx(engine: std::sync::Weak<Engine>, path: std::sync::Weak<Path>, sock: Arc<UdpSocket>) {
    let mut buf = vec![0u8; MAX_DGRAM];
    loop {
        let n = match sock.recv(&mut buf).await {
            Ok(n) => n,
            Err(_) => {
                // Connected UDP reports ICMP errors here; keep listening.
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let (Some(e), Some(p)) = (engine.upgrade(), path.upgrade()) else { return };
        let Some(inner) = p.link.unwrap_all(&buf[..n]) else { continue };
        let Ok(plain) = e.exit.open(&inner) else { continue };
        if let Ok(f) = Frame::decode(&plain) {
            e.on_frame(&p, f).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Role;

    fn relay(n: &str, r: Role) -> Relay {
        Relay { name: n.into(), addr: "1.1.1.1:1".into(), public_key: String::new(), role: r, token: String::new() }
    }

    #[test]
    fn enumerates_chains_without_self_or_repeats() {
        let (b1, b2) = (relay("b1", Role::Bridge), relay("b2", Role::Bridge));
        let x = relay("x", Role::Exit);
        let all = [b1, b2, x.clone()];
        let ifs = [None];
        assert_eq!(enumerate_routes(&all, &x, 0, &ifs).len(), 1);
        assert_eq!(enumerate_routes(&all, &x, 1, &ifs).len(), 3, "direct + two bridges; exit is not its own bridge");
        let r = enumerate_routes(&all, &x, 2, &ifs);
        assert_eq!(r.len(), 5, "adds b1>b2 and b2>b1");
        assert_eq!(r[3].label(), "b1 > b2 > x");
    }

    #[test]
    fn flows_are_shared_across_routes_and_capped() {
        let x = relay("x", Role::Exit);
        let b = relay("b", Role::Bridge);
        let specs = enumerate_routes(&[b], &x, 1, &[None]);
        assert_eq!(specs.len(), 2);
        let f = expand_flows(&specs, 5);
        assert_eq!(f.iter().map(|s| s.bridges.len()).collect::<Vec<_>>(), [0, 1, 0, 1, 0]);
        assert_eq!(expand_flows(&specs, 1).len(), 2, "every route is still tried once");
        assert_eq!(expand_flows(&specs, 99).len(), MAX_PATHS);
        assert!(expand_flows(&[], 4).is_empty());
    }

    #[test]
    fn keeps_enough_spares() {
        assert_eq!(keep_count(1), 4);
        assert_eq!(keep_count(2), 4);
        assert_eq!(keep_count(5), 7);
        assert_eq!(keep_count(99), MAX_PATHS);
    }

    #[test]
    fn enumerates_per_interface() {
        let x = relay("x", Role::Exit);
        let i = Iface { name: "wifi".into(), ip: Ipv4Addr::LOCALHOST, index: 1 };
        let r = enumerate_routes(&[], &x, 1, &[Some(i.clone()), None]);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].label(), "[wifi] x");
        assert_eq!(r[0].iface_key(), "wifi");
    }

    #[test]
    fn virtual_interfaces_are_excluded() {
        assert!(is_virtual_iface("docker0"));
        assert!(is_virtual_iface("lagrelay0"));
        assert!(is_virtual_iface("vEthernet (WSL)"));
        assert!(!is_virtual_iface("eth0"));
        assert!(!is_virtual_iface("Wi-Fi"));
    }
}
