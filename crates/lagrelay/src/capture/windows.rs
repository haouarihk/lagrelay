//! Windows capture through WinDivert: picks packets by owning process, rewrites
//! the source to the tunnel address, and injects replies as inbound packets.
use super::windivert::{Address, Handle, ERROR_INVALID_HANDLE, ERROR_NO_DATA, MTU_MAX};
use super::{Applier, Book, Capture, CaptureParams, Seen};
use anyhow::Result;
use lagcore::ip::{clamp_mss, fix_checksums, parse_ipv4, rewrite_dst, rewrite_src, PROTO_TCP, PROTO_UDP};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use windows_sys::Win32::Foundation::{CloseHandle, FALSE, INVALID_HANDLE_VALUE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPTABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};

const FLOW_TTL: Duration = Duration::from_secs(300);
/// A tunnelled TCP flow can't fall back to direct mid-connection, so an idle one
/// must keep its entry far longer than anything else.
const TCP_TUNNEL_TTL: Duration = Duration::from_secs(24 * 3600);
const OWNER_REFRESH: Duration = Duration::from_millis(5);

/// Reads the OS table of which process owns each local port.
struct PortOwners {
    tcp: HashMap<u16, u32>,
    udp: HashMap<u16, u32>,
    refreshed: Option<Instant>,
    names: HashMap<u32, (String, Instant)>,
}

/// (pid, lowercase executable name) of every running process.
pub fn snapshot_processes() -> Vec<(u32, String)> {
    let mut out = Vec::new();
    // SAFETY: the snapshot handle is closed below and `e` is correctly sized.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut e);
        while ok != 0 {
            let len = e.szExeFile.iter().position(|c| *c == 0).unwrap_or(e.szExeFile.len());
            out.push((e.th32ProcessID, String::from_utf16_lossy(&e.szExeFile[..len]).to_ascii_lowercase()));
            ok = Process32NextW(snap, &mut e);
        }
        CloseHandle(snap);
    }
    out
}

fn table(call: impl Fn(*mut core::ffi::c_void, *mut u32) -> u32) -> Option<Vec<u64>> {
    let mut size = 0u32;
    call(std::ptr::null_mut(), &mut size);
    // Over-allocate: the table can grow between the two calls. A u64 buffer
    // guarantees alignment for the table structs.
    let mut buf = vec![0u64; (size as usize + 4096) / 8 + 1];
    let mut cap = (buf.len() * 8) as u32;
    (call(buf.as_mut_ptr().cast(), &mut cap) == NO_ERROR).then_some(buf)
}

impl PortOwners {
    fn new() -> Self {
        PortOwners { tcp: HashMap::new(), udp: HashMap::new(), refreshed: None, names: HashMap::new() }
    }

    fn refresh(&mut self) {
        if self.refreshed.is_some_and(|t| t.elapsed() < OWNER_REFRESH) {
            return;
        }
        self.refreshed = Some(Instant::now());
        self.tcp.clear();
        self.udp.clear();
        let tcp = table(|p, s| {
            // SAFETY: p and s are valid for the buffer size reported in s.
            unsafe { GetExtendedTcpTable(p, s, FALSE, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0) }
        });
        if let Some(b) = tcp {
            // SAFETY: the API filled the buffer with a table of dwNumEntries rows.
            let t = unsafe { &*(b.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
            let rows = unsafe { std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize) };
            for r in rows {
                // TIME_WAIT rows have PID 0 and could hide the real owner.
                if r.dwOwningPid != 0 {
                    self.tcp.insert(u16::from_be(r.dwLocalPort as u16), r.dwOwningPid);
                }
            }
        }
        let udp = table(|p, s| {
            // SAFETY: p and s are valid for the buffer size reported in s.
            unsafe { GetExtendedUdpTable(p, s, FALSE, AF_INET as u32, UDP_TABLE_OWNER_PID, 0) }
        });
        if let Some(b) = udp {
            // SAFETY: as above.
            let t = unsafe { &*(b.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
            let rows = unsafe { std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize) };
            for r in rows {
                self.udp.insert(u16::from_be(r.dwLocalPort as u16), r.dwOwningPid);
            }
        }
    }

    /// Looks the name up in a system-wide process snapshot. This deliberately
    /// never opens a handle to the process: anti-cheat systems watch for handles
    /// to the game and often deny them, which would also misclassify the flow.
    fn process_name(&mut self, pid: u32) -> Option<String> {
        if let Some((n, t)) = self.names.get(&pid) {
            if t.elapsed() < Duration::from_secs(30) {
                return Some(n.clone());
            }
        }
        for (p, n) in snapshot_processes() {
            self.names.insert(p, (n, Instant::now()));
        }
        self.names.get(&pid).map(|(n, _)| n.clone())
    }

    /// The executable name that owns a local port, refreshing the table on a miss.
    fn owner(&mut self, proto: u8, port: u16) -> Option<String> {
        let look = |s: &Self| if proto == PROTO_TCP { s.tcp.get(&port).copied() } else { s.udp.get(&port).copied() };
        let pid = look(self).or_else(|| {
            self.refresh();
            look(self)
        });
        match pid {
            Some(pid) => self.process_name(pid),
            // A dual-stack socket (common in Java and .NET) appears only in the
            // IPv6 tables, even when it is sending IPv4 packets.
            None => owner_v6(proto, port),
        }
    }
}

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct FlowKey {
    proto: u8,
    local_port: u16,
    remote: Ipv4Addr,
    remote_port: u16,
}

#[derive(Clone, Copy)]
struct Flow {
    tunnel: bool,
    local_ip: Ipv4Addr,
    if_idx: u32,
    sub_if_idx: u32,
    last_seen: Instant,
}

#[derive(Default)]
struct Flows {
    map: HashMap<FlowKey, Flow>,
    /// The most recent local route per remote host, for fragments that carry
    /// no ports and so cannot be looked up by flow.
    by_remote: HashMap<Ipv4Addr, (Ipv4Addr, u32, u32)>,
}

impl Flows {
    fn expire(&mut self) {
        self.map.retain(|k, f| f.last_seen.elapsed() < if f.tunnel && k.proto == PROTO_TCP { TCP_TUNNEL_TTL } else { FLOW_TTL });
    }
}

fn build_filter(p: &CaptureParams) -> String {
    filter_string(&p.relay_ips, &p.matcher.ports, !p.matcher.processes.is_empty())
}

/// Port narrowing is skipped for process rules, because those need to see every
/// flow from the game to decide on it.
pub fn filter_string(relay_ips: &[Ipv4Addr], ports: &[(u16, u16)], by_process: bool) -> String {
    // Later IP fragments have no TCP or UDP header, so `tcp or udp` alone would
    // let them leave with the real source address.
    let mut f = String::from("outbound and !loopback and !impostor and (tcp or udp or (ip and fragment))");
    // WinDivert only allows `not` before a field, and ip.DstAddr != x is false for
    // IPv6 packets, which must still reach the IPv6 blocking logic.
    for r in relay_ips {
        f += &format!(" and (ipv6 or ip.DstAddr != {r})");
    }
    if !ports.is_empty() && !by_process {
        let parts: Vec<String> = ports.iter().map(|(a, b)| format!("(tcp.DstPort >= {a} and tcp.DstPort <= {b}) or (udp.DstPort >= {a} and udp.DstPort <= {b})")).collect();
        f += &format!(" and (fragment or {})", parts.join(" or "));
    }
    f
}

pub fn start(p: CaptureParams) -> Result<Capture> {
    let filter = build_filter(&p);
    let handle = Arc::new(Handle::open(&filter)?);
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(4096);
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(4096);
    let flows = Arc::new(Mutex::new(Flows::default()));
    let book: Arc<Mutex<Book<(Vec<u8>, Address)>>> = Arc::default();
    let vip = p.vip;
    let (h1, f1, o1, b1) = (handle.clone(), flows.clone(), out_tx.clone(), book.clone());
    std::thread::Builder::new().name("lagrelay-capture".into()).spawn(move || outbound_loop(h1, f1, b1, p, o1))?;
    let (h2, f2) = (handle.clone(), flows.clone());
    std::thread::Builder::new().name("lagrelay-inject".into()).spawn(move || inbound_loop(h2, f2, in_rx))?;
    let h3 = handle.clone();
    let apply: Applier = Arc::new(move |dst, direct, force| {
        let held = book.lock().unwrap().resolve(dst, direct);
        for (mut pkt, addr) in held {
            let Some(i) = parse_ipv4(&pkt) else { continue };
            remember_flow(&flows, &i, &addr, !direct);
            if direct {
                let _ = h3.send(&pkt, &addr);
            } else {
                send_tunnelled(&mut pkt, &i, vip, &out_tx);
            }
        }
        if force {
            let mut fl = flows.lock().unwrap();
            let mut route = None;
            for (_, f) in fl.map.iter_mut().filter(|(k, _)| k.remote == dst) {
                f.tunnel = !direct;
                route = Some((f.local_ip, f.if_idx, f.sub_if_idx));
            }
            match (direct, route) {
                (true, _) => {
                    fl.by_remote.remove(&dst);
                }
                (false, Some(r)) => {
                    fl.by_remote.insert(dst, r);
                }
                _ => {}
            }
        }
    });
    Ok(Capture { outbound: out_rx, inbound: in_tx, guard: Box::new(ShutdownGuard(handle)), apply, description: "WinDivert, by process".into() })
}

/// The capture threads hold their own references to the handle, so dropping one
/// reference would not stop diverting. This stops it explicitly.
struct ShutdownGuard(Arc<Handle>);

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

/// Rewrites a captured packet for the tunnel and queues it. When the queue is full
/// the packet is dropped, as a congested network would, rather than stalling every
/// other process's traffic.
fn send_tunnelled(pkt: &mut [u8], i: &lagcore::ip::Ipv4Info, vip: Ipv4Addr, out: &mpsc::Sender<Vec<u8>>) {
    if i.tcp_syn {
        clamp_mss(pkt, lagcore::TUNNEL_MSS);
    }
    rewrite_src(pkt, vip);
    fix_checksums(pkt);
    let _ = out.try_send(pkt.to_vec());
}

fn remember_flow(flows: &Mutex<Flows>, i: &lagcore::ip::Ipv4Info, addr: &Address, tunnel: bool) {
    let key = FlowKey { proto: i.proto, local_port: i.src_port, remote: i.dst, remote_port: i.dst_port };
    let mut fl = flows.lock().unwrap();
    if !(i.is_fragment && !i.is_first_fragment) {
        fl.map.insert(key, Flow { tunnel, local_ip: i.src, if_idx: addr.if_idx, sub_if_idx: addr.sub_if_idx, last_seen: Instant::now() });
    }
    if tunnel {
        fl.by_remote.insert(i.dst, (i.src, addr.if_idx, addr.sub_if_idx));
    }
}

/// What the capture thread should do with one packet.
enum Verdict {
    Direct,
    Tunnel,
    Held,
}

fn outbound_loop(h: Arc<Handle>, flows: Arc<Mutex<Flows>>, book: Arc<Mutex<Book<(Vec<u8>, Address)>>>, p: CaptureParams, out: mpsc::Sender<Vec<u8>>) {
    let mut owners = PortOwners::new();
    let mut buf = vec![0u8; MTU_MAX];
    let mut last_expire = Instant::now();
    let mut v6_cache: HashMap<(u8, u16), (bool, Instant)> = HashMap::new();
    loop {
        let (n, addr) = match h.recv(&mut buf) {
            Ok(v) => v,
            Err(e) if matches!(e.raw_os_error(), Some(ERROR_NO_DATA | ERROR_INVALID_HANDLE)) => return,
            Err(_) => {
                // Leaving now would keep diverting with nobody reading, which
                // would black-hole every matched packet on the machine.
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
        };
        let pkt = &mut buf[..n];
        if addr.is_ipv6() {
            if p.block_ipv6 && !p.matcher.processes.is_empty() {
                // Drop the matched game's IPv6 so it falls back to the IPv4 tunnel.
                if let Some(key) = ipv6_src_port(pkt) {
                    let hit = v6_cache.get(&key).filter(|(_, t)| t.elapsed() < Duration::from_secs(5)).map(|(b, _)| *b);
                    let blocked = hit.unwrap_or_else(|| {
                        let b = owner_v6(key.0, key.1).is_some_and(|n| p.matcher.wants_process(&n));
                        if v6_cache.len() > 4096 {
                            v6_cache.clear();
                        }
                        v6_cache.insert(key, (b, Instant::now()));
                        b
                    });
                    if blocked {
                        continue;
                    }
                }
            }
            let _ = h.send(pkt, &addr);
            continue;
        }
        let Some(i) = parse_ipv4(pkt) else {
            let _ = h.send(pkt, &addr);
            continue;
        };
        if last_expire.elapsed() > Duration::from_secs(30) {
            flows.lock().unwrap().expire();
            last_expire = Instant::now();
        }
        match decide(&i, pkt, &addr, &flows, &book, &mut owners, &p) {
            Verdict::Direct => {
                let _ = h.send(pkt, &addr);
            }
            Verdict::Tunnel => send_tunnelled(pkt, &i, p.vip, &out),
            Verdict::Held => {}
        }
    }
}

/// Returns (protocol, source port) of an IPv6 packet with no extension headers.
fn ipv6_src_port(p: &[u8]) -> Option<(u8, u16)> {
    if p.len() < 44 || p[0] >> 4 != 6 || !matches!(p[6], PROTO_TCP | PROTO_UDP) {
        return None;
    }
    Some((p[6], u16::from_be_bytes([p[40], p[41]])))
}

/// Resolves the owner of an IPv6 socket through the dual-stack tables.
fn owner_v6(proto: u8, port: u16) -> Option<String> {
    use windows_sys::Win32::Networking::WinSock::AF_INET6;
    let mut size = 0u32;
    // SAFETY: first call only reports the size; second fills our buffer.
    unsafe {
        if proto == PROTO_TCP {
            GetExtendedTcpTable(std::ptr::null_mut(), &mut size, FALSE, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        } else {
            GetExtendedUdpTable(std::ptr::null_mut(), &mut size, FALSE, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0);
        }
        let mut b = vec![0u64; (size as usize + 4096) / 8 + 1];
        let mut cap = (b.len() * 8) as u32;
        let rc = if proto == PROTO_TCP {
            GetExtendedTcpTable(b.as_mut_ptr().cast(), &mut cap, FALSE, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0)
        } else {
            GetExtendedUdpTable(b.as_mut_ptr().cast(), &mut cap, FALSE, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0)
        };
        if rc != NO_ERROR {
            return None;
        }
        let pid = if proto == PROTO_TCP {
            let t = &*(b.as_ptr() as *const windows_sys::Win32::NetworkManagement::IpHelper::MIB_TCP6TABLE_OWNER_PID);
            std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize)
                .iter()
                .find(|r| u16::from_be(r.dwLocalPort as u16) == port)
                .map(|r| r.dwOwningPid)
        } else {
            let t = &*(b.as_ptr() as *const windows_sys::Win32::NetworkManagement::IpHelper::MIB_UDP6TABLE_OWNER_PID);
            std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize)
                .iter()
                .find(|r| u16::from_be(r.dwLocalPort as u16) == port)
                .map(|r| r.dwOwningPid)
        }?;
        PortOwners::new().process_name(pid)
    }
}

fn decide(i: &lagcore::ip::Ipv4Info, pkt: &[u8], addr: &Address, flows: &Mutex<Flows>, book: &Mutex<Book<(Vec<u8>, Address)>>, owners: &mut PortOwners, p: &CaptureParams) -> Verdict {
    let verdict = |t| if t { Verdict::Tunnel } else { Verdict::Direct };
    let key = FlowKey { proto: i.proto, local_port: i.src_port, remote: i.dst, remote_port: i.dst_port };
    {
        let mut fl = flows.lock().unwrap();
        // A later fragment has no ports. Follow the first fragment's decision,
        // which recorded this remote host only if the flow was tunnelled.
        if i.is_fragment && !i.is_first_fragment {
            return verdict(fl.by_remote.contains_key(&i.dst));
        }
        if let Some(f) = fl.map.get_mut(&key) {
            f.last_seen = Instant::now();
            return verdict(f.tunnel);
        }
    }
    // Lookups below can take milliseconds, so they run without the lock that the
    // inject thread needs for every returning packet.
    let dest_ok = p.matcher.wants_dest(i.dst, i.dst_port, false);
    let by_process = !p.matcher.processes.is_empty();
    let proc_ok = if dest_ok && by_process {
        match owners.owner(i.proto, i.src_port) {
            Some(n) => p.matcher.wants_process(&n),
            // Owner not known yet: the socket may be brand new. Send this packet
            // direct, but don't remember, so the next packet is decided again.
            None => return Verdict::Direct,
        }
    } else {
        dest_ok
    };
    // TCP connections that were established before capture started cannot move
    // to a new source address, so they stay direct until the game reconnects.
    let tcp_ok = i.proto != PROTO_TCP || i.tcp_syn;
    let up = p.tunnel_up.load(Ordering::Relaxed);
    let wanted = dest_ok && proc_ok && tcp_ok;
    if wanted && !up {
        return Verdict::Direct; // Don't remember: retry once the tunnel is up.
    }
    let mut tunnel = wanted;
    if wanted && p.auto_direct {
        let seen = book.lock().unwrap().see(i.dst, (pkt.to_vec(), *addr));
        match seen {
            Seen::Direct(_) => tunnel = false,
            Seen::Relay(_) => {}
            Seen::Held => return Verdict::Held,
            Seen::HeldNew => {
                let _ = p.decide.send(i.dst);
                return Verdict::Held;
            }
        }
    }
    remember_flow(flows, i, addr, tunnel);
    verdict(tunnel)
}

fn inbound_loop(h: Arc<Handle>, flows: Arc<Mutex<Flows>>, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(mut pkt) = rx.blocking_recv() {
        let Some(i) = parse_ipv4(&pkt) else { continue };
        let route = {
            let fl = flows.lock().unwrap();
            let by_flow = (!i.is_fragment || i.is_first_fragment)
                .then(|| FlowKey { proto: i.proto, local_port: i.dst_port, remote: i.src, remote_port: i.src_port })
                .and_then(|k| fl.map.get(&k))
                .filter(|f| f.tunnel)
                .map(|f| (f.local_ip, f.if_idx, f.sub_if_idx));
            // Replies always start from a flow we opened, so a miss on a whole
            // packet is unsolicited traffic and must not reach the local stack.
            if i.is_fragment {
                by_flow.or_else(|| fl.by_remote.get(&i.src).copied())
            } else {
                by_flow
            }
        };
        let Some((local_ip, if_idx, sub_if_idx)) = route else { continue };
        if i.tcp_syn {
            clamp_mss(&mut pkt, lagcore::TUNNEL_MSS);
        }
        rewrite_dst(&mut pkt, local_ip);
        fix_checksums(&mut pkt);
        let _ = h.send(&pkt, &Address::inbound(if_idx, sub_if_idx));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compiles against the real DLL when it sits beside the test binary.
    #[test]
    fn filters_compile_in_windivert() {
        let dir = std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
        if !dir.join("WinDivert.dll").exists() {
            return;
        }
        let ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        for f in [
            filter_string(&[], &[], true),
            filter_string(&[ip, ip], &[], true),
            filter_string(&[ip], &[(27000, 27100), (9000, 9000)], false),
        ] {
            super::super::windivert::validate_filter(&f).unwrap_or_else(|e| panic!("{e:#}"));
        }
    }
}
