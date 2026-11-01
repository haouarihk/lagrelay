//! Packet capture backends.
//!
//! Each backend delivers the game's outbound IPv4 packets with the source
//! already set to the tunnel address, and injects returned packets into the
//! local stack as if they had arrived from the network.
use crate::rules::Matcher;
use anyhow::Result;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::mpsc;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(windows)]
pub mod windivert;
#[cfg(windows)]
pub mod windows;

/// Sets how traffic to a server travels: `(server, use_direct, move_live_traffic)`.
/// Without the last flag, only connections that haven't started yet are affected.
pub type Applier = Arc<dyn Fn(Ipv4Addr, bool, bool) + Send + Sync>;

/// Most packets held for one server while its route is being measured.
const MAX_HELD: usize = 64;

enum BookEntry<T> {
    Pending(Vec<T>),
    Direct,
    Relay,
}

/// What to do with a packet whose server has this state.
#[derive(Debug, PartialEq)]
pub enum Seen<T> {
    Direct(T),
    Relay(T),
    Held,
    /// Held, and this is the first packet, so a measurement must be requested.
    HeldNew,
}

/// Per-server route choices, plus packets waiting for a server's first decision.
pub struct Book<T> {
    entries: HashMap<Ipv4Addr, BookEntry<T>>,
}

impl<T> Default for Book<T> {
    fn default() -> Self {
        Book { entries: HashMap::new() }
    }
}

impl<T> Book<T> {
    pub fn see(&mut self, dst: Ipv4Addr, item: T) -> Seen<T> {
        match self.entries.get_mut(&dst) {
            Some(BookEntry::Direct) => Seen::Direct(item),
            Some(BookEntry::Relay) => Seen::Relay(item),
            Some(BookEntry::Pending(q)) => {
                if q.len() < MAX_HELD {
                    q.push(item);
                }
                Seen::Held
            }
            None => {
                self.entries.insert(dst, BookEntry::Pending(vec![item]));
                Seen::HeldNew
            }
        }
    }

    /// Records the choice and returns any packets that were waiting for it.
    pub fn resolve(&mut self, dst: Ipv4Addr, direct: bool) -> Vec<T> {
        let new = if direct { BookEntry::Direct } else { BookEntry::Relay };
        match self.entries.insert(dst, new) {
            Some(BookEntry::Pending(q)) => q,
            _ => vec![],
        }
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn is_pending(&self, dst: Ipv4Addr) -> bool {
        matches!(self.entries.get(&dst), Some(BookEntry::Pending(_)))
    }
}

pub struct CaptureParams {
    pub matcher: Matcher,
    pub vip: Ipv4Addr,
    /// Relay addresses whose traffic must never be captured.
    pub relay_ips: Vec<Ipv4Addr>,
    #[cfg_attr(not(windows), allow(dead_code))]
    pub block_ipv6: bool,
    /// While false, new flows bypass the tunnel instead of being black-holed.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub tunnel_up: Arc<AtomicBool>,
    /// When on, each new server is measured first and may stay on the direct route.
    pub auto_direct: bool,
    /// Requests a route measurement for a newly contacted server.
    pub decide: mpsc::UnboundedSender<Ipv4Addr>,
}

pub struct Capture {
    pub outbound: mpsc::Receiver<Vec<u8>>,
    pub inbound: mpsc::Sender<Vec<u8>>,
    pub guard: Box<dyn Send>,
    pub apply: Applier,
    pub description: String,
}

#[cfg(windows)]
pub async fn start(p: CaptureParams) -> Result<Capture> {
    windows::start(p)
}

#[cfg(target_os = "linux")]
pub async fn start(p: CaptureParams) -> Result<Capture> {
    linux::start(p).await
}

#[cfg(not(any(windows, target_os = "linux")))]
pub async fn start(_: CaptureParams) -> Result<Capture> {
    anyhow::bail!("packet capture is only implemented for Windows and Linux")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn book_holds_until_resolved_then_routes() {
        let ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let mut b = Book::default();
        assert_eq!(b.see(ip, 1), Seen::HeldNew);
        assert_eq!(b.see(ip, 2), Seen::Held, "only the first packet requests a measurement");
        assert!(b.is_pending(ip));
        assert_eq!(b.resolve(ip, true), vec![1, 2]);
        assert_eq!(b.see(ip, 3), Seen::Direct(3));
        assert!(b.resolve(ip, false).is_empty());
        assert_eq!(b.see(ip, 4), Seen::Relay(4), "a later choice applies to new traffic");
    }

    #[test]
    fn book_limits_held_packets() {
        let ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let mut b = Book::default();
        for i in 0..MAX_HELD + 50 {
            b.see(ip, i);
        }
        assert_eq!(b.resolve(ip, true).len(), MAX_HELD);
    }
}
