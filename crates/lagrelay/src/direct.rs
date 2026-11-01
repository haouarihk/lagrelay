//! The built-in `direct` route: compares going straight to a game server with
//! going through the relay, per server, and keeps comparing while connected.
//!
//! Relays can replace each other without the game server noticing, because they
//! all leave through the same exit address. Direct traffic has a different source
//! address, so moving a live connection between the two looks like a new player.
//! That's why a better route is normally only used by new connections, and live
//! traffic moves only when its route has failed, or with `--live-switch`.
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Whether a server should use the direct route, given measured latencies.
/// The relay must win by `margin`, because it's an extra thing that can fail.
pub fn choose_direct(direct: Option<f64>, relay: Option<f64>, margin: f64) -> bool {
    match (direct, relay) {
        (Some(d), Some(r)) => r + margin >= d,
        (None, Some(_)) => false,
        // Nothing to compare, or the relay can't reach it: don't add a detour.
        (_, None) => true,
    }
}

/// A change to apply to one server's route.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Action {
    /// New connections should use this route; live ones stay where they are.
    Prefer { direct: bool },
    /// Move all traffic to this route now.
    Move { direct: bool },
}

const FAILS_TO_MOVE: u32 = 3;
const LIVE_SWITCH_HOLD: Duration = Duration::from_secs(15);

/// Follows one server's two routes over time.
#[derive(Debug)]
pub struct Track {
    pub ip: Ipv4Addr,
    /// The route live traffic is on.
    pub live_direct: bool,
    /// The route new connections will use.
    pub prefer_direct: bool,
    pub direct_ms: Option<f64>,
    pub relay_ms: Option<f64>,
    direct_fails: u32,
    relay_fails: u32,
    better_since: Option<Instant>,
}

impl Track {
    pub fn new(ip: Ipv4Addr, direct: Option<f64>, relay: Option<f64>, margin: f64) -> Self {
        let d = choose_direct(direct, relay, margin);
        Track { ip, live_direct: d, prefer_direct: d, direct_ms: direct, relay_ms: relay, direct_fails: 0, relay_fails: 0, better_since: None }
    }

    /// Takes a new measurement. A missing value counts as a failure only if that
    /// route has answered before: some servers never answer pings at all.
    pub fn review(&mut self, direct: Option<f64>, relay: Option<f64>, margin: f64, live_switch: bool) -> Vec<Action> {
        let mut out = vec![];
        self.direct_fails = if direct.is_some() { 0 } else if self.direct_ms.is_some() { self.direct_fails + 1 } else { 0 };
        self.relay_fails = if relay.is_some() { 0 } else if self.relay_ms.is_some() { self.relay_fails + 1 } else { 0 };
        let direct_failed = self.direct_fails >= FAILS_TO_MOVE;
        let relay_failed = self.relay_fails >= FAILS_TO_MOVE;
        if direct.is_some() {
            self.direct_ms = direct;
        }
        if relay.is_some() {
            self.relay_ms = relay;
        }
        if self.live_direct && direct_failed && relay.is_some() {
            self.move_to(false, &mut out);
            return out;
        }
        if !self.live_direct && relay_failed && direct.is_some() {
            self.move_to(true, &mut out);
            return out;
        }
        // One route has only ever been a guess, and the other is now known to
        // work. Traffic on the unproven route may be going nowhere, so move it.
        if self.live_direct && self.direct_ms.is_none() && relay.is_some() {
            self.move_to(false, &mut out);
            return out;
        }
        if !self.live_direct && self.relay_ms.is_none() && direct.is_some() {
            self.move_to(true, &mut out);
            return out;
        }
        // Compare only with fresh values from both sides.
        let (Some(_), Some(_)) = (direct, relay) else { return out };
        let best = choose_direct(direct, relay, margin);
        if best != self.prefer_direct {
            self.prefer_direct = best;
            out.push(Action::Prefer { direct: best });
        }
        if live_switch && best != self.live_direct {
            match self.better_since {
                Some(t) if t.elapsed() >= LIVE_SWITCH_HOLD => self.move_to(best, &mut out),
                Some(_) => {}
                None => self.better_since = Some(Instant::now()),
            }
        } else {
            self.better_since = None;
        }
        out
    }

    /// Every relay is down, so move now rather than waiting for failed samples.
    /// Pointless if direct has never worked for this server.
    pub fn relays_down(&mut self) -> Vec<Action> {
        let mut out = vec![];
        if !self.live_direct && self.direct_ms.is_some() {
            self.move_to(true, &mut out);
        }
        out
    }

    fn move_to(&mut self, direct: bool, out: &mut Vec<Action>) {
        self.live_direct = direct;
        self.prefer_direct = direct;
        self.better_since = None;
        out.push(Action::Move { direct });
    }
}

/// Median ping along the normal route, bypassing the game routes.
#[cfg(target_os = "linux")]
pub async fn ping_direct(ip: Ipv4Addr) -> Option<f64> {
    let out = tokio::process::Command::new("ping")
        .args(["-n", "-q", "-c", "3", "-i", "0.2", "-W", "1", "-m", crate::capture::linux::DIRECT_MARK, &ip.to_string()])
        .output()
        .await
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    s.rsplit('=').next()?.trim().split('/').nth(1)?.parse().ok()
}

/// Windows capture only takes TCP and UDP, so ICMP always goes the normal way.
#[cfg(windows)]
pub async fn ping_direct(ip: Ipv4Addr) -> Option<f64> {
    tokio::task::spawn_blocking(move || {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::NetworkManagement::IpHelper::{IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY};
        // SAFETY: the buffer is larger than one reply plus its data, the handle is
        // checked, and it's closed before returning.
        unsafe {
            let h = IcmpCreateFile();
            if h == INVALID_HANDLE_VALUE {
                return None;
            }
            let data = [0x42u8; 32];
            let mut reply = [0u64; 32];
            let mut times = vec![];
            for _ in 0..3 {
                let n = IcmpSendEcho(h, u32::from_ne_bytes(ip.octets()), data.as_ptr().cast(), data.len() as u16, std::ptr::null(), reply.as_mut_ptr().cast(), std::mem::size_of_val(&reply) as u32, 1000);
                if n > 0 {
                    let r = &*(reply.as_ptr() as *const ICMP_ECHO_REPLY);
                    if r.Status == 0 {
                        times.push(r.RoundTripTime as f64);
                    }
                }
            }
            IcmpCloseHandle(h);
            times.sort_by(f64::total_cmp);
            times.get(times.len() / 2).copied()
        }
    })
    .await
    .ok()
    .flatten()
}

#[cfg(not(any(windows, target_os = "linux")))]
pub async fn ping_direct(_: Ipv4Addr) -> Option<f64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> Ipv4Addr {
        "1.2.3.4".parse().unwrap()
    }

    #[test]
    fn choice_needs_relay_to_win_by_margin() {
        assert!(choose_direct(Some(45.0), Some(70.0), 3.0), "direct is faster");
        assert!(!choose_direct(Some(70.0), Some(45.0), 3.0), "relay is faster");
        assert!(choose_direct(Some(50.0), Some(48.0), 3.0), "too close, so skip the detour");
        assert!(!choose_direct(None, Some(48.0), 3.0), "direct doesn't answer");
        assert!(choose_direct(Some(50.0), None, 3.0), "relay can't reach it");
        assert!(choose_direct(None, None, 3.0), "no evidence, so no detour");
    }

    #[test]
    fn better_route_only_affects_new_connections_by_default() {
        let mut t = Track::new(ip(), Some(45.0), Some(70.0), 3.0);
        assert!(t.live_direct);
        assert_eq!(t.review(Some(90.0), Some(70.0), 3.0, false), vec![Action::Prefer { direct: false }]);
        assert!(t.live_direct, "live traffic stays put");
        assert!(!t.prefer_direct);
        assert!(t.review(Some(90.0), Some(70.0), 3.0, false).is_empty(), "reported once");
    }

    #[test]
    fn direct_failure_moves_live_traffic_to_relay() {
        let mut t = Track::new(ip(), Some(45.0), Some(70.0), 3.0);
        assert!(t.review(None, Some(70.0), 3.0, false).is_empty());
        assert!(t.review(None, Some(70.0), 3.0, false).is_empty(), "a couple of lost samples isn't an outage");
        assert_eq!(t.review(None, Some(70.0), 3.0, false), vec![Action::Move { direct: false }]);
        assert!(!t.live_direct);
    }

    #[test]
    fn relay_failure_moves_live_traffic_to_direct() {
        let mut t = Track::new(ip(), Some(70.0), Some(45.0), 3.0);
        for _ in 0..2 {
            assert!(t.review(Some(70.0), None, 3.0, false).is_empty());
        }
        assert_eq!(t.review(Some(70.0), None, 3.0, false), vec![Action::Move { direct: true }]);
    }

    #[test]
    fn no_failover_onto_a_dead_route() {
        let mut t = Track::new(ip(), Some(45.0), Some(70.0), 3.0);
        for _ in 0..5 {
            assert!(t.review(None, None, 3.0, false).is_empty());
        }
        assert!(t.live_direct);
    }

    #[test]
    fn server_that_never_answers_pings_is_not_an_outage() {
        let mut t = Track::new(ip(), None, Some(70.0), 3.0);
        assert!(!t.live_direct);
        for _ in 0..5 {
            assert!(t.review(None, Some(70.0), 3.0, false).is_empty());
        }
    }

    #[test]
    fn a_route_chosen_without_evidence_gives_way_to_one_that_works() {
        let mut t = Track::new(ip(), None, None, 3.0);
        assert!(t.live_direct, "nothing measured yet, so no detour");
        assert_eq!(t.review(None, Some(40.0), 3.0, false), vec![Action::Move { direct: false }]);
        assert!(!t.live_direct);
        // The relay was picked because direct didn't answer; it hasn't been proven either way.
        let mut t = Track::new(ip(), None, None, 3.0);
        t.live_direct = false;
        assert_eq!(t.review(Some(40.0), None, 3.0, false), vec![Action::Move { direct: true }]);
    }

    #[test]
    fn relays_down_moves_only_if_direct_has_worked() {
        let mut t = Track::new(ip(), Some(70.0), Some(45.0), 3.0);
        assert_eq!(t.relays_down(), vec![Action::Move { direct: true }]);
        assert!(t.relays_down().is_empty(), "already there");
        let mut t = Track::new(ip(), None, Some(45.0), 3.0);
        assert!(t.relays_down().is_empty(), "direct has never reached this server");
    }

    #[test]
    fn live_switch_waits_for_a_sustained_win() {
        let mut t = Track::new(ip(), Some(45.0), Some(70.0), 3.0);
        assert_eq!(t.review(Some(90.0), Some(70.0), 3.0, true), vec![Action::Prefer { direct: false }]);
        assert!(t.live_direct, "first sighting only starts the timer");
        t.better_since = Some(Instant::now() - LIVE_SWITCH_HOLD);
        assert_eq!(t.review(Some(90.0), Some(70.0), 3.0, true), vec![Action::Move { direct: false }]);
        assert!(!t.live_direct);
    }

    #[test]
    fn live_switch_timer_resets_if_the_win_fades() {
        let mut t = Track::new(ip(), Some(45.0), Some(70.0), 3.0);
        t.review(Some(90.0), Some(70.0), 3.0, true);
        t.review(Some(45.0), Some(70.0), 3.0, true);
        assert!(t.better_since.is_none());
    }
}
