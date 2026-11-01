//! Path quality scoring and the route optimizer's switching policy.
use std::time::{Duration, Instant};

const LOSS_WINDOW: u32 = 20;

/// Rolling path statistics, measured with encrypted pings to the exit relay.
#[derive(Debug, Clone)]
pub struct PathStats {
    pub rtt_ms: f64,
    pub jitter_ms: f64,
    pub samples: u64,
    pub sent: u64,
    pub received: u64,
    window_sent: u32,
    window_recv: u32,
    windows_closed: u32,
    pub loss_pct: f64,
    pub last_rx: Option<Instant>,
}

impl Default for PathStats {
    fn default() -> Self {
        PathStats {
            rtt_ms: 0.0,
            jitter_ms: 0.0,
            samples: 0,
            sent: 0,
            received: 0,
            window_sent: 0,
            window_recv: 0,
            windows_closed: 0,
            loss_pct: 0.0,
            last_rx: None,
        }
    }
}

impl PathStats {
    pub fn on_sent(&mut self) {
        // Close the window before counting this ping, so the previous ping has
        // had a full interval to be answered. Pongs still in flight simply
        // count towards the next window.
        if self.window_sent >= LOSS_WINDOW {
            let got = self.window_recv.min(self.window_sent);
            let w = (self.window_sent - got) as f64 / self.window_sent as f64 * 100.0;
            self.loss_pct = if self.windows_closed == 0 { w } else { self.loss_pct * 0.5 + w * 0.5 };
            self.windows_closed += 1;
            self.window_recv = self.window_recv.saturating_sub(got);
            self.window_sent = 0;
        }
        self.sent += 1;
        self.window_sent += 1;
    }

    pub fn on_rtt(&mut self, rtt_ms: f64) {
        if self.samples == 0 {
            self.rtt_ms = rtt_ms;
        } else {
            // RFC 3550-style jitter and a fast-reacting RTT average.
            self.jitter_ms += ((rtt_ms - self.rtt_ms).abs() - self.jitter_ms) / 8.0;
            self.rtt_ms += (rtt_ms - self.rtt_ms) / 4.0;
        }
        self.samples += 1;
        self.received += 1;
        self.window_recv += 1;
        self.last_rx = Some(Instant::now());
    }

    pub fn is_alive(&self, timeout: Duration) -> bool {
        self.last_rx.is_some_and(|t| t.elapsed() < timeout)
    }

    /// Lower is better. Jitter and loss are expressed as equivalent latency:
    /// in a game they hurt more than a constant few extra milliseconds.
    pub fn score(&self) -> f64 {
        score(self.rtt_ms, self.jitter_ms, self.loss_pct)
    }
}

pub fn score(rtt_ms: f64, jitter_ms: f64, loss_pct: f64) -> f64 {
    rtt_ms + 2.0 * jitter_ms + 10.0 * loss_pct
}

/// Switching policy: a candidate must beat the current route by `threshold`,
/// sustained for `hold`. The threshold rises after each switch to prevent
/// flapping, and decays again while the route stays stable.
#[derive(Debug, Clone)]
pub struct Optimizer {
    pub threshold_pct: f64,
    pub min_pct: f64,
    pub max_pct: f64,
    hold: Duration,
    decay_every: Duration,
    candidate: Option<(usize, Instant)>,
    last_change: Instant,
}

impl Optimizer {
    pub fn new(hold: Duration, decay_every: Duration) -> Self {
        Optimizer {
            threshold_pct: 15.0,
            min_pct: 5.0,
            max_pct: 50.0,
            hold,
            decay_every,
            candidate: None,
            last_change: Instant::now(),
        }
    }

    /// Decides whether `best` should replace `current`. Returns true to switch.
    pub fn evaluate(&mut self, current_score: f64, best: usize, best_score: f64) -> bool {
        if self.last_change.elapsed() >= self.decay_every {
            self.threshold_pct = (self.threshold_pct * 0.8).max(self.min_pct);
            self.last_change = Instant::now();
        }
        let beats = best_score < current_score * (1.0 - self.threshold_pct / 100.0);
        if !beats {
            self.candidate = None;
            return false;
        }
        match self.candidate {
            Some((c, since)) if c == best => {
                if since.elapsed() >= self.hold {
                    self.candidate = None;
                    self.threshold_pct = (self.threshold_pct * 1.5).min(self.max_pct);
                    self.last_change = Instant::now();
                    return true;
                }
                false
            }
            _ => {
                self.candidate = Some((best, Instant::now()));
                false
            }
        }
    }
}

/// Decides when to try new flows, and how many: a slow trickle normally, and a
/// burst when the routes in use have become clearly worse than their recent best.
#[derive(Debug)]
pub struct ExplorePolicy {
    baseline: Option<f64>,
    degraded_since: Option<Instant>,
    last: Instant,
    every: Duration,
    burst_every: Duration,
    give_up_after: Duration,
}

pub const EXPLORE_NORMAL: usize = 4;
pub const EXPLORE_BURST: usize = 8;

impl ExplorePolicy {
    pub fn new(every: Duration, burst_every: Duration, give_up_after: Duration) -> Self {
        ExplorePolicy { baseline: None, degraded_since: None, last: Instant::now(), every, burst_every, give_up_after }
    }

    /// Call regularly with the best active route's score. Returns how many new
    /// flows to try now, if any.
    pub fn tick(&mut self, score: Option<f64>) -> Option<usize> {
        let mut degraded = false;
        if let Some(s) = score {
            let base = *self.baseline.get_or_insert(s);
            // The fixed margin stops tiny jitter on a very low ping counting.
            if s > base * 1.2 + 3.0 {
                let since = *self.degraded_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= self.give_up_after {
                    // Everything got slower and searching hasn't helped, so this
                    // is the new normal. Stop bursting.
                    self.baseline = Some(s);
                    self.degraded_since = None;
                } else {
                    degraded = true;
                }
            } else {
                self.degraded_since = None;
                self.baseline = Some(base.min(s));
            }
        }
        let (due, n) = if degraded { (self.burst_every, EXPLORE_BURST) } else { (self.every, EXPLORE_NORMAL) };
        if self.last.elapsed() >= due {
            self.last = Instant::now();
            return Some(n);
        }
        None
    }
}

/// One measured path offered to [`select_active`].
#[derive(Debug, Clone)]
pub struct Candidate {
    pub idx: usize,
    pub iface: String,
    pub first_hop: String,
    pub score: f64,
    pub alive: bool,
}

/// Picks up to `n` paths, best score first, preferring routes that fail
/// independently. In multi-internet mode each network interface is used before
/// any interface is used twice; a different first hop is preferred next, so a
/// single relay outage cannot take out every copy of the traffic.
pub fn select_active(cands: &[Candidate], n: usize, multi_internet: bool) -> Vec<usize> {
    let mut alive: Vec<&Candidate> = cands.iter().filter(|c| c.alive).collect();
    alive.sort_by(|a, b| a.score.total_cmp(&b.score));
    let mut out: Vec<&Candidate> = Vec::new();
    if multi_internet {
        for c in &alive {
            if out.len() < n && !out.iter().any(|o| o.iface == c.iface) {
                out.push(c);
            }
        }
    }
    for c in &alive {
        if out.len() < n && !out.iter().any(|o| o.idx == c.idx || o.first_hop == c.first_hop) {
            out.push(c);
        }
    }
    for c in &alive {
        if out.len() < n && !out.iter().any(|o| o.idx == c.idx) {
            out.push(c);
        }
    }
    out.iter().map(|c| c.idx).collect()
}

/// Which paths survive a prune: anything carrying traffic, plus the `keep` best
/// by the same rules as [`select_active`], so spares stay diverse too.
pub fn paths_to_keep(cands: &[Candidate], active: &[usize], keep: usize, multi_internet: bool) -> Vec<usize> {
    let mut out = select_active(cands, keep, multi_internet);
    for a in active {
        if !out.contains(a) {
            out.push(*a);
        }
    }
    out.sort_unstable();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ExplorePolicy {
        ExplorePolicy::new(Duration::from_secs(3600), Duration::ZERO, Duration::from_secs(3600))
    }

    #[test]
    fn explore_stays_quiet_while_healthy() {
        let mut p = policy();
        assert_eq!(p.tick(Some(45.0)), None);
        assert_eq!(p.tick(Some(47.0)), None, "normal variation");
        assert_eq!(p.tick(None), None);
    }

    #[test]
    fn explore_bursts_when_clearly_worse_than_baseline() {
        let mut p = policy();
        p.tick(Some(45.0));
        assert_eq!(p.tick(Some(70.0)), Some(EXPLORE_BURST));
        assert_eq!(p.tick(Some(45.0)), None, "recovered");
    }

    #[test]
    fn explore_baseline_follows_improvement() {
        let mut p = policy();
        p.tick(Some(60.0));
        p.tick(Some(40.0));
        assert_eq!(p.tick(Some(55.0)), Some(EXPLORE_BURST), "judged against the new, better baseline");
    }

    #[test]
    fn explore_gives_up_when_everything_is_slower() {
        let mut p = ExplorePolicy::new(Duration::from_secs(3600), Duration::ZERO, Duration::ZERO);
        p.tick(Some(45.0));
        assert_eq!(p.tick(Some(80.0)), None, "accepted as the new normal");
        assert_eq!(p.tick(Some(80.0)), None);
    }

    #[test]
    fn explore_trickles_on_schedule() {
        let mut p = ExplorePolicy::new(Duration::ZERO, Duration::ZERO, Duration::from_secs(3600));
        assert_eq!(p.tick(Some(45.0)), Some(EXPLORE_NORMAL));
    }

    #[test]
    fn prune_keeps_best_and_everything_active() {
        let c = [cand(0, "e", "a", 66.0, true), cand(1, "e", "a", 45.0, true), cand(2, "e", "a", 46.0, true), cand(3, "e", "a", 60.0, true), cand(4, "e", "a", 10.0, false)];
        assert_eq!(paths_to_keep(&c, &[], 2, false), vec![1, 2]);
        assert_eq!(paths_to_keep(&c, &[0], 2, false), vec![0, 1, 2], "an active route is never dropped");
        assert_eq!(paths_to_keep(&c, &[], 9, false), vec![0, 1, 2, 3], "dead candidates are dropped");
    }

    #[test]
    fn prune_keeps_spares_on_other_first_hops() {
        let c = [cand(0, "e", "a", 10.0, true), cand(1, "e", "a", 11.0, true), cand(2, "e", "b", 50.0, true)];
        assert_eq!(paths_to_keep(&c, &[], 2, false), vec![0, 2], "a slower bridge beats a second flow to the same one");
    }

    fn cand(idx: usize, iface: &str, hop: &str, score: f64, alive: bool) -> Candidate {
        Candidate { idx, iface: iface.into(), first_hop: hop.into(), score, alive }
    }

    #[test]
    fn select_prefers_best_and_skips_dead() {
        let c = [cand(0, "e", "a", 50.0, true), cand(1, "e", "b", 10.0, false), cand(2, "e", "c", 20.0, true)];
        assert_eq!(select_active(&c, 1, false), vec![2]);
        assert_eq!(select_active(&c, 5, false), vec![2, 0]);
        assert!(select_active(&[], 2, false).is_empty());
    }

    #[test]
    fn select_prefers_first_hop_diversity() {
        let c = [cand(0, "e", "a", 10.0, true), cand(1, "e", "a", 11.0, true), cand(2, "e", "b", 30.0, true)];
        assert_eq!(select_active(&c, 2, false), vec![0, 2]);
        assert_eq!(select_active(&c, 3, false), vec![0, 2, 1]);
    }

    #[test]
    fn select_multi_internet_uses_every_interface() {
        let c = [cand(0, "wifi", "a", 10.0, true), cand(1, "wifi", "b", 11.0, true), cand(2, "lte", "a", 90.0, true)];
        assert_eq!(select_active(&c, 2, true), vec![0, 2]);
        assert_eq!(select_active(&c, 2, false), vec![0, 1]);
    }

    #[test]
    fn stats_track_rtt_jitter_and_loss() {
        let mut s = PathStats::default();
        for _ in 0..20 {
            s.on_sent();
            s.on_rtt(50.0);
        }
        assert_eq!(s.rtt_ms, 50.0);
        assert_eq!(s.jitter_ms, 0.0);
        s.on_sent();
        assert_eq!(s.loss_pct, 0.0, "every ping in the closed window was answered");
        for _ in 0..20 {
            s.on_sent();
        }
        assert_eq!(s.loss_pct, 50.0, "half-weight blend of 0% and 100%");
        assert!(s.is_alive(Duration::from_secs(5)));
    }

    #[test]
    fn in_flight_pong_is_not_reported_as_loss() {
        // Pongs arrive one ping late, as when RTT exceeds the ping interval.
        let mut s = PathStats::default();
        s.on_sent();
        for _ in 0..60 {
            s.on_sent();
            s.on_rtt(300.0);
        }
        assert!(s.loss_pct < 3.0, "loss {}", s.loss_pct);
    }

    #[test]
    fn stats_converge_after_spike() {
        let mut s = PathStats::default();
        s.on_rtt(20.0);
        s.on_rtt(120.0);
        assert!(s.rtt_ms > 20.0 && s.rtt_ms < 120.0);
        assert!(s.jitter_ms > 0.0);
        for _ in 0..50 {
            s.on_rtt(20.0);
        }
        assert!((s.rtt_ms - 20.0).abs() < 0.5);
    }

    #[test]
    fn dead_path_is_not_alive() {
        assert!(!PathStats::default().is_alive(Duration::from_secs(1)));
    }

    #[test]
    fn score_prefers_stable_route() {
        assert!(score(40.0, 1.0, 0.0) < score(35.0, 10.0, 0.0));
        assert!(score(60.0, 1.0, 0.0) < score(40.0, 1.0, 5.0));
    }

    #[test]
    fn optimizer_requires_margin_and_hold() {
        let mut o = Optimizer::new(Duration::ZERO, Duration::from_secs(600));
        assert!(!o.evaluate(100.0, 1, 95.0), "within threshold");
        assert!(!o.evaluate(100.0, 1, 70.0), "first sighting only starts hold");
        assert!(o.evaluate(100.0, 1, 70.0));
        assert!(o.threshold_pct > 15.0, "raises threshold after a switch");
    }

    #[test]
    fn optimizer_resets_when_candidate_changes_or_fades() {
        let mut o = Optimizer::new(Duration::ZERO, Duration::from_secs(600));
        assert!(!o.evaluate(100.0, 1, 50.0));
        assert!(!o.evaluate(100.0, 2, 50.0), "new candidate restarts hold");
        assert!(!o.evaluate(100.0, 2, 99.0));
        assert!(!o.evaluate(100.0, 2, 50.0), "fading candidate restarts hold");
        assert!(o.evaluate(100.0, 2, 50.0));
    }

    #[test]
    fn optimizer_threshold_decays_when_stable() {
        let mut o = Optimizer::new(Duration::ZERO, Duration::ZERO);
        o.threshold_pct = 40.0;
        for _ in 0..20 {
            o.evaluate(100.0, 1, 100.0);
        }
        assert_eq!(o.threshold_pct, o.min_pct);
    }
}
