//! Sequence tracking: replay protection, multipath de-duplication, and
//! NACK-based loss recovery for tunnelled packets.
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const WINDOW: u64 = 8192;
const WORDS: usize = (WINDOW / 64) as usize;

/// Sliding bitmap over a monotonically growing u64 sequence.
pub struct ReplayWindow {
    top: u64,
    any: bool,
    bits: [u64; WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        ReplayWindow { top: 0, any: false, bits: [0; WORDS] }
    }

    /// True if `n` has not been seen and is still inside the window.
    pub fn check(&self, n: u64) -> bool {
        if !self.any || n > self.top {
            return true;
        }
        if self.top - n >= WINDOW {
            return false;
        }
        let (w, b) = ((n / 64) as usize % WORDS, n % 64);
        self.bits[w] & (1 << b) == 0
    }

    /// Marks `n` as seen. Returns false if it was a duplicate or too old.
    pub fn update(&mut self, n: u64) -> bool {
        if !self.check(n) {
            return false;
        }
        if !self.any {
            self.any = true;
            self.top = n;
        } else if n > self.top {
            let (old_word, new_word) = (self.top / 64, n / 64);
            if new_word - old_word >= WORDS as u64 {
                self.bits = [0; WORDS];
            } else {
                for w in old_word + 1..=new_word {
                    self.bits[w as usize % WORDS] = 0;
                }
            }
            self.top = n;
        }
        self.bits[(n / 64) as usize % WORDS] |= 1 << (n % 64);
        true
    }
}

/// Keeps recently sent packets so a NACK can be answered.
pub struct TxRing {
    slots: Vec<Option<(u64, Instant, Vec<u8>)>>,
    max_age: Duration,
}

impl TxRing {
    pub fn new(capacity: usize, max_age: Duration) -> Self {
        TxRing { slots: (0..capacity).map(|_| None).collect(), max_age }
    }

    pub fn push(&mut self, seq: u64, packet: &[u8]) {
        let i = seq as usize % self.slots.len();
        // Reuse the slot's allocation: this runs for every tunnelled packet.
        match &mut self.slots[i] {
            Some((s, t, buf)) => {
                *s = seq;
                *t = Instant::now();
                buf.clear();
                buf.extend_from_slice(packet);
            }
            slot => *slot = Some((seq, Instant::now(), packet.to_vec())),
        }
    }

    /// The packet for `seq`, if retained and still fresh enough to be useful.
    pub fn get(&self, seq: u64) -> Option<&[u8]> {
        match &self.slots[seq as usize % self.slots.len()] {
            Some((s, t, b)) if *s == seq && t.elapsed() <= self.max_age => Some(b),
            _ => None,
        }
    }
}

struct Gap {
    first_seen: Instant,
    nacks: u8,
}

/// Receiver side: drops duplicates and works out which sequence numbers to
/// request again.
pub struct RxTracker {
    seen: ReplayWindow,
    highest: Option<u64>,
    gaps: BTreeMap<u64, Gap>,
    nack_delay: Duration,
    max_nacks: u8,
    gap_ttl: Duration,
    pub duplicates: u64,
    pub unique: u64,
    pub recovered: u64,
    pub lost: u64,
}

impl RxTracker {
    pub fn new(nack_delay: Duration, max_nacks: u8, gap_ttl: Duration) -> Self {
        RxTracker {
            seen: ReplayWindow::new(),
            highest: None,
            gaps: BTreeMap::new(),
            nack_delay,
            max_nacks,
            gap_ttl,
            duplicates: 0,
            unique: 0,
            recovered: 0,
            lost: 0,
        }
    }

    pub fn set_nack_delay(&mut self, d: Duration) {
        self.nack_delay = d;
    }

    /// Returns true if `seq` is new and should be delivered.
    pub fn accept(&mut self, seq: u64) -> bool {
        if !self.seen.update(seq) {
            self.duplicates += 1;
            return false;
        }
        self.unique += 1;
        if self.gaps.remove(&seq).is_some() {
            self.recovered += 1;
        }
        match self.highest {
            None => self.highest = Some(seq),
            Some(h) if seq > h => {
                let now = Instant::now();
                // A jump larger than the window is treated as a restart, not
                // as thousands of missing packets.
                if seq - h <= 512 {
                    for s in h + 1..seq {
                        self.gaps.insert(s, Gap { first_seen: now, nacks: 0 });
                    }
                }
                self.highest = Some(seq);
            }
            _ => {}
        }
        true
    }

    /// Sequence ranges due for a NACK now. Gaps past their TTL count as lost.
    pub fn due_nacks(&mut self) -> Vec<(u64, u16)> {
        let now = Instant::now();
        let (delay, ttl, max) = (self.nack_delay, self.gap_ttl, self.max_nacks);
        let mut lost = 0;
        self.gaps.retain(|_, g| {
            let keep = now.duration_since(g.first_seen) < ttl;
            lost += !keep as u64;
            keep
        });
        self.lost += lost;
        let mut out: Vec<(u64, u16)> = Vec::new();
        for (&s, g) in self.gaps.iter_mut() {
            if g.nacks >= max {
                continue;
            }
            // Back off: wait one extra delay for every NACK already sent.
            if now.duration_since(g.first_seen) < delay * (g.nacks as u32 + 1) {
                continue;
            }
            let extends = matches!(out.last(), Some((start, n)) if *start + *n as u64 == s && *n < u16::MAX);
            if !extends && out.len() >= 64 {
                break;
            }
            g.nacks += 1;
            if extends {
                out.last_mut().unwrap().1 += 1;
            } else {
                out.push((s, 1));
            }
        }
        out
    }

    pub fn pending_gaps(&self) -> usize {
        self.gaps.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_rejects_duplicates_and_old() {
        let mut w = ReplayWindow::new();
        assert!(w.update(0));
        assert!(!w.update(0));
        assert!(w.update(5));
        assert!(w.update(3));
        assert!(!w.update(3));
        assert!(w.update(WINDOW + 100));
        assert!(!w.update(5), "outside window");
        assert!(w.update(WINDOW + 99));
    }

    #[test]
    fn window_clears_recycled_words() {
        let mut w = ReplayWindow::new();
        assert!(w.update(10));
        assert!(w.update(WINDOW * 3 + 10), "same bit position in a later cycle");
        assert!(w.update(WINDOW * 3 + 9));
        assert!(!w.update(WINDOW * 3 + 10));
    }

    #[test]
    fn window_handles_top_value_without_overflow() {
        let mut w = ReplayWindow::new();
        assert!(w.update(u64::MAX - 1));
        assert!(w.update(u64::MAX));
        assert!(!w.update(u64::MAX));
    }

    #[test]
    fn tx_ring_expires_and_overwrites() {
        let mut r = TxRing::new(4, Duration::from_secs(5));
        r.push(1, b"a");
        assert_eq!(r.get(1), Some(&b"a"[..]));
        r.push(5, b"b");
        assert_eq!(r.get(1), None, "slot was reused");
        assert_eq!(r.get(5), Some(&b"b"[..]));
        let mut r = TxRing::new(4, Duration::ZERO);
        r.push(1, b"a");
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(r.get(1), None, "too old");
    }

    #[test]
    fn rx_nacks_gaps_after_delay_and_counts_recovery() {
        let mut r = RxTracker::new(Duration::ZERO, 2, Duration::from_secs(5));
        assert!(r.accept(0));
        assert!(r.accept(4));
        assert!(!r.accept(4));
        assert_eq!(r.duplicates, 1);
        assert_eq!(r.due_nacks(), vec![(1, 3)]);
        assert!(r.accept(2));
        assert_eq!(r.recovered, 1);
        assert_eq!(r.due_nacks(), vec![(1, 1), (3, 1)]);
        assert!(r.due_nacks().is_empty(), "NACK limit reached");
    }

    #[test]
    fn rx_respects_delay_and_ttl() {
        let mut r = RxTracker::new(Duration::from_secs(60), 2, Duration::from_secs(120));
        r.accept(0);
        r.accept(2);
        assert!(r.due_nacks().is_empty(), "not due yet");
        let mut r = RxTracker::new(Duration::ZERO, 2, Duration::ZERO);
        r.accept(0);
        r.accept(2);
        std::thread::sleep(Duration::from_millis(2));
        assert!(r.due_nacks().is_empty());
        assert_eq!(r.lost, 1);
        assert_eq!(r.pending_gaps(), 0);
    }

    #[test]
    fn rx_large_jump_does_not_allocate_gaps() {
        let mut r = RxTracker::new(Duration::ZERO, 2, Duration::from_secs(5));
        r.accept(0);
        r.accept(1_000_000);
        assert_eq!(r.pending_gaps(), 0);
    }
}
