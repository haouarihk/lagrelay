//! Noise IK handshake and per-datagram transport encryption.
//!
//! Datagram layouts:
//!   HS_INIT: [1][sender_idx u32][noise]
//!   HS_RESP: [2][receiver_idx u32][sender_idx u32][noise]
//!   DATA:    [3][receiver_idx u32][nonce u64][ciphertext]
use crate::reliab::ReplayWindow;
use anyhow::{anyhow, bail, Result};
use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD},
    Engine,
};
use snow::{Builder, HandshakeState, StatelessTransportState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// The access token is mixed in as a pre-shared key before the first message
/// (`psk0`), so without it the relay can't even decrypt a connection attempt.
/// It never travels over the network, and failures get no reply at all.
const PATTERN: &str = "Noise_IKpsk0_25519_ChaChaPoly_BLAKE2s";
/// Only used for key generation and derivation, which involve no access token.
const KEY_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const TOKEN_PREFIX: &str = "lrt_";
pub const KIND_HS_INIT: u8 = 1;
pub const KIND_HS_RESP: u8 = 2;
pub const KIND_DATA: u8 = 3;
pub const DATA_HDR: usize = 13;
pub const TAG: usize = 16;
/// Largest datagram either side will ever process.
pub const MAX_DGRAM: usize = 2048;
/// A handshake older or further in the future than this is refused.
pub const HS_MAX_SKEW_MS: u64 = 5 * 60 * 1000;

pub fn encode_key(k: &[u8; 32]) -> String {
    B64.encode(k)
}

pub fn decode_key(s: &str) -> Result<[u8; 32]> {
    let v = B64.decode(s.trim())?;
    v.try_into().map_err(|_| anyhow!("key must be 32 bytes"))
}

/// Creates a new random access token with 256 bits of entropy.
pub fn generate_token() -> String {
    let bytes: [u8; 32] = rand::random();
    format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
}

pub fn decode_token(s: &str) -> Result<[u8; 32]> {
    let body = s.trim().strip_prefix(TOKEN_PREFIX).ok_or_else(|| anyhow!("access token must start with {TOKEN_PREFIX}"))?;
    let v = URL_SAFE_NO_PAD.decode(body).map_err(|_| anyhow!("access token is malformed"))?;
    v.try_into().map_err(|_| anyhow!("access token must be 32 bytes"))
}

pub struct Keypair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

pub fn generate_keypair() -> Result<Keypair> {
    let k = Builder::new(KEY_PATTERN.parse()?).generate_keypair()?;
    Ok(Keypair {
        private: k.private.try_into().map_err(|_| anyhow!("bad private key length"))?,
        public: k.public.try_into().map_err(|_| anyhow!("bad public key length"))?,
    })
}

/// Derives the public half, so configs only need to store the private key.
pub fn public_from_private(private: &[u8; 32]) -> Result<[u8; 32]> {
    // A throwaway handshake is the only way snow exposes the X25519 base-point
    // multiplication: the responder learns the initiator's static public key.
    let params: snow::params::NoiseParams = KEY_PATTERN.parse()?;
    let resp = generate_keypair()?;
    let mut init = Builder::new(params.clone())
        .local_private_key(private)
        .remote_public_key(&resp.public)
        .build_initiator()?;
    let mut r = Builder::new(params).local_private_key(&resp.private).build_responder()?;
    let mut m = [0u8; 256];
    let n = init.write_message(&[], &mut m)?;
    let mut p = [0u8; 256];
    r.read_message(&m[..n], &mut p)?;
    r.get_remote_static()
        .ok_or_else(|| anyhow!("no remote static"))?
        .try_into()
        .map_err(|_| anyhow!("bad public key length"))
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Unique, increasing handshake timestamp, even for several in the same millisecond.
fn next_timestamp() -> u64 {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = now_ms();
    let mut cur = LAST.load(Ordering::Relaxed);
    loop {
        let next = now.max(cur + 1);
        match LAST.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(c) => cur = c,
        }
    }
}

/// Rejects replayed handshakes. Handshakes for different routes can arrive out
/// of order, so this remembers recent timestamps instead of requiring each to
/// be newer than the last. Anything older than the remembered set is refused.
#[derive(Default)]
pub struct HandshakeReplayGuard {
    seen: std::collections::BTreeSet<u64>,
}

impl HandshakeReplayGuard {
    const CAPACITY: usize = 1024;

    /// True the first time a timestamp is presented, false for any replay.
    pub fn admit(&mut self, ts: u64) -> bool {
        if self.seen.contains(&ts) {
            return false;
        }
        if self.seen.len() >= Self::CAPACITY {
            if self.seen.first().is_some_and(|oldest| ts <= *oldest) {
                return false;
            }
            self.seen.pop_first();
        }
        self.seen.insert(ts);
        true
    }
}

pub struct Session {
    transport: StatelessTransportState,
    pub local_idx: u32,
    pub remote_idx: u32,
    tx_nonce: AtomicU64,
    replay: Mutex<ReplayWindow>,
}

impl Session {
    fn new(transport: StatelessTransportState, local_idx: u32, remote_idx: u32) -> Self {
        Session { transport, local_idx, remote_idx, tx_nonce: AtomicU64::new(0), replay: Mutex::new(ReplayWindow::new()) }
    }

    /// Encrypts `plain` into a complete DATA datagram.
    pub fn seal(&self, plain: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.tx_nonce.fetch_add(1, Ordering::Relaxed);
        let mut out = vec![0u8; DATA_HDR + plain.len() + TAG];
        out[0] = KIND_DATA;
        out[1..5].copy_from_slice(&self.remote_idx.to_le_bytes());
        out[5..13].copy_from_slice(&nonce.to_le_bytes());
        let n = self.transport.write_message(nonce, plain, &mut out[DATA_HDR..])?;
        out.truncate(DATA_HDR + n);
        Ok(out)
    }

    /// Authenticates and decrypts a DATA datagram, rejecting replays.
    pub fn open(&self, dgram: &[u8]) -> Result<Vec<u8>> {
        if dgram.len() < DATA_HDR + TAG || dgram[0] != KIND_DATA {
            bail!("malformed data datagram");
        }
        let nonce = u64::from_le_bytes(dgram[5..13].try_into()?);
        let mut out = vec![0u8; dgram.len() - DATA_HDR];
        // The replay window is only updated after authentication succeeds, so
        // forged datagrams cannot advance it.
        if !self.replay.lock().unwrap().check(nonce) {
            bail!("replayed datagram");
        }
        let n = self.transport.read_message(nonce, &dgram[DATA_HDR..], &mut out)?;
        if !self.replay.lock().unwrap().update(nonce) {
            bail!("replayed datagram");
        }
        out.truncate(n);
        Ok(out)
    }
}

/// The receiver index of a DATA or HS_RESP datagram.
pub fn receiver_idx(dgram: &[u8]) -> Option<u32> {
    if dgram.len() < 5 {
        return None;
    }
    Some(u32::from_le_bytes(dgram[1..5].try_into().ok()?))
}

pub struct Initiator {
    hs: HandshakeState,
    local_idx: u32,
}

impl Initiator {
    pub fn new(private: &[u8; 32], server_public: &[u8; 32], token: &[u8; 32]) -> Result<(Self, Vec<u8>)> {
        let mut hs = Builder::new(PATTERN.parse()?)
            .local_private_key(private)
            .remote_public_key(server_public)
            .psk(0, token)
            .build_initiator()?;
        let local_idx: u32 = rand::random();
        let mut out = vec![0u8; 512];
        out[0] = KIND_HS_INIT;
        out[1..5].copy_from_slice(&local_idx.to_le_bytes());
        let n = hs.write_message(&next_timestamp().to_le_bytes(), &mut out[5..])?;
        out.truncate(5 + n);
        Ok((Initiator { hs, local_idx }, out))
    }

    pub fn finish(mut self, resp: &[u8]) -> Result<Session> {
        if resp.len() < 9 || resp[0] != KIND_HS_RESP {
            bail!("malformed handshake response");
        }
        if receiver_idx(resp) != Some(self.local_idx) {
            bail!("handshake response for a different session");
        }
        let remote_idx = u32::from_le_bytes(resp[5..9].try_into()?);
        let mut p = [0u8; 64];
        self.hs.read_message(&resp[9..], &mut p)?;
        Ok(Session::new(self.hs.into_stateless_transport_mode()?, self.local_idx, remote_idx))
    }
}

pub struct Accepted {
    pub session: Session,
    pub peer: [u8; 32],
    pub response: Vec<u8>,
    pub timestamp_ms: u64,
}

/// Handles HS_INIT. `authorize` sees the verified peer key and handshake time;
/// it is how the caller enforces its client list and blocks handshake replays.
pub fn accept(
    private: &[u8; 32],
    token: &[u8; 32],
    dgram: &[u8],
    authorize: impl FnOnce(&[u8; 32], u64) -> bool,
) -> Result<Accepted> {
    if dgram.len() < 5 || dgram[0] != KIND_HS_INIT {
        bail!("malformed handshake init");
    }
    let remote_idx = u32::from_le_bytes(dgram[1..5].try_into()?);
    let mut hs = Builder::new(PATTERN.parse()?).local_private_key(private).psk(0, token).build_responder()?;
    let mut p = [0u8; 64];
    let n = hs.read_message(&dgram[5..], &mut p)?;
    if n != 8 {
        bail!("bad handshake payload");
    }
    let timestamp_ms = u64::from_le_bytes(p[..8].try_into()?);
    if now_ms().abs_diff(timestamp_ms) > HS_MAX_SKEW_MS {
        bail!("handshake timestamp outside the allowed clock skew");
    }
    let peer: [u8; 32] = hs
        .get_remote_static()
        .ok_or_else(|| anyhow!("no remote static key"))?
        .try_into()
        .map_err(|_| anyhow!("bad remote key"))?;
    if !authorize(&peer, timestamp_ms) {
        bail!("peer not authorized");
    }
    let local_idx: u32 = rand::random();
    let mut out = vec![0u8; 256];
    out[0] = KIND_HS_RESP;
    out[1..5].copy_from_slice(&remote_idx.to_le_bytes());
    out[5..9].copy_from_slice(&local_idx.to_le_bytes());
    let n = hs.write_message(&[], &mut out[9..])?;
    out.truncate(9 + n);
    Ok(Accepted {
        session: Session::new(hs.into_stateless_transport_mode()?, local_idx, remote_idx),
        peer,
        response: out,
        timestamp_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: [u8; 32] = [7; 32];

    fn pair() -> (Session, Session, [u8; 32]) {
        let (c, s) = (generate_keypair().unwrap(), generate_keypair().unwrap());
        let (init, msg) = Initiator::new(&c.private, &s.public, &TOKEN).unwrap();
        let a = accept(&s.private, &TOKEN, &msg, |_, _| true).unwrap();
        let cs = init.finish(&a.response).unwrap();
        assert_eq!(a.peer, c.public);
        (cs, a.session, c.public)
    }

    #[test]
    fn handshake_and_bidirectional_data() {
        let (c, s, _) = pair();
        let d = c.seal(b"hello").unwrap();
        assert_eq!(receiver_idx(&d), Some(s.local_idx));
        assert_eq!(s.open(&d).unwrap(), b"hello");
        let d = s.seal(b"world").unwrap();
        assert_eq!(c.open(&d).unwrap(), b"world");
    }

    #[test]
    fn replay_rejected_and_reordering_allowed() {
        let (c, s, _) = pair();
        let a = c.seal(b"a").unwrap();
        let b = c.seal(b"b").unwrap();
        assert_eq!(s.open(&b).unwrap(), b"b");
        assert_eq!(s.open(&a).unwrap(), b"a");
        assert!(s.open(&a).is_err());
    }

    #[test]
    fn tamper_rejected_and_does_not_burn_nonce() {
        let (c, s, _) = pair();
        let good = c.seal(b"payload").unwrap();
        let mut bad = good.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(s.open(&bad).is_err());
        assert_eq!(s.open(&good).unwrap(), b"payload");
    }

    #[test]
    fn wrong_server_key_and_unauthorized_peer_fail() {
        let (c, s, other) = (generate_keypair().unwrap(), generate_keypair().unwrap(), generate_keypair().unwrap());
        let (_, msg) = Initiator::new(&c.private, &other.public, &TOKEN).unwrap();
        assert!(accept(&s.private, &TOKEN, &msg, |_, _| true).is_err());
        let (_, msg) = Initiator::new(&c.private, &s.public, &TOKEN).unwrap();
        assert!(accept(&s.private, &TOKEN, &msg, |_, _| false).is_err());
    }

    #[test]
    fn wrong_token_fails_before_authorization_runs() {
        let (c, s) = (generate_keypair().unwrap(), generate_keypair().unwrap());
        let (_, msg) = Initiator::new(&c.private, &s.public, &[8; 32]).unwrap();
        let mut consulted = false;
        let r = accept(&s.private, &TOKEN, &msg, |_, _| {
            consulted = true;
            true
        });
        assert!(r.is_err());
        assert!(!consulted, "a bad token must not reveal the client's identity to the relay");
    }

    #[test]
    fn token_text_roundtrip_and_validation() {
        let t = generate_token();
        assert!(t.starts_with("lrt_"));
        assert_ne!(t, generate_token());
        decode_token(&t).unwrap();
        assert!(decode_token("nope").is_err());
        assert!(decode_token("lrt_c2hvcnQ").is_err(), "too short");
        assert!(decode_token("lrt_!!!!").is_err());
    }

    #[test]
    fn replay_guard_allows_reordering_but_not_repeats() {
        let mut g = HandshakeReplayGuard::default();
        assert!(g.admit(100));
        assert!(g.admit(99), "out of order is fine");
        assert!(!g.admit(100));
        assert!(!g.admit(99));
        for t in 1000..1000 + HandshakeReplayGuard::CAPACITY as u64 {
            assert!(g.admit(t));
        }
        assert!(!g.admit(5), "older than everything still remembered");
    }

    #[test]
    fn timestamps_are_unique_and_increasing() {
        let (a, b) = (next_timestamp(), next_timestamp());
        assert!(b > a);
    }

    #[test]
    fn derives_public_key() {
        let k = generate_keypair().unwrap();
        assert_eq!(public_from_private(&k.private).unwrap(), k.public);
    }

    #[test]
    fn key_text_roundtrip() {
        let k = generate_keypair().unwrap();
        assert_eq!(decode_key(&encode_key(&k.public)).unwrap(), k.public);
        assert!(decode_key("c2hvcnQ=").is_err());
    }
}
