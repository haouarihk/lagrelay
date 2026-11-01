//! Frames carried inside encrypted datagrams.
use anyhow::{bail, Result};

const T_IP: u8 = 0x10;
const T_PING: u8 = 0x11;
const T_PONG: u8 = 0x12;
const T_NACK: u8 = 0x13;
const T_FWD_OPEN: u8 = 0x14;
const T_FWD_OK: u8 = 0x15;
const T_FWD: u8 = 0x16;
const T_HELLO: u8 = 0x17;
const T_HELLO_ACK: u8 = 0x18;
const T_SPEED_START: u8 = 0x19;
const T_SPEED_DATA: u8 = 0x1A;
const T_SPEED_END: u8 = 0x1B;
const T_SPEED_RESULT: u8 = 0x1C;
const T_PROBE: u8 = 0x1D;
const T_PROBE_RESULT: u8 = 0x1E;
const T_CLOSE: u8 = 0x1F;

/// Largest payload the speed test will generate; keeps it under the path MTU.
pub const SPEED_PKT_MAX: u16 = 1200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame<'a> {
    /// A tunnelled IPv4 packet. `seq` is per-direction and shared by every
    /// path, so the receiver can drop the duplicates multipath creates.
    Ip { seq: u64, path: u8, packet: &'a [u8] },
    /// `active` marks the path as one the exit should send downlink traffic on.
    Ping { id: u32, t_ns: u64, path: u8, active: bool },
    Pong { id: u32, t_ns: u64, path: u8 },
    Nack { ranges: Vec<(u64, u16)> },
    FwdOpen { route: u32, target: String },
    FwdOk { route: u32, ok: bool },
    Fwd { route: u32, datagram: &'a [u8] },
    Hello,
    HelloAck { vip: [u8; 4], exit: bool, mtu: u16, name: String },
    /// `down`: relay sends to client; otherwise client sends and relay counts.
    SpeedStart { id: u32, down: bool, bytes: u64, rate_kbps: u32, pkt: u16 },
    SpeedData { id: u32, seq: u32, sent_ns: u64, filler: &'a [u8] },
    SpeedEnd { id: u32 },
    SpeedResult { id: u32, bytes: u64, packets: u32 },
    /// Ask the relay how far it is from `target`. `tcp` selects TCP connect
    /// timing; otherwise ICMP echo is used.
    Probe { id: u32, target: [u8; 4], port: u16, tcp: bool },
    /// `rtt_us` is `u32::MAX` when the probe failed.
    ProbeResult { id: u32, rtt_us: u32 },
    Close,
}

struct R<'a>(&'a [u8]);
impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            bail!("truncated frame");
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into()?))
    }
    fn string(&mut self) -> Result<String> {
        let n = self.u16()? as usize;
        Ok(String::from_utf8(self.take(n)?.to_vec())?)
    }
}

fn put_str(o: &mut Vec<u8>, s: &str) {
    o.extend_from_slice(&(s.len() as u16).to_le_bytes());
    o.extend_from_slice(s.as_bytes());
}

impl<'a> Frame<'a> {
    pub fn encode(&self, o: &mut Vec<u8>) {
        match self {
            Frame::Ip { seq, path, packet } => {
                o.push(T_IP);
                o.extend_from_slice(&seq.to_le_bytes());
                o.push(*path);
                o.extend_from_slice(packet);
            }
            Frame::Ping { id, t_ns, path, active } => {
                o.push(T_PING);
                o.extend_from_slice(&id.to_le_bytes());
                o.extend_from_slice(&t_ns.to_le_bytes());
                o.push(*path);
                o.push(*active as u8);
            }
            Frame::Pong { id, t_ns, path } => {
                o.push(T_PONG);
                o.extend_from_slice(&id.to_le_bytes());
                o.extend_from_slice(&t_ns.to_le_bytes());
                o.push(*path);
            }
            Frame::Nack { ranges } => {
                o.push(T_NACK);
                o.extend_from_slice(&(ranges.len() as u16).to_le_bytes());
                for (start, count) in ranges {
                    o.extend_from_slice(&start.to_le_bytes());
                    o.extend_from_slice(&count.to_le_bytes());
                }
            }
            Frame::FwdOpen { route, target } => {
                o.push(T_FWD_OPEN);
                o.extend_from_slice(&route.to_le_bytes());
                put_str(o, target);
            }
            Frame::FwdOk { route, ok } => {
                o.push(T_FWD_OK);
                o.extend_from_slice(&route.to_le_bytes());
                o.push(*ok as u8);
            }
            Frame::Fwd { route, datagram } => {
                o.push(T_FWD);
                o.extend_from_slice(&route.to_le_bytes());
                o.extend_from_slice(datagram);
            }
            Frame::Hello => o.push(T_HELLO),
            Frame::HelloAck { vip, exit, mtu, name } => {
                o.push(T_HELLO_ACK);
                o.extend_from_slice(vip);
                o.push(*exit as u8);
                o.extend_from_slice(&mtu.to_le_bytes());
                put_str(o, name);
            }
            Frame::SpeedStart { id, down, bytes, rate_kbps, pkt } => {
                o.push(T_SPEED_START);
                o.extend_from_slice(&id.to_le_bytes());
                o.push(*down as u8);
                o.extend_from_slice(&bytes.to_le_bytes());
                o.extend_from_slice(&rate_kbps.to_le_bytes());
                o.extend_from_slice(&pkt.to_le_bytes());
            }
            Frame::SpeedData { id, seq, sent_ns, filler } => {
                o.push(T_SPEED_DATA);
                o.extend_from_slice(&id.to_le_bytes());
                o.extend_from_slice(&seq.to_le_bytes());
                o.extend_from_slice(&sent_ns.to_le_bytes());
                o.extend_from_slice(filler);
            }
            Frame::SpeedEnd { id } => {
                o.push(T_SPEED_END);
                o.extend_from_slice(&id.to_le_bytes());
            }
            Frame::SpeedResult { id, bytes, packets } => {
                o.push(T_SPEED_RESULT);
                o.extend_from_slice(&id.to_le_bytes());
                o.extend_from_slice(&bytes.to_le_bytes());
                o.extend_from_slice(&packets.to_le_bytes());
            }
            Frame::Probe { id, target, port, tcp } => {
                o.push(T_PROBE);
                o.extend_from_slice(&id.to_le_bytes());
                o.extend_from_slice(target);
                o.extend_from_slice(&port.to_le_bytes());
                o.push(*tcp as u8);
            }
            Frame::ProbeResult { id, rtt_us } => {
                o.push(T_PROBE_RESULT);
                o.extend_from_slice(&id.to_le_bytes());
                o.extend_from_slice(&rtt_us.to_le_bytes());
            }
            Frame::Close => o.push(T_CLOSE),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(64);
        self.encode(&mut v);
        v
    }

    pub fn decode(b: &'a [u8]) -> Result<Frame<'a>> {
        let mut r = R(b);
        Ok(match r.u8()? {
            T_IP => Frame::Ip { seq: r.u64()?, path: r.u8()?, packet: r.0 },
            T_PING => Frame::Ping { id: r.u32()?, t_ns: r.u64()?, path: r.u8()?, active: r.u8()? != 0 },
            T_PONG => Frame::Pong { id: r.u32()?, t_ns: r.u64()?, path: r.u8()? },
            T_NACK => {
                let n = r.u16()? as usize;
                let mut ranges = Vec::with_capacity(n.min(128));
                for _ in 0..n {
                    ranges.push((r.u64()?, r.u16()?));
                }
                Frame::Nack { ranges }
            }
            T_FWD_OPEN => Frame::FwdOpen { route: r.u32()?, target: r.string()? },
            T_FWD_OK => Frame::FwdOk { route: r.u32()?, ok: r.u8()? != 0 },
            T_FWD => Frame::Fwd { route: r.u32()?, datagram: r.0 },
            T_HELLO => Frame::Hello,
            T_HELLO_ACK => Frame::HelloAck {
                vip: r.take(4)?.try_into()?,
                exit: r.u8()? != 0,
                mtu: r.u16()?,
                name: r.string()?,
            },
            T_SPEED_START => Frame::SpeedStart {
                id: r.u32()?,
                down: r.u8()? != 0,
                bytes: r.u64()?,
                rate_kbps: r.u32()?,
                pkt: r.u16()?,
            },
            T_SPEED_DATA => Frame::SpeedData { id: r.u32()?, seq: r.u32()?, sent_ns: r.u64()?, filler: r.0 },
            T_SPEED_END => Frame::SpeedEnd { id: r.u32()? },
            T_SPEED_RESULT => Frame::SpeedResult { id: r.u32()?, bytes: r.u64()?, packets: r.u32()? },
            T_PROBE => Frame::Probe {
                id: r.u32()?,
                target: r.take(4)?.try_into()?,
                port: r.u16()?,
                tcp: r.u8()? != 0,
            },
            T_PROBE_RESULT => Frame::ProbeResult { id: r.u32()?, rtt_us: r.u32()? },
            T_CLOSE => Frame::Close,
            t => bail!("unknown frame type {t:#x}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_frames() {
        let frames = vec![
            Frame::Ip { seq: 7, path: 2, packet: b"abc" },
            Frame::Ping { id: 1, t_ns: 2, path: 3, active: true },
            Frame::Pong { id: 1, t_ns: 2, path: 3 },
            Frame::Nack { ranges: vec![(5, 2), (100, 1)] },
            Frame::FwdOpen { route: 9, target: "1.2.3.4:5".into() },
            Frame::FwdOk { route: 9, ok: true },
            Frame::Fwd { route: 9, datagram: b"zz" },
            Frame::Hello,
            Frame::HelloAck { vip: [10, 77, 0, 2], exit: true, mtu: 1340, name: "r".into() },
            Frame::SpeedStart { id: 1, down: true, bytes: 9, rate_kbps: 8, pkt: 1000 },
            Frame::SpeedData { id: 1, seq: 2, sent_ns: 3, filler: b"f" },
            Frame::SpeedEnd { id: 1 },
            Frame::SpeedResult { id: 1, bytes: 2, packets: 3 },
            Frame::Probe { id: 1, target: [1, 1, 1, 1], port: 443, tcp: true },
            Frame::ProbeResult { id: 1, rtt_us: 5 },
            Frame::Close,
        ];
        for f in frames {
            let b = f.to_vec();
            assert_eq!(Frame::decode(&b).unwrap(), f);
        }
    }

    #[test]
    fn truncated_frames_are_errors_not_panics() {
        let b = Frame::Ping { id: 1, t_ns: 2, path: 3, active: true }.to_vec();
        for n in 0..b.len() {
            assert!(Frame::decode(&b[..n]).is_err());
        }
        assert!(Frame::decode(&[0xEE]).is_err());
    }
}
