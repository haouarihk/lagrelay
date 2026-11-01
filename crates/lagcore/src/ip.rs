//! Minimal IPv4/TCP/UDP parsing and rewriting for captured packets.
use std::net::Ipv4Addr;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Info {
    pub proto: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub ihl: usize,
    /// Zero for ICMP and for non-first fragments.
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_syn: bool,
    pub is_fragment: bool,
    pub is_first_fragment: bool,
}

pub fn parse_ipv4(p: &[u8]) -> Option<Ipv4Info> {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((p[0] & 0xF) as usize) * 4;
    let total = u16::from_be_bytes([p[2], p[3]]) as usize;
    if ihl < 20 || total < ihl || p.len() < total {
        return None;
    }
    let frag = u16::from_be_bytes([p[6], p[7]]);
    let (mf, offset) = (frag & 0x2000 != 0, frag & 0x1FFF);
    let proto = p[9];
    let mut info = Ipv4Info {
        proto,
        src: Ipv4Addr::new(p[12], p[13], p[14], p[15]),
        dst: Ipv4Addr::new(p[16], p[17], p[18], p[19]),
        ihl,
        src_port: 0,
        dst_port: 0,
        tcp_syn: false,
        is_fragment: mf || offset != 0,
        is_first_fragment: mf && offset == 0,
    };
    if offset == 0 && matches!(proto, PROTO_TCP | PROTO_UDP) {
        let l4 = &p[ihl..total];
        if l4.len() < 4 {
            return None;
        }
        info.src_port = u16::from_be_bytes([l4[0], l4[1]]);
        info.dst_port = u16::from_be_bytes([l4[2], l4[3]]);
        if proto == PROTO_TCP && l4.len() >= 14 {
            info.tcp_syn = l4[13] & 0x02 != 0;
        }
    }
    Some(info)
}

fn sum(data: &[u8], mut acc: u32) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        acc += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [b] = chunks.remainder() {
        acc += (*b as u32) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    !(acc as u16)
}

/// Recomputes the IPv4 header checksum and, on a whole packet or first
/// fragment boundary that allows it, the TCP or UDP checksum.
///
/// Captured outbound packets often have checksums left for the NIC to fill in,
/// so this always computes them from scratch instead of patching incrementally.
pub fn fix_checksums(p: &mut [u8]) -> bool {
    let Some(info) = parse_ipv4(p) else { return false };
    let total = u16::from_be_bytes([p[2], p[3]]) as usize;
    let ihl = info.ihl;
    p[10] = 0;
    p[11] = 0;
    let c = fold(sum(&p[..ihl], 0));
    p[10..12].copy_from_slice(&c.to_be_bytes());
    // A fragment does not contain the whole L4 segment, so its checksum cannot
    // be recomputed; see `patch_fragment_l4_checksum` for the first fragment.
    if info.is_fragment {
        return true;
    }
    let l4_off = match info.proto {
        PROTO_TCP if total >= ihl + 20 => 16,
        PROTO_UDP if total >= ihl + 8 => 6,
        _ => return true,
    };
    let was_zero_udp = info.proto == PROTO_UDP && p[ihl + 6] == 0 && p[ihl + 7] == 0;
    p[ihl + l4_off] = 0;
    p[ihl + l4_off + 1] = 0;
    let mut acc = sum(&p[12..20], 0);
    acc += info.proto as u32;
    acc += (total - ihl) as u32;
    acc = sum(&p[ihl..total], acc);
    let mut c = fold(acc);
    if info.proto == PROTO_UDP {
        if was_zero_udp {
            return true; // "no checksum" stays that way.
        }
        if c == 0 {
            c = 0xFFFF;
        }
    }
    p[ihl + l4_off..ihl + l4_off + 2].copy_from_slice(&c.to_be_bytes());
    true
}

/// Adjusts an L4 checksum for one changed 32-bit pseudo-header address (RFC 1624).
fn patch_fragment_l4_checksum(p: &mut [u8], off: usize, old: [u8; 4], new: [u8; 4]) {
    let cur = u16::from_be_bytes([p[off], p[off + 1]]);
    if cur == 0 {
        return;
    }
    let mut acc = (!cur) as u32;
    for c in old.chunks_exact(2) {
        acc += (!u16::from_be_bytes([c[0], c[1]])) as u32;
    }
    for c in new.chunks_exact(2) {
        acc += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    let v = fold(acc);
    p[off..off + 2].copy_from_slice(&v.to_be_bytes());
}

fn rewrite(p: &mut [u8], at: usize, new: Ipv4Addr) -> bool {
    let Some(info) = parse_ipv4(p) else { return false };
    let old: [u8; 4] = p[at..at + 4].try_into().unwrap();
    p[at..at + 4].copy_from_slice(&new.octets());
    if info.is_first_fragment {
        let off = match info.proto {
            PROTO_TCP => Some(16),
            PROTO_UDP => Some(6),
            _ => None,
        };
        if let Some(off) = off {
            if p.len() >= info.ihl + off + 2 {
                patch_fragment_l4_checksum(p, info.ihl + off, old, new.octets());
            }
        }
    }
    fix_checksums(p)
}

pub fn rewrite_src(p: &mut [u8], new: Ipv4Addr) -> bool {
    rewrite(p, 12, new)
}

pub fn rewrite_dst(p: &mut [u8], new: Ipv4Addr) -> bool {
    rewrite(p, 16, new)
}

/// Lowers the MSS option on a TCP SYN so tunnelled segments fit the tunnel MTU.
/// Returns true if the packet changed. The caller must fix checksums afterwards.
pub fn clamp_mss(p: &mut [u8], mss: u16) -> bool {
    let Some(i) = parse_ipv4(p) else { return false };
    if i.proto != PROTO_TCP || !i.tcp_syn || i.is_fragment {
        return false;
    }
    let total = u16::from_be_bytes([p[2], p[3]]) as usize;
    if total < i.ihl + 20 {
        return false;
    }
    let doff = ((p[i.ihl + 12] >> 4) as usize) * 4;
    if doff < 20 || i.ihl + doff > total {
        return false;
    }
    let mut o = i.ihl + 20;
    let end = i.ihl + doff;
    while o < end {
        match p[o] {
            0 => return false,
            1 => o += 1,
            kind => {
                if o + 1 >= end {
                    return false;
                }
                let len = p[o + 1] as usize;
                if len < 2 || o + len > end {
                    return false;
                }
                if kind == 2 && len == 4 {
                    if u16::from_be_bytes([p[o + 2], p[o + 3]]) > mss {
                        p[o + 2..o + 4].copy_from_slice(&mss.to_be_bytes());
                        return true;
                    }
                    return false;
                }
                o += len;
            }
        }
    }
    false
}

/// RFC1918, loopback, link-local, CGNAT, multicast and broadcast ranges are
/// never tunnelled unless a game rule names them explicitly.
pub fn is_local_scope(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a.is_private()
        || a.is_loopback()
        || a.is_link_local()
        || a.is_multicast()
        || a.is_broadcast()
        || a.is_unspecified()
        || (o[0] == 100 && (64..128).contains(&o[1]))
}

/// Parses `a.b.c.d/len` (or a bare address) into (network, prefix length).
pub fn parse_cidr(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip, len) = match s.split_once('/') {
        Some((i, l)) => (i, l.parse().ok()?),
        None => (s, 32u8),
    };
    if len > 32 {
        return None;
    }
    Some((ip.parse().ok()?, len))
}

pub fn cidr_contains(net: Ipv4Addr, len: u8, a: Ipv4Addr) -> bool {
    if len == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - len as u32);
    u32::from(net) & mask == u32::from(a) & mask
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Independent RFC 1071 verification: summing a valid header gives 0xFFFF.
    fn verify(p: &[u8]) -> bool {
        let i = parse_ipv4(p).unwrap();
        if fold(sum(&p[..i.ihl], 0)) != 0 {
            return false;
        }
        let total = u16::from_be_bytes([p[2], p[3]]) as usize;
        let mut acc = sum(&p[12..20], 0);
        acc += i.proto as u32;
        acc += (total - i.ihl) as u32;
        fold(sum(&p[i.ihl..total], acc)) == 0
    }

    fn udp(payload: &[u8]) -> Vec<u8> {
        let total = 28 + payload.len();
        let mut p = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 1, 0x40, 0, 64, PROTO_UDP, 0, 0, 192, 168, 1, 5, 8, 8, 8, 8];
        let l = (8 + payload.len()) as u16;
        p.extend_from_slice(&5000u16.to_be_bytes());
        p.extend_from_slice(&53u16.to_be_bytes());
        p.extend_from_slice(&l.to_be_bytes());
        p.extend_from_slice(&[0xAA, 0xBB]);
        p.extend_from_slice(payload);
        p
    }

    fn tcp_syn(mss: u16) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 48, 0, 1, 0x40, 0, 64, PROTO_TCP, 0, 0, 10, 0, 0, 1, 1, 1, 1, 1];
        p.extend_from_slice(&[0x13, 0x88, 0x01, 0xBB, 0, 0, 0, 1, 0, 0, 0, 0, 0x70, 0x02, 0xFF, 0xFF, 0, 0, 0, 0]);
        p.extend_from_slice(&[1, 1, 2, 4]);
        p.extend_from_slice(&mss.to_be_bytes());
        p.extend_from_slice(&[1, 1]);
        p
    }

    #[test]
    fn parses_and_recomputes_udp() {
        let mut p = udp(b"hello");
        let i = parse_ipv4(&p).unwrap();
        assert_eq!((i.proto, i.src_port, i.dst_port, i.is_fragment), (PROTO_UDP, 5000, 53, false));
        assert!(fix_checksums(&mut p));
        assert!(verify(&p));
    }

    #[test]
    fn known_vector_ip_header_checksum() {
        // Worked example widely used for RFC 1071: expected checksum 0xB861.
        let mut h = vec![0x45, 0, 0, 0x73, 0, 0, 0x40, 0, 0x40, 0x11, 0, 0, 0xC0, 0xA8, 0, 1, 0xC0, 0xA8, 0, 0xC7];
        h.resize(0x73, 0);
        h[20..28].copy_from_slice(&[0, 53, 0, 53, 0, 0x5F, 0, 0]);
        fix_checksums(&mut h);
        assert_eq!(&h[10..12], &[0xB8, 0x61]);
    }

    #[test]
    fn odd_length_payload_checksum() {
        let mut p = udp(b"abc");
        fix_checksums(&mut p);
        assert!(verify(&p));
    }

    #[test]
    fn rewrite_keeps_checksums_valid() {
        let mut p = udp(b"payload!");
        fix_checksums(&mut p);
        assert!(rewrite_src(&mut p, Ipv4Addr::new(10, 77, 0, 2)));
        assert_eq!(parse_ipv4(&p).unwrap().src, Ipv4Addr::new(10, 77, 0, 2));
        assert!(verify(&p));
        assert!(rewrite_dst(&mut p, Ipv4Addr::new(1, 2, 3, 4)));
        assert!(verify(&p));
    }

    #[test]
    fn udp_zero_checksum_stays_zero() {
        let mut p = udp(b"x");
        p[26] = 0;
        p[27] = 0;
        fix_checksums(&mut p);
        assert_eq!(&p[26..28], &[0, 0]);
    }

    #[test]
    fn first_fragment_l4_checksum_stays_consistent() {
        // Whole datagram gets a real checksum; the first fragment then carries
        // it. After rewriting the fragment's source the checksum must equal
        // the checksum of the whole datagram under the new source.
        let payload = vec![7u8; 64];
        let mut whole = udp(&payload);
        fix_checksums(&mut whole);
        let mut frag = whole[..52].to_vec(); // 24 bytes of L4 data
        frag[2..4].copy_from_slice(&52u16.to_be_bytes());
        frag[6] = 0x20; // MF
        let new = Ipv4Addr::new(10, 77, 0, 9);
        assert!(rewrite_src(&mut frag, new));
        assert!(rewrite_src(&mut whole, new));
        assert_eq!(&frag[26..28], &whole[26..28]);
    }

    #[test]
    fn fragments_are_flagged_and_have_no_ports() {
        let mut p = udp(&[0; 16]);
        p[6] = 0;
        p[7] = 10; // offset 10, last fragment
        let i = parse_ipv4(&p).unwrap();
        assert!(i.is_fragment && !i.is_first_fragment);
        assert_eq!((i.src_port, i.dst_port), (0, 0));
    }

    #[test]
    fn clamps_mss_only_when_higher() {
        let mut p = tcp_syn(1460);
        assert!(parse_ipv4(&p).unwrap().tcp_syn);
        assert!(clamp_mss(&mut p, 1300));
        assert_eq!(u16::from_be_bytes([p[44], p[45]]), 1300);
        fix_checksums(&mut p);
        assert!(verify(&p));
        let mut q = tcp_syn(1000);
        assert!(!clamp_mss(&mut q, 1300));
    }

    #[test]
    fn malformed_packets_never_panic() {
        assert!(parse_ipv4(&[]).is_none());
        assert!(parse_ipv4(&[0x45; 10]).is_none());
        let good = tcp_syn(1460);
        for n in 0..good.len() {
            let mut t = good[..n].to_vec();
            let _ = parse_ipv4(&t);
            let _ = clamp_mss(&mut t, 1300);
            let _ = fix_checksums(&mut t);
        }
        let mut bad = tcp_syn(1460);
        bad[43] = 0xFF; // MSS option length runs off the header
        assert!(!clamp_mss(&mut bad, 1300));
        let mut bad = tcp_syn(1460);
        bad[32] = 0xF0; // data offset beyond packet
        assert!(!clamp_mss(&mut bad, 1300));
        let mut v6 = good;
        v6[0] = 0x60;
        assert!(parse_ipv4(&v6).is_none());
    }

    #[test]
    fn scope_and_cidr() {
        assert!(is_local_scope("192.168.1.1".parse().unwrap()));
        assert!(is_local_scope("100.64.0.1".parse().unwrap()));
        assert!(is_local_scope("224.0.0.1".parse().unwrap()));
        assert!(!is_local_scope("8.8.8.8".parse().unwrap()));
        let (n, l) = parse_cidr("10.1.2.0/24").unwrap();
        assert!(cidr_contains(n, l, "10.1.2.200".parse().unwrap()));
        assert!(!cidr_contains(n, l, "10.1.3.1".parse().unwrap()));
        assert!(cidr_contains("0.0.0.0".parse().unwrap(), 0, "9.9.9.9".parse().unwrap()));
        assert_eq!(parse_cidr("1.2.3.4"), Some(("1.2.3.4".parse().unwrap(), 32)));
        assert!(parse_cidr("1.2.3.4/33").is_none());
        assert!(parse_cidr("nope/8").is_none());
    }
}
