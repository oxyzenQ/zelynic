// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// NIGHT-improve-44: the L4 parsing family (L4Shape, parse_l4,
// the remote-seed derivation, the bounded readers) moved out of
// quic.rs at the 600-line cap — nested #[path], re-exported
// through quic so every consumer keeps resolving quic::parse_l4.
//
/// What the packet's outer headers told the parse: where the UDP
/// header starts, and which address family the remote-identity
/// window reads. THE TWO-READ SPLIT (night-audit-1, the 5.13 floor
/// law): `l4_off` is a SCALAR the wiring hands bpf_skb_load_bytes
/// for the second bounded read — never a memory offset inside the
/// pure core — because the second read rebases the L4 window so
/// every QUIC byte the core touches sits at a family-constant
/// offset of a fresh stack buffer. The v22 core parsed one
/// 96-byte window, so every field past the IP header lived at a
/// runtime offset (IHL-dependent) and the loads behind re-sliced
/// pointers were exactly what the 5.13 verifier refused to bound.
#[derive(Clone, Copy)]
pub struct L4Shape {
    /// Offset of the UDP header inside the PACKET (IHL*4 for IPv4,
    /// 40 for IPv6) — consumed by the wiring's second load_bytes
    /// call only; the pure core never reads through it.
    pub l4_off: usize,
    /// true = IPv4 (the remote address is the 12..16 or 16..20
    /// window); false = IPv6 (the /48 prefix is the 8..14 or
    /// 24..30 window).
    pub v4: bool,
}

/// Parse the packet's IP header far enough to attribute a UDP
/// conversation: IPv4 (any IHL, protocol 17) or IPv6 (next header
/// 17 — extension headers honestly refuse, the residue the docs
/// carry), UDP implied by the protocol check. Every bounds or
/// shape failure returns None and the caller rides the cookie lane
/// unchanged. `ip` is the packet's FIRST bytes (the IP header
/// window — the fields this reads all live at constant offsets in
/// it), so the same function serves the wiring's bounded read and
/// the test tree's whole-packet view.
#[inline(always)]
pub fn parse_l4(ip: &[u8]) -> Option<L4Shape> {
    let b0 = *ip.first()?;
    match b0 >> 4 {
        4 => {
            let ihl = usize::from(b0 & 0x0f);
            if ihl < 5 {
                return None;
            }
            if *ip.get(9)? != 17 {
                return None;
            }
            Some(L4Shape {
                l4_off: ihl * 4,
                v4: true,
            })
        }
        6 => {
            if *ip.get(6)? != 17 {
                return None;
            }
            Some(L4Shape {
                l4_off: 40,
                v4: false,
            })
        }
        _ => None,
    }
}

/// Build the remote-identity seed: the remote address's first bytes
/// (4 for IPv4, 6 for IPv6 — the /48 prefix) followed by the remote
/// port, zero-padded to a fixed 8-byte shape.
///
/// THE eBPF-SAFE FORM (night-audit-1): every byte is read at a
/// LITERAL offset of its own buffer — the address windows are
/// IP-header constants and the port windows UDP-header constants
/// (the wiring's second read rebases the L4 window so `l4[0]` IS
/// the UDP source port) — so no load's address ever carries a
/// runtime term. The v22 shape re-sliced `ip` and `port` out of one
/// buffer and copied them through an index loop; both moves are the
/// variable-offset stack access class the 5.13 verifier refuses.
/// A missing byte (truncated head area) refuses the whole seed —
/// the caller rides the cookie, never a guess.
#[inline(always)]
pub(crate) fn remote_seed(ip: &[u8], l4: &[u8], v4: bool, is_ingress: bool) -> Option<u64> {
    if v4 {
        // IPv4: the 4-byte address window then the 2-byte port.
        if is_ingress {
            Some(
                u64::from(*ip.get(12)?)
                    | (u64::from(*ip.get(13)?) << 8)
                    | (u64::from(*ip.get(14)?) << 16)
                    | (u64::from(*ip.get(15)?) << 24)
                    | (u64::from(*l4.first()?) << 32)
                    | (u64::from(*l4.get(1)?) << 40),
            )
        } else {
            Some(
                u64::from(*ip.get(16)?)
                    | (u64::from(*ip.get(17)?) << 8)
                    | (u64::from(*ip.get(18)?) << 16)
                    | (u64::from(*ip.get(19)?) << 24)
                    | (u64::from(*l4.get(2)?) << 32)
                    | (u64::from(*l4.get(3)?) << 40),
            )
        }
    } else if is_ingress {
        // IPv6 ingress: the source /48 prefix (bytes 8..14) then the
        // source port.
        Some(
            u64::from(*ip.get(8)?)
                | (u64::from(*ip.get(9)?) << 8)
                | (u64::from(*ip.get(10)?) << 16)
                | (u64::from(*ip.get(11)?) << 24)
                | (u64::from(*ip.get(12)?) << 32)
                | (u64::from(*ip.get(13)?) << 40)
                | (u64::from(*l4.first()?) << 48)
                | (u64::from(*l4.get(1)?) << 56),
        )
    } else {
        // IPv6 egress: the destination /48 prefix (bytes 24..30)
        // then the destination port.
        Some(
            u64::from(*ip.get(24)?)
                | (u64::from(*ip.get(25)?) << 8)
                | (u64::from(*ip.get(26)?) << 16)
                | (u64::from(*ip.get(27)?) << 24)
                | (u64::from(*ip.get(28)?) << 32)
                | (u64::from(*ip.get(29)?) << 40)
                | (u64::from(*l4.get(2)?) << 48)
                | (u64::from(*l4.get(3)?) << 56),
        )
    }
}

// ─ The QUIC header laws ─

/// Read a big-endian u32 at `buf[off..off+4]`, None on truncation.
/// The eBPF-safe form: four reads at compile-time-constant offsets
/// of the caller's own buffer (night-audit-1, the 5.13 floor law —
/// the v22 shape took a re-sliced subslice whose runtime base the
/// old verifier could not bound).
#[inline(always)]
pub(crate) fn be32_at(buf: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *buf.get(off)?,
        *buf.get(off + 1)?,
        *buf.get(off + 2)?,
        *buf.get(off + 3)?,
    ]))
}

/// The QUIC header shape one packet parses into. The invariant
/// bits (RFC 8999): long headers set both 0x80 and 0x40; short
/// headers set 0x40 alone; any packet with 0x40 clear is not QUIC.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Header {
    /// A v1/v2 long header with well-formed CID fields: both
    /// lengths explicit (dl is the DCID length, sl the SCID's).
    Long { dl: usize, sl: usize },
    /// A short header: the DCID sits right after the first byte,
    /// its length learned (the hint word), never parsed here.
    Short,
    /// Anything else — including every packet that is simply not
    /// QUIC. The caller rides the cookie lane.
    NotQuic,
}
