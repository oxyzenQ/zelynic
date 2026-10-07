// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// The zelynic QUIC-aware attribution core (NIGHT-private-research-4
// candidate, schema v22): the pure header arithmetic behind
// per-CONNECTION keys for QUIC traffic, extracted the math.rs/ecn.rs
// way — zero aya/eBPF dependencies so the SAME file compiles into
// the kernel object (ebpf/src/quic_flow.rs wires it with #[path]
// through ebpf/src/bin/limiter.rs) AND into the userspace test tree
// (test/ebpf/limiter/quic_tests.rs), where the header laws are
// pinned rootlessly.
//
// THE PROBLEM, stated honestly. QUIC (RFC 9000 — HTTP/3, the shape
// a modern browser moves a large share of its traffic in) rides
// UDP and multiplexes many connections over ONE socket, demuxed by
// CONNECTION ID: Chromium and Firefox share a single UDP socket
// across every QUIC session, and the QUIC server shape demuxes
// every client CID through one listening socket. The limiter's
// attribution — bpf_get_socket_cookie, the join the per-socket
// lane and the v20 CAKE flow lane both key by — sees ONE cookie
// for all of them:
//
//   * the flow lane (cake_flow.rs): every QUIC connection of a
//     browser shares ONE flow bucket inside the leaf — the exact
//     monopoly shape the lane exists to stop, measured by its own
//     battery at 2.9:1 under a shared bucket against 1.1:1 under
//     isolated ones. For HTTP/3 the v20 lane quietly degrades to
//     its own before-picture.
//   * the per-socket lane (socket_flow.rs): every QUIC connection
//     shares ONE budget — the documented promise "each connection
//     its own bucket at the policy rate" (the --per-socket help
//     text) silently collapses to "the whole socket shares one"
//     for the protocol that needs it most.
//
// THE FIX, and its honest limit. QUIC packets carry the connection
// ID in the CLEAR even when the payload is encrypted: a long
// header (handshake family) carries BOTH endpoint CIDs with
// EXPLICIT lengths; a short header (all 1-RTT data) carries the
// peer's CID with a length that is CONNECTION STATE — RFC 9000
// negotiates it through NEW_CONNECTION_ID frames the middlebox
// cannot read, which is precisely why QUIC-LB exists. So the core
// statelessly parses long headers exactly, and learns the short
// header's CID length from the handshake's own explicit-length
// bytes: a long-header packet seen on direction D exposes the CID
// class D's own short headers will carry (its DCID, post-switch)
// AND the class the OPPOSITE direction's short headers will carry
// (its SCID). The learned length is CONFIRMATION-GATED — the same
// length must be seen twice before any short header keys on it —
// so the pre-switch Initial DCID (a throwaway random value the
// peer replaces after its Server Initial) cannot poison the lane
// by itself: it lands, and the post-switch long headers overwrite
// it before data flows. Every shape the core cannot parse falls
// back to the RAW COOKIE — exactly today's behavior, coarser but
// never wrong — so the feature strictly REFINES attribution and
// never invents it:
//
//   * non-UDP, non-IP, IPv6 with extension headers, QUIC headers
//     past the 56-byte L4 window (impossible for legal v1/v2
//     headers, whose worst case is 55), malformed headers: cookie.
//   * QUIC version other than v1 (1) and v2 (0x6b3343cf), version
//     negotiation (version 0), DCID/SCID lengths above the RFC 9000
//     v1 bound of 20: cookie — the strict-shape check, not a guess.
//   * a short header with no confirmed hint yet (the first data
//     packets of a connection): cookie — the connection's steady
//     state arrives within a few packets and rides per-CID from
//     then on.
//   * zero-length CIDs (an endpoint that chose them): cookie for
//     that direction — the packets carry nothing to key on, and a
//     zero hint never confirms.
//   * a single-direction policy (strict -d only, or -u only): the
//     UNPOLICED direction's hook takes the unlimited fast path
//     before any attribution work (the NIGHT-lts-2 law — the
//     unlimited majority pays two lookups, never a parse), and
//     that direction's long headers are the only place the
//     policed direction's CID length is learnable — so the policed
//     direction's short headers ride the cookie until a dual-leg
//     policy (the single lane's default) or any traffic the
//     policed side itself emits teaches it. The refusal is the
//     documented residue of the pinned fast-path law, the same
//     posture every other refusal here carries: coarser, never
//     wrong.
//
// THE RESIDUES, each stated where the tests pin the bound: a CID
// longer than 8 bytes keys by its first 8 (two connections of one
// socket differing only past byte 8 share a bucket — coarser,
// safe); a hint key packs the remote endpoint as IPv4 addr+port
// (v4) or the IPv6 /48 prefix + port (v6 — first 6 address bytes),
// so two v6 remotes past the 48-bit prefix share a hint entry and
// cross-pollinate lengths until the confirm gate converges them;
// a connection that rotates CIDs mid-flight (NEW_CONNECTION_ID,
// encrypted) keys the rotated packets under the new CID — a flow
// split the share word's decay heals in the fairness lane, and a
// fresh budget stream in the per-socket lane (one rotation = one
// re-armed burst, the lane's own documented "rate x concurrent"
// shape, stated in the v22 schema note); a GSO/GRO super-packet
// (UDP segmentation offload on egress, generic receive offload on
// ingress) is ONE skb to the cgroup hook, so its whole length
// attributes to the FIRST segment's connection — a multiplexed
// socket's coalesced burst may charge several connections' bytes
// to the first CID's bucket, still never coarser than the cookie
// lane's one-bucket-for-the-whole-socket verdict this feature
// refined (the attribution never crosses the socket, and the
// cgroup and per-socket caps bound the total regardless); the
// server-role shape (the policed host serving QUIC) may learn a
// throwaway length when the peer's Initial DCID and its real CID
// differ — the confirm gate plus the opposite-direction SCID
// source hold the dominant shapes correct and every wrong case
// degrades toward cookie, documented, never silently
// re-engineered.
//
// This module must stay `core`-only: no std, no alloc, no aya (the
// math.rs contract, verbatim — any dependency added here reaches
// both trees at once). Every buffer access is bounds-checked
// through .get() with graceful fallbacks: a parse that could panic
// would hang the BPF program (the no_std panic handler is a loop),
// so the core is panic-free by construction, and the test tree
// drives the SAME code the kernel runs.

/// The RFC 9000 v1 connection-ID length bound: DCIDs and SCIDs are
/// 0 to 20 bytes. A length byte above this is not a QUIC v1/v2
/// header (or a malformed one) — the parser refuses the shape
/// instead of guessing, and the packet rides the cookie lane.
pub const QUIC_MAX_CID_LEN: u8 = 20;

/// QUIC version 1 (RFC 9000).
const QUIC_VERSION_V1: u32 = 1;

/// QUIC version 2 (RFC 9369) — a v1-compatible header layout with
/// a different version tag; the core accepts both, nothing else.
const QUIC_VERSION_V2: u32 = 0x6b33_43cf;

// ─ The learned-hint word ─
//
// One u64 map value, the packed form every hint reader and writer
// agrees on: bits 0..8 carry the learned CID length, bit 8 carries
// the confirmation. A cold (absent) entry reads 0 — length 0,
// unconfirmed — which is exactly the "no hint" verdict, so the
// wiring needs no insert-before-read step and the short-header
// path degrades to the cookie on a miss without special cases.
// Zero-length CIDs never confirm: there is nothing to key on.

/// The confirmation bit of a hint word: set once the SAME nonzero
/// length has been seen by two long-header packets.
const HINT_CONFIRMED: u64 = 1 << 8;

/// Pack one learned length into a fresh (unconfirmed) hint word.
#[inline(always)]
pub fn hint_word(len: u8) -> u64 {
    u64::from(len)
}

/// Read the learned length out of a hint word.
#[inline(always)]
pub fn hint_len(word: u64) -> u8 {
    (word & 0xff) as u8
}

/// The confirmation predicate: a hint is usable only after the same
/// NONZERO length survived a second sighting. The gate exists
/// because a QUIC connection's first long-header packets carry a
/// throwaway DCID the peer replaces after its Server Initial —
/// an unconfirmed single sighting could key every data packet of
/// the connection against the wrong length, splitting the flow per
/// garbage key (the isolation-collapse shape the cake battery
/// measured); the second sighting comes from the post-switch
/// handshake packets or the opposite direction's Initial SCID, and
/// by then data flows against the confirmed geometry.
#[inline(always)]
pub fn hint_confirmed(word: u64) -> bool {
    word & HINT_CONFIRMED != 0 && (word & 0xff) != 0
}

/// The learn step, pure: fold one long-header sighting of `len`
/// into the hint state. The same length seen again confirms; a
/// changed length restarts unconfirmed (last-write-wins, the
/// transient the confirm gate exists to absorb); a zero length
/// never confirms (nothing to key on).
#[inline(always)]
pub fn hint_learn(old: u64, len: u8) -> u64 {
    if (old & 0xff) == u64::from(len) && len != 0 {
        old | HINT_CONFIRMED
    } else {
        u64::from(len)
    }
}

// ─ The key mixers ─
//
// Both keys are u64 values in u64-keyed LRU maps the lane already
// owns, so the substitution changes no map layout — only the key
// VALUE an attributed QUIC packet arrives under. The mixer is the
// splitmix64 finalizer: injective enough on distinct 64-bit inputs
// that a collision needs a 2^-64 coincidence, and the collision's
// consequence is the safe one everywhere (two flows share a bucket
// — coarser policing, the cookie lane's own behavior — never an
// unlimited pass, never a budget the policy did not grant).

/// The splitmix64 finalizer mix.
#[inline(always)]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// Pack the first 8 bytes of the window `buf[off..off + len]` into
/// a u64, little-endian, zero-padded past `len` — the CID prefix
/// and the remote-identity seed both use this fixed shape (a CID
/// longer than 8 bytes keys by its first 8: two connections of one
/// socket differing only past byte 8 then share a bucket, the
/// documented coarser-safe residue).
///
/// THE eBPF-SAFE BYTE COLLECTOR (night-audit-1, the 5.13 floor
/// law): every read rides the buffer's OWN base pointer at a
/// compile-time-constant `off + k` index gated by the scalar `k <
/// len` — no subslice is ever formed and no loop index is ever
/// loaded through. The v22 core's original loop-shaped collector
/// lowered to stack reads at pointer bases a re-slice had already
/// made variable, and the 5.13 verifier — whose imprecise range
/// tracking predates the 5.14 precision rework — could not bound
/// the combined offset, so BPF_PROG_LOAD refused the whole object
/// on the verified floor (supermassive runs 187+). The unrolled
/// form makes the safety structural instead of optimization-
/// dependent: `off` is a literal at every call site, so each load's
/// address is a frame constant the oldest verifier in the matrix
/// proves on sight.
#[inline(always)]
fn pack8_bounded(buf: &[u8], off: usize, len: usize) -> u64 {
    let b = |k: usize| -> u64 {
        if k < len {
            u64::from(buf.get(off + k).copied().unwrap_or(0))
        } else {
            0
        }
    };
    b(0) | (b(1) << 8)
        | (b(2) << 16)
        | (b(3) << 24)
        | (b(4) << 32)
        | (b(5) << 40)
        | (b(6) << 48)
        | (b(7) << 56)
}

/// The per-CONNECTION flow key: the socket cookie XOR the mixed CID
/// prefix. The cookie term keeps two sockets' flows distinct
/// whatever their CIDs; the mixed CID term keeps two connections of
/// ONE socket distinct (the kernel assigns cookies dense small
/// integers, the mix spreads the CID term across the full word —
/// the xor of two random-shaped terms collides with 2^-64 odds, and
/// the collision shares a bucket, the safe direction).
//
// allow(dead_code): the userspace test tree compiles this file and
// drives THIS form as its key oracle — every pinned key assertion
// names flow_key(cookie, &cid) — while the kernel object's datapath
// reads CIDs through flow_key_bounded at literal offsets (the 5.13
// floor law), so within the object compile this wrapper is dead
// code the -D warnings gate would refuse; the classify precedent
// one block below carries the same rationale.
#[allow(dead_code)]
#[inline(always)]
pub fn flow_key(cookie: u64, cid: &[u8]) -> u64 {
    flow_key_bounded(cookie, cid, 0, cid.len())
}

/// The per-CONNECTION flow key over a CID window INSIDE a buffer:
/// the first `len` bytes at `buf[off..]`, zero-padded past `len`,
/// mixed with the cookie. This is the form the datapath and the
/// parse core call — the CID window is named by (offset, length)
/// instead of a re-sliced pointer, the 5.13 floor law the pack8_bounded
/// doc above carries (a subslice pointer would drag the window's
/// runtime origin into every load's address and hand the old
/// verifier an offset it cannot bound).
#[inline(always)]
pub fn flow_key_bounded(cookie: u64, buf: &[u8], off: usize, len: usize) -> u64 {
    cookie ^ mix64(pack8_bounded(buf, off, len))
}

/// The conversation key for the hint maps: the socket cookie XOR the
/// mixed remote-identity seed (IPv4 addr+port, or the IPv6 /48
/// prefix + port). One UDP conversation = one socket cookie + one
/// remote endpoint, so the hint a handshake teaches lands beside the
/// conversation that taught it; a browser's one socket to N servers
/// holds N distinct hint entries. Two v6 remotes sharing the first
/// 6 address bytes pollinate each other's hint until the confirm
/// gate converges — the documented residue, coarser not wrong.
#[inline(always)]
pub fn hint_key(cookie: u64, remote_seed: u64) -> u64 {
    cookie ^ mix64(remote_seed)
}

// ─ The L3/L4 shape ─

/// The UDP payload's first byte in the L4 window (the QUIC header
/// starts at the UDP header's own 8-byte fixed size).
const QUIC_OFF: usize = 8;

/// The DCID length byte's offset in the L4 window (long headers:
/// first byte, 4 version bytes, then the length).
const DCID_LEN_OFF: usize = QUIC_OFF + 5;

/// The DCID's first byte in the L4 window (the length byte itself
/// sits between the version field and the DCID bytes).
const DCID_OFF: usize = DCID_LEN_OFF + 1;

/// The SCID length byte sits at `DCID_OFF + dl` — a RUNTIME family
/// position (the DCID's explicit length decides it). Read the whole
/// candidate window at compile-time-constant offsets and extract
/// the wanted byte with a scalar shift, so the object carries ZERO
/// variable-offset stack reads: the three u64 windows below pack
/// bytes DCID_OFF..DCID_OFF+21 little-endian, and the `dl`-indexed
/// byte is a shift-and-mask of the packed registers (pure ALU, no
/// memory access at any runtime address — the 5.13 floor law,
/// night-audit-1). A window past the buffer reads as 0; the caller's
/// span check turns that into the honest refusal (a missing length
/// byte cannot produce a span that fits).
#[inline(always)]
fn scid_len_byte(l4: &[u8], dl: usize) -> u8 {
    let b = |k: usize| -> u64 { u64::from(l4.get(DCID_OFF + k).copied().unwrap_or(0)) };
    let lo = b(0)
        | (b(1) << 8)
        | (b(2) << 16)
        | (b(3) << 24)
        | (b(4) << 32)
        | (b(5) << 40)
        | (b(6) << 48)
        | (b(7) << 56);
    let mid = b(8)
        | (b(9) << 8)
        | (b(10) << 16)
        | (b(11) << 24)
        | (b(12) << 32)
        | (b(13) << 40)
        | (b(14) << 48)
        | (b(15) << 56);
    let hi = b(16) | (b(17) << 8) | (b(18) << 16) | (b(19) << 24) | (b(20) << 32);
    if dl <= 7 {
        (lo >> (8 * dl)) as u8
    } else if dl <= 15 {
        (mid >> (8 * (dl - 8))) as u8
    } else {
        (hi >> (8 * (dl - 16))) as u8
    }
}

/// Parse one QUIC header out of the L4 window (the wiring's second
/// bounded read rebased it: l4[0] is the UDP source port, the QUIC
/// first byte is l4[8]). The strict-shape checks: version must be
/// v1 or v2 (version 0 is Version Negotiation — refused); DCID and
/// SCID lengths must sit inside the RFC 9000 v1 bound of 20; the
/// fixed bit must be set; every field must live inside the window.
/// A refusal is the cookie lane, never a guess.
#[inline(always)]
fn parse_quic(l4: &[u8]) -> Header {
    let b0 = match l4.get(QUIC_OFF) {
        Some(&b) => b,
        None => return Header::NotQuic,
    };
    if b0 & 0x40 == 0 {
        return Header::NotQuic;
    }
    if b0 & 0x80 == 0 {
        return Header::Short;
    }
    let version = match be32_at(l4, QUIC_OFF + 1) {
        Some(v) => v,
        None => return Header::NotQuic,
    };
    if version != QUIC_VERSION_V1 && version != QUIC_VERSION_V2 {
        return Header::NotQuic;
    }
    let dl = usize::from(*l4.get(DCID_LEN_OFF).unwrap_or(&u8::MAX));
    if dl > QUIC_MAX_CID_LEN as usize {
        return Header::NotQuic;
    }
    let sl = usize::from(scid_len_byte(l4, dl));
    if sl > QUIC_MAX_CID_LEN as usize {
        return Header::NotQuic;
    }
    // The whole header must fit the window: first byte + version +
    // the two length bytes + both CIDs.
    if DCID_OFF + dl + 1 + sl > l4.len() {
        return Header::NotQuic;
    }
    Header::Long { dl, sl }
}

// ─ The one pure decision ─

/// The verdict for one attributed packet: what the wiring should
/// key the flow on, and what (if anything) the handshake just
/// taught the hint maps.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Classify {
    /// Ride the socket cookie, exactly today's behavior: not QUIC,
    /// unparsable, or a short header with no confirmed hint.
    Cookie,
    /// A v1/v2 long header: key the flow by its EXACT DCID (the
    /// length is explicit — stateless, no hint needed), and fold
    /// the two endpoint lengths into the hint maps — `learn_this`
    /// (this direction's DCID length) into this direction's hint
    /// map, `learn_other` (the SCID length) into the opposite
    /// direction's, both at `hkey` (the conversation's key). The
    /// wiring applies hint_learn and writes only what changed.
    Long {
        key: u64,
        hkey: u64,
        learn_this: u8,
        learn_other: u8,
    },
    /// A short header: `Some(key)` when the hint is confirmed and
    /// the DCID sits inside the buffer — the per-connection key the
    /// feature exists for; `None` rides the cookie (the first data
    /// packets of every connection, and every shape that never
    /// confirmed).
    Short { key: Option<u64> },
}

/// The conversation a packet belongs to: the hint-map key that
/// names it (one socket cookie + one remote endpoint). The wiring
/// reads THIS direction's hint word at `hkey` between the two pure
/// steps — the lookup it needs the conversation's identity for.
pub struct Conversation {
    /// The conversation's hint-map key, both directions' maps.
    pub hkey: u64,
}

/// Step one: name the conversation from the two bounded windows —
/// `ip` the packet's first bytes (the IP header window the wiring's
/// first read landed), `l4` the rebased UDP window (its second
/// read), `shape` what parse_l4 concluded about the IP header.
/// None (not IP, not UDP, truncated, extension headers) is the
/// cookie lane — the caller never consults QUIC.
#[inline(always)]
pub fn conversation(
    cookie: u64,
    ip: &[u8],
    l4: &[u8],
    shape: &L4Shape,
    is_ingress: bool,
) -> Option<Conversation> {
    let seed = remote_seed(ip, l4, shape.v4, is_ingress)?;
    Some(Conversation {
        hkey: hint_key(cookie, seed),
    })
}

/// Step two: the QUIC decision over the rebased L4 window, with
/// this direction's current hint word in hand (0 on a miss — the
/// packed "no hint" verdict). See Classify for the verdicts. Every
/// CID read rides flow_key_bounded at a literal offset (the
/// short-header DCID starts one byte past the QUIC first byte, the
/// long-header DCID at DCID_OFF), so the eBPF object's loads all
/// sit at frame constants — the 5.13 floor law, night-audit-1.
#[inline(always)]
pub fn decide(cookie: u64, l4: &[u8], conv: &Conversation, hint_this: u64) -> Classify {
    match parse_quic(l4) {
        Header::NotQuic => Classify::Cookie,
        Header::Short => {
            let len = hint_len(hint_this);
            let key = if hint_confirmed(hint_this) {
                // The whole learned CID must fit the window — the
                // same fit the v22 re-slice demanded, stated as one
                // scalar check before any byte is read.
                match (QUIC_OFF + 1).checked_add(usize::from(len)) {
                    Some(end) if end <= l4.len() => {
                        Some(flow_key_bounded(cookie, l4, QUIC_OFF + 1, usize::from(len)))
                    }
                    _ => None,
                }
            } else {
                None
            };
            Classify::Short { key }
        }
        Header::Long { dl, sl } => {
            // parse_quic already proved the header fits; the scalar
            // belt keeps a future parse change from turning a miss
            // into a read past the window.
            if DCID_OFF.checked_add(dl).is_some_and(|end| end > l4.len()) {
                return Classify::Cookie;
            }
            Classify::Long {
                key: flow_key_bounded(cookie, l4, DCID_OFF, dl),
                hkey: conv.hkey,
                learn_this: dl as u8,
                learn_other: sl as u8,
            }
        }
    }
}

/// The whole QUIC-aware decision, pure on one packet's bytes — the
/// two steps composed, the form the rootless battery drives: split
/// the packet the way the wiring's two bounded reads do (the IP
/// header window is the packet itself; the L4 window is the
/// IHL-rebased tail), parse the outer headers for the conversation
/// identity, parse the QUIC header for the connection identity, and
/// hand the caller the key plus the hint-state updates. `hint_this`
/// is the CURRENT word of this direction's hint map at the
/// conversation's key (0 on a miss — the packed "no hint" verdict).
/// Everything that can refuse, refuses to the cookie lane.
//
// allow(dead_code): the userspace test tree compiles this file
// without the datapath that inlines the two steps separately — the
// kernel object's quic_flow_key calls conversation() and decide()
// on its own because the hint-map read must run BETWEEN them, so
// this composed form is the test battery's entry point, never the
// object's; the during.rs span-predicate family carries the same
// rationale, the math.rs POLICY_FLAG_PER_SOCKET precedent one
// feature earlier.
#[allow(dead_code)]
#[inline(always)]
pub fn classify(cookie: u64, pkt: &[u8], is_ingress: bool, hint_this: u64) -> Classify {
    let shape = match parse_l4(pkt) {
        Some(s) => s,
        None => return Classify::Cookie,
    };
    // Userspace rebase (the wiring's second load_bytes lands the
    // same window on its own stack buffer): slicing is free here,
    // and no verifier ever sees this body in the kernel object.
    let l4 = match pkt.get(shape.l4_off..) {
        Some(w) => w,
        None => return Classify::Cookie,
    };
    let conv = match conversation(cookie, pkt, l4, &shape, is_ingress) {
        Some(c) => c,
        None => return Classify::Cookie,
    };
    decide(cookie, l4, &conv, hint_this)
}

// NIGHT-improve-44: the 600-line cap split — the L4 parsing family
// lives in quic_l4.rs now, #[path]-wired as a nested module with a
// glob re-export (quic::parse_l4 and quic::L4Shape resolve as they
// always did, in the bin root and the rootless test tree alike).
#[path = "quic_l4.rs"]
mod quic_l4;
pub use quic_l4::*;
