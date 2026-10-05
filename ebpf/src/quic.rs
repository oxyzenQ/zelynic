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
//   * non-UDP, non-IP, IPv6 with extension headers, IP options
//     beyond the 96-byte parse window, malformed headers: cookie.
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
//     policy (the strict-single default) or any traffic the
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
// shape, stated in the v22 schema note); the server-role shape
// (the policed host serving QUIC) may learn a throwaway length
// when the peer's Initial DCID and its real CID differ — the
// confirm gate plus the opposite-direction SCID source hold the
// dominant shapes correct and every wrong case degrades toward
// cookie, documented, never silently re-engineered.
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

/// Pack the first 8 bytes of a slice into a u64, little-endian,
/// zero-padded — the CID prefix and the remote-identity seed both
/// use this fixed shape (a CID longer than 8 bytes keys by its
/// first 8: two connections of one socket differing only past byte
/// 8 then share a bucket, the documented coarser-safe residue).
#[inline(always)]
fn pack8(bytes: &[u8]) -> u64 {
    let mut v: u64 = 0;
    let n = core::cmp::min(8, bytes.len());
    let mut i = 0;
    while i < n {
        v |= u64::from(bytes[i]) << (8 * i);
        i += 1;
    }
    v
}

/// The per-CONNECTION flow key: the socket cookie XOR the mixed CID
/// prefix. The cookie term keeps two sockets' flows distinct
/// whatever their CIDs; the mixed CID term keeps two connections of
/// ONE socket distinct (the kernel assigns cookies dense small
/// integers, the mix spreads the CID term across the full word —
/// the xor of two random-shaped terms collides with 2^-64 odds, and
/// the collision shares a bucket, the safe direction).
#[inline(always)]
pub fn flow_key(cookie: u64, cid: &[u8]) -> u64 {
    cookie ^ mix64(pack8(cid))
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

// ─ The L3/L4 span ─

/// Where the UDP header starts and where the remote endpoint's
/// identity sits in the parse buffer — the two facts every QUIC
/// decision needs from the packet's outer headers.
#[derive(Clone, Copy)]
pub struct L4Span {
    /// Offset of the UDP header (IHL*4 for IPv4, 40 for IPv6).
    pub l4_off: usize,
    /// The remote endpoint's IP address span (ingress: source;
    /// egress: destination — the same host both directions).
    pub remote: (usize, usize),
    /// The remote endpoint's port span inside the UDP header
    /// (ingress: source port; egress: destination port).
    pub port: (usize, usize),
}

/// Parse the L3/L4 outer headers far enough to attribute a UDP
/// conversation: IPv4 (any IHL, protocol 17) or IPv6 (next header
/// 17 — extension headers honestly refuse, the residue the docs
/// carry), UDP implied by the protocol check. Every bounds or
/// shape failure returns None and the caller rides the cookie lane
/// unchanged.
#[inline(always)]
pub fn parse_l4(buf: &[u8], is_ingress: bool) -> Option<L4Span> {
    let b0 = *buf.get(0)?;
    match b0 >> 4 {
        4 => {
            let ihl = usize::from(b0 & 0x0f);
            if ihl < 5 {
                return None;
            }
            let l4_off = ihl * 4;
            if *buf.get(9)? != 17 || buf.len() < l4_off + 8 {
                return None;
            }
            Some(L4Span {
                l4_off,
                remote: if is_ingress { (12, 16) } else { (16, 20) },
                port: if is_ingress {
                    (l4_off, l4_off + 2)
                } else {
                    (l4_off + 2, l4_off + 4)
                },
            })
        }
        6 => {
            let l4_off = 40;
            if *buf.get(6)? != 17 || buf.len() < l4_off + 8 {
                return None;
            }
            Some(L4Span {
                l4_off,
                remote: if is_ingress { (8, 24) } else { (24, 40) },
                port: if is_ingress {
                    (l4_off, l4_off + 2)
                } else {
                    (l4_off + 2, l4_off + 4)
                },
            })
        }
        _ => None,
    }
}

/// Build the remote-identity seed: the remote address's first bytes
/// (4 for IPv4, 6 for IPv6 — the /48 prefix) followed by the remote
/// port, zero-padded to a fixed 8-byte shape.
#[inline(always)]
fn remote_seed(buf: &[u8], span: &L4Span) -> Option<u64> {
    let ip = buf.get(span.remote.0..span.remote.1)?;
    let port = buf.get(span.port.0..span.port.1)?;
    let mut seed = [0u8; 8];
    let ip_n = core::cmp::min(6, ip.len());
    let mut i = 0;
    while i < ip_n {
        seed[i] = ip[i];
        i += 1;
    }
    let mut j = 0;
    while j < core::cmp::min(2, port.len()) {
        seed[ip_n + j] = port[j];
        j += 1;
    }
    Some(pack8(&seed))
}

// ─ The QUIC header laws ─

/// Read a big-endian u32 out of a slice, None on truncation.
#[inline(always)]
fn be32(buf: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes([
        *buf.get(0)?,
        *buf.get(1)?,
        *buf.get(2)?,
        *buf.get(3)?,
    ]))
}

/// The QUIC header shape one packet parses into. The invariant
/// bits (RFC 8999): long headers set both 0x80 and 0x40; short
/// headers set 0x40 alone; any packet with 0x40 clear is not QUIC.
#[derive(Clone, Copy, Debug)]
enum Header {
    /// A v1/v2 long header with well-formed CID fields: the exact
    /// DCID and SCID spans, both lengths explicit.
    Long {
        dcid: (usize, usize),
        scid: (usize, usize),
    },
    /// A short header: the DCID sits right after the first byte,
    /// its length learned (the hint word), never parsed here.
    Short,
    /// Anything else — including every packet that is simply not
    /// QUIC. The caller rides the cookie lane.
    NotQuic,
}

/// Parse one QUIC header at `l4_off + 8` (the UDP payload). The
/// strict-shape checks: version must be v1 or v2 (version 0 is
/// Version Negotiation — refused); DCID and SCID lengths must sit
/// inside the RFC 9000 v1 bound of 20; the fixed bit must be set;
/// every field must live inside the buffer. A refusal is the
/// cookie lane, never a guess.
#[inline(always)]
fn parse_quic(buf: &[u8], l4_off: usize) -> Header {
    let q = l4_off + 8;
    let b0 = match buf.get(q) {
        Some(&b) => b,
        None => return Header::NotQuic,
    };
    if b0 & 0x40 == 0 {
        return Header::NotQuic;
    }
    if b0 & 0x80 == 0 {
        return Header::Short;
    }
    let version = match be32(buf.get(q + 1..).unwrap_or(&[])) {
        Some(v) => v,
        None => return Header::NotQuic,
    };
    if version != QUIC_VERSION_V1 && version != QUIC_VERSION_V2 {
        return Header::NotQuic;
    }
    let dcid_len = *buf.get(q + 5).unwrap_or(&u8::MAX);
    if dcid_len > QUIC_MAX_CID_LEN {
        return Header::NotQuic;
    }
    let dl = usize::from(dcid_len);
    let scid_len = *buf.get(q + 6 + dl).unwrap_or(&u8::MAX);
    if scid_len > QUIC_MAX_CID_LEN {
        return Header::NotQuic;
    }
    let sl = usize::from(scid_len);
    if q + 6 + dl + 1 + sl > buf.len() {
        return Header::NotQuic;
    }
    Header::Long {
        dcid: (q + 6, q + 6 + dl),
        scid: (q + 6 + dl + 1, q + 6 + dl + 1 + sl),
    }
}

// ─ The one pure decision ─

/// The verdict for one attributed packet: what the wiring should
/// key the flow on, and what (if anything) the handshake just
/// taught the hint maps.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Classify {
    /// Ride the socket cookie, exactly today's behavior: not QUIC,
    /// unparseable, or a short header with no confirmed hint.
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

/// The conversation a packet belongs to: where its UDP header
/// sits, and the hint-map key that names it (one socket cookie +
/// one remote endpoint). The wiring reads THIS direction's hint
/// word at `hkey` between the two pure steps — the lookup it needs
/// the conversation's identity for.
pub struct Conversation {
    /// Offset of the UDP header inside the parse buffer.
    pub l4_off: usize,
    /// The conversation's hint-map key, both directions' maps.
    pub hkey: u64,
}

/// Step one: parse the outer headers far enough to name the
/// conversation. None (not IP, not UDP, truncated, extension
/// headers) is the cookie lane — the caller never consults QUIC.
#[inline(always)]
pub fn conversation(cookie: u64, buf: &[u8], is_ingress: bool) -> Option<Conversation> {
    let span = parse_l4(buf, is_ingress)?;
    let seed = remote_seed(buf, &span)?;
    Some(Conversation {
        l4_off: span.l4_off,
        hkey: hint_key(cookie, seed),
    })
}

/// Step two: the QUIC decision, with this direction's current hint
/// word in hand (0 on a miss — the packed "no hint" verdict). See
/// Classify for the verdicts.
#[inline(always)]
pub fn decide(cookie: u64, buf: &[u8], conv: &Conversation, hint_this: u64) -> Classify {
    match parse_quic(buf, conv.l4_off) {
        Header::NotQuic => Classify::Cookie,
        Header::Short => {
            let len = hint_len(hint_this);
            let key = if hint_confirmed(hint_this) {
                let off = conv.l4_off + 8 + 1;
                buf.get(off..off + usize::from(len))
                    .map(|cid| flow_key(cookie, cid))
            } else {
                None
            };
            Classify::Short { key }
        }
        Header::Long { dcid, scid } => {
            let key = match buf.get(dcid.0..dcid.1) {
                Some(cid) => flow_key(cookie, cid),
                None => return Classify::Cookie,
            };
            Classify::Long {
                key,
                hkey: conv.hkey,
                learn_this: (dcid.1 - dcid.0) as u8,
                learn_other: (scid.1 - scid.0) as u8,
            }
        }
    }
}

/// The whole QUIC-aware decision, pure on the packet bytes — the
/// two steps composed, the form the rootless battery drives: parse
/// the outer headers for the conversation identity, parse the QUIC
/// header for the connection identity, and hand the caller the key
/// plus the hint-state updates. `hint_this` is the CURRENT word of
/// this direction's hint map at the conversation's key (0 on a
/// miss — the packed "no hint" verdict). Everything that can
/// refuse, refuses to the cookie lane.
#[inline(always)]
pub fn classify(cookie: u64, buf: &[u8], is_ingress: bool, hint_this: u64) -> Classify {
    match conversation(cookie, buf, is_ingress) {
        Some(conv) => decide(cookie, buf, &conv, hint_this),
        None => Classify::Cookie,
    }
}
