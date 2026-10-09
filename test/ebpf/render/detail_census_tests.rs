// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the displayable-census gate (`detail::is_displayable`)
//! — the is-this-socket-worth-a-line law every surface shares: the
//! eagle tree, the depth report's endpoint rows, and the JSON
//! endpoints array all census through this one gate (NIGHT-
//! private-research-3: shared, never duplicated — a second copy is
//! how the surfaces drift). The family lives in its own file since
//! night-improve-62: the v6 arms (Tcp6/Udp6/Raw6) pushed
//! detail_tests.rs past the owner's LOC cap, and the split follows
//! the bytes family's precedent (NIGHT-boost-26) — one file per
//! contract, a pure move, gates green in between.

use super::*;

/// night-audit-6 pin: a CONNECTED UDP socket (the QUIC-client shape)
/// is traffic, not noise. /proc/net/udp reports the sk_state
/// verbatim — 01 (ESTABLISHED) for a connected socket, 07 (CLOSE)
/// for an unconnected one (probe-verified live: connect() a UDP
/// socket and its table row reads 01) — and the former gate accepted
/// only CLOSE, which filtered every connected-UDP row out of the
/// depth report and the live tree. The bound-only listener (the
/// hunt-15 shape) stays hidden; the unconnected-with-remote row (the
/// nc fixture shape) stays shown.
#[test]
fn displayable_connected_udp_is_traffic() {
    use crate::ebpf::connections::{Proto, SocketInfo};

    let udp = |remote: &str, state: &'static str| SocketInfo {
        proto: Proto::Udp,
        remote: remote.to_string(),
        state,
        queued: false,
        cookie: None,
    };

    // Connected UDP (state 01, real remote): the QUIC-client shape.
    assert!(is_displayable(&udp("142.250.191.78:443", "ESTABLISHED")));
    // Unconnected with a real remote (state 07): the nc shape.
    assert!(is_displayable(&udp("8.8.8.8:53", "CLOSE")));
    // Bound-only listeners: noise either family — hidden.
    assert!(!is_displayable(&udp("0.0.0.0:0", "CLOSE")));
    assert!(!is_displayable(&udp("[::]:0", "CLOSE")));
    // The TCP law is untouched.
    assert!(is_displayable(&SocketInfo {
        proto: Proto::Tcp,
        remote: "10.90.170.143:443".to_string(),
        state: "ESTABLISHED",
        queued: false,
        cookie: None,
    }));
    assert!(!is_displayable(&SocketInfo {
        proto: Proto::Tcp,
        remote: "0.0.0.0:22".to_string(),
        state: "LISTEN",
        queued: false,
        cookie: None,
    }));
}

/// night-improve-57 pin: raw sockets (SOCK_RAW from /proc/net/raw{,6})
/// are shown unconditionally. Raw sockets are not connection-oriented
/// — the kernel reports the TCP-style sk_state (07=CLOSE for
/// unconnected, 01=ESTABLISHED for connect()ed) but neither maps to
/// a "moving bytes" verdict the way TCP's ESTABLISHED does. A raw
/// socket can move bytes via sendto() without ever calling
/// connect(), so the remote stays 0.0.0.0:0 in the table while the
/// socket is actively sending — the same remote guard the UDP
/// branch uses would hide exactly the traffic the raw tag exists to
/// surface. The raw arm accepts every state (an unbound raw socket
/// is rare in userland and worth surfacing; the byte suffix carries
/// the activity signal). This pin mirrors the night-audit-6 UDP pin
/// for the raw arm.
#[test]
fn displayable_raw_sockets_show_unconditionally() {
    use crate::ebpf::connections::{Proto, SocketInfo};

    let raw = |remote: &str, state: &'static str| SocketInfo {
        proto: Proto::Raw,
        remote: remote.to_string(),
        state,
        queued: false,
        cookie: None,
    };

    // Connect()ed raw socket (state 01, real remote): the ping shape.
    assert!(is_displayable(&raw("1.2.3.4:0", "ESTABLISHED")));
    // Unconnected raw socket with no remote: the nmap/sendto shape.
    // The remote is 0.0.0.0:0 but the socket is still worth surfacing.
    assert!(is_displayable(&raw("0.0.0.0:0", "CLOSE")));
    // Unconnected raw socket with a bound local address but no remote
    // (some tools bind() but never connect()): still shown.
    assert!(is_displayable(&raw("0.0.0.0:0", "ESTABLISHED")));
    // An IPv6 raw socket with no remote: still shown.
    assert!(is_displayable(&raw("[::]:0", "CLOSE")));
    // A raw socket with the LISTEN state (rare, but the kernel can
    // report it for a bound-but-not-active raw socket): still shown.
    assert!(is_displayable(&raw("0.0.0.0:0", "LISTEN")));
}

/// night-improve-62 pin: the v6 arms ride the same gates — the
/// family changes the tag, never the census: tcp6 keeps the
/// ESTABLISHED law, udp6's `:0` listener guard, raw6 unconditional.
#[test]
fn displayable_v6_arms_ride_the_same_gates() {
    use crate::ebpf::connections::{Proto, SocketInfo};

    let mk = |proto: Proto, remote: &'static str, state: &'static str| SocketInfo {
        proto,
        remote: remote.to_string(),
        state,
        queued: false,
        cookie: None,
    };
    // tcp6: ESTABLISHED shows, LISTEN stays noise (the Tcp law).
    assert!(is_displayable(&mk(
        Proto::Tcp6,
        "[2001:db8::1]:443",
        "ESTABLISHED"
    )));
    assert!(!is_displayable(&mk(Proto::Tcp6, "[::]:22", "LISTEN")));
    // udp6: the bound-only v6 listener stays hidden (hunt-15's `:0` law).
    assert!(is_displayable(&mk(
        Proto::Udp6,
        "[2001:db8::53]:53",
        "CLOSE"
    )));
    assert!(!is_displayable(&mk(Proto::Udp6, "[::]:0", "CLOSE")));
    // raw6: unconditional — the raw law carries the family along.
    assert!(is_displayable(&mk(Proto::Raw6, "[::1]:0", "CLOSE")));
}
