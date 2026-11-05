// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The socket-table type contract (night-dragon-maintenance-5).
//!
//! A pure move out of the parent module: [`Proto`] and
//! [`SocketInfo`] are the data vocabulary the /proc/net table
//! parsers and every renderer share, and they hold zero logic that
//! touches the crate. Standing alone here keeps the parent module
//! free to import the identity/loader machinery while the type
//! contract stays std-only and crate-import-free — the property the
//! fuzz harness's path-include law requires (see
//! fuzz/Cargo.toml and scripts/gates/check-fuzz-includes.sh). The
//! parent re-exports both names, so every existing
//! `connections::{Proto, SocketInfo}` path is unchanged.

/// Transport protocol a socket row was read from. Six variants,
/// six kernel tables, one-for-one: night-improve-62 split the
/// family suffix out of the walk. Before it, the v6 tables
/// collapsed into the v4 spellings at `read_socket_tables`, so an
/// IPv6 socket read `tcp` and the family reached the eye only
/// through the bracketed remote (`[::1]:443`), never through the
/// tag — a dual-stack deployment's two kinds of 443 were tagged
/// identically. The suffix spelling (`tcp6` / `udp6` / `raw6`) is
/// the one ss and netstat already speak — the operator's existing
/// vocabulary, not a new dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    /// The /proc/net/tcp6 spelling of TCP — same transport, v6
    /// family; the tag carries the family the table already knows.
    Tcp6,
    Udp,
    /// The /proc/net/udp6 spelling of UDP — QUIC rides both
    /// families; the suffix tells the operator which one this
    /// socket speaks.
    Udp6,
    /// Raw IP sockets (SOCK_RAW) — /proc/net/raw, /proc/net/raw6.
    /// night-improve-57: raw sockets are rare in userland (ping,
    /// nmap, custom IP-level tools), but their bytes ARE counted by
    /// the cgroup_skb observer (the BPF path is protocol-agnostic —
    /// keyed on cgroup id + socket cookie, no L4 filtering). Before
    /// this variant the per-endpoint attribution was invisible: a
    /// process using a raw socket showed its bytes in the cgroup
    /// total but no detail line in the eagle-eyes tree, because the
    /// /proc walk only matched tcp/udp inodes. The raw table joins
    /// the same fd-walk + SO_COOKIE plumbing the other two tables
    /// already use, so the same per-socket byte maps now attribute
    /// the raw socket's traffic too.
    Raw,
    /// The /proc/net/raw6 spelling of raw — rare squared (a v6
    /// raw socket is a specialist's specialist), but the family
    /// law carves no exceptions: the table name is the tag.
    Raw6,
}

impl Proto {
    /// The row spelling every surface renders — one copy since
    /// night-hunt-40 (the depth focus rows, the basic census
    /// fallback, and the JSON document each carried their own
    /// identical ternary; three future drift points become none).
    /// night-improve-57 added the raw spelling — the same law (one
    /// canonical spelling, one copy) extends to the third variant.
    /// night-improve-62 added the three v6 spellings — and the
    /// chain's third step: the tag surfaces now render through this
    /// one function alone (endpoint_text's three-if chain retired
    /// in the same task — a fourth copy would have been a drift
    /// point born the same day).
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Tcp6 => "tcp6",
            Proto::Udp => "udp",
            Proto::Udp6 => "udp6",
            Proto::Raw => "raw",
            Proto::Raw6 => "raw6",
        }
    }
}

/// One live socket endpoint, as the kernel sees it.
#[derive(Debug, Clone)]
pub struct SocketInfo {
    /// The socket's kernel inode from the /proc/net table row it was
    /// parsed from (night-verdict-closure-T6 (H3)): the stable
    /// kernel-global identity that distinguishes "one socket held by
    /// several fds" (one inode) from "two sockets to the same remote"
    /// (two inodes) — the join key the JSON document's per-endpoint
    /// `socket_inode` field carries so a consumer can dedupe.
    pub inode: u64,
    pub proto: Proto,
    /// Remote endpoint formatted for display ("142.250.191.78:443").
    pub remote: String,
    /// Kernel state name ("ESTABLISHED", "LISTEN", ...).
    pub state: &'static str,
    /// True when the socket had bytes sitting in tx/rx queues at scan
    /// time — the closest /proc gets to "this socket is moving".
    pub queued: bool,
    /// The socket's kernel cookie (NIGHT-boost-26): the join key for
    /// the BPF per-socket byte maps. None when discovery failed
    /// (pidfd_getfd refused, kernel without the syscall, or the
    /// socket table row was matched without an fd-side lookup).
    pub cookie: Option<u64>,
    /// The TCP deep sample (night-netrunner-4, the Netrunner-3
    /// design): the kernel's own RFC 6298 pair and the monotone
    /// retransmit counters, read via one `getsockopt(TCP_INFO)` on
    /// the SAME duplicated fd the cookie read rides — measured live
    /// at ~194 ns, 1.27x the SO_COOKIE read the walk already pays.
    /// None for every non-TCP socket (the failing call is never
    /// made — the walk knows the proto before it samples) and for
    /// every TCP socket whose dup was refused (the walk's own
    /// graceful degradation; absence renders an em dash, never a
    /// fabricated zero).
    pub deep: Option<TcpDeepSample>,
}

/// One TCP socket's kernel-measured deep sample (night-netrunner-4):
/// the exact fields the Netrunner-3 audit's feasibility table cites
/// from v5.15's `include/uapi/linux/tcp.h` — read through the same
/// duplicated fd the cookie read rides, zero new plumbing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpDeepSample {
    /// `tcpi_rtt` — the kernel's own smoothed RTT (SRTT),
    /// microseconds (RFC 6298 smoothing across every segment, not a
    /// noisy per-packet sample).
    pub rtt_us: u32,
    /// `tcpi_rttvar` — the kernel's RTT mean deviation, the RFC 6298
    /// jitter figure in the kernel's own words, microseconds.
    pub rttvar_us: u32,
    /// `tcpi_total_retrans` — lifetime retransmitted-segment count,
    /// monotone: the window figure is the walk-to-walk difference.
    pub total_retrans: u32,
    /// `tcpi_segs_out` — segments sent, the retransmit share's
    /// denominator (the count AND the ratio, so no consumer has to
    /// trust a bare percentage).
    pub segs_out: u32,
}

/// One TCP socket's walk-to-walk deep window (night-netrunner-4):
/// the RTT pair read THIS generation plus the retransmit/segs deltas
/// across the two walks (saturating — the house discipline). A
/// window entry exists only for cookies present in BOTH generations
/// with a sample on each side; a fresh connection contributes
/// NOTHING (no truth about the gap it was born in) — absence is the
/// renderer's em dash, never a fabricated zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpDeepWindow {
    /// This generation's smoothed RTT, microseconds.
    pub rtt_us: u32,
    /// This generation's RTT mean deviation (jitter), microseconds.
    pub rttvar_us: u32,
    /// Retransmitted segments across the window
    /// (`saturating_sub(now, prev)`).
    pub retrans_window: u32,
    /// Segments sent across the window (the same differencing).
    pub segs_out_window: u32,
}
