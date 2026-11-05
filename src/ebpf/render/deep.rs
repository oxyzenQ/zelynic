// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The `--deep` figure family (night-netrunner-4, the netrunner-3
//! design's sections 4.3 and 4.4): the secondary deep line under a
//! ranked row, the focus view's per-endpoint suffixes, and the tag
//! family that renders what the kernel cannot measure — honestly.
//!
//! The datapath stays byte-identical (the design's own contract):
//! every figure here is a kernel-owned counter read the walk already
//! performed (TCP_INFO on the duplicated fd), displayed at the
//! cadence the truth actually has — the walk's 3s TTL. Absence is
//! information: a refused read renders the em dash, an unmeasurable
//! protocol renders its tag (`[encrypted/quic]` for sealed UDP,
//! `[no l4 truth]` for raw), and nothing ever renders a fabricated
//! zero. Two different absences, two different glyphs — the same
//! discipline the empty-board and waiting-for-traffic frames draw.

use crate::ebpf::connections::{ConnectionMap, Proto, SocketInfo};
use crate::ebpf::loader::SocketBytes;

use super::detail::is_displayable;

/// Format a microsecond RTT figure the way an operator reads it:
/// whole milliseconds at or above 1 ms (trimmed of trailing zeros),
/// microseconds below. Pure — the deep lines' one number formatter.
#[must_use]
pub(crate) fn format_rtt_us(us: u32) -> String {
    if us >= 1_000 {
        let ms = us as f64 / 1_000.0;
        if (ms - ms.trunc()).abs() < f64::EPSILON {
            format!("{}ms", ms.trunc() as u64)
        } else {
            format!("{ms:.1}ms")
        }
    } else {
        format!("{us}us")
    }
}

/// The RFC 6298 jitter figure's spelling: `±9ms` rides the rtt
/// figure it qualifies (`19ms ±9ms`), so the pair reads as one
/// measurement, not two.
#[must_use]
pub(crate) fn format_jitter_us(us: u32) -> String {
    format!("±{}", format_rtt_us(us))
}

/// The window's retransmit share (pure): the count AND the ratio —
/// `1/712 segs (0.14%)` — so no consumer has to trust a bare
/// percentage. A zero denominator (a socket that sent nothing this
/// window yet retransmitted — a counter restart edge) renders the
/// count honestly and no ratio (absence where the math has no
/// input, never a fabricated figure).
#[must_use]
pub(crate) fn retrans_share(retrans: u32, segs: u32) -> String {
    if segs == 0 {
        format!("{retrans}/0 segs")
    } else {
        let pct = (f64::from(retrans) / f64::from(segs)) * 100.0;
        format!("{retrans}/{segs} segs ({pct:.2}%)")
    }
}

/// The hungriest displayable endpoint of one cgroup (pure): the
/// walk's socket set ranked by the byte join's total (the focus
/// view's own law, one flat pass over every holder), stable within
/// equals. Byteless endpoints keep the walk's established-first
/// order behind the traffic-carriers — the exact
/// rank_endpoints_by_bytes discipline, widened to the whole row.
fn hungriest_endpoint(conns: &ConnectionMap, cgroup_id: u32) -> Option<&SocketInfo> {
    let detail = conns.get(cgroup_id)?;
    let mut best: Option<(&SocketInfo, u64)> = None;
    for holder in &detail.socket_holders {
        for socket in &holder.sockets {
            if !is_displayable(socket) {
                continue;
            }
            let total = socket
                .cookie
                .and_then(|c| conns.socket_bytes().get(&c))
                .map_or(0, |b: &SocketBytes| b.dl.saturating_add(b.ul));
            if best.is_none_or(|(_, t)| total > t) {
                best = Some((socket, total));
            }
        }
    }
    best.map(|(s, _)| s)
}

/// One ranked row's deep line (night-netrunner-4, the design's
/// section 4.3): the row's hungriest endpoint's deep figures — for
/// TCP the kernel's own `rtt X ±Y · retrans N/M segs (P%)` family
/// with the row's TCP endpoint count; for UDP/raw the protocol tag
/// the kernel cannot argue with. None when the row holds nothing
/// displayable (no deep line — absence, not an empty promise).
#[must_use]
pub(crate) fn row_deep_line(conns: Option<&ConnectionMap>, cgroup_id: u32) -> Option<String> {
    let conns = conns?;
    let socket = hungriest_endpoint(conns, cgroup_id)?;
    Some(match socket.proto {
        Proto::Tcp | Proto::Tcp6 => {
            let tcp_eps = conns.get(cgroup_id).map_or(0, |d| {
                d.socket_holders
                    .iter()
                    .flat_map(|h| h.sockets.iter())
                    .filter(|s| matches!(s.proto, Proto::Tcp | Proto::Tcp6))
                    .count()
            });
            let figures = match socket.cookie.and_then(|c| conns.deep_window().get(&c)) {
                Some(win) => format!(
                    "rtt {} {} · retrans {}",
                    format_rtt_us(win.rtt_us),
                    format_jitter_us(win.rttvar_us),
                    retrans_share(win.retrans_window, win.segs_out_window)
                ),
                // TCP tracked but no readable window (first walk, or
                // the dup was refused): the em dash per figure — the
                // row has TCP, the read did not happen, `0` would be
                // a claim nobody made.
                None => "rtt — · retrans —".to_string(),
            };
            format!("{figures} · {tcp_eps} tcp eps")
        }
        Proto::Udp | Proto::Udp6 => "[encrypted/quic]".to_string(),
        Proto::Raw | Proto::Raw6 => "[no l4 truth]".to_string(),
    })
}

/// The focus view's per-endpoint deep suffix (the design's section
/// 4.3, the inline suffix family the `[dl | ul]` figures ride):
/// TCP gains ` [rtt Xms ±Yms | retrans N/M (Z%)]` (or the em-dash
/// figures when the window was not readable), UDP gains
/// ` [encrypted/quic]`, raw gains ` [no l4 truth]`. Empty string
/// for a socket with no cookie and no tag (the pre-netrunner-4
/// lean row) — callers append whatever this returns.
#[must_use]
pub(crate) fn endpoint_deep_suffix(socket: &SocketInfo, conns: Option<&ConnectionMap>) -> String {
    match socket.proto {
        Proto::Tcp | Proto::Tcp6 => {
            let figures = socket
                .cookie
                .and_then(|c| conns?.deep_window().get(&c))
                .map_or_else(
                    || "rtt — · retrans —".to_string(),
                    |win| {
                        format!(
                            "rtt {} {} · retrans {}",
                            format_rtt_us(win.rtt_us),
                            format_jitter_us(win.rttvar_us),
                            retrans_share(win.retrans_window, win.segs_out_window)
                        )
                    },
                );
            format!(" [{figures}]")
        }
        Proto::Udp | Proto::Udp6 => " [encrypted/quic]".to_string(),
        Proto::Raw | Proto::Raw6 => " [no l4 truth]".to_string(),
    }
}

/// The footer legend's one line (the design's section 4.3, Full
/// tier only): the three laws the deep figures ride, spelled once —
/// the figures on screen never outrun the space to explain them.
#[must_use]
pub(crate) fn footer_legend_line() -> String {
    "deep: rtt ± is RFC 6298 rttvar · retrans counted per 3s walk · quic = [encrypted/quic]"
        .to_string()
}

#[cfg(test)]
#[path = "../../../test/ebpf/render/deep_tests.rs"]
mod deep_tests;
