// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The detail tree's pooled-row composers (night-frontier-Z11) —
//! split from detail.rs by the NIGHT-improve-44 LOC law (a pure
//! move, gates green in between): the into-twins the ranked frame's
//! detail block pushes with, one pooled row per line, the holders'
//! walk scratch the block's named residual.

use super::Duration;
use super::detail::{
    DETAIL_LINE_CAP, ENDPOINT_SHOWN, is_displayable, rank_endpoints_by_bytes, socket_bytes_of,
};
use crate::ebpf::connections::{ConnectionMap, ProcessDetail, SocketInfo};

/// The into-twin of [`steady_rate_field`] (night-frontier-Z11):
/// the same bytes into a caller-owned buffer — the "0 B/s" literal
/// or the SI ladder's bytes via `format_bytes_into` — no owned
/// String per endpoint figure.
fn push_steady_rate_field(out: &mut String, rate: u64) {
    if rate == 0 {
        out.push_str("0 B/s");
    } else {
        crate::ebpf::limiter::format_bytes_into(rate, out);
        out.push_str("/s");
    }
}

/// The into-twin of [`endpoint_text`] (night-frontier-Z11): the
/// same bytes into a caller-owned buffer — the proto tag, the
/// remote, the busy tag, the joined figures (via the steady-rate
/// twin), and the deep suffix all append without an owned String
/// per endpoint. The deep suffix stays owned (the focus view's
/// deep mode; the ranked frame runs deep=false and pays nothing).
fn push_endpoint_text(
    out: &mut String,
    socket: &SocketInfo,
    conns: Option<&ConnectionMap>,
    window: Duration,
    deep: bool,
) {
    use std::fmt::Write as _;
    out.push_str(socket.proto.as_str());
    out.push(' ');
    out.push_str(&socket.remote);
    if socket.queued {
        out.push_str(" [busy]");
    }
    if let Some(b) = socket_bytes_of(socket, conns)
        && (b.dl > 0 || b.ul > 0)
    {
        let _ = write!(out, " [dl ");
        push_steady_rate_field(out, super::rate_bps(b.dl, window));
        let _ = write!(out, " | ul ");
        push_steady_rate_field(out, super::rate_bps(b.ul, window));
        let _ = write!(out, "]");
    }
    // The deep suffix (night-netrunner-4, --deep): the figure family
    // or the protocol tag rides the SAME line — inline suffixes,
    // natural width, the steady_rate_field precedent. The ranked
    // view passes deep=false (the default table's contract: bytes
    // and rates only); the focus view passes the flag through.
    if deep {
        out.push_str(&super::deep::endpoint_deep_suffix(socket, conns));
    }
}

/// The into-twin of [`eagle_holder_lines`] (night-frontier-Z11):
/// the same bytes pushed as pooled rows — one `pooled_line` pop per
/// line, the composition via `write!` and the endpoint twin, the
/// walk's ranking scratch (the ranked slice) the only owned Vec
/// left in the block. The owned [`eagle_holder_lines`] stays for
/// [`full_detail_lines`] (the focus view's tree).
fn push_eagle_holder_lines(
    lines: &mut Vec<String>,
    proc: &ProcessDetail,
    endpoints: &[&SocketInfo],
    conns: Option<&ConnectionMap>,
    window: Duration,
    deep: bool,
) {
    if endpoints.len() == 1 {
        let mut line = super::pool::pooled_line();
        {
            use std::fmt::Write as _;
            let _ = write!(line, "    \u{2514} {} ({}) \u{2192} ", proc.comm, proc.pid);
        }
        push_endpoint_text(&mut line, endpoints[0], conns, window, deep);
        lines.push(line);
        return;
    }
    let mut ranked = endpoints.to_vec();
    rank_endpoints_by_bytes(&mut ranked, conns);
    let shown = ranked.len().min(ENDPOINT_SHOWN);
    {
        let mut line = super::pool::pooled_line();
        {
            use std::fmt::Write as _;
            let _ = write!(line, "    \u{2514} {} ({}) ", proc.comm, proc.pid);
        }
        crate::ebpf::limiter::format_count_into(endpoints.len() as u64, &mut line);
        line.push_str(" sockets:");
        lines.push(line);
    }
    for (i, socket) in ranked.iter().take(shown).enumerate() {
        let branch = if i + 1 == shown {
            "\u{2514}"
        } else {
            "\u{251c}"
        };
        let mut line = super::pool::pooled_line();
        {
            use std::fmt::Write as _;
            let _ = write!(line, "        {branch} ");
        }
        push_endpoint_text(&mut line, socket, conns, window, deep);
        lines.push(line);
    }
}

/// Detail lines for one cgroup row (NIGHT-hunt-8, tree shape since
/// NIGHT-boost-21): the processes holding network sockets inside the
/// cgroup, multi-socket holders expanded into endpoint children,
/// capped at [`DETAIL_LINE_CAP`] lines including the summary.
/// NIGHT-boost-26: the endpoint figures ride the ConnectionMap's
/// per-frame byte join (see [`ConnectionMap::socket_bytes`]).
/// The into-twin of [`detail_lines`] (night-frontier-Z11): the same
/// bytes pushed as pooled rows into the caller's working vector —
/// the ranked view's per-cgroup detail block stops owning a fresh
/// `Vec<String>` of fresh Strings per cgroup per frame. The
/// holders' walk scratch (the outer Vec plus one Vec per holder)
/// stays the block's named residual. The owned [`detail_lines`]
/// stays for the pins.
pub(crate) fn push_detail_lines(
    lines: &mut Vec<String>,
    conns: Option<&ConnectionMap>,
    cgroup_id: u32,
    window: Duration,
) {
    let Some(conns) = conns else {
        return;
    };
    let Some(detail) = conns.get(cgroup_id) else {
        return;
    };

    // Holders with at least one traffic-bearing socket, in the
    // refresh sort order (most sockets, any-queued, pid).
    let holders: Vec<(&ProcessDetail, Vec<&SocketInfo>)> = detail
        .socket_holders
        .iter()
        .map(|p| {
            let eps: Vec<&SocketInfo> = p.sockets.iter().filter(|s| is_displayable(s)).collect();
            (p, eps)
        })
        .filter(|(_, eps)| !eps.is_empty())
        .collect();

    // Compose within DETAIL_LINE_CAP lines, summary included: the
    // summary slot is reserved while unshown holders remain, so the
    // overflow note can never push the block past the budget the
    // flat list kept (three holders plus one summary line). The
    // ranked view never carries the deep suffixes — the default
    // table's deep family rides the row's own deep line instead
    // (the audit's secondary-line design, no doubling).
    let block_start = lines.len();
    let mut shown = 0usize;
    for (proc, endpoints) in &holders {
        let cost = if endpoints.len() > 1 {
            1 + endpoints.len().min(ENDPOINT_SHOWN)
        } else {
            1
        };
        let summary_slot = usize::from(shown + 1 < holders.len());
        if lines.len() - block_start + cost + summary_slot > DETAIL_LINE_CAP {
            break;
        }
        push_eagle_holder_lines(lines, proc, endpoints, Some(conns), window, false);
        shown += 1;
    }
    let remaining = holders.len().saturating_sub(shown);
    if remaining > 0 {
        let mut line = super::pool::pooled_line();
        {
            use std::fmt::Write as _;
            let _ = write!(line, "    \u{2500} +");
        }
        crate::ebpf::limiter::format_count_into(remaining as u64, &mut line);
        line.push_str(" more socket-holding processes");
        lines.push(line);
    }
}
