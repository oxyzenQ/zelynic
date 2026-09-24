// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Connection detail lines (NIGHT-hunt-8 eagle eyes): the per-cgroup
//! process-count label suffix and the indented socket-endpoint lines
//! rendered under monitor rows. Shared by the eagle-eyes renderers
//! (ranked table + focus view); the single-cgroup focus view uses
//! the uncapped variant.
//!
//! NIGHT-boost-21 (the tree subprocess pass): the detail lines grew
//! into a two-level TREE — process headers with their remote
//! endpoints as indented children (`├` mid-list, `└` last), sharp
//! and simple. One-socket processes stay inline (a child line that
//! only restates its parent is waste); multi-socket processes
//! expand. The eagle view caps each expansion at two children — the
//! socket table sorts established-first, queued-first, so the two
//! shown are the live ones and the header's socket count carries
//! the scale — while the focus view expands every endpoint (the
//! "who exactly" view). The eagle budget is unchanged: at most
//! [`DETAIL_LINE_CAP`] lines per row, the same four the flat list
//! spent (three process lines plus one summary).

use crate::ebpf::connections::{ConnectionMap, ProcessDetail, Proto, SocketInfo};
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::{format_bytes, format_count};
use crate::ebpf::loader::SocketBytes;

/// Total detail lines one eagle-eyes row may grow (NIGHT-boost-21):
/// the flat contract spent three process lines plus one summary; the
/// tree spends the same four — a multi-socket process expanded
/// (header + two endpoint children) plus an inline neighbor, or any
/// mix that fits, overflow folded into the summary line.
const DETAIL_LINE_CAP: usize = 4;

/// Endpoint children one expanded process shows under its header in
/// the eagle view (NIGHT-boost-21): two — the socket table sorts
/// established first, queued first, so the two shown are the live
/// ones; the header's socket count carries the rest, and the focus
/// view names every endpoint when the detail matters.
const ENDPOINT_SHOWN: usize = 2;

/// Identity label enriched with the cgroup's process count:
/// `cg:73386 (alacritty +3)` when more than one process lives there.
///
/// This is the direct fix for the owner's "alacritty1,2,3,4,5"
/// complaint — a session cgroup whose row name is the first PID the
/// identity walk saw now says out loud that it is multi-tenant, and
/// the detail lines name the actual inhabitants. The count rides
/// the SI compact ladder (NIGHT-engrave-7): a long-lived cgroup
/// hosting thousands of PIDs reads `+2.4K`, never a raw explosion.
#[must_use]
pub(crate) fn label_with_count(
    identity: &IdentityMap,
    conns: Option<&ConnectionMap>,
    cgroup_id: u32,
) -> String {
    let base = identity.label(cgroup_id);
    let Some(conns) = conns else {
        return base;
    };
    let procs = conns.proc_count(cgroup_id);
    if procs > 1 {
        // Splice before the closing paren: "(alacritty)" -> "(alacritty +3)".
        if let Some(stripped) = base.strip_suffix(')') {
            return format!("{stripped} +{})", format_count((procs - 1) as u64));
        }
    }
    base
}

/// Extract the primary comm from a label, tolerating the "+N" suffix
/// (used by the top-consumer autodetect, NIGHT-hunt-8 lineage,
/// restored by NIGHT-engrave-4): `cg:73386 (alacritty +3)` yields
/// `alacritty`. Labels without a parenthesized comm (the raw
/// `cg:73386` of an unresolved identity) yield None — the caller
/// falls back to the whole label, the identity-honest name.
#[must_use]
pub(crate) fn comm_from_label(label: &str) -> Option<String> {
    let inner = label.split('(').nth(1)?.strip_suffix(')')?;
    let comm = inner.split(" +").next().unwrap_or(inner);
    if comm.is_empty() || comm == "unknown" {
        return None;
    }
    Some(comm.to_string())
}

/// One detail line's endpoint text: UDP is tagged (QUIC-era traffic
/// lives there), busy sockets are flagged. NIGHT-boost-26: when the
/// join resolved this socket's bytes, the endpoint carries its own
/// byte figures — `[dl X | ul Y]`, the footer speed pair's dl/ul
/// vocabulary — so a five-connection process finally answers WHICH
/// endpoint is eating (the 2.4 frontier: "the socket that MAKAN, not
/// just the ones that exist"). The suffix appears only when there
/// ARE bytes: a displayable-but-silent socket keeps its lean row,
/// and a cookie-less socket (pidfd_getfd refused) renders exactly as
/// before — absence is the honest no-figures signal.
fn endpoint_text(socket: &SocketInfo, conns: Option<&ConnectionMap>) -> String {
    let mut out = String::new();
    if socket.proto == Proto::Udp {
        out.push_str("udp ");
    }
    out.push_str(&socket.remote);
    if socket.queued {
        out.push_str(" [busy]");
    }
    if let Some(b) = socket_bytes_of(socket, conns) {
        out.push_str(&format!(
            " [dl {} | ul {}]",
            format_bytes(b.dl),
            format_bytes(b.ul)
        ));
    }
    out
}

/// The joined bytes for one socket, if any (NIGHT-boost-26): the
/// cookie's entry in the ConnectionMap's per-frame join result — a
/// socket without a cookie or without bytes renders no figures.
fn socket_bytes_of<'a>(
    socket: &SocketInfo,
    conns: Option<&'a ConnectionMap>,
) -> Option<&'a SocketBytes> {
    socket
        .cookie
        .and_then(|cookie| conns?.socket_bytes().get(&cookie))
}

/// Is this socket worth a detail line? Established TCP and connected
/// UDP carry traffic; LISTEN/TIME_WAIT rows are noise.
///
/// The UDP branch needs the remote guard (NIGHT-hunt-15):
/// /proc/net/udp reports state 07 (CLOSE) for connected AND
/// unconnected sockets alike, so a bound-only listener (chronyd,
/// systemd-resolved, mDNS) would otherwise render as `udp 0.0.0.0:0`
/// noise under its cgroup row. A real remote endpoint never carries
/// port 0, and both `0.0.0.0:0` and `[::]:0` end in `:0`.
fn is_displayable(socket: &SocketInfo) -> bool {
    match socket.proto {
        Proto::Tcp => socket.state == "ESTABLISHED",
        // /proc/net/udp uses state 07 for a connected UDP socket.
        Proto::Udp => socket.state == "CLOSE" && !socket.remote.ends_with(":0"),
    }
}

/// One process's eagle-eyes tree lines (NIGHT-boost-21): inline when
/// it holds a single displayable endpoint, header plus capped
/// children when more. The header carries the socket count, so a
/// truncated expansion still says its scale. NIGHT-boost-26: each
/// endpoint line carries its joined byte figures when the per-socket
/// maps know them.
fn eagle_holder_lines(
    proc: &ProcessDetail,
    endpoints: &[&SocketInfo],
    conns: Option<&ConnectionMap>,
) -> Vec<String> {
    if endpoints.len() == 1 {
        return vec![format!(
            "    └ {} ({}) → {}",
            proc.comm,
            proc.pid,
            endpoint_text(endpoints[0], conns)
        )];
    }
    let mut out = Vec::with_capacity(1 + ENDPOINT_SHOWN);
    out.push(format!(
        "    └ {} ({}) {} sockets:",
        proc.comm,
        proc.pid,
        format_count(endpoints.len() as u64)
    ));
    let shown = endpoints.len().min(ENDPOINT_SHOWN);
    for (i, socket) in endpoints.iter().take(shown).enumerate() {
        let branch = if i + 1 == shown { "└" } else { "├" };
        out.push(format!("        {branch} {}", endpoint_text(socket, conns)));
    }
    out
}

/// Detail lines for one cgroup row (NIGHT-hunt-8, tree shape since
/// NIGHT-boost-21): the processes holding network sockets inside the
/// cgroup, multi-socket holders expanded into endpoint children,
/// capped at [`DETAIL_LINE_CAP`] lines including the summary.
/// NIGHT-boost-26: the endpoint figures ride the ConnectionMap's
/// per-frame byte join (see [`ConnectionMap::socket_bytes`]).
#[must_use]
pub(crate) fn detail_lines(conns: Option<&ConnectionMap>, cgroup_id: u32) -> Vec<String> {
    let mut lines = Vec::new();
    let Some(conns) = conns else {
        return lines;
    };
    let Some(detail) = conns.get(cgroup_id) else {
        return lines;
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
    // flat list kept (three holders plus one summary line).
    let mut shown = 0usize;
    for (proc, endpoints) in &holders {
        let cost = if endpoints.len() > 1 {
            1 + endpoints.len().min(ENDPOINT_SHOWN)
        } else {
            1
        };
        let summary_slot = usize::from(shown + 1 < holders.len());
        if lines.len() + cost + summary_slot > DETAIL_LINE_CAP {
            break;
        }
        lines.extend(eagle_holder_lines(proc, endpoints, Some(conns)));
        shown += 1;
    }
    let remaining = holders.len().saturating_sub(shown);
    if remaining > 0 {
        lines.push(format!(
            "    └ +{} more socket-holding processes",
            format_count(remaining as u64)
        ));
    }

    lines
}

/// Uncapped detail view for the single-cgroup monitor (NIGHT-hunt-8,
/// full tree since NIGHT-boost-21): every socket-holding process,
/// each of its displayable endpoints an indented child line — the
/// deep answer to "who exactly is talking inside this cgroup".
/// NIGHT-boost-26: the join's byte figures ride every endpoint line,
/// and each process's endpoints RANK by their bytes — the hungriest
/// endpoint first (the 2.4 promise: "the focus view could rank
/// endpoints within a cgroup"); byteless endpoints keep the walk's
/// established-first order behind them.
#[must_use]
pub(crate) fn full_detail_lines(conns: Option<&ConnectionMap>, cgroup_id: u32) -> Vec<String> {
    let mut lines = Vec::new();
    let Some(conns) = conns else {
        return lines;
    };
    let Some(detail) = conns.get(cgroup_id) else {
        return lines;
    };
    if detail.socket_holders.is_empty() {
        return lines;
    }

    lines.push(format!(
        "  processes with sockets ({} total processes):",
        format_count(detail.total_procs as u64)
    ));
    for proc in &detail.socket_holders {
        let mut endpoints: Vec<&SocketInfo> =
            proc.sockets.iter().filter(|s| is_displayable(s)).collect();
        if endpoints.is_empty() {
            continue;
        }
        // Bytes-desc, stable within equals (Rust's sort_by is stable,
        // so byteless endpoints keep the established-first walk order
        // behind the traffic-carriers).
        endpoints.sort_by_key(|s| {
            let total = socket_bytes_of(s, Some(conns)).map_or(0, |b| b.dl.saturating_add(b.ul));
            std::cmp::Reverse(total)
        });
        if endpoints.len() == 1 {
            lines.push(format!(
                "  └ {} ({}) → {}",
                proc.comm,
                proc.pid,
                endpoint_text(endpoints[0], Some(conns))
            ));
        } else {
            lines.push(format!(
                "  └ {} ({}) {} sockets:",
                proc.comm,
                proc.pid,
                format_count(endpoints.len() as u64)
            ));
            let last = endpoints.len() - 1;
            for (i, socket) in endpoints.iter().enumerate() {
                let branch = if i == last { "└" } else { "├" };
                lines.push(format!(
                    "      {branch} {}",
                    endpoint_text(socket, Some(conns))
                ));
            }
        }
    }
    lines
}

// NIGHT-boost-21: the detail pins live under the single test/ tree
// (cosmostrix Pattern C), #[path]-wired across trees exactly like the
// eagle, footer, and border pins — the tree pass pushed this file
// past the LOC cap the same way boost-15 pushed format.rs.
#[cfg(test)]
#[path = "../../../test/ebpf/render/detail_tests.rs"]
mod detail_tests;

// NIGHT-boost-26: the byte-attribution pins took their own file when
// they pushed detail_tests.rs past the owner's LOC cap — one file
// per contract, the footer tree's own split discipline.
#[cfg(test)]
#[path = "../../../test/ebpf/render/detail_bytes_tests.rs"]
mod detail_bytes_tests;
