// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The detail tree's pooled-row composers (night-frontier-Z11) —
//! split from detail.rs by the NIGHT-improve-44 LOC law (a pure
//! move, gates green in between): the into-twins the ranked frame's
//! detail block pushes with, one pooled row per line. The holders'
//! walk scratch — the block's named residual since the ladder — is
//! closed by night-frontier-Z13 stage 4a: the walk reads indices
//! from a capacity-warm thread-local buffer (references cannot ride
//! a thread-local cell, indices can), re-iterating the holders in
//! their refresh order, so the block composes with zero heap events
//! in steady state. The focus view's tree rides the same machinery
//! (night-frontier-Z13 stage 5a): the uncapped full-detail block
//! composes into its own retained scratch with pooled rows, the
//! fresh Vec per frame gone.

use std::cell::RefCell;

use super::Duration;
use super::detail::{DETAIL_LINE_CAP, ENDPOINT_SHOWN, is_displayable, socket_bytes_of};
use crate::ebpf::connections::{ConnectionMap, ProcessDetail, SocketInfo};

thread_local! {
    /// The holders' walk scratch (night-frontier-Z13 stage 4a): the
    /// displayable-endpoint index buffer the walk sorts per holder.
    /// Capacity-warm across holders and frames — a buffer that never
    /// leaves the cell never hands its allocation to the allocator.
    /// Indices (u32), not references: a thread-local cell cannot
    /// carry borrows of the caller's map, but it can carry numbers.
    static HOLDER_WALK: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };

    /// The focus tree's retained scratch (night-frontier-Z13 stage
    /// 5a): the uncapped full-detail block composes here per frame
    /// and its pooled rows MOVE into the frame — the scratch keeps
    /// its capacity, the per-frame fresh Vec is gone.
    static FOCUS_TREE: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// The index twin of [`rank_endpoints_by_bytes`] (night-frontier-Z13
/// stage 4a): the same bytes-desc law — Reverse(dl+ul) saturating,
/// the stable sort keeping the census row order behind the
/// traffic-carriers — applied to the holder's socket slice through
/// the walk scratch's displayable indices. The key reads the same
/// `socket_bytes_of` figures the reference twin reads, so the two
/// ranks agree line for line (the detail pins hold the bytes).
fn rank_endpoint_indices(
    sockets: &[SocketInfo],
    indices: &mut [u32],
    conns: Option<&ConnectionMap>,
) {
    indices.sort_by_key(|&i| {
        let total =
            socket_bytes_of(&sockets[i as usize], conns).map_or(0, |b| b.dl.saturating_add(b.ul));
        std::cmp::Reverse(total)
    });
}

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
/// line, the composition via `write!` and the endpoint twin. The
/// ranked slice rides the walk scratch's indices (night-frontier-Z13
/// stage 4a: no per-holder Vec) — the single-endpoint case takes the
/// scratch's first (and only) displayable index, the multi case the
/// bytes-ranked ones, the same bytes the owned twin formats.
/// The owned [`eagle_holder_lines`] stays for the pins.
fn push_eagle_holder_lines(
    lines: &mut Vec<String>,
    proc: &ProcessDetail,
    ranked: &[u32],
    conns: Option<&ConnectionMap>,
    window: Duration,
    deep: bool,
) {
    let sockets = &proc.sockets;
    if ranked.len() == 1 {
        let mut line = super::pool::pooled_line();
        {
            use std::fmt::Write as _;
            let _ = write!(line, "    \u{2514} {} ({}) \u{2192} ", proc.comm, proc.pid);
        }
        push_endpoint_text(&mut line, &sockets[ranked[0] as usize], conns, window, deep);
        lines.push(line);
        return;
    }
    let shown = ranked.len().min(ENDPOINT_SHOWN);
    {
        let mut line = super::pool::pooled_line();
        {
            use std::fmt::Write as _;
            let _ = write!(line, "    \u{2514} {} ({}) ", proc.comm, proc.pid);
        }
        crate::ebpf::limiter::format_count_into(ranked.len() as u64, &mut line);
        line.push_str(" sockets:");
        lines.push(line);
    }
    for (i, socket_idx) in ranked.iter().take(shown).enumerate() {
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
        push_endpoint_text(
            &mut line,
            &sockets[*socket_idx as usize],
            conns,
            window,
            deep,
        );
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
/// bytes pushed as pooled rows into the caller's working vector.
/// The holders' walk scratch is CLOSED (night-frontier-Z13 stage
/// 4a): the walk re-iterates the holders in their refresh order and
/// reads each holder's displayable endpoints as indices from the
/// capacity-warm [`HOLDER_WALK`] buffer — the outer Vec and the per
/// holder endpoint Vecs of the Z11 era are gone, and the block
/// composes with zero heap events in steady state. The owned
/// [`detail_lines`] stays for the pins.
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
    // refresh sort order (most sockets, any-queued, pid): the
    // filtered count the summary slot and the overflow note need.
    // Re-iterated below — no outer Vec holds the walk anymore.
    let holders_total = detail
        .socket_holders
        .iter()
        .filter(|p| p.sockets.iter().any(is_displayable))
        .count();

    // Compose within DETAIL_LINE_CAP lines, summary included: the
    // summary slot is reserved while unshown holders remain, so the
    // overflow note can never push the block past the budget the
    // flat list kept (three holders plus one summary line). The
    // ranked view never carries the deep suffixes — the default
    // table's deep family rides the row's own deep line instead
    // (the audit's secondary-line design, no doubling).
    //
    // The walk itself runs INSIDE the scratch borrow: moving the
    // buffer out would hand the walk's warm capacity back to the
    // allocator on every holder — the exact event the stage closes.
    // The closure's verdict names the old loop's three branches
    // (empty holders skip as the filter did, the budget failure
    // breaks as the walk did, a pushed holder returns Pushed).
    let block_start = lines.len();
    let mut shown = 0usize;
    for proc in &detail.socket_holders {
        enum Verdict {
            Skip,
            Break,
            Pushed,
        }
        let verdict = HOLDER_WALK.with(|cell| {
            let mut indices = cell.borrow_mut();
            indices.clear();
            indices.extend(
                proc.sockets
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| is_displayable(s))
                    .map(|(i, _)| i as u32),
            );
            if indices.is_empty() {
                return Verdict::Skip;
            }
            rank_endpoint_indices(&proc.sockets, &mut indices, Some(conns));
            let cost = if indices.len() > 1 {
                1 + indices.len().min(ENDPOINT_SHOWN)
            } else {
                1
            };
            let summary_slot = usize::from(shown + 1 < holders_total);
            if lines.len() - block_start + cost + summary_slot > DETAIL_LINE_CAP {
                return Verdict::Break;
            }
            push_eagle_holder_lines(lines, proc, &indices, Some(conns), window, false);
            shown += 1;
            Verdict::Pushed
        });
        if matches!(verdict, Verdict::Break) {
            break;
        }
    }
    let remaining = holders_total.saturating_sub(shown);
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

/// The into-twin of [`full_detail_lines`] (night-frontier-Z13 stage
/// 5a): the focus view's UNCAPPED tree — every socket-holding
/// process, each of its displayable endpoints an indented child
/// line, the endpoints ranked bytes-desc (`rank_endpoint_indices`,
/// the same law the owned twin reads) — pushed as pooled rows into
/// the caller's scratch. The same walk scratch ([`HOLDER_WALK`])
/// serves the indices, so the per-holder endpoint Vec the owned
/// twin still builds for the pins costs the frame nothing. The deep
/// suffix rides the endpoint twin (owned String, deep=true focus
/// episodes only; the steady default pays nothing).
pub(crate) fn push_full_detail_lines(
    lines: &mut Vec<String>,
    conns: Option<&ConnectionMap>,
    cgroup_id: u32,
    window: Duration,
    deep: bool,
) {
    let Some(conns) = conns else {
        return;
    };
    let Some(detail) = conns.get(cgroup_id) else {
        return;
    };
    if detail.socket_holders.is_empty() {
        return;
    }
    // The header (the owned twin's bytes: the SI-laddered process
    // count inside the parenthetical).
    let mut line = super::pool::pooled_line();
    line.push_str("  processes with sockets (");
    crate::ebpf::limiter::format_count_into(detail.total_procs as u64, &mut line);
    line.push_str(" total processes):");
    lines.push(line);
    for proc in &detail.socket_holders {
        // The walk runs INSIDE the scratch borrow (push_detail_lines'
        // own law): moving the buffer out would hand the walk's warm
        // capacity back to the allocator on every holder.
        HOLDER_WALK.with(|cell| {
            let mut indices = cell.borrow_mut();
            indices.clear();
            indices.extend(
                proc.sockets
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| is_displayable(s))
                    .map(|(i, _)| i as u32),
            );
            if indices.is_empty() {
                return;
            }
            rank_endpoint_indices(&proc.sockets, &mut indices, Some(conns));
            if indices.len() == 1 {
                // The inline shape: one endpoint, no header row.
                let mut line = super::pool::pooled_line();
                {
                    use std::fmt::Write as _;
                    let _ = write!(line, "  \u{2514} {} ({}) \u{2192} ", proc.comm, proc.pid);
                }
                push_endpoint_text(
                    &mut line,
                    &proc.sockets[indices[0] as usize],
                    Some(conns),
                    window,
                    deep,
                );
                lines.push(line);
                return;
            }
            // The header-plus-children shape: the socket count rides
            // the header (a truncated expansion still says its scale).
            let mut line = super::pool::pooled_line();
            {
                use std::fmt::Write as _;
                let _ = write!(line, "  \u{2514} {} ({}) ", proc.comm, proc.pid);
            }
            crate::ebpf::limiter::format_count_into(indices.len() as u64, &mut line);
            line.push_str(" sockets:");
            lines.push(line);
            let last = indices.len() - 1;
            for (i, socket_idx) in indices.iter().enumerate() {
                let branch = if i == last { "\u{2514}" } else { "\u{251c}" };
                let mut line = super::pool::pooled_line();
                {
                    use std::fmt::Write as _;
                    let _ = write!(line, "      {branch} ");
                }
                push_endpoint_text(
                    &mut line,
                    &proc.sockets[*socket_idx as usize],
                    Some(conns),
                    window,
                    deep,
                );
                lines.push(line);
            }
        });
    }
}

/// The focus view's per-frame tree composition (night-frontier-Z13
/// stage 5a): the uncapped block composes into the retained
/// [`FOCUS_TREE`] scratch and its pooled rows MOVE into the frame —
/// the caller's vector gains the block, the scratch keeps its
/// capacity. The room law is the focus renderer's own (the adaptive
/// compact: an honest "+N more hidden" note, degenerate heights drop
/// the block) and it runs INSIDE the scratch borrow — every dropped
/// row hands its buffer BACK to the pool (dropping a pooled row
/// starved the warm capacity and made the next frame pay a fresh
/// allocation, the stage-4c starvation lesson).
pub(crate) fn push_focus_tree(
    lines: &mut Vec<String>,
    conns: Option<&ConnectionMap>,
    cgroup_id: u32,
    window: Duration,
    deep: bool,
    room: usize,
) {
    FOCUS_TREE.with(|cell| {
        let mut details = cell.borrow_mut();
        details.clear();
        push_full_detail_lines(&mut details, conns, cgroup_id, window, deep);
        if details.len() > room {
            if room == 0 {
                for line in details.drain(..) {
                    super::pool::recycle_line(line);
                }
            } else {
                let hidden = details.len() - (room - 1);
                for line in details.drain(room - 1..) {
                    super::pool::recycle_line(line);
                }
                let mut note = super::pool::pooled_line();
                note.push_str("  \u{2514} +");
                crate::ebpf::limiter::format_count_into(hidden as u64, &mut note);
                note.push_str(" more hidden \u{2014} raise the window");
                details.push(note);
            }
        }
        for line in details.drain(..) {
            lines.push(line);
        }
    });
}
