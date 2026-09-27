// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The footer's top-consumer ranking (NIGHT-dinner-6): the champion
//! cgroup's hungriest process, picked by the per-socket byte join
//! (NIGHT-boost-26) instead of the socket-count walk order.
//!
//! The footer's contract says "busiest process" — and a process is
//! busy when it MOVES BYTES, not when it holds sockets. The
//! pre-dinner-6 pick took `socket_holders.first()`, whose order the
//! /proc walk sorts by SOCKET COUNT (connections.rs): a three-socket
//! idle daemon out-ranked a one-socket download, and the headline
//! named the wrong process exactly when it mattered most — the
//! champion cgroup under a limit. This module re-ranks by the joined
//! lifetime bytes the cookie maps carry, the same figures the
//! endpoint rows already render.
//!
//! Honesty contract (the fallback): when the join carries no figures
//! for any holder — a cookie-less host, a pre-first-join frame, an
//! all-zero fixture — the walk order STANDS. The ranking degrades to
//! the pre-dinner-6 behavior rather than going dark, the exact shape
//! the footer's curl pin carries.

use std::collections::HashMap;

use crate::ebpf::connections::{ConnectionMap, ProcessDetail};
use crate::ebpf::loader::SocketBytes;

/// One process's joined lifetime bytes: `dl + ul` summed over every
/// socket whose cookie the walk resolved AND the join carries a
/// figure for. Saturating u128 — each leg is a u64 counter and the
/// wide integer's job is the SUM's exactness (the footer ladder's
/// own lts-5 discipline).
fn process_bytes(p: &ProcessDetail, join: &HashMap<u64, SocketBytes>) -> u128 {
    p.sockets
        .iter()
        .filter_map(|s| s.cookie)
        .filter_map(|cookie| join.get(&cookie))
        .map(|sb| u128::from(sb.dl.saturating_add(sb.ul)))
        .fold(0, u128::saturating_add)
}

/// The champion cgroup's hungriest process for the footer's
/// "top consumer" line (NIGHT-dinner-6).
///
/// Delegate: looks the cgroup's connection detail up and hands the
/// pure byte ranking the join the monitor loop parked. Max by joined
/// bytes, FIRST in walk order on ties — strictly greater only, so an
/// all-zero join leaves the walk order untouched (the pre-dinner-6
/// shape the curl pin pins) and a tie never depends on iteration or
/// hash order. `None` when the cgroup has no socket holders at all —
/// the footer's comm-from-label fallback owns that case, unchanged.
pub(super) fn top_consumer(conns: &ConnectionMap, cgroup_id: u32) -> Option<&ProcessDetail> {
    let detail = conns.get(cgroup_id)?;
    let holders = &detail.socket_holders;
    let join = conns.socket_bytes();
    let mut best = holders.first()?;
    let mut best_bytes = process_bytes(best, join);
    for holder in holders.iter().skip(1) {
        let bytes = process_bytes(holder, join);
        if bytes > best_bytes {
            best = holder;
            best_bytes = bytes;
        }
    }
    Some(best)
}

// NIGHT-dinner-6: the ranking pins live under the single test/ tree
// (cosmostrix Pattern C), #[path]-wired exactly like the footer's.
#[cfg(test)]
#[path = "../../../test/ebpf/render/rank_tests.rs"]
mod rank_tests;
