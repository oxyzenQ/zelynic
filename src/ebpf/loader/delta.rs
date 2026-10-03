// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The observer's counter-delta family (split from loader.rs when
//! the NIGHT-total-lts-5 discriminator pushed that file past the
//! owner's 500-LOC cap — the connections/parse.rs precedent, one
//! theme one module): the wrap-coherent delta and its
//! eviction-restart discriminator, the ONE boundary every
//! poll_and_summarize delta flows through.

/// The server long-endurance coherence fix (NIGHT-lts-5):
/// modulo-2^64 subtraction, the exact inverse of the kernel side's
/// `fetch_add` booking (ebpf/src/stats.rs — BPF atomics WRAP at
/// u64::MAX, 18.4 EB, and a 1-Tbps-backed cgroup reaches the wrap in
/// ~4.7 years of monitor uptime). The old `saturating_sub` clamped
/// every post-wrap poll to a ZERO delta — the moment a kernel
/// counter wrapped, its cgroup went SILENT on the board (rates zero,
/// totals frozen) for another full 18.4 EB. Modulo subtraction stays
/// exact across a wrap whenever the true per-interval delta stays
/// under 2^63 bytes — ~9.2 EB per POLL interval, which a 1-Tbps link
/// needs 2.3 YEARS to produce: every real interval is nine orders of
/// magnitude inside the bound.
///
/// But `prev > cur` is NOT always a wrap, and the NIGHT-lts-5 note
/// that claimed "a backwards step is a wrap, full stop" went stale
/// the day the dinner-6 E1 rider moved these maps to the LRU lane:
/// past 4096 distinct live cgroups in one session the kernel evicts
/// an idle entry, and an evicted-then-returning cgroup RESTARTS its
/// accumulator from zero — a backwards step that is a restart, not
/// a wrap (a genuine wrap needs 18.4 EB through one cgroup; the
/// session-scoped maps die long before any real host produces it).
/// Read as a wrap, that restart produced a phantom delta of
/// ~2^64 - prev: an 18-exabyte spike on the returning row's rate,
/// a permanent +18 EB on the session leaderboard (boost-16 closed
/// the "wrap-around winner" at the accumulator; the phantom
/// reopened it through the delta layer), and a false
/// bypass-divergence verdict in the `--depth` shadow audit
/// (charger-core-1-a compares these totals against NIC counters) —
/// the monitor inventing bytes its own honesty contract forbids.
///
/// The discriminator is the coherence bound this family's own pins
/// already document: a delta AT or PAST 2^63 (half the u64 space)
/// is not a delta any real poll interval produces — ~9.2 EB in one
/// second is ~73 Pbps, nine orders past any deployed link — so the
/// only reachable producer is the LRU restart, and the restart's
/// honest delta is `cur` itself: the fresh bytes booked since the
/// re-insert. Genuine wraps (true delta deep inside the band) stay
/// exactly as modulo-exact as the NIGHT-lts-5 pins demand; the
/// unreachable corner (a restart whose gap is itself past 2^63,
/// needing 9.2+ EB accumulated inside one session) degrades to the
/// old modulo reading — never worse than the pre-audit behavior,
/// and documented here rather than engineered around.
#[inline]
pub(super) fn wrap_coherent_delta(cur: u64, prev: u64) -> u64 {
    let delta = cur.wrapping_sub(prev);
    // The half-space discriminator (NIGHT-total-lts-5): past the
    // coherence bound the only reachable reading is the eviction
    // restart — the fresh accumulator IS the honest delta.
    if delta >= HALF_SPACE {
        cur
    } else {
        delta
    }
}

/// The coherence band's ceiling: deltas at or past half the u64
/// space (~9.2 EB in one poll interval, ~73 Pbps) are not deltas
/// any real link produces — the discriminator bound
/// (NIGHT-total-lts-5; the NIGHT-lts-5 pins' own documented exact
/// band is everything strictly below this).
const HALF_SPACE: u64 = 1u64 << 63;

// NIGHT-lts-5: the wrap-coherence pins — the delta arithmetic the
// long-endurance server uptime leans on (the kernel counters wrap;
// the userspace must wrap WITH them, never clamp). NIGHT-total-lts-5
// added the eviction-restart family: the LRU lane dinner-6 gave these
// maps means a backwards step can be a RESTART, and the restart must
// read as its fresh bytes, never a wrap phantom.
#[cfg(test)]
#[path = "../../../test/ebpf/loader_wrap_tests.rs"]
mod loader_wrap_tests;
