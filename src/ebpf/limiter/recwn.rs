// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The RECWN userspace half (night-spark-2, schema v25 — Receive
//! Window Control, the quota saver's Layer 1): hint-map
//! invalidation on policy removal.
//!
//! The kernel half (ebpf/src/recwn_flow.rs) primes a cookie-keyed
//! LRU hint on the ingress policed path — socket cookie -> the
//! receive window the live policy derives — and the sock_ops
//! program reads it back at the connection callbacks to clamp
//! SO_RCVBUF. The hint's one blind spot is removal: once a policy
//! is gone the ingress path stops re-priming (the policy miss
//! returns long before the prime site), so a socket whose RTT_CB
//! flag is armed would keep re-applying its LAST window until the
//! LRU ages the row out. The answer is the MMSPA flush's own
//! posture, one lane over: every policy REMOVAL sweeps the whole
//! hint map — removals are CLI-rare, the map is bounded at 4096,
//! and a swept socket's next callback finds no row and answers the
//! OS default (its remaining window rides the connection's own
//! lifetime; connection churn heals the rest — the documented
//! residue in ebpf/src/recwn_flow.rs's header).
//!
//! ADDITIONS and RATE CHANGES never need the sweep: the ingress
//! prime overwrites the row on the very next packet (the upsert
//! contract), so the sweep runs beside the removal-path
//! invalidations only — the same call sites mmspa's own
//! invalidation rides.

use anyhow::{Context, Result};
use aya::maps::HashMap as BpfHashMap;

use super::lanes::map_error_means_absent;
use crate::ebpf::pin::{self, PIN_MAP_RECWN_HINT};

/// Verbose trace line for one hint sweep: pure formatting so the
/// wording is unit-pinned (the mmspa flush_trace_line discipline).
/// The count is the number of cookie rows dropped — the sockets
/// whose next connection callback answers the OS default window.
pub(super) fn hint_flush_trace_line(swept: u32) -> String {
    if swept == 0 {
        "[limiter] recwn hint map: 0 rows — no receive-window hints stood".to_string()
    } else {
        format!(
            "[limiter] recwn hint map: swept {swept} row{} — each covered socket answers \
             the OS default window on its next callback",
            if swept == 1 { "" } else { "s" }
        )
    }
}

/// The sweep-failure line: a removal whose hint sweep cannot run is
/// never silent but never fails the removal either — a stale hint
/// only means one connection keeps its last receive window until it
/// closes or the LRU ages the row, while the enforcement itself (the
/// policy map) is already gone. Pure formatting so the wording is
/// unit-pinned.
pub(super) fn hint_flush_failed_line(cause: &str) -> String {
    format!(
        "recwn hint sweep failed ({cause}) — a removed policy's last receive window \
         can linger on its live connections until they close; run 'zelynic recover' if \
         this persists"
    )
}

impl super::Limiter {
    /// Sweep every cookie row out of the pinned recwn hint map.
    ///
    /// Key snapshot first, then delete — an iterator over a map the
    /// datapath is still priming cannot be trusted to hold still
    /// (the mmspa_cache_flush discipline verbatim). The map is
    /// u64-COOKIE-keyed, which is why this sweep does not ride the
    /// u32-keyed acquisition lanes (lanes.rs): the one-off belongs
    /// here, pin-opened directly, exactly the way the mmspa key
    /// snapshot opens its pins for reading.
    ///
    /// Mutations run through `Limiter::open_pinned()` (the fire-and-
    /// forget architecture — attach() drops the object before any
    /// write lane runs), so the sweep opens the pin directly; a
    /// missing pin is `Ok(0)`, the fresh-install shape, not an error.
    pub(super) fn recwn_hint_flush(&mut self) -> Result<u32> {
        // A missing pin reads as "nothing to sweep" — the
        // fresh-install shape, the absent-lens contract every
        // monitor-side reader rides; an UNREADABLE pin (permissions,
        // a corrupted bpffs entry) is the honest error the caller
        // names.
        if !std::path::PathBuf::from(PIN_MAP_RECWN_HINT).exists() {
            return Ok(0);
        }
        let mut map_obj = pin::open_pinned_lru_hash_map(PIN_MAP_RECWN_HINT)?;
        let keys: Vec<u64> = {
            let map: BpfHashMap<_, u64, u64> = BpfHashMap::try_from(&map_obj)
                .context("Failed to open pinned recwn_socket_hint")?;
            map.keys().flatten().collect()
        };
        let mut swept = 0u32;
        let mut map: BpfHashMap<_, u64, u64> = BpfHashMap::try_from(&mut map_obj)
            .context("Failed to open recwn_socket_hint for sweep")?;
        for key in keys {
            match map.remove(&key) {
                Ok(()) => swept += 1,
                // ENOENT mid-sweep: the datapath's LRU evicted the
                // row (or a concurrent sweep won it) — absent counts
                // as swept, the map-empty verdict is the goal.
                Err(e) if map_error_means_absent(&e) => swept += 1,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "remove cookie {key} from recwn_socket_hint: {e}"
                    ));
                }
            }
        }
        Ok(swept)
    }

    /// The invalidation's never-fail wrapper: sweep the hint map and
    /// trace it verbosely; on failure print the honest degradation
    /// line — never silent, never failing the removal's own verdict,
    /// which outranks the housekeeping (the mmspa
    /// mmspa_memo_invalidate_best_effort contract, one lane over).
    pub(super) fn recwn_hint_invalidate_best_effort(&mut self) {
        match self.recwn_hint_flush() {
            Ok(swept) => {
                crate::output::verbose::vlog_line!(hint_flush_trace_line(swept));
            }
            Err(cause) => {
                eprintln_safe!(
                    "{}",
                    crate::output::grey(&hint_flush_failed_line(&cause.to_string()))
                );
            }
        }
    }
}

// The sweep-line pins (the mmspa_flush_lines_tests discipline),
// #[path]-wired under the single test/ tree.
#[cfg(test)]
#[path = "../../../test/ebpf/limiter/recwn_flush_lines_tests.rs"]
mod recwn_flush_lines_tests;
