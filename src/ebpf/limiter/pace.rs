// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The pacing userspace half (night-spark-5, schema v27 — Egress
//! Socket Pacing, the quota saver's Layer 3): the hint-map sweep
//! every policy removal runs, and the loader's fourth attach lane.
//!
//! The kernel half (ebpf/src/pace_flow.rs) primes a cookie-keyed
//! LRU hint on the egress policed path — socket cookie -> the
//! upload rate the live policy carries — and the sock_ops program
//! reads it back at the connection callbacks to pin
//! SO_MAX_PACING_RATE. The hint's one blind spot is removal: once a
//! policy is gone the egress path stops re-priming (the policy miss
//! returns long before the prime site), so a socket whose RTT_CB
//! flag is armed would keep re-applying its LAST rate until the LRU
//! ages the row out. The answer is the recwn sweep's own posture,
//! one lane over: every policy REMOVAL sweeps the whole hint map —
//! removals are CLI-rare, the map is bounded at 4096, and a swept
//! socket's next callback finds no row and answers the kernel's
//! default pacing (its remaining rate rides the connection's own
//! lifetime; connection churn heals the rest — the documented
//! residue in ebpf/src/pace_flow.rs's header).
//!
//! ADDITIONS and RATE CHANGES never need the sweep: the egress
//! prime overwrites the row on the very next packet (the upsert
//! contract), so the sweep runs beside the removal-path
//! invalidations only — the same call sites the recwn sweep rides.
//!
//! The attach half (attach_pace_lane) is the loader's FOURTH
//! program/link pair: the sock_ops pacing program loads, pins, and
//! attaches at the cgroup root beside the two enforcement hooks and
//! the RECWN twin — the recwn twin's own shape, one call site in
//! mod.rs. One attach strategy since the night-netrunner-1 floor
//! (5.15.0): bpf_link's create-and-pin, the link pin's removal
//! detaching in-kernel — the legacy ProgAttach shape is gone with
//! the pre-5.7 kernels it served.

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::maps::HashMap as BpfHashMap;
use aya::programs::SockOps;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd};

use super::lanes::map_error_means_absent;
use crate::ebpf::bpf_syscall::{
    BPF_CGROUP_SOCK_OPS, create_and_pin_link, load_with_verifier_verdict,
};
use crate::ebpf::pin::{self, PIN_LINK_PACE, PIN_MAP_PACE_HINT, PIN_PROG_PACE};

/// Verbose trace line for one hint sweep: pure formatting so the
/// wording is unit-pinned (the recwn hint_flush_trace_line
/// discipline, one lane over). The count is the number of cookie
/// rows dropped — the sockets whose next connection callback
/// answers the kernel's default pacing.
pub(super) fn pace_hint_trace_line(swept: u32) -> String {
    if swept == 0 {
        "[limiter] pace hint map: 0 rows — no egress pacing hints stood".to_string()
    } else {
        format!(
            "[limiter] pace hint map: swept {swept} row{} — each covered socket answers the kernel's default pacing on its next callback",
            if swept == 1 { "" } else { "s" }
        )
    }
}

/// The sweep-failure line: a removal whose hint sweep cannot run is
/// never silent but never fails the removal either — a stale hint
/// only means one connection keeps its last pacing rate until it
/// closes or the LRU ages the row, while the enforcement itself (the
/// policy map) is already gone. Pure formatting so the wording is
/// unit-pinned.
pub(super) fn pace_hint_failed_line(cause: &str) -> String {
    format!(
        "pace hint sweep failed ({cause}) — a removed policy's last pacing rate can linger on its live connections until they close; run 'zelynic recover' if this persists"
    )
}

/// Load, pin, and attach the pacing sock_ops program (the loader's
/// fourth lane — the recwn twin's own shape, one call site in mod.rs).
/// The cgroup root file opens here so the call site stays one line.
/// The attach strategy is bpf_link's create-and-pin (the link pin's
/// removal detaches in-kernel — the unstrict contract); the legacy
/// ProgAttach + take_link + forget shape is gone with the pre-5.7
/// kernels it served (night-netrunner-1's 5.15.0 floor). A FREE
/// function, not a Limiter method: the attach
/// lane runs before any Limiter instance exists (the fire-and-forget
/// architecture — attach() drops the object before any write lane
/// runs), exactly the shape the recwn twin's inline lane rode inside
/// mod.rs.
pub(super) fn attach_pace_lane(bpf: &mut Ebpf) -> Result<()> {
    let prog: &mut SockOps = bpf
        .program_mut("zelynic_pace")
        .context(
            "BPF program 'zelynic_pace' not found — the embedded object \n             predates the pacing lane (schema v27); run \n             ./scripts/release/refresh-prebuilt.sh and rebuild",
        )?
        .try_into()?;
    load_with_verifier_verdict(|| prog.load(), "zelynic_pace")?;
    prog.pin(PIN_PROG_PACE)
        .context("Failed to pin zelynic_pace")?;
    let cgroup_file =
        File::open("/sys/fs/cgroup").context("Failed to open cgroup root directory")?;
    let prog_raw = prog
        .fd()
        .context("Failed to get zelynic_pace fd")?
        .as_fd()
        .as_raw_fd();
    create_and_pin_link(
        prog_raw,
        cgroup_file.as_raw_fd(),
        BPF_CGROUP_SOCK_OPS,
        PIN_LINK_PACE,
    )
    .context("Failed to create + pin zelynic_pace link")?;
    Ok(())
}

impl super::Limiter {
    /// Sweep every cookie row out of the pinned pacing hint map.
    ///
    /// Key snapshot first, then delete — an iterator over a map the
    /// datapath is still priming cannot be trusted to hold still
    /// (the recwn_hint_flush discipline verbatim). The map is
    /// u64-COOKIE-keyed, which is why this sweep does not ride the
    /// u32-keyed acquisition lanes (lanes.rs): the one-off belongs
    /// here, pin-opened directly, exactly the way the recwn sweep
    /// opens its pins for reading.
    ///
    /// Mutations run through `Limiter::open_pinned()` (the fire-and-
    /// forget architecture — attach() drops the object before any
    /// write lane runs), so the sweep opens the pin directly; a
    /// missing pin is `Ok(0)`, the fresh-install shape, not an error.
    pub(super) fn pace_hint_flush(&mut self) -> Result<u32> {
        // A missing pin reads as "nothing to sweep" — the
        // fresh-install shape, the absent-lens contract every
        // monitor-side reader rides; an UNREADABLE pin (permissions,
        // a corrupted bpffs entry) is the honest error the caller
        // names.
        if !std::path::PathBuf::from(PIN_MAP_PACE_HINT).exists() {
            return Ok(0);
        }
        let mut map_obj = pin::open_pinned_lru_hash_map(PIN_MAP_PACE_HINT)?;
        let keys: Vec<u64> = {
            let map: BpfHashMap<_, u64, u64> =
                BpfHashMap::try_from(&map_obj).context("Failed to open pinned pace_socket_hint")?;
            map.keys().flatten().collect()
        };
        let mut swept = 0u32;
        let mut map: BpfHashMap<_, u64, u64> = BpfHashMap::try_from(&mut map_obj)
            .context("Failed to open pace_socket_hint for sweep")?;
        for key in keys {
            match map.remove(&key) {
                Ok(()) => swept += 1,
                // ENOENT mid-sweep: the datapath's LRU evicted the
                // row (or a concurrent sweep won it) — absent counts
                // as swept, the map-empty verdict is the goal.
                Err(e) if map_error_means_absent(&e) => swept += 1,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "remove cookie {key} from pace_socket_hint: {e}"
                    ));
                }
            }
        }
        Ok(swept)
    }

    /// The invalidation's never-fail wrapper: sweep the hint map and
    /// trace it verbosely; on failure print the honest degradation
    /// line — never silent, never failing the removal's own verdict,
    /// which outranks the housekeeping (the recwn
    /// recwn_hint_invalidate_best_effort contract, one lane over).
    pub(super) fn pace_hint_invalidate_best_effort(&mut self) {
        match self.pace_hint_flush() {
            Ok(swept) => {
                crate::output::verbose::vlog_line!(pace_hint_trace_line(swept));
            }
            Err(cause) => {
                eprintln_safe!(
                    "{}",
                    crate::output::grey(&pace_hint_failed_line(&cause.to_string()))
                );
            }
        }
    }
}

// The sweep-line pins (the recwn_flush_lines_tests discipline,
// one lane over), #[path]-wired under the single test/ tree.
#[cfg(test)]
#[path = "../../../test/ebpf/limiter/pace_flush_lines_tests.rs"]
mod pace_flush_lines_tests;
