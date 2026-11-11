// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! eBPF limiter — token-bucket rate enforcement per cgroup or group.
//!
//! Module layout (NIGHT-hunt-3 restructure):
//! - `types.rs`   — constants + BPF map structs + high-level API types
//! - `schema.rs`  — the schema-version anchor + history (grows per bump)
//! - `format.rs`  — rate/duration parsing + formatting helpers
//! - `parse.rs`   — the value parsers (the research-3 split)
//! - `policy.rs`  — the apply family (unset-leg removal, improve-29)
//! - `atomic.rs`  — the group lane's transactional write (charger-core-2)
//! - `policy_lines.rs` — the policy surface's pure line formatters
//! - `policy_write.rs` — the per-cgroup leg writer (improve-40 split)
//! - `reclaim.rs` — the remove path (unstrict) + state reclamation
//! - `recwn.rs`   — the RECWN userspace half: the hint-map sweep
//!   every policy removal runs (night-spark-2, schema v25)
//! - `pace.rs`    — the pacing userspace half: the hint-map sweep
//!   every policy removal runs + the loader's fourth attach lane
//!   (night-spark-5, schema v27)
//! - `stats.rs`   — status printing + map readers + identity
//! - `mmspa.rs`   — the MMSPA userspace half: the leaf-cache flush
//!   every policy mutation runs (private-research-2)
//! - `during*.rs` — the --during family (night-during): grammar,
//!   translation twin, and window map lanes
//! - `rate_ring.rs` — the time-series ring's read half + mirror
mod atomic;
mod during;
mod during_map;
mod during_parse;
mod format;
mod lanes;
mod mmspa;
mod pace;
mod parse;
mod policy;
mod policy_lines;
mod policy_write;
pub mod rate_ring;
mod reclaim;
mod recwn;
mod resolve;
mod schema;
// The schema ledger's history half (night-T-3's 600-line split): a
// doc-only sibling module of schema.rs, declared the standard way —
// the test-tree discipline reserves src/ #[path] wirings for the
// test/ tree, and a plain sibling mod is exactly how schema.rs
// itself is declared.
mod schema_ledger;
mod stats;
pub mod types;
mod unstrict;
mod zombie;

// The rootless test-tree wiring for the pure cores, one file over
// (NIGHT-private-research-4's LOC-cap split: mod.rs rode the
// 500-line owner cap at exactly 500 and the ECN lane's sixth wiring
// crossed it, so the whole family moved into the test tree it
// wires — depth preserved, no test text changes).
#[cfg(test)]
#[path = "../../../test/ebpf/limiter/wiring.rs"]
mod wiring;
// Re-export public types/functions for external use (the
// parse/format LOC-cap splits kept this surface unchanged).
pub use format::{
    default_burst, format_bytes, format_bytes_exact, format_bytes_wide, format_count, format_rate,
    format_rate_exact, monotonic_ns, terminal_width,
};
pub use parse::{
    parse_focus_window, parse_monitor_interval, parse_rate, parse_time_duration, validate_rate,
};
pub use types::{
    BracketPair, BracketSpec, Direction, LIMITER_ELF, LimiterStatsRaw, PolicyRaw, RateSpec, Target,
};
// night-during (schema v23): the --during surfaces the command
// layer consumes (the display join rides the re-exports). The
// persistence trio (WindowPersist + its two halves) went with the
// snapshot/restore pair when NIGHT-improve-55 retired the feature
// whole — nothing command-layer reaches into during's file format
// anymore, so no re-export rides for it.
pub use during::{dormancy_note, format_wall_utc, wall_minus_mono, wall_now_ns, window_state};
pub use during_parse::parse_during;

pub use crate::ebpf::pin::{
    PIN_DIR, PIN_LINK_DL, PIN_LINK_UL, PIN_PROG_DL, PIN_PROG_UL, pin_dir_has_files,
    read_pinned_schema_version, unpin_all,
};

use anyhow::{Context, Result, anyhow, bail};
use aya::{
    Ebpf, EbpfLoader,
    maps::Array as BpfArray,
    programs::{CgroupSkb, SockOps},
};
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd};
use std::path::PathBuf;

use crate::ebpf::bpf_syscall::{
    BPF_CGROUP_INET_EGRESS, BPF_CGROUP_INET_INGRESS, BPF_CGROUP_SOCK_OPS, create_and_pin_link,
    kernel_release, load_with_verifier_verdict,
};
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::pin::{
    PIN_LINK_PACE, PIN_LINK_RECWN, PIN_PROG_PACE, PIN_PROG_RECWN, link_mode_line, pins_operational,
};
use crate::ebpf::trace;
use types::SCHEMA_VERSION_EXPECTED;

// ━━ Limiter struct ━━

pub struct Limiter {
    bpf: Option<Ebpf>,
    identity: IdentityMap,
    // night-dragon-maintenance-xenric-1: no `verbose` field — the
    // diagnostic lane is process-global state (the output group's
    // static flag), read through the one vlog door instead of
    // threading a bool through every Limiter method.
}

impl Limiter {
    /// Load limiter BPF object and attach to cgroup v2 root (both ingress + egress).
    /// Programs AND links are pinned to /sys/fs/bpf/zelynic/ so they survive process exit.
    ///
    /// NIGHT-boost-6: `-v` traces the full attach anatomy — object
    /// size, kernel release, load timing, the loaded map inventory
    /// (id / type / key / value / max_entries, the bpftool facts),
    /// and the total attach cost.
    pub fn attach() -> Result<()> {
        let started = std::time::Instant::now();
        // night-netrunner-2 (the Adaptive Orchestra): ONE probe, every
        // attach decision reads the struct. The refusal ladder (floor,
        // cgroup v2, root, then the hunt-28 bpffs preflight) is the
        // HostCaps verdict — the same wordings the re-derived checks
        // carried, now one home. The verbose lane opens with the
        // probe's own two-line table.
        let caps = crate::ebpf::host_caps::HostCaps::probe();
        crate::output::verbose::vlog_line!(&caps.trace_lines()[0]);
        crate::output::verbose::vlog_line!(&caps.trace_lines()[1]);
        if let Some(refusal) = caps.limiter_refusal() {
            bail!(refusal);
        }
        let cgroup_path = caps
            .cgroup2_mount_path
            .clone()
            .unwrap_or_else(|| "/sys/fs/cgroup".to_string());

        // Check if the pinned state is fully operational from a previous
        // run. NIGHT-hunt-19: one predicate everywhere — on bpf_link
        // kernels the link pins are load-bearing (they ARE the cgroup
        // attachment), so a half-attached state must reload, never reuse.
        let all_pinned = Self::is_pinned();

        if all_pinned {
            // Check schema version. If mismatch (e.g. upgraded from v1 to v2),
            // clean up + reload to avoid struct layout incompatibility.
            match read_pinned_schema_version() {
                Some(v) if v == SCHEMA_VERSION_EXPECTED => {
                    crate::output::verbose::vlog!(
                        "limiter",
                        "BPF programs + links already pinned (schema v{v}) — reusing"
                    );
                    // night-during: refresh the wall-clock bridge
                    // on the reuse lane too (best-effort).
                    during_map::stamp_offset_on_pinned();
                    return Ok(());
                }
                Some(v) => {
                    crate::output::verbose::vlog!(
                        "limiter",
                        "Schema version mismatch: pinned v{v} ≠ expected v{SCHEMA_VERSION_EXPECTED} — reloading"
                    );
                    unpin_all()?;
                }
                None => {
                    crate::output::verbose::vlog!(
                        "limiter",
                        "Schema version map missing — reloading"
                    );
                    unpin_all()?;
                }
            }
        } else {
            // If SOME pins exist but not all → stale state from old version or
            // crashed run. Clean up everything before reloading.
            if pin_dir_has_files() {
                crate::output::verbose::vlog!("limiter", "Stale pin files detected — cleaning up");
                unpin_all()?;
            }
        }

        let obj_data = LIMITER_ELF;
        crate::output::verbose::vlog!(
            "limiter",
            "Loading embedded BPF limiter object ({} bytes)",
            obj_data.len()
        );
        crate::output::verbose::vlog_line!(trace::kernel_line("limiter", &kernel_release()));

        // NIGHT-hunt-30: alignment preflight — structurally impossible
        // with the AlignedElf embedding (src/ebpf/embedded.rs), kept
        // so a future regression fails with a one-line diagnosis
        // instead of aya's opaque "error parsing ELF data" on a
        // healthy object (the owner host's 2026-09-20..21 blocker:
        // every symptom pointed at the artifact, the artifact was
        // fine, and the address of the embedded bytes was the bug).
        if let Some(violation) = crate::ebpf::embedded::alignment_violation(obj_data, "limiter") {
            bail!("{violation}");
        }

        // NIGHT-hunt-28: the pin-filesystem preflight rides the
        // Orchestra now (the HostCaps limiter ladder above refused on
        // a non-bpffs /sys/fs/bpf before any pin attempt — same
        // wording, one home). The observer is deliberately NOT gated:
        // its maps are unpinned, so observe works without bpffs —
        // which also gives a natural diagnostic split: observe works
        // + strict fails = pin filesystem.

        // Create pin directory BEFORE load so maps with LIBBPF_PIN_BY_NAME
        // can be auto-pinned by EbpfLoader.
        std::fs::create_dir_all(PIN_DIR)?;

        // EbpfLoader + the pin directory: every map declared with
        // __uint(pinning, LIBBPF_PIN_BY_NAME) auto-pins to
        // /sys/fs/bpf/zelynic/<map_name> — this is what makes policies
        // persist across invocations (without it, maps vanish when the
        // Ebpf object drops and open_pinned() hits ENOENT; the bytes are
        // the embedded pure-Rust aya-ebpf build, improve-1). NIGHT-depthtest:
        // aya 0.14 renamed map_pin_path(path) to default_map_pin_directory.
        let load_started = std::time::Instant::now();
        let mut bpf = EbpfLoader::new()
            .default_map_pin_directory(PIN_DIR)
            .load(obj_data)
            .context("Failed to load BPF object")?;

        // NIGHT-boost-6: the loaded map inventory — one line per map
        // in bpftool vocabulary (id, type, key/value size,
        // max_entries). This is the -v surface a hacker needs when a
        // policy map fills (max_entries 1024) or a pin disagrees with
        // the object: the object's own view, printed at the moment it
        // loaded. Scoped so the immutable `bpf.maps()` borrow ends
        // before the map_mut section below takes the object over.
        if crate::output::verbose::enabled() {
            crate::output::verbose::vlog_line!(trace::load_line(
                "limiter",
                bpf.programs().count(),
                bpf.maps().count(),
                load_started.elapsed()
            ));
            for (name, map) in bpf.maps() {
                if let Some(info) = trace::map_info(map) {
                    let kind = info
                        .map_type()
                        .map(trace::map_type_name)
                        .unwrap_or("unknown");
                    crate::output::verbose::vlog_line!(trace::map_line(
                        "limiter",
                        name,
                        info.id(),
                        kind,
                        info.key_size(),
                        info.value_size(),
                        info.max_entries()
                    ));
                }
            }
        }

        // Write schema version to the pinned schema_version map.
        // This enables future migrations: if the pinned version doesn't match
        // SCHEMA_VERSION_EXPECTED, attach() cleans up + reloads.
        {
            let mut schema_map: BpfArray<_, u32> = BpfArray::try_from(
                bpf.map_mut("schema_version")
                    .context("schema_version map not found")?,
            )
            .context("Failed to access schema_version map")?;
            schema_map
                .set(0, SCHEMA_VERSION_EXPECTED, 0)
                .map_err(|e| anyhow!("Failed to write schema version: {e}"))?;
        }

        // Load + pin download program (ingress).
        let dl_prog: &mut CgroupSkb = bpf
            .program_mut("enforce_dl")
            .context("BPF program 'enforce_dl' not found")?
            .try_into()?;
        load_with_verifier_verdict(|| dl_prog.load(), "enforce_dl")?;
        dl_prog
            .pin(PIN_PROG_DL)
            .context("Failed to pin enforce_dl")?;

        // night-netrunner-1: ONE attach strategy — create-and-pin
        // bpf_links, the fire-and-forget contract. The 5.15.0 kernel
        // floor makes bpf_link (5.7+) unconditional, so the legacy
        // bpf_prog_attach path (pre-5.7, the leaked-links shape) is
        // GONE: no conditional attach, no second code path to verify.
        // The block scope ends the program-fd borrows before the pace
        // lane below takes the object.
        crate::output::verbose::vlog_line!(link_mode_line());
        {
            // Extract fd, then borrow ul_prog separately.
            let dl_prog_raw = dl_prog
                .fd()
                .context("Failed to get enforce_dl fd")?
                .as_fd()
                .as_raw_fd();

            // Load + pin upload program (egress).
            let ul_prog: &mut CgroupSkb = bpf
                .program_mut("enforce_ul")
                .context("BPF program 'enforce_ul' not found")?
                .try_into()?;
            load_with_verifier_verdict(|| ul_prog.load(), "enforce_ul")?;
            ul_prog
                .pin(PIN_PROG_UL)
                .context("Failed to pin enforce_ul")?;
            let ul_prog_raw = ul_prog
                .fd()
                .context("Failed to get enforce_ul fd")?
                .as_fd()
                .as_raw_fd();

            // Create + pin bpf_links (fire-and-forget with pin).
            let cgroup_file =
                File::open(&cgroup_path).context("Failed to open cgroup root directory")?;
            let cgroup_raw = cgroup_file.as_raw_fd();
            create_and_pin_link(
                dl_prog_raw,
                cgroup_raw,
                BPF_CGROUP_INET_INGRESS,
                PIN_LINK_DL,
            )
            .context("Failed to create + pin enforce_dl link")?;
            create_and_pin_link(ul_prog_raw, cgroup_raw, BPF_CGROUP_INET_EGRESS, PIN_LINK_UL)
                .context("Failed to create + pin enforce_ul link")?;

            // night-spark-2 (RECWN, schema v25 — the quota saver's
            // Layer 1): the third program, the sock_ops
            // receive-window lane. Loaded and pinned beside the two
            // enforcement hooks, then attached at the same cgroup
            // root through the SAME raw-syscall link lane — the
            // create-and-pin discipline the cgroup_skb pair rides,
            // one attach type over (BPF_CGROUP_SOCK_OPS). The
            // program plants with the object on every strict-family
            // attach, exactly when a rate limit is applied; its
            // cookie-keyed hint map is pinned by name with every
            // other map, and the unstrict teardown unlinks the whole
            // pin directory as ever (unpin_all sweeps the third
            // pair with the rest — the link pin's removal detaches
            // it in-kernel, the bpf_syscall contract).
            let recwn_prog: &mut SockOps = bpf
                .program_mut("zelynic_recwn")
                .context("BPF program 'zelynic_recwn' not found")?
                .try_into()?;
            load_with_verifier_verdict(|| recwn_prog.load(), "zelynic_recwn")?;
            recwn_prog
                .pin(PIN_PROG_RECWN)
                .context("Failed to pin zelynic_recwn")?;
            let recwn_prog_raw = recwn_prog
                .fd()
                .context("Failed to get zelynic_recwn fd")?
                .as_fd()
                .as_raw_fd();
            create_and_pin_link(
                recwn_prog_raw,
                cgroup_raw,
                BPF_CGROUP_SOCK_OPS,
                PIN_LINK_RECWN,
            )
            .context("Failed to create + pin zelynic_recwn link")?;
        }

        // night-spark-5 (Layer 3, egress pacing — schema v27): the
        // fourth program, the sock_ops pacing lane — loaded, pinned,
        // and attached at the same cgroup root through the same lane
        // the RECWN twin rides (pace.rs owns the shape; this call
        // site stays one line — one attach strategy since the
        // night-netrunner-1 floor, the legacy twin is gone). The
        // program plants with the object on every strict-family
        // attach, exactly when a rate limit is applied; its
        // cookie-keyed hint map is pinned by name with every other
        // map, and the unstrict teardown unlinks the whole pin
        // directory as ever (unpin_all sweeps the fourth pair with
        // the rest — the link pin's removal detaches it in-kernel,
        // the bpf_syscall contract).
        pace::attach_pace_lane(&mut bpf)?;

        crate::output::verbose::vlog!(
            "limiter",
            "Attached + pinned to {cgroup_path} (ingress + egress + sock_ops) in {}ms",
            trace::ms(started.elapsed())
        );

        // Drop Ebpf object — programs stay loaded because pinned, links stay
        // attached because pinned. Maps stay loaded because pinned via
        // LIBBPF_PIN_BY_NAME.
        drop(bpf);
        Ok(())
    }

    /// Check whether the limiter's pinned state is fully operational.
    ///
    /// On the bpf_link estate (the 5.15.0 floor is 5.7+ by eight
    /// minors): both program pins AND both link pins — the links are
    /// what attach the programs to the cgroup, so a state without them
    /// enforces nothing. NIGHT-hunt-19 closed the silent-no-enforcement
    /// trap where the old program-pins-only check "reused" exactly that
    /// half-attached state. (The pre-5.7 legacy attach — programs
    /// hooked without link pins — is gone with the night-netrunner-1
    /// floor: one attach strategy, one operational shape.)
    pub fn is_pinned() -> bool {
        pins_operational(
            PathBuf::from(PIN_PROG_DL).exists(),
            PathBuf::from(PIN_PROG_UL).exists(),
            PathBuf::from(PIN_PROG_RECWN).exists(),
            PathBuf::from(PIN_PROG_PACE).exists(),
            PathBuf::from(PIN_LINK_DL).exists(),
            PathBuf::from(PIN_LINK_UL).exists(),
            PathBuf::from(PIN_LINK_RECWN).exists(),
            PathBuf::from(PIN_LINK_PACE).exists(),
        )
    }

    /// Open pinned maps for read/write access (no BPF program load needed).
    /// Used by short-lived CLI invocations to read and write the pinned
    /// policy maps directly — the maps persist because they are pinned,
    /// so no background process is required.
    ///
    /// Identity refresh is lazy — only triggered when `refresh_identity()`
    /// or `maybe_refresh_identity()` is called. This speeds up startup
    /// for write operations (`strict` etc.) that don't need identity.
    pub fn open_pinned() -> Result<Self> {
        let limiter = Limiter {
            bpf: None, // No Ebpf object — using pinned maps directly
            identity: IdentityMap::new(),
        };

        crate::output::verbose::vlog!("limiter", "Opened pinned maps (identity lazy-loaded)");

        Ok(limiter)
    }
}

impl Drop for Limiter {
    fn drop(&mut self) {
        if self.bpf.is_some() {
            self.bpf = None;
        }
    }
}
