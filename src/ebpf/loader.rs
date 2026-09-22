// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! eBPF loader — load, attach, and read cgroup counters directly.
//!
//! Simplified: no ring buffer. BPF program updates a hash map,
//! userspace reads the map directly every interval.
//!
//! NIGHT-improve-1 phase 3: the object is EMBEDDED — the pure-Rust
//! aya-ebpf build (build.rs nested nightly build) stages the
//! zelynic-observer ELF into OUT_DIR and it rides inside the binary
//! via include_bytes!. The former on-disk object search (bpf/ path,
//! /usr/lib/zelynic/) is gone: one binary, zero loose artifacts, and
//! the "BPF object file not found" error class is structurally
//! impossible now.

use anyhow::{bail, Context, Result};
use aya::{
    maps::HashMap as BpfHashMap,
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType},
    Ebpf,
};
use std::fs::File;
use std::path::PathBuf;

use crate::ebpf::bpf_syscall::kernel_release;
use crate::ebpf::identity::IdentityMap;
use crate::ebpf::trace;
// Rendering of CounterSummary moved to ebpf/render.rs (NIGHT-hunt-7);
// the loader is now I/O-only. Byte formatting lives in
// limiter::format (unified decimal-SI, NIGHT-hunt-5).

/// The embedded pure-Rust observer object (NIGHT-improve-1 phase 3):
/// the aya-ebpf ELF staged into OUT_DIR by build.rs's nested nightly
/// build. `Ebpf::load` takes the bytes directly — no file path, no
/// object discovery, no "not found" error class.
///
/// NIGHT-hunt-30: wrapped in [`AlignedElf`] for guaranteed 8-byte
/// address alignment — the `object` crate's ELF64 parser requires
/// it, and the plain align-1 static landed unaligned on the owner
/// host (see src/ebpf/embedded.rs for the hunt record).
static OBSERVER_ELF: &[u8] = &crate::ebpf::embedded::AlignedElf::new(*include_bytes!(concat!(
    env!("OUT_DIR"),
    "/zelynic-observer"
)))
.bytes;

/// Per-cgroup stats from BPF map (must match the observer
/// program's CgroupStats in ebpf/src/main.rs — layout contract).
/// Must be Plain Old Data for aya's Pod trait.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[repr(align(8))]
pub struct CgroupStatsRaw {
    pub packets: u64,
    pub bytes: u64,
    pub last_event_packet: u64,
}

unsafe impl aya::Pod for CgroupStatsRaw {}

pub struct Observer {
    bpf: Option<Ebpf>,
    /// Previous egress stats for delta calculation.
    prev_stats: std::collections::HashMap<u32, CgroupStatsRaw>,
    /// Previous ingress stats for delta calculation.
    prev_stats_ingress: std::collections::HashMap<u32, CgroupStatsRaw>,
    /// Cosmic Dragon Architecture Layer 2: cgroup ID → process identity resolver.
    /// Refreshed lazily via `maybe_refresh()` before each summary print.
    identity: IdentityMap,
}

impl Observer {
    /// Attach with the verbose trace surfaced on stderr (NIGHT-boost-6
    /// renamed `attach_quiet(!verbose)` — a double negative — into the
    /// same forward contract `Limiter::attach(verbose)` carries).
    ///
    /// `-v` traces the full attach anatomy: object size, kernel
    /// release, load timing, the loaded map inventory, and the total
    /// attach cost — all before the alt screen takes over in the
    /// eagle-eyes path, so the diagnostics are never swallowed by the
    /// TUI. Silent by default; stdout JSON stays clean.
    pub fn attach(verbose: bool) -> Result<Self> {
        let started = std::time::Instant::now();
        let cgroup_path = "/sys/fs/cgroup";
        if !PathBuf::from(cgroup_path).exists() {
            bail!("cgroup v2 not found at {cgroup_path}");
        }

        if verbose {
            eprintln_safe!(
                "[ebpf] Loading embedded BPF observer object ({} bytes)",
                OBSERVER_ELF.len()
            );
            eprintln_safe!("{}", trace::kernel_line("ebpf", &kernel_release()));
        }

        // NIGHT-hunt-30: alignment preflight — structurally impossible
        // with the AlignedElf embedding, kept so a future regression
        // fails with a one-line diagnosis instead of aya's opaque
        // "error parsing ELF data" on a healthy object.
        if let Some(violation) =
            crate::ebpf::embedded::alignment_violation(OBSERVER_ELF, "observer")
        {
            bail!("{violation}");
        }

        let load_started = std::time::Instant::now();
        let mut bpf = Ebpf::load(OBSERVER_ELF).context("Failed to load BPF object")?;

        // NIGHT-boost-6: the loaded map inventory in bpftool
        // vocabulary — the observer's whole contract is its two
        // counter maps, so -v shows exactly what loaded (ids, sizes,
        // capacities) before any traffic flows through them. Scoped
        // so the immutable borrows end before the program_mut
        // section below takes the object over.
        if verbose {
            eprintln_safe!(
                "{}",
                trace::load_line(
                    "ebpf",
                    bpf.programs().count(),
                    bpf.maps().count(),
                    load_started.elapsed()
                )
            );
            for (name, map) in bpf.maps() {
                if let Some(info) = trace::map_info(map) {
                    let kind = info
                        .map_type()
                        .map(trace::map_type_name)
                        .unwrap_or("unknown");
                    eprintln_safe!(
                        "{}",
                        trace::map_line(
                            "ebpf",
                            name,
                            info.id(),
                            kind,
                            info.key_size(),
                            info.value_size(),
                            info.max_entries()
                        )
                    );
                }
            }
        }

        let cgroup_file =
            File::open(cgroup_path).context("Failed to open cgroup root directory")?;

        // Load + attach egress observer
        let egress_prog: &mut CgroupSkb = bpf
            .program_mut("observe_egress")
            .context("BPF program 'observe_egress' not found")?
            .try_into()?;
        egress_prog.load()?;
        egress_prog
            .attach(
                cgroup_file.try_clone()?,
                CgroupSkbAttachType::Egress,
                CgroupAttachMode::default(),
            )
            .context("Failed to attach observe_egress")?;

        // Load + attach ingress observer
        let ingress_prog: &mut CgroupSkb = bpf
            .program_mut("observe_ingress")
            .context("BPF program 'observe_ingress' not found")?
            .try_into()?;
        ingress_prog.load()?;
        ingress_prog
            .attach(
                cgroup_file,
                CgroupSkbAttachType::Ingress,
                CgroupAttachMode::default(),
            )
            .context("Failed to attach observe_ingress")?;

        if verbose {
            eprintln_safe!(
                "[ebpf] Observer attached to {cgroup_path} (egress + ingress) in {}ms",
                trace::ms(started.elapsed())
            );
            eprintln_safe!("[ebpf] Monitoring traffic for all processes");
        }

        Ok(Observer {
            bpf: Some(bpf),
            prev_stats: std::collections::HashMap::new(),
            prev_stats_ingress: std::collections::HashMap::new(),
            identity: IdentityMap::new(),
        })
    }

    /// Borrow the identity map (read-only) for label rendering.
    pub fn identity(&self) -> &IdentityMap {
        &self.identity
    }

    /// Force-refresh the identity map. Returns the number of cgroups resolved.
    pub fn refresh_identity(&mut self) -> usize {
        self.identity.refresh()
    }

    /// Lazily refresh the identity map if its TTL has elapsed.
    /// Call this before printing a summary to ensure labels are fresh.
    pub fn maybe_refresh_identity(&mut self) -> bool {
        self.identity.maybe_refresh()
    }

    /// Read a cgroup stats map by name. Returns (cgroup_id, stats) pairs.
    ///
    /// NIGHT-optimized-2: `read_counters` and `read_counters_ingress`
    /// were byte-identical except for the map name — one reader now
    /// carries the one contract, and the error messages name the map
    /// that failed (the old "map not found" told neither which one).
    fn read_stats_map(&self, map_name: &str) -> Result<Vec<(u32, CgroupStatsRaw)>> {
        let bpf = self.bpf.as_ref().context("BPF not loaded")?;
        let map: BpfHashMap<_, u32, CgroupStatsRaw> =
            BpfHashMap::try_from(bpf.map(map_name).context("map not found")?)
                .context(format!("Failed to access {map_name} map"))?;

        let mut results = Vec::new();
        for (key, value) in map.iter().flatten() {
            results.push((key, value));
        }
        Ok(results)
    }

    /// Read counters (egress + ingress), compute deltas, return summary.
    pub fn poll_and_summarize(&mut self) -> Result<CounterSummary> {
        let current_egress = self.read_stats_map("cgroup_counters")?;
        // NIGHT-optimized-2: the ingress read used to swallow errors
        // (`unwrap_or_default`) — asymmetric with the egress line
        // directly above, and the exact "fabricated absence"
        // anti-pattern the hunt-22 contract banned on the limiter
        // surface: an unreadable ingress map rendered as
        // "download: 0" while download flowed. Both counter families
        // now share one propagation contract. (Unreachable-difference
        // analysis: after detach() both reads fail identically, and
        // the embedded object always defines both maps — the lenient
        // branch could only ever mask real corruption.)
        let current_ingress = self.read_stats_map("cgroup_counters_ingress")?;
        let mut summary = CounterSummary::default();

        // Process egress (upload) deltas
        for (cgroup_id, stats) in &current_egress {
            let prev = self.prev_stats.get(cgroup_id).copied().unwrap_or_default();
            let delta_packets = stats.packets.saturating_sub(prev.packets);
            let delta_bytes = stats.bytes.saturating_sub(prev.bytes);

            if delta_packets > 0 {
                summary.total_packets += delta_packets;
                summary.total_bytes += delta_bytes;
                summary.cgroups.push(CgroupDelta {
                    cgroup_id: *cgroup_id,
                    packets: delta_packets,
                    bytes: delta_bytes,
                    total_bytes: stats.bytes,
                    ingress_packets: 0,
                    ingress_bytes: 0,
                    ingress_total_bytes: 0,
                });
            }
        }

        // Merge ingress (download) deltas into existing cgroups
        for (cgroup_id, stats) in &current_ingress {
            let prev = self
                .prev_stats_ingress
                .get(cgroup_id)
                .copied()
                .unwrap_or_default();
            let delta_packets = stats.packets.saturating_sub(prev.packets);
            let delta_bytes = stats.bytes.saturating_sub(prev.bytes);

            if delta_packets > 0 {
                summary.total_ingress_packets += delta_packets;
                summary.total_ingress_bytes += delta_bytes;

                if let Some(entry) = summary
                    .cgroups
                    .iter_mut()
                    .find(|c| c.cgroup_id == *cgroup_id)
                {
                    entry.ingress_packets = delta_packets;
                    entry.ingress_bytes = delta_bytes;
                    entry.ingress_total_bytes = stats.bytes;
                } else {
                    summary.cgroups.push(CgroupDelta {
                        cgroup_id: *cgroup_id,
                        packets: 0,
                        bytes: 0,
                        total_bytes: 0,
                        ingress_packets: delta_packets,
                        ingress_bytes: delta_bytes,
                        ingress_total_bytes: stats.bytes,
                    });
                }
            }
        }

        // Update prev_stats
        self.prev_stats.clear();
        for (cgroup_id, stats) in current_egress {
            self.prev_stats.insert(cgroup_id, stats);
        }
        self.prev_stats_ingress.clear();
        for (cgroup_id, stats) in current_ingress {
            self.prev_stats_ingress.insert(cgroup_id, stats);
        }

        // Refresh identity map if stale
        self.maybe_refresh_identity();

        Ok(summary)
    }

    pub fn detach(&mut self) {
        self.bpf = None;
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        self.bpf = None;
    }
}

#[derive(Debug, Default)]
pub struct CounterSummary {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub total_ingress_packets: u64,
    pub total_ingress_bytes: u64,
    pub cgroups: Vec<CgroupDelta>,
}

#[derive(Debug, Clone)]
pub struct CgroupDelta {
    pub cgroup_id: u32,
    /// Upload packets since the previous poll.
    pub packets: u64,
    /// Upload bytes since the previous poll.
    pub bytes: u64,
    /// Lifetime upload bytes (the map counter since attach).
    pub total_bytes: u64,
    /// Download packets since the previous poll.
    pub ingress_packets: u64,
    /// Download bytes since the previous poll.
    pub ingress_bytes: u64,
    /// Lifetime download bytes (the ingress map counter since
    /// attach). improve-13 precision: the filtered monitor's
    /// "lifetime" row previously summed `ingress_bytes` (a per-poll
    /// delta) with `total_bytes` (a lifetime figure) — a mixed-
    /// horizon number that shrank frame over frame on a 1s refresh;
    /// the honest lifetime needs the ingress map's own cumulative
    /// counter, the exact twin of `total_bytes`.
    pub ingress_total_bytes: u64,
}

// NIGHT-improve-1 phase 3: the embedded-object pins live under the
// single test/ tree (cosmostrix Pattern C), #[path]-wired across
// trees exactly like the limiter policy pins.
#[cfg(test)]
#[path = "../../test/ebpf/embedded_object_tests.rs"]
mod embedded_object_tests;
