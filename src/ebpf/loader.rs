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

use crate::ebpf::identity::IdentityMap;
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
    /// Dragon Architecture Layer 2: cgroup ID → process identity resolver.
    /// Refreshed lazily via `maybe_refresh()` before each summary print.
    identity: IdentityMap,
}

impl Observer {
    /// Attach with optional quiet mode (suppresses eprintln messages).
    /// Used by observe/top when running in alt-screen mode.
    pub fn attach_quiet(quiet: bool) -> Result<Self> {
        let cgroup_path = "/sys/fs/cgroup";
        if !PathBuf::from(cgroup_path).exists() {
            bail!("cgroup v2 not found at {cgroup_path}");
        }

        if !quiet {
            eprintln_safe!("[ebpf] Loading embedded BPF observer object");
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

        let mut bpf = Ebpf::load(OBSERVER_ELF).context("Failed to load BPF object")?;

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

        if !quiet {
            eprintln_safe!("[ebpf] Observer attached to {cgroup_path} (egress + ingress)");
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

    /// Read egress cgroup_counters map. Returns (cgroup_id, stats) pairs.
    pub fn read_counters(&self) -> Result<Vec<(u32, CgroupStatsRaw)>> {
        let bpf = self.bpf.as_ref().context("BPF not loaded")?;
        let map: BpfHashMap<_, u32, CgroupStatsRaw> =
            BpfHashMap::try_from(bpf.map("cgroup_counters").context("map not found")?)
                .context("Failed to access cgroup_counters map")?;

        let mut results = Vec::new();
        for (key, value) in map.iter().flatten() {
            results.push((key, value));
        }
        Ok(results)
    }

    /// Read ingress cgroup_counters_ingress map. Returns (cgroup_id, stats) pairs.
    pub fn read_counters_ingress(&self) -> Result<Vec<(u32, CgroupStatsRaw)>> {
        let bpf = self.bpf.as_ref().context("BPF not loaded")?;
        let map: BpfHashMap<_, u32, CgroupStatsRaw> = BpfHashMap::try_from(
            bpf.map("cgroup_counters_ingress")
                .context("map not found")?,
        )
        .context("Failed to access cgroup_counters_ingress map")?;

        let mut results = Vec::new();
        for (key, value) in map.iter().flatten() {
            results.push((key, value));
        }
        Ok(results)
    }

    /// Read counters (egress + ingress), compute deltas, return summary.
    pub fn poll_and_summarize(&mut self) -> Result<CounterSummary> {
        let current_egress = self.read_counters()?;
        let current_ingress = self.read_counters_ingress().unwrap_or_default();
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
                } else {
                    summary.cgroups.push(CgroupDelta {
                        cgroup_id: *cgroup_id,
                        packets: 0,
                        bytes: 0,
                        total_bytes: 0,
                        ingress_packets: delta_packets,
                        ingress_bytes: delta_bytes,
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
    pub packets: u64,
    pub bytes: u64,
    pub total_bytes: u64,
    pub ingress_packets: u64,
    pub ingress_bytes: u64,
}

// NIGHT-improve-1 phase 3: the embedded-object pins live under the
// single test/ tree (cosmostrix Pattern C), #[path]-wired across
// trees exactly like the limiter policy pins.
#[cfg(test)]
#[path = "../../test/ebpf/embedded_object_tests.rs"]
mod embedded_object_tests;
