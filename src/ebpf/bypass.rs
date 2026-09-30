// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The bypass-shadow audit core (NIGHT-upgrade-charger-core-1-a, the
//! TIER S "bypass detection" ability): the one honesty check no other
//! rate limiter runs — compare what the kernel's cgroup_skb hooks
//! SAW against what the network interfaces actually MOVED over the
//! same window, and report the gap instead of hiding it.
//!
//! The threat shape: zelynic enforces through cgroup_skb/ingress +
//! egress at the cgroup root, which sees every packet the IP stack
//! moves for a socket in the hierarchy. But a process can move bytes
//! WITHOUT traversing those hooks — AF_XDP rings drive the NIC
//! directly, RDMA/RoCE bypasses the IP stack entirely, AF_PACKET raw
//! injection enters at the device layer below the hook, and a kernel
//! module can inject at the driver. To that traffic a cgroup rate
//! limit is decorative: the BPF meter reads the limit while the
//! interface meter reads the truth. The audit makes the difference a
//! first-class report line instead of a silent lie — the same
//! honesty culture that prints "enforced" only when the ledger says
//! so.
//!
//! Scope, honestly: /sys/class/net statistics are MACHINE-scope
//! counters — no per-process attribution exists outside the hooks
//! (that is the whole point of a bypass). So the comparison is
//! machine-wide over the measured window: NIC aggregate delta minus
//! BPF-seen aggregate delta. A gap above the thresholds means
//! SOMETHING on the machine skipped the hooks — not necessarily the
//! inspected target; the report says exactly that and hands over the
//! triage commands (`ss -e`, `lsof -i`) rather than a guess.
//!
//! Bias, honestly measured and thresholded away: the interfaces
//! count link-layer headers (~14 B/frame, under 1% at MTU 1500), ARP,
//! and on overlay/container hosts the tunnel-encap and veth noise
//! that never traverses THIS netns's cgroup hooks. The RX side adds
//! every frame the stack dropped before socket demux (firewalls,
//! port scans, no-listener noise) — structurally larger, so its
//! threshold is looser. The io_uring-zerocopy escape the feature brief
//! hypothesized does NOT exist: those sends ride the socket sendmsg
//! path and traverse the egress hook like any other — verified
//! against the io_uring source at implementation time and stated
//! here so the docs never repeat the wrong guess.
//!
//! The measurement is read-only sysfs arithmetic: no new BPF
//! program, no daemon, no eBPF schema change. It runs inside the
//! eagle-eyes --depth focus window (the observer the report already
//! attaches) — see commands/eagle.rs for the wiring and
//! render/bypass.rs for the report surface.

use std::path::Path;

/// The per-window interface aggregate: tx/rx bytes summed over every
/// entry in /sys/class/net (loopback included — its traffic traverses
/// the cgroup hooks on both sides, so it stays comparable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NicTotals {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

/// Read the interface aggregate from a /sys/class/net-shaped
/// directory. `None` is the honest failure (the directory unreadable,
/// or ANY interface carrying a name without readable counters — an
/// undercounted aggregate would fabricate a clean verdict, the exact
/// lie the hunt-22 contract bans), never a partial zero.
pub fn nic_totals_from_dir(class_net: &Path) -> Option<NicTotals> {
    let entries = std::fs::read_dir(class_net).ok()?;
    let mut totals = NicTotals::default();
    for entry in entries.flatten() {
        let stats = entry.path().join("statistics");
        let tx = read_counter(&stats.join("tx_bytes"))?;
        let rx = read_counter(&stats.join("rx_bytes"))?;
        totals.tx_bytes = totals.tx_bytes.wrapping_add(tx);
        totals.rx_bytes = totals.rx_bytes.wrapping_add(rx);
    }
    Some(totals)
}

/// One u64 counter file, or None (the honest-failure contract above).
fn read_counter(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

/// Read the live interface aggregate from sysfs.
pub fn nic_totals() -> Option<NicTotals> {
    nic_totals_from_dir(Path::new("/sys/class/net"))
}

// ── The verdict thresholds (integer percent math — no float drift
// between the pinned tests and the shipped verdict) ─────────────────

/// TX shadow must exceed BOTH this share of the window's NIC tx
/// delta AND [`SHADOW_TX_FLOOR_BYTES`] to flag. Headers + ARP noise
/// sit under 2% on a physical host; 25% leaves an order of magnitude
/// of margin while still catching any real bypass (a bypass exists to
/// move volume — 47x was the motivating example, not the edge).
pub const SHADOW_TX_NUM_PERCENT: u64 = 25;

/// TX absolute floor: a fixed 1 MiB per window, so a 3s default
/// focus window flags from ~350 KB/s of shadow traffic upward and a
/// 30s window from ~35 KB/s — below that the gap is noise-scale.
pub const SHADOW_TX_FLOOR_BYTES: u64 = 1024 * 1024;

/// RX shadow share threshold: the receive side carries every frame
/// the stack dropped before socket demux (firewall drops, scans,
/// no-listener noise), so its honest ceiling is structurally higher —
/// 40% instead of 25%.
pub const SHADOW_RX_NUM_PERCENT: u64 = 40;

/// RX absolute floor (the TX twin's double, for the same reason).
pub const SHADOW_RX_FLOOR_BYTES: u64 = 2 * 1024 * 1024;

/// One side's flag: `shadow > floor && shadow * 100 > nic * percent`.
/// Pure integer math, pinned.
fn side_flagged(shadow: u64, nic: u64, floor: u64, num_percent: u64) -> bool {
    shadow > floor && shadow.saturating_mul(100) > nic.saturating_mul(num_percent)
}

/// The verdict over one measured window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowVerdict {
    /// Interfaces and hooks agree inside the threshold bands.
    Clean,
    /// The tx side exceeded both thresholds (machine-scope — see the
    /// module header for what that does and does not name).
    BypassedTx,
    /// The rx side exceeded both thresholds.
    BypassedRx,
    /// Both sides exceeded their thresholds.
    BypassedBoth,
    /// The window ran but the interface counters could not be read —
    /// the honest absence, never a fabricated clean.
    Unavailable,
}

/// The audit over one measured focus window (all fields byte deltas
/// over the window, not rates — the render derives rates).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShadowAudit {
    pub window_secs: u64,
    /// True when both interface snapshots read and the numbers mean
    /// something; false renders "unavailable" and keeps the zeros.
    pub measured: bool,
    pub nic_tx: u64,
    pub nic_rx: u64,
    pub bpf_tx: u64,
    pub bpf_rx: u64,
    pub shadow_tx: u64,
    pub shadow_rx: u64,
    pub verdict: ShadowVerdict,
}

/// Compose the audit from the window's boundary snapshots and the
/// observer's machine-wide totals. `bpf_tx`/`bpf_rx` are the closing
/// poll's aggregate deltas since the baseline poll (loader.rs's
/// `total_bytes`/`total_ingress_bytes` — the same polls the traffic
/// section already trusts); the NIC snapshots bracket the same span.
///
/// Wrap-coherent on both sides (the NIGHT-lts-5 discipline): the
/// u64 interface counters wrap at ~18.4 EB and the BPF counters at
/// the same horizon, so both deltas ride `wrapping_sub` — a wrapped
/// poll interval reads as the true delta, never a clamped zero.
///
/// Pure: every input is a value, so the verdict bands pin rootlessly.
#[must_use]
pub fn shadow_audit(
    start: Option<NicTotals>,
    end: Option<NicTotals>,
    bpf_tx: u64,
    bpf_rx: u64,
    window_secs: u64,
) -> ShadowAudit {
    let (start, end) = match (start, end) {
        (Some(s), Some(e)) => (s, e),
        _ => {
            return ShadowAudit {
                window_secs,
                measured: false,
                nic_tx: 0,
                nic_rx: 0,
                bpf_tx,
                bpf_rx,
                shadow_tx: 0,
                shadow_rx: 0,
                verdict: ShadowVerdict::Unavailable,
            };
        }
    };
    let nic_tx = end.tx_bytes.wrapping_sub(start.tx_bytes);
    let nic_rx = end.rx_bytes.wrapping_sub(start.rx_bytes);
    // saturating, not wrapping: a NIC-vs-BPF mismatch in BPF's favor
    // is measurement skew (the snapshots and polls bracket slightly
    // different spans), not negative shadow — it reads as zero gap.
    let shadow_tx = nic_tx.saturating_sub(bpf_tx);
    let shadow_rx = nic_rx.saturating_sub(bpf_rx);
    let tx_flagged = side_flagged(
        shadow_tx,
        nic_tx,
        SHADOW_TX_FLOOR_BYTES,
        SHADOW_TX_NUM_PERCENT,
    );
    let rx_flagged = side_flagged(
        shadow_rx,
        nic_rx,
        SHADOW_RX_FLOOR_BYTES,
        SHADOW_RX_NUM_PERCENT,
    );
    let verdict = match (tx_flagged, rx_flagged) {
        (true, true) => ShadowVerdict::BypassedBoth,
        (true, false) => ShadowVerdict::BypassedTx,
        (false, true) => ShadowVerdict::BypassedRx,
        (false, false) => ShadowVerdict::Clean,
    };
    ShadowAudit {
        window_secs,
        measured: true,
        nic_tx,
        nic_rx,
        bpf_tx,
        bpf_rx,
        shadow_tx,
        shadow_rx,
        verdict,
    }
}

/// The shadow's share of one side's interface traffic, whole percent
/// (0 when the interface moved nothing — a quiet window is clean, not
/// a division by zero). Pure; the render prints it.
#[must_use]
pub fn shadow_percent(shadow: u64, nic: u64) -> u64 {
    if nic == 0 {
        0
    } else {
        shadow.saturating_mul(100).checked_div(nic).unwrap_or(0)
    }
}

// The bypass core pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the loader and limiter pins.
#[cfg(test)]
#[path = "../../test/ebpf/bypass_tests.rs"]
mod tests;
