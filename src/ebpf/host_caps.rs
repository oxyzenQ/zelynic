// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The Adaptive Orchestra (night-netrunner-2 design, landed): ONE
//! capability probe, ONE struct, every attach decision.
//!
//! The netrunner-2 flow audit found the capability probes real but
//! their composition scattered — the floor law refused at two attach
//! paths, the bpffs preflight lived only in the limiter, the cgroup
//! check re-derived per surface, and the shape facts (bpf_link,
//! BPF_ATOMIC, the ECN helper, BTF) were tribal knowledge recorded in
//! audit docs instead of runtime truth. This module consolidates: the
//! host is probed ONCE per attach entry, into [`HostCaps`], and every
//! attach decision (the observer's, the limiter's, and the
//! eagle-eyes surfaces that ride them) reads THIS struct — never a
//! re-derived check, never a syscall-time surprise.
//!
//! The shape is deliberately the audit's sketch. Two layers:
//!
//! - **Layer 0 — the non-negotiables.** Kernel floor, cgroup v2,
//!   bpffs, root. The attach refusal ladder reads them in order and
//!   stops at the first miss with the actionable message — the same
//!   wordings the pre-orchestra paths carried, now one home.
//! - **Layer 1 — the shape facts.** Constants on (or derived beside)
//!   the 5.15.0 floor, recorded so a future floor drop re-opens the
//!   probe question honestly instead of silently: bpf_link (5.7+),
//!   64-bit BPF_ATOMIC (5.12+), the ECN set-CE helper (5.1+,
//!   cgroup_skb, CONFIG_INET), BTF presence (probed; the runtime
//!   answer to "does this host carry vmlinux BTF" — aya loads
//!   without it, so nothing consumes the absence), and the QUIC hint
//!   maps' availability (the v22 schema lane — compile-time truth on
//!   a full-life build).
//!
//! Honesty law: a missing capability degrades to a REFUSAL NAMED AT
//! ATTACH — the verbose trace prints the whole table, the refusal
//! names the fix — never a silent partial attach and never a deep
//! EPERM surfacing from inside a BPF syscall where no hint lives.

/// The QUIC hint maps' compile-time verdict (see the struct field):
/// the ebpf-gated path reads the limiter's schema constant, the
/// half-life build answers false — no object, no maps, honestly.
#[cfg(feature = "ebpf")]
const QUIC_HINT_MAPS: bool =
    cfg!(feature = "ebpf") && crate::ebpf::limiter::types::SCHEMA_VERSION_EXPECTED >= 22;
#[cfg(not(feature = "ebpf"))]
const QUIC_HINT_MAPS: bool = false;

/// The Layer 1 shape facts, derived PURELY from one parsed kernel
/// version (night-netrunner-2's version ladder): bpf_link (5.7+),
/// 64-bit BPF_ATOMIC (5.12+), the ECN set-CE helper (5.1+). An
/// unparsable version honestly claims nothing — the probe cannot
/// verify, so it does not. Pure so the ladder is unit-pinned
/// release by release without a host.
#[must_use]
fn shape_facts(version: Option<(u32, u32)>) -> (bool, bool, bool) {
    match version {
        Some(v) => (v >= (5, 7), v >= (5, 12), v >= (5, 1)),
        None => (false, false, false),
    }
}

/// The one capability probe (night-netrunner-2, the Orchestra).
///
/// Built once at the first attach-family entry (or the doctor's
/// report), read by every attach decision after. Field order is the
/// audit's: Layer 0 gates first, shape facts behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCaps {
    // ── Layer 0 — the non-negotiables (attach refuses when false) ──
    /// The 5.15.0 floor law's verdict on the running kernel
    /// (kernel_floor.rs). False below the floor or on an unparsable
    /// release — the honest "cannot verify" answer, never a guess.
    pub kernel_floor_met: bool,
    /// The kernel release string the verdict was judged on (the
    /// verbose trace and the doctor's report render it; a bug report
    /// that opens with it needs no follow-up uname).
    pub kernel_release: String,
    /// cgroup v2 unified hierarchy mounted (the observer and limiter
    /// both attach to /sys/fs/cgroup).
    pub cgroup_v2: bool,
    /// The cgroup v2 mount path when found (the attach surfaces name
    /// it; None = no unified mount).
    pub cgroup2_mount_path: Option<String>,
    /// bpffs mounted at /sys/fs/bpf (the limiter's pin filesystem —
    /// the observer stays unpinned by design and does not require
    /// it: observe works + strict fails = pin filesystem, the
    /// documented diagnostic split).
    pub bpffs_mounted: bool,
    /// Root / capability proxy (CAP_BPF + CAP_SYS_ADMIN ride the
    /// root set on every kernel the floor covers; the audit's own
    /// note — a fine-grained capability probe would be a new syscall
    /// surface for the same verdict).
    pub is_root: bool,

    // ── Layer 1 — the shape facts (recorded, not re-derived) ────────
    /// bpf_link availability (kernel 5.7+): the BPF_LINK_CREATE path
    /// the observer's cgroup attach rides.
    pub bpf_link: bool,
    /// 64-bit BPF_ATOMIC availability (kernel 5.12+): the
    /// enforcement core's ISA floor.
    pub bpf_atomic_64: bool,
    /// The ECN-first lane's helper (`bpf_skb_ecn_set_ce`, helper 97,
    /// cgroup_skb, CONFIG_INET — kernel 5.1+). Unconditional on the
    /// floor; the runtime refusal stays graceful either way.
    pub ecn_set_ce: bool,
    /// BTF presence fact (`/sys/kernel/btf/vmlinux` readable).
    /// NOTHING in the tree requires it — aya's objects carry no
    /// CO-RE relocations, so a BTF-less kernel attaches identically
    /// (the audit's `needs_kernel_btf: false`, recorded as the pair
    /// "not needed" x "present or not"; the MMSPA/QUIC lanes key off
    /// pinned maps and compile-time schema constants, never BTF —
    /// the consumer walk found zero readers). Kept as a recorded
    /// fact so a future CO-RE adoption re-opens the question with
    /// data — which is exactly what the trace line's
    /// "(informational)" parenthetical says (night-ux-2: the former
    /// "(not required)" read as "we probe this but it does not
    /// matter" without saying the probe exists for the record).
    pub btf_present: bool,
    /// The QUIC hint maps' availability (schema v22+): the
    /// `quic_cid_hint_dl/ul` + `recwn_socket_hint` LRU maps the
    /// QUIC-aware attribution and RECWN lanes key by. Compile-time
    /// truth — the limiter object is embedded whole on a full-life
    /// build, so the maps ride exactly when the schema does; a
    /// half-life build answers false honestly (no object, no maps).
    pub quic_hint_maps: bool,
}

impl HostCaps {
    /// Probe the host once. Every fact is a file read or a compile
    /// time constant — no BPF syscall, no privilege required, so the
    /// probe itself can never fail the way the attach it feeds can.
    /// Failure-class facts (an unreadable /proc) degrade to the
    /// honest false, the refusal ladder's own language.
    #[must_use]
    pub fn probe() -> HostCaps {
        let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let floor_ok = crate::ebpf::kernel_floor::kernel_floor_error(&kernel_release).is_ok();

        // Version shape facts ride the parsed (major, minor) — the
        // same parse the floor law runs, one read, three derived
        // truths (the pure [`shape_facts`] ladder).
        let (bpf_link, bpf_atomic_64, ecn_set_ce) = shape_facts(
            crate::ebpf::kernel_floor::parse_kernel_release(&kernel_release),
        );

        let cgroup2_mount_path = crate::capabilities::bpffs::find_cgroup2_mount();
        let btf_present = std::fs::metadata("/sys/kernel/btf/vmlinux").is_ok();

        HostCaps {
            kernel_floor_met: floor_ok,
            kernel_release,
            cgroup_v2: cgroup2_mount_path.is_some(),
            cgroup2_mount_path,
            bpffs_mounted: crate::capabilities::bpffs::bpffs_mounted_at("/sys/fs/bpf"),
            is_root: nix::unistd::geteuid().is_root(),
            bpf_link,
            bpf_atomic_64,
            ecn_set_ce,
            btf_present,
            quic_hint_maps: QUIC_HINT_MAPS,
        }
    }

    /// The observer's attach verdict (Layer 0, the audit's decision
    /// tree): floor, cgroup v2, root — in that order, first miss
    /// refused. bpffs is deliberately NOT required: the observer's
    /// maps are unpinned, the documented diagnostic split.
    ///
    /// The returned message is the actionable refusal the attach
    /// surfaces verbatim — one law, one wording, every consumer.
    /// allow(dead_code) on the dormant lane: the only callers are
    /// the ebpf-gated attach paths (the half-life build probes for
    /// the doctor's facts, it never attaches).
    #[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
    #[must_use]
    pub fn observer_refusal(&self) -> Option<String> {
        if let Some(msg) = self.floor_refusal() {
            return Some(msg);
        }
        if !self.cgroup_v2 {
            return Some(
                "cgroup v2 not found at /sys/fs/cgroup — the observer attaches its \
                 cgroup_skb hooks there\n  tip: boot with systemd's unified hierarchy \
                 (cgroup_no_v1=all) or mount: sudo mount -t cgroup2 none /sys/fs/cgroup"
                    .to_string(),
            );
        }
        if !self.is_root {
            return Some(
                "eBPF attach requires root — the cgroup_skb hooks and map loads are \
                 privileged operations\n  tip: run with sudo"
                    .to_string(),
            );
        }
        None
    }

    /// The limiter's attach verdict (Layer 0 + the pin filesystem):
    /// the observer's ladder plus the bpffs preflight (the hunt-28
    /// tip — a non-bpffs /sys/fs/bpf turns every pin into an EINVAL
    /// deep inside the object load).
    #[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
    #[must_use]
    pub fn limiter_refusal(&self) -> Option<String> {
        if let Some(msg) = self.observer_refusal() {
            return Some(msg);
        }
        if !self.bpffs_mounted {
            return Some(
                "/sys/fs/bpf is not a mounted bpf filesystem — the limiter pins \
                 its maps there so limits survive process exit, and every pin \
                 would fail (EINVAL) deep inside the object load\n  \
                 tip: sudo mount -t bpf bpf /sys/fs/bpf\n  \
                 tip: make it permanent with an fstab entry or a systemd mount \
                 unit — pins are wiped at boot unless the mount is"
                    .to_string(),
            );
        }
        None
    }

    /// The floor refusal, worded by the pure law itself (one floor,
    /// one message, everywhere — the netrunner-1 contract the doctor
    /// already renders).
    #[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
    fn floor_refusal(&self) -> Option<String> {
        if self.kernel_floor_met {
            return None;
        }
        crate::ebpf::kernel_floor::kernel_floor_error(&self.kernel_release).err()
    }

    /// The verbose trace's one-line-per-layer table (NIGHT-boost-6's
    /// attach anatomy, opened with the host's own answer): yes/no
    /// pairs in the audit's order, the shape facts named beside the
    /// gates. Two lines, the whole verdict — the -v lane's first
    /// output on every attach-family command.
    #[must_use]
    pub fn trace_lines(&self) -> [String; 2] {
        let yn = |v: bool| if v { "yes" } else { "no" };
        (
            format!(
                "[host-caps] kernel {} (floor 5.15 {}) · cgroup v2 {} · bpffs {} · root {}",
                self.kernel_release,
                yn(self.kernel_floor_met),
                yn(self.cgroup_v2),
                yn(self.bpffs_mounted),
                yn(self.is_root),
            ),
            format!(
                "[host-caps] bpf_link {} · bpf_atomic_64 {} · ecn_set_ce {} · btf {} (informational) · quic hints {}",
                yn(self.bpf_link),
                yn(self.bpf_atomic_64),
                yn(self.ecn_set_ce),
                yn(self.btf_present),
                yn(self.quic_hint_maps),
            ),
        )
        .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The probe never panics and always populates every verdict —
    /// the doctor's own detect() contract, now the Orchestra's.
    #[test]
    fn probe_never_panics_and_fills_every_field() {
        let caps = HostCaps::probe();
        assert!(!caps.kernel_release.is_empty());
        // The floor verdict must always agree with the pure law on
        // the release string it was judged from (the doctor's twin
        // assertion — one law, every probe).
        assert_eq!(
            caps.kernel_floor_met,
            crate::ebpf::kernel_floor::kernel_floor_error(&caps.kernel_release).is_ok(),
            "floor verdict disagrees with the law on kernel {}",
            caps.kernel_release
        );
    }

    /// The shape facts ladder derives from the parsed release
    /// exactly — pinned release by release, including the honest
    /// all-false on an unparsable one (the pure fn, no host).
    #[test]
    fn shape_facts_ride_the_parsed_release() {
        let cases: &[(&str, bool, bool, bool)] = &[
            // (release, bpf_link, atomic64, ecn_set_ce)
            ("5.15.0-52-generic", true, true, true),
            ("6.8.0-45", true, true, true),
            ("5.12.0", true, true, true),
            ("5.7.0", true, false, true),
            ("5.4.0-42-generic", false, false, true),
            ("5.1.0", false, false, true),
            ("4.19.0", false, false, false),
            // An unparsable release honestly claims nothing.
            ("unknown", false, false, false),
            ("", false, false, false),
        ];
        for (release, want_link, want_atomic, want_ecn) in cases {
            let parsed = crate::ebpf::kernel_floor::parse_kernel_release(release);
            let (link, atomic, ecn) = shape_facts(parsed);
            assert_eq!(link, *want_link, "{release} bpf_link");
            assert_eq!(atomic, *want_atomic, "{release} atomic");
            assert_eq!(ecn, *want_ecn, "{release} ecn");
        }
    }

    /// The observer's refusal ladder: floor first, then cgroup v2,
    /// then root. bpffs is NOT a refusal for the observer (the
    /// unpinned-maps diagnostic split).
    #[test]
    fn observer_refusal_ladder_orders_the_gates() {
        let base = HostCaps {
            kernel_floor_met: true,
            kernel_release: "6.8.0-45".to_string(),
            cgroup_v2: true,
            cgroup2_mount_path: Some("/sys/fs/cgroup".to_string()),
            bpffs_mounted: false,
            is_root: true,
            bpf_link: true,
            bpf_atomic_64: true,
            ecn_set_ce: true,
            btf_present: true,
            quic_hint_maps: true,
        };
        // A capable host refuses nothing — even bpffs-less.
        assert_eq!(base.observer_refusal(), None);
        // ...but the limiter refuses on the missing pin filesystem.
        let limiter_msg = base.limiter_refusal().expect("bpffs miss refuses");
        assert!(
            limiter_msg.contains("not a mounted bpf filesystem"),
            "{limiter_msg}"
        );
        assert!(limiter_msg.contains("mount -t bpf"), "{limiter_msg}");

        // Below the floor: the floor law's wording leads.
        let mut old_kernel = base.clone();
        old_kernel.kernel_floor_met = false;
        old_kernel.kernel_release = "5.10.0-21-amd64".to_string();
        let msg = old_kernel.observer_refusal().expect("floor miss refuses");
        assert!(msg.contains("below zelynic's minimum 5.15"), "{msg}");
        // The limiter ladder stops at the same first miss.
        assert_eq!(
            old_kernel.observer_refusal(),
            old_kernel.limiter_refusal(),
            "the limiter inherits the observer's first refusal"
        );

        // No cgroup v2: the mount hint.
        let mut no_cgroup = base.clone();
        no_cgroup.cgroup_v2 = false;
        let msg = no_cgroup.observer_refusal().expect("cgroup miss refuses");
        assert!(msg.contains("cgroup v2 not found"), "{msg}");
        assert!(msg.contains("mount -t cgroup2"), "{msg}");

        // Not root: the capability hint.
        let mut not_root = base.clone();
        not_root.is_root = false;
        let msg = not_root.observer_refusal().expect("root miss refuses");
        assert!(msg.contains("requires root"), "{msg}");
    }

    /// The trace table renders both layers with the yes/no verdicts —
    /// the -v lane's contract, worded so a paste into a bug report
    /// reads whole.
    #[test]
    fn trace_lines_render_both_layers() {
        let caps = HostCaps::probe();
        let lines = caps.trace_lines();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("[host-caps] kernel"), "{}", lines[0]);
        assert!(lines[0].contains("floor 5.15"), "{}", lines[0]);
        assert!(lines[0].contains("cgroup v2"), "{}", lines[0]);
        assert!(lines[1].contains("bpf_link"), "{}", lines[1]);
        assert!(lines[1].contains("ecn_set_ce"), "{}", lines[1]);
        assert!(lines[1].contains("quic hints"), "{}", lines[1]);
        assert!(
            !lines[1].contains("not required"),
            "the misleading parenthetical is retired, got: {}",
            lines[1]
        );
        assert!(lines[1].contains("informational"), "{}", lines[1]);
    }

    /// The QUIC hint verdict is the compile-time contract: true
    /// exactly when the ebpf feature compiled AND the schema carries
    /// the v22 lane (the module-level const — this pin catches a
    /// drifted threshold).
    #[test]
    fn quic_hint_verdict_matches_the_schema_lane() {
        let caps = HostCaps::probe();
        #[cfg(feature = "ebpf")]
        let want = crate::ebpf::limiter::types::SCHEMA_VERSION_EXPECTED >= 22;
        #[cfg(not(feature = "ebpf"))]
        let want = false;
        assert_eq!(caps.quic_hint_maps, want);
    }
}
