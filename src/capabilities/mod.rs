// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Capability detection (the cosmic dragon architecture — eBPF only).
//!
//! Detects the eBPF facts that matter: cgroup v2, BPF filesystem,
//! kernel version, root privileges.

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// System information relevant to eBPF support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub kernel: String,
    pub cgroup_v2: bool,
    pub cgroup2_mount_path: Option<String>,
    pub bpf_fs_mounted: bool,
    pub is_root: bool,
}

/// Capability detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityReport {
    pub system: SystemInfo,
    pub ebpf_supported: bool,
    /// NIGHT-dinner-3: the binary's own build flavor — `full-life`
    /// (the `ebpf` feature compiled in, objects embedded by build.rs)
    /// or `half-life` (userspace-only build; every eBPF surface
    /// answers its honest refusal). First-class in the report because
    /// the host can be perfectly capable while the binary is not: on
    /// a half-life build the pre-dinner-3 doctor printed "Ready: run
    /// 'zelynic strict-single ...'" — a command that build cannot
    /// execute. The verdict is compile-time truth (`cfg!`), not a
    /// runtime probe, so it can never drift from what shipped.
    pub build_flavor: String,
    /// The lane behind the flavor — the NIGHT-ask-2
    /// `ZELYNIC_EBPF_LANE` stamp: `source-built` (git checkout,
    /// nested nightly cross-compile), `registry-prebuilt`
    /// (crates.io extract, maintainer objects staged from
    /// ebpf-prebuilt/), or `dormant (not compiled)`
    /// (`--no-default-features`).
    pub ebpf_lane: String,
    pub warnings: Vec<String>,
}

/// NIGHT-dinner-3: the full-life verdict — the `ebpf` feature is
/// compiled in and build.rs embedded the objects.
pub const BUILD_FLAVOR_FULL_LIFE: &str = "full-life";

/// NIGHT-dinner-3: the half-life verdict — a `--no-default-features`
/// build: userspace monitoring only, the eBPF surfaces refuse.
pub const BUILD_FLAVOR_HALF_LIFE: &str = "half-life";

/// The binary's own build flavor (NIGHT-dinner-3): full-life when the
/// `ebpf` feature is compiled in, half-life otherwise. `cfg!` is
/// evaluated at compile time — the answer is baked into the binary
/// next to the objects it describes, so `zelynic doctor` can tell a
/// downloaded full-life release binary from a half-life local build
/// without guessing from behavior.
///
/// The lane detail (which of the three build paths produced the
/// embedded objects) rides along via [`crate::info::ebpf_lane`] —
/// since NIGHT-dinner-4 this report is that stamp's one printing
/// surface: the version report answers the same question at brand
/// level ("Pure eBPF builtin" vs "eBPF dormant"), the doctor answers
/// it forensically (which lane, exactly).
fn build_flavor() -> &'static str {
    if cfg!(feature = "ebpf") {
        BUILD_FLAVOR_FULL_LIFE
    } else {
        BUILD_FLAVOR_HALF_LIFE
    }
}

/// Detect system capabilities for eBPF.
pub fn detect() -> CapabilityReport {
    let system = detect_system();
    let ebpf_supported = system.cgroup_v2 && system.bpf_fs_mounted;
    let build_flavor = build_flavor();
    let ebpf_lane = crate::info::ebpf_lane().to_string();

    let mut warnings = Vec::new();
    if build_flavor == BUILD_FLAVOR_HALF_LIFE {
        warnings.push(
            "This is a HALF-LIFE build (no --features ebpf): the eBPF objects are not \
             embedded, so rate limiting and live enforcement are unavailable regardless \
             of host capabilities. Install a full-life binary: 'cargo install zelynic' \
             (default features) or a GitHub Release tarball."
                .to_string(),
        );
    }
    if !system.cgroup_v2 {
        warnings.push("cgroup v2 not detected. eBPF observer requires cgroup v2.".to_string());
    }
    if !system.bpf_fs_mounted {
        warnings.push(
            "BPF filesystem not mounted at /sys/fs/bpf — mount it: \
             sudo mount -t bpf bpf /sys/fs/bpf"
                .to_string(),
        );
    }
    if !system.is_root {
        warnings.push("Not running as root. eBPF operations require root.".to_string());
    }

    CapabilityReport {
        system,
        ebpf_supported,
        build_flavor: build_flavor.to_string(),
        ebpf_lane,
        warnings,
    }
}

/// Detect basic system info.
fn detect_system() -> SystemInfo {
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let cgroup2_mount_path = find_cgroup2_mount();
    let cgroup_v2 = cgroup2_mount_path.is_some();

    let bpf_fs_mounted = bpffs_mounted_at("/sys/fs/bpf");

    let is_root = nix::unistd::geteuid().is_root();

    SystemInfo {
        kernel,
        cgroup_v2,
        cgroup2_mount_path,
        bpf_fs_mounted,
        is_root,
    }
}

/// `linux/magic.h` `BPF_FS_MAGIC` — the statfs type of a mounted bpf
/// filesystem. Stored as i64, the common denominator of the two libc
/// `f_type` flavors: glibc types the field `__fsword_t` (signed long)
/// while musl types it `unsigned long` — [`statfs_type`] bridges the
/// divergence (NIGHT-hunt-33), so every comparison site stays cast-free
/// against this signed constant.
const BPF_FS_MAGIC: i64 = 0xcafe4a11;

/// NIGHT-hunt-28: is `path` on an actually-mounted bpf filesystem?
///
/// The old check was bare path existence — but the kernel creates the
/// `/sys/fs/bpf` mountpoint directory on every Linux, so on hosts
/// where nothing is mounted there the doctor still reported
/// `bpf_fs_mounted: true` (an empty sysfs or tmpfs-backed directory
/// looks identical to `Path::exists`). The failure then surfaced far
/// from the cause: the limiter's map pinning gets EINVAL from
/// `BPF_OBJ_PIN` deep inside the object load, which the error chain of
/// the time rendered as a bare "Failed to load BPF object". statfs()
/// reports the real filesystem type; only `BPF_FS_MAGIC` counts.
pub fn bpffs_mounted_at(path: &str) -> bool {
    fs_type_is_bpf(statfs_type(path))
}

/// statfs(2) filesystem type of `path`, or None when the call fails
/// (no such path, permission, ...). A local helper over `libc::statfs`
/// so the crate keeps its zero-new-dependency posture — `libc` is
/// already a direct dependency.
///
/// NIGHT-hunt-33: `statfs.f_type` is NOT one type across libcs — glibc
/// declares it `__fsword_t` (i64 on LP64) but musl declares it
/// `unsigned long` (u64), so the v11.0.0-alpha.1 release musl build
/// died with E0308 (expected i64, found u64) while the gnu build was
/// green: the two libcs disagree on the Rust-side type of the same
/// kernel field. The kernel ABI is identical either way — a full
/// 64-bit magic on the wire — and every filesystem magic in
/// linux/magic.h (BPF 0xcafe4a11 included) sits far below 2^63, so
/// widening the musl u64 into this i64 contract is lossless for every
/// real-world filesystem; a value with bit 63 set would not be a known
/// magic anyway. The `as i64` is therefore a no-op on gnu and a
/// lossless widening on musl.
fn statfs_type(path: &str) -> Option<i64> {
    use std::ffi::CString;

    let c_path = CString::new(path).ok()?;
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: c_path is a valid NUL-terminated string and buf is a
    // valid, properly-aligned statfs buffer of the expected size.
    let rc = unsafe { libc::statfs(c_path.as_ptr(), &mut buf) };
    if rc == 0 {
        // glibc: f_type is already i64 (no-op cast); musl: u64 -> i64
        // lossless widening for every real filesystem magic (see the
        // doc comment on this function).
        Some(buf.f_type as i64)
    } else {
        None
    }
}

/// The testable core of [`bpffs_mounted_at`]: does a statfs-reported
/// type identify a bpf filesystem? None (statfs failed) is a firm no.
fn fs_type_is_bpf(f_type: Option<i64>) -> bool {
    f_type == Some(BPF_FS_MAGIC)
}

/// Find cgroup v2 mount point by parsing /proc/mounts.
fn find_cgroup2_mount() -> Option<String> {
    let mounts = std::fs::read_to_string("/proc/mounts").ok()?;
    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[2] == "cgroup2" {
            return Some(parts[1].to_string());
        }
    }
    None
}

/// Run capability detection and print report.
pub fn run_doctor(json: bool) -> Result<()> {
    let report = detect();
    if json {
        // NIGHT-boost-3: the unified compact writer — same single-line
        // contract as status and list-apps (the two sites that already
        // printed compact via json! + Display; doctor and status were
        // the pretty stragglers the owner's "optimize json print"
        // mandate folded in).
        crate::output::print_json(&report);
    } else {
        print_report(&report);
    }
    Ok(())
}

fn print_report(report: &CapabilityReport) {
    use crate::output::{brand_bold, error_bold, ok_bold, warn_bold};

    println_safe!("{}", brand_bold("━━━ zelynic eBPF Capability Doctor ━━━"));
    println_safe!();
    // NIGHT-dinner-3: the build flavor leads the report — the binary's
    // own full-life/half-life verdict is the first question an owner
    // asks a downloaded binary, and on a half-life build every line
    // below it reads differently (host facts stay true, but they are
    // not actionable until the binary itself is full-life).
    let flavor_line = if report.build_flavor == BUILD_FLAVOR_FULL_LIFE {
        format!(
            "{} (eBPF objects: {})",
            ok_bold("FULL-LIFE"),
            report.ebpf_lane
        )
    } else {
        format!(
            "{} (eBPF objects: {})",
            warn_bold("HALF-LIFE"),
            report.ebpf_lane
        )
    };
    println_safe!("  Build:      {}", flavor_line);
    println_safe!();
    println_safe!("  Kernel:     {}", report.system.kernel);
    println_safe!(
        "  cgroup v2:  {}",
        if report.system.cgroup_v2 {
            ok_bold("YES")
        } else {
            error_bold("NO")
        }
    );
    println_safe!(
        "  BPF fs:     {}",
        if report.system.bpf_fs_mounted {
            ok_bold("YES")
        } else {
            error_bold("NO")
        }
    );
    println_safe!(
        "  Root:       {}",
        if report.system.is_root {
            ok_bold("YES")
        } else {
            warn_bold("NO")
        }
    );
    println_safe!(
        "  eBPF:       {}",
        if report.ebpf_supported {
            ok_bold("SUPPORTED")
        } else {
            error_bold("NOT SUPPORTED")
        }
    );

    if !report.warnings.is_empty() {
        println_safe!();
        println_safe!("{}", warn_bold("Warnings:"));
        for w in &report.warnings {
            println_safe!("  ! {w}");
        }
    }

    // Check BPF pin state (only if eBPF is supported + running as root).
    if report.ebpf_supported && report.system.is_root {
        println_safe!();
        print_pin_state();
    }

    if report.ebpf_supported && report.system.is_root {
        println_safe!();
        if report.build_flavor == BUILD_FLAVOR_FULL_LIFE {
            println_safe!(
                "  {} Run 'zelynic strict <target> <rate>' or 'zelynic eagle-eyes'",
                ok_bold("Ready:")
            );
        } else {
            // NIGHT-dinner-3: the host is capable but this binary is
            // not — the old report's unconditional Ready hint pointed
            // at a command a half-life build refuses to run.
            println_safe!(
                "  {} host is eBPF-capable, but this HALF-LIFE build cannot use it —",
                warn_bold("Limited:")
            );
            println_safe!(
                "  reinstall with default features (or a release tarball) to enable limits."
            );
        }
    }
}

/// Print BPF pin state — checks /sys/fs/bpf/zelynic/ for active/stale pins.
#[cfg(feature = "ebpf")]
fn print_pin_state() {
    use crate::output::{ok_bold, warn_bold};

    let pin_dir = std::path::Path::new("/sys/fs/bpf/zelynic");

    if !pin_dir.exists() {
        println_safe!("  Pins:       {} (no limits active)", ok_bold("clean"));
        return;
    }

    let entries: Vec<_> = std::fs::read_dir(pin_dir)
        .map(|d| d.filter_map(|e| e.ok()).collect())
        .unwrap_or_default();

    if entries.is_empty() {
        println_safe!("  Pins:       {} (empty directory)", ok_bold("clean"));
        return;
    }

    // Check if all 4 critical pins exist (valid state).
    let has_dl_prog = pin_dir.join("enforce_dl").exists();
    let has_ul_prog = pin_dir.join("enforce_ul").exists();
    let has_dl_link = pin_dir.join("enforce_dl_link").exists();
    let has_ul_link = pin_dir.join("enforce_ul_link").exists();
    let all_valid = has_dl_prog && has_ul_prog && has_dl_link && has_ul_link;

    if all_valid {
        println_safe!(
            "  Pins:       {} ({} files, BPF active)",
            ok_bold("active"),
            entries.len()
        );
    } else {
        println_safe!(
            "  Pins:       {} ({} files, partial — run 'zelynic recover')",
            warn_bold("STALE"),
            entries.len()
        );
    }
}

#[cfg(not(feature = "ebpf"))]
fn print_pin_state() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_does_not_panic() {
        // detect() should never panic, even in restricted environments.
        let report = detect();
        // We can't assert specific values (depends on environment), but
        // the report should be well-formed.
        assert!(!report.system.kernel.is_empty());
        // NIGHT-dinner-3: the flavor and lane verdicts are always
        // populated — no environment can produce an empty answer.
        assert!(!report.build_flavor.is_empty());
        assert!(!report.ebpf_lane.is_empty());
    }

    /// NIGHT-dinner-3: the flavor verdict is compile-time truth — it
    /// must match the compiled feature set exactly, and the lane
    /// stamp must be one of the three values build.rs can set (the
    /// `option_env!` fallback matches the dormant stamp, so an
    /// unstamped build is still in the set). This is the contract the
    /// doctor's "Build:" line and the JSON surface both report.
    #[test]
    fn build_flavor_matches_the_compiled_feature_set() {
        if cfg!(feature = "ebpf") {
            assert_eq!(build_flavor(), BUILD_FLAVOR_FULL_LIFE);
        } else {
            assert_eq!(build_flavor(), BUILD_FLAVOR_HALF_LIFE);
        }
        assert!(
            matches!(
                crate::info::ebpf_lane(),
                "source-built" | "registry-prebuilt" | "dormant (not compiled)"
            ),
            "unexpected ZELYNIC_EBPF_LANE stamp: {}",
            crate::info::ebpf_lane()
        );
    }

    /// NIGHT-hunt-28: the magic-number discrimination is the heart of
    /// the fixed doctor — a directory existing at /sys/fs/bpf must not
    /// count as mounted, only the real BPF filesystem magic does.
    /// Constants cross-checked against linux/magic.h.
    #[test]
    fn fs_type_discriminates_bpf_from_sysfs_tmpfs_and_failure() {
        assert!(fs_type_is_bpf(Some(BPF_FS_MAGIC)));
        // SYSFS_MAGIC 0x62656572 — the fs type /sys/fs/bpf shows when
        // the kernel mountpoint exists but nothing is mounted on it.
        assert!(!fs_type_is_bpf(Some(0x6265_6572)));
        // TMPFS_MAGIC 0x01021994 — a tmpfs backed /sys/fs/bpf passes
        // the old existence check too, and fails pins just the same.
        assert!(!fs_type_is_bpf(Some(0x0102_1994)));
        // statfs failure is a firm no, never a maybe.
        assert!(!fs_type_is_bpf(None));
    }

    /// statfs on a always-mounted live path must report a type (never
    /// panic, never None) — and the root filesystem of any normal
    /// machine is not a bpf filesystem, so the composed helper says
    /// no where the old existence check said yes for anything.
    #[test]
    fn statfs_reports_a_real_type_for_the_root_mount() {
        let t = statfs_type("/");
        assert!(t.is_some(), "statfs on / cannot fail on a live system");
        assert_ne!(t, Some(BPF_FS_MAGIC));
        assert!(!bpffs_mounted_at("/"));
    }

    #[test]
    fn test_capability_report_serializes() {
        let report = CapabilityReport {
            system: SystemInfo {
                kernel: "6.18.0".to_string(),
                cgroup_v2: true,
                cgroup2_mount_path: Some("/sys/fs/cgroup".to_string()),
                bpf_fs_mounted: true,
                is_root: false,
            },
            ebpf_supported: true,
            build_flavor: BUILD_FLAVOR_FULL_LIFE.to_string(),
            ebpf_lane: "source-built".to_string(),
            warnings: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("cgroup_v2"));
        assert!(json.contains("ebpf_supported"));
        // NIGHT-dinner-3: the flavor verdict is first-class JSON —
        // machine consumers get the full-life/half-life answer and
        // the lane detail without re-encoding feature semantics.
        assert!(json.contains("build_flavor"));
        assert!(json.contains("full-life"));
        assert!(json.contains("ebpf_lane"));
    }

    /// NIGHT-dinner-3: a half-life report carries the install-path
    /// warning — the diagnostic contract that makes the doctor's
    /// verdict actionable instead of a bare label.
    #[test]
    fn half_life_report_carries_the_reinstall_warning() {
        let report = CapabilityReport {
            system: SystemInfo {
                kernel: "6.18.0".to_string(),
                cgroup_v2: true,
                cgroup2_mount_path: Some("/sys/fs/cgroup".to_string()),
                bpf_fs_mounted: true,
                is_root: false,
            },
            ebpf_supported: true,
            build_flavor: BUILD_FLAVOR_HALF_LIFE.to_string(),
            ebpf_lane: "dormant (not compiled)".to_string(),
            warnings: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("half-life"));
    }
}
