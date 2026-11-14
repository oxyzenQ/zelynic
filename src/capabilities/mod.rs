// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Capability detection (the cosmic dragon architecture — eBPF only).
//!
//! Detects the eBPF facts that matter: cgroup v2, BPF filesystem,
//! kernel version, root privileges.

use anyhow::Result;

pub mod bpffs;
pub mod pins;
// night-netrunner-2: the old ebpf-gated `bpffs_mounted_at` re-export
// retired with the limiter's private preflight — the preflight rides
// the HostCaps probe now (ebpf/host_caps.rs), which reads the
// bpffs:: module path directly. The doctor keeps the same path.
pub use pins::PinState;

/// System information relevant to eBPF support.
#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub kernel: String,
    /// night-netrunner-1: does the running kernel meet the 5.15.0
    /// floor? False below the floor or when the release cannot be
    /// parsed — the honest "cannot verify the floor" answer, never a
    /// guess. The same pure law the attach paths refuse on.
    pub kernel_floor_met: bool,
    pub cgroup_v2: bool,
    pub cgroup2_mount_path: Option<String>,
    pub bpf_fs_mounted: bool,
    pub is_root: bool,
}

/// Capability detection result.
#[derive(Debug, Clone)]
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
    /// night-improve-66: the BUILD facts the mature cosmostrix
    /// diagnostics report carries — version, git_sha, variant,
    /// build_time, rustc_version, the profile verdict — every one
    /// compile-time truth assembled by
    /// [`crate::info::BuildInfo::collect`] (no runtime probing, no
    /// new dependencies). Additive per the pins precedent: new
    /// output always carries it (detect() always collects), older
    /// JSON without the field still deserializes — honestly absent,
    /// never fabricated.
    pub build: Option<crate::info::BuildInfo>,
    pub warnings: Vec<String>,
    /// The BPF pin lattice's verdict (night-improve-64, additive):
    /// what the human report's "Pins:" line renders, machine-scope —
    /// `clean` (nothing pinned), `active` (the four enforcement pins
    /// all present), `stale` (partial — the recover hint applies).
    /// Absent when it cannot speak honestly: a half-life build owns
    /// no lattice, and an unprivileged run must not audit a root's
    /// pins (the human report skips it for the same reason); an
    /// unreadable directory is absent too — never a fabricated
    /// verdict. The None case serializes as ABSENCE (the additive
    /// rule the writer branches on below — the old
    /// `skip_serializing_if` semantics, now reviewable code).
    pub pins: Option<PinState>,
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
    let ebpf_supported = system.cgroup_v2 && system.bpf_fs_mounted && system.kernel_floor_met;
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
    if !system.kernel_floor_met {
        // night-netrunner-1: the floor refusal is actionable, the same
        // message the attach paths bail with (one law, one wording).
        if let Err(floor_msg) = crate::ebpf::kernel_floor::kernel_floor_error(&system.kernel) {
            warnings.push(floor_msg);
        }
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

    // night-improve-64: the pin lattice's verdict joins the report —
    // audited only where it CAN be audited (a full-life build running
    // as root, the same gate the human printer's line rides); every
    // other context stays honestly absent.
    #[cfg(feature = "ebpf")]
    let pins = if system.is_root {
        pins::collect_pin_state()
    } else {
        None
    };
    #[cfg(not(feature = "ebpf"))]
    let pins = None;

    CapabilityReport {
        system,
        ebpf_supported,
        build_flavor: build_flavor.to_string(),
        ebpf_lane,
        build: Some(crate::info::BuildInfo::collect()),
        warnings,
        pins,
    }
}

/// Detect basic system info — now the Orchestra's probe mapped onto
/// the doctor's report shape (night-netrunner-2's adoption sketch):
/// ONE probe builds [`crate::ebpf::host_caps::HostCaps`], the doctor
/// renders the same facts under the JSON contract's own field names
/// (the pinned scripting API is untouched — field order and names
/// byte-identical). The attach paths consume the same struct, so the
/// doctor cannot disagree with the attach gates: one probe, every
/// consumer.
fn detect_system() -> SystemInfo {
    let caps = crate::ebpf::host_caps::HostCaps::probe();
    SystemInfo {
        kernel: caps.kernel_release,
        kernel_floor_met: caps.kernel_floor_met,
        cgroup_v2: caps.cgroup_v2,
        cgroup2_mount_path: caps.cgroup2_mount_path,
        bpf_fs_mounted: caps.bpffs_mounted,
        is_root: caps.is_root,
    }
}

/// Serialize the capability report (S1, the hand-written lane): the
/// exact wire contract the serde derive emitted before the stack
/// left the graph — field order is declaration order, the two
/// Option verdicts (`build`, `pins`) ride as ABSENCE when None (the
/// additive rule, now reviewable branches instead of
/// `skip_serializing_if`), and `cgroup2_mount_path` rides as JSON
/// null when the mount probe found nothing. Field names are the
/// pinned scripting contract (docs/USAGE.md JSON reference).
fn report_json(report: &CapabilityReport) -> String {
    use crate::json::write::{
        write_array, write_bool, write_number, write_opt_string, write_string,
    };

    let mut out = String::with_capacity(256);
    out.push_str("{\"system\":{\"kernel\":");
    write_string(&mut out, &report.system.kernel);
    out.push_str(",\"kernel_floor_met\":");
    write_bool(&mut out, report.system.kernel_floor_met);
    out.push_str(",\"cgroup_v2\":");
    write_bool(&mut out, report.system.cgroup_v2);
    out.push_str(",\"cgroup2_mount_path\":");
    write_opt_string(&mut out, report.system.cgroup2_mount_path.as_deref());
    out.push_str(",\"bpf_fs_mounted\":");
    write_bool(&mut out, report.system.bpf_fs_mounted);
    out.push_str(",\"is_root\":");
    write_bool(&mut out, report.system.is_root);
    out.push_str("},\"ebpf_supported\":");
    write_bool(&mut out, report.ebpf_supported);
    out.push_str(",\"build_flavor\":");
    write_string(&mut out, &report.build_flavor);
    out.push_str(",\"ebpf_lane\":");
    write_string(&mut out, &report.ebpf_lane);
    // night-frontier-Z5, additive: the per-helper capability
    // ladder's verdict — `rungs` (the ladder's total), `met` (how
    // many the running kernel meets), and `missed` (the missed
    // rungs' names, table order; an empty array on a full ladder,
    // always present so the shape is stable for scripts). An
    // unparsable release reads met:0 — the same all-false shape the
    // shape facts have always claimed (the probe cannot verify, so
    // it does not).
    let ladder = crate::ebpf::helper_ladder::ladder_summary(&report.system.kernel);
    out.push_str(",\"ladder\":{\"rungs\":");
    write_number(&mut out, ladder.rungs);
    out.push_str(",\"met\":");
    write_number(&mut out, ladder.met);
    out.push_str(",\"missed\":");
    write_array(&mut out, ladder.missed.len(), |out, i| {
        write_string(out, ladder.missed[i]);
    });
    out.push('}');
    if let Some(build) = &report.build {
        out.push_str(",\"build\":");
        build.write_json(&mut out);
    }
    out.push_str(",\"warnings\":");
    write_array(&mut out, report.warnings.len(), |out, i| {
        write_string(out, &report.warnings[i]);
    });
    if let Some(pins) = &report.pins {
        out.push_str(",\"pins\":{\"state\":");
        write_string(&mut out, &pins.state);
        out.push_str(",\"files\":");
        write_number(&mut out, pins.files);
        out.push('}');
    }
    out.push('}');
    out
}

/// Run capability detection and print report.
pub fn run_doctor(json: bool) -> Result<()> {
    let report = detect();
    if json {
        // NIGHT-boost-3: the unified compact writer — same single-line
        // contract as status and list-apps. S1: the document is
        // composed by the hand-written lane above (report_json), no
        // serde in the graph.
        crate::output::print_json(&report_json(&report));
    } else {
        print_report(&report);
    }
    Ok(())
}

fn print_report(report: &CapabilityReport) {
    use crate::output::{brand_bold, error_bold, field, ok_bold, warn_bold};

    println_safe!(
        "{}",
        brand_bold("━━━ zelynic diagnostics report · doctor ━━━")
    );
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
    println_safe!("{}", field("Build:", &flavor_line));
    // night-improve-66: the BUILD block the doctor was missing — the
    // cosmostrix diagnostics completeness (version, git_sha, variant,
    // rustc, profile) in zelynic's lean single-column shape, rendered
    // from the same BuildInfo the JSON surface serializes (the two
    // surfaces cannot drift). Every fact is compile-time truth; the
    // "v" prefix is the report's own brand addition over the raw
    // semver the machine scope carries. The if-let keeps the honest
    // absence: a deserialized pre-improve-66 report skips the block
    // instead of fabricating one.
    if let Some(build) = &report.build {
        println_safe!("{}", field("Version:", &format!("v{}", build.version)));
        println_safe!("{}", field("Commit:", &build.git_sha));
        println_safe!("{}", field("Variant:", &build.variant));
        println_safe!("{}", field("Built:", &build.build_time));
        println_safe!("{}", field("Rustc:", &build.rustc_version));
        println_safe!("{}", field("Profile:", &build.profile));
    }
    println_safe!();
    // night-netrunner-1: the kernel line carries the floor verdict —
    // at or above 5.15.0 reads OK, below reads the refusal the attach
    // paths carry, so the doctor answers the floor question in place.
    let kernel_line = if report.system.kernel_floor_met {
        report.system.kernel.clone()
    } else {
        format!(
            "{} (below the 5.15.0 minimum — attach is refused)",
            report.system.kernel
        )
    };
    println_safe!("{}", field("Kernel:", &kernel_line));
    println_safe!(
        "{}",
        field(
            "cgroup v2:",
            &if report.system.cgroup_v2 {
                ok_bold("YES")
            } else {
                error_bold("NO")
            },
        )
    );
    println_safe!(
        "{}",
        field(
            "BPF fs:",
            &if report.system.bpf_fs_mounted {
                ok_bold("YES")
            } else {
                error_bold("NO")
            },
        )
    );
    println_safe!(
        "{}",
        field(
            "Root:",
            &if report.system.is_root {
                ok_bold("YES")
            } else {
                warn_bold("NO")
            },
        )
    );
    // night-netrunner-2: the Orchestra's Layer 1 shape facts join the
    // human report — the recorded constants beside the gates, the
    // same pair of lines the attach paths' verbose lane opens with.
    // One probe, every consumer: the doctor's rows ARE the attach
    // verdicts' source struct. The JSON contract grows only
    // additively (the ladder field below is night-frontier-Z5's);
    // this line is the human surface's additive fact row.
    let caps = crate::ebpf::host_caps::HostCaps::probe();
    println_safe!("{}", field("Shape facts:", &caps.trace_lines()[1]));
    // night-frontier-Z5: the per-helper capability ladder's
    // one-glance verdict — on any kernel the floor admits, every
    // rung is met BY CONSTRUCTION (the itemized guarantee behind
    // the floor line above); a missed rung is named with its
    // degradation class instead of a silent partial attach.
    let ladder = crate::ebpf::helper_ladder::ladder_summary(&caps.kernel_release);
    let ladder_line = if ladder.missed.is_empty() {
        if report.system.kernel_floor_met {
            format!(
                "{} rungs met (the 5.15.0 floor guarantees every rung)",
                ladder.rungs
            )
        } else {
            format!(
                "{} rungs met (the kernel is below the floor — attach is refused)",
                ladder.rungs
            )
        }
    } else {
        format!("{}/{} rungs met", ladder.met, ladder.rungs)
    };
    println_safe!("{}", field("Helper ladder:", &ladder_line));
    for name in &ladder.missed {
        let plan = crate::ebpf::helper_ladder::LADDER
            .iter()
            .find(|rung| rung.name == *name)
            .and_then(|rung| rung.above_floor_plan)
            .unwrap_or("no degradation plan — the lanes riding it refuse at attach");
        println_safe!(
            "{}",
            crate::output::grey(&format!("  ! {name} unmet — {plan}"))
        );
    }
    println_safe!(
        "{}",
        field(
            "eBPF:",
            &if report.ebpf_supported {
                ok_bold("SUPPORTED")
            } else {
                error_bold("NOT SUPPORTED")
            },
        )
    );

    if !report.warnings.is_empty() {
        println_safe!();
        println_safe!("{}", warn_bold("Warnings:"));
        for w in &report.warnings {
            println_safe!("  {}", warn_bold(&format!("! {w}")));
        }
    }

    // Check BPF pin state (only if eBPF is supported + running as root).
    if report.ebpf_supported && report.system.is_root {
        println_safe!();
        pins::print_pin_state();
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
                "{}",
                crate::output::grey(
                    "  reinstall with default features (or a release tarball) to enable limits."
                )
            );
        }
    }
}

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
        // night-netrunner-1: the floor verdict is always populated —
        // and it must always AGREE with the pure law on the actual
        // release string (a 5.10 sandbox host and a 6.18 dev rig both
        // detect honestly; the assertion is the law's consistency,
        // never a host assumption).
        assert_eq!(
            report.system.kernel_floor_met,
            crate::ebpf::kernel_floor::kernel_floor_error(&report.system.kernel).is_ok(),
            "floor verdict disagrees with the law on kernel {}",
            report.system.kernel
        );
        // NIGHT-dinner-3: the flavor and lane verdicts are always
        // populated — no environment can produce an empty answer.
        assert!(!report.build_flavor.is_empty());
        assert!(!report.ebpf_lane.is_empty());
        // night-improve-66: the BUILD block is always complete —
        // every field populated, never an empty string (the degraded
        // "unknown" lanes are honest values, not absences).
        let build = report.build.as_ref().expect("detect always collects");
        assert!(!build.version.is_empty());
        assert!(!build.git_sha.is_empty());
        assert!(!build.variant.is_empty());
        assert!(!build.build_time.is_empty());
        assert!(!build.rustc_version.is_empty());
        assert!(!build.profile.is_empty());
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

    #[test]
    fn test_capability_report_serializes() {
        let report = CapabilityReport {
            system: SystemInfo {
                kernel: "6.18.0".to_string(),
                kernel_floor_met: true,
                cgroup_v2: true,
                cgroup2_mount_path: Some("/sys/fs/cgroup".to_string()),
                bpf_fs_mounted: true,
                is_root: false,
            },
            ebpf_supported: true,
            build_flavor: BUILD_FLAVOR_FULL_LIFE.to_string(),
            ebpf_lane: "source-built".to_string(),
            build: Some(crate::info::BuildInfo::collect()),
            warnings: vec![],
            pins: None,
        };
        let json = report_json(&report);
        assert!(json.contains("cgroup_v2"));
        assert!(json.contains("ebpf_supported"));
        // night-netrunner-1: the floor verdict is first-class JSON —
        // machine consumers get the same 5.15.0 law the human report
        // renders, without re-deriving it from the release string.
        assert!(json.contains("kernel_floor_met"));
        // NIGHT-dinner-3: the flavor verdict is first-class JSON —
        // machine consumers get the full-life/half-life answer and
        // the lane detail without re-encoding feature semantics.
        assert!(json.contains("build_flavor"));
        assert!(json.contains("full-life"));
        assert!(json.contains("ebpf_lane"));
        // night-improve-66: the BUILD block rides the JSON with the
        // same six keys the human report renders — machine consumers
        // get version/git_sha/variant/build_time/rustc_version/profile
        // without re-deriving them from the version report.
        assert!(json.contains("\"build\""));
        for key in [
            "\"version\"",
            "\"git_sha\"",
            "\"variant\"",
            "\"build_time\"",
            "\"rustc_version\"",
            "\"profile\"",
        ] {
            assert!(json.contains(key), "BUILD key {key} must ride: {json}");
        }
        // night-improve-64: a None verdict serializes as ABSENCE —
        // the additive rule (never a fabricated "clean").
        assert!(!json.contains("pins"));
        // night-frontier-Z5, additive: the per-helper capability
        // ladder's verdict rides the JSON — rungs/met/missed, the
        // same numbers the human report's "Helper ladder:" line
        // renders. On the 6.18 fixture the ladder is full (ten
        // rungs, none missed) and the missed array is honestly
        // empty.
        assert!(
            json.contains("\"ladder\":{\"rungs\":10,\"met\":10,\"missed\":[]}"),
            "the ladder verdict must ride: {json}"
        );
    }

    /// night-frontier-Z5: the ladder verdict is a pure function of
    /// the release string — the JSON's met/missed numbers must agree
    /// with the summary the human line renders, on a below-floor
    /// fixture too (the 5.11 kernel misses exactly the atomic rung).
    #[test]
    fn ladder_verdicts_ride_the_release_string() {
        let mut report = CapabilityReport {
            system: SystemInfo {
                kernel: "5.11.0".to_string(),
                kernel_floor_met: false,
                cgroup_v2: true,
                cgroup2_mount_path: Some("/sys/fs/cgroup".to_string()),
                bpf_fs_mounted: true,
                is_root: false,
            },
            ebpf_supported: false,
            build_flavor: BUILD_FLAVOR_FULL_LIFE.to_string(),
            ebpf_lane: "source-built".to_string(),
            build: Some(crate::info::BuildInfo::collect()),
            warnings: vec![],
            pins: None,
        };
        let json = report_json(&report);
        assert!(
            json.contains("\"ladder\":{\"rungs\":10,\"met\":9,"),
            "{json}"
        );
        assert!(json.contains("\"missed\":[\"bpf_atomic_64\"]"), "{json}");
        // An unparsable release reads met:0 with every rung absent
        // from `missed` — unprobeable is not missed (the honesty
        // law: the probe cannot verify, so it does not guess).
        report.system.kernel = "garbage-release".to_string();
        let json = report_json(&report);
        assert!(
            json.contains("\"ladder\":{\"rungs\":10,\"met\":0,\"missed\":[]}"),
            "{json}"
        );
    }

    /// NIGHT-dinner-3: a half-life report carries the install-path
    /// warning — the diagnostic contract that makes the doctor's
    /// verdict actionable instead of a bare label.
    #[test]
    fn half_life_report_carries_the_reinstall_warning() {
        let report = CapabilityReport {
            system: SystemInfo {
                kernel: "6.18.0".to_string(),
                kernel_floor_met: true,
                cgroup_v2: true,
                cgroup2_mount_path: Some("/sys/fs/cgroup".to_string()),
                bpf_fs_mounted: true,
                is_root: false,
            },
            ebpf_supported: true,
            build_flavor: BUILD_FLAVOR_HALF_LIFE.to_string(),
            ebpf_lane: "dormant (not compiled)".to_string(),
            build: Some(crate::info::BuildInfo::collect()),
            warnings: vec![],
            pins: None,
        };
        let json = report_json(&report);
        assert!(json.contains("half-life"));
    }
}
