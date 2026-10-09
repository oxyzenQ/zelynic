// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// night-improve-66 (the build.rs split the 600-line law demanded):
// the binary's own identity stamps — the rustc that compiled it and
// the profile facts. Extracted from main() so the crate root stays
// under the cap (the build/flags.rs precedent, a pure move).

/// Stamp the compile-time identity env vars the doctor's BUILD block
/// reads (night-improve-66):
///
/// - `ZELYNIC_RUSTC_VERSION` — cosmostrix doctor parity: the exact
///   compiler that produced this binary. `RUSTC` is the path cargo
///   itself drives (the rust-toolchain.toml pin for root builds), so
///   `--version` is the toolchain truth, not a PATH guess; the first
///   line carries the whole "rustc X.Y.Z (hash DATE)" shape. The
///   fallback "unknown" only fires on a compiler that cannot answer
///   `--version` — which cannot produce a binary either, so the
///   doctor never lies.
/// - `ZELYNIC_PROFILE` + `ZELYNIC_OPT_LEVEL` — the profile mode
///   ("release"/"debug") and the actual optimization level cargo
///   used, handed to build scripts by cargo itself, so the doctor
///   states the real mode instead of guessing from a release-only
///   assumption. The deeper release contract (lto/panic/strip/
///   codegen-units) stays in the source's info module — pinned
///   against Cargo.toml by a unit test, not stamped here, because
///   cargo exposes no env for them and a hand-parsed manifest read
///   would be the fragile lane this repo avoids.
pub(crate) fn stamp_identity() {
    println!("cargo:rerun-if-env-changed=RUSTC");
    let rustc_bin = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let rustc_version = std::process::Command::new(&rustc_bin)
        .arg("--version")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|stdout| stdout.lines().next().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=ZELYNIC_RUSTC_VERSION={rustc_version}");

    println!("cargo:rerun-if-env-changed=PROFILE");
    println!("cargo:rerun-if-env-changed=OPT_LEVEL");
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());
    let opt_level = std::env::var("OPT_LEVEL").unwrap_or_else(|_| "?".to_string());
    println!("cargo:rustc-env=ZELYNIC_PROFILE={profile}");
    println!("cargo:rustc-env=ZELYNIC_OPT_LEVEL={opt_level}");
}
