// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

fn main() {
    // Re-run build.rs whenever git HEAD changes so GIT_HASH stays fresh.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/");

    // NIGHT-improve-1 phase 3: drive the pure-Rust eBPF object build
    // for ebpf-feature builds (see build_ebpf_objects below).
    build_ebpf_objects();

    // Forward the ZELYNIC_BUILD label into the compile-time env consumed
    // by info::build_label() (cosmostrix canonical_build_label lineage).
    // The label is set by the cargo aliases pro-native-gnu /
    // pro-native-musl (.cargo/config.toml `env.ZELYNIC_BUILD=...`) or by
    // CI/release scripts exporting it directly. Tracked via
    // rerun-if-env-changed so switching between an alias build and a
    // plain build recompiles the crate and the version report never
    // shows a stale label.
    println!("cargo:rerun-if-env-changed=ZELYNIC_BUILD");
    if let Ok(label) = std::env::var("ZELYNIC_BUILD") {
        println!("cargo:rustc-env=ZELYNIC_BUILD={label}");
    }

    // Commit-sha resolution chain (NIGHT-ask-1, cosmostrix
    // packaged_vcs_sha lineage), first hit wins:
    //   1. `git rev-parse --short=7 HEAD` — local/git checkouts.
    //   2. `GITHUB_SHA` env — CI environments (full 40-hex sha,
    //      normalized to the same 7-char short shape).
    //   3. `.cargo_vcs_info.json` — registry tarball builds (`cargo
    //      install zelynic`): cargo embeds this file in the published
    //      package with the sha1 of the commit the crate was packaged
    //      from, so builds without a .git directory still recover the
    //      exact source revision. Previously the chain dead-ended at
    //      the git probe and a registry build reported `unknown`.
    let git_hash = git_short_sha()
        .or_else(|| env_short_sha("GITHUB_SHA"))
        .or_else(packaged_vcs_sha)
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=GIT_HASH={}", git_hash);
    // The registry fallback rides a file that only exists inside a
    // packed crate (and appears the moment cargo packs one) — watching
    // the path keeps a dev checkout and a registry extract from
    // sharing one stale cached build.rs verdict.
    println!("cargo:rerun-if-changed=.cargo_vcs_info.json");

    // Build timestamp (NIGHT-hunt-6, cosmostrix lineage): computed from
    // SystemTime via Howard Hinnant's civil_from_days algorithm — std only,
    // no chrono and no [build-dependencies]. Freshness equals the build.rs
    // run time: re-executed whenever git HEAD, ZELYNIC_BUILD, or source
    // inputs change (cargo's standard build-script caching).
    let build_time = format_build_time_utc();
    println!("cargo:rustc-env=ZELYNIC_BUILD_TIME={build_time}");

    // night-improve-66: the doctor's BUILD block identity — the rustc
    // that compiled this binary plus the profile facts — lives in
    // build/identity.rs (the 600-line split; a pure move).
    identity::stamp_identity();
}

///
/// With the `ebpf` feature on, the shipped BPF objects are the
/// aya-ebpf crate's own binaries (zelynic-observer / zelynic-limiter)
/// cross-compiled for bpfel-unknown-none by a NESTED cargo invocation
/// with cwd inside ebpf/. The nested build resolves ebpf/
/// rust-toolchain.toml (the dated nightly pin — the bpfel target needs
/// -Z build-std, nightly-only by design) and ebpf/.cargo/config.toml
/// (target + build-std), and compiles into ebpf/target — its own
/// target directory, because the crate is a detached workspace on
/// purpose: no package-graph or lock overlap with this root build, so
/// a stable-toolchain cargo can drive a nightly sub-build safely.
/// The artifacts are copied into OUT_DIR, where the loaders embed them
/// via include_bytes!
///
/// Prerequisites (one-time per machine, one command —
/// scripts/dev/bootstrap-ebpf.sh; see ebpf/rust-toolchain.toml and
/// docs/PURE_RUST_EVALUATION.md): the dated nightly with rust-src,
/// and the bpf-linker 0.11.1 prebuilt binary on PATH. The preflight
/// (NIGHT-host-1) below fails fast, naming the exact missing piece
/// and the one-command fix. An ebpf-feature build is a pure-Rust
/// build — there is no C fallback.
///
/// A dormant build (feature off — `--no-default-features`, since
/// NIGHT-ask-2 made `ebpf` the default) never enters the nightly path
/// at all: the dormant-mode stable-toolchain contract of the root
/// build is unchanged.
///
/// The dated nightly pin driving the nested cross-build — mirrors
/// ebpf/rust-toolchain.toml (which the nested build resolves from its
/// own directory) and the pin scripts/dev/bootstrap-ebpf.sh installs on
/// hosts. Bump all three together (docs/PURE_RUST_EVALUATION.md
/// records why a dated pin, never a floating channel).
const EBPF_TOOLCHAIN: &str = "nightly-2026-09-18";

fn build_ebpf_objects() {
    let manifest_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let ebpf_dir = manifest_dir.join("ebpf");

    // Rerun triggers: the ebpf crate's sources and its build wiring.
    // ebpf/target is deliberately NOT watched — the nested cargo owns
    // its own freshness, and watching build output would loop.
    for rel in [
        "src",
        "Cargo.toml",
        "Cargo.lock",
        ".cargo/config.toml",
        "rust-toolchain.toml",
    ] {
        println!("cargo:rerun-if-changed={}", ebpf_dir.join(rel).display());
    }

    // Only the ebpf feature needs the objects.
    if std::env::var_os("CARGO_FEATURE_EBPF").is_none() {
        // NIGHT-ask-2: the lane stamp consumed by info::ebpf_lane()
        // so `zelynic -V` reports which path built (or skipped) the
        // objects — dormant builds say so instead of staying silent.
        println!("cargo:rustc-env=ZELYNIC_EBPF_LANE=dormant (not compiled)");
        return;
    }

    // NIGHT-ask-2: the registry lane. Cargo's package walk
    // auto-excludes nested packages (any directory carrying its own
    // Cargo.toml), so a crates.io source extract carries no ebpf/
    // tree — verified live on this manifest twice, including with
    // ebpf/* patterns in `include` (NIGHT-ask-1). The lane that makes
    // a plain `cargo install zelynic` land the FULL-FEATURED binary
    // without a nightly toolchain stages the maintainer-built objects
    // from ebpf-prebuilt/ — the same bytes the GitHub Release
    // binaries embed, so kernel compatibility is identical by
    // construction. Provenance lives in ebpf-prebuilt/manifest.toml;
    // scripts/gates/check-prebuilt-parity.sh pins its freshness
    // against the live ebpf/ tree. The old NIGHT-ask-1 fail-fast
    // panic survives as the LAST resort inside the staging helper: a
    // tarball that lost the prebuilt lane is an incomplete crate, not
    // a supported configuration.
    if !ebpf_dir.join("Cargo.toml").is_file() {
        stage_registry_prebuilt_objects(&manifest_dir);
        return;
    }

    // NIGHT-host-1: preflight the two host prerequisites BEFORE the
    // nested build, so a failure names the exact missing piece and
    // the one-command fix (scripts/dev/bootstrap-ebpf.sh) instead of
    // surfacing rustup's or the linker's raw error text after the
    // dependency tree has already compiled — and so a missing
    // bpf-linker is caught even when ebpf/target is fully cached (a
    // warm nested build skips the link step, so without this check
    // the prerequisite violation passes silently and only explodes
    // on the next clean build — reproduced while testing this
    // change).
    preflight_ebpf_prerequisites(EBPF_TOOLCHAIN);

    // The invocation itself — toolchain forcing, cwd, environment
    // hygiene — lives in run_nested_ebpf_build below, factored out so
    // the NIGHT-hunt-29 self-heal in the staging step can force a
    // second run after deleting a damaged artifact.
    run_nested_ebpf_build(&ebpf_dir);

    // NIGHT-hunt-29: stage both objects into OUT_DIR for include_bytes!
    // embedding — read plus STRUCTURAL validation, and when an
    // artifact is damaged, self-heal instead of failing the build:
    // delete every on-disk copy (see delete_damaged_artifact — cargo
    // keeps a canonical copy BESIDE the published name, and only a
    // missing canonical copy forces the unit dirty again) and re-run
    // the nested build once. The hard-panic alternative strands a
    // user host: cargo's freshness never re-verifies output
    // integrity, so every later build would re-embed the same corpse
    // and die at load time with "error parsing BPF object: error
    // parsing ELF data". The hunt record lives on
    // validate_ebpf_object below.
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let release_dir = ebpf_dir
        .join("target")
        .join("bpfel-unknown-none")
        .join("release");
    let mut staged: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut damaged: Vec<(&str, String)> = Vec::new();
    for name in ["zelynic-observer", "zelynic-limiter"] {
        match read_validated_ebpf_object(&release_dir.join(name)) {
            Ok(data) => staged.push((name, data)),
            Err(problem) => damaged.push((name, problem)),
        }
    }
    if !damaged.is_empty() {
        // cargo:warning lines always render (plain build-script stdout
        // is captured and only replayed on failure), so the repair is
        // visible in the build log without -vv.
        for (name, problem) in &damaged {
            println!(
                "cargo:warning=eBPF object {name} failed validation ({problem}) — \
                 forcing one rebuild of it"
            );
            delete_damaged_artifact(&release_dir, name);
        }
        run_nested_ebpf_build(&ebpf_dir);
        for (name, first_problem) in &damaged {
            let data = read_validated_ebpf_object(&release_dir.join(name)).unwrap_or_else(
                |second_problem| {
                    panic!(
                        "eBPF object {name} is damaged again immediately after a \
                         forced rebuild — before: {first_problem}; after: \
                         {second_problem}. Either bpf-linker is producing a broken \
                         object (reinstall the pin: ./scripts/dev/bootstrap-ebpf.sh), or \
                         something on this host is modifying build outputs as they \
                         land (indexer, antivirus, full disk)"
                    )
                },
            );
            staged.push((*name, data));
        }
    }
    for (name, data) in staged {
        let dst = out_dir.join(name);
        std::fs::write(&dst, &data)
            .unwrap_or_else(|e| panic!("failed to stage {} into OUT_DIR: {e}", dst.display()));
    }

    // NIGHT-ask-2: the lane stamp for the source-built path — see
    // the dormant early-return above and the registry lane below.
    println!("cargo:rustc-env=ZELYNIC_EBPF_LANE=source-built");
}

/// NIGHT-ask-2: stage the two prebuilt eBPF objects for a registry
/// source extract — the lane that makes `cargo install zelynic`
/// full-featured on a plain stable toolchain.
///
/// The objects are the maintainer-built release artifacts tracked in
/// ebpf-prebuilt/ (generated by scripts/release/refresh-prebuilt.sh,
/// which drives this repo's own validated build pipeline and records
/// provenance in ebpf-prebuilt/manifest.toml). They are the SAME
/// bytes the GitHub Release binaries embed, so a registry install and
/// a release tarball have identical kernel compatibility — the
/// CO-RE objects carry no host assumptions.
///
/// Every object passes the same NIGHT-hunt-29 structural validation
/// the nested lane applies (`read_validated_ebpf_object`), then lands
/// in OUT_DIR under the exact names the loaders' include_bytes!
/// concat paths expect — the embedding pipeline downstream of this
/// point is byte-for-byte the nested lane's. A missing or damaged
/// prebuilt object panics with the honest diagnosis: the crate is
/// INCOMPLETE (the prebuilt lane did not survive packaging), and the
/// remedies are the git checkout build and the GitHub Release binary.
fn stage_registry_prebuilt_objects(manifest_dir: &std::path::Path) {
    let prebuilt_dir = manifest_dir.join("ebpf-prebuilt");
    // Watched only on the lane that consumes it: a git checkout
    // builds its objects from ebpf/ and never reads this directory,
    // so refreshing the prebuilt lane must not rebuild such trees.
    println!("cargo:rerun-if-changed={}", prebuilt_dir.display());
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    for name in ["zelynic-observer", "zelynic-limiter"] {
        let data = read_validated_ebpf_object(&prebuilt_dir.join(name)).unwrap_or_else(|problem| {
            panic!(
                "the ebpf feature was requested from a registry tarball (no ebpf/ \
                 workspace rides a registry package — cargo's package walk cannot \
                 carry nested packages), and the prebuilt object {name} is missing or \
                 damaged ({problem}). This crate is INCOMPLETE: the ebpf-prebuilt/ lane \
                 that makes `cargo install zelynic` full-featured did not survive \
                 packaging. Report it, and meanwhile build from a git checkout (git \
                 clone https://github.com/oxyzenQ/zelynic, then cargo build --release \
                 --features ebpf) or install the flagship binary from GitHub Releases \
                 — see docs/VERIFY_RELEASE.md for both channels"
            )
        });
        let dst = out_dir.join(name);
        std::fs::write(&dst, &data)
            .unwrap_or_else(|e| panic!("failed to stage {} into OUT_DIR: {e}", dst.display()));
    }
    // The lane stamp consumed by info::ebpf_lane(): `zelynic -V`
    // answers "eBPF objects: registry-prebuilt", and the provenance
    // (source tree pin, toolchain, linker) rides the shipped
    // ebpf-prebuilt/manifest.toml.
    println!("cargo:rustc-env=ZELYNIC_EBPF_LANE=registry-prebuilt");
}

/// The nested eBPF cross-build invocation, factored out of
/// [`build_ebpf_objects`] so the NIGHT-hunt-29 self-heal can force a
/// second run after deleting a damaged artifact. Same command, same
/// environment hygiene, same failure panics — nothing about the
/// happy path changes.
///
/// Invoke the nested build through `rustup run <pin> cargo` — the
/// aya-build upstream lesson: the CARGO env var handed to build
/// scripts points at the RESOLVED toolchain cargo (stable 1.98.1
/// here), which bypasses rustup's toolchain-file resolution and
/// would silently drop the nightly-only -Z build-std flag. Forcing
/// the toolchain through rustup makes the sub-build deterministic
/// regardless of how this build script was invoked. cwd inside
/// ebpf/ keeps the crate's own .cargo/config.toml in effect;
/// target and build-std are ALSO passed explicitly so the
/// invocation is correct even without the config. Environment is
/// inherited so CI's strict RUSTFLAGS contract covers this crate
/// too — with one carved-out exception (NIGHT-hunt-28): the
/// rustflags themselves pass through strip_host_poison_rustflags
/// first, because host-CPU and host-linker flags are poison for
/// the bpfel cross-build (see that function's doc comment).
/// --locked keeps the committed Cargo.lock authoritative.
/// Stdio is inherited: the nested build's own compiler output
/// streams through to the user/CI log.
fn run_nested_ebpf_build(ebpf_dir: &std::path::Path) {
    let mut nested = std::process::Command::new("rustup");
    nested
        .args(["run", EBPF_TOOLCHAIN, "cargo"])
        .current_dir(ebpf_dir)
        .args([
            "build",
            "--release",
            "--locked",
            "--target",
            // NIGHT-boost-38: the repo-local spec clone (ebpf/
            // bpfel-unknown-none.json) — identical to the builtin
            // bpfel-unknown-none except `atomic-cas: true`, which
            // unblocks core's 64-bit atomic RMW (fetch_add /
            // compare_exchange) so the SMP-safe token bucket in
            // ebpf/src/math.rs compiles. The builtin spec still
            // carries the pre-5.12 `atomic-cas: false` even though
            // the ISA (BPF_ATOMIC, Linux 5.12+) and the verified
            // floor (5.13) both support it. The file stem keeps the
            // artifact directory at target/bpfel-unknown-none/, so
            // every consumer of that path (this file, ci.yml
            // artifact checks, cache keys) is untouched.
            "bpfel-unknown-none.json",
        ])
        .args(["-Z", "build-std=core"])
        // NIGHT-boost-38: a JSON target spec (ebpf/
        // bpfel-unknown-none.json) needs this unstable cargo flag on
        // the same invocation; the dated nightly pin makes it a
        // constant, not a variable.
        .args(["-Z", "json-target-spec"])
        // The aya-build upstream workaround: the parent cargo exports
        // RUSTC pointing at the ROOT build's (stable) rustc — without
        // removing it, the nightly sub-build would compile build-std
        // core with the stable compiler and fail on its missing
        // rust-src. The sub-build must resolve its own rustc.
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER");
    strip_host_poison_rustflags(&mut nested);
    force_bpf_v3_rustflags(&mut nested);
    let status = nested.status().unwrap_or_else(|e| {
        panic!(
            "failed to launch `rustup run {EBPF_TOOLCHAIN} cargo` — rustup is a \
             hard prerequisite of the pure-Rust eBPF build: {e}"
        )
    });
    if !status.success() {
        // The preflight already verified both prerequisites present,
        // so reaching this branch means a real compile/link failure:
        // the nested build's own output above is the diagnosis.
        panic!(
            "the pure-Rust eBPF build failed with prerequisites present \
             ({EBPF_TOOLCHAIN} and bpf-linker were both verified by the \
             preflight) — the nested cargo output above is the actual \
             error (rationale: docs/PURE_RUST_EVALUATION.md)"
        );
    }
}

/// NIGHT-hunt-29: remove every on-disk copy of one damaged eBPF
/// artifact so the nested cargo run that follows is forced to RELINK
/// it — the second half of the self-heal (validation is the first).
///
/// Two locations, both required. Cargo's target layout keeps the
/// canonical unit output in
/// `build/zelynic-ebpf/<fingerprint-hash>/out/<name-with-underscores>`
/// and publishes a HARDLINK at
/// `bpfel-unknown-none/release/<name-with-dashes>` — the published
/// name and the canonical copy share one inode, so damage through
/// either name corrupts both. Deleting only the published name
/// changes nothing (verified empirically on the nested cargo):
/// cargo sees the canonical copy intact, declares the unit fresh,
/// and silently re-publishes the corpse — a 0.05s "Finished" with
/// the damaged file resurrected, mtime untouched. A missing CANONICAL
/// output is what actually dirties the unit: with both copies gone
/// the relink is forced ("Compiling zelynic-ebpf", sub-second on a
/// warm tree, verified with a byte-identical-to-good result). All
/// fingerprint-hash subdirectories are swept because which one is
/// current depends on the parent build's rustflags environment.
fn delete_damaged_artifact(release_dir: &std::path::Path, name: &str) {
    let published = release_dir.join(name);
    if let Err(e) = std::fs::remove_file(&published)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        panic!(
            "failed to delete the damaged eBPF object {}: {e} — cannot \
                 force a clean rebuild around this",
            published.display()
        );
    }
    let canonical_pkg = release_dir.join("build").join("zelynic-ebpf");
    let canonical_name = name.replace('-', "_");
    match std::fs::read_dir(&canonical_pkg) {
        Ok(hashes) => {
            for hash in hashes.flatten() {
                let out = hash.path().join("out").join(&canonical_name);
                if let Err(e) = std::fs::remove_file(&out)
                    && e.kind() != std::io::ErrorKind::NotFound
                {
                    panic!(
                        "failed to delete the damaged canonical eBPF \
                             artifact {}: {e} — cannot force a clean rebuild \
                             around this",
                        out.display()
                    );
                }
            }
        }
        // No build/ directory — no canonical copies; the published
        // name above was the only copy.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!(
            "failed to scan {} for canonical artifact copies: {e} — cannot \
             force a clean rebuild around this",
            canonical_pkg.display()
        ),
    }
}

fn format_build_time_utc() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let Ok(secs) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return "unknown".to_string();
    };
    let total_secs: i64 = i64::try_from(secs.as_secs()).unwrap_or(0);
    format_unix_secs_as_build_time(total_secs)
}

/// Pure formatting function — takes unix-epoch seconds and returns
/// `M/D/YYYY HH:MM (UTC)`. Separated from `format_build_time_utc` so
/// the algorithm is unit-testable without depending on the wall clock.
///
/// Algorithm: split `total_secs` into days + seconds-of-day, then use
/// Howard Hinnant's `civil_from_days` algorithm
/// (http://howardhinnant.github.io/date_algorithms.html) to convert
/// days-since-epoch to (year, month, day). All arithmetic is on `i64`
/// to avoid unsigned-underflow issues when subtracting the 719468-day
/// shift constant.
fn format_unix_secs_as_build_time(total_secs: i64) -> String {
    let days_since_epoch = total_secs.div_euclid(86_400);
    let secs_of_day = total_secs.rem_euclid(86_400);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;

    // Howard Hinnant's civil_from_days: converts days-since-1970-01-01
    // to (year, month, day) in the proleptic Gregorian calendar.
    // http://howardhinnant.github.io/date_algorithms.html#civil_from_days
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };

    format!("{m}/{d}/{year} {hour:02}:{minute:02} (UTC)")
}

// The split modules (NIGHT-improve-31's plan, NIGHT-improve-44's
// execution) — #[path] keeps them inside this crate root with zero
// new dependencies.
#[path = "build/flags.rs"]
mod flags;
#[path = "build/identity.rs"]
mod identity;
#[path = "build/preflight.rs"]
mod preflight;
#[path = "build/validate.rs"]
mod validate;
#[path = "build/vcs.rs"]
mod vcs;

use flags::{force_bpf_v3_rustflags, strip_host_poison_rustflags};
use preflight::preflight_ebpf_prerequisites;
use validate::read_validated_ebpf_object;
use vcs::{env_short_sha, git_short_sha, packaged_vcs_sha};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_time_format_matches_known_unix_epochs() {
        // All constants verified against `date -u -d @<epoch>` (not from
        // memory): the cosmostrix reference build.rs carried two wrong
        // constants here (1_709_210_440 asserted as "12:34" but is
        // 12:40:40; 1_787_930_200 asserted as "8/4 15:30" but is
        // 8/28 15:16:40) — latent because `cargo test` never executes
        // build-script tests. This suite runs standalone via
        // `rustc --edition 2021 --test build.rs`, so the constants must
        // be real ground truth.

        // UNIX epoch: 1970-01-01 00:00:00 UTC.
        assert_eq!(format_unix_secs_as_build_time(0), "1/1/1970 00:00 (UTC)");

        // 2000-01-01 00:00:00 UTC = 946_684_800 seconds since epoch.
        // Computed via: date -u -d '2000-01-01 00:00:00' +%s
        assert_eq!(
            format_unix_secs_as_build_time(946_684_800),
            "1/1/2000 00:00 (UTC)"
        );

        // 2024-02-29 12:34:00 UTC = 1_709_210_040 seconds since epoch.
        // Leap-day boundary check — Feb 29 must not roll to Mar 1.
        // Computed via: date -u -d '2024-02-29 12:34:00' +%s
        assert_eq!(
            format_unix_secs_as_build_time(1_709_210_040),
            "2/29/2024 12:34 (UTC)"
        );

        // 2026-08-04 15:30:00 UTC = 1_785_857_400 seconds since epoch.
        // Computed via: date -u -d '2026-08-04 15:30:00' +%s
        assert_eq!(
            format_unix_secs_as_build_time(1_785_857_400),
            "8/4/2026 15:30 (UTC)"
        );
    }

    #[test]
    fn build_time_format_truncates_sub_minute_seconds() {
        // 1_709_210_440 = 2024-02-29 12:40:40 UTC: the 40 sub-minute
        // seconds are dropped (minute precision, matching the cosmostrix
        // `%-m/%-d/%Y %H:%M` format contract), never rounded up.
        assert_eq!(
            format_unix_secs_as_build_time(1_709_210_440),
            "2/29/2024 12:40 (UTC)"
        );
    }

    #[test]
    fn build_time_format_handles_negative_seconds_gracefully() {
        // Pre-epoch timestamps (negative seconds) should still produce
        // a valid proleptic Gregorian date via the algorithm's signed
        // arithmetic, not panic or underflow.
        // 1969-12-31 23:59:00 UTC = -60 seconds.
        let result = format_unix_secs_as_build_time(-60);
        assert!(
            result.ends_with("(UTC)"),
            "negative-epoch result should still be (UTC)-suffixed: {result}"
        );
        assert!(
            result.contains("1969"),
            "negative-epoch result should land in 1969: {result}"
        );
    }

    /// NIGHT-hunt-29: the self-heal's deletion must remove the
    /// published dashed name AND every canonical underscored copy in
    /// cargo's fingerprint-hash directories — deleting only the
    /// published name lets cargo re-publish the corpse from the
    /// canonical inode (verified live). Per-name scoping: the other
    /// object's copies are untouched. Idempotent: a clean tree is a
    /// no-op, not a panic.
    #[test]
    fn damaged_artifact_deletion_removes_both_names_and_all_hash_copies() {
        let dir = std::env::temp_dir().join(format!("zelynic-h29-{}", std::process::id()));
        let release = dir.join("release");
        let hash_one = release.join("build/zelynic-ebpf/hash-one/out");
        let hash_two = release.join("build/zelynic-ebpf/hash-two/out");
        std::fs::create_dir_all(&hash_one).expect("fake release tree");
        std::fs::create_dir_all(&hash_two).expect("fake release tree");
        std::fs::write(release.join("zelynic-limiter"), b"published corpse").unwrap();
        std::fs::write(hash_one.join("zelynic_limiter"), b"canonical corpse 1").unwrap();
        std::fs::write(hash_two.join("zelynic_limiter"), b"canonical corpse 2").unwrap();
        std::fs::write(release.join("zelynic-observer"), b"innocent bystander").unwrap();
        std::fs::write(hash_one.join("zelynic_observer"), b"innocent bystander").unwrap();

        delete_damaged_artifact(&release, "zelynic-limiter");

        assert!(!release.join("zelynic-limiter").exists());
        assert!(!hash_one.join("zelynic_limiter").exists());
        assert!(!hash_two.join("zelynic_limiter").exists());
        // The healthy twin object keeps every copy — the heal is per-name.
        assert!(release.join("zelynic-observer").exists());
        assert!(hash_one.join("zelynic_observer").exists());

        // Idempotent on an already-clean tree.
        delete_damaged_artifact(&release, "zelynic-limiter");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
