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

    let git_hash = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=GIT_HASH={}", git_hash);

    // Build timestamp (NIGHT-hunt-6, cosmostrix lineage): computed from
    // SystemTime via Howard Hinnant's civil_from_days algorithm — std only,
    // no chrono and no [build-dependencies]. Freshness equals the build.rs
    // run time: re-executed whenever git HEAD, ZELYNIC_BUILD, or source
    // inputs change (cargo's standard build-script caching).
    let build_time = format_build_time_utc();
    println!("cargo:rustc-env=ZELYNIC_BUILD_TIME={build_time}");
}

/// NIGHT-improve-1 phase 3: build the pure-Rust eBPF objects.
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
/// scripts/bootstrap-ebpf.sh; see ebpf/rust-toolchain.toml and
/// docs/PURE_RUST_EVALUATION.md): the dated nightly with rust-src,
/// and the bpf-linker 0.11.1 prebuilt binary on PATH. The preflight
/// (NIGHT-host-1) below fails fast, naming the exact missing piece
/// and the one-command fix. An ebpf-feature build is a pure-Rust
/// build — there is no C fallback.
///
/// Default builds (feature off) never enter the nightly path at all:
/// the dormant-mode stable-toolchain contract of the root build is
/// unchanged.
///
/// The dated nightly pin driving the nested cross-build — mirrors
/// ebpf/rust-toolchain.toml (which the nested build resolves from its
/// own directory) and the pin scripts/bootstrap-ebpf.sh installs on
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
        return;
    }

    // NIGHT-host-1: preflight the two host prerequisites BEFORE the
    // nested build, so a failure names the exact missing piece and
    // the one-command fix (scripts/bootstrap-ebpf.sh) instead of
    // surfacing rustup's or the linker's raw error text after the
    // dependency tree has already compiled — and so a missing
    // bpf-linker is caught even when ebpf/target is fully cached (a
    // warm nested build skips the link step, so without this check
    // the prerequisite violation passes silently and only explodes
    // on the next clean build — reproduced while testing this
    // change).
    preflight_ebpf_prerequisites(EBPF_TOOLCHAIN);

    // Invoke the nested build through `rustup run <pin> cargo` — the
    // aya-build upstream lesson: the CARGO env var handed to build
    // scripts points at the RESOLVED toolchain cargo (stable 1.98.1
    // here), which bypasses rustup's toolchain-file resolution and
    // would silently drop the nightly-only -Z build-std flag. Forcing
    // the toolchain through rustup makes the sub-build deterministic
    // regardless of how this build script was invoked. cwd inside
    // ebpf/ keeps the crate's own .cargo/config.toml in effect;
    // target and build-std are ALSO passed explicitly so the
    // invocation is correct even without the config. Environment is
    // inherited so CI's strict RUSTFLAGS contract covers this crate
    // too. --locked keeps the committed Cargo.lock authoritative.
    // Stdio is inherited: the nested build's own compiler output
    // streams through to the user/CI log.
    let status = std::process::Command::new("rustup")
        .args(["run", EBPF_TOOLCHAIN, "cargo"])
        .current_dir(&ebpf_dir)
        .args([
            "build",
            "--release",
            "--locked",
            "--target",
            "bpfel-unknown-none",
        ])
        .args(["-Z", "build-std=core"])
        // The aya-build upstream workaround: the parent cargo exports
        // RUSTC pointing at the ROOT build's (stable) rustc — without
        // removing it, the nightly sub-build would compile build-std
        // core with the stable compiler and fail on its missing
        // rust-src. The sub-build must resolve its own rustc.
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .status()
        .unwrap_or_else(|e| {
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

    // Copy both objects into OUT_DIR for include_bytes! embedding,
    // verifying the ELF magic so a truncated or wrong-format artifact
    // fails the build here instead of at load time on a user host.
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    for name in ["zelynic-observer", "zelynic-limiter"] {
        let src = ebpf_dir
            .join("target")
            .join("bpfel-unknown-none")
            .join("release")
            .join(name);
        let data = std::fs::read(&src)
            .unwrap_or_else(|e| panic!("expected eBPF object {} not readable: {e}", src.display()));
        assert!(
            data.len() > 4
                && data[0] == 0x7f
                && data[1] == b'E'
                && data[2] == b'L'
                && data[3] == b'F',
            "eBPF object {} is not an ELF file (bpf-linker output corrupt?)",
            src.display()
        );
        let dst = out_dir.join(name);
        std::fs::write(&dst, &data)
            .unwrap_or_else(|e| panic!("failed to stage {} into OUT_DIR: {e}", dst.display()));
    }
}

/// NIGHT-host-1: verify the two host prerequisites of an
/// ebpf-feature build up front, panicking with the exact missing
/// piece and the one-command fix. Cheap on purpose: one
/// `rustup toolchain list` (tens of milliseconds) plus a PATH scan,
/// and only on the ebpf-feature path — default builds never pay it.
fn preflight_ebpf_prerequisites(toolchain: &str) {
    // Toolchain: `rustup run` on a missing toolchain fails with
    // rustup's own error text AFTER the dependency tree compiled; the
    // preflight moves that failure to the front and makes it
    // actionable. If rustup itself cannot run, stay silent — the
    // nested invocation's launch panic names rustup as the hard
    // prerequisite with its own precise message.
    if let Some(list) = rustup_toolchain_list() {
        if !list_has_toolchain(&list, toolchain) {
            panic!(
                "the pinned nightly toolchain {toolchain} is not installed, \
                 but the ebpf feature requires it (ebpf/rust-toolchain.toml \
                 pins it for the bpfel-unknown-none cross-build). \
                 One-command fix:\n  \
                 ./scripts/bootstrap-ebpf.sh\n  \
                 (manual: rustup toolchain install {toolchain} --profile \
                 minimal --component rust-src --component rustfmt)"
            );
        }
    }

    // bpf-linker: the link step only runs when ebpf/target is cold,
    // so a warm cache hides a missing linker until the next clean
    // build (reproduced while testing this change) — hence an
    // unconditional PATH scan here, not a nested-build failure.
    if !path_has_tool("bpf-linker") {
        panic!(
            "bpf-linker is not on PATH, but the ebpf feature requires it \
             to link the bpfel-unknown-none objects (pinned version: \
             0.11.1). One-command fix:\n  \
             ./scripts/bootstrap-ebpf.sh\n  \
             (already installed under ~/.local/bin? Put ~/.local/bin \
             on PATH — the bootstrap script warns about exactly this)"
        );
    }
}

/// `rustup toolchain list` output, or None when rustup is missing or
/// fails — in that case the nested invocation produces the real
/// error and the preflight stays silent instead of guessing.
fn rustup_toolchain_list() -> Option<String> {
    let output = std::process::Command::new("rustup")
        .args(["toolchain", "list"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Match a pin against `rustup toolchain list` output. Each line is
/// "<toolchain-name>-<host-triple>" (optionally suffixed " (active)"),
/// so a pin matches only when the line's first token IS the pin or
/// the pin plus a "-" host-triple suffix — a longer lookalike pin
/// sharing the prefix ("...-09-180-...") must not match.
fn list_has_toolchain(list: &str, pin: &str) -> bool {
    list.lines().any(|line| {
        let name = line.split_whitespace().next().unwrap_or("");
        name == pin || name.starts_with(&format!("{pin}-"))
    })
}

/// Is `tool` present as an executable file anywhere on PATH?
/// `command -v` semantics without spawning a shell, so the check
/// works under any parent environment cargo hands the build script.
fn path_has_tool(tool: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| path_value_has_tool(&paths, tool))
        .unwrap_or(false)
}

/// The testable core of [`path_has_tool`]: scan one PATH value.
fn path_value_has_tool(path_value: &std::ffi::OsStr, tool: &str) -> bool {
    std::env::split_paths(path_value).any(|dir| is_executable_file(&dir.join(tool)))
}

/// A regular file with at least one execute bit set — the same test
/// shells apply when resolving a command name.
fn is_executable_file(path: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(metadata) => metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
            Err(_) => false,
        }
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

/// Build timestamp in `M/D/YYYY HH:MM (UTC)` format, computed from
/// `std::time::SystemTime` without any time crate.
///
/// cosmostrix `format_build_time_utc()` port (NIGHT-hunt-6): the Hinnant
/// civil-from-days algorithm replaces what other projects pull `chrono`
/// for, keeping the supply-chain surface at zero extra crates. Returns
/// "unknown" only if `SystemTime::now()` is before `UNIX_EPOCH`
/// (a broken system clock).
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

    #[test]
    fn toolchain_list_matching_pins_the_host_triple_suffix_contract() {
        // NIGHT-host-1: real `rustup toolchain list` shape — one
        // "<name>-<host-triple>" line per toolchain, possibly suffixed
        // "(active)" / "(default)". The preflight's toolchain probe
        // must accept the pin and reject lookalikes.
        let list = "1.98.1-x86_64-unknown-linux-gnu (active, default)\n\
                    nightly-2026-09-18-x86_64-unknown-linux-gnu\n\
                    stable-x86_64-unknown-linux-gnu\n";
        assert!(list_has_toolchain(list, "nightly-2026-09-18"));
        assert!(list_has_toolchain(list, "1.98.1"));
        assert!(!list_has_toolchain(list, "nightly-2026-09-17"));

        // A longer pin sharing the prefix must NOT match: only the
        // exact pin, or the pin plus a "-" host-triple suffix, counts.
        assert!(!list_has_toolchain(
            "nightly-2026-09-180-x86_64-unknown-linux-gnu",
            "nightly-2026-09-18"
        ));

        // Empty output (rustup with nothing installed yet) matches
        // nothing — the preflight reports the pin as missing.
        assert!(!list_has_toolchain("", "nightly-2026-09-18"));
    }

    #[cfg(unix)]
    #[test]
    fn path_scan_finds_only_executable_files_named_like_the_tool() {
        // NIGHT-host-1: the preflight's bpf-linker probe is
        // command-v semantics — an executable regular file on PATH.
        // Non-executable files and directories of the same name must
        // not satisfy it (the warm-cache blind spot fix relies on
        // this being a real resolution test).
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("zelynic-buildrs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir setup");

        // 1. executable file named like the tool -> found
        let exec_dir = dir.join("exec");
        std::fs::create_dir_all(&exec_dir).unwrap();
        std::fs::write(exec_dir.join("bpf-linker"), b"").unwrap();
        std::fs::set_permissions(
            exec_dir.join("bpf-linker"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        // 2. plain file, no execute bit -> not found despite the name
        let plain_dir = dir.join("plain");
        std::fs::create_dir_all(&plain_dir).unwrap();
        std::fs::write(plain_dir.join("bpf-linker"), b"").unwrap();
        std::fs::set_permissions(
            plain_dir.join("bpf-linker"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        // 3. a directory named like the tool -> not found (is_file gate)
        let dir_case = dir.join("dircase");
        std::fs::create_dir_all(dir_case.join("bpf-linker")).unwrap();

        let with_exec = std::env::join_paths([&exec_dir, &plain_dir]).unwrap();
        assert!(path_value_has_tool(&with_exec, "bpf-linker"));

        let without_exec = std::env::join_paths([&plain_dir, &dir_case]).unwrap();
        assert!(!path_value_has_tool(&without_exec, "bpf-linker"));

        // hermetic: repeated runs reuse the same pid-keyed dir
        let _ = std::fs::remove_dir_all(&dir);
    }
}
