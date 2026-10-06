// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// NIGHT-improve-31 phase 3, executed by NIGHT-improve-44: the
// toolchain preflight (NIGHT-host-1) — the rustup and PATH probes
// that name the exact missing piece — plus the detector tests.
/// NIGHT-host-1: verify the two host prerequisites of an
/// ebpf-feature build up front, panicking with the exact missing
/// piece and the one-command fix. Cheap on purpose: one
/// `rustup toolchain list` (tens of milliseconds) plus a PATH scan,
/// and only on the ebpf-feature path — default builds never pay it.
pub(crate) fn preflight_ebpf_prerequisites(toolchain: &str) {
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
                 ./scripts/dev/bootstrap-ebpf.sh\n  \
                 (manual: rustup toolchain install {toolchain} --profile \
                 minimal --component rust-src --component rustfmt)"
            );
        }
        // NIGHT-hunt-27: a listed pin can still be DAMAGED (an
        // interrupted install leaves the directory registered with
        // no manifests); probe the manifests before the nested build
        // turns that into raw errors far from the cause.
        if !toolchain_manifests_loadable(toolchain) {
            panic!(
                "the pinned nightly toolchain {toolchain} is listed but \
                 damaged: its component manifests are missing (an \
                 interrupted install — Ctrl-C, power loss, or a full disk). \
                 One-command repair:\n  \
                 ./scripts/dev/bootstrap-ebpf.sh\n  \
                 (it detects this state, removes the damaged toolchain, and \
                 reinstalls it — no manual rustup commands needed)"
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
             ./scripts/dev/bootstrap-ebpf.sh\n  \
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

/// NIGHT-hunt-27: can the pin's component manifests be loaded? A
/// toolchain listed by `rustup toolchain list` can still be damaged —
/// an interrupted install (Ctrl-C, power loss, full disk) leaves the
/// directory registered while its manifests are gone, and the exact
/// operation that then fails is the component enumeration
/// ("missing manifest in toolchain ..."), while `rustup run ... rustc`
/// still succeeds (the binaries are intact) — so the breakage only
/// surfaces later, deep in build-std. A local metadata read, never a
/// network fetch. When rustup itself cannot run, report "loadable"
/// and stay silent — the same contract as [`rustup_toolchain_list`]:
/// the nested invocation then produces the real error.
fn toolchain_manifests_loadable(toolchain: &str) -> bool {
    std::process::Command::new("rustup")
        .args(["component", "list", "--toolchain", toolchain])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(true)
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

#[cfg(test)]
mod tests {
    use super::*;

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

    /// NIGHT-hunt-27: verify the damaged-toolchain detector against
    /// real rustup behavior, hermetically — a fake RUSTUP_HOME holding
    /// an EMPTY toolchain directory reproduces the exact damaged state
    /// an interrupted install leaves behind: the pin is listed, while
    /// the component enumeration dies with "missing manifest"
    /// (reproduced against rustup 1.29.1). Skipped when rustup is not
    /// installed — the detector then reports "loadable" by contract.
    #[test]
    #[ignore = "mutates RUSTUP_HOME; run alongside the bootstrap self-heal matrix"]
    fn damaged_toolchain_detection_matches_rustup_reality() {
        if rustup_toolchain_list().is_none() {
            return; // no rustup on this machine — nothing to verify against
        }

        let pin = "nightly-2026-09-18";
        let host = std::env::consts::ARCH.to_string()
            + "-unknown-linux-"
            + match std::env::consts::OS {
                "linux" => "gnu",
                _ => return, // zelynic is Linux-only; other hosts lack the triple
            };

        let home = std::env::temp_dir().join(format!("zelynic-damaged-tc-{}", std::process::id()));
        let toolchains = home.join("toolchains");
        std::fs::create_dir_all(toolchains.join(format!("{pin}-{host}")))
            .expect("fake toolchain dir");

        let saved = std::env::var_os("RUSTUP_HOME");
        std::env::set_var("RUSTUP_HOME", &home);
        let verdict = toolchain_manifests_loadable(pin);
        match saved {
            Some(v) => std::env::set_var("RUSTUP_HOME", v),
            None => std::env::remove_var("RUSTUP_HOME"),
        }
        let _ = std::fs::remove_dir_all(&home);

        assert!(
            !verdict,
            "an empty (manifest-less) toolchain directory must be reported as damaged"
        );
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
