// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Command-surface wiring pins: aliases route to their canonical
//! commands' validation ladders, and removed surfaces fail loudly as
//! usage errors instead of silently changing behavior.

use crate::zelynic_cmd;

/// NIGHT-hunt-10 / NIGHT-improve-53: `strict` is the masterclass
/// verb's canonical name (the former shorthand) and 's' its short
/// alias — missing <target> must be a usage error (exit 2) about
/// the required positional <TARGET>, proving both spellings are
/// wired to the real command instead of rejected outright.
#[test]
fn test_strict_and_s_require_a_target() {
    for form in ["strict", "s"] {
        let output = zelynic_cmd()
            .arg(form)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {form}: {e}"));

        assert_eq!(
            output.status.code(),
            Some(2),
            "{form} without a target must be a usage error"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("required arguments were not provided") && stderr.contains("<TARGET>"),
            "error must name the missing {form} positional, got:\n{stderr}"
        );
    }
}

/// NIGHT-hunt-10: the strict verb must reach its validation ladder —
/// an invalid rate surfaces its did-you-mean tip BEFORE the root
/// guard, so this pins the dispatch without requiring root or eBPF
/// state. ebpf-gated: the rate ladder lives in the feature-gated
/// handler (the default build answers "eBPF not compiled").
#[cfg(feature = "ebpf")]
#[test]
fn test_strict_shorthand_reaches_rate_validation() {
    let output = zelynic_cmd()
        .args(["strict", "brave", "1MB"])
        .output()
        .expect("Failed to execute zelynic strict brave 1MB");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Invalid rate '1MB'"),
        "strict must route into its rate validation, got:\n{stderr}"
    );
}

/// NIGHT-improve-53: the masterclass '::' routing, pinned end to
/// end through the real binary — a list target enters the group
/// lane (the rate rung inside it names the list grammar), and the
/// per-socket scope call refuses a list BEFORE any parsing. Both
/// surface pre-root, so the pin is deterministic on any uid.
/// ebpf-gated: the routing lives in the feature-gated handler.
#[cfg(feature = "ebpf")]
#[test]
fn test_strict_list_lane_pins_the_routing_law() {
    // The group lane: the '::' list reaches the group lane's own
    // no-rate rung — the rung whose example names the list grammar
    // (a different example string than the single lane's).
    let output = zelynic_cmd()
        .args(["s", "brave::curl"])
        .output()
        .expect("Failed to execute zelynic s brave::curl");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No rate specified"),
        "the list target must reach the group lane's no-rate rung, got:\n{stderr}"
    );
    assert!(
        stderr.contains("zelynic strict brave::curl"),
        "the group lane's example names the '::' grammar, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("root required"),
        "the group lane's input error must precede the root guard, got:\n{stderr}"
    );

    // The scope call: --per-socket on a list is refused before any
    // parsing — the routing law's own rung.
    let output = zelynic_cmd()
        .args(["s", "brave::curl", "1mb", "--per-socket"])
        .output()
        .expect("Failed to execute zelynic s brave::curl 1mb --per-socket");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--per-socket is the single-target lane"),
        "the list lane must refuse --per-socket, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("root required"),
        "the scope refusal must precede the root guard, got:\n{stderr}"
    );
}

/// NIGHT-improve-54: the --all sweep lanes, pinned end to end
/// through the real binary — the routing law (target vs fleet), the
/// rate reinterpretation (a lone positional on the sweep IS the
/// rate: clap parks it in TARGET's slot), and the no-target
/// refusals, all pre-root and deterministic on every uid.
/// ebpf-gated: the lanes live in the feature-gated handlers.
#[cfg(feature = "ebpf")]
#[test]
fn test_sweep_lanes_pin_the_all_routing() {
    // The sweep's own no-rate rung: `s --all` with nothing else names
    // the sweep spelling in its example (the single lane's example
    // names the target grammar instead).
    let output = zelynic_cmd()
        .args(["s", "--all"])
        .output()
        .expect("Failed to execute zelynic s --all");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No rate specified"),
        "the bare sweep must reach the sweep lane's no-rate rung, got:\n{stderr}"
    );
    assert!(
        stderr.contains("zelynic s --all 500kb"),
        "the sweep lane's example names the --all spelling, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("root required"),
        "the sweep's input error must precede the root guard, got:\n{stderr}"
    );

    // The rate reinterpretation: `s --all 1MB` parks "1MB" in the
    // TARGET slot, and the sweep re-feeds it as the RATE — the rate
    // ladder's own refusal is the proof (an uppercase rate never
    // reaches the root guard).
    let output = zelynic_cmd()
        .args(["s", "--all", "1MB"])
        .output()
        .expect("Failed to execute zelynic s --all 1MB");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Invalid rate '1MB'"),
        "the lone positional must ride the sweep's rate ladder, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("root required"),
        "the rate refusal must precede the root guard, got:\n{stderr}"
    );

    // The lane confusions: a target beside --all is refused on every
    // family, before any parsing of the values.
    for (argv, needle) in [
        (
            vec!["s", "--all", "brave", "100kb"],
            "takes a rate, not a target",
        ),
        (vec!["b", "--all", "brave"], "takes no target"),
        (vec!["u", "--all", "brave"], "takes no target"),
    ] {
        let output = zelynic_cmd()
            .args(&argv)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {argv:?}: {e}"));
        assert_eq!(
            output.status.code(),
            Some(1),
            "{argv:?} must refuse the lane confusion"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(needle),
            "{argv:?} must name the --all lane law, got:\n{stderr}"
        );
        assert!(
            stderr.contains("--all"),
            "{argv:?} must name the flag in the refusal, got:\n{stderr}"
        );
        assert!(
            !stderr.contains("root required"),
            "the lane refusal must precede the root guard, got:\n{stderr}"
        );
    }
}

/// NIGHT-improve-53: unstrict carries the '::' list lane on the same
/// verb — a list target reaches the handler (the root guard fires
/// for a non-root caller, proving the routing never fell through to
/// a name lookup). ebpf-gated and skipped under root for the same
/// reason the owner-invocation pin below carries the pair.
#[cfg(feature = "ebpf")]
#[test]
fn test_unstrict_list_lane_reaches_the_handler() {
    if crate::euid_is_root() {
        return; // past the root guard these would remove for real
    }
    for argv in [vec!["unstrict", "brave::curl"], vec!["u", "brave::curl"]] {
        let output = zelynic_cmd()
            .args(&argv)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {argv:?}: {e}"));
        assert_eq!(
            output.status.code(),
            Some(1),
            "'{argv:?}' must reach the handler and stop at the root guard"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("root required"),
            "'{argv:?}' must be inside the unstrict handler (root guard), got: {stderr}"
        );
    }
}

/// NIGHT-hunt-10 introduced the alias; hunt-16 flipped the canonical
/// to unstrict-single; NIGHT-improve-53 merged the pair — `unstrict`
/// IS the verb now, and its short form is 'u'. Missing <target> is a
/// usage error naming the required positional — for BOTH spellings.
#[test]
fn test_unstrict_and_u_require_a_target() {
    for form in ["unstrict", "u"] {
        let output = zelynic_cmd()
            .arg(form)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {form}: {e}"));

        assert_eq!(
            output.status.code(),
            Some(2),
            "{form} without a target must be a usage error"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("required arguments were not provided") && stderr.contains("<TARGET>"),
            "error must name the missing {form} positional, got:\n{stderr}"
        );
    }
}

// ── Short aliases (NIGHT-improve-25) ────────────────────────────────────────

/// NIGHT-improve-25 / NIGHT-improve-53/54: the surviving short
/// aliases route to their canonical commands. The routing
/// discriminator is the unrecognized-subcommand error an unwired
/// name would produce: every alias invocation must NOT end in
/// "unrecognized subcommand" — the positional-carrying trio lands
/// in clap's required-argument usage error instead (pinned below),
/// and the sweeps route through their --all flags (the retired
/// sa/ba/ua spellings are redirects, pinned in the sweep-redirect
/// test above). Safe on any uid: nothing here reaches an
/// enforcement handler as root.
#[test]
fn test_short_aliases_route_to_canonical_commands() {
    for alias in ["s", "b", "u", "ee"] {
        let output = zelynic_cmd()
            .arg(alias)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {alias}: {e}"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains(&format!("unrecognized subcommand '{alias}'")),
            "short alias '{alias}' must route to its canonical command, got: {stderr}"
        );
    }
}

/// NIGHT-improve-53: the positional-carrying short forms land in
/// their canonical command's required-argument usage error (exit 2,
/// naming the missing <TARGET>) — the unified surface has ONE
/// positional per verb now (the list rides the same target slot
/// through the '::' grammar).
#[test]
fn test_short_aliases_with_positionals_hit_usage_errors() {
    for alias in ["s", "b", "u"] {
        let output = zelynic_cmd()
            .arg(alias)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {alias}: {e}"));

        assert_eq!(
            output.status.code(),
            Some(2),
            "'{alias}' without its positional must be a usage error"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("required arguments were not provided") && stderr.contains("<TARGET>"),
            "'{alias}' must name its canonical positional <TARGET>, got: {stderr}"
        );
    }
}

/// NIGHT-improve-25: the owner's exact invocations must parse through
/// to the handler ladder. ebpf-gated (the rate validation and the
/// monitor ladder live in the feature-gated handlers) and skipped
/// under root: past the root guard these would enforce for real —
/// the same reason the strict-shorthand rate test above carries the
/// same pair of gates.
#[cfg(feature = "ebpf")]
#[test]
fn test_owner_short_alias_invocations_reach_handlers() {
    if crate::euid_is_root() {
        return; // past the root guard these would enforce for real
    }
    for argv in [
        vec!["s", "brave", "100kb"],
        vec!["ee", "brave", "--interval", "1s"],
    ] {
        let output = zelynic_cmd()
            .args(&argv)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute zelynic {argv:?}: {e}"));

        assert_eq!(
            output.status.code(),
            Some(1),
            "'{argv:?}' must reach the handler and stop at the root guard"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("root required"),
            "'{argv:?}' must be inside its canonical handler (root guard), got: {stderr}"
        );
    }
}

/// NIGHT-master-1: the eagle-eyes depth surface — the missing-target
/// error teaches the invocation (BEFORE the root guard, deterministic
/// on any uid), the retired --info alias fails as a usage error whose
/// tip names --depth (NIGHT-blade-4), and the live-only --interval
/// flag answers with the honest one-stderr-line note the --print-json
/// ignored-note established.
#[cfg(feature = "ebpf")]
#[test]
fn test_eagle_eyes_depth_surface_pins() {
    use crate::euid_is_root;

    // --depth with no target: the actionable usage error, before the
    // privilege guard (the parse-before-execute ladder).
    let output = zelynic_cmd()
        .args(["ee", "--depth"])
        .output()
        .expect("Failed to execute zelynic ee --depth");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--depth needs a TARGET"),
        "the no-target error must teach the invocation, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("root required"),
        "the usage error must precede the root guard, got:\n{stderr}"
    );

    // NIGHT-blade-4: the --info alias is retired (--depth is the
    // only spelling) — it must fail as an unrecognized argument
    // whose ONE tip points at --depth, the vocabulary-rescue
    // contract allow-dangerous carries (every live flag sits under
    // clap's 0.7 jaro bar for "info", so the rescue table is the
    // only bridge — without it the old muscle memory dies tip-less).
    let output = zelynic_cmd()
        .args(["eagle-eyes", "--info"])
        .output()
        .expect("Failed to execute zelynic eagle-eyes --info");
    assert_eq!(
        output.status.code(),
        Some(2),
        "retired '--info' must be a usage error"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected argument '--info'"),
        "error must name the retired alias, got:\n{stderr}"
    );
    assert!(
        stderr.contains("'--depth'"),
        "retired '--info' must redirect to --depth, got:\n{stderr}"
    );

    // --depth --interval: the cadence flag is live-only, and the
    // one-shot mode says so on stderr exactly once — stdout and the
    // exit code carry the depth run's own verdict.
    let output = zelynic_cmd()
        .args(["eagle-eyes", "12345", "--depth", "--interval", "5s"])
        .output()
        .expect("Failed to execute zelynic eagle-eyes 12345 --depth --interval 5s");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.matches("--interval ignored").count(),
        1,
        "exactly one honest note, got:\n{stderr}"
    );
    if euid_is_root() {
        // Root: the one-shot report RUNS piped (no interactive gate —
        // that refusal belongs to the live TUI only) and names the
        // target it inspected.
        assert_eq!(
            output.status.code(),
            Some(0),
            "root: the one-shot report runs even piped, got:\n{stderr}"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("cg:12345"),
            "the report names the inspected target, got:\n{stdout}"
        );
    } else {
        // Non-root: the root guard fires after the note, exit 1.
        assert_eq!(output.status.code(), Some(1));
        assert!(
            stderr.contains("root required"),
            "non-root: the root guard teaches sudo, got:\n{stderr}"
        );
    }
}
