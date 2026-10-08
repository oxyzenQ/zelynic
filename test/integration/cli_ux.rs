// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Flag and error UX contract pins: rejected flags name themselves,
//! typos get did-you-mean tips, global flags parse globally, and a
//! short pipe reader never turns EPIPE into a panic.

use crate::zelynic_cmd;

/// NIGHT-hunt-5: the --no-color flag is gone — purple is branding and
/// branding has no CLI opt-out. Color control is env-only (NO_COLOR /
/// CLICOLOR / CLICOLOR_FORCE), exactly like cosmostrix.
#[test]
fn test_no_color_flag_is_rejected() {
    let output = zelynic_cmd()
        .args(["--no-color", "doctor"])
        .output()
        .expect("Failed to execute zelynic --no-color");

    assert_eq!(
        output.status.code(),
        Some(2),
        "--no-color must be a usage error (exit 2)"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected argument"),
        "must report the unknown flag, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("--no-color'\n  tip"),
        "no self-suggestion for the removed flag"
    );
}

/// Typo suggestions are flagship: a near-miss subcommand must produce
/// clap's did-you-mean tip with the right exit code.
#[test]
fn test_typo_subcommand_gets_suggestion() {
    // NIGHT-improve-53: the near-miss 'strict-singl' once pointed at
    // the retired strict-single; the masterclass vocabulary it can
    // reach now is 'strict' itself (the redirect table owns the
    // exact retired spelling, pinned in surface_pins).
    let output = zelynic_cmd()
        .arg("strict-singl")
        .output()
        .expect("Failed to execute zelynic strict-singl");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("tip:"),
        "typo must carry a suggestion tip, got:\n{stderr}"
    );
    assert!(
        stderr.contains("strict"),
        "tip must point at the strict family's living vocabulary, got:\n{stderr}"
    );
}

/// Case-variant flag typos are rescued: clap's own did-you-mean engine
/// is case-sensitive, so `--VERBOS` would render tip-less without the
/// case-insensitive fallback in cli::ux (NIGHT-hunt-5).
#[test]
fn test_case_variant_flag_typo_gets_rescued() {
    let output = zelynic_cmd()
        .args(["--VERBOS", "doctor"])
        .output()
        .expect("Failed to execute zelynic --VERBOS");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--verbose"),
        "case-variant typo must suggest --verbose, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Usage: zelynic"),
        "error must carry the real usage line, got:\n{stderr}"
    );
}

/// NIGHT-hunt-9: -v/--verbose is a real global flag — it must parse on
/// any command path (here: doctor, which never touches eBPF) without
/// changing the exit contract. Pins the global=true wiring so a future
/// refactor cannot silently demote it to a per-command flag.
#[test]
fn test_verbose_flag_parses_globally() {
    let output = zelynic_cmd()
        .args(["--verbose", "doctor"])
        .output()
        .expect("Failed to execute zelynic --verbose doctor");

    assert_eq!(
        output.status.code(),
        Some(0),
        "--verbose must be accepted globally, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Piping into a short reader must not panic: the safe print macros
/// discard EPIPE instead of aborting with exit 101 (verified live
/// before NIGHT-hunt-5: `zelynic --help | head -2` panicked — then the
/// flag was still --help-all; merged into --help by NIGHT-improve-3).
#[test]
fn test_help_pipe_to_head_does_not_panic() {
    use std::io::Read as _;
    use std::process::Stdio;

    let mut child = zelynic_cmd()
        .arg("--help")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn zelynic --help");

    // Read a sliver, then drop the pipe handle — the reader end closes
    // while the child is still producing output, so its remaining
    // writes hit EPIPE. (If the child finishes first the test passes
    // trivially; either way a panic-exit-101 regression fails it.)
    if let Some(mut stdout) = child.stdout.take() {
        let mut buf = [0u8; 16];
        let _ = stdout.read(&mut buf);
        drop(stdout);
    }

    let status = child.wait().expect("Failed to wait for zelynic --help");
    assert!(
        status.success(),
        "EPIPE must truncate silently, not panic: {status}"
    );
}

/// NIGHT-hunt-39 peak extension (owner approved): the error lane's
/// flag mentions ride the calm-grey grammar tier. The canonical
/// footer's `--help` spelling composes grey in the ux bridge, and
/// clap paints its did-you-mean candidates with the `valid` style —
/// the same #8B8B8B the output layer's grey slot rides. Two escape
/// laws at this pinned env (CLICOLOR_FORCE skips capability
/// probing, so clap emits its RGB raw — truecolor — while the
/// output layer still parses TERM for depth and lands on the 245
/// rung): the footer carries `[38;5;245m`, the clap candidates
/// carry `[38;2;139;139;139m` — same tier, same color, each lane's
/// own encoding recorded here. The typed MISTAKE keeps the invalid
/// yellow: it never rides a grey span.
#[test]
fn test_error_lane_flag_mentions_render_grey() {
    let mut cmd = zelynic_cmd();
    cmd.arg("--verbos")
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR")
        .env("CLICOLOR_FORCE", "1")
        .env("TERM", "xterm-256color");
    let colored = cmd
        .output()
        .expect("Failed to execute zelynic --verbos (grey-tier run)");
    assert_eq!(colored.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&colored.stderr);
    // The output layer's lane: the footer's --help spelling rides
    // the theme's 245 rung at 256-color depth — grey span, quotes
    // and prose default (the span-exact law flag_row set).
    let grey = "\x1b[38;5;245m";
    let reset = "\x1b[0m";
    assert!(
        stderr.contains(&format!("try '{grey}--help{reset}'.")),
        "the footer's --help mention must render calm grey (245), got:\n{stderr}"
    );
    // clap's lane: the did-you-mean candidate rides the valid style
    // — #8B8B8B raw (truecolor escape under force), same tier.
    let clap_grey = "\x1b[38;2;139;139;139m";
    assert!(
        stderr.contains(&format!("'{clap_grey}--verbose{reset}'")),
        "the suggestion candidate must render calm grey (#8B8B8B), got:\n{stderr}"
    );
    // The typed mistake never greys — the invalid yellow owns it.
    assert!(
        !stderr.contains(&format!("{clap_grey}--verbos{reset}")),
        "the typo stays the mistake tier, never grey, got:\n{stderr}"
    );
}

/// The hunt-39 peak extension's redirect surface: a removed
/// subcommand's successor renders as one valid span — command and
/// flag spelling together, the grey grammar tier (`zelynic --help`,
/// `strict --all`). The successor is what to type next: grammar.
#[test]
fn test_removed_subcommand_redirect_successor_renders_grey() {
    let mut cmd = zelynic_cmd();
    cmd.arg("help")
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR")
        .env("CLICOLOR_FORCE", "1")
        .env("TERM", "xterm-256color");
    let colored = cmd
        .output()
        .expect("Failed to execute zelynic help (redirect grey-tier run)");
    assert_eq!(colored.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&colored.stderr);
    // clap's lane under force: the valid style's #8B8B8B rides its
    // raw truecolor escape — same tier, the encoding law the
    // footer/candidate pin above records.
    let clap_grey = "\x1b[38;2;139;139;139m";
    let reset = "\x1b[0m";
    assert!(
        stderr.contains(&format!("run '{clap_grey}zelynic --help{reset}'")),
        "the redirect successor must render calm grey (#8B8B8B), got:\n{stderr}"
    );
}

/// The mono contract of the peak extension: piped without color
/// force, the same error render carries zero escapes — the footer,
/// the candidates, and the typo all keep their plain bytes (grey is
/// capability-aware, clap strips at Auto, the reference's piped
/// contract holds on the error lane too).
#[test]
fn test_error_lane_mono_keeps_plain_bytes() {
    let output = zelynic_cmd()
        .arg("--verbos")
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR")
        .env_remove("CLICOLOR_FORCE")
        .output()
        .expect("Failed to execute zelynic --verbos (mono run)");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains('\x1b'),
        "piped errors must stay plain (zero escapes), got:\n{stderr}"
    );
    assert!(
        stderr.contains("try '--help'."),
        "the mono footer keeps its canonical wording, got:\n{stderr}"
    );
}
