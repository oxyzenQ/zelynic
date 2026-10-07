// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The flag-rescue family's pins (NIGHT-improve-42): the
//! shadowed-suggestion rescue — the supermassive v4 depth battery's
//! own catch — driven through the ux bridge's rendered output (the
//! only honest way to pin a suggestion: what matters is the TIP the
//! user reads, not the context object it came from).

use super::*;

/// NIGHT-improve-42 (the supermassive v4 depth battery's own catch):
/// the shadowed-suggestion rescue. clap's UnknownArgument tip at a
/// SUBCOMMAND position draws from that subcommand's flag pool only —
/// the root-level flags never join it — so once the improve-40-b
/// bracket family put `--ceil-upload` in the strict verb's pool, the
/// typo `--check-updat` (a 0.97 Jaro match for the root's
/// `--check-update`) was answered with the 0.78 `--ceil-upload`:
/// clap's local pool fired over the silent-fallback path that would
/// have named the right flag. The rescue re-scores both candidates
/// with the one metric and keeps the better tip — and because
/// `--check-update` parses at the ROOT only, the redirect names the
/// top-level spelling (a bare `--check-update` tip at subcommand
/// position would point at a position where the flag still fails).
#[cfg(feature = "ebpf")]
#[test]
fn shadowed_root_flag_typo_gets_the_authority_redirect() {
    let rendered = render_via_bridge(&["zelynic", "s", "brave", "1mb", "--check-updat"]);
    assert!(
        rendered.contains("'zelynic --check-update'"),
        "the authority redirect wins, got:\n{rendered}"
    );
    assert!(
        !rendered.contains("--ceil-upload"),
        "the 0.78 local-pool shadow must not survive, got:\n{rendered}"
    );
}

/// The rescue's own fence: a subcommand-flag typo KEEPS clap's own
/// tip (its pool knows the subcommand's flags — the right authority
/// when both readings compete), and the root-position behavior is
/// unchanged (clap's root pool carries the globals natively).
#[cfg(feature = "ebpf")]
#[test]
fn shadow_rescue_never_hijacks_subcommand_flag_typos() {
    // The new-grammar typos keep their subcommand tips.
    let during = render_via_bridge(&["zelynic", "s", "brave", "1mb", "--durign", "2h"]);
    assert!(
        during.contains("'--during'"),
        "clap's own subcommand tip survives, got:\n{during}"
    );
    let floor = render_via_bridge(&["zelynic", "s", "brave", "1mb", "--flor", "100kb"]);
    assert!(
        floor.contains("'--floor'"),
        "clap's own subcommand tip survives, got:\n{floor}"
    );
    // The root position behaves exactly as before.
    let root = render_via_bridge(&["zelynic", "--check-updat"]);
    assert!(
        root.contains("'--check-update'"),
        "the root pool's own tip is unchanged, got:\n{root}"
    );
}
