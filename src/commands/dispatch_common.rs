// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// NIGHT-improve-44: the dispatch-shared surfaces live here since the
// 600-line cap split — the apply-verb epilogue (NIGHT-improve-28), the
// root gate, the no-match hard-error contract (NIGHT-dinner-11), the
// dormant-lane refusal, and the pin cleanup every arm leans on. The
// mod.rs re-exports keep the super:: call sites resolving identically.

#[cfg(feature = "ebpf")]
use anyhow::Result;
#[cfg(not(feature = "ebpf"))]
use anyhow::Result;

#[cfg(feature = "ebpf")]
use crate::ebpf::pin::unpin_all;

/// Legacy PID file (kept for cleanup of old installations).
#[cfg(feature = "ebpf")]
const PID_FILE: &str = "/tmp/zelynic.pid";

// ── The apply-verb success epilogue (NIGHT-improve-28) ──────────────
//
// The owner's verbosity audit: the apply verbs (strict and its
// siblings) answered with a two-line report that restated the request
// ("Limiting 'cg:48181' to 10.0 KB/s + 10.0 KB/s (2 policies, active
// in background)") before the follow-up line. The pro contract is the
// affirmative-verdict grammar: a green "OK." (the #50FA7B tier that
// affirmative verdicts already own) plus the follow-up commands in
// the runnable-example green tier — the same "this is what you type"
// color the --help examples render in (NIGHT-boost-4). The request
// echo lives in the shell history, the enforced facts (rates, policy
// counts) live in 'zelynic status', and the success surface stays
// one glance.
//
// The follow-up must ROUND-TRIP: each caller passes the exact unstrict
// form that reverses what it applied. The former shared suggestion
// was wrong advice on two shapes — 'zelynic unstrict brave:curl'
// does not split lists (the single lane takes one target), and
// 'zelynic unstrict 3 apps' is not a target at all — so the list and
// all lanes now suggest 'unstrict <list>' / 'unstrict-all' (the
// improve-53 masterclass grammar: the list rides the same verb).

/// The pure line builder behind the apply-verb epilogue (pinned in
/// test/cli/apply_epilogue_tests.rs): line 1 is the affirmative
/// verdict, line 2 the follow-up with both runnable commands wrapped
/// in the green tier. Pure so the exact wording — including the
/// 'or' the owner specced — is a contract, not an accident.
#[cfg(feature = "ebpf")]
#[must_use]
pub(crate) fn apply_success_lines(unstrict_cmd: &str, action: &str) -> [String; 2] {
    [
        crate::output::ok("OK."),
        format!(
            "Run '{}' to {action}, or '{}' to check.",
            crate::output::ok(unstrict_cmd),
            crate::output::ok("zelynic status")
        ),
    ]
}

/// Print the apply-verb success epilogue (NIGHT-improve-28): green
/// "OK." on its own line, then the follow-up commands in green —
/// `action` names what the unstrict form does ("remove" for the
/// strict family, "restore access" for the block family).
#[cfg(feature = "ebpf")]
pub(crate) fn apply_success_epilogue(unstrict_cmd: &str, action: &str) {
    for line in apply_success_lines(unstrict_cmd, action) {
        eprintln_safe!("{line}");
    }
}

/// Shared root guard — one clean branded error instead of the old
/// double print (a plain "requires root" line followed by a second
/// duplicated "root required" error from the anyhow path).
///
/// The tip line renders white via the line-aware error renderer.
/// ebpf-gated: every caller is an eBPF-surface command handler.
#[cfg(feature = "ebpf")]
pub(crate) fn ensure_root() -> Result<()> {
    if nix::unistd::geteuid().is_root() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "root required — eBPF operations need CAP_BPF\n  \
             tip: re-run with sudo"
        ))
    }
}

// ── The no-match hard-error contract (NIGHT-dinner-11) ──────────────
//
// The owner's eBPF-verifier lineage mandate, applied to the CLI
// surface: a target that resolves to nothing is REJECTED, never
// soft-exited. The old paths printed a plain stderr line
// ("No cgroup found for 'cg8401'. Nothing to limit.") and returned
// Ok — exit 0 — so a typo'd target was indistinguishable from an
// enforced limit to every script (and to a skimming human: the
// owner's own transcript showed `ss cg8401` reading as calm
// success). The kernel's verifier rejects a program it cannot
// prove instead of loading it half-working; the CLI now holds the
// same line: a command that NAMES a target must find it, or fail.
//
// Every conversion below returns `Err` on purpose — main's single
// exit-adjacent renderer paints the branded block (bold red
// `error:` label, red body, white `tip:` lines — green when the tip
// quotes a command to run, NIGHT-dinner-12) and exits 1.
// The one carve-out: `unstrict-all` on an already-clean system
// keeps its exit 0 — the requested state already holds, the same
// clean-state precedent `recover`'s clean path owns.

/// The discovery tip every no-match error carries: the live-target
/// surface (one command away from the correct spelling).
#[cfg(feature = "ebpf")]
pub(crate) const TIP_LIST_APPS: &str = "try 'zelynic list-apps' to see live targets";

/// The state tip the unstrict family's no-match errors carry: the
/// surface that lists what is actually limited.
#[cfg(feature = "ebpf")]
pub(crate) const TIP_STATUS: &str = "try 'zelynic status' to see active limits";

/// Build the anyhow payload for a no-match refusal (NIGHT-dinner-11):
/// `head` carries the verdict, every tip rides its own indented
/// `tip:` line — the shape the line-aware labeled renderer paints
/// (bold red label, red body, white tips; a tip that quotes a command
/// like 'zelynic list-apps' renders green — NIGHT-dinner-12, the
/// "this is what you type" tier) before exit 1. Pure, so
/// the exact contract is pinned rootlessly in
/// test/cli/no_match_tests.rs.
#[cfg(feature = "ebpf")]
pub(crate) fn target_no_match_error(head: String, tips: &[String]) -> anyhow::Error {
    let mut msg = head;
    for tip in tips {
        msg.push_str("\n  tip: ");
        msg.push_str(tip);
    }
    anyhow::anyhow!("{msg}")
}

/// Shared error for commands compiled without the `ebpf` feature:
/// a single actionable message instead of the old eprintln + Err pair,
/// which printed the failure twice. Since NIGHT-ask-2 made `ebpf` the
/// default, this path is the explicit opt-out (`--no-default-features`)
/// — the message names both ways out: the default crate (full build)
/// and the source rebuild. The wording keeps the two substrings the
/// integration test pins (test/integration/privilege.rs: "eBPF not
/// compiled" + "cargo build --features ebpf").
#[cfg(not(feature = "ebpf"))]
pub(crate) fn ebpf_disabled() -> Result<()> {
    Err(anyhow::anyhow!(
        "eBPF not compiled into this build (built with --no-default-features)\n  \
         tip: cargo install zelynic ships the full build, or rebuild from \
         source with 'cargo build --features ebpf'"
    ))
}

// ━━ Command handlers (ebpf feature) ━━

/// Remove ALL BPF pin files + directory. Full cleanup.
/// Delegates to `limiter::unpin_all()` which iterates the pin directory
/// and removes every file, then removes the directory. Also removes the
/// legacy PID file if present.
#[cfg(feature = "ebpf")]
pub(crate) fn unpin_all_bpf() -> Result<()> {
    unpin_all()?;
    // Remove legacy PID file if present (from old serve-child versions).
    let _ = std::fs::remove_file(PID_FILE);
    Ok(())
}

// NIGHT-improve-28: the apply-verb epilogue pins live under the single
// test/ tree (cosmostrix Pattern C), #[path]-wired exactly like the
// print-json scope pins in cli/mod.rs.
#[cfg(test)]
#[cfg(feature = "ebpf")]
#[path = "../../test/cli/apply_epilogue_tests.rs"]
mod apply_epilogue_tests;

// NIGHT-dinner-11: the no-match hard-error pins — same single-test-tree
// wiring (the shape is a contract now, not a formatting accident).
#[cfg(test)]
#[cfg(feature = "ebpf")]
#[path = "../../test/cli/no_match_tests.rs"]
mod no_match_tests;
