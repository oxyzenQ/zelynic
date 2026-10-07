// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Line-aware labeled rendering for stderr diagnostics (cosmostrix
//! S-master-HUNT-5 contract, ported in NIGHT-hunt-5).
//!
//! The owner color contract: errors render as `error: <body>` with a
//! bold red label and a red body; warnings render as `! <body>` with a
//! bold yellow label. Suggestion lines embedded anywhere in the block
//! (`tip:`, `hint:`, did-you-mean, possible-value lists) switch to the
//! suggestion white semantic so a typo tip never drowns in the error
//! color it lives inside. In Mono mode everything is plain text.
//!
//! NIGHT-dinner-12 (the owner's green-suggestion call): a tip that
//! carries a quoted command to RUN (`'zelynic ...`, `'cargo ...`) is
//! not passive advice — it renders in the status-green "this is what
//! you type" tier (the same semantic NIGHT-boost-4 gave every
//! `--help` example line), so the way out of a red block reads as an
//! action instead of more of the error.
//!
//! All emitters are broken-pipe-safe via the crate-wide
//! `eprintln_safe!` macro (textual scope from the output module).
//!
//! NIGHT-hunt-Z9 (the CLI echo boundary): every line rendered here
//! passes through [`super::sanitize_comm`] BEFORE its semantic wrap
//! — control bytes become `?` before any color code is added. The
//! labeled pair is the single exit-adjacent renderer for runtime
//! failures (`main` funnels every anyhow error through
//! `eprintln_error_labeled`) and the warn channel the guards use,
//! so user-supplied strings echoed inside error and warn bodies
//! (targets, rates, durations — the OSC-52 clipboard payload a
//! paste-attack crafts into a target name) can never reach the
//! terminal raw. The wrap functions add this layer's OWN escapes
//! after sanitization, so the branded colors survive untouched —
//! the same terminal-injection contract the /proc comm boundary
//! (NIGHT-cybersecurity-1) and the release-tag boundary
//! (NIGHT-cybersecurity-2) already enforce, extended to the one
//! input class neither covered: the command line itself.

use super::sanitize_comm;
use super::{error, error_bold, ok, suggestion};
#[cfg(feature = "ebpf")]
use super::{warn, warn_bold};

/// Recognize a suggestion line inside an error/warning block.
///
/// Matches lines whose trimmed content starts with one of the canonical
/// suggestion prefixes: `tip:` (clap-style did-you-mean and the value
/// suggestion engine in `cli::ux`), `hint:` (JSON status hints),
/// `[possible values` / `(possible values` (enum value lists), and
/// `did you mean` (legacy phrasing kept for safety). Indentation is
/// irrelevant — messages compose these lines at varying depths.
fn is_suggestion_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("tip:")
        || t.starts_with("hint:")
        || t.starts_with("[possible values")
        || t.starts_with("(possible values")
        || t.starts_with("did you mean")
}

/// Recognize a RUNNABLE tip: a suggestion line whose text carries a
/// quoted command to type (`'zelynic ...`, `'cargo ...`).
///
/// NIGHT-dinner-12: the owner's call — after a hard refusal the line
/// that matters is the way out (`tip: try 'zelynic list-apps'`), and
/// it must read as an action, not as more of the red block it lives
/// in. The status-green "this is what you type" tier (NIGHT-boost-4,
/// the `--help` example tier) is exactly that semantic, so runnable
/// tips join it. Passive suggestions — did-you-mean, possible-value
/// lists, "re-run without sudo" advice — keep the crystal-white
/// tier: they explain, they do not hand you a command. The quoting
/// convention (`'zelynic list-apps'`) is the classifier's contract:
/// every producer that names a command quotes it, so the split stays
/// mechanical, never guessed from sentence shape.
fn is_runnable_tip_line(line: &str) -> bool {
    let t = line.trim_start();
    (t.starts_with("tip:") || t.starts_with("hint:"))
        && (t.contains("'zelynic ") || t.contains("'cargo "))
}

/// Render a labeled multi-line message with per-line semantic colors.
///
/// The FIRST line gets `{label} {body}` with the label bold in the
/// message semantic. Every subsequent line keeps the message color —
/// EXCEPT suggestion lines (see [`is_suggestion_line`]), which render
/// in the suggestion (white) semantic, and runnable tips among them
/// (see [`is_runnable_tip_line`]), which render in the status-green
/// "this is what you type" semantic. In Mono mode everything is plain
/// text.
fn render_labeled_block(
    label: &str,
    label_wrap: fn(&str) -> String,
    body_wrap: fn(&str) -> String,
    msg: &str,
) -> String {
    let mut lines = msg.split('\n');
    let mut out = String::with_capacity(msg.len() + 32);
    // First line: always the labeled head, always the message
    // semantic. NIGHT-hunt-Z9: each line is sanitized BEFORE its
    // wrap — the wrap adds this layer's own escapes around a clean
    // body, so only user-supplied control bytes die (the labels and
    // wraps are program-generated and control-free).
    if let Some(first) = lines.next() {
        out.push_str(&format!(
            "{} {}",
            label_wrap(label),
            body_wrap(&sanitize_comm(first))
        ));
    }
    // Subsequent lines: runnable tips go green (this is what you
    // type), the remaining suggestion lines white, the rest keeps
    // the message semantic. Classification runs on the RAW line
    // (the `tip:`/`hint:` prefixes are program-generated text, so
    // sanitization cannot move a line across tiers).
    for line in lines {
        out.push('\n');
        let styled = if is_runnable_tip_line(line) {
            ok(&sanitize_comm(line))
        } else if is_suggestion_line(line) {
            suggestion(&sanitize_comm(line))
        } else {
            body_wrap(&sanitize_comm(line))
        };
        out.push_str(&styled);
    }
    out
}

/// Print a labeled error to stderr: `error: <msg>` in red, line-aware.
///
/// The single exit-adjacent error renderer for runtime failures —
/// every anyhow message that reaches `main()` flows through here, so
/// all runtime errors share one branded shape (bold red label, red
/// body, white tip lines, green runnable tips).
pub fn eprintln_error_labeled(msg: &str) {
    eprintln_safe!("{}", render_labeled_block("error:", error_bold, error, msg));
}

/// Print a labeled warning to stderr: `! <msg>` in yellow, line-aware.
///
/// ASCII label only — icon glyphs and pictographs render as tofu on
/// some terminals, and the repo-wide emoji gate forbids them anyway.
///
/// ebpf-gated: every current caller is a limiter-surface warning.
#[cfg(feature = "ebpf")]
pub fn eprintln_warn_labeled(msg: &str) {
    eprintln_safe!("{}", render_labeled_block("!", warn_bold, warn, msg));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_all_suggestion_prefixes() {
        for line in [
            "tip: a similar value exists: '1mb'",
            "  tip: a similar subcommand exists: 'strict-single'",
            "hint: run 'zelynic recover'",
            "[possible values: b, kb, mb, gb]",
            "(possible values: s, m, h)",
            "did you mean 'strict-single'?",
        ] {
            assert!(is_suggestion_line(line), "must classify: {line:?}");
        }
    }

    #[test]
    fn rejects_non_suggestion_lines() {
        for line in [
            "error: something broke",
            "  This may destabilize your system.",
            "Rate 500 is below minimum (1000 B/s).",
            "",
            "tips are not a prefix match here",
        ] {
            assert!(!is_suggestion_line(line), "must NOT classify: {line:?}");
        }
    }

    /// NIGHT-dinner-12: a tip that carries a quoted runnable command
    /// classifies into the green "this is what you type" tier; passive
    /// tips stay in the white suggestion tier.
    #[test]
    fn classifies_runnable_tips_apart_from_passive_ones() {
        for line in [
            "  tip: try 'zelynic list-apps' to see live targets",
            "  tip: try 'zelynic status' to see active limits",
            "  tip: run 'zelynic recover'",
            "  tip: find ids with 'zelynic list-apps'",
            "  hint: run 'zelynic recover'",
            "  tip: retry 'zelynic recover', or 'zelynic u --all' to force-clear",
            "  tip: rebuild with 'cargo build --features ebpf'",
        ] {
            assert!(is_runnable_tip_line(line), "runnable: {line:?}");
            assert!(is_suggestion_line(line), "still a suggestion: {line:?}");
        }
        for line in [
            "  tip: a similar value exists: '1mb'",
            "  tip: re-run without sudo",
            "  tip: use --allow-dangerous",
            "  tip: system apps need --force-this",
            "  tip: the list separator is '::' — single ':' stays inside a target",
            "  did you mean 'strict-single'?",
            "  error: not a tip at all",
        ] {
            assert!(!is_runnable_tip_line(line), "passive: {line:?}");
        }
    }

    /// The labeled head always renders as `{label} {first-line}`.
    #[test]
    fn labeled_block_head_shape() {
        let rendered = render_labeled_block("error:", error_bold, error, "root required");
        assert!(rendered.starts_with("error: root required"));
    }

    /// Suggestion lines inside a block keep their exact text — only the
    /// semantic wrapper differs per capability, which is covered by the
    /// escape-tier tests in the parent module.
    #[test]
    fn labeled_block_preserves_line_text() {
        let msg = "rate below minimum\n  tip: use --allow-dangerous";
        let rendered = render_labeled_block("error:", error_bold, error, msg);
        assert!(rendered.contains('\n'));
        assert!(rendered.contains("tip: use --allow-dangerous"));
    }

    /// NIGHT-hunt-Z9 (the CLI echo boundary): every control byte in
    /// an error body dies at this renderer — the OSC-52
    /// clipboard-write payload a paste-attack crafts into a target
    /// name renders with `?` in place of every control character
    /// (ESC and BEL alike), so the sequence can never reach the
    /// terminal raw. The clean part of the line survives verbatim.
    #[test]
    fn labeled_block_kills_osc52_payload_in_body() {
        let payload = "sshd\u{1b}]52;c;aGVsbG8=\u{7} is a system process";
        let rendered = render_labeled_block("error:", error_bold, error, payload);
        assert!(
            !rendered.contains('\u{1b}'),
            "no raw ESC may survive the render, got: {rendered:?}"
        );
        assert!(
            !rendered.contains('\u{7}'),
            "no raw BEL may survive the render, got: {rendered:?}"
        );
        assert!(
            rendered.contains("sshd?]52;c;aGVsbG8=? is a system process"),
            "the payload renders with '?' substitutions, got: {rendered:?}"
        );
    }

    /// Subsequent lines sanitize too — a CSI color smuggled into the
    /// second line of a multi-line error (the tip body, a caused-by
    /// hop) is neutralized the same way, and the newline structure
    /// the line-aware tiers depend on is untouched.
    #[test]
    fn labeled_block_kills_csi_payload_in_later_lines() {
        let msg = "Invalid number in rate '1\u{1b}[31mxkb'\n  tip: a similar value exists: '1kb'";
        let rendered = render_labeled_block("error:", error_bold, error, msg);
        assert!(
            !rendered.contains('\u{1b}'),
            "no raw ESC in any line, got: {rendered:?}"
        );
        assert!(
            rendered.contains("rate '1?[31mxkb'"),
            "the smuggled CSI renders with the '?' substitution, got: {rendered:?}"
        );
        assert!(
            rendered.contains("tip: a similar value exists: '1kb'"),
            "the clean tip line survives verbatim, got: {rendered:?}"
        );
    }

    /// Clean text passes byte-identical — the fast path must not
    /// alter honest names, tips, or punctuation (the sanitize_comm
    /// passthrough contract, pinned here at the render boundary).
    #[test]
    fn labeled_block_clean_text_passes_through() {
        let msg = "'sshd' is a system process\n  tip: re-run with --force-this";
        let rendered = render_labeled_block("error:", error_bold, error, msg);
        assert!(rendered.contains("'sshd' is a system process"));
        assert!(rendered.contains("tip: re-run with --force-this"));
    }
}
