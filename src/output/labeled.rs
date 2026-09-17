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
//! All emitters are broken-pipe-safe via the crate-wide
//! `eprintln_safe!` macro (textual scope from the output module).

use super::{error, error_bold, suggestion};
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

/// Render a labeled multi-line message with per-line semantic colors.
///
/// The FIRST line gets `{label} {body}` with the label bold in the
/// message semantic. Every subsequent line keeps the message color —
/// EXCEPT suggestion lines (see [`is_suggestion_line`]), which render
/// in the suggestion (white) semantic. In Mono mode everything is
/// plain text.
fn render_labeled_block(
    label: &str,
    label_wrap: fn(&str) -> String,
    body_wrap: fn(&str) -> String,
    msg: &str,
) -> String {
    let mut lines = msg.split('\n');
    let mut out = String::with_capacity(msg.len() + 32);
    // First line: always the labeled head, always the message semantic.
    if let Some(first) = lines.next() {
        out.push_str(&format!("{} {}", label_wrap(label), body_wrap(first)));
    }
    // Subsequent lines: suggestion lines switch to the white semantic.
    for line in lines {
        out.push('\n');
        let styled = if is_suggestion_line(line) {
            suggestion(line)
        } else {
            body_wrap(line)
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
/// body, white tip lines).
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
}
