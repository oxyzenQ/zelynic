// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Untrusted-string sanitization — the terminal display boundary
//! (NIGHT-cybersecurity-1; relocated from src/ebpf/identity/ by
//! NIGHT-cybersecurity-2 so the one canonical sanitizer is reachable
//! from BOTH feature graphs).
//!
//! Two classes of untrusted string reach zelynic's printing surfaces:
//!
//!  * `/proc` comm labels — `prctl(PR_SET_NAME)` lets ANY
//!    unprivileged process set its own `/proc/<pid>/comm` to 15
//!    bytes of near-arbitrary content.
//!  * the `--check-update` release tag — a network string from the
//!    GitHub API response, where curl inherits the invoking user's
//!    proxy environment (a MITM'd or compromised proxy is in the
//!    threat model even over TLS).
//!
//! Every surface that prints either runs as the admin's terminal, so
//! an unsanitized string is a terminal-injection vector: OSC 52 can
//! rewrite the clipboard, newlines can forge lines that look like
//! zelynic's own output (a fake cgroup-id row nudges an admin toward
//! the wrong target), and escape sequences corrupt the alt-screen
//! monitor.
//!
//! All consumers — the identity walk's `pid_comm`, the update
//! check's tag rendering, display, JSON, matching, majority-vote
//! tally — pass their labels through [`sanitize_comm`], making every
//! downstream consumer safe by construction. The empty-label and
//! fallback paths (`cg:{id}`, `pid {pid}`) are kernel- or
//! program-generated and need no extra pass.

// NON_LATIN_FIXTURE: the CJK comm row in the tests below is
// intentional Unicode passthrough coverage for the sanitizer
// contract, not prose (scripts/gates/check-language.sh exemption).

/// Replace every control character (Rust `char::is_control` covers C0,
/// DEL, and C1) with '?'. procps-ng applies the same substitution to
/// comm for the same reason. Clean labels take an unchanged clone
/// through the fast path.
///
/// night-hunt-40 (white-hat extension): the same `?` substitution
/// also catches the Unicode bidi formatting characters that
/// `char::is_control` does NOT see (Cf category, not Cc): the
/// embedding/override family U+202A..=U+202E (LRE, RLE, PDF, LRO,
/// RLO) and the isolate family U+2066..=U+2069 (LRI, RLI, FSI, PDI).
/// A comm carrying RLO (`\u{202E}`) flips every following character's
/// display direction in the admin's terminal — the CVE-2021-42574
/// "Trojan Source" class applied to terminal rendering instead of
/// source code. The 15-byte comm budget admits three of these (each
/// is 3 UTF-8 bytes) plus 6 ASCII chars, enough to craft a label
/// that visually masquerades as a different name. `char::is_control`
/// returns false for all nine — verified against Rust 1.98.1 — so
/// the old gate let them through to every downstream consumer
/// (display, JSON, matching, majority-vote tally) exactly as the
/// raw bytes came in from /proc or the docker Engine API. The
/// extension closes that hole at the same choke point the C0/C1
/// family lives; the matching lane operates on the sanitized
/// string so two comms that differ only in an RLO cannot be
/// mistaken for each other.
pub fn sanitize_comm(raw: &str) -> String {
    if raw.chars().any(needs_sanitize) {
        raw.chars()
            .map(|c| if needs_sanitize(c) { '?' } else { c })
            .collect()
    } else {
        raw.to_string()
    }
}

/// The substitution predicate: every control character (Rust's C0 +
/// DEL + C1) AND the Unicode bidi formatting family that
/// `char::is_control` does not catch. Separated from
/// [`sanitize_comm`] so the predicate is one name in the source
/// and the test suite can pin each family independently.
#[inline]
fn needs_sanitize(c: char) -> bool {
    if c.is_control() {
        return true;
    }
    // The bidi embedding/override + isolate family — Cf category,
    // invisible, display-direction-affecting. `is_control()` returns
    // false for all nine (verified against rustc 1.98.1, the repo's
    // pinned toolchain). The other Cf chars (ZWJ, ZWNJ, ZWSP, LRM,
    // RLM, WJ, BOM) are invisible but NOT display-direction-affecting
    // and have legitimate uses in some scripts/emoji, so they ride
    // the fast path; only the bidi family is the terminal-injection
    // vector.
    matches!(c as u32,
        0x202A..=0x202E   // LRE, RLE, PDF, LRO, RLO
        | 0x2066..=0x2069 // LRI, RLI, FSI, PDI
    )
}

#[cfg(test)]
mod tests {
    use super::sanitize_comm;

    /// NIGHT-cybersecurity-1: every control character in a comm label
    /// is replaced — the OSC/ANSI terminal-injection family (ESC-led),
    /// the row-forging family (newline, CR, tab), and the DEL/C1
    /// range — while printable ASCII and non-control UTF-8 pass.
    #[test]
    fn test_sanitize_comm_replaces_every_control_char() {
        // OSC 52 clipboard-write attempt: ESC ] 5 2 ; p ; <base64> BEL
        let osc52 = "\u{1b}]52;p;SGVsbG8=\u{7}";
        assert_eq!(sanitize_comm(osc52), "?]52;p;SGVsbG8=?");
        // CSI color reset smuggled around a name.
        assert_eq!(sanitize_comm("\u{1b}brave"), "?brave");
        // Newline + CR: the forged-output-line family.
        assert_eq!(sanitize_comm("evil\nroot\tX11"), "evil?root?X11");
        assert_eq!(sanitize_comm("evil\r\n8066"), "evil??8066");
        // DEL and a C1 control (8-bit terminals).
        assert_eq!(sanitize_comm("a\u{7f}b"), "a?b");
        assert_eq!(sanitize_comm("a\u{9b}b"), "a?b");
        // NUL never survives read_to_string, but the function is total.
        assert_eq!(sanitize_comm("\u{0}"), "?");
    }

    /// NIGHT-cybersecurity-1: clean labels pass through byte-identical
    /// — the fast path must not alter honest names (including CJK and
    /// the dashed/punctuated shapes the label column truncates).
    #[test]
    fn test_sanitize_comm_clean_labels_pass_through() {
        assert_eq!(sanitize_comm("brave"), "brave");
        assert_eq!(sanitize_comm("rust-analyzer"), "rust-analyzer");
        assert_eq!(sanitize_comm("firefox.bin.2"), "firefox.bin.2");
        assert_eq!(sanitize_comm("谷歌浏览器"), "谷歌浏览器");
        assert_eq!(sanitize_comm(""), "");
    }

    /// night-hunt-40 white-hat: the Unicode bidi formatting family
    /// (Cf category — `is_control()` returns false for all nine)
    /// must be substituted with `?` at the same choke point as the
    /// C0/C1 family. A comm carrying an RLO flips every following
    /// character's display direction in the admin's terminal; the
    /// 15-byte comm budget admits three bidi chars plus six ASCII
    /// chars, enough to craft a label that visually masquerades as
    /// a different name (the CVE-2021-42574 "Trojan Source" class
    /// applied to terminal rendering). The fast path's `any` gate
    /// fires on the first bidi char, so this test pins the
    /// substitution for every member of both families.
    #[test]
    fn test_sanitize_comm_replaces_every_bidi_format_char() {
        // The embedding/override family U+202A..=U+202E.
        assert_eq!(sanitize_comm("\u{202A}"), "?"); // LRE
        assert_eq!(sanitize_comm("\u{202B}"), "?"); // RLE
        assert_eq!(sanitize_comm("\u{202C}"), "?"); // PDF
        assert_eq!(sanitize_comm("\u{202D}"), "?"); // LRO
        assert_eq!(sanitize_comm("\u{202E}"), "?"); // RLO
                                                    // The isolate family U+2066..=U+2069.
        assert_eq!(sanitize_comm("\u{2066}"), "?"); // LRI
        assert_eq!(sanitize_comm("\u{2067}"), "?"); // RLI
        assert_eq!(sanitize_comm("\u{2068}"), "?"); // FSI
        assert_eq!(sanitize_comm("\u{2069}"), "?"); // PDI
                                                    // A realistic Trojan-Source comm: RLO flips the suffix
                                                    // direction so "evil\u{202E}nwp" would render as "evil" + RLO
                                                    // + "pwn" (visually "nwp" reversed). The `?` substitution
                                                    // makes the bidi visible AND neutralizes the override — the
                                                    // admin sees "evil?nwp", the matching lane compares the
                                                    // sanitized bytes, and the terminal never sees the RLO.
        assert_eq!(sanitize_comm("evil\u{202E}nwp"), "evil?nwp");
        // An LRO + RLO stack — the kind a careful attacker piles on
        // to break out of a defender's halfway fix that only strips
        // RLO. Both die at the same gate.
        assert_eq!(sanitize_comm("\u{202D}\u{202E}"), "??");
        // PDF and PDI are the directional POPs that close an
        // embedding/isolate; an attacker can carry one without an
        // opening to nudge the terminal out of a defender's
        // partial fix. They die at the same gate.
        assert_eq!(sanitize_comm("evil\u{202C}\u{2069}"), "evil??");
    }

    /// night-hunt-40 white-hat: the OTHER Cf chars (ZWJ, ZWNJ, ZWSP,
    /// LRM, RLM, WJ, BOM) ride the fast path — they are invisible
    /// but NOT display-direction-affecting, and they have legitimate
    /// uses in some scripts and emoji sequences. The sanitize
    /// contract deliberately leaves them alone; this pin guards
    /// against an over-eager future "strip all Cf" change that
    /// would break an honest emoji comm or a Persian/Arabic word
    /// carrying a ZWNJ.
    #[test]
    fn test_sanitize_comm_leaves_other_cf_chars_untouched() {
        assert_eq!(sanitize_comm("a\u{200B}b"), "a\u{200B}b"); // ZWSP
        assert_eq!(sanitize_comm("a\u{200C}b"), "a\u{200C}b"); // ZWNJ
        assert_eq!(sanitize_comm("a\u{200D}b"), "a\u{200D}b"); // ZWJ
        assert_eq!(sanitize_comm("a\u{200E}b"), "a\u{200E}b"); // LRM
        assert_eq!(sanitize_comm("a\u{200F}b"), "a\u{200F}b"); // RLM
        assert_eq!(sanitize_comm("a\u{2060}b"), "a\u{2060}b"); // WJ
        assert_eq!(sanitize_comm("a\u{FEFF}b"), "a\u{FEFF}b"); // BOM/ZWNBSP
    }
}
