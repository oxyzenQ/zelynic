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
// contract, not prose (scripts/check-language.sh exemption).

/// Replace every control character (Rust `char::is_control` covers C0,
/// DEL, and C1) with '?'. procps-ng applies the same substitution to
/// comm for the same reason. Clean labels take an unchanged clone
/// through the fast path.
pub fn sanitize_comm(raw: &str) -> String {
    if raw.chars().any(|c| c.is_control()) {
        raw.chars()
            .map(|c| if c.is_control() { '?' } else { c })
            .collect()
    } else {
        raw.to_string()
    }
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
}
