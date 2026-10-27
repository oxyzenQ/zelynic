// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Fuzz target: the terminal-safety neutralizer (the fuzz lane,
//! night-dragon-maintenance-5, ported from the zejtron estate's
//! sanitize_display target).
//!
//! [`sanitize_comm`] is the one gate between hostile text (process
//! names a local process sets byte for byte via prctl(PR_SET_NAME),
//! the `--check-update` release tag from a possibly-MITM'd proxy) and
//! the rendered row. Its contract is three properties, and the
//! harness asserts them on every input the fuzzer invents:
//!
//! 1. Terminal safety (the CWE-150 class): NO control character -
//!    C0, DEL, C1 - survives into the output. An escape sequence
//!    that reaches the terminal can forge the evidence stream
//!    zelynic's rows are trusted for; a violation here is a fuzzer
//!    crash, libFuzzer saves the input, and CI fails.
//! 2. Bidi safety (the night-hunt-40 extension): no character of
//!    the bidi embedding/override family (U+202A..=U+202E) or the
//!    isolate family (U+2066..=U+2069) survives - the CVE-2021-42574
//!    "Trojan Source" display-direction class, which
//!    `char::is_control` does NOT see.
//! 3. Honest-data fidelity: input carrying nothing the sanitizer's
//!    own predicate catches comes back byte-identical (the fast
//!    path's contract) - including the other Cf characters (ZWJ,
//!    ZWNJ, ZWSP, LRM, RLM, WJ, BOM) the contract deliberately
//!    passes through, so an over-eager future "strip everything"
//!    change fails here too.
//!
//! The `&str` type system refuses non-UTF-8 before this function
//! runs (the /proc readers' `read_to_string` and the update check's
//! UTF-8 gate sit upstream), so the harness drives the same UTF-8
//! gate the real callers sit behind. The source is path-included,
//! not copied (see fuzz/Cargo.toml for the full rationale): the
//! harness compiles the same bytes the binary ships.

#![no_main]

#[path = "../../src/output/sanitize.rs"]
mod sanitize;

use libfuzzer_sys::fuzz_target;

/// The bidi display-direction family the sanitizer's predicate
/// names explicitly - spelled here so the fidelity fast-path check
/// and the safety assertion agree on exactly one definition.
fn is_bidi_directional(c: char) -> bool {
    matches!(c as u32, 0x202A..=0x202E | 0x2066..=0x2069)
}

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let sanitized = sanitize::sanitize_comm(text);

        assert!(
            !sanitized.chars().any(char::is_control),
            "terminal injection: sanitize_comm let a control character \
             through (input {text:?}, output {sanitized:?})"
        );

        assert!(
            !sanitized.chars().any(is_bidi_directional),
            "bidi injection: sanitize_comm let a display-direction \
             format character through (input {text:?}, output \
             {sanitized:?})"
        );

        let honest = !text.chars().any(char::is_control) && !text.chars().any(is_bidi_directional);
        if honest {
            assert_eq!(
                sanitized, text,
                "sanitize_comm mutated honest data (input {text:?})"
            );
        }
    }
});
