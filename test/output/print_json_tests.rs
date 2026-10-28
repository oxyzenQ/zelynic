// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The print_json primitive pins (night-dragon-maintenance-T1 (s)):
//! the one write path, one shape. These pins hold the byte contract
//! on success (compact single line, the NDJSON newline) and the
//! failure law (a serialization failure can never produce the ONE
//! output shape no JSON consumer can parse: a partial document that
//! ends in a newline), plus the debug-only grammar preflight that
//! kills the non-string map key class at development time.

use std::collections::HashMap;

use serde_json::json;

use super::print_json;
use super::write_json_line;

/// Success shape: compact field stream straight into the writer, then
/// exactly one trailing newline. No pretty whitespace, no double
/// newline — `jq`-ready and NDJSON-composable by construction.
#[test]
fn valid_document_writes_exact_compact_bytes() {
    let mut buf: Vec<u8> = Vec::new();
    write_json_line(&mut buf, &json!({"watchdog": "clean", "active_limits": 0}));
    assert_eq!(
        String::from_utf8(buf).unwrap(),
        // serde_json's Value map is a BTreeMap by default, so the
        // compact stream sorts the keys; the pin holds the exact
        // bytes a consumer receives.
        "{\"active_limits\":0,\"watchdog\":\"clean\"}\n",
        "the success shape is one compact line plus one newline"
    );
}

/// The failure law, exercised by the incident class itself: a null
/// map key is exactly the shape the JSON grammar cannot represent
/// (serde_json answers "Null is not a valid map key" — it stringifies
/// the number and bool key rungs, so None is the honest reachable
/// case). The buffer must NOT gain the trailing newline — a failed
/// document stays an obviously incomplete shape, never a
/// complete-looking line.
#[test]
fn failed_serialization_never_ends_with_a_newline() {
    let mut non_string_keys: HashMap<Option<u8>, u8> = HashMap::new();
    non_string_keys.insert(None, 2);
    let mut buf: Vec<u8> = Vec::new();
    write_json_line(&mut buf, &non_string_keys);
    let text = String::from_utf8(buf).unwrap();
    assert!(
        !text.ends_with('\n'),
        "a failed document must not gain the trailing newline: got {text:?}"
    );
}

/// The debug-only preflight: print_json itself refuses the grammar
/// class BEFORE any byte reaches stdout (the sink pass runs first),
/// so a future call site's type mistake dies as a developer-visible
/// panic with the incident-class name, not as a partial document in a
/// user's pipe. Test-only builds panic on the preflight; the release
/// path keeps the single-pass write (the cfg keeps this pin out of a
/// release test run, where the preflight does not exist).
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "violates the JSON grammar")]
fn debug_preflight_panics_on_grammar_violation() {
    let mut non_string_keys: HashMap<Option<u8>, u8> = HashMap::new();
    non_string_keys.insert(None, 2);
    print_json(&non_string_keys);
}
