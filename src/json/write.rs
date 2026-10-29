// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The writer helpers every JSON document lane shares — the zejtron
//! lineage (the sibling's std-only evidence/doctor lanes): one escape
//! law, one array bracket grammar, one typed-absence vocabulary. No
//! document lane hand-rolls its own separators or its own escaping,
//! so the lanes cannot drift apart on the bytes a consumer receives.
//!
//! The escape law: quote and backslash take their two-character
//! forms, the named control bytes take `\b` `\f` `\n` `\r` `\t`, any
//! other control byte takes `\u00xx`, and every other scalar
//! (including all of UTF-8) passes through untouched — em-dash
//! labels and non-ASCII paths survive verbatim, as valid JSON.
//!
//! Self-contained by design: std imports only (the black-box
//! integration harness `#[path]`-includes the parse sibling; this
//! file keeps the same property).

use std::fmt;
use std::fmt::Write as _;

/// Write one JSON string literal (see the module escape law).
pub fn write_string(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            _ if (character as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", character as u32);
            }
            _ => out.push(character),
        }
    }
    out.push('"');
}

/// Write a JSON boolean (the two literals — no 0/1). Every build
/// flavor rides this one (the doctor's report_json emits four).
pub fn write_bool(out: &mut String, value: bool) {
    out.push_str(if value { "true" } else { "false" });
}

/// Write one JSON number — every Rust unsigned/signed integer type
/// renders through Display, the lexeme the consumer parses.
pub fn write_number<T: fmt::Display>(out: &mut String, value: T) {
    let _ = write!(out, "{value}");
}

/// Write a string only when the value exists; JSON null otherwise.
/// The typed absence every JSON lane shares: an absent fact is
/// absent, never an empty string.
pub fn write_opt_string(out: &mut String, value: Option<&str>) {
    match value {
        Some(value) => write_string(out, value),
        None => out.push_str("null"),
    }
}

/// Write a number only when the value exists; JSON null otherwise.
/// Same typed-absence law, for the numeric fields the /proc reads
/// leave unanswered. The ebpf graph's own vocabulary (the status and
/// depth lanes' null-riding numerics) — the dormant lane's doctor
/// emits no such field, and no test calls it either (the harness
/// #[path]-includes the parse sibling, never this file), so the
/// gate is feature-ONLY: a test-armed helper with zero dormant
/// callers is dead code the moment ci.yml's workflow-level
/// RUSTFLAGS="-D warnings" law compiles the dormant test build —
/// the S1 shape that kept main red, closed by the S3 gate
/// tightening.
#[cfg(feature = "ebpf")]
pub fn write_opt_number<T: fmt::Display>(out: &mut String, value: Option<T>) {
    match value {
        Some(value) => write_number(out, value),
        None => out.push_str("null"),
    }
}

/// Write a JSON array: the bracket grammar around `items` element
/// emissions, comma-separated. The one array shape every JSON lane
/// shares, so no serializer hand-rolls its own separators.
pub fn write_array(out: &mut String, items: usize, emit: impl Fn(&mut String, usize)) {
    out.push('[');
    for index in 0..items {
        if index > 0 {
            out.push(',');
        }
        emit(out, index);
    }
    out.push(']');
}
