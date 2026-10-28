// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The JSON parser pins (night-dragon-maintenance-T1 (S1)): the
//! grammar the docker lane and every test lens rely on — strict
//! strings (control bytes and lone surrogates are errors), the
//! number lexeme preserved byte-exact, the depth cap, the
//! trailing-content refusal, and the serde_json indexing semantics
//! the assertion lenses chain on (a miss is Null, never a panic).

use super::*;

// ── scalars ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn scalars_round_trip() {
    assert_eq!(Value::parse_str("null").unwrap(), Value::Null);
    assert_eq!(Value::parse_str("true").unwrap(), Value::Bool(true));
    assert_eq!(Value::parse_str("false").unwrap(), Value::Bool(false));
    assert_eq!(
        Value::parse_str("\"hi\"").unwrap(),
        Value::Str("hi".to_string())
    );
}

/// The number keeps its raw lexeme; the typed accessors parse
/// on-demand. Floats never round an integer on the way through.
#[test]
fn number_lexemes_are_preserved_and_typed() {
    let v = Value::parse_str("18446744073709551615").unwrap();
    assert_eq!(v.as_u64(), Some(u64::MAX));
    assert_eq!(Value::parse_str("-42").unwrap().as_i64(), Some(-42));
    let f = Value::parse_str("1.25e2").unwrap();
    assert_eq!(f.as_f64(), Some(125.0));
    // The lexeme itself survives (a future writer pinning it sees
    // the exact bytes the producer sent).
    match Value::parse_str("1.25e2").unwrap() {
        Value::Num(lex) => assert_eq!(lex, "1.25e2"),
        other => panic!("expected a number, got {other:?}"),
    }
}

/// Number grammar: no leading zeros, no bare `+`, no empty fraction
/// or exponent. Each refusal names the offset.
#[test]
fn number_grammar_is_strict() {
    for bad in ["+1", "01", "1.", ".5", "1e", "1e+", "-", "1.2.3"] {
        assert!(Value::parse_str(bad).is_err(), "`{bad}` must not parse");
    }
}

// ── strings ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn escapes_decode() {
    let v = Value::parse_str(r#""a\"b\\c\/d\be\ff\ng\rh\ti""#).unwrap();
    assert_eq!(
        v,
        Value::Str("a\"b\\c/d\u{08}e\u{0c}f\ng\rh\ti".to_string())
    );
}

/// The full non-BMP round trip: a surrogate pair decodes to its
/// scalar; UTF-8 passes through verbatim.
#[test]
fn unicode_round_trips() {
    // The raw non-BMP scalar rides as UTF-8 bytes (composed from the
    // escape so this file stays ASCII for the sweep gates).
    let v = Value::parse_str(&format!("\"{}\"", '\u{1f600}')).unwrap();
    assert_eq!(v, Value::Str('\u{1f600}'.to_string()));
    let v = Value::parse_str("\"\\ud83d\\ude00\"").unwrap();
    assert_eq!(v, Value::Str("\u{1f600}".to_string()));
    let v = Value::parse_str(&format!(
        "\"{}\"",
        "\u{3b5}\u{3bb}\u{3bb}\u{3b7}\u{3bd}\u{3b9}\u{3ba}\u{3ac}"
    ))
    .unwrap();
    assert_eq!(
        v,
        Value::Str("\u{3b5}\u{3bb}\u{3bb}\u{3b7}\u{3bd}\u{3b9}\u{3ba}\u{3ac}".to_string())
    );
}

/// Lone surrogates are errors (the strictness the docker lane
/// inherited from serde_json), as are raw control bytes.
#[test]
fn strict_strings_reject_the_hostile_classes() {
    assert!(Value::parse_str(r#""\ud83d""#).is_err(), "lone high");
    assert!(Value::parse_str(r#""\ude00""#).is_err(), "lone low");
    assert!(
        Value::parse_str(r#""\ud83dA""#).is_err(),
        "high surrogate not followed by \\u"
    );
    assert!(Value::parse_str("\"\u{7f}\"").is_ok(), "DEL is legal JSON");
    assert!(Value::parse_str("\"\u{1}\"").is_err(), "raw control byte");
}

// ── structure ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A docker-shaped reply: the accessors the lane actually calls,
/// plus a field the lane ignores. The Index semantics chain exactly
/// like the serde_json lens the tests used before S1.
#[test]
fn docker_shaped_reply_walks() {
    let v = Value::parse_str(
        r#"[{"Id":"abc123","Names":["/nginx"],"State":{"Running":true},"Image":"nginx:latest"}]"#,
    )
    .unwrap();
    let first = &v[0];
    assert_eq!(first["Id"].as_str(), Some("abc123"));
    assert_eq!(first["State"]["Running"].as_bool(), Some(true));
    assert_eq!(first["Names"][0].as_str(), Some("/nginx"));
    // Misses are Null, never a panic: a missing key, a missing slot,
    // and a miss THROUGH a scalar all read as Null.
    assert!(first["Nope"].is_null());
    assert!(v[7].is_null());
    assert!(first["Id"]["deep"].is_null());
    // get() stays Option-shaped for the optional-field walks.
    assert!(first.get("Nope").is_none());
    assert!(first.get("State").is_some());
}

#[test]
fn trailing_content_and_broken_grammar_are_errors() {
    assert!(Value::parse_str("{} {}").is_err(), "trailing content");
    assert!(Value::parse_str("{}garbage").is_err());
    assert!(Value::parse_str("").is_err(), "empty input");
    assert!(Value::parse_str("{\"a\":}").is_err(), "missing value");
    assert!(Value::parse_str("{\"a\" 1}").is_err(), "missing colon");
    assert!(Value::parse_str("[1,]").is_err(), "trailing comma");
    assert!(Value::parse_str("{1:2}").is_err(), "non-string key");
    assert!(Value::parse_str("nul").is_err(), "truncated literal");
}

/// The depth cap: a hostile reply cannot blow the stack. 128 frames
/// parse fine; past the cap the parser refuses with its reason.
#[test]
fn nesting_past_the_depth_cap_is_refused() {
    let ok = format!("{}{}", "[".repeat(128), "]".repeat(128));
    assert!(Value::parse_str(&ok).is_ok(), "exactly at the cap parses");
    let deep = format!("{}{}", "[".repeat(DEPTH_CAP + 1), "]".repeat(DEPTH_CAP + 1));
    let err = Value::parse_str(&deep).expect_err("past the cap must refuse");
    assert_eq!(err.reason, "nesting too deep");
}

/// Whitespace is insignificant, objects keep insertion order (the
/// first duplicate-key win `get` documents), and empty containers
/// parse.
#[test]
fn whitespace_order_and_empty_containers() {
    let v = Value::parse_str("  { \"a\" : 1 ,\n\t \"b\" : [ 2 , 3 ] }  ").unwrap();
    assert_eq!(v["a"].as_u64(), Some(1));
    assert_eq!(v["b"][1].as_u64(), Some(3));
    let dup = Value::parse_str(r#"{"k":1,"k":2}"#).unwrap();
    assert_eq!(dup.get("k").and_then(Value::as_u64), Some(1), "first wins");
    assert_eq!(Value::parse_str("[]").unwrap(), Value::Arr(vec![]));
    assert_eq!(Value::parse_str("{}").unwrap(), Value::Obj(vec![]));
}

/// The error Display rides the docker lane's wording (a sentence
/// fragment after "docker API reply is not JSON: ").
#[test]
fn error_display_names_the_offset() {
    let err = Value::parse_str("[1,2,x]").expect_err("bad token");
    assert!(
        err.to_string().contains("unexpected character"),
        "reason rides: {err}"
    );
    assert!(err.to_string().contains("byte 5"), "offset rides: {err}");
}
