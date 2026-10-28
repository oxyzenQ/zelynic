// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The JSON [`Value`] tree and the RFC 8259 parser that fills it.
//!
//! The parser exists for ONE runtime consumer — the docker Engine
//! API lane, whose replies are foreign bytes the daemon controls —
//! and for every test's assertion lens (the documents the writer
//! lanes emit are parsed back and pinned field-by-field). Both ride
//! the same tree, so the parse side and the write side can never
//! drift apart on what a JSON document is.
//!
//! Strictness follows the grammar serde_json enforced here before
//! (S1 keeps the docker lane's contract, including its error
//! wording): control bytes below 0x20 inside strings are errors,
//! lone surrogate escapes are errors, trailing content after the
//! top-level value is an error, and numbers follow the RFC shape
//! (no leading `+`, no leading zeros, a fraction and exponent when
//! present). The tree preserves number LEXEMES — a consumer reads
//! them through the typed accessors, so no float rounding ever
//! touches a PID or a byte count on the way through.
//!
//! Self-contained by design: std imports only. The black-box
//! integration harness `#[path]`-includes this file without linking
//! the binary crate.

use std::fmt;
use std::ops::Index;

/// How deep the parser may nest containers before refusing (a
/// hostile reply must not overflow the stack — the docker reply
/// budget caps bytes at 4 MiB, but 4 MiB of `[[[[...` is a stack
/// bomb all the same). The cap counts CONTAINER frames: the 128-deep
/// document parses, the 129th frame refuses.
const DEPTH_CAP: usize = 128;

/// A parsed JSON document.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// The number's raw lexeme, byte-preserved. The typed accessors
    /// (`as_u64`/`as_i64`/`as_f64`) parse on demand — the tree never
    /// rounds what it did not have to.
    Num(String),
    Str(String),
    Arr(Vec<Value>),
    /// Insertion-ordered object. `get` returns the FIRST match, the
    /// JSON semantics every consumer here needs (docker replies are
    /// daemon-shaped, our own documents never duplicate a key).
    Obj(Vec<(String, Value)>),
}

/// The parse error: the byte offset and the reason. Display rides
/// the docker lane's error wording ("docker API reply is not JSON:
/// {e}"), so the reason reads as a sentence fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub offset: usize,
    pub reason: &'static str,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.reason, self.offset)
    }
}

impl std::error::Error for Error {}

impl Value {
    /// Parse a complete JSON document from bytes.
    ///
    /// # Errors
    /// Any grammar violation, with the byte offset.
    pub fn parse(input: &[u8]) -> Result<Value, Error> {
        let mut p = Parser { b: input, pos: 0 };
        p.ws();
        let v = p.value(0)?;
        p.ws();
        if p.pos != p.b.len() {
            return Err(p.err("trailing content after the document"));
        }
        Ok(v)
    }

    /// Parse a complete JSON document from a string. The test lens's
    /// entry — the binary's runtime lane parses bytes (the docker
    /// reply), so this sibling is cfg(test)-gated to keep the
    /// non-test build free of never-called surface (the -D warnings
    /// law).
    #[cfg(test)]
    pub fn parse_str(input: &str) -> Result<Value, Error> {
        Self::parse(input.as_bytes())
    }

    /// First match for `key`, or None (objects only).
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The array slice (the docker lane's Names walk). The
    /// black-box integration harness shares this file without the
    /// binary's code, where no call site exists — the allow keeps
    /// that target's -D warnings green without splitting the lane.
    #[allow(dead_code)]
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Arr(items) => Some(items),
            _ => None,
        }
    }

    /// The lexeme as u64 (rejects negatives and non-integers).
    #[cfg(test)]
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Num(lex) => lex.parse().ok(),
            _ => None,
        }
    }

    /// The lexeme as i64 (rejects non-integers).
    #[cfg(test)]
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Num(lex) => lex.parse().ok(),
            _ => None,
        }
    }

    /// The lexeme as f64 (every RFC number shape parses).
    #[cfg(test)]
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Num(lex) => lex.parse().ok(),
            _ => None,
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
}

/// serde_json's indexing semantics: a missing key or an out-of-range
/// slot is `&Value::Null`, never a panic — assertion lenses (and the
/// docker lane's optional-field walks) chain without `unwrap` noise.
impl Index<&str> for Value {
    type Output = Value;
    fn index(&self, key: &str) -> &Value {
        self.get(key).unwrap_or(&Value::Null)
    }
}

impl Index<usize> for Value {
    type Output = Value;
    fn index(&self, i: usize) -> &Value {
        match self {
            Value::Arr(items) => items.get(i).unwrap_or(&Value::Null),
            _ => &Value::Null,
        }
    }
}

struct Parser<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn err(&self, reason: &'static str) -> Error {
        Error {
            offset: self.pos,
            reason,
        }
    }

    fn ws(&mut self) {
        while let Some(c) = self.b.get(self.pos) {
            match c {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        match self
            .peek()
            .ok_or_else(|| self.err("unexpected end of input"))?
        {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => Ok(Value::Str(self.string()?)),
            b't' => self.literal("true", Value::Bool(true)),
            b'f' => self.literal("false", Value::Bool(false)),
            b'n' => self.literal("null", Value::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(self.err("unexpected character")),
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, Error> {
        if self.b[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(self.err("invalid literal"))
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, Error> {
        if depth >= DEPTH_CAP {
            return Err(self.err("nesting too deep"));
        }
        self.pos += 1; // '{'
        let mut entries = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Obj(entries));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected a string object key"));
            }
            let key = self.string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return Err(self.err("expected ':' after the object key"));
            }
            self.pos += 1;
            self.ws();
            let val = self.value(depth + 1)?;
            entries.push((key, val));
            self.ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Obj(entries));
                }
                _ => return Err(self.err("expected ',' or '}' in the object")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, Error> {
        if depth >= DEPTH_CAP {
            return Err(self.err("nesting too deep"));
        }
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Arr(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth + 1)?);
            self.ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Arr(items));
                }
                _ => return Err(self.err("expected ',' or ']' in the array")),
            }
        }
    }

    /// One string with the full escape grammar. Returns an owned
    /// String only when escapes are present — the common daemon fast
    /// path (hex ids, plain names) slices without allocating.
    fn string(&mut self) -> Result<String, Error> {
        self.pos += 1; // opening '"'
        let mut start = self.pos;
        let mut out = String::new();
        loop {
            match self.peek().ok_or_else(|| self.err("unterminated string"))? {
                b'"' => {
                    if out.is_empty() {
                        // Fast path: no escapes — the whole span is
                        // the value.
                        let s = std::str::from_utf8(&self.b[start..self.pos])
                            .map_err(|_| self.err("invalid UTF-8 in string"))?
                            .to_owned();
                        self.pos += 1;
                        return Ok(s);
                    }
                    // Escaped path: the final (post-escape) segment
                    // still rides to the closing quote.
                    let s = std::str::from_utf8(&self.b[start..self.pos])
                        .map_err(|_| self.err("invalid UTF-8 in string"))?;
                    out.push_str(s);
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    let s = std::str::from_utf8(&self.b[start..self.pos])
                        .map_err(|_| self.err("invalid UTF-8 in string"))?;
                    out.push_str(s);
                    self.pos += 1;
                    self.escape(&mut out)?;
                    start = self.pos;
                }
                0x00..=0x1f => return Err(self.err("raw control byte in string")),
                _ => self.pos += 1,
            }
        }
    }

    /// One backslash escape (the leading `\\` is consumed).
    fn escape(&mut self, out: &mut String) -> Result<(), Error> {
        let c = self.peek().ok_or_else(|| self.err("unterminated escape"))?;
        self.pos += 1;
        match c {
            b'"' => out.push('"'),
            b'\\' => out.push('\\'),
            b'/' => out.push('/'),
            b'b' => out.push('\u{08}'),
            b'f' => out.push('\u{0c}'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'u' => {
                let hi = self.hex4()?;
                let ch = if (0xd800..0xdc00).contains(&hi) {
                    // High surrogate: the low surrogate MUST follow
                    // (lone surrogates are not scalars — an error,
                    // the strictness serde_json enforced here).
                    if self.b[self.pos..].starts_with(b"\\u") {
                        self.pos += 2;
                        let lo = self.hex4()?;
                        if !(0xdc00..0xe000).contains(&lo) {
                            return Err(self.err("invalid low surrogate"));
                        }
                        let combined =
                            0x1_0000 + ((u32::from(hi) - 0xd800) << 10) + (u32::from(lo) - 0xdc00);
                        char::from_u32(combined)
                            .ok_or_else(|| self.err("invalid surrogate pair"))?
                    } else {
                        return Err(self.err("lone high surrogate"));
                    }
                } else if (0xdc00..0xe000).contains(&hi) {
                    return Err(self.err("lone low surrogate"));
                } else {
                    char::from_u32(u32::from(hi)).ok_or_else(|| self.err("invalid escape"))?
                };
                out.push(ch);
            }
            _ => return Err(self.err("invalid escape character")),
        }
        Ok(())
    }

    /// Four ASCII hex digits, nothing else. Byte-wise validation,
    /// not `u16::from_str_radix`: the radix parser accepts a leading
    /// `+` sign (`u16::from_str_radix("+abc", 16)` is `Ok(2748)`),
    /// so a from_str_radix draft parsed `"\u+abc"` as U+0ABC — a
    /// strictness deviation serde_json never allowed (the T1 re-audit
    /// catch, the one bug the S1 lane shipped with). Every non-hex
    /// byte, sign included, is an error; non-UTF-8 needs no separate
    /// check because a byte that is not a hex digit is rejected on
    /// sight.
    fn hex4(&mut self) -> Result<u16, Error> {
        let slice = self
            .b
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| self.err("truncated \\u escape"))?;
        let mut value: u16 = 0;
        for &byte in slice {
            let digit = match byte {
                b'0'..=b'9' => u16::from(byte - b'0'),
                b'a'..=b'f' => u16::from(byte - b'a') + 10,
                b'A'..=b'F' => u16::from(byte - b'A') + 10,
                _ => return Err(self.err("invalid \\u escape")),
            };
            value = value * 16 + digit;
        }
        self.pos += 4;
        Ok(value)
    }

    /// The RFC 8259 number grammar, lexeme-preserved: `-`? (`0` |
    /// `[1-9][0-9]*`)? (`.` digits+)? (`[eE]` sign? digits+)?
    fn number(&mut self) -> Result<Value, Error> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(self.err("invalid number")),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("digit required after the decimal point"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("digit required in the exponent"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        // SAFETY-free: the slice is ASCII digits/punctuation by
        // construction above.
        let lex = std::str::from_utf8(&self.b[start..self.pos])
            .map_err(|_| self.err("invalid number"))?;
        Ok(Value::Num(lex.to_owned()))
    }
}

// The parser pins (one test file per module, cosmostrix Pattern C —
// #[path]-wired exactly like the display_json pins).
#[cfg(test)]
#[path = "../../test/json/parse_tests.rs"]
mod parse_tests;
