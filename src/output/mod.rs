// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Capability-aware terminal output — the zelynic output layer.
//!
//! Module map (NIGHT-boost-5 split, the display.rs precedent for the
//! owner's 500-line cap):
//! - [`color`] — the brand tier: capability detection + every escape
//!   builder and wrapper (purple brand, green ok, red error, yellow
//!   warn, crystal-white suggestion, signature footer colors)
//! - [`labeled`] — labeled error/warning stderr lines
//! - [`sanitize`] — comm sanitization
//! - this root — the broken-pipe-safe print macros, the JSON print
//!   primitive, and the signature footer text
//!
//! Owner branding rule (ported from the cosmostrix output contract):
//! the zelynic brand color is purple #A855F7 (168,85,247), rendered
//! in whatever color depth the terminal actually supports — the full
//! capability table lives in the [`color`] module docs.
//!
//! Color is ALWAYS on for terminals — there is no `--no-color` CLI
//! flag (NIGHT-hunt-5 owner mandate: purple is branding, branding has
//! no opt-out). The standard env vars remain the only control
//! surface, exactly like cosmostrix, `bat`, `fd`, and `ripgrep`:
//! - `NO_COLOR` (https://no-color.org/) disables all colors.
//! - `CLICOLOR=0` disables colors.
//! - `CLICOLOR_FORCE=1` forces colors even when piped.
//! - Colors are stripped when stderr is not a TTY.
//!
//! Every user-facing print goes through the broken-pipe-safe macros
//! [`println_safe!`] / [`eprintln_safe!`]: Rust ignores SIGPIPE, so a
//! piped reader exiting early (`zelynic --help | head -2`) turns
//! `println!` into a panic with exit 101. The safe macros discard the
//! write error instead — the report is truncated at the pipe boundary
//! and the process exits with its intended code, standard Unix CLI
//! behavior for closed readers.

mod color;

// The `*_open()` escape builders stay color-internal: the wrapper
// functions below are the crate's entire color API surface (nothing
// outside the output layer ever assembles its own escape bytes).
pub use color::{brand, brand_bold, error, error_bold, ok, ok_bold, suggestion, warn_bold};
#[cfg(feature = "ebpf")] // champion tier + warn wrapper live under the eagle-eyes graph
pub use color::{hot, hot_blink, warn};

// ── Broken-pipe-safe println/eprintln (cosmostrix contract) ────────────────
//
// Rust ignores SIGPIPE by default, so when the user pipes a report into
// head/jq/grep and the reader exits early, println!/eprintln! panic on
// EPIPE with exit 101 (verified live on zelynic: `zelynic --help |
// head -2` aborted with 101). The macros below discard the write error
// instead — safe for every reachable output site, including the
// error paths that run while the terminal is being torn down.

/// Like `eprintln!` but never panics on a broken stderr pipe.
macro_rules! eprintln_safe {
        () => {{
                use std::io::Write as _;
                let _ = std::io::stderr().write_fmt(format_args!("\n"));
                let _ = std::io::stderr().flush();
        }};
        ($($arg:tt)*) => {{
                use std::io::Write as _;
                let _ = std::io::stderr().write_fmt(format_args!($($arg)*));
                let _ = std::io::stderr().write_fmt(format_args!("\n"));
                let _ = std::io::stderr().flush();
        }};
}

/// Like `println!` but never panics on a broken/closed stdout pipe.
macro_rules! println_safe {
    () => {{
            use std::io::Write as _;
            let _ = std::io::stdout().write_fmt(format_args!("\n"));
            let _ = std::io::stdout().flush();
    }};
    ($($arg:tt)*) => {{
            use std::io::Write as _;
            let _ = std::io::stdout().write_fmt(format_args!($($arg)*));
            let _ = std::io::stdout().write_fmt(format_args!("\n"));
            let _ = std::io::stdout().flush();
    }};
}

// ── JSON print primitive (NIGHT-boost-3) ────────────────────────────────────
//
// The `--print-json` write path, unified. The five call sites
// (status clean / status stale-pins / status proper / list-apps /
// doctor) previously mixed two renderers: `to_string_pretty` +
// `println_safe!` on two sites (a full pretty document allocated as
// a String, then copied a second time through the format machinery)
// and ad-hoc `json!` + Display on three. Every site now rides the
// one primitive below.

/// Print one JSON document to stdout as a single compact line.
///
/// Contract (NIGHT-boost-3, owner mandate "optimize json print"):
/// - compact single line — the machine-first format. One document
///   per invocation, `jq`-ready and NDJSON-friendly; pretty-printing
///   belongs to the consumer (`... | jq '.'`), not the producer.
/// - direct writer — `serde_json::to_writer` serializes field-by-field
///   into the locked stdout: no intermediate String allocation, no
///   second copy through the format machinery.
/// - broken-pipe-safe — write errors are discarded exactly like
///   [`println_safe!`], so a piped reader exiting early truncates
///   the document instead of panicking the process.
pub fn print_json<T: serde::Serialize + ?Sized>(value: &T) {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    let _ = serde_json::to_writer(&mut out, value);
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

/// The signature footer (NIGHT-boost-5): the identity line every
/// flagship surface signs its work with — `zelynic status` prints it
/// under the table, the eagle-eyes monitor carries it as the bottom
/// line of every frame (bottom-left, the owner's contract). The
/// version rides the crate manifest (`env!`), so the stamp can never
/// go stale the way a hardcoded literal would; brand purple because
/// the signature IS the brand mark (NIGHT-hunt-5: purple is
/// branding, and this line is the engraving).
#[must_use]
#[cfg(feature = "ebpf")] // every flagship surface lives under the ebpf graph
pub fn signature_footer() -> String {
    color::brand(&format!(
        "zelynic v{} by oxyzenQ (rezky_nightky)",
        env!("CARGO_PKG_VERSION")
    ))
}

mod labeled;
mod sanitize;

pub use labeled::eprintln_error_labeled;

#[cfg(feature = "ebpf")]
pub use labeled::eprintln_warn_labeled;
pub use sanitize::sanitize_comm;
