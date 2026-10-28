// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The print_json primitive pins (night-dragon-maintenance-T1 (s),
//! rewritten onto the hand-written lane by (S1)): the one write
//! path, one shape. These pins hold the byte contract — the document
//! bytes, exactly one trailing newline, nothing else — and the io
//! discipline (a broken pipe discards its error instead of panicking
//! the process). The grammar-violation class the (s) preflight
//! guarded died structurally with the serde derive stack: the hand
//! writers cannot emit a non-string key, so no preflight remains.

use super::write_json_line;

/// Success shape: the document bytes straight into the writer, then
/// exactly one trailing newline. No pretty whitespace, no double
/// newline — `jq`-ready and NDJSON-composable by construction.
#[test]
fn document_writes_exact_bytes_plus_one_newline() {
    let mut buf: Vec<u8> = Vec::new();
    write_json_line(&mut buf, "{\"watchdog\":\"clean\",\"active_limits\":0}");
    assert_eq!(
        String::from_utf8(buf).unwrap(),
        "{\"watchdog\":\"clean\",\"active_limits\":0}\n",
        "the success shape is one compact line plus one newline"
    );
}

/// The newline law: the primitive never invents or doubles the
/// separator. A document already carrying its own newline would be a
/// lane bug, and the pin holds the primitive's side: what goes in is
/// what lands, plus the one NDJSON terminator.
#[test]
fn empty_document_still_gets_its_newline() {
    let mut buf: Vec<u8> = Vec::new();
    write_json_line(&mut buf, "");
    assert_eq!(
        String::from_utf8(buf).unwrap(),
        "\n",
        "the newline rides even a degenerate empty document"
    );
}

/// The io discipline: a failing writer (the broken-pipe shape) has
/// its error discarded — no panic, no partial retry loop. The
/// process keeps its intended exit code; the reader that left early
/// keeps its truncation.
#[test]
fn broken_pipe_errors_are_discarded() {
    struct BrokenPipe;
    impl std::io::Write for BrokenPipe {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
    }
    let mut sink = BrokenPipe;
    write_json_line(&mut sink, "{\"watchdog\":\"clean\",\"active_limits\":0}");
}
