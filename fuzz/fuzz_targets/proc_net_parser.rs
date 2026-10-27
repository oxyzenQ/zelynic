// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Fuzz target: the /proc/net socket-table row grammar (the fuzz
//! lane, night-dragon-maintenance-5, the zejtron estate's
//! proc-parser shape aimed at zelynic's own hostile surface).
//!
//! [`parse_proc_net_line`] reads the rows `/proc/net/{tcp,tcp6,udp,
//! udp6,raw,raw6}` expose - bytes a malicious or corrupted host
//! controls (a container's own netns, a compromised root, a fuzzed
//! kernel patch). The parser is the boundary between that hostility
//! and every renderer, matcher, and JSON document downstream, and
//! its documented contract is totality: any input line yields
//! either a well-formed row or None - never a panic, never an
//! unwrap explosion, never an arithmetic overflow.
//!
//! The harness drives the totality contract across all six table
//! spellings on every input the fuzzer invents, and pins the
//! invariants a Some(row) promises:
//!
//! 1. Totality: no input panics (the property itself - a panic IS
//!    the crash libFuzzer saves).
//! 2. Row sanity: a parsed row's state name is non-empty and ASCII
//!    (the parser's own `state_name` table vocabulary, not a
//!    /proc-supplied string).
//! 3. Family fidelity: the parsed row echoes the Proto the caller
//!    asked about - the parser never rewrites the table family.
//!
//! The sources are path-included, not copied (see fuzz/Cargo.toml
//! for the full rationale): the harness compiles the same
//! types.rs + parse.rs bytes the binary ships. parse.rs reaches its
//! types through `super::types`, a path that resolves identically
//! in the crate and in this harness module tree - the include law
//! scripts/gates/check-fuzz-includes.sh holds. The BPF kernel-side
//! code is deliberately not fuzzed: it runs behind the kernel
//! verifier, not in userspace.

#![no_main]

#[path = "../../src/ebpf/connections/types.rs"]
mod types;

#[path = "../../src/ebpf/connections/parse.rs"]
mod parse;

use libfuzzer_sys::fuzz_target;

use parse::parse_proc_net_line;
use types::Proto;

/// All six spellings, in the order the family law lists them - one
/// loop, no table drift.
const ALL_PROTOS: [Proto; 6] = [
    Proto::Tcp,
    Proto::Tcp6,
    Proto::Udp,
    Proto::Udp6,
    Proto::Raw,
    Proto::Raw6,
];

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        for proto in ALL_PROTOS {
            if let Some((_, info)) = parse_proc_net_line(line, proto) {
                assert!(
                    !info.state.is_empty() && info.state.is_ascii(),
                    "state name escaped the parser's own table vocabulary \
                     (input {line:?}, state {:?})",
                    info.state
                );
                assert_eq!(
                    info.proto, proto,
                    "the parser rewrote the table family the caller asked \
                     about (input {line:?})"
                );
            }
        }
    }
});
