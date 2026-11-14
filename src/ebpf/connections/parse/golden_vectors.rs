// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The golden vectors (night-frontier-Z5) — the release attestation
//! corpus over the pure IP layer: named, frozen input rows with
//! their exact expected verdicts, one test that walks the whole
//! corpus and refuses any drift. This module is the corpus of
//! record (docs/GOLDEN_VECTORS.md mirrors it for reading; the test
//! is the authority) and every CI run — commit and release alike —
//! re-ratifies it: an output that changes is a corpus change, and a
//! corpus change is a release-note event. The vectors are a pure
//! function of the parser (input bytes in, verdict out, no clock,
//! no environment), which is exactly what makes the engine's
//! behavior attestable knowledge — the determinism contract's
//! release-time proof (docs/STABILITY.md).
use super::*;

/// One vector's expected verdict (the fields the pure layer
/// publishes; the parser's whole contract for a data row).
#[derive(Debug)]
struct Want {
    inode: u64,
    remote: &'static str,
    state: &'static str,
    queued: bool,
}

/// One golden vector: a frozen /proc/net row and its verdict.
/// `want: None` means the row must be REJECTED (the no-match
/// contract — reject, never guess).
struct GoldenVector {
    name: &'static str,
    line: &'static str,
    proto: Proto,
    want: Option<Want>,
}

const GOLDEN_VECTORS: &[GoldenVector] = &[
    GoldenVector {
        name: "GV-01:tcp-established-v4",
        line: "  3: 0100007F:8D2A 34120A0A:01F5 01 00000000:00000014 \
               00:00000000 00000000  1000 0 777001 1 0000000000000000 100 0 0 10 0",
        proto: Proto::Tcp,
        want: Some(Want {
            inode: 777001,
            remote: "10.10.18.52:501",
            state: "ESTABLISHED",
            queued: true,
        }),
    },
    GoldenVector {
        name: "GV-02:tcp-listen-v4",
        line: "  0: 00000000:0016 00000000:0000 0A 00000000:000000 \
               00:00000000 00000000     0 0 22221 1 0000000000000000 100 0 0 10 0",
        proto: Proto::Tcp,
        want: Some(Want {
            inode: 22221,
            remote: "0.0.0.0:0",
            state: "LISTEN",
            queued: false,
        }),
    },
    GoldenVector {
        name: "GV-03:tcp-time-wait-v4",
        line: "  9: 0100007F:8D2A 8FAA5A0A:01BB 06 00000000:00000000 \
               00:00000000 00000000  1000 0 555003 1 0000000000000000 100 0 0 10 0",
        proto: Proto::Tcp,
        want: Some(Want {
            inode: 555003,
            remote: "10.90.170.143:443",
            state: "TIME_WAIT",
            queued: false,
        }),
    },
    GoldenVector {
        name: "GV-04:tcp-established-v6",
        line: " 24: 00000000000000000000000000000000:9C40 \
               00000000000000000000000001000000:01BB 01 00000000:00000000 \
               00:00000000 00000000  1000 0 888004 1 0000000000000000 100 0 0 10 0",
        proto: Proto::Tcp6,
        want: Some(Want {
            inode: 888004,
            remote: "[::1]:443",
            state: "ESTABLISHED",
            queued: false,
        }),
    },
    GoldenVector {
        name: "GV-05:udp-connected-v4",
        line: " 12: 00000000:0000 0100007F:0035 01 00000000:00000438 \
               00:00000000 00000000  1000 0 333002 1 0000000000000000 100 0 0 10 0",
        proto: Proto::Udp,
        want: Some(Want {
            inode: 333002,
            remote: "127.0.0.1:53",
            state: "ESTABLISHED",
            queued: true,
        }),
    },
    GoldenVector {
        name: "GV-06:raw-established-v4",
        line: "  0: 00000000:0000 04030201:0000 01 00000000:00000012 \
               00:00000000 00000000  0  0 444010 1 0000000000000000 0",
        proto: Proto::Raw,
        want: Some(Want {
            inode: 444010,
            remote: "1.2.3.4:0",
            state: "ESTABLISHED",
            queued: true,
        }),
    },
    GoldenVector {
        name: "GV-07:raw-unbound-v4",
        line: "  0: 00000000:0000 00000000:0000 07 00000000:00000000 \
               00:00000000 00000000  0  0 444011 1 0000000000000000 0",
        proto: Proto::Raw,
        want: Some(Want {
            inode: 444011,
            remote: "0.0.0.0:0",
            state: "CLOSE",
            queued: false,
        }),
    },
    GoldenVector {
        name: "GV-08:raw6-close-v6",
        line: "  0: 00000000000000000000000000000000:0000 \
               00000000000000000000000001000000:0000 07 00000000:00000000 \
               00:00000000 00000000  0  0 444012 1 0000000000000000 0",
        proto: Proto::Raw6,
        want: Some(Want {
            inode: 444012,
            remote: "[::1]:0",
            state: "CLOSE",
            queued: false,
        }),
    },
    // The byte-swap law's dedicated witness: 78563412 is the
    // little-endian word 0x12345678 — the kernel prints each
    // address as four byte-swapped hex pairs, 18.52.86.120 out.
    GoldenVector {
        name: "GV-09:byte-swap-law-v4",
        line: "  5: 0100007F:8D2A 78563412:0050 01 00000000:00000000 \
               00:00000000 00000000  1000 0 666005 1 0000000000000000 100 0 0 10 0",
        proto: Proto::Tcp,
        want: Some(Want {
            inode: 666005,
            remote: "18.52.86.120:80",
            state: "ESTABLISHED",
            queued: false,
        }),
    },
    // The IPv4-mapped v6 endpoint: the kernel prints
    // ::ffff:127.0.0.1 for a v4-speaking v6 socket and the
    // display form must survive the round trip verbatim.
    GoldenVector {
        name: "GV-10:v6-mapped-endpoint",
        line: " 31: 00000000000000000000000000000000:9C40 \
               0000000000000000FFFF00000100007F:0016 01 00000000:00000000 \
               00:00000000 00000000  1000 0 999006 1 0000000000000000 100 0 0 10 0",
        proto: Proto::Tcp6,
        want: Some(Want {
            inode: 999006,
            remote: "[::ffff:127.0.0.1]:22",
            state: "ESTABLISHED",
            queued: false,
        }),
    },
    // ── The rejection vectors: the no-match contract — reject,
    //    never guess. Each shape the parser can refuse, named.
    GoldenVector {
        name: "GV-11:reject-unknown-state",
        line: "  3: 0100007F:8D2A 34120A0A:01F5 FF 00000000:00000014 \
               00:00000000 00000000  1000 0 777001 1 0000000000000000 100 0 0 10 0",
        proto: Proto::Tcp,
        want: None,
    },
    GoldenVector {
        name: "GV-12:reject-short-hex-endpoint",
        line: "  3: 0100007F:8D2A 0A0A123:01F5 01 00000000:00000014 \
               00:00000000 00000000  1000 0 777001 1 0000000000000000 100 0 0 10 0",
        proto: Proto::Tcp,
        want: None,
    },
    GoldenVector {
        name: "GV-13:reject-odd-address-width",
        line: "  3: 0100007F:8D2A 0000FFFF00000100:0050 01 00000000:00000014 \
               00:00000000 00000000  1000 0 777001 1 0000000000000000 100 0 0 10 0",
        proto: Proto::Tcp,
        want: None,
    },
    GoldenVector {
        name: "GV-14:reject-queue-without-colon",
        line: "  3: 0100007F:8D2A 34120A0A:01F5 01 00000014 \
               00:00000000 00000000  1000 0 777001 1 0000000000000000 100 0 0 10 0",
        proto: Proto::Tcp,
        want: None,
    },
    GoldenVector {
        name: "GV-15:reject-non-numeric-inode",
        line: "  3: 0100007F:8D2A 34120A0A:01F5 01 00000000:00000014 \
               00:00000000 00000000  1000 0 garbage 1 0000000000000000 100 0 0 10 0",
        proto: Proto::Tcp,
        want: None,
    },
    GoldenVector {
        name: "GV-16:reject-header-line",
        line: "  sl  local_address rem_address   st tx_queue rx_queue tr \
               tm->when retrnsmt   uid  timeout inode",
        proto: Proto::Tcp,
        want: None,
    },
    GoldenVector {
        name: "GV-17:reject-truncated-row",
        line: "  3: 0100007F:8D2A 34120A0A:01F5 01",
        proto: Proto::Tcp,
        want: None,
    },
    // The sixth table family's witness: udp6 rows print the
    // same 32-hex address + port shape the tcp6/raw6 rows do,
    // and the corpus demands every family carry at least one.
    GoldenVector {
        name: "GV-18:udp6-close-v6",
        line: " 17: 00000000000000000000000000000000:9C40 \
               00000000000000000000000001000000:0035 07 00000000:00000000 \
               00:00000000 00000000  1000 0 444013 1 0000000000000000 100 0 0 10 0",
        proto: Proto::Udp6,
        want: Some(Want {
            inode: 444013,
            remote: "[::1]:53",
            state: "CLOSE",
            queued: false,
        }),
    },
];

/// The corpus of record: every vector's verdict is the exact
/// expected one — full-field equality on the data rows, honest
/// rejection on the refusal shapes. One failure names its
/// vector, so a drifted output is found by its stable id (the
/// appendix's row), not by a diff hunt.
#[test]
fn the_golden_corpus_ratifies_the_ip_layer() {
    for vector in GOLDEN_VECTORS {
        let got = parse_proc_net_line(vector.line, vector.proto);
        match (&got, &vector.want) {
            (Some((inode, info)), Some(want)) => {
                assert_eq!(
                    inode, &want.inode,
                    "{}: inode drifted (want {})",
                    vector.name, want.inode
                );
                assert_eq!(
                    &info.remote, &want.remote,
                    "{}: remote endpoint drifted (want {})",
                    vector.name, want.remote
                );
                assert_eq!(
                    &info.state, &want.state,
                    "{}: state drifted (want {})",
                    vector.name, want.state
                );
                assert_eq!(
                    &info.queued, &want.queued,
                    "{}: queued flag drifted (want {})",
                    vector.name, want.queued
                );
                assert_eq!(&info.proto, &vector.proto, "{}: proto echoed", vector.name);
                assert_eq!(
                    &info.inode, &want.inode,
                    "{}: the SocketInfo inode mirrors the row inode",
                    vector.name
                );
            }
            (None, None) => {}
            (got, want) => panic!(
                "{}: verdict drifted (want {:?}, got {:?})",
                vector.name, want, got
            ),
        }
    }
}

/// The state table is canonical: the kernel's eleven codes spell
/// exactly these names, in exactly this case, and everything
/// else (unknown codes, zero, lowercase, two letters) is
/// rejected — the no-match contract at the state column's own
/// grain.
#[test]
fn the_state_table_is_canonical() {
    let table: &[(&str, &str)] = &[
        ("01", "ESTABLISHED"),
        ("02", "SYN_SENT"),
        ("03", "SYN_RECV"),
        ("04", "FIN_WAIT1"),
        ("05", "FIN_WAIT2"),
        ("06", "TIME_WAIT"),
        ("07", "CLOSE"),
        ("08", "CLOSE_WAIT"),
        ("09", "LAST_ACK"),
        ("0A", "LISTEN"),
        ("0B", "CLOSING"),
    ];
    for (code, name) in table {
        assert_eq!(
            state_name(code),
            Some(*name),
            "state code {code} must spell {name}"
        );
    }
    for unknown in ["FF", "00", "0C", "0a", "0b", "1", "AB", ""] {
        assert!(
            state_name(unknown).is_none(),
            "state code {unknown:?} must be rejected, never guessed"
        );
    }
}

/// The corpus's own integrity: the stable ids are unique (the
/// appendix's rows are keyed by them) and the corpus covers all
/// six table families the layer parses.
#[test]
fn the_corpus_keeps_its_names_unique_and_families_covered() {
    let mut names: Vec<&str> = GOLDEN_VECTORS.iter().map(|v| v.name).collect();
    let count = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names.len(),
        count,
        "golden vector ids must be unique — the appendix keys on them"
    );
    for proto in [
        Proto::Tcp,
        Proto::Tcp6,
        Proto::Udp,
        Proto::Udp6,
        Proto::Raw,
        Proto::Raw6,
    ] {
        assert!(
            GOLDEN_VECTORS.iter().any(|v| v.proto == proto),
            "the corpus must cover the {} family",
            proto.as_str()
        );
    }
}
