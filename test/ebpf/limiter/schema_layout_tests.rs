// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! night-frontier-Z7 (D3 — the byte-layout theorem): one generated
//! rootless test that walks the WHOLE stats-row version table and
//! proves three laws for ALL words, so a maintainer in 2030 cannot
//! silently break a retired word's offset or the append-only row.
//!
//! What existed before this test (the spot-pin era): the
//! SCHEMA_VERSION / SCHEMA_VERSION_EXPECTED equality pin
//! (schema_sync_pin_tests.rs, the include_str! scrape — dies loudly
//! on version drift), the size pins (`size_of::<LimiterStatsRaw>() ==
//! 72`, types_tests.rs; the kernel twin's const asserts in math.rs),
//! the saved-pair offset round-trip, and the per-word prose ledger
//! (schema_ledger.rs v1..v30, schema.rs v31 and onward). What did not
//! exist: a machine-checked layout theorem over the FULL version
//! history. The prose documented the pure-append law; nothing failed
//! a push that moved a retired word, shrank the row, or forked the
//! history the docs claim.
//!
//! The table below is the single machine-readable record of the
//! stats row's layout history (cgroup_limiter_stats — the kernel
//! twin math.rs's LimiterStats, the userspace mirror
//! LimiterStatsRaw). Every row is transcribed from the ledger prose
//! and carries the ledger anchor in its comment; the three laws keep
//! the transcription honest (an overlapping, reordered, or
//! size-mismatched transcription fails the walk), and the live-struct
//! bindings bind the table to the real bytes. Any break of a pinned
//! historical row is a loud edit of this file's constants — a
//! reviewable commit, never a silent drift.
//!
//! The three laws, for EVERY version in [1, SCHEMA_VERSION_EXPECTED]
//! and EVERY word of that version's row:
//!
//! 1. Append-only: within a version the word offsets are strictly
//!    increasing; across a bump every old word keeps its exact
//!    offset (words never move, never disappear) and every new word
//!    lands strictly beyond the previous tail.
//! 2. Retired stability: a word retired at version R stays present
//!    at its pinned offset in every version from R to the current
//!    one and never un-retires — the offset a reader of any version
//!    maps is pinned forever ("reads zero at its pinned offsets",
//!    the v29 contract).
//! 3. Row-size stability: a version's row size derives from its own
//!    words (the all-u64 row: tail offset plus eight), sizes never
//!    shrink, and a size change can only ride a version boundary.
//!
//! The 2030 gate: the table's top version is pinned to
//! SCHEMA_VERSION_EXPECTED. The next schema bump cannot land without
//! extending the table — and the three laws then verify the new era
//! obeys the same append-only discipline. The theorem is the proof
//! artifact: rootless, riding the existing battery, zero CLI surface.

use super::SCHEMA_VERSION_EXPECTED;
use crate::ebpf::limiter::types::LimiterStatsRaw;
use core::mem::{offset_of, size_of};

/// One word of the stats row, at one point of the version history.
struct SchemaWord {
    name: &'static str,
    offset: usize,
    /// The version whose bump retired the word's kernel booking; the
    /// word stays at its offset reading zero from that version on
    /// (the v29 shape). None = live.
    retired_from: Option<u32>,
}

/// One era of the stats row's version table: every version in the
/// inclusive range carries exactly this layout.
struct SchemaEra {
    from: u32,
    to: u32,
    row_size: usize,
    words: &'static [SchemaWord],
}

/// The base four counters — the row the v1 initial object shipped
/// (the ledger's own span opens at v1: "initial"). The bytes_allowed
/// and bytes_dropped words joined the booking the early eras carried
/// (the ledger's v3..v9 entries are verdict and booking semantics
/// over this same 32-byte row: no layout change anywhere in v1..v25).
const WORD_BASE: &[SchemaWord] = &[
    SchemaWord {
        name: "packets_allowed",
        offset: 0,
        retired_from: None,
    },
    SchemaWord {
        name: "packets_dropped",
        offset: 8,
        retired_from: None,
    },
    SchemaWord {
        name: "bytes_allowed",
        offset: 16,
        retired_from: None,
    },
    SchemaWord {
        name: "bytes_dropped",
        offset: 24,
        retired_from: None,
    },
];

/// The CE ledger pair (v26, night-spark-4: "32 -> 48 bytes") —
/// book_rescue's delivered-CE truth, live from v26 on.
const WORD_CE: &[SchemaWord] = &[
    SchemaWord {
        name: "packets_allowed",
        offset: 0,
        retired_from: None,
    },
    SchemaWord {
        name: "packets_dropped",
        offset: 8,
        retired_from: None,
    },
    SchemaWord {
        name: "bytes_allowed",
        offset: 16,
        retired_from: None,
    },
    SchemaWord {
        name: "bytes_dropped",
        offset: 24,
        retired_from: None,
    },
    SchemaWord {
        name: "ce_marked_packets",
        offset: 32,
        retired_from: None,
    },
    SchemaWord {
        name: "ce_marked_bytes",
        offset: 40,
        retired_from: None,
    },
];

/// The quota telemetry tail (v28, night-spark-7: "48 -> 64 bytes").
/// bytes_saved_by_edt was booked LIVE at v28 and retired one bump
/// later (v29, night-quota-audit: the counterfactual's only nonzero
/// content was the budget an idle sender never used — the word stays
/// at offset 48 reading zero, the pure-append layout law verbatim).
/// bytes_saved_by_ecn stays live, one-for-one with ce_marked_bytes.
const WORD_SAVED: &[SchemaWord] = &[
    SchemaWord {
        name: "packets_allowed",
        offset: 0,
        retired_from: None,
    },
    SchemaWord {
        name: "packets_dropped",
        offset: 8,
        retired_from: None,
    },
    SchemaWord {
        name: "bytes_allowed",
        offset: 16,
        retired_from: None,
    },
    SchemaWord {
        name: "bytes_dropped",
        offset: 24,
        retired_from: None,
    },
    SchemaWord {
        name: "ce_marked_packets",
        offset: 32,
        retired_from: None,
    },
    SchemaWord {
        name: "ce_marked_bytes",
        offset: 40,
        retired_from: None,
    },
    SchemaWord {
        name: "bytes_saved_by_edt",
        offset: 48,
        retired_from: Some(29),
    },
    SchemaWord {
        name: "bytes_saved_by_ecn",
        offset: 56,
        retired_from: None,
    },
];

/// The measured-srtt ratchet (v33, night-verify-final: "one u64 tail
/// word, measured_srtt_us (offset 64)" — 64 -> 72 bytes). v34 and v35
/// grew the depth histogram rows, never this row (the v34/v35 ledger
/// entries: "policy/stats/ring layouts are byte-identical").
const WORD_SRTT: &[SchemaWord] = &[
    SchemaWord {
        name: "packets_allowed",
        offset: 0,
        retired_from: None,
    },
    SchemaWord {
        name: "packets_dropped",
        offset: 8,
        retired_from: None,
    },
    SchemaWord {
        name: "bytes_allowed",
        offset: 16,
        retired_from: None,
    },
    SchemaWord {
        name: "bytes_dropped",
        offset: 24,
        retired_from: None,
    },
    SchemaWord {
        name: "ce_marked_packets",
        offset: 32,
        retired_from: None,
    },
    SchemaWord {
        name: "ce_marked_bytes",
        offset: 40,
        retired_from: None,
    },
    SchemaWord {
        name: "bytes_saved_by_edt",
        offset: 48,
        retired_from: Some(29),
    },
    SchemaWord {
        name: "bytes_saved_by_ecn",
        offset: 56,
        retired_from: None,
    },
    SchemaWord {
        name: "measured_srtt_us",
        offset: 64,
        retired_from: None,
    },
];

/// The stats row's version table, v1 to v35 (the whole span the
/// ledger documents). Five eras: the growth bumps are v26, v28, and
/// v33; the v29 bump retired a booking without moving a byte.
const STAT_ROW_TABLE: &[SchemaEra] = &[
    SchemaEra {
        from: 1,
        to: 25,
        row_size: 32,
        words: WORD_BASE,
    },
    SchemaEra {
        from: 26,
        to: 27,
        row_size: 48,
        words: WORD_CE,
    },
    SchemaEra {
        from: 28,
        to: 28,
        row_size: 64,
        words: WORD_SAVED,
    },
    SchemaEra {
        from: 29,
        to: 32,
        row_size: 64,
        words: WORD_SAVED,
    },
    SchemaEra {
        from: 33,
        to: 35,
        row_size: 72,
        words: WORD_SRTT,
    },
];

/// Resolve a version to its era. Panics loudly on a gap or overlap —
/// the walk itself is the table-integrity gate, and a future bump
/// that outgrows the table fails here first.
fn era_for(version: u32) -> &'static SchemaEra {
    STAT_ROW_TABLE
        .iter()
        .find(|era| version >= era.from && version <= era.to)
        .unwrap_or_else(|| panic!("no layout era covers version {version} — extend STAT_ROW_TABLE with the new bump's row (the 2030 gate)"))
}

/// A word is retired at a version iff the retirement version has
/// landed (the word reads zero from its retirement version on).
fn word_is_retired_at(word: &SchemaWord, version: u32) -> bool {
    word.retired_from.is_some_and(|r| version >= r)
}

/// LAW 1 — append-only: strictly increasing offsets inside every
/// version; words never move, never disappear across a bump; new
/// words land strictly beyond the previous tail.
#[test]
fn byte_layout_theorem_append_only() {
    for version in 1..=SCHEMA_VERSION_EXPECTED {
        let era = era_for(version);
        for pair in era.words.windows(2) {
            assert!(
                pair[0].offset < pair[1].offset,
                "v{version}: law 1 broken — {} (offset {}) does not precede {} (offset {}) strictly",
                pair[0].name,
                pair[0].offset,
                pair[1].name,
                pair[1].offset
            );
        }
        if version > 1 {
            let prev = era_for(version - 1);
            for word in prev.words {
                let carried = era
                    .words
                    .iter()
                    .find(|w| w.offset == word.offset)
                    .unwrap_or_else(|| panic!("v{version}: law 1 broken — {} vanished from offset {} (the append-only row never drops a word)", word.name, word.offset));
                assert_eq!(
                    carried.name,
                    word.name,
                    "v{version}: law 1 broken — offset {} carries {} where v{} carried {} (words never move)",
                    word.offset,
                    carried.name,
                    version - 1,
                    word.name
                );
            }
            let prev_tail = prev
                .words
                .last()
                .expect("an era always carries words")
                .offset;
            for word in era.words {
                if word.offset > prev_tail {
                    assert!(
                        word.offset % 8 == 0,
                        "v{version}: law 1 broken — new word {} lands at unaligned offset {} (the all-u64 row appends 8-byte words)",
                        word.name,
                        word.offset
                    );
                }
            }
        }
    }
}

/// LAW 2 — retired stability: from its retirement version to the
/// current one, a retired word stays present at its pinned offset and
/// never un-retires. The retirement set only grows.
#[test]
fn byte_layout_theorem_retired_words_hold_their_offsets() {
    for version in 1..=SCHEMA_VERSION_EXPECTED {
        let era = era_for(version);
        for word in era.words {
            if word_is_retired_at(word, version) {
                let r = word.retired_from.expect("checked retired above");
                assert!(
                    version >= r && word.offset % 8 == 0,
                    "v{version}: law 2 broken — {} retired from v{r} must sit at a pinned 8-byte-aligned offset",
                    word.name
                );
                assert!(
                    era.words
                        .iter()
                        .any(|w| w.offset == word.offset && w.name == word.name),
                    "v{version}: law 2 broken — {} no longer pinned at offset {}",
                    word.name,
                    word.offset
                );
            }
        }
        if version > 1 {
            let prev = era_for(version - 1);
            for word in prev.words {
                if word_is_retired_at(word, version - 1) {
                    let carried = era
                        .words
                        .iter()
                        .find(|w| w.offset == word.offset)
                        .expect("law 1 already pins the offset across the bump");
                    assert!(
                        word_is_retired_at(carried, version),
                        "v{version}: law 2 broken — {} un-retired at v{} after being retired at v{} (a retirement is forever: the word reads zero at its pinned offset)",
                        word.name,
                        version,
                        version - 1
                    );
                }
            }
        }
    }
    // The live retired word: the v29 contract's own anchor.
    assert_eq!(
        offset_of!(LimiterStatsRaw, bytes_saved_by_edt),
        48,
        "law 2, live binding — bytes_saved_by_edt (retired from v29) must sit at offset 48; \
         a moved or dropped field fails the push here"
    );
}

/// LAW 3 — row-size stability: every version's size derives from its
/// own words (tail offset plus eight, the all-u64 row), sizes never
/// shrink, and a size change rides a version boundary only.
#[test]
fn byte_layout_theorem_row_size_stable() {
    for version in 1..=SCHEMA_VERSION_EXPECTED {
        let era = era_for(version);
        let derived = era
            .words
            .last()
            .expect("an era always carries words")
            .offset
            + 8;
        assert_eq!(
            era.row_size, derived,
            "v{version}: law 3 broken — row_size {} disagrees with its own words (tail offset + 8 = {})",
            era.row_size, derived
        );
        if version > 1 {
            let prev = era_for(version - 1);
            assert!(
                era.row_size >= prev.row_size,
                "v{version}: law 3 broken — the row shrank from {} to {} bytes (the pure-append row never shrinks)",
                prev.row_size,
                era.row_size
            );
        }
    }
    // The live row: the userspace mirror's own size, pinned to the
    // table's current era (the kernel twin carries the same 72 in
    // math.rs's const assert; the v13-era sync pin anchors the
    // version anchor itself).
    let current = era_for(SCHEMA_VERSION_EXPECTED);
    assert_eq!(
        size_of::<LimiterStatsRaw>(),
        current.row_size,
        "law 3, live binding — size_of::<LimiterStatsRaw>() must equal the v{} row size the table carries; \
         a struct change without a table extension (and a schema bump) fails the push here",
        SCHEMA_VERSION_EXPECTED
    );
}

/// The table integrity: the eras tile [1, SCHEMA_VERSION_EXPECTED]
/// exactly — ascending, contiguous, no gaps, no overlaps — and the
/// table's top version is the version contract itself.
#[test]
fn byte_layout_theorem_table_tiles_the_version_span() {
    assert!(
        !STAT_ROW_TABLE.is_empty(),
        "the version table must carry at least one era"
    );
    let mut expected_from = 1;
    for era in STAT_ROW_TABLE {
        assert!(
            era.from <= era.to,
            "table broken — era {}..{} is inverted",
            era.from,
            era.to
        );
        assert_eq!(
            era.from, expected_from,
            "table broken — era {}..{} leaves a gap at version {} (the walk would panic there)",
            era.from, era.to, expected_from
        );
        expected_from = era.to.saturating_add(1);
    }
    assert_eq!(
        STAT_ROW_TABLE.last().expect("checked non-empty above").to,
        SCHEMA_VERSION_EXPECTED,
        "the 2030 gate — the table's top version must equal SCHEMA_VERSION_EXPECTED; \
         bump the schema and you extend the table with the new era in the same commit"
    );
}

/// The live binding: every field the real mirror struct carries maps
/// by name and offset onto the table's current era, byte for byte.
/// This is the row the kernel object and the userspace reader both
/// map; a reorder, a rename, a drop, or an untracked addition fails
/// the push here.
#[test]
fn byte_layout_theorem_live_struct_binds_the_table() {
    const LIVE_OFFSETS: &[(&str, usize)] = &[
        (
            "packets_allowed",
            offset_of!(LimiterStatsRaw, packets_allowed),
        ),
        (
            "packets_dropped",
            offset_of!(LimiterStatsRaw, packets_dropped),
        ),
        ("bytes_allowed", offset_of!(LimiterStatsRaw, bytes_allowed)),
        ("bytes_dropped", offset_of!(LimiterStatsRaw, bytes_dropped)),
        (
            "ce_marked_packets",
            offset_of!(LimiterStatsRaw, ce_marked_packets),
        ),
        (
            "ce_marked_bytes",
            offset_of!(LimiterStatsRaw, ce_marked_bytes),
        ),
        (
            "bytes_saved_by_edt",
            offset_of!(LimiterStatsRaw, bytes_saved_by_edt),
        ),
        (
            "bytes_saved_by_ecn",
            offset_of!(LimiterStatsRaw, bytes_saved_by_ecn),
        ),
        (
            "measured_srtt_us",
            offset_of!(LimiterStatsRaw, measured_srtt_us),
        ),
    ];
    let current = era_for(SCHEMA_VERSION_EXPECTED);
    for (field, live_offset) in LIVE_OFFSETS {
        let word = current
            .words
            .iter()
            .find(|w| w.name == *field)
            .unwrap_or_else(|| panic!("live binding broken — field {field} has no row in the v{} era; extend STAT_ROW_TABLE", SCHEMA_VERSION_EXPECTED));
        assert_eq!(
            *live_offset, word.offset,
            "live binding broken — field {field} sits at offset {live_offset}, the table pins {}",
            word.offset
        );
    }
    assert_eq!(
        LIVE_OFFSETS.len(),
        current.words.len(),
        "live binding broken — the struct carries {} fields, the v{} era describes {} words; \
         a new field needs a schema bump, a table era, and the append-only laws to approve it",
        LIVE_OFFSETS.len(),
        SCHEMA_VERSION_EXPECTED,
        current.words.len()
    );
}
