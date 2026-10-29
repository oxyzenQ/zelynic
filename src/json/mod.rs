// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The hand-written JSON lane (night-dragon-maintenance-T1 (S1)) —
//! the crate's one JSON module, std-only. No serde, no serde_json:
//! the dependency law (peak-lean runtime graph, the zejtron lineage)
//! holds even for the scripting surface, and the supply-chain
//! surface shrinks by the two crates (plus their derive stack:
//! serde_core, serde_derive, itoa, ryu, memchr) that existed here
//! only to move JSON.
//!
//! Three parts:
//! - [`write`] — the writer helpers every document lane shares:
//!   the escape law (quote and backslash two-character forms, the
//!   named control bytes, `\u00xx` for the rest of the control
//!   range, every other scalar — all of UTF-8 — verbatim), the one
//!   array bracket grammar, the typed-absence writers. Compiled in
//!   EVERY build flavor: the capability doctor's JSON report rides
//!   it on the dormant lane too.
//! - [`parse`] — the [`Value`] tree and the RFC 8259 parser that
//!   fills it: the docker Engine API lane's deserializer (the one
//!   runtime consumer of foreign JSON) and every test's assertion
//!   lens. Self-contained by design: std imports only, so the
//!   black-box integration harness can `#[path]`-include it without
//!   linking the binary crate. Gated to the ebpf graph + tests —
//!   the docker lane is its only runtime consumer.
//! - the document lanes themselves stay in their own modules
//!   (display_json, depth_json, capabilities, list_apps,
//!   info::BuildInfo, pins): each type owns a `write_json`/`to_json`
//!   pair, field order is the pinned scripting contract, and the
//!   former derive semantics (`skip_serializing_if`) are the
//!   writer's explicit branches — reviewable byte-exact code, no
//!   macro expansion between the contract and the bytes.

pub mod write;

#[cfg(any(feature = "ebpf", test))]
pub mod parse;

// The re-export is ebpf-ONLY (no test arm): its sole consumer is the
// docker lane's `use crate::json::Value` — the parse tests reach the
// type through `super::*` inside the module, and the black-box
// integration harness binds its own #[path] copy, so no test rides
// this alias. A test-armed re-export with zero dormant consumers is
// an unused import the moment ci.yml's workflow-level
// RUSTFLAGS="-D warnings" law compiles the dormant test build — the
// S1 shape that kept main red, closed by the S3 gate tightening.
#[cfg(feature = "ebpf")]
pub use parse::Value;
