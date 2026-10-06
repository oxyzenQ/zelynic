// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// NIGHT-improve-44: the 600-line cap split — the Cli struct (the
// root invocation: globals, version banner, the help interception)
// lives in root.rs and the Commands enum (the command surface: every
// verb, its flags, the hidden probe pair) in surface.rs, the same
// one-concern-one-module discipline styles.rs and scope.rs set when
// this file crossed the 500 cap twice before. Every consumer import
// resolves identically through the re-exports below: crate::cli::Cli
// and crate::cli::Commands are the paths they always were.
pub(crate) mod argv;
// NIGHT-improve-42: the flag-rescue family, split from ux.rs at the
// 500-line cap — the tables and matchers that decide WHAT to suggest
// (top-level authorities, cross-tool vocabulary, the
// shadowed-suggestion rescue); ux.rs owns the enrichment chain and
// the rendering.
pub(crate) mod rescue;
pub(crate) mod styles;
pub(crate) mod suggestion;
pub(crate) mod tips;
pub(crate) mod ux;

// The split halves of this file's former body, wired back as one
// surface: the struct the Parser derives, and the enum it feeds.
mod root;
pub use root::Cli;
mod surface;
pub use surface::Commands;

// The clap brand-styling block lives in cli/styles.rs since
// NIGHT-master-1 (the depth surface's docs pushed this file past the
// 500-line cap) — one theme, one concern, re-exported for the
// `#[command(styles = ...)]` attribute below.
pub(crate) use styles::clap_styles;

// The --print-json scope contract lives in cli/scope.rs since
// NIGHT-private-research-3 (the --focus field's docs pushed this file
// past the cap again) — same split discipline, same re-export shape:
// every consumer import resolves identically.
mod scope;
pub(crate) use scope::{command_honors_print_json, warn_print_json_ignored};

// NIGHT-boost-24: the --print-json scope pins live under the single
// test/ tree (cosmostrix Pattern C), #[path]-wired exactly like the
// argv and ux tests.
#[cfg(test)]
#[path = "../../test/cli/print_json_tests.rs"]
mod print_json_tests;
