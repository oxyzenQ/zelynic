// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Cosmic Dragon Architecture discipline pins (NIGHT-dinner-15, the
//! architecture half; extended by NIGHT-dinner-16).
//!
//! Rootless source-contract pins: each test reads the src/ tree as
//! bytes and asserts ONE architectural invariant — the six
//! layer-discipline rules of the four-layer shape
//! (docs/COSMIC_DRAGON_ARCHITECTURE.md, "Layer discipline holds") and
//! the verdict-order rule dinner-16 added (every apply handler
//! verifies the pin state before its success verdict prints). Prose
//! can rot; a pin fails the build the day a violator lands. Every
//! check here is textual — no root, no eBPF, no kernel — so they run
//! in the plain `cargo test --test integration` lane on any machine,
//! CI included, and in the --no-default-features lane too (the
//! discipline is feature-independent).
//!
//! Textual pins are tripwires, not proofs: they catch the shapes the
//! tree actually uses today (the literal `crate::ebpf::` path, the
//! literal `#[path = ...]` wiring). A creative rewrite can slip past
//! prose AND past these — but the ordinary "just add one direct
//! call" regression, the kind that actually happens, dies here.

use std::fs;
use std::path::{Path, PathBuf};

/// Read one file from the crate root, as text.
fn src(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// Every .rs file under `dir` (recursively), as (repo-relative name,
/// text), sorted for deterministic failure output.
fn rs_files(dir: &str) -> Vec<(String, String)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    let mut stack = vec![root.join(dir)];
    while let Some(d) = stack.pop() {
        let entries = fs::read_dir(&d).unwrap_or_else(|e| panic!("read_dir {}: {e}", d.display()));
        for entry in entries {
            let path = entry.unwrap_or_else(|e| panic!("dir entry: {e}")).path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let name = path
                    .strip_prefix(&root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                let text = fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                out.push((name, text));
            }
        }
    }
    out.sort();
    out
}

/// NIGHT-dinner-15: the CLI layer touches the eBPF layer ONLY through
/// the feature-gated typo-rescue validators re-exported by
/// `ebpf::limiter` (`parse_rate`, `parse_time_duration` — src/cli/tips.rs,
/// the did-you-mean tips). Any other `crate::ebpf::` path from cli/
/// would couple the argument UX to the map layer — the exact spaghetti
/// the layering exists to prevent.
#[test]
fn cli_touches_ebpf_only_through_the_limiter_validators() {
    for (name, text) in rs_files("src/cli") {
        for line in text.lines() {
            if let Some(idx) = line.find("crate::ebpf::") {
                let tail = &line[idx..];
                assert!(
                    tail.starts_with("crate::ebpf::limiter::parse_rate(")
                        || tail.starts_with("crate::ebpf::limiter::parse_time_duration("),
                    "{name}: cli reaches past the limiter validators: {line}"
                );
            }
        }
    }
}

/// NIGHT-dinner-15: the terminal layer is reached by exactly one
/// command — monitor.rs — and monitor.rs itself only through the
/// top-level module surface (`use crate::terminal;`, one-level calls
/// like `terminal::require_interactive()`). No command dips into
/// terminal/diff.rs or terminal/screen.rs directly; no other command
/// raw-modes the user's terminal at all.
#[test]
fn the_terminal_layer_is_reached_only_by_monitor_at_its_top_surface() {
    for (name, text) in rs_files("src/commands") {
        if name == "src/commands/monitor.rs" {
            continue;
        }
        assert!(
            !text.contains("crate::terminal"),
            "{name}: only monitor.rs may touch the terminal layer"
        );
    }
    let monitor = src("src/commands/monitor.rs");
    assert!(
        monitor.contains("use crate::terminal;"),
        "monitor.rs must use the terminal layer's top-level module surface"
    );
    for line in monitor.lines() {
        if let Some(idx) = line.find("terminal::") {
            let tail = &line[idx + "terminal::".len()..];
            let ident: String = tail
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            // The module surface speaks in two shapes: CamelCase types
            // (`terminal::Monitor::open` — the type and its associated
            // fn, both defined by terminal/mod.rs) and one-level fn
            // calls (`terminal::require_interactive()`). A lowercase
            // identifier followed by `::` is a SUBMODULE path
            // (terminal::diff::..., terminal::screen::...) — that is
            // the dip past the surface this pin forbids.
            if ident.starts_with(|c: char| c.is_ascii_lowercase()) {
                assert!(
                    !tail[ident.len()..].starts_with(':'),
                    "monitor.rs must not reach into a terminal submodule: {line}"
                );
            }
        }
    }
}

/// NIGHT-dinner-15: aya's pinned-map acquisition (`from_pin`,
/// `PinnedMapData`) lives in exactly one file — src/ebpf/pin.rs
/// (`open_pinned_hash_map` / `open_pinned_array_map`, the
/// improve-10/optimized-2 single gate). Every other surface opens
/// pinned maps through those helpers, so the pin-path handling
/// (error wording, bpf_fs checks) stays in one place.
#[test]
fn every_pinned_map_open_flows_through_the_pin_helpers() {
    for (name, text) in rs_files("src") {
        if name == "src/ebpf/pin.rs" {
            continue;
        }
        assert!(
            !text.contains("from_pin") && !text.contains("PinnedMapData"),
            "{name}: pinned-map acquisition belongs in src/ebpf/pin.rs"
        );
    }
}

/// NIGHT-dinner-15: the kernel/userspace arithmetic twin
/// (ebpf/src/math.rs + ebpf/src/stats.rs) stays pure `core` — zero
/// aya imports, zero std imports — and the ONLY bridge into
/// userspace is the #[path] wiring in test/ebpf/limiter/math_tests.rs
/// (the rootless token-bucket tests). A std or aya import in the twin
/// would break the eBPF crate's no_std compilation.
#[test]
fn the_ebpf_math_twin_stays_core_only_and_path_wired() {
    for file in ["ebpf/src/math.rs", "ebpf/src/stats.rs"] {
        let text = src(file);
        for line in text.lines() {
            let trimmed = line.trim_start();
            assert!(
                !trimmed.starts_with("use aya")
                    && !trimmed.starts_with("use std")
                    && !trimmed.starts_with("extern crate"),
                "{file}: the twin must stay core-only — {line}"
            );
        }
    }
    let wiring = src("test/ebpf/limiter/math_tests.rs");
    assert!(
        wiring.contains("#[path = \"../../../ebpf/src/math.rs\"]"),
        "test/ebpf/limiter/math_tests.rs: the #[path] wiring to the ebpf twin must stay"
    );
}

/// NIGHT-dinner-15: every `/proc/<pid>/comm` read site flows through
/// the canonical sanitizer (`sanitize_comm`, src/output/sanitize.rs —
/// cybersecurity-1/2: a process controls its own comm, so an
/// unsanitized comm can inject terminal escapes into status output).
/// Textual rule: a src file that builds the comm path also references
/// the sanitizer.
#[test]
fn every_proc_comm_read_flows_through_the_sanitizer() {
    for (name, text) in rs_files("src") {
        if text.contains("/proc/{pid}/comm") {
            assert!(
                text.contains("sanitize_comm"),
                "{name}: reads /proc/<pid>/comm without the canonical sanitizer"
            );
        }
    }
}

/// NIGHT-dinner-16: every apply-family handler verifies the pin state
/// BEFORE printing its success verdict. The race is real: a concurrent
/// `unstrict-all` in another terminal can tear the BPF pins down
/// between apply and the epilogue — a success verdict printed on a
/// torn-down limit reads as enforced while it is gone. The six
/// handlers (strict-single/multi/all, block-single/multi/all) each
/// carry the check; the textual tripwire counts the literal error
/// sites per file so a handler that loses its check fails here, in
/// the plain test lane, before it ships.
#[test]
fn every_apply_handler_verifies_pins_before_the_success_verdict() {
    for (file, handlers) in [
        ("src/commands/strict.rs", 3usize),
        ("src/commands/block.rs", 3usize),
    ] {
        let text = src(file);
        let checks = text.matches("BPF pins missing after apply").count();
        assert_eq!(
            checks, handlers,
            "{file}: every apply handler (single/multi/all) must verify the \
             post-apply pin state before the success verdict"
        );
        // And the verification precedes the verdict: walking the file
        // line by line, every epilogue call must arrive AFTER the
        // pins check of its own handler — the running count of checks
        // never trails the running count of verdicts.
        let mut checks_seen = 0usize;
        let mut verdicts_seen = 0usize;
        for line in text.lines() {
            if line.contains("BPF pins missing after apply") {
                checks_seen += 1;
            }
            if line.contains("apply_success_epilogue(") {
                verdicts_seen += 1;
                assert!(
                    checks_seen >= verdicts_seen,
                    "{file}: epilogue #{verdicts_seen} prints before its \
                     handler's pins verification — the verdict must be \
                     verified first"
                );
            }
        }
    }
}

/// NIGHT-dinner-15 (hunt-20 lineage, moved with its subject to
/// lanes.rs by NIGHT-perf-0): `with_u32_map` (src/ebpf/limiter/
/// lanes.rs) is the ONE acquisition path for u32-keyed limiter map
/// mutation. The only sanctioned `.map_mut(` sites in the limiter
/// tree: the lanes file itself (reclaim.rs until perf-0's Array
/// twin split) and attach's ephemeral schema_version array write
/// (mod.rs) — pinned by name so a new direct mutation fails here,
/// in the plain test lane, before it ships.
#[test]
fn limiter_map_mutation_has_one_acquisition_path() {
    for (name, text) in rs_files("src/ebpf/limiter") {
        for line in text.lines() {
            if line.contains(".map_mut(") {
                assert!(
                    name == "src/ebpf/limiter/lanes.rs" || name == "src/ebpf/limiter/mod.rs",
                    "{name}: map mutation outside the with_u32_map lane — {line}"
                );
            }
        }
    }
    let mod_rs = src("src/ebpf/limiter/mod.rs");
    assert!(
        mod_rs.contains(".map_mut(\"schema_version\")"),
        "the mod.rs map_mut site is exactly the attach-time schema_version write"
    );
    let lanes = src("src/ebpf/limiter/lanes.rs");
    assert!(
        lanes.contains("pub(super) fn with_u32_map"),
        "with_u32_map stays defined in the limiter tree (lanes.rs)"
    );
    // The helper's own file is the implementation, not a caller: the
    // site inside lanes.rs is the acquisition itself.
    assert!(Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/ebpf/limiter/lanes.rs")
        .exists());
}
