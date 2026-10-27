<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-dragon-lts-2c audit — the standing SAFETY gate takes the owner's call

> Audit date: 2026-10-27 (night-dragon-lts-2c, the owner-call round the
> lts-2b closure set up). Scope: the single residual the lts-2b pass
> left on the table — wiring `clippy::undocumented_unsafe_blocks` as a
> standing gate — executed at the owner's direction after the tree was
> already proven clean under the lint's own rule. Audited and executed
> at d6c98d6; the wiring lands in the same session. The sibling
> reference stays zejtron.

## 1. The mandate

The lts-2b closure record (section 6) ended with the lint at zero on
both crates and the wiring decision held back by the gate-inventory
freeze: "wiring the lint as a standing lane remains the owner's call —
this pass deliberately did not touch clippy.toml, the `[lints]` table,
or any CI workflow, so the decision arrives with the tree already
clean under the lint's own rule." The owner has now made the call:
wire it. The round's mandate is exactly that and nothing more — the
gate-inventory freeze governs standing-lint wiring, so no other gate
moves, no lint level changes, no CI workflow is edited.

## 2. The pre-flight proof — the floor is measured before the gate adopts it

A deny gate must adopt a proven floor, not create one. Both baseline
runs predate the manifest edits and use the exact instruments the
sibling records carry:

- **Root crate** (`cargo clippy --locked --all-targets --all-features
  -- -D warnings -D clippy::undocumented_unsafe_blocks`, stable
  1.98.1): finished green — zero undocumented-unsafe findings, zero
  other warnings under the CI's own deny posture. The 68 sites the
  lts-2b round annotated hold.
- **Kernel crate** (`cargo clippy` inside `ebpf/`, the pinned
  nightly-2026-09-18 toolchain, `-- -D
  clippy::undocumented_unsafe_blocks`): finished green — zero
  undocumented-unsafe findings. The 41 sites hold. The run's 15+23
  remaining warnings are the kernel shape's pre-existing clippy
  lints (needless-borrow family and peers) that the nightly
  instrument has always reported at warn level; they are not this
  gate's subject and no level changed for them.

## 3. The execution — one table per manifest, level deny

The wiring is two `[lints]` tables, one line of lint each:

```toml
[lints]
clippy = { undocumented_unsafe_blocks = "deny" }
```

- **Root `Cargo.toml`** — covers the loader, the terminal family, the
  build script, and every test target the package owns.
- **`ebpf/Cargo.toml`** — the kernel half must carry its own table:
  the crate is detached (the empty `[workspace]` table in its own
  manifest keeps it outside the root package), so there is no
  workspace-level `[lints]` inheritance to receive it.

The three design points the tables encode:

1. **Level `deny`, not `warn`.** CI's clippy lane already runs `-D
   warnings`, so a warn wiring would gate CI only; deny makes every
   clippy invocation anywhere — maintenance, a casual local run, a
   contributor's first build — fail on the first unsafe block without
   an inline contract. LTS-14's memory-safety basis ("every unsafe
   site speaks its own safety contract") becomes mechanically
   enforced on every future lane instead of true at audit time.
2. **Clippy-namespace only.** Cargo forwards `[lints.clippy]` entries
   solely to the clippy driver; plain rustc (cargo check/build, the
   nested nightly cross-compile build.rs drives, the registry install
   lane) silently ignores foreign tool lints. No non-clippy lane
   moves — the nightly `build` inside the ebpf feature and the
   release lanes byte-behave exactly as before.
3. **No CI edit.** The gate rides the manifests, so the CI's existing
   `cargo clippy -- -D warnings` invocation inherits it without a
   workflow change — the gate-inventory freeze stays intact by
   construction.

## 4. The verification — the gate proven live, then the tree proven clean under it

- **Negative probe (functional proof the gate fires).** A temporary
  `tests/gate_probe.rs` with one undocumented unsafe block, wired as
  a temporary explicit `[[test]]` target (the root manifest runs
  `autotests = false`, so directory convention alone would not
  compile it): `cargo clippy --locked --all-targets
  --no-default-features` **failed with exit 101**, the failure citing
  `clippy::undocumented_unsafe_blocks` and naming the probe unit —
  the manifest's deny is on the driver's command line and bites.
  Probe file, directory, and manifest entry removed immediately
  after; the probe never became part of the tree.
- **Positive shapes with the gate live.** The root CI shape (`cargo
  clippy --locked --all-targets --all-features -- -D warnings`) exits
  0; the kernel instrument (`cargo clippy` in `ebpf/`) exits 0; the
  light lane (`cargo clippy --locked --no-default-features
  --all-targets`) exits 0.
- **The rootless-and-full suite.** `cargo test --locked` at default
  features: 975 passed, 0 failed, 4 ignored (the benchmark
  harnesses, by design) — the widest local suite shape of the
  series, green under the wired gate.
- **The gate-keeper battery.** 24/0 green. The two first-run FAILs
  were the expected artifacts of the wiring itself, both resolved
  with zero repo drift beyond the round's intent:
  - the sandbox umask's 664 modes on two dated audit docs, fixed to
    the 644/755 policy (the same zero-diff artifact the lts-2b round
    recorded — no tracked content moved);
  - the prebuilt-parity check failing closed on the ebpf tree pin —
    the pin legitimately moved because this round edited
    `ebpf/Cargo.toml`; re-pinned through the one writer
    (`scripts/release/refresh-prebuilt.sh`), the two objects
    byte-identical (a manifest comment-plus-lints-table edit
    compiles to the same kernel bytes — sizes unchanged at 3216 and
    79872), the manifest's `generated` stamp and
    `ebpf_tree_blake3` the only lines that moved.
- **The probe's own lesson, recorded.** The root manifest's
  `autotests = false` means a throwaway probe needs an explicit
  `[[test]]` row to ever compile — the mechanical note for the next
  verification author, mirroring the lts-2b macro-window note.

## 5. The verdicts

| Surface | Verdict | Basis |
|---------|---------|-------|
| Root crate gate | GREEN | `[lints]` deny wired; CI shape, light lane, and full suite green; probe red on demand |
| Kernel crate gate | GREEN | own `[lints]` deny (detached crate); instrument zero; pre-existing warn-level lints untouched |
| LTS-14 claim | MECHANICALLY ENFORCED | the lint's rule now denies, everywhere clippy runs — not merely true at audit time |
| Gate inventory | UNCHANGED | zero workflow edits, zero lint-level changes outside the one lint |
| Prebuilt lane | RE-PINNED | objects byte-identical; tree pin follows the manifest edit through the one writer |
| Benchmark | SKIPPED | the docs-only rule: manifest metadata and comments only, no render-path or performance-relevant line moved |

## 6. Honest residuals

- The nightly clippy run inside `ebpf/` stays a manual instrument:
  the kernel shape's pre-existing warn-level clippy lints (the
  needless-borrow family, 15 + 23 across the two bins) remain a
  future owner's hunt; this round's freeze governs the one gate, and
  the gate lint itself measures zero.
- The live-eBPF legs (crash recovery, races, reload, endurance, the
  VM matrix) remain CI-owned — no root or KVM on the audit host, the
  standing boundary of the whole series.
- The deny level's flip side is deliberate: a future undocumented
  unsafe block fails the lane it lands in until it speaks its
  contract. That is the gate working as wired, and the fix is the
  comment the LTS-14 basis already asks for.

<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `ebpf/src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
