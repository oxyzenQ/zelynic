<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-dragon-lts-2d audit — the kernel instrument's own warnings taken to zero

> Audit date: 2026-10-27 (night-dragon-lts-2d, the follow-through the
> lts-2c standing-gate round set up). Scope: the pre-existing clippy
> warnings the nightly instrument has always reported at warn level on
> the kernel crate — the residual every sibling record carried — taken
> to zero at the owner's direction. Audited and executed at 873ea9e;
> the fixes land in the same session. The sibling reference stays
> zejtron.

## 1. The mandate

The lts-2c record wired the SAFETY gate and left the kernel crate's
warn-level clippy noise as the honest residual: "the kernel shape's
pre-existing warn-level clippy lints (the needless-borrow family, 15
+ 23 across the two bins) remain a future owner's hunt." The owner
called the hunt. The mandate is exactly that hunt and nothing more:
no lint level changes, no new gates, the CI workflow untouched — the
warning count itself goes to zero, and the nightly instrument becomes
silent for the first time in the series.

## 2. The census

The structured census (`cargo clippy --message-format=json`, both
bins, the pinned nightly-2026-09-18 pair): 38 primary sites —
29 `needless_borrows_for_generic_args`, 6 `collapsible_if`, 1
`empty_line_after_outer_attr`, 1 `too_many_arguments`, 1
`redundant_closure` — across nine files (`main.rs`, `limiter.rs`,
`mmspa_resolve.rs`, `drr_flow.rs`, `drr_flow_draw.rs`, `cake_flow.rs`,
`quic_flow.rs`, `enforce.rs`, `enforce_helpers.rs`; the shared modules
compile into both bins, so one fix silences both). The fix pass
exposed exactly one more site the JSON's primary-span filter had
dropped (`enforce_helpers.rs:216`, the debt map's get-or-create) —
39 sites fixed in total, then the instrument measured zero.

## 3. The fixes — three mechanics, one house allow, one demotion

- **Needless borrows (30)**: the redundant `&` dropped at each call
  site — the auto-reborrow shape (the callee's generic parameter
  already takes the value; the compiler verifies each site, and a
  wrong drop would not type-check). The aya map-call sites
  (`get_ptr`/`get_ptr_mut`/`insert`/`remove`) carry no unsafe of
  their own — every SAFETY comment around them comments the pointer
  derefs, which did not move.
- **Collapsed ifs (6)**: the nested
  `if cond { if let Some(x) = e { ... } }` pairs fused through the
  edition-2024 let-chain form (`if cond && let Some(x) = e`). The
  short-circuit CFG is the branch structure the nesting already was.
  The two debt-pay pairs and the ring-verdict wrap keep their SAFETY
  comments immediately above their `unsafe` blocks — the lts-2c deny
  gate was live during every edit and the final build is green under
  it, so the three-line window provably held.
- **The demotion (1)**: the limiter's pre-`enforce_dl` narrative
  block (the think-like-light-years-3 get-stats lineage note) was a
  `///` doc block attached to nothing, split from the function's own
  doc by a blank line — demoted to plain `//` comments, text
  preserved byte-for-byte, and the function's real doc block now
  attaches to its function alone.
- **The house allow (1)**: `try_draw`'s nine names are the fixed
  operand set of the v13 draw sequence (policy, two buckets, two
  maps, two keys, stamp, now); the repo's own answer to the same lint
  on the same crate already exists at `enforce.rs:42` (`try_enforce`
  carries `#[allow(clippy::too_many_arguments)]`) — the draw
  orchestrator mirrors it, zero body churn, no call-site edits.
- **The eta reduction (1)**: `.map(|p| word_read(p))` is
  `.map(word_read)` — `word_read` is exactly the `*const u64 -> u64`
  the closure spelled.

## 4. Behavior preservation and the object bytes

Every fix is one of three semantics-preserving mechanics (borrow
elision the compiler checks, short-circuit fusion, eta reduction)
plus a comment demotion and an attribute line — no expression
reordered, no call sequence touched, no branch order changed. The
recompiled objects still moved (the branch fusion and borrow removal
shift codegen and section layout): the observer 3216 -> 3296 bytes,
the limiter 79872 -> 79472 (400 bytes off). The refresh gate's own
structural checks pass on both (sane ELF, closed relocation surface,
loader-parse parity, tree pin matches), the rootless suite's embedded
object tests parse the new bytes against the schema, and the
live-eBPF legs remain CI-owned — the standing boundary of the series.

## 5. The verification stack

- Kernel clippy: **zero warnings** — the first silent run of the
  series (`cargo clippy` in `ebpf/`, pinned nightly, exit 0, no
  warning footer).
- rustfmt clean on both crates (`cargo fmt --all -- --check`, exit 0
  each — the kernel crate through its pinned toolchain).
- The full default-features suite on the new objects: 975 passed,
  0 failed, 4 ignored (the benchmark harnesses, by design).
- The gate-keeper battery: 24/0.
- The SAFETY gate: live and green throughout — no annotation moved
  out of its window, zero undocumented-unsafe findings before and
  after.

## 6. The verdicts

| Surface | Verdict | Basis |
|---------|---------|-------|
| Kernel instrument | SILENT — PEAK | 39 sites fixed, zero warnings, no level changed, no new allow beyond the house pattern |
| Behavior | PRESERVED | three compile-checked mechanics; no expression or call moved |
| Objects | RE-PINNED | both rebuilt from the fixed sources, structural gates green, suite parses the new bytes |
| SAFETY gate (lts-2c) | UNMOVED | deny live during the edits; zero findings before and after |
| Benchmark | SKIPPED | the docs-only rule's code twin: lint-shape edits only, no render-path or performance-relevant line moved — the object byte shift is section layout, not instruction-path work |
| CI workflow | UNCHANGED | zero workflow edits, the gate-inventory freeze holds |

## 7. Honest residuals

- The nightly clippy run inside `ebpf/` stays a manual instrument —
  but it is now a SILENT instrument: any future kernel-side warning
  will be new, not inherited noise. Wiring it as a standing CI lane
  remains the owner's gate-inventory call (the freeze that held for
  lts-2c's gate holds here; this round changed no wiring).
- The live-eBPF legs (crash recovery, races, reload, endurance, the
  VM matrix) remain CI-owned — no root or KVM on the audit host.
- The observer object grew 80 bytes while the limiter shed 400:
  section-alignment movement from the same fix set, structurally
  verified on both sides; recorded here so the movement is on the
  record, not a surprise for the next byte-pinned round.

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
