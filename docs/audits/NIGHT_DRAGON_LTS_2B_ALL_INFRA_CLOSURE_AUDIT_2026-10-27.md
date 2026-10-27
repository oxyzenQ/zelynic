<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-dragon-lts-2b audit — the all-infra re-verification and the safety-contract closure

> Audit date: 2026-10-27 (night-dragon-lts-2b, the second pass of the
> lts-2 task name, one session with the annotation commit it landed).
> Scope: the whole infrastructure estate re-verified with fresh
> instruments where the first pass ran on gates alone — the
> gate-keeper battery with the complete local tool set, the
> dependency and supply-chain posture, the compile and test lanes on
> both crates — plus the one execution the sibling sharpest-skill
> pass left as an owner-call candidate: closing the SAFETY-annotation
> gap the real lint measures. Audited at 503eb4f; the execution
> landed as 98d1a1e. The sibling reference stays zejtron.

## 1. The mandate

The all-infra leg asks the LTS five of everything that is not the
per-packet kernel core: the shell gates that hold the repo's laws,
the build and packaging machinery, the CI workflow estate, the
dependency graph, and the documentation surface. The rule of the
round is the standing one — a leg already at peak is skipped with its
reason, and the audit hunts beyond the ask wherever a fresh
instrument can measure something the standing gates cannot. This
round's fresh instrument is the real clippy run of
`clippy::undocumented_unsafe_blocks` on both crates, the reproduction
the lts-1 record named and this host's toolchain can finally pay for.

## 2. The gate-keeper battery — green with two local-only artifacts

The full `gate-keepers.sh` battery ran on this host with the complete
tool set installed user-space (shellcheck 0.10.0, shfmt 3.11.0,
actionlint 1.7.7, codespell 2.4.3, yamllint 1.38.0, b3sum 1.8.7, and
the pinned toolchain pair: stable 1.98.1 plus the dated
nightly-2026-09-18 with rust-src, rustfmt, and clippy). All 24
checks pass. Two first-run FAILs were local artifacts, not repo
state, and both are worth the record because they cost zero bytes of
diff:

- **Permissions**: the sandbox's umask clones the tree as 664/775
  (group-writable), which the permission guard rightly refuses. The
  guard's own `--fix` restored the 644/755 policy; `git status` after
  the fix is empty — git never tracked the non-executable bits, so
  the repository state on the forge was always correct. No commit.
- **Prebuilt parity**: the check fails closed when `b3sum` is absent
  (the lane's pins are blake3, night-dragon-maintenance-0). With
  b3sum installed the lane passes in full: manifest present, both
  objects structurally sane ELFs with closed relocation surfaces,
  every blake3 + size row matching, and the tree pin describing the
  live ebpf/ sources. A missing tool is a diagnosable environment
  gap, exactly as the check's own message says — not a stale lane.

## 3. The supply chain — fresh where fresh is measurable

`cargo deny check` runs all four legs green at HEAD (advisories,
bans, licenses, sources), the advisory DB current at run time — the
first local verification of that lane this cycle; CI owns the
standing run. `cargo update --dry-run` locks zero packages: every
dependency sits at its latest Rust-1.98-compatible version, one
dependency behind latest for toolchain reasons the resolver already
owns. The commit gate's actions-pin health reports 38 pins kept,
23 skipped-for-cause, checked live at commit time. The four-secret
inventory stays canonical and the fuzz-include law holds.

## 4. The compile and test lanes — clean on both crates

The light lane verifies in seconds: `cargo check --no-default-features`
finishes in under nine seconds, `cargo clippy --locked
--no-default-features --all-targets` warns nothing, and the rootless
suite passes 193 of 196 tests (three ignored — the benchmark
harnesses, by design). The heavy lane runs where its cost belongs:
the kernel crate compiles through the nested nightly cross-compile on
this host once the bootstrap pair is installed, and its clippy run —
the instrument section below — is equally clean. No local run touches
the live-eBPF legs (crash recovery, races, reload, endurance, the VM
matrix): no root, no KVM, CI's verdict stands as the record.

## 5. The docs surface — the drift spot-checks hold

The standing spot-check set re-verifies in sync: the 100 MB
`default_burst` clamp, the 256-slot group maps, the 1024-entry policy
maps — every doc number checked against its source constant matches.
The disclaimer gate counts 102 living .md files, every one carrying
the stale-data warning at the bottom; the audits index counts 63/63
tracked audit docs with rows; the language gate finds no non-Latin
prose and no Indonesian vocabulary; the LOC cap holds at 273 files,
zero over. The lts-1 audit record's census figure (78 of 120) is a
point-in-time measurement by the repo's own convention — the dated
audit docs are records, not living claims — and this round's record
carries the corrected live numbers (section 6) without rewriting the
sibling's.

## 6. The execution — every unsafe block speaks its own contract

The one find the lts-1 pass left as an owner-call candidate is now
closed, in the direction that touches no gate inventory. The real
lint, run for the first time with a toolchain on the audit host:

- **Root crate** (`cargo clippy --all-targets --all-features -- -W
  clippy::undocumented_unsafe_blocks`): 68 unique sites — 61 unsafe
  block openers and 7 unsafe trait impls.
- **Kernel crate** (the nightly clippy run inside `ebpf/`): 41 more
  unsafe block openers.
- **Total 109**, against the static census's 78-of-120 estimate — the
  census's own epsilon caveat, confirmed by measurement. The census
  mirrored the lint's positional rule by text; the real instrument
  also counts the impl sites the census's rule could not see, and
  drops the sites whose three-line window already carried a SAFETY
  comment.

Every flagged site now carries a SAFETY comment stating the actual
local invariant — never boilerplate: the aya map-value lifetime
contract behind every `get_ptr` deref, the helper-ID transmute chain
in the ECN helper, the READ_ONCE volatile discipline the belt reads
ride, the raw-place debt-pay lanes and their consumed-borrow
non-overlap, the POD value contract each `aya::Pod` impl rests on,
the size-pinned transmute round trip in the layout pin, and the
descriptor-ownership shape every termios/fcntl/poll site rides in
the terminal family and its tests. Comments only: no expression
moved, no call reordered, no signature touched — one block's
`ptsname_r` call was reformatted to carry its comment as the block's
first statement because the lint's window does not see comments
inside a macro invocation's argument list (the mechanical lesson of
the round, recorded here for the next annotator).

The verification stack after the pass:

- The lint runs at **zero** undocumented-unsafe warnings on both
  crates, all targets.
- rustfmt clean on the kernel crate (the exact CI command) and the
  light lane clippy clean.
- The rootless suite green: 143 + 50 passed, the same three ignores.
- The 600-line cap holds repo-wide — the annotations added 338
  comment lines across 28 files and pushed nothing over.
- The full gate-keeper battery passes 24/0 with the changes staged.
- The prebuilt lane re-pins at commit time through its one writer:
  the manifest's tree pin moved (the sources changed), the two
  objects stayed byte-identical (comment-only edits compile to the
  same bytes — sizes unchanged at 3216 and 79872).
- The commit gate itself (`.githooks/pre-commit`) re-verified the
  lane parity, staged-with-lane pairing, and live actions-pin health
  on the commit.

The LTS-14 memory-safety row's claim is now mechanically true: a
future unsafe block without an inline contract shows up under the
one-command reproduction the lts-1 record carries, reproducible on
any host with the toolchain. Wiring the lint as a standing lane
remains the owner's call under the gate-inventory freeze — this pass
deliberately did not touch clippy.toml, the `[lints]` table, or any
CI workflow, so the decision arrives with the tree already clean
under the lint's own rule.

## 7. The benchmark protocol — skipped with the standing reason

The A/B frame benchmark does not run for this round: the change set
is comment-only (docs-class under the round's own rule — "if the
change only docs don't run just waste time"), no render-path or
performance-relevant line moved, and the protocol's value is the
byte-exact before/after of the layout engine, which comments cannot
alter. The frame harness itself stays untouched and ignored-by-design
in the tree, runnable rootless wherever the bootstrap pair exists.

## 8. The verdict table

| Area | Verdict | Note |
|---|---|---|
| Gate-keeper battery | GREEN, verified live | 24/0 with the full tool set; two first-run FAILs local-only artifacts |
| Permissions law | GREEN | sandbox umask artifact, zero repo drift |
| Prebuilt parity | GREEN, verified live | b3sum tool gap, not lane staleness; re-pinned with the round's ebpf/ edits |
| Supply chain | GREEN, verified live | cargo-deny 4/4, zero lockable updates, pins healthy |
| Compile lanes | GREEN | both crates check+clippy clean; heavy legs CI-owned |
| Rootless tests | GREEN | 193 passed, 3 by-design ignores |
| Docs surface | GREEN | spot-checks in sync, 102 disclaimers, 63/63 index, language law |
| Hygiene | PEAK, skip | zero TODO/FIXME debt, cap green, splits wired — nothing to hunt past the gates |
| Optimization | PEAK, skip | render path measured by the A/B protocol; comment-only round, no hot path touched |
| Security hardening | STRENGTHENED | the trust-boundary comments now state each clamp's contract inline; behavior unchanged |
| LTS stability | STRENGTHENED | the safety contracts survive at the exact sites future maintainers will edit |
| The annotation closure (this round) | LANDED | 109 sites, zero lint, 98d1a1e |

## 9. This audit's own honest residuals

- The live eBPF legs stay CI-owned (no root, no KVM on this host) —
  the standing posture, unchanged.
- The nightly clippy run inside `ebpf/` is a manual instrument, not a
  standing lane; the census's impl-site lesson (the root crate's
  seven `unsafe impl`s were invisible to the static rule) applies to
  any future re-census.
- The one-command reproduction's zero is today's zero: any new unsafe
  block re-opens the gap until the owner wires the lint as a standing
  lane, the decision the freeze holds open on purpose.

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
