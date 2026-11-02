<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# night-dragon-maintenance-xenric-1 — the CLI output lane and the relicense audit (2026-11-02)

The owner mandate (night-dragon-maintenance-xenric-1): a total
master-depth audit of the CLI's clean-output lane — non-verbose and
verbose — measured against the sibling zejtron implementation, plus
the total license upgrade to AGPL-3.0. This document is the session's
standing record: what was audited, what was found, what was fixed in
the same session, and what stays open on purpose.

Method note, stated honestly: the audit host is a rootless sandbox
(kernel 5.10, no cgroup v2, no BPF fs, no sudo, no system LLVM) with
the pinned stable 1.98.1 toolchain. The dormant lane ran for real
(compile, clippy, 164 unit + 62 integration tests, the CLI surface
matrix); the full-featured userspace lane was compiled and tested
through the committed prebuilt objects (the registry lane — 946 unit
+ 70 integration green); the eBPF cross-compile lane (bpf-linker +
system LLVM) was unavailable locally and stays CI-owned.

## Lane 1: the CLI output lane, measured against the zejtron law

zejtron's verbose masterclass, read from its source: one static flag
armed once by main straight after the CLI parse; a `vlog!` macro that
guards BEFORE any format machinery runs (a silent run pays one atomic
load and never allocates); one bracketed-tag shape (`[engine]`,
`[btf]`, `[lane]`) on stderr, factual and boring by law; stdout holds
only the report bytes — the pipe law.

zelynic's lane, audited against that law, found the same contract
enforced through a different shape:

- The pipe law held: every trace rode stderr through the
  broken-pipe-safe macros, zero raw `println!`/`eprintln!` bypasses
  in src/ or ebpf/src (a full sweep). The JSON lanes stay
  machine-parseable under `-v` by construction.
- The tag vocabulary held: `[limiter]` (50 sites), `[ebpf]` (8),
  `[container]` (5), `[eagle-eyes]` (3), `[cleanup]` (1) — every
  line bracket-tagged, every trace line either unit-pinned in
  `trace.rs` or a guarded ad-hoc site.
- The gap was the plumbing: a `verbose: bool` threaded by hand
  through every handler signature, the `Limiter` and `Observer`
  constructors, the container resolvers, and the dormant stubs —
  25+ call sites carrying a parameter that exists to be forwarded —
  and every print site hand-rolling the same
  `if verbose { eprintln_safe!("{}", grey(&format!("[tag] ..."))) }`
  five-line dance. The hand-rolled guard carries a permanent hazard
  class: a future site can format-then-guard by accident, and
  nothing in the shape stops it.

Fixed in the same session (commit with the verbose-lane subject):

- `output::verbose` — the zejtron module, adapted to zelynic's
  contract: one `AtomicBool`, `init()` called once by main, `enabled()`
  as the one read door for the sites whose verbose value is control
  flow (the monitor's pre-TUI observer attach), `log()` as the one
  write door, and two guarded macros: `vlog!(tag, fmt, ...)` for the
  standard bracketed shape and `vlog_line!(line)` for the unit-pinned
  `trace::` formatters that own their tag. Both macros sit in front
  of the format machinery, so the format-then-guard hazard class is
  closed structurally, not by review discipline.
- The bool threading is gone: ~20 handler signatures, the `Limiter`
  struct field, the `Observer::attach` parameter, the container
  resolver signatures, and every dormant-stub read dropped their
  parameter. The diff lands at a net negative line count while
  ADDING the module and its tests.
- Wording is byte-identical: every trace line's text and tier (the
  grammar grey; the two observer attach verdicts keep their
  deliberate green) is unchanged, and the `trace.rs` shapes plus
  their pins are untouched.
- The module rides the chroma gate (`cfg(any(feature = "ebpf",
  test))`): every trace call site lives under the ebpf graph, and
  CI's `-D warnings` keeps the dormant lane honest — a featureless
  build never arms what it never reads.
- One test-hazard find: the verbose flag tests share a process-global
  static while the harness runs tests in parallel threads — the
  first run flaked exactly that way (an assertion observed a
  neighbor's `init(false)`). The pin file now holds one shared
  `FLAG_GATE` mutex; every flag-touching test arms, probes, and
  disarms under it.

Found and left as designed, recorded so the next auditor does not
re-hunt them: the `[cleanup]` legacy-sweep line and the depth
report's focus-window announce print WITHOUT `-v` on purpose (both
are one-time lifecycle announcements with their own doc comments);
the `[ebpf] Monitoring traffic for all processes` line rides the ok
tier, not the grey trace tier (it is the attach verdict, a status
word, still verbose-gated).

Instrument note worth institutional memory: this sandbox's output
transport strips the literal two-byte sequence `[m` from displayed
text (an over-aggressive ANSI sanitizer), which renders Rust's
`#[macro_use]` as `#acro_use]` and once masqueraded as a committed
syntax error during this session's first hour. Source-of-truth probes
(python byte reads) disproved it. Any future audit reading this
repo's code through a sanitized transport should distrust bracketed
artifacts the same way before calling them bugs.

## Lane 2: the total AGPL-3.0 relicense

The sibling precedent is unambiguous: zejtron — the owner's mature
reference — is dual-licensed AGPL-3.0-only + Commercial, ships the
full AGPL text in LICENSE, and carries AGPL SPDX headers tree-wide.
zelynic now matches it:

- LICENSE ships the full GNU Affero General Public License text (the
  sibling's canonical copy); the dual-license shape is unchanged.
- Every SPDX header moved `GPL-3.0-only` -> `AGPL-3.0-only` (488
  files), plus the manifests (root + ebpf), the deny.toml allow
  list, the header/policy gates' expectation, and the pricing prose.
- The paired runtime contract moved as one: `src/info/mod.rs`'s
  contiguous `License: AGPL-3.0-only` rodata literal, its doc
  comment and pin, and the release lane's `strings` probe — the
  v11-beta.2 incident's contiguous-bytes contract holds on the new
  id (verified live: the built binary carries the new literal and no
  stale one).
- Living docs updated as one: README, NOTICE, AI_AGENTS_READ_THIS,
  CONTRIBUTING, CLA, COMMERCIAL_LICENSE, LICENSING_FAQ, TRADEMARK,
  SAFETY_ANALYSIS, RULES, and the pricing research.
- The frozen history keeps its bytes on purpose: past changelog
  entries and the two archived era records state what past releases
  stated, and rewriting them would falsify the record (their file
  headers carry the new id like every tracked file). A changelog
  [Unreleased] entry records the relicense. No version bump rides
  the change (the owner owns the version).

Prebuilt-lane note, disclosed: the ebpf/ delta against the
previously pinned tree is license metadata only (SPDX id lines plus
the ebpf manifest's license field — zero statement changes), and
comments compile to no bytes, so the staged objects are unchanged;
the manifest's tree pin was advanced by hand with the documented
recipe because the rebuild lane needs bpf-linker and system LLVM,
absent on this rootless host. CI's full-life lanes rebuild the
objects on every push and the parity gate re-verifies there.

## What this audit did not run, on purpose

- The full-life enforcement path (root, cgroup v2, BPF fs): absent
  on this host by construction; CI's ebpf lanes own it.
- The frame A/B benchmark: no byte of the render path
  (src/ebpf/render/) changed — the verbose lane touches attach-path
  tracing and the license lane touches metadata and docs — so the
  visual-density and fps instruments have nothing to A/B (the same
  non-applicability class the X1 session recorded).

## Verdict

The CLI output lane now enforces the zejtron verbose law structurally
(one door, one static flag, no threading) while keeping zelynic's
byte-pinned trace vocabulary and color contract; the relicense lands
the project on the sibling's AGPL-3.0-only precedent with every
contract surface moved in step and the frozen history left honest.
Both lanes verified on the audited bytes: dormant 164 unit + 62
integration, full-featured 946 unit + 70 integration, clippy clean
on both lanes, rustfmt clean, header/permission/language gates green,
the prebuilt parity gate green. LTS-ready from this seat, with the
full-life lane CI-owned as always.

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
