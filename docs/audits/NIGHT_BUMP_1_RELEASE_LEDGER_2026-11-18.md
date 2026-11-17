<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-bump-1 record — the release ledger verifies its own writes

> Task date: 2026-11-18 (night-bump-1). Scope: scripts/dev/
> version-to.sh's CHANGELOG ledger handling — the release flow the
> owner drives on every bump. Trigger: the owner's live report on the
> v80.0.x line — a bump to v80.0.6 made with the existing script
> landed the version line BELOW the unreleased section of
> CHANGELOG.md instead of inside ## [Released] above ## [Unreleased],
> and the release's content (the git history since v80.0.5) had to be
> reconstructed by hand. The owner's framing is the correct one: this
> is a fatal-class problem — a release record in the wrong place
> silently breaks the provenance chain every future reader, gate, and
> release note generator trusts — and the fix must make the class
> impossible, not patch one instance. Honesty note: the owner's
> breaking tree state lives on the owner's machine and is not visible
> in this seat, so the root cause is proven by code reading plus a
> reproduction matrix against every shape the old code could meet,
> not by a direct replay of the owner's exact file.

## 1. The root cause (read from the old code, not guessed)

The old changelog_release() had five gaps that compound into the
fatal class:

1. No post-write verification. The splice ran blind — awk printed the
   section around the first "## [Released]" match and the script
   echoed "OK ... (## [Released], newest first)" without ever
   re-reading the file to confirm the version line landed inside the
   Released section, above Unreleased, exactly once. A drifted or
   reordered ledger (the owner's v80.0.x line reset was exactly the
   kind of hand-restucturing that drifts one) wrote anywhere the awk
   happened to aim, and the output still said OK.
2. No pre-flight. The ledger shape was probed mid-flow — AFTER
   Cargo.toml and Cargo.lock had already moved — so a shape refusal
   left a half-bumped tree, and nothing protected the bump itself
   from landing on a ledger that was never in the owner's shape.
3. No section-order law. Nothing in the old code knew that
   "## [Released]" must PRECEDE "## [Unreleased]"; a file whose
   sections had been reordered still spliced "successfully" — the
   version line landing at the bottom of the unreleased area is the
   direct product of this gap.
4. No semver gate. A bump below the ledger's top (a stale tree
   bumping to an old line, or a reset line) was accepted silently;
   "newest first" was claimed by raw top-splicing regardless of what
   the version actually was.
5. No history derivation. The owner's own release rule — a release
   IS the git history since the previous release — had no
   implementation anywhere; every bump left the association between
   the ledger line and the work it releases to manual git
   archaeology.

## 2. The fix: four machine-checked laws, run as a pre-flight

The ledger work moved to the front of the script (before the
already-at early exit and before any file is mutated), under four
laws the record names and the code enforces:

- Law 1 — shape: exactly one "## [Released]" and one
  "## [Unreleased]" heading (multiples refuse); Released must
  precede Unreleased; inside Released only the owner's pure shape
  (blank spacers + bare version lines) is legal. The two repairable
  shapes heal in place, loudly: a Released block sitting below
  Unreleased relocates above it (purity-checked first — foreign
  content refuses, a ledger this script did not create is not one it
  rewrites); a version line stranded outside Released is deleted and
  the verified splice below re-records it (the owner's exact broken
  state heals with one re-run of the bump).
- Law 2 — semver: a bump that is not a step up from the ledger's top
  (sort -V) refuses with the stale-tree-downgrade message; --force
  records the deliberate release-line reset and names it in the
  output. Idempotent re-runs at an already-recorded version skip the
  gate by design.
- Law 3 — verification: after any splice the file is re-parsed and
  must show the version line inside ## [Released] exactly once with
  Released above Unreleased; any other outcome restores the mktemp
  backup and fails the run. A write this script cannot verify is a
  write it does not keep.
- Law 4 — history: after a verified write the release's git history
  prints — the commits since the previous release commit, found by
  the "release: vPREV" commit-message convention (regex-escaped,
  matching both the bare and the suffixed message shapes the history
  carries); no such commit falls back honestly to the last 10
  commits.

The laws ride the existing script contract untouched: the Cargo/
lock/README/ebpf/prebuilt flows, the --commit parity refusal, and
the owner's bare-line ledger shape are all unchanged — this fix
changed only WHERE and HOW VERIFIED the ledger work happens.

## 3. The reproduction matrix (the proof)

The harness (a seat-side instrument, scripts/night_bump1_tests.sh in
the workspace tree — not a repo gate) builds a crafted repo per case
and drives the real script end to end:

| Case | Setup | Expected | Verdict |
|---|---|---|---|
| T1 | healthy owner-shape ledger, git history with a release: v80.3.1 commit plus two work commits, bump 80.3.1 → 80.3.2 | line splices under [Released], verified-in-place message, "2 commit(s) since v80.3.1" listing both work commits | PASS |
| T2 | healthy ledger, bump to v80.0.6 (below the v80.3.1 top) | refused, exit 1, CHANGELOG.md and Cargo.toml byte-identical to before | PASS |
| T3 | same as T2 with --force | reset recorded with the named note, line takes the top, Cargo moves | PASS |
| T4 | the owner's broken state A: Released block BELOW Unreleased with v80.0.6 inside it, Cargo already at 80.0.6, re-run | block relocates above Unreleased, then "already recorded in ## [Released]", nothing else changes | PASS |
| T5 | the owner's broken state B (the literal report): stray v80.0.6 line at the bottom of the unreleased area, Cargo at 80.0.6, re-run | stray deleted, line re-spliced inside [Released] exactly once, verified | PASS |
| T6 | foreign prose inside Released | refused before any mutation | PASS |
| T7 | the blank spacer under ## [Released] missing (hand-edit drift) | refused with the restore-the-blank-line recipe | PASS |
| T8 | healthy ledger already carrying v80.0.6, re-run | "already recorded in ## [Released]" + the early exit, file byte-identical | PASS |
| T9 | no Released heading yet, Unreleased present | section created above Unreleased, verified in place | PASS |
| T10 | neither heading | honest "no anchor" skip, the bump continues | PASS |

10/10 green. The static quad passes too: bash -n, shfmt -d (the
rewrite kept the file's tab shape), and shellcheck -x clean from the
repo root. The gate-keepers battery passes 27/27 on the tree that
carries the fix.

## 4. Peak-skips and rejections, with reasons

- NOT re-sorting the whole Released list by semver on every bump: the
  ledger records release events in the owner's own newest-first
  order; a full re-sort rewrites history this script did not create.
  The semver gate plus the honest --force note cover the reset class
  without surgery.
- NOT embedding the git history into the ledger: the owner's shape is
  bare version lines (NIGHT-improve-76's documented contract); the
  history prints at bump time and the commit history remains the
  single source. Tell once, don't dedup.
- NOT adding a new CI gate for the bump script: the shell quad in
  gate-keepers already covers the script's syntax, format, and
  analysis on every push; the behavioral matrix lives in the harness
  and this record. The gate-inventory freeze stays frozen.
- NOT changing the ebpf/prebuilt/--commit flows: the fix's scope is
  the ledger; the rest of the script is byte-preserved behavior and
  passed its own existing tests untouched.

## 5. The evidence ledger

| Claim | Evidence | Verdict |
|---|---|---|
| The old code could write the version line outside Released and still claim OK | code reading of the old changelog_release() (no re-parse after the splice; no order check) | proven |
| The four laws close the class | the 10-case matrix above, every shape the old code could meet | 10/10 PASS |
| The heal reaches the owner's exact broken states | T4 (Released below Unreleased) and T5 (the stray line at the bottom of the unreleased area) both heal on one re-run | PASS |
| The owner's flow is otherwise unchanged | git diff of the script: the Cargo/lock/README/ebpf/prebuilt/--commit sections are byte-identical | in tree |
| The tree carrying the fix passes the estate's own gates | gate-keepers 27/27 on the changed tree | PASS |

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
