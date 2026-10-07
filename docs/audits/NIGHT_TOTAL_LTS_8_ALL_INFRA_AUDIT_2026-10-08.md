<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-total-lts-8 depth audit — the all-infra pass, round two: the map catches up with the memory

> Audit date: 2026-10-08 (NIGHT-total-lts-8). Scope: the owner's ask —
> depth audit of all infra, total LTS, honest, cross-checked across
> the whole root repo under the five areas (stability & crash, code
> hygiene, optimization, security hardening, LTS stability), with
> the peak-skip protocol: if a sub-task is already at peak, skip it
> and note why. Audited at a972192 (night-total-lts-9's HEAD;
> v50.0.0-alpha.1; the eBPF enforcement object byte-pinned, re-proven
> by the prebuilt-parity gatekeeper). Lineage: lts-1/2/4/6 are the
> infra rounds, lts-6 the most recent — but lts-6 ran at 81a8712,
> BEFORE the four-commit delta (improve-54, improve-55's total
> retirement, the vocabulary sweep, audit-3's ledger) that lts-9
> audited at the feature seams. This round audited the delta's INFRA
> surfaces the prior rounds never saw — the test tree after the
> persist-pair's 436 lines of pins left it, the scripts estate after
> v4's restore rows became REMOVED proofs, the newest public doc
> (the innovation ledger) under the no-secrets lens, and the
> doc-reference map — and re-ran the class instruments fresh (the
> orphan-reachability scan, the zombie-marker sweep, the crash-pattern
> count). Status: ONE find — the audits index (docs/README.md)
> stopped at the 2026-10-03 Z10 row: twenty audit docs, both
> total-lts rounds included, invisible in the institutional-memory
> map — closed with the full re-index (36/36 docs, newest-first).
> Every other surface verified clean or at peak with its evidence.

## 1. The mandate

The owner's ask: all infra, the five areas, honest, peak-skip in
force. The instrument table:

| # | The ask | The instrument this audit used |
|---|---------|-------------------------------|
| 1 | Stability & crash | the orphan-reachability scan rebuilt fresh (every tracked test/*.rs file must be reachable from a compile root — a silently-unwired test file is a test count that drops without a failure, the quietest failure class a test tree owns); the crash-pattern count re-run at HEAD (27 hits across src/, every one the pre-classified set — test blocks, the connect-loop invariant, the build-time schema belt); the battery from the lts-9 run stands (829 + 55 / 0 failed; the delta since is docs-only) |
| 2 | Code hygiene (the dragon hunt) | the index-completeness diff (all tracked docs/audits/*.md vs the docs/README.md index — THE FIND, 20 missing rows); the path-reference check over the newest doc (INNOVATIONS.md's 13 source paths all resolve); v4.py's case tables after the restore-row removal (every remaining mention an intentional REMOVED-pair proof or history narration); USAGE.md's TOC against its section list (11/11, the restore subsection gone, numbering continuous); the TODO/FIXME/HACK sweep (zero in production source); the root-docs vocabulary check (README/QA's "snapshot" hits are the blocklist-capture and color-engine Cloud senses, domain vocabulary, not the retired verb) |
| 3 | Optimization | no hot path exists in the delta (deletions, comments, help strings, doc rows) — the lts-6/7/9 peak verdicts stand with their own A/B evidence; re-anchored, not re-run |
| 4 | Security hardening (white hat, kernel hacker mode) | the newest public doc under the no-secrets lens (INNOVATIONS.md: zero credential/token/API-key material — the "token" and "api" hits are the AMMSP subtree token and the docker Engine API, domain terms); the attacker-facing surfaces (update lane, lock module, CI estate, QUIC parser, /proc boundary) untouched by the delta, verified by diff — skipped on lts-6/Z7/Z9's own fresh reads |
| 5 | LTS stability | the upgrade-with-leftovers question for the retired pair answered at the filesystem: the legacy state file (/var/lib/zelynic/limits.json) is INERT — zero references anywhere in src/ or scripts/ (nothing reads it, nothing writes it, nothing chokes on it); the schema-version migration lane, the pin lifecycle predicate, the watchdog dormancy, the retirement family — all untouched by the delta, skipped on lts-6's re-verification |

## 2. The find — the institutional memory outgrew its map

The audits index in docs/README.md is the project's
institutional-memory map ("dated, immutable records... the
institutional memory" is the section's own contract). The table was
maintained faithfully through the 2026-10-03 Z10 row — and then
stopped: twenty docs filed under docs/audits/ between 2026-10-03
(Z11, the same day as the last indexed row) and this audit's own
sibling (lts-9, 2026-10-08) were never given rows. Both total-lts
rounds, all three mitigate rounds, both hunt-30 records, the
depthbore engine audit, the improve-46..50 arc, hunt-27/28/29, the
krun asymmetry, hunt-32's scripts disease, and Z11 — invisible in
the one table a new maintainer reads first.

The class is the exact shape LTS-6's stale-reference sweep could
not see: that instrument checked whether a doc's PATH references
resolve (every audits/ path in the index did), not whether the
index covers the directory it maps. Eighteen sessions shipped
audit docs without indexing them; no gate exists for index
completeness (none failed); the drift compounded silently.

The fix: the full re-index — twenty rows written newest-first from
each doc's own header (title + scope block, so every one-liner is
grounded in the doc it maps, never invented), the table now complete — every
tracked audit doc indexed, this round's own record included. A
future audit can rebuild the completeness check from
this doc's recipe: `git ls-files 'docs/audits/*.md'` minus the
index's link set must be empty.

## 3. Stability & crash — SOUND, the quiet class hunted fresh

- **The orphan-reachability scan** (built fresh this round, the
  two-level cascade honored): every tracked file under test/ must
  be reachable from a compile root — the src/ module tree's
  #[path] includes, the wiring.rs cascade that mounts the limiter
  test siblings, or the cargo-declared integration root. Verdict:
  ZERO orphans. The persist pair's two test files left the tree
  with the feature (436 lines of pins, gone whole), during_user_tests
  slimmed in place, and nothing dangles: the battery count
  (829 + 55) is the true wired count, not a count shrunken by a
  silently-unwired file.
- **The crash-pattern count**: 27 hits across src/ at HEAD, every
  one the set lts-6 classified (test blocks, the provable
  connect-loop invariant, the build-time SCHEMA_VERSION belt). The
  delta added zero — it was deletions, comments, and help strings.
- **The live stress legs** (crash-recovery, race, reload,
  endurance, limiter-depth): root + eBPF required, CI-owned — the
  same residual every rootless round carries, noted not hidden.

## 4. Code hygiene — the dragon hunt, ONE find (closed), the rest clean

- **THE FIND**: the index drift (section 2) — closed with the
  20-row re-index.
- **INNOVATIONS.md** (the newest doc, audit-3's ledger): all 13
  source-file path references resolve against the tree; the
  provenance note and reading order read clean. No stale symbol,
  no invented claim (the doc's own pre-commit fact-check was
  audit-3's; this round re-proved the paths).
- **v4.py** (the supermassive harness after improve-55): every
  remaining restore/snapshot mention is an intentional REMOVED-pair
  proof row (the retired spellings pinned as unrecognized-or-
  redirect) or dated history narration — the case tables hold no
  dangling references to deleted cases.
- **USAGE.md**: the TOC (11 entries) matches the section list
  exactly; the restore subsection is gone with the pair; the
  command-reference numbering flows continuously (strict's three
  lanes, block, unstrict, recover, status, list-apps, eagle-eyes's
  two modes, doctor).
- **Zombie markers**: zero TODO/FIXME/HACK in production source;
  the dead_code allow sites carry their dual-compile rationales
  (lts-6's classification, unchanged by the delta).
- **Root docs** (README.md, QA.md): the three "snapshot" hits are
  the blocklist-capture sense ("rules are a snapshot — new apps
  need a re-run") and the color engine's immutable Cloud — domain
  vocabulary, not the retired verb.

## 5. Optimization — PEAK, skipped with the evidence

The delta contains no hot path: deletions, comments, help strings,
doc rows. The optimization verdicts of record stand — lts-6/7's
decline tables (the loader join's point lookups, ranked()'s
determinism sort, the retirement walk's cap gate at its own 7.6%
A/B) and lts-9's re-anchoring one commit earlier. Re-running any
of them against a docs-and-strings delta would measure noise.

## 6. Security hardening — the surfaces untouched, the new doc clean

The attacker-facing estate is the delta's non-estate: the update
lane, the lock module, the CI workflows, the QUIC parser, the
/proc boundary — zero non-comment changes since lts-6 read them
fresh (verified by diff; skipped on that evidence). The one new
public surface is the innovation ledger, and it carries no
secrets: the no-secrets lens over INNOVATIONS.md finds domain
terms only (the AMMSP subtree token, the docker Engine API), no
credential, no token material, no internal hostname. The index
repair adds twenty public one-liners of already-public doc
summaries — nothing new to harden.

## 7. LTS stability — the leftovers question, answered honestly

The retirement's hidden-failure-mode question is the filesystem
one: what does an upgraded host do with the pair's leftovers?
Answered at the source: the legacy state file
(/var/lib/zelynic/limits.json) is referenced NOWHERE in src/ or
scripts/ — nothing reads it, nothing writes it, nothing chokes on
it. Inert is the verdict: no failure mode, only litter. Whether a
cleanup lane should sweep root's /var/lib content is an owner
policy call, not an audit's default — declined and recorded here
as the pointer. The pinned family (schema-version migration,
operational-pin predicate, watchdog dormancy, retirement freeze
lifter, data-explosion bound, claims ceiling law) is untouched by
the delta — skipped on lts-6's re-verification and mitigate-1/3's
own arithmetic.

## 8. The verdict table

| Area | Verdict | The evidence |
|------|---------|--------------|
| 1. Stability & crash | PEAK (fresh confirms) | zero orphans; 27 pre-classified crash-pattern hits, zero new; battery 829 + 55 / 0 failed |
| 2. Code hygiene | ONE find, CLOSED | the 20-row index re-index (36/36); INNOVATIONS/v4.py/USAGE/root-docs all clean |
| 3. Optimization | PEAK (skip) | no hot path in the delta; lts-6/7/9's decline tables stand |
| 4. Security hardening | PEAK (skip) | attacker-facing estate untouched by diff; the new doc carries no secrets |
| 5. LTS stability | PEAK (skip + one answer) | the legacy state file INERT (zero references); the pinned family untouched |

## 9. This audit's own honest residuals

- The live eBPF stress legs remain CI-owned (the rootless cgroup-v1
  host constraint every night round records).
- The twenty new index rows are one-line summaries grounded in each
  doc's header, not re-reads of every doc's full body — a future
  pass that deepens any row should read the doc it maps first (the
  rows are map entries, never replacements for the records).
- The state-file sweep (removing /var/lib/zelynic/limits.json on
  upgraded hosts) is declined as an owner policy call; this doc is
  the pointer if the owner wants a legacy-sweep lane.
- No index-completeness gate exists yet — the drift's root cause
  is that nothing failed for eighteen sessions. This doc's recipe
  (section 2) is rebuildable in one command; wiring it into the
  gatekeeper battery is an owner-scope decision (the gate inventory
  is a frozen surface), noted here as the honest next step.

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
