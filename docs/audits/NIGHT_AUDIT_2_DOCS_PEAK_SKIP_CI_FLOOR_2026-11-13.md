<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# night-audit-2 — the docs-and-comments cleaning audit: peak-skip holds, and the CI floor rule was found already standing

Date: 2026-11-13. The owner's mandate, in shape: peak cleaning and
masterclass for all docs and commented code (archive excluded) —
stale-free, inconsistency-free, zero residual at 99 percent, "tell
once, don't dup" (single-source documentation) — with the standing
instruction that if it is already peak, skip and do not
over-engineer. Plus: add the rule that the maximum CI run is 10
minutes.

## The CI rule: found standing, verified live

The mandate's rule already exists in the tree — implemented in
night-zen-2 as the "CI Runtime Caps" discipline (docs/RULES.md,
"## CI Runtime Caps" is the rule's home) and machine-enforced at
every push by `scripts/gates/check-timeout-caps.py`, wired into
`gate-keepers.sh`. The rule's shape: every workflow job must declare
an explicit `timeout-minutes` cap (an uncapped job hangs to the
platform default instead of failing loudly), and no cap may sit
below the sanctioned floor — `MIN_CAP = 10` minutes. The floor
governs only how tight a cap may never be (a too-tight cap kills
honest work on runner jitter); heavy lanes keep their larger,
deliberate ceilings (the supermassive batteries ride 40-60, sized to
observed runtimes per the documented wedge-guard discipline).

Live verification at HEAD: `OK: 32 jobs across the estate, every
one capped, no cap below the 10-minute floor` — 32 jobs, 11
workflows, zero unbounded, zero below the floor. The mandate is
satisfied; adding a second rule would duplicate the first (the
tell-once law applies to rules too). Nothing added.

## The cleaning sweep: the peak-skip protocol, with today's evidence

The peak-skip protocol requires citing the signed state, not
asserting freshness. Three signed audits cover the mandate's
surface, in recency order:

1. **night-zen-lts-1** (2026-11-10, three days ago) — the final
   all-docs consistency audit: ten cross-checks (A-J) each answered
   MATCH or DRIFT with file:line proof, the stale-reference sweeps
   clean, three drift classes found and closed in the same session
   (fix ab6a515), gates green live (1104 tests, gate-keepers 26/0/0,
   check-all exit 0).
2. **night-audit-3** (2026-11-13, this turn) — the structure depth
   audit: the docs-tree half rode the formatter's pipe-end law, the
   audits-index completeness gate extended to the whole docs tree
   (119 pages then; 120 with this audit family's records).
3. **night-signature-advanced-1** (2026-11-13) — the masked
   provenance session: its doc set (README, USAGE, CLAIMS_VERIFICATION,
   DEPENDENCY_AUDIT) written against the standing contracts and
   verified by the gates the same day.

Today's mechanical sweep, run live at HEAD for this record:

- **Stale markers**: `TODO|FIXME|TBD|HACK` across living docs
  (archive excluded) and production source — zero actual markers;
  the only hits are audit records DESCRIBING the hygiene sweeps
  themselves (historical records are allowed to name the pattern
  they hunted).
- **Single-source spot-checks** (the tell-once law): the pricing
  ladder — the retired $99 tier appears only as the dated
  retirement record itself (README.md:1108, "The $99 tier was
  retired"), consistent with the zen-lts-1 verdict; the License
  line's single source is the source const (the release probe greps
  the binary, not the docs); the new Depth-matrix surface teaches
  complementary halves, not duplicates — README shows the `-V`
  example, USAGE teaches the command and the grep idiom, the source
  pins the shape.
- **Index completeness**: the audits-index gate (87/87) and the
  docs-index gate (120/120) both green — every record mapped, every
  mapped path resolving.
- **The formatter and language gates**: markdownlint, codespell, the
  language gate, the SPDX headers, the permission guard, the LOC
  caps — all green in the battery this session's final gate re-runs.

## Verdict

Peak-skip APPLIES: the docs-and-comments surface is already peak
under the standing signed audits plus today's live evidence, the CI
floor rule is already standing and gate-enforced, and the honest
deliverable is this record — zero fixes, zero code changes, no new
rule where the rule exists. Over-engineering here would be the
residual the mandate told this audit to refuse.

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
