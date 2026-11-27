<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# night-solid-defense-1 — the maintenance lane becomes AXP1-ZnQ, the security supply-chain sentinel

Date: 2026-11-22. Session scope: the owner's maintenance CI (whose
default function is the dependency update) becomes a security
supply-chain smart bot named **AXP1-ZnQ** (Architect's eXecution
Protocol 1) — a Sunday-morning sentinel
that detects CVE-critical, vulnerable, unmaintained, unsound, and
yanked dependencies, and separates the owner's two scenarios: the
finding the sweep CAN fix (update now, the fix ships) and the finding
it CANNOT (dangerous dep, no automatic update path — CALL OWNER, the
lane holds). The owner's words named the clock (Sunday 10 in the
morning, while the dragon sleeps) and the standard (verify it
complete, prove 100% works real, no gimmick). The mature reference
the owner pointed at is the sister repo zejtron, whose production
lane already carries the pattern.

## The sentinel design (what watches, what speaks)

Three pieces, each one job or one script:

1. **The engine** — `scripts/ci/supplychain-verdict.sh`, ported from
   the zejtron production line. A `--pre` pass scans every committed
   lockfile against the RustSec advisory database (the same walk the
   sweep script owns, all four workspaces), stores the findings, the
   sweep runs, and the `--post` pass scans the swept lane and diffs it
   against the stored snapshot:
   - **Scenario A (fixable)** — the key is gone from the swept lane:
     the advisory was real and the update took the clean version. The
     job stays green, a loud `::warning` notice still fires, and the
     validated lane ships the fix in the same run. Without the Sunday
     lane the tree would have carried the advisory for a week.
   - **Scenario B (unfixable)** — the finding survives the sweep (no
     fixed version inside the current version requirements, or no fix
     released at all): the job fails hard, one `::error` annotation
     per finding, the banner reads CALL OWNER, and the commit job
     never runs — nothing ships while the lane is red. A scheduled
     run failing is GitHub's own call-the-owner channel: the red run
     and its annotations greet the dragon with the week's first
     coffee.
   - Fail-closed law: a scanner that cannot run or cannot be parsed
     is a verdict failure, never a silent pass.
2. **The lane** — `maintenance.yml` (the file name stays: it is the
   night-fly-1 exempt-set key). The display name becomes
   `Dragon Guard - AXP1-ZnQ Supply-Chain Sentinel`; the workflow wraps
   its existing sweep with the pre-pass and the verdict, gates the
   ship lane on the verdict, and grows the `scan_only` dispatch input
   — the owner's red button: any day of the week, the advisory state
   of every workspace, one click, nothing ships.
3. **The clock** — `0 3 * * 0` UTC: every Sunday at 10:00 WIB, the
   owner's explicit window. The night-fly-1 law keeps this lane's
   schedule by its own exception (maintenance-critical lanes watch
   external state — the advisory database, the registry, the signing
   key — state no commit event can carry), and the per-push estate
   keeps covering the tree itself (audit.yml rides every push).

The gpg-key-check job rides the same Sunday clock (the signing-subkey
expiry monitor is part of the same morning report).

## Find 1: the honest battery corrected the reference engine twice

The port was byte-identical to the zejtron production script; the
verification battery was not content with the reference's pedigree
and ran the engine for real — the pinned cargo-audit 0.22.2 (compiled
from source, 4m59s) against the live advisory database — on the real
swept repo AND on three vulnerable-dep fixtures. The fixtures caught
two defects the byte-identical port inherited:

1. **The scenario-A join lost the composite key.** The lookup read
   `$1` (workspace) instead of the full key, and the cleared row
   printed with only the workspace field stripped — a workspace
   keeping one surviving finding would silently lose its cleared
   sibling, and the cleared banner's columns shifted (the mio fixture
   printed the garble live: workspace read "vulnerability", the
   version column read the advisory id). Fixed: the join keys on the
   full composite (workspace, kind, id, package; version-joined for
   yanked) and the cleared rows print WHOLE, so the banner and the
   step-summary table read the same seven columns every other table
   reads.
2. **The coalescer crashed on the warning families.** The filter
   indexed every advisory family through `.list` — but cargo-audit
   0.22.2 ships the warning families (unmaintained, unsound, yanked)
   as plain arrays, so the first Sunday an unmaintained dependency
   appeared, the verdict would have died on a jq exit 5 (fail-closed
   direction, but a crash, not a verdict). Fixed: one `items()`
   normalizer reads object-with-list, plain array, and absent shapes;
   anything it still cannot read fails closed exactly as before.

The proof tape, all against the pinned scanner and the live DB:

| Case | Lane | Verdict |
|------|------|---------|
| the real swept repo (4 workspaces, clean) | pre + sweep + post | PASS, 0 hard findings, exit 0 |
| fixture A: mio 0.8.10 (RUSTSEC-2024-0019) | pre + sweep + post | scenario A: cleared with true columns, `::warning` fired, exit 0 |
| fixture B: atty 0.2.14 (RUSTSEC-2024-0375 unmaintained + RUSTSEC-2021-0145 unsound) | pre + post (nothing to clear) | scenario B: two `::error` CALL OWNER annotations, exit 1 |
| fixture C: mio + atty in ONE workspace | pre + sweep + post | both scenarios in one verdict: the cleared sibling reported AND the two surviving findings named — the exact shape the old join dropped |

The zejtron copy still carries both defects (its warning shape would
crash the same way, and its join drops the same sibling); the fixed
engine is the zelynic lineage now, and the correction is the honest
divergence the battery bought.

## Find 2: the red button exposed the GPG monitor's empty-success hole

The first scan_only dispatch (run 44937754549) carried the verdict
lane green on hosted infra — `AXP1-ZnQ verdict: PASS - 4
workspace(s) scanned, 0 hard finding(s), 0 cleared by the sweep, 0
informational`, the validate job 3m55s wall, the commit job skipped
whole by the scan_only guard — and it exposed a latent hole in the
GPG signing-key expiry monitor: the keyserver answered its fetch arm
with exit 0 while importing NOTHING (the empty-success class), the
fallback arm never fired, and the expiry walk died on `gpg: error
reading key: No public key` under errexit (exit 2) — instead of the
step's own documented law, a keyserver outage must not break the
pipeline. The fix: the fetch loop verifies the key actually landed
(recv + list) after every arm, so a server that answers but serves
no key degrades to the same non-fatal `::warning` a dead server
gets. The re-dispatch (run 44938278865) reads full green: validate
success in 3m04s, GPG check success, commit skipped.

The second dispatch's verdict line, from the hosted log:
`AXP1-ZnQ pre-pass: 0 finding(s) stored across 4 workspace(s)` then
`AXP1-ZnQ verdict: PASS - 4 workspace(s) scanned, 0 hard finding(s),
0 cleared by the sweep, 0 informational`.

## Find 3: the E2E floor-kernel leg's single-source dependency, recorded

The supermassive-e2e stage job went red on five attempts across
three commits (runs 44936228796 and its rerun, 44938271821 and its
rerun, and the doc push's run with its rerun), every time in the
same step — "Fetch the Arch LTS 6.6 kernel (the 6.6 family leg)" —
on `curl: (28) Connection timed out` against archive.archlinux.org.
The evidence chain:

- the host answers nothing from the runners AND from independent
  sandbox probes hours apart (HTTP 000 at 45s, then 000 at 20s
  again) — a global outage of the archive, the same host and class
  night-fly-1 recorded;
- the current mirror fleet serves linux-lts at 6.18.64 (the core
  index measured) — the 6.6 floor line exists nowhere else; no
  mirror walk can substitute (the Debian 6.1 leg got the walk
  because the pool mirrors carry the 6.1 line; the Arch 6.6 floor
  has exactly one canonical history source);
- the session's diff is unrelated to the leg (the lane never touched
  it; gate-keepers, CI, audit, codeql, fuzz, miri, proofs, the four
  supermassive family lanes, verify, and the sentinel dispatch all
  green around the red);
- the honest contrast the same evening supplied: the supermassive
  desktop lane's realnet probe flaked once (one of 104, the
  removed-mid-window busy-hour residual class) and greened on its
  failed-jobs rerun minutes later — that is what a transient looks
  like; four identical reds at one external host for an hour, with
  no recovery, is an outage, and no rerun manufactures a verdict
  against a dead source.

The named lever for a follow-up task: cache the once-fetched floor
kernel (actions/cache keyed on the resolved package name — the
archive answered for the Nov 16 scheduled run, so a hit would ride
that download past future outages) — a lane-design decision with its
own signed round, deliberately not improvised tonight. Until the
archive returns, the leg's red is the honest report of an external
dependency down, not a regression.

## Find 4: the clock moves to the owner's Sunday, the doctrine prose follows

The maintenance clock moved Monday 10:07 WIB to Sunday 10:00 WIB (the
owner's words; the zejtron estate's one clock). The zero-residual
sweep walked the living-doc surface the move touches:

- `miri.yml`'s comment still promised a Sunday 03:07 UTC run its
  retired weekly clock no longer makes — rewritten to the per-push +
  dispatch reality.
- `reproducible.yml`'s comment still paired its Monday window with
  audit.yml's retired clock — rewritten; its own Monday 03:37 UTC
  window stays (the D4 publish-provenance re-check, the exempt set).
- `docs/MAINTENANCE.md`: the maintenance table row now names the
  sentinel, the two scenarios, and the red button; the clock-lane
  prose no longer lists the retired weekly audit/CodeQL/miri
  schedules; the cadence row says Sun.
- `docs/DEPENDENCY_AUDIT.md`: the chrono-ban enforcement and the
  nine-ban wall no longer point at "the weekly audit.yml observation
  run"; the four-gate defense chain names the Sunday sentinel verdict.

History keeps its era-true text (audit records, the README index
rows, the CROSS_DISTRO retirement note).

## Verification ledger

Local (every number measured, not estimated):

- `bash -n` + `shellcheck -x` + `shfmt -d` on the engine: exit 0.
- `yamllint` (repo config) + `actionlint` (repo runner-label config)
  on the three touched workflows: exit 0.
- The gates battery, all green: runtime-law (37 jobs capped, no
  schedule on a test lane), policy, name-case (680 files),
  permissions (680 files — after the engine's mode tightened 775 to
  755), secret names, version anti-patterns, Rust-version sync,
  scripts-loc, loc (365 files), fuzz includes, audits-index
  (99/99 + 134/134 before this session's doc lands), language
  (673 files, zero findings), headers (636 files). The actions-pins
  health prints its standing advisory (dependency-review-action
  v4.9.0 -> v5.0.1 upstream move — advisory mode, pre-existing).
- The engine proof tape: the table above (4 cases, live scanner,
  live DB).
- File permissions gate: PASS after `chmod 755`.

Hosted (the API record, not estimates):

- The per-push estate on the engine-correction commit (9ba19d98):
  12 of 13 lanes green — Gate-keepers wholesale (the hosted battery
  over the new script and the YAML), CI, Security Audit, CodeQL,
  Fuzz, Miri, Proofs, the four Supermassive family lanes minus E2E,
  netrunner, Verify. The one red is Find 3's external archive
  outage (three runs, one step, one host), unrelated to this
  session's diff.
- The red button, dispatched twice for real:
  - run 44937754549 (scan_only=true, commit 9ba19d98): the verdict
    lane green — pre-pass `0 finding(s) stored across 4 workspace(s)`,
    the sweep probe, the post verdict `PASS - 4 workspace(s) scanned,
    0 hard finding(s), 0 cleared by the sweep, 0 informational`, the
    validate job 3m55s wall (well inside the 15-minute law), the
    commit job skipped by the guard; the GPG job's exit 2 became
    Find 2's fix.
  - run 44938278865 (scan_only=true, commit 9ce28b0e, after the
    fix): full green — validate 3m04s, GPG check success, commit
    skipped. The sentinel's first complete hosted verdict, red
    button to report, inside four minutes.
- The per-push estate on the fix commit (9ce28b0e) and the record
  commit (e56744b5): Gate-keepers, CI, Security Audit, CodeQL, Fuzz,
  Miri, Proofs, Supermassive Server, Supermassive Container E2E,
  netrunner, Verify green on both; the desktop shard's one realnet
  probe flaked on e56744b5 and greened on its failed-jobs rerun
  (the busy-hour residual class); the E2E archive leg stayed red
  across every push and rerun while the archive is down (Find 3),
  the rerun button is the verdict when it returns.
- The Sunday clock is registered: the first scheduled fire lands
  2026-11-29 03:00 UTC (10:00 WIB), the verdict greets the dragon
  with the week's first coffee.

## Continuation (same night, commit a84a50d): the bounded walk and the outage verdict

The outage outlived the record — probes hours apart still read the
archive dead — so the named cache lever stayed a lever (it needs its
own signed round), and the leg shipped the smaller honest fix
instead. Three things, all measured:

- The substitute-source question is closed with evidence, not
  assumption: the third-party estate carries no
  `/packages/l/linux-lts` tree (every archive-path shape probed 404
  at tuna, sjtug, ustc, zju, kernel.org's edge, osbeck, mit, and
  rackspace; the official mirror API lists no mirror serving the
  archive), the Internet Archive's per-package collection
  (`archlinux_pkg_linux-lts`) tops out at linux-lts 3.10.43, and its
  full-snapshot item (`archlinuxarchive`) carries no package tree —
  archive.archlinux.org is the one canonical history source, exactly
  what Find 3 read from the core index (6.18.64 and nothing older).
- The fetch walks bounded now (a84a50d): two tight attempts
  (connect-timeout 10, max-time 60 for the index, 240 for the
  package) replaced the seven blind retries, and on failure the
  DNS-vs-host diagnosis speaks. The live run 44947108301 measured
  it: 25 seconds from step entry to a verdict that names the class
  (`resolver answers + connect dead = host-side outage of
  archive.archlinux.org ... not a code regression; rerun the lane
  when the archive returns`), against the five-and-a-half-minute
  bare exit 28 this same outage produced the night before.
- The verdict machinery itself re-proved on the host, not only in
  CI: the fixture battery rode the live advisory DB. Scenario B
  held the lane (time 0.1.45 under its exact pin survives the
  sweep — RUSTSEC-2020-0071, the per-finding `::error` CALL OWNER
  annotation, exit 1). Scenario A's clearing printed both cleared
  rows whole (chrono 0.4.19 and the transitive time 0.1.45 under
  RUSTSEC-2020-0159, the `::warning` notices, exit 0). The
  fail-closed class fired twice on scanner-unreadable inputs. And
  the live DB added one unscripted proof: the sweep's own move
  (chrono 0.4.45) carries RUSTSEC-2026-0543 (unmaintained), the
  post-pass flagged it and held the lane — an unmaintained advisory
  has no version fix, so the verdict's refusal is the contract
  working, not the fixture failing.

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
