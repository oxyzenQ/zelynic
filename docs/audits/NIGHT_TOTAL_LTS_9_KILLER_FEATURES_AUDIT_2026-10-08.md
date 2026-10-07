<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-total-lts-9 depth audit — the killer-features pass, round four

> Audit date: 2026-10-08 (NIGHT-total-lts-9). Scope: the owner's ask —
> depth audit focused on the killer features (the limiter and the
> monitoring/eagle-eyes), then the UX CLI/flag surface, then the other
> Rust code, total LTS, honest. Audited at 39b5b2e
> (night-audit-3's HEAD; v50.0.0-alpha.1; the eBPF enforcement object
> byte-pinned — the prebuilt-parity gatekeeper re-proves the tree
> pin). Method: lts-3, lts-5, and lts-7 read the feature engines line
> by line, and hunt-29 (the same night as lts-7) already closed the
> one residual lts-7 declared open — so this round hunted the DELTA
> none of those rounds could have seen: the four commits that landed
> after the last audit point (improve-54's --all lane and --no-test,
> improve-55's total retirement of the snapshot/restore pair, the
> improve-53/54 vocabulary sweep, audit-3's innovation ledger). The
> fresh reads sat on the removal seams inside the killer-feature
> paths, the help surface the retirement reshaped, and the
> re-export/grammar boundaries the pair left behind. Status: ONE real
> find — the help reference's --print-json line still carried
> `restore` as the pair's fifth JSON surface after the verb's total
> removal (the machine truth in cli/scope.rs never drifted; the help
> mirror did) — closed with the one-line collapse, the pin's new
> shape, and a negative pin so the retired spelling cannot ride the
> line back. A second find (the audits index in docs/README.md
> stopped at 2026-10-03, eighteen docs invisible in the
> institutional-memory map) is this round's honest note and lands in
> the lts-8 commit — the audit-family split lts-6 and lts-7 used for
> their own shared find. Every other surface read SOUND at peak or
> verified already-closed by the same-night audits this round
> cross-checked.

## 1. The mandate

The owner's ask: killer features first — the limiter engine, the
eagle-eyes monitor — then UX/CLI, then the remaining Rust code, under
the five infra areas and the peak-skip protocol. The instrument
table:

| # | The ask | The instrument this audit used |
|---|---------|-------------------------------|
| 1 | Stability & crash over the limiter and the monitor | fresh reads of every removal seam (during.rs after the -121-line retirement, during_map's rollback/sweep/stamp lanes, the mod.rs re-export trim); the crash-pattern classes inherited from lts-6/7 re-confirmed untouched (no new unwrap/expect/panic entered with the delta — the four commits' diffs verified line-class); the full battery fresh (829 + 55 / 0 failed at HEAD after the fix) |
| 2 | Code hygiene across the killer-feature dirs | the retired-vocabulary hunt over every live surface (src/, test/, the help text, the suggestion dictionary, the ux redirects): every remaining `restore`/`snapshot` hit classified — terminal-domain vocabulary, history narration, or the intentional redirect pair; the kernel-side and src-side sweep diffs re-read line-class (comment-only in ebpf/, user-facing string updates to the improve-53/54 surfaces in commands — nothing unexpected) |
| 3 | Optimization of the hot paths | no hot path touched by the delta or the fix (the find lives in the --help printer; the frame harness never executes it) — the lts-6/7 peak verdicts stand with their own evidence, re-anchored not re-run |
| 4 | Security hardening at the feature surfaces | the honesty contract is the surface: the QUIC parser, the /proc boundary, and the update lane untouched by the delta (verified by diff) — the one honesty defect in the delta was the find itself (help advertised a dead surface to script authors) |
| 5 | LTS stability of the feature contracts | the retirement's seam verdicts: legacy window rows honored at the verdict level (an older build's promise keeps its promise), the grammar refuses the retired shapes at the flag, the re-export surface trimmed to the live four — all re-read at HEAD and pinned |

## 2. The find — the help mirror lagged the machine truth

`cli/scope.rs` (the --print-json scope contract) is the single
machine truth: `JSON_SURFACE_COMMANDS` names exactly four surfaces —
status, list-apps, eagle-eyes --depth, doctor. The stderr
ignored-flag note prints that list; the dispatcher honors exactly
that set. The help reference (the one end-to-end surface `--help`
prints) mirrored the list faithfully while the pair lived — and
improve-55's total retirement deleted the verb, the commands module,
the persist files, and the scope contract's fifth entry, but left
the help line's trailing continuation standing:

```
  --print-json     JSON output for status, list-apps, eagle-eyes --depth, doctor,
                   restore
```

The stale shape is the exact class the improve-53/54 vocabulary
sweep was chartered to remove — and the sweep missed it because its
instrument hunted the retired spellings as command vocabulary in
code paths, while this line carried `restore` as a JSON-surface
noun inside a wrapped string literal split across two
`println_safe!` calls (the comma-close shape the help pin then
froze verbatim, pinning the defect as a fixture). A script author
reading the one reference surface would target a verb that exits 2.

The fix: the pair collapses into the single line the contract names
(`... --depth, doctor`), the help pin's needle follows, and a new
negative assertion (`doctor,` must not trail a continuation naming a
retired verb) closes the class — the next retirement that leaves a
wrapped noun behind fails the pin the moment it lands, not four
commits later when an audit reads the help output again.

## 3. The limiter engine — the removal seams read fresh, the rest PEAK

- **during.rs** (the -121-line seam): the persistence form
  (WindowPersist and its two halves) went whole with the pair; what
  stays is the live machinery — the duration-only translation, the
  userspace twin, the wall renderers, the state classifier. The
  module doc marks the Span/Daily row kinds as the restore lane's
  vocabulary honestly (legacy rows an older build pinned keep their
  promise at the verdict level; nothing in userspace constructs them
  anymore). The twin arithmetic (saturating offset bridge, the
  margin-eroded daily comparator) re-read against its grid pin —
  SOUND.
- **during_map.rs** (the map plumbing): the read/write/remove lanes,
  the rollback ledger (survivors named, never hidden), the lazy
  sweep (ended spans only, best-effort, the row stays on failure),
  the two offset-bridge stamps (the apply lane authoritative, the
  reuse lane best-effort) — re-read end to end, SOUND.
- **mod.rs**: the re-export line trimmed to the live four
  (dormancy_note, format_wall_utc, wall_minus_mono, wall_now_ns,
  window_state) — no dead re-export survived (deny-warnings would
  have caught an unused import; the grep confirms zero
  `window_persist`/`WindowPersist` hits outside history narration).
- **Kernel files** (enforce.rs, quic.rs, ecn.rs, schema.rs,
  bin/limiter.rs): the vocabulary sweep's diffs verified comment-only
  line-class — the objects stayed byte-identical through the sweep
  (the prebuilt re-pin in the sweep commit, re-proven by the parity
  gate at HEAD). The engine internals are lts-3/5/7's
  line-by-line territory, untouched since — PEAK, skipped beyond the
  diff verification.
- **atomic.rs / policy.rs / reclaim.rs / resolve.rs / types.rs /
  schema.rs (userspace)**: the sweep diffs are the same
  comment-class; the group-lane vocabulary rename changed no
  behavior. PEAK, skipped on the lts-7 fresh reads.

## 4. The eagle-eyes monitor — the declared blind spot, verified CLOSED

- **The lts-7 residual, re-measured**: lts-7's own honest residuals
  named the frame harness's `cookie: None` fixture as the blind spot
  its find lived in and left the closure "noted, not engineered this
  round." Hunt-29 (the same night, 2026-10-07) engineered it: the
  bench fixture now resolves kernel-shaped synthetic cookies (unique
  per socket, one dup'd-fd pair sharing a cookie — the dedup's
  collapse case), and the harness runs the monitor's exact join
  wiring per frame with deterministic per-cookie counters (no LCG
  draw). This round verified the fixture and its pins in place —
  the residual is CLOSED, not open; the skip is the verification.
- **The join fix site** (connections.rs socket_cookies): the
  lts-6/7 HashSet dedup read in place with its lineage comment (the
  desktop-shape decline measured against the dense-host class) and
  its two pins standing (first-seen order, the dense fixture's
  exact-set assertion) — SOUND, unchanged since.
- **monitor.rs / eagle.rs / session.rs / the render tree**: zero
  non-comment changes in the delta since lts-7's line-by-line —
  PEAK, skipped with the diff as evidence. The render frame path
  carries lts-7's byte-exact A/B (1,919.0 bytes/frame) and this
  round's fix touches nothing the frame harness executes (the skip
  reason, honest: re-running the A/B would measure two binaries
  identical in every measured path — noise, not information).

## 5. The UX surface — the find's home, otherwise SOUND

- **The redirects** (ux.rs): `("snapshot", "status")` and
  `("restore", "status")` are the intentional graceful-degradation
  pair (a user typing the retired verb gets the unrecognized-command
  error plus the redirect hint), pinned by ux_tests'
  removed_snapshot_redirects_to_status pair — intentional, tested,
  correct. The suggestion dictionary (suggestion.rs, rescue.rs,
  tips.rs) carries zero retired-verb entries — the matchers cannot
  suggest a dead spelling.
- **The scope contract** (scope.rs): the ignored-flag note, the
  dispatcher predicate, and the featureless-build honest set — all
  re-read SOUND; this file is the truth the help line now mirrors.
- **The epilogue strings** (block.rs, strict.rs, strict_all.rs):
  the improve-53/54 surface updates (the `u --all` spellings, the
  `::` separator tip) verified as the only non-comment string deltas
  — current, pinned by the ux/help pin family.

## 6. Optimization — PEAK, the skip reasons on the record

| Surface | Verdict | The evidence |
|---------|---------|--------------|
| The frame render path | PEAK (skip) | lts-7's byte-exact A/B stands; the delta and this round's fix touch nothing the harness executes |
| The loader join point-lookups | PEAK (skip) | lts-6/7's design note (2 syscalls per cookie vs 4096-entry iteration) unchanged since |
| ranked()'s full sort / retire_dead walk | PEAK (skip) | lts-6/7's decline evidence (determinism contract; mitigate-1's 7.6% A/B) — re-measuring repeats those audits for no new information |
| The help printer | NOT A PATH | the find lives here — a string constant outside every measured path; the pin test is the instrument (output-level, byte-exact) |

## 7. Security hardening — the honesty contract is the surface

The attacker-facing surfaces (the QUIC parser's bounds-checked read
family, the /proc boundary's honest-miss ladder, the update lane's
sanitize boundary, the lock module's symlink-safe unlink) are
untouched by the delta — verified by diff, skipped on lts-6/Z7/Z9's
own fresh reads. The delta's one honesty defect was the find itself:
the help surface advertising a dead JSON lane to the script authors
who read it. Closed here.

## 8. LTS stability — the retirement's seams, re-verdicted

The retirement family's hidden-failure-mode question — what happens
to a host that upgrades with the pair's leftovers — answers at the
seams this round read: legacy window rows (SPAN pre-translated,
DAILY) stay honored at the verdict level (window_active_user /
window_state / dormancy_note all carry the arms); the flag grammar
refuses the retired shapes by name (pinned in during_user_tests);
the sweep-through-unstrict removal is the same lane it always was;
the re-export surface carries no dead symbols. The battery fresh at
HEAD after the fix: 829 + 55 tests, 0 failed (4 ignored — the
pre-existing ignored set including the frame harness the bench
drives); the count drift from lts-6/7's 837 + 48 is improve-55's own
test deletions (the persist pair's 258 + 178 lines of pins left the
tree with the feature), named here so the next audit reads the
delta as intent, not rot.

## 9. The verdict table

| Area | Verdict | Note |
|------|---------|------|
| Limiter kernel datapath | PEAK, skipped beyond diff verification | comment-only delta; objects byte-pinned through the sweep |
| Limiter userspace (the removal seams) | SOUND, read fresh | during/during_map/mod re-read; no dead re-export, no constructible retired shape |
| Monitor ingestion & join | PEAK (lts-6/7 fix verified in place) | hunt-29 closed the declared bench blind spot the same night lts-7 declared it |
| Render tree / diff engine | PEAK | untouched since lts-7's line-by-line |
| UX/CLI surface | ONE find, closed | the help line's stale fifth JSON surface; the pin now guards the class |
| Crash-pattern classes | CLEAN | no new unwrap/expect/panic entered with the delta |
| Battery | GREEN | 829 + 55 / 0 failed at HEAD after the fix |

## 10. This audit's own honest residuals

- The live eBPF legs (crash-recovery, race, reload, endurance,
  limiter-depth) remain CI-owned — this rootless cgroup-v1 host
  cannot attach an observer; the seam re-reads stand in for the live
  shapes, the same residual lts-6/7 carry.
- The frame A/B was skipped with its reason on the record (section
  4): the fix is invisible to the harness's measured paths — the pin
  test is the byte-level instrument for a text surface.
- The second find (the audits index drift, section 2's sibling)
  lands in the lts-8 commit: docs/README.md's audits table stops at
  2026-10-03, leaving eighteen audit docs (2026-10-04 through
  2026-10-07 — both lts rounds included) invisible in the map. The
  class is a hygiene find in infra territory, not a feature-surface
  defect; the split keeps each commit one-task-scoped, the same
  family split lts-6/7 used for the cookie-join find.

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
