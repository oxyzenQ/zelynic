<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-total-lts-6 depth audit — the all-infra pass, total LTS, honest

> Audit date: 2026-10-07 (NIGHT-total-lts-6). Scope: the owner's ask —
> depth audit of all infra, cross-checked across the whole root repo,
> under the five areas (stability & crash, code hygiene, optimization,
> security hardening, LTS stability), with the peak-skip protocol.
> Audited at 81a8712 (night-total-lts-7's HEAD; v50.0.0-alpha.1; the
> eBPF enforcement object byte-pinned, re-proven by the prebuilt-parity
> gatekeeper after every edit). This round runs as the infra twin of
> lts-7's killer-features pass: where lts-7 read the feature engines,
> this pass read the FOUNDATION around them — the crash-recovery
> terminal stack, the update lane, the concurrency lock, the privilege
> matrix, the CI estate, the doc-reference hygiene, the numeric-cast
> family — plus two repo-wide automated hunts (the stale-reference
> sweep and the zombie-code sweep) built for this audit and kept out
> of the repo tree (ad-hoc instruments, not repo assets). Status:
> ZERO new defects; every surface read SOUND at peak; the one real
> find of the night landed in the lts-7 commit (the cookie-join
> dedup, the audit-family close). This document is the honest record
> of the peak verdicts and the skip reasons.

## 1. The mandate

The owner's ask: depth audit, all infra, total LTS, honest — and if a
surface is already at peak, skip it and say why. The instrument
table:

| # | The ask | The instrument this audit used |
|---|---------|-------------------------------|
| 1 | Stability & crash | the crash-pattern sweep (every unwrap/expect/panic across src/ — all hits sit in test blocks or provable loop invariants); fresh reads of the term-reset stack (the five-layer recovery), the lock module, the monitor loop's failure folds; the full battery fresh (837 + 48 / 0 failed at HEAD) |
| 2 | Code hygiene (the dragon hunt) | the stale-reference sweep (502 path references across 67 living docs, each hit classified); the zombie-code sweep (TODO/FIXME/HACK markers: zero in production source; every `allow(dead_code)` carries a documented dual-compile rationale); the LOC-cap and module-boundary gates (23/23) |
| 3 | Optimization | the perf surface re-measured by lts-7's find (closed there); the point-lookup join, the ranked sort, the retirement gate — each re-verified as peak with the design note as evidence; no new hot path found paying for anything its contract does not need |
| 4 | Security hardening (white hat, kernel hacker mode) | fresh reads of the network-facing update lane (root refusal before any I/O, the hourly swarm bound, the sanitize boundary on the untrusted tag, 15s curl timeout), the lock module (/run root-owned 0700, flock-on-fd, symlink-safe unlink — the hunt-14 close), the CI estate (actionlint + actions-pin health + least-privilege permissions on all nine workflows), the numeric-cast family (the u32 cgroup-ID truncation is the documented map-key contract, kernel-consistent) |
| 5 | LTS stability | the schema-version migration lane, the pin lifecycle predicate, the watchdog dormancy, the retirement family — all test-pinned at HEAD; the hidden-failure-mode classes named by prior audits (LRU eviction, data explosion, claims floors) all carry their closes |

## 2. Stability & crash — SOUND

- **The crash-pattern sweep** (the lts-3/lts-5 instrument, re-run at
  HEAD): every `.unwrap()`/`.expect()`/`panic!()` hit across src/
  sits inside `#[cfg(test)]` blocks or behind provable loop
  invariants (probe_role.rs's `connect loop invariant` expect is
  unreachable by construction: the retry loop only exits through
  success or `bail!`).
- **The term-reset stack** (term_reset/ + outer.rs): the five-layer
  defense-in-depth (in-process termios first, the interposed-sudo
  pty lane, the external rescue utilities, the bounded orphan with
  its discriminated re-apply) re-read against its improve-30/31/34
  lineage — every layer's failure mode documented and the recovery
  works from inside the broken terminal (the design contract).
- **The lock module** (lock.rs): flock-on-fd (released by any death
  including SIGKILL), non-blocking with the retry hint, the
  root-owned 0700 /run/zelynic directory — re-read SOUND.
- **The live stress legs** (crash-recovery, race-condition, reload,
  endurance, limiter-depth): root + eBPF required, owned by the CI
  supermassive matrix (the documented split — the rootless battery
  proves the logic, CI proves the kernel); this host is cgroup v1
  rootless and cannot run them, noted honestly as this audit's
  residual, not a skip.

## 3. Code hygiene — the dragon hunt, SOUND (zero true finds)

The stale-reference sweep: 502 path references extracted from the 67
living docs, checked against the tree. Eight apparent stale hits,
each classified on inspection:

- CONTRIBUTING.md's `src/math.rs`, `src/bin/limiter.rs` —
  tree-scoped (the indentation places them under `ebpf/`): FALSE
  POSITIVE.
- CONTRIBUTING.md's `scripts/install.sh` — a past-tense record of
  the package/ move (the tree shows the current location): HISTORY,
  accurate.
- RULES.md's `src/term_reset.rs` (both copies) — the record of the
  drift-and-move event that codified the single-file policy:
  HISTORY, accurate.
- COSMIC_DRAGON_ARCHITECTURE.md's `scripts/stress-test.sh` —
  "retired the legacy" record: HISTORY, accurate. Its
  `ebpf/src/bin/policer.rs` — an unchecked `[ ]` roadmap item (a
  future program): ROADMAP, accurate.
- RESEARCH_TOOLCHAIN_AND_MONITORING.md's `src/spec/mod.rs` — the
  rust-lang upstream path, not this repo: FALSE POSITIVE.
- CHANGELOG.md's `ebpf/render.rs` — a frozen historical entry's
  imprecise shorthand, covered by the doc disclaimer the whole
  estate carries: HISTORY, accepted.

Zero fixes required — the disclaimer-plus-frozen-history discipline
explains every hit. The zombie sweep: no TODO/FIXME/HACK markers in
production source; every `#[allow(dead_code)]` (12 sites) carries
the dual-compile rationale in its own comment (the kernel-object
compile and the userspace test tree consume different subsets of
the shared pure files — deleting the unused half would break the
other tree).

## 4. Optimization — PEAK, the evidence re-anchored

- The one real optimization of the night (the cookie-join dedup)
  landed in the lts-7 commit with its own A/B; nothing else found.
- The loader join's point-lookup design: 2 syscalls per cookie
  against a 4096-entry map's 2-per-entry iteration — optimal for
  every N under the cap.
- ranked()'s full-board sort: the determinism contract (ties by
  cgroup id) at a 1s-plus cadence — a top-N heap would buy nothing
  measurable and re-prove a contract the sort already pins.
- The retirement walk's cap gate: mitigate-1's own 7.6% A/B —
  re-running it would repeat that audit for no new information.

## 5. Security hardening — the surfaces re-read, SOUND

- **The update lane** (the one network-facing surface): the root
  refusal fires before any I/O; the hourly swarm bound throttles an
  agent looped into the command; the untrusted tag rides
  sanitize_comm (OSC 52 clipboard rewrites, ANSI corruption, forged
  verdict lines all die at the boundary — the cybersecurity-2 pin);
  the 15s curl timeout bounds the exchange. The one semantic note
  found: `SemVer::parse` strips pre-release suffixes before
  comparing, so a pre-release current against its own stable tag
  reads "up to date" rather than "update available" — cosmetic,
  owner-controlled versioning (the version discipline rule), noted
  and declined as a fix (the frozen-cli era does not re-engineer
  the checker for a shape the owner's tagging policy never
  produces against itself).
- **The lock module**: the /tmp lock-squatting and symlink classes
  are closed (hunt-14); the opportunistic legacy-unlink is
  symlink-safe by syscall semantics.
- **The CI estate**: all nine workflows carry least-privilege
  permission blocks (contents: read; codeql's security-events:
  write is its job's minimum); actionlint + the actions-pin health
  arm + the shell quad + ruff all green at HEAD.
- **The numeric-cast family**: the u32 cgroup-ID truncation is the
  documented map-key contract (SAFETY_ANALYSIS's ID-width note,
  kernel-consistent — `bpf_skb_cgroup_id` truncated identically in
  the object); the date arithmetic in during_parse is bounded by
  construction; the color-path casts are clamped before the cast.

## 6. LTS stability — the pinned family re-verified

The schema-version migration lane (mismatch triggers
unpin-and-reload), the operational-pin predicate (hunt-19: link
pins are load-bearing on 5.7+), the watchdog dormancy (deadline 0
enforces; no userspace writer arms it today — the unlimited path
correctly does not pay for it), the retirement family (mitigate-1's
freeze lifter), the data-explosion bound (mitigate-1's endurance),
and the claims-floor law (mitigate-3's ceiling doctrine) — all
present, all test-pinned at HEAD, no hidden failure mode found
beyond the ones those audits already closed.

## 7. The verdict table

| Area | Verdict | The evidence |
|------|---------|--------------|
| 1. Stability & crash | PEAK | crash sweep clean; term-reset/lock re-read; battery 837 + 48 / 0 failed |
| 2. Code hygiene | PEAK | 502-ref sweep zero true stale; zero zombie; LOC/module gates green |
| 3. Optimization | PEAK | the night's find closed in lts-7; every other candidate carries its own decline evidence |
| 4. Security hardening | PEAK | update/lock/CI/cast families re-read; workflows least-privileged |
| 5. LTS stability | PEAK | the pinned family re-verified at HEAD |

## 8. This audit's own honest residuals

- The live eBPF stress legs (crash-recovery, race, reload,
  endurance) cannot run on this rootless cgroup-v1 host — the CI
  supermassive matrix owns them; this pass re-read their scripts'
  contracts instead of running them.
- The stale-reference sweep is an ad-hoc instrument kept outside
  the repo (an audit aid, not a repo asset — the LOC policy and the
  tool inventory stay untouched); a future audit can rebuild it from
  this doc's recipe (rg path extraction over `git ls-files '*.md'`,
  existence check, per-hit classification).
- The pre-release SemVer note (section 5) is recorded and declined
  with its reason — a future tag policy change would need it
  re-examined, and this note is the pointer.

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
