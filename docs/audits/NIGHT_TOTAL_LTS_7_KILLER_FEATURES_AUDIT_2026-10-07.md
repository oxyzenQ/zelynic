<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-total-lts-7 depth audit — the killer-features pass, round three

> Audit date: 2026-10-07 (NIGHT-total-lts-7). Scope: the owner's ask —
> depth audit focused on the killer features (the limiter and the
> monitoring/eagle-eyes), then the UX CLI/flag surface, then the other
> Rust code, total LTS, honest. Audited at f3e471b
> (night-mitigate-3's HEAD; v50.0.0-alpha.1; the eBPF enforcement
> object byte-pinned — the prebuilt-parity gatekeeper re-proves the
> tree pin). Method: lts-3 and lts-5 already read the kernel
> enforcement math, the render tree, the observer modules, and the
> CLI surface line by line, so this pass hunted the SEAMS those two
> rounds did not cross-check against each other's own decline
> decisions — the deferred residuals re-measured against the product's
> dense-host target class — plus fresh independent reads of the QUIC
> attribution lane (both halves), the during window family (the
> userspace stamp and the kernel gate), the reclaim path, and the
> crash-pattern sweep.
> Status: ONE real find where an audit's own decline reason met the
> product's own target class (the socket-cookie join's quadratic
> dedup, declined by lts-5 on a desktop-shaped measurement, quadratic
> on the dense-host shape the object's own 4096 LRU caps exist for),
> closed with a one-HashSet fix and two new pins; every other
> surface read SOUND at peak.

## 1. The mandate

The owner's ask: killer features first — the limiter engine, the
eagle-eyes monitor — then UX/CLI, then the remaining Rust code,
under the five infra areas and the peak-skip protocol. The
instrument table:

| # | The ask | The instrument this audit used |
|---|---------|-------------------------------|
| 1 | Stability & crash over the limiter and the monitor | fresh reads of the QUIC wiring (the hint-map CAS family, the two-read split), the during gate chain (stamp, bridge, kernel comparator), the reclaim family; the crash-pattern sweep re-run (every unwrap/expect/panic in src/ — all in test blocks or provable loop invariants); the full battery fresh (837 + 48 / 0 failed after the close) |
| 2 | Code hygiene across the killer-feature dirs | the stale-doc hunt over the join's own documentation (the fix updates the module doc where the dedup shape was implicit); module boundaries unchanged (no file crossed its LOC cap) |
| 3 | Optimization of the hot paths | the per-frame join path re-measured: the O(sockets x distinct) dedup closed to O(n) (the find); the frame A/B after the close — bytes/frame byte-exact at 1,919.0 both sides, fps +1% noise-class |
| 4 | Security hardening at the feature surfaces | the /proc boundary family re-verified (pidfd tri-state, the cookie join's honest-miss ladder); the QUIC parser's bounds-checked read family re-read (every access .get()-gated, panic-free by construction) |
| 5 | LTS stability of the feature contracts | the join's observable contract frozen by the two new pins (first-seen order + dense-set exactness); the frame bench's visual metrics byte-identical |

## 2. The find — a decline reason measured against the wrong host class

NIGHT-total-lts-5 (2026-10-03) declined to restructure
`socket_cookies()`'s dedup, recording: "bounded by the /proc walk's
own scale (hundreds typically), measured in the class of the frame
budget, and rebuilding it as a HashSet would churn the frame path
this audit's benchmark just proved byte-exact — declined, noted."

Both halves of that sentence deserve the dragon hunt this round:

- **"hundreds typically"** — the measurement anchored on the desktop
  shape. But the product's own object carries 4096-entry LRU caps
  for exactly the dense-host class ("host server padat"), and the
  monitor's join key set scales with resolved sockets: a server
  host holding thousands of live sockets pays the Vec::contains
  linear scan per distinct cookie — O(resolved x distinct), the
  quadratic the decline's own "hundreds" bound never reaches on a
  desktop and blows past on the class the caps exist for.
- **"the benchmark just proved byte-exact"** — the frame harness's
  fixture builds its socket detail with `cookie: None`
  (test/ebpf/render/bench.rs, the graceful-degradation shape): the
  dedup loop NEVER RUNS under the benchmark. The byte-exactness the
  decline protected was protecting a path the benchmark does not
  exercise.

The fix this round is the one lts-5 declined, now measured honestly:
the seen-set rides a HashSet (O(1) per socket), the Vec keeps the
first-seen order verbatim, and the join's consumers are
order-independent by construction (loader.rs `socket_bytes` folds
the point lookups into a HashMap either way) — so the swap changes
nothing observable, and the two new pins freeze that claim by test
instead of by argument.

## 3. The limiter engine — SOUND at peak, the fresh reads

- **enforce.rs** (the one verdict path every packet rides): the
  unlimited fast path, the AMMSP miss branch, the window gate, the
  blocked-booking, the burst clamp, the per-socket/group/DRR lane
  selection — all re-read fresh. The fail-open-on-map-race belt (the
  TOCTOU note on the root re-lookup) holds; the group-lane degrade
  (lts-7's own earlier close, folded into the unreleased v8) reads
  exactly as documented.
- **math.rs** (refill_window / try_consume): the window-ownership
  CAS, the seed clamp, the absurd-excursion heal, the four-attempt
  consume — re-verified against the SMP pin family. No new defect;
  the shape is the documented one.
- **quic.rs + quic_flow.rs** (both halves of the v22 attribution
  lane): the pure core's bounds discipline (every buffer access
  .get()-gated, the +1 length shape, the two-read split's
  verifier-friendly offsets) and the wiring's hint-map CAS family
  (BPF_NOEXIST cold-seed, two-attempt learn, confirmation gate)
  re-read end to end. Every refusal degrades to the cookie lane —
  the refine-never-invent contract holds on every branch.
- **during family** (window gate chain): the userspace stamp (two
  points: attach-reuse lane + apply-family lane), the saturating
  wall-minus-mono bridge, the kernel-side DAILY/SPAN split, the
  sweep-through-unstrict removal — re-read. The enforce-not-allow
  direction on the unreadable Array belt is the documented safe
  side.
- **reclaim.rs**: the bucket/ring/stats/window removal family and
  the dead-group reclaim — re-read. The Z4 ring reclamation and the
  window-rides-row-death gate both hold.

## 4. The eagle-eyes monitor — the find's home, otherwise SOUND

- **monitor.rs frame loop** (the per-frame sequence): the TTL-gated
  census, the cookie join, the baseline lane refresh, the render
  call — the sequence is the boost-26 shape. The find above is the
  join's dedup; everything else re-read SOUND.
- **session.rs**: absorb/ranked/retire_dead/note_frame — the cap
  gate on retirement (7.6%-of-throughput decline honored), the
  tie-break by cgroup id, the saturating fold — all SOUND. `ranked()`
  sorts the full accumulated board per frame (4096-cap class worst
  case) — at the 1s-plus poll cadence this is noise-class; top-N
  selection would buy nothing measurable against the sort's own
  determinism contract (ties by id).
- **render tree**: zero `.clone()` in the frame path (re-verified by
  sweep); the emit discipline and the diff engine unchanged this
  round (lts-3/improve-2's own territory, untouched by the find).

## 5. The UX surface — the frozen CLI, re-swept

- **suggestion.rs**: the edit-distance and case-insensitive Jaro
  matchers re-read against their clap-parity rationales
  (lowercase-first scoring, the >= tie-break mirroring
  clap's pop-last) — SOUND, pins intact.
- The retired-surface exit contract (removed verbs exit with usage
  errors on purpose) is enforced in the dispatcher, unchanged.
- No flag, command, or output-format change rode this audit's fix
  (the join is invisible to the rendered frame — the A/B proves it
  at 1,919.0 bytes/frame both sides).

## 6. Optimization — the find closed, the rest re-anchored

| Surface | Verdict | The evidence |
|---------|---------|--------------|
| socket_cookies dedup | CLOSED (was the quadratic) | O(n) HashSet seen-set, first-seen order preserved; 2 new pins (order + 4096-socket dense fixture) |
| The render frame path | PEAK (skip) | the A/B after the close: bytes/frame 1,919.0 byte-exact, emit 511.3/510.7 noise, gini/entropy/dirty ±0.0001 noise, fps 7244.1 -> 7317.4 (+1.0%, shared-host noise class) |
| The loader join point-lookups | PEAK (skip) | 2 syscalls per cookie against a 4096-entry map's 2-per-entry iteration — point lookups win for every N under the cap; the design note in monitor.rs already carries the trade |
| ranked()'s full sort | PEAK (skip) | 4096-cap class at 1s+ cadence is noise; determinism (ties by cgroup id) is the contract a heap selection would have to re-prove |

## 7. Security hardening — the honesty contract is the surface

The QUIC parser re-read (section 3) is the kernel's
attacker-controlled-input surface: version gating, CID-length caps
at the RFC 9000 bound of 20, span-fit checks before every read, the
confirmation gate on learned lengths — a hostile packet can only
reach the cookie lane, never a key the policy did not grant. The
userspace /proc boundary family (pidfd tri-state, the honest-miss
ladder on the cookie join) re-verified unchanged.

## 8. LTS stability — the pins and the docs

- The join's observable contract is now frozen by
  `socket_cookies_preserve_first_seen_order` and
  `socket_cookies_dense_fixture_stays_exact` (the 4096-socket shape
  at exact-set and no-duplicate assertions) — behavior pinned, not
  argued.
- CHANGELOG carries the Fixed entry.
- This audit doc is the find's record; the module doc at the fix
  site carries the dense-host reasoning so the next audit reads the
  decline-and-close lineage in one place.

## 9. The verdict table

| Area | Verdict | Note |
|------|---------|------|
| Limiter kernel datapath | PEAK, skipped beyond fresh reads | enforce/math/quic/during all re-read SOUND |
| Limiter userspace (attach/pin/reclaim) | PEAK | hunt-19/28/30, Z4 all hold |
| Monitor ingestion & join | ONE find, closed | the quadratic dedup, this audit |
| Render tree / diff engine | PEAK | byte-exact A/B after the close |
| UX/CLI surface | PEAK | frozen surface untouched |
| Crash-pattern sweep | CLEAN | all hits in test blocks or invariants |

## 10. This audit's own honest residuals

- The live join's dense-host cost (thousands of point-lookup
  syscalls per frame) is bounded by design but not measured on a
  live dense host in this audit — the rootless harness cannot
  attach an observer here (cgroup v1 host); the CI supermassive
  legs own the live shapes.
- The `retire_dead` walk's 4096-row linear pass at the cap is the
  documented accepted cost (mitigate-1's own A/B); re-measuring it
  would repeat that audit's work for no new information.
- The frame harness's `cookie: None` fixture shape (the exact blind
  spot this audit's find lived in) is now documented here; a future
  fixture variant that resolves synthetic cookies would close the
  blind spot for the next audit — noted, not engineered this round
  (the join's pins already freeze the contract the fixture would
  drive).

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
