<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-total-lts-1 depth audit — the total-infra LTS sweep

> Audit date: 2026-10-02 (NIGHT-total-lts-1). Scope: the owner's
> five infra areas — stability & crash, code hygiene, optimization,
> security hardening, LTS stability — audited across the root repo
> at e977df4 (v20.0.0-beta.1; the code byte-identical to the v20.0.0
> LTS baseline 52ca421 — the two intervening commits touch version
> strings and README contract text only, so every verdict here reads
> against the locked LTS era itself). Method: per-stage (the
> important directories first, the owner's own instruction), the
> peak-skip protocol in force (a sub-task already at its peak is
> skipped with its evidence named, never re-performed for theater),
> and every verdict re-verified against source and fresh runs at
> HEAD — never against an earlier doc's claim. Status: four of five
> areas answer SOUND at peak; one real find in code hygiene (an
> orphaned depth suite, closed docs-only) and one live find caught
> by the audit's own CI watch (the 9a78dfc low-spec supermassive
> red — the live anti-monopoly band sat inside the low-spec medium's
> concentration tail; recalibrated on nine measured draws,
> battery-only, the eBPF object untouched).

## 1. The mandate

"Depth audit focus for all infra total lts, and keep be honest"
decomposes into five measurable asks, each with its own
instrument:

| # | The ask | The instrument this audit used |
|---|---------|-------------------------------|
| 1 | Stability & crash: crashes, coredumps, engine failures, foundation breakage, vulnerabilities; no visual/performance regressions | the panic-path census over all of `src/`, the render totality re-verification, all three test lanes + the engine self-test fresh at HEAD, the full-budget frame-bench, the supermassive CI watch |
| 2 | Code hygiene: the dragon hunt — spaghetti, duplicate, redundant, stale, zombie code, important directories first | the reference-map sweep over `scripts/`, the cfg-wall and allow-marker census over `src/`, the orphan scan over `test/` (84 files), the wrapper-pair and drift-copy checks |
| 3 | Optimization: peak-optimize, profiling data where available, micro-optimize hot paths | the repo's own instruments (frame-bench full budget, PERFORMANCE.md's recorded A/B eras) run fresh at HEAD; the byte-pin constraint honored |
| 4 | Security hardening: input validation, memory safety, injection risks | the trust-boundary inventory (env, exec, file trust, untrusted strings, unsafe blocks, pin namespace, supply chain) |
| 5 | LTS stability: hidden failure modes, months-scale behavior | the pin-namespace finiteness proof, the fence re-verification, the Z4 state budget honored, the wrap and monotonicity audit |

The honest headline: this repo has been through an unbroken
LTS-hardening campaign (lts-5 through lts-9, NIGHT-hunt-Z1 through
Z6, blade-6, long-horizon-1) and it shows — most surfaces answer
at peak with structural guarantees rather than one-time audits.
The two finds below are real, but both live in the seams between
systems (a suite nobody references; a live CI bound borrowing a
sim's constant), not in any load-bearing wall.

## 2. Stability & crash — SOUND, zero live-path panics

**The panic-path census.** Twenty-seven `unwrap`/`expect`/`panic!`
candidates in the entire userspace `src/` (counted with grep,
classified by reading each one):

- 26 sit inside `#[cfg(test)]` modules (parse.rs 13, schema.rs 3,
  lock.rs 2, update/mod.rs 2, capabilities 2, info 4) — test-only.
- 1 is live: `probe_role.rs:115`, `stream.expect("connect loop
  invariant")` — a provable-total invariant (the retry loop above
  it exits only through the `Ok` arm that sets the `Option` or the
  `Err` arm that `bail!`s), not a reachable panic.

Zero live-path panics in a 29 kLOC userspace is a discipline, not
an accident — and the kernel side cannot panic by construction
(BPF programs carry no unwinding semantics; any bounds doubt is a
load-time verifier rejection, and the shipped object is
byte-pinned so even that surface is frozen).

**The render totality ladder, re-verified line by line.** Every
raw subtraction in the render pipeline was inspected against its
guard: `plan_eagle_columns` guards each `width - RANK_W - ...` with
the identical expression in its own `if`; `border.rs` pads only
under `visible < width`; `baseline.rs` counts hidden rows only
under `rows.len() > usable`; `focus.rs` clears the block at
`room == 0` and truncates only under `len > room`; `width.rs` is
total on degenerate budgets with the `w == 0` early return and
tests pinning them. The release profile wraps rather than aborts
on any residual overflow — and the sweep found none reachable.
A 1-column or 0-row terminal degrades through the designed ladder,
it cannot crash the monitor.

**Fresh batteries at HEAD (e977df4).**

| Battery | Result |
|---------|--------|
| engine self-test (`supermassive-test.py --self-test`) | 34 passed / 0 failed / 0 skipped (14.5 s) |
| `build.sh check-all -q` | all quality checks passed (10.6 s, inside the 2-min cap) |
| `cargo test --no-default-features` | 104 + 41 passed / 0 failed / 3 root-ignored |
| `cargo test` (default) | 647 + 46 passed / 0 failed |
| `cargo test --features ebpf` | 647 + 46 passed / 0 failed |

The +3 against the 644 era is exactly Z6's three highload pins —
the count delta is accounted, not mysterious.

**Stress posture, honestly.** The audit host runs kernel 5.10.134
(below the 5.13 floor), uid 1001, no sudo: live eBPF stress is CI
territory by design (the supermassive legs boot the true impish
5.13 floor kernel and the latest archive kernel on every push).
The local instruments are the batteries above, the source-level
census, and the frame-bench — all green. The live stress verdict
for this era: supermassive on 9a78dfc reddened both low-spec legs
on exactly one row — that find is Section 3's close, and its
diagnosis (byte-identical objects, aggregates held, the worst-leaf
draw moved) doubles as the strongest stability evidence this audit
can offer: the enforcement object is frozen, and what varies is
the medium, which the battery is now calibrated to tell apart.

**Visual/performance regressions: none, by construction and by
measurement.** The two commits since the benched v20.0.0 era touch
version strings and README text only. The fresh full-budget
frame-bench (Section 5's table) shows bytes/frame byte-exact at
1919.0 and every other metric inside the documented run-to-run
class.

**Peak-skips honored:** Z1's critical single-direction bypass fix
and the dead-transient belt (−12%), blade-6's ultra-endurance
audit, the boot-edge epoch floor pin, boost-28/33's terminal
crash-safety, and the v2 survival battery's crash-family teardown —
all previously delivered, all still pinned, none re-performed.

## 3. The live find — the 9a78dfc low-spec red lane

Caught by this audit's own CI watch: supermassive failed on
9a78dfc, both low-spec legs, exactly one row — `mmspa fair-share:
many24 no leaf monopolizes the refill` (low-gnu worst 1,671,246 B
vs bound 1,621,086; low-musl 1,638,478 vs 1,592,414 — 3% over
each). Both best-spec legs green; the engine self-test, the v2
survival battery, the claims proof, and the MMSPA-vs-legacy delta
green on every leg.

The diagnosis, from the runs' own ledgers:

1. **The objects never moved.** The prebuilt-parity rows PASSED on
   that very push — the enforcement object is byte-identical to
   the green run 128 era. A version-string commit reddened a law
   row; the law did not change.
2. **The pool law held.** The failing legs' aggregates sat at
   102-105% of policy; the round ledgers show the same
   admitted/dropped shape as the green era. The DISTRIBUTION's
   worst draw moved, not the pool.
3. **The bound sat inside the medium's tail.** Nine worst/fair
   draws collected across every observed era — Z5's legs ~1.80,
   run 128 (1.77, 1.91, 2.03, 2.13), the red run (1.73, 1.99,
   2.39, 2.40): the best-spec legs draw 1.73-1.99, the low-spec
   legs 2.03-2.40. The 1.75x+quantum shape's effective ratio is
   only 2.32-2.39 once the 400 KB quantum rides a ~630-700 KB
   fair. Half the low-spec draws cross it. The row was a lottery
   on the slow legs — the exact class Z5 closed for the single and
   quietest rows, sitting one row over.

The physics is the frozen basin again: a leaf delivers its banked
admits while its neighbors sit in RTO silence — sender-side
concentration the token model does not own (the sims rightly pin
the law tighter: 1.29x worst/fair sustained over 12 s at 24
leaves, `drr_highload_tests`, every push).

The close walks the Z5 doctrine one row further, without weakening
anything that is actually certifiable:

- The LAW's band — 1.75x fair + quantum — stays exactly where it
  is provable: the rootless ledger sims, green in every push's
  test lanes.
- The LIVE concentration tripwire now rides a band that separates
  the measured healthy tail from real monopoly: **3x fair +
  quantum** — 49-52% above the observed tail (no healthy draw has
  come within 20% of it), and still tripping by the first quintile
  of the full-monopoly signal (a broken law funnels the pool
  toward one leaf: the 24x of an equal 24-leaf draw).
- The quietest stays advisory, the aggregate stays hard, the
  ceiling rows untouched. Battery-only; the eBPF object is
  byte-identical (the prebuilt pin proves it); no benchmark A/B is
  due (no product surface).

The nine-draw evidence table and the per-leg numbers are filed in
CROSS_DISTRO_RESULTS; the CHANGELOG carries the entry.

## 4. Code hygiene — one find (the orphaned suite), closed

**The find: `scripts/depth/install-flow-test.sh`.** Referenced by
nothing — no workflow, no gate, no doc, no harness, no sandbox
script — while carrying a contract nothing else covers: the
blade-8 six-row package lifecycle (`--user` install with the
binary answering `-V`, the root-without-sudo `--system` install,
enforcement-before-uninstall, the no-escalation `--user` uninstall
warn, the enforcement-first `--all` teardown, the idempotent
re-run). The dragon was the orphaned reference, not the file:
deleting a unique rootful suite is coverage loss, not hygiene. The
close is one row — the suite now rides CLAIMS_VERIFICATION's
inventory (the "Package lifecycle" claim against README's
improve-15 note), where every sibling depth suite already lives.

**The sweep that found nothing else (the peak-skip evidence):**

- **scripts/, the reference map.** The supermassive family is all
  live: v1 is the CI matrix plus both self-test gates (ci.yml,
  setup.sh, supermassive-init.sh); v2 rides its own lanes;
  mmspa-vs-legacy is the conditional legacy A/B (init.sh, guarded
  on the legacy binary's presence). The `.sh`/`.py` pairs are thin
  exec wrappers by design (sudo entry, python engine), not
  duplicates. The bench family (benchmarking, proof-claims,
  frame-bench) is referenced from workflows, PERFORMANCE, USAGE,
  and CROSS_DISTRO.
- **No fourth drift copy.** The harness_lib dedup removed three
  drifting copies of the logging block; install-flow-test.sh (the
  one depth script the dedup did not touch) carries none of that
  block — no zombie copy hides in the corner case.
- **src/, the cfg walls.** Compile-visible dead code is
  structurally fenced: the quality gate builds with `-D warnings`
  at three feature levels on every push (the dinner-30 fresh-
  checkout gap, closed by rider 2). Two `#[allow(dead_code)]`
  markers survive in `src/`, both deliberate and documented:
  `RingReads::absent()` (test-facing constructor, the BucketRaw
  precedent) and `BucketRaw` itself (schema-layout pin plus the
  reclaim path's key type).
- **test/, the orphan scan.** All 84 test files are wired: 79
  directly (`#[path]`/`mod` declarations from `src/`), the four
  DRR siblings through `drr_tests.rs`'s own `#[path]` block, and
  `test/integration/main.rs` is the harness root. Zero orphans,
  zero dangling wirings.
- **Docs.** codespell and the language gate run in CI; the CLI
  surface is pinned by `surface_pins.rs`/`help_pins.rs` (the 647
  battery), so doc-vs-code drift on the surface is structurally
  caught.

## 5. Optimization — PEAK, skipped with the evidence

The fresh full-budget frame-bench at HEAD, against the recorded
eras:

| Metric | HEAD (this audit) | Recorded eras | Reading |
|--------|-------------------|---------------|---------|
| fps (render path) | 7,282.5 | 7,361.5-8,155.7 | in class (host-load noise) |
| bytes/frame | 1,919.0 | 1,919.0 | byte-exact — the render path unchanged |
| emit bytes/frame | 511.0 | 504.8-510.2 | in class (cross-host phase mix) |
| dirty cells/frame | 40.0 | 39.4-40.0 | matching |
| density gini | 0.3504 | 0.3547-0.3587 | in class |
| frame entropy | 3.0296 | 2.9992-3.0033 | in class (phase mix) |

Why no micro-optimization is warranted, honestly: the render hot
path has been through the optimization eras (hunt-7's A/B
protocol, improve-2's diff engine, lts-2/perf-3's unlimited fast
path, Z1's −12% transient belt) and every remaining candidate
shape is either already fast-pathed (the ASCII width fast returns,
the pad single-scan, the fit early-out) or fenced by the
byte-parity discipline that makes regressions visible to the
decimal. In maintenance mode an unfounded rewrite buys noise, not
speed. The eBPF side is byte-pinned by the LTS lock; Z6 audited
the law's arithmetic SOUND; the per-packet cost is bounded by
design and measured live (the claims proof's `run_time_ns` rows on
every supermassive push). Any `ebpf/src` change forces an object
refresh and lane regeneration — no performance reason exists, so
none is made. The benchmark A/B is skipped on purpose for this
audit's own commits: battery and docs only, the product surface
byte-identical.

## 6. Security hardening — SOUND, the boundary inventory

| Boundary | Mechanism | Status |
|----------|-----------|--------|
| Untrusted `/proc` comm (any process can set 15 near-arbitrary bytes) | `sanitize_comm`, the one canonical boundary (cybersecurity-1); every consumer routes through it | closed + pinned |
| Untrusted network string (the release tag; MITM'd-proxy threat model documented, even over TLS) | the same `sanitize_comm` (cybersecurity-2); the OSC-52 clipboard-write forgery test | closed + pinned |
| Env reads | color/term capability detection (NO_COLOR, CLICOLOR, COLORTERM, TERM); the two XDG uses are documented tradeoffs — the cooldown stamp is root-refused before it matters (self-inflicted at worst), the docker socket candidate is deliberate rootless-docker support, last in probe order behind the system sockets | reviewed, accepted |
| Exec from the binary | three sites: curl (hardcoded args, https, 15 s bound), `current_exe()` re-exec (probe roles, internal args), rescue utils (hardcoded names; `RESCUE_SYSTEM_PATH` pinned when root — the improve-31 boundary) | audited, closed |
| File trust | kernel-owned paths only (`/proc`, `/sys/fs/bpf`, `/dev/tty`); no user-writable config file exists by design (the CLI is the config; state lives in pinned maps) | verified |
| Memory safety | `unsafe` is FFI-disciplined libc wrappers (termios, poll, flock, ioctl, pidfd, fork-guard); no pointer arithmetic over attacker data; map-value `Pod` types are `repr(C)` with size assertions pinning the kernel schema | audited |
| PID races | `pidfd_open` + `pidfd_getfd` fd borrowing — clone-safe against PID reuse by construction | verified |
| Pin namespace | 19 hardcoded constants under `/sys/fs/bpf/zelynic`, zero dynamic path construction, root-only bpffs (no symlink support) | finite, verified |
| Supply chain | actions SHA-pinned (hunt-20), CI tools version-pinned, `cargo deny` every push, CodeQL every push, the 7-direct/54-lockfile diet re-countable on demand | green |
| The root catch-all blast radius | Z3's position checks at four doors (id, resolved name, sweeps, force) | closed (prior era, honored) |
| Script injection | shellcheck 0.10.0 + shfmt + ruff gates green; the python engines take explicit argparse args, no shell interpolation of user input | green |

CodeQL green on every push is the floor this inventory stands on,
not the ceiling: every row above was verified by reading the
source at HEAD.

## 7. LTS stability — PEAK, the hidden-failure-mode sweep

What a months-LTS host actually accumulates, re-verified:

- **Pin namespace: finite.** Nineteen constants, no dynamic
  construction anywhere (grepped across `src/`) — a crashed or
  killed zelynic leaves the same fixed pin set a clean one does,
  and `recover`/`cleanup` walk it by design. No bpffs growth mode
  exists.
- **Map state: budgeted.** Z4's table stands (worst ~0.6 MB at the
  full 1024-root census; the rings now reclaimed with their
  buckets; 4x LRU margins; the 13.7-year epoch wrap). Re-verified
  in shape, not re-performed — the peak-skip protocol.
- **Userspace accumulators: fenced.** The silent-killer inventory
  (memory, fds, arithmetic, kernel resources, time) documents each
  fence; this audit spot-verified the load-bearing ones (u128
  ledgers, the Instant-based uptime, the u12 saturations).
- **Terminal state on crash: owned.** The outer reset, the guard
  process, and the sink-death paths carry their own test trees;
  boost-28/33's shapes hold.
- **Clock weirdness:** the eBPF side rides ktime (monotonic); the
  monitor's uptime rides `Instant` (CLOCK_MONOTONIC); the cooldown
  reads wall time fail-open (`unwrap_or(0)` — a backward NTP step
  can only re-allow a check, never wedge one).
- **The contract:** v20.0.0's stable API lock with the surface
  pins in the 647 battery; schema migration auto-detected and
  auto-cleaned (the SCHEMA_VERSION pin); the dated nightly and aya
  pins isolating the toolchain; DEPENDENCY_AUDIT's diet claim
  re-countable on demand.

The honest residuals are already owned in STABILITY's limits list
(verifier drift, dated-nightly aging, aya evolution, loopback
measurement physics, the bounded monitor endurance, the Z6 release
window) — this audit adds none, and confirms each fence it
touched.

## 8. The verdict table

| Area | Verdict | The one-line evidence |
|------|---------|----------------------|
| 1. Stability & crash | SOUND | zero live-path panics; total render ladder; 3 lanes + self-test green at HEAD; frame-bench parity; the live stress find diagnosed as medium, not law (Section 3) |
| 2. Code hygiene | one find, closed | install-flow-test.sh orphaned from every reference surface — now in the claims ledger; every other surface structurally fenced |
| 3. Optimization | PEAK (skip) | fresh full-budget bench in class on every metric, bytes/frame byte-exact; no candidate survives the A/B discipline; eBPF byte-pinned with no reason to touch it |
| 4. Security hardening | SOUND | the full boundary inventory closed or documented-accepted; CodeQL green; Z3 honored |
| 5. LTS stability | PEAK (skip) | finite pin namespace, budgeted maps, fenced accumulators, owned residuals — the campaign's claims hold under independent re-verification |

## 9. This audit's own honest residuals

- Live eBPF stress cannot run on the audit host (kernel 5.10.134
  below the 5.13 floor; rootless uid): the LIVE verdicts ride the
  supermassive legs on every push. At file time the 9a78dfc
  verdict is the Section 3 red (diagnosed and closed here); the
  recalibrated battery's first verdict rides the push that carries
  this audit.
- The frame-bench deltas against recorded eras (entropy +0.9%,
  emit +0.2-1.2%) are cross-host phase-mix class: the recorded A/B
  eras ran on different hosts at different frame counts. The
  byte-exact bytes/frame is the anchor that makes the comparison
  honest; per-host A/B runs (same host, before/after) remain the
  repo's law for change-proving, and no change to prove was found.
- The nine-draw calibration is every draw the logs retain. If a
  future healthy draw crosses 3x fair + quantum on any leg, the
  row reddens honestly — and the ledger evidence says the next
  suspect is the medium, with the sims as the law's standing
  alibi.
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
