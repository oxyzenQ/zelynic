<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->

# NIGHT-CAFE-MCLAREN-2 rev 3 — the independent re-audit and the bot's own hardening

Scope: rev 2 audited the estate as it stood at `aa05a50`. Twelve
commits landed since — rev 2's own recover-order fix and verdict
record, then the ten night-learning-into-darkness-1 commits that
ported the AXP1-ZnQ (Architect's eXecution Protocol 1) repos-for-ci
bot in. Rev 3 re-derives everything independently at the new head
(nothing trusted from rev 2's run), spot-checks rev 2's evidence
file-by-file, and aims the deepest new attention at exactly the code
rev 2 never saw: the ported bot itself. Method unchanged: a fresh
ground-truth battery from the clean toolchain, a test-module-aware
census with file:line evidence, and a two-front deep hunt (one on the
engine's hot paths, one on the bot and its CI wiring).

## Verdict

**The engine holds at Peak — zero live defects in any Rust hot path.
The re-audit's real find is in the new bot, and it is landed: one
live crash-class defect (A1) plus three integrity gaps (B1-B3) fixed
and pinned by a nine-law proof harness.** The works-vs-gimmick
verdict of rev 2 stands for the chassis and powertrain; the newest
part of the car gets its own seat belt, tested against the exact
failure shapes it will meet on a Sunday runner.

## The ground-truth battery at the new head

| Gate | Result |
| --- | --- |
| `bash scripts/build.sh check-all -q` | exit 0 in 13.7 s (warm seat) — fmt, clippy, workspace tests, policy, LOC, version family sync all pass |
| `cargo test --bin zelynic` | 1203 passed, 0 failed, 1 ignored |
| `cargo test --test integration` | 74 passed, 0 failed, 3 ignored |
| `bash scripts/gate-keepers.sh` | 28 passed, 0 failed, 0 skipped |
| fresh kernel build (`cargo build --release` in `ebpf/`) | exit 0 in 14.52 s — both programs compile from source at the head |
| bot harness `axp1znq_edge_proof.py` | **all nine laws hold** (was four before rev 3) |

## Independent re-derivation (nothing inherited)

- Gimmick markers (`todo!`, `unimplemented!`, `FIXME`, `XXX`, `HACK`):
  zero across `src/`, `ebpf/src/`, `proofs/src/`, `build/`, `fuzz/`.
- Kernel panic surface: zero `.unwrap()`, `.expect(`, `panic!`,
  `unreachable!` in `ebpf/src/` production code (the census is
  test-module-aware this pass — a line-level grep alone overcounts,
  `capabilities/tests.rs`'s test-side expect and
  `golden_vectors.rs`'s test assertion are the shapes a naive grep
  misreads).
- Userspace production panic paths: zero `.unwrap()`, three
  `.expect(`, each a named invariant (`probe_role.rs:118` connect
  loop, `drift.rs:333` non-NotFound errno, `pool.rs:121` String
  writes) — rev 2's claims verified line-exact at the new head.
- Tree: 382 tracked Rust files, 107,620 LOC. Zero 600-LOC-cap
  violations (the cap gate ran in the green gate-keepers pass).
- rev 2's other evidence spot-checked at the head: the recover fix
  still pinned (`sorted_orphan_ids` + the rootless ascending-id law
  test), the unlimited fast path comment block intact
  (`enforce.rs:139-145`), the ring honesty contract line intact
  (`rate_ring.rs:45`), the `tips.rs` pure-parser reach unchanged, and
  the four `// SAFETY:`-gap unsafe sites still exactly the four
  recorded ones.

## The engine deep hunt (what rev 2 might have missed)

A dedicated pass over `rate_ring.rs`, `enforce.rs`,
`enforce_helpers.rs`, `hist.rs`, the drr/cake family, the socket and
pace flows, `math.rs`/`math_atomics.rs`, the render path and the
limiter state machine: **zero live-A findings, zero B findings, five
documented-or-minor C postures.** Memory orderings are consistent
(AcqRel RMW pairs, volatile reads where a relaxed read can only
produce the safe verdict); every bucket count is a power of two and
every index is ladder-produced or masked; every traffic-keyed map is
LRU-bounded; the render path allocates nothing per row in steady
state and its memo keys cover the complete pure-function domain; all
divisions sit behind `< 2` guards and the two epoch `as u32`
narrowings are handled or benign within their documented 13.6/13.7
year horizons. The one new note (C-5, recorded, not fixed): the
per-socket arrival-rate join (`monitor.rs:445-448`) uses
`saturating_sub` where the cgroup delta path uses the wrap-coherent
discriminator (`delta.rs:54-67`) — undercount-only for one frame
after an LRU eviction, self-heals, and its phantom direction needs
18.4 EB through one socket per session. An inconsistency of
conservatism, not a bug.

## The bot audit — the re-audit's live finds, all landed

The ported bot had never been depth-audited. The hunt found one
live defect and six hardening gaps; the fixes are proven by the
extended harness, not claimed:

- **A1 (fixed):** `http.client.HTTPException` escaped the probe's
  except clauses — verified live on this CPython (`BadStatusLine` is
  not an `OSError` subclass). A mirror answering a garbage status
  line would have crashed the refresher's thread pool and failed the
  Sunday lane — the exact "never blocks the ship lane" law, broken by
  the flaky-mirror class the catalog exists to absorb. The probe now
  catches the family, narrates `malformed HTTP conversation (...)`,
  and calls the address DOWN.
- **B1 (fixed):** the catalog rewrite was truncate-then-write; a
  mid-write failure could have shipped a partial or empty pool past
  the diff gate — the never-empty guard's own nightmare. The rewrite
  is now atomic (same-directory temp + `os.replace`, the temp never
  survives a failure).
- **B2 (fixed):** duplicate address lines probed separately could
  split their verdicts across a flaky second, and the rewrite maps
  lines to entries by raw text — a DOWN-then-PASS pair could
  tombstone every line while the alive count believed otherwise,
  writing a zero-active catalog past the guard. One address now gets
  one probe and one shared verdict (the duplicate-honesty law); the
  guard's invariant holds by construction.
- **B3 (fixed):** a 2xx with no parsable `Date` header was treated as
  fresh — the freshness witness was only enforced when the header
  happened to parse. Under the refresher's contract (max-age + probe
  path set) an unwitnessed 2xx is now STALE; the resolver's
  freshness-never-blocks-the-pick law is unchanged (no max-age rides
  it).
- **B6 (fixed):** the tcp kind's port parsing accepted out-of-range
  digits that `socket.create_connection` silently wraps modulo 65536
  — a listener on the wrapped port could have produced a false PASS.
  Out-of-range is now a DOWN, and the bracketed-IPv6 limitation is
  documented at the site.
- **B4 (documented):** DNS resolution rides the OS resolver's own
  timeout; the script's socket timeout bounds connect and read only.
  The probe's timeout-honesty paragraph now says so plainly.
- **B5 (documented, accepted):** the commit job's artifact mirror
  carries the same narrow staleness race the lockfile lane has always
  carried (an owner edit landing mid-validate). The catalog joins
  that accepted posture; the workflow comment at the rsync site says
  which lane the catalog rides.
- **C1 (fixed):** the proof harness docstring said "three verdict
  paths" while the code ran four, and never exercised the `--first`
  capture contract. The harness now carries **nine laws** — the
  original four, plus malformed-HTTP-DOWN, `--first` purity,
  index-404-DOWN, the witness law, and duplicate-honesty-atomic-write
  — and its docstring tells the truth.
- **C2 (documented, deliberate):** the Sunday refresher probes the
  pool through `dists/noble/InRelease` while the jammy seats consume
  jammy — a mirror fresh-on-noble but frozen-on-jammy stays in the
  pool. The per-suite precision happens at resolve time by design;
  the divergence is documented in the workflow.

## Classes

- **Class A (live defect):** one — the bot's exception contract
  (A1). Landed with its reproduction test.
- **Class B (hardening):** six — B1, B2, B3, B6 fixed; B4, B5
  documented where the honest fix is the record, not the code.
- **Class C (owner-decision queue, carried):** 1. the `tips.rs`
  pure-parser reach (deliberate, rev 2); 2. the four `// SAFETY:`
  comment gaps — still deferred deliberately: a comment-only edit to
  `ebpf/src/` shifts the tree the prebuilt lane pins, so the honest
  cost is a prebuilt regen commit, and the value stays documentation
  (the rev-2 judgment stands); 3. the C-5 join inconsistency above;
  4. the capture battery's windowed-row blind spot (owner-side sudo
  run, carried from night-dragon-fly-1).

## Honest edges of this audit

- The 10 s A/B benchmark was not run: the rev-3 delta touches no
  engine byte (three Python tooling files and records), and the bench
  needs a sudo eBPF seat this sandbox does not have (`/dev/kvm`
  absent). The engine-side verification is the fresh battery plus the
  hot-path hunt, and the claim ledger's own scripts remain the
  performance proof on capable hardware.
- The subagent census's SAFETY-window ratio (75.3 percent userspace
  in-window at ±3 lines) is a different ruler than rev 2's (72.5
  percent) — the annotated set is the same four-site residual either
  way; the ruler difference is stated so nobody reconciles ghosts.
- The maintenance lane's live dispatch (scan_only=false, the full
  ship path including the repos-for-ci refresh) runs as this record
  lands — the wiring has been statically and locally proven, and the
  Sunday-class live run is the final proof the lane's newest step
  works where it will actually fire.

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
