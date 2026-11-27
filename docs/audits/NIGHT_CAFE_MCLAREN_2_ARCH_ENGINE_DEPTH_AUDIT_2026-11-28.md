<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->

# NIGHT-CAFE-MCLAREN-2 — architecture and engine depth audit verdict (the works-vs-gimmick proof)

Scope: the whole estate, audited the way a chassis, powertrain and
design are audited before the car is signed off — not "does it
compile" but "is every load-bearing claim real, is there one honest
verdict per lane, and is there a single bottleneck or a single
hidden stub anywhere in the frame". Method: a full local ground-truth
battery rebuilt from source in a clean toolchain (nothing trusted
from a previous build), three line-precise censuses (architecture,
safety/determinism/gimmick, engine hot paths) with file:line
evidence for every claim, and the CI watch on the base commit.

## Verdict

**Peak — the works are real, and the audit's one live find is already
landed.** In a full-depth pass over 382 tracked Rust files
(107,562 LOC, userspace + kernel + proofs + tests), the audit found
exactly one live defect: `recover`'s orphan census walked a
`HashSet` iteration order into its printed rows and its delete
sweep (rev 1 of this ticket, `de6ffe3`, landed and pinned by a
rootless test). Everything else the audit could attack — the kernel
panic surface, the per-packet cost structure, the determinism laws,
the claims mechanism, the fuzz/Kani/bench harnesses — held. There is
no gimmick to fix and nothing left where engineering effort would
buy more reliability than it costs in churn, so the skip law applies:
no refactor was performed where none was needed.

## The ground-truth battery (works, proven on this machine)

Every line below was run fresh in this session, from a clean
toolchain install (rust 1.98.1, the exact `rust-toolchain.toml` pin):

| Gate | Result |
| --- | --- |
| `cargo fmt --check` | exit 0, clean |
| `cargo clippy --all-targets` | exit 0, zero warnings, zero errors |
| `cargo test --bin zelynic` | 1203 passed, 0 failed, 1 ignored |
| `cargo test --test integration` | 74 passed, 0 failed, 3 ignored |
| `./scripts/dev/bootstrap-ebpf.sh` | exit 0, 149 s — flagship binary built (`pro-native-musl`, 4.26 MB static) |
| binary smoke (`--version`, `--help`) | `v80.5.0-dragon.2`, build stamp `aa05a50`, depth-matrix self-verify `status=verified` with its blake3 anchor |
| kernel crate fresh build (`cargo build --release` in `ebpf/`, pinned `nightly-2026-09-18` + bpf-linker 0.11.1) | exit 0, 15.19 s — both `zelynic-observer` and `zelynic-limiter` are real eBPF ELF relocatables compiled from source, not vendored blobs |
| `bash scripts/build.sh check-all -q` | exit 0 — all quality checks passed, version family zero drift |
| `bash scripts/gate-keepers.sh` | exit 0 — all checks passed |
| CI on the base `aa05a50` | 13 of 13 workflows `success` (CI, Gate-keepers, Miri, Supermassive ×5, netrunner-night-C77, CodeQL, Fuzz, Audit, Proofs) |

The smoke line is the one a gimmick cannot pass: the binary names its
own commit (`Build: local-pro-native-musl (aa05a50)`), and the
signature depth-matrix runs its own masked-words / dual-fingerprint /
blake3-anchor ladder at runtime and reports `verified`.

## The works-vs-gimmick ledger

The gimmick scan covered every Rust tree (`src/`, `ebpf/src/`,
`proofs/src/`, `fuzz/`, `test/`, `build/`) for the full marker set
(`todo!`, `unimplemented!`, `FIXME`, `XXX`, `HACK`, "not
implemented", "placeholder", "fake", "stub"):

- **Zero marker hits in production code.** `todo!`/`unimplemented!`/
  `FIXME`/`XXX`/`HACK`: zero repo-wide. The only "placeholder" token
  is the real styling API call (`src/cli/styles.rs:75,110`), and the
  `raw_stub.rs` the proofs crate names is a documented pipe-sink seam
  the harnesses deliberately include, not a hidden stub.
- **Fuzz is real: 3 of 3 targets** are `#![no_main]`
  `libfuzzer_sys::fuzz_target!` harnesses that include the production
  sources by `#[path]` and assert properties, with seeds committed:
  the proc-net parser's totality/family fidelity, the during-spec
  parser's 1 s floor / 5 y ceiling, and sanitize_display's
  control-char CWE-150 plus bidi masquerade set.
- **Kani is real: 27 `#[kani::proof]` harnesses, 195 `kani::` uses**
  across `kani_cores.rs`, `kani_interleave.rs`, `kani_terminal.rs`,
  plus the proptest regression ledgers — and the `zelynic - Proofs`
  workflow is green on the base commit.
- **The claims mechanism is real, not prose.** The claims booking law
  (`docs/CLAIMS_VERIFICATION.md`) rejects any row that cannot name a
  LIVE mechanism; `scripts/bench/proof-claims.py` (2,458 lines,
  stdlib-only) actually spawns the binary, measures loopback traffic
  through witness cgroups, snapshots `/proc`, `tc`, `nft` and the BPF
  counters, and asserts the headline claims in CI
  (`scripts/bench/proof-claims.sh`). `docs/PERFORMANCE.md` cites its
  measurement scripts and carries measured/stdev tables with a dated
  hardware row — no unpinned assertion was found.

## The chassis: architecture census

- **Shape:** `src/` 161 files / 49,004 LOC (cli 2,774; commands
  8,945; ebpf 27,246 — limiter 7,180, render 9,499, identity 3,424,
  connections 1,023; output 3,225; terminal 2,016; json 614;
  capabilities 992; update 442; info 1,506; term_reset 978; main
  266) · kernel `ebpf/src/` 30 files / 9,781 · `proofs/src/` 13 /
  4,446 · `fuzz/` 3 / 259 · `build/` 10 / 2,839 · `test/` 165 /
  41,233. The test tree is 38 percent of the estate — the mass
  sits where a McLaren puts its crash structure.
- **The 600-LOC cap: zero violations tree-wide** (382 files
  scanned). 17 files ride the 550-599 band, `src/cli/ux.rs` sits
  exactly at 600 — the cap is doing its job as a design pressure,
  not as a rubber stamp.
- **Layering holds with one documented reach.** The intended
  direction `main → cli → commands → ebpf/terminal/output` is clean:
  `src/output/` imports nothing above it, `src/json/` is a std-only
  leaf, and the kernel crate imports **zero** host symbols. The one
  reach is `src/cli/tips.rs:66,84,107,121` calling the limiter's
  pure `parse_rate` / `parse_time_duration` so the repair tips can
  prove a suggested spelling actually parses. That is a leaf
  function reach with no state coupling — re-homing the parsers to a
  neutral layer would churn two modules for zero behavior change,
  so the audit records it as deliberate rather than fixing it
  (class C, below). The single `commands → terminal` import
  (`monitor.rs:188`) rides the same facade the ebpf layer itself
  uses — no bypass exists.
- **Dependencies are thin on purpose.** No async runtime, no HTTP
  client; `aya` is the one heavyweight and it is optional behind the
  `ebpf` feature; `deny.toml` bans the serde family and chrono;
  the proofs crate carries **zero runtime dependencies**. Nothing in
  the bill of materials a supplier audit could flag as bloat.

## The powertrain: engine, safety, math

- **Kernel panic surface: zero.** `ebpf/src/` carries no `unwrap`,
  no `expect`, no `panic!`, no `unreachable!`, no `todo!`. All 13
  `assert!` sites are compile-time `const` layout proofs (they fail
  the build, never the packet path). Direct indexing exists at
  exactly 4 sites, all fixed-size arrays with the index AND-masked
  to the bucket count (`enforce_helpers.rs:487-518`,
  `hist.rs:171-195`) — the verifier-proof pattern, documented at the
  site.
- **Per-packet cost is O(1) by construction.** The ring protocol
  (`ebpf/src/rate_ring.rs`) pays one volatile load plus one
  `fetch_add` in the common case, one CAS + one atomic swap on a
  window boundary, and its only loss mode is documented and bounded:
  CPUs × 1 packet of undercount per one-second boundary, undercount
  only ("the ledger never lies; the ring never invents" — the module
  carries the honesty contract in its header). The modulo that picks
  the slot folds to a mask, so the branch-free index arithmetic
  survives the verifier. The enforcement flow's unlimited fast path
  (`enforce.rs:139-165`) skips the timestamp work entirely — an
  unpolicing packet never pays for a dormancy check it cannot use.
- **Userspace panic paths: three `expect`s in the whole prod tree,
  each a named invariant** (`probe_role.rs:118` connect-loop
  invariant, `drift.rs:333` non-NotFound errno already matched by
  its own arm, `pool.rs:121` String-write infallibility), zero
  `unwrap`, zero `panic!`. The hot render path writes one frame
  into one `String` buffer (`render.rs:357`) with bounded per-frame
  growth and memo caches on the hot lookups — no per-row allocation
  storm, no unbounded structure.
- **unsafe census: 74 prod userspace + 115 kernel occurrences;
  137 of 189 (72.5 percent, kernel-only 73.9 percent) carry a
  `// SAFETY:` annotation inside the 3-line window, 185 of 189
  within ±6 lines.** The residual four (one fork/exec arm in
  `term_reset/outer.rs:440`, three kernel sites
  `pace_flow.rs:201`, `recwn_flow.rs:295,427`) are documentation
  gaps, not correctness gaps — recorded as class C hardening, not
  fixed (a comment-only commit would fail the value-per-churn bar
  this audit is asked to apply).
- **Math proofs are load-bearing.** The pure cores
  (`math.rs`, `mmspa.rs`, `drr.rs`, `rate_ring.rs`) compile
  standalone in both trees and are pinned by rootless tests in both
  (`test/ebpf/limiter/…`), the layout laws are `const`-asserted
  (`RateRing == 128` bytes), and the interleave/terminal models ride
  27 Kani harnesses plus proptest regressions in CI.

## The determinism audit — and the one live find

Every render/display surface pins a total order: 13 sort sites in
`src/ebpf/` under the `display_order.rs` law (name-then-id; the
session, baseline, depth-traffic, rank and drift ladders each name
their key), every HashMap that feeds output is collected and sorted
before it prints, and the JSON lane emits u64 integers only —
zero float formatting exists in `src/json/` ("no float rounding
ever"). The battery's G01/G02 byte-identical laws hold on the smoke
binary.

**The one gap — class B, live on `main` until rev 1:** the orphan
census in `src/commands/recover.rs` built its `Vec<u32>` straight
from a `HashSet<u32>` iteration and walked it twice, for the printed
`- cg:{id}` rows and for the delete sweep, with no sort. `std`'s
`RandomState` reseeds per process, so two identical machines could
print the census rows — and replay the destructive deletes — in
different orders. Content was always honest; order was luck. Rev 1
of this ticket lands the fix: a pure `sorted_orphan_ids` helper
(ascending cgroup id, `sort_unstable` on `u32`), the rootless test
pin `orphan_ids_ride_the_ascending_id_law`, and the contract
sentence in `docs/USAGE.md`'s NIGHT-hunt-30 paragraph. Verified:
fmt/clippy clean, 1203 + 74 tests green.

## Classes

- **Class A (stale, environment-only, closed):** three files from
  the rev-5 write set carried sandbox-local `664` modes in this
  workspace (`docs/USAGE.md`, `src/ebpf/display_json_window.rs`,
  `test/ebpf/display_window_tests.rs`). git never tracked them —
  git stores only the executable bit, the committed tree was already
  `644` — so the gate-keepers permission finding was restored
  locally and nothing was committed. Zero repository bytes changed.
- **Class B (live defect, fixed):** the `recover` orphan-order
  drift above, landed in rev 1 (`de6ffe3`).
- **Class C (owner-decision queue, deliberately untouched):**
  1. the `tips.rs` cli→ebpf pure-parser reach — judged deliberate,
     recorded here; re-homing the two parsers is churn without a
     behavior win;
  2. four `unsafe` sites lacking an in-window `// SAFETY:` comment
     (`term_reset/outer.rs:440`, `pace_flow.rs:201`,
     `recwn_flow.rs:295`, `recwn_flow.rs:427`) — documentation
     hardening only;
  3. seventeen files in the 550-599 LOC band — inside the cap, no
     action;
  4. carried forward from night-dragon-fly-1: the capture battery
     has never yet caught a windowed row at `status` time — the
     blind spot closes only with an owner-side
     `sudo RUN_ROOT=1 ./scripts/labs-exp/capture-cli-ux-e2e.sh` run.

## The watch

The base commit `aa05a50` sat 13/13 green before this audit began
(the carry-over discipline held). The audit's own commits — rev 1
`de6ffe3` and this verdict record — are pushed together and the CI
watch runs on the pushed head until every workflow reads `success`,
per the standing rule: watching CI until all green is the
discipline, not a courtesy.

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
