<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The MMSPA implementation audit (NIGHT-private-research-2 & think-like-light-years-2, 2026-09-30)

The design brief lives at
[research/NIGHT_PRIVATE_RESEARCH_2_MMSPA_DESIGN.md](../research/NIGHT_PRIVATE_RESEARCH_2_MMSPA_DESIGN.md)
— the owner's directive, the verified root cause, the four
candidate designs, the risk register. This audit records what was
actually BUILT, the decisions made in the building, and the honest
residuals. Method: every claim below was re-verified against the
tree as committed, not as planned.

## 1. What shipped

- **The datapath** (`ebpf/src/bin/limiter.rs`,
  `ebpf/src/mmspa_resolve.rs`, `ebpf/src/mmspa.rs`): the leaf's own
  policy lookup stays first and unchanged (every pre-MMSPA scenario
  is bit-identical — one lookup, enforce at the leaf); on miss, the
  LRU memo answers (cached 0 = unlimited at one lookup, the whole
  fast-path cost of MMSPA); on no memo or a stale one, the ancestor
  walk (absolute levels ascending, zero-break, last-match-wins =
  nearest root, bounded at 32) resolves against the live policy map
  and re-memoizes. Enforcement keys bucket AND stats at the ROOT
  id: one shared subtree budget, one status row that aggregates it.
- **The userspace half** (`src/ebpf/limiter/mmspa.rs`): the whole
  memo flush, once per mutation, inside the flock the mutation
  already holds — `apply_single`, `apply_group`, and `unstrict`
  run it on both their success and error paths (a rolled-back apply
  still mutated). Never fails the caller's verdict; never silent
  on its own failure (the unstrict partial-failure precedent).
- **Schema v10** (`src/ebpf/limiter/schema.rs`, split from
  types.rs at this bump — the version-history block is the one
  piece of types.rs that grows by design, and the cap was full):
  new pinned `mmspa_leaf_cache` map (LRU, 4096 entries), existing
  struct layouts, the same one-time reload-and-re-apply contract as
  v4..v9.
- **The lane twin** (`reclaim.rs::with_lru_u32_map`): the
  architecture pin (one acquisition path for every u32-keyed
  limiter map mutation) fired on the first draft of the flush —
  it had opened the map directly. The fix honors the pin's intent
  instead of weakening it: the LRU twin lives in the same lane
  file, and only the flush rides it.
- **The live stage** (`scripts/supermassive/supermassive-test.py::
  test_mmspa_subtree`): the owner's scenario, made permanent —
  child born after the apply (policed), poisoned pre-apply memo
  (invalidated by the flush), parent+child pair under one budget
  (the SUM is one 100kb, not two), grandchild under nested roots
  (nearest root's budget), aggregate-at-root stats row, kernel-drop
  proof. Every verdict a measured band, every band the harness's
  own.
- **The rootless pins** (`test/ebpf/limiter/mmspa_tests.rs`,
  `test/ebpf/limiter/mmspa_flush_lines_tests.rs`): the pure core
  compiles from `ebpf/src/mmspa.rs` — the same file the BPF object
  builds (the math.rs discipline) — and the walk state machine,
  the exhaustive cache verdict table, the memo value contract, the
  depth bound and its cost curve are pinned without root.
- **The prebuilt lane**: refreshed
  (`scripts/release/refresh-prebuilt.sh`) — the parity gate's
  ebpf-tree pin moved to the subtree-aware object; the
  ebpf-prebuilt/ artifacts are committed with the sources they
  carry, the atomic-revert-unit contract.

## 2. Decisions made in the building

- **The stale-GPL comment was wrong, and is now corrected in
  place**: limiter.rs's license block claimed
  `bpf_skb_cgroup_id` is a GPL-only helper — verified false
  against torvalds/linux master AND v5.13 (both cgroup id helpers
  are `gpl_only = false`). The GPL license section itself stays:
  C-twin parity, the dual-license contract, and free insurance for
  any future gpl_only helper.
- **Nested roots shipped NOW, not in v11.2**: the directive's
  staging ("flat first") assumed the tracking-map design, where
  nesting is extra bookkeeping. In the walk design, nearest-root
  is the only natural semantics of ascending last-match — deferring
  it would have meant deliberately building a WRONG resolution
  first. The supermassive stage pins the nested verdict.
- **`memo_value` is used at the datapath's insert site; the
  cost-curve helper is cfg(test)-facing**: the ebpf release build
  carries no dead symbol (clippy -D warnings owns that), and the
  userspace test tree compiles the same file with the test profile
  so the pins see the curve.
- **The LOC-cap splits happened as the gates demanded, not
  preemptively**: limiter.rs crossed 500 with the resolution block
  (the aya-touching half moved to `ebpf/src/mmspa_resolve.rs`;
  the decidable half was already pure in `mmspa.rs`), mod.rs was
  trimmed under the cap, and types.rs's schema block grew its own
  file at the bump that filled it. Every split follows the
  policy_lines/parse precedent: re-export surfaces unchanged.

## 3. Verified locally (this container: rootless)

- `cargo check` / `cargo test`: 506 + 46 passed, 0 failed (the
  battery grew by 14 pins — 11 core + 3 wording).
- `cargo clippy --all-targets -- -D warnings`: clean.
- `cargo fmt` + the ebpf crate's nightly rustfmt: clean.
- `build.sh check-all -q`: exit 0 (fmt, 103-test policy lane,
  policy, anti-patterns; cargo-audit/deny CI-owned).
- `gate-keepers.sh`: 22/22 (codespell over the new prose included).
- `refresh-prebuilt.sh`: the parity gate green over the new tree
  pin.
- Frame A/B (the owner's rule, 10s): bytes/frame 1919.0 ->
  1919.0 byte-identical, density gini 0.3564 -> 0.3547, frame
  entropy 2.9992 -> 3.0033, dirty cells 39.6 -> 40.0, fps -4.0%
  (container-load noise; no render-path byte changed — the
  datapath is not exercisable rootlessly here, same constraint as
  every prior session).

## 4. Residuals — stated, not hidden

- **The depth bound (32)**: a socket deeper than 32 levels from
  the cgroup root resolves unlimited. No real deployment reaches
  a third of it. Documented in USAGE.md's honest limitations and
  in the design brief; one line to raise if reality ever asks.
- **The live proofs ride CI root lanes, not this container**: no
  cgroup v2 delegation and no KVM here — the subtree stage, the
  verifier's acceptance of the walk, and the helper's availability
  prove out on the Supermassive matrix (which already exercises
  the limiter's real datapath on every push that touches it).
- **The memo is per-BOOT state**: like every pin, bpffs is wiped
  at reboot; kernfs ids are reassigned with it. No cross-boot
  staleness exists by construction.
- **A first-packet walk cost exists per new leaf** (~depth+2
  helper calls + lookups, once): the LRU memo amortizes it to one
  lookup for the socket's lifetime; the flush re-primes it once
  per policy mutation — the honest cost of correctness, measured
  by CI's overhead stage in aggregate.
- **The eagle-eyes depth PNG** (assets/eagle-eyes-depth.png) shows
  the report family's pre-compact shape and is untouched here, as
  in NIGHT-private-research-3 — a regeneration task of its own
  when the owner next captures screens.

## 5. The verdict

The owner asked for an ability upgrade to the limiter engine's
skill set — adaptive, dynamic, no daemon, no config, no exception.
What shipped is exactly that shape: the kernel itself now resolves
what covers a socket, per packet, against the only authority (the
live policy map), with a memo that keeps the price at one lookup.
The 2026-09-27 audit's "peak for its class" verdict stands — the
class grew a dimension, and the dimension is covered.
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
