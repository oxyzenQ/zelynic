<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# The night-zen-lts-1 audit — the sharpest skill, re-proven at schema v35

> Audit date: 2026-11-18 (night-zen-lts-1). Scope: the sharpest
> skill — the per-packet kernel enforcement core (`ebpf/src`, 28
> files) and its userspace half (`src/ebpf` loader, pin,
> capabilities, lock) — audited against the LTS five: stability and
> crash, hygiene, optimization, security hardening, and hidden
> failure modes. Audited at 312509b (origin/main, post
> night-depth-cleanup-1), 232 commits and one schema storm
> (v30 → v35) after the zen-lts-1 book-close of 2026-11-10 — the
> audit's real question is whether the storm kept the edge sharp.
> Method: every claim re-derived mechanically at HEAD, nothing
> inherited from a prior record's say-so; the hot-path deltas read
> hunk by hunk; the full local battery re-run live. The honest
> boundary, stated once: this seat has no root, no BPF attach, no
> KVM (uid non-zero), so the live eBPF legs stay CI-owned as always
> — the kernel object itself, however, was BUILT here (release,
> `target-cpu=v3`, byte-parity against the shipped manifest) and the
> push verdict rides the 40-job Dragon Guard suite. One
> instrument-drift note owned plainly in §7: the audit's first
> kernel-clippy attempt invented a stricter invocation than CI's
> (`--all-targets` on a target-specific crate) and errored; CI's
> exact shape is the contract and runs green below.

## 1. The mandate

The sharpest skill is the code that runs per packet on every host
that polices traffic. The v31–v35 window rebuilt parts of it in
flight: the pacing hint moved from a cookie-keyed LRU to sk-storage
(v32), the RTT lane learned the socket's own measured srtt (v31/v33),
the depth histogram arrived as two new LRU families plus a per-CPU
sampler (v34/v35). New kernel code is new attack surface and new
verifier surface; the LTS five were asked of exactly that code, at
the exactly-current tree.

## 2. Stability and crash — the census holds, the new code carries its proofs

The panic family census (unwrap, expect, panic, unreachable, todo,
unimplemented) over `ebpf/src`, comment lines excluded: **zero
hits**. The kernel object still cannot panic by construction.

The userspace half's census strips every `#[cfg(test)]` body first
(brace-matched, script-run) and finds five hits, each classified at
its line: two are whole test modules declared test-only at their
parents (`parse.rs`'s `#[cfg(test)] mod golden_vectors`,
`capabilities/mod.rs`'s `#[cfg(test)] mod tests`), and three are
documented-invariant checked-then-expects — `probe_role.rs:118` (the
connect loop's own exit condition makes `stream` `Some` or the arm
`bail!`s first), `drift.rs:333` (the walk sets `cause` in the same
branch that clears `absent`, so the expect guards an invariant the
construction holds), and `pool.rs:99` (String's fmt writes are
infallible — the same law `format!` itself rides). Zero true
production panic paths.

The division census found 19 division sites across `ebpf/src` and
traced every dynamic denominator to its guard at HEAD: the three
drawee denominators early-return under the `< 2` law
(`epoch_allowance` drr_epoch.rs:82-86 → `u64::MAX`, `flow_leaf_budget`
drr_flow_law.rs:95-103 → the whole refill, `flow_allowance`
:115-121 → `u64::MAX`); the refill math returns before the divide on
`rate_bps == 0 || elapsed == 0` (math_atomics.rs:209-211); the two
sparse-pool takes divide by `learned + 2` (≥ 2); the rest are
constants. Not one unguarded divisor.

The new histogram core (hist.rs, read in full) is bounded and
verifier-proof by construction: the bucket index rides the explicit
comparison ladder whose own doc records why the clamp and the AND
mask were both provably dead to LLVM (the hooks hand a u32 length;
direct comparisons are the one shape nothing optimizes away); a
zero-length packet answers bucket 0, never a clz panic; the row is a
compile-time-pinned 816 bytes (`size_of::<HistRow>() == 816` at
hist.rs:111, the mirror's twin assert and the test pins beside it);
the tail scan is an unrolled 8-slot pass with the ts store LAST so a
reader never sees a half-filled live slot.

## 3. The delta read — v31–v35 hunk by hunk

- The sk-storage migration (pace_flow.rs, v32): the hint row hangs
  off the kernel's own `struct sock` — the sk pointer the fullsock
  guard vetted IS the identity; no hash, no LRU cap, the kernel GCs
  the row at sock destruction. The union read that fetches the sk is
  null-checked before any use (enforce.rs, PTR_TO_SOCK_COMMON_OR_NULL,
  the fullsock ops as the second belt). The `PaceHint` value is a
  16-byte repr(C) pair whose explicit `pad` member exists because
  the 5.15 floor's verifier refuses an indirect stack read over
  compiler padding ("invalid indirect read from stack ... size 16" —
  the jammy floor lane's verdict is quoted in the comment); the
  compile-time assert pins the size. The generation belt replaces
  the removal sweep: rate first, generation LAST (the seq-lock write
  order), and the reader takes the generation FIRST — a row primed
  under a retired generation answers nothing, so the post-removal
  residue the v27 doc carried is structurally gone.
- The measured-srtt ratchet (recwn.rs/recwn_flow.rs, v31/v33): the
  sock_ops context carries the uapi `srtt_us` (microseconds << 3,
  populated from tcp_sk whenever is_fullsock holds, v4.16+ — the 5.13
  floor carries it), and the runtime law is
  `window = rate × max(measured srtt, 200 ms)` with the 200 ms
  constant re-framed as the receiver's window-update CADENCE floor
  (the delayed-ACK band measured 145-160 ms, topping at 200), the
  [2 × MSS, 1 MiB] band bounding both directions. The totality law:
  sub-floor srtt — every short link and every unmeasured socket —
  answers the exact v25 derivation byte for byte; the retune can
  only extend the pipe, never shrink it.
- The depth histogram (v34/v35): the unlimited majority pays ONE
  per-CPU counter tick (per-CPU isolation, no atomics, no hash);
  the sampled packet (1 in 1024) pays the LRU row. The row's birth
  is the BPF_NOEXIST one-birth discipline (a concurrent first sample
  never clobbers; the loser re-looks-up and adds onto the winner's
  row); the init row COPIES from a kernel-pre-zeroed staging entry
  because an 816-byte value can never touch the BPF stack (the
  linker's own verdict quoted in the comment); the aggregates ride
  fetch_add for count/sum and the volatile check-then-store replace
  law for min/max — the BPF ISA has no plain-atomic-load instruction
  (the LLVM bpf target cannot select one; the build's own lesson),
  and replace semantics never need one: a lost min/max candidate is
  far under the sampling resolution, never a wrong count.
- The maps: `depth_hist_dl`/`depth_hist_ul` are pinned LRU 2048
  (bin/limiter.rs), the histogram keyed at the LEAF the ee --depth
  target already names; a full LRU drops the sample — the honest
  miss every bookkeeping lane here takes, never a wrong count.
- `schema_ledger.rs` is history-doc only (zero code — the 600-line
  cap's verbatim move); the operative `SCHEMA_VERSION` stays in
  schema.rs at 35.

## 4. The userspace half — sync, wipe, parity

The schema pin is bidirectional and test-pinned: kernel
`SCHEMA_VERSION` 35 (schema.rs:154) == userspace
`SCHEMA_VERSION_EXPECTED` 35 (src/ebpf/limiter/schema.rs:156), the
walk pin asserts equality at types_tests.rs:300 and carries the full
version history. The version-mismatch reload is intact at mod.rs:
161-191 — any non-35 value gets the vlog, `unpin_all()?`, a full
fresh load, and the re-stamp; a pre-v35 ledger on an upgraded host
is wiped cleanly, no panic path. The upgrade across v31/v32 is a
FORCED reload by design (a pinned v31 row is LRU-map bytes a v32
loader would open as sk_storage — a different map TYPE entirely;
the contract is documented in schema.rs's own ledger).

The kernel object was built in this seat — release, the CI shape,
`RUSTFLAGS="-D warnings -C target-cpu=v3"` (the flag the BPF_ATOMIC
instruction selection needs) — and the prebuilt-parity discipline
ran live around it: the committed lane verified against its
manifest, the refresh re-stamped the tree pin after the comment
edits below, and the gate returned green on the refreshed lane. One
honest measurement this seat adds: a from-scratch rebuild here
produced a limiter object of IDENTICAL SIZE but different bytes
(one blake3 row moved with the tree stamp) — byte-level
reproducibility across build seats is NOT established (line-table
or build-path metadata is the suspected carrier; comments shift
line numbers), so the behavior-preservation proof rests on the
pins — the 1,232-test battery, the shape asserts, and the CI
verifier lanes — not on byte equality.

The render pool (the Z4 userspace addition) is bounded: 128 lines,
4096 capacity each, clear-on-pop so a composer cannot inherit a
previous line's bytes, thread-local RefCell (no mutex poisoning
class), and the allocation floor is pinned by
test/ebpf/render/bench.rs — the Z4 Miri lane already walked it (the
lens catch that spawned the fix is the record).

## 5. Security hardening

The enforcement path's hardening generations all hold at HEAD: the
unlimited fast path first (an unpolicied packet now pays cgroup
identity, the policy lookup, and one per-CPU tick — the histogram
amendment measured and kept under the NIGHT-lts-2 law), the
security-3 trust-boundary clamp before any consumer derives a bound
from the stored burst, the cookie-0 fall-through to the DRR lane
(never an unlimited pass), and the degrade-not-fail-open posture.
The new lookups take no user-controlled key: the histogram keys on
the cgroup id the kernel helper resolves, the sk-storage rows key on
the kernel's own sock pointer, and the RTT lane reads the uapi field
the fullsock ops carry — no remote byte reaches a length, an index,
or a key. The spawn census still counts exactly three `Command::new`
sites, each pinned (`probe.rs` spawns `current_exe()`, the term_reset
rescue pins `RESCUE_SYSTEM_PATH`, the update check invokes curl with
a constant argument array — root-refused before any network I/O).

The unsafe census (production bodies): 188 block openers (74
userspace + 114 kernel) against 200 SAFETY-contract mentions, with
`clippy::undocumented_unsafe_blocks = deny` wired in BOTH manifests
(root Cargo.toml:151-152, ebpf/Cargo.toml:101-102 — the lts-2c/2d
resolution of the dragon-lts-1 owner-call) and enforced green by
this seat's clippy runs. The dragon-lts-1 finding is verified CLOSED
at HEAD, not just claimed.

## 6. Hygiene

Zero TODO/FIXME/HACK/XXX across `src/` and `ebpf/src/`. The 600-line
cap is green repo-wide (the gate ran in the 27/27 battery). The two
new kernel files ride the file-shape discipline: hist.rs carries
zero aya dependencies and is `#[path]`-wired into BOTH the limiter
and the rootless userspace test tree, so the bucket law carries
rootless pins; schema_ledger.rs is the history half's pure move.
The new userspace modules (pool, sentences, hist_section) are
cohesion splits through their module roots. The dup census found no
copy-paste pair in the new code — the ladder is one shared fn with
two callers-shaped names (size/srtt), each the domain's own law.

The audit's one find — found by reading, proven by the file's own
asserts: both histogram comment blocks (ebpf/src/hist.rs and the
mirror src/ebpf/limiter/hist.rs) still spoke the v34 shape's
arithmetic — "the eight exact aggregates (count/sum/min/max per
half)" and "512 + 64 + 256 = 832 bytes" — while the v35 struct
carries SIX aggregate words (the count rides no word; the buckets
are the count) and the compile-time asserts pin 816
(hist.rs:111, the mirror's :72, the test pins at hist_tests.rs:85
and hist_raw_tests.rs:18-19). The mirror's own next line said "one
816-byte map copy" two lines under the 832 — an internal
contradiction within one comment. Fixed comments-only in both
blocks: the six-aggregate description, the count-is-the-buckets
law, and the 512 + 48 + 256 = 816 arithmetic. Zero code change
(the asserts and the compiled bytes were already right; the words
catching up is the fix).

## 7. Optimization — PEAK, skipped with reason

The hot path's cost class is named, measured, and bounded: the
unlimited majority pays one per-CPU tick (per-CPU isolation, no
atomics, no hash); the sampled packet pays a constant-bounded O(1)
(32-bucket ladder, 8-slot scan) paid 1 in 1024; the steady-state
live frame performs zero heap events (the pool + the diff engine's
zero-alloc law, allocation pin in the test tree). The release
profile is already maxed (opt-level 3, fat LTO, one codegen unit) —
actually the ebpf object's own profile — and the root pro profiles
ride the release matrix. No profiling data exists in this seat and
no unverifiable micro-opt will be invented: that is the honesty
rule, and the surface already carries the laws the perf audits
landed. PEAK — skipped.

Instrument-drift note, owned once here: the audit's first kernel
clippy attempt ran `--all-targets --target bpfel-unknown-none` —
stricter than CI's standing lane (`cargo clippy --locked -- -D
warnings`, no target override, no all-targets; the crate's test tree
is not target-compilable and the lane was never shaped for it). The
invented invocation errored; CI's exact shape ran green (zero
warnings), and the object build ran green beside it. The auditor's
error, recorded so the next seat runs the contract shape first.

## 8. LTS hidden failure modes

Every horizon the mandate names has its answer already standing: the
version walk accepts ANY pinned value (non-35 → wipe → fresh load);
the epoch wrap horizons are documented benign (the first post-wrap
asker is capped like every other drawer); the retune's extend-only
law means a measurement accident can only widen a window, never
starve a host; the hint's generation belt means a removed policy's
sockets answer the OS default on the very next callback; the
histogram's worst-case memory is two 2048-row pinned LRUs — a
constant, declared at build time. The live legs (root/KVM lanes)
stay CI-owned; the 40-job Dragon Guard suite is the runner's own
verdict on this tree (the public commit-checks record for 312509b).

## 9. The verdict table

| Dimension | Verdict | Evidence |
|-----------|---------|----------|
| Kernel stability and crash | PEAK | zero panic family; 19/19 divisors guarded or constant; the ladder, the AND-mask history, and the size pins all re-derived |
| Userspace stability | PEAK | 5 census hits classified (2 test modules, 3 documented invariants); wipe path intact; schema 35==35 test-pinned |
| The v31–v35 delta | PEAK | sk-storage null-checks, generation belt, pad-field verifier fix, one-birth discipline, staging zero-row — all read and proven at HEAD |
| Kernel security | PEAK | trust-boundary clamp, TOCTOU belt, no user-controlled key in any new lookup; spawn census still exactly 3 |
| Memory-safety wiring | CLOSED (prior find) | the deny lint wired in both manifests, enforced green here — dragon-lts-1's owner-call resolved |
| Hygiene | PEAK after one comment find | zero debt markers, cap green, pure-core file shapes, no dup pairs; the v34-era 832-byte echo in both histogram comment blocks fixed to the asserts' 816 truth |
| Optimization | PEAK, skipped with reason | one tick on the majority, bounded sampled work, zero-alloc steady state; no profiling data, no speculative opt |
| LTS failure modes | PEAK | wipe path, forced v31/v32 reload, extend-only retune, generation belt, constant declared memory |

Comment-only changes shipped — two histogram comment blocks (the
words catching up to the asserts' own truth) — and the tree-pin
consequence owned, measured, and stated honestly: the prebuilt
manifest's ebpf tree hash counts comments, the parity gate went red
exactly as designed, and refresh-prebuilt re-stamped the lane; the
rebuilt limiter object moved bytes at IDENTICAL size (the line-table
carrier suspected, codegen semantics untouched — the battery and
the shape asserts are the behavior proof, not byte equality). The
sharpest skill held on every dimension the mandate named, through
the biggest schema storm since v17, and the record's value is the
re-derivation itself.

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
