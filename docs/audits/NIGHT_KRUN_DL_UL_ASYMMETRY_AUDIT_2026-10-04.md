<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# NIGHT-curio-1: the 605ns vs 233ns per-run asymmetry - enforcement lane vs memoized bypass (2026-10-04)

The owner's live full-mode run of the claims proof, after the
kernel-cost heal (5d81e46) finally made the row measurable, printed
this on nightpc:

```
footprint: kernel enforcement cost — avg per attached-prog run 605ns
(bound 20,000ns) — enforce_dl 605ns/run x1,194; enforce_ul 233ns/run
x1,203
```

The curiosity under audit: the DOWNLOAD program costs 2.6x more per
run than the UPLOAD program, on the same machine, in the same 5.0s
window, with run counts nearly identical (1,194 vs 1,203). Is the
ingress hook more expensive than egress? Is there a defect in one of
the two programs? Neither. The two programs are line-identical
twins; the number measures two different LANES through that same
code, and the proof window's own design guarantees they differ.
This audit is the full derivation, written for future reading: it
reconciles every number in the row against the source and closes
with the falsifiable corollaries that would confirm the reading.

## Fact 1: the programs are twins

`enforce_dl` and `enforce_ul` (ebpf/src/bin/limiter.rs) are two
four-line wrappers around the same `#[inline(always)] fn
try_enforce`, differing only in which mirror-image map set they pass
(cgroup_policy_dl vs cgroup_policy_ul, and the same dl/ul split for
buckets, DRR state, rings, socket buckets). Same helpers, same
branch structure, same lane dispatch. There is no structural
asymmetry to find: if both programs faced the same policy-map state
they would cost the same per run, because they are the same code.

## Fact 2: the hooks are machine-wide, and that is why the run counts match

Both programs attach at the cgroup v2 ROOT - `/sys/fs/cgroup`
(src/ebpf/limiter/mod.rs, `attach()`: enforce_dl gets a
BPF_CGROUP_INET_INGRESS link at the root, enforce_ul the
BPF_CGROUP_INET_EGRESS link, both pinned). Every packet the machine
moves runs BOTH programs once: it egresses through one hook and
ingresses through the other. The kernel accumulates run_time_ns and
run_cnt per PROGRAM (the aggregate across all its attach points),
so each row in the harness output is one program's whole-machine
total.

That is why the run counts are near-equal: both programs counted the
SAME packet set, seen from its two sides. The server's data skbs
egress (enforce_ul run) then ingress into the client (enforce_dl
run); the client's ACKs egress (enforce_ul) then ingress into the
server (enforce_dl). 1,194 vs 1,203 - and the +9 skew is
systematic, not noise: for server-to-client data the EGRESS run
happens before the peer's INGRESS run, so at the bpftool snapshot
instant the in-flight tail (plus the teardown exchange that follows
the window deadline) has already been counted by enforce_ul but not
yet by enforce_dl. The direction of the skew follows the direction
of the packets; the magnitude is 0.7%.

## Fact 3: the window is single-direction by design

`stage_footprint` (scripts/bench/proof-claims.py) applies ONE policy
row - `strict-single <A> -d 5mb` writes cgroup_policy_dl[A] and
leaves the ul map with no row for A. The harness moved ITSELF into
cgroup A (PairCgroups.setup writes the harness pid into
CGROUP_A/cgroup.procs), so the TrafficServer threads and the
downloading client thread both live in A: every packet of the window
resolves to leaf A on both sides of the flow. The window then runs
`tracked_download(5.0)` - one TCP flow, server thread to client
thread, over loopback, at PURE_RATE = 5,000,000 bps.

The consequence, packet by packet:

- EVERY enforce_dl run hits `policy_map.get_ptr(&leaf)` = HIT (the
  dl map carries A's 5 Mbps row). Full enforcement lane.
- EVERY enforce_ul run hits the same lookup = MISS (the ul map has
  no row for A). Bypass lane.

The two programs saw the same packets; one of them had a law to
enforce and the other did not.

## What each run actually executes

The bypass lane (every ul run, 233ns average): policy-map lookup
miss, then `amssp_resolve_root` (ebpf/src/amssp_resolve.rs) reads
the generation array and hits the direction-scoped LRU memo - the
negative memo (current generation, root 0) - and returns allow.
Past the cgroup-id helper that is TWO hash lookups and ONE array
read. This is the NIGHT-lts-2 unlimited fast path with AMMSP's
one-lookup-plus-memo extension doing exactly what it was designed
to do: the cost of deciding there is nothing to enforce.

The enforcement lane (every dl run, 605ns average): watchdog array
read, bpf_ktime_get_ns, stats-map lookup, the burst clamp,
pool-bucket lookup with the refill CAS, leaf-bucket LRU lookup with
the generation belt, `try_consume`, and - the dominant case under
saturation - the drop path: failed consume, then `try_draw`
(share-map lookup, ledger-map lookup, pool CAS, stamp CAS), failed
draw, then the atomic drop booking; an allowed run additionally
books the rate ring. Six to ten map operations, two helper calls,
three to six atomic read-modify-writes. The 372ns delta between the
lanes is the price of actually enforcing, in map lookups and
atomics, on hardware where a hash lookup costs tens of nanoseconds.

## Why 605 is the HEAVY average: the drop path dominates

The policy arithmetic fixes the traffic shape. At 5 Mbps the steady
admit budget is 625,000 B/s - 3.125 MB over the window - and one
draw moves one quantum: max(rate x 100ms, 64 KiB) = 65,536 B at this
rate (the GSO admit floor, ebpf/src/drr.rs). That is 9.5 draw-admits
per second, roughly one admitted 64 KiB GSO skb per 100ms. Loopback
TCP attempts far more than 625 KB/s, so most hook arrivals fail the
consume and walk the whole draw-then-drop branch - the longest path
through drr_flow. Reconciling the arithmetic: the refill budget
plus the initial pool credit (default_burst = 5,000,000 B for this
rate: rate_bps clamped between the 64 KiB floor and the 100 MB
ceiling, src/ebpf/limiter/format.rs) bounds admitted bytes at 3.1
to 8.1 MB, which across ~1,194 GSO-sized arrivals is a single-digit
to ~10 percent admit fraction. The rest are booked drops.

So the dl average is not a happy-path number: it is dominated by the
drop branch, which is precisely the branch a policer exists to run.
Under saturation, the heavy branch IS the typical workday. (Honest
caveat, stated: the skb-size distribution is not recoverable from
run_cnt alone, so the admit fraction is inferred from the rate
arithmetic, not counted directly.)

One belt fires exactly once in the window and is worth reading:
the claim-4 stage ran the same cgroup's maps at 100 MB/s before this
stage re-applied a 5 Mbps policy, and every policy mutation bumps
ammsp_generation - so the footprint window's FIRST dl packet finds
a generation-mismatched leaf bucket and zeroes its stale quantum
(the v13/v17 belt in ebpf/src/drr_flow.rs, designed for exactly this
apply-over-live-traffic sequence). Every later run sees matching
generations and pays nothing for the belt.

## The verdict

The 2.6x is the ratio between the cost of enforcing a law and the
cost of proving there is none - measured on the same packets, at
the same moment, on the same machine. It is not ingress-vs-egress
(the hooks are symmetric machine-wide root attachments), not a
defect (the programs are twins), and not drift (the row's bound,
20,000ns, sits 33x above the worst lane). Two falsifiable
corollaries follow, and either owner rig can run them:

1. A dual-direction window (`strict-single A -d 5mb -u 5mb`, then
   the proof) should move BOTH rows into the same ~600ns band - two
   enforcement lanes through twin code.
2. An unlimited machine (no policy anywhere) should show BOTH rows
   in the ~230ns band - two bypass lanes through twin code.

If either corollary fails, THIS audit is wrong and something else is
asymmetric; that is what falsifiable means.

## Is 605ns "peak"? The capacity framing

- The window itself: 1,194 runs x 605ns = 0.72ms of CPU across 5.0s
  of wall time - 0.014 percent of one core. Enforcement is free at
  the scale it was asked to police.
- Per admitted byte at this window's own shape: 605ns per ~64 KiB
  GSO skb is ~9.3ns per KB - a single-core enforcement ceiling
  around 108 GB/s, an order of magnitude above this machine's own
  loopback baseline (9.9 GB/s in this run's environment line). The
  limiter cannot be this host's bottleneck.
- At the rig's full loopback line rate with GSO-shaped bulk traffic
  (~150-230K skbs/s at 9.9-14.9 GB/s), enforcing on EVERY packet
  costs 9 to 14 percent of one core.
- The honest far corner: small-packet line-rate routing without
  GSO (14.88M pps at 10GbE) would need ~9 cores at 605ns per run.
  That is not zelynic's deployment surface - cgroup policing on
  hosts and containers rides GSO/GRO-shaped bulk traffic - and the
  unlimited majority on such a machine pays the 233ns bypass
  (~3.5 cores at that same corner), which is the fast path's whole
  reason to exist.
- Every run_time_ns figure carries per-invocation overhead -
  program entry and exit plus the accounting itself - so part of
  the 233ns floor is a toll every BPF program pays regardless of
  its body. The lanes are even closer than the raw ratio suggests.

## The Z1 echo: why the cheap lane is ALLOWED to be cheap

The ACK egress packets riding the ul bypass today are the exact
traffic class that once poisoned the v10..v17 SHARED AMMSP memo
(NIGHT-hunt-Z1 - the v18 schema notes in ebpf/src/bin/limiter.rs
and the ammsp_leaf_cache_ul map docs in ebpf/src/amssp_resolve.rs
carry the full find): handshake and ACK egress memoized the leaf
onto the root catch-all, and every download data packet then
enforced at the ANCESTOR's rate - 3.5-4.7x over budget
while the probe reported failure against a policy that never ran.
The v18 direction-scoped memo split is what makes a cached negative
on the upload lane safe to trust indefinitely: each direction
memoizes only what its own walk resolved. The 233ns lane is not
merely cheap - it is cheap because an earlier audit already paid
for its correctness with a live over-admission find.

## Where every number in the row lives

- The row and its bound: `stage_footprint` and
  FOOTPRINT_KRUN_MAX_NS = 20,000 in scripts/bench/proof-claims.py;
  the claim-5 contract in docs/CLAIMS_VERIFICATION.md.
- The measurement mechanics (kernel.bpf_stats_enabled enable and
  restore, per-PROGRAM aggregation): the 5d81e46 heal and its audit
  trail; the ruff-format followup 837895b that unblocked the lane's
  CI parity.
- The enforcement lane: try_enforce in ebpf/src/bin/limiter.rs,
  drr_flow in ebpf/src/drr_flow.rs, the refill/consume/book math in
  ebpf/src/math.rs.
- The bypass lane: ammsp_resolve_root and the direction-scoped memo
  maps in ebpf/src/amssp_resolve.rs.
- The traffic shape constants: PURE_RATE = 5,000,000 and the 5.0s
  window in scripts/bench/proof-claims.py; default_burst in
  src/ebpf/limiter/format.rs; GSO_ADMIT_FLOOR = 65,536 in
  ebpf/src/drr.rs.

No code changed in this audit - it is the reading of a healthy row,
written down so the next curiosity starts from the answer instead
of the question.
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
