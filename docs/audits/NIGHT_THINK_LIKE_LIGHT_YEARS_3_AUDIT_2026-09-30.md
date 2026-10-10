<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-think-like-light-years-3 depth audit — limiter and monitoring at the LTS ceiling

> Audit date: 2026-09-30 (NIGHT-think-like-light-years-3).
> Scope: the two surfaces the owner named — the limiter and the
> monitor — audited for the three questions that decide an LTS
> tool: can it ENDURE extreme conditions (ultra loads, bursts),
> can it ULTRA-SCALE on servers (near the kernel's own limits),
> and does it FLEX down to desktop/mini/low hardware without
> manual intervention. Plus the standing directive: hunt beyond
> what the owner found, land what the hunt lands.
> Status: two fixes landed (one kernel-side through the sanctioned
> prebuilt-refresh cycle, one userspace-side), pinned, gated, and
> the verdicts below re-verified against the source at HEAD.

## 1. The mandate

The owner's ask, verbatim in substance: depth audit the limiter
and monitoring "until peak because aim to usage LTS and sharpest
tool", then answer three load-bearing questions before spending
any further investment. The audit method is the house method:
walk the code path live (kernel side first — the enforcement
boundary is where endurance lives), verify every prior doc claim
against the current tree, and treat every "verified peak" verdict
as a hypothesis to attack, not a fact to repeat.

## 2. What the hunt found — and landed

**Finding F1 (kernel, the headline): the limiter's init-path
inserts rode BPF_ANY — the C-era residue the observer fix never
swept.** `get_stats_ptr` and `get_bucket_ptr`
(ebpf/src/bin/limiter.rs) each ran miss-then-insert-then-relookup
with flag 0 — a wholesale value reset on a hash map under the
bucket spinlock. The reachable window is the birth instant of a
fresh bucket under many-CPU fire (a freshly-policed busy cgroup
with flows spread over cores — the exact ultra-burst shape the
owner's question names): CPU A inserts, re-looks up, starts
enforcing; CPU B, having missed the same lookup microseconds
earlier, inserts over the entry and resets three things A had
already advanced — consumed tokens resurrect to the full burst
(an over-allow of up to one burst), `last_refill_ns` rolls back
behind a window the ownership CAS had already credited (a
double-credit bounded only by the 1s elapsed cap), and `frac_rem`
zeroes; on the stats twin every increment booked before the reset
vanishes. NIGHT-improve-29 closed this exact class in the observer
(BPF_NOEXIST, loser re-looks up and books onto the winner's entry)
and the dinner-6 audit verified the limiter's FIELD-level races
closed (v7/v8/v9) — but the init-path plain wholesale write stood
until this task, because no per-field atomic downstream can defend
against the reset itself. Landed as schema v11 (no layout change,
verdict math untouched) through the full prebuilt-refresh cycle:
limiter object rebuilt (ed1c297a), observer reproduced
byte-identically (5adb44ca — untouched source, untouched bytes),
parity gate green.

**Finding F2 (userspace): the poll's ingress merge was the one
superlinear spot at dense-host scale.** `poll_and_summarize`
(loader.rs) merged ingress deltas with a linear
`iter_mut().find()` over the egress-built vector — O(egress x
ingress) per poll, ~8.4M comparisons at the 4096-entry counter-map
ceiling with both maps full, a per-second tax that grows with the
square of live cgroups on exactly the hosts the "host server
padat" question names. Fixed with a u32-to-position index built
once after the egress pass: O(n), vector order byte-identical
(egress walk order, ingress-only rows appended), every field
written the same field the find wrote. No pins moved.

**Suspects investigated and CLOSED (the negative results the
next auditor should not re-dig):** the prev_stats baselines are
cleared and rebuilt from the current poll only (no unbounded
growth under churn — loader.rs); the u32 cgroup-id key is the
documented deliberate contract (kernfs ids do not wrap inside any
real host's lifetime — ebpf/src/stats.rs); the watchdog array is
dormant by design with no userspace writer; the maps' fixed
capacities (1024/256/4096) are the documented bounded-memory
posture with honest fail-open semantics (USAGE limitation 11,
STABILITY's endurance table); and the MMSPA walk bound
(MMSPA_MAX_DEPTH 32) is three times deeper than real
hierarchies with early break at first 0 (a depth-6 socket pays
seven queries, not 32).

## 3. The verdicts — the owner's three questions

### 3.1 Endurance under extreme conditions — YES, now without asterisks

The enforcement datapath is straight-line code with no loops, no
tail calls, no allocation, bounded instruction count — the
verifier budget is structural, not tuned. Every shared-field
mutation is now an atomic RMW (v7), the burst consume retries
bounded (v8, the 28x probe), the block verdict books atomically
(v9), and with v11 the entry birth itself can no longer be
clobbered — the SMP story has no plain wholesale write left
anywhere in the object. Overflow safety is proven, not assumed
(the fill-detect guard bounds every product by construction;
layout pins hold the repr(C) contracts). Under a hostile or
drifted map state the clamp family degrades to healthy values,
never to a verdict change; under a full bookkeeping map the
packet is allowed and only its accounting is lost — a rate limiter
that bricks the network on a bookkeeping miss would be worse than
one that under-reports. The burst shield is a DROP policer by
product class: an ultra burst is absorbed by the token bucket's
burst cap and the excess dies at the hook, with sub-burst pacing
deliberately out of scope (the shaping question — see 3.4).

### 3.2 Ultra-scale on a server — bounded by DESIGN, honest at the ceiling

"Millions even billions of data" needs unpacking into the two
surfaces. PACKETS: the datapath cost is constant per packet
(policy lookup + the MMSPA memo for the unlimited majority,
watchdog + ktime + bucket + stats for the policed minority) —
10Mpps through the hooks costs the same per-packet budget at 1M
pps, and nothing in the program scales with session history.
CGROUPS: the counting surface is bounded — 4096 LRU slots per
direction for the observer (churn-proof: an idle entry ages out,
a live one always finds room), 1024 policy/bucket/stats slots
and 256 group slots for the limiter, kept proportional to LIVE
state by the reclaim family. This is the deliberate trade: bounded
kernel memory (128 KiB observer payload per session, KBs for the
limiter) against unbounded accounting. A host with more than 1024
SIMULTANEOUSLY policed cgroups is beyond the product's design
point — and it says so loudly (map-full inserts fail open with
the documented contract, applies roll back all-or-nothing) rather
than silently. Near-kernel-limit posture: the u64 counters wrap
at 18.4 EB per cgroup per session (wrap-coherent on the
userspace side since lts-5), the u32 cgroup id is the documented
deliberate key, and the 1-Tbps-backed cgroup reaches the counter
wrap horizon in ~4.7 years of monitor uptime. Verdict: peak for
the class it chose to be; the class boundary is documented, not
accidental.

### 3.3 Adaptive flex to desktop/mini/low hardware — YES, by boundedness, not by knobs

The tool carries no adaptive machinery because its costs are
CONSTANT, not proportional to the host: kernel memory is fixed by
map caps (the same 128 KiB observer payload on a 2-core mini PC
and a 128-core server), the render loop is zero-alloc through
the diff engine with one winsize ioctl per 50ms wake, the /proc
walks are TTL-memoized (10s identity, 3s connections) and refresh
in place, and the poll's per-second work is now linear in live
cgroups (F2) with the point-lookup socket join over the known
socket set. A low-end host with 40 cgroups pays microseconds of
poll; the same binary on the dense server pays linearly for its
density and nothing for idle slots. The adaptive answer is
architecture (bounded maps, self-evicting LRU, honest degradation
everywhere a lesser tool would fabricate or spin), not runtime
auto-tuning — knobs would be state to drift, and the
over-engineering guard applies. No manual intervention is needed
at any host size inside the documented caps.

### 3.4 High-gain investments — what was taken, what was declined

Taken: F1 (the last SMP hole, kernel-side) and F2 (the last
superlinear spot, userspace-side). Declined, with reasons on the
record: shaping/queueing (EDT, FQ, pacing) is a different
product class with a different failure model — the
single-hooking-layer architecture is the product; per-CPU stats
maps would trade the now-SMP-exact single-entry atomics for
sum-on-read cost and memory with no accuracy left to buy;
auto-resizing maps would turn the documented caps into
undocumented drift; and a schema migration to u64 cgroup keys
would widen every map for a collision no deployed kernel can
produce (the documented u32 contract). The limiter is at the
ceiling of its design class, and the class is the product.

## 4. Verification

- `cargo test --locked`: 506 + 46 green (0 failed) — the schema
  pin now asserts v11; zero behavior pins moved (the merge fix is
  byte-identical on output; the init fix is kernel-side).
- `cargo fmt --check` and the ebpf crate's own fmt: clean.
  `cargo clippy --locked --all-targets --all-features
  -- -D warnings`: clean.
- The prebuilt-refresh cycle ran end to end (refresh-prebuilt.sh):
  the limiter object rebuilt with the fix, the observer
  reproduced byte-identically from untouched sources, the parity
  gate green on the new tree pin (f09eacbd...).
- The commit gate held both ebpf/ commits to their prebuilt
  pairing (staged together in the same commit, per the contract).

## 5. The benchmark decision

Run at the audit's close (after the last code commit), per the
A/B harness protocol: the monitor's frame path is untouched by
construction (the merge fix changes the poll's internal
complexity, not one byte of frame output; the kernel fix changes
enforcement birth semantics, not rendering), so the expectation
is frame-parity — the run exists to prove the no-regression
claim, and its record lands in docs/PERFORMANCE.md.

## 6. Residuals (honest)

- The init-race fix's live behavior (two CPUs racing a fresh
  bucket's birth) cannot be observed in THIS development
  container (no cgroup v2, no CAP_BPF, no KVM for the sandbox
  micro-VM) — the same residual every kernel-side change in this
  repo carries. The mechanism is pinned by construction (the
  NOEXIST flag is a kernel-uapi constant, the loser-relookup
  path is the improve-29 pattern the observer's SMP pins already
  exercise under real thread contention), and the owner-host or
  CI root lanes own the live confirmation.
- The 1024-slot policy ceiling on very dense deployments remains
  the documented design point (USAGE honest limitations), not a
  bug to fix — raising it is an owner decision that would ride a
  schema bump and a memory-cost trade, and nothing in this audit
  argues for it.
- This audit doc, the STABILITY rows, the CHANGELOG entries,
  and the docs index are updated in the same commit as this
  writing; the eagle-eyes screenshot assets still show pre-v11
  eras where noted in prior audits (the text contracts and pins
  are the source of truth — the standing disclaimer rule).
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
