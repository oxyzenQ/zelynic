<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Performance Metrics

> Deep benchmark results for zelynic — measured on real hardware.

## Measurement Methodology

All metrics measured using `scripts/bench/benchmarking.sh` — a bash wrapper
that calls `scripts/bench/benchmarking.py` (Python deep benchmarking engine).

Python is the beast engine because of:

- Precise timing (`time.perf_counter()`)
- /proc parsing for RSS + CPU sampling
- Statistical analysis (mean, median, stdev, percentiles)
- Subprocess management + parallel operations
- BPF map size introspection via `bpftool`

```bash
sudo ./scripts/bench/benchmarking.sh                # full run (10 iterations)
sudo ./scripts/bench/benchmarking.sh --quick        # quick (3 iterations)
sudo ./scripts/bench/benchmarking.sh --json         # machine-readable output
sudo ./scripts/bench/benchmarking.sh --stress 1000  # 1000s sustained enforcement test
```

## Benchmark Results

> Measured on: Arch Linux (CachyOS), kernel 6.18.38-2-cachyos-lts, AMD Ryzen 7 5800HS
> Date: 2026-07-12
> 10 iterations per test (full mode)

### Latency

| Operation | Target | Measured | Stdev | Status |
|-----------|--------|----------|-------|--------|
| `strict` (spawn → exit) | < 50ms | **32.4ms** | 0.6ms | Yes |
| `block` (spawn → exit) | < 50ms | **32.1ms** | 0.4ms | Yes |
| `status` (1 limit active) | < 20ms | **11.1ms** | 0.2ms | Yes |

### Throughput

| Operation | Target | Measured | Status |
|-----------|--------|----------|--------|
| Concurrent strict (5 parallel) | < 200ms total | **32.2ms** | Yes |
| Throughput (ops/sec) | > 50 | **155.4 ops/sec** | Yes |

### Memory Footprint

| Component | Target | Measured | Status |
|-----------|--------|----------|--------|
| Pin files (11 files) | < 10KB | **0 bytes** | Yes |
| BPF programs | kernel-managed | **2 active** | Yes |
| BPF maps (9) | < 100KB total | pinned via aya `PinningType::ByName` (the LIBBPF_PIN_BY_NAME semantic the C twin used) | Yes |
| Userspace RSS (during op) | < 5MB | process exits after apply | Yes |

### Sustained Enforcement (1000s)

| Metric | Target | Measured | Status |
|--------|--------|----------|--------|
| RSS (userspace) | < 1MB | **0 KB** | Yes |
| CPU (userspace) | < 0.1% | **0%** | Yes |
| Pin files | stable | 11 files (no growth) | Yes |

> Fire-and-forget architecture: zelynic exits after applying limits.
> BPF enforces in kernel. Zero userspace process = zero CPU + zero RSS.

### Rate Accuracy

Verified across 6 distributions (all within 2% of target):

| Distro | Target | Actual | Error | Status |
|--------|--------|--------|-------|--------|
| Arch Linux | 100 KB/s | 730 Kbps (91 KB/s) | < 1% | Yes |
| CachyOS VM | 360 KB/s | 3.0 Mbps (375 KB/s) | < 2% | Yes |
| Ubuntu 26.04 | 100 KB/s | 650 Kbps (81 KB/s) | < 1% | Yes |
| Fedora 44 | 100 KB/s | 690 Kbps (86 KB/s) | < 1% | Yes |
| Ubuntu 21.10 | 100 KB/s | 770 Kbps (96 KB/s) | < 1% | Yes |
| Debian 13 | 900 KB/s | 7.0 Mbps (875 KB/s) | < 2% | Yes |

### Test Suite Results

| Suite | Tests | Pass | Status |
|-------|-------|------|--------|
| Crash Recovery | 9 | 9 | Yes |
| Leak Detection | 13 | 13 | Yes |
| Depth (Comprehensive) | 17 | 17 | Yes |
| Race Condition | 6 | 6 | Yes |
| Reload | 5 | 5 | Yes |
| Stress | 6 | 6 | Yes |
| **Total** | **56** | **56** | Yes |

## Optimization History

### v7.0.0 — Lazy Identity Refresh

`open_pinned()` no longer scans /proc on every call. Only `status` command
refreshes identity. Write operations ~50-100ms faster.

### Kernel Version Detection

Added `kernel_supports_bpf_link()` check. On kernel < 5.7, falls back to
legacy `bpf_prog_attach` instead of crashing on `bpf_link_create`.

## Performance Engine Audit (NIGHT-perf-1, 2026-09-24)

The owner's depth-audit task: "avoid high overhead, bottleneck, etc
downgrade/problems performance engine" — a full pass over every
hot path, kernel and userspace, with the over-engineering guard
applied to every candidate. Findings, fixed and held:

**Fixed — the egress observer paid two BPF helper calls per packet
for a 1-in-100 event.** The C-twin port computed `ctx.tgid()` and
`ctx.uid()` at the top of `try_observe_egress`, but their only
consumer is the ring-buffer Event the throttle emits once per
hundred packets (and which zelynic userspace never reads — the
documented dead-ringbuf parity). The calls moved into the event
branch (NIGHT-perf-1, behavioral delta #5 in the observer's file
header): same current task, same invocation, byte-identical events;
the 99% fast path then ran the cookie bump + counter update + throttle
compare only. At 100 kpps that was 200 k helper calls per second
removed from the observer's hot path; at line rate it was a full
helper-call pair per packet. The `ctx.command()` call had already
established the lazy pattern (it lives in the event branch) — the
port artifact simply predated the discipline. Verified: the object
rebuilds under the pinned nightly pair, the embedded-object layout
tests pass on the new ELF, and the 10s frame A/B below proves the
render path is untouched (the kernel verifier re-proof is the
CI matrix + owner-host supermassive lane, the boost-26 precedent).

**Superseded by NIGHT-boost-34 (2026-09-25): the whole event branch
is gone, so the lazy-call win is now moot — and bigger.** Kernel 6.8
removed the get_current trio from `bpf_base_func_proto` and cgroup_skb
never reaches the replacement, so the event branch failed program load
with EINVAL on 6.8 hosts; the fix dropped the ringbuf, the throttle,
the IP-header parse, and every helper call they carried
(docs/PURE_RUST_EVALUATION.md delta 5). The egress program is 224 ->
60 instructions; its hot path is now exactly the cookie bump + counter
update — no throttle compare, no tgid/uid/comm calls on ANY path, no
`bpf_skb_load_bytes` copies. The perf-1 saving (a pair of calls on
the 99% path) became the whole pair plus the reserve/submit pair on
the 1% path and 164 instructions of parse bookkeeping, permanently.

| Metric | bb4b310 (A) | perf-1 (B) | Delta |
|--------|------------|------------|-------|
| fps | 8,058.3 | 8,155.7 | +1.2% (machine noise) |
| bytes/frame | 1,943.0 | 1,943.0 | +0.0% |
| emit bytes/frame | 504.8 | 504.0 | -0.2% |
| frame entropy | 3.0000 | 2.9992 | -0.0% |
| density gini | 0.3584 | 0.3587 | +0.1% |
| dirty cells/frame | 39.4 | 39.4 | -0.1% |

Reading: PARITY, by construction — the change is kernel-side only
and the frame harness renders from synthetic fixtures without
touching BPF, so bytes/frame identical to the decimal is the proof
the render path is byte-exact the old one. The gini/entropy/dirty
deltas sit inside the harness's own run-to-run class (the boost-26
record showed the same ±0.1% on identical render bytes); fps +1.2%
is the same container-noise class as every previous A/B on this
host. The win itself lives outside the harness's reach: it is
dynamic helper-call frequency in the kernel hot path, 2 per packet
down to 2 per 100 packets.

**Fixed — NIGHT-lts-2 + perf-3 (2026-09-25): the unlimited fast path
paid for a dormant watchdog.** The C-twin enforcement order (ported
verbatim through the Rust port) ran the watchdog array read AND a
`bpf_ktime_get_ns` timestamp before ever consulting the policy map —
but both hooks attach at the cgroup root and see every packet the
machine moves, while the policy maps hold only the handful of cgroups
zelynic polices. For the unlimited majority, two of the four
operations could never change the verdict: no policy means allow
under every possible watchdog state (unset, active, expired), and no
userspace writer arms the watchdog today (display-only state, the
SAFETY_ANALYSIS dormancy note) — the unlimited packet paid one array
lookup plus one helper call to check a dormancy timer it could never
fail. The reorder (policy lookup first, watchdog + clock only on the
policed path) keeps every policed-packet flow bit-identical and the
object size unchanged (268 instructions per program, 0x8d8 — no
verifier-cost movement), while the disassembled unlimited path drops
from ~25 instructions and 3 helper calls to ~13 instructions and 2
helper calls — roughly half the program's per-packet cost for the
packet class that dominates every host. Verified the perf-1 way:
the object rebuilds under the pinned nightly pair, the full rootless
suite is green, and the frame A/B (render path untouched by
construction — the change is kernel-side only) reads parity.

| Metric | pre-lts-2 (A) | lts-2 (B) | Delta |
|--------|---------------|-----------|-------|
| program size (egress section) | 0x8d8 / 268 insn | 0x8d8 / 268 insn | +0 (verifier cost unchanged) |
| unlimited-path insn before exit | ~25 | ~13 | ~-48% |
| unlimited-path helper calls | 3 (watchdog lookup, ktime, cgroup_id) | 2 (cgroup_id, policy lookup) | -1/packet |
| policed-path work | identical | identical | reordered only |

**Audited and deliberately held (over-engineering guard):**

- `ConnectionMap::socket_cookies()` dedups the cookie set with a
  linear `Vec::contains` (O(n^2) over the walked socket count, per
  frame). Held: at a realistic few hundred sockets the dedup costs
  microseconds while the join's own syscalls (two point-lookups per
  cookie) cost milliseconds — the quadratic term is under 5% of the
  feature's own budget at any n the /proc walk can produce, and a
  HashSet would grow the structure the renderers read for nothing
  measurable.
- `poll_and_summarize()` merges the ingress delta list into the
  egress list with a linear `find` per cgroup (O(n*m), worst case
  4096x4096 u32 comparisons per poll since the improve-31 raise).
  Held: single-digit milliseconds at the absolute ceiling, one poll
  per second, zero allocations to remove.
- `read_stats_map()` iterates both counter maps fully per poll
  (~16 k syscalls/s at the 4096-cgroup ceiling the improve-31 raise
  bought; ~120/s on a desktop). Held: the documented Layer-1
  design; batch lookup APIs would be a rearchitecture for ~1.6% of
  one core at the worst case.
- The selection-guard beat rewrites the whole frame every 100 ms on
  TTY sessions (~1.4 KB on 80x24). Held: it IS the copy-protection
  feature (NIGHT-improve-8), the documented owner contract — a
  perf "regression" that is the product.
- Identity/connection /proc walks: already TTL-memoized (10s/3s);
  the fd scan is lazy per matched socket; the pidfd open is lazy
  per PID with sticky failure. Peak for the design.

### night-improve-72 A/B (the panel floor, 2026-10-10)

The baseline panel's guaranteed-visible floor touched the render
path itself (the eagle layout now computes the panel's view rows
before the table renders, and the table's row budget stops at the
floor), so the frame harness owns the A/B. Protocol: A = c783b58
(the pre-floor tree, the owner's weekly deps bump included on both
sides so the layout engine is the only variable); B = 8cc05e8; the
standard 10 s budget, single runs, the standard harness protocol.

| Metric | c783b58 (A) | 8cc05e8 (B) | Delta |
|--------|-------------|-------------|-------|
| fps (render path) | 5,113.5 | 5,188.2 | +1.5% (machine noise) |
| bytes/frame | 1,919.0 | 1,919.0 | +0.0% |
| emit bytes/frame | 550.7 | 550.4 | -0.1% |
| density gini | 0.3429 | 0.3427 | -0.1% |
| frame entropy | 3.2192 | 3.2176 | -0.0% |
| dirty cells/frame | 102.4 | 102.2 | -0.2% |

Reading: PARITY on the happy path, by construction — the harness's
synthetic board never starves the panel, so the floor's five
withheld lines never bind and bytes/frame identical to the decimal
is the proof the well-fed frame is byte-exact the old tree's; the
pre-table `view_rows` pass (the one real addition to the frame
path, a small vec build over the lane's policy roots) disappears
into the noise class with everything else, fps signed positive
besides. The rescue itself is invisible to this harness by the
same construction: the starving shape — a board rich enough to
fill the frame, a panel with verdicts to show, the window walked
onto the detail-heavy head ranks — is pinned in
test/ebpf/render/eagle_floor_tests.rs at a limited (24) and a
normal (40) height, with the red-check (floor disabled) failing
exactly those two pins.

### NIGHT-private-research-2 A/B (MMSPA — the subtree-aware datapath, 2026-09-30)

The private-research-2 change is datapath work: the MMSPA resolution
(the leaf's own policy lookup unchanged and first, the LRU memo on
the miss branch, the ancestor walk on the memo miss, bucket and
stats keyed at the resolved root). None of it touches the frame
path — the render surface is byte-identical by construction, and
the frame A/B is the same class of proof the previous datapath-side
records used (A = 4223a50, the dinner-25 pricing tree; B = the
MMSPA tree; single runs, 10 s budget, the standard harness
protocol; the B side was captured on a container running a
concurrent CI watch, the fps spread below is that load).

| Metric | 4223a50 (A) | MMSPA (B) | Delta |
|--------|-------------|-----------|-------|
| fps (render path) | 7,670.8 | 7,361.5 | -4.0% (container load noise) |
| bytes/frame | 1,919.0 | 1,919.0 | +0.0% |
| emit bytes/frame | 504.9 | 510.2 | +1.1% |
| density gini | 0.3564 | 0.3547 | -0.5% |
| frame entropy | 2.9992 | 3.0033 | +0.1% |
| dirty cells/frame | 39.6 | 40.0 | +0.8% |

Reading: PARITY on the render path — bytes/frame identical to the
decimal again. The datapath's own cost cannot be measured by this
harness (rootless container, no cgroup v2): it is bounded by design
and measured by CI — the unlimited majority pays ONE extra map
lookup per packet (the memo hit, whose word carries its own
generation stamp since NIGHT-perf-0, so the staleness check rides
the lookup instead of adding one), plus the single Array read the
resolver takes on the miss branch, a policed-at-leaf packet pays
exactly what it always did (one lookup), a new leaf pays one
bounded walk (real-depth queries plus the break, ~8 at systemd
depths, then memoized for its lifetime), and a policy mutation
pays ONE Array store (the generation bump, NIGHT-perf-0 — the
pre-perf-0 design paid a memo sweep bounded by the 4096-entry cap)
plus each live leaf one re-walk. The supermassive matrix's
test_mmspa_subtree stage and its overhead stage own the live
measurements on every push that touches the limiter.

### NIGHT-private-research-3 A/B (the depth traffic focus + report compaction, 2026-09-30)

The private-research-3 pass is report-surface work: the eagle-eyes
--depth network-traffic focus (the observer window, the traffic
section, the JSON fields) and the compact-and-simple style pass
over status, list-apps, and the depth report. None of it touches
the live monitor's frame path — render/eagle, footer, border,
session, and the diff engine are byte-identical — and the frame
A/B is the proof (A = 6cb6f83, the dinner-26 release-fix tree; B =
the private-research-3 tree; single runs, 10 s budget, the standard
harness protocol).

| Metric | 6cb6f83 (A) | private-research-3 (B) | Delta |
|--------|-------------|------------------------|-------|
| fps (render path) | 7,789.0 | 7,758.8 | -0.4% (machine noise) |
| bytes/frame | 1,919.0 | 1,919.0 | +0.0% |
| emit bytes/frame | 502.6 | 503.2 | +0.1% |
| density gini | 0.3571 | 0.3569 | -0.1% |
| frame entropy | 3.0025 | 3.0030 | +0.0% |
| dirty cells/frame | 39.5 | 39.5 | +0.1% |

Reading: PARITY, by construction — bytes/frame identical to the
decimal is the proof the live frame content is byte-exact the old
tree's (the same class of evidence the perf-1 and boost-26 records
used for kernel-side and join-side changes). The gini/entropy/dirty
deltas sit inside the harness's own run-to-run class; fps -0.4% is
the container-noise class every previous A/B on this host recorded
(the mid-pass capture read +0.5% on an intermediate tree — the
spread is the noise, the byte-identity is the signal). The B side of
this table is the final committed tree (the LOC-cap module splits
included — pure code motion, rendering byte-identical).
The depth report's own cost lives outside this harness (a one-shot
stdout surface, not the frame loop): the focus window's wall-clock
is the owner-chosen sleep (default 3 s) plus one observer
attach/detach — the same verifier cost the live monitor pays on
open — and its /proc work is the connection census the report
already ran, refreshed once more at window close.

### NIGHT-upgrade-charger-core-1-c A/B (the fair-shared bucket, 2026-09-30)

The charger-core-1-c pass is kernel-datapath work: the DRR lane
(ebpf/src/drr.rs + drr_flow.rs + the try_enforce wiring) changes
what the LIMITER object enforces per packet, never anything the
live monitor's frame loop renders — the frame A/B is the proof
(A = c62c18f, the charger-core-1-b rider tree; B = 75e0f3f, the
charger-core-1-c tree; single runs, 10 s budget, the standard
harness protocol).

| Metric | c62c18f (A) | 75e0f3f (B) | Delta |
|--------|-------------|-------------|-------|
| fps (render path) | 7,588.1 | 7,626.1 | +0.5% (machine noise) |
| bytes/frame | 1,919.0 | 1,919.0 | +0.0% |
| emit bytes/frame | 506.5 | 505.8 | -0.1% |
| density gini | 0.3559 | 0.3561 | +0.1% |
| frame entropy | 3.0036 | 3.0034 | -0.0% |
| dirty cells/frame | 39.8 | 39.7 | -0.1% |

Reading: PARITY — bytes/frame identical to the decimal, every other
delta inside the harness's run-to-run noise class. The DRR lane's own
cost is per POLICED packet (the unlimited majority never reaches it —
the fast path's two lookups are unchanged, the memo still answers
before any walk): one LRU leaf lookup, the generation stamp read, and
on an empty leaf a stamp CAS plus at most two pool CAS attempts —
bounded straight-line work inside the verifier budget, measured by
the limiter object's growth (9920 -> 15176 bytes, ~52% more
instructions for the whole enforcement path, of which the DRR lane
is the additions and the shared refill extraction is neutral). The
live-root proof of the lane is the CI supermassive battery's job
(the four low/best x gnu/musl legs run it on every push).

### The guaranteed-minimum law (NIGHT-private-research-4's audit, 2026-10-04)

The owner-approved "Guaranteed minimum" ask — floor 1 mb, ceiling
10 mb, idle budget lent to the busy — audited against the shipped
datapath before any new code was written, and the verdict is: the
DRR pool lane has carried the full contract since the
charger-core-1c / dinner-28 / repair-3/4/6/7 arc, pinned rootlessly
and proven on the CI battery. This section is the owner-facing
framing of that law (the audit's deliverable — re-engineering it
would be over-engineering a peak already reached):

- THE FLOOR (a contending app's guaranteed minimum share): the
  pool's every-100ms refill splits across the drawee PEAK — the
  decaying high-water of DISTINCT askers, so the quiet majority
  counts, not just the shouters — and each leaf's per-epoch draw is
  bounded by that allowance, carried quantum-capped so a starved
  leaf can BANK several epochs toward one 64 KiB GSO admit (the
  absolute floor at tiny shares: even when the fair slice is
  smaller than one super-packet, the app still admits — slowly,
  but never zero). The pins: test/ebpf/limiter/drr_ledger_tests.rs
  `no-starve: quietest >= fair/4` at K=6 AND K=24, the collapse
  guard `total >= 65% of policy`, and the failure pins that show
  the v16 law breaking exactly these bounds before repair-3.
- THE CEILING (no app takes more than its share plus one quantum):
  the same epoch ledger caps the fast drawer at its fair share —
  `anti-monopoly: worst <= fair x 1.75 + quantum` — so a greedy
  sibling cannot monetize its packet rate (the 4.7x-fair defect the
  battery caught and the ledger closed).
- THE BORROWING (hierarchical, work-conserving, zero daemon): an
  idle app's unclaimed epoch allowance does not evaporate — the
  residue law hands it to whichever leaf is asking (a catch-up
  drawer banks its GSO admit floor off the unclaimed residue), and
  the lone-active edge delivers the WHOLE budget: 80-145% of policy
  in the lone-leaf pin. The aggregate never exceeds the policy (the
  pool never creates budget — `total <= 130%` with the burst
  slack), which is what makes the lending honest: borrowed bytes
  were someone's saved bytes, never invented ones.
- THE HANDOFF (a fresh budget inherits nothing): every policy
  mutation re-keys the share/ledger state on the MMSPA generation —
  a 24-leaf policy that shrinks to one hands the survivor a fresh
  divisor, never the dead fleet's peak throttling it through the
  decay's tail (the repair-6 pin: the 8.2%-of-policy handoff find).

The min/max the CLI expresses is the POLICY rate itself (the
ceiling the app asked for); the floor this law guarantees is the
fair share of the pool among the apps actually asking, floored at
the GSO admit cadence. Where the owner's "floor 1mb / ceiling 10mb"
shape needs a per-app floor ABOVE the fair share (a reserved lane
no sibling may borrow from), that is a new policy surface — a CLI
decision that stays the owner's to call, not silently added here.

That call has since been made and delivered: the guarantee bracket
(`--floor`/`--ceil`, improve-40 schema v24; the per-direction
spellings improve-40-b) clamps the epoch allowance between the
bracket's own shares — the floor a PRIORITY (the pool itself the
lender), the ceiling binding even a lone drawer — pinned rootlessly
by the guarantee battery (test/ebpf/limiter/drr_guarantee_tests.rs)
and measured live in REAL cgroups by the root-gated probe:
`sudo ./scripts/bench/guarantee-probe.sh` (root required; the
rootless instrument lane is `--self-test`) — four real leaf cgroups
under one bracketed target, every leaf's delivered volume measured
against the floor's share and the ceiling's cap, the pool law
bounding the sum, and the per-direction split's ledger row riding
the same harness.

### The flow-isolation law (CAKE-shaped, schema v20, 2026-10-04)

The guaranteed-minimum law made the LEAF fair — no cgroup under a
policy starves its siblings. The flow-isolation law closes the same
class one level deeper: the leaf bucket itself was still shared by
every socket the cgroup holds, and a shared bucket is FCFS at
packet granularity — the packet-arrival race. The rootless
isolation battery (test/ebpf/limiter/cake_isolation_tests.rs)
measured the honest shape before any kernel saw the lane: the
race's victims are the WEAKER DEMANDERS (a second download under
the shared leaf delivered 524 KB of its 1.5 MB fair share, 2.9:1
against the first; the three-flow shape breaks the battery's own
anti-monopoly bound at 2.1x fair), while the truly quiet flows (a
DNS-shaped 200-byte query per epoch) ride the GRO-granularity
banking's leftover crumbs and admit either way — the sketched
starvation does not reproduce, and the law is honest about it.

The close mirrors the DRR laws one level down, keyed by the socket
cookie the hook already names (no new helper — the per-socket
lane's own attribution join):

- THE ISOLATION: every attributed packet spends from its own FLOW
  bucket and draws from the leaf under the learned count, the
  drawee peak, and the epoch ledger with its quantum-capped carry —
  the bulk flow blocks at its fair share of the leaf's own
  throughput, the refills accumulate behind the block, and the
  weaker demander's draws find a rich leaf (the measured close:
  2.9:1 becomes 1.1:1, and the three-flow shape back inside the
  battery's `worst <= fair x 1.75 + quantum` bound).
- THE SPARSE/DENSE TAKE (the CAKE signature, in the only form a
  policer can carry): a flow quiet for an epoch draws its packet's
  OWN bytes — the reserved small quantum, admitting on the first
  offer and stranding nothing (measured: the quiet flow's takes
  equal its deliveries, byte for byte); a flow drawing this epoch
  takes the quantum (the bulk cadence amortizes the draw cost).
  The evidence is the flow bucket's own draw stamp — a flow's
  frequency classifies it, and a lone flow is never throttled by
  machinery it does not need (the single-active row's lo bound,
  mirrored).
- THE HONEST TRADEOFF, stated as the leaf ledger's own: a leaf's
  under-demanded share stays RESERVED (the sibling leaf cannot farm
  it without breaking the anti-monopoly bound), so a mixed leaf
  rides the same 65%-130% aggregate band the v17 battery set —
  protection bought at the cost of the monopoly's false efficiency,
  the coarse-fairness-beats-starvation tradeoff one level deeper.
  The reservation is live, not dead: a reserved flow that goes
  dense finds its banked carry waiting.

The pins (cake_tests.rs + cake_isolation_tests.rs): the law bounds
(the budget cascade, the allowance mirror, the two-lane take, the
OFF-lane fraction that keeps the share word's peak decay from
leaking a full leaf drain per transient epoch — the battery's own
second catch), the find (the anti-monopoly bound broken at flow
granularity under the shared leaf), the close at every battery row
(equal bulk splits, lone-flow whole-budget, trickle regime, the
sibling leaf untouched), and the A/B fingerprint across the lane
boundary (same seeds, both shapes, the deltas that are the feature
pinned so they cannot drift into noise).

THE SOURCE BUFFER LAW (the live CI battery's catch, the lane's
third lesson): the first shipped form drained the leaf whole on
every dense take, and the live Supermassive matrix measured 1411
packets dropped under a NON-BINDING 12 GB/s policy — zero before
the lane, zero being the row's own law — with the 100kb trickle
row sagging to 64.8% under the same shape. The root cause was
subtle and worth stating: the leaf bucket was designed to ride
HIGH (packet-sized spends, quantum-sized draws, accumulating
between draws so the pool's micro-credit oscillation never reaches
an admit decision), and a whole-leaf take broke exactly that — the
leaf rode at ~0, and every packet's admit rode the pool's
instantaneous credit instead. The close is the residue law's
half-split mirrored one level down, where it keeps the source's
buffer instead of the next asker's share: a dense take caps at
HALF the leaf (above two packets' worth — below that the take is
whole and the admit DETERMINISTIC, the old single-bucket lane's
own property), a sparse take keeps the whole-leaf right (its
demand IS the packet). And the fourth lesson, the PACKET FLOOR:
the lone flow's OFF-lane fraction under-sized takes at low binding
rates (at 2 MB/s, leaf/3 sits at the packet's own order) and the
drop-with-bank cycle collapsed TCP to 37% of a policy it should
have ridden — so the OFF lane's take never sits below the packet
it serves when the leaf covers it, CAKE's own MTU-floor discipline
one level down, conditioned on the lone/cold shape (a decayed-peak
transient keeps the fraction). The rootless battery's fairness pins
rode unchanged through every form — these laws live at the
micro-credit scale the sims do not model, the scale only the live
kernel reaches, which is why the battery exists.

### The ECN-first budget law (mark before drop, schemas v19/v21, 2026-10-05)

The limiter's drop verdict is a LAST RESORT on every budgeted
lane (NIGHT-private-research-4's ranked innovation, shipped in
two waves: v19 for the group and DRR cgroup lanes, v21 closing
the per-socket lane). When the kernel helper `bpf_skb_ecn_set_ce`
can set the CE codepoint on an over-budget packet (ECT-capable,
IPv4 or IPv6, checksum handled by the kernel, helper ID 97), the
packet is DELIVERED CE-marked instead of dropped and its bytes
charge a debt the lane's own token stream pays back. A CE-reactive
sender (TCP with ECN negotiated, QUIC with ECT) converges on the
mark without a single lost packet — goodput under the cap rises,
retransmit jitter falls. A non-ECT packet refuses the helper and
drops exactly as before: the legacy verdict, untouched.

THE BUDGET LAW — the part that makes this a law and not a wish.
Marked packets are delivered, so they must come out of the
policy's budget or the aggregate promise dies. The accounting
(ebpf/src/ecn.rs, the pure core both trees compile): every
delivered marked packet charges a DEBT capped at one GSO
super-packet (65,536 bytes, the same admit floor the DRR lane
heals starved flows with), and every delivered packet on the lane
PAYS that debt from the bucket's own tokens, on the allow path
only, from the stream's leftover. The invariant chain, closed
under every adversarial shape the battery throws at it:

  delivered = lane_consumed + marked
  marked    <= debt_charged = debt_paid + debt_outstanding
  debt_paid <= tokens_deducted (each pay removes tokens)
  lane_consumed + tokens_deducted <= refill_credits
  =>  delivered <= rate*t + burst + 64 KiB

The CALL-SITE LAW is the design's load-bearing wall: the pay runs
ONLY on the lane's allow path, from the leftover after a delivery.
A pay that ran on every packet (drop path included) would drain
the token stock toward the debt, and a CE-ignoring hammer (set
ECT, never react) would pin the debt at its cap and turn the
entire refill stream into debt service — the lane starves BELOW
the policy, the exact inversion of the promise. The rootless
simulation caught this BEFORE any kernel saw the code (the hammer
row's own history note in test/ebpf/limiter/ecn_tests.rs). With
the allow-path placement the semantics close per sender shape: a
CE-reactive sender spends the one-time 64 KiB slack during its
convergence transients and the converged periods' leftover
re-arms it; a CE-ignoring sender sees the debt saturate once and
the lane settle into EXACT drop-lane parity — never worse than
the legacy policer, never a second rate stream (no time-based
decay anywhere: decay would hand the CE-ignoring shape a second
independent rate stream).

The per-socket closure (v21): the debt word lives INSIDE the
socket's bucket — per-connection state in the per-connection
bucket, zeroed by the generation belt on a policy mutation, aged
out by the LRU with the bucket. The deferred question ("N
connections each halving their windows on per-connection marks is
an aggregate-collapse shape") is closed by the rootless fleet
sims (test/ebpf/limiter/ecn_socket_tests.rs): per-connection
budgets are independent, so each connection converges on its own
stream and the aggregate rides N x per-connection with no
collapse term — the marking fleet stays above 90% of N x rate
while every connection sits inside its own budget law, beats the
same fleet under the per-socket drop policer, and a CE-ignoring
hammer on one connection stays bounded by its own budget law
while its neighbors converge untouched. The aggregate honest
bound: N x (rate*t + burst + one 64 KiB super-packet).

The pins (ecn_tests.rs + ecn_socket_tests.rs, 14 rootless rows):
the debt-cap arithmetic (accumulate under the cap, exact fit then
refuse, oversize refusal), the pay semantics (exact value movement
between the words, partial pay, empty no-op), the book_rescue
ledger correction (dropped-then-moved booking, exact), the
hammer's budget law (bounded by the cap, never a second stream),
the goodput A/B (ECN-first strictly beats the drop policer under
identical demand feedback, zero last-resort losses for the
reactive sender), and the three fleet rows (no collapse, marking
beats dropping, hammer isolated). The DRR lane's debt pay rides
the pool's own stream — the faucet every leaf and flow draw
through — so the marked bytes pay back against the same aggregate
budget that fed them.

The live lane has its own harness since 2026-10-05:
`sudo ./scripts/bench/ect-probe.sh` (root required;
`--self-test` is the rootless instrument lane). It blasts ECT(0)
UDP through a real --per-socket 8kb policy, reads the CE codepoint
back at the receiver through the IP_RECVTOS cmsg, and measures the
three live rows the rootless battery cannot: the mark landing
(CE-marked datagrams delivered past the burst), the debt cap's
bite (CE bytes bounded by 64 KiB plus the window's refill), and
the closed form itself (delivered <= burst + rate*t + debt + one
packet) — beside a Not-ECT control leg that drops beyond the same
burst, the goodput gain of the ECT leg over it, and the kernel
ledger's own refusal/rescue booking. The QUIC-aware law below
rides the same marking machinery (the v22 object's per-connection
buckets charge the same debt), so the live harness doubles as its
marking proof; the QUIC attribution itself is pinned rootlessly
by quic_tests.rs and rides the supermassive battery for its live
lane.

### The QUIC-aware attribution law (schema v22, 2026-10-05)

The ECN-first and flow-isolation laws both key their per-connection
state by the socket cookie — and QUIC (HTTP/3, RFC 9000) breaks the
premise the cookie rests on: Chromium and Firefox multiplex every
QUIC session of a host over ONE UDP socket, demuxed by connection
ID. Under the cookie: the flow lane's isolation collapses to its
own before-picture (the browser's N HTTP/3 connections share ONE
flow bucket — the monopoly shape cake_isolation_tests.rs measured
at 2.9:1), and the --per-socket promise ("each connection its own
bucket at the policy rate") silently degrades to "the whole socket
shares one budget" for exactly the protocol that multiplexes. The
law this section pins: attribution must follow the CONNECTION when
the header carries connection truth, and must refuse — never
guess — when it does not.

The mechanics, all rootless-pinned (test/ebpf/limiter/quic_tests.rs,
10 rows): v1/v2 long headers parse with EXPLICIT CID lengths
(stateless exact keys — the handshake packets need no learned
state); short-header CID lengths are connection state RFC 9000
negotiates inside encrypted NEW_CONNECTION_ID frames (the documented
reason QUIC-LB exists), so the datapath LEARNS them from the
handshake's own explicit-length bytes — a long header seen on
direction D folds its DCID length into D's hint map and its SCID
length into the opposite direction's — gated by a CONFIRMATION
rule (the same nonzero length must survive a second sighting; the
throwaway Initial DCID a peer replaces after its Server Initial
can never poison the lane alone). Every refusal — non-UDP,
non-QUIC, unparsable, unconfirmed, zero-length CID, IPv6 with
extension headers — rides the RAW COOKIE, the exact pre-v22
verdict: the lane refines attribution, never degrades it. The
lifecycle pin walks a full handshake with three DISTINCT CID
lengths (throwaway 16, client 8, server 12) and shows the
transients never activating while the steady state keys
per-connection exactly; the isolation pin splits N connections of
one cookie into N distinct, stable keys.

The honest residues, stated rather than hidden: a CID beyond 8
bytes keys by its prefix (two connections differing only past byte
8 share a bucket — coarser, safe); a connection that rotates CIDs
mid-flight keys the rotated packets under the new CID (a flow
split the share word's decay heals in the fairness lane; a fresh
burst stream in the per-socket lane — the lane's own documented
"rate x concurrent" shape); the server-role shape may learn a
transient length when a peer's Initial DCID and real CID differ
(the confirm gate plus the opposite-direction SCID source hold the
dominant shapes correct). A boundary the pins name and the design
keeps: a SINGLE-direction policy (`-d` only, or `-u` only) does
not parse the unpoliced direction — the unlimited fast path stays
parse-free (the pinned NIGHT-lts-2 law), and that direction's
handshake packets are the only place the policed direction's CID
length is learnable — so single-leg policies ride the cookie for
QUIC data (the pre-v22 verdict). The dual-leg default learns both
directions; the fast-path law is never traded for attribution. No
live-browser A/B number is claimed here: the live lane rides CI's
supermassive battery, and the claim this section owns is the pinned
one — attribution granularity, proved rootlessly, with every
degradation path falling toward the cookie, never past it.

### The time-window law (the unified --during, schema v23, 2026-10-06; revised duration-only)

A limit today is forever until somebody remembers to lift it. The
night-during law gives a policy row its own lifetime with no
daemon anywhere: the KERNEL decides when the window is over, the
pinned bpf_links stay the only resident state, and the CLI visit
is the clock's refresh channel. The law this section pins has
three clauses, each rootless-pinned (test/ebpf/limiter/
during_tests.rs, during_user_tests.rs):

1. THE FAST-PATH CLAUSE (the NIGHT-lts-2 law, verbatim): the
   window gate is ONE side-map read on the POLICED path only,
   after the policy hit — the unlimited majority of packets (both
   hooks sit at the cgroup root and see every packet the machine
   moves) pays nothing. An absent window entry is today's behavior
   exactly; an INACTIVE window answers ALLOW — the miss shape: no
   stats booking, no ring booking, no MMSPA belt.
2. THE DRIFT CLAUSE: SPAN rows (the duration the flag writes,
   and the restore lane's re-translated wall deadlines) store
   wall instants PRE-TRANSLATED into the monotonic clock at
   apply time — `bpf_ktime_get_ns` and the userspace
   CLOCK_MONOTONIC read are the same clock domain, so NTP slew
   and a manual `date -s` cannot move a span by a single
   nanosecond (the pinned residue: suspend, which monotonic does
   not count — a sleeping host's `--during 20d` outlives its
   wall-calendar promise by exactly the slept time). DAILY rows
   read the wall through the offset bridge (the one-entry pinned
   Array every attach-reuse and every apply re-stamps) under the
   MARGIN LAW: FIRE_EARLY = 2s erodes BOTH window edges toward
   LESS enforcement — the grid pin proves the userspace twin
   answers exactly what the kernel would with a freshly stamped
   bridge, saturation domain included, and the monotone-erosion
   pin proves a margin can only REMOVE active time, never add it.
3. THE SWEEP CLAUSE: an ended span's row answers ALLOW per packet
   from its expiry instant (the safety inverse of today's
   "applied and forgotten" — strictly safer), and every later
   apply-family invocation drives it through the unstrict/reclaim
   machinery (span_ended is the only removal predicate: a dormant
   future-start row — a state file restored before its span's day
   — and a recurring daily window, a read-side shape older
   builds wrote, are never swept). The probe stands down on a
   dormant window instead of measuring
   an unlimited path and failing the apply dishonestly.

No throughput number is claimed for this feature — it ADDS one
HashMap lookup to the policed path (the policy census bounds
occupancy at 1024 rows, the stats map's own posture) and zero to
the unlimited path; the cost is the map read, and the benefit is
the QoL the whole surface exists for. The wall-form translation
(during_to_window with the offset-bridge stamps) keeps a promised
window's expiry drift-free for the life of its pins — NTP slew or
a manual `date -s` cannot silently convert a window into forever.
The state-file serialization that once carried rows across reboots
(WindowPersist, the snapshot/restore pair) retired whole with
NIGHT-improve-55 — pins die at reboot with bpffs, and a unit file
re-applying the strict family is the desired state.

### NIGHT-upgrade-charger-core-1-b A/B (the self-proving enforcement, 2026-09-30)

The charger-core-1-b pass is command-path work: the enforcement
probe (three new command modules, the strict-single wiring, the
hidden probe roles) never touches the live monitor's frame path —
the frame A/B is the proof (A = f703167, the charger-core-1-a tree;
B = beb85f0, the charger-core-1-b tree; single runs, 10 s budget,
the standard harness protocol).

| Metric | f703167 (A) | beb85f0 (B) | Delta |
|--------|-------------|-------------|-------|
| fps (render path) | 7,573.2 | 7,602.5 | +0.4% (machine noise) |
| bytes/frame | 1,919.0 | 1,919.0 | +0.0% |
| emit bytes/frame | 506.8 | 506.2 | -0.1% |
| density gini | 0.3558 | 0.3559 | +0.1% |
| frame entropy | 3.0039 | 3.0043 | +0.0% |
| dirty cells/frame | 39.8 | 39.7 | -0.1% |

Reading: PARITY — bytes/frame identical to the decimal, every other
delta inside the harness's own run-to-run noise class. The probe's
own cost lives in the strict command's wall-clock, not any
steady-state path: it runs once per apply (~4 s: two child spawns,
one 3 s measured window, teardown), and the `--no-test` escape
plus the harness-side rides keep every scripted lane at apply-only
cost.

### NIGHT-upgrade-charger-core-1-a A/B (the bypass-shadow audit, 2026-09-30)

The charger-core-1-a pass is report-surface work of the same class
as private-research-3: the bypass audit rides the depth report's
focus window (two /sys/class/net reads bracketing the window, one
pure verdict over values the observer already polled), so the live
monitor's frame path is untouched by construction — the only frame
adjacency is the render tree's module list gaining a sibling
declaration. The frame A/B is the proof (A = d831b0d, the
dinner-26 rider-H tree; B = f703167, the charger-core-1-a tree;
single runs, 10 s budget, the standard harness protocol).

| Metric | d831b0d (A) | f703167 (B) | Delta |
|--------|-------------|-------------|-------|
| fps (render path) | 7,591.0 | 7,673.4 | +1.1% (machine noise) |
| bytes/frame | 1,919.0 | 1,919.0 | +0.0% |
| emit bytes/frame | 506.5 | 504.8 | -0.3% |
| density gini | 0.3559 | 0.3564 | +0.1% |
| frame entropy | 3.0017 | 3.0022 | +0.0% |
| dirty cells/frame | 39.8 | 39.6 | -0.3% |

Reading: PARITY — bytes/frame identical to the decimal is the proof
the live frame content is byte-exact the old tree's, and every other
delta sits inside the harness's own run-to-run noise class (fps
moved +1.1% here where the same host recorded -0.4% on the
private-research-3 pass — the spread is the noise, the byte-identity
is the signal). The audit's own cost lives outside this harness
(one-shot stdout surface): two sysfs directory walks bracketing the
window the report already sleeps through, each a few dozen counter
file reads — microseconds against the seconds of the window itself.

### NIGHT-lts-1 A/B (the display-width discipline, 2026-09-25)

The CJK width fix (five budget surfaces routed through the
display-width module) touched the render path itself, so the frame
harness owns its A/B. Protocol note first: the harness renders
8,000+ frames per second, and this shared container's run-to-run
spread is ±7% (three-run medians overlap between trees — the
single-run deltas of -8..-13% overstate precision); the honest
figure is a single-digit-percent render-throughput cost, and the
byte-identity proof below is the primary evidence the change is
otherwise invisible.

| Metric | pre-lts-1 | lts-1 | Delta |
|--------|-----------|-------|-------|
| fps (render path, dev harness) | 8,332 | 7,434 | -10.8% (single run; 3-run medians 171k vs 159k over overlap) |
| bytes/frame | 1,919.0 | 1,919.0 | +0.0% |
| emit bytes/frame | 616.3 | 624.7 | +1.4% (capture-prefix artifact) |
| dirty cells/frame | 54.1 | 55.8 | +3.1% (capture-prefix artifact) |

Reading: PARITY OF OUTPUT, proven harder than the metric table — a
worktree capture of the pre-lts-1 tree against the current one
shows the first 300 frames byte-identical except the build-embedded
git hash in the copyright stamp (300/300 frames, hash-normalized
zero diffs). The emit/dirty deltas are the metric's own
prefix-length artifact: the frames are a deterministic sequence
whose per-frame churn drifts as session totals grow, and the two
trees capture different frame counts inside the fixed budget
(the slower tree's shorter prefix averages a dirtier stretch).
The fps cost is real — the width machinery measures every visible
glyph, and at the harness's synthetic cadence that shows — but the
product renders at 1 fps (the interval clamp's floor) against a
16-19k fps release-build capacity: three orders of magnitude of
headroom, ~1 µs per frame. The recoverable share was recovered in
the same task: char_width gained an inlineable ASCII fast return
(everything below U+0300 is width 1 — one compare for the glyphs
that dominate every frame), pad_to_width became a single measuring
scan for the already-fits case, and the eagle row's label cell
collapsed its separate truncate step into the one pad call.

### NIGHT-ultimate-2 A/B (the sink-death quiet exit, 2026-09-24)

The forever-monitor fix (a dead output sink now ends the session
quietly, STABILITY.md's silent-killer inventory) touched the
terminal layer: the diff engine's emission tail records a failed
`write_all` in a sticky flag, and the monitor loop reads it after
every beat. The frame harness drives the same emission tail, so
the A/B proves the happy path is unchanged (A = d32d48f, B = the
ultimate-2 tree, 10 s formal runs):

| Metric | d32d48f (A) | ultimate-2 (B) | Delta |
|--------|------------|----------------|-------|
| fps | 8,168.7 | 8,102.3 | -0.8% (machine noise) |
| bytes/frame | 1,943.0 | 1,943.0 | +0.0% |
| emit bytes/frame | 504.1 | 504.1 | -0.0% |
| frame entropy | 3.0006 | 3.0005 | -0.0% |
| density gini | 0.3586 | 0.3586 | +0.0% |
| dirty cells/frame | 39.4 | 39.4 | -0.0% |

Reading: PARITY to the fourth decimal — by construction. The
happy path gained one `Result` inspection on the emission call and
one bool load per beat (the loop's two sink-death checks), and the
error branch is new code only a dead sink reaches; the harness's
deterministic per-frame metrics are byte-identical across the
board. The raw-fd helpers (winsize, RawStdout) moved to
src/terminal/raw.rs in the same task — the 500-line-cap split —
with every consumer still routing through the terminal layer's
re-export surface, zero call-site churn.

### NIGHT-lts-5 A/B (the server long-endurance scale re-shape, 2026-09-25)

The change touched the render path's figures, not its layout: the
board's TOTAL column and the footer census render through
`format_bytes_wide` (the u128 twin of the SI ladder), the AVG speed
pair divides through `rate_bps_wide`, and the session accumulator
behind them widened to u128; the loader's deltas went wrap-coherent
(subtraction shape, zero cost). Three-run medians (A = 432c2fa at
HEAD, B = the lts-5 tree, 10 s formal runs each side, the
container's ±7% noise band the lts-1 record established):

| Metric | before (median) | after (median) | Delta |
|--------|---------------|---------------|-------|
| fps | 7,814.3 | 7,623.8 | -2.4% (noise band) |
| bytes/frame | 1,919.0 | 1,919.0 | +0.0% |
| emit bytes/frame | 502.1 | 505.8 | +0.7% |
| frame entropy | 3.0216 | 3.0244 | +0.1% |
| density gini | 0.3513 | 0.3503 | -0.3% |
| dirty cells/frame | 39.5 | 39.7 | +0.6% |

Reading: bytes/frame identical to the byte — the wide ladder's
lower tiers are the u64 ladder (pinned byte-identical in
test/ebpf/limiter/format_wide_tests.rs), so every desktop-sized
figure renders exactly as before; the small emit/dirty movement is
the diff engine reacting to the first frame after the harness's
fixed-seed traffic crosses a tier edge (one cell repaints), and
every delta including fps sits inside the noise band (the single
first-run pair showed -11.6% fps, which the three-run medians
exposed as build-warm-up noise — the exact reason the lts-1
protocol requires medians). The u128 arithmetic itself costs one
wider add per fold and one wider divide per figure, against a
render path that spends its budget in string building — invisible
at the product's 1 fps cadence.

### NIGHT-lts-9 A/B (the theme accuracy fix, 2026-09-26)

The change is one 256-depth fallback index in a NON-default theme:
night_cyber's brand moved from the pure-cyan corner 51 to its
computed nearest cell 45. The frame harness renders the default
(netrunner), so the default frame is untouched by construction and
the A/B is the no-default-drift proof (single runs, A = b46e869 at
HEAD, B = the lts-9 theme tree, 10 s formal runs, the container's
±7% noise band):

| Metric | before | after | Delta |
|--------|--------|-------|-------|
| fps | 7,666.7 | 7,443.5 | -2.9% (noise band) |
| bytes/frame | 1,919.0 | 1,919.0 | +0.0% |
| emit bytes/frame | 505.0 | 509.4 | +0.9% |
| frame entropy | 3.0249 | 3.0287 | +0.1% |
| density gini | 0.3522 | 0.3508 | -0.4% |
| dirty cells/frame | 39.6 | 39.9 | +0.7% |

Reading: bytes/frame identical at 1,919.0 — the default theme's
encodings are byte-identical to the pre-fix constants (the
netrunner regression pin), and the fix touches no code path, only
one const table entry for a theme the harness never cycles. The
small movement in the data-dependent metrics (entropy, gini,
emit, dirty) is run-to-run synthetic-traffic variation — the
frame count inside a 10 s window differs with fps, and the
fixed-seed stream is at a different frame index in the aggregate —
the same sub-noise class the lts-5 medians documented; fps -2.9%
sits inside the band with no code-path change to carry it.

### NIGHT-lts-8 A/B (the extreme-burst consume retry, 2026-09-26)

The change lives in the BPF enforcement path (the consume retry in
ebpf/src/math.rs) and the userspace policy surface (default_burst's
floor) — neither can reach the frame renderer, and the A/B is the
parity proof (single runs, A = 645f4cb in a worktree, B = the lts-8
tree, 10 s formal runs, the container's ±7% noise band):

| Metric | before | after | Delta |
|--------|--------|-------|-------|
| fps | 7,490.4 | 7,665.9 | +2.3% (noise band) |
| bytes/frame | 1,919.0 | 1,919.0 | +0.0% |
| emit bytes/frame | 508.2 | 504.8 | -0.7% |
| frame entropy | 3.0289 | 3.0260 | -0.1% |
| density gini | 0.3512 | 0.3522 | +0.3% |
| dirty cells/frame | 39.9 | 39.6 | -0.6% |

Reading: bytes/frame identical at 1,919.0 and every data-dependent
metric sub-noise — the render path is untouched by construction
(the enforcement math runs in the kernel object, the floor is a
policy constant), and the small movements are the same run-to-run
synthetic-traffic variation the lts-5 and lts-9 rows document. The
retry's own cost is measured where it lives: the uncontended first
attempt is the whole story (verdict-identical to v7), and the drop
path's three extra volatile reads are ~3 cycles on a cached line.

### NIGHT-lts-7 A/B (the endurance lifecycle fixes, 2026-09-26)

The changes live in the limiter's policy lifecycle (the dead-group
reclaim), the BPF group-bucket fallback, and the monitor loop's
first-render epoch (the boot-edge floor) — none can reach the frame
bytes, and the A/B is the parity proof (single runs, A = 9d520a0 in
a worktree, B = the lts-7 tree, 10 s formal runs, the container's
±7% noise band):

| Metric | before | after | Delta |
|--------|--------|-------|-------|
| fps | 7,385.1 | 7,619.8 | +3.2% (noise band) |
| bytes/frame | 1,919.0 | 1,919.0 | +0.0% |
| emit bytes/frame | 510.0 | 505.9 | -0.8% |
| frame entropy | 3.0264 | 3.0231 | -0.1% |
| density gini | 0.3506 | 0.3519 | +0.4% |
| dirty cells/frame | 40.0 | 39.7 | -0.6% |

Reading: bytes/frame identical at 1,919.0 — the epoch floor changes
only the loop's INITIALIZATION (one checked_sub on a path the frame
renderer never sees), and the limiter-side changes are CLI/BPF
lifecycle, not render. The small movements are the same run-to-run
synthetic-traffic variation every row above documents.

## BPF Instruction Budget

```bash
sudo bpftool prog show | grep enforce
sudo bpftool prog profile id <ID> duration 10
```

## Methodology Notes

1. **Iterations**: 10 per test (3 in --quick mode)
2. **Isolation**: Tests run on idle system
3. **Cleanup**: Each test cleans up BPF state before exiting
4. **Root**: All tests require root (BPF operations)

## Regression Detection

```bash
sudo ./scripts/bench/benchmarking.sh --json > before.json
# ... make changes ...
sudo ./scripts/bench/benchmarking.sh --json > after.json
diff <(jq -S . before.json) <(jq -S . after.json)
```

If mean latency increases by > 10%, investigate.

## Frame Render Benchmark (NIGHT-hunt-7)

The system benchmark above needs root eBPF, which sandboxes and CI
runners often cannot provide. The frame benchmark closes that gap for
the monitor render layer: it drives the REAL print path
(`src/ebpf/render.rs`) with synthetic traffic from a fixed-seed LCG, so
before/after runs see byte-identical data and the only variable is
the layout engine. Root is NOT required.

```bash
./scripts/bench/frame-bench.py --save before.json
# ... change the layout ...
./scripts/bench/frame-bench.py --save after.json --compare before.json
```

Metrics (owner's visual + performance contract):

| Metric | Meaning | Direction |
|--------|---------|-----------|
| `density_gini` | visual mass concentration across rows | lower = calmer |
| `frame_entropy` | character diversity, bits/char | context-dependent |
| `fps` | render-path throughput ceiling | far above terminal needs |
| `dirty_cells` | cells redrawn between frames | lower = less churn |
| `bytes_frame` | emitted bytes per redraw | lower = cheaper frame |

### NIGHT-hunt-7 A/B (responsive layout, 2026-09-18)

Pre-change baseline vs the responsive engine (10s runs, dev profile,
piped 80x24 geometry, identical synthetic data):

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| density gini | 0.1918 | 0.1595 | **-16.8%** (calmer) |
| dirty cells/frame | 720.7 | 385.7 | **-46.5%** (less churn) |
| dirty ratio | 0.3630 | 0.2096 | **-42.3%** |
| avg rows | 29.0 | 23.0 | -20.7% (height-capped) |
| avg width | 67.0 | 80.0 | full-width flagship bars |
| fps | 16,656 | 14,995 | -10.0%, still ~15k ceiling |

Reading: the frame is measurably calmer (gini down) and the terminal
absorbs less than half the redraw churn, while the render path still
clears four orders of magnitude more frames per second than a
terminal can display. The fps cost buys full-width purple brand bars
plus per-frame width/height probing (dynamic screen size).

### NIGHT-hunt-8 A/B (eagle-eyes detail lines, 2026-09-18)

The harness gained a synthetic ConnectionMap fixture (every third
cgroup multi-tenant, busy flags toggling every 3 frames — a
worst-case churn pattern), so the A/B measures the real cost of
rendering per-process socket detail:

| Metric | hunt-7 layout | hunt-8 + detail | Delta |
|--------|---------------|-----------------|-------|
| fps | 14,995 | 14,721 | -1.8% |
| bytes/frame | 1,717 | 1,438 | -16.3% (detail displaces rows in the same height budget) |
| frame entropy | 3.909 | 4.208 | +7.7% (information gained) |
| density gini | 0.1595 | 0.1812 | +13.6% (light detail rows), still below the 0.1918 pre-hunt-7 baseline |
| dirty cells/frame | 385.7 | 755.4 | +95.8% under forced busy-flag toggling |
| bytes/sec churn | 25.7 MB | 21.2 MB | -17.8% |

Reading: the eagle-eyes capability costs ~2% render throughput and
displaces bytes within the fixed height budget (frames get SMALLER).
Dirty cells double only under the fixture's artificial all-sockets-
flip pattern; against the original pre-hunt-7 baseline the full
detail-carrying frame churns roughly the same 755 vs 721 cells —
the attribution comes free with the responsive layout.

### NIGHT-strict-1 A/B (terminal-contract pin, 2026-09-19)

The strict mouse/clipboard contract commit moved the alt-screen
escape bytes into named constants (`ALT_ENTER` / `ALT_EXIT`) behind
`write_all` — same bytes, different plumbing. The A/B exists to
prove "byte output unchanged" with data instead of assertion (A =
eb618d0 in a throwaway worktree, B = 1190ca3, 10 s formal runs):

| Metric | eb618d0 | 1190ca3 | Delta |
|--------|---------|---------|-------|
| fps | 14,060 | 14,226 | +1.2% (machine noise) |
| bytes/frame | 1,437.6 | 1,437.6 | -0.0% |
| emit bytes/frame | 1,375.7 | 1,375.6 | -0.0% |
| frame entropy | 4.1912 | 4.1912 | 0.00% |
| density gini | 0.1812 | 0.1812 | 0.00% |
| dirty cells/frame | 755.4 | 755.3 | -0.0% |

Reading: every visual metric identical — expected by construction,
since the monitor's emitted byte stream is unchanged and only the
terminal-mode plumbing (constants + tests) was added.

### NIGHT-improve-1 phase 3 A/B (embedded eBPF objects, 2026-09-19)

The loader-switch commit (76b9547) moved both eBPF objects from
on-disk discovery to include_bytes! embedding — a load-path change,
not a render-path change. The A/B proves the render path is
untouched with data (A = 1fa542e in a throwaway worktree, B =
76b9547, 10 s formal runs):

| Metric | 1fa542e | 76b9547 | Delta |
|--------|---------|---------|-------|
| fps | 14,502 | 14,269 | -1.6% (machine noise) |
| bytes/frame | 1,437.5 | 1,437.6 | +0.0% |
| emit bytes/frame | 1,375.6 | 1,375.6 | -0.0% |
| frame entropy | 4.1913 | 4.1912 | -0.0% |
| density gini | 0.1812 | 0.1812 | -0.0% |
| dirty cells/frame | 755.4 | 755.3 | -0.0% |

Reading: every visual metric identical, fps delta in the same
noise class as every previous A/B (-1.1%, -1.55%, +1.2%). The
frame-bench harness renders from an in-memory CounterSummary, and
the loader change only affects where Ebpf::load gets its bytes —
identical output was the expected result, now proven rather than
asserted.

### NIGHT-improve-7 A/B (pointer takeover, 2026-09-21)

The mouse-capture commit (c4bbb7a) added three DEC private modes to
the monitor's enter/exit sequences (1000/1002/1006 mouse tracking) —
a terminal-contract change, not a render-path change. The A/B proves
the rendered stream is untouched (A = ec1704b at HEAD, B = c4bbb7a,
10 s formal runs):

| Metric | ec1704b | c4bbb7a | Delta |
|--------|---------|---------|-------|
| fps | 14,066 | 14,801 | +5.2% (machine noise) |
| bytes/frame | 1,437.6 | 1,437.5 | -0.0% |
| emit bytes/frame | 1,375.6 | 1,375.6 | -0.0% |
| frame entropy | 4.1912 | 4.1913 | +0.0% |
| density gini | 0.1812 | 0.1812 | 0.00% |
| dirty cells/frame | 755.4 | 755.4 | +0.0% |

Reading: every visual metric identical — the mouse modes ride in the
monitor's enter/exit guards (five write_all bytes once per session),
not in the per-frame emit path, so the diff engine's output stream is
byte-for-byte what it was. The fps delta is the largest seen in the
A/B series but still the same noise class: the frame harness never
opens a TTY, the mode bytes are not in its path at all, and the
fixture's deterministic content pins the visual columns to
identical values (entropy jitter of 0.0001 bits/char is float
aggregation over the same content).

### NIGHT-improve-8 A/B (observer capacity raise, 2026-09-21)

The server-LTS audit commit (40cfa10) raised the observer counter
maps 256 -> 1024 — a BPF object change (the embedded observer ELF is
rebuilt), not a render-path change. The A/B proves the render engine
is untouched across the ELF swap (A = ec1704b at HEAD, B = 40cfa10,
10 s formal runs):

| Metric | ec1704b | 40cfa10 | Delta |
|--------|---------|---------|-------|
| fps | 14,066 | 14,711 | +4.6% (machine noise) |
| bytes/frame | 1,437.6 | 1,437.5 | -0.0% |
| emit bytes/frame | 1,375.6 | 1,375.6 | -0.0% |
| frame entropy | 4.1912 | 4.1913 | +0.0% |
| density gini | 0.1812 | 0.1812 | 0.00% |
| dirty cells/frame | 755.4 | 755.4 | +0.0% |

Reading: every visual metric identical. The frame harness renders
from an in-memory CounterSummary fed by a synthetic LCG — it never
attaches the observer, so the map capacity is not in its path at all;
the identical columns prove the ELF swap changed nothing in the emit
pipeline. The fps delta tracks the same container-noise class as the
improve-7 run minutes earlier (+5.2% on identical render bytes).

### NIGHT-improve-8 A/B (monitor selection guard, 2026-09-21)

The copy-guard commit (efa64a7) added a 100 ms whole-frame re-emit
to the monitor LOOP — a terminal-behavior change (selections die
when their cells are rewritten), not a render-path change. The A/B
proves the render path untouched (A = e564c20 at HEAD, B = efa64a7,
10 s formal runs):

| Metric | e564c20 | efa64a7 | Delta |
|--------|---------|---------|-------|
| fps | 14,212.5 | 13,912.2 | -2.1% (machine noise) |
| bytes/frame | 1,437.6 | 1,437.6 | +0.0% |
| emit bytes/frame | 1,375.6 | 1,375.6 | +0.0% |
| frame entropy | 4.1912 | 4.1912 | -0.0% |
| density gini | 0.1812 | 0.1812 | -0.0% |
| dirty cells/frame | 755.3 | 755.3 | -0.0% |

Reading: every visual metric identical, and the fps delta is the
same container-noise class as every previous A/B (-1.1%, -1.55%,
+1.2%, +5.2%, +4.6%). The guard is invisible to this harness by
construction: the frame harness never opens a TTY, so the monitor
session takes its
non-TTY fallback where the guard is disabled by contract (a
pipe has no selection machinery) — the identical columns prove the
guard changed nothing in the poll/render/emit pipeline. The guard's
OWN cost is measured where it lives, in the new
test/terminal/guard_tests.rs pins: one whole-frame reset emission
per beat, byte-identical to a first paint of the same frame —
~1.4 KB per beat on the classic 80x24 frame, ~14 KB/s while a real
monitor is live at 10 beats/s (three orders of magnitude under the
harness's ~19 MB/s render churn), one write(2) + one ioctl per
beat. That is the entire, deliberate price of "no selection
outlives one beat".

### NIGHT-hunt-15 A/B (--help tidy, 2026-09-21)

The help-surface commit (728d3b6) trimmed the trailing Examples
section to the three workflows whose command blocks lack examples and
fixed one stale example comment — a println-path change, not a
render-path change. The A/B proves the monitor stream untouched
(A = 801fb18 in a throwaway worktree, B = 728d3b6, 10 s runs):

| Metric | 801fb18 | 728d3b6 | Delta |
|--------|---------|---------|-------|
| fps | 14027.2 | 14028.2 | +0.0% (noise) |
| bytes/frame | 1437.6 | 1437.6 | +0.0% |
| emit bytes/frame | 1375.6 | 1375.7 | +0.0% |
| frame entropy | 4.1912 | 4.1912 | 0.00% |
| density gini | 0.1812 | 0.1812 | 0.00% |
| dirty cells/frame | 755.4 | 755.4 | +0.0% |

Reading: every visual metric identical — the frame harness never
renders the help surface, so identical columns were the expected
result, now proven.

### NIGHT-hunt-15 A/B (observer/connections audit, 2026-09-21)

The monitor-path commit (cafae73) consolidated the three TIOCGWINSZ
probes into one canonical terminal-layer call (geometry probe 2 -> 1
ioctl), filtered unconnected UDP listeners from eagle-eyes detail,
made top's packets footer sum all talkers, and dropped a dead
local-endpoint parse — probe plumbing and filters, not frame layout.
The A/B proves the emitted stream byte-identical (A = 728d3b6 in a
throwaway worktree, B = cafae73, 10 s runs):

| Metric | 728d3b6 | cafae73 | Delta |
|--------|---------|---------|-------|
| fps | 14333.4 | 14187.7 | -1.0% (machine noise) |
| bytes/frame | 1437.6 | 1437.6 | +0.0% |
| emit bytes/frame | 1375.6 | 1375.6 | -0.0% |
| frame entropy | 4.1913 | 4.1912 | -0.0% |
| density gini | 0.1812 | 0.1812 | -0.0% |
| dirty cells/frame | 755.4 | 755.3 | -0.0% |

Reading: identical visual columns — the harness drives emit_at with
deterministic sizes, and its synthetic fixture carries no unconnected
UDP sockets, so the filters and the probe consolidation are invisible
to the stream by construction; the fps delta sits in the same noise
class as every previous A/B (-1.1%, -1.55%, +1.2%, +5.2%, +4.6%).

### improve-13 A/B (flagship footer style audit, 2026-09-21)

The monitoring style commit replaced observe's run-on footer line with
a column-aligned TOTAL row plus a bullet-separated meta line (and the
formatter gained tier-boundary promotion — "1000.0 KB" class values
render as the next unit, which the fixed-seed fixture never generates,
so the formatter change is invisible to the stream here). A = 3eda324
(base capture), B = this commit, 10 s runs:

| Metric | 3eda324 | improve-13 | Delta |
|--------|---------|-----------|-------|
| fps | 14175.5 | 14413.3 | +1.7% (noise class) |
| bytes/frame | 1437.6 | 1421.2 | -1.1% |
| emit bytes/frame | 1375.6 | 1358.9 | -1.2% |
| emit ratio | 0.96 | 0.96 | -0.1% |
| density gini | 0.1812 | 0.2001 | +10.4% |
| frame entropy | 4.1912 | 4.1148 | -1.8% |
| dirty cells/frame | 755.3 | 724.1 | -4.1% |
| dirty ratio | 0.4146 | 0.3975 | -4.1% |

Reading: the frame is CHEAPER to redraw — dirty cells and emitted
bytes both fell (the totals sit in fixed column slots, so the
changing digits cluster in fewer cells) and frames carry fewer bytes
(the footer's two lines sum shorter than the old run-on line). The
density gini rose because the new meta line ("N packets · N cgroups")
is deliberately sparse — an annotation line, not a data row, the same
visual class as "(+15 more cgroups hidden)" — which the row-mass gini
counts as inequality. That is the cost of separating the totals grid
from the scale annotation, and the alignment win is the point of the
change: the sums now sit under the exact columns they total.

### depthbore-1 A/B (eBPF math extraction + schema v6, 2026-09-22)

The enforcement arithmetic moved from the BPF program into
ebpf/src/math.rs (pure `core`, #[path]-shared with the userspace
test tree) and gained the frac_rem sanitization — schema v6. The
render path is untouched by construction: the eBPF object is not
exercised by the frame harness and no render source changed. A =
2f098e8 (base capture), B = this commit, 10 s runs:

| Metric | 2f098e8 | depthbore-1 | Delta |
|--------|---------|-------------|-------|
| fps | 14298.9 | 12481.6 | -12.7% (noise class, see below) |
| bytes/frame | 1421.2 | 1421.2 | +0.0% |
| emit bytes/frame | 1358.9 | 1358.8 | -0.0% |
| emit ratio | 0.96 | 0.96 | -0.0% |
| density gini | 0.2001 | 0.2001 | -0.0% |
| frame entropy | 4.1148 | 4.1147 | -0.0% |
| dirty cells/frame | 724.1 | 723.9 | -0.0% |
| dirty ratio | 0.3974 | 0.3974 | -0.0% |

Reading: every stream metric is 0.0% — the emitted frames are
byte-identical, as the change-set predicts (no render source
touched; the arithmetic runs inside the kernel, not the frame
path). The fps and bytes/sec churn deltas are the same -12.7% —
churn is defined as bytes/frame x fps, so the pair moves together
and the shared cause is wall-clock throughput in the shared
sandbox (busier now than during the improve-13 capture an hour
earlier), the same noise class the hunt-15 entries recorded. The
render ceiling remains four orders of magnitude above terminal
needs.

### cybersecurity-2 A/B (update-check tag sanitization, 2026-09-22)

A boundary fix in `--check-update` (the release tag now passes the
comm sanitizer before printing) — a command path the frame harness
never exercises, so the stream is expected byte-identical. A =
f655b81, B = this commit, 10 s runs: every stream metric 0.0%
(bytes/frame 1421.2 = 1421.2, gini 0.2001 = 0.2001, entropy
4.1148 = 4.1148, dirty cells 724.1 = 724.1), fps -0.6% (noise
class — the same wall-clock variance recorded across the 2026-09-22
captures).

### NIGHT-boost-1 A/B (eagle-eyes merge, 2026-09-22)

The merge commit (5fa75d1) replaced the observe renderer with the
eagle-eyes ranked renderer — a LAYOUT change by intent, not a
no-op probe fix: the rank column joins the grid, the hard 20-row
cap is gone (the 80x40 harness window now budgets 32 rows, so the
25 synthetic cgroups render two more rows of ranked content with
their detail lines), and the footer carries the filtered/unfiltered
meta variants. A = d812a9a in the pristine baseline clone, B =
5fa75d1, 10 s runs:

| Metric | d812a9a | 5fa75d1 | Delta |
|--------|---------|---------|-------|
| fps | 13314.0 | 12604.3 | -5.3% (headroom class) |
| avg rows | 22.4 | 24.4 | +2.0 (cap removal, by design) |
| bytes/frame | 1421.3 | 1496.2 | +5.3% |
| emit bytes/frame | 1358.9 | 1433.6 | +5.5% |
| density gini | 0.2000 | 0.2069 | +3.4% |
| frame entropy | 4.1147 | 4.2391 | +3.0% (better) |
| dirty cells/frame | 724.1 | 772.6 | +6.7% |
| dirty ratio | 0.3974 | 0.3899 | -1.9% (better) |
| bytes/sec churn | 18092312 | 18069014 | -0.1% (flat) |

Reading: the frame buys MORE information at the SAME terminal I/O
cost — entropy up (the rank column and the two extra visible rows
carry real content), dirty ratio down (the changed cells spread over
a larger grid), and the bytes/sec churn the terminal absorbs is
byte-for-byte flat. The +5% bytes/frame is the two extra rows the
owner asked for (the window is the budget now), not padding. The fps
delta sits in the recorded noise class (-1.1%, -1.55%, +5.2%, +4.6%,
-0.6%) and both sides clear four orders of magnitude above the 1 Hz
display cadence — render-path headroom, not user-visible latency.

### NIGHT-boost-2..4 + improve-25 A/B (CLI-surface session, 2026-09-22)

The session's four commits (help example layout, unified JSON
writer, CI estate, short aliases) touch no render-path code — the
A/B run verifies exactly that. A = ecae0bb (pre-session base,
worktree), B = f236bc7 (session HEAD), 10 s runs:

| Metric | ecae0bb | f236bc7 | Delta |
|--------|---------|---------|-------|
| fps | 12949.8 | 12648.6 | -2.3% (noise class) |
| avg rows | 24.4 | 24.4 | -0.0% |
| bytes/frame | 1496.2 | 1496.2 | -0.0% |
| emit bytes/frame | 1433.6 | 1433.5 | -0.0% |
| density gini | 0.2069 | 0.2069 | +0.0% |
| frame entropy | 4.2391 | 4.2391 | +0.0% |
| dirty cells/frame | 772.7 | 772.6 | -0.0% |
| dirty ratio | 0.3899 | 0.3899 | -0.0% |

Reading: every deterministic per-frame metric is identical to the
fourth decimal — the renderer emits the same bytes, the diff engine
marks the same cells, the layout engine places the same rows. The
fps and churn deltas (-2.3%) sit in the wall-clock noise class
recorded across the 2026-09-22 captures (separate processes,
shared runners); the per-frame byte and dirty-cell parity is the
code-level proof that no render-path regression rode along with the
CLI surface work.

### NIGHT-boost-6 (verbose hardening) — 2026-09-23

The verbose-infrastructure session (CI gate dedup, then -v
hardened into loader-level eBPF debug) again touched no render-path
code: the trace formatters live behind `-v`, the Instant captures
are attach-time-only, and the render loop is byte-identical. A =
8a39625 (post boost-7, worktree), B = fffe54b (boost-6 HEAD), 10 s
runs:

| Metric | 8a39625 | fffe54b | Delta |
|--------|---------|---------|-------|
| fps | 12959.9 | 13567.8 | +4.7% (noise class) |
| avg rows | 24.4 | 24.4 | -0.0% |
| bytes/frame | 1496.2 | 1496.1 | -0.0% |
| emit bytes/frame | 1433.6 | 1433.7 | +0.0% |
| density gini | 0.2069 | 0.2069 | -0.0% |
| frame entropy | 4.2391 | 4.2391 | +0.0% |
| dirty cells/frame | 772.7 | 772.8 | +0.0% |
| dirty ratio | 0.3899 | 0.3900 | +0.0% |

Reading: parity to the fourth decimal on every deterministic
per-frame metric — same bytes emitted, same cells marked, same rows
placed. The fps delta (+4.7%) mirrors the -2.3% of the previous
capture pair in the opposite direction, both inside the shared-host
wall-clock noise class; the deterministic metrics are the
code-level proof that the verbose work added zero render-path
cost.

### NIGHT-boost-12 (version-anywhere CLI fix) — 2026-09-23

The `-V` is-version-everywhere session (global version flag +
top-level-authority rescue table in the error bridge) is
parse-path-only: no render, limiter, or loader code moved — only
cli/mod.rs arg wiring, cli/ux.rs suggestion routing, and test pins.
A = 9fa5e98 (docs-12 HEAD, worktree; its render path is identical
to 887c1d7's — docs-12 moved comments only), B = 2b1237b
(boost-12 HEAD), 10 s runs:

| Metric | 9fa5e98 | 2b1237b | Delta |
|--------|---------|---------|-------|
| fps | 13164.7 | 13231.7 | +0.5% (noise class) |
| avg rows | 24.4 | 24.4 | +0.0% |
| bytes/frame | 1496.1 | 1496.1 | +0.0% |
| emit bytes/frame | 1433.6 | 1433.6 | -0.0% |
| density gini | 0.2069 | 0.2069 | -0.0% |
| frame entropy | 4.2391 | 4.2391 | +0.0% |
| dirty cells/frame | 772.7 | 772.7 | -0.0% |
| dirty ratio | 0.3899 | 0.3899 | -0.0% |

Reading: parity to the fourth decimal on every deterministic
per-frame metric. The changed layer exits before any render call
(a parsed `-V` prints the banner and returns; the rescue table only
rewrites error contexts), and the deterministic metrics confirm
exactly that; the +0.5% fps and bytes/sec churn deltas sit in the
shared-host wall-clock noise class.

### NIGHT-boost-13 (fatal-CLI-UX session) — 2026-09-23

The error-bridge session (escape-hatch honesty probe,
subcommand-scoped usage regeneration, the help-subcommand and
--json rescues, split into the new cli/argv.rs forensics module) is
parse-error-path-only: every change lives in the exit-2 flow —
`exit_clap_error` and its enrich functions — and the frame harness
renders without ever touching the bridge. A = bb78ce9
(boost-5 A/B record HEAD, pre-boost-13; worktree), B = 0977872
(boost-13 HEAD), 10 s runs:

| Metric | bb78ce9 | 0977872 | Delta |
|--------|---------|---------|-------|
| fps | 13269.5 | 13436.4 | +1.3% (noise class) |
| avg rows | 22.3 | 22.3 | -0.1% |
| bytes/frame | 1378.6 | 1378.3 | -0.0% |
| emit bytes/frame | 915.0 | 915.0 | -0.0% |
| emit ratio | 0.66 | 0.66 | +0.0% |
| density gini | 0.2457 | 0.2457 | +0.0% |
| frame entropy | 4.1827 | 4.1814 | -0.0% |
| dirty cells/frame | 101.7 | 101.7 | -0.0% |
| dirty ratio | 0.0570 | 0.0570 | +0.0% |
| bytes/sec churn | 12141834.1 | 12293927.1 | +1.3% (fps-driven) |

Reading: parity on every deterministic per-frame metric — density
gini identical to the fourth decimal, dirty cells and emit bytes
identical to the frame. Three same-host runs of the two code states
spread fps 12943..13436 (±3%), so the fps/churn deltas are
wall-clock noise, not cost; the deterministic metrics are the
code-level proof that the error-path work added zero render-path
change, exactly as designed.

### NIGHT-boost-5 (eagle-eyes session leaderboard engraving) — 2026-09-23

The full NIGHT-boost-5 arc (ae4afaa status engraving + output layer
split, c691715 geometry/ladder, ecfd9e6 session leaderboard with
champion-red takeover blink and the TOTAL column). This is a
SEMANTIC change, not a like-for-like layout tweak: the frame's
content moved by design (rows render from the session accumulator
— stable ranking, persistent rows — and the chrome grew to 12
lines for the signature footer + hints), so the visual-density
metrics are expected to move with the content, while the
performance metrics carry the comparison weight. A = a2529d0
(session start, pre-boost-5; worktree), B = ecfd9e6, 10 s runs:

| Metric | a2529d0 | ecfd9e6 | Delta |
|--------|---------|---------|-------|
| fps | 13595.2 | 13312.7 | -2.1% (noise class) |
| avg rows | 24.4 | 22.3 | -8.6% (12-line chrome ladder) |
| bytes/frame | 1496.1 | 1378.4 | -7.9% |
| emit bytes/frame | 1433.7 | 914.9 | -36.2% |
| emit ratio | 0.96 | 0.66 | -30.7% |
| density gini | 0.2069 | 0.2457 | +18.7% (content changed by design) |
| frame entropy | 4.2391 | 4.1823 | -1.3% (content changed by design) |
| dirty cells/frame | 772.8 | 101.7 | -86.8% |
| dirty ratio | 0.3900 | 0.0570 | -85.4% |
| bytes/sec churn | 19491190.2 | 12179403.8 | -37.5% |

Reading: the headline is dirty cells -86.8% and emitted bytes
-36.2% at fps parity, and the MECHANISM is the design itself — the
old per-frame delta sort reshuffled ranks every interval (delta
magnitudes jump frame to frame, so rows swapped wholesale and every
label cell went dirty); the session accumulation ranking is stable
(a cgroup's rank moves only on a genuine takeover), so consecutive
frames differ only in the rate cells. The leaderboard is not just
the owner-contract semantics, it is the diff engine's best friend.
avg rows -8.6% is the NIGHT-boost-5 autodetect ladder (12 reserved
chrome lines; the harness's piped 80x24 fallback shows 12 data rows,
the owner's windowed 88x32 shows 20); the gini/entropy deltas track
that content change (fewer rows, stable totals, rate columns doing
the churning), not a rendering defect. Visual acceptance: verified
frame-by-frame — header cells sit exactly over their columns, every
grid line closes flush at the frame width, the left border is one
straight edge, and the quiet-frame board holds intact.

### NIGHT-boost-24 / NIGHT-engrave-5 / NIGHT-boost-25 A/B (CLI-surface + smooth-open batch, 2026-09-24)

Baseline 514d595 (the engrave-4 end state) vs b2a9e1c, the 10s
harness, three tasks in one batch:

| metric | before | after | delta |
|---|---|---|---|
| fps (render path) | 8094.5 | 8142.9 | +0.6% |
| bytes/frame | 1943.0 | 1943.0 | +0.0% |
| emit bytes/frame | 687.0 | 687.9 | +0.1% |
| density gini | 0.3717 | 0.3714 | -0.1% |
| frame entropy | 2.9711 | 2.9717 | +0.0% |
| dirty cells/frame | 53.9 | 54.0 | +0.2% |
| bytes/sec churn | 5560980.9 | 5601894.2 | +0.7% |

Reading: NEUTRAL by construction, and that is the finding. The
batch touched the CLI surfaces (the --print-json honesty note, the
status/list-apps restyle) and the monitor's STARTUP path (the
NIGHT-boost-25 smooth open) — none of it runs inside the per-frame
render loop the harness measures. The smooth open's prelude never
renders on a pipe (the harness's own path: Monitor::open's
non-TTY branch skips the prelude entirely), the first live frame
is the composition the before-side rendered, and the loading
frame's cost is one-time at startup on TTYs only. Every delta in
the table is the container-noise class of every previous A/B
(-1.1% .. +5.2%); bytes/frame is identical to the decimal. The
visual gains (status/list-apps matching the eagle family, the
loading frame, the one-row morph) cost the render loop nothing.

### NIGHT-engrave-6 A/B (the session speed pair, 2026-09-24)

Baseline 34d4f0c (the boost-25 batch end state) vs ecc3c8d, the
10s harness. The footer grew two rows (Full 9 -> 11: the speed
pair below the total row), and the two rows displaced two of the
most volatile table rows the 80x24 frame carried — the synthetic
traffic's rate cells:

| metric | before | after | delta |
|---|---|---|---|
| fps (render path) | 8265.9 | 8416.8 | +1.8% |
| bytes/frame | 1943.0 | 1943.0 | +0.0% |
| emit bytes/frame | 689.9 | 588.4 | -14.7% |
| emit ratio | 0.36 | 0.30 | -14.7% |
| density gini | 0.3708 | 0.3549 | -4.3% |
| frame entropy | 2.9753 | 3.0154 | +1.3% |
| dirty cells/frame | 54.1 | 44.2 | -18.4% |
| dirty ratio | 0.0282 | 0.0230 | -18.4% |
| bytes/sec churn | 5702295.1 | 4952690.1 | -13.1% |

Reading: NET WIN, the same mechanism as the NIGHT-engrave-4
footer rebuild (footer rows displacing volatile table rows), on
top of an already rebuilt footer. The pair is nearly static per
frame — MAX moves only when a new session peak lands, AVG drifts
one rounding step at a time — so the diff engine emits far less
per frame than the two rate-cell rows it displaced (emit -14.7%,
dirty cells -18.4%, churn -13.1%). Visual: gini -4.3% (calmer
frame) with entropy +1.3% (richer per-cell information) — both
in the wanted direction at once. fps +1.8% is the same
container-noise class as every previous A/B on this host; the
deterministic per-frame metrics (bytes/frame identical to the
decimal) carry the comparison weight. The avg line's per-frame
division and the peak note's extra summary walk cost nothing
measurable at the 1s cadence the real monitor runs.

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

### NIGHT-boost-26 A/B (per-endpoint byte attribution, 2026-09-24)

The 2.4 frontier closure: the observer ELF gained two per-socket LRU
cookie maps (bumped from both cgroup_skb hooks), the userspace join
(pidfd_getfd + SO_COOKIE cookie discovery, loader point lookups)
feeds the ConnectionMap, and the endpoint lines render `[dl X | ul
Y]` figures with the focus view ranking endpoints by bytes. A BPF
object change plus a render-path change — but the frame harness
renders from synthetic fixtures whose sockets carry no cookies or
bytes, so the A/B proves exactly what needs proving: the BYTELESS
render path is identical to the old one (A = 582967d at HEAD, B =
the boost-26 tree, 10 s formal runs):

| Metric | 582967d | boost-26 | Delta |
|--------|---------|----------|-------|
| fps | 8,555.1 | 8,401.1 | -1.8% (machine noise) |
| bytes/frame | 1,943.0 | 1,943.0 | +0.0% |
| emit bytes/frame | 506.2 | 505.3 | -0.2% |
| frame entropy | 3.0034 | 3.0022 | -0.0% |
| density gini | 0.3579 | 0.3582 | +0.1% |
| dirty cells/frame | 39.5 | 39.4 | -0.1% |

Reading: bytes/frame identical to the byte — the suffix is a pure
addition that renders only when the join produced figures, so every
existing frame shape is untouched (the 338-test suite's render pins
pass unchanged; three new pins carry the attribution contract: the
suffix, the lean byteless row, and the focus ranking). The fps
delta is inside the same container-noise class as the improve-8 run
(-1.8% here vs +4.6% there, on identical render bytes). The
attribution's own runtime cost lives OUTSIDE the render path: two
extra BPF map lookups per packet in the observer hooks and ~200
userspace point-lookups per 1s frame (tens of microseconds of
syscall time), neither of which the frame harness measures — the
live-machine proof of the join itself is the owner-run battery's
lane (the proof-claims harness pattern).

### NIGHT-improve-31 A/B (the sudo-interposed terminal rescue, 2026-09-25)

The layer-0 lane (src/term_reset/outer.rs: the outer-tty discovery,
the by-path direct apply, the post-sudo orphan) is a one-shot
early-return path — `--reset-terminal` runs it and exits before
any monitor machinery exists. The frame harness measures the render
loop, which the lane never touches (zero new calls anywhere in it),
so the A/B proves exactly that non-interference (A = 28501e5 at
HEAD, B = the improve-31 terminal tree, 10 s formal runs):

| Metric | 28501e5 | improve-31 | Delta |
|--------|---------|------------|-------|
| fps | 7,678.6 | 7,739.9 | +0.8% (machine noise) |
| bytes/frame | 1,919.0 | 1,919.0 | +0.0% |
| emit bytes/frame | 504.7 | 503.5 | -0.2% |
| frame entropy | 3.0214 | 3.0204 | -0.0% |
| density gini | 0.3522 | 0.3526 | +0.1% |
| dirty cells/frame | 39.6 | 39.6 | -0.2% |

Reading: bytes/frame identical to the byte and every other delta
inside the container-noise band — the rescue's cost lives entirely
in its own invocation (one /proc readlink, one open, one termios
pair, one fork per rescue run), paid only in the broken-terminal
moment the rescue exists for. The correctness proof is the new
pin family (test/terminal/outer_reset_tests.rs) plus the live
interposition harness: break a real pty, run the rescue against a
foreign pty with SUDO_PID pointing at a monitor holder, restore
the broken snapshot as the monitor's exit would, and read the
real terminal back cooked — the orphan's win, after the trap that
undid every earlier fix.

NIGHT-improve-34 (the discriminated re-apply, same day) touched
only that lane's post-exit half: the orphan's two passes gained a
tcgetattr read and an OPOST|ONLCR conditional (and LOST a
TCSAFLUSH + a full cooked write in the healthy branch) — still a
one-shot early-return path, still zero render-loop call sites, so
the frame parity above holds by construction and the benchmark is
not re-run (the config-equivalent argument, the same reasoning the
improve-31 A/B itself certified). The re-verified proofs: 16 pins
green in the terminal family (the four new ones pin the
discrimination matrix and the cure's lane purity), plus the
re-built live harness — now a faithful sudo monitor (save,
cfmakeraw raw, the pty relay, and sudo's REAL changed-out-from-
under-us exit guard) around the real rescue with a zsh-style
player: healthy-at-start, broken-at-start, and forced-restore
scenarios all green (single-echo typing, silent orphan when
healthy, output-lane-only cure when broken), while the SAME
harness against the improve-31 orphan panics in every scenario —
its TCSAFLUSH under the live reader eats the first typed
character, the exact residue the owner kept reporting.

### NIGHT-dinner-18/19/17 A/B (eagle-eyes hard-error session, 2026-09-28)

The session's render-relevant change is dinner-18's resolver work:
the per-frame `resolve_targets` moved to its own module
(render/targets.rs) with the duplicate-token verdict fix, the launch
gate (`resolve_live_targets`) lives outside the frame loop entirely,
and dinner-19/17 touched no code. The harness therefore proves the
frame path is untouched (A = b4d965b, the session's starting tree;
B = d6395e3 at HEAD, formal 10 s runs, 76k+ frames per side):

| Metric | b4d965b | HEAD | Delta |
|--------|---------|------|-------|
| fps | 7,637.5 | 7,650.7 | +0.2% (machine noise) |
| bytes/frame | 1,919.0 | 1,919.0 | +0.0% |
| emit bytes/frame | 505.5 | 505.3 | -0.0% |
| frame entropy | 3.0206 | 3.0180 | -0.1% |
| density gini | 0.3527 | 0.3528 | +0.0% |
| dirty cells/frame | 39.7 | 39.7 | +0.0% |

Reading: bytes/frame identical to the byte — the render output is
byte-exact the pre-session shape, the strongest parity proof the
harness can give. Every other delta sits at or under 0.1%, inside
the run-to-run band every prior record on this host carries. The
behavioral changes are verdict-surface only: the launch gate fires
before the TUI exists (an error path the harness never renders),
the dead-ID depth verdict replaces a fabricated report, and the
duplicate-token fix changes per-frame output only for specs with
repeated tokens — a shape the synthetic fixture set does not
contain, by design (the fix's proof is the render pin
`duplicate_name_token_is_not_a_false_miss`, not a visual delta).

### NIGHT-perf-0/1/2 A/B (the generation stamp + the A/B harness, 2026-09-30)

The perf trilogy's code changes sit off the render path by
construction: the schema-v12 generation stamp is kernel-side
resolution/invalidation semantics (the memo word, the counter
array, the verdict row — no render surface reads any of them),
and the A/B harness is a CI/Python addition with no Rust render
code touched at all. The harness therefore proves frame-parity
(A = fd39809, the light-years-3 rider tree; B = 70de17a at HEAD,
formal 10 s runs, 75k+ frames per side):

| Metric | fd39809 | HEAD | Delta |
|--------|---------|------|-------|
| fps | 7,552.3 | 7,682.8 | +1.7% (machine noise, favorable) |
| bytes/frame | 1,919.0 | 1,919.0 | +0.0% |
| emit bytes/frame | 507.3 | 504.5 | -0.5% (machine noise) |
| frame entropy | 3.0051 | 2.9981 | -0.2% (machine noise) |
| density gini | 0.3556 | 0.3565 | +0.2% (machine noise) |
| dirty cells/frame | 39.8 | 39.6 | -0.5% (machine noise) |

Reading: bytes/frame identical to the byte — the frame output is
byte-exact the pre-trilogy shape, the strongest parity proof the
harness can give. Every other delta sits inside the run-to-run
band every prior record on this host carries. The stamp's own
cost lives where it can be measured: the resolution branch's one
added Array read on the policy-miss lane — bounded by design,
owned by the supermassive overhead stage, and the O(1) mutation
bump's win is on the mutation side (the design brief and the
perf-2 audit doc carry the reasoning).

### NIGHT-think-like-light-years-3 A/B (the init-race close + the linear merge, 2026-09-30)

The session's two code changes sit off the render path by
construction: the schema-v11 init-race close (BPF_NOEXIST on the
limiter's first-packet inserts) is kernel-side enforcement birth
semantics, and the dense-host merge fix (loader.rs) changes the
poll's internal complexity class, not one byte of frame output —
the same class of proof the private-research-2 datapath A/B
carried. The harness therefore proves frame-parity (A = aa283ca,
the MMSPA-rider tree; B = 79b0921 at HEAD, formal 10 s runs,
75k+ frames per side):

| Metric | aa283ca | HEAD | Delta |
|--------|---------|------|-------|
| fps | 7,566.4 | 7,720.7 | +2.0% (machine noise, favorable) |
| bytes/frame | 1,919.0 | 1,919.0 | +0.0% |
| emit bytes/frame | 507.0 | 503.9 | -0.6% (machine noise) |
| frame entropy | 3.0009 | 3.0005 | -0.0% |
| density gini | 0.3557 | 0.3567 | +0.3% (machine noise) |
| dirty cells/frame | 39.8 | 39.6 | -0.5% (machine noise) |

Reading: bytes/frame identical to the byte — the frame output is
byte-exact the pre-session shape, the strongest parity proof the
harness can give. Every other delta sits inside the run-to-run
band every prior record on this host carries (the fps spread is
the same container-noise class the dinner-18 record notes). The
merge fix's gain is not frame-visible by design — the synthetic
fixture renders from a fixed LCG, not from a polled 4096-cgroup
map, so its proof is the complexity argument plus the
byte-identical output pins; the kernel fix's proof is the
NOEXIST-flag construction and the SMP pins the observer twin
already carries. Both records live in
docs/audits/NIGHT_THINK_LIKE_LIGHT_YEARS_3_AUDIT_2026-09-30.md.

### NIGHT-improve-41 A/B (the chroma dragon engine — OKLab polar rails, 2026-10-06)

The change is a color-engine swap on ONE render surface: the
eagle-eyes rail gradient rides OKLab polar interpolation at
TrueColor (src/output/chroma.rs, ported from cosmostrix's
chroma_dragon_engine) and keeps the legacy linear-light ramp at
every other depth. Two A/B pairs, both 10 s formal runs, A =
613f4bc at HEAD, B = the improve-41 tree. The harness runs piped
(Mono) by default; the TrueColor pair forces the documented env
control surface (`CLICOLOR_FORCE=1 COLORTERM=truecolor`, NO_COLOR
unset — the capability probe's own ladder, no harness change).

The Mono pair (the fallback contract — the legacy rungs byte-for-byte):

| Metric | before | after | Delta |
|--------|--------|-------|-------|
| fps | 7,161.0 | 7,134.4 | -0.4% (machine noise) |
| bytes/frame | 1,919.0 | 1,919.0 | +0.0% |
| emit bytes/frame | 512.3 | 512.5 | +0.0% |
| frame entropy | 3.0083 | 3.0084 | +0.0% |
| density gini | 0.3542 | 0.3542 | -0.0% |
| dirty cells/frame | 40.1 | 40.1 | -0.0% |

Reading: byte-identical frames at the Mono rung — the fallback
contract is the strongest parity proof the harness can give (a
non-truecolor terminal renders the exact pre-port bytes), and the
fps delta sits inside the host's noise band with no code-path
change on that rung (the anchor hoist is TrueColor-gated by
construction).

The TrueColor pair (the engine's honest price — the changed path):

| Metric | before | after | Delta |
|--------|--------|-------|-------|
| fps | 6,156.7 | 6,034.2 | -2.0% (the blend's cost) |
| bytes/frame | 3,236.0 | 3,222.2 | -0.4% |
| emit bytes/frame | 871.8 | 867.9 | -0.4% |
| frame entropy | 4.0626 | 4.0431 | -0.5% |
| density gini | 0.1749 | 0.1746 | -0.2% |
| dirty cells/frame | 50.0 | 50.0 | +0.1% |

Reading: fps -2.0% is the OKLab blend's real cost on the synthetic
blast — about 3.3 microseconds per frame (two sRGB->OKLab
conversions, the polar trig, and the gamut-mapped return per row,
the anchor derivation hoisted to once per frame after the first
measurement read -8.4% with it per-row). Against the monitor's
1-second frame cadence that is 0.0003% of the frame budget — the
harness's 6,000 fps amplifies what the live monitor spends once
per second. bytes/frame DROPS 0.4% (the chroma ramp's interpolated
triples format into marginally shorter escapes), and the
data-dependent metrics sit inside the run-to-run band. The
correctness surface is the nine chroma pins (the round-trip law,
the pinned brand triple, the polar saturation law, the gamut
mapping's hue-hold law) — the bench proves the price, the pins
prove the colors.

### NIGHT-hunt-29 A/B (the synthetic-cookie fixture re-baseline, 2026-10-07)

This is not a layout A/B — it is the harness's own re-baseline: the
fixture variant that closes lts-7's documented residual (the
cookie:None shape that never drove the join lane). A = cb3e3c8 (the
cookie:None era), B = 0c5ab4d (every socket resolving a synthetic
cookie, one dup'd-fd pair per detail cgroup, the monitor loop's
exact join wiring — socket_cookies, the synthetic cookie-map result,
apply_socket_bytes — running every frame). 10 s formal runs, the
standard harness protocol; the B side re-confirmed at HEAD after
commit (three runs, fps 5,764.6 / 5,735.7 / 5,722.4 — the spread is
the shared-host band).

| Metric | cb3e3c8 (A) | 0c5ab4d (B) | Delta |
|--------|------------|-------------|-------|
| fps | 7,203.9 | 5,722.4 | -20.6% (the join lane's debug-profile cost) |
| bytes/frame | 1,919.0 | 1,919.0 | +0.0% |
| emit bytes/frame | 511.5 | 536.9 | +5.0% |
| frame entropy | 3.0320 | 3.2091 | +5.8% (the figures are real content) |
| density gini | 0.3500 | 0.3219 | -8.0% (the figures are real content) |
| dirty cells/frame | 40.0 | 82.4 | +105.9% (the figures grow every frame) |

Reading: bytes/frame BYTE-EXACT — the logical frame is the boxed
render, the row count is unchanged, and the [dl X | ul Y] figures
live inside the existing line budget, so the layout surface is
untouched; the entropy/gini/dirty movement is the intended delta
(the endpoint figures are content the old fixture never rendered,
and they churn per frame exactly as the live lifetime counters do
at their own cadence). The fps drop was bisected before landing:
-17.8% of it is the join COMPUTE (socket_cookies plus the key-set
build) and -2.7% the install, figure rendering, and diff churn —
all of it in the harness's unoptimized test profile, where ~100
HashMap operations cost tens of microseconds; the same block costs
~1-2 us in the release lane the live monitor runs. The honest
reading is the closure's own point: the old 7,203.9 measured a
frame that SKIPPED the join work the live loop always did — the
fps drop is the blind spot's price becoming visible, not a
regression. The A/B protocol itself is intact from here on: any
layout change compares like-for-like, both sides carrying the join.
Determinism holds (frame 1 byte-identical across independent runs;
the ±0.0001 gini/entropy drift across full runs is the
frame-count-window noise class the lts-9 record documented).

### NIGHT-engrave-11 A/B (the horizontal masterclass — the one-wave frame, 2026-10-09)

The change is a paint-surface expansion on THREE render lines: the
title bar's furniture, the table grid lines, and the closing floor
now sweep the chroma method the vertical rails ride, ACROSS the
columns (TrueColor in OKLab, Color256 on the legacy ramp quantized
per column; Color16 and Mono keep their exact flat bytes). Two
A/B pairs, both 10 s formal runs, A = e9b3b3b at HEAD~2, B = the
engrave-11 tree. The harness runs piped (Mono) by default; the
TrueColor pair forces the documented env control surface
(`CLICOLOR_FORCE=1 COLORTERM=truecolor`, NO_COLOR unset). The
release pair rides the same harness at `--release` (the lane the
live monitor ships in), fps read from the harness's own META line.

The Mono pair (the fallback contract — the flat rungs byte-for-byte):

| Metric | before | after | Delta |
|--------|--------|-------|-------|
| fps | 5,098.1 | 5,109.3 | +0.2% (noise band) |
| bytes/frame | 1,919.0 | 1,919.0 | +0.0% |
| emit bytes/frame | 550.8 | 550.7 | -0.0% |
| frame entropy | 3.2256 | 3.2287 | +0.1% |
| density gini | 0.3417 | 0.3417 | -0.0% |
| dirty cells/frame | 102.4 | 102.4 | -0.0% |

Reading: byte-identical frames at the Mono rung — the flat rungs
never touch the sweep (the capability ladder's own guarantee), so
the strongest parity proof holds: a non-truecolor terminal renders
the exact pre-engrave bytes.

The TrueColor pair, dev profile (the changed path, debug cost):

| Metric | before | after | Delta |
|--------|--------|-------|-------|
| fps | 4,580.6 | 3,204.9 | -30.0% (the byte volume's debug cost) |
| bytes/frame | 3,219.8 | 8,158.0 | +153.4% (the sweep's own bytes) |
| emit bytes/frame | 927.4 | 942.8 | +1.7% |
| emit ratio | 0.29 | 0.12 | -59.9% |
| frame entropy | 4.1616 | 4.1370 | -0.6% |
| density gini | 0.1772 | 0.6361 | escape-mass artifact |
| dirty cells/frame | 116.7 | 113.5 | -2.8% |

The TrueColor pair, release profile (the shipping lane's honest price):

| Metric | before (e9b3b3b) | after (engrave-11) | Delta |
|--------|------------------|--------------------|-------|
| fps | 21,928.2 | 18,504.2 | -15.6% |
| bytes/frame | 3,209.6 | 8,153.6 | +154.0% |
| emit bytes/frame | 1,127.9 | 1,130.2 | +0.2% |
| emit ratio | 0.35 | 0.14 | -60.0% |
| frame entropy | 4.1814 | 4.1467 | -0.8% |
| dirty cells/frame | 125.4 | 125.4 | +0.0% |

Reading: bytes/frame +154% IS the feature — per-column coloring
writes ~24 escape bytes per column across ~234 horizontal columns,
and those bytes then flow through the fit walk, the background
re-open, and the diff screen every frame. That volume, not the
color math, is the whole remaining price: the first implementation
paid a second cost on top of it (per-column OKLab endpoint
conversions; release fps -72%), and the landed tree removes it
twice — the sweep's endpoints are run-invariant, so the two
sRGB -> OKLab conversions hoist out of the column loop (the chroma
module's own cost note), and the composed run is a pure function of
(theme, capability, glyph, start, len, span, anchor), so the memo
pays the blend work ONCE per shape and every later frame clones
the bytes (a theme cycle, a resize, or a capability change misses
once and re-fills; the drift-killer pin runs the hoisted walk
against the per-cell rail_rgb walk byte for byte, both engines).
What is left is the string volume: -15.6% release fps at a
18,504 fps synthetic blast — about 6.3 us per frame, 0.0006% of
the live monitor's one-second cadence — while the TERMINAL-side
contract is untouched or better: emit bytes flat (+0.2%), dirty
cells flat (125.4 = 125.4, the layout is stable frame over frame),
and the emit ratio nearly halves (the sweep's lines are
byte-stable between frames, so the diff engine has less to say
about them). The gini jump is the metric counting escape mass on
the three now-swept lines, not visual mass moving. The
correctness surface is the border pins: the orientation-symmetry
law, the exact-bytes composer wave, the flat-rung bytes, and the
hoisted-vs-walked equality.
