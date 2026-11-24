<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# The zelynic Innovation Ledger

This page records the research and innovations that define zelynic's
enforcement core. It is the result of the owner's own thinking and
design research, conducted together with AI, in October 2026 —
written simple on purpose, so a new maintainer (or a curious
competitor) can learn the whole engine in one sitting. Each entry
names the problem it kills, the mechanism in one breath, and the
file where the truth lives. The canonical version-by-version history
is `ebpf/src/schema.rs`; this page is the map, not the ledger.

One law runs through everything below: **no daemon, no config file,
no agent** — every mechanism lives in the eBPF datapath or in a
one-shot CLI run, and the kernel state is the only truth. The pure
cores (`mmspa.rs`, `drr.rs`, `math.rs`, `ecn.rs`, `quic.rs`,
`rate_ring.rs`, ...) are `core`-only files compiled into BOTH the
kernel object and the userspace test tree, so every law below is
pinned by rootless unit tests, not by hope.

## The engine, named

The core these fourteen compose has a name (NIGHT-improve-68):
**the cosmic dragon engine** — the zelynic enforcement core, the
heart of the cosmic dragon architecture. The architecture is the
body (pure eBPF, one hooking layer, no daemon); the engine is the
heart (the verdict path that body exists to run). The naming keeps
the family's one law — one identity, one name, many engines:
cosmostrix's diff-based renderer is **the cosmic dragon render
engine** (its `cosmic_dragon_engine` module path, whose discipline
`src/terminal/diff.rs` ports), and this engine, the family's
default, is the one that counts bytes. The canonical definition:

> **the cosmic dragon engine** — the zelynic enforcement core: the
> six-layer verdict path that turns a binary allow/drop hook into a
> smooth shaper. MMSPA resolves which budget owns a packet (subtree
> truth); the token pool refills with sub-byte precision, SMP-safe,
> no false drops; DRR shares it fair across processes (learned-share,
> starvation killed); CAKE-shaped flow buckets keep the quiet flow's
> latency; QUIC-aware attribution restores the fair unit for HTTP/3;
> and the ECN-first debt law converts the would-be drop into a CE
> mark the sender converges on without losing a packet — debt paid
> from the stream's own tokens, so the aggregate stays exactly
> `rate × t + burst + 64 KiB` under every adversarial shape. A
> policer with a shaper's manners: the first verdict-only engine
> that polices smooth.

The honest edge is written into the definition on purpose: the
smooth lane is the ECT lane. Non-ECT traffic still meets the drop
when the burst is spent — that is the physics of a verdict-only
hook, damped by the burst allowance and the GSO admit floor, never
hidden. "Polices smooth" is exact for the lane that can hear the
signal, and the ledger never pretends otherwise.

## The arc above the engine

The fourteen scales, the heart they beat with (MMSPA and DRR), the
eyes that watch (the lazy camera and bypass detection), and the
claws that grip the kernel (the eBPF objects and their loaders)
compose one whole with its own name (the arc consolidation,
2026-11-03): **the cosmic dragon arc** — the official umbrella for
zelynic's entire architectural stack. Where this page is the
per-scale ledger and the architecture doc is the body, the arc is
the whole animal: the canonical index, the estate map (Scales,
Heart, Eyes, Claws), and the owner's quota-saver roadmap all
live in [COSMIC_DRAGON_ARC.md](COSMIC_DRAGON_ARC.md). When a doc,
a license, or a roadmap says "the cosmic dragon arc", it means
everything the entries below detail.

## The fourteen, in dependency order

**1. MMSPA — Multi-Micro Sub-Process Aware** (`ebpf/src/mmspa.rs`).
The subtree hole: a policy written for cgroup A must
police A AND every descendant socket (A/**), sharing one token
budget — a socket born in a child cgroup that did not exist at apply
time must not escape. The walk resolves the policy through
ancestor levels in the BPF program itself, with generation-stamped
memos so a fresh budget never inherits a stale one. Found live by
the owner (a 100kb cgroup's subprocess downloading >1mbps), closed
in the datapath.

**2. Fair-Shared Bucket — DRR inside MMSPA** (`ebpf/src/drr.rs`,
schema v13). When several processes share one limited cgroup, FCFS
lets one loud subprocess starve its siblings. The shared budget is
handed out Deficit-Round-Robin: each member draws a bounded quantum,
unused quantum carries forward, and the aggregate stays exactly the
policy. The starvation shape (one subprocess at ~100%, siblings at
~0%) becomes bounded shares.

**3. CAKE-style flow isolation inside the cgroup** (`ebpf/src/cake_flow.rs`,
`drr_flow*.rs`, schema v20). The same fairness problem one level
down: two flows inside ONE cgroup (a download and an SSH session)
still strangle each other under a single bucket. Flows are isolated
per-connection and scheduled flow-fair, the CAKE insight carried
into a cgroup policer — the quiet flow keeps its latency while the
bulk flow eats its own share.

**4. Per-socket limiting — beyond the cgroup** (schema v15,
`--per-socket`). The cgroup is the unit, but sometimes the promise
is per-CONNECTION: each socket gets its own bucket, keyed by
`bpf_get_socket_cookie`, attributed with no tracepoint. A group
policy remains the shared-budget answer; the option opts a row into
individual budgets when that is the honest shape.

**5. QUIC-aware attribution** (`ebpf/src/quic.rs`, schema v22).
QUIC (HTTP/3) multiplexes every connection of a session over ONE
UDP socket — so the socket cookie the per-socket and flow lanes
keyed by collapsed all of a browser's QUIC connections into one
bucket. When the QUIC header carries a finer truth (the connection
id), the lanes key by CID instead; short-header CID length is
learned, never guessed. The refusal is documented, never silent.

**6. ECN-first policing** (`ebpf/src/ecn.rs`, schema v19; the CE
ledger, schema v26). A policer that can mark instead of drop
should: an ECT-capable packet over budget is delivered CE-marked
and its bytes charge a debt word the budget's own refills pay
back — the sender backs off at the transport layer instead of
paying retransmits. Non-ECT traffic refuses the helper and drops
exactly as before. Debt is keyed by generation-prefixed budget,
so no fresh budget inherits a predecessor's debt. The v26 ledger
(night-spark-4, the quota saver's Layer 2) makes the lane's own
truth readable: `book_rescue` books every delivered CE-marked
packet into `ce_marked_packets` / `ce_marked_bytes` at the exact
spot the drop booking moves to the allowed column — a refused mark
(non-ECT, a debt at its cap) never reaches the words — and `status
--print-json` names the pair on every limit row, so convergence is
measurable. Rootless pins: `ecn_tests.rs`, `ecn_socket_tests.rs`,
the v26 layout/JSON pins in the display and types suites; live
proof: `scripts/bench/ecn-probe.sh` (the cgroup UDP legs witnessed
by the receiver's IP_RECVTOS cmsg, the non-ECT control leg, the
ledger cross-check, the tcpdump egress witness, the internet TCP
leg, the QUIC leg).

**7. Guaranteed minimum** (`src/commands/guarantee.rs`,
`ebpf/src/drr_guarantee.rs`, schema v24). A rate cap with no floor
lets the fair scheduler hand a busy sibling everything: the
guarantee bracket (`--floor` / `--ceil`) writes a minimum the DRR
draw honors before any contention. Validated against the resolved
rates BEFORE the root ask — a contradictory bracket surfaces its
wording with the numbers it would have policed.

**8. In-kernel time-series ring** (`ebpf/src/rate_ring.rs`,
schema v14). Userspace rate math differentiates two counter
snapshots — miss a sample and the peak between them is averaged
away. The kernel keeps the last eight one-second windows per
policed cgroup per direction, so the SHAPE of a target's traffic
survives between polls. The honesty contract: the ring is a
monitor, the ledger is the truth — the ring never invents bytes.

**9. Self-proving enforcement** (`src/commands/probe.rs`,
`--no-test` to skip). "Applied" is a claim; "VERIFIED" is a
measurement. After an apply, the probe runs its own traffic through
the live policy and reads the verdict from the enforcement ledger —
the tool proves its own enforcement instead of trusting the write.
The lock's scope is the apply, never the probe.

**10. Bypass detection, shadow mode** (`src/ebpf/bypass.rs`, rides
`eagle-eyes`). Limits police the cgroup hooks; traffic that exits
through an interface the hooks never see (a VPN, a raw socket
escape) is invisible to the counters. The shadow audit compares the
window's interface-level deltas against what the hooks booked and
flags the gap — detection only, named honestly, with floors that
keep ARP and header noise from crying wolf.

**11. Container-native resolution** (`src/ebpf/identity/container/`,
`docker://nginx`, `k8s://prod/web-abc`). Containers are not a
separate feature — a container reference is just another way to
NAME a cgroup. The URI resolves to the workload's cgroup id through
the docker Engine API or the kubelet, read-only, and every
downstream surface is the same single-lane machinery.

**12. Atomic multi-target with rollback** (`src/ebpf/limiter/atomic.rs`).
A `::` list applies whole or fails whole: pre-flight resolution of
every segment, then a group write whose mutation ledger restores
each policy to its pre-apply value on any mid-flight failure. The
sweep lane (`--all`) deliberately stays best-effort — its target
list is a snapshot of live apps, and an app exiting must not abort
the fleet.

**13. Time-windowed policies, CLI-only** (`--during`, schema v23).
"Block the kid's laptop at bedtime, lift it at dawn" with no daemon
to keep alive: the window rides the policy row itself, wall-clock
translated to the monotonic clock at write time so NTP slew and
manual `date -s` cannot move an expiry. The grammar is one shape
(a span from the apply instant); legacy rows are honored forever.
Scripts read the expiry straight off `status --print-json`:
`limits[].window` carries the state vocabulary and the span's wall
instants (`end_wall_ns` is the expiry, ns since epoch), and is
honestly absent on windowless rows.

**14. RECWN receive-window control** (schema v25, night-spark-2 —
the quota saver's Layer 1). The owner's coined name for the
receive-window lane: a policed cgroup's own sockets advertise a
window shaped like the policy's bandwidth-delay product (rate x
200 ms delivery-cadence estimate — raised from the briefed 50 ms
by the live E2E evidence, the scale-14 entry below names why —
clamped to [2 x MSS, 1 MiB]), so the remote TCP
sender holds its in-flight bytes down BEFORE the ingress link
bills them — the one knob that answers README limitation #15's
physics (a dropped download saves no quota; a slowed sender does).
The lane rides the limiter object's first sock_ops program
(`zelynic_recwn`, attached at the cgroup root beside the two
enforcement hooks) and one pinned socket-local hint map. Two
kernel truths shaped the build, both verified against v5.15
source: the `BPF_SOCK_OPS_RWND_INIT` return value is an MSS
multiplier where 0 is the OS default (returning the sketched
"1 for default" would have clamped every unpoliced socket on the
machine to one segment — the program answers 0 and
`bpf_setsockopt(SO_RCVBUF)` carries the clamp byte-exactly), and
sock_ops on the 5.15 floor cannot resolve its own cgroup
(`bpf_get_current_cgroup_id` is absent from `sock_ops_func_proto`)
— so the ingress enforcement hook, which resolves every packet's
socket cgroup exactly, primes the socket-local hint on the policed
path (one sk_storage lookup, steady state no write), and the
program reads it back at the connection callbacks. Active connecters — the
download-quota case — clamp at establishment; rate changes
re-apply within one RTT on sockets whose establishment armed the
RTT_CB flag; the unpoliced majority pays nothing. The status
surfaces carry the owner-defined schema:
`status --print-json` reports the top-level `recwn_limits`
object (`enabled`, `window_bytes` — the binding window across
active download policies, `rtt_estimate_us`), and the human table
prints the lane's subordinate line. Rootless pins:
`recwn_tests.rs` (the law's clamp table and the userspace-twin
parity); live proof: `scripts/bench/recwn-probe.sh` (the owner's
verification recipe — 100 kb/s apply, a curl child in the cgroup,
`ss -ti` clamp evidence, the throughput band, retransmits near
zero). night-T-3 (schema v31) closed the section's documented
Layer-1+ trade — the honest clamp: the hint row carries the
policy's download rate now, and the sock_ops program derives the
window per callback as `rate x max(measured srtt, 200 ms)` — the
srtt read straight from the sock_ops context
(`bpf_sock_ops.srtt_us`, microseconds << 3, v4.16+), no new
helper, no new map, no userspace involvement. In landing, the 200
ms constant re-framed from RTT guess to the receiver's
window-update CADENCE floor the live evidence had measured (the
delayed-ACK band at 145-160 ms, topping at 200 ms): every short
link and every unmeasured socket answers the exact v25 window byte
for byte, a link longer than the band — the satellite class the
fixed floor under-admitted at `rate x 200 ms` — derives its true
pipe, and the [2 x MSS, 1 MiB] band, the status schema stay exactly as
they were. night-T-4 (schema v32) landed the migration that
night-T-3 deferred — the sk-storage architectural deepening: the
hint left the cookie-keyed LRU-4096 world for
`BPF_MAP_TYPE_SK_STORAGE`, the row hanging off the kernel's own
`struct sock` (`bpf_sk_storage_get`, the `#[btf_map]` .maps
section, `BPF_F_NO_PREALLOC`). The row pairs the policy rate with
the MMSPA GENERATION the prime ran under, and every callback
compares it against the live generation — the generation belt
REPLACES the removal sweep (the flush lanes retired; the sweep's
enumeration problem dissolves because nothing needs enumerating
anymore). The kernel floor carries it — `cg_skb_func_proto` and
`sock_ops_func_proto` both list `bpf_sk_storage_get/delete` since
v5.9 (verified v5.13 + v5.15 net/core/filter.c), the helper's own
`sk_fullsock` guard answers NULL on request/timewait socks (the
same miss posture the cookie-0 skip was) — and the gains are the
brief's own: no hash to pay at the callback (one list walk on the
socket's local-storage chain), no LRU cap to fake-evict a live
connection under, no cookie-reuse ambiguity, rows die with the
socket (kernel GC, no aging lane), and a policy removal heals on
the very FIRST callback — the v25 removal blind spot is closed,
not swept. What did NOT move and why: a sock_ops hint row is
genuine socket-identity state (the setsockopt lands on THE socket
the row hangs off), while the other cookie-keyed maps key finer
or coarser identities — `quic_cid_hint` keys the per-CONVERSATION
CID geometry (a QUIC connection migrates across sockets;
sk_storage would break the multiplexing budget the v22 promise
restored), the `ecn_debt` words key the per-BUDGET identity, the
cake/drr flow maps key the scheduler's own flow identities — each
stays a hash map with its own aging law.

Scope the "rows die with the socket" gain honestly (night-frontier
hardening, the live session's ghost-row find): it names the HINT
rows — the RECWN and pacing sk_storage rows the kernel frees at sock
destruction. The POLICY rows (the cgroup-keyed limit rows the status
table prints) are a different class: they have no kernel-side GC,
and their retirement is deliberately fail-closed — the zombie belt
reclaims a row only when the cgroupfs census PROVES the directory
gone (a systemd scope can outlive its members for seconds, and a
held row still enforces, the "enforcement preserved over
bookkeeping" law). A row that outlived its members renders marked —
`cg:14696 (no live member)` in the table and the JSON label alike,
never a bare cg: id that reads like a healthy limit — and `zelynic
recover` owns the manual sweep. The claim was always true for the
rows it described; this note names the boundary so a reader cannot
stretch it over the rows it never described.

**15. Egress socket pacing** (schema v27, night-spark-5 — the
quota saver's Layer 3). The egress twin of the receive-window
lane: a policed cgroup's UPLOAD policy is pinned onto its TCP
sockets as `SO_MAX_PACING_RATE` (SOL_SOCKET option 47, the rate
in bytes per second) by the object's second sock_ops program
(`zelynic_pace`, the loader's fourth program/link pair beside the
two enforcement hooks and the RECWN twin) plus one pinned
socket-local hint map (`pace_socket_hint`, the
`recwn_socket_hint` posture — sk-storage since night-T-4's
schema v32, the recwn twin's migration verbatim). The kernel's own TCP pacer then
spaces the outgoing stream at the policy's byte rate BEFORE the
link bills the bytes — no tc, no fq, no nftables anywhere: the
stack's internal pacer (net/ipv4/tcp_output.c's
tcp_internal_pacing on the 5.15 floor) hrtimer-limits the write
path while no pacing qdisc claims the socket, so upload quota is
saved without a loss event (no over-budget burst, no drop, no CE
mark). The attribution rides the same architecture Layer 1
proved: the egress hook primes the cookie hint on the policed
path (sock_ops still cannot resolve its own cgroup on the 5.15
floor), active connecters pace from establishment (the SYN's
egress primes the cookie before ACTIVE_ESTABLISHED_CB dispatches
— the un-paced exposure is the handshake itself), rate changes
re-apply within one RTT on sockets whose establishment armed the
RTT_CB flag, and a policy removal heals on the very first callback (the
generation belt — the sweep night-T-3's doc carried retired with
schema v32). The
pure law (`ebpf/src/pace.rs pacing_decision`) is pinned
rootlessly by `pace_tests.rs` — the simulated sock_ops call
shapes and the exact rate the wiring hands `bpf_setsockopt`.
`status --print-json` names `limits[].pacing_rate_bytes` (the
lane's commanded value — absent on upload-less and blocked rows,
never a fabricated zero) and the human table prints the Upload
Pacing subordinate line; live proof:
`scripts/bench/edt-probe.sh` (100 kb/s apply, the uploader joined
the recwn way — fork, join cgroup.procs, execv, `ss -tip` scoped
to its own pid reading the pacer at the policy's own rate, the
throttle band, the ledger's dropped counters moving zero). The
documented residue: the sock_ops dispatch is TCP-only by
construction (every `tcp_call_bpf` call site lives in TCP code)
— QUIC paces itself (RFC 9000) and the policer remains UDP's
enforcement lane.

**16. netns:// and iface:// native targeting** (night-netns-1 +
night-T-2 — the five-frontier review's #4, both halves landed: the
netns lane first, its iface twin once the VRF physics was pinned).
The third workload URI (`src/ebpf/identity/container/netns.rs`,
`netns://sandbox`): a named network namespace (the
`ip netns add <name>` family) resolves through its member
processes to the ONE workload cgroup living in it. The handle's
nsfs inode is matched against every `/proc/<pid>/ns/net` link —
the namespace is read, never entered, and no eBPF changed. A
namespace spanning two or more cgroups refuses with them named:
`ip netns exec` leaves the exec'd process in the caller's
cgroup, and a URI target can starve the workload, never a
host-side cgroup the operator shares — the direct `cg:<id>`
route is the honest door there. Volatility is stated, not
hidden: namespace names are host-local and their inodes churn
across reboots; resolution reads live state at apply time, the
same contract the process-name lane owns, and the resolved
cgroup id is the durable handle. Rootless pins: `netns_tests.rs`
(the grammar arm, the ns-link parser, the verdict reduction);
live proof: `sudo zelynic -v s netns://sandbox 500kb` (the
verbose trace names the handle, the member count, the cgroup).
The fourth URI (`src/ebpf/identity/container/iface.rs`,
`iface://red`) targets a VRF domain: `ip vrf exec` groups its
processes into the `vrf/<name>` cgroup under the cgroup2 root
(the iproute2 contract, verified against ipvrf.c's vrf_switch path
construction — and the exact `/vrf/<name>` segment its own
`ip vrf identify` reads back; the matcher pins the parent-vrf law,
refusing same-named impostors under slices or at the root), and the
resolver reads that cgroup's own `cgroup.procs` for liveness. The physics is stated, not hidden: a VRF owns a cgroup,
a plain interface does not — the plain-interface shape refuses
with `netns://` and `cg:<id>` named as the honest doors. Rootless
pins: `iface_tests.rs` (the grammar arm, the parent-vrf law); live
proof: `sudo zelynic -v s iface://red 2mb`; CI proof: the
Supermassive Container E2E netns/iface legs (a real namespace and
a real VRF domain resolving and enforcing on a real runner
kernel).

**17. The depth histogram — the sampled distribution** (`ebpf/src/hist.rs`,
schema v34, night-frontier-2B). The observability hole: `--depth`
answered WHAT a cgroup is and WHAT moved its window, but not the SHAPE
of the traffic — a limiter that smooths bursts shows its subjects only
as totals. Two LRU maps (`depth_hist_dl`/`depth_hist_ul`), one 512-byte
row per cgroup per direction keyed at the leaf, each a pair of 32-bucket
log2 halves: packet size in bytes, TCP srtt in microseconds. Recording
never taxes the hot path — a per-CPU sampler answers 1-in-1024 (the
unlimited majority pays one per-CPU counter tick, the sampled packet
the LRU write — the NIGHT-lts-2 law's measured frontier-2B amendment),
and the srtt half fills only from the RTT lane's own harvest (the
read-only sk-storage peek — no new helper, no CO-RE). The userspace
reads the buckets, not raw samples: bucket-bounded quantiles (the
lower bound of the first bucket whose cumulative count reaches the
quantile — a value in [2^b, 2^(b+1))) render one line per direction
in `ee --depth`, and the JSON block carries the full arrays so a
frontend recomputes what it wants. Rootless pins: the kernel's own
`hist.rs` compiles into the test tree (`test/ebpf/limiter/hist_tests.rs`
and `hist_raw_tests.rs`, the render pins in `depth_json_tests.rs`);
CI proof: the supermassive server phase's histogram leg
(night-verify-1) — a 1tb clamp (a ceiling loopback physics cannot
touch, held purely so the pin session survives the zombie sweep's
skeleton-unpinning teardown) over bulk loopback traffic driven on a
worker thread through cgroup A, the `ee --depth --print-json` read
taken MID-TRAFFIC (the depth command's liveness gate refuses a
cgroup whose members are gone — the worker is the subject's live
member) — asserted: `sample_shift` pinned at 10, the
download size half non-null with samples == sum(buckets) > 0 and
non-null quantiles. The clamp never engages — the sampler records
the unlimited-rate stream (enforce.rs ticks every packet the
cgroup-root hooks see and keys the socket's own cgroup); the upload
and srtt halves stay named-not-asserted (loopback does not
guarantee them).

**18. The histogram depth pack — the exact figures and the story**
(`ebpf/src/hist.rs`, schema v35, night-frontier-Z1). The depth hole
left after 2B: the buckets answer the SHAPE but the render's every
figure is a bucket bound — an exact min/max/mean (the words the
bounds can never say) did not exist, and a distribution without a
story cannot answer "WHICH transfer was the monster". The row grows
IN PLACE (512 → 816 bytes, no new map, no new lookup — the pressure
law: one map family, reused): six exact-aggregate words
(sum/min/max for size and srtt — sum an RMW add, min/max the
volatile check-then-store replace law over map memory, a zero-length
skb stays bucket-consistent but skips the mass words) and eight 32-byte
tail story slots (ts_ns/size/srtt_us/cookie — the worst-BY-SIZE
samples, replaced strictly, the ktime stamp written LAST so an
empty slot never reads half-filled). The story's "who" rides the
socket COOKIE — the identity userspace's walk already maps to an
endpoint — so the kernel never parses the wire and never reads a
kernel-struct offset (the no-CO-RE law's own currency); a cookie
the walk missed renders the raw cookie, never a fabricated
endpoint. ee --depth's line gains the exact mean and the worst
slot; the JSON block gains the exact aggregates beside the bounds
and the `tail` list (additive at the end, the stable scripting API
reads on). The COUNT is deliberately not a word: the buckets ARE the
count — the CI probe's own structural lesson (a second count source
under the dense fleet's 4100-leaf LRU churn read zero while its
buckets read three; "never a wrong count" is structural, not a
hope), and the tail's worst-vs-p99 law is asserted live on a CLEAN
row (the probe's two-leg pre-state read proves the row is
single-generation — no samples, no tail — before the law may fire;
the first CI lesson's "settled = 300+ samples" gate REFUTED itself
on the 2026-11-14 run: 1039 cumulative samples still carried a
storm-era 35-byte slot no single generation could hold — a settled
count is NOT a generation certificate, the row outlives every
session that touches it). The dive's
own limit, recorded honestly: the BPF_F_
MMAPABLE zero-copy read (a Z1 candidate) is IMPOSSIBLE at this
depth — the flag exists for ARRAY maps only, and the histogram's
per-cgroup attribution NEEDS the LRU keying (every cgroup on the
host is a candidate row); an ARRAY would buy zero syscalls and lose
the identity — the trench floor, mapped and documented, not
crossed. Rootless pins: the write-side words' laws in the kernel's
own test copy (`hist_tests.rs` — the sentinel-aware CAS min, the
plain CAS max, the weakest-slot replacement), the mirror's 816-byte
pin and the mean/tail read in `hist_raw_tests.rs`, the JSON wire in
`depth_json_tests.rs`; CI proof: the supermassive server phase's
histogram leg (the two-leg shape: leg one reads the live pre-state,
leg two drives the session under test) grew the Z1 assertions — the
derived count == bucket samples (the tautology pinned live), min ≤
max, the quantile ladder monotonic, mean == sum/count, the session
proof (a size half that GREW across the second leg, or a tail slot
stamped inside the leg's ktime window — the sampler demonstrably
recorded the session, whatever the loopback attribution did to the
download half), the census join scoped to the session's window (the
slots the leg wrote belong to the leg's own live connection;
pre-stage slots — dead sockets, the honest remainder — ride the
note, never the verdict), and — on a clean pre-state row — the
tail's weakest ≥ the p99 bucket's lower bound (the worst-8 ARE the
top 0.8%; the generation gate is the churn physics, named where it
cannot be asserted).

**19. The tail-aware clamp bracket — honesty from the mean to the
tail** (`src/ebpf/render/bracket_section.rs`, night-frontier-Z2,
userspace-only — no map, no kernel word, no schema bump). Dive 1
gave the depth report the cgroup's RTT distribution; the RECWN lane
(#14) clamps every owned socket's receive window by the per-socket
law (`rate x max(measured srtt, 200 ms)`). The hole between them:
the report named ONE window figure and stayed silent about whether
ONE clamp is even honest for the fleet behind the histogram — a
cgroup whose sockets ride both a local path (sub-millisecond RTT)
and a remote path (hundreds of milliseconds) cannot be served by
one receive-window value without lying to one class of them. The
bracket is the composition of the two existing features (the
value-per-line reason it ships): from the srtt half's EXACT min
word (Z1's aggregate) and the bucket-bounded p99 (the quantile
ladder), through the RECWN window law's own userspace twin, it
derives the two ends of the honest single-clamp range —
`ceiling_bytes` = BDP(min RTT), the tightest clamp that still lets
the fastest path fill its pipe (any window below it under-delivers
even the min-RTT socket); `floor_bytes` = BDP(p99 RTT), the clamp
under which the tail's paths stop filling theirs (a lower-bound
read, the p99 bucket bound's own honesty, the >= prefix admits
it) — and one new metric: the HONESTY RATIO = p99/min RTT, the one
number that grades the fleet. Ratio near 1: the paths agree, the
bracket collapses, one clamp serves (the recommendation is the
LARGER end — the pipe no measured socket under-fills; the
delivery-first pick the quota saver's own contract wants).
Ratio past ONE LOG2 OCTAVE (permille 2000 — the 32-bucket
histogram's own resolution quantum; a tail within one octave of
the min is the same path class as far as this instrument can
certify) WITH the law's ends diverged: the acceptable single-clamp
range is EMPTY and the report REFUSES — "no single clamp (mixed
local+remote paths)" — and names the per-socket door that already
exists (the traffic section's `[rtt X ±Y]` pairs, the JSON
`endpoints[].rtt_us`). The divergence clause keeps the refusal
honest at the cadence floor: when both RTTs ride sub-cadence the
law answers byte-identical windows and one clamp DOES serve — the
ratio alone cannot refuse (the floor absorbed the spread at this
rate), refusing there would be noise dressed as rigor. On Mixed
the module names NO clamp value — the refusal IS the answer; the
per-socket CLAMP (sk-storage EWMA granularity) is the Dive
ladder's -4000m rung, deferred by the owner's verdict, and the
self-auditing clamp (achieved-vs-honest-ceiling grading) the
-8000m rung beside it — this refusal is the honest door both will
open through. The verdict clause pair (octave-cross AND
ends-diverged) and the larger-end recommendation are pinned in
`test/ebpf/render/bracket_tests.rs` (absence law, cadence-floor
collapse, the inclusive 2000-permille edge, the mixed refusal's
null clamp, the additive JSON wire); the render row rides one grey
kv line under the histogram (`clamp bracket:`), download lane only
— the RECWN lane shapes receive windows, so an upload bracket
would name a clamp nothing applies. The JSON key `clamp_bracket`
rides the target object additively (the stable v11 scripting API
reads on; null on every honest absence — no samples, no live
download rate, a zero min word). Honest limits, stated: the ratio
rides the bucket-bounded p99 and is itself a lower bound (a MIXED
verdict is final — the bound already crossed the octave; a SINGLE
verdict is the octaves the bound can vouch for); the bracket is
rate-conditional (BDP semantics — a higher policy rate can split a
fleet the current rate collapses); and the histogram half can lag
its exact words by an in-flight sample (the row doc's own
coarseness — a zero min word reads as the honest absent bracket).

**20. The identity drift alarm — the URI's contract, verified per
read** (`src/ebpf/identity/drift.rs`, night-frontier-Z3,
userspace-only — no map, no kernel word, no schema bump). The
container lanes' documented contract ("the resolved cgroup id is
the durable handle, the URI is the speller") carried a blind spot:
the URI resolved ONCE, at apply time, and nothing re-checked the
handle after. `ip netns del x && ip netns add x` recreates the
namespace — a new nsfs inode, a new workload cgroup — and the
pinned policy keeps enforcing against the OLD cgroup id while
`status` shows a live-looking row; a fresh apply with the same URI
silently writes a SECOND policy; kernfs inode recycling can even
point the old row at an unrelated cgroup. The watch pointed at a
corpse, and nothing said so. The alarm pins the lane's identity AT
ATTACH — the netns handle's nsfs inode (captured from the stat the
resolution already paid, zero extra syscalls), the iface VRF
device's ifindex (a recreated VRF draws a fresh index from the
kernel's monotonic counter; a domain with no device at attach
records the 0 sentinel, the honest absence) — into
`/run/zelynic/identity/` (tmpfs, one line-format file per URI; the
volatility class the nsfs inode itself owns, the same class the BPF
pins ride) and re-verifies with ONE stat() per read. Three mouths,
all best-effort (a warning lane never fails the visit that carries
it): ATTACH re-pins beside the writes and warns when the same
URI's identity drifted since the last apply — the re-apply that
heals the ghost also names it; READ (`zelynic status`) prints the
STALE warning — handle gone: "STALE: netns://x is gone — policy
cg:N still enforces against the dead namespace (the watch points
at a corpse)"; changed word: "STALE: netns://x was recreated
(identity A -> B) — policy cg:N enforces against the OLD
namespace"; a probe that cannot DETERMINE (EACCES, EIO, an
untrustworthy parse — night-frontier-Z4's errno taxonomy) reads
BLIND: "BLIND: netns://x cannot be verified (Permission denied
(os error 13)) — policy cg:N keeps enforcing while the watch cannot
see the namespace" — the blind watch never claims a corpse; only
the VERIFIED absence (every probe answering ENOENT) reads is-gone —
each naming the two honest doors (re-apply to follow
the new identity, or `zelynic u cg:N` to remove the ghost row),
the warnings riding stderr so the status frame and the JSON
contract on stdout stay byte-stable; TEARDOWN drops the pin with
the policy it describes — by URI (the recreated-identity case,
where the pin's cgroup id differs from the current resolution) or
by cgroup id (any spelling that resolves to it) — and
`unpin_all_bpf` sweeps the directory beside the retired
persistence pair's state file. A pin whose cgroup no longer holds
a policy is residue, not a watch — dropped silently, the census
sweeps' own law. Honest limits: an iface pin with the 0 sentinel
reads UNVERIFIABLE (honest silence, never a false alarm) while the
device stays absent, and a fresh ifindex the day it appears reads
recreated — appearing IS a change; the alarm verifies the identity
word only — the workload MOVED inside an unchanged namespace (a
new cgroup, same inode) is the re-apply's own act, not a drift the
alarm can see from the handle (the cgroup-id pin updates silently
on that path). The verdict reduction, the file-name law, the line
format, and the wording are pinned in
`test/ebpf/identity/drift_tests.rs` (the tempdir-driven IO round
trips included — the unpin_dir discipline, every production
wrapper a thin IDENTITY_DIR call). Dive 4's -4000m rung
(resolution transparency — the resolution CHAIN printed, not just
the answer) stays deferred by verdict; Dive 3's story family is
deferred whole (see Deferred by verdict).

**The determinism law beneath them all** (night-depth-hardening-1,
`src/ebpf/connections.rs` + `src/ebpf/identity/drift.rs` +
`test/ebpf/render/determinism_tests.rs`).
The fourteen and the twenty all render rows, and a row whose order is
not intrinsic breaks every one of them the same way: a frame diff
reads a change that never happened. The law: every output row order
is a total order the kernel never perturbs — the census's socket
rows carry the kernel inode as the final tie (the /proc table's
hash-bucket enumeration and the fd readdir order are contractual to
nobody, and both reshuffle across boots, rehashes, and distros), the
holders carry the pid, the boards carry the cgroup ID, the alarm
mouths carry the pin's uri (the STALE lines and the resolver's
ambiguity list print ascending, the readdir beneath sorted away at
the source), and no render path iterates a hash map. The
compositional pins render a permuted census through the traffic
focus, the text report, and the JSON document and require
byte-identical output — the determinism the
5.15-floor cross-distro matrix verifies on hardware, pinned in unit
form so it cannot regress between releases. The full contract lives
in STABILITY.md. The night-depth-hardening-2 sweep (2026-11-17)
re-walked the law's whole surface hunting a residual gap and
returned signed PEAK: the two display laws hold at their seats, the
session board collects into a Vec and breaks ties by cgroup ID (its
own comment names the hazard), the baseline lane's retire and panel
walks sort and dedup their u32 keys into a total order before any
output, the histogram label maps are lookup-only, the sweep cache
never reaches row order, and the remaining float seats (the
gradients, the suggestion similarity, the deep lane's ms split) are
IEEE-deterministic arithmetic formatted by Rust's own locale-free
fmt — no distro's LC_NUMERIC can bend them. The byte-shape surface
the sweep added to the standing battery (one terminal newline, no
trailing whitespace, no doubled blank line, every rootless lane)
rides night-depth-infra-1's hygiene test. No code moved; the audit
is the verdict.

**The allocation lens and the pooled composition** (night-frontier-Z4,
`src/ebpf/render.rs` + `test/ebpf/render/alloc_lens.rs`). The diff
engine's zero-alloc law (NIGHT-blade-16) covered its own half end to
end; the composition half still spent 249 heap events per busy frame
at the lens's first sight. The lens — a counting global allocator,
test-binary-only — is the proof instrument: without it every
zero-alloc claim is theater. The pool is the law: the composers pop
capacity-warm, bytes-free strings (`pooled_line` clears on pop — the
deep-layout pins caught a composer inheriting a previous line's
bytes and the fix landed before the commit did), the monitor's REAL
loop returns the frame's spent lines after the diff engine's swap,
and the ladders gained into-twins (one ladder per contract, the
owned form its first consumer — format_bytes/format_bytes_wide/
format_count/fit_to_width, the color wrappers' paint_in_place, the
rate and label cells). The ranked rows, their labels, the header,
the title core, and the grey detail fitting render allocation-free;
the lens pins the measured floor in the A/B harness's own test —
164 heap events, down from 249 — with the named remainder (the
border wrap's per-row pair, the footer's owned-Vec builders, the
detail tree's contracts, title_bar's internals) enumerated beside
the assert: a frame allocating above the floor fails the battery,
and closing a named site lowers the floor in the same commit. That
is the staged ladder NIGHT-blade-16 rode — stage 2 opens when the
next allocation rung is worth its churn. The proof the law holds is
the battery's own history: the pins failed twice while this landed
(the inheritance bug, a lost cell spacer) and the raw-frame capture
diffed byte-identical before the commit rode.

**The per-helper capability ladder** (night-frontier-Z5,
`src/ebpf/helper_ladder.rs` + `src/ebpf/host_caps.rs`). The floor
law is one gate — at or above 5.15.0 the attach proceeds, below it
everything is refused — and its guarantee was folklore: "the modern
helper set" named nowhere itemized. The ladder makes the folklore a
table: one rung per eBPF fact the two embedded objects consume,
eight helper calls (ktime_get_ns 4.1, skb_load_bytes 4.5,
get_socket_cookie 4.12, setsockopt 4.13, skb_cgroup_id 4.18,
skb_ancestor_cgroup_id 4.19, skb_ecn_set_ce 5.1, sk_storage_get 5.2)
and two shape rungs (bpf_link 5.7, bpf_atomic_64 5.12), each
versioned from the canonical introducing commits, the rows climbing
since-ascending with the top rung one below the floor — every rung
is met BY CONSTRUCTION on any kernel the floor admits, the itemized
proof. Three surfaces ride one table: the shape facts derive from
it by name (the hardcoded 5.7/5.12/5.1 thresholds retired, the
pre-existing release-by-release pin passing unchanged —
byte-identical, the trace lines cannot drift), the doctor renders
the one-glance verdict ("Helper ladder: 10/10 rungs met") naming any
missed rung with its degradation class (verified live on a 5.10
host: 9/10, the atomic rung unmet), and the doctor's JSON carries
the same numbers additively (`{"rungs":10,"met":10,"missed":[]}`,
unprobeable never reads as met). The graceful-degradation gate is a
test, not a hope: a future rung whose introduction release sits
ABOVE the floor cannot land without naming its per-feature
degradation plan in the same commit, and the coverage pin demands
the table stay in sync with the helper set the objects actually
call. Stage 2 — the attach-time wiring that executes a plan — opens
when the first above-floor rung is adopted; writing it earlier
would be untestable speculation, the gimmick trap the ledger
refuses.

**The golden vectors — the release attestation appendix**
(night-frontier-Z5, `src/ebpf/connections/parse.rs` +
`docs/GOLDEN_VECTORS.md`). A release's checksums and GPG signature
attest the artifact — that the package is authentic and intact; the
golden vectors attest the behavior — that the engine's pure IP
layer produces exactly the verdicts the release says it does.
Eighteen frozen `/proc/net` rows (the six table families, the
byte-swap law's dedicated witness `78563412` reading back
`18.52.86.120`, the IPv4-mapped display form surviving verbatim)
plus seven rejection shapes and the eleven-code state table, each
vector carrying a stable `GV-NN:slug` id, walked by one test on
every CI run — commit and release tag alike — so a tagged release
whose parse layer disagrees with its appendix cannot exist. The
layer is a total function of its input bytes (no clock, no
environment, no map iteration), which is exactly what makes the
engine's behavior attestable knowledge: the determinism contract's
own release-time proof, reproducible on any machine offline
(`cargo test --locked golden_vectors` — no root, no eBPF, no
network). The law that keeps the appendix honest: an output change
IS a corpus change, and a corpus change is a release-note event —
the diff between two releases' appendix states is the pure layer's
behavioral changelog between them. Honest scope is stated in the
appendix itself: the vectors attest the parse law, the cross-distro
matrix attests the kernel law, the signature attests the artifact
law — three legs, one attestation. Stage 2 (per-release appendix
stamps the day release engineering cuts one) opens with the next
tag; the mechanical ratification already runs ahead of it.

## The proof layer — the for-all tier (night-frontier-Z6)

The scales above are pinned by rootless unit tests (sampled inputs,
hand-picked edges) and the SMP hammers (sampled schedules). The
proof layer (night-frontier-Z6, D1) adds the instruments above both:
a dedicated detached package, `proofs/` — the ebpf crate's own
detachment shape, so the instruments never enter the root manifest's
dependency graph — whose harnesses compile the SAME law files the
kernel object builds (the fuzz harnesses' #[path] include law: a law
the proofs verify is a law the datapath runs). Two instruments, one
per-push lane (.github/workflows/proofs.yml on every push, capped at
15 minutes wall — the estate ceiling the night-fly-1 law enforces on
every CI job), three honest tiers:

- **The for-all tier (kani, bounded model checking).** Each harness
  turns a named law into a machine-checked theorem over ALL inputs
  in its stated domain — the claims the docs make in prose ("the
  fill-detect branch is the overflow guard", "the ladder IS the
  verifier's own proof", "the cache decision table") become solver
  verdicts. Six theorems decided at census time on the pinned kani
  release (0.68.0): the consume sufficiency pair (try_consume
  deducts exactly-want iff the stock covers it, for every state),
  the 32-bucket ladder bounds and their exact power-of-two
  boundaries (hist.rs, for every u64), the hint learn state machine
  (confirm/restart/zero laws, every sighting pair), the memo word
  round-trip and the cache decision table (mmspa.rs, every
  generation/root/memo shape), the share-state word's rollover and
  ratchet laws (drr.rs, every packed word and epoch), and the
  window domain totality (during.rs, every wall instant in
  [0, NS_PER_DAY) plus the unknown-kind enforcement posture). Four
  theorems sit behind nonlinear multiply/divide circuits (the
  refill overflow guard, the hostile-state enforce totality, the
  ring stamp law, the bounded key) and stood RETIRED from CI by the
  night-fly-1 law: the sandbox census measured them unfinished at
  ten minutes and undecided under every SMT backend, the hosted
  per-push run was cancelled at 59m44s still inside its first
  harness, and their night vehicle's single scheduled fire
  (proofs-night.yml, run 44896512098) burned its full 300-minute
  cap and died cancelled with zero solver verdicts — the 15-minute
  ceiling is now estate law, and a budget the ceiling can never
  afford is not a verdict vehicle. The return condition the record
  named — a proof-shape change that fits the ceiling — is exactly
  what night-frontier-Z12 delivered: all five wired-out statements
  (the four above plus the margin-erosion monotonicity) are standing
  solver verdicts again, stronger than their pre-retirement forms,
  and the tier carries twelve theorems as one-harness matrix jobs
  (the Z12 section below holds the record). The rate-domain note the
  heavy theorems carried — the system's own ceiling (MAX_RATE, the
  parse family's refusal line) as the quantifier's bound — is
  RETIRED WITH THEM: the Z12 refill and enforce theorems quantify
  over the FULL u64 rate domain, hostile persistent-map state
  included, no assumption beyond the burst contract the kernel side
  sanitizes for itself.
- **The sampled tier (proptest, 4096 shrinkable cases per law).**
  Every law the for-all tier covers plus the ones the solvers
  cannot yet decide: the aggregate replace words, the tail's
  worst-8 contract, the margin-erosion monotonicity end-to-end
  through daily_active (the Z12 comparator lemma carries the
  for-all half; the day-reduction composition rides the sampler;
  the credited whole's magnitude law rode it too until the Z15
  re-census measured the direct obligation deciding — see the Z15
  section), the flow key's determinism half,
  the DRR take laws, the rate-ring stamp law. The instrument's first
  real catch is itself the record: the fraction sanitize-on-read
  law's counterexample (shrunk to rate=0, frac=NS_PER_SEC) sharpened
  the property from "stored fraction is healthy" to the exact
  documented contract — the regression store replays it on every
  run (proofs/proptest-regressions/).
- **The census verdicts (the honest NOs).** Loom was examined and
  rejected signed: no location-backed atomics (no AtomicU64::from_ptr
  in 0.7.3), and the datapath's CAS discipline is pointer-cast over
  raw map-value memory — restructuring the core-only law files for a
  test instrument, or reimplementing the protocol in a harness, would
  be a model rather than a proof of the bytes the kernel runs.
  Reopens the day loom ships from_ptr semantics — and the NO is
  standing-enforced, not archival: the proofs lane's loom-census job
  (the checks-list seat the check-name discipline signs — "Loom
  concurrency census (absence guard, signed verdict)", the Miri
  shape) re-reads the tree on every push and fails the day the basis
  moves: a location-backed atomic landing outside the kernel crate's
  access primitives (the pointer-cast discipline), or a loom
  reference or dependency landing without a standing lane. The reopen
  trigger is mechanical now. The per-instrument dependency record
  rides docs/DEPENDENCY_AUDIT.md; the tier table rides the proofs
  manifest comments.

The lane: `cargo test` in proofs/ (the sampled tier, rootless,
stable-only) and `cargo kani --lib` per harness (the for-all tier's
decidable half, the pinned kani release) — the proofs.yml workflow
runs both on every push, one invocation per harness so a verdict is
never lost to a sibling's budget, capped at 15 minutes wall; the four
solver-bound theorems stand retired from CI (their night vehicle
burned 300.6 minutes cancelled with zero verdicts on its single
scheduled fire — see the for-all tier above). A red is a
counterexample or an undecided theorem, never a skip — and the third
seat on the proofs checks list, the loom-census absence guard, runs
no harness at all: it re-reads the census basis out of the tree and
fails loudly the day the signed verdict goes stale (a guard, not a
lane — the honest NO is enforced, not merely archived).

## night-frontier-Z7 — the byte-layout theorem (D3) and the ACK-clock census (D4)

The Z7 depth lands two records, one theorem and one rejection, both
rootless, both honest about what they verify.

**D3 — the byte-layout theorem (the schema contract, machine-checked
over its whole history).** The stats row (cgroup_limiter_stats — the
kernel twin math.rs's LimiterStats, the userspace mirror
LimiterStatsRaw) carried its layout history as prose (the schema
ledger, v1..v30 in schema_ledger.rs, v31 onward beside the anchor)
and as spot pins (the include_str! version-equality pin, the size
pins, the offset-48 retirement note). The deepening turns the whole
table into one generated rootless test —
test/ebpf/limiter/schema_layout_tests.rs, wired as schema.rs's second
test module — whose five-era version table (v1..v35, every era
carrying its ledger anchor) is walked for every version and every
word under three laws: offsets strictly increasing with append-only
bumps (words never move, never disappear, new words land 8-byte
aligned beyond the old tail), retired words hold their pinned offsets
forever and never un-retire (the v29 offset-48 zero contract), and
row size derives from each version's own words, never shrinks, and
rides version boundaries only. The live bindings bind the table to
the real bytes — every LimiterStatsRaw field maps by name and offset
onto the current era, the row size rides size_of, and the 2030 gate
pins the table's top version to SCHEMA_VERSION_EXPECTED: the next
schema bump cannot land without extending the table, and the laws
then verify the new era obeys the same discipline. Verified both
ways: the walk passes clean, and a deliberately corrupted pin fails
loudly naming the field, the offsets, and the law. A maintainer in
2030 cannot silently break a retired word's offset — the theorem
gate fails the push.

**D4 — the ACK-clock hypothesis (the ninth lane, research note only).**
The one lever class the eight physics losses leave unowned — shaping
the sender's ACK clock at cgroup scope, synthetic RTT inflation via
delayed-ACK modulation, targeting losses 3 and 4 — now carries its
whitepaper and its signed census verdict
(docs/ACK_CLOCK_HYPOTHESIS.md): ten rungs, every fact verified
against the v5.15 sources line-cited, the inflation direction censused
NO on the floor. The census's honest delta beyond the vault's
predicted flat NO: TCP_BPF_DELACK_MAX shipped IN 5.15 — a real,
cgroup-scoped, sock_ops-reachable ACK-timing write — but the rung is
INVERTED (the setter rejects any ceiling above the kernel's own
200 ms TCP_DELACK_MAX; the consumer clamps the ACK timer down), so
the only reachable direction makes ACKs leave sooner — more upstream
packets, a faster sender clock, fatal to the hypothesis in three
independent ways the record carries. The reopen conditions are named
and sharp (a raisable ceiling, a per-ACK callback, suppression plus
emission at cgroup scope, forced-delay semantics); the reopen path
runs experiment-before-code on the project's own harness; the shelf
holds at -11000m — whitepaper vault only, zero code.

## night-frontier-Z8 — the claims-instrument closure (D5) and the bypass shelf (D6)

The Z8 depth lands one closure and one shelf: the last standing open
find signed into the machine record, and the one deepening that
stays on the shelf on purpose.

**D5 — the claims-instrument closure (the one standing open find,
closed at the real instrument's own count).** The sharpest-skill
audit (night-dragon-lts-1, section 5) re-checked the memory-safety
claim's basis mechanically and found it not standing: no wiring
anywhere enabled `clippy::undocumented_unsafe_blocks` (a
restriction-group lint the default groups never turn on — CI's
`-D warnings` does not reach it), and a static census mirroring the
lint's positional rule counted 120 unsafe block openers in the tree
(`src` 61 + `ebpf/src` 59) with 78 carrying no safety-mentioning
comment in the window — the rationale genuinely living at doc level,
the house convention the mechanical lint does not read. Two
owner-call options were recorded: wire the lint as a standing lane
and annotate, or re-spell the LTS-14 row's basis to the convention
the tree actually holds. The owner took the first, across four
signed rounds, each measured before it moved: the lts-2b closure
annotated the gap at the real lint's own count — 109 sites (68
root-crate: 61 blocks + 7 unsafe impls the static census cannot
see; 41 kernel-crate blocks), every site carrying its actual local
invariant, comments only, the lint measured zero on both crates
(98d1a1e); lts-2c took the owner's call and wired the standing deny
gate through one `[lints]` table per manifest — the root manifest
and the detached kernel crate each carrying their own, level deny
so every clippy invocation anywhere enforces the basis instead of
CI alone, clippy-namespace only so plain rustc lanes byte-behave
unchanged, the negative probe (a temporary undocumented unsafe
block) denied with exit 101 naming the lint (d6c98d6); lts-2d took
the kernel crate's pre-existing warn noise to zero (39 sites across
nine files), the deny gate live during every edit; lts-2e made the
kernel instrument standing — ci.yml's ebpf-host job runs
`cargo clippy --locked -- -D warnings` on the pinned nightly beside
the direct crate build, every push and PR. The delta between the
census's 78-of-120 estimate and the lint's own 109 is the
record's precision lesson: the static rule approximates the lint's
accepted-comment semantics (inside-block first-statement comments,
distance edges, the unsafe-impl class it never counts), so the
closure was driven by the real instrument, not the estimate. The
basis re-measured zero on 2026-11-17 at 046212d (check-all 53.6s
exit 0, gate-keepers 27/27). LTS-14's memory-safety row is no
longer a claim; it is a gate.

**D6 — the bypass three-way reconciliation (the low rung, shelved
by verdict).** Exists today: the bypass.rs interface-delta shadow
audit (scale 10), the apply-side cgroupfs liveness census
(night-total-hardening-1 find 1), the observer census maps. The
deepening would cross the three inside the EXISTING status/depth
JSON — a cgroup alive in cgroupfs, booking zero observer rows,
while its interface delta is nonzero, names a bypass class the
interface-only delta cannot (namespace-hosted workloads exiting
another interface). Shadow only; detection never enforcement. The
honest caveat holds: the audits call the bypass lane PEAK, and a
new lie-class surface must earn its place — a marginal deepening is
not field evidence, and building it without a witnessed miss is
exactly the innovation-for-its-own-sake shape the honesty rule
forbids. Verdict: SKIP unless field evidence arrives. The trigger
is recorded in the deferred ledger below (a user-reported bypass
class the delta demonstrably misses); nothing was built.

## night-frontier-Z9 — the verifier budget ledger (D7)

The gap the ledger's own prose recorded without a number: "the
enforcer's budget is FULL, pre-existing" — and the only verifier-cost
figure in the tree was a failure story (the mirror's census refusal,
"Processed 1000001 insn"). Nothing pinned what the verifier charges
for the six programs the estate ships, so a verdict-path change could
eat the floor kernel's headroom silently: the one LTS failure class
that arrives without any code misbehaving on the machine that measures
it. The Z9 depth turns the verifier's own cost into a pinned contract
— **the verifier budget ledger** — the first verifier-cost gate this
class of tool carries.

**The instrument** (`scripts/supermassive/verifier-budget-test.py` +
`verifier-budget-ledger.json`, riding the supermassive lane as its own
shard pair on BOTH kernel envelopes). The battery loads both embedded
objects on the kernel it booted (a real strict apply for the limiter's
four programs, a live eagle-eyes monitor session on a pty — the
survival battery's proven shape — for the observer's two, whose lazy
camera pins nothing and whose programs exist only mid-session), and
prices every estate program with the kernel's own channels. The price
is `verified_insns` (UAPI aba64c7da983, the v5.16 merge window —
"bpf: Add verified_insns to bpf_prog_info and fdinfo"), read through
BPF_OBJ_GET_INFO_BY_FD at its fixed UAPI offset (216 — appended after
recursion_misses, before the attach_btf words, identical on every
kernel that carries the field), behind three gates the info struct
itself carries: the filled length names the 5.15 floor's shorter
struct, the type word must be an estate program type, and the id word
must equal the bpftool-confirmed program id.

**The identity channel that cannot lie**: the limiter's four programs
come through their pinned files (`prog show pinned <file>` — the pin
name IS the loader's program name), and the observer's pair through
the kernel's own link table (`link show` — the surface NIGHT-boost-12's
hunt proved carries zelynic's links, since `cgroup show` walks only the
legacy attach list) joined on attach direction. The kernel-side program
NAME is not an identity the census leans on: aya stamps prog_name only
when its BpfName feature probe passes, and the live reads saw empty
names beside the tools' own tables.

**The laws** (each enforced live, validated rootlessly by --self-test
and twelve negative probes):

- **The completeness law** — every program the estate loads carries a
  row in both envelopes; the inventory gate arms at landing, never
  deferred.
- **The growth law** — a measured value above the pinned budget fails
  the battery; a raise names its number and reason in the row's
  history.
- **The ratchet law** — lowering is free and recorded.
- **The census law** — a null budget is census debt: the landing run
  measured in census posture (`armed:false`, MASS-CENSUS rows printing)
  and the arming commit pinned the watched run's numbers and flipped
  `armed:true` in the same change; no half-armed state exists.
- **The availability law** — the verified_insns field landed in the
  v5.16 merge window: the 5.15 floor kernel does not expose it (the
  kernel fills 80 of the info bytes and the census names the absence),
  so the floor envelope prices by inventory — the load-proof IS the
  floor's gate — and the head envelope prices fully.

**The live lessons the first runs recorded** (each one a seat the
next maintainer walks around): the FIELD is kernel UAPI, the DISPLAY
tool only grew it in Oct 2026 — the staged bpftool never printed the
number, so the census reads the kernel directly; the cgroup id is the
kernfs inode (NIGHT-hunt-31 — no cgroup.id file exists in any mainline
kernel, and the first census run stepped into that documented trap);
`bpftool prog show`'s pin filter spells `pinned`, the positional path
reads as an unrecognized token; `cgroup show` walks only the legacy
attach list; link-table rows span two lines (the attach_type word on
the tab-indented continuation); and the calibration counts the prog
types from the header's own order (TRACEPOINT at 5 — a dropped entry
made the first gate refuse a CORRECT program info with type-7).

**The armed numbers** (the supermassive census run 44595619920,
kernel 7.3.0-11-generic, the calibrated (13,15) channel, fill 232):
enforce_dl 664129, enforce_ul 703842, zelynic_recwn 139, zelynic_pace
63, observe_egress 70, observe_ingress 70 — carried verbatim into the
ledger's head rows as budgets, with the floor rows null forever (an
inventory envelope cannot price). The mirror's reopen condition "a
walk-cost optimization frees the enforcer's ceiling" is now measurable
by the same gate: the ledger IS the ceiling's ruler.

**The observability rider**: the guest console is a read-hostile
channel, so the census emits its rows as ::warning:: workflow commands
(warnings create check-run annotations; notices do not) sized to the
ten-per-step cap, the watch summary step re-emits the failure bullets
under its own budget, and every shard uploads its boot log as an
artifact. The diagnosis and the numbers land where the API reads them.

## night-frontier-Z10 — the no-corruption theorem (D8)

PHILOSOPHY.md names the fear: "terminal corruption is the one bug
class a monitoring tool cannot apologize its way out of." Every
countermeasure the tree carried before this depth was an EXAMPLE of
the emission contract holding — the layered reset contract, the
five-layer `--reset-terminal`, the raw-frame capture diffed
byte-identical, the ghost-cell soak's 20,000 replayed frames —
evidence by enumeration, never a for-all. And the proof layer (Z6)
rode only the ebpf law files: the renderer's own engine had no
theorem. The Z10 depth closes exactly that gap.

**The instrument** (`proofs/src/vt_model.rs` + `terminal_laws.rs` +
`kani_terminal.rs`, wired in `proofs/src/lib.rs` beside the Z6
cores): the diff emission engine (`src/terminal/diff.rs`) is
included into the proof crate by `#[path]` — the fuzz harnesses'
include law, the SAME bytes the flagship binary runs — and a
minimal VT state machine is checked against it. The model
implements exactly the emission set the engine owns (HOME,
MoveTo at column 1, erase-below, erase-EOL, LF, content payloads,
with complete SGR spans riding content verbatim — the render
layer's style bytes are content, and a style change is a row
change) and is deliberately STRICT: any token outside the grammar
panics, the `ESC[2J` class included. One law quantifies over frame
pairs — for EVERY pair (prev, next) in the domain,
`apply_terminal(emit_diff(prev, next), prev) == next` — and three
structural laws ride the same check: the absence of `ESC[2J` in
any emission, the idle fast path's zero-byte verdict for an
identical frame at identical geometry, and the
one-batched-write-per-frame rule with the emitted byte count equal
to the bytes the write carries.

**The two tiers, the Z6 shape**: proptest's sampled tier runs the
session property over wide frames — up to 64 rows x 200 columns,
three-frame sessions with independently generated geometry
(first frames, width resizes, tall regimes, grows, shrinks, and
idle repeats all occur naturally; 4096 shrinkable cases per run) —
riding the proofs.yml property lane's existing `cargo test` seat,
per-push. Kani's for-all tier STATES the same conformance law over
the bounded 3x8 domain (two-symbol alphabet in full-width rows,
fully symbolic row counts and screen heights) as the harness
`emission_conformance_holds_for_all_small_frames` — and the census
around it is now a two-machine record: the first census (four local
attempts: 4x16 at unwind 120, 3x8 at 72 before and after the
parser's token-budget restructure, 2x6 at 44) measured the solver
out of memory inside about two and a half minutes on the 4 GB / 2
CPU sandbox; the 2026-11-21 census extended it to eleven shapes and
both machines — 2x8@68, 3x4@68, 1x8@68, 2x4@36, 2x6@44, 1x4@36,
1x4@24, and the MINIMAL 1x1@16 all die in the sandbox kernel's
global OOM (cbmc, anon-rss 3.35 GB, the sandbox's ceiling), and the
hosted 16 GB runner killed the 3x8@68 seat mid-symbolic-execution
twice (runs 44727607551 and 44876980805, both at 24-25 minutes, no
solver verdict, the sibling seats alive past minute 27). The
measured law the census proves: the weight is INVARIANT to the
domain dimensions — the engine's own symbolic heap (the frame
vectors the emission swaps and clones, the emission buffer's
growth, the model's rows, and the panic-path machinery the direct
indexings carry), not one shrinkable circuit, is the wall. The
harness removed its own measured-heaviest single path (the
symbolic-length `truncate`'s slice-index panic branch; rows are
full-width now, variable lengths ride the sampled tier) and it
still exceeds every ceiling. The seat therefore STANDS DOWN from
the night matrix by measurement — a red that can never become a
verdict is not an honest finding shape — and returns when one of
its named levers lands: per-loop unwind annotations on a toolchain
generation that carries them, a behavior-preserving proof-friendly
indexing form inside the engine, or the lemma decomposition that
splits the stream conformance into per-token theorems (each its own
signed round). The per-push kani seat keeps the Z6 theorems it can
afford; the sampled tier covers the wide frames meanwhile.

**The model sharpened itself first** (the Z6 fraction law's
precedent, honest again): the sampled property's first
counterexample was not an engine bug — it was the MODEL being
stricter than the grammar it checks. The strict parser rejected
the engine's bare `ESC[H` (HOME) for failing the MoveTo shape it
shares a final byte with; the grammar gained the HOME arm and the
witness rides the committed regression store
(`proofs/proptest-regressions/terminal_laws.txt`) like Z6's does.
The theorem is therefore also a model-conformance pin: a future
emission token the model does not know fails the lane the same
way, and the model must be taught the token deliberately — never
silently.

**Why never-done**: tmux, vim, cosmostrix — no terminal renderer
ships a machine-checked emission law against a modeled terminal
state. The claim is whitepaper-grade and mechanical: the first
terminal renderer whose diff emission is machine-checked against a
modeled terminal state — the proof is a solver verdict and a
shrinkable-witness property lane, not prose.

**The honest appendix boundary** (the golden vectors' rule): the
theorem holds over the op-set the engine emits and the domains the
instruments state. The model is a MODEL: its resize semantics
(shrink drops the bottom rows, grow reveals blank ones) and its
row-as-payload equivalence (content is written wholesale at
column 1; the erased tail is blank) are the standard terminal
reading the standing soak already verified across 20,000 frames,
restated as law. Rows in the theorem's domain carry plain payloads
plus complete SGR spans — a payload impersonating a cursor move or
an erase is outside the render layer's contract, and the model
rejects it rather than guessing. The engine's probe wrappers
(`src/terminal/raw.rs`) are not includeable standalone (their
crate paths reach the whole terminal module), so the proof crate
restates the piped-sink answers beside their source
(`proofs/src/raw_stub.rs`, the Z6 `SYSTEM_MAX_RATE` restatement
precedent) and the harnesses drive the size-injectable cores the
benchmark harness already pins — the probes never enter a verdict.
The for-all tier's domain is the bounded pair (blank to first
frame, first frame to next frame) at 3x8 with a two-symbol
alphabet in full-width rows; variable row lengths, multi-hop
sessions, SGR-bearing rows, and the wide-frame domain ride the
sampled tier, where the solver's budget is not a guest. The tier's
solver verdict is the measured-open gap the census records (see
"the two tiers" above); its stand-down is the honest shape until a
lever lands.

## night-frontier-Z11 — the zero-heap frame ladder (D9)

Z4's allocation lens named the frame's remaining heap events and
staged them; Z11 closes the ladder's stages and pins every landing.
The floor pin (`steady_state_frame_composition_allocates_zero`,
test/ebpf/render/bench_floor.rs since the Z13-8 split) measures the
QUIETEST busy frame through a counting global allocator — the walk
STEPS until a contamination-free window reads the composition's own
count, bounded at 4096 busy frames (the lens's counter is process-
wide, the battery's parallel tests leak into windows, and Z13-12's
musl twin once contaminated every window of a 32-frame sample; a
real regression raises every window including the clean ones, so the
assert keeps its power). Its ceiling lowers in the same commit that
closes a named site — the ladder's own ratchet. The
measured floor, one line per stage, all on the same glibc dev box
and the same fixture:

- 249 heap events per frame — the pre-pool era (Z4's baseline).
- 164 after Z4's pooled-line discipline (~172 on the musl CI twin —
  the heap events are code x allocator, so every ceiling carries
  cross-allocator headroom).
- 150 after Z11 stage 1: the title bar, the swept bar, the grid
  lines, and the rail escapes write into caller-owned buffers
  (`title_bar_into`, `push_swept_bar`, `grid_line_into`,
  `push_rail_escape`, `push_sweep_run`), the frame path pops pooled
  rows for them, and the sweep memo's hit path appends the composed
  bytes instead of cloning them — the clone WAS the per-frame heap
  event the memo itself was paying.
- 100 after stage 2: the border wrap composes IN the pooled rows
  (`fit_in_place_border` walks the buffer in place, the background
  re-open splice lands via replace_range, the rails write through
  the escape twin, and the composed row stays in the buffer the
  call site handed over — the old shape even discarded that pooled
  buffer with `*line = row`); the closing row rides a pooled buffer
  with the sweep runs appending from the memo; the per-frame
  background escape writes into a retained module scratch. A
  drift-guard pin holds the in-place fit and the reference fit
  byte-identical over a hostile row set (CJK, wide glyphs, escapes
  mid-row, unclosed colors) — and it earned its keep immediately:
  its first run caught two wrong box-drawing escapes in the port
  itself, fixed before landing.
- 86 after stage 3a: the detail tree's line composition pushes
  pooled rows (`push_detail_lines` and the holder/endpoint/
  steady-rate twins beneath it) — the per-cgroup owned Vec<String>
  of fresh format!-built Strings was the named site.
- 34 after stage 3b: the footer's rows write into pooled buffers —
  every census, speed-pair, limit, legend, status, and signature
  row (the grey and brand brackets push their static opens and
  resets around `write!`-composed figures; the counts ride the Z4
  twins). The source-scan pin that grepped the old `brand(&format!())`
  spelling now greps the tier's own markers — the same contract,
  the into-twin's spelling.

The named remainder (each a stage-4 reopen, honestly small): the
detail tree's holders' walk scratch (the outer Vec plus one Vec per
holder), the signature engraving's internals (the output layer's
identity seat), and the focus view's own tree
(`full_detail_lines` plus the ranked board's Vec — outside this
pin's window, its own lens when the focus frame earns one).

**The A/B the owner's law asks for** (frame-bench.py, quick window
vs quick window, byte-identical LCG fixture, before = b21d345,
after = a3387d2): bytes/frame 1919.0 on both sides — the visual
parity the 204 render pins already proved, read back through the
metrics (emit bytes/frame 682.1 vs 682.2, density gini 0.3263 vs
0.3265, frame entropy 3.3526 vs 3.3515, dirty cells 113.5 vs 113.8
— every delta inside the window's noise). The allocation floor
dropped 164 to 34 across the same boundary: 4.8x fewer heap events
per frame, the deterministic-latency win without a visual change.

**Why it matters**: the monitor loop renders all day — a
zero-heap-approaching frame path means no allocator jitter in the
per-frame latency, no GC-adjacent pauses (Rust has none to amortize,
but the malloc/free churn still taxes the path), and a craft ceiling
a counting allocator in CI pins end to end. The claim this stage
earns: the composition half of the render loop runs at a measured
34 heap events per frame (down 86% from the pre-pool era), with the
pin holding every landing and the named remainder staged for the
next session.

## night-frontier-Z12 — the for-all completion (D10, the lemma decomposition)

The proof layer's own record named the lever ("the tier returns the
day its verdict fits the ceiling — lemma decomposition") and the Z12
depth is its execution, measured first. The census re-ran every
wired-out harness solo on the pinned kani 0.68.0 and, for the first
time, ISOLATED the wall instead of recording a timeout: the shapes
that grind are (1) division-inversion derivations (from
`elapsed < threshold / rate` conclude `elapsed x rate < threshold` —
the refill guard's pre-Z12 obligation), (2) multiply-monotonicity
relations (`elapsed <= NS` implies `elapsed x rate <= NS x rate`),
and (3) function-boundary arithmetic equalities (the harness's
recomputed mod/div chain against the function's internal one). The
shapes that decide in fractions of a second: constant div/mod chains
with CSE, constant-multiplier range claims over bounded symbolics,
single-site range bounds, and pure comparison implications. One
batch-measurement artifact fell out immediately: the bounded flow-key
collector decides in 0.2s solo — its pre-Z12 retirement was the
batch's cost, not its own.

**The rebirths, one per wall class:**

- **refill_credits — the split-multiply guard (the overflow-guard
  theorem, stronger than pre-retirement).** The fill-detect compare
  moved to the PRODUCT side of the threshold — the predicate the
  function's own contract always stated ("the exact arithmetic runs
  only while `elapsed x rate < 2 x burst x NS_PER_SEC`"), now the
  literal code: rate splits into its 32-bit halves, the one-second
  cap bounds both multiplies under 2^62, a shift-carry compare reads
  the overflow bit (the true product is `q x 2^32 + low`, and it
  reaches 2^64 exactly when `q` reaches 2^32), and the fitting side
  assembles the exact product. The shape is BIT-EXACT against the
  division-era form for every input — hostile rate, hostile burst,
  every boundary — so the boundary-window delta class the first
  draft carried does not exist. Two hard finds rode the landing: the
  prebuilt-parity gate caught the first draft's `checked_mul`
  lowering to the `__multi3` compiler-rt helper the aya loader
  cannot relocate (the gate's own find, the fail-closed arm working),
  and the split form is the gate-clean answer. The dividend: the
  per-packet refill path drops a symbolic 64-bit division from the
  BPF object, and the theorem's rate quantifier drops the
  SYSTEM_MAX_RATE assumption — for ALL u64 rates, the hostile
  persistent-map state included. The credited whole's magnitude law
  (`whole <= rate + burst`) stays with the sampled tier by
  measurement (wall class 2), the boundary vectors
  (`refill_credits_fill_detect_lands_on_the_threshold_edges`,
  `refill_credits_division_boundary_window_pins_the_product_shape`)
  hold the edges. The verifier budget's verdict was measured, not
  guessed: the first draft predicted a walk ratchet (a division out
  of the path seemed smaller to explore) and the Z9 census measured
  the OPPOSITE — the overflow branch and the product reassembly
  widened the explored walk by +2506/+2287 states on enforce_dl/ul
  (+0.35 percent), the growth law raised both budgets in the same
  commit and named the reason, and the trade is the honest one: a
  small verified-state price for a guard that carries no symbolic
  division and no loader-unrelocatable helper.
- **enforce — the hostile-state totality (the deepest statement in
  the tier).** The full verdict path (security-3 seed clamp, the
  window-ownership CAS, the refill, the lts-8 consume retry, the
  booking) now decides in 4.5s on the 2-CPU sandbox: with the refill
  guard structural, every remaining obligation is a range claim or a
  single-threaded CAS composition. The theorem keeps its full assert
  set — the boolean verdict, the burst cap on the stock, the
  sanitize-on-read fraction law — and quantifies over the same
  unbounded rate domain.
- **the ring law — two lemmas, honestly split.** Lemma one: the
  unbounded index bound (`(now / 1s) % 8 < 8`, for all clocks). Lemma
  two: the stamp protocol over the residue-complete clock range
  [0, 8s) — every index residue and every stamp-vs-window comparison
  class occurs there, the pre-states are arbitrary u64, and the
  protocol's translation invariance under `w -> w + 8k` generalizes;
  the harness states the domain reduction instead of hiding it, and
  it UPGRADES the pre-Z12 claim while it is there: all eight slots
  carry symbolic pre-states, and the no-backward law plus the
  untouched-slot law ride beside the stamp law.
- **the margin law — the extracted comparator.** `daily_active_rel`
  (a pure move out of `daily_active`, both trees compile it) is the
  three-comparison erosion law the for-all tier proves over every
  (rel, len, margin) triple; the day-reduction composition stays
  with the sampled tier and the during_tests vectors because the
  definitional link across two recomputed mod chains is wall class 3.
- **the bounded flow-key collector — re-armed as measured.**

**The lane**: proofs.yml carries TWELVE theorems now, as the matrix
of one-harness jobs the return condition always named — one verdict
per job, a grind can never starve a sibling's, every ceiling the
estate's own. The measured verdicts (2-CPU sandbox, the conservative
bound against the hosted runners): refill 1.5s, enforce 4.5s, ring
0.02s + 1.2s, margin 0.1s, flow-key 0.2s, the six standing theorems
unchanged (0.02–0.5s each). The tier table: twelve solver verdicts
per push, rootless, no assumptions hidden.

**Why never-done**: no per-app bandwidth limiter in this class ships
a machine-checked totality theorem over its verdict path — and none
ships one over the FULL hostile-state domain the persistent maps can
carry. The honest residue is named, not hidden: the credited whole's
magnitude law rides the sampler (wall class 2) — UNTIL the Z15
re-census measured the direct obligation on the post-Z12 bytes
deciding and landed it in the standing refill theorem (see the Z15
section; the Z12-era probes had measured a neighboring derivation
class, not the obligation itself) — the Z10 emission
conformance seat stays stood-down (the engine-heap circuit class,
its levers unchanged, re-confirmed by the Z15 per-path census), and
the Z12 census's probe record — which
algebra this solver generation decides — is the next maintainer's
map for every future harness.

## night-frontier-Z13 — the subprogram census (D11) and the zero-heap completion (D12)

### D11 — the bpf2bpf subprogram census: the rung the mirror named is already landed

The hole: the mirror's deferred entry (and the Z6 audit beside it) carried
two unmeasured sentences — "the B2B subprogram shape cannot dedup on a
loader that ships no func_info", and a reopen condition "the hand-rolled
loader ships program func_info (BTF-driven B2B dedup — real verifier
headroom for any future enforcer lane)". Both date from the raw-syscall
loader era; nothing in the tree counted the subprogram population of the
two embedded objects, and nothing recorded whether program func_info rides
the load path. A verifier rung proposed on unmeasured premises is exactly
the shape the estate's honesty law refuses — so Z13 measures before it
builds (the ACK-clock census precedent, Z7's D4).

The instrument (`scripts/supermassive/verifier-subprogram-census.py`): a
raw ELF/BTF walk of both embedded objects — BTF_FUNC kinds with linkage,
.BTF.ext func_info records, every call instruction (opcode 0x85) split by
its src_reg spelling, and the R_BPF_64_32 call relocations (the bpf-linker
on-disk spelling of a not-yet-relocated b2b call: opcode 0x85, imm -1, the
target arriving through the reloc; the loader rewrites it to
BPF_PSEUDO_CALL with the callee's byte offset at BPF_PROG_LOAD time). No
kernel needed; the objects are the parity-gated bytes both lanes embed
(ebpf-prebuilt/manifest.toml + scripts/gates/check-prebuilt-parity.sh).

The measured population (the v80.4.0 objects, the night-frontier-Z12
build):

- `zelynic-limiter.o`: 10 BTF_FUNC kinds — the four estate programs
  (enforce_dl cgroup_skb/ingress, enforce_ul cgroup_skb/egress,
  zelynic_pace and zelynic_recwn sockops) plus ONE user subprogram:
  `hist_record` (static linkage, .text+0, 292 insns), and the five
  compiler builtins (memcpy, memmove, memset, bcmp, memcmp). 30 b2b call
  sites, all in the two enforcers: 1 x hist_record + 14 x memset per
  enforcer, every one reloc-backed.
- `zelynic-observer.o`: 7 BTF_FUNC kinds — observe_egress and
  observe_ingress plus the same five builtins; ZERO b2b call sites and
  zero relocs (the dead rung by measurement on the observer side).

And the load-path proof (the sentence the audits got wrong): the loader is
not the raw-syscall walker of the Z6 era — it is aya 0.16
(`EbpfLoader::load`, src/ebpf/limiter/mod.rs), and aya-obj 0.6 parses the
objects' .BTF.ext func_info (the obj.rs Program struct carries
func_info/func_info_rec_size, filtered to the program's own section), then
aya fills them into the BPF_PROG_LOAD attributes (aya programs/mod.rs:
`func_info: func_info.clone()` into the load attr). Program func_info
ships on EVERY load — measured 116 B covering all ten limiter functions,
84 B all seven observer functions.

The verdict, three parts:

1. The rung "ship program func_info (BTF-driven B2B dedup)" is NOT A RUNG
   ANYMORE: it is the load path's standing reality. The mirror's reopen
   condition is satisfied-today and retires as a condition (the mirror
   stays deferred — its remaining conditions, the walk-cost ceiling and
   the in-process observer surface, are untouched).
2. The Z9 verifier budget ledger's armed numbers (enforce_dl 666635 /
   enforce_ul 706129, the night-frontier-Z12 raise, supermassive run
   45001505055) are measured ON THIS load path — they already carry
   whatever B2B dedup the kernel applies to the shipped func_info and the
   30 call sites. No hidden headroom is unlocked by "shipping func_info";
   it ships.
3. The census is the map for the future rung that DOES exist: the estate's
   b2b machinery (one static subprogram, one shared callee class, both
   enforcers calling it) is present and Z9-measurable — a future enforcer
   lane that wants the callee-once walk shape (the mirror's walk-cost
   condition) can lean on this shape and price it through the budget
   ledger. The observer's census is the honest zero: nothing to dedup
   there. (The rung landed as night-frontier-Z14 — the callee family,
   the walk collapse, and the two boundary laws the load census paid
   for; see the Z14 section above.)

The mirror's ledger correction rides this census (the stale loader
sentence and the satisfied reopen condition are rewritten in the deferred
entry, with this section as their proof).

### D12 — the zero-heap completion: the lens ceiling reaches zero, and the focus view too

The Z11 ladder stopped at 34 heap events per frame with the remainder
named — the detail tree's walk scratch, the signature engraving's
internals, the focus view's own tree. Z13 closes every named site,
measured phase by phase with the lens, each site named before it died:

- **stage 4a** (night-frontier-Z13-2, 19da5d2): the detail tree's
  holders' walk reads its endpoints through the capacity-warm
  HOLDER_WALK index buffer — the outer Vec plus one Vec per holder
  plus the ranked `to_vec` copy per multi-socket holder are gone.
- **stage 4b** (night-frontier-Z13-3, 4fbd782): the signature
  engraving materializes once into a `OnceLock<String>` and returns
  `&'static str` — process-constant bytes never re-format per frame.
  The ladder's ratchet: 34 -> 30 -> 27.
- **stage 4c** (night-frontier-Z13-4, d289db8): the composition's
  remaining events close whole — the board composes in the session's
  own warm scratch, the engraved footer assembles into the retained
  FOOTER_BLOCK with the champion's name resolving into the warm
  TOP_NAME buffer, the per-row detail block rides the retained
  DETAIL_BLOCK scratch, the scroll note composes into the pooled
  scratch, and every blank pad row pops the pool (a fresh
  `String::new()` carried zero capacity and the border wrap grew it
  six heap events per row). Every dropped row — the champion trim,
  the over-budget break, the scroll-note pop — hands its buffer BACK
  to the pool: dropping a pooled row starved the warm capacity and
  made the next frame pay a fresh allocation the walk could see. The
  measured quiet count: 27 -> 0, `FLOOR = 0` as an `assert_eq`.
- **stage 5** (night-frontier-Z13-5, 52f797b): the lens extends to
  the single-cgroup focus view — the uncapped full-detail tree composes
  as pooled rows through the SAME HOLDER_WALK scratch (5a, 114 -> 85),
  the key/value chrome rides the into-twin family with the blanks
  popping the pool (5b, 85 -> 7), the id lane resolves into the
  frame's STACK buffer and the baseline phrases compose through the
  pooled twins (5c, 7 -> 2), and the last two events were the walk's
  receipt, not a site: the focus title scratch was dropped without
  returning to the pool, the balance was EXACT, and the closing row's
  pop starved every frame — one recycle, zero.

The claim this closes: **a full-duty terminal monitor whose
steady-state frame allocates zero bytes — the ranked board and the
single-cgroup focus view alike — machine-pinned in CI with a counting
allocator ratchet**. The pins walk busy frames until a
contamination-free window reads the zero — `quietest of N walked
frames = 0 (floor 0)` on both frames, the scheduler lottery of the
parallel battery's global counter out of the verdict (Z13-12); the
htop/tmux/vim class allocates per
frame. The honest residue stays named: the claim covers the
composition half and the focus walk (the diff engine's half was
already zero, NIGHT-blade-16), the fixtures' assembly sits OUTSIDE
every lens window, and the owned twins that remain do so behind
`cfg(test)` for the oracle pins. The pins' homes after the Z13-8
split: `test/ebpf/render/bench_floor.rs` (the ranked frame) and
test/ebpf/render/bench_focus.rs (the focus view) — one file per
contract, the A/B harness staying in bench.rs.

## night-frontier-Z14 — the callee rung (D13): the enforcer's walk collapse

The rung Z13's census named: the b2b machinery (one static
subprogram, program func_info on every load) was present and
Z9-measurable, the mirror's walk-cost reopen condition pointed at
exactly this lever, and the Z12 lesson fixed the discipline — a
walk change is guessed by nobody, the ledger decides. The move:
the verdict path's DUPLICATED tail family — the code every
enforcement lane carries a flattened copy of at each call site —
becomes bpf2bpf callees, the shape hist_record has shipped since
night-frontier-2B. An inlined copy is priced by the verifier's
walk at every site it is flattened into, and the walk's state
pruning can never merge two copies at different instruction
addresses; a callee is one instruction range whose own frame keeps
its stack writes out of the caller's compared state. The landed
family: `ring_verdict` (every lane's return wrap — five sites),
`ecn_rescue` (the group and DRR drop tails), and `quic_flow_key`
(the 717-insn QUIC parser the per-socket and flow lanes each
carried whole — two sites), all `#[inline(never)]` beside
hist_record in the shipped objects.

**The boundary law, measured twice before it was believed** (the
Z14 load census, a local micro-VM instrument booting Debian's
7.3.5 kernel — the same 7.3 generation the ledger's armed pins
were priced on, reproducing the armed numbers byte-exactly on the
baseline side before the change was judged): a bpf2bpf argument or
return must be a SINGLE MACHINE WORD. The six-function family
first tried was refused by the kernel's verifier twice, at two
distinct boundaries — a 16-byte `Option<*mut>` argument crosses as
a stack arg the subprogram ABI refuses to read ("invalid read from
stack arg off 8", the ecn_rescue site), and the same shape carrying
`Option<*mut>` RETURNS was refused at the get_stats_ptr site
beside it (a register-invalidation verdict at the caller's
post-call code). ecn_rescue's stats seat therefore rides a RAW
pointer with null as the caller's None — the Option's own niche
spelling, semantically identical, one word wide — and the
get-or-create trio (`get_stats_ptr`, `get_bucket_ptr`,
`get_debt_ptr`) stays inline per the seat law: their bodies are
22-29 insns each (second-order walk beside the three big bodies),
their `Option<*mut>` returns would cross the measured boundary
law, and the call-site adaptation would churn enforce.rs against
its 600-line cap. Single-site helpers stay inline for the same
seat-law reason — a callee for a body reached once adds the call
sequence without removing any duplicated walk. The full record
lives in enforce_helpers.rs's Z14 block; the ABI law is the kind
of kernel truth this tree records because it cost two load
censuses to learn.

**The A/B, same kernel both sides** (the local instrument's
discipline: baseline objects first, armed-ledger reproduction
confirmed, then the factored objects):

| program | before (the armed pins) | after | the collapse |
|---|---:|---:|---:|
| enforce_dl | 666635 | 141893 | -79% |
| enforce_ul | 706129 | 133020 | -81% |
| zelynic_recwn | 139 | 139 | at pin |
| zelynic_pace | 63 | 63 | at pin |
| observe_egress | 70 | 70 | at pin |
| observe_ingress | 70 | 70 | at pin |

The enforcer's walk collapsed to a fifth of its armed budget —
524742 / 573109 verified_insns of headroom freed — while the four
programs outside the verdict path sit exactly at their pins
(untouched, as designed: the observer's census stays the honest
zero). The object tells the same story from the other side: each
enforcer section shrank from ~4.67K to ~3.1K insns (the duplicated
bodies now emitted once in .text), and the callee frames move each
callee's init scratch off the enforcer's single 512-byte stack
frame — headroom future enforcer lanes would otherwise eat first.
The mechanism is the state-pruning one: the walk's re-exploration
of the caller's branch tree no longer carries the inlined tails'
stack writes in every compared state, and each callee body is
priced per distinct entry state instead of per flattened site.
The CI supermassive battery is the pinning authority for the
ratchet (the census law's own rule: budgets move on watched-run
numbers); the local numbers above are the A/B the decision rode,
and the shape gate below holds the landed family against silent
regression.

**The shape gate** (the works-not-gimmick law, wired into the
supermassive verifier battery): the census script gained the
`--assert` mode and a pinned shape manifest
(`scripts/supermassive/verifier-subprogram-shape.json`) — the four
user static subprograms by name (hist_record, quic_flow_key,
ring_verdict, ecn_rescue) and the per-enforcer b2b call-site
counts (14 each: six reloc-pending beside eight direct
BPF_PSEUDO_CALL spellings), so a future change that re-inlines a
callee (the `#[inline(always)]` regression) or silently grows the
family fails the battery before the walk budget can drift one
commit at a time — the Z9 growth law's discipline, applied to the
shape the walk rides. Additions fail too: the shape file is the
ratchet, and a deliberate family change updates it in the same
commit. The battery line rides
`scripts/ci/supermassive-init.sh`'s verifier lane beside the
budget census, so the shape and the walk verdict share one lane on
every kernel envelope. The same census fixed its own decoder on
the way (the Z13 instrument read the register byte's LOW nibble —
the DST — for the call's src_reg, a misread invisible while the
baseline carried only reloc-pending sites; the direct-call
spelling the callee family introduced exposed it, and every direct
BPF_PSEUDO_CALL is now counted in its own bucket).

**The gate's first CI firing, and the floor-kernel forensics it
bought** (the shakedown the landing needed — every new gate earns
its first red before its first green means anything): the Z14
commit's own CI run (45180990128) fired the shape gate for the
first time and the gate failed LOUD, exactly as designed — with
`ModuleNotFoundError: No module named 'elftools'` on both verifier
lanes. The census imports pyelftools for its section/symbol/
relocation walk, and the micro-VM rootfs's tools closure
(`python3 iproute2 kmod curl nftables`) never carried it; the
gate's failure mode is loud by design (a shape gate that quietly
skips itself on a missing import is a ratchet that cannot
ratchet), so the fix belongs to the rootfs assembly: the
distro's pure-Python `python3-pyelftools` package rides the apt
line now (no pip lane, no PEP 668 dance), and the census
docstring names its own import contract where the next reader
looks. The same run's D4 byte-identity verdict job (45185192449)
died before `cmp` ever ran — "Can't find 'action.yml' ... Did
you forget to run actions/checkout" — one more member of the
v80.2.0 frontier SEAT's class (a job consuming the local
`./.github/actions/harden-dns` composite without riding a full
checkout; the estate's own law, written in release.yml's seat
comment, now holds everywhere by construction). Both fixes ride
the workflow files, not the gates: the gates named their own
missing parts, precisely.

**The floor-kernel histogram forensics** (the same run's engine
low lane — the honest unknown that stays an unknown): the
histogram live proof failed on the jammy 5.15.0 floor kernel
with the depth read's histogram answering null for the target
row mid-traffic, after gigabytes of bulk loopback traffic —
while the same commit's best-specs lane (newer kernel) answered
`download size samples 3->634`, and the pre-Z14 floor run
(b3bc25e) answered `430->431` on the same kernel, same battery,
same payload lane. The depth read's histogram section answers
null on exactly two branches (the pinned-schema gate at
`src/ebpf/render/depth_json/hist.rs`, or the row absent from
both direction maps), and the bare "answered null" note cannot
tell them apart. The local instrument could not reproduce it:
five independent floor-kernel runs of the exact CI payload
binary (the run's own `supermassive-vm-low` artifact booted
under TCG) — the fresh-attach shape, the `u --all` reload seam
the zombie stage leaves, and the FULL engine battery twice
(SMP=2 and SMP=1, matching the CI low lane's one-vCPU envelope)
— every run answered PRESENT with growing samples (18->24
across legs, 5->9, 6->15), the sampler and the read both alive
on the kernel the CI red came from. The remaining delta is
KVM-speed packet volume (27.8 GB per leg on CI vs 269 MB under
TCG emulation), which no local instrument here reaches. So the
failure path now carries the discriminator
(`_hist_null_facts` in the battery): on a null, the note names
the branch with the kernel's own facts — the pinned schema stamp
and the per-direction hist row counts, read through the bpftool
the VM already rides — turning the next red (if one lands) into
a bisected measurement instead of a mystery. The census-first
discipline, applied to a CI color: a walk change is guessed by
nobody, and a red that cannot yet be explained is instrumented,
never named away.

**The mirror's ledger correction**: the deferred mirror's first
reopen condition — "a walk-cost optimization frees the enforcer's
ceiling" — is satisfied by measurement as of this depth (the
ledger's own ruler: enforce_dl/ul at 141893/133020 leave the
walk under a fifth of the armed budgets, where the 32-branch
ladder's census refusal once measured "Processed 1000001 insn"
against a 666K base). The mirror itself stays deferred — its
other conditions (the in-process observer surface) stand
untouched — but the ceiling it names is no longer the wall it
was; the deferred entry below carries the pointer.

**Why never-done**: no per-app bandwidth limiter in this class
ships its verdict path as priced bpf2bpf callees — and none
carries the two-sided instrument that made the landing honest:
a walk ledger (Z9) that pins the verifier's own cost, and now a
shape gate that pins the codegen shape the walk rides. The
lesson the load census bought is the entry's second product: the
kernel's subprogram ABI is one machine word wide at every
crossing, and the estate now has that law written where the next
lane will read it.

## night-frontier-Z15 — the gigi census (D14): the magnitude law lands, the floor pulse is priced

Two disciplines, one depth. The proof layer's lemma-decomposition
craft (the "gigi theorem" — the obligation reformulated until the
solver decides, one tooth at a time) ran its first full census over
the two residues the tier carries; the kernel-floor watch (the LTS
pulse) ran its first scheduled sweep and priced the event it found.
Both products are measured, never guessed — the Z12 law, twice over.

### D14a — the gigi census: the credited whole's magnitude law rises to for-all

The census instrument: every candidate tooth a standalone harness
over the REAL law bytes (the #[path] include discipline, unchanged),
measured solo on the pinned kani 0.68.0 / CBMC 6.11.0, the 2-CPU
4 GB census sandbox — the conservative bound against every hosted
runner — under the 15-minute estate ceiling. The instrument was
calibrated BOTH directions before any verdict was believed: a
deliberately false bound on a constrained domain refutes in 0.10 s
with a concrete counterexample (VERIFICATION FAILED, the red path
proven live), and every decided verdict reproduced across runs.

The measured teeth, residue one (the credited whole's magnitude
law, `whole <= rate + burst`, the wall-class-2 record Z12 left):

| the tooth | the shape | the verdict |
|---|---|---|
| the direct obligation | the law as written, solo harness | **DECIDES — 2.07 s, 17 VCCs, zero failures** |
| the direct obligation, standing harness | the law added to the refill theorem | **DECIDES — 2.42-2.48 s, 31 VCCs** |
| the composition lemma | teeth imply law, pure comparison | **DECIDES — 0.029 s** |
| the threshold tooth | whole <= 2 x burst | UNDECIDED at the 570 s local ceiling |
| the rate tooth | whole == burst or whole <= rate + 1 | UNDECIDED at the 570 s local ceiling |
| the negative control | a deliberately false bound, constrained | refutes in 0.10 s (the calibration) |

The headline is the inversion the discipline exists to catch: the
record said the law was wall class 2 (multiply-monotonicity, "the
exact circuit class the probes measured undecided") — and the
DIRECT obligation on the post-Z12 bytes decides in two seconds.
The Z12-era probes had measured the derivation CLASS (elapsed <= NS
implies elapsed x rate <= NS x rate — two full symbolic
multipliers, a genuine grind) and the residue verdict generalized
from the neighboring class to the obligation. But the Z12
split-multiply restructure had already replaced the obligation's
own circuit — the product assembles from two cap-bounded
multiplies and the solver never needs the monotonicity algebra at
all. The Z12 lesson sharpened itself: a residue verdict is
re-censused against the CURRENT bytes before it is believed,
because a code change underneath a census can retire the wall
without a sound. And the census's second inversion: the FACTORED
teeth are harder for this solver generation than the assembled law
(the threshold and rate teeth both grind past the local ceiling
while the full obligation decides) — the inverse of the Z12
experience, where only decomposition fit. The map for the next
solver generation: the composition lemma (0.029 s) is the socket;
a future release that decides a factored tooth plugs it in with
zero further work.

The landing: the standing refill theorem
(`refill_credits_is_total_and_domain_bounded_for_all_inputs`) now
carries ALL THREE output laws for-all — the fraction domain, the
credited whole's magnitude, the zero-window credit — over the full
unbounded u64 rate domain, hostile persistent-map state included.
The assert rides the existing matrix job (no new CI seat, the
twelve-harness tier shape unchanged, the refill theorem's content
grown); the sampled twin keeps hammering the law 4096 cases per
run (the defense-in-depth shape, two instruments one law); the
rootless boundary vectors hold the edges as they always have. This
is the deferred-value conversion the Z12 record priced: a residue
rising to for-all is a theorem gained with zero churn — the
proptest harness, the boundary vectors, and the law bytes are all
exactly what they were; only the verdict tier moved.

Residue two (the Z10 emission conformance seat): the per-path
decomposition census measured three engine teeth — the idle
fast-path law (identical frame at identical geometry answers zero
bytes, no model application), the first-paint conformance (the
reset path alone, the standing theorem's first half), and the
batch law over the steady-state hop (one write per frame, no
model) — plus three per-token model teeth (content-commit,
erase-below, MoveTo). ALL of them exceed the census box: the
engine teeth die in the kernel's OOM (the same class the
2026-11-21 census recorded — the engine's symbolic heap, invariant
to domain dimensions, now measured INVARIANT TO PATHS TOO: even
the zero-byte idle path carries it), and the model teeth blow past
the unwind and VCC budget in the Vec machinery (1980 VCCs after
slicing, unfinished at the 300 s triage ceiling). The seat
therefore STAYS stood down, by measurement, with its named levers
unchanged — per-loop unwind annotations on a future toolchain
generation, a behavior-preserving proof-friendly indexing form
inside the engine, or the engine-side decomposition a future
solver generation can afford. The watch that guards the tier's
economics: the pinned kani 0.68.0 (2026-09-16) remains the LATEST
release as of this census (2026-11-24) — no free solver
generation arrived; the pin is current, and the next release is
the census's next scheduled re-run.

### D14b — the kernel-floor watch: the LTS pulse priced

The maintenance-mode contract names "kernel compatibility" one of
the three legal roads, and the watch is how that road is walked:
net-next read as rung events, each event priced through the
estate's own instruments. The first sweep (2026-11-24):

- **The ledger ratchet (the priced event).** The Z14 callee rung
  left the head envelope's walk budgets at the Z12 numbers with
  the collapse measured beside them; the watched run
  (45209186940, the Z14d commit's own CI) measured enforce_dl
  141893 / enforce_ul 133020 against the 666635 / 706129 pins —
  and the ratchet law's "encouraged follow-up" executed in Z15a:
  both pins lowered to the measured numbers with the run named in
  each row's history. The growth law now guards the COLLAPSED
  shape — any future walk growth above a fifth of the old budget
  fails the battery on every kernel envelope run. The other four
  rows measured exactly at their pins and did not move.
- **The rung facts that moved (recorded where they live).** The
  ACK-clock census table gained the v6.15 facts —
  `bpf_getsockopt(TCP_BPF_DELACK_MAX / TCP_BPF_RTO_MIN)` (the
  delack knob's READ side, new since 6.15) and the
  `TCP_DELACK_MAX_US` / `TCP_RTO_MIN_US` uapi sockopts — with all
  four reopen conditions re-verified CLOSED against torvalds/master
  (mainline 7.4-rc3): the 200 ms ceiling still binds both setter
  arms, no per-ACK sock_ops callback exists, `bpf_tcp_send_ack`
  remains unreachable from every func_proto table, and the BPF
  setsockopt allow list still carries no QUICKACK-class member.
  The record rides ACK_CLOCK_HYPOTHESIS.md section 7b — the
  hypothesis's rejection is now a standing watch, not a snapshot.
- **The LTS span asset (the claim kept alive).** kernel.org's
  longterm list still carries 5.15 (5.15.225, 2026-11-06) — the
  documented floor is a supported line, not archaeology — with
  6.1 / 6.6 / 6.12 / 6.18 beside it and 7.3.5 stable / 7.4-rc3
  mainline above. The span's both ends are CI-proven per push
  (the jammy 5.15.0 floor lane; the best-specs envelope's
  7.3.0-11-generic), and the compatibility matrix gained its 7.3
  row — the dynamically-resolved latest kernel the supermassive
  battery has been measuring green since the ledger's arming
  census. The BPF token deferred entry carries its first dated
  watch note: the delegation model is stable (Incus/LXD ship it),
  neither reopen condition moved. The capability ladder itself did
  not move — all ten rungs the objects consume sit at or under the
  5.15 floor, and net-next through next-20261118 grew nothing the
  lanes consume above it. The watch's own honest shape: most
  sweeps find nothing, and the finding is the value — an LTS claim
  that is re-verified against the moving kernel is an ASSET; one
  that is merely old is a liability.

**Why never-done**: no per-app bandwidth limiter in this class
re-censuses its proof-layer residues against the current bytes
(the residues most estates never name at all), and none prices its
kernel-floor claims through its own watched-run ledger — the LTS
span as a ratcheted, CI-proven contract rather than a marketing
line. The two disciplines are one habit: measure before believing,
re-measure before re-believing, and record the number with the
name of the run that produced it.

## night-frontier-Z16 — the field sensor (D15) and the booking law (D16)

Two disciplines that are not engineering: one turns the owner's
daily use into a standing instrument, the other names the claim
process as the estate's sellable asset. Both are documentation of
work the tree has already done — the harvesting backfilled from
the record, the law codified from retirements already kept — which
is exactly what makes them honest: nothing here is promised, only
recorded.

### D15 — the field sensor: field-evidence harvesting made durable

The estate's two most valuable deferred items wait on field
evidence, not code: the emit-on-change histogram (-9000m) reopens
on "field measurements across real traffic shapes", and the bypass
three-way (D6) reopens on "a user-reported bypass class the
interface-only delta demonstrably cannot see". The sandbox cannot
fabricate either — a KVM leg has no opinion about a real browser
session's histogram drift, and a witnessed miss is by definition
unscripted — so the only honest source is the owner's own machine
in daily use. The sensor was always free and always running; what
it never had was a ledger, so the evidence evaporated at 2 a.m.
and the reopen conditions' corpus stayed empty by bookkeeping, not
by absence.

[FIELD_EVIDENCE.md](FIELD_EVIDENCE.md) is that ledger: the watch
table (the two reopen conditions quoted verbatim from this page's
deferred rows — the conditions stay owned here, the log owns only
the evidence), the five-field entry format (date, observation,
instrument, home, disposition), the harvest protocol (record the
anomaly the same day; run the existing harnesses —
`quota-saver-ab.sh`, `ee-resource-bench.sh` — when a workload
class changes, never on a clock), and the graduation rule (an
entry satisfies a watch target by a dated update to the deferred
row naming the entries — the same pattern the Z14 mirror update
set — and the reopen itself stays the owner's call).

The founding entries E1-E5 are backfilled from the record the tree
already carries, and they are the proof the format works: the
2026-10-07 live bug-hunt session (four finds, four closures), the
2026-10-28 blocked teardown (the `__pycache__` class), the
2026-11-06 bounded-pair ~0% finding (the workload condition of the
whole quota-saver claim), the 2026-11-07 campaign day (the
five-rate curve, the 200kb-on-Brave session that made the bypass
audit name its band, the floor-bound window), and the 2026-11-09
masterclass — the owner's live readings that retired two bookings
at 36.8x and ~25x over, caught by daily use after every mechanism
the estate had blessed them. That last entry is the sensor's
calibration: field evidence is not a nice-to-have beside the
harnesses; it is the instrument that has caught what the harnesses
missed.

### D16 — the booking law: the claim process named as the asset

The claims ledger maps every public claim to the mechanism that
verifies it; what it never wrote down is the door every row passes
through first. [CLAIMS_VERIFICATION.md](CLAIMS_VERIFICATION.md)'s
booking-law section is that door, codified from the masterclass:
every number the estate publishes must carry the physics it owns
(the named mechanism a reader can derive, not "the formula looked
conservative"), the conservative pole (errs LOW, never high — and
when the honest booking is zero, zero ships), and the retirement
door (the named instrument whose reading kills it, with the
promise to run it). The v28 pair each named a conservative pole
and each over-claimed an order of magnitude anyway — the law's
lesson is that a pole is not a decoration, it is a contract, and
the audit that breaks it is an asset.

The law's six enforcement seats are all real, runnable, and
CI-enforced — the append-only layout walk (retired words read zero
at pinned offsets forever), the one-for-one booking pins (the sole
live counterfactual books exactly the delivered marks, never a
modeled multiple), the render-contract pins (the total is the live
booking alone, the honest "(est., counterfactual)" label), the
wire-truth door (the A/B harness — the booked number is never the
claimed saving), the dated-immutable record gate (retirements stay
on display, indexed), and the golden-vector ratification law. The
section's close names the commercial truth the owner's licensing
conversations already price: what a buyer buys is not the binary
but the claim process that survives its own audit — the ledger,
the dated-immutable trail, the vectors, and two graves on display.
A vendor with no graves has either no audits or no honesty.

**Why never-done**: no limiter in this class runs a standing
field-evidence ledger for its deferred items (most estates never
name their deferred items at all, so their reopen conditions can
never be satisfied — only abandoned), and none publishes a claim
law whose graves are the proof it is enforced. The two disciplines
are one posture: the evidence that would reopen a deferred item is
harvested before it is needed, and the numbers that survive are
the ones that can be killed.

## night-frontier-Z17 — the interleaving theorem (D17): the budget core proven for every schedule

The estate's proof tier had twelve theorems strong, every one of
them a single-threaded law: the refill totality, the clamp family
over hostile state, the consume sufficiency, the ring pair, the
margin erosion — all for-all over INPUTS, all silent over
SCHEDULES. The SMP hammers hammered sample interleavings; the
concurrency space itself — for every CPU interleaving of the CAS
draw / refill / debt pay / generation belt / NOEXIST init on the
same bucket, no corrupt state is reachable — stayed a sample
class. This rung closes that: the budget core is now proven for
every schedule, by a theorem shape the tier never had.

### The physics

`proofs/src/interleave_model.rs` + `interleave_segments.rs` +
`interleave_actors.rs` build a two-CPU model whose scheduling unit
is the SEGMENT — one observation phase plus at most one RMW/write,
the granularity at which the kernel's verbs are actually
preemptible (a volatile read feeding a later CAS is its own
scheduling point: the stale-observation window is the race the
boost-38 discipline exists to survive). Every segment calls the
dual-compiled primitives themselves — tokens_cas, tokens_fetch_add,
draw_stamp_take, gen_stamp_read/write, refill_credits, the debt
pair — the same bytes the kernel object builds. Two restatements
exist and are pinned, never hidden: the ecn word twins (private in
the core, restated verbatim, fidelity-pinned) and the draw/belt
program orders (the aya-touching halves, not includeable by the
proofs package's core-only law — their sequencing is pinned by the
segment bytes plus the sampler, the boundary stated in the model
header). The anti-gimmick instrument is the FIDELITY PIN: for all
inputs, each verb's actor run with nothing interleaved reproduces
the kernel function's own final state exactly — a machine that
restates instead of proving the bytes fails there, and the
property tier hammers the same equivalence per-push (4096
shrinkable cases per law, plus the chain pin — kernel == driver ==
actor). The fidelity tier's own census retired one lemma with
the record honest (the forward-clock refill lemma: two
refill_credits division pipelines the solver will not
common-subexpress; the backward-clock lemma stands verified, the
forward rides the sampled tier) — the full census, the two
findings, and the domain boundaries live in
[docs/research/NIGHT_Z17_INTERLEAVING_CENSUS.md](research/NIGHT_Z17_INTERLEAVING_CENSUS.md).

### The theorem

The schedule space is unbounded, so the proof is INDUCTION, not
enumeration: a corrupted reachable state implies a first
invariant-failing segment from a P-satisfying state, so
machine-checking that EVERY segment preserves P from EVERY
P-state (kani::assume(P) — the induction hypothesis, stated) proves
every interleaving of every length preserves P at every point.
The single-step tier quantifies over a conservative
over-approximation of the reachable schedule class (it admits
orders no verb's program order produces — green covers the real
coroutine schedules a priori), and the sampler exercises the
coroutine-shaped schedules directly (two actors, an adversarial
bit stream, the invariant asserted after every micro-step). The
invariant P is the "no corrupt state" claim made checkable — eight
laws, the ledger the exact conservation move: the token stock
accounted to the byte through every credit, burn, spend, pay, and
draw half in flight; the debt word capped; the leaf's taint split
exact; the belt's dead law; the stamp bound; the fraction domain;
the absent slot; the stamp provenance.
That ledger IS drr.rs's own headline — "DRR redistributes the
budget, it cannot create one" — as a machine-checked law, and it
is the no-lost-refill / no-debt-double-pay lemma pair the budget
core never had at the for-all tier.

### The finding the instrument filed

The theorem tier did not just verify the bytes — it
falsified one of the claims the kernel then shipped, with a
witness. The pre-patch generation belt's stamp write was
unconditional after its zeroing CAS: `let _ = tokens_cas(bkt,
stale, 0); gen_stamp_write(...)`.
Under an adversarial interleaving — a racing spend's remnant or a
racing draw's in-flight credit moving the stock between the belt's
read and its CAS — the zeroing loses, the discard swallows the
failure, and the stamp write certifies a dead remnant as
current-budget tokens: spendable forever, one belt episode wide,
bounded by the leaf's stockpile. The conservation ledger holds
throughout (the surviving tokens are real budget, never minted);
the violation is the certification, not the conservation — exactly
the class the belt exists to close. The witnesses are pinned
deterministically in `interleave_laws.rs` (both classes, shrunk to
hand-built schedules — the PRE-PATCH record, kept as the
falsification that drove the byte change), the sampler carries
the statistical pin (the violation class is reachable under
random schedules), and the GATED stamp segment — the six-line
close — refuses to certify an unzeroed stock and re-fires on the
next packet. The close's own landing arc is the rung's second
finding, and the estate's own gates wrote it: rung 4 (owner-approved,
2026-11-24) landed the re-observing form — the stamp write also
requiring the stock to re-observe zero, carrying the full law P4
with its own preservation theorem — and the live e2e lanes went
RED on the sustained-throughput rows the model cannot see: the
jammy sustain median 56% -> 11%, noble 62% -> 12%, the alpine
non-binding overhead +51.9% with zero drops — under sustained
delivery the stock moves through the re-observation, the belt
never converges, and it keeps zeroing freshly drawn budget. Rung 8
re-shaped the shipped bytes the same day to the zeroed-verdict
gate (the stamp lands when the zeroing CAS won or the stock read
zero): the stockpile-bounded class stays closed (a lost CAS
never certifies the remnant it failed to zero — the witness flips
green), the convergence restores the pre-patch timing (the live
lanes green again, the jammy sustain median 83%), and the form
carries ONE named residual — a racing draw's in-flight credit
inside the belt's write window, bounded by one armed take (the
quantum), the two-word atomicity floor itself — with the
conservative preservation theorem
(`every_shipped_belt_segment_preserves_the_conservative_laws`) at
the kani tier, while the re-observing QUIET form stands beside it
as the certified-but-unshippable certificate
(`every_quiet_belt_segment_preserves_the_full_laws`) — the full
close, priced. A second, smaller finding came from the law's own precision:
the single-step tier caught the mutation's catch-up corner (a
hostile genesis stamp the live generation can land on, in the
over-approximated pre-state space) — closed not by a quiet assume
but by naming the stamp's provenance as law P8 (a stamp that ever
moved is a belt write, at or under the live generation), the same
honesty discipline the carve-outs above carry. The honest claim
since the re-shape: the belt's zero claim holds at quiescence for
every schedule, the stockpile-bounded certification class is
closed in the shipped bytes, and the quantum-bounded in-flight
window remains — named, bounded, priced, and recorded (the
legacy witnesses and the ungated family's sampler statistic kept
as the falsification record).

**Why never-done**: no limiter in this class — not the Cilium
family, not the qdisc/sch_cake family, not any eBPF policer tool —
publishes an exhaustive interleaving theorem for its kernel
concurrency core. The industry standard is load testing and
fuzzing: samples, forever samples. The claim this rung banks is
narrow and honest: the budget core (the words the conservation
law rides) is proven for every schedule, not a sample — with its
instruments' boundaries stated (the shaping words' documented
slack, the memory-ordering tier unchecked, the two-word belt's
atomicity floor priced, the live-throughput tier outside the
model and caught by the estate's own e2e lanes), its
falsification on display, its first close falsified by its own
gates and re-shaped the same day, and its final shape landed as
the kernel's own bytes with the residual named — the prebuilt
lane re-pinned behind every byte change. Competitors cannot copy
that claim without building the proof culture first.

## The Quota Saver — the Workload-Conditional Claim

The fourteenth, fifteenth, and sixteenth entries above (RECWN, ECN,
pacing) save quota by three different physics — the clamp holds what
the sender CAN send, the CE mark makes the sender back off, the
pacer spaces the departure — and the Layer 4 telemetry (schema v28)
books each lane's saving by the physics it actually owns. The
formulas are the empirical math the telemetry fills — one live
(the ECN one-for-one) and two retired with their graves pinned the
same way — every one held by rootless unit tests and read live by
the probes.

**The formulas.**

- `bytes_saved_by_recwn` — RETIRED (night-recvn-audit, schema v30).
  The v28-era law booked the userspace window-law counterfactual
  (`display.rs recwn_saved_bytes`):

      bytes_saved_by_recwn = (bytes_allowed / clamped) x (default - clamped)

  with `default` pinned at 128 KiB (the kernel's `tcp_rmem[0]`
  initial receive buffer), named "the conservative pole: the
  estimate errs LOW, never high". The owner's live ss -tip reading
  (2026-11-09, brave at 200kb) proved the assumption false on a
  normal WiFi link — autotuned rcv_wnd of 48-78 KB across 11
  connections (the 128 KiB default was never on the wire), 1 of 11
  connections with a BDP at or above the 40 KB clamp (the other
  ten at 1.8-14.7 KB, impossible to fill the clamp with), almost
  every socket app_limited — and the formula booked 165 MB against
  72.4 MB of allowed traffic while the honest upper bound
  recomputes to at most a few MB: 10-30x over, erring HIGH against
  the contract it named. The honest booking is zero: the JSON key
  stays reading zero, the estimate function is gone, and the
  lane's real work (the SO_RCVBUF clamp) is untouched.

- `bytes_saved_by_ecn` — the QUIC 1:1 retransmission prevention
  (kernel-booked, one-for-one with `ce_marked_bytes`). Every
  delivered CE-marked byte is a byte that never becomes a
  loss-and-retransmission pair — and a dropped byte costs metered
  quota TWICE (the lost delivery plus the retransmission that
  finally delivers it), so the one-for-one floor is the conservative
  pole: the column books exactly the marked volume, never a modeled
  multiple.

- `bytes_saved_by_edt` — RETIRED (night-quota-audit, schema v29).
  The v28 booking read `(rate x time_elapsed) - bytes_uploaded` —
  the lane's theoretical budget minus the volume actually delivered,
  the preserved-headroom counterfactual. The owner's 2026-11-09 live
  reading broke the contract the other two lanes keep: a brave at
  500kb booked 744.6 MB against a 20 MB doc-formula prediction
  (36.8x over), a python3 at 300kb booked 1.8x over — different
  ratios per cgroup because the formula's only NONZERO content is
  the budget the sender did not use. A saturated paced lane books
  nothing (the budget lands within the packet's own length); an
  idle-ish lane books `rate x capped-gap` per packet — headroom for
  an upload that was never pending. A pacer RESCHEDULES bytes; it
  does not remove them, and no cap short of zero makes the
  counterfactual honest. From v29 on the word stays at its offset
  (offset 48, the pure-append layout law) and reads zero; the
  pacing lane's ENFORCEMENT (the SO_MAX_PACING_RATE pin, the
  policed verdicts) is untouched, and its wire effect — the
  suppressed burst-retransmission storm — is the A/B harness's
  measurement, never a booked number.

- `bytes_saved_total` — the sum of the surviving lanes (the ECN
  one-for-one, plus the retired EDT and RECWN words reading zero),
  the number `status --print-json` carries and the human table
  renders as `Quota Saved: X (EDT: Y, ECN: Z, RECWN: W)`.

**The probe record.** The live proofs carry a saved row each
(`recwn-probe.sh` row 6, `ecn-probe.sh`'s saved twin, `edt-probe.sh`
row 6 — the EDT row pins its retirement live since schema v29 and
the RECWN row pins its retirement live since schema v30: the words
move ZERO over the driven legs, and a reintroduced booking
fails the probe), and the recorded runs read like this:

- A 3 MB download with RECWN active booked 18.1 MB by the
  window-law estimate — the booking night-recvn-audit retired
  (schema v30): the estimate was the counterfactual, not a wire
  measurement; the clamp's real effect is the clamped window the
  recwn-probe rows pin plus the A/B harness's wire verdict.
- A 3 MB QUIC stream saved 65 KB of retransmission storm via ECN.

**The limitation, stated plainly.** QUIC first-packet still crosses
the WiFi. We save the retransmission storms, not the initial packet.
The lanes shape what a sender is ALLOWED to push and rescue what an
honest congestion signal can rescue; they do not un-send a datagram
the wire already carried.

The headline is workload-conditional, not a single number: the
ledger's counterfactual — the ECN one-for-one alone since the EDT
and RECWN retirements (schema v29/v30) — prices the marks the
lanes delivered, while the measured A/B ground truth on a bounded
20 MB pair came back at ~0%, the enforced leg moving equal-or-more
wire than the unenforced leg on both directions (2026-11-06). A
bounded
transfer's sender never attempts the overrun the booking prices;
the overrunning workload's sender never stops, and the A/B harness
(`scripts/bench/quota-saver-ab.sh`) now carries the overrunning leg
that measures the real saving. The deep derivations (the combined-
ledger granularity concession, the datapath call sites, and the
EDT booking's retirement record) live in `COSMIC_DRAGON_ARC.md`'s
Layer 4 section.

## Retired by verdict

Honest research includes what was tried and rejected. Both
rejections below are as load-bearing as the scales.

- **snapshot/restore — "GitOps for bandwidth" without a daemon.**
  Implemented, live-tested by the owner, and retired whole
  (NIGHT-improve-55, October 2026): a state file you must remember
  to dump before every reboot is a workflow your own script
  already owns, and pins die at reboot with bpffs anyway. A unit
  file re-applying the strict family IS the desired state.

- **Rate limit presets.** Shipped in the pre-v11 era
  (`strict --preset gaming/streaming/background`) and cut in the
  v11 surface freeze: named presets were indirection over three
  numbers the operator already knows, and the alias hid the actual
  rate from the very person responsible for it. The surface kept
  the numbers.

## Deferred by verdict

The frontier ledger — the five asks from the night-frontier-1 list
that are measured, named, and NOT built, each with the condition that
would reopen it. Honest research includes what was never started on
purpose; a silent no is the only dishonest one. The surface law every
rung rides (the owner's word, night-depth-hardening-1): no new CLI
subcommand, no new flag — depth lands inside the verbs and surfaces
that already exist, a minor bump, never a major.

- **BPF CO-RE — compile once, run everywhere.** The ask: one object
  image across kernel versions, no recompile per target. The measure
  (night-core-1, 2026-11-12): the datapath's kernel-internal field
  reads count exactly ONE (`bpf_sock.protocol`, frozen UAPI offset 12,
  two guard sites) beside helper-mediated call sites and UAPI context
  reads the kernel translates at load time, and both shipped objects
  parse to `core_relo_len = 0` — zero relocations to carry. The rustc
  `preserve_access_index` limitation is real but irrelevant: there is
  nothing to relocate. Deferred because CO-RE solves a cost this
  datapath does not pay; BTF is already the verifier's validation
  backstop and the versioned prebuilt lane carries distribution.
  Reopens when: the datapath starts reading kernel-internal structs
  directly — a structural rewrite, not a migration.

- **XDP ingress hook.** The ask: drop earlier than `cgroup_skb`, save
  stack CPU on drop-heavy ingress. Deferred: the engine is a POLICER —
  it shapes traffic to a rate; it does not exist to discard it. XDP
  runs before socket and cgroup attribution exist, so per-cgroup
  verdicts would have to be rebuilt at that layer, and a second
  hooking layer beside the cgroup-root ingress/egress pair breaks the
  one-hooking-layer design the whole engine rests on. Reopens when:
  the owner ships a pure-ingress discard product — a different tool,
  not an upgrade to this one.

- **Per-tenant hierarchical fair-share.** The ask: guaranteed,
  separate bandwidth shares between tenants (A and B) on one host.
  The state: the cgroup v2 hierarchy is already the tenancy substrate
  (subtree-aware attribution, #16's member resolution), and the DRR
  fair-shared bucket (#2) arbitrates siblings INSIDE one cgroup. The
  deferred step is the inter-tenant scheduler across sibling
  subtrees — the natural next rung, deliberately unbuilt until a real
  multi-tenant host exists to measure it honestly (the sandbox cannot
  fabricate tenancy, and a fairness claim without a measurement is
  the kind this tree refuses). Reopens when: such a host is available.

- **LSM-BPF enforcement hooks.** The ask: block socket creation by
  policy, enforcement stricter than policing. Deferred, leaning
  permanently: zelynic is read-only by design — it taxes traffic,
  it never refuses to create it, and bypass detection answers in
  shadow, never with a kill. An LSM hook would let the tool deny
  syscalls: a different trust contract, a different threat model, a
  different review surface. Reopens when: the owner decides to ship
  a second, access-control product.

- **BPF token — unprivileged enforcement (kernel 6.9+).** The ask:
  load the enforcement programs without root. The state: the 5.15
  floor and root-by-design are pinned contracts (the surface refuses
  loudly without both — the reliable-lts-1 ledger's Q1/Q5), and the
  kernel's BPF-token delegation is its own future lane for
  unprivileged loading. Deferred until the supported floor rises past
  6.9 AND a rootless enforcement story is measured safe: attribution
  without privilege is already honest (the resolver tree proves it),
  but enforcement without privilege changes the security model this
  tool ships with. Reopens when: both conditions hold. (Watched
  2026-11-24, night-frontier-Z15: the delegation model — bpffs
  delegate_cmds/maps/progs/attachs — is stable and shipping in
  Incus/LXD, a Cilium BPF-token CFP is the loudest pending consumer,
  and neither reopen condition moved on 7.3/7.4-rc; the next watch
  rides the kernel-floor pulse, KERNEL_COMPATIBILITY.md.)

- **Dive 3's sk_storage story family — socket CV, phase FSM, story
  export (night-frontier-Z3).** The ask: sk_storage carrying the
  socket's biography (birth timestamp, observer-seen
  retransmissions, the last-16-sample ring), a kernel-side phase
  byte (ramp → steady → decay → bad, inferred from pure packet
  metrics, never kernel-internal reads), and the story export — one
  socket printed as a timeline ("born → ramped 40ms → steady
  12Mbps → degraded@T+3s → recovered → closed": what happened on
  THIS socket, in order). Deferred whole by verdict: the mechanics
  are compositions of lanes the tree already carries (the
  sk_storage hint family of schema v31/v32, the rate rings, the
  depth histogram), but every consumer they would serve is a socket
  REPORT rewrite (night-engrave) that has not been commissioned —
  state without a story-reader is cost without a customer. Reopens
  when: the owner touches the socket report again — Stage 1 (the
  socket CV value struct) climbs to NOW for free the day that
  report is a real surface.

- **Resolution transparency (`--resolve`, Dive 4's -4000m rung).**
  The ask: `zelynic targets netns://x` printing the resolution
  CHAIN — URI → netns inode → cgroup path → pinned programs — the
  target not just answered but explained. Deferred by verdict: the
  substance already exists (every resolver failure names its
  discovery tip; the drift alarm, #20, verifies the identity the
  chain pinned) and what remains is a read-only verb plumbing those
  facts into one printout — a convenience surface, not a capability
  gap. Reopens when: an operator surface (a dashboard, a support
  flow) needs the chain as text more than the estate needs its next
  enforcement feature.

- **The clamp ladder's deep rungs — the per-socket clamp (-4000m)
  and the self-auditing clamp (-8000m).** The asks, stacked beneath
  #19's refusal: sk_storage carrying a per-socket EWMA RTT so the
  clamp's granularity is the socket, not the cgroup; and, after
  shaping is applied, the observability layer measuring
  achieved-vs-honest-ceiling and grading its own advice ("clamp
  verified: 94% of the honest ceiling") — a closed loop with no
  enforcement step in it, the observer auditing the limiter.
  Deferred by verdict: #19's bracket refusal is the honest surface
  both open through, and the rungs ride the same deferred floor as
  Dive 3's story family (per-socket state wants sk_storage, the
  self-audit wants a story reader to grade against). Reopens when:
  the refusal starts being felt in the field — a measured
  mixed-fleet surface the bracket cannot serve honestly.

- **Emit-on-change histogram (-9000m).** The ask: the kernel itself
  detects drift in the distribution's shape (a bucket's delta
  crossing a threshold) and the ringbuf speaks only when the story
  changes — silence as the default state, emission as the event.
  Deferred by verdict: the mechanics compose lanes the tree already
  carries (the depth histogram, the ringbuf paths), but the
  threshold is the research problem — when does a shape change MEAN
  something — and a mis-tuned threshold fails both ways at once:
  silence on a real drift, or the same periodic flood wearing a
  smarter hat. Reopens when: field measurements across real traffic
  shapes exist to tune the threshold honestly. (Watched since
  2026-11-24, night-frontier-Z16, D15: the reopen condition now has
  a standing instrument — the field sensor's log
  ([FIELD_EVIDENCE.md](FIELD_EVIDENCE.md)), whose traffic-shape watch
  records depth-histogram reads across real workload classes; the
  condition is judged against the log's accumulated entries when a
  graduation is proposed, and the reopen stays the owner's call.)

- **The mirror — zelynic publishing its own per-packet tax
  (night-frontier-Z6).** The ask: the datapath's own verdict-path
  wall time, sampled by a 1-in-1024 per-CPU tick and published in
  the `ee --depth` JSON — the one number no other limiter in the
  class publishes. The MECHANISM is proven and preserved whole:
  the law file (row shape, the clz bucket law, the record law, the
  fold, the bucket-bounded bounds) lives in the test tree with
  every law rootless-pinned (selfcost_core.rs +
  selfcost_core_tests.rs), ready to wire the day a live lane
  exists. The live leg refused three shapes, each its own signed
  lesson: the 32-branch log2 ladder exploded the verifier's
  explored states against the six-layer verdict path's state space
  ("BPF program is too large. Processed 1000001 insn"); the clz
  law (four instructions) still tipped the walk — the enforcer's
  budget is FULL, pre-existing, and any tail addition multiplies
  the widest state set; and the B2B subprogram shape's dedup premise
  is resolved by measurement (night-frontier-Z13, D11): the loader
  today is aya, it ships program func_info on every load, and the
  objects carry a live b2b shape (hist_record, the compiler's
  memset) — the Z6-era "ships no func_info" premise no longer
  describes the tree. The observer reframe measured
  worse still: the observer's maps are session-scoped in-process
  (the lazy camera pins nothing), so a one-shot depth read can
  never see them — publishing them would need pins, which would
  change the observer's session model. Deferred because the
  estate's honesty law prices a lane that cannot be read live as a
  gimmick. Reopens when: a walk-cost optimization frees the
  enforcer's ceiling (now measurable: the Z9 verifier budget ledger
  prices the estate's programs and gates their growth — and the Z13
  census proves the b2b subprogram shape and the shipped func_info
  such a lane would lean on already exist. UPDATE, night-frontier-Z14:
  this condition's walk-cost half is now SATISFIED BY MEASUREMENT —
  the callee rung collapsed the enforcer walks to 141893 / 133020
  verified_insns on the 7.3-generation kernel, a fifth of the armed
  budgets, where the mirror's census refusal once measured
  "Processed 1000001 insn" against a 666K base; the walk room the
  32-branch ladder lacked now exists. The mirror itself stays
  deferred — the observer's in-process surface condition below is
  untouched, and reopening is the owner's call), or the
  monitor gains an in-process surface that reads its own live
  observer handle. (The Z6-era loader condition — shipping program
  func_info — measured as already-satisfied: aya 0.16 ships it on
  every load; retired as a condition, not a blocker.)

- **Bypass three-way reconciliation (night-frontier-Z8, D6 — the low
  rung).** The ask: cross the three instruments the tree already
  carries — the bypass.rs interface-delta shadow audit (scale 10),
  the apply-side cgroupfs liveness census (night-total-hardening-1
  find 1), the observer census maps — inside the status/depth JSON
  that already exists, so a cgroup alive in cgroupfs that books zero
  observer rows while its interface delta is nonzero names the
  bypass class the interface-only delta cannot (namespace-hosted
  workloads exiting another interface). Shadow only; detection never
  enforcement. Deferred because the audits call the bypass lane PEAK
  and a new lie-class surface must earn its place — no field
  evidence exists of a bypass class the delta misses, and a marginal
  deepening built without a witnessed miss is innovation for its own
  sake. Reopens when: a user-reported bypass class lands that the
  interface-only delta demonstrably cannot see. (Watched since
  2026-11-24, night-frontier-Z16, D15: the reopen condition now has
  a standing instrument — the field sensor's log
  ([FIELD_EVIDENCE.md](FIELD_EVIDENCE.md)), whose witnessed-miss watch
  books the bypass-audit windows and session invisibilities daily
  use surfaces; the graduation names the entries, and the reopen
  stays the owner's call.)

## Reading order for a new maintainer

`ebpf/src/schema.rs` (the version-by-version contract history) →
`ebpf/src/mmspa.rs` + `drr.rs` (the budget core) → `enforce.rs`
(the verdict path) → `src/cli/surface.rs` (the frozen grammar) →
`docs/PHILOSOPHY.md` (why it is shaped this way at all).

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
