<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

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
in STABILITY.md.

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
Seventeen frozen `/proc/net` rows (the six table families, the
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

## The Quota Saver — the Workload-Conditional Claim

The fourteenth, fifteenth, and sixteenth entries above (RECWN, ECN,
pacing) save quota by three different physics — the clamp holds what
the sender CAN send, the CE mark makes the sender back off, the
pacer spaces the departure — and the Layer 4 telemetry (schema v28)
books each lane's saving by the physics it actually owns. The
formulas are the empirical math the telemetry fills; every one is
pinned by rootless unit tests and read live by the probes.

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
  tool ships with. Reopens when: both conditions hold.

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
  shapes exist to tune the threshold honestly.

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
