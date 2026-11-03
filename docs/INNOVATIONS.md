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
Heart, Eyes, Claws), and the owner's v81 quota-saver roadmap all
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
policy remains the shared-budget answer; the flag opts a row into
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
enforcement hooks) and one pinned cookie-keyed LRU hint map. Two
kernel truths shaped the build, both verified against v5.15
source: the `BPF_SOCK_OPS_RWND_INIT` return value is an MSS
multiplier where 0 is the OS default (returning the sketched
"1 for default" would have clamped every unpoliced socket on the
machine to one segment — the program answers 0 and
`bpf_setsockopt(SO_RCVBUF)` carries the clamp byte-exactly), and
sock_ops on the 5.15 floor cannot resolve its own cgroup
(`bpf_get_current_cgroup_id` is absent from `sock_ops_func_proto`)
— so the ingress enforcement hook, which resolves every packet's
socket cgroup exactly, primes the cookie hint on the policed path
(one LRU lookup, steady state no write), and the program reads it
back at the connection callbacks. Active connecters — the
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
zero).

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
