<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Eagle-Eyes Deep Metrics Architecture — 2026-11-05 (night-netrunner-3)

The research-and-design audit the owner ordered: can eagle-eyes carry
Latency, Jitter, and Packet Loss without violating the product's three
laws — Zero Daemon, Pure eBPF, Boring and Serious? This document answers
the feasibility questions with file:line and kernel-source proofs,
measures the one number the cost argument turns on (live, this audit),
and lays out the UI contract for a default-mode `retrans` column and a
`--deep` secondary-line layout. It deliberately contains NO Rust code:
every figure below is either already measured by the kernel, already
read by the tree, or measured live for this audit — the design's whole
thesis is that nothing new needs to be built in the datapath.

The one-sentence answer: **the kernel already measures every honest
metric we want to display; eagle-eyes already holds the fds to read
them; the feature is a read, not a build.**

## The feasibility table

| Question | Verdict | Evidence |
|----------|---------|----------|
| **1a. Can we cheaply read `tcp_info` (RTT, retransmits) for active TCP sockets?** | **YES — in userspace, on fds the walk already duplicates; zero datapath change** | The socket census already duplicates every matched foreign fd via `pidfd_open` + `pidfd_getfd` and reads `SO_COOKIE` through it (`src/ebpf/connections.rs:369-418` — open `:375`, dup `:391`, cookie read `:400-408`, close `:412`). One `getsockopt(fd, IPPROTO_TCP, TCP_INFO)` at the same instant returns `tcpi_rtt`, `tcpi_rttvar`, `tcpi_total_retrans`, `tcpi_lost`, `tcpi_segs_out` (v5.15 `include/uapi/linux/tcp.h:214`, fields at `:231`, `:232`, `:244`, `:245`, `:254`) — measured LIVE at **194 ns/call** vs the 153 ns `SO_COOKIE` read the walk already pays (this audit's benchmark, one core pinned, 1,000,000 calls). `bpf_getsockopt` is NOT a door: it is absent from the cgroup_skb helper set at the 5.15 product floor (v5.15 `net/core/filter.c:7265` `sk_filter_func_proto` and `:7287` `cg_skb_func_proto` — no `BPF_FUNC_getsockopt` case in either switch). `bpf_sock_ops` IS a door (`sock_ops_func_proto`, filter.c `:7501`, carries getsockopt + `tcp_sock`) but it is a NEW program type, attach, and map family for a TCP-only sampler — rejected on the zero-surface law, section 3.1. |
| **1b. Can QUIC loss/jitter be measured purely in kernel eBPF?** | **NO — proven; the honest refusal is a designed tag, never a fake zero** | QUIC is TLS-encrypted userspace flow over UDP: the kernel sees sealed datagrams. RFC 9001 §5.4 header-protection masks EVEN the packet numbers with payload-derived samples, so no sequence numbers, no ACK clock, no timestamps are visible without keys the kernel never holds; loss detection lives entirely endpoint-side (RFC 9002). The tree's own QUIC core states the truth in its header: "QUIC packets carry the connection ID in the CLEAR even when the payload is encrypted... RFC 9000 negotiates it through NEW_CONNECTION_ID frames the middlebox cannot read" (`ebpf/src/quic.rs:35-44`), and every shape it cannot parse falls back to the raw cookie — coarser, never wrong (`quic.rs:52-69`). The kernel's only QUIC truths: outer UDP/IP byte counts (already booked, `ebpf/src/main.rs:265-356`) and ECN CE marks on the policed lane (`ce_marked_*`, schema v26). The UI must read `[encrypted/quic]`, never `0ms` — section 4.4. |
| **1c. What does per-packet latency/jitter math in the kernel cost?** | **REJECTED for the datapath; the sampled alternative is measured and negligible** | A per-packet engine needs one clock read (~20-30 ns, order-of-magnitude), one per-flow LRU lookup + EWMA RMW (~100-200 ns, order-of-magnitude) — roughly **0.15-0.25 us per packet per direction**, and the observer hook runs on EVERY packet of EVERY app unconditionally (`ebpf/src/main.rs:265-308`, `:314-356`): at 1 Mpps that is 15-25% of one core forever, spent on a column most sessions never open. The sampled userspace path costs **194 ns per socket per 3-second walk** (measured) — a 100-socket host spends ~19 us per walk, ~0.0006% of one core: five orders of magnitude apart, with strictly more truth (the kernel's own RFC 6298 smoothed RTT and RTTVAR). The full enforcement hook is already bounded at "1.75x + one-quantum" (`docs/audits/NIGHT_DRAGON_1_MASTER_SCALE_PROFILE_AUDIT_2026-10-27.md:53-54`) — per-packet vanity metrics would spend the observer's own bound on display. `--deep` therefore gates DISPLAY and figure granularity, never the datapath; the "1 in 10 frames" sampling idea maps onto the walk's 3 s TTL, the cadence the data already has (section 4.3). |

## Phase 1 findings

### 3.1 TCP metrics: three doors, one boring winner

The brief asks: "is `tcp_info` available via `bpf_getsockopt` or
`bpf_sock_ops`?" The audit checked all three doors against the 5.15.0
product floor (`src/ebpf/limiter/mod.rs:129`, `src/ebpf/loader.rs:93`,
the night-netrunner-1 law):

**Door 1 — `bpf_getsockopt` from cgroup_skb: CLOSED at the floor.**
The cgroup_skb helper set is exactly `cg_skb_func_proto` plus its
`sk_filter_func_proto` fallthrough (v5.15 `net/core/filter.c:7287`,
`:7265`; the tree's own cookie precedent is documented at
`ebpf/src/main.rs:22-24`). Neither switch carries
`BPF_FUNC_getsockopt`: the helper belongs to tc/clsact and sock_ops
programs, not to cgroup_skb. Any design that assumes it fails to LOAD
on the verified floor — the same class of wall that killed the events
ringbuf on 6.8 (`ebpf/src/main.rs:32-47`), and the audit treats
load-time walls as non-starters.

**Door 2 — a new `BPF_PROG_TYPE_SOCK_OPS` sampler: OPEN but OFF-LIMITS.**
`sock_ops_func_proto` (filter.c `:7501`) carries `getsockopt` and
`tcp_sock`, and sock_ops fires on TCP connection events where the full
`bpf_tcp_sock` view is legal. But this door means: a third program
family, a second attach point, new state maps, a schema bump, and a
TCP-only sampler that still cannot see UDP — the opposite of boring.
The kernel-native fields it would read are the SAME fields Door 3
reads for free. Rejected on surface, not on feasibility.

**Door 3 — read `TCP_INFO` on the fd the walk already duplicates: OPEN,
boring, and strictly dominant.** The connections walk already performs
`pidfd_open` + `pidfd_getfd` per PID and holds each matched socket's
duplicated fd long enough to read its cookie
(`src/ebpf/connections.rs:369-418` — the dup exists at `:391`, the
`SO_COOKIE` read at `:400-408`, the close at `:412`). A
`getsockopt(IPPROTO_TCP, TCP_INFO)` slots between `:408` and `:412`
with ZERO new plumbing — one extra syscall per matched TCP socket per
3 s walk. The struct it fills carries everything the feature needs
(v5.15 `include/uapi/linux/tcp.h:214`):

| Field | Offset | Meaning |
|-------|--------|---------|
| `tcpi_rtt` | `:244` | the kernel's own smoothed RTT (SRTT), microseconds |
| `tcpi_rttvar` | `:245` | the kernel's RTT mean deviation — RFC 6298 jitter, in the kernel's words |
| `tcpi_total_retrans` | `:254` | lifetime retransmitted-segment count, monotone — a differencing counter |
| `tcpi_lost` | `:231` | sender's in-flight lost estimate (recorded, non-goal) |
| `tcpi_segs_out` | `:260` | segments sent — the denominator for a retransmit share |

The walk's join key needs nothing new either: the cookie resolved at
`:400-408` is already the canonical per-socket identity the byte maps
use (`SocketInfo.cookie`, `src/ebpf/connections/types.rs:99-103`;
`ebpf/src/main.rs:199-210`). Deep metrics ride the SAME key, the SAME
walk, the SAME 3 s TTL (`connections.rs:57-59` — "detail lines
tolerate 3s staleness" is an EXISTING display contract this design
inherits, not a new one).

The kernel-native alternative inside the existing cgroup_skb hook —
`ctx->sk` (readable, `PTR_TO_SOCK_COMMON_OR_NULL`, filter.c
`cg_skb_is_valid_access :7820` delegating to
`bpf_skb_is_valid_access`) → `bpf_sk_fullsock` → `bpf_tcp_sock`
(both helpers ARE in the cgroup_skb set, filter.c `:7287` under
CONFIG_INET; fields at uapi `bpf.h:5357` incl. `srtt_us`,
`rtt_min`, `total_retrans`, `retrans_out`, `lost_out`, `segs_out`,
`segs_in`, `delivered_ce`) — is REAL and available at the floor. The
audit still rejects it: per-packet cost (section 3.3), verifier
surface on the always-on observer, a v29 schema bump, and new floor
verification work — all for figures the userspace read already
carries. Recorded here so the next audit does not re-open it as a
discovery.

### 3.2 UDP/QUIC: the honest refusal

The proof, in four steps, each checkable:

1. **Encryption covers everything the kernel would need.** QUIC
   payloads are TLS-protected end to end (RFC 9001), and header
   protection masks the packet-number field itself with samples taken
   from the payload (RFC 9000 §5.4; RFC 9001 §5.4.1). A kernel
   observer without the TLS keys cannot read packet numbers, cannot
   match ACKs to sent packets, cannot compute RTT or inter-arrival
   statistics. There is no "parse harder" — the bytes are noise by
   construction.
2. **Loss detection is endpoint-defined.** RFC 9002 puts loss
   detection inside the endpoint's state machine; the network path
   (and the kernel) sees only datagrams. A middlebox can guess at
   loss from timing patterns; guessing is exactly what this product
   refuses to display (the honest-read discipline: nothing pinned is
   honestly "unlimited", a failed read is an error, never a
   fabricated verdict — `src/commands/eagle.rs` header, and the
   footer's own law that a policy verdict is not a traffic
   observation, `src/ebpf/render/detail.rs:162-170`).
3. **The tree already accepts this truth in code.** The QUIC
   attribution core keys on the one clear-field family (connection
   IDs) and falls back to the raw cookie for every shape it cannot
   parse — "coarser, never wrong" is the module's stated law
   (`ebpf/src/quic.rs:52-69`). Metrics the kernel cannot count get
   the same treatment: coarser, never wrong. Coarser here means a
   TAG instead of a number.
4. **The kernel's QUIC truths are already on screen.** Byte totals
   (observer maps, `main.rs:265-356`), per-endpoint byte rates (the
   cookie join, `src/ebpf/render/detail.rs:135-153`), and — on
   policed paths — ECN CE marks (the v26 ledger). These stay. The
   refusal is only about Latency/Jitter/Loss figures.

**Design consequence:** for `udp`/`udp6` endpoints the metrics family
renders `[encrypted/quic]` — the tag is the truth. The tag names the
dominant shape (QUIC) but honestly covers every sealed-UDP payload:
DTLS, WireGuard, encrypted WebRTC. The kernel sees none of them; the
tag does not pretend to distinguish.

### 3.3 Cost: the per-packet tax vs the measured walk

**The kernel-per-packet estimate (order-of-magnitude, labeled as
such).** A latency/jitter datapath adds, per packet per direction: one
clock fetch (`bpf_ktime_get_ns`, ~20-30 ns), one per-flow LRU lookup
(~100-200 ns with bucket lock and state RMW), and an EWMA update
(~tens of ns). Sum: ~0.15-0.25 us. Scaling:

| Traffic shape | Packets/s | Core cost of the metric engine |
|---------------|-----------|-------------------------------|
| Quiet desktop | 5 Kpps | ~0.08-0.13% of one core, forever |
| Busy desktop / many apps | 50 Kpps | ~0.8-1.3% of one core, forever |
| Server / CI host | 1 Mpps | **~15-25% of one core, forever** |

The decisive fact is WHO pays: the observer hooks run unconditionally
on every packet of every cgroup (`main.rs:265-308` egress,
`:314-356` ingress — two helper calls, one to two LRU ops, two atomic
adds each, `stats.rs:97-111`). There is no per-session gate: a
feature gated by a `--deep` FLAG in userspace cannot un-tax packets
processed before, after, or without the flag, unless the hot path
grows a per-packet enable-map lookup — friction the flow audit just
finished removing (`docs/audits/NIGHT_NETRUNNER_2_FLOW_AUDIT_2026-11-05.md`,
the second-cookie find). The battery's overhead row
(`scripts/supermassive/supermassive-test.py:4381-4450`) would spend
its non-binding-policy budget on a display column.

**The userspace sampled path — measured live, this audit.** The
benchmark (loopback TCP connection, `taskset -c 0`, 1,000,000 calls,
gcc -O2, kernel 5.10.134 host — a floor-class CPU, not a fast one):

```
getsockopt(TCP_INFO):   193.6 ns/call   (the deep read)
getsockopt(SO_COOKIE):  152.7 ns/call   (the read the walk already does)
dup+close pair:         228.7 ns/pair   (the walk's existing per-fd plumbing)
```

One deep read costs 1.27x the read the walk already performs on the
SAME fd — the same cost class, not a new one. Scaling the walk:

| Host shape | Tracked TCP sockets | Extra cost per 3 s walk | Core share |
|------------|--------------------|------------------------|------------|
| Desktop | 30 | ~5.8 us | ~0.00006% |
| Dense session | 100 | ~19.4 us | ~0.0006% |
| Server census | 500 | ~97 us | ~0.003% |

Five orders of magnitude below the per-packet path, with strictly
MORE truth: `tcpi_rtt`/`tcpi_rttvar` are the kernel's own RFC 6298
EWMA pair — smoothed by the stack across every segment, not a noisy
per-packet sample. The kernel measured better than we would have.

**Why `--deep` still exists.** The flag gates the DISPLAY surface and
the figure family, not datapath work (there is none): default mode
keeps the two-column rate table plus ONE retrans count; `--deep`
adds the RTT/jitter family to the detail lines and the focus view
(section 4.3). The brief's "sample 1 out of 10 frames" maps onto the
walk's existing 3 s TTL: at the 1 s cadence the deep figures refresh
every ~3rd frame, already coarser than 1-in-10 — no sampler to build,
no new cadence machinery, the data arrives at the cadence it is
honest at. A future per-frame sampler (re-dup per frame: ~4 syscalls
per socket per frame, ~1 us/socket) is recorded here as the fallback
if an operator ever needs sub-3 s latency figures; it does not change
the datapath either.

## Phase 2: the design (no code)

### 4.1 The contract — what never changes

1. **The datapath stays byte-identical.** No new program, helper,
   map, attach, or schema bump. Every metric is a kernel-owned
   counter read through an existing fd.
2. **Zero daemon.** The figures ride the monitor's existing loop
   (`src/commands/monitor.rs:350-448`) and the existing 3 s walk —
   no background process, no new thread, no timer of its own.
3. **Absence, never a fake zero.** A figure exists only when the
   kernel state it came from was read this generation; everything
   else renders `—` or the honest tag. The house law, verbatim from
   the join ("Absent cookie = no figures, never a fabricated zero",
   `connections.rs:134`) and the JSON document ("null = no measured
   window... absence, never zero-as-fact",
   `src/ebpf/render/depth_json/mod.rs:73-77`).
4. **One figure, one home.** Every display surface renders from the
   same per-cookie sample store the walk fills; no surface re-derives
   (the `Proto::as_str` lesson, `connections/types.rs:57-79`).

### 4.2 Default mode: the `retrans` column

One field read, one new column, exactly as the brief scopes it.

**Where the figure comes from.** Each walk generation records, per
tracked TCP cookie, the sample
`{ total_retrans, segs_out, srtt_us, rttvar_us, at }` — taken at the
`cookie_for` window (`connections.rs:400-408`) where the dup already
exists. The default table's figure is the walk-to-walk difference:

```
retrans(row) = SUM over the row's TCP cookies present in BOTH generations of
               saturating_sub(total_retrans_now, total_retrans_prev)
```

The differencing pattern is the byte join's own (`join_prev` fold,
`monitor.rs:349`, `:398-415`); the saturating discipline is the house
style (NIGHT-boost-16). A socket present now but absent last
generation (fresh connection) contributes NOTHING — no truth about
the gap it was born in. A socket that died between generations
removes its lifetime count from both sums; the window figure
undercounts by exactly its last contribution — the documented
best-effort trade the socket LRU maps already carry
(`main.rs:180-184`).

**Where the column sits.** Right of `upload`, left of `total` — the
session figure keeps the rightmost anchor the right-gutter contract
gave it (`render.rs:215-232`). Column width 7 (the header spells
`retrans` in full — the surface vocabulary never abbreviates).
The ladder math (`render.rs:243-287`) gains one rung instead of
shifting the existing ones:

| Width | Columns | Change |
|-------|---------|--------|
| >= 62 | rank \| label \| download \| upload \| retrans \| total | new full rung |
| >= 54 | rank \| label \| download \| upload \| total | unchanged (retrans folds into detail lines) |
| >= 43 | rank \| label \| download \| upload | unchanged |
| < 43 | narrow fallback | unchanged |

The reservation: `RANK_W(7) + LABEL_MIN(12) + 3 x (1 + NUM_W(10)) +
(1 + 7) + RIGHT_GUTTER(2) = 62`. On the 54-61 width band the default
frame keeps its current shape entirely — a narrow frame never loses
a column it had.

**Row semantics.** A cgroup row's figure aggregates the row's TCP
sockets (the same set the detail tree renders from). Rows with no
tracked TCP sockets — QUIC-only browsers, UDP-heavy games — render
`—` in the column, never `0`: for that row the kernel holds no TCP
truth, and `0` would read as "no loss happening", a claim nobody
made. `0` renders only when a previous generation existed and the
difference was measured zero.

Mock (80 columns, default mode; the alignment law follows the
existing header format, `eagle.rs:354-376`):

```
    top process                  download     upload  retrans      total
   ----------------------------------------------------------------------
   1  brave (cg:73386 +3)        257 KB/s     8 KB/s       1   10.2 GB
      └ brave (1234) 2 sockets:
          ├ tcp 142.250.191.78:443 [busy] [dl 257 KB/s | ul 8 KB/s]
          └ udp 8.8.8.8:443 [dl 0 B/s | ul 0 B/s]
   2  chrome (cg:512)             12 KB/s    40 KB/s       —    1.1 GB
   3  syncthing (cg:998)               —          —        —    3.4 GB
```

The refresh cadence is the walk's: the column updates every 3 s, the
same staleness the endpoint lines already disclose. A figure that
only moves at walk granularity is honest; a figure that appears to
move per frame would be a rendering lie on a 3 s truth.

### 4.3 Deep mode (`--deep`): the secondary line, not a wider table

The ranked table's width ladder is already tight at 62 columns; four
more numeric columns would push the full shape past 100 and starve
the label. The design adds ZERO columns: the deep figures ride the
row's SECONDARY line — the detail-tree family the frame already
budgets per row (`eagle.rs:388-419`, the `used + need` row-slot
accounting).

**Flag.** `--deep` joins the `eagle-eyes` surface
(`src/cli/surface.rs:306-324`), orthogonal to `--depth` (the one-shot
report) and `--focus` (the depth window): on the live monitor it
widens the figure family; combined with `--depth --print-json` it
adds the JSON fields (section 4.5). One spelling; the vocabulary-tip
law applies to any future alias.

**Ranked view.** In `--deep`, each board row may grow ONE extra grey
line after its detail tree — the row's deep line for its hungriest
TCP endpoint (the ranking `rank_endpoints_by_bytes` already
establishes, `detail.rs:268-273`):

```
   1  brave (cg:73386 +3)        257 KB/s     8 KB/s       1   10.2 GB
      └ brave (1234) 2 sockets:
          ├ tcp 142.250.191.78:443 [busy] [dl 257 KB/s | ul 8 KB/s]
          │   rtt 19ms ±9ms · retrans 1/712 segs (0.14%) · 12 tcp eps
          └ udp 8.8.8.8:443 [dl 0 B/s | ul 0 B/s]
              [encrypted/quic]
```

Reading: `rtt 19ms` is `tcpi_rtt`; `±9ms` is `tcpi_rttvar` (the
legend names RFC 6298 once, in the footer line below — the screen
never spells theory); `retrans 1/712 segs (0.14%)` is the window's
retransmit share with the denominator shown — the count AND the
ratio, so no consumer has to trust a bare percentage. The row's UDP
children carry the `[encrypted/quic]` tag on their own lines
(section 4.4). The line budget: one deep line per row costs one row
slot; the frame shows fewer rows when it must — the adaptive budget
already degrades exactly this way (`eagle.rs:401-419`), and the
deep line hides below the same `show_total` boundary that hides
detail lines (the narrow-frame sacrifice ladder keeps its order:
detail first, deep figures first to go).

**Focus view.** The single-target view renders EVERY endpoint
(uncapped, `detail.rs:389-444`), so every TCP endpoint line gains
the `[rtt Xms ±Yms | retrans N/M (Z%)]` suffix — the same inline
suffix family as `[dl | ul]` (`detail.rs:135-178`, the
`steady_rate_field` precedent: inline figures, natural width, no
padding estate) — and every UDP/raw endpoint gains its tag. The
focused view is where an operator dissects one app; it is where the
full family belongs.

**Footer legend (one line, Full tier only).** When `--deep` is live
and the footer holds the Full tier (11 lines, `footer.rs:139`), one
grey legend line joins the census family, above the speed pair:

```
  deep: rtt ± is RFC 6298 rttvar · retrans counted per 3s walk · quic = [encrypted/quic]
```

Compact/Minimal/Tiny tiers drop it (the tier ladder's own
degradation, `footer.rs:139-165`); the figures on screen never
outrun the space to explain them.

**Cadence.** Deep figures refresh on the walk (3 s TTL). They are
snapshot figures at walk instants — RTT/jitter are the kernel's
running EWMAs read at that moment; retrans/segs are differenced
across generations. No per-frame smoothing, no client-side EWMA of
an EWMA: the kernel already did the smoothing; displaying it per
frame would only invent churn the underlying truth does not have.

### 4.4 Adaptive honesty: the tag family

The renderer law — figures ride the protocol, and the tag carries
what the number cannot:

| Endpoint proto | Latency/Jitter | Retrans/Loss | Rendered as |
|----------------|----------------|--------------|-------------|
| `tcp` / `tcp6` | `tcpi_rtt` / `tcpi_rttvar` | window retrans share | real figures, `—` when the walk's dup was refused (the graceful-degradation contract, `connections.rs:31-35`) |
| `udp` / `udp6` | NOT MEASURABLE | NOT MEASURABLE | `[encrypted/quic]` |
| `raw` / `raw6` | no L4 truth | no L4 truth | `[no l4 truth]` |

Rules that keep it honest:

1. **The tag never approximates.** `[encrypted/quic]` is not "0ms
   with extra steps": it claims nothing, which is the claim the
   kernel can back. A session where every figure is a tag still
   renders a working monitor — bytes and rates are untouched.
2. **`—` and the tag are different lies' opposite.** `—` on a TCP
   row means "this row has TCP but the read was refused" (dup
   refused, first generation); `[encrypted/quic]` on a UDP row means
   "no number exists in the kernel for this, by protocol
   construction". Two different absences, two different glyphs —
   the same discipline the empty-board and waiting-for-traffic
   frames already draw (`eagle.rs:259-263`).
3. **The cgroup row aggregates only what it owns.** The ranked row's
   retrans figure sums TCP truth only; the row's QUIC traffic is
   visible in the SAME row's bytes/rates, so the operator's mental
   join ("this row moved 257 KB/s, 12 of its sockets speak encrypted
   QUIC") is carried by the row itself, never by a fabricated
   blended "average loss" — averaging TCP loss with unmeasurable
   QUIC would be a fake number wearing an honest column's clothes.

### 4.5 JSON: additive fields on the depth document

`--depth --print-json` extends `EndpointJson`
(`src/ebpf/render/depth_json/mod.rs:67-83`) with four trailing
optional fields — additive under the stable contract, ignored by
existing consumers:

```json
{
  "pid": 1234,
  "comm": "brave",
  "proto": "tcp",
  "remote": "142.250.191.78:443",
  "state": "ESTABLISHED",
  "download_bytes": 2937600,
  "upload_bytes": 84200,
  "socket_inode": 1122334,
  "rtt_us": 19000,
  "rttvar_us": 9000,
  "retrans_window": 1,
  "segs_out_window": 712
}
```

For `udp`/`udp6`/`raw` endpoints, and for any TCP endpoint whose dup
was refused or whose first generation has no predecessor, the four
fields render `null` — the document's own absence law
(`depth_json/mod.rs:73-77`): absence is information, zero-as-fact is
fabrication. `segs_out_window` rides along so a frontend computes
its own share; the text surfaces never show a percentage without
its denominator (section 4.3). The live monitor's status JSON is
NOT touched in v1 — the depth document is where per-endpoint truth
already lives.

### 4.6 The cost ledger (design totals)

| Item | Cost | Class |
|------|------|-------|
| Kernel datapath change | 0 bytes | no program, map, helper, attach, or schema change |
| Walk-time syscalls | +1 `getsockopt(TCP_INFO)` per matched TCP socket per 3 s walk | 194 ns measured; 1.27x the `SO_COOKIE` read already paid on the same fd |
| Monitor-loop work | one saturating_sub per TCP cookie per generation | the `join_prev` fold's existing shape (`monitor.rs:398-415`) |
| Memory | one sample struct per tracked TCP cookie, two generations deep | bounded by the walk's own socket set; a hundred-socket host holds ~100 x ~24 B x 2 |
| TUI cost | one grey line per row in `--deep`, one footer legend line at Full tier | the diff engine emits only changed lines (`eagle.rs:89-91`) |
| Core share, 100-socket host | ~0.0006% | measured arithmetic, section 3.3 |

### 4.7 What this design does NOT do

- No Layer 5, no AI-ML, no anomaly scoring: the figures are
  deterministic kernel counters, displayed.
- No new eBPF program type, no `BPF_PROG_TYPE_SOCK_OPS` sampler, no
  `bpf_tcp_sock` in the observer hook (rejected with proof,
  section 3.1), no schema v29.
- No daemon, no thread, no timer: the walk and the loop own the
  cadence, as they own the bytes today.
- No blended cross-protocol averages, no "estimated QUIC loss" from
  timing heuristics, no per-frame jitter theater.
- No kernel-floor movement: every syscall and struct cited exists on
  the 5.15.0 floor and every kernel after it (TCP_INFO, pidfd_getfd,
  SO_COOKIE are all older than the floor itself).

### 4.8 Open questions, recorded honestly

1. **MPTCP.** v5.15 MPTCP sockets do not present a classic
   `tcp_sock` view through a plain `getsockopt(TCP_INFO)` on the
   MPTCP socket; the fallback is the same honest `—` a refused dup
   gets. Recorded, not solved — MPTCP deployment on the target
   estate is rare enough that absence beats a special case.
2. **Dup-refused sockets.** Locked-down hosts (no CAP_SYS_PTRACE for
   foreign fds) already render cookie-less endpoint rows today
   (`connections.rs:31-35`); deep metrics inherit exactly that
   posture — `—`, never zeros. The feature's graceful degradation is
   the walk's existing one.
3. **UDP sockets with `TCP_INFO`-shaped curiosity.** `getsockopt`
   on a UDP socket with `IPPROTO_TCP` fails cleanly (ENOPROTOOPT
   family); the walk knows the proto before it samples
   (`SocketInfo.proto`), so the failing call is never made. Stated
   because it is the kind of thing a rushed implementation would
   discover in production.
4. **`delivered_ce` per socket.** uapi `bpf.h:5357` exposes a
   per-socket CE counter; on POLICED paths the limiter's ECN ledger
   already counts CE marks (v26). Surfacing per-socket `delivered_ce`
   in deep mode is a natural follow-up that costs one more struct
   field — deliberately NOT in this design's scope; recorded so the
   follow-up finds its own entry.

## Conclusion

The feasibility question resolves the way the product's best
features do: the kernel already measured RTT, jitter, and retransmits
per socket — RFC 6298 smoothing, monotone counters, decades of
hardening — and eagle-eyes already holds, for every socket it
renders, a duplicated fd and a stable cookie join. The feature is a
read where competitors would build a datapath. QUIC cannot be
measured in kernel space, and the design treats that as a truth to
display (`[encrypted/quic]`), not an obstacle to fake past. The cost
case is measured, not argued: 194 ns per socket per walk against a
0.15-0.25 us per-packet datapath tax that would have run forever on
every packet of every app. Default mode grows one honest column;
`--deep` grows secondary lines the frame already knows how to
budget; the JSON grows four nullable fields. Nothing in the kernel
object moves a byte, and nothing in this document requires new
machinery to believe — every claim carries a file:line, an RFC, or a
measurement taken during this audit. That is the whole design: the
boring read, honestly tagged, at the cadence the truth actually has.

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
