<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-skill-2 audit — the two honest answers: hardware agnostic? and can it accelerate internet?

> Audit date: 2026-11-08 (night-skill-2, the owner's verify task).
> Scope: TWO questions that every claim in the README, the
> whitepaper, and the threat model silently assumes, stated nowhere
> in one place until this document. This is a VERIFY task under the
> peak-skip protocol: a surface already correct gets its verdict
> with proof; a gap gets its failure mode and the minimum fix. No
> new features, no new BPF programs, no schema bumps. Audited at
> 7dea86e (the clone the audit read; this document and the one-line
> USAGE pointer land as the task's single `research:` commit).

## The method, stated before the findings

The record was read before it was judged: the threat model
(THREAT_MODEL.md), the kernel compatibility ledger
(KERNEL_COMPATIBILITY.md), the architecture (COSMIC_DRAGON_
ARCHITECTURE.md), the whitepaper (QUOTA_SAVER_PHYSICS.md), and the
usage guide's honest-limitations section (USAGE.md). Then the code
the answers rest on was read: the limiter object source
(ebpf/src/bin/limiter.rs), the attach path
(src/ebpf/limiter/mod.rs), the enforcement verdict
(ebpf/src/enforce.rs), the identity resolver
(src/ebpf/identity/mod.rs), the token-bucket math (ebpf/src/math.rs),
the two sock_ops lanes (ebpf/src/pace.rs, ebpf/src/recwn.rs), the
bypass-shadow core (src/ebpf/bypass.rs), and the A/B harness
(scripts/bench/quota-saver-ab.py). Every file:line below was opened.
The tree was grepped for hardcoded interface names with the owner's
own pattern, and for any acceleration claim, with the counts
reported. The kernel's own cgroup_skb dispatch was verified against
the upstream Linux source (torvalds/linux master and the v5.15
floor, fetched at audit time — this audit host carries no local
kernel source), and the exact functions, macros, and call sites are
cited. The honest boundary: no wire was measured here — the
multi-carrier legs are a future campaign (named in Phase 4), and no
root-and-cgroup host was needed for these two questions, which are
structural, not empirical.

## Phase 1 — the record read (what was already signed)

| Surface | What it already states | Where |
|---|---|---|
| Threat boundary | Enforcement keys on the cgroup the process lives in, "resolved by the kernel on the packet path (`bpf_skb_cgroup_id`)"; moving between interfaces stays inside the same cgroup bucket | THREAT_MODEL.md:32-34, :37-39 |
| Bypass concession | AF_XDP, RDMA/RoCE, AF_PACKET raw injection exit through paths the cgroup hooks do not see; detected by the bypass-shadow audit, not closed | src/ebpf/bypass.rs:13-14; THREAT_MODEL.md:62-65 |
| Kernel floor | 5.15.0 floor; `bpf_skb_cgroup_id()` 4.18+; the helper set verified against kernel source | KERNEL_COMPATIBILITY.md:12, :21 |
| Hook model | cgroup_skb/ingress + cgroup_skb/egress, two programs, token-bucket enforcement | COSMIC_DRAGON_ARCHITECTURE.md:83-84, :92 |
| Quota physics | The savings formula, the five-rung measured curve, the peak declaration, the closure rules | QUOTA_SAVER_PHYSICS.md:129, :132-144, :286-311 |
| Honest limitations | The USAGE section future readers consult first | USAGE.md:1918-1923 |

Nothing in Phase 2 or 3 below contradicts the record; the two
answers make its silent assumptions explicit and dated.

## Phase 2 — Q1: is zelynic hardware agnostic?

**The owner's question, verbatim** (translated: is zelynic hardware
agnostic — whatever the internet type, WiFi, Ethernet, USB tethering,
4G dongle, Bluetooth tethering, as long as internet arrives, zelynic
is ready to control it; the analogy: a toll road, and zelynic is the
toll owner that opens and closes the gates).

**Verdict: YES, with named boundaries.** The toll-gate analogy is
structurally accurate: zelynic sits at the cgroup boundary, not the
interface boundary, and the cgroup boundary is upstream of every
carrier. The evidence chain:

### 1. The hook is cgroup_skb, not interface-bound

The two enforcement programs declare the kernel's cgroup socket-level
hooks:

- `ebpf/src/bin/limiter.rs:324` — `#[cgroup_skb(ingress)]` on
  `enforce_dl` (download).
- `ebpf/src/bin/limiter.rs:346` — `#[cgroup_skb(egress)]` on
  `enforce_ul` (upload).

Both attach at the cgroup v2 root, not to any device:

- `src/ebpf/limiter/mod.rs:137-140` — the attach path resolves the
  cgroup2 mount (`caps.cgroup2_mount_path`, default `/sys/fs/cgroup`)
  and opens that directory as the attach target. There is no
  ifindex, no ifname, no device flag anywhere in the call.
- `src/ebpf/limiter/mod.rs:322-328` — `create_and_pin_link(dl_prog_
  raw, cgroup_raw, BPF_CGROUP_INET_INGRESS, PIN_LINK_DL)` — the
  ingress attach rides the cgroup fd.
- `src/ebpf/limiter/mod.rs:329-330` — the same call shape with
  `BPF_CGROUP_INET_EGRESS` for the upload leg.
- `src/ebpf/limiter/mod.rs:359-365` and the pace twin — the RECWN
  and pacing sock_ops lanes attach at the same cgroup root, one
  attach type over (`BPF_CGROUP_SOCK_OPS`), so all four lanes share
  the interface-free attach surface.

A `cgroup_skb` hook fires for every packet attributed to a socket
owned by the cgroup, regardless of which physical or virtual device
the packet entered or left through. The device is not an input to
the hook's dispatch and not an input to the program's verdict.

### 2. Attribution is by cgroup ID, not by interface

The first datapath operation on every packet is the cgroup lookup:

- `ebpf/src/enforce.rs:92` — `let leaf = unsafe {
  bpf_skb_cgroup_id(ctx.skb.skb) } as u32;` — the SOCKET OWNER's
  cgroup ID, returned by the kernel helper. The helper never
  inspects the interface name, MAC, IP, protocol, or route.
- `ebpf/src/enforce.rs:100-109` — the policy lookup keys on that ID
  (the socket's own cgroup first, then the MMSPA ancestor walk via
  `bpf_skb_ancestor_cgroup_id`, `ebpf/src/mmspa_resolve.rs:197`,
  which is likewise interface-blind).
- `src/ebpf/identity/mod.rs:420-432` — the userspace resolver maps
  a cgroup v2 path to the same ID space with `stat(2)`: the kernfs
  inode number IS the cgroup ID (`bpf_skb_cgroup_id()` returns
  `cgrp->kn->id`). Resolution is filesystem metadata — again, no
  interface anywhere.

A corollary the record already states and this audit pins: a cgroup
with sockets on WiFi AND Ethernet has ALL its traffic policed by ONE
bucket. The budget is per-cgroup, not per-interface
(THREAT_MODEL.md:37-39). That is correct behavior by design; nobody
should expect separate per-interface budgets.

### 3. No interface name is configured anywhere

The owner's grep, run at audit time over `*.rs`, `*.toml`, `*.json`
(excluding `target/`, `.git/`, `docs/`):

```
grep -rniE 'eth[0-9]|wlan[0-9]|wlp[0-9]|enp[0-9]|usb[0-9]|wwan[0-9]|rmnet[0-9]|bnep[0-9]' \
  --include='*.rs' --include='*.toml' --include='*.json' \
  --exclude-dir=target --exclude-dir=.git --exclude-dir=docs .
```

Hits: 5 lines, ALL in one test fixture — `test/ebpf/bypass_tests.rs`
lines 44, 55, 66, 69, 75. These are synthetic `/sys/class/net`
directory fixtures (`class_net_fixture` with "eth0", "wlan0", "lo")
that stand in for a kernel-created class-net tree so the
bypass-shadow audit core can be tested rootlessly. They are data
built by the test, not configuration read by production code.
**Zero production hits.**

The complementary grep confirms the negative from the other side:
`rg 'ifindex|iif|oif'` over `ebpf/src/` and `src/ebpf/` returns
zero hits — neither the BPF objects nor the loader ever touch a
device index.

The A/B harness agrees by construction:
`scripts/bench/quota-saver-ab.py:173` defines
`VIRTUAL_IFACE_PREFIXES = ("lo", "docker", "veth", "br-", "virbr",
"tun", "tap", "wg")` and lines 516-522 sum `total_wire_bytes` over
EVERY OTHER interface in `/proc/net/dev` — the wire counter is
carrier-agnostic by design: whatever interface the bytes rode, they
count.

### 4. The kernel's own cgroup_skb semantics

This audit host carries no local kernel source, so the dispatch was
verified against upstream Linux (torvalds/linux, master and v5.15
tag, fetched 2026-11-08):

- `kernel/bpf/cgroup.c:1789` — `int __cgroup_bpf_run_filter_skb(
  struct sock *sk, struct sk_buff *skb, enum cgroup_bpf_attach_type
  atype)`. The first parameter is THE SOCKET. The function's own doc
  comment: "@sk: The socket sending or receiving traffic", and "If
  no socket is passed, or the socket is not of type INET or INET6,
  this function does nothing and returns 0."
- `kernel/bpf/cgroup.c:1802` — `cgrp = sock_cgroup_ptr(&sk->
  sk_cgrp_data);` — the cgroup whose program array runs is resolved
  FROM THE SOCKET's cgroup data. `skb->dev` is never consulted.
- `kernel/bpf/cgroup.c:1822, :1848` — the verdict runs
  `bpf_prog_run_array_cg(&cgrp->bpf, atype, skb, ...)` — the
  cgroup's effective program array, reached through the socket.
- `net/ipv4/ip_output.c:321, :340` — the egress dispatch sites:
  `BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb)` inside
  `ip_finish_output()` and `ip_mc_finish_output()` — the L3 output
  path, ABOVE the driver. The kernel hands the function the socket
  it already holds; the NIC is downstream of the verdict.
- `include/linux/bpf-cgroup.h:205-214` (master; the same shape at
  v5.15's line 243-251, the project's floor kernel) — the ingress
  macro gates the run on `cgroup_bpf_sock_enabled(sk, ...)`, whose
  fast-path check reads the socket's own cgroup data, and on
  `sk && sk_fullsock(sk)`. No full socket, no hook run.

The conclusion is structural, not statistical: the cgroup_skb
verdict rides the socket's cgroup, and every carrier — WiFi NIC,
Ethernet NIC, USB tethering (`usb*`/`rndis*`), 4G/5G modem
(`wwan*`/`rmnet*`), Bluetooth tethering (`bnep*`), VPN tunnel
(`tun*`/`wg*`), Docker bridge (`veth*`/`br-*`) — terminates at the
same socket layer. The dispatch is identical because the socket
layer is identical; the driver below it is not an input.

### 5. The honest boundaries

- **Forwarded traffic is NOT attributed.** A kernel bridge or
  router forwarding for other hosts moves packets with no
  originating local socket; the kernel's own contract is "if no
  socket is passed... this function does nothing and returns 0"
  (kernel/bpf/cgroup.c, the `__cgroup_bpf_run_filter_skb` doc), and
  zelynic's fast path allows a packet whose socket-cgroup lookup
  misses (`ebpf/src/enforce.rs:107-109`). zelynic is a
  process-level policer, not a router policer.
- **Bypass protocols are DETECTED, not closed.** AF_XDP rings drive
  the NIC directly, RDMA/RoCE bypasses the IP stack, AF_PACKET raw
  injection skips the socket path — the cgroup hooks never see that
  traffic (`src/ebpf/bypass.rs:13-14`). The eagle-eyes bypass-shadow
  audit detects the gap by comparing NIC totals against the ledger;
  closing it would require driver-level or hardware enforcement,
  which the pure-eBPF rule excludes (THREAT_MODEL.md:62-65 concedes
  hardware-level attacks outright).
- **Loopback fires, and is deliberately not counted.** cgroup
  attribution works on loopback traffic; the harness excludes `lo`
  from `total_wire_bytes` (quota-saver-ab.py:173) because local
  traffic does not bill a metered plan. No interface configuration
  is needed to make this so.
- **Virtual interfaces inherit the same verdict.** VPN tunnels,
  Docker bridges, macvlan: the hooks fire as packets enter/leave the
  cgroup's sockets; attribution is at the socket, not the interface.
- **Multi-interface same-cgroup is one bucket.** Stated explicitly
  (Phase 2.2 corollary): one cgroup budget across all its carriers,
  by design.

### 6. The single honest question that remains

Whether cgroup_skb empirically fires on each specific carrier —
4G/5G dongles (`wwan*`/`rmnet*`), USB tethering (`usb*`), Bluetooth
tethering (`bnep*`) — is a question of TESTING, not of mechanism.
Structurally the answer is yes: these are kernel netdevs terminating
at the same socket layer, and the dispatch above is carrier-blind.
But the verified cross-distro matrix and the 2026-11-07 five-rung
campaign ran on conventional NICs and WiFi; no dongle, no tether,
no modem was on the bench. The attribution is interface-agnostic by
construction; the empirical per-carrier verification is the owner's
(or community's) future campaign. The harness is already
carrier-agnostic — `total_wire_bytes` sums every non-virtual
interface (quota-saver-ab.py:173, :516-522) — so a multi-carrier
campaign needs a new run, not a new counter. That is a future
campaign, not a defect in this record.

## Phase 3 — Q2: can zelynic accelerate internet?

**Verdict: NO.** No software at the cgroup boundary can exceed the
physical link's capacity, and zelynic never tries. What it does is
preserve quota, allocate fairly, and improve latency within the
SAME bandwidth. The evidence chain:

### 1. The rate limit is an upper bound, never a lower bound

- `ebpf/src/math.rs:166-178` — the `Policy` struct carries
  `rate_bps` (line 167), `burst_bytes` (168), and the v24 guarantee
  bracket `floor_bps`/`ceil_bps` (the epoch allowance "never earns
  below" the floor and "never earns above" the ceiling — a bracket,
  not a boost; a row with 0/0 is the plain token-bucket law).
- `ebpf/src/math.rs:209-212` — the `Bucket` state is `tokens`,
  `last_refill_ns`, `frac_rem`. Tokens deplete on admitted traffic
  and refill at `rate x t`; the refill is `(elapsed_ns * rate_bps) %
  NS_PER_SEC` (math.rs:199). There is no code path that INCREASES a
  sender's rate: the hook's only possible verdicts are allow, drop,
  or ECN-mark — the kernel's egress return values are
  NET_XMIT_SUCCESS, NET_XMIT_DROP, NET_XMIT_CN (kernel/bpf/cgroup.c,
  the `__cgroup_bpf_run_filter_skb` doc and its two run sites at
  :1822/:1848). A policing decision cannot manufacture bandwidth.
- The two sock_ops lanes only ever push DOWN: the pacing lane sets
  `SO_MAX_PACING_RATE` to the policy rate (ebpf/src/pace.rs:14, :25,
  :47, :67 — the rate lands in `sk_max_pacing_rate`), and the RECWN
  lane clamps the advertised receive window (ebpf/src/recwn.rs:22-29
  — the RWND_INIT callback's return is a multiplier of MSS,
  SO_RCVBUF carries the floor). Lowering a window or a pacing cap
  reduces wire bytes; neither can raise them.

### 2. Physical bandwidth is the ceiling

The hook runs AFTER the TCP stack has produced the packet (for
egress, at the L3 output path — net/ipv4/ip_output.c:321 — after
the socket's send buffer, before the driver's queue). A packet can
only be allowed if the kernel already produced it; the kernel
produces packets only when the socket has data and the interface
can carry it. No software at the cgroup boundary can push bytes
into the interface that the kernel did not put there. The link's
capacity is the link's capacity.

### 3. What zelynic DOES do (the honest list)

- **Save quota on metered plans.** The savings is the rate limit
  itself: `(network_speed - rate_limit) / network_speed x 100%`
  (QUOTA_SAVER_PHYSICS.md:129), measured across five rungs on one
  host (:132-144). The link's speed is unchanged; the plan's bytes
  last longer. The telemetry books it as `bytes_saved_total` with
  the EDT/ECN/RECWN split (README.md:86, schema v28).
- **Improve fairness across apps.** The DRR / CAKE-shaped flow
  lanes (ebpf/src/drr.rs, ebpf/src/cake_flow.rs; wired at
  ebpf/src/bin/limiter.rs:79-126) ensure one greedy app cannot
  starve others. Multi-app browsing feels smoother because no app
  monopolizes the link. This is fair allocation of the SAME
  bandwidth.
- **Reduce bufferbloat-induced latency.** ECN-first marking
  (ebpf/src/bin/limiter.rs:284-303, the `ecn_debt_dl/ul` maps;
  math.rs v26 CE ledger) marks instead of drops where the packet
  allows it, avoiding the retransmit storm; the pacing lane paces
  egress at the socket. The whitepaper's 1mb finding — the ECN
  rescue adding ~33pp above the naive prediction at 1mb download
  (QUOTA_SAVER_PHYSICS.md:142, :150) — is exactly this: the lane
  preserved throughput that a drop-based policer would have lost to
  retransmits. The wire bytes at the receiver are the same as the
  unpoliced case once the sender converges; the lane avoids the
  storm in between. This is a quality-of-experience improvement
  within the SAME bandwidth.

### 4. What zelynic does NOT do (the honest negatives)

- Does NOT compress traffic (no gzip, brotli, no QUIC multiplexing
  magic — the QUIC lane, schema v22, is ATTRIBUTION, not
  transformation: it learns which cgroup owns an encrypted flow so
  the existing policy applies).
- Does NOT bond multiple links (no MP-TCP, no multi-path).
- Does NOT cache content (no CDN, no proxy).
- Does NOT change the kernel's congestion control algorithm —
  CUBIC/BBR are untouched; zelynic only paces at the socket level
  via `SO_MAX_PACING_RATE` (pace.rs:14) and shapes the receive
  window via SO_RCVBUF (recwn.rs:29).
- Does NOT exceed the physical NIC's line rate.

Verified by scan: a case-insensitive grep for `accelerat` across
README.md, docs/, src/, and ebpf/src/ returns ZERO hits. No
surface claims acceleration; nothing here to retract.

### 5. The user misconception to correct

"Quota saver" is NOT "speed booster." The name is accurate: a
metered plan's quota lasts longer because the app is held at a rate
below the network's speed. The byte count at the plan level is
smaller; the raw speed is unchanged. A user who reads "80% quota
saver" and expects "80% faster internet" is misreading the number —
80% is the share of the wire refused for the overrunning workload,
not a speed gain. The whitepaper already states the saver's
contract as the overrunning workload's marginal savings
(QUOTA_SAVER_PHYSICS.md:219-221); this audit pins the counterpart:
no speed claim exists, and none should ever be added — a "hardware
acceleration mode" would violate physics and the closure rule.

## Phase 4 — gaps found (the Phase-5 tripwires)

The verify task names three conditions under which a code change is
warranted. Each was checked; none fired:

1. **A hardcoded interface name in production code** — WOULD BE a
   hardware-binding gap. FOUND: none. The owner's grep hits only
   the `test/ebpf/bypass_tests.rs` fixtures (data, named above);
   `ifindex|iif|oif` has zero hits in ebpf/src/ and src/ebpf/.
2. **An "acceleration" code path** — WOULD BE a claim to verify.
   FOUND: none. The token bucket's only verdicts are allow/drop/
   mark (math.rs:199-212, enforce.rs); both sock_ops lanes push
   rates and windows DOWN (pace.rs:14, recwn.rs:22-29). There is no
   rate-increase path to verify.
3. **A documentation surface falsely claiming acceleration** —
   WOULD BE a doc lie. FOUND: none. Zero `accelerat` hits across
   the tree's user-facing surfaces; the whitepaper's framing is
   already the honest one (savings, not speed).

**Peak — confirmed, zero code changes.** The audit document and the
one-line USAGE pointer are the only deliverables, which is the
correct outcome under the peak-skip protocol.

The one honest limiter of BOTH answers: the empirical multi-carrier
test (4G dongle, USB tethering, Bluetooth tethering) has not been
run. The mechanism is carrier-blind by construction (Phase 2.4) and
the harness is carrier-agnostic by construction (Phase 2.3), so the
campaign is new runs on new wires — not a defect in this record,
and not a blocker for either verdict.

## Phase 5 — the verdicts

- **Q1 — hardware agnostic: YES, with named boundaries.** The
  cgroup_skb hooks at the cgroup v2 root, the socket-owned-cgroup
  attribution, the zero production interface names, and the
  kernel's socket-first dispatch (kernel/bpf/cgroup.c:1789, :1802;
  net/ipv4/ip_output.c:321) carry the verdict. Boundaries: no
  forwarded traffic, no bypass protocols (detected only), loopback
  uncounted, one budget per cgroup across all carriers, and the
  multi-carrier empirical run is a future campaign.
- **Q2 — acceleration: NO.** An upper-bound policer cannot create
  bandwidth. The honest alternative framing, in one line: zelynic
  preserves quota, improves fairness, and reduces
  bufferbloat-induced latency within the SAME bandwidth — the toll
  owner controls the gates; the road's width never changes.

## Gate results

This task changed documentation only (one new audit document, one
USAGE pointer line). Per the house rule, docs-only tasks skip the
benchmark wire run and run the light gate instead: the results are
recorded in the task's report, alongside the gate-keepers pass.

## Sources

- ebpf/src/bin/limiter.rs:324, :346, :376-380
- src/ebpf/limiter/mod.rs:126-140, :322-330, :359-365
- ebpf/src/enforce.rs:92, :100-109
- ebpf/src/mmspa_resolve.rs:197
- src/ebpf/identity/mod.rs:420-432
- ebpf/src/math.rs:166-178, :197-212
- ebpf/src/pace.rs:14, :25, :47, :67
- ebpf/src/recwn.rs:22-29
- src/ebpf/bypass.rs:13-14, :66
- scripts/bench/quota-saver-ab.py:173, :516-522
- docs/THREAT_MODEL.md:32-34, :37-39, :62-65
- docs/KERNEL_COMPATIBILITY.md:12, :21
- docs/COSMIC_DRAGON_ARCHITECTURE.md:83-84, :92
- docs/QUOTA_SAVER_PHYSICS.md:129, :132-144, :142, :150, :219-221, :286-311
- docs/USAGE.md:1918-1923
- README.md:86
- Upstream Linux (torvalds/linux, master and v5.15, fetched
  2026-11-08; no local kernel source on the audit host):
  kernel/bpf/cgroup.c:1789, :1802, :1822, :1848;
  net/ipv4/ip_output.c:321, :340;
  include/linux/bpf-cgroup.h:205-214 (master) / :243-251 (v5.15)

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
