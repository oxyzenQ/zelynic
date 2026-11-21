<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# The ACK-Clock Hypothesis — night-frontier-Z7, D4 (the ninth lane, research note only)

> The shelf in one paragraph: the quota saver's eight physics losses
> are signed and closed by construction (QUOTA_SAVER_PHYSICS.md,
> section 4), and seven of the eight admit no receiver-side lever.
> The one lever class nobody has implemented at cgroup scope — shaping
> the sender's ACK clock, synthetic RTT inflation via delayed-ACK
> modulation — is hypothesized here, censused here, and closed here:
> the project's own helper-ladder discipline (the 10/10 rungs shape,
> one rung per eBPF fact the hypothesis consumes) ran against the
> 5.15 floor and returns a signed NO for the inflation direction,
> with one verified rung recorded in the INVERTED direction —
> present, reachable, and useless for the saver. Zero code ships with
> this note. The record exists so a future floor's verdict is a
> diff against named facts, not folklore.

## 1. The hypothesis

A TCP download is self-clocking on the ACK stream: the sender paces
and grows its congestion window off the RTT and the ACK cadence the
receiver's ACKs reveal. The receiver chooses — inside its own delayed-
ACK parameters — WHEN each acknowledgement leaves, and every ACK is
also an upstream packet the plan bills. The hypothesis: a cgroup-
scoped receiver program that modulates the ACK clock (delaying
acknowledgements on the policed download sockets) would pace the
sender's congestion-window growth without a single drop and without a
single CE mark, through the same cooperative-sender physics the RECWN
lane already rides — the sender's own stack does the shaping, the
receiver only bends the timing signal the sender trusts.

The targeted losses are the two the current three physics (clamp,
mark, space) do not touch:

- **Loss 3 — the TCP timer and ramp-up tax at low rates.** The
  sender's slow-start ramp and retransmit timers spend wire time the
  formula does not model (~6 pp under at 100 kb). A slowed clock
  spends that time differently; whether it saves is a measurement
  question, gated below.
- **Loss 4 — the upstream ACK lane.** On a symmetric metered plan the
  acknowledgements bill upstream. Fewer, later ACKs (per-ACK coalescing
  by delay) would directly shrink the lane's packet count — the direct
  quota effect — while the induced RTT inflation works on loss 3.

The honest constraints the hypothesis inherits: no drops, no CE
marks, and the receiver must never stall the flow (section 4's own
warning — "a receiver cannot refuse to acknowledge without stopping
the flow entirely"). The lever shapes timing, never removes the
obligation.

## 2. The honest gate

The D4 verdict from the vault was explicit: whitepaper only, zero
code until the project's own helper-ladder census verdicts first —
the same discipline the attach floor rides (the ten-rung table in
`src/ebpf/helper_ladder.rs`, one rung per eBPF fact the objects
consume, each versioned from the canonical introducing commits). The
predicted verdict was a measured NO: "no bpf sock_ops lever for ACK
timing is known on the 5.15 floor." A predicted NO is a hypothesis
about the floor, and a hypothesis about the floor is checkable — so
this census checks it against the 5.15 sources themselves, line by
line, and records what the prediction missed.

## 3. The census — one rung per fact the hypothesis consumes

Every fact below was verified against the v5.15 source tree
(torvalds/linux, tag v5.15), with the file and line named. The floor
the project admits is 5.15.0; a rung is MET on the floor iff its
introduction release is at or below 5.15 AND its direction serves the
hypothesis.

| Rung | The fact | Since | Verdict on the 5.15 floor |
|---|---|---|---|
| 1 | `bpf_setsockopt` reachable from a cgroup-scoped sock_ops program (the delivery vehicle every other rung needs) | 4.13 | MET — `sock_ops_func_proto` returns `bpf_sock_ops_setsockopt_proto` (net/core/filter.c:7501); the pace lane pins `SO_MAX_PACING_RATE` through it live |
| 2 | `TCP_BPF_DELACK_MAX` — write the socket's max delayed-ACK timeout from BPF | 5.15 | PRESENT, INVERTED — the setter bounds the value to `[TCP_TIMEOUT_MIN, TCP_DELACK_MAX]` and stores `icsk_delack_max` (filter.c:4893-4898); the consumer clamps the ACK timer DOWN (`ato = min(ato, icsk_delack_max)`, tcp_output.c:3912) — the only writable direction is SOONER ACKs |
| 3 | RAISE the delack ceiling beyond the kernel's own cap | — | ABSENT — the setter rejects `timeout > TCP_DELACK_MAX` (200 ms, tcp.h:131) at compile time; the kernel's shipped ceiling cannot be raised by BPF |
| 4 | A per-ACK BPF callback (fires on ACK receipt or scheduling) | — | ABSENT — the v5.15 `bpf_sock_ops_cb_flags` enum carries RTO, RETRANS, STATE, RTT, and the header-option callbacks (bpf.h:5756+) — no ACK-schedule op |
| 5 | An ACK-suppression primitive (silence the kernel's own ACKs, own the clock) | — | ABSENT — no cb flag or op suppresses kernel ACK emission; the delack timer is not BPF-interceptable |
| 6 | `bpf_tcp_send_ack` (emit an ACK with a chosen rcv_nxt) | — | RESERVED, UNREACHABLE — the uapi table carries `FN(tcp_send_ack)` (bpf.h:4998) but NO func_proto set in v5.15 returns it (net/core/filter.c and net/ipv4/bpf_tcp_ca.c: zero matches) — no program type can call it on the floor |
| 7 | `TCP_QUICKACK` from BPF (force-immediate-ACK semantics) | — | ABSENT — outside the allowed SOL_TCP set (filter.c:4879-5000); and forcing immediate ACKs is the anti-direction anyway |
| 8 | A cgroup_skb delay primitive on the ACK path (re-time or queue an skb) | — | ABSENT — `cg_skb_func_proto` (filter.c:7287) exposes no setsockopt and no skb-scheduling helper class; a packet hook renders a verdict, it cannot reschedule the skb's departure |
| 9 | Write the socket's srtt (forge the RTT signal directly) | — | ABSENT — `bpf_sock_ops.srtt_us` and the `bpf_tcp_sock` fields are read-only context; the v31 lane reads them, nothing writes them |
| 10 | QUIC ACK-clock modulation at cgroup scope | — | OUT OF SCOPE for kernel levers — the endpoint application owns the QUIC ACK clock (RFC 9002 ACK policy is application state); a cgroup-skb hook cannot inject or delay frames without reimplementing the protocol — a model, not a lever |

## 4. The verdict

Signed, night-frontier-Z7 (2026-11-17): **the inflation direction is
censused NO on the 5.15 floor.** Rungs 3 through 10 are absent,
unreachable, or out of scope; rung 2 — the only kernel write to ACK
timing the floor carries — points the WRONG WAY. The predicted
verdict holds, and now holds with rung-by-rung evidence instead of
folklore.

The census's honest delta beyond the prediction: the prediction said
"no bpf sock_ops lever for ACK timing is known on the 5.15 floor."
That was one rung short. `TCP_BPF_DELACK_MAX` shipped IN 5.15 — the
floor's own release — and it IS a cgroup-scoped, sock_ops-reachable
ACK-timing write. It survives the census only as an inverted rung,
and the inversion is the section 5 verdict: the lever the floor
carries bends the ACK clock in the direction that bills MORE, not
less. The rejection record is therefore sharper than a flat NO: the
lane is closed not because no lever exists but because the lever
that exists is the wrong direction, and the direction that would help
is compile-time-capped.

## 5. Why the inverted rung cannot serve the saver

`TCP_BPF_DELACK_MAX` lowers `icsk_delack_max`, and the consumer
clamps the delayed-ACK timer DOWN (tcp_output.c:3912). Three
consequences, each independently fatal to the hypothesis:

1. **More upstream packets, not fewer.** A shorter delack ceiling
   makes ACKs leave sooner and cover fewer received segments each —
   MORE ACK packets on the upstream lane. On a symmetric metered plan
   that is loss 4 made WORSE, byte for byte of header overhead.
2. **A faster sender clock, not a slower one.** Sooner ACKs shrink
   the sender's measured RTT and feed its window sooner — the
   congestion-window ramp (loss 3) speeds UP. The saver's whole
   posture is making the sender send FEWER bytes sooner-billed; the
   inverted rung makes it send MORE.
3. **The ceiling is not even the binding constraint.** The stack's
   own timer is already bounded by the socket's measured RTT — when
   an estimate is known, the intersegment bound `max_ato` is lowered
   to `max(usecs_to_jiffies(tp->srtt_us >> 3), TCP_DELACK_MIN)` before
   the `icsk_delack_max` clamp (tcp_output.c:3899-3912) — and
   `icsk_delack_max` defaults to the kernel cap itself (tcp.c:429,
   2992). On any real link the dynamic timer rarely reaches the
   shipped 200 ms ceiling; lowering it only moves ACKs off the
   stack's RTT-adaptive schedule toward immediate-ACK behavior.

The saver's contract — err LOW, never high (the v29/v30 audit law) —
cannot ride a lever whose only reachable direction books more.

## 6. What the inverted rung IS good for

The record, stated honestly: rung 2 is a working, cgroup-scoped
kernel knob for ACK cadence — in the anti-direction. Its uses are
latency-hygiene shapes (pull a policed socket's ACKs off the delayed
path — the inverse of the saver's goal), not quota shapes. The vault
records it as the closest existing rung so a future reader does not
re-hunt it believing the flat NO left it undiscovered.

## 7. Reopen conditions

The lane reopens when a future floor exposes ANY of:

a. **A raisable ceiling** — a kernel where the BPF delack ceiling may
   exceed `TCP_DELACK_MAX` (a raised cap or an unclamped setter path).
   The minimal lever: synthetic RTT inflation by ceiling alone.
b. **A per-ACK callback** — a `BPF_SOCK_OPS_*` op fired on ACK
   receipt or scheduling, making per-ACK policy writable from BPF.
c. **Suppression plus emission at cgroup scope** — an ACK-suppression
   primitive paired with `bpf_tcp_send_ack` wired into the sock_ops
   or cgroup_skb func_proto sets. This hands the program the whole
   ACK clock and carries its own correctness obligation: the receiver
   must never stall the flow (the section 4 warning), so the design
   needs its own convergence analysis before it ships — the v21
   per-socket ECN closure's precedent, a research step before a lane.
d. **Forced-delay semantics** — `TCP_QUICKACK`-class mode forcing
   (or its delayed counterpart) entering the BPF setsockopt allow
   list.

The literature already prototypes the class: configurable TCP
delayed ACK under eBPF was implemented in the 2019 "Making the Linux
TCP stack more extensible with eBPF" work (Tran et al.) by ADDING new
eBPF callbacks to the kernel — the vanilla-floor gap the census
records is the same gap the paper had to patch around.

## 8. If a floor reopens it: experiment before code

The reopen path runs through the project's own gates, in order: the
census first (a diff of this document's rung table against the new
floor's sources), then a rootful A/B experiment on the project's own
harness — the policed cgroup's download sockets under the candidate
lever versus the current lanes, measuring the billed-byte delta, the
retransmission delta, and the bufferbloat cost of the induced delay —
and only a positive measurement opens the whitepaper's implementation
section. A lane that never took a measurement stays a lane that
never books a number; the v29/v30 audit law is the posture. Until a
floor reopens one of the four conditions, this shelf holds at
-11000m: whitepaper vault only, zero code, the ninth lane named and
closed.

## 9. Sources

- torvalds/linux tag v5.15, net/core/filter.c: `sock_ops_func_proto`
  (line 7501, `bpf_setsockopt` exposed to sock_ops),
  `cg_skb_func_proto` (line 7287, no setsockopt), the
  `__bpf_setsockopt` SOL_TCP switch (lines 4879-5000:
  `TCP_BPF_IW`, `TCP_BPF_SNDCWND_CLAMP`, `TCP_BPF_DELACK_MAX`,
  `TCP_BPF_RTO_MIN`, `TCP_SAVE_SYN`, the keepalive family,
  `TCP_SYNCNT`, `TCP_USER_TIMEOUT`, `TCP_NOTSENT_LOWAT`,
  `TCP_WINDOW_CLAMP`, `TCP_CONGESTION`, `TCP_SAVED_SYN` —
  `TCP_QUICKACK` absent).
- torvalds/linux tag v5.15, net/ipv4/tcp_output.c:3899-3912: the
  delack timer's `ato` computation — the srtt bound, then the
  `icsk_delack_max` clamp.
- torvalds/linux tag v5.15, net/ipv4/tcp.c:429, 2992: the
  `icsk_delack_max` default (`TCP_DELACK_MAX`).
- torvalds/linux tag v5.15, include/net/tcp.h:131-141:
  `TCP_DELACK_MAX` (HZ/5 — 200 ms), `TCP_DELACK_MIN` (HZ/25 — 40 ms),
  `TCP_TIMEOUT_MIN` (2 jiffies).
- torvalds/linux tag v5.15, include/uapi/linux/bpf.h: the
  `bpf_sock_ops_cb_flags` enum (lines 5756+ — no ACK-schedule op) and
  `FN(tcp_send_ack)` (line 4998 — reserved, zero func_proto exposure
  in net/core/filter.c and net/ipv4/bpf_tcp_ca.c on the same tag).
- tran, V.-H. et al., 2019, "Making the Linux TCP stack more
  extensible with eBPF": configurable TCP delayed ACK implemented via
  new kernel-side eBPF callbacks — the patched-kernel precedent the
  vanilla floor lacks.
- The project's own instruments: `src/ebpf/helper_ladder.rs` (the
  ten-rung discipline, the shape this census borrows),
  `src/ebpf/host_caps.rs` (the floor law), docs/QUOTA_SAVER_PHYSICS.md
  (the eight losses, section 4), docs/INNOVATIONS.md (the Z7 landing).

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
