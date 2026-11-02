<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# The cosmic dragon arc

> One name for the whole animal. The thirteen scales, the heart
> that beats them, the eyes that watch, the claws that grip the
> kernel — the official index of every architectural power zelynic
> owns, and the roadmap for the power it is about to grow.

## The name and the family

**The cosmic dragon arc** is the official name of zelynic's entire
architectural stack — the enforcement core and everything that
loads, feeds, and watches it. The family already had names for the
parts (NIGHT-improve-68 named the engine, NIGHT-improve-17 named
the architecture); the arc names the whole, so docs, licenses, and
roadmaps can point at one banner instead of re-listing the
inventory:

- **the cosmic dragon architecture** — the body: pure eBPF, one
  hooking layer, no daemon (the architecture doc is the canon:
  [COSMIC_DRAGON_ARCHITECTURE.md](COSMIC_DRAGON_ARCHITECTURE.md));
- **the cosmic dragon engine** — the heart: the six-layer verdict
  path, defined canonically in [INNOVATIONS.md](INNOVATIONS.md);
- **the cosmic dragon render engine** — the sibling's engine
  (cosmostrix's diff-based renderer, ported by
  `src/terminal/diff.rs`);
- **the cosmic dragon arc** — the whole animal. One identity, one
  name, many engines; the arc is the name under which the engines
  ship, license, and evolve.

The lowercase law rides along (BRANDING.md 3.1b): the dragon is
lowercase everywhere and carries the definite article in prose,
exactly like `zelynic` itself.

## The anatomy

The arc names four estates. They are views over one codebase, not
a partition — a scale can sit in two estates at once (MMSPA is a
scale and half the heart), and that is the point: the estates
describe how each part earns its name inside the whole.

### The Scales — the thirteen kernel innovations

The thirteen research wins, in dependency order, each pinned by
rootless tests (the ledger with the full story per scale is
[INNOVATIONS.md](INNOVATIONS.md)):

| # | Scale | Schema | Code anchor | Rootless pin |
|---|-------|--------|-------------|--------------|
| 1 | MMSPA subtree law | v10/v12/v18 | `ebpf/src/mmspa.rs:183` | `mmspa_tests.rs`, `mmspa-vs-legacy-test.sh` |
| 2 | Fair-shared bucket (DRR) | v13/v17 | `ebpf/src/drr.rs`, `drr_flow.rs:203` | `drr_tests.rs`, `drr_ledger_tests.rs` |
| 3 | CAKE-style flow isolation | v20 | `ebpf/src/cake_flow.rs:203` | `cake_tests.rs`, `cake_battery_tests.rs` |
| 4 | Per-socket limiting | v15 | `ebpf/src/socket_flow.rs:174` | `policy_tests.rs` |
| 5 | QUIC-aware attribution | v22 | `ebpf/src/quic.rs:458` | `quic_tests.rs` |
| 6 | ECN-first policing | v19/v21 | `ebpf/src/ecn.rs:146` | `ecn_tests.rs`, `ecn_socket_tests.rs` |
| 7 | Guaranteed minimum (floor/ceil) | v24 | `ebpf/src/drr_guarantee.rs` | `drr_guarantee_tests.rs` |
| 8 | In-kernel time-series ring | v14 | `ebpf/src/rate_ring.rs:142` | `rate_ring_tests.rs` |
| 9 | Self-proving enforcement | — | `src/commands/probe.rs` | integration `smoke.rs`, `proof-claims.sh` |
| 10 | Bypass detection (shadow) | — | `src/ebpf/bypass.rs:170` | depth JSON verdicts, depth harness |
| 11 | Container-native resolution | — | `src/ebpf/identity/container/mod.rs:160` | `supermassive-test-v3.sh`, CI kind lane |
| 12 | Atomic multi-target rollback | — | `src/ebpf/limiter/atomic.rs:74` | `atomic_tests.rs` |
| 13 | Time-windowed policies | v23 | `ebpf/src/during.rs:216` | `during_tests.rs`, `during_user_tests.rs` |

Status of the audit behind this table: all thirteen live in code
today, all thirteen are documented, all thirteen are pinned — no
dormant scale, no orphaned doc (the 2026-11-03 depth audit, below).

### The Heart — the MMSPA and DRR engines

The two engines the verdict path beats with (scales 1-3): MMSPA
resolves which budget owns a packet through the cgroup subtree
(`mmspa.rs` + `mmspa_resolve.rs`, the generation-stamped leaf
cache), and DRR shares that budget fair across the leaves that
draw it (`drr.rs` + the `drr_flow*` family, the epoch ledger and
the guarantee brackets). The heart is where the pool lives; every
other estate exists to feed or watch it.

### The Eyes — the lazy camera and bypass detection

- **The lazy camera** (`ebpf/src/main.rs`, `observe_egress`:266 /
  `observe_ingress`:315) — the observer hooks that count every
  packet at `cgroup_skb` and never wake anyone: no event ring, no
  push, no daemon (the C-era ringbuf was dropped at NIGHT-boost-34).
  The counters and the rate-ring film develop in kernel maps until
  a reader arrives. Lazy by design: the camera records, the CLI
  develops.
- **Bypass detection** (`src/ebpf/bypass.rs:170`, the shadow audit,
  scale 10) — the eye that notices what the hooks never saw:
  interface-level deltas compared against what enforcement booked,
  floors that keep ARP noise honest, detection only, named
  honestly.

### The Claws — the eBPF objects and the userspace loaders

The grip that gets the kernel code loaded and lets go:

- `ebpf/` — the nested pure-Rust workspace (aya-ebpf, pinned
  nightly + `bpf-linker`), the two programs (`main.rs` observer,
  `bin/limiter.rs` enforcer) and the shared `core`-only law files;
- the staged objects under the **.o name law** — every object that
  leaves the build pipeline lands on disk as `zelynic-observer.o`
  / `zelynic-limiter.o` (the zejtron staged-object convention;
  raw nested cargo artifacts stay extensionless);
- `ebpf-prebuilt/` — the maintainer-built registry lane with the
  b3sum/size manifest pins, what `build.rs` stages into a plain
  stable-toolchain build and what the release tarballs embed;
- the userspace loaders — `src/ebpf/embedded.rs` (the aligned
  embed), `loader.rs`, `pin.rs`, `bpf_syscall.rs`, `lock.rs`:
  open the pinned maps, stamp the schema version, attach the
  bpf_links, exit. Fire-and-forget: the claws close on the kernel
  and release the process.

## The depth audit (2026-11-03)

The audit that named the arc, recorded so the next maintainer
starts from evidence instead of folklore:

- **QUIC-aware attribution verified end to end (schema v22).**
  `parse_quic` (`quic.rs:356`) statelessly parses long headers —
  version pinned to QUIC v1 (RFC 9000) and v2 (RFC 9369), both CID
  lengths bounded by the RFC 9000 v1 limit of 20 (`quic.rs:123`),
  the fixed bit checked, the whole header fitted inside the
  56-byte L4 window. Short headers carry the peer's CID with a
  length that is connection state (RFC 9000 negotiates it inside
  encrypted NEW_CONNECTION_ID frames), so the datapath learns the
  length from the handshake's own explicit bytes into the two
  per-direction hint maps (`quic_flow.rs:116`, LRU 4096,
  conversation-keyed), confirmation-gated: the same nonzero length
  must survive a second long-header sighting before any short
  header keys on it (`hint_confirmed`, `quic.rs:169`). Every
  refusal — non-UDP, non-QUIC, unconfirmed, zero-length CID, IPv6
  extension headers — rides the raw cookie: the lane refines
  attribution, never degrades it.
- **Enforcement-integrated, observability-neutral.** The per-socket
  lane and the v20 CAKE flow lane key their buckets by CID; the
  hint maps are datapath-internal by design (userspace never opens
  them, `quic_flow.rs:113`). The stats ledger stays the four-u64
  contract (`math.rs:220`, `types.rs:236`) — packets/bytes
  allowed/dropped — so no counter names CID-attributed or
  CE-marked traffic; the monitor's UDP endpoint tagging
  (`src/ebpf/render/detail.rs:89`) is the QUIC-adjacent surface.
  That is the documented posture, and it is also the first thing
  the quota saver must grow (the quota gap, below).
- **All thirteen scales green on Code/Doc/Test** — the table above
  is the verdict, each anchor re-checked against the tree during
  this audit.
- **One drift flagged, not fixed here** (kernel-side comment only):
  `ebpf/src/schema.rs`'s history comment skips the v16 and v20
  notes its userspace twin carries
  (`src/ebpf/limiter/schema.rs:155` and `:271`). The twin plus the
  rootless pins are the truth; the comment edit rides a future
  ebpf-side commit so this one stays docs-only.

## The quota gap

The honest limiter physics (README limitation #15): a dropped
download does not save quota — the ingress hook runs after the
packets crossed the WiFi link, and retransmits bill them again.
Egress drops save; ingress drops mostly do not. The 80% quota
saver therefore cannot be a drop feature — it must make the
SENDERS slow down before the bytes cross the link. Measured against
that goal, the arc holds four gaps:

1. **No quota accumulator.** Policies are rate policies; the
   ledger's `bytes_allowed` is cumulative-since-apply. There is no
   volume budget (a human quota with its own window and reset), so
   there is nothing for an "80%" threshold to read.
2. **No TCP receive-window enforcement.** Zero RWND code exists
   (verified: no `rcv_wnd`, `sndbuf`, `rcvbuf`, or window-rewrite
   path anywhere under `ebpf/src/` or `src/ebpf/`). The advertised
   window is the one knob that caps a TCP sender's in-flight bytes
   before they cross the link.
3. **ECN is enforcement-driven, not quota-driven — and invisible.**
   CE marking exists (v19 budget lanes, v21 per-socket lane,
   `ecn.rs`), and QUIC stacks that implement RFC 9002 ECN react to
   CE — the marking machinery is reusable. But marks fire only on
   budget overrun, and the four-counter ledger books a CE-marked
   packet as plain allowed: the saver's convergence could not be
   measured today.
4. **No EDT pacing.** Zero `skb->tstamp` / earliest-departure-time
   code exists (verified). The architectural tension to settle
   before building: EDT expects an `fq` qdisc to honor the
   departure time, and the architecture law bans configuring
   `tc`-qdiscs — the design must ride whatever qdisc the host
   already runs, or pace by other kernel means, and fail open.

## The next evolution (v81) — the owner's roadmap

The three layers below are the owner's stated vision, recorded
verbatim in substance so a future agent neither invents a fourth
layer nor reorders these. Docs and organization only landed this
roadmap; no RWND/EDT code exists yet, and none should until the
owner's build order says so.

- **Layer 1 — TCP receive window (RWND) enforcement.** Clamp the
  advertised window a policed cgroup's sockets advertise, so remote
  TCP senders hold their in-flight bytes down before the link
  bills them. The mechanism that actually saves download quota —
  the sender throttles itself, no drop, no retransmit bill.
- **Layer 2 — ECN CE-marking for QUIC backoff.** Reuse the
  ECN-first machinery (scale 6) as a quota signal: mark QUIC
  traffic toward the threshold so RFC 9002-ECN-capable QUIC
  senders back off on CE, per connection where the v22 hint maps
  can name one. Needs the ledger to count marks (the quota gap,
  item 3) so convergence is measurable.
- **Layer 3 — EDT pacing (earliest departure time) for egress.**
  Shape egress by departure time instead of drop: stamp packets
  with their earliest departure and let the kernel's pacing path
  smooth them. Egress already saves quota when dropped; paced it
  saves without the loss event at all.

The sequence is the owner's: RWND first (the quota saver's spine),
ECN-for-QUIC second (the lossless signal), EDT third (the egress
finish). The arc's existing scales are the foundation all three
stand on — the hint maps already name QUIC connections, the debt
word already charges per budget, the verdict path already runs on
both directions.

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
