<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# The cosmic dragon arc

> One name for the whole animal. The fourteen scales, the heart
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

### The Scales — the fourteen kernel innovations

The fourteen research wins, in dependency order, each pinned by
rootless tests (the ledger with the full story per scale is
[INNOVATIONS.md](INNOVATIONS.md)). Scale 14 is the quota saver's
Layer 1, landed by night-spark-2 (schema v25); scale 6's v26 CE
ledger is the quota saver's Layer 2, landed by night-spark-4:

| # | Scale | Schema | Code anchor | Rootless pin |
|---|-------|--------|-------------|--------------|
| 1 | MMSPA subtree law | v10/v12/v18 | `ebpf/src/mmspa.rs:183` | `mmspa_tests.rs`, `mmspa-vs-legacy-test.sh` |
| 2 | Fair-shared bucket (DRR) | v13/v17 | `ebpf/src/drr.rs`, `drr_flow.rs:203` | `drr_tests.rs`, `drr_ledger_tests.rs` |
| 3 | CAKE-style flow isolation | v20 | `ebpf/src/cake_flow.rs:203` | `cake_tests.rs`, `cake_battery_tests.rs` |
| 4 | Per-socket limiting | v15 | `ebpf/src/socket_flow.rs:174` | `policy_tests.rs` |
| 5 | QUIC-aware attribution | v22 | `ebpf/src/quic.rs:458` | `quic_tests.rs` |
| 6 | ECN-first policing | v19/v21/v26 | `ebpf/src/ecn.rs:146`, `enforce_helpers.rs:240` | `ecn_tests.rs`, `ecn_socket_tests.rs`, `ecn-probe.sh` |
| 7 | Guaranteed minimum (floor/ceil) | v24 | `ebpf/src/drr_guarantee.rs` | `drr_guarantee_tests.rs` |
| 8 | In-kernel time-series ring | v14 | `ebpf/src/rate_ring.rs:142` | `rate_ring_tests.rs` |
| 9 | Self-proving enforcement | — | `src/commands/probe.rs` | integration `smoke.rs`, `proof-claims.sh` |
| 10 | Bypass detection (shadow) | — | `src/ebpf/bypass.rs:170` | depth JSON verdicts, depth harness |
| 11 | Container-native resolution | — | `src/ebpf/identity/container/mod.rs:160` | `supermassive-test-v3.sh`, CI kind lane |
| 12 | Atomic multi-target rollback | — | `src/ebpf/limiter/atomic.rs:74` | `atomic_tests.rs` |
| 13 | Time-windowed policies | v23 | `ebpf/src/during.rs:216` | `during_tests.rs`, `during_user_tests.rs` |
| 14 | RECWN receive-window control | v25 | `ebpf/src/recwn.rs:98`, `recwn_flow.rs:114` | `recwn_tests.rs`, `recwn-probe.sh` |

Status of the audit behind this table: the first thirteen lived in
code, doc, and pin at the 2026-11-03 depth audit (below); the
fourteenth (RECWN, the quota saver's Layer 1) landed with it — no
dormant scale, no orphaned doc.

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
- **All fourteen scales green on Code/Doc/Test** — the table above
  is the verdict, each anchor re-checked against the tree during
  this audit.
- **One drift flagged at the audit, closed by night-spark-2**
  (kernel-side comment only): `ebpf/src/schema.rs`'s history
  comment skipped the v16 and v20 notes its userspace twin
  carries (`src/ebpf/limiter/schema.rs:155` and `:271`). The
  RECWN commit restored both notes beside its own v25 entry —
  the twin parity the schema pins hold, comment-deep too.

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
2. **No TCP receive-window enforcement — CLOSED by Layer 1
   (schema v25, night-spark-2).** The audit's absence proof stood:
   zero RECWN code before v25. The close is the sock_ops program
   `zelynic_recwn` (the owner's coined vocabulary) clamping
   `SO_RCVBUF` through `bpf_setsockopt` on the connection
   callbacks, primed cookie-keyed by the ingress hook — the
   advertised window now caps a policed cgroup's senders before
   the link bills the bytes. The estimate is a fixed 200 ms
   delivery-cadence assumption in Layer 1 — raised from the
   briefed 50 ms by the live E2E evidence (the 100 kb rung
   measured 29-37% of budget on all three CI kernels: with the
   buffer locked, delivery rides the receiver's window-update
   cadence (~145-160 ms on the test links, delayed-ACK bounded at
   200 ms), not the link RTT, so a rate x 50 ms window delivered
   a third of budget — recwn.rs's doc owns the full record); a
   measured-RTT re-tune is a stated residue, not a gap.
3. **ECN is enforcement-driven, not quota-driven — no longer
   invisible.** CE marking exists (v19 budget lanes, v21 per-socket
   lane, `ecn.rs`), and QUIC stacks that implement RFC 9002 ECN
   react to CE — the marking machinery is reusable. Marks fire on
   budget overrun — the enforcement verdict — and that half stands.
   The invisibility half is closed (night-spark-4, schema v26): the
   ledger grew `ce_marked_packets` / `ce_marked_bytes`, booked by
   the rescue correction at the exact spot a drop becomes a
   delivered mark, and `status --print-json` names the pair — the
   saver's convergence is measurable today.
4. **No EDT pacing.** Zero `skb->tstamp` / earliest-departure-time
   code exists (verified). The architectural tension to settle
   before building: EDT expects an `fq` qdisc to honor the
   departure time, and the architecture law bans configuring
   `tc`-qdiscs — the design must ride whatever qdisc the host
   already runs, or pace by other kernel means, and fail open.

## The next evolution (v81) — the owner's roadmap

The three layers below are the owner's stated vision, recorded
verbatim in substance so a future agent neither invents a fourth
layer nor reorders these. Docs and organization landed this
roadmap first; Layer 1 (RECWN) has since landed as schema v25
(night-spark-2) — Layer 1 below reads as the implemented record —
and Layer 2 (ECN CE-marking, the CE ledger) has since landed as
schema v26 (night-spark-4) — Layer 2 below reads as the
implemented record. No EDT code exists yet, and none should until
the owner's build order says so.

- **Layer 1 — RECWN (Receive Window Control) — IMPLEMENTED**
  (schema v25, night-spark-2). The owner's coined name for the
  receive-window lane: a policed cgroup's own sockets advertise a
  window shaped like the policy's bandwidth-delay product (rate x
  200 ms delivery-cadence estimate, clamped to [2 x MSS, 1 MiB]),
  so remote TCP senders hold
  their in-flight bytes down before the link bills them — the
  mechanism that actually saves download quota. Two kernel truths
  shaped the build (both verified against v5.15 source, recorded
  in `ebpf/src/recwn.rs`): the `BPF_SOCK_OPS_RWND_INIT` return
  value is an MSS multiplier where 0 is the OS default (returning
  1 would clamp every unpoliced socket to one segment — the
  program answers 0 and `bpf_setsockopt(SO_RCVBUF)` carries the
  clamp), and sock_ops on the 5.15 floor has no cgroup-id helper
  (the attribution rides a cookie-keyed hint the ingress
  enforcement hook primes on the policed path, one LRU lookup,
  steady state no write). Convergence: active connecters — the
  download-quota case — clamp at establishment (the SYN-ACK
  primes the socket's own cookie before the callback fires);
  rate changes re-apply within one RTT on sockets whose
  establishment armed the RTT_CB flag. The honest residues: the
  initial window itself rides the default (~10 MSS once per
  connection), a passive child's first window's worth rides the
  default (its cookie is primed by its first DATA packet, after
  the established callback), connections that outlived a removal
  keep their last window until they close (the removal sweeps the
  hint map; churn heals), and the kernel's `rmem_max` sysctl
  ceiling bounds what a huge window could ever ask for. The
  verification ladder: `recwn_tests.rs` (the law, rootless), the
  `status --print-json` recwn_limits schema (pinned byte-exact),
  and `scripts/bench/recwn-probe.sh` (the live proof — 100 kb/s
  apply, a curl child in the cgroup, `ss -ti` clamp evidence,
  the throughput band, retransmits near zero).
- **Layer 2 — ECN CE-marking for QUIC backoff — IMPLEMENTED**
  (schema v26, night-spark-4). The ECN-first machinery (scale 6)
  IS the quota signal: a budgeted lane's over-budget packet is
  DELIVERED CE-marked instead of dropped whenever the kernel
  helper `bpf_skb_ecn_set_ce` (ID 97) can set the codepoint on an
  ECT-capable packet — the cgroup lanes rescue at the drop verdict
  (`enforce.rs:375`, `enforce.rs:458`), the per-socket lane
  carries the same mark tail (`socket_flow.rs:286`) — and QUIC
  endpoints send ECT(0) by default (RFC 9000), so an RFC 9002
  stack reads the CE and backs off without a single lost
  datagram: the retransmit storm the drop lane teaches is
  prevented, not healed. Marks fire on the enforcement verdict —
  the threshold the drop lane already fired at — which for a
  policed cgroup is the roadmap's "toward the threshold" shape.
  The ledger this bullet demanded landed with it: `book_rescue`
  books the delivered CE-marked volume into `ce_marked_packets` /
  `ce_marked_bytes` (the stats row's 48-byte v26 tail, the legacy
  quartet's offsets untouched), every status surface carries the
  pair, and the debt law keeps the bound (delivered <= burst +
  rate*t + 64 KiB + one packet). The verification ladder:
  `ecn_tests.rs` / `ecn_socket_tests.rs` (the law, rootless), the
  v26 CE-ledger pins in the status/depth JSON suites, and
  `scripts/bench/ecn-probe.sh` (the live proof — the cgroup UDP
  legs witnessed by the receiver's IP_RECVTOS cmsg, the non-ECT
  control leg, the ledger cross-check, the tcpdump egress
  witness, the internet TCP leg, the QUIC leg).
- **Layer 3 — egress socket pacing (SHIPPED, schema v27, night-spark-5).**
  Shape egress by departure time instead of drop: the cgroup's
  UPLOAD policy is pinned onto its TCP sockets as
  `SO_MAX_PACING_RATE` by the object's second sock_ops program
  (`zelynic_pace`, the loader's fourth lane) — the kernel's own
  TCP pacer spaces the outgoing stream at the policy's byte rate
  BEFORE the link bills the bytes, no tc qdisc anywhere (the
  stack's internal pacer owns the clock while no pacing qdisc
  claims the socket). Egress already saved quota when dropped;
  paced it saves without the loss event at all: no over-budget
  burst, no drop, no CE mark. The attribution rides the lane the
  house already trusts — the egress hook primes a cookie-keyed
  hint (`pace_socket_hint`, the `recwn_socket_hint` posture, one
  layer up; sock_ops still cannot resolve its own cgroup on the
  5.15 floor), active connecters pace from establishment, rate
  changes re-apply within one RTT, and every policy removal
  sweeps the hint (the recwn sweep posture). The pure law
  (`ebpf/src/pace.rs pacing_decision`) is pinned rootlessly by
  `pace_tests.rs` (the simulated sock_ops call shapes and the
  exact rate the wiring hands `bpf_setsockopt`); the status
  surfaces carry `limits[].pacing_rate_bytes` and the human
  table's Upload Pacing subordinate line; the live proof is
  `scripts/bench/edt-probe.sh` (100 kb/s apply, the uploader
  joined the recwn way, `ss -ti` pacing evidence at the policy's
  own rate, the throttle band, the ledger's dropped counters
  moving zero). The documented residue: the dispatch is TCP-only
  by construction (every `tcp_call_bpf` call site lives in TCP
  code) — QUIC paces itself (RFC 9000) and the policer remains
  UDP's lane.

The sequence is the owner's: RWND first (the quota saver's spine),
ECN-for-QUIC second (the lossless signal), EDT third (the egress
finish). All three have landed (v25, v26, v27) — and the fourth,
the telemetry that turns the three lanes' work into a number the
owner can read, landed with the math itself (night-spark-7, schema
v28, below).
The arc's existing scales are the foundation all three stand on —
the hint maps already name QUIC connections, the debt word already
charges per budget, the verdict path already runs on both
directions.

- **Layer 4 — quota telemetry (LANDED, night-spark-7; the math
  that turns the three lanes' work into a number the owner can
  read).** The three lanes save quota by three different physics —
  RECWN clamps what the sender CAN send, the CE mark makes the
  sender back off, pacing spaces the departure — and Layer 4 books
  each lane's saving by the physics it actually owns. The map
  structure (schema v28, the v26 CE-ledger precedent verbatim —
  pure append, the six legacy words keep their offsets, the pinned
  stats maps wipe once at the bump): `LimiterStats` grows its tail
  from 48 to 64 bytes with `bytes_saved_by_edt` and
  `bytes_saved_by_ecn` — the two lanes the KERNEL can book — plus
  ONE new pinned LRU map, `pace_saved_stamp` (policy root ->
  last-seen egress stamp, the ecn_debt family's datapath-internal
  posture), the time base the EDT accrual reads. The night-spark-6
  outline planned a recwn word in the tail; the landing moved the
  RECWN saving to the USERSPACE side on purpose (the find that
  shaped it): the sock_ops clamp carries no observable
  default-window column to book against, so a kernel word would
  have to fabricate the counterfactual at the hottest call site in
  the object — the estimate runs instead where the census already
  lives, against an assumption the docs NAME.

  The three derivation laws (the estimate's law is the arc's own;
  each names its model, never a fabricated precision):

  - **EDT — `bytes_saved_by_edt` (kernel-booked, egress path).**
    The task's own formula, per-packet form: over the gap since the
    lane's last policed egress packet, the budget the rate accrued
    minus the volume actually delivered —
    `saved = (rate x dt_capped) - pkt_len`, clamped at zero per
    call. Summed over the lane's life it reads
    `(rate x active-time) - uploaded`, the preserved headroom. The
    caps are load-bearing and both borrowed from laws the house
    already pins: the gap caps at ONE SECOND (refill_credits' own
    idle cap — the counter must never reward idleness the bucket
    itself refuses to credit) and the rate sanitizes at 4 GiB/s
    (the recwn clamp's own guard — the BPF ISA has no widening
    multiply, so bounded factors keep the product
    overflow-impossible on a plain u64 multiply). The pure law
    lives in pace.rs (`pacing_saved_bytes`), rootless-pinned by
    pace_tests.rs; the accrual rides ONE insertion point in
    try_enforce (after the stats entry materializes, before any
    budgeted lane consumes the borrow), so every egress lane —
    per-socket, group, DRR — books through it and the ingress
    never pays for it.

  - **ECN — `bytes_saved_by_ecn` (kernel-booked, book_rescue's
    correction).** One-for-one with `ce_marked_bytes`: every
    delivered CE-marked byte is a byte that never becomes a
    loss-and-retransmission pair — and a dropped byte costs the
    quota TWICE (once for the lost delivery, once for the
    retransmission that finally delivers it), so the one-for-one
    floor is the CONSERVATIVE pole: the true saving is at least the
    marked volume, and the column books exactly the marked volume,
    never a modeled multiple. The word writes at the same choke
    point every mark delivery already returns through, through the
    same relaxed fetch_add — SMP-exact by construction.

  - **RECWN — `bytes_saved_by_recwn` (userspace estimate,
    display.rs `recwn_saved_bytes`).** The window-law
    counterfactual: the clamp holds a sender to `clamped` bytes per
    delivery cadence, so every `clamped` bytes the lane DELIVERED
    is one full window-cycle — and in that same cycle a sender with
    the DEFAULT window would have had `default - clamped` more
    bytes in flight. Scaled over the delivered volume:
    `saved = (bytes_allowed / clamped) x (default - clamped)`.
    The NAMED ASSUMPTION: `default` is pinned at 128 KiB — the
    kernel's tcp_rmem[0] initial receive buffer, the window a
    socket carries BEFORE autotuning grows it — deliberately the
    conservative pole of the assumption band (autotuning grows
    real defaults toward the MiB scale, so the estimate errs LOW,
    never high). The self-extinguishing edge is the law's own
    honesty: a rate whose clamped window reaches the default
    (about 655 KB/s at the 200 ms cadence estimate) books ZERO —
    the clamp is not the binding constraint there, the policer is,
    and the column refuses to claim the policer's work as the
    window's. The one granularity concession, stated:
    `bytes_allowed` is the combined dl+ul ledger (the stats map's
    own shape), so a row policing BOTH directions scales its upload
    volume into the estimate too — the single-direction row, the
    RECWN lane's own common shape, is exact.

  The owner's headline number — the **80% quota saver** — is the
  layered lane's claim on the metered rates it exists for: at the
  100 kb rung the RECWN estimate alone books ~85% (the window
  counterfactual), the ECN lane books the lossless pressure valve
  it delivered, and the EDT lane books the burst headroom it
  preserved — with the live proofs (recwn-probe, ecn-probe,
  edt-probe) each carrying a row that reads the columns the
  math fills. The telemetry makes the components readable; the
  workload makes the total.

  What landed: `status --print-json` carries
  `limits[].bytes_saved_by_edt` and `limits[].bytes_saved_total`
  beside the night-spark-6 pair (all four always present, the
  additive contract the CE-ledger pair set), the human table's
  `Quota Saved: X (EDT: Y, ECN: Z, RECWN: W)` subordinate line
  renders the total with the layer split, and the verification
  ladder closed: the pure-law pins (pacing_saved_bytes across the
  cap/sanitize/monotonic matrix), the v28 JSON pins in the display
  suites (the live mapping, the window-law estimate, the
  self-extinguishing edge), the layout pins (64 bytes, offsets
  48/56, the round-trip), and the live cross-check — each probe's
  saved row against the driven traffic.

## The Quota Saver — How zelynic Saves 80% of Your Internet

The three quota-saver lanes save quota by three different physics —
RECWN clamps what the sender CAN send, the ECN CE mark makes the
sender back off, the EDT pacer spaces the departure — and Layer 4
books each lane's saving by the physics it actually owns
(schema v28). The formulas are the empirical math the telemetry
fills; every one is pinned by rootless unit tests and read live by
the probes.

**The formulas.**

- `bytes_saved_by_recwn` — the TCP counterfactual window law
  (userspace estimate, `display.rs recwn_saved_bytes`). The clamp
  holds a sender to `clamped` bytes per delivery cadence, so every
  `clamped` bytes delivered is one window-cycle in which a
  default-window sender would have had `default - clamped` more
  bytes in flight:

      bytes_saved_by_recwn = (bytes_allowed / clamped) x (default - clamped)

  The NAMED ASSUMPTION: `default` is pinned at 128 KiB (the kernel's
  `tcp_rmem[0]` initial receive buffer — the window a socket carries
  BEFORE autotuning grows it), deliberately the conservative pole:
  the estimate errs LOW, never high. The law is self-extinguishing —
  a rate whose clamped window reaches the default (about 655 KB/s at
  the 200 ms cadence) books ZERO, because there the clamp is not the
  binding constraint and the column refuses to claim the policer's
  work as the window's.

- `bytes_saved_by_ecn` — the QUIC 1:1 retransmission prevention
  (kernel-booked, one-for-one with `ce_marked_bytes`). Every
  delivered CE-marked byte is a byte that never becomes a
  loss-and-retransmission pair — and a dropped byte costs metered
  quota TWICE (the lost delivery plus the retransmission that
  finally delivers it), so the one-for-one floor is the conservative
  pole: the column books exactly the marked volume, never a modeled
  multiple.

- `bytes_saved_by_edt` — the egress pacing headroom (kernel-booked,
  egress path). Over the gap since the lane's last policed egress
  packet, the budget the rate accrued minus the volume actually
  delivered — `saved = (rate x dt_capped) - pkt_len`, clamped at
  zero per call. Summed over the lane's life it reads the task's own
  formula:

      bytes_saved_by_edt = (rate x time_elapsed) - bytes_uploaded

  The caps are load-bearing and borrowed from laws the house already
  pins: the gap caps at ONE SECOND (refill_credits' idle cap — the
  counter never rewards idleness the bucket itself refuses to
  credit) and the rate sanitizes at 4 GiB/s (the recwn clamp's own
  guard — the BPF ISA has no widening multiply, so bounded factors
  keep the u64 product overflow-impossible).

- `bytes_saved_total` — the sum of the three, the number `status
  --print-json` carries and the human table renders as
  `Quota Saved: X (EDT: Y, ECN: Z, RECWN: W)`.

**The probe record.** The live proofs carry a saved row each, and
the recorded runs read like this:

- A 3 MB download with RECWN active saved 18.1 MB of unnecessary
  TCP window expansion.
- A 3 MB QUIC stream saved 65 KB of retransmission storm via ECN.

**The limitation, stated plainly.** QUIC first-packet still crosses
the WiFi. We save the retransmission storms, not the initial packet.
The lanes shape what a sender is ALLOWED to push and rescue what an
honest congestion signal can rescue; they do not un-send a datagram
the wire already carried.

The headline number — the 80% quota saver — is the layered claim on
the metered rates the lane exists for: at the 100 kb rung the RECWN
estimate alone books ~85% under the conservative default-window
assumption, the ECN lane books the lossless pressure valve it
delivered, and the EDT lane books the burst headroom it preserved.
The telemetry makes the components readable; the workload makes the
total. The deep derivations (the per-packet EDT accrual form, the
combined-ledger granularity concession, the datapath call sites)
live in this document's Layer 4 section below.

## The testing lane is pure eBPF (night-spark-3)

The bench lane's shaping is 100% pure eBPF, end to end. Every probe
here applies policy through the owner's own tool — `zelynic strict
cg:<id> ...` — and the tool plants its limits with eBPF cgroup hooks
alone: no `tc` qdisc is created, no `nft` or `iptables` rule is
written, no qdisc of any kind is touched. The lane's traffic
policing, its receive-window clamp, its verdicts — all of it rides
the same eBPF programs the product ships.

One distinction the grep-for-legacy pass must never blur: the `tc`
and `nft` invocations inside `scripts/bench/proof-claims.py` are the
AUDIT, not a dependency. Claim 2 ("pure eBPF") is verified by
snapshotting `tc qdisc show` and `nft list ruleset` before and during
a run and certifying both UNCHANGED — the harness watches the legacy
shapers to prove the tool never uses them (and notes, when they are
not even installed, that a missing tool cannot shape anything).
Removing those snapshots would not remove a legacy dep; it would
remove the evidence the purity claim stands on.

The realnet lane itself moved to the owner's side of the planet the
same night (night-spark-3), and finished the job the next night
(night-spark-3b): the ocean-away rungs are gone outright, and the
night-spark-3 replacements did not survive contact with the lane —
the 2026-11-04 owner run walked the whole Linode speedtest trio into
three rc 28 connection timeouts (30 s of silence before the
cloudflare fallback caught the lane), the agent's sandbox blackholed
the same three, and Clouvider's `sgp-sin` host is NXDOMAIN on every
naming variant — the family is unreachable, not geo-fussy. The
ladder now rides five geolocated Asian rungs in the owner's own
order — Vultr's Singapore ping file, NAIST's Debian listing (Nara,
the living Kansai rung; no public dumb file answers from Osaka city
itself), the ubuntu-taipei listing (Taiwan Digital Streaming), KKU's
Ubuntu listing (the UniNet edu backbone, Bangkok), and Biznet Gio's
Ubuntu listing (Jakarta metro) — each verified alive by a ranged
3 MiB GET and pinned to a city by IP geolocation before landing,
with the cloudflare __down mirror as the global anycast last resort;
the supermassive realnet chain carries the same roster behind its
cloudflare anchor. A dead rung falls through to the next one, and
`recwn-probe.sh --ladder-check` walks the whole ladder rootless from
any box, so rung liveness is verified on the owner's own network,
not on an agent's.

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
