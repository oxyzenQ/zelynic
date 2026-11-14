<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The zelynic Glossary

One line per coined term — the vocabulary the docs, the commit
history, and the source comments speak in. A term that is already a
whole document elsewhere gets its one-line decode here plus a
pointer; the canonical home stays the document. Entries are grouped
by where a new reader meets them: the engine first, then the
surfaces, then the state model, then the working vocabulary of the
build and audit estate. This file decodes terms; it does not
re-explain features ([INNOVATIONS.md](INNOVATIONS.md) owns the
feature stories) or commands ([USAGE.md](USAGE.md) owns the
grammar).

Why a glossary at all: the project names things deliberately and
keeps the names (internal consistency beats external grammar — a
name that is "wrong" but consistent is easier to remember and to
grep than a corrected one that breaks commit history, test pins,
and docs at once). The cost of that policy is cognitive for a
first-time reader, and this page pays it once, up front.

## The engine (the limiter's moving parts)

- **MMSPA — Multi-Micro Sub-Process Aware**: the subtree-aware
  enforcement mechanism — a policy written for cgroup A polices A
  and every descendant (A/**) through ONE shared budget, resolved
  by an ancestor walk inside the BPF program. The name is the
  owner's coinage and stays. (INNOVATIONS.md #1,
  `ebpf/src/mmspa.rs`)
- **The memo**: the LRU cache of leaf-to-root resolutions the MMSPA
  walk consults; every apply-family mutation bumps a generation
  stamp so a fresh policy never resolves through a stale memo.
- **DRR lane**: Deficit Round Robin — the shared budget is a POOL
  and each member (leaf) draws a bounded QUANTUM, unused quantum
  carrying forward; the aggregate stays exactly the policy.
  (`ebpf/src/drr.rs`)
- **Fair-Shared Bucket**: DRR inside MMSPA — several processes
  sharing one limited cgroup get bounded shares instead of an FCFS
  race. (INNOVATIONS.md #2)
- **Flow isolation (CAKE-style)**: the same fairness one level down
  — per-connection flow buckets inside a leaf, so a bulk download
  does not strangle an SSH session in the same cgroup. (schema v20)
- **Per-socket lane**: `--per-socket` — the budget keyed by socket
  cookie instead of cgroup, when the promise is per-CONNECTION.
  (schema v15)
- **QUIC-aware attribution**: the socket cookie refined by the QUIC
  connection id when the header carries one — the browser shape
  (N HTTP/3 connections on one UDP socket) gets per-connection
  budgets back. (schema v22)
- **ECN-first policing**: an over-budget ECT-capable packet is
  delivered CE-marked instead of dropped, its bytes charging a debt
  the budget's own refills pay back. (schema v19)
- **The debt word**: the per-budget outstanding ECN debt, keyed by
  generation-prefixed budget so a fresh budget never inherits its
  predecessor's debt.
- **The guarantee bracket**: `--floor` / `--ceil` — a minimum the
  DRR draw honors before any contention, validated against the
  resolved rates before the root ask. (schema v24)
- **RECWN — Receive Window Control**: the owner's coined name for
  the receive-window lane (deliberately NOT "RWND" — brand identity
  over the standard acronym): a policed cgroup's own sockets
  advertise a rate-shaped window (rate x max(measured srtt,
  200 ms) — the 200 ms delivery-cadence floor the live E2E
  evidence set, extended by the socket's own measured RTT since
  v31 — clamped to [2 x MSS, 1 MiB]) via the sock_ops program
  clamping SO_RCVBUF, so remote TCP senders hold their in-flight
  bytes down before the ingress link bills them — the quota
  saver's Layer 1. The socket-local sk_storage hint the ingress
  hook primes carries the attribution the sock_ops floor cannot
  resolve on its own. (schema v25; the measured-RTT retune v31
  and the sk-storage migration v32 — INNOVATIONS.md #14)
- **The quota saver**: the umbrella name for the landed layer stack
  that turns policing into savings — RECWN, ECN-CE, EDT, and the
  Layer 4 books, one budget story per lane (INNOVATIONS.md, the
  "The Quota Saver — the Workload-Conditional Claim" section).
- **The quota saver's layers**: the four landed layers plus the one
  unbuilt slot — Layer 0 reserved (DSCP/XDP ideas, unscheduled),
  Layer 1 RECWN (the ingress receive window), Layer 2 ECN-CE (mark
  instead of drop), Layer 3 EDT (the egress socket pacing), Layer 4
  the quota telemetry books (schema v28). (INNOVATIONS.md,
  COSMIC_DRAGON_ARC.md)
- **ECN-CE**: ECN with the Congestion Experienced mark (RFC 3168) —
  an ECT-capable packet delivered with CE set instead of dropped,
  the wire shape the ECN-first policing lane books one-for-one into
  the saved byte. (schema v19, the ECN-first entry above)
- **CE marked**: the ECN-first lane's delivered CE-marked volume —
  a drop prevented, the packet delivered with the CE codepoint
  instead. Booked in `ce_marked_packets` / `ce_marked_bytes`; the
  status row renders it as the grey "CE Marked" sub-line. (schema
  v26, `ebpf/src/ecn.rs`, USAGE.md §reading)
- **EDT — Earliest Departure Time**: the quota saver's Layer 3 —
  the EGRESS lane: the upload policy pinned onto the cgroup's TCP
  sockets as SO_MAX_PACING_RATE at connection setup, the kernel's
  own TCP pacer spacing the stream BEFORE the link bills the bytes
  — no tc, no qdisc. (`ebpf/src/pace.rs`,
  scripts/bench/edt-probe.py)
- **SO_MAX_PACING_RATE**: the socket option the EDT lane pins — the
  kernel-native pacing knob behind the lane (the internal pacer on
  the 5.15 floor), no qdisc and no userspace clock involved.
- **The steal-tick budget**: the EDT probe's drop-row tolerance — a
  steal-tick tail priced as a share of the leg's policed volume,
  1.0% (the RECWN retrans bound's convention; 0.5% was the clean-VM
  calibration, recalibrated night-netrunner-7).
  (scripts/bench/edt-probe.py, DROP_BUDGET_FRAC)
- **drop_verdict**: the EDT probe's drop-row helper — the actual
  share always prints; PASS inside the steal-tick budget, X past it.
- **pacing_rate_bytes**: the `--print-json` `limits[]` field
  carrying the upload lane's commanded rate (absent on upload-less
  and blocked rows). (schema v27)
- **allowed**: the cumulative bytes the token bucket ADMITTED since
  the policy applied, per cgroup, both directions aggregated — the
  wire bytes the app received. The column header is the contract;
  the name stays. (src/ebpf/limiter/stats.rs, USAGE.md §reading)
- **dropped**: the cumulative bytes the token bucket's drop verdict
  DISCARDED since the policy applied. Under the saver lanes, most
  would-be drops are prevented (RECWN), marked (ECN), or paced
  (EDT) before reaching this verdict; a small value under a policed
  cgroup is the lanes working, a large one means the lane is not
  binding at this rate. Ingress drops burn quota, egress drops save
  it. (src/ebpf/limiter/stats.rs, USAGE.md §reading)
- **The saved-quota books**: `bytes_saved_by_recwn` /
  `bytes_saved_by_ecn` / `bytes_saved_by_edt` / `bytes_saved_total`
  — the schema v28 ledger tail: the layers' saved-byte words plus
  the sum, the human table's Quota Saved line (the ECN word is the
  sole live booking, one-for-one with the delivered marks; the EDT
  word is RETIRED — schema v29, night-quota-audit — and the RECWN
  estimate is RETIRED — schema v30, night-recvn-audit: the
  window-law counterfactual over-claimed 10-30x on the owner's
  live reading — both read zero).
- **bytes_saved_total**: the sum of the lanes' counterfactual
  savings bookings (the ECN one-for-one alone, plus the retired
  EDT and RECWN words reading zero since schema v29/v30). NOT a
  wire
  measurement — the
  wire-measured savings is the A/B harness's output — and NOT the
  same number as `dropped`; the status surface labels it
  "(est., counterfactual)". (schema v30, src/ebpf/display.rs,
  USAGE.md §reading)
- **Quota Saved (status line)**: the saved-lane telemetry's sum
  (since schema v30: the ECN one-for-one alone, the EDT and RECWN
  words retired and reading zero),
  rendered with the honest "(est., counterfactual)" label. NOT the
  same number as `dropped`; for the distinction, see USAGE.md
  §reading. (src/ebpf/display_lines.rs, USAGE.md §reading)
- **HostCaps**: the one-probe capability snapshot taken once per
  attach entry (`src/ebpf/host_caps.rs`) — the Adaptive Orchestra
  reads it for every attach decision, so no lane re-probes the host.
- **The ledger**: `cgroup_limiter_stats` — the exact cumulative
  byte/packet counters every verdict books through. "The ring is a
  monitor, the ledger is the truth."
- **The ring**: the in-kernel time-series — the last eight
  one-second delivered-byte windows per policy root per direction;
  it never invents bytes and never gates a verdict. (schema v14,
  INNOVATIONS.md #8)
- **Census-bounded**: a map whose occupancy is claimed to be
  bounded by the live-policy census (at most one entry per policy
  row) — the reclaim family exists to keep that claim true.
- **The policy family**: the two policy maps and their per-root
  state maps (buckets, stats, window, rings) — 1024 slots each, the
  capacity class every sweep respects.
- **Group lane**: `--group` — members share one bucket keyed by a
  fresh quasi-random group id; the LAST reference out reclaims it.
- **Fail-open**: a bookkeeping failure (full map, torn pin) never
  bricks the network — the packet is allowed, never dropped on
  lost state. Enforcement truths propagate errors; monitors do
  not.
- **Wrap-coherent delta**: a backwards counter step reads as a
  kernel-counter wrap (the half-space discriminator), never as a
  negative delta — LRU eviction restarts cannot phantom 18 EB.
- **Generation stamp**: the version prefix that makes fresh state
  uninheritable — memos, ECN debt, and bucket births all reset
  with the epoch that created them.

## The surfaces (what the operator sees)

- **Eagle eyes**: the fullscreen live monitor (`zelynic ee`) —
  session leaderboard, baseline panel, and grip footer in one
  bordered frame.
- **The session leaderboard**: the ranked table of per-cgroup bytes
  accumulated SINCE THE MONITOR STARTED — rank by session total,
  not last-second twitch; quiet apps keep their rows with em-dash
  rates.
- **The baseline lane / panel**: EAGLE EYES V2 — the ring lens read
  every frame, folded into per-policy-root integer EMAs, rendered
  as `learning n/8`, `steady`, `above +N%`, `below -N%` under the
  table's policy-aggregate header.
- **The focus view**: one target resolving to one cgroup switches
  to the deep single-cgroup view (the old `observe --cgroup`
  depth, autodetected).
- **The grip footer**: the bottom-pinned footer block (census,
  uptime, speed pair, tiers) — built BEFORE the table renders, so
  its measured length pins it to the bottom.
- **The observer**: the passive monitor half — counters, identity,
  and connections read without a limiter instance.
- **The probe / self-proving enforcement**: after an apply, the
  tool runs its own traffic through the live policy and reads the
  verdict from the ledger — "VERIFIED" is a measurement, not a
  claim. (INNOVATIONS.md #9)
- **Bypass detection (shadow mode)**: interface-level deltas
  compared against what the hooks booked — traffic that exits
  where the hooks cannot see is flagged; detection only, named
  honestly. (INNOVATIONS.md #10)
- **The depth report**: `--depth` — the per-target deep report
  (endpoints, sockets, enforcement state).
- **The clamp bracket**: the depth report's tail-aware clamp row
  (night-frontier-Z2, INNOVATIONS.md #19) — whether ONE
  receive-window clamp can honestly serve the fleet the histogram's
  srtt half sampled. Renders the two ends through the RECWN window
  law (`floor` from the bucket-bounded p99, `ceiling` from the
  exact min RTT) and the verdict; download lane only, absent on the
  honest absences.
- **Honesty Ratio**: `p99/min RTT` — the clamp bracket's grading
  metric. Near 1x the paths agree (one clamp serves); past one
  log2 octave with the bracket's ends diverged the report refuses
  the single clamp — a cgroup mixing local and remote paths has no
  honest one-number window, and the per-socket rtt pairs are the
  answer. The p99 read is a bucket lower bound, so the ratio is
  one too — the `>=` prefix admits it everywhere it prints.
- **Identity drift alarm**: the container URI lanes' pinned
  identity (the netns handle's nsfs inode, the VRF device's
  ifindex — night-frontier-Z3, INNOVATIONS.md #20), re-verified
  with one stat() on every `status` read. A recreated namespace or
  VRF reads STALE ("the watch points at a corpse") instead of
  silently enforcing against the old cgroup; the pin lives under
  `/run/zelynic/identity/` and dies with the policy it describes.
- **Doctor**: `zelynic doctor` — the kernel/dist capability check;
  reports the build flavor (full-life / half-life, see
  [FAQ.md](FAQ.md)).
- **The scroll note**: `(-N above · )+M more — ↑↓ scroll` — the
  truncation honesty line when a section outlives the terminal
  (night-improve-58: the arrows walk the rows the frame cut; the
  window is the budget, the scroll is the window's walk).
- **Em-dash rate**: the rate cell of a quiet app — on the board
  with its totals, rates absent rather than zero-as-fact.
- **`dl` / `ul`**: the monitor's two-letter direction tags —
  **d**own**l**oad / **up**l**oad**, lowercase, the same vocabulary
  the leaderboard's rate columns, the footer's speed pair, and the
  endpoint suffix all speak (a lowercase L, never the digit one —
  the font-confusable pair the owner's transcript caught; this line
  is the decode). Since night-private-research-7 every dl/ul figure
  is a per-second ARRIVAL rate — comparable against the policy on
  sight, no mental math. (USAGE.md, the eagle-eyes tables)
- **Arrival**: what REACHED the interface, pre-verdict — the
  observer's own count, including the bytes a limit then dropped
  and TCP retransmits (night-private-research-7's honesty label:
  `status`'s allowed/dropped ledger is the twin that splits arrival
  into its verdicts). A `peak arrival` above the policy is the
  demand the limit absorbed, not a bypass.
- **The endpoint suffix**: `[dl X | ul Y]` on a tree line — that
  endpoint's per-second ARRIVAL rate over the measured window (the
  live view differences the per-socket cookie counters frame over
  frame and divides by the same span the rate columns use; the
  `--depth` report divides the window's bytes by the window's own
  seconds — one vocabulary, both horizons; NIGHT-boost-26's join
  carried to its rate form by night-private-research-7). A
  connected-but-quiet socket keeps its lean row: absence is the
  "quiet now" signal.
- **The `+N` label suffix**: `cg:7001 (brave +22)` — 23 processes
  hold sockets inside the cgroup: the named one plus 22 more, the
  label's honest scale.
- **`[busy]`**: a tree endpoint's saturated-socket flag — the
  socket's send queue is full (it is being policed hard, or its
  peer is slow); a display fact, not a verdict.
- **The proto tags (`tcp` / `tcp6` / `udp` / `udp6` / `raw` / `raw6`)**: a tree endpoint's
  protocol and family flag — every displayable endpoint names its
  protocol (night-improve-61: only UDP carried a tag once, and the
  owner read the untagged TCP rows as the unnamed default);
  night-improve-62 split the family out of the walk, so the v6
  tables stop collapsing into the v4 spellings — the suffix is the
  one ss and netstat already speak. `udp` is the
  CONNECTED-UDP shape (QUIC-era traffic lives there), `raw` the
  rare IP-level socket.

## The state model (how the no-daemon design holds state)

- **The pin dir**: `/sys/fs/bpf/zelynic` — the pinned eBPF maps
  that outlive each CLI invocation. bpffs dies at reboot, so
  pinned state is per-boot by construction.
- **Pin epoch**: one lifetime of the pin dir — a fresh load unpins
  everything first, so no state crosses a reload.
- **Schema version guard**: the one-entry pinned Array every reader
  checks before touching a pinned object; a version mismatch reads
  as absent for BOTH directions, never as a silent stale layout.
- **The operation lock**: the flock serializing every policy
  mutation and pin teardown; report surfaces take it try-lock,
  never block.
- **The watchdog**: the pinned auto-expiry deadline — enforcement
  armed without a follow-up visit expires on its own rather than
  lingering forever (the safety inverse of a lost unstrict).
- **The wall-clock bridge**: `wall_clock_offset` — wall-minus-mono
  stamped at every attach and apply, so a `--during` window can
  compare wall time inside the BPF program with no daemon.
- **"The CLI is the daemon"**: the design law that every CLI visit
  is the refresh channel — sweeps and stamps ride applies, status,
  and recover; nothing runs between visits.
- **The lazy sweep**: the ended-`--during`-span collector — every
  apply-family mutation and status visit drives expired window
  rows through the unstrict machinery.
- **retire_dead**: the leaderboard's dead-row retirement — a row
  with no identity entry and no window traffic retires after a
  3-frame grace, only when the board is at its cap, behind an
  identity signal guard (NIGHT-mitigate-1). Since NIGHT-hunt-34
  the same law rides the baseline panel (display-only — a verdict
  row hides, the learned EMA stays).
- **Orphan**: a policy row whose cgroup no longer exists — since
  night-hunt-43 the zombie sweep collects them automatically at
  the next mutation-capable visit (the two-signal walk: no
  identity entry, no ring traffic for the 8s horizon);
  `zelynic recover` remains the manual, reported override.
- **Reclaim**: the family that returns dead per-root state
  (buckets, rings, stats, windows) to the maps on removal — and,
  since NIGHT-hunt-34, the orphan-census sweep that collects the
  residue a failed or interrupted reclaim leaves behind, riding
  the next mutation-capable CLI visit. Since night-hunt-43 the
  family also owns the zombie-policy sweep (limiter/zombie.rs),
  the collector one gate up: whole roots (policies AND state)
  whose cgroup died, retired by the same two-signal law the
  session board's retire_dead rides.
- **The absent-lens contract**: a failed read of a MONITOR map (the
  rings) renders the field honestly absent — never a fabricated
  empty series, and never a failed enforcement report.
- **Unstrict / recover / u --all**: the removal family — per-target
  removal, the orphan hygiene command, and the full teardown
  (verified unpins, no residue).

## The estate's working vocabulary (build, test, audit)

- **The gatekeeper battery**: `./scripts/build.sh check-all -q` +
  `./scripts/gate-keepers.sh` — the pre-commit verification pair.
- **Pattern C**: the single `test/` tree with `#[path]`-wired
  module includes — one pin file per contract, no parallel test
  tree (the cosmostrix lineage).
- **The 500-LOC cap**: the owner's module-size discipline — a file
  past the cap splits by contract, never by convenience.
- **The frame bench**: `scripts/bench/frame-bench.py` — the
  render-path A/B instrument (density_gini, frame_entropy, fps,
  dirty_cells).
- **A/B**: the before/after frame-bench comparison at a commit
  pair — the render lane's regression gate for every
  render-touching change.
- **Supermassive**: the VM scale-test fleet (`scripts/supermassive`)
  — live cgroup counts past the product's own caps.
- **The sandbox**: the local KVM micro-VM for root testing without
  touching the host ([SANDBOX.md](SANDBOX.md)).
- **The cosmic dragon**: the pure-eBPF architecture's name — one
  hooking layer, cgroup v2, Linux-only
  ([COSMIC_DRAGON_ARCHITECTURE.md](COSMIC_DRAGON_ARCHITECTURE.md)).
- **the cosmic dragon engine**: the enforcement core's name
  (NIGHT-improve-68) — the six-layer verdict path that polices
  smooth, the architecture's heart
  ([INNOVATIONS.md](INNOVATIONS.md)).
- **The cosmic dragon arc**: the canonical index document of the
  enforcement core — the fourteen scales, the estate map, the quota-saver
  roadmap ([COSMIC_DRAGON_ARC.md](COSMIC_DRAGON_ARC.md)); the named
  whole animal — the architecture, the engine, and the render
  lineage each keep their own entry on this page.
- **the cosmic dragon render engine**: cosmostrix's diff-based
  renderer whose discipline `src/terminal/diff.rs` ports (QA.md Q8)
  — the render lineage, distinct from the enforcement engine.
- **The purple**: the brand color and the dragon's tone
  ([BRANDING.md](BRANDING.md)); regular purple is the brand layer,
  warn yellow the finding layer, suggestion white the recovery
  layer.
- **Verdict bands**: the baseline lane's departure rule — ±50% AND
  a 4 KiB floor per window, two consecutive windows before a flag
  renders; every figure pinned.

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
