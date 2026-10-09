<!-- SPDX-License-Identifier: GPL-3.0-only -->
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

- **AMMSP — Aware Multi Micro Sub-Process**: the subtree-aware
  enforcement mechanism — a policy written for cgroup A polices A
  and every descendant (A/**) through ONE shared budget, resolved
  by an ancestor walk inside the BPF program. The name is the
  owner's coinage and stays. (INNOVATIONS.md #1,
  `ebpf/src/ammsp.rs`)
- **The memo**: the LRU cache of leaf-to-root resolutions the AMMSP
  walk consults; every apply-family mutation bumps a generation
  stamp so a fresh policy never resolves through a stale memo.
- **DRR lane**: Deficit Round Robin — the shared budget is a POOL
  and each member (leaf) draws a bounded QUANTUM, unused quantum
  carrying forward; the aggregate stays exactly the policy.
  (`ebpf/src/drr.rs`)
- **Fair-Shared Bucket**: DRR inside AMMSP — several processes
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
- **The proto tags (`tcp` / `udp` / `raw`)**: a tree endpoint's
  protocol flag — every displayable endpoint names its protocol
  (night-improve-61: only UDP carried a tag once, and the owner
  read the untagged TCP rows as the unnamed default); `udp` is the
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
