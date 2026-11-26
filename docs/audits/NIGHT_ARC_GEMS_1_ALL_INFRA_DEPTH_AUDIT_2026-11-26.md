<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# NIGHT-arc-gems-1 — the all-infra depth audit (kernel datapath + userspace hot paths)

> Audit date: 2026-11-26. Status: complete — one real fix landed (the
> DRR share-epoch width mismatch), two doc-claim corrections landed in
> the same pass (the render-loop I/O claim, the zero-alloc claim
> scope), and every other finding is either CLEAN with the invariant
> that proves it or MINOR with the cost spelled out. The audit ran the
> kernel datapath (ebpf/src, 30 files) and the userspace hot paths
> (render loop, /proc walks, monitor closure) end to end, with the
> load-bearing arithmetic re-derived at the cited lines.

## 1. The one real bug: the DRR share-epoch width mismatch (FIXED)

`ebpf/src/drr.rs`, `pool_share_note` compared the share word's stored
epoch against the raw epoch counter. The stored field is the counter
masked to 28 bits (`pool_share_pack`), the counter is a full u32 — so
once boot-relative ktime passed 2^28 epochs of 100 ms (2^28 x 10^8 ns
= ~310.7 days of uptime), the comparison went forever-false: every
packet read as a rollover, `running`/`last`/`peak` collapsed to <= 1,
and the DRR fairness ledger silently turned itself off
(`epoch_allowance(drawees < 2)` returns `u64::MAX`). The
K > 2 geometric-decay unfairness the dinner-28/repair-3/repair-4
machinery exists to close would silently return on every long-uptime
host. No over-allow (the pool CAS still conserves), no crash — a
silent fairness regression only.

The field comment's own horizon was wrong with it: "an 8.5 year
horizon" is 2^28 x 1 s epochs; the code runs 100 ms epochs, so the
true horizon is 0.85 years. Fixed: the comparison masks the counter
to the field's width (`now_epoch & 0x0FFF_FFFF`), the rollover writes
the masked value, and the comment states the true horizon and the
mask law. The decay cadence intentionally keeps the raw counter —
2^28 is a multiple of `PEAK_DECAY_EPOCHS` (8), so `is_multiple_of` is
invariant under the mask. The ledger word is NOT affected: it stores
the full u32 and uses `wrapping_sub` with `ELAPSED_CEILING`, the
documented 13.7-year design that already handles its own wrap. The
fix is one expression plus the honest comments; the prebuilt lane was
regenerated through the one writer and passed the parity gate
(structural ELF checks, no undefined GLOBAL symbols, manifest blake3
rows, the ebpf/ tree pin).

## 2. The kernel datapath verdict (ebpf/src)

- **Per-packet cost — CLEAN where it claims, characterized where it
  does not.** The unlimited majority rides one helper call, one
  per-CPU tick, one policy lookup, one generation read + one memo LRU
  lookup — genuinely lean, and the NIGHT-lts-2 ordering (timestamp and
  watchdog only after a policy hit) is real. A policed packet on the
  DRR lane with QUIC attribution pays ~15-25 hash-map operations worst
  case (policy, window gate, watchdog, stats, sk_storage, generation,
  QUIC key reads, pool/leaf/flow buckets, share notes, ledger room and
  spend, ECN debt, ring) with bounded CAS retries — straight-line,
  loop-free except the bounded MMSPA walk (<= 32, early break) and the
  sampled hist tail (8 slots, 1/1024 packets), zero spinlocks, the
  verifier budget (~141k insns) accounted honestly. Lean is true of
  the unlimited path; the policed path is a designed, bounded cost.
- **Math — CLEAN at the load-bearing sites.** The token-bucket refill
  split-multiply is bit-exact and overflow-impossible by the Z12 bound
  argument; the burst clamp (`pol_sane`) is applied before every
  consumer; every division is const or count-guarded (drawee guards,
  `learned + 2 >= 2`, const divisors); the RECWN bandwidth-delay
  product fits u64 by the sanitize cap (rate <= 2^32, rtt_us <= 2^32-1)
  with the clamp band applied after; the ECN debt charge/pay ordering
  is over-pay-safe and generation-prefixed. Two hostile-rate wrap
  paths in the DRR ledger (`allowance * elapsed_epochs`, the u32 carry
  truncation) only ever under-count credit — fewer draws, more drops,
  never an over-allow — and are contained by `min(earned, cap)`.
- **Determinism — CLEAN.** Fixed-constant splitmix64 key mixing (no
  seeds, no RNG), the MMSPA walk in fixed ascending-level order,
  monotonic ktime only, and every documented race window lands in the
  monitor-only or drop-direction class. No verdict-affecting
  nondeterminism found.
- **Memory and lifecycle — CLEAN.** Every unbounded-key map is
  LRU-capped (2x4096 through 6x4096 per family, hist 6.6 MB pinned
  budget), census-bounded maps key only on resolved policy roots,
  sk_storage rows die with the socket, and the schema-reload +
  per-field clamp family defends pinned state against pre-upgrade
  layouts.
- **MINOR, left alone on purpose.** (a) Every policed TCP packet pays
  the QUIC attribution header read before the UDP check rejects it —
  one 40-byte stack copy per policed packet, bounded, panic-free by
  construction; an early protocol check is the obvious optimization
  and is a behavior-adjacent datapath change that earns its own
  measured pass, not a rider on this audit. (b) The fail-open
  postures on a full-flow-LRU miss are documented (the cake_flow
  wording was the one dishonest phrasing — "never a silent unlimited
  pass" described a packet that does ride through unpoliced; reworded
  to say exactly that this one packet rides through while the leaf's
  bucket keeps enforcing).

## 3. The userspace hot-path verdict (render loop, walks)

- **The diff engine — TRUE as stated.** Shadow swap with zero
  cloning, linear byte-compares, maximal dirty-run batching, a
  byte-exact sparse-vs-sequential cost model, one reused `Vec<u8>`,
  one buffered `write_all` through raw `write(2)`; the idle fast path
  emits zero bytes. Resize (full reset on width, painted clamp on
  height shrink), sticky geometry on probe failure, hard-capped pools,
  and a 20k-frame resize soak test — no leak path found.
- **Claim corrections landed in the docs (README, QA): the two
  headline sentences outran their measured scope.** "Idle frames cost
  zero I/O" describes the emission path, not the session: the
  deliberate selection-guard beat (~100 ms, anti-selection physics)
  re-emits the full frame between refresh ticks, and each wake pays a
  winsize probe plus a periodic OSC 11 query — a live idle session is
  never at zero I/O, by design and documented, but not by the old
  sentence. "Zero-alloc render loop" is proven (by the counting
  allocator pin) for the composition half and the diff engine with an
  EMPTY baseline lane; a policy-pinned frame allocates (panel rows,
  label strings, lane-refresh collections) and a name-targeted frame
  allocates a lowercase copy per identity entry per token — small,
  churn-not-leak, but outside the pin's fixture. The docs now say
  what is proven and where the measured scope ends. The allocation
  sites themselves are candidates for a future pooling pass; none is
  a leak, a quadratic, or a per-line syscall regression, so none was
  churned in this audit.
- **The /proc walks — CLEAN.** O(processes + fds), TTL-bounded (10 s
  identity, 3 s connections), the one historical O(n^2)
  (`socket_cookies` `Vec::contains`) already fixed to HashSet, sorts
  n log n with tie-breakers, the launch gate a pure map scan. The
  honest cost note: on a very dense host the 3 s connection walk
  stalls input handling for its duration — inherent to /proc polling,
  the same class htop pays, bounded by the TTLs.

## 4. The LTS verdict

The estate holds: pins on latest release commits (the actions-pin
seat verified the same day), the schema-reload + clamp contracts
defending pinned kernel state, LRU caps everywhere, the wrap-safety
direction proved for every arithmetic site, one latent 310-day bug
now fixed with its lane rebuilt, and the datapath deterministic
modulo documented monitor-class races. The honest residuals are the
ones the audit names: the QUIC pre-parse on the policed path, the
fail-open bookkeeping misses, the pinned-frame allocation churn, and
the guard-beat I/O floor — each with its cost spelled out, none
hidden behind a wrong sentence anymore.

<!--
  ZELYNIC-DISCLAIMER
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
