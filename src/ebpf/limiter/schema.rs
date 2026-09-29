// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The limiter's BPF schema-version contract.
//!
//! Split from types.rs at the NIGHT-private-research-2 bump (the
//! version-history doc block grows one entry per schema bump — the
//! 500-LOC owner cap was already full at v9, and this constant's
//! history is the one piece of types.rs that grows by design).
//! Re-exported through types.rs so every existing
//! `use types::SCHEMA_VERSION_EXPECTED` import resolves unchanged —
//! the parse.rs precedent (NIGHT-private-research-3) applied to the
//! schema anchor.

/// BPF schema version. Must match `SCHEMA_VERSION` in
/// `ebpf/src/bin/limiter.rs`.
/// Increment both when BPF struct layouts or semantics change. Userspace checks
/// the pinned schema_version map on attach — if mismatch, cleans up + reloads.
/// v1: initial (no frac_rem in bucket, no schema_version map)
/// v2: added frac_rem to bucket for fractional token tracking
/// v3: rate_bps == 0 changed from "allow all" to "block all" (block-single)
/// v4: enforcement-boundary sanitization (NIGHT-improve-10 / security-3) —
///     burst and tokens clamped before any refill math; no layout change.
///     The bump forces pinned v3 programs to reload into the hardened
///     object (active limits are dropped once — re-apply after upgrade).
/// v5: the rate-0 block verdict books its drops into cgroup_limiter_stats
///     (NIGHT-improve-14) — verdict unchanged; pinned v4 programs otherwise
///     keep dropping blocked traffic with an empty, invisible drop counter.
///     Same one-time re-apply contract as the v3 -> v4 bump.
/// v6: frac_rem sanitized on read in the refill math (NIGHT-depthbore-1,
///     ebpf/src/math.rs) — the third persistent stored field, missed by the
///     v4 clamp family, is clamped to the healthy range (< 1s of rate
///     remainder) so a drifted or hostile value can never wrap the
///     fractional accumulation; no layout change, same one-time re-apply.
/// v7 (NIGHT-boost-38): SMP-safe enforcement — the token-bucket
///     read-modify-write in ebpf/src/math.rs moves to lock-free atomics
///     (window-ownership CAS + CAS consume + fetch_add stats). The v6
///     plain loads/stores lost updates whenever two CPUs enforced the
///     same cgroup concurrently, over-allowing 130-146% of budget under
///     2-6 flows (the E2E strict-multi and curl-burst reds, 2026-09-24).
///     No layout change — the pinned u64 fields are identical; the bump
///     forces pinned v6 programs to reload into the race-free object,
///     same one-time limit re-apply contract as v4/v5/v6.
/// v8 (NIGHT-lts-8): the extreme-burst consume retry — the CAS
///     consume in ebpf/src/math.rs re-observes and retries up to
///     four attempts, so a concurrent deduction between one packet's
///     read and its CAS no longer falsely drops an affordable packet
///     under many-CPU bursts on one bucket (measured on the
///     budget-covers probe: 1.35% of packets at one attempt, 28x
///     fewer at four). No layout change; the bump forces pinned v7
///     programs to reload into the retry object, same one-time
///     re-apply contract as v4..v7.
/// v9 (NIGHT-master-3): the rate-0 BLOCK verdict books its drops
///     through the same atomic fetch_add the enforce() path uses —
///     the v5 booking kept the plain `+=` the v7 SMP rewrite erased
///     everywhere else, so a blocked multi-CPU cgroup lost drop
///     increments like the pre-v7 ledger lost allowed bytes. Verdict
///     unchanged, no layout change; same one-time re-apply as v4..v8.
/// v10 (NIGHT-private-research-2, AMMSP): the leaf-anchored policy
///     lookup becomes subtree-aware — a policy written for cgroup A
///     now polices every socket born under A/** with ONE shared
///     budget, resolved per packet through the new pinned
///     ammsp_leaf_cache map (LRU, leaf cgroup id -> resolved policy
///     root, 0 = resolved unlimited) and enforced with bucket +
///     stats keyed at the ROOT, so the subtree shares the budget and
///     the ledger rolls up to the target. New map, new coverage,
///     existing struct layouts; every userspace policy mutation
///     flushes the cache. The bump forces pinned v9 programs to
///     reload into the subtree-aware object — active limits are
///     dropped once, re-apply after upgrade, the same contract as
///     v4..v9.
pub const SCHEMA_VERSION_EXPECTED: u32 = 10;
