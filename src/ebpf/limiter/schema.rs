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
/// v11 (NIGHT-think-like-light-years-3): the init-path inserts
///     (get_stats_ptr, get_bucket_ptr in ebpf/src/bin/limiter.rs)
///     switch from BPF_ANY to BPF_NOEXIST — under a many-CPU
///     first-packet burst on a fresh bucket, the ANY flag let a
///     racing initializer wholesale-reset an entry another CPU was
///     already enforcing through: consumed tokens resurrected to
///     full burst, the window-ownership stamp rolled back to
///     re-credit an already-paid window (bounded by the 1s elapsed
///     cap), and booked stats increments vanished. The loser of the
///     init race now re-looks up and rides the winner's entry — the
///     NIGHT-improve-29 observer pattern, applied to the limiter
///     twin. No layout change, verdict math untouched; the bump
///     forces pinned v10 programs to reload into the init-race-free
///     object — the same one-time re-apply contract as v4..v10.
/// v12 (NIGHT-perf-0): AMMSP memos become generation-stamped —
///     the ammsp_leaf_cache value widens u32 -> u64, packing
///     `(generation << 32) | root`, and a new one-entry pinned
///     ammsp_generation counter array is read by the datapath
///     before every resolution and bumped by userspace after every
///     policy mutation's writes land. The stamp closes the insert
///     race the whole-map delete flush could not (a walk whose
///     tail an NMI/IRQ storm stretched past the sweep inserted
///     pre-mutation state after the flush finished — a stale
///     verdict that lived until the next mutation), and the bump
///     replaces the O(memo-cap) syscall sweep with one O(1) array
///     store (the sweep stays only as the bump's failure
///     fallback). Map set + value layout change; the bump forces
///     pinned v11 programs to reload into the generation-stamped
///     object — active limits are dropped once, re-apply after
///     upgrade, the same one-time contract as v4..v11.
/// v13 (NIGHT-upgrade-charger-core-1c, the fair-shared bucket): the
///     individual-bucket lane becomes DRR-shaped — the shared bucket is
///     now a POOL (refilled by the same refill_window, drained only by
///     per-LEAF quantum draws), and every packet spends from a per-leaf
///     bucket keyed by the socket's own cgroup id in the two new pinned
///     LRU maps leaf_bucket_dl/ul (4096 entries, the memo map's
///     posture). A greedy leaf can no longer consume every token the
///     instant it refills: it holds at most one quantum
///     (max(rate x 100ms, the 64 KiB GSO admit floor)) at a time, and
///     the pool's next refills flow to whichever leaf is empty and
///     asking — the AMMSP starvation shape becomes bounded shares
///     while the aggregate stays exactly the policy. The
///     stale-quantum belt stamps leaf quanta with the AMMSP
///     generation at their draw and zeroes mismatching stamps before
///     the packet proceeds, so a policy mutation can never leave a
///     leaf spending a dead budget's quantum. New maps, new
///     enforcement semantics on the individual lane; the bump forces
///     pinned v12 programs to reload into the fair-sharing object —
///     active limits are dropped once, re-apply after upgrade, the
///     same one-time contract as v4..v12.
/// v14 (NIGHT-upgrade-charger-core-3a, the in-kernel time-series
///     ring — Tier B #8, EAGLE EYES V1): two new pinned maps
///     rate_ring_dl/ul (u32 policy-root cgroup id -> 128-byte
///     eight-slot ring, one-second windows) book every ALLOWED
///     packet's bytes into the current window — the rolling rate
///     horizon `status --print-json` surfaces per limit (the
///     `rate_ring` field: eight one-second byte totals, oldest
///     first, plus how many windows are live). Monitor-only: no
///     verdict change, no layout change on any existing struct —
///     the exact ledger stays cgroup_limiter_stats. The bump is
///     load-bearing because the status reader opens the new pins: a
///     stale pinned object must reload instead of silently serving
///     no-ring state. This bump also restores the BPF-side anchor's
///     parity: the v13 bump raised this constant but missed
///     `SCHEMA_VERSION` in ebpf/src/bin/limiter.rs (it stayed 12 —
///     dead code there, so nothing broke at runtime, but the anchor
///     lied about which semantics the source carried). The sync pin
///     below (the include_str! equality test) makes that drift
///     class impossible to repeat.
/// v15 (NIGHT-upgrade-charger-core-3b, per-socket limiting —
///     Tier B #7): Policy.flags — the four padding bytes at offset
///     20 become contract (bit 0 = POLICY_FLAG_PER_SOCKET: enforce
///     per SOCKET, every connection its own bucket at the policy
///     rate, beyond the cgroup; the struct stays 24 bytes) — plus
///     two new pinned LRU maps socket_bucket_dl/ul (socket cookie
///     u64 -> 32-byte SocketBucket: the standard bucket + the
///     AMM-generation stamp of the stale-token belt). Attribution
///     rides bpf_get_socket_cookie, the observer's proven helper
///     (NIGHT-boost-26) — no tracepoint needed; a zero cookie
///     degrades to the DRR cgroup lane, still policed. The CLI
///     surface is strict-single's --per-socket flag (the lane is
///     deliberately individual: a group policy IS the shared-budget
///     answer). One-time re-apply as ever.
/// v16 (NIGHT-dinner-28, the learned-share draw): the DRR draw's
///     take is the residue law's bound FURTHER capped by the
///     quantum's fair split across a LEARNED drawee count — the
///     number of distinct leaves that drew in the last completed
///     100ms epoch, kept per (pool, direction) in the two new pinned
///     LRU maps drr_pool_state_dl/ul (ROOT cgroup id -> the packed
///     word `last:u16 | running:u16 | epoch:u32`, drr.rs's packing).
///     The find this closes is live, from the fair-share battery on
///     every CI leg: the residue law splits a TWO-asker pool evenly
///     but at K > 2 drawers the takes decay geometrically (50% /
///     25% / 12.5% ... of the pool per epoch) — the worst leaf read
///     3.35x its fair share while the quietest starved below one
///     admit (78 B over the whole window), the aggregate staying
///     exactly the policy the whole time. With the learned cap the
///     first-asker position itself stops paying: every drawer's take
///     is bounded by quantum/(K+1), a cold pool (learned 0) keeps
///     the exact v13 shape, and a state-map miss fails OPEN onto
///     the v13 law. The note rides the draw's success path; the
///     state is an estimate (concurrent notes may lose one
///     increment) whose slack the bounds absorb — pinned rootlessly
///     by the simulation battery in drr_share_tests.rs, which
///     reproduces the CI decay against the v13 law first. New maps,
///     verdict math unchanged on every other lane; one-time re-apply
///     as ever.
/// v17 (NIGHT-repair-3, the epoch ledger): the DRR draw's take is
///     further capped by the leaf's remaining per-EPOCH allowance —
///     the pool's 100ms refill split across the learned drawee
///     count, kept per LEAF in the two new pinned LRU maps
///     drr_leaf_state_dl/ul (leaf cgroup id -> the packed
///     `drawn:u32 | epoch:u32` word, drr.rs's packing) — and the
///     pool-share note moves from a plain read + BPF_ANY insert to
///     a two-attempt CAS (the v16 form lost increments to racing
///     writers on the ONE word every note touches, converging the
///     learned count to 1-3 under the multi-CPU draw storm — the
///     cap silently weakened back to the v13 residue shape). The
///     find the ledger closes is the improve-1b battery's own: a
///     per-take cap cannot bound a per-epoch share, because draw
///     frequency is TCP feedback — the flow that admits grows its
///     window and draws on every packet, the starved flows back
///     off to retransmit timers, and the measured shape read worst
///     4.7x fair with the quietest at ONE admit (65536 + 78 B over
///     4s). With the ledger the fast drawer blocks at its fair
///     share, the refills accumulate behind the block, and the
///     starved leaf's rare draws find a rich pool instead of an
///     empty one — the feedback simulation (drr_ledger_tests.rs)
///     reproduces both sides rootlessly before the close. learned
///     < 2 keeps the ledger OFF (a cold pool, a missed state
///     lookup, a lone drawer — the single-active row's whole-
///     budget bound), and every ledger word fails open onto the
///     v16 law. New maps, verdict math unchanged on every other
///     lane; the usual one-time re-apply contract as ever.
pub const SCHEMA_VERSION_EXPECTED: u32 = 17;

#[cfg(test)]
mod sync_pin {
    //! The BPF-side anchor pin (NIGHT-upgrade-charger-core-3a). The
    //! v13 bump drifted this constant from its ebpf-crate twin for
    //! one full schema era — harmless at runtime (userspace stamps
    //! the pinned map; the BPF const is the parity ANCHOR, never
    //! executed), but the anchor existed precisely so a reader of
    //! either tree could trust the number, and it lied. This pin
    //! reads the anchor out of the BPF source itself and fails the
    //! build on any future drift — the layout-contract discipline
    //! (size pins) applied to the version contract.

    /// The BPF-side parity anchor, scraped from the source file that
    /// declares it (it cannot be compiled into this tree — the file
    /// is aya-ebpf `#![no_std]` — but its TEXT is a contract this
    /// pin owns, the same way the size pins own struct offsets).
    fn bpf_schema_version() -> u32 {
        let src = include_str!("../../../ebpf/src/bin/limiter.rs");
        let needle = "const SCHEMA_VERSION: u32 = ";
        let start = src
            .find(needle)
            .expect("ebpf/src/bin/limiter.rs must declare SCHEMA_VERSION");
        let rest = &src[start + needle.len()..];
        let end = rest
            .find(';')
            .expect("SCHEMA_VERSION declaration must terminate");
        rest[..end]
            .trim()
            .parse()
            .expect("SCHEMA_VERSION must be a plain u32 literal")
    }

    #[test]
    fn bpf_anchor_matches_expected() {
        assert_eq!(
            bpf_schema_version(),
            super::SCHEMA_VERSION_EXPECTED,
            "SCHEMA_VERSION (ebpf/src/bin/limiter.rs) drifted from \
             SCHEMA_VERSION_EXPECTED (src/ebpf/limiter/schema.rs) — \
             bump BOTH together, the v13 lesson"
        );
    }
}
