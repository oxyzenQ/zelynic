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
/// v17 (NIGHT-repair-3/4, the epoch ledger): the DRR draw's take is
///     further capped by the leaf's banked per-EPOCH allowance — the
///     pool's 100ms refill split across the drawee PEAK (a decaying
///     high-water of distinct askers packed into the re-widened
///     pool-share word, so the split does not inflate when starved
///     siblings go retransmit-quiet), earned per epoch and held as
///     a quantum-capped CARRY per LEAF in the two new pinned LRU maps
///     drr_leaf_state_dl/ul (leaf cgroup id -> the packed
///     `carry:u32 | epoch:u32` word, drr.rs's packing — the carry
///     banks toward the 64 KiB GSO admit floor, healing the starved
///     flow's TCP and the aggregate floor with it) — and the
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
///     starved leaf's rare draws find a rich pool — the feedback
///     simulation (drr_ledger_tests.rs) reproduces both sides
///     rootlessly before the close. learned < 2 keeps the ledger
///     OFF (a cold pool, a missed state lookup, a lone drawer — the
///     single-active row's whole-budget bound), and every ledger
///     word fails open onto the v16 law. New maps, the pool-share
///     word re-packed (the askers' peak joined it) and the share +
///     ledger state maps re-keyed on the AMMSP generation (repair-6:
///     a mutated budget hands its successor a fresh divisor and a
///     fresh carry, never the previous budget's peak throttling it
///     through the decay's tail — the key is (generation << 32) |
///     id, the memo map's own packing shape); verdict math
///     unchanged on every other lane; the usual one-time re-apply
///     contract as ever.
/// v18 (NIGHT-hunt-Z1, the cross-direction memo close): the AMMSP
///     leaf cache splits into TWO direction-scoped pinned LRU maps —
///     ammsp_leaf_cache_dl and ammsp_leaf_cache_ul — because a memo's
///     root is only valid for the direction whose walk produced it:
///     the walk resolves against THAT direction's policy map, and
///     the single-direction applies (`strict -d`, `strict -u`)
///     legitimately leave the two maps disagreeing about a leaf's
///     nearest root (the written leg resolves to the target, the
///     deleted leg to an ancestor catch-all or unlimited). The
///     v10..v17 shared map let the first direction to walk a leaf
///     poison the other's every later packet — on the owner's
///     machine the handshake/ACK egress packets memoized the probe
///     leaf onto the root catch-all, every download data packet then
///     enforced at the ANCESTOR's 150 KB/s instead of the target's
///     10 KB/s (measured 338.2 and 589.8 KB over a 3s window vs the
///     95.5/125.5 KB budgets — 3.5-4.7x, the ledger booked at the
///     ancestor, the verdict FAILED against a policy that never
///     ran), and the stale-detect belt could not catch it because
///     the catch-all carries a row in both policy maps. Two maps
///     close the class; each direction memoizes only what its own
///     walk resolved. The ammsp_generation counter stays shared (one
///     bump retires both lanes at once); the fallback sweep walks
///     both maps. New map layout on the memo lane; the bump forces
///     pinned v17 programs to reload into the direction-scoped
///     object — active limits are dropped once, re-apply after
///     upgrade, the same one-time contract as every bump before it.
/// v19 (NIGHT-private-research-4, ECN-first policing): the drop
///     verdict of a budgeted lane becomes a LAST RESORT. When the
///     kernel helper bpf_skb_ecn_set_ce (helper ID 97, exposed to
///     cgroup_skb by cg_skb_func_proto under CONFIG_INET — inside
///     the 5.13 verified floor) can set the CE codepoint on the
///     packet's IPv4 or IPv6 header, the packet is DELIVERED
///     CE-marked instead of dropped, and its bytes charge a debt
///     word in the two new pinned LRU maps ecn_debt_dl/ul (keyed by
///     the generation-prefixed budget key: the pool's root on the
///     DRR lane, the group id on the strict-multi lane — the
///     repair-6 discipline). Every DELIVERED packet on the lane pays
///     that debt from the budget's own token stream afterwards, out
///     of the leftover the delivery left behind (ebpf/src/ecn.rs
///     debt_pay, on the allow path only — the call-site law that
///     keeps a CE-ignoring hammer from starving the lane below the
///     policy), which keeps the
///     budget law closed for CE-reactive AND CE-ignoring senders
///     alike: delivered <= rate*t + burst + one 64 KiB super-packet
///     (the ecn.rs proof — no time-based decay, no second rate
///     stream a cheating sender could farm). A non-ECT packet is
///     refused by the helper and drops exactly as before; the
///     per-socket lane keeps its drop shape by documented scope
///     (per-connection CE marking needs its own convergence
///     analysis — an aggregate-collapse shape for servers). New
///     maps, new verdict semantics on the budgeted lanes; the bump
///     forces pinned v18 programs to reload into the ECN-first
///     object — active limits are dropped once, re-apply after
///     upgrade, the same one-time contract as v4..v18.
/// v20 (CAKE-shaped flow isolation): the DRR lane's leaf stops
///     being one shared bucket for every socket the cgroup holds —
///     an attributed packet (bpf_get_socket_cookie, the per-socket
///     lane's own join, no new helper) spends from its own FLOW
///     bucket and draws from the leaf under the DRR laws mirrored
///     one level down: the learned flow count and drawee peak in the
///     two new flow_share_dl/ul words ((generation << 32) | leaf),
///     the epoch allowance and quantum-capped carry in the two new
///     flow_ledger_dl/ul words (RAW cookie keyed — a u64 the
///     generation prefix cannot carry; a mutated budget's successor
///     inherits at most one quantum of carry, availability-capped),
///     the buckets themselves the pinned 24-byte Bucket with the
///     draw stamp on last_refill_ns and the generation belt on
///     frac_rem (the leaf bucket's own trick). The SPARSE/DENSE
///     distinction rides the flow bucket's draw-stamp epoch (a flow
///     quiet for an epoch draws its packet's own bytes — the
///     reserved small quantum; a flow drawing this epoch takes the
///     quantum), and the OFF lane's take is the learned-share
///     fraction leaf/(learned+2) — the rootless isolation battery's
///     measured catch: the share word's peak decay reads MAX for the
///     epochs between a decay and its re-ratchet, and a lane-law-only
///     take there would drain the leaf whole once per transient
///     epoch. The honest verdict the battery delivered first: the
///     sketched starvation of the quiet flow does not reproduce (the
///     banking's leftovers carry it, measured 100% admits in both
///     lanes) — the race's real victims are the weaker demanders
///     (a second download at 2.9:1 under the shared leaf, 1.1:1
///     under the lane), and the quiet flow's protection is the
///     zero-stranding demand-sized take (taken == got, measured).
///     cookie == 0 (the hook's honest attribution limit) rides the
///     leaf lane verbatim; the per-socket and strict-multi lanes are
///     untouched by documented scope. Six new maps, all
///     datapath-internal (the leaf_bucket family's contract); the
///     bump forces pinned v19 programs to reload into the
///     flow-isolated object — the same one-time re-apply contract
///     as ever.
/// v21 (the per-socket convergence closure): the v19 ECN scope
///     note's deferred question — "a server's N connections each
///     halving their windows on per-connection marks is an
///     aggregate-collapse shape that needs its own convergence
///     analysis before it ships" — is answered, and the answer
///     ships the marking: the per-socket lane joins the ECN-first
///     family, mark before drop, per connection. The rootless
///     fleet sims (test/ebpf/limiter/ecn_tests.rs) are the
///     analysis: N independent per-connection budgets converge on
///     their own streams (the aggregate rides N x per-connection,
///     no collapse term — the feared synchronized halving costs
///     each connection its own sawtooth, never the fleet its
///     total), the marking fleet beats the same fleet under
///     per-socket drops (the lane's shipped shape), and a
///     CE-ignoring hammer on one connection stays inside its own
///     budget law while its neighbors converge untouched (the
///     per-connection budget IS the isolation). The debt word
///     lives inside SocketBucket — now 40 bytes: core, gen_stamp,
///     ecn_debt — instead of the budget-keyed debt map the cgroup
///     lanes ride: per-connection state in the per-connection
///     bucket, belt-zeroed on the generation a policy mutation
///     bumps (the repair-6 discipline, structural), aged out with
///     the bucket by the LRU the lane already trusts. The
///     per-connection budget law is the ecn.rs closed form
///     unchanged: delivered_i <= rate*t + burst + one 64 KiB
///     super-packet, so the aggregate honest bound is N x that
///     (the lane's documented "rate x concurrent sockets" shape
///     plus the one-time per-connection ECN slack). Non-ECT traffic
///     refuses the helper and drops exactly as before — the legacy
///     verdict, untouched. Map-VALUE layout change (the socket
///     bucket maps); the bump forces pinned v20 programs to reload
///     into the per-socket-ECN object — active limits are dropped
///     once, re-apply after upgrade, the same one-time re-apply
///     contract as ever.
/// v22 (NIGHT-private-research-4 candidate, QUIC-aware attribution):
///     the per-socket lane and the v20 CAKE flow lane key their
///     per-connection buckets by the packet's QUIC CONNECTION ID
///     when the header carries finer truth than the socket cookie —
///     QUIC (HTTP/3) multiplexes many connections over ONE UDP
///     socket (the browser shape: Chromium and Firefox share a
///     single socket across every QUIC session, demuxed by CID), so
///     the cookie the two lanes attributed by collapsed all of them
///     into one bucket: the flow lane's own monopoly shape, and the
///     --per-socket promise ("each connection its own budget")
///     silently shared by the whole socket for the protocol that
///     multiplexes. The pure core (ebpf/src/quic.rs, pinned
///     rootlessly by test/ebpf/limiter/quic_tests.rs): v1/v2 long
///     headers parse exactly (explicit CID lengths — stateless
///     keys); short-header CID lengths are CONNECTION STATE (RFC
///     9000 negotiates them inside encrypted NEW_CONNECTION_ID
///     frames, the documented reason QUIC-LB exists), so the wiring
///     LEARNS them from the handshake's own explicit-length bytes
///     into two new pinned LRU maps quic_cid_hint_dl/ul (conversation
///     key -> the packed hint word, shared across both hooks by
///     object construction), gated by a CONFIRMATION rule (the same
///     nonzero length must survive a second long-header sighting
///     before any short header keys on it — a throwaway Initial DCID
///     the peer replaces after its Server Initial can never poison
///     the lane alone). Every refusal — non-UDP, non-QUIC,
///     unparsable, unconfirmed, zero-length CID, IPv6 extension
///     headers — rides the RAW COOKIE, exactly the pre-v22 verdict:
///     the feature refines attribution, never degrades it, and the
///     flow of residues a QUIC middlebox cannot close (CID rotation
///     mid-flight, the >8-byte prefix share, the v6 /48 hint seed,
///     the GSO/GRO super-packet's whole-length attribution to its
///     first segment's connection — one skb is one verdict at a
///     cgroup hook, still finer than the cookie lane it refined)
///     is stated in the core's module docs and pinned by the tests.
///     No existing struct layout changes; new maps, new key VALUES
///     on two internal lanes; the bump forces pinned v21 programs to
///     reload into the QUIC-aware object — active limits are dropped
///     once, re-apply after upgrade, the same one-time re-apply
///     contract as ever.
/// v23 (night-during, the unified --during time windows): a policy
///     row may carry its own LIFETIME — the side map policy_window
///     (HashMap, resolved policy-root cgroup id -> the 32-byte
///     PolicyWindow row, pinned, both hooks reading one shared map)
///     and the one-entry pinned Array wall_clock_offset (the
///     wall-minus-mono bridge userspace stamps at every attach and
///     apply-family mutation, the watchdog/schema_version
///     userspace-written contract). The gate reads the window AFTER
///     the policy hit on the policed path only: absent = today's
///     behavior, INACTIVE = ALLOW (the miss shape — no stats, no
///     ring, no belt) until the unstrict/reclaim sweep removes an
///     ENDED span; a dormant future-date row and a daily window are
///     never swept. SPAN rows carry wall instants pre-translated to
///     the monotonic clock at apply time (drift-free: NTP slew and
///     `date -s` move nothing; the stated residue is suspend, which
///     monotonic does not count); DAILY rows carry seconds-of-day
///     UTC with the midnight wrap and read the wall through the
///     bridge under the margin law (FIRE_EARLY = 2s eroding BOTH
///     edges toward less enforcement — a stale bridge can
///     under-enforce by at most the margin, never over-enforce).
///     The grammar (owner decision, design brief section 8, then
///     revised duration-only): --during 2h 20d (duration, s m h
///     d mn y, 1s..10y) — the window and date forms the first
///     decision carried are gone from the flag, but the row kinds
///     stay readable (older builds' pinned rows and the restore
///     lane's state files still carry them; a grammar change
///     never narrows a map). No existing struct layout changes;
///     new maps, one new verdict
///     on the policed path; the bump forces pinned v22 programs to
///     reload into the time-windowed object — active limits are
///     dropped once, re-apply after upgrade, the same one-time
///     contract as every bump before it.
///
/// v24 (NIGHT-improve-40, the guarantee brackets): the DRR pool's
///     fair split gains per-LEAF min/max brackets — floor_bps and
///     ceil_bps ride the Policy row itself (24 -> 40 bytes, the
///     first VALUE-SIZE change a bump ever carried: the two u64s
///     slot between burst_bytes and the tail word pair, moving
///     group_id/flags to 32/36; the reload the bump forces is
///     therefore REQUIRED, not polite — a pinned v23 map holds
///     24-byte rows this object would misread mid-struct). The
///     zero sentinel is UNSET: floor 0 = the fair split stands,
///     ceil 0 = the lone drawer keeps the whole budget, and a 0/0
///     row is the exact v23 arithmetic (the fail-open posture —
///     the bracket composes onto the v16/v17 laws, it never
///     replaces them). A set floor raises the epoch allowance to
///     the floor's share (a PRIORITY, not a reservation: no tokens
///     held back, an absent leaf costs nothing, the unspent
///     allowance stays in the pool — the pool's own accumulation
///     IS the lender, the hierarchical borrowing with no carve-out
///     and no daemon); a set ceiling lowers the allowance AND the
///     stockpile cap to the ceiling's own quantum and binds even a
///     lone drawer (a cap that folds when siblings appear is not a
///     cap). Over-subscribed floors (sum of floors above the
///     refill) degrade to the pool law — the pool never hands out
///     what it does not have — the same documented honesty as the
///     trickle tradeoff. The laws live in the pure core (drr.rs's
///     v24 section) pinned rootlessly by drr_guarantee_tests.rs;
///     the datapath reads the bracket off the row it already
///     fetched (no new maps, no new lookups, no new verdict); the
///     bump forces pinned v23 programs to reload into the
///     bracketed object — active limits are dropped once, re-apply
///     after upgrade, the same one-time contract as every bump
///     before it.
pub const SCHEMA_VERSION_EXPECTED: u32 = 24;

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
        // NIGHT-improve-44: the anchor moved with the 600-line split
        // (bin/limiter.rs -> schema.rs, the doc ledger's own file) —
        // the pin follows the declaration, wherever it lives.
        let src = include_str!("../../../ebpf/src/schema.rs");
        let needle = "const SCHEMA_VERSION: u32 = ";
        let start = src
            .find(needle)
            .expect("ebpf/src/schema.rs must declare SCHEMA_VERSION");
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
            "SCHEMA_VERSION (ebpf/src/schema.rs) drifted from \
             SCHEMA_VERSION_EXPECTED (src/ebpf/limiter/schema.rs) — \
             bump BOTH together, the v13 lesson"
        );
    }
}
