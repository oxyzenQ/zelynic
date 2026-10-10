// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// NIGHT-improve-44: the schema-version ledger (the v1..v24
// contract history) and the SCHEMA_VERSION const it documents,
// moved out of limiter.rs at the 600-line cap. Same file the
// userspace loader contract names; the doc text is verbatim.
//
// ---------------------------------------------------------------------------
// Shared layout contract with the userspace loader (src/ebpf/limiter/
// types.rs: PolicyRaw, BucketRaw, LimiterStatsRaw) and the C twin. The
// compile-time size pins guarantee the layouts can never drift
// silently; the C side relies on kernel headers for the same
// invariants, the userspace tests assert the third copy.
// (NIGHT-depthbore-1: the struct definitions, the size pins,
// NS_PER_SEC, MAX_ENFORCABLE_BURST, and the enforce math moved to
// math.rs — this block keeps the contract statement.)
// ---------------------------------------------------------------------------

/// Current schema version. Increment when struct layouts or
/// semantics change. Kept in sync with SCHEMA_VERSION_EXPECTED in
/// src/ebpf/limiter/types.rs (v3: rate_bps == 0 drops instead of
/// allowing; v4: enforcement-boundary sanitization — burst and
/// tokens are clamped before any refill math so no stored map value
/// can overflow the kernel arithmetic; v5: the rate-0 block verdict
/// books its drops into cgroup_limiter_stats — verdict unchanged, but
/// pinned v4 programs must reload or blocked traffic keeps dying
/// with an empty drop counter; v6 (NIGHT-depthbore-1): frac_rem —
/// the third persistent stored field, missed by the v4 clamp family
/// — is sanitized on read in the refill math (math.rs), completing
/// the burst/tokens/frac clamp triple; no layout change; v7
/// (NIGHT-boost-38): SMP-safe enforcement — the bucket/stat
/// read-modify-writes in math.rs move to lock-free atomics so two
/// CPUs on one bucket can no longer lose updates and over-allow
/// 130-146% of budget under concurrent flows; no layout change;
/// v8 (NIGHT-lts-8): the extreme-burst consume retry — the CAS
/// consume re-observes and retries up to four attempts, so a
/// concurrent deduction between one packet's read and its CAS no
/// longer falsely drops an affordable packet under many-CPU bursts
/// (measured: 1.35% of packets at one attempt, 28x fewer at four);
/// no layout change; v9 (NIGHT-master-3): the rate-0 block verdict
/// books its drops through the SAME atomic fetch_add the enforce
/// path uses — the v5 booking kept the plain `+=` the v7 rewrite
/// erased everywhere else, so a blocked cgroup with traffic on
/// several CPUs lost drop-accounting increments exactly the way
/// the pre-v7 ledger lost allowed bytes; verdict unchanged, no
/// layout change, same one-time re-apply contract; v10
/// (NIGHT-private-research-2, MMSPA): the leaf-anchored policy
/// lookup becomes subtree-aware — a policy written for cgroup A now
/// polices every socket born under A/** with ONE shared budget,
/// resolved per packet through the new pinned mmspa_leaf_cache map
/// (LRU, leaf cgroup id → resolved policy root, 0 = resolved
/// unlimited) and enforced with bucket + stats keyed at the ROOT, so
/// the subtree shares the budget and the ledger rolls up to the
/// target. New map, new coverage, existing layouts; every
/// userspace policy mutation flushes the cache. The bump forces
/// pinned v9 programs to reload into the subtree-aware object —
/// the same one-time re-apply contract as every bump before it.
/// v11 (NIGHT-think-like-light-years-3): the init-path inserts
/// (get_stats_ptr, get_bucket_ptr) switch from BPF_ANY to
/// BPF_NOEXIST — under a many-CPU first-packet burst on a fresh
/// bucket, the ANY flag let a racing initializer wholesale-reset an
/// entry another CPU was already enforcing through: consumed tokens
/// resurrected to full burst, the window-ownership stamp rolled back
/// to re-credit an already-paid window, and booked stats increments
/// vanished. No layout change, verdict math untouched; the bump
/// forces pinned v10 programs to reload into the init-race-free
/// object — the same one-time re-apply contract as v4..v10.
/// v12 (NIGHT-perf-0): MMSPA memos become generation-stamped — the
/// mmspa_leaf_cache value widens u32 -> u64, packing
/// `(generation << 32) | root`, and a new one-entry pinned
/// mmspa_generation counter array is bumped by every userspace
/// policy mutation after its writes land (read by the datapath before
/// every resolution). The stamp closes the one hole the whole-map
/// delete flush could not: a walk whose tail an NMI/IRQ storm
/// stretched past the flush inserted a memo computed against
/// pre-mutation state AFTER the sweep finished — a stale verdict
/// that lived until the next mutation. A stamp mismatch is detected
/// per packet, so no insert can outlive the state it summarized; the
/// O(4096)-syscall sweep becomes an O(1) counter store with the
/// sweep kept only as its failure fallback. Map set + value layout
/// change; the bump forces pinned v11 programs to reload into the
/// generation-stamped object — active limits are dropped once,
/// re-apply after upgrade, the same one-time contract as v4..v11.
/// v13 (NIGHT-upgrade-charger-core-1c, the fair-shared bucket): the
/// individual-bucket lane becomes DRR-shaped — the shared bucket is
/// now a POOL (refilled by the same refill_window, drained only by
/// per-LEAF quantum draws), and every packet spends from a per-leaf
/// bucket keyed by the socket's own cgroup id in the two new pinned
/// LRU maps leaf_bucket_dl/ul (4096 entries, the memo map's
/// posture). A greedy leaf can no longer consume every token the
/// instant it refills: it holds at most one quantum
/// (max(rate x 100ms, the 64 KiB GSO admit floor)) at a time, and
/// the pool's next refills flow to whichever leaf is empty and
/// asking — the starvation shape (one subprocess at ~100%, its
/// siblings at ~0%) becomes bounded shares. The aggregate stays
/// exactly the policy (the pool never hands out what it does not
/// have); the group-bucket lane (the former strict-multi verb)
/// keeps the legacy FCFS shape by documented scope. The stale-quantum
/// belt: leaf
/// quanta are stamped with the MMSPA generation at their draw, and
/// a mismatching stamp zeroes them before the packet proceeds — a
/// policy mutation can never leave a leaf spending a dead budget's
/// quantum. New maps, new enforcement semantics on the individual
/// lane; the bump forces pinned v12 programs to reload into the
/// fair-sharing object — active limits are dropped once, re-apply
/// after upgrade, the same one-time contract as v4..v12.
/// No layout change since v2; each bump forces pinned older
/// programs to reload into the hardened object — a one-time limit
/// re-apply, documented in CHANGELOG.
/// The BPF program never writes it — userspace stamps
/// the pinned map after load — so the constant exists purely as the
/// parity anchor for that three-way contract.
/// v14 (NIGHT-upgrade-charger-core-3a, the in-kernel time-series
/// ring): two new pinned maps rate_ring_dl/ul (u32 policy-root
/// cgroup id -> 128-byte eight-slot ring) book every ALLOWED
/// packet's bytes into one-second windows — the rolling rate
/// horizon `status --print-json` surfaces (the EAGLE EYES V1
/// foundation). Monitor-only: no verdict change, no layout change
/// on any existing struct, the ledger (cgroup_limiter_stats)
/// stays the exact truth. The bump is still load-bearing, not
/// ceremonial: the userspace reader opens the new pins, so a stale
/// pinned object must reload instead of serving no-ring state
/// silently — the same one-time re-apply contract as v4..v13.
/// The bump also restores THIS anchor's parity: the v13 bump
/// (charger-core-1c) raised the userspace twin to 13 but missed
/// this const (it stayed 12 — dead code here, so nothing broke at
/// runtime, but the anchor lied about which semantics the source
/// carried; the userspace sync pin added with this task makes the
/// drift class impossible to repeat).
/// v15 (NIGHT-upgrade-charger-core-3b, per-socket limiting —
/// Tier B #7): Policy.flags — the four padding bytes at offset 20
/// become CONTRACT (bit 0 = POLICY_FLAG_PER_SOCKET: enforce per
/// SOCKET, every connection its own bucket at the policy rate,
/// beyond the cgroup) — and two new pinned LRU maps
/// socket_bucket_dl/ul (socket cookie u64 -> 32-byte SocketBucket:
/// the standard bucket + the AMM-generation stamp of the
/// stale-token belt). The attribution needs NO tracepoint: the
/// kernel already names the owning socket per packet in both
/// cgroup_skb hooks (bpf_get_socket_cookie, the observer's
/// NIGHT-boost-26 cookie join). A zero cookie (no socket
/// attribution available) degrades to the DRR cgroup lane — still
/// policed, honestly coarser. Struct size stays 24 (the size pin
/// unchanged); the bump is load-bearing for the usual reason (new
/// maps, and a field that was padding is now read), and the
/// one-time re-apply contract holds as ever.
/// v17 (NIGHT-repair-3/4, the epoch ledger, the carry form): the
/// DRR draw's take is further capped by the leaf's banked
/// per-EPOCH allowance — the pool's 100ms refill split across the
/// drawee PEAK (a decaying high-water of distinct askers, newly
/// packed into the pool-share word so the split does not inflate
/// when starved siblings go retransmit-quiet), earned per epoch
/// and held as a quantum-capped CARRY per leaf in two new pinned
/// LRU maps drr_leaf_state_dl/ul (LEAF cgroup id -> the packed
/// `carry:u32 | epoch:u32` word, drr.rs's packing — the carry
/// banks toward the 64 KiB GSO admit floor, healing the starved
/// flow's TCP and the aggregate floor with it) — and the
/// pool-share note rides a two-attempt CAS instead of the v16
/// plain-read-plus-BPF_ANY insert (concurrent notes clobbered
/// each other's increments until the learned count itself lied,
/// converging to 1-3 drawers under the multi-CPU draw storm).
/// The close is the battery's own find: a per-take cap cannot
/// bound a per-epoch share — the flow that admits grows its TCP
/// window and draws on every packet, so the worst leaf read 4.7x
/// fair while the quietest measured one admit; with the ledger
/// the fast drawer blocks at its fair share, the refills
/// accumulate behind it, and the starved leaf's rare draws find
/// a rich pool. No existing struct layout changes; new maps, the
/// share word re-packed and both state maps re-keyed on the MMSPA
/// generation (the usual one-time re-apply contract).
/// v18 (NIGHT-hunt-Z1, the cross-direction memo close): the MMSPA
/// leaf cache splits into TWO direction-scoped maps —
/// mmspa_leaf_cache_dl and mmspa_leaf_cache_ul — because a memo's
/// root is only valid for the direction whose walk produced it. The
/// v10..v17 single map was read by both enforce_dl and enforce_ul,
/// and the single-direction applies (`strict -d`, `strict -u`)
/// legitimately leave the two policy maps disagreeing about a
/// leaf's nearest root (the written leg resolves to the target, the
/// deleted leg to an ancestor catch-all or unlimited): the first
/// direction to walk a leaf poisoned the other's every later packet
/// — the handshake/ACK egress packets memoized the probe leaf onto
/// the root catch-all, every download data packet then enforced at
/// the ANCESTOR's rate (measured 3.5-4.7x the target budget, the
/// ledger booked at the ancestor, the probe FAILED against a policy
/// that never ran), and the stale-detect belt could not catch it
/// because the catch-all carries a row in both policy maps. Two
/// maps close the class; each direction memoizes only what its own
/// walk resolved. The mmspa_generation counter stays SHARED (a
/// mutation bump retires both lanes' memos at once — the stamp
/// contract is unchanged). New map layout on the memo lane; the
/// bump forces pinned v17 programs to reload into the
/// direction-scoped object — active limits are dropped once,
/// re-apply after upgrade, the same one-time contract as every
/// bump before it.
/// v19 (NIGHT-private-research-4, ECN-first policing): the drop
/// verdict of a budgeted lane becomes a LAST RESORT. When the
/// kernel helper bpf_skb_ecn_set_ce can set the CE codepoint on the
/// packet's IP header (ECT-capable, IPv4 or IPv6, checksum handled
/// by the kernel), the packet is DELIVERED CE-marked instead of
/// dropped, and its bytes charge an ECN debt word (the two new
/// pinned LRU maps ecn_debt_dl/ul, keyed by the generation-prefixed
/// BUDGET key — the pool's root on the DRR lane, the group id on
/// the group lane). Every DELIVERED packet on the lane pays
/// that debt from the budget's own token stream afterwards, out of
/// the leftover the delivery left behind (ecn.rs debt_pay, on the
/// allow path only — the call-site law that keeps a CE-ignoring
/// hammer from starving the lane below the policy), which is what
/// keeps the budget law closed: delivered <= rate*t + burst + one
/// 64 KiB super-packet,
/// for CE-reactive AND CE-ignoring senders alike (the ecn.rs proof —
/// no time-based decay, no second rate stream). A non-ECT packet
/// (the RFC 3168 majority) is refused by the helper and drops
/// exactly as before. The per-socket lane keeps its drop shape by
/// documented scope (per-connection CE marking is an
/// aggregate-collapse shape that needs its own convergence
/// analysis). New maps, new verdict semantics on the budgeted
/// lanes; the bump forces pinned v18 programs to reload into the
/// ECN-first object — active limits are dropped once, re-apply
/// after upgrade, the same one-time contract as v4..v18.
/// v21 (the per-socket convergence closure): the v19 scope note's
/// deferred question is answered and the per-socket lane joins the
/// ECN-first family — mark before drop, per connection. The debt
/// word lives INSIDE SocketBucket (40 bytes now: core, gen_stamp,
/// ecn_debt) instead of the budget-keyed debt map: a per-connection
/// budget's debt is per-connection state, the generation belt zeroes
/// it with the tokens on a mutation (the repair-6 discipline,
/// structural), and the LRU ages the whole bucket out together. The
/// deferred "aggregate-collapse" question is closed by the rootless
/// fleet sims (test/ebpf/limiter/ecn_tests.rs, the per-socket
/// convergence analysis): per-connection budgets are independent,
/// so N marked connections converge on their own streams and the
/// aggregate rides N x per-connection — no collapse term, the
/// fleet beats the drop fleet, a CE-ignoring hammer stays bounded
/// by its own budget law and its neighbors' convergence is
/// untouched. Non-ECT traffic still refuses the helper and drops
/// exactly as before. Map-value layout change (the socket bucket
/// maps); the bump forces pinned v20 programs to reload into the
/// per-socket-ECN object — active limits are dropped once, re-apply
/// after upgrade, the same one-time contract as every bump before.
/// v22 (NIGHT-private-research-4 candidate, QUIC-aware attribution):
///     the per-socket lane and the v20 CAKE flow lane key their
///     per-connection buckets by the packet's QUIC CONNECTION ID when
///     the header carries finer truth than the socket cookie — QUIC
///     (HTTP/3) multiplexes many connections over ONE UDP socket
///     (the browser shape: Chromium and Firefox share a single socket
///     across every QUIC session, demuxed by CID), so the cookie the
///     two lanes attributed by collapsed all of them into one bucket
///     (the flow lane's own monopoly shape; the --per-socket promise
///     "each connection its own budget" silently shared by the whole
///     socket). The pure core (../quic.rs, pinned rootlessly by
///     test/ebpf/limiter/quic_tests.rs): v1/v2 long headers parse
///     exactly (explicit CID lengths); short-header CID lengths are
///     CONNECTION STATE (RFC 9000 negotiates them inside encrypted
///     NEW_CONNECTION_ID frames — the documented reason QUIC-LB
///     exists), so the wiring LEARNS them from the handshake's own
///     explicit-length bytes into two new pinned LRU maps
///     quic_cid_hint_dl/ul (conversation key -> the packed hint
///     word, shared across both hooks by object construction),
///     gated by a CONFIRMATION rule (the same nonzero length must
///     survive a second long-header sighting before any short
///     header keys on it — a throwaway Initial DCID a peer replaces
///     after its Server Initial can never poison the lane alone).
///     Every refusal — non-UDP, non-QUIC, unparsable, unconfirmed,
///     zero-length CID, IPv6 extension headers — rides the RAW
///     COOKIE, exactly the pre-v22 verdict: the feature refines
///     attribution, never degrades it. No existing struct layout
///     changes; new maps, new key VALUES on two internal lanes; the
///     bump forces pinned v21 programs to reload into the QUIC-aware
///     object — active limits are dropped once, re-apply after
///     upgrade, the same one-time contract as every bump before it.
/// v23 (night-during, the unified --during time windows): a policy
///     row may carry its own LIFETIME — one new side map,
///     policy_window (HashMap, resolved policy-root cgroup id ->
///     the 32-byte during::PolicyWindow row, pinned, both hooks
///     sharing it by object construction, keyed exactly like the
///     stats ledger), read AFTER the policy hit on the policed
///     path only: an absent entry is today's behavior exactly, and
///     the unlimited fast path pays nothing (the NIGHT-lts-2 law,
///     verbatim). A row whose window is INACTIVE answers ALLOW —
///     the miss shape, no stats booking, no ring booking, no
///     MMSPA belt — until the userspace sweep (the unstrict/
///     reclaim path) removes an ENDED span; a dormant future-date
///     row and a recurring daily window are never swept. The two
///     shapes: SPAN rows (the duration and date grammar) store
///     wall instants PRE-TRANSLATED to the monotonic clock at
///     apply time — bpf_ktime_get_ns and the userspace
///     CLOCK_MONOTONIC read are the same clock domain, so NTP slew
///     and a manual `date -s` cannot move a span by a single
///     nanosecond (the stated residue: suspend, which monotonic
///     does not count, so a sleeping host's span outlives its
///     wall-calendar promise by the slept time); DAILY rows (the
///     09:00-17:00 grammar, UTC, midnight wrap) store
///     seconds-of-day and read the wall through the offset
///     bridge — the new one-entry pinned Array wall_clock_offset
///     (userspace-written, the watchdog/schema_version contract:
///     never written by this program), stamped at every attach
///     and apply-family mutation so the CLI visit IS the refresh
///     channel, with the margin law (during.rs FIRE_EARLY = 2s)
///     eroding BOTH daily edges toward LESS enforcement — a stale
///     bridge under-enforces by at most the margin, never
///     over-enforces, the direction a limiter fails safe in. No
///     existing struct layout changes; two new maps, one new
///     verdict on the policed path; the bump forces pinned v22
///     programs to reload into the time-windowed object — active
///     limits are dropped once, re-apply after upgrade, the same
///     one-time contract as every bump before it.
///
/// v24 (NIGHT-improve-40, the guarantee brackets): the DRR pool's
///     fair split gains per-LEAF min/max brackets — the HTB
///     rate/ceil idiom carried into a policer that cannot queue
///     (HFSC-lite, the owner's lane list's close of the DRR arc).
///     The Policy row itself grows the pair: floor_bps and ceil_bps
///     slot between burst_bytes and the tail word pair (24 -> 40
///     bytes, the FIRST value-size change a bump ever carried —
///     every earlier bump added maps or flags in padding, this one
///     moves group_id/flags to 32/36, so the reload the bump
///     forces is not merely polite but REQUIRED: a pinned v23 map
///     holds 24-byte rows this object would misread mid-struct).
///     The zero sentinel is UNSET on both sides — floor 0 = no
///     guarantee (the fair split stands), ceil 0 = no cap (the
///     lone drawer keeps the whole budget); a 0/0 row is the exact
///     v23 arithmetic, the fail-open posture. A set floor RAISES
///     the epoch allowance to the floor's share (a PRIORITY, not
///     a reservation — no tokens are held back, an absent leaf
///     costs nothing, and the borrowing is the pool's own natural
///     accumulation: unspent allowance stays in the pool for
///     whoever is under their ceiling); a set ceiling LOWERS the
///     allowance and the stockpile cap to the ceiling's own
///     quantum, and binds even a LONE drawer — a cap that folds
///     when siblings appear is not a cap. The guarantee laws
///     themselves live in the pure core (drr.rs's v24 section,
///     pinned rootlessly by drr_guarantee_tests.rs); the datapath
///     reads them off the row it already fetched (no new maps, no
///     new lookups); the bump forces pinned v23 programs to reload
///     into the bracketed object — active limits are dropped once,
///     re-apply after upgrade, the same one-time contract as every
///     bump before it.
#[allow(dead_code)]
pub(crate) const SCHEMA_VERSION: u32 = 24;

// ---------------------------------------------------------------------------
// Maps. The static names ARE the userspace contract (limiter/mod.rs
// and pin.rs open each map by name or by pin path), so they stay
// lowercase exactly like the C object's symbols; the allow attribute
// suppresses the non-upper-case globals lint for that reason. Every
// map is pinned by name: policies must survive process exit, which
// is the whole point of the /sys/fs/bpf/zelynic directory.
// ---------------------------------------------------------------------------

// ─ Download (ingress) maps ─
