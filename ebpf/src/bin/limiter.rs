// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// zelynic eBPF limiter, the pure-Rust BPF source (NIGHT-improve-1,
// phase 2, stage 1: port of the former bpf/limiter.bpf.c; phase 3
// deleted the C side — the port is now the production source).
//
// Cosmic Dragon Architecture Layer 0: Enforcement. Pure eBPF. No tc, no
// nft, no cgroup-wrapper. The kernel enforces. Two programs:
//   enforce_dl — attached to cgroup_skb/ingress (download)
//   enforce_ul — attached to cgroup_skb/egress (upload)
//
// Line-for-line translation of the C twin onto aya-ebpf 0.2.1. The
// ELF contract with src/ebpf/limiter/mod.rs is identical (names,
// sections, map types, struct layouts, pinning, GPL license): the
// userspace loader opens every map through EbpfLoader::map_pin_path,
// so all eleven maps declare PIN_BY_NAME exactly like the C twin's
// LIBBPF_PIN_BY_NAME annotations (aya-ebpf exposes this as
// HashMap::pinned / Array::pinned, which the map macro emits as the
// pinning field of the legacy bpf_map_def; aya-obj parses that field
// and aya 0.13.1 pins ByName maps on load — verified against the
// pinned userspace source, not assumed).
//
// One deliberate behavioral delta from the C twin (schema v11,
// NIGHT-think-like-light-years-3): the init-path inserts below use
// BPF_NOEXIST, not the C twin's BPF_ANY. The C-era ANY let a racing
// first-packet initializer wholesale-clobber an entry another CPU
// had already booked onto or enforced through — the exact
// lost-update shape NIGHT-improve-29 closed in the observer twin
// (see the BPF_NOEXIST note at the constant); the limiter twin kept
// the hole until this task. The loser of the init race now re-looks
// up and rides the winner's entry.
//
// One map is deliberately never touched by this program:
// schema_version is written by userspace after load (see
// attach in src/ebpf/limiter/mod.rs) and exists in the BPF object
// so the pin file /sys/fs/bpf/zelynic/schema_version materializes
// and future schema migrations can detect layout drift.
//
// Build: cd ebpf && cargo +nightly build --release

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_socket_cookie, bpf_ktime_get_ns, bpf_skb_cgroup_id},
    macros::{cgroup_skb, map},
    maps::{Array, HashMap, LruHashMap},
    programs::SkBuffContext,
};

// NIGHT-depthbore-1: the enforcement arithmetic lives in
// ../math.rs — pure `core`, zero aya dependencies, wired here with
// #[path] AND into the userspace test tree the same way, so the
// kernel-side math is pinned by rootless unit tests
// (test/ebpf/limiter/math_tests.rs) instead of root-run integration
// alone. The structs and the refill math moved verbatim; the module
// doc there records the one behavioral change (the schema-v6
// frac_rem sanitization).
#[path = "../math.rs"]
mod math;

// NIGHT-private-research-2 (AMMSP): the resolution core lives in
// ../ammsp.rs — same discipline as math.rs: pure `core`, zero aya
// dependencies, wired here with #[path] AND into the userspace test
// tree, pinned rootlessly by test/ebpf/limiter/ammsp_tests.rs. The
// walk state machine, the cache decision table, and the depth
// bound are the pinned surface; the helper calls and map plumbing
// stay here because only this side can touch them.
#[path = "../ammsp.rs"]
mod ammsp;

// The datapath wiring half of AMMSP (NIGHT-private-research-2): the
// pinned LRU memo map + the ancestor-walk driver — the aya-touching
// split that holds this file under the 500-LOC owner cap, the same
// discipline the userspace tree's policy_lines/parse splits set.
#[path = "../ammsp_resolve.rs"]
mod ammsp_resolve;

use ammsp_resolve::ammsp_resolve_root;
use drr_flow::drr_flow;

// NIGHT-upgrade-charger-core-1c (the fair-shared bucket): the pure
// quantum core — same discipline as math.rs/ammsp.rs: pure `core`,
// zero aya dependencies, wired here with #[path] AND into the
// userspace test tree, pinned rootlessly by
// test/ebpf/limiter/drr_tests.rs.
#[path = "../drr.rs"]
mod drr;

// The DRR datapath wiring (NIGHT-upgrade-charger-core-1c): the two
// pinned LRU leaf-bucket maps + the pool/leaf orchestration — the
// aya-touching split, the ammsp_resolve precedent one feature over.
#[path = "../drr_flow.rs"]
mod drr_flow;

// NIGHT-upgrade-charger-core-3a (the in-kernel time-series ring): the
// pure window-protocol core — same discipline as math.rs/ammsp.rs/
// drr.rs: pure `core`, zero aya dependencies, wired here with #[path]
// AND into the userspace test tree, pinned rootlessly by
// test/ebpf/limiter/rate_ring_tests.rs.
#[path = "../rate_ring.rs"]
mod rate_ring;

// NIGHT-upgrade-charger-core-3b (per-socket limiting, Tier B #7):
// the per-socket datapath wiring — the drr_flow precedent one
// feature over (the aya-touching split; the cookie-keyed LRU bucket
// maps + the belt/refill/consume lane try_enforce's per-socket
// branch rides).
#[path = "../socket_flow.rs"]
mod socket_flow;

// NIGHT-private-research-4 (ECN-first policing): the debt core lives
// in ../ecn.rs — same discipline as math.rs/ammsp.rs/drr.rs: pure
// `core`, zero aya dependencies, wired here with #[path] AND into
// the userspace test tree the same way, pinned rootlessly by
// test/ebpf/limiter/ecn_tests.rs. The charge/pay arithmetic and the
// budget law's proof are the pinned surface; the kernel helper call
// and the map plumbing stay here because only this side can touch
// them.
#[path = "../ecn.rs"]
mod ecn;
use math::{
    Bucket, LimiterStats, MAX_ENFORCABLE_BURST, POLICY_FLAG_PER_SOCKET, Policy, book, book_rescue,
    enforce,
};
use rate_ring::{RateRing, RateSlot, ring_book};
use socket_flow::socket_flow;

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
/// (NIGHT-private-research-2, AMMSP): the leaf-anchored policy
/// lookup becomes subtree-aware — a policy written for cgroup A now
/// polices every socket born under A/** with ONE shared budget,
/// resolved per packet through the new pinned ammsp_leaf_cache map
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
/// v12 (NIGHT-perf-0): AMMSP memos become generation-stamped — the
/// ammsp_leaf_cache value widens u32 -> u64, packing
/// `(generation << 32) | root`, and a new one-entry pinned
/// ammsp_generation counter array is bumped by every userspace
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
/// have); the group-bucket lane (strict-multi) keeps the legacy
/// FCFS shape by documented scope. The stale-quantum belt: leaf
/// quanta are stamped with the AMMSP generation at their draw, and
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
/// share word re-packed and both state maps re-keyed on the AMMSP
/// generation (the usual one-time re-apply contract).
/// v18 (NIGHT-hunt-Z1, the cross-direction memo close): the AMMSP
/// leaf cache splits into TWO direction-scoped maps —
/// ammsp_leaf_cache_dl and ammsp_leaf_cache_ul — because a memo's
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
/// walk resolved. The ammsp_generation counter stays SHARED (a
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
/// the strict-multi lane). Every DELIVERED packet on the lane pays
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
#[allow(dead_code)]
const SCHEMA_VERSION: u32 = 19;

// ---------------------------------------------------------------------------
// Maps. The static names ARE the userspace contract (limiter/mod.rs
// and pin.rs open each map by name or by pin path), so they stay
// lowercase exactly like the C object's symbols; the allow attribute
// suppresses the non-upper-case globals lint for that reason. Every
// map is pinned by name: policies must survive process exit, which
// is the whole point of the /sys/fs/bpf/zelynic directory.
// ---------------------------------------------------------------------------

// ─ Download (ingress) maps ─

#[allow(non_upper_case_globals)]
#[map]
static cgroup_policy_dl: HashMap<u32, Policy> = HashMap::pinned(1024, 0);

#[allow(non_upper_case_globals)]
#[map]
static cgroup_bucket_dl: HashMap<u32, Bucket> = HashMap::pinned(1024, 0);

#[allow(non_upper_case_globals)]
#[map]
static group_bucket_dl: HashMap<u32, Bucket> = HashMap::pinned(256, 0);

// ─ Upload (egress) maps ─

#[allow(non_upper_case_globals)]
#[map]
static cgroup_policy_ul: HashMap<u32, Policy> = HashMap::pinned(1024, 0);

#[allow(non_upper_case_globals)]
#[map]
static cgroup_bucket_ul: HashMap<u32, Bucket> = HashMap::pinned(1024, 0);

#[allow(non_upper_case_globals)]
#[map]
static group_bucket_ul: HashMap<u32, Bucket> = HashMap::pinned(256, 0);

// ─ Shared maps ─

/// Watchdog deadline: monotonic time after which BPF becomes a
/// no-op (0 = no deadline set, enforce forever). Written by
/// userspace only.
#[allow(non_upper_case_globals)]
#[map]
static watchdog_deadline: Array<u64> = Array::pinned(1, 0);

/// Schema version: userspace writes it after load so future
/// migrations can detect layout drift. Never read here.
#[allow(non_upper_case_globals)]
#[map]
static schema_version: Array<u32> = Array::pinned(1, 0);

/// Per-cgroup enforcement stats (combined dl + ul), read by the
/// `zelynic status` command surface (text + --print-json).
#[allow(non_upper_case_globals)]
#[map]
static cgroup_limiter_stats: HashMap<u32, LimiterStats> = HashMap::pinned(1024, 0);

// ─ The time-series rings (NIGHT-upgrade-charger-core-3a, Tier B #8
// — EAGLE EYES V1) ─ one ring per policed cgroup per direction,
// keyed at the RESOLVED POLICY ROOT (the same key the stats ledger
// uses, so the status join needs no new identity plumbing). The
// datapath books every ALLOWED packet's bytes into the current
// one-second window (ring_book in rate_ring.rs); drops never enter
// the ring — it is the delivered-rate shape a baseline detector
// reads, not a second ledger (cgroup_limiter_stats keeps the exact
// truth). HashMap, not LRU, because occupancy is bounded by the
// policy census (the stats map's own posture).

#[allow(non_upper_case_globals)]
#[map]
static rate_ring_dl: HashMap<u32, RateRing> = HashMap::pinned(1024, 0);

#[allow(non_upper_case_globals)]
#[map]
static rate_ring_ul: HashMap<u32, RateRing> = HashMap::pinned(1024, 0);

// ─ The ECN debt words (NIGHT-private-research-4, schema v19 —
// ECN-first policing) ─ one debt word per policed BUDGET per
// direction, keyed by the generation-prefixed budget key (the
// pool's root on the DRR lane, the group id on the strict-multi
// lane — the repair-6 discipline: a fresh budget never inherits the
// predecessor's debt, stale entries age out through the LRU). The
// word carries the outstanding marked bytes the budget has not yet
// bought back; ecn.rs's charge/pay pair keeps the budget law
// (delivered <= refill + burst + one 64 KiB super-packet — the
// ecn.rs proof). LRU + pinned (the leaf_bucket posture);
// datapath-internal (userspace never opens it — the leaf_bucket
// family's contract).

#[allow(non_upper_case_globals)]
#[map]
static ecn_debt_dl: LruHashMap<u64, u64> = LruHashMap::pinned(4096, 0);

#[allow(non_upper_case_globals)]
#[map]
static ecn_debt_ul: LruHashMap<u64, u64> = LruHashMap::pinned(4096, 0);

// ---------------------------------------------------------------------------
// Enforcement program flow. The refill math (fill-detect, fractional
// carry, cap, drop) lives in math.rs (NIGHT-depthbore-1); everything
// here is map plumbing: stats/bucket lookup, the trust-boundary
// clamp, and the schema-v3 rate-0 block verdict.
// ---------------------------------------------------------------------------

/// Get or create the stats entry for a cgroup. Ported from the C
/// `get_stats` helper, with the v11 init-flag delta: an
/// init-then-relookup pair whose insert rides BPF_NOEXIST so a
/// concurrent initializer's entry is never clobbered by a BPF_ANY
/// overwrite — the loser of the insert race re-looks up and books
/// its packet onto the winner's entry (the NIGHT-improve-29 observer
/// pattern, applied to the limiter twin by think-like-light-years-3).
/// A failed insert beyond the race (full map) leaves the relookup
/// returning None and enforcement continues unbooked — the same
/// fail-open bookkeeping contract the C twin carried.
#[inline(always)]
fn get_stats_ptr(cgroup_id: &u32) -> Option<*mut LimiterStats> {
    match cgroup_limiter_stats.get_ptr_mut(cgroup_id) {
        Some(ptr) => Some(ptr),
        None => {
            let init = LimiterStats {
                packets_allowed: 0,
                packets_dropped: 0,
                bytes_allowed: 0,
                bytes_dropped: 0,
            };
            let _ = cgroup_limiter_stats.insert(cgroup_id, &init, BPF_NOEXIST);
            cgroup_limiter_stats.get_ptr_mut(cgroup_id)
        }
    }
}

/// Get or create a bucket in `map` (individual or group), keyed by
/// cgroup_id or group_id. Ported from the C `get_bucket` helper,
/// with the v11 init-flag delta: the insert rides BPF_NOEXIST so a
/// racing first-packet initializer can never wholesale-reset an
/// entry another CPU is already enforcing through — the pre-v11
/// BPF_ANY let the loser's insert rewind THREE things the winner had
/// already advanced: consumed tokens resurrected to the full burst
/// (an over-allow of up to one burst), last_refill_ns rolled back
/// behind a window the ownership CAS had already credited (a
/// double-credit bounded only by the 1s elapsed cap), and frac_rem
/// zeroed. The loser of the init race now re-looks up and enforces
/// against the winner's entry — one bucket, one birth, no
/// resurrection. A failed insert beyond the race (the map full,
/// or a corrupted pin) makes the relookup return None and the
/// caller allows the packet (never drops on bookkeeping failure) —
/// the same fail-open contract the C twin carried.
#[inline(always)]
fn get_bucket_ptr(
    map: &HashMap<u32, Bucket>,
    key: &u32,
    burst: u64,
    now: u64,
) -> Option<*mut Bucket> {
    match map.get_ptr_mut(key) {
        Some(ptr) => Some(ptr),
        None => {
            let init = Bucket {
                tokens: burst,
                last_refill_ns: now,
                frac_rem: 0,
            };
            let _ = map.insert(key, &init, BPF_NOEXIST);
            map.get_ptr_mut(key)
        }
    }
}

/// Get or create the ring entry for a policed cgroup (the
/// get_stats_ptr discipline): zero-initialized (every stamp 0 —
/// window 0 only exists in the first second of uptime, so a zeroed
/// slot is "never written" on every real host), inserted with
/// BPF_NOEXIST so a racing first-packet initializer can never
/// clobber a ring another CPU is already booking into — the v11
/// init-race contract, one map family over. A failed insert beyond
/// the race (full map — impossible while policies stay under the
/// 1024 census, but the belt stays) returns None and the caller
/// skips the ring booking: the RING is a monitor, and a monitor's
/// bookkeeping failure must never touch a verdict (the ledger's own
/// fail-open contract, stated for its exact twin in get_stats_ptr).
#[inline(always)]
fn get_ring_ptr(map: &HashMap<u32, RateRing>, key: &u32) -> Option<*mut RateRing> {
    match map.get_ptr_mut(key) {
        Some(ptr) => Some(ptr),
        None => {
            let init = RateRing {
                slots: [RateSlot {
                    window: 0,
                    bytes: 0,
                }; rate_ring::RING_SLOTS as usize],
            };
            let _ = map.insert(key, &init, BPF_NOEXIST);
            map.get_ptr_mut(key)
        }
    }
}

/// Book an allowed packet into the direction's ring, then hand the
/// verdict through untouched — the wrap every enforcement lane
/// returns through (group, DRR; the rate-0 block lane books
/// nothing: it delivers nothing). Extracted so each lane's return
/// stays a one-line wrap and the ring can never reorder, mask, or
/// invent a verdict: `ring_book` runs only on the allow path, after
/// the kernel already decided.
#[inline(always)]
fn ring_verdict(
    verdict: i32,
    ring_map: &HashMap<u32, RateRing>,
    key: &u32,
    now: u64,
    pkt_len: u32,
) -> i32 {
    if verdict == 1 {
        if let Some(ptr) = get_ring_ptr(ring_map, key) {
            ring_book(unsafe { &mut *ptr }, now, pkt_len);
        }
    }
    verdict
}

// ---------------------------------------------------------------------------
// Program bodies. Both directions share the flow (the C twin
// duplicates it per program; the port factors the shared tail into
// one #[inline(always)] helper — the verifier sees the same
// instructions either way).
// ---------------------------------------------------------------------------

/// `bpf_map_update_elem` flag: fail the insert if the key already
/// exists (kernel uapi: BPF_ANY = 0, BPF_NOEXIST = 1, BPF_EXIST = 2).
/// Schema v11 (NIGHT-think-like-light-years-3): every init-path
/// insert rides NOEXIST — the loser of a first-packet init race
/// re-looks up and books onto the winner's entry, never clobbers
/// it. The observer twin has carried the same flag since
/// NIGHT-improve-29; the limiter twin's BPF_ANY was the C-era
/// residue that fix never swept (the one place the SMP story still
/// had a plain wholesale write: a reset no amount of per-field
/// atomics downstream could defend against).
const BPF_NOEXIST: u64 = 1;

// ---------------------------------------------------------------------------
// The ECN-first lane (NIGHT-private-research-4, schema v19). The
// drop verdict of a budgeted lane is a LAST RESORT: when the kernel
// can set the CE codepoint on the packet, the packet is delivered
// CE-marked and its bytes charge a debt the budget stream pays
// back (ecn.rs holds the arithmetic and the budget law's proof;
// the test tree pins both rootlessly).
// ---------------------------------------------------------------------------

/// The kernel helper binding, declared in the exact shape the
/// aya-ebpf-bindings crates generate (the helper ID transmuted into
/// the call immediate — no extern symbol, no relocation): ID 97,
/// pinned against include/uapi/linux/bpf.h's FN(skb_ecn_set_ce, 97)
/// and aya-obj 0.3's own BPF_FUNC_skb_ecn_set_ce = 97. Exposed to
/// cgroup_skb programs by cg_skb_func_proto under CONFIG_INET
/// (present in the 5.13 verified floor and every kernel above it,
/// gpl_only = false — net/core/filter.c). aya-ebpf 0.2.1 does not
/// wrap this helper in its safe helpers module, so the object
/// declares the binding itself.
///
/// SAFETY: the skb pointer must be the program's own context
/// pointer (ARG_PTR_TO_CTX — the verifier checks); the transmute
/// materializes the BPF call immediate the verifier resolves.
#[inline(always)]
unsafe fn bpf_skb_ecn_set_ce(skb: *mut core::ffi::c_void) -> i64 {
    // SAFETY: the transmute materializes the helper-ID call immediate
    // (the bindings-crate convention); the call hands the program's
    // own context pointer to the kernel — the contract the SAFETY
    // note above this function pins.
    let fun: unsafe extern "C" fn(*mut core::ffi::c_void) -> i64 =
        unsafe { core::mem::transmute(97usize) };
    unsafe { fun(skb) }
}

/// The generation-prefixed debt key for one budget (the repair-6
/// discipline, the share/ledger keying one lane over): a fresh
/// budget never inherits the predecessor's debt, and stale
/// entries age out through the LRU the leaf buckets already trust.
#[inline(always)]
fn debt_key_for(budget_key: u32) -> u64 {
    (u64::from(ammsp_resolve::current_generation()) << 32) | u64::from(budget_key)
}

/// Get or create the debt word for a budget key (the get_stats_ptr
/// discipline): zero-initialized, inserted with BPF_NOEXIST so a
/// racing first-packet initializer never clobbers a debt another
/// CPU is already paying down — the v11 init-race contract, one
/// map family over. A failed insert beyond the race (the LRU full
/// under 4096+ concurrent budgets) returns None and the caller
/// treats the miss as the leaf/socket lanes treat theirs: the
/// packet drops — the debt is BUDGET, not bookkeeping, so the miss
/// takes the safe verdict, never an unlimited pass.
#[inline(always)]
fn get_debt_ptr(debt_map: &LruHashMap<u64, u64>, key: &u64) -> Option<*mut u64> {
    match debt_map.get_ptr_mut(key) {
        Some(ptr) => Some(ptr),
        None => {
            let init: u64 = 0;
            let _ = debt_map.insert(key, &init, BPF_NOEXIST);
            debt_map.get_ptr_mut(key)
        }
    }
}

/// The ECN-first rescue (private-research-4): called on the DROP
/// verdict of a budgeted lane (the rate-0 block verdict returned
/// long before this point, so every caller carries rate > 0 — the
/// block verdict never delivers, so it never rescues). The order
/// is the whole design: the kernel helper runs FIRST (it is
/// side-effect-free when it refuses — non-ECT, cloned-not-writable,
/// header-not-linear, non-IP — and returns 1 exactly when the
/// packet now carries CE), then the debt charge, then the ledger
/// correction. A charge that finds the debt at its cap returns
/// false and the CE-marked packet drops — harmless: a dropped mark
/// signals nothing the receiver will read, and the safe-verdict
/// discipline (never over-allow) holds. A debt-map miss (the
/// full-LRU class above) drops the same way. On success the
/// caller's ring wrap books the delivered bytes exactly as any
/// allowed packet's.
#[inline(always)]
fn ecn_rescue(
    skb: *mut core::ffi::c_void,
    debt_map: &LruHashMap<u64, u64>,
    debt_key: &u64,
    pkt_len: u32,
    stats_ptr: Option<*mut LimiterStats>,
) -> bool {
    if unsafe { bpf_skb_ecn_set_ce(skb) } == 0 {
        return false;
    }
    let debt_ptr = match get_debt_ptr(debt_map, debt_key) {
        Some(ptr) => ptr,
        None => return false,
    };
    if !ecn::debt_charge(debt_ptr, pkt_len) {
        return false;
    }
    if let Some(sp) = stats_ptr {
        book_rescue(unsafe { &mut *sp }, pkt_len);
    }
    true
}

/// Shared enforcement flow for one direction. `policy_map` selects
/// download vs upload; `bucket_map` / `group_bucket_map` are the
/// matching individual/group bucket (pool) maps, `leaf_bucket_map`
/// the direction's DRR leaf map (charger-core-1c), `share_map` the
/// direction's learned-share state map (dinner-28), `ledger_map`
/// the direction's epoch-ledger state map (repair-3), `rate_ring_map`
/// the direction's time-series ring (charger-core-3a), `debt_map`
/// the direction's ECN debt map (private-research-4).
#[inline(always)]
fn try_enforce(
    ctx: SkBuffContext,
    policy_map: &HashMap<u32, Policy>,
    memo_map: &LruHashMap<u32, u64>,
    bucket_map: &HashMap<u32, Bucket>,
    group_bucket_map: &HashMap<u32, Bucket>,
    leaf_bucket_map: &LruHashMap<u32, Bucket>,
    share_map: &LruHashMap<u64, u64>,
    ledger_map: &LruHashMap<u64, u64>,
    rate_ring_map: &HashMap<u32, RateRing>,
    socket_bucket_map: &LruHashMap<u64, socket_flow::SocketBucket>,
    debt_map: &LruHashMap<u64, u64>,
) -> i32 {
    // The unlimited fast path FIRST (NIGHT-lts-2): cgroup identity +
    // the direction's policy are the only two lookups a packet with
    // no policy ever needs — and on any real host that is the
    // overwhelming majority of packets, because both hooks are
    // attached at the cgroup root and see EVERY packet the machine
    // moves, while the policy maps hold only the handful of cgroups
    // zelynic was asked to police. The C twin's order (ported
    // verbatim through the Rust port) read the watchdog array and
    // took a bpf_ktime_get_ns timestamp before ever consulting the
    // policy — two operations per packet whose results could not
    // change the verdict: no policy means allow under every possible
    // watchdog state (deadline unset, active, or expired), so the
    // unlimited packet paid for a dormancy check it could never
    // fail. The reorder keeps every policed-packet semantics
    // bit-identical: when a policy exists, the watchdog read and the
    // timestamp run exactly as before, just after the policy lookup.
    //
    // AMMSP (NIGHT-private-research-2) adds exactly ONE lookup to
    // this fast path's miss branch: the LRU leaf cache, answered
    // with a resolved 0 for every socket no root covers — the
    // unlimited majority stays one-lookup-plus-memo, never a walk.
    // A socket whose OWN cgroup carries the policy (every
    // pre-AMMSP scenario) still takes the single direct lookup
    // below — its cgroup IS the root, no resolution runs.
    let leaf = unsafe { bpf_skb_cgroup_id(ctx.skb.skb) } as u32;
    let pkt_len = ctx.len();

    // Look up the direction's policy at the socket's own cgroup
    // first — the nearest possible root. No policy means the leaf
    // itself is unpoliced, but AMMSP must still ask whether an
    // ANCESTOR of it is: a strict on cgroup A covers every socket
    // born under A/** (the subtree contract), resolved per packet.
    let (cgroup_id, pol) = match policy_map.get_ptr(&leaf) {
        Some(ptr) => (leaf, unsafe { &*ptr }),
        None => {
            let root = ammsp_resolve_root(&ctx, leaf, policy_map, memo_map);
            if root == 0 {
                return 1;
            }
            match policy_map.get_ptr(&root) {
                Some(ptr) => (root, unsafe { &*ptr }),
                // TOCTOU belt: the policy vanished between the walk
                // and this lookup (flush + remove raced the packet).
                // Allow, the same fail-open every bookkeeping miss
                // here takes — never drop on a map race.
                None => return 1,
            }
        }
    };

    // Watchdog check (only policed packets reach here). deadline == 0
    // means "no deadline set" — always enforce. deadline != 0 means
    // "fail-safe timeout" — allow all if expired. (Preserved for the
    // future --timeout feature; the serve child refresh was removed;
    // no userspace writer arms it today, so the check is dormant —
    // which is exactly why the unlimited path must not pay for it.)
    // Array entries are pre-created by the kernel, so a None here is
    // unreachable in practice; the C twin checks for NULL regardless
    // and so does the port.
    let deadline = match watchdog_deadline.get_ptr(0) {
        Some(ptr) => unsafe { *ptr },
        None => return 1,
    };
    let now = unsafe { bpf_ktime_get_ns() };
    if deadline != 0 && now > deadline {
        return 1;
    }

    // rate_bps == 0 means BLOCKED (drop all packets). Used by the
    // block-single command. Schema v3: changed from allow to drop.
    // Schema v5 (NIGHT-improve-14): the drop is BOOKED here, the
    // same packets_dropped/bytes_dropped accounting the enforce()
    // drop branch keeps. The pre-v5 verdict returned before the
    // stats lookup ever ran, so cgroup_limiter_stats stayed empty
    // under block-* — enforcement was total (zero goodput) yet
    // invisible: `zelynic status` and the supermassive "kernel drops
    // engaged" proof both read "0 packets dropped" (the only light
    // failure on the 2026-09-21 nightpc run). An unbooked drop is
    // invisible enforcement.
    //
    // Schema v9 (NIGHT-master-3): the booking rides the SAME atomic
    // fetch_add (math::book) the enforce() path uses — the v5 `+=`
    // was the last plain read-modify-write on a stats entry, and a
    // blocked cgroup with traffic on several CPUs lost drop
    // increments exactly the way the pre-v7 ledger lost allowed
    // bytes. Verdict untouched: the drop itself was always total.
    if pol.rate_bps == 0 {
        let stats = get_stats_ptr(&cgroup_id).map(|ptr| unsafe { &mut *ptr });
        if let Some(s) = stats {
            book(s, false, pkt_len);
        }
        return 0;
    }

    // security-3 trust boundary: clamp the stored burst before ANY
    // consumer sees it — the fill-detect threshold below and the
    // bucket initializer both derive their overflow-safety proofs
    // from this bound. Every legit userspace write carries
    // burst <= 100 MB (default_burst), so the clamp is invisible
    // for healthy state and total for hostile or drifted state.
    let pol_sane = if pol.burst_bytes > MAX_ENFORCABLE_BURST {
        Policy {
            rate_bps: pol.rate_bps,
            burst_bytes: MAX_ENFORCABLE_BURST,
            group_id: pol.group_id,
            flags: pol.flags,
        }
    } else {
        *pol
    };

    // The stats entry, held as the RAW pointer the ECN rescue
    // reuses after a lane consumed the borrow (private-research-4):
    // each budgeted lane moves the Option<&mut> into itself and
    // returns, so the rescue tail books through the raw pointer —
    // the same entry the lane booked the drop into, one lookup,
    // no second map read.
    let stats_ptr = get_stats_ptr(&cgroup_id);
    let stats = stats_ptr.map(|ptr| unsafe { &mut *ptr });

    // The per-socket lane (NIGHT-upgrade-charger-core-3b, Tier B
    // #7): POLICY_FLAG_PER_SOCKET spends through a bucket keyed by
    // the packet's own SOCKET — every connection its own budget at
    // the policy rate (the server shape: the cgroup total is
    // bounded by rate x concurrent sockets, not by rate). The
    // attribution is the observer's own cookie join (no tracepoint):
    // the kernel names the owning socket per packet in both hooks.
    // cookie == 0 (no attribution the hook carries) falls through
    // to the DRR cgroup lane below — the packet stays policed at
    // the cgroup's shared budget, honestly coarser, never an
    // unlimited pass. The stats ledger and the ring both stay keyed
    // at the RESOLVED POLICY ROOT — the roll-up the AMMSP contract
    // already owns.
    if pol_sane.flags & POLICY_FLAG_PER_SOCKET != 0 {
        let cookie = unsafe { bpf_get_socket_cookie(ctx.skb.skb.cast()) };
        if cookie != 0 {
            let verdict = socket_flow(&pol_sane, cookie, socket_bucket_map, now, pkt_len, stats);
            return ring_verdict(verdict, rate_ring_map, &cgroup_id, now, pkt_len);
        }
    }

    // Individual or group bucket? group_id selects the shared
    // bucket keyed by the group; 0 rides the DRR lane (charger-core-1c).
    // Both paths see the sanitized burst so the initializer never
    // seeds tokens above the bound.
    // NIGHT-lts-7 (folded into the unreleased v8): a group lookup
    // that cannot materialize a bucket (the 256-slot group map
    // full, or a corrupted pin) DEGRADES the member to its own
    // individual bucket at the group's rate — over-admission
    // against the shared-bucket intent, but never the unlimited
    // fail-open the plain None return used to be. The userspace
    // half of the fix (reclaiming dead groups on removal/apply,
    // reclaim.rs) keeps the map from filling in the first place;
    // this fallback is the belt for whatever still slips through.
    if pol_sane.group_id != 0 {
        // The strict-multi group lane keeps the legacy FCFS shape
        // (documented scope): its members are enumerated by the
        // apply itself, so the fairness problem AMMSP has (unbounded
        // unknown leaves) does not exist here.
        //
        // The ECN budget key rides the bucket the packet actually
        // spends from (the lts-7 degrade included): the group word on
        // the shared lane, the member's own root on the fallback —
        // the debt must be paid out of the SAME stream the marked
        // bytes were delivered against (private-research-4).
        let mut ecn_budget_key = pol_sane.group_id;
        let bkt_ptr = match get_bucket_ptr(
            group_bucket_map,
            &pol_sane.group_id,
            pol_sane.burst_bytes,
            now,
        ) {
            Some(ptr) => Some(ptr),
            None => {
                ecn_budget_key = cgroup_id;
                get_bucket_ptr(bucket_map, &cgroup_id, pol_sane.burst_bytes, now)
            }
        };
        let bkt_raw = match bkt_ptr {
            Some(ptr) => ptr,
            None => return 1,
        };
        let debt_key = debt_key_for(ecn_budget_key);
        let bkt = unsafe { &mut *bkt_raw };
        let verdict = enforce(&pol_sane, bkt, pkt_len, now, stats);
        // The ECN debt pay (private-research-4), on the ALLOW path
        // only, from the stream's leftover AFTER the lane delivered:
        // the call-site law (ecn.rs debt_pay docs) — a pay that ran
        // on every packet would drain the token stock toward the
        // debt and starve the lane below the policy. The raw place
        // never overlaps the &mut borrow the lane consumed above.
        if verdict == 1 {
            if let Some(dp) = get_debt_ptr(debt_map, &debt_key) {
                unsafe { ecn::debt_pay(core::ptr::addr_of_mut!((*bkt_raw).tokens), dp) };
            }
        }
        // The ECN-first rescue: a drop verdict asks the kernel for a
        // CE mark first; only a refusal (or a debt at its cap, or a
        // debt-map miss) lets the drop stand (private-research-4).
        if verdict == 0 && ecn_rescue(ctx.skb.skb.cast(), debt_map, &debt_key, pkt_len, stats_ptr) {
            return ring_verdict(1, rate_ring_map, &cgroup_id, now, pkt_len);
        }
        return ring_verdict(verdict, rate_ring_map, &cgroup_id, now, pkt_len);
    }

    // The DRR lane (NIGHT-upgrade-charger-core-1c): the shared
    // bucket is a POOL and the packet spends from its LEAF's bucket
    // — a greedy leaf holds at most one quantum at a time, and the
    // pool's refills flow to whichever leaf is empty and asking
    // (the starvation close; the aggregate stays exactly the policy).
    // The pool is the same map entry the legacy path enforced
    // through, and the leaf is keyed by the socket's own cgroup id
    // (the direct-hit path's leaf IS the root — one shape, no mixed
    // regime between a target's own sockets and its subtree's).
    let pool_ptr = match get_bucket_ptr(bucket_map, &cgroup_id, pol_sane.burst_bytes, now) {
        Some(ptr) => ptr,
        None => return 1,
    };
    let debt_key = debt_key_for(cgroup_id);
    let pool = unsafe { &mut *pool_ptr };
    let verdict = drr_flow(
        &pol_sane,
        pool,
        leaf_bucket_map,
        share_map,
        ledger_map,
        &cgroup_id,
        &leaf,
        pkt_len,
        now,
        stats,
    );
    // The ECN debt pay (private-research-4), the DRR pool's own
    // stream, on the ALLOW path only — from the leftover between
    // the leaf draws, AFTER the lane delivered: the call-site law
    // (ecn.rs debt_pay docs — the starvation close). The raw place
    // never overlaps the &mut borrow the lane consumed above.
    if verdict == 1 {
        if let Some(dp) = get_debt_ptr(debt_map, &debt_key) {
            unsafe { ecn::debt_pay(core::ptr::addr_of_mut!((*pool_ptr).tokens), dp) };
        }
    }
    // The ECN-first rescue: a drop verdict asks the kernel for a CE
    // mark first; only a refusal (or a debt at its cap, or a debt-map
    // miss) lets the drop stand (private-research-4). The leaf-level
    // fairness shape is untouched — a marked packet never carries
    // leaf tokens, so the greedy-leaf bound rides exactly as before.
    if verdict == 0 && ecn_rescue(ctx.skb.skb.cast(), debt_map, &debt_key, pkt_len, stats_ptr) {
        return ring_verdict(1, rate_ring_map, &cgroup_id, now, pkt_len);
    }
    ring_verdict(verdict, rate_ring_map, &cgroup_id, now, pkt_len)
}

/// Download enforcement (ingress). Ported from enforce_dl.
#[cgroup_skb(ingress)]
fn enforce_dl(ctx: SkBuffContext) -> i32 {
    try_enforce(
        ctx,
        &cgroup_policy_dl,
        &ammsp_resolve::ammsp_leaf_cache_dl,
        &cgroup_bucket_dl,
        &group_bucket_dl,
        &drr_flow::leaf_bucket_dl,
        &drr_flow::drr_pool_state_dl,
        &drr_flow::drr_leaf_state_dl,
        &rate_ring_dl,
        &socket_flow::socket_bucket_dl,
        &ecn_debt_dl,
    )
}

/// Upload enforcement (egress). Ported from enforce_ul.
#[cgroup_skb(egress)]
fn enforce_ul(ctx: SkBuffContext) -> i32 {
    try_enforce(
        ctx,
        &cgroup_policy_ul,
        &ammsp_resolve::ammsp_leaf_cache_ul,
        &cgroup_bucket_ul,
        &group_bucket_ul,
        &drr_flow::leaf_bucket_ul,
        &drr_flow::drr_pool_state_ul,
        &drr_flow::drr_leaf_state_ul,
        &rate_ring_ul,
        &socket_flow::socket_bucket_ul,
        &ecn_debt_ul,
    )
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// The license section stays GPL for C-twin parity: the object's
// declared license has been GPL since the bpf/limiter.bpf.c era and
// the dual-license contract keeps it so. (Verified against
// torvalds/linux master and v5.13, net/core/filter.c: bpf_skb_cgroup_id
// and bpf_skb_ancestor_cgroup_id are both gpl_only = false — the old
// "GPL-only helper" claim was stale; a mismatch would still fail the
// verifier at load time on helpers that ARE gpl_only, so the section
// is cheap insurance either way.)
#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
static LICENSE: [u8; 4] = *b"GPL\0";
