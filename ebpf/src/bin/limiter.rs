// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// zelynic eBPF limiter, the pure-Rust BPF source (NIGHT-improve-1,
// phase 2, stage 1: port of the former bpf/limiter.bpf.c; phase 3
// deleted the C side — the port is now the production source).
//
// The cosmic dragon architecture, Layer 0: Enforcement. Pure eBPF. No tc, no
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

// schema v20 (CAKE-shaped flow isolation): the per-flow lane's
// aya-touching half — the flow bucket/share/ledger map families and
// the flow draw, drr_flow's own precedent one level down. Same
// #[path] discipline: the pure laws live in drr.rs and are pinned
// rootlessly by the cake test family.
#[path = "../cake_flow.rs"]
mod cake_flow;

// NIGHT-private-research-4 candidate, schema v22 (QUIC-aware
// attribution): the pure header core — same discipline as
// math.rs/ammsp.rs/drr.rs/ecn.rs: pure `core`, zero aya
// dependencies, wired here with #[path] AND into the userspace
// test tree the same way, pinned rootlessly by
// test/ebpf/limiter/quic_tests.rs. The QUIC v1/v2 header laws,
// the confirmation-gated hint state machine, and the key mixers
// are the pinned surface.
#[path = "../quic.rs"]
mod quic;

// The QUIC-aware datapath wiring (schema v22): the two learned-hint
// maps and the cookie-to-connection-key call — the aya-touching
// split, the cake_flow precedent one feature over.
#[path = "../quic_flow.rs"]
mod quic_flow;

// night-during, schema v23 (the unified --during time windows): the
// pure verdict core — same discipline as math.rs/ammsp.rs/drr.rs/
// ecn.rs/quic.rs: pure `core`, zero aya dependencies, wired here
// with #[path] AND into the userspace test tree the same way,
// pinned rootlessly by test/ebpf/limiter/during_tests.rs. The
// daily comparator with its midnight wrap and both-edges margin,
// the drift-free span verdict, and the sweep predicates are the
// pinned surface; the map plumbing stays here because only this
// side can touch it.
#[path = "../during.rs"]
mod during;

use math::{Bucket, LimiterStats, Policy};
use rate_ring::RateRing;

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

// ─ The time-window side map (night-during, schema v23 — the
// unified --during) ─ one row per policed cgroup, keyed at the
// RESOLVED POLICY ROOT exactly like the stats ledger (the same
// join the AMMSP resolution already produces; a row's two legs
// share one window, one shared map both hooks read). The gate
// reads it AFTER the policy hit on the policed path only: an
// absent entry is today's behavior exactly, and a row whose
// window is INACTIVE answers ALLOW — the miss shape, no stats,
// no ring, no belt — until the userspace sweep removes an ENDED
// span. HashMap, not LRU, because occupancy is bounded by the
// policy census (the stats map's own posture — every window row
// rides a policy row's root).

#[allow(non_upper_case_globals)]
#[map]
static policy_window: HashMap<u32, during::PolicyWindow> = HashMap::pinned(1024, 0);

/// The wall-clock bridge (night-during, schema v23): the offset
/// `wall_minus_mono_ns` userspace stamps at every attach and every
/// apply-family mutation, so a DAILY window's per-packet comparison
/// can read the wall as `bpf_ktime_get_ns() + wall_clock_offset` —
/// the bridge the no-daemon claim stands on (the CLI visit IS the
/// refresh channel; the drift between visits is bounded by NTP
/// slew, and the margin law in during.rs pays it toward less
/// enforcement). Userspace-written only, never touched by this
/// program — the watchdog_deadline/schema_version contract.
#[allow(non_upper_case_globals)]
#[map]
static wall_clock_offset: Array<u64> = Array::pinned(1, 0);

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
// pool's root on the DRR lane, the group id on the group
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

/// Download enforcement (ingress). Ported from enforce_dl.
#[cgroup_skb(ingress)]
fn enforce_dl(ctx: SkBuffContext) -> i32 {
    try_enforce(
        ctx,
        true,
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
        &cake_flow::flow_bucket_dl,
        &cake_flow::flow_share_dl,
        &cake_flow::flow_ledger_dl,
    )
}

/// Upload enforcement (egress). Ported from enforce_ul.
#[cgroup_skb(egress)]
fn enforce_ul(ctx: SkBuffContext) -> i32 {
    try_enforce(
        ctx,
        false,
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
        &cake_flow::flow_bucket_ul,
        &cake_flow::flow_share_ul,
        &cake_flow::flow_ledger_ul,
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
// NIGHT-improve-44: the 600-line cap split — the schema ledger
// (the version const and its history), the enforcement helpers, and
// the try_enforce verdict path each live in their own module now,
// #[path]-wired exactly like the family above (the same resolution
// the test tree's twin inclusions rely on).
#[path = "../enforce.rs"]
mod enforce;
#[path = "../enforce_helpers.rs"]
mod enforce_helpers;
#[path = "../schema.rs"]
mod schema;

use enforce::try_enforce;
// socket_flow's ECN rescue call rides super:: — the fn now lives in
// enforce_helpers; this re-export keeps the sibling path resolving.
pub(crate) use enforce_helpers::bpf_skb_ecn_set_ce;
