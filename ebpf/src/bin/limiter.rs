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
// so all nine maps declare PIN_BY_NAME exactly like the C twin's
// LIBBPF_PIN_BY_NAME annotations (aya-ebpf exposes this as
// HashMap::pinned / Array::pinned, which the map macro emits as the
// pinning field of the legacy bpf_map_def; aya-obj parses that field
// and aya 0.13.1 pins ByName maps on load — verified against the
// pinned userspace source, not assumed).
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
    helpers::{bpf_ktime_get_ns, bpf_skb_cgroup_id},
    macros::{cgroup_skb, map},
    maps::{Array, HashMap},
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

use math::{Bucket, LimiterStats, MAX_ENFORCABLE_BURST, Policy, enforce};

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
/// the burst/tokens/frac clamp triple; no layout change). No layout
/// change since v2; each bump forces pinned older programs to
/// reload into the hardened object — a one-time limit re-apply,
/// documented in CHANGELOG.
/// The BPF program never writes it — userspace stamps
/// the pinned map after load — so the constant exists purely as the
/// parity anchor for that three-way contract.
#[allow(dead_code)]
const SCHEMA_VERSION: u32 = 6;

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
/// `zelynic rates` command surface.
#[allow(non_upper_case_globals)]
#[map]
static cgroup_limiter_stats: HashMap<u32, LimiterStats> = HashMap::pinned(1024, 0);

// ---------------------------------------------------------------------------
// Enforcement program flow. The refill math (fill-detect, fractional
// carry, cap, drop) lives in math.rs (NIGHT-depthbore-1); everything
// here is map plumbing: stats/bucket lookup, the trust-boundary
// clamp, and the schema-v3 rate-0 block verdict.
// ---------------------------------------------------------------------------

/// Get or create the stats entry for a cgroup. Ported from the C
/// `get_stats` helper: an init-then-relookup pair whose insert
/// result is ignored exactly like the C twin (a failed insert
/// simply yields None and enforcement continues unbooked).
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
            let _ = cgroup_limiter_stats.insert(cgroup_id, &init, 0);
            cgroup_limiter_stats.get_ptr_mut(cgroup_id)
        }
    }
}

/// Get or create a bucket in `map` (individual or group), keyed by
/// cgroup_id or group_id. Ported from the C `get_bucket` helper:
/// the insert result is ignored exactly like the C twin — a failed
/// update makes the relookup return None and the caller allows the
/// packet (never drops on bookkeeping failure).
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
            let _ = map.insert(key, &init, 0);
            map.get_ptr_mut(key)
        }
    }
}

// ---------------------------------------------------------------------------
// Program bodies. Both directions share the flow (the C twin
// duplicates it per program; the port factors the shared tail into
// one #[inline(always)] helper — the verifier sees the same
// instructions either way).
// ---------------------------------------------------------------------------

/// Shared enforcement flow for one direction. `policy_map` selects
/// download vs upload; `bucket_map` / `group_bucket_map` are the
/// matching individual/group bucket maps.
#[inline(always)]
fn try_enforce(
    ctx: SkBuffContext,
    policy_map: &HashMap<u32, Policy>,
    bucket_map: &HashMap<u32, Bucket>,
    group_bucket_map: &HashMap<u32, Bucket>,
) -> i32 {
    // Watchdog check. deadline == 0 means "no deadline set" —
    // always enforce. deadline != 0 means "fail-safe timeout" —
    // allow all if expired. (Preserved for the future --timeout
    // feature; the serve child refresh was removed.) Array entries
    // are pre-created by the kernel, so a None here is unreachable
    // in practice; the C twin checks for NULL regardless and so
    // does the port.
    let deadline = match watchdog_deadline.get_ptr(0) {
        Some(ptr) => unsafe { *ptr },
        None => return 1,
    };
    let now = unsafe { bpf_ktime_get_ns() };
    if deadline != 0 && now > deadline {
        return 1;
    }

    let cgroup_id = unsafe { bpf_skb_cgroup_id(ctx.skb.skb) } as u32;
    let pkt_len = ctx.len();

    // Look up the direction's policy. No policy means unlimited.
    let pol = match policy_map.get_ptr(&cgroup_id) {
        Some(ptr) => unsafe { &*ptr },
        None => return 1,
    };

    // rate_bps == 0 means BLOCKED (drop all packets). Used by the
    // block-single command. Schema v3: changed from allow to drop.
    // Schema v5 (NIGHT-improve-14): the drop is BOOKED here, the
    // same packets_dropped/bytes_dropped accounting the enforce()
    // drop branch keeps. The pre-v5 verdict returned before the
    // stats lookup ever ran, so cgroup_limiter_stats stayed empty
    // under block-* — enforcement was total (zero goodput) yet
    // invisible: `zelynic rates` and the supermassive "kernel drops
    // engaged" proof both read "0 packets dropped" (the only light
    // failure on the 2026-09-21 nightpc run). An unbooked drop is
    // invisible enforcement.
    if pol.rate_bps == 0 {
        let stats = get_stats_ptr(&cgroup_id).map(|ptr| unsafe { &mut *ptr });
        if let Some(s) = stats {
            s.packets_dropped += 1;
            s.bytes_dropped += u64::from(pkt_len);
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
        }
    } else {
        *pol
    };

    let stats = get_stats_ptr(&cgroup_id).map(|ptr| unsafe { &mut *ptr });

    // Individual or group bucket? group_id selects the shared
    // bucket keyed by the group; 0 falls back to the per-cgroup
    // bucket keyed by cgroup_id. Both paths see the sanitized
    // burst so the initializer never seeds tokens above the bound.
    let bkt_ptr = if pol_sane.group_id != 0 {
        get_bucket_ptr(
            group_bucket_map,
            &pol_sane.group_id,
            pol_sane.burst_bytes,
            now,
        )
    } else {
        get_bucket_ptr(bucket_map, &cgroup_id, pol_sane.burst_bytes, now)
    };
    let bkt = match bkt_ptr {
        Some(ptr) => unsafe { &mut *ptr },
        None => return 1,
    };

    enforce(&pol_sane, bkt, pkt_len, now, stats)
}

/// Download enforcement (ingress). Ported from enforce_dl.
#[cgroup_skb(ingress)]
fn enforce_dl(ctx: SkBuffContext) -> i32 {
    try_enforce(ctx, &cgroup_policy_dl, &cgroup_bucket_dl, &group_bucket_dl)
}

/// Upload enforcement (egress). Ported from enforce_ul.
#[cgroup_skb(egress)]
fn enforce_ul(ctx: SkBuffContext) -> i32 {
    try_enforce(ctx, &cgroup_policy_ul, &cgroup_bucket_ul, &group_bucket_ul)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// The license section must stay GPL: bpf_skb_cgroup_id is a
// GPL-only helper, and the C twin declares GPL. A mismatch here
// would fail the verifier at program load time on a real host.
#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
static LICENSE: [u8; 4] = *b"GPL\0";
