// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// zelynic eBPF limiter, the pure-Rust BPF source (NIGHT-improve-1,
// phase 2, stage 1: port of the former bpf/limiter.bpf.c; phase 3
// deleted the C side — the port is now the production source).
//
// Dragon Architecture Layer 0: Enforcement. Pure eBPF. No tc, no
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

// ---------------------------------------------------------------------------
// Shared layout contract with the userspace loader (src/ebpf/limiter/
// types.rs: PolicyRaw, BucketRaw, LimiterStatsRaw) and the C twin. The
// compile-time size pins guarantee the layouts can never drift
// silently; the C side relies on kernel headers for the same
// invariants, the userspace tests assert the third copy.
// ---------------------------------------------------------------------------

/// The BPF-side policy layout; the userspace mirror is `PolicyRaw`
/// in src/ebpf/limiter/types.rs (layout contract). group_id == 0 means
/// "individual" (use cgroup bucket); group_id != 0 means "shared
/// group" (use the group bucket keyed by group_id).
#[repr(C)]
#[derive(Clone, Copy)]
struct Policy {
    rate_bps: u64,
    burst_bytes: u64,
    group_id: u32,
}

/// The BPF-side token-bucket layout, schema v2 (userspace mirror:
/// `BucketRaw` in src/ebpf/limiter/types.rs — the layout contract).
///
/// `frac_rem` tracks the sub-byte fractional remainder from the
/// refill calculation: `(elapsed_ns * rate_bps) % NS_PER_SEC`.
/// Without this, integer division truncates up to ~1 byte per
/// refill, causing 0.5-1% rate error at common rates.
#[repr(C)]
#[derive(Clone, Copy)]
struct Bucket {
    tokens: u64,
    last_refill_ns: u64,
    frac_rem: u64,
}

/// The BPF-side stats layout (userspace mirror: `LimiterStatsRaw`
/// in src/ebpf/limiter/types.rs — the layout contract). Combined
/// download + upload enforcement stats per cgroup.
#[repr(C)]
#[derive(Clone, Copy)]
struct LimiterStats {
    packets_allowed: u64,
    packets_dropped: u64,
    bytes_allowed: u64,
    bytes_dropped: u64,
}

const _: () = assert!(core::mem::size_of::<Policy>() == 24);
const _: () = assert!(core::mem::size_of::<Bucket>() == 24);
const _: () = assert!(core::mem::size_of::<LimiterStats>() == 32);

/// Refill rate math: nanoseconds per second.
const NS_PER_SEC: u64 = 1_000_000_000;

/// Current schema version. Increment when struct layouts or
/// semantics change. Kept in sync with SCHEMA_VERSION_EXPECTED in
/// src/ebpf/limiter/types.rs (v3: rate_bps == 0 drops instead of
/// allowing). The BPF program never writes it — userspace stamps
/// the pinned map after load — so the constant exists purely as the
/// parity anchor for that three-way contract.
#[allow(dead_code)]
const SCHEMA_VERSION: u32 = 3;

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
// Enforcement core. Ported from the C `enforce` helper: refill
// tokens and return 1 (allow) or 0 (drop).
// ---------------------------------------------------------------------------

/// Refill tokens and enforce. `pol` is the policy, `bkt` the bucket
/// (individual or group), `stats` an optional stats entry (the C
/// twin passes NULL when the stats insert failed and keeps
/// enforcing without bookkeeping).
///
/// Fractional remainder tracking keeps the rate precise (see the
/// Bucket docs); the refill multiply is overflow-safe (the
/// NIGHT-cybersecurity-1 fill-detect shape, ported verbatim):
///
///  * fill-detect: once elapsed is large enough that the true
///    refill reaches 2x burst, the bucket caps at burst anyway —
///    skip the multiply and credit burst directly (the fraction
///    resets, matching the cap branch below).
///  * exact multiply: below that threshold the product is
///    < 2 * burst * NS_PER_SEC, safely representable in u64 for any
///    burst the userspace clamp admits.
///
/// Callers guarantee rate_bps > 0 (rate 0 short-circuits to the
/// block drop before enforce); the explicit guard keeps that
/// invariant local and protects the division.
#[inline(always)]
fn enforce(
    pol: &Policy,
    bkt: &mut Bucket,
    pkt_len: u32,
    now: u64,
    stats: Option<&mut LimiterStats>,
) -> i32 {
    // Refill tokens based on elapsed time.
    let mut elapsed = if now > bkt.last_refill_ns {
        now - bkt.last_refill_ns
    } else {
        0
    };

    // Cap elapsed at 1 second to limit burst after idle.
    if elapsed > NS_PER_SEC {
        elapsed = NS_PER_SEC;
    }

    let mut refill_whole: u64 = 0;
    let mut new_frac: u64 = bkt.frac_rem;
    if elapsed > 0 && pol.rate_bps > 0 {
        let fill_ns = (2 * pol.burst_bytes * NS_PER_SEC) / pol.rate_bps;
        if elapsed >= fill_ns {
            // Refill >= 2x burst: the cap below makes the exact value
            // irrelevant — burst is the answer.
            refill_whole = pol.burst_bytes;
            new_frac = 0;
        } else {
            let product = elapsed * pol.rate_bps;
            refill_whole = product / NS_PER_SEC;
            let refill_frac = product % NS_PER_SEC;

            // Accumulate the fractional remainder. If it overflows
            // NS_PER_SEC, carry 1 byte into the integer tokens.
            new_frac = bkt.frac_rem + refill_frac;
            if new_frac >= NS_PER_SEC {
                refill_whole += 1;
                new_frac -= NS_PER_SEC;
            }
        }
    }

    // New token count, capped at burst.
    let mut new_tokens = bkt.tokens + refill_whole;
    if new_tokens > pol.burst_bytes {
        new_tokens = pol.burst_bytes;
        // Reset the fraction on cap — at burst, no accumulation is
        // needed.
        new_frac = 0;
    }

    bkt.last_refill_ns = now;
    bkt.frac_rem = new_frac;

    // Check if enough tokens for this packet.
    if new_tokens >= u64::from(pkt_len) {
        bkt.tokens = new_tokens - u64::from(pkt_len);
        if let Some(s) = stats {
            s.packets_allowed += 1;
            s.bytes_allowed += u64::from(pkt_len);
        }
        1
    } else {
        bkt.tokens = new_tokens;
        if let Some(s) = stats {
            s.packets_dropped += 1;
            s.bytes_dropped += u64::from(pkt_len);
        }
        0
    }
}

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
    if pol.rate_bps == 0 {
        return 0;
    }

    let stats = get_stats_ptr(&cgroup_id).map(|ptr| unsafe { &mut *ptr });

    // Individual or group bucket? group_id selects the shared
    // bucket keyed by the group; 0 falls back to the per-cgroup
    // bucket keyed by cgroup_id.
    let bkt_ptr = if pol.group_id != 0 {
        get_bucket_ptr(group_bucket_map, &pol.group_id, pol.burst_bytes, now)
    } else {
        get_bucket_ptr(bucket_map, &cgroup_id, pol.burst_bytes, now)
    };
    let bkt = match bkt_ptr {
        Some(ptr) => unsafe { &mut *ptr },
        None => return 1,
    };

    enforce(pol, bkt, pkt_len, now, stats)
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
