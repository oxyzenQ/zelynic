// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// NIGHT-improve-44: the enforcement helpers (the map pointer
// probes, the ring verdict, the ECN rescue pair, the window gate)
// moved out of limiter.rs at the 600-line cap. The static map block stays
// in the bin root; these reach them through crate:: (descendant
// visibility), same #[inline(always] discipline as before.
//
use aya_ebpf::maps::HashMap;
use aya_ebpf::maps::LruHashMap;

use crate::cgroup_limiter_stats;
use crate::during;
use crate::ecn;
use crate::math::Bucket;
use crate::math::LimiterStats;
use crate::math::book_rescue;
use crate::mmspa_resolve;
use crate::policy_window;
use crate::rate_ring;
use crate::rate_ring::RateRing;
use crate::rate_ring::RateSlot;
use crate::rate_ring::ring_book;
use crate::wall_clock_offset;
#[inline(always)]
pub(crate) fn get_stats_ptr(cgroup_id: &u32) -> Option<*mut LimiterStats> {
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
pub(crate) fn get_bucket_ptr(
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
pub(crate) fn get_ring_ptr(map: &HashMap<u32, RateRing>, key: &u32) -> Option<*mut RateRing> {
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
pub(crate) fn ring_verdict(
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
pub(crate) unsafe fn bpf_skb_ecn_set_ce(skb: *mut core::ffi::c_void) -> i64 {
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
pub(crate) fn debt_key_for(budget_key: u32) -> u64 {
    (u64::from(mmspa_resolve::current_generation()) << 32) | u64::from(budget_key)
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
pub(crate) fn get_debt_ptr(debt_map: &LruHashMap<u64, u64>, key: &u64) -> Option<*mut u64> {
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
pub(crate) fn ecn_rescue(
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

/// The time-window gate (night-during, schema v23): the ONE call
/// every policed packet makes after its policy resolves — an
/// absent window entry answers true (enforce, today's behavior
/// exactly), an INACTIVE window answers false and the caller
/// returns the unlimited miss shape. DAILY rows read the offset
/// bridge; an unreadable Array entry (unreachable in practice —
/// the kernel pre-creates Array entries; the belt stays) ENFORCES:
/// the row's default state, never an unlimited pass born from a
/// bookkeeping miss. SPAN rows pass offset 0 — the core ignores
/// it, the drift-free translation is the whole point.
#[inline(always)]
pub(crate) fn window_gate(cgroup_id: &u32, now_mono_ns: u64) -> bool {
    match policy_window.get_ptr(cgroup_id) {
        None => true,
        Some(w) => {
            let win = unsafe { &*w };
            if win.kind == during::WINDOW_KIND_DAILY {
                match wall_clock_offset.get_ptr(0) {
                    Some(off) => during::window_active(win, now_mono_ns, unsafe { *off }),
                    None => true,
                }
            } else {
                during::window_active(win, now_mono_ns, 0)
            }
        }
    }
}
