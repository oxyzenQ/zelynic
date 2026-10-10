// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// NIGHT-improve-44: try_enforce — the one verdict path every
// packet rides — moved out of limiter.rs at the 600-line cap.
// The entry programs (enforce_dl / enforce_ul) stay in the bin
// root; the static map block and the helpers reach through crate::.
//
/// Shared enforcement flow for one direction. `policy_map` selects
/// download vs upload; `bucket_map` / `group_bucket_map` are the
/// matching individual/group bucket (pool) maps, `leaf_bucket_map`
/// the direction's DRR leaf map (charger-core-1c), `share_map` the
/// direction's learned-share state map (dinner-28), `ledger_map`
/// the direction's epoch-ledger state map (repair-3), `rate_ring_map`
/// the direction's time-series ring (charger-core-3a), `debt_map`
/// the direction's ECN debt map (private-research-4), and the
/// `flow_*` triple the direction's flow lane (v20 — CAKE-shaped
/// isolation inside the leaf) draws through. `is_ingress` names the
/// direction the QUIC-aware attribution lane learns and keys by
/// (schema v22): the ingress hook reads the download hint map and
/// the egress hook the upload one — the two programs share both
/// maps by object construction.
use aya_ebpf::{
    helpers::{bpf_get_socket_cookie, bpf_ktime_get_ns, bpf_skb_cgroup_id},
    maps::{HashMap, LruHashMap},
    programs::SkBuffContext,
};

use crate::drr_flow::drr_flow;
use crate::ecn;
use crate::enforce_helpers::{
    debt_key_for, ecn_rescue, get_bucket_ptr, get_debt_ptr, get_stats_ptr, ring_verdict,
    window_gate,
};
use crate::math::{Bucket, MAX_ENFORCABLE_BURST, POLICY_FLAG_PER_SOCKET, Policy, book, enforce};
use crate::mmspa_resolve::mmspa_resolve_root;
use crate::quic_flow;
use crate::rate_ring::RateRing;
use crate::socket_flow::{self, socket_flow};
use crate::watchdog_deadline;
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn try_enforce(
    ctx: SkBuffContext,
    is_ingress: bool,
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
    flow_bucket_map: &LruHashMap<u64, Bucket>,
    flow_share_map: &LruHashMap<u64, u64>,
    flow_ledger_map: &LruHashMap<u64, u64>,
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
    // MMSPA (NIGHT-private-research-2) adds exactly ONE lookup to
    // this fast path's miss branch: the LRU leaf cache, answered
    // with a resolved 0 for every socket no root covers — the
    // unlimited majority stays one-lookup-plus-memo, never a walk.
    // A socket whose OWN cgroup carries the policy (every
    // pre-MMSPA scenario) still takes the single direct lookup
    // below — its cgroup IS the root, no resolution runs.
    let leaf = unsafe { bpf_skb_cgroup_id(ctx.skb.skb) } as u32;
    let pkt_len = ctx.len();

    // Look up the direction's policy at the socket's own cgroup
    // first — the nearest possible root. No policy means the leaf
    // itself is unpoliced, but MMSPA must still ask whether an
    // ANCESTOR of it is: a strict on cgroup A covers every socket
    // born under A/** (the subtree contract), resolved per packet.
    let (cgroup_id, pol) = match policy_map.get_ptr(&leaf) {
        Some(ptr) => (leaf, unsafe { &*ptr }),
        None => {
            let root = mmspa_resolve_root(&ctx, leaf, policy_map, memo_map);
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

    // The monotonic clock, taken here (one fetch, reused by the
    // window gate below, the watchdog, and every lane's refill
    // math). It sits AFTER the policy resolution on purpose: the
    // unlimited fast path (NIGHT-lts-2) never pays for a timestamp
    // it cannot use — only a packet whose policy EXISTS can reach
    // the window gate or the watchdog that follows it.
    let now = unsafe { bpf_ktime_get_ns() };

    // The time-window gate (night-during, schema v23): a row
    // whose --during window is INACTIVE answers ALLOW, exactly
    // the unlimited fast path's miss shape — the row is not being
    // removed, it is simply not policing this packet (no stats,
    // no ring, no belt; the SWEEP through the unstrict/reclaim
    // path is what removes an ENDED span). One map read on the
    // policed path only: the unlimited majority pays nothing.
    if !window_gate(&cgroup_id, now) {
        return 1;
    }

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
    if deadline != 0 && now > deadline {
        return 1;
    }

    // rate_bps == 0 means BLOCKED (drop all packets). Used by the
    // block verb. Schema v3: changed from allow to drop.
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
            // improve-40 (schema v24): the bracket carries through
            // the burst clamp verbatim — it is rate-family metadata,
            // not a stockpile bound; the law-side consumers clamp it
            // against the row's own rate (drr.rs's v24 section).
            floor_bps: pol.floor_bps,
            ceil_bps: pol.ceil_bps,
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
    // at the RESOLVED POLICY ROOT — the roll-up the MMSPA contract
    // already owns.
    if pol_sane.flags & POLICY_FLAG_PER_SOCKET != 0 {
        let cookie = unsafe { bpf_get_socket_cookie(ctx.skb.skb.cast()) };
        if cookie != 0 {
            // The skb pointer rides in for the lane's own ECN-first
            // rescue (schema v21, the per-socket convergence closure):
            // the debt lives inside the socket's bucket — the lane
            // charges it where the belt already owns it, so the rescue
            // runs inside socket_flow, one map lookup, no debt-map
            // keying the u64 cookie could not carry (the group/DRR
            // lanes' map shape stays theirs). Non-ECT traffic refuses
            // the helper and drops exactly as before — the legacy
            // verdict, untouched.
            //
            // schema v22 (QUIC-aware): the cookie becomes the
            // per-CONNECTION key when the packet's QUIC connection ID
            // attributes it finer (the browser shape — one UDP socket,
            // N HTTP/3 connections sharing one cookie). The lane's
            // arithmetic, its belt, and its ECN debt all key by the
            // value handed here, so a QUIC connection gets exactly the
            // budget a TCP connection gets — the --per-socket promise,
            // restored for the protocol that multiplexes. A refusal
            // (non-QUIC, unconfirmed) hands back the raw cookie: the
            // pre-v22 verdict, untouched.
            let key = quic_flow::quic_flow_key(&ctx, cookie, is_ingress);
            let verdict = socket_flow(
                &pol_sane,
                key,
                socket_bucket_map,
                now,
                pkt_len,
                stats,
                ctx.skb.skb.cast(),
            );
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
        // The group lane keeps the legacy FCFS shape
        // (documented scope): its members are enumerated by the
        // apply itself, so the fairness problem MMSPA has (unbounded
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
    //
    // schema v20 (CAKE-shaped flow isolation): an attributed packet
    // spends from its own FLOW bucket inside the leaf — the cookie
    // the per-socket lane already consumes, fetched here once, only
    // on the lane that spends it. cookie == 0 rides the leaf lane
    // verbatim (the hook's honest attribution limit).
    //
    // schema v22 (QUIC-aware): the flow key is the cookie refined
    // by the QUIC connection ID when the header carries finer truth
    // — the v20 lane's isolation restored for the browser shape
    // (one socket, N HTTP/3 connections the cookie collapses into
    // one flow bucket). The bucket/share/ledger maps key by the
    // value handed to drr_flow unchanged; every QUIC refusal rides
    // the raw cookie, exactly the v20 verdict.
    let cookie = unsafe { bpf_get_socket_cookie(ctx.skb.skb.cast()) };
    let flow_key = if cookie != 0 {
        quic_flow::quic_flow_key(&ctx, cookie, is_ingress)
    } else {
        0
    };
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
        flow_bucket_map,
        flow_share_map,
        flow_ledger_map,
        flow_key,
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
