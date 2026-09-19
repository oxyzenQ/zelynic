// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// zelynic eBPF limiter — cgroup_skb token-bucket rate enforcer
//
// Dragon Architecture Layer 0: Enforcement.
// Pure eBPF. No tc, no nft, no cgroup-wrapper. The kernel enforces.
//
// Two programs:
//   enforce_dl — attached to cgroup_skb/ingress (download)
//   enforce_ul — attached to cgroup_skb/egress (upload)
//
// Two enforcement modes:
//   strict-single: cgroup has individual policy + individual bucket
//   strict-multi:  cgroup maps to group_id, shares group bucket
//
// Build: clang -O2 -g -target bpf -c bpf/limiter.bpf.c -o bpf/limiter.bpf.o

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/// Per-cgroup policy. Written by userspace.
/// group_id == 0 means "individual" (use cgroup_bucket).
/// group_id != 0 means "shared group" (use group_bucket).
struct policy {
    __u64 rate_bps;    // refill rate in bytes per second
    __u64 burst_bytes; // maximum burst size in bytes
    __u32 group_id;    // 0 = individual, N = shared group
};

/// Token bucket state. Updated by BPF on every packet.
///
/// `frac_rem` tracks the sub-byte fractional remainder from the refill
/// calculation: `(elapsed_ns * rate_bps) % NS_PER_SEC`. Without this, integer
/// division truncates up to ~1 byte per refill, causing 0.5–1% rate error
/// at common rates (e.g. 100 KB/s → actual 99.3 KB/s).
///
/// Schema version 2 (added frac_rem). Version 1 (no frac_rem) is incompatible.
struct bucket {
    __u64 tokens;         // current token count in bytes (integer part)
    __u64 last_refill_ns; // timestamp of last refill (bpf_ktime_get_ns)
    __u64 frac_rem;       // fractional remainder: (elapsed * rate) % NS_PER_SEC
};

/// Per-cgroup enforcement stats.
struct limiter_stats {
    __u64 packets_allowed;
    __u64 packets_dropped;
    __u64 bytes_allowed;
    __u64 bytes_dropped;
};

// ━━ Download (ingress) maps ━━

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct policy);
} cgroup_policy_dl SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct bucket);
} cgroup_bucket_dl SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct bucket);
} group_bucket_dl SEC(".maps");

// ━━ Upload (egress) maps ━━

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct policy);
} cgroup_policy_ul SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct bucket);
} cgroup_bucket_ul SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct bucket);
} group_bucket_ul SEC(".maps");

// ━━ Shared maps ━━

/// Watchdog deadline — monotonic time after which BPF becomes no-op.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);   // always 0
    __type(value, __u64); // deadline in nanoseconds
} watchdog_deadline SEC(".maps");

/// Schema version — used by userspace to detect struct layout changes.
/// If the pinned version doesn't match SCHEMA_VERSION_EXPECTED, userspace
/// cleans up all pins and reloads. This enables safe schema evolution.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);   // always 0
    __type(value, __u32); // schema version number
} schema_version SEC(".maps");

/// Current schema version. Increment when BPF struct layouts change.
/// v1: initial (no frac_rem in bucket, no schema_version map)
/// v2: added frac_rem to bucket for fractional token tracking
#define SCHEMA_VERSION 3

/// Per-cgroup stats (combined dl+ul).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct limiter_stats);
} cgroup_limiter_stats SEC(".maps");

#define NS_PER_SEC 1000000000ULL

/// Refill tokens and enforce. Returns 1 (allow) or 0 (drop).
/// `pol` is the policy. `bkt` is the bucket (individual or group).
///
/// Uses fractional remainder tracking for high precision: sub-byte
/// fractions from the refill calculation are accumulated in `frac_rem`
/// and carried over to the next refill. This eliminates the truncation
/// error that would otherwise cause ~0.7% rate inaccuracy.
static __always_inline int enforce(struct policy *pol, struct bucket *bkt,
                                   __u32 pkt_len, __u64 now,
                                   struct limiter_stats *stats) {
    // Refill tokens based on elapsed time.
    __u64 elapsed;
    if (now > bkt->last_refill_ns) {
        elapsed = now - bkt->last_refill_ns;
    } else {
        elapsed = 0;
    }

    // Cap elapsed at 1 second to limit burst after idle.
    if (elapsed > NS_PER_SEC) {
        elapsed = NS_PER_SEC;
    }

    // Calculate refill with fractional precision, overflow-safe
    // (NIGHT-cybersecurity-1).
    //
    // The former single product elapsed * rate_bps overflowed u64
    // whenever rate exceeded u64::MAX / 1s (~18.4 GB/s) and the
    // bucket sat idle past ~0.18s — inside the tool's documented
    // 1 TB/s ceiling (NIGHT-research-1 option B) on 8-TbE-class
    // hardware. The wrapped product made the refill garbage (still
    // capped at burst, so no enforcement bypass, but the rate precision
    // contract broke exactly at the high end). Two paths now:
    //
    //  * fill-detect: once elapsed is large enough that the true
    //    refill reaches 2x burst, the bucket caps at burst anyway —
    //    skip the multiply and credit burst directly (the fraction
    //    resets, matching the cap branch below).
    //  * exact multiply: below that threshold the product is
    //    < 2 * burst * NS_PER_SEC, which is <= 2e17 for any burst
    //    the userspace clamp admits (100 MB; the formula itself stays
    //    inside u64 up to ~9.2 GB burst) — safely representable.
    //
    // Callers guarantee rate_bps > 0 (rate 0 short-circuits to the
    // block drop before enforce); the explicit guard keeps that
    // invariant local and protects the division.
    __u64 refill_whole = 0;
    __u64 new_frac     = bkt->frac_rem;
    if (elapsed > 0 && pol->rate_bps > 0) {
        __u64 fill_ns = (2ULL * pol->burst_bytes * NS_PER_SEC) / pol->rate_bps;
        if (elapsed >= fill_ns) {
            // Refill >= 2x burst: the cap below makes the exact value
            // irrelevant — burst is the answer.
            refill_whole = pol->burst_bytes;
            new_frac     = 0;
        } else {
            __u64 product     = elapsed * pol->rate_bps;
            refill_whole      = product / NS_PER_SEC;
            __u64 refill_frac = product % NS_PER_SEC;

            // Accumulate fractional remainder. If it overflows
            // NS_PER_SEC, carry 1 byte into the integer tokens.
            new_frac = bkt->frac_rem + refill_frac;
            if (new_frac >= NS_PER_SEC) {
                refill_whole += 1;
                new_frac -= NS_PER_SEC;
            }
        }
    }

    // New token count, capped at burst.
    __u64 new_tokens = bkt->tokens + refill_whole;
    if (new_tokens > pol->burst_bytes) {
        new_tokens = pol->burst_bytes;
        new_frac =
            0; // reset fraction on cap — at burst, no accumulation needed
    }

    bkt->last_refill_ns = now;
    bkt->frac_rem       = new_frac;

    // Check if enough tokens for this packet.
    if (new_tokens >= pkt_len) {
        bkt->tokens = new_tokens - pkt_len;
        if (stats) {
            stats->packets_allowed += 1;
            stats->bytes_allowed += pkt_len;
        }
        return 1;
    } else {
        bkt->tokens = new_tokens;
        if (stats) {
            stats->packets_dropped += 1;
            stats->bytes_dropped += pkt_len;
        }
        return 0;
    }
}

/// Get or create stats entry for a cgroup.
static __always_inline struct limiter_stats *get_stats(__u32 cgroup_id) {
    struct limiter_stats *stats =
        bpf_map_lookup_elem(&cgroup_limiter_stats, &cgroup_id);
    if (!stats) {
        struct limiter_stats init = {};
        bpf_map_update_elem(&cgroup_limiter_stats, &cgroup_id, &init, BPF_ANY);
        stats = bpf_map_lookup_elem(&cgroup_limiter_stats, &cgroup_id);
    }
    return stats;
}

/// Get or create bucket. `map` is the bucket map, `key` is cgroup_id or
/// group_id.
static __always_inline struct bucket *get_bucket(void *map, __u32 key,
                                                 __u64 burst, __u64 now) {
    struct bucket *bkt = bpf_map_lookup_elem(map, &key);
    if (!bkt) {
        struct bucket init  = {};
        init.tokens         = burst;
        init.last_refill_ns = now;
        init.frac_rem       = 0;
        bpf_map_update_elem(map, &key, &init, BPF_ANY);
        bkt = bpf_map_lookup_elem(map, &key);
    }
    return bkt;
}

/// Download enforcement (ingress).
SEC("cgroup_skb/ingress")
int enforce_dl(struct __sk_buff *skb) {
    // ━━ Watchdog check ━━
    // deadline == 0 means "no deadline set" → always enforce.
    // deadline != 0 means "fail-safe timeout" → allow all if expired.
    // (Preserved for future --timeout feature; serve child refresh removed.)
    __u32 zero      = 0;
    __u64 *deadline = bpf_map_lookup_elem(&watchdog_deadline, &zero);
    if (!deadline)
        return 1;
    __u64 now = bpf_ktime_get_ns();
    if (*deadline != 0 && now > *deadline)
        return 1;

    __u64 cgid      = bpf_skb_cgroup_id(skb);
    __u32 cgroup_id = (__u32)cgid;
    __u32 pkt_len   = skb->len;

    // Look up download policy.
    struct policy *pol = bpf_map_lookup_elem(&cgroup_policy_dl, &cgroup_id);
    if (!pol)
        return 1;
    // rate_bps == 0 means BLOCKED (drop all packets).
    // Used by 'zelynic block-single' command.
    // Schema v3: changed from return 1 (allow) to return 0 (drop).
    if (pol->rate_bps == 0)
        return 0;

    struct limiter_stats *stats = get_stats(cgroup_id);

    // Individual or group bucket?
    if (pol->group_id != 0) {
        struct bucket *bkt =
            get_bucket(&group_bucket_dl, pol->group_id, pol->burst_bytes, now);
        if (!bkt)
            return 1;
        return enforce(pol, bkt, pkt_len, now, stats);
    } else {
        struct bucket *bkt =
            get_bucket(&cgroup_bucket_dl, cgroup_id, pol->burst_bytes, now);
        if (!bkt)
            return 1;
        return enforce(pol, bkt, pkt_len, now, stats);
    }
}

/// Upload enforcement (egress).
SEC("cgroup_skb/egress")
int enforce_ul(struct __sk_buff *skb) {
    // ━━ Watchdog check ━━
    // deadline == 0 means "no deadline set" → always enforce.
    // deadline != 0 means "fail-safe timeout" → allow all if expired.
    // (Preserved for future --timeout feature; serve child refresh removed.)
    __u32 zero      = 0;
    __u64 *deadline = bpf_map_lookup_elem(&watchdog_deadline, &zero);
    if (!deadline)
        return 1;
    __u64 now = bpf_ktime_get_ns();
    if (*deadline != 0 && now > *deadline)
        return 1;

    __u64 cgid      = bpf_skb_cgroup_id(skb);
    __u32 cgroup_id = (__u32)cgid;
    __u32 pkt_len   = skb->len;

    // Look up upload policy.
    struct policy *pol = bpf_map_lookup_elem(&cgroup_policy_ul, &cgroup_id);
    if (!pol)
        return 1;
    // rate_bps == 0 means BLOCKED (drop all packets).
    // Used by 'zelynic block-single' command.
    // Schema v3: changed from return 1 (allow) to return 0 (drop).
    if (pol->rate_bps == 0)
        return 0;

    struct limiter_stats *stats = get_stats(cgroup_id);

    // Individual or group bucket?
    if (pol->group_id != 0) {
        struct bucket *bkt =
            get_bucket(&group_bucket_ul, pol->group_id, pol->burst_bytes, now);
        if (!bkt)
            return 1;
        return enforce(pol, bkt, pkt_len, now, stats);
    } else {
        struct bucket *bkt =
            get_bucket(&cgroup_bucket_ul, cgroup_id, pol->burst_bytes, now);
        if (!bkt)
            return 1;
        return enforce(pol, bkt, pkt_len, now, stats);
    }
}

char _license[] SEC("license") = "GPL";
