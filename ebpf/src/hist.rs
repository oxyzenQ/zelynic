// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The depth histogram's pure core (night-frontier-2B, schema v34):
//! the log2 bucket law, the sampling cadence, and the row shape —
//! the same file-shape discipline as math.rs and drr.rs: zero aya
//! dependencies, wired into the limiter with #[path] AND into the
//! userspace test tree, so the math carries rootless pins.
//!
//! The kernel keeps the plumbing (the two LRU rows and the sampler
//! tick in bin/limiter.rs, the recorded write in enforce.rs); this
//! file owns only what both sides must agree on — the one arithmetic
//! the schema bump pins.

/// Bucket count per metric half. log2 scale: bucket b covers
/// [2^b, 2^(b+1)) of the metric's own unit — bytes for the size
/// half, microseconds for the srtt half. 32 buckets reach 2^31
/// bytes (past any skb the kernel can hand a cgroup_skb hook) and
/// 2^31 us (~35 minutes) of RTT, both far past any real sample.
pub const HIST_BUCKETS: usize = 32;

/// The sampler cadence: record every 2^SHIFT-th packet, per CPU.
/// 1024 keeps the recorder's map work off the hot path — the
/// NIGHT-lts-2 law's frontier-2B amendment: the unlimited majority
/// pays ONE per-CPU counter tick (per-CPU isolation, no atomics, no
/// hash), the sampled packet pays the LRU row — while a busy cgroup
/// still fills the distribution in seconds (100 pps is ~6 samples
/// a second, ~3600 a minute; the quantiles read off the sample
/// distribution).
pub const HIST_SAMPLE_SHIFT: u32 = 10;

/// The tick mask pairing with HIST_SAMPLE_SHIFT: a tick qualifies
/// for recording when `tick & MASK == 0`.
pub const HIST_SAMPLE_MASK: u64 = (1 << HIST_SAMPLE_SHIFT) - 1;

/// One cgroup's distribution row: the two metric halves back to
/// back, 32 u64 buckets each — 512 bytes, the shape the userspace
/// mirror (src/ebpf/limiter/hist.rs HistRowRaw) hand-copies under
/// this schema's pin. Bucket counters take cross-CPU atomic adds
/// (the share-word discipline); the row itself is never rewritten
/// wholesale, so no seq-lock is owed.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct HistRow {
    pub size: [u64; HIST_BUCKETS],
    pub srtt: [u64; HIST_BUCKETS],
}

const _: () = assert!(core::mem::size_of::<HistRow>() == 512);

/// The log2 bucket of a byte count (the size half). Zero answers
/// bucket 0 — a zero-length skb is not traffic, but a count there
/// beats a clz panic on 0.
///
/// The ladder IS the verifier's own proof, and the third form this
/// fn took: the clamp (build one) and the AND mask (build two) were
/// both PROVABLY DEAD to LLVM — the hooks hand a u32 skb length, so
/// the compiler knows ilog2(bytes) <= 31 before any cap runs, and it
/// deleted each cap while the verifier (which cannot see LLVM's
/// reasoning) modeled leading_zeros as an opaque scalar and rejected
/// the load at off=2040. Direct comparisons on the raw value are the
/// one shape nothing can optimize away: each bound is a branch the
/// verifier merges natively, and the straight-line sequence has no
/// merge to miss. Only sampled packets (1 in 1024) pay the ladder.
#[inline]
pub fn size_bucket(bytes: u64) -> usize {
    if bytes >= 1 << 31 {
        return 31;
    }
    if bytes >= 1 << 30 {
        return 30;
    }
    if bytes >= 1 << 29 {
        return 29;
    }
    if bytes >= 1 << 28 {
        return 28;
    }
    if bytes >= 1 << 27 {
        return 27;
    }
    if bytes >= 1 << 26 {
        return 26;
    }
    if bytes >= 1 << 25 {
        return 25;
    }
    if bytes >= 1 << 24 {
        return 24;
    }
    if bytes >= 1 << 23 {
        return 23;
    }
    if bytes >= 1 << 22 {
        return 22;
    }
    if bytes >= 1 << 21 {
        return 21;
    }
    if bytes >= 1 << 20 {
        return 20;
    }
    if bytes >= 1 << 19 {
        return 19;
    }
    if bytes >= 1 << 18 {
        return 18;
    }
    if bytes >= 1 << 17 {
        return 17;
    }
    if bytes >= 1 << 16 {
        return 16;
    }
    if bytes >= 1 << 15 {
        return 15;
    }
    if bytes >= 1 << 14 {
        return 14;
    }
    if bytes >= 1 << 13 {
        return 13;
    }
    if bytes >= 1 << 12 {
        return 12;
    }
    if bytes >= 1 << 11 {
        return 11;
    }
    if bytes >= 1 << 10 {
        return 10;
    }
    if bytes >= 1 << 9 {
        return 9;
    }
    if bytes >= 1 << 8 {
        return 8;
    }
    if bytes >= 1 << 7 {
        return 7;
    }
    if bytes >= 1 << 6 {
        return 6;
    }
    if bytes >= 1 << 5 {
        return 5;
    }
    if bytes >= 1 << 4 {
        return 4;
    }
    if bytes >= 1 << 3 {
        return 3;
    }
    if bytes >= 1 << 2 {
        return 2;
    }
    if bytes >= 1 << 1 {
        return 1;
    }
    0
}

/// The log2 bucket of an srtt sample in MICROSECONDS — the recwn
/// row's stored form (the RTT callback already shifted the uapi
/// sock_ops `srtt_us` >> 3 before writing the word). Zero (the
/// unmeasured sentinel) answers bucket 0; callers only record when
/// the word is nonzero. The ladder is the verifier's own proof, the
/// same lesson size_bucket's doc carries.
#[inline]
pub fn srtt_bucket(srtt_us: u64) -> usize {
    if srtt_us >= 1 << 31 {
        return 31;
    }
    if srtt_us >= 1 << 30 {
        return 30;
    }
    if srtt_us >= 1 << 29 {
        return 29;
    }
    if srtt_us >= 1 << 28 {
        return 28;
    }
    if srtt_us >= 1 << 27 {
        return 27;
    }
    if srtt_us >= 1 << 26 {
        return 26;
    }
    if srtt_us >= 1 << 25 {
        return 25;
    }
    if srtt_us >= 1 << 24 {
        return 24;
    }
    if srtt_us >= 1 << 23 {
        return 23;
    }
    if srtt_us >= 1 << 22 {
        return 22;
    }
    if srtt_us >= 1 << 21 {
        return 21;
    }
    if srtt_us >= 1 << 20 {
        return 20;
    }
    if srtt_us >= 1 << 19 {
        return 19;
    }
    if srtt_us >= 1 << 18 {
        return 18;
    }
    if srtt_us >= 1 << 17 {
        return 17;
    }
    if srtt_us >= 1 << 16 {
        return 16;
    }
    if srtt_us >= 1 << 15 {
        return 15;
    }
    if srtt_us >= 1 << 14 {
        return 14;
    }
    if srtt_us >= 1 << 13 {
        return 13;
    }
    if srtt_us >= 1 << 12 {
        return 12;
    }
    if srtt_us >= 1 << 11 {
        return 11;
    }
    if srtt_us >= 1 << 10 {
        return 10;
    }
    if srtt_us >= 1 << 9 {
        return 9;
    }
    if srtt_us >= 1 << 8 {
        return 8;
    }
    if srtt_us >= 1 << 7 {
        return 7;
    }
    if srtt_us >= 1 << 6 {
        return 6;
    }
    if srtt_us >= 1 << 5 {
        return 5;
    }
    if srtt_us >= 1 << 4 {
        return 4;
    }
    if srtt_us >= 1 << 3 {
        return 3;
    }
    if srtt_us >= 1 << 2 {
        return 2;
    }
    if srtt_us >= 1 << 1 {
        return 1;
    }
    0
}
