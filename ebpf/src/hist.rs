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
#[inline]
pub fn size_bucket(bytes: u64) -> usize {
    if bytes == 0 {
        return 0;
    }
    let b = 63 - bytes.leading_zeros() as usize;
    if b >= HIST_BUCKETS {
        HIST_BUCKETS - 1
    } else {
        b
    }
}

/// The log2 bucket of an srtt sample in MICROSECONDS — the recwn
/// row's stored form (the RTT callback already shifted the uapi
/// sock_ops `srtt_us` >> 3 before writing the word, so the peek
/// hands this fn plain microseconds; the v31 ledger's <<3 note
/// describes the UAPI read, not the stored word). Zero (the
/// unmeasured sentinel) answers bucket 0; callers only record when
/// the word is nonzero.
#[inline]
pub fn srtt_bucket(srtt_us: u64) -> usize {
    if srtt_us == 0 {
        return 0;
    }
    let b = 63 - srtt_us.leading_zeros() as usize;
    if b >= HIST_BUCKETS {
        HIST_BUCKETS - 1
    } else {
        b
    }
}
