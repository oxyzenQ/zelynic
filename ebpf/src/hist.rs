// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The depth histogram's pure core (night-frontier-2B, schema v34;
//! the Z1 depth pack rides schema v35): the log2 bucket law, the
//! sampling cadence, and the row shape — the same file-shape
//! discipline as math.rs and drr.rs: zero aya dependencies, wired
//! into the limiter with #[path] AND into the userspace test tree,
//! so the math carries rootless pins.
//!
//! The kernel keeps the plumbing (the two LRU rows and the sampler
//! tick in bin/limiter.rs, the recorded write in enforce.rs); this
//! file owns only what both sides must agree on — the one arithmetic
//! the schema bump pins, and since Z1 the row's WRITE-side words
//! (the volatile replace-law aggregates and the tail story slots,
//! both pointer-based over map memory so the rootless pins drive
//! real rows; the aggregates ride check-then-store volatile pairs —
//! the measured_srtt ratchet's own discipline, because the BPF ISA
//! has no plain-atomic-load instruction for the CAS shape and the
//! replace law never needs one — and the tail scan is an 8-slot
//! linear pass the verifier unrolls, the sampled write's one
//! bounded extra).

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

/// One tail slot (night-frontier-Z1, schema v35): the worst-by-size
/// sample's story row — WHEN (ktime ns, boot-relative monotonic),
/// HOW BIG (skb bytes), at WHAT RTT (the socket's recwn word, 0 =
/// the unmeasured sentinel), on WHICH socket (the bpf cookie — the
/// identity userspace's walk already maps to an endpoint, so the
/// kernel never parses the wire and never reads a kernel-struct
/// offset; the no-CO-RE law's own currency). 32 bytes, all-u64.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct HistTail {
    pub ts_ns: u64,
    pub size: u64,
    pub srtt_us: u64,
    pub cookie: u64,
}

/// The tail's depth: the worst 8 size samples kept per direction
/// row. 8 slots × 32 bytes ride IN the row (no new map — the
/// pressure law: one map family, reused), a linear 8-slot scan on
/// the sampled path (1 in 1024 packets) the verifier unrolls.
pub const HIST_TAIL: usize = 8;

/// One cgroup's distribution row (v35): the two metric halves back
/// to back — 32 u64 buckets each — then the exact aggregates the
/// sampled set carries (count, sum, min, max per half; the sum/min/
/// max words the bucket bounds can never say exactly), then the
/// tail story rows. 512 + 64 + 256 = 832 bytes, the shape the
/// userspace mirror (src/ebpf/limiter/hist.rs HistRowRaw)
/// hand-copies under this schema's pin. Bucket counters and the
/// count/sum words take cross-CPU atomic adds (the share-word
/// discipline); min/max take the volatile check-then-store replace
/// law; the tail slots take volatile field stores (ts last); the
/// row itself is never rewritten wholesale, so no seq-lock is owed.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct HistRow {
    pub size: [u64; HIST_BUCKETS],
    pub srtt: [u64; HIST_BUCKETS],
    /// The sampled set's exact aggregates. `*_min` words ride the
    /// 0-sentinel (a fresh row answers 0 = "no min yet"); a
    /// zero-length skb increments count/sum (bucket-consistent)
    /// but skips min/max — the aggregates describe traffic mass.
    pub size_count: u64,
    pub size_sum: u64,
    pub size_min: u64,
    pub size_max: u64,
    pub srtt_count: u64,
    pub srtt_sum: u64,
    pub srtt_min: u64,
    pub srtt_max: u64,
    /// The worst-8-by-size story slots (ts_ns 0 = the empty
    /// sentinel; the ts write goes LAST, so a reader never sees a
    /// half-filled live slot — the sampling coarseness a torn read
    /// may still show, one walk's lag at worst).
    pub tail: [HistTail; HIST_TAIL],
}

const _: () = assert!(core::mem::size_of::<HistRow>() == 832);

/// One aggregate-min word's update (night-frontier-Z1): the
/// check-then-store replace law — the measured_srtt ratchet's own
/// volatile discipline (enforce.rs's pair). Plain aligned volatile
/// loads/stores, NOT atomics: the BPF ISA has no plain-atomic-load
/// instruction (the LLVM bpf target cannot select one — the Z1
/// build's own lesson, the same wall that keeps the record site a
/// fetch_add-only family), and replace semantics never need one: a
/// lost candidate under cross-CPU sampling contention is far under
/// the sampling resolution, never a wrong count (count/sum stay RMW
/// adds; only min/max can miss by one contender). The 0-sentinel:
/// a fresh row's first real sample always lands.
#[inline]
pub fn agg_min_word(word: *mut u64, v: u64) {
    // SAFETY: an aligned u64 map word in stable kernel memory — the
    // same single-instruction contract the measured_srtt ratchet
    // rides; no tearing on the aligned word, the volatile guards
    // compiler elision.
    let cur = unsafe { word.read_volatile() };
    if cur != 0 && v >= cur {
        return;
    }
    // SAFETY: the same aligned u64 map word the read above guards —
    // the replace store is one aligned instruction, no tearing.
    unsafe { word.write_volatile(v) };
}

/// The aggregate-max word's update — the same volatile replace law,
/// no sentinel (0 loses to any real sample).
#[inline]
pub fn agg_max_word(word: *mut u64, v: u64) {
    // SAFETY: the same aligned-word contract as agg_min_word.
    let cur = unsafe { word.read_volatile() };
    if v <= cur {
        return;
    }
    // SAFETY: the same aligned u64 map word the read above guards —
    // the replace store is one aligned instruction, no tearing.
    unsafe { word.write_volatile(v) };
}

/// The tail's bounded record (night-frontier-Z1): an 8-slot scan
/// picks the weakest slot (an empty slot — ts 0 — scores 0 and
/// always loses to a real sample), the sample qualifies only when
/// it BEATS that weakest size (strictly greater — equal keeps the
/// incumbent), and the slot's four fields store as volatile writes
/// with the ts LAST. Skips a zero-length skb (no story in massless
/// traffic). The scan-and-write is the sampled path's one O(8) —
/// still O(1) in any realistic reading: constant, bounded, paid
/// 1 in 1024 packets.
#[inline]
pub fn tail_update(row: *mut HistRow, size: u64, srtt_us: u64, cookie: u64, ts_ns: u64) {
    if size == 0 {
        return;
    }
    let mut pick = 0usize;
    let mut weakest = u64::MAX;
    for i in 0..HIST_TAIL {
        // SAFETY: the row's map memory (the same stable-memory
        // contract the bucket adds ride); volatile reads, never
        // aliased with a &mut, never copied to the stack.
        let slot = unsafe { core::ptr::addr_of_mut!((*row).tail[i]) };
        // SAFETY: the slot's field words — the same map-memory
        // contract; volatile reads, never copied to the stack.
        let empty = unsafe { core::ptr::addr_of_mut!((*slot).ts_ns).read_volatile() } == 0;
        let scored = if empty {
            0
        } else {
            // SAFETY: the same slot field, the same contract.
            unsafe { core::ptr::addr_of_mut!((*slot).size).read_volatile() }
        };
        if scored < weakest {
            weakest = scored;
            pick = i;
        }
    }
    if weakest != 0 && size <= weakest {
        return;
    }
    // SAFETY: the picked slot's address in the row's map memory —
    // the same stable-memory contract, one addr_of_mut, no copy.
    let slot = unsafe { core::ptr::addr_of_mut!((*row).tail[pick]) };
    // SAFETY: the row's map memory — the same stable-memory contract
    // the bucket adds ride; volatile field stores, never aliased
    // with a &mut, never copied to the stack. The ts LAST: the
    // slot's emptiness sentinel is the visibility gate.
    unsafe {
        core::ptr::addr_of_mut!((*slot).size).write_volatile(size);
        core::ptr::addr_of_mut!((*slot).srtt_us).write_volatile(srtt_us);
        core::ptr::addr_of_mut!((*slot).cookie).write_volatile(cookie);
        core::ptr::addr_of_mut!((*slot).ts_ns).write_volatile(ts_ns);
    }
}

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
