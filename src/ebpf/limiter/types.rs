// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Limiter constants and data types.
//!
//! BPF map value structs mirror the limiter program's structs in
//! `ebpf/src/bin/limiter.rs` (layout contract); the high-level types
//! drive the CLI-facing API.

// ━━ Constants ━━

/// The embedded pure-Rust limiter object (NIGHT-improve-1 phase 3):
/// the aya-ebpf ELF staged into OUT_DIR by build.rs's nested nightly
/// build, riding inside the binary via include_bytes!. `EbpfLoader`
/// takes the bytes directly — no file path, no object discovery.
///
/// NIGHT-hunt-30: the bytes ride inside [`AlignedElf`] so their
/// address is 8-byte aligned BY CONSTRUCTION — the `object` crate's
/// ELF64 parser reads its structures straight out of the buffer and
/// requires that alignment, and the plain align-1 `include_bytes!`
/// static landed unaligned on the owner host's builds (deterministic
/// per host: every build there failed, every build in the dev
/// container passed — the artifact itself was healthy the whole
/// time). See src/ebpf/embedded.rs for the full hunt record.
pub static LIMITER_ELF: &[u8] = &crate::ebpf::embedded::AlignedElf::new(*include_bytes!(concat!(
    env!("OUT_DIR"),
    "/zelynic-limiter"
)))
.bytes;

/// Minimum allowed rate: 1 KB/s (1000 B/s, decimal SI).
///
/// NIGHT-hunt-5 harmonization: matches `parse_rate`, where 1kb = 1000
/// (decimal SI, the documented contract). The old value 1024 was a
/// binary-unit leftover that rejected the documented minimum input
/// `1kb` (1000 < 1024) — the parser, the guard, and the docs disagreed.
pub const MIN_RATE: u64 = 1000;

/// Maximum allowed rate: 1 TB/s.
///
/// Owner-approved option B (NIGHT-research-1): 8-TbE-class headroom —
/// a decade of margin over shipping NICs — while staying far inside
/// u64 and the BPF refill guard's exact-multiply bound (the
/// cybersecurity-1 fill-detect fix is rate-agnostic: at this ceiling
/// it engages after 200us of idle, and the product bound stays
/// 2 * burst * NS_PER_SEC <= 2e17 at the 100 MB burst clamp).
/// zelynic can enforce up to infinity; use `--force-this` to
/// override.
pub const MAX_RATE: u64 = 1_000_000_000_000;

/// BPF schema version. Must match `SCHEMA_VERSION` in
/// `ebpf/src/bin/limiter.rs`.
///
/// The constant and its full version history live in the schema
/// sibling (split at the NIGHT-private-research-2 v10 bump to hold
/// this file under the 500-LOC owner cap — the history block grows
/// one entry per bump by design); re-exported here so every existing
/// `use types::SCHEMA_VERSION_EXPECTED` import resolves unchanged.
pub use super::schema::SCHEMA_VERSION_EXPECTED;
use crate::ebpf::identity::container::ContainerRef;

/// The burst floor (NIGHT-lts-8): the largest single packet the
/// kernel hands a cgroup_skb hook by default — GSO egress
/// (segmentation happens after the hook) and GRO ingress (merging
/// happens before it) both produce super-packets up to GSO_MAX_SIZE
/// = 64 KiB. A token bucket capped below that can NEVER admit one
/// (tokens never reach the packet's length), so a policed cgroup at
/// a trickle rate under GSO/GRO traffic would bar an entire packet
/// class forever; the floor guarantees every default-kernel packet
/// is admissible once a burst window accumulates. The residual: BIG
/// TCP links (kernel 6.x, opt-in per-link `gro-max-size` above
/// 64 KiB) keep the old physics — an inherent property of any
/// bounded bucket (STABILITY's honest limits), not chased here.
pub const BURST_FLOOR_BYTES: u64 = 65_536;

/// The burst ceiling: 100 MB, the documented policy contract
/// (security-3's userspace half; the BPF side re-clamps at
/// MAX_ENFORCABLE_BURST regardless).
pub const BURST_CEIL_BYTES: u64 = 100_000_000;

/// Hard ceiling a stored `burst_bytes` may carry into the BPF refill
/// math (NIGHT-improve-10 / security-3). Mirror of `MAX_ENFORCABLE_BURST`
/// in `ebpf/src/math.rs` (the enforcement arithmetic, depthbore-1) —
/// the exact mathematical ceiling under
/// which every product the refill can form is representable in u64:
/// `2 * burst * NS_PER_SEC` (the fill-detect threshold) and
/// `tokens + 2 * burst` (worst pre-cap sum). Userspace writes are
/// clamped to 100 MB by `default_burst`, far below this bound — the
/// kernel-side clamp exists for the values no legit writer produces
/// (map corruption, schema drift, raw pin writes). Both sides pin
/// this value in tests; keep them textually in sync when either
/// changes.
pub const MAX_ENFORCABLE_BURST: u64 = u64::MAX / (2 * 1_000_000_000);

// ━━ BPF map value structs (must match the ebpf crate's structs) ━━

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(align(8))]
pub struct PolicyRaw {
    pub rate_bps: u64,
    pub burst_bytes: u64,
    /// The guarantee bracket's floor (NIGHT-improve-40, schema
    /// v24): the per-LEAF guaranteed minimum rate the DRR pool's
    /// epoch allowance never earns below while the pool can cover
    /// the split. 0 = unset — the v23 fair-split arithmetic,
    /// exactly (the zero-sentinel fail-open posture). The BPF-side
    /// twin lives in ebpf/src/math.rs (`Policy::floor_bps`).
    pub floor_bps: u64,
    /// The guarantee bracket's ceiling (NIGHT-improve-40, schema
    /// v24): the per-LEAF maximum rate — the allowance and the
    /// stockpile cap lower to the ceiling's own quantum, and the
    /// cap binds even a lone drawer. 0 = unset. The BPF-side twin
    /// lives in ebpf/src/math.rs (`Policy::ceil_bps`).
    pub ceil_bps: u64,
    pub group_id: u32,
    /// The policy flag bits (charger-core-3b, schema v15): the
    /// v2 layout's offset-20 padding, now at offset 36 after the
    /// v24 pair (size 40) — bit 0 = per-socket enforcement. Every
    /// userspace write sets it explicitly; the BPF-side twin and
    /// the bit constant live in ebpf/src/math.rs
    /// (`POLICY_FLAG_PER_SOCKET`).
    pub flags: u32,
}

unsafe impl aya::Pod for PolicyRaw {}

/// Policy flag bit 0 (charger-core-3b, schema v15): enforce per
/// SOCKET — every connection its own bucket at the policy rate (the
/// cgroup total is bounded by rate x concurrent sockets, not by
/// rate). The BPF-side twin lives in ebpf/src/math.rs; both trees
/// pin the bit value in tests.
pub const POLICY_FLAG_PER_SOCKET: u32 = 1 << 0;

/// The time-window side-map row (night-during, schema v23 — the
/// unified --during): userspace mirror of `PolicyWindow` in
/// ebpf/src/during.rs (the layout contract the PolicyRaw family
/// owns, one map family over). One row per resolved policy root,
/// shared by both direction hooks; written by the apply family
/// beside the policy legs (`--during X` writes X, an apply without
/// `--during` removes any existing entry — the improve-29 law one
/// level up), removed by the unstrict/reclaim sweep with the legs.
///
/// SPAN rows set `start_mono_ns`/`end_mono_ns` (wall instants
/// PRE-TRANSLATED to the monotonic clock at apply time — the
/// drift-free shape; meaningless across a reboot, which is why the
/// persistence pair serializes the WALL form instead); DAILY rows
/// set `start_s`/`end_s` (seconds-of-day UTC, wrapping midnight
/// when start > end). `kind` values are the `WINDOW_KIND_*`
/// constants; `reserved` is the explicit zero pad so every byte of
/// the 32-byte row is written by construction.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(align(8))]
pub struct PolicyWindowRaw {
    pub kind: u32,
    /// Explicit zero pad (never read): keeps all 32 bytes
    /// initialized for the Pod contract.
    pub reserved: u32,
    /// SPAN: inclusive start, monotonic ns. DAILY: unused (zero).
    pub start_mono_ns: u64,
    /// SPAN: exclusive end, monotonic ns. DAILY: unused (zero).
    pub end_mono_ns: u64,
    /// DAILY: window start, seconds-of-day UTC (inclusive). SPAN:
    /// unused (zero).
    pub start_s: u32,
    /// DAILY: window end, seconds-of-day UTC (exclusive). SPAN:
    /// unused (zero).
    pub end_s: u32,
}

unsafe impl aya::Pod for PolicyWindowRaw {}

/// Window kind: an absolute monotonic span (the duration and date
/// grammar). The BPF-side twin lives in ebpf/src/during.rs; both
/// trees pin the value in tests.
pub const WINDOW_KIND_SPAN: u32 = 0;

/// Window kind: a recurring daily window in seconds-of-day UTC
/// (read-side belt: rows older builds wrote — the flag's window
/// form is gone, a state file still restores them verbatim). The
/// BPF-side twin lives in ebpf/src/during.rs; both trees pin the
/// value in tests.
pub const WINDOW_KIND_DAILY: u32 = 1;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[repr(align(8))]
// Userspace mirror of the BPF token-bucket map value. Production
// never constructs a value (buckets are kernel-internal state), but
// the type carries two contracts: the schema-layout pin (size/field
// assertions below guard drift against `struct Bucket` in
// ebpf/src/bin/limiter.rs) and the key type of the unstrict/recover
// reclaim path (NIGHT-improve-10), which deletes stale per-cgroup
// entries so the 1024-slot bucket maps never fill with dead state.
#[allow(dead_code)]
pub struct BucketRaw {
    pub tokens: u64,
    pub last_refill_ns: u64,
    pub frac_rem: u64,
}

unsafe impl aya::Pod for BucketRaw {}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[repr(align(8))]
pub struct LimiterStatsRaw {
    pub packets_allowed: u64,
    pub packets_dropped: u64,
    pub bytes_allowed: u64,
    pub bytes_dropped: u64,
}

unsafe impl aya::Pod for LimiterStatsRaw {}

// ━━ High-level API types ━━

/// The strict-multi group-id derivation (NIGHT-master-3 hardening).
///
/// The former derivation — `pid*1000 + nanos%1000` — had a
/// STRUCTURED collision: two invocations collide exactly when pid
/// space wraps back to a live group's creator pid AND the 1/1000
/// nanos residue matches; a collision makes two groups share ONE
/// bucket (over-admission against the lower group's intent), and
/// the pid cycle on a long-lived host is hours-to-days. The fix
/// mixes the same inputs through a splitmix64-style avalanche so
/// input changes spread across the full u32 space (same-pid pairs
/// now collide at ~2^-32, not 1/1000), and the one zero result maps
/// away from the individual-bucket sentinel (group_id == 0, the
/// math.rs layout contract). Pure so the spread contracts are pinned.
pub(crate) fn group_id_from(pid: u32, nanos: u64) -> u32 {
    let mut z = (u64::from(pid) << 32) ^ nanos;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    let mixed = (z ^ (z >> 31)) as u32;
    if mixed == 0 {
        1
    } else {
        mixed
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RateSpec {
    pub download: Option<u64>,
    pub upload: Option<u64>,
}

/// One direction's guarantee bracket (improve-40-b, riding schema
/// v24's per-row fields): the (floor, ceil) pair a single
/// direction's rows carry — the same zero-sentinel posture the
/// one-flag law set (0 = unset, the fail-open v23 arithmetic).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BracketPair {
    /// The per-LEAF guaranteed minimum rate. 0 = unset.
    pub floor_bps: u64,
    /// The per-LEAF maximum rate. 0 = unset.
    pub ceil_bps: u64,
}

impl BracketPair {
    /// The unset pair: both sides the zero sentinel.
    pub const UNSET: BracketPair = BracketPair {
        floor_bps: 0,
        ceil_bps: 0,
    };

    /// True when neither side is set (the zero-sentinel row).
    pub fn is_unset(&self) -> bool {
        self.floor_bps == 0 && self.ceil_bps == 0
    }
}

/// The per-direction guarantee bracket (improve-40-b): one pair per
/// direction, the way `RateSpec` carries one rate per direction —
/// the row's own fields worn per leg (the schema needs no bump:
/// v24 already stores floor_bps/ceil_bps on every direction row;
/// the one-flag `--floor 100kb` sets BOTH pairs, the per-direction
/// spellings (`--floor-download`, ...) set one).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BracketSpec {
    /// The download rows' pair.
    pub download: BracketPair,
    /// The upload rows' pair.
    pub upload: BracketPair,
}

impl BracketSpec {
    /// The all-unset bracket — the block family's permanent unset
    /// (a rate-0 row never carries a bracket).
    pub const UNSET: BracketSpec = BracketSpec {
        download: BracketPair::UNSET,
        upload: BracketPair::UNSET,
    };
}

#[derive(Debug, Clone)]
pub enum Target {
    CgroupId(u32),
    ProcessName(String),
    /// A container reference (charger-core-2, TIER A #5):
    /// `docker://<name>` / `k8s://<ns>/<pod>` — resolved to the
    /// workload's cgroup id by identity::container; every
    /// downstream surface is the strict-single machinery.
    Container(ContainerRef),
}

impl Target {
    /// Parse a target token: a bare numeric string (`73386`) is a
    /// cgroup ID, anything else a process name for the /proc walk.
    ///
    /// NIGHT-boost-37: the canonical display prefix round-trips —
    /// every output surface (the status table's rows, eagle-eyes'
    /// footer, the policy trace lines, the `unstrict` echo) prints
    /// cgroups as `cg:48181`, and the eagle-eyes footer's actionable
    /// line suggests exactly `sudo zelynic ss cg:48181 100kb` when
    /// the top consumer's identity is unresolved. `Target::parse`
    /// must accept what those surfaces print: a `cg:` prefix over
    /// a numeric remainder resolves to the same direct ID as the
    /// bare form (no /proc walk — the suggestion could never match
    /// a process named "cg:48181", which made the suggested command
    /// a guaranteed no-op, the owner's fatal find). A non-numeric
    /// remainder keeps the whole string as a process name, so a
    /// typo like `cg:brave` stays the graceful no-match it always
    /// was — the prefix never silently rewrites a name target.
    pub fn parse(s: &str) -> Self {
        if let Some(c) = crate::ebpf::identity::container::parse_container(s) {
            return Target::Container(c);
        }
        let id_part = s.strip_prefix("cg:").unwrap_or(s);
        if let Ok(id) = id_part.parse::<u32>() {
            Target::CgroupId(id)
        } else {
            Target::ProcessName(s.to_string())
        }
    }

    /// The display label every surface prints for a target: the
    /// canonical `cg:` prefix, the process name, or the container
    /// URI (round-trips through parse, charger-core-2).
    pub fn label(&self) -> String {
        match self {
            Target::CgroupId(id) => format!("cg:{id}"),
            Target::ProcessName(name) => name.clone(),
            Target::Container(c) => c.display(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Download,
    Upload,
}

impl Direction {
    pub fn suffix(&self) -> &'static str {
        match self {
            Direction::Download => "dl",
            Direction::Upload => "ul",
        }
    }

    /// Human-readable direction name for the verbose trace surface
    /// (NIGHT-hunt-9): `suffix()` is the BPF map-name fragment
    /// ("dl"/"ul"); this is the full word the diagnostic lines print.
    pub fn label(&self) -> &'static str {
        match self {
            Direction::Download => "download",
            Direction::Upload => "upload",
        }
    }

    /// The other direction (NIGHT-hunt-Z7, the dual-limit hardening):
    /// the probe's counter-direction — the lane its own TCP
    /// acknowledgments ride, the first suspect when a policed flow
    /// starves.
    pub fn opposite(&self) -> Self {
        match self {
            Direction::Download => Direction::Upload,
            Direction::Upload => Direction::Download,
        }
    }
}

// NIGHT-hunt-17: pins live under the single test/ tree, #[path]-wired
// across trees (cosmostrix Pattern C) — moved out of the inline test
// module at charger-core-3b (the flags field grew the file past the
// 500-LOC owner cap; the pins themselves are unchanged).
#[cfg(test)]
#[path = "../../../test/ebpf/limiter/types_tests.rs"]
mod types_tests;
