// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// The zelynic time-window core (night-during, schema v23): the pure
// verdict arithmetic behind the unified --during flag, extracted the
// math.rs/ecn.rs/quic.rs way — zero aya/eBPF dependencies so the
// SAME file compiles into the kernel object (ebpf/src/bin/limiter.rs
// wires it with #[path]) AND into the userspace test tree
// (test/ebpf/limiter/during_tests.rs), where the laws are pinned
// rootlessly.
//
// THE PROBLEM, stated honestly. A limit today is forever until
// somebody remembers to lift it: the maintenance-window shape
// (shape the backup job for two hours, leave the weekend clean),
// the bedtime shape (block the shorts app at night, unblock it
// manually three times a week), and the trial shape (limit the
// game for twenty days, then forget) all want the ROW to carry its
// own lifetime — applied once, enforced for the promised span, and
// expired by the KERNEL itself with no resident process (the
// pinned bpf_links ARE the daemon; the design brief,
// docs/research/NIGHT_PRIVATE_RESEARCH_4_TIME_WINDOWED_POLICIES_
// DESIGN.md section 8, is the decision record).
//
// THE GRAMMAR the owner approved, then REVISED to one shape
// (night-during-7): the CLI's --during takes a duration only —
// s m h d mn y, 1s floor, 10y ceiling (the CLI parses, this
// core never sees a string). The window and date shapes the
// first decision carried are GONE from the flag (refused at
// parse time, the wording naming the shape that replaced them)
// but NOT from this core: the verdict below still honors every
// kind a pinned row may carry — a DAILY row written by an older
// build keeps its hours, a dormant future span keeps sleeping —
// because a grammar change must never narrow a map (the
// read-side belt). The restore lane re-translates both shapes
// out of a state file's wall form, so the kinds remain
// reachable, just not creatable from the flag.
//
// THE TWO STORAGE SHAPES, and why they differ. A SPAN (the
// duration the flag writes, and the restore lane's re-translated
// wall deadlines) has absolute ends, so userspace pre-translates
// its wall instants into the kernel's monotonic clock at apply
// time, and the datapath compares ktime against them directly
// (bpf_ktime_get_ns and the userspace CLOCK_MONOTONIC read are
// the same clock domain, so NTP slew and manual `date -s` cannot
// move a span by a single nanosecond — a hardening over the
// design brief's original one-word sketch; the residue that
// remains is stated: monotonic time does not count suspend, so a
// span on a host that sleeps outlives its wall-calendar promise
// by exactly the slept time).
// A DAILY window recurs forever, so no pre-translation can name
// its next edge; the datapath reads the wall through the offset
// bridge (wall = ktime + wall_minus_mono_ns, a one-entry pinned
// Array userspace re-stamps at every attach and apply — the CLI
// visit IS the refresh channel) and reduces it to seconds-of-day.
// Daily rows ride only builds older than the revision now (the
// flag cannot create them; a state file still restores them).
//
// THE MARGIN LAW (the drift residue, paid honestly). Between CLI
// visits the offset ages: NTP slew is bounded around 500 ppm
// (~43 s/day worst case) and a manual clock step jumps
// arbitrarily, so a daily edge the datapath computes can sit on
// either side of the true edge. The FIRE_EARLY margin below skews
// BOTH edges toward LESS enforcement: the window opens `margin`
// late and closes `margin` early, so a stale offset can
// under-enforce by at most the margin's seconds and never
// over-enforce — the direction a limiter fails safe in. Spans
// carry no margin: their clock is drift-free by construction.
//
// THE VERDICT LAW. A row whose window is INACTIVE answers ALLOW,
// per packet, exactly the unlimited fast path's miss shape — no
// stats booking, no ring booking, no AMMSP belt (the row is not
// being removed, it is simply not policing this packet; the sweep
// through the unstrict/reclaim path is what removes an ENDED span,
// and a DORMANT span or a recurring window is never swept). An
// ABSENT entry is today's behavior exactly: the gate is one map
// read on the policed path only, so the unlimited majority of
// packets pays nothing (the NIGHT-lts-2 law, verbatim).

// ━━ The window row (the shared layout contract) ━━

/// The window kind: an absolute monotonic span (duration and date
/// shapes — start inclusive, end exclusive). The default kind, so a
/// zeroed row is a zero-length span that enforces nothing extra
/// (start == end is the never-active belt for spans too).
pub const WINDOW_KIND_SPAN: u32 = 0;

/// The window kind: a recurring daily window in seconds-of-day UTC
/// (the 09:00-17:00 shape), wrapping midnight when start > end.
pub const WINDOW_KIND_DAILY: u32 = 1;

/// One row's time window, the side-map value keyed at the RESOLVED
/// POLICY ROOT (the same key the policy row and the stats ledger
/// use; one shared map both hooks read, a row's two legs share one
/// window — the design brief section 8.1 dormancy law).
///
/// SPAN rows set `start_mono_ns`/`end_mono_ns` (translated at apply;
/// `start == 0` means "started at apply" and the CLI never writes
/// an empty span — the parse family refuses zero and past-ends).
/// DAILY rows set `start_s`/`end_s` (seconds-of-day, the window
/// `[start_s, end_s)` wrapping when `start_s > end_s`). The unused
/// half stays zero. `reserved` is the explicit zero pad so every
/// byte of the 32-byte row is written by construction (the Pod
/// discipline the implicit-padding layout would violate).
///
/// The userspace twin (`PolicyWindowRaw`, src/ebpf/limiter/types.rs)
/// pins the same size/field offsets in its tests, the PolicyRaw
/// contract one map family over.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(align(8))]
pub struct PolicyWindow {
    /// WINDOW_KIND_SPAN or WINDOW_KIND_DAILY; any other value makes
    /// [`window_active`] answer true (enforce) — an unreadable
    /// window is today's behavior, the absent-entry verdict.
    pub kind: u32,
    /// Explicit zero pad (never read): keeps all 32 bytes
    /// initialized for the userspace Pod twin.
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

// ━━ The margin and the day ━━

/// The both-edges safety margin for DAILY windows (default 2s, the
/// design brief section 3.1's fire-early value): the window opens
/// FIRE_EARLY late and closes FIRE_EARLY early, so a stale offset
/// bridge under-enforces by at most this much and never
/// over-enforces. Spans carry no margin (drift-free by
/// construction). Two seconds, not more: wide enough to cover a
/// day of NTP slew on a disciplined host (well under 500 ppm),
/// narrow enough that a maintenance window's honest edges stay
/// honest.
pub const FIRE_EARLY_NS: u64 = 2_000_000_000;

/// Nanoseconds in one UTC day. The seconds-of-day domain of the
/// DAILY shape lives in [0, 86_400) seconds; the comparator below
/// works in the ns domain so the margin arithmetic stays exact.
pub const NS_PER_DAY: u64 = 86_400 * 1_000_000_000;

// ━━ The verdict ━━

/// Reduce a wall-clock instant to its position in the day (ns).
/// Pure: any u64 input maps into [0, NS_PER_DAY) — a corrupt or
/// stale offset can move a daily window's computed position
/// arbitrarily but can NEVER make this reduction panic, hang, or
/// leave its domain, which is the totality law the datapath needs.
#[inline(always)]
pub fn wall_of_day_ns(wall_ns: u64) -> u64 {
    wall_ns % NS_PER_DAY
}

/// The DAILY comparator with the margin law, the whole design in
/// one arithmetic block. `secs` is the current position in the day
/// (ns); `[start_s, end_s)` is the window in seconds-of-day. The
/// position-relative formulation (`rel` and `len` below) handles
/// the midnight wrap with no case split and makes the margin an
/// exact erosion of m from each edge measured in the WINDOW's own
/// frame:
///
/// * `rel = (secs - start) mod day` — how far into the window the
///   instant sits (wrap-aware by construction),
/// * `len = (end - start) mod day` — the window's true length
///   (nonzero for any parsed window; zero is the never-active
///   belt),
/// * active iff `rel < len` (inside) AND `rel >= m` (the first m
///   of the window is skipped — it opens LATE) AND `len - rel > m`
///   (the last m is skipped — it closes EARLY).
///
/// A window shorter than 2m is fully consumed and never active.
/// The subtraction `len - rel` cannot underflow past zero (rel <
/// len is checked first); the mods are total on u64. Unknown kinds
/// never reach this function (the caller dispatches on kind), but
/// the function stays total for any (secs, start_s, end_s) it is
/// handed — the pin family holds that.
#[inline(always)]
pub fn daily_active(secs: u64, start_s: u32, end_s: u32, margin_ns: u64) -> bool {
    let start = u64::from(start_s).saturating_mul(1_000_000_000);
    let end = u64::from(end_s).saturating_mul(1_000_000_000);
    let len = end.wrapping_sub(start) % NS_PER_DAY;
    if len == 0 {
        // start == end: the parse family refuses it; the belt keeps
        // an ambiguous zero-width window from meaning "all day".
        return false;
    }
    let rel = secs.wrapping_sub(start) % NS_PER_DAY;
    rel < len && rel >= margin_ns && len - rel > margin_ns
}

/// The window verdict for one packet, the whole gate in one call.
///
/// * SPAN: active iff `start_mono_ns <= now_mono_ns <
///   end_mono_ns` — inclusive start, exclusive end, no margin (the
///   monotonic translation is drift-free; a zero-length span is
///   the never-active belt above).
/// * DAILY: the wall is `now_mono_ns + wall_offset_ns`
///   (saturating — a corrupt offset can produce an arbitrary
///   position-in-day but never an overflow panic), reduced to
///   seconds-of-day and compared with the margin law.
/// * Any other kind: TRUE — enforce. An unreadable window is
///   today's behavior exactly (the absent-entry verdict); the
///   feature refines enforcement, never degrades it.
///
/// `wall_offset_ns` is ignored for SPAN rows (the callers pass 0;
/// the parameter rides one signature so the datapath site is a
/// single call).
#[inline(always)]
pub fn window_active(win: &PolicyWindow, now_mono_ns: u64, wall_offset_ns: u64) -> bool {
    match win.kind {
        WINDOW_KIND_DAILY => {
            let wall = now_mono_ns.saturating_add(wall_offset_ns);
            daily_active(wall_of_day_ns(wall), win.start_s, win.end_s, FIRE_EARLY_NS)
        }
        WINDOW_KIND_SPAN => now_mono_ns >= win.start_mono_ns && now_mono_ns < win.end_mono_ns,
        // Unknown kind: enforce — today's behavior exactly (the
        // absent-entry verdict); the feature refines enforcement,
        // never degrades it. Garbage fields under a garbage kind
        // must not get to arbitrate the verdict.
        _ => true,
    }
}

// ━━ The sweep predicates (userspace side of the map) ━━

// The two predicates below are the USERSPACE half's vocabulary: the
// eBPF object's during gate calls window_active only (its try_enforce
// never sweeps — the CLI is the daemon, the sweep rides the unstrict/
// reclaim path), so within the kernel-object compile each function is
// dead code the -D warnings gate would refuse. allow(dead_code) marks
// the split honestly instead of deleting the shared surface: the
// userspace sweep (src/ebpf/limiter/during.rs inlines the same
// arithmetic) and the rootless battery (test/ebpf/limiter/
// during_tests.rs) both pin these laws against THIS file — one copy,
// two trees, the math.rs POLICY_FLAG_PER_SOCKET precedent verbatim.

/// Has a SPAN ended (monotonic `now_mono_ns` at or past its
/// exclusive end)? The sweep predicate: an ended span rides the
/// unstrict/reclaim path; a DAILY window never ends (returns
/// false), and a not-yet-started span returns false too — a
/// dormant row (a future date) must survive every sweep until its
/// day arrives, exactly the dormancy law the design brief pins.
#[allow(dead_code)]
#[inline(always)]
pub fn span_ended(win: &PolicyWindow, now_mono_ns: u64) -> bool {
    win.kind == WINDOW_KIND_SPAN && now_mono_ns >= win.end_mono_ns
}

/// Is a window ACTIVE-BUT-NOT-STARTED (a dormant future span)? The
/// status surface prints it ("sleeps until ..."); the sweep never
/// acts on it (`span_ended` above is the only removal predicate).
#[allow(dead_code)]
#[inline(always)]
pub fn span_dormant(win: &PolicyWindow, now_mono_ns: u64) -> bool {
    win.kind == WINDOW_KIND_SPAN && now_mono_ns < win.start_mono_ns
}
