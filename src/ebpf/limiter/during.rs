// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The --during userspace half (night-during, schema v23): the
//! wall-to-monotonic translation the apply path writes and the
//! verdict twin the probe/status surfaces read. The grammar lives
//! in the during_parse sibling (the parse.rs discipline one feature
//! over); the pure verdict arithmetic lives in ebpf/src/during.rs
//! (the kernel object's own file); the map plumbing (the window
//! lanes, the rollback ledger, the sweep, the offset-bridge
//! stamps) lives in the during_map sibling — night-audit-1 task
//! 17's split, the seam the file already wore.
//!
//! The translation (during_to_window): SPAN rows carry wall
//! instants PRE-TRANSLATED into the monotonic clock (a FUTURE
//! start translates forward so the row sleeps until its day; a
//! past start translates backward from the apply instant), so
//! `bpf_ktime_get_ns` decides the verdict with zero drift — NTP
//! slew and a manual `date -s` cannot move it (the stated
//! residue: monotonic does not count suspend, so a sleeping
//! host's span outlives its wall-calendar promise by the slept
//! time). DAILY rows need no translation.
//!
//! The twin (window_active_user): the userspace-side verdict for
//! the probe gate and the status surface — the SAME margin law the
//! kernel comparator applies, evaluated with the true wall the CLI
//! holds (no bridge uncertainty). Pinned against the kernel core
//! by the during_user_tests grid: for any (wall, mono) pair the
//! twin answers exactly what the kernel would with a freshly
//! stamped bridge — the drift-freedom the twin exists to prove.

use super::during_parse::{civil_from_days, DuringSpec, NS_PER_DAY, NS_PER_SEC};
use super::types::{PolicyWindowRaw, WINDOW_KIND_DAILY, WINDOW_KIND_SPAN};

// ━━ The clocks and the translation ━━

/// The wall clock as ns since the Unix epoch (the CLI's own clock
/// read; every translation and stamp flows through here so tests
/// can inject theirs).
pub fn wall_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// The bridge value: wall minus monotonic, the offset the kernel
/// comparator adds to `bpf_ktime_get_ns` (saturating — the wall is
/// ~1.78e18 ns against a boot-fresh mono near zero on any real
/// host; a backwards wall saturates to 0, the under-enforcement
/// direction).
pub fn wall_minus_mono(wall_ns: u64, mono_ns: u64) -> u64 {
    wall_ns.saturating_sub(mono_ns)
}

/// Translate one spec into the side-map row, at the apply instant.
/// SPAN/DURATION: a FUTURE start translates forward
/// (`start_mono = mono + (start_wall - wall)`, the dormancy law —
/// the row sleeps until its day arrives), a PAST start translates
/// backward (`mono - (wall - start_wall)`, saturating — a start
/// before the host booted clamps to "since boot", the span simply
/// already running) and `end_mono = mono + (end_wall - wall)`
/// (never negative: the parse family refuses past ends). DURATION:
/// start is the mono now. DAILY: fields verbatim, no clock.
pub fn during_to_window(spec: &DuringSpec, wall_now_ns: u64, mono_now_ns: u64) -> PolicyWindowRaw {
    let mut row = PolicyWindowRaw::default();
    match spec {
        DuringSpec::Daily { start_s, end_s } => {
            row.kind = WINDOW_KIND_DAILY;
            row.start_s = *start_s;
            row.end_s = *end_s;
        }
        DuringSpec::Span {
            start_wall_ns,
            end_wall_ns,
        } => {
            row.kind = WINDOW_KIND_SPAN;
            row.start_mono_ns = if *start_wall_ns > wall_now_ns {
                // The dormancy law: a future date must sleep until
                // its instant. The naive saturating subtraction
                // collapsed a future start onto the apply instant
                // (over-enforcement, the direction the margin law
                // forbids) — night-audit-1 task 17.
                mono_now_ns.saturating_add(*start_wall_ns - wall_now_ns)
            } else {
                mono_now_ns.saturating_sub(wall_now_ns - *start_wall_ns)
            };
            row.end_mono_ns = mono_now_ns.saturating_add(end_wall_ns.saturating_sub(wall_now_ns));
        }
        DuringSpec::Duration { ns } => {
            row.kind = WINDOW_KIND_SPAN;
            row.start_mono_ns = mono_now_ns;
            row.end_mono_ns = mono_now_ns.saturating_add(*ns);
        }
    }
    row
}

// ━━ The userspace twin (the probe gate / status verdict) ━━

/// The daily comparator's twin: the position-relative formulation
/// with the margin erosion, byte-for-byte the kernel core's law
/// (ebpf/src/during.rs daily_active) — pinned equal by the
/// during_user_tests grid. Private here because the kernel file
/// owns the law's text; this copy exists only because src/ never
/// compiles the ebpf tree (the mirror-types discipline).
fn daily_active_twin(secs: u64, start_s: u32, end_s: u32, margin_ns: u64) -> bool {
    let start = u64::from(start_s).saturating_mul(NS_PER_SEC);
    let end = u64::from(end_s).saturating_mul(NS_PER_SEC);
    let len = end.wrapping_sub(start) % NS_PER_DAY;
    if len == 0 {
        return false;
    }
    let rel = secs.wrapping_sub(start) % NS_PER_DAY;
    rel < len && rel >= margin_ns && len - rel > margin_ns
}

/// The twin of the kernel verdict, evaluated the way the kernel
/// does: the wall is `mono + (wall - mono)` — the same SATURATING
/// offset arithmetic the bridge stamp uses, so the twin answers
/// exactly what the datapath would with a freshly stamped bridge
/// for EVERY (wall, mono) pair, saturation domain included (on any
/// real host wall >> mono and the effective wall IS the true wall;
/// the saturation only bites in synthetic tests, and the grid pin
/// owns the whole domain). The margin is the kernel core's
/// FIRE_EARLY (2s): both edges erode toward less enforcement, so a
/// caller standing down (the probe) or claiming "active" (status)
/// stays on the conservative side of every boundary.
pub fn window_active_user(win: &PolicyWindowRaw, wall_now_ns: u64, mono_now_ns: u64) -> bool {
    match win.kind {
        WINDOW_KIND_DAILY => {
            let effective_wall =
                mono_now_ns.saturating_add(wall_minus_mono(wall_now_ns, mono_now_ns));
            let secs = effective_wall % NS_PER_DAY;
            daily_active_twin(secs, win.start_s, win.end_s, 2 * NS_PER_SEC)
        }
        // SPAN and unknown kinds: the span compare is exact (the
        // monotonic domain holds no drift); unknown kinds enforce,
        // the kernel core's absent-entry verdict.
        _ => mono_now_ns >= win.start_mono_ns && mono_now_ns < win.end_mono_ns,
    }
}

/// Why a window is NOT policing right now (the probe's stand-down
/// note and the status row's lifetime line share it): a dormant
/// future span names its wake instant (translated back to wall
/// through the same offset pair), an ended span names expiry, a
/// daily window names its hours. `None` = active now.
pub fn dormancy_note(win: &PolicyWindowRaw, wall_now_ns: u64, mono_now_ns: u64) -> Option<String> {
    match win.kind {
        WINDOW_KIND_DAILY => {
            if window_active_user(win, wall_now_ns, mono_now_ns) {
                return None;
            }
            Some(format!(
                "outside the daily window {:02}:{:02}-{:02}:{:02} UTC — the row is \
                 not policing this minute",
                win.start_s / 3600,
                (win.start_s / 60) % 60,
                win.end_s / 3600,
                (win.end_s / 60) % 60
            ))
        }
        WINDOW_KIND_SPAN => {
            if mono_now_ns < win.start_mono_ns {
                let wake_wall = win
                    .start_mono_ns
                    .saturating_add(wall_minus_mono(wall_now_ns, mono_now_ns));
                Some(format!(
                    "the window sleeps until {} — the row is not policing yet",
                    format_wall_utc(wake_wall)
                ))
            } else if mono_now_ns >= win.end_mono_ns {
                Some(format!(
                    "the window expired at {} — the row is no longer policing \
                     (awaiting sweep)",
                    format_wall_utc(
                        win.end_mono_ns
                            .saturating_add(wall_minus_mono(wall_now_ns, mono_now_ns))
                    )
                ))
            } else {
                None
            }
        }
        // Unknown kinds enforce (the absent-entry verdict) — no
        // dormancy to name.
        _ => None,
    }
}

/// Wall instant as "YYYY-MM-DD HH:MM:SS UTC" (the CLI's own
/// calendar renderer — no chrono dependency, the Hinnant pair
/// above; pinned on known instants).
pub fn format_wall_utc(wall_ns: u64) -> String {
    let secs = wall_ns / NS_PER_SEC;
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        sod / 3600,
        (sod / 60) % 60,
        sod % 60
    )
}

// ━━ The status classifier + the persistence form ━━

/// The window's current state, the one vocabulary the human table,
/// the JSON document, and the pins share: "active" (policing now),
/// "dormant" (a future span sleeping), "outside" (a daily window
/// between its hours), "expired" (an ended span awaiting the
/// sweep). Unknown kinds are "active" (the absent-entry verdict).
pub fn window_state(win: &PolicyWindowRaw, wall_now_ns: u64, mono_now_ns: u64) -> &'static str {
    match win.kind {
        WINDOW_KIND_SPAN => {
            if mono_now_ns < win.start_mono_ns {
                "dormant"
            } else if mono_now_ns >= win.end_mono_ns {
                "expired"
            } else {
                "active"
            }
        }
        WINDOW_KIND_DAILY => {
            if window_active_user(win, wall_now_ns, mono_now_ns) {
                "active"
            } else {
                "outside"
            }
        }
        _ => "active",
    }
}

/// The WALL-clock persistence form of one window row (the snapshot
/// document's `during` field): a span's monotonic deadlines are
/// meaningless across a reboot (mono resets), so the census
/// serializes the WALL instants (reconstructed through the same
/// offset pair the twin uses) and the daily pair verbatim; the
/// restore re-translates through a fresh bridge. A restored row
/// must never convert "auto-expires" into "forever" — the design
/// brief's safety direction.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct WindowPersist {
    /// "span" or "daily" (the WINDOW_KIND_* twins by name).
    pub kind: String,
    /// SPAN: inclusive start, wall ns since epoch. DAILY: 0.
    pub start_wall_ns: u64,
    /// SPAN: exclusive end, wall ns since epoch. DAILY: 0.
    pub end_wall_ns: u64,
    /// DAILY: window start, seconds-of-day UTC. SPAN: 0.
    pub start_s: u32,
    /// DAILY: window end, seconds-of-day UTC. SPAN: 0.
    pub end_s: u32,
}

/// One row's persistence form (pure): the span's wall instants
/// reconstructed as `mono + (wall - mono)` — the exact inverse of
/// the apply-time translation, the twin's own arithmetic.
pub fn window_persist_form(
    win: &PolicyWindowRaw,
    wall_now_ns: u64,
    mono_now_ns: u64,
) -> WindowPersist {
    let offset = wall_minus_mono(wall_now_ns, mono_now_ns);
    match win.kind {
        WINDOW_KIND_DAILY => WindowPersist {
            kind: "daily".to_string(),
            start_wall_ns: 0,
            end_wall_ns: 0,
            start_s: win.start_s,
            end_s: win.end_s,
        },
        _ => WindowPersist {
            kind: "span".to_string(),
            start_wall_ns: win.start_mono_ns.saturating_add(offset),
            end_wall_ns: win.end_mono_ns.saturating_add(offset),
            start_s: 0,
            end_s: 0,
        },
    }
}

/// The restore half (pure): the persistence form back into the
/// spec the apply family takes — a fresh bridge re-translates the
/// span at the restore instant. A file whose kind is neither name
/// refuses (the state-schema honesty: never a best-guess parse).
pub fn window_persist_to_spec(form: &WindowPersist) -> Option<DuringSpec> {
    match form.kind.as_str() {
        "daily" => Some(DuringSpec::Daily {
            start_s: form.start_s,
            end_s: form.end_s,
        }),
        "span" => Some(DuringSpec::Span {
            start_wall_ns: form.start_wall_ns,
            end_wall_ns: form.end_wall_ns,
        }),
        _ => None,
    }
}

// NIGHT-hunt-17: pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the policy pins.
#[cfg(test)]
#[path = "../../../test/ebpf/limiter/during_user_tests.rs"]
mod during_user_tests;
