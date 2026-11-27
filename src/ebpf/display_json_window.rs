// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The limit entry's policy-window JSON object (night-during, schema
//! v23 — the scripting surface; see display_json.rs's WindowJson
//! doc for the wire contract). night-dragon-fly-1 rev 5's
//! visibility pair grew the parent past the 600-LOC owner cap; the
//! window's own file is the split (the display_json_recwn
//! discipline — the parent imports the type and the builder so
//! every existing path rides unchanged).

use crate::ebpf::display_lines::format_duration_compact;
use crate::ebpf::limiter::types::PolicyWindowRaw;
use crate::ebpf::limiter::{format_wall_utc_iso, wall_minus_mono, window_state};
use crate::json::write::{write_number, write_string};

/// One row's window as JSON (night-during, schema v23 — the
/// scripting surface): the kind, the STATE vocabulary the status
/// pins own ("active" / "dormant" / "outside" / "expired"), and
/// the shape's own fields — a span's WALL instants (ns since
/// epoch, reconstructed through the same offset pair the twin
/// uses; the monotonic deadlines a map row carries would be
/// meaningless to a script and across reboots alike), a daily
/// window's seconds-of-day pair.
pub(super) fn window_json(win: &PolicyWindowRaw, wall_now: u64, mono_now: u64) -> WindowJson {
    let offset = wall_minus_mono(wall_now, mono_now);
    let state = window_state(win, wall_now, mono_now);
    match win.kind {
        crate::ebpf::limiter::types::WINDOW_KIND_DAILY => WindowJson {
            kind: "daily",
            state,
            start_wall_ns: None,
            end_wall_ns: None,
            during: None,
            expires_at_utc: None,
            start_s: Some(win.start_s),
            end_s: Some(win.end_s),
        },
        _ => {
            // The rev 5 visibility pair: the remaining lifetime in
            // the flag's own grammar (the snapshot's own instant —
            // the same mono clock the state above judged) and the
            // end instant as ISO-8601 (the readable twin of the
            // wall-ns end). An expired span reads during "0s" — the
            // honest floor, the sweep's pending state the state
            // field already names.
            let end_wall_ns = win.end_mono_ns.saturating_add(offset);
            WindowJson {
                kind: "span",
                state,
                start_wall_ns: Some(win.start_mono_ns.saturating_add(offset)),
                end_wall_ns: Some(end_wall_ns),
                during: Some(format_duration_compact(
                    win.end_mono_ns.saturating_sub(mono_now),
                )),
                expires_at_utc: Some(format_wall_utc_iso(end_wall_ns)),
                start_s: None,
                end_s: None,
            }
        }
    }
}

/// One row's window (see [`LimitEntry::window`] in the parent —
/// the additive-absence law and the pinned field order live there).
#[derive(Debug, Clone)]
pub(super) struct WindowJson {
    /// "span" or "daily".
    pub(super) kind: &'static str,
    /// "active", "dormant", "outside", or "expired" (the state
    /// vocabulary the status pins own).
    pub(super) state: &'static str,
    /// SPAN: inclusive start, wall ns since epoch. DAILY: absent.
    pub(super) start_wall_ns: Option<u64>,
    /// SPAN: exclusive end, wall ns since epoch. DAILY: absent.
    pub(super) end_wall_ns: Option<u64>,
    /// SPAN (night-dragon-fly-1 rev 5): the remaining lifetime in
    /// the flag's own compact grammar, against the snapshot instant
    /// every other clock fact in the document rides (improve-65's
    /// one-snapshot law) — the full duration at apply time, counting
    /// down at every later status read, "0s" once expired. DAILY:
    /// absent (no single expiry exists).
    pub(super) during: Option<String>,
    /// SPAN (night-dragon-fly-1 rev 5): the end instant as ISO-8601
    /// UTC — `jq`'s `fromdateiso8601` parses it directly, no custom
    /// recipe (the wall-ns pair above stays the machine-precise
    /// form; this is the readable echo of the same instant). DAILY:
    /// absent.
    pub(super) expires_at_utc: Option<String>,
    /// DAILY: window start, seconds-of-day UTC. SPAN: absent.
    pub(super) start_s: Option<u32>,
    /// DAILY: window end, seconds-of-day UTC. SPAN: absent.
    pub(super) end_s: Option<u32>,
}

impl WindowJson {
    pub(super) fn write_json(&self, out: &mut String) {
        out.push_str("{\"kind\":");
        write_string(out, self.kind);
        out.push_str(",\"state\":");
        write_string(out, self.state);
        // SPAN rides the wall instants, DAILY the seconds-of-day —
        // the other pair is honestly absent (the derive's
        // Option::is_none branches).
        if let Some(start) = self.start_wall_ns {
            out.push_str(",\"start_wall_ns\":");
            write_number(out, start);
        }
        if let Some(end) = self.end_wall_ns {
            out.push_str(",\"end_wall_ns\":");
            write_number(out, end);
        }
        // The rev 5 visibility pair (the span's own family): the
        // remaining lifetime and the ISO end instant — present only
        // on a span (a daily window has no single expiry; the derive's
        // Option::is_none branch is the absence law).
        if let Some(during) = &self.during {
            out.push_str(",\"during\":");
            write_string(out, during);
        }
        if let Some(expires) = &self.expires_at_utc {
            out.push_str(",\"expires_at_utc\":");
            write_string(out, expires);
        }
        if let Some(start) = self.start_s {
            out.push_str(",\"start_s\":");
            write_number(out, start);
        }
        if let Some(end) = self.end_s {
            out.push_str(",\"end_s\":");
            write_number(out, end);
        }
        out.push('}');
    }
}
