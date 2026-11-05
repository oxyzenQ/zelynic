// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The `--depth` traffic focus window (split from the depth handler
//! at night-netrunner-4's 600-LOC law — the pure-move discipline the
//! render tree's splits rode): attach, measure, close, and the
//! FocusMeasure the report composes from.

use std::collections::HashMap;
use std::time::Duration;

use crate::ebpf::bypass::{self, ShadowAudit};
use crate::ebpf::connections::ConnectionMap;
use crate::ebpf::loader::{CgroupDelta, Observer, SocketBytes};

/// The focus window's measured result (NIGHT-private-research-3):
/// the closing poll's per-cgroup deltas (the kernel's window totals)
/// plus the per-socket cookie join keyed by the closing census's
/// cookies — the two inputs [`traffic_focus`] composes per target.
/// The bypass audit (charger-core-1-a) rides along unconditionally:
/// the window's interface-vs-hooks shadow verdict.
pub(crate) struct FocusMeasure {
    pub(crate) deltas: Vec<CgroupDelta>,
    pub(crate) socket_bytes: HashMap<u64, SocketBytes>,
    /// The TCP deep windows across the measured span
    /// (night-netrunner-4): the walk-to-walk fold the two census
    /// refreshes own — the handler's pre-window refresh seeds the
    /// baseline generation, the closing refresh folds the window —
    /// so the depth report's retrans share covers exactly the
    /// window the traffic section measures. Empty when neither walk
    /// resolved TCP samples (the honest absence everywhere).
    pub(crate) deep_windows: HashMap<u64, crate::ebpf::connections::TcpDeepWindow>,
    pub(crate) shadow: ShadowAudit,
}

/// Run the network-traffic focus window (NIGHT-private-research-3,
/// the think-like-light-years-3 ability): attach an observer, seed
/// the delta baseline, let `focus_secs` pass, close the window with
/// a second poll, and join the BPF per-socket cookie maps onto the
/// post-window census — the exact machinery the live monitor runs
/// per frame (NIGHT-boost-26), composed once for the one-shot
/// report instead.
///
/// The `conns` census is refreshed at window END (the sockets alive
/// NOW are the rows the report lists and the join keys on); a failed
/// window leaves the caller's baseline census untouched.
///
/// Best-effort by contract, honest about every failure: the return
/// carries the measurement OR the one-line reason it could not run
/// (observer attach refused, a map read failed) — the report renders
/// the basic socket census plus the reason, never a fabricated
/// zero-traffic window (the hunt-22 honest-read discipline). A quiet
/// window (zero deltas) is a MEASUREMENT, not a failure — it
/// composes a zero-total focus that renders the no-traffic verdict.
pub(crate) fn run_focus_window(
    conns: &mut ConnectionMap,
    focus_secs: u64,
) -> (Option<FocusMeasure>, Option<String>) {
    // The loading indicator (night-dragon-maintenance-4): one announce
    // line used to be all the window said before going silent for the
    // whole capture; the spinner ticks live elapsed/total on stderr
    // (inert when piped) and Drop erases its line on every exit path.
    let _window_spinner =
        crate::output::Spinner::start("capturing traffic window".to_string(), focus_secs);
    crate::output::verbose::vlog!(
        "eagle-eyes",
        "traffic focus: attaching observer for a {focus_secs}s window"
    );
    let mut observer = match Observer::attach() {
        Ok(o) => o,
        Err(e) => return (None, Some(format!("observer attach failed: {e}"))),
    };
    // The baseline poll seeds the per-cgroup delta baseline; its own
    // summary is discarded on purpose (bytes between attach and the
    // window start stay out of the ledger — the same horizon
    // contract the live monitor's opening poll owns).
    if let Err(e) = observer.poll_and_summarize() {
        return (None, Some(format!("baseline poll failed: {e}")));
    }
    // Bypass audit baseline (charger-core-1-a): the interface snapshot
    // brackets the window the BPF polls measure — like spans compare.
    let nic_start = bypass::nic_totals();
    std::thread::sleep(Duration::from_secs(focus_secs));
    let summary = match observer.poll_and_summarize() {
        Ok(s) => s,
        Err(e) => return (None, Some(format!("focus poll failed: {e}"))),
    };
    let nic_end = bypass::nic_totals();
    // Fresh census at window end: the closing join keys on exactly
    // the sockets alive NOW (a socket that died mid-window keeps its
    // bytes in the kernel totals but leaves the attribution — both
    // numbers stay true, they answer different questions).
    conns.refresh();
    let cookies = conns.socket_cookies();
    let mut socket_bytes = HashMap::new();
    if !cookies.is_empty() {
        // An Err folds an empty join: the window totals stay (kernel
        // truth), the endpoint figures degrade to honest absence —
        // the one-frame-tolerance contract the live join carries.
        if let Ok(bytes) = observer.socket_bytes(&cookies) {
            socket_bytes = bytes;
        }
    }
    // The deep window fold (night-netrunner-4): the closing
    // refresh just computed closing-minus-baseline over the walk's
    // own TCP cookie set — clone it for the report before the
    // observer detaches (the map itself is the conns map's, the
    // caller's borrow continues below).
    let deep_windows = conns.deep_window().clone();
    observer.detach();
    let bpf_tx = summary.total_bytes;
    let bpf_rx = summary.total_ingress_bytes;
    let shadow = bypass::shadow_audit(nic_start, nic_end, bpf_tx, bpf_rx, focus_secs);
    (
        Some(FocusMeasure {
            shadow,
            deltas: summary.cgroups,
            socket_bytes,
            deep_windows,
        }),
        None,
    )
}
