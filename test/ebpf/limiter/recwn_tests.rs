// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! night-spark-2 (RECWN — Receive Window Control, Layer 1 of the
//! quota saver): precision pins for the receive-window law
//! (ebpf/src/recwn.rs — the same file the BPF object builds).
//! Before this harness the window arithmetic was provable only
//! through root-run integration; these pins make the quota saver's
//! spine testable rootlessly, the NIGHT-depthbore-1 math_tests
//! discipline applied one lane over.
//!
//! Every pin maps to a documented contract:
//!
//!  * the owner's task matrix — 1 kb, 100 kb, 1 mb, 0, and the
//!    extremes — reads its exact clamped window;
//!  * the two clamp edges — a window below 2 x MSS lifts to the
//!    floor (a 1 kb/s policy must not stall the handshake), a
//!    window above 1 MiB sinks to the ceiling (no over-buffering);
//!  * the saturating posture — a hostile rate above u64's product
//!    band clamps instead of wrapping;
//!  * the RTT assumption is a parameter, so a different estimate
//!    reshapes the window linearly inside the band;
//!  * the twin parity — the userspace status derivation
//!    (src/ebpf/display.rs recwn_window_bytes, the twin this
//!    status surface reports) must agree with the kernel core at
//!    EVERY rate in the matrix, the default_burst twin discipline.

// The production law itself, compiled into this test module: the
// SAME file the BPF object builds (ebpf/src/bin/limiter.rs wires
// it with its own #[path]). Only the test tree reaches across
// trees — src/ wirings stay under test/ (the gate-tree discipline).
#[path = "../../../ebpf/src/recwn.rs"]
pub(super) mod ebpf_recwn;

use self::ebpf_recwn::{
    RECWN_DEFAULT_RTT_US, RECWN_MSS_ASSUME_BYTES, RECWN_WINDOW_MAX_BYTES, RECWN_WINDOW_MIN_BYTES,
    layer1_window, target_window_bytes,
};

/// The owner's own matrix, the task brief's arithmetic verbatim:
/// target_window = (rate_bytes_per_sec * rtt_us) / 1_000_000,
/// clamped to [2 x MSS, 1 MiB], 50 ms assumed RTT.
#[test]
fn owner_matrix_reads_its_exact_windows() {
    // 1 kb/s x 50 ms = 50 B -> the 2 x MSS floor (2920 B): a
    // sub-two-segment window would invite delayed-ACK stall
    // pathologies, so the clamp lifts it.
    assert_eq!(layer1_window(1_000), RECWN_WINDOW_MIN_BYTES);
    // 100 kb/s x 50 ms = 5000 B — the owner's brief's own example
    // band, in-band exactly.
    assert_eq!(layer1_window(100_000), 5000);
    // 1 mb/s x 50 ms = 50 KB — in-band.
    assert_eq!(layer1_window(1_000_000), 50_000);
    // 0 (the block verdict) reads as the floor — though the prime
    // lane never carries it there (enforce returns before the
    // prime site on rate 0; the law documents the shape anyway).
    assert_eq!(layer1_window(0), RECWN_WINDOW_MIN_BYTES);
    // The extremes: 8 mb/s x 50 ms = 400 KB, in-band; 40 mb/s x
    // 50 ms = 2 MB -> the 1 MiB ceiling (over-buffering guard).
    assert_eq!(layer1_window(8_000_000), 400_000);
    assert_eq!(layer1_window(40_000_000), RECWN_WINDOW_MAX_BYTES);
    // u64::MAX saturates the product before the divide, lands above
    // the ceiling, clamps back down — never wraps.
    assert_eq!(layer1_window(u64::MAX), RECWN_WINDOW_MAX_BYTES);
}

/// The clamp band's own edges: the floor is exactly 2 x the
/// canonical MSS, the ceiling exactly 1 MiB, and the raw product
/// straddles both cleanly.
#[test]
fn clamp_band_edges_are_pinned() {
    assert_eq!(RECWN_WINDOW_MIN_BYTES, 2 * RECWN_MSS_ASSUME_BYTES);
    assert_eq!(RECWN_WINDOW_MIN_BYTES, 2920);
    assert_eq!(RECWN_WINDOW_MAX_BYTES, 1_048_576);
    // Just inside the floor (58_400 B/s x 50 ms = 2920) and just
    // below it (58_399 -> 2919.95 -> 2919 -> clamped up).
    assert_eq!(layer1_window(58_400), 2920);
    assert_eq!(layer1_window(58_399), 2920);
    // Just below the ceiling (20_971_520 B/s x 50 ms = 1_048_576)
    // and just above it.
    assert_eq!(layer1_window(20_971_520), 1_048_576);
    assert_eq!(layer1_window(20_971_521), 1_048_576);
}

/// The RTT is a parameter: a longer estimate widens the window
/// linearly inside the band, and the default is the 50 ms constant
/// the whole lane carries.
#[test]
fn rtt_is_a_parameter_with_the_documented_default() {
    assert_eq!(RECWN_DEFAULT_RTT_US, 50_000);
    // 100 kb/s at 20 ms -> 2000 B -> floored; at 50 ms -> 5000; at
    // 100 ms -> 10_000 — linear in the estimate, band intact.
    assert_eq!(target_window_bytes(100_000, 20_000), RECWN_WINDOW_MIN_BYTES);
    assert_eq!(target_window_bytes(100_000, 50_000), 5000);
    assert_eq!(target_window_bytes(100_000, 100_000), 10_000);
    // A zero RTT collapses to the floor (the degenerate estimate
    // cannot stall the lane — the floor is the answer).
    assert_eq!(target_window_bytes(100_000, 0), RECWN_WINDOW_MIN_BYTES);
}

/// The twin-parity contract: the userspace status derivation
/// (src/ebpf/display.rs recwn_window_bytes — the number
/// `status --print-json` reports as window_bytes) must agree with
/// the kernel core's layer1_window at EVERY rate, the
/// default_burst twin discipline one lane over. A drift here means
/// the reported window lies about the one the datapath primes.
#[test]
fn userspace_status_twin_agrees_with_the_kernel_core() {
    let rates = [
        0u64,
        1,
        1_000,
        58_399,
        58_400,
        100_000,
        1_000_000,
        8_000_000,
        20_971_520,
        40_000_000,
        u64::MAX,
    ];
    for rate in rates {
        assert_eq!(
            crate::ebpf::display::recwn_window_bytes(rate),
            layer1_window(rate),
            "the userspace twin drifted from the kernel core at rate {rate} B/s"
        );
    }
}

/// The binding-window derivation the status surfaces report: the
/// minimum across active download policies (the single-policy case
/// reads exactly that policy's window; a multi-policy tree reports
/// the tightest clamp), and block rows (rate 0) shape no window.
#[test]
fn recwn_lane_reports_the_binding_window() {
    use crate::ebpf::display::{RecwnLane, recwn_lane};
    use crate::ebpf::limiter::types::PolicyRaw;

    let pol = |rate: u64| PolicyRaw {
        rate_bps: rate,
        burst_bytes: 65_536,
        floor_bps: 0,
        ceil_bps: 0,
        group_id: 0,
        flags: 0,
    };

    // Not planted: no window, no lane at all.
    assert_eq!(
        recwn_lane(&[(7, pol(100_000))], false),
        RecwnLane {
            planted: false,
            window_bytes: None,
        }
    );

    // The owner's single-policy scenario: 100 kb/s -> 5000 B.
    assert_eq!(
        recwn_lane(&[(7, pol(100_000))], true),
        RecwnLane {
            planted: true,
            window_bytes: Some(5000),
        }
    );

    // Multi-policy: the BINDING (minimum) window wins.
    assert_eq!(
        recwn_lane(&[(7, pol(1_000_000)), (9, pol(100_000))], true).window_bytes,
        Some(5000),
    );

    // Block-only (rate 0) and upload-only census: no window shaped.
    assert_eq!(recwn_lane(&[(7, pol(0))], true).window_bytes, None);
    assert_eq!(recwn_lane(&[], true).window_bytes, None);
}
