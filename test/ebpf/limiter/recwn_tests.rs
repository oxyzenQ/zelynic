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
    layer1_window, measured_window_bytes, target_window_bytes,
};

/// The owner's own matrix, the task brief's arithmetic verbatim:
/// target_window = (rate_bytes_per_sec * rtt_us) / 1_000_000,
/// clamped to [2 x MSS, 1 MiB], 50 ms assumed RTT.
#[test]
fn owner_matrix_reads_its_exact_windows() {
    // 1 kb/s x 200 ms = 200 B -> the 2 x MSS floor (2920 B): a
    // sub-two-segment window would invite delayed-ACK stall
    // pathologies, so the clamp lifts it.
    assert_eq!(layer1_window(1_000), RECWN_WINDOW_MIN_BYTES);
    // 100 kb/s x 200 ms = 20_000 B — the delivery-cadence estimate
    // the live E2E evidence set (recwn.rs's doc owns the record),
    // in-band exactly.
    assert_eq!(layer1_window(100_000), 20_000);
    // 1 mb/s x 200 ms = 200 KB — in-band.
    assert_eq!(layer1_window(1_000_000), 200_000);
    // 0 (the block verdict) reads as the floor — though the prime
    // lane never carries it there (enforce returns before the
    // prime site on rate 0; the law documents the shape anyway).
    assert_eq!(layer1_window(0), RECWN_WINDOW_MIN_BYTES);
    // The extremes: 8 mb/s x 200 ms = 1.6 MB -> the 1 MiB ceiling
    // (over-buffering guard); 40 mb/s lands deeper into it.
    assert_eq!(layer1_window(8_000_000), RECWN_WINDOW_MAX_BYTES);
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
    // Just inside the floor (14_600 B/s x 200 ms = 2920) and just
    // below it (14_599 -> 2919.8 -> 2919 -> clamped up).
    assert_eq!(layer1_window(14_600), 2920);
    assert_eq!(layer1_window(14_599), 2920);
    // Just below the ceiling (5_242_880 B/s x 200 ms = 1_048_576)
    // and just above it.
    assert_eq!(layer1_window(5_242_880), 1_048_576);
    assert_eq!(layer1_window(5_242_881), 1_048_576);
}

/// The RTT is a parameter: a longer estimate widens the window
/// linearly inside the band, and the default is the 50 ms constant
/// the whole lane carries.
#[test]
fn rtt_is_a_parameter_with_the_documented_default() {
    assert_eq!(RECWN_DEFAULT_RTT_US, 200_000);
    // 100 kb/s at 20 ms -> 2000 B -> floored; at 50 ms -> 5000 (the
    // briefed estimate's own window); at 100 ms -> 10_000 — linear
    // in the estimate, band intact.
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
        14_599,
        14_600,
        100_000,
        1_000_000,
        5_242_880,
        5_242_881,
        8_000_000,
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
        recwn_lane(&[(7, pol(100_000))], &[], false),
        RecwnLane {
            planted: false,
            window_bytes: None,
            binding_policies: 1,
            measured_srtt_us: None,
        }
    );

    // The owner's single-policy scenario: 100 kb/s -> 20_000 B.
    assert_eq!(
        recwn_lane(&[(7, pol(100_000))], &[], true),
        RecwnLane {
            planted: true,
            window_bytes: Some(20_000),
            binding_policies: 1,
            measured_srtt_us: None,
        }
    );

    // Multi-policy: the BINDING (minimum) window wins.
    let multi = recwn_lane(&[(7, pol(1_000_000)), (9, pol(100_000))], &[], true);
    assert_eq!(multi.window_bytes, Some(20_000));
    // night-ux-1: the count names the unit the clamp binds — both
    // active policies, the human line's "across 2 download policies".
    assert_eq!(multi.binding_policies, 2);

    // Block-only (rate 0) and upload-only census: no window shaped.
    assert_eq!(recwn_lane(&[(7, pol(0))], &[], true).window_bytes, None);
    assert_eq!(recwn_lane(&[], &[], true).window_bytes, None);
}

/// The measured-RTT retune (night-T-3, schema v31): the runtime law
/// extends the window above the cadence floor ONLY where the
/// socket's own srtt runs longer than the band. Every sub-floor
/// measurement — every short link, and every unmeasured socket
/// (the sock_ops srtt_us field reads zero before the first sample)
/// — answers the exact v25 derivation byte for byte: the retune
/// can only extend the pipe, never shrink it (the 50 ms brief's
/// own under-delivery regression, held off by law).
#[test]
fn measured_rtt_retune_only_extends_above_the_cadence_floor() {
    // The floor identity: at and below the cadence floor — a zero
    // srtt (the unmeasured socket), a 50 ms srtt (the briefed
    // guess), and the floor itself — the law IS layer1_window at
    // every rate in the matrix.
    let rates = [0u64, 1_000, 14_599, 100_000, 1_000_000, 5_242_880, u64::MAX];
    for rate in rates {
        assert_eq!(
            measured_window_bytes(rate, 0),
            layer1_window(rate),
            "an unmeasured socket must answer the exact v25 window at rate {rate}"
        );
        assert_eq!(
            measured_window_bytes(rate, 50_000),
            layer1_window(rate),
            "a sub-floor srtt must answer the exact v25 window at rate {rate}"
        );
        assert_eq!(
            measured_window_bytes(rate, RECWN_DEFAULT_RTT_US),
            layer1_window(rate),
            "the floor boundary is the identity at rate {rate}"
        );
    }

    // The brief's own regression, held off by law: 100 kb/s at a
    // measured 20 ms answers the 20_000 B floor derivation, never
    // the 2_000 B pure-BDP shape the E2E legs measured delivering
    // 29-37% of budget.
    assert_eq!(measured_window_bytes(100_000, 20_000), 20_000);

    // A link longer than the band derives its true pipe: a 600 ms
    // satellite path on 100 kb/s = 60_000 B — 3x the floor window,
    // in-band; 1 mb/s at 600 ms = 600 KB, in-band.
    assert_eq!(measured_window_bytes(100_000, 600_000), 60_000);
    assert_eq!(measured_window_bytes(1_000_000, 600_000), 600_000);

    // The band still binds both edges at long RTT: 1 kb/s at 600 ms
    // = 600 B -> the 2 x MSS floor (a 1 kb/s policy must not stall
    // the handshake); 8 mb/s at 600 ms = 4.8 MB -> the 1 MiB
    // ceiling (the bufferbloat guard); and the u32-saturated srtt
    // (u32::MAX >> 3 = 536_870_911 us, ~9 min of pathological RTT)
    // collapses into the ceiling too — never a wrap.
    assert_eq!(
        measured_window_bytes(1_000, 600_000),
        RECWN_WINDOW_MIN_BYTES
    );
    assert_eq!(
        measured_window_bytes(8_000_000, 600_000),
        RECWN_WINDOW_MAX_BYTES
    );
    assert_eq!(
        measured_window_bytes(100_000, u32::MAX >> 3),
        RECWN_WINDOW_MAX_BYTES
    );
}

/// The measured twin's parity contract (night-verify-final, schema
/// v33): the userspace status derivation (src/ebpf/display.rs
/// recwn_measured_window_bytes — the number the status surfaces fold
/// into window_bytes) must agree with the kernel core's
/// measured_window_bytes at EVERY (rate, srtt) pair in the matrix —
/// the same twin discipline the floor derivation pins one test up. A
/// drift here means the reported window lies about the one the
/// datapath derives from the socket's own samples.
#[test]
fn userspace_measured_twin_agrees_with_the_kernel_core() {
    let rates = [0u64, 1_000, 14_599, 100_000, 1_000_000, 5_242_880, u64::MAX];
    let srtts = [
        0u32,
        1,
        50_000,
        199_999,
        200_000,
        200_001,
        300_104,
        600_000,
        u32::MAX >> 3,
    ];
    for rate in rates {
        for srtt in srtts {
            assert_eq!(
                crate::ebpf::display::recwn_measured_window_bytes(rate, srtt),
                measured_window_bytes(rate, srtt),
                "the measured twin drifted from the kernel core at rate {rate} B/s, srtt {srtt} us"
            );
        }
    }
}

/// The stats-row ratchet the status reads (night-verify-final,
/// schema v33): a policy whose row carries a high-water above the
/// cadence floor derives the measured extension — the binding window
/// AND its own rtt reported together, one policy's pair; an
/// unmeasured row (zero, the birth state) or a missing one answers
/// the exact floor derivation with the field honestly absent; a
/// sub-floor sample is real data, not absence — the floor still
/// binds and the sample still reports.
#[test]
fn recwn_lane_folds_the_measured_ratchet_into_the_binding_window() {
    use crate::ebpf::display::recwn_lane;
    use crate::ebpf::limiter::types::{LimiterStatsRaw, PolicyRaw};

    let pol = |rate: u64| PolicyRaw {
        rate_bps: rate,
        burst_bytes: 65_536,
        floor_bps: 0,
        ceil_bps: 0,
        group_id: 0,
        flags: 0,
    };
    let stats_row = |srtt: u64| LimiterStatsRaw {
        packets_allowed: 0,
        packets_dropped: 0,
        bytes_allowed: 0,
        bytes_dropped: 0,
        ce_marked_packets: 0,
        ce_marked_bytes: 0,
        bytes_saved_by_edt: 0,
        bytes_saved_by_ecn: 0,
        measured_srtt_us: srtt,
    };

    // The measured extension: 100 kb/s at the verify workflow's leg-B
    // srtt (300_104 us) derives 30_010 B — the pipe the floor
    // under-admitted — and reports the rtt beside it.
    let measured = recwn_lane(&[(7, pol(100_000))], &[(7, stats_row(300_104))], true);
    assert_eq!(measured.window_bytes, Some(30_010));
    assert_eq!(measured.measured_srtt_us, Some(300_104));

    // An unmeasured row (the birth state) rides the floor exactly.
    let floor = recwn_lane(&[(7, pol(100_000))], &[(7, stats_row(0))], true);
    assert_eq!(floor.window_bytes, Some(20_000));
    assert_eq!(floor.measured_srtt_us, None);

    // A stats row missing entirely (no policed packet yet) — the
    // same honest floor shape.
    let absent = recwn_lane(&[(7, pol(100_000))], &[], true);
    assert_eq!(absent.window_bytes, Some(20_000));
    assert_eq!(absent.measured_srtt_us, None);

    // A sub-floor sample is real data, not absence: 100 kb/s at the
    // leg-A srtt (56_398 us) keeps the 20_000 B floor window and
    // reports the sample beside it — the floor still binds, the
    // measurement is still true.
    let sub = recwn_lane(&[(7, pol(100_000))], &[(7, stats_row(56_398))], true);
    assert_eq!(sub.window_bytes, Some(20_000));
    assert_eq!(sub.measured_srtt_us, Some(56_398));

    // The binding window's own rtt wins the report: two policies,
    // the 1 mb/s one measured long (extending to 400_000 B) and the
    // 100 kb/s one unmeasured (the 20_000 B floor) — the 100 kb/s
    // floor binds the minimum, and the reported srtt is ITS absence,
    // never the other policy's measurement.
    let mixed = recwn_lane(
        &[(7, pol(1_000_000)), (9, pol(100_000))],
        &[(7, stats_row(400_000))],
        true,
    );
    assert_eq!(mixed.window_bytes, Some(20_000));
    assert_eq!(mixed.measured_srtt_us, None);
}
