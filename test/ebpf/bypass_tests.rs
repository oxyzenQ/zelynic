// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the bypass-shadow audit core (NIGHT-upgrade-charger-core-1-a):
//! the sysfs aggregation seam (a /sys/class/net-shaped fixture, not the
//! host — the same rootless discipline the pin tests carry) and every
//! verdict band the pure constructor owns: healthy windows stay clean,
//! header-scale gaps stay clean, real bypass shapes flag with their
//! side named, and unreadable counters are "unavailable", never a
//! fabricated clean.

use super::*;

use std::fs;
use std::path::PathBuf;

/// Build a /sys/class/net-shaped fixture: one directory per interface
/// with a statistics/ subtree of counter files. Returns the root path
/// (the caller drops it; a tempdir would be cleaner but the stdlib
/// has no owned one, and a fixed subdir under the target-less
/// std::env::temp_dir is the repo's existing fixture pattern).
fn class_net_fixture(ifaces: &[(&str, u64, u64)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "zelynic-bypass-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    for (name, tx, rx) in ifaces {
        let stats = dir.join(name).join("statistics");
        fs::create_dir_all(&stats).expect("fixture dir");
        fs::write(stats.join("tx_bytes"), format!("{tx}\n")).expect("fixture tx");
        fs::write(stats.join("rx_bytes"), format!("{rx}\n")).expect("fixture rx");
    }
    dir
}

/// The aggregate sums every interface, loopback included — its traffic
/// traverses the cgroup hooks on both sides, so it stays comparable.
#[test]
fn nic_totals_sum_every_interface() {
    let dir = class_net_fixture(&[("lo", 100, 100), ("eth0", 1_000, 2_000), ("wlan0", 50, 25)]);
    let totals = nic_totals_from_dir(&dir).expect("the fixture reads");
    assert_eq!(totals.tx_bytes, 1_150);
    assert_eq!(totals.rx_bytes, 2_125);
    fs::remove_dir_all(&dir).ok();
}

/// The counter parser takes the kernel's trailing newline (a fixture
/// without it stays legal too — trim first).
#[test]
fn nic_totals_parse_kernel_counter_shapes() {
    let dir = class_net_fixture(&[("eth0", 18_446_744_073_709_551_615, 0)]);
    let totals = nic_totals_from_dir(&dir).expect("u64::MAX parses");
    assert_eq!(totals.tx_bytes, u64::MAX);
    fs::remove_dir_all(&dir).ok();
}

/// An interface without readable counters fails the WHOLE snapshot
/// (None), never a partial sum — an undercounted aggregate would
/// fabricate exactly the clean verdict the honesty contract bans.
#[test]
fn unreadable_interface_fails_the_whole_snapshot() {
    let dir = class_net_fixture(&[("eth0", 10, 10)]);
    // A counter file with garbage in it.
    fs::write(
        dir.join("eth0").join("statistics").join("tx_bytes"),
        "not-a-number",
    )
    .expect("garbage counter");
    assert!(nic_totals_from_dir(&dir).is_none());
    // A missing counter file is the same honest failure.
    fs::remove_file(dir.join("eth0").join("statistics").join("rx_bytes")).expect("remove rx");
    assert!(nic_totals_from_dir(&dir).is_none());
    fs::remove_dir_all(&dir).ok();
}

/// The healthy window: a ~2% header-scale gap stays clean on both
/// sides (the tx threshold is 25%, the rx threshold 40% — an order of
/// magnitude of margin over the physical bias).
#[test]
fn header_scale_gap_stays_clean() {
    let audit = shadow_audit(
        Some(NicTotals::default()),
        Some(NicTotals {
            tx_bytes: 1_000_000,
            rx_bytes: 1_000_000,
        }),
        980_000,
        960_000,
        3,
    );
    assert!(audit.measured);
    assert_eq!(audit.verdict, ShadowVerdict::Clean);
    assert_eq!(audit.shadow_tx, 20_000);
    assert_eq!(audit.shadow_rx, 40_000);
}

/// The absolute floor: a 2% gap on a 100 KB window is noise-scale and
/// stays clean even though the ratio alone would pass — the floor is
/// what keeps short quiet windows from flagging on rounding.
#[test]
fn small_windows_need_the_absolute_floor() {
    let audit = shadow_audit(
        Some(NicTotals::default()),
        Some(NicTotals {
            tx_bytes: 100_000,
            rx_bytes: 100_000,
        }),
        60_000,
        40_000,
        1,
    );
    assert_eq!(audit.verdict, ShadowVerdict::Clean);
}

/// The motivating shape: a 47x bypass on the tx side flags with the
/// side named — the NIC moved megabytes the hooks never saw.
#[test]
fn bypass_shape_flags_with_its_side() {
    let audit = shadow_audit(
        Some(NicTotals::default()),
        Some(NicTotals {
            tx_bytes: 14_100_000,
            rx_bytes: 100_000,
        }),
        300_000,
        90_000,
        3,
    );
    assert_eq!(audit.verdict, ShadowVerdict::BypassedTx);
    assert_eq!(audit.shadow_tx, 13_800_000);

    let both = shadow_audit(
        Some(NicTotals::default()),
        Some(NicTotals {
            tx_bytes: 20_000_000,
            rx_bytes: 20_000_000,
        }),
        100_000,
        100_000,
        3,
    );
    assert_eq!(both.verdict, ShadowVerdict::BypassedBoth);
}

/// The rx side's looser band: a 30% receive gap (firewall drops,
/// scan noise scale) stays clean where the tx side would flag.
#[test]
fn rx_band_is_looser_than_tx() {
    let audit = shadow_audit(
        Some(NicTotals::default()),
        Some(NicTotals {
            tx_bytes: 10_000_000,
            rx_bytes: 10_000_000,
        }),
        9_900_000,
        6_500_000,
        3,
    );
    assert_eq!(
        audit.verdict,
        ShadowVerdict::Clean,
        "35% rx gap is inside the band"
    );
}

/// The boundary itself: exactly at the floor or exactly at the
/// percent is NOT flagged (strict >), one byte above is.
#[test]
fn thresholds_are_strictly_greater() {
    let at_floor = shadow_audit(
        Some(NicTotals::default()),
        Some(NicTotals {
            tx_bytes: SHADOW_TX_FLOOR_BYTES,
            rx_bytes: 0,
        }),
        0,
        0,
        3,
    );
    assert_eq!(
        at_floor.verdict,
        ShadowVerdict::Clean,
        "exactly the floor is clean"
    );
    let above_floor = shadow_audit(
        Some(NicTotals::default()),
        Some(NicTotals {
            tx_bytes: SHADOW_TX_FLOOR_BYTES + 1,
            rx_bytes: 0,
        }),
        0,
        0,
        3,
    );
    assert_eq!(above_floor.verdict, ShadowVerdict::BypassedTx);
}

/// A measurement skew where BPF counted MORE than the interfaces
/// (snapshots and polls bracketing slightly different spans) reads as
/// zero shadow, never a wrapped "negative" gap.
#[test]
fn bpf_favoring_skew_saturates_to_zero() {
    let audit = shadow_audit(
        Some(NicTotals::default()),
        Some(NicTotals {
            tx_bytes: 100_000,
            rx_bytes: 100_000,
        }),
        100_500,
        200_000,
        3,
    );
    assert_eq!(audit.verdict, ShadowVerdict::Clean);
    assert_eq!(audit.shadow_tx, 0);
    assert_eq!(audit.shadow_rx, 0);
}

/// Wrap-coherent on the interface side (the NIGHT-lts-5 discipline):
/// a u64 counter that wrapped mid-window reads as the true delta.
#[test]
fn interface_counters_wrap_coherently() {
    let start = NicTotals {
        tx_bytes: u64::MAX - 100,
        rx_bytes: 0,
    };
    let end = NicTotals {
        tx_bytes: 50,
        rx_bytes: 0,
    };
    let audit = shadow_audit(Some(start), Some(end), 0, 0, 3);
    assert_eq!(audit.nic_tx, 151, "wrapping delta, not a clamped zero");
}

/// A window that ran against unreadable counters is the named
/// "unavailable" verdict with the BPF totals carried — never a
/// fabricated clean and never a silent drop of the measurement.
#[test]
fn unreadable_counters_are_unavailable() {
    let audit = shadow_audit(
        None,
        Some(NicTotals {
            tx_bytes: 5,
            rx_bytes: 5,
        }),
        1000,
        2000,
        3,
    );
    assert!(!audit.measured);
    assert_eq!(audit.verdict, ShadowVerdict::Unavailable);
    assert_eq!(audit.bpf_tx, 1000, "the hook totals still ride");
}

/// The whole-percent helper: quiet interfaces divide to zero, not by
/// zero.
#[test]
fn shadow_percent_handles_quiet_interfaces() {
    assert_eq!(shadow_percent(0, 0), 0);
    assert_eq!(shadow_percent(250, 1000), 25);
    assert_eq!(shadow_percent(999, 1000), 99, "truncates, never rounds up");
}
