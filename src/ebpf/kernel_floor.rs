// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The kernel release floor (night-netrunner-1) — the oldest kernel
//! zelynic supports, enforced identically in every build shape.
//!
//! 5.15.0 is the documented minimum — BTF, ringbuf, and the modern
//! eBPF helper set the three quota-saver lanes ride (bpf_link 5.7+,
//! BPF_ATOMIC 5.12+, bpf_skb_ecn_set_ce 5.1+) are all fully mature
//! there, and 5.15 LTS is the oldest line the verified matrix still
//! covers. Kernels below the floor are refused at attach and flagged
//! by the doctor; nothing is conditionally degraded.
//!
//! This module is deliberately NOT gated behind the `ebpf` feature:
//! the doctor (a half-life build's main surface) rides the same pure
//! law the full-life attach paths refuse on — one floor, one message,
//! every shape (`bpf_syscall`, the syscall lanes it once lived in, is
//! ebpf-gated and cannot serve the half-life doctor).

/// The kernel release floor: the oldest kernel zelynic supports.
pub const KERNEL_FLOOR: (u32, u32) = (5, 15);

/// Kernel release string ("6.8.0-45-generic") for the verbose trace
/// surface and the floor law (NIGHT-boost-6): the release decides
/// bpf_link support, verifier features, and the cgroup v2 shape — a
/// bug report that opens with it needs no follow-up uname. Lives here
/// (ungated) because the half-life doctor reads it for the floor
/// verdict; bpf_syscall re-exports for its syscall-lane callers.
/// ebpf-gated like its full-life consumers (the trace lines and the
/// attach gate) — a half-life build never calls it.
#[cfg(feature = "ebpf")]
pub fn kernel_release() -> String {
    nix::sys::utsname::uname()
        .map(|u| u.release().to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Parse a kernel release string into a comparable (major, minor)
/// tuple. Handles the shapes real distros ship: "5.15.0-52-generic",
/// "6.8.0-45", "6.12.27-2-cachyos". Returns None on an unparsable
/// release (the verdict then reports honestly that it cannot judge —
/// never guesses). Pure so the floor law is unit-pinned.
pub fn parse_kernel_release(release: &str) -> Option<(u32, u32)> {
    let first = release.split(['-', '+']).next()?;
    let mut parts = first.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// The floor verdict for one release string: Ok(()) at or above the
/// floor, Err(actionable message) below it or when the release cannot
/// be judged. Pure — the Orchestra consumes it through
/// [`crate::ebpf::host_caps::HostCaps::probe`] (the one probe, every
/// attach decision; the pre-orchestra live gate fn retired with the
/// re-derivations it served).
pub fn kernel_floor_error(release: &str) -> Result<(), String> {
    match parse_kernel_release(release) {
        Some((major, minor)) if (major, minor) >= KERNEL_FLOOR => Ok(()),
        Some((major, minor)) => Err(format!(
            "kernel {major}.{minor} is below zelynic's minimum {}.{} — the eBPF \
             surfaces zelynic rides (BTF, ringbuf, the modern helper set) need \
             5.15.0 or newer. Upgrade the kernel (any current LTS qualifies) and \
             re-run this command",
            KERNEL_FLOOR.0, KERNEL_FLOOR.1
        )),
        None => Err(format!(
            "kernel release {release:?} cannot be parsed (wanted major.minor) — \
             zelynic cannot verify the {}.{} floor here; upgrade to 5.15.0 or \
             newer and re-run this command",
            KERNEL_FLOOR.0, KERNEL_FLOOR.1
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_handles_the_distro_release_shapes() {
        assert_eq!(parse_kernel_release("5.15.0-52-generic"), Some((5, 15)));
        assert_eq!(parse_kernel_release("6.8.0-45"), Some((6, 8)));
        assert_eq!(parse_kernel_release("6.12.27-2-cachyos"), Some((6, 12)));
        assert_eq!(parse_kernel_release("5.10"), Some((5, 10)));
        // The garbage shapes a /proc/sys/kernel/osrelease can carry:
        // an honest None, never a guessed tuple.
        assert_eq!(parse_kernel_release("unknown"), None);
        assert_eq!(parse_kernel_release(""), None);
        assert_eq!(parse_kernel_release("x.y.z"), None);
    }

    #[test]
    fn floor_law_passes_at_and_above_5_15() {
        assert!(kernel_floor_error("5.15.0-52-generic").is_ok());
        assert!(kernel_floor_error("5.15.0").is_ok());
        assert!(kernel_floor_error("5.16.7-arch1").is_ok());
        assert!(kernel_floor_error("6.1.0-13-amd64").is_ok());
        assert!(kernel_floor_error("6.8.0-45-generic").is_ok());
        assert!(kernel_floor_error("7.0.0-0620-generic").is_ok());
    }

    #[test]
    fn floor_law_refuses_below_5_15_with_the_actionable_fix() {
        for release in ["5.13.0-52-generic", "5.10.0-21-amd64", "5.4.0-42-generic"] {
            let err =
                kernel_floor_error(release).expect_err("below-floor releases must be refused");
            assert!(
                err.contains("below zelynic's minimum 5.15"),
                "the refusal must name the floor: {err}"
            );
            assert!(
                err.contains("Upgrade the kernel"),
                "the refusal must name the fix: {err}"
            );
        }
    }

    #[test]
    fn unparsable_release_is_refused_not_guessed() {
        let err = kernel_floor_error("unknown").expect_err("an unparsable release must be refused");
        assert!(err.contains("cannot be parsed"), "{err}");
        assert!(err.contains("5.15.0"), "{err}");
    }

    #[test]
    fn floor_constant_is_the_documented_minimum() {
        assert_eq!(KERNEL_FLOOR, (5, 15));
    }
}
