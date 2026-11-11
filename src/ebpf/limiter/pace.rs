// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The pacing userspace half (night-spark-5, schema v27 — Egress
//! Socket Pacing, the quota saver's Layer 3): the loader's fourth
//! attach lane.
//!
//! The kernel half (ebpf/src/pace_flow.rs) primes a SOCKET-LOCAL
//! hint on the egress policed path since night-T-4's schema v32 —
//! the sk-storage row hanging off the kernel's own struct sock,
//! value = upload rate + the MMSPA generation — and the sock_ops
//! program reads it back at the connection callbacks to pin
//! SO_MAX_PACING_RATE. The v27-era removal sweep is GONE: the row
//! carries the generation it was primed under and the callback's
//! belt answers the default pacing on the first callback after any
//! policy mutation retires it — the invalidation the whole-map
//! flush used to run now rides the mmspa_generation word the
//! mutation tail already bumps (ebpf/src/pace_flow.rs's header
//! carries the full migration record). Sockets' own deaths garbage
//! collect the rows; userspace never reads one.
//!
//! The attach half (attach_pace_lane) is the loader's FOURTH
//! program/link pair: the sock_ops pacing program loads, pins, and
//! attaches at the cgroup root beside the two enforcement hooks and
//! the RECWN twin — the recwn twin's own shape, one call site in
//! mod.rs. One attach strategy since the night-netrunner-1 floor
//! (5.15.0): bpf_link's create-and-pin, the link pin's removal
//! detaching in-kernel — the legacy ProgAttach shape is gone with
//! the pre-5.7 kernels it served.

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::programs::SockOps;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd};

use crate::ebpf::bpf_syscall::{
    BPF_CGROUP_SOCK_OPS, create_and_pin_link, load_with_verifier_verdict,
};
use crate::ebpf::pin::{PIN_LINK_PACE, PIN_PROG_PACE};

/// Load, pin, and attach the pacing sock_ops program (the loader's
/// fourth lane — the recwn twin's own shape, one call site in mod.rs).
/// The cgroup root file opens here so the call site stays one line.
/// The attach strategy is bpf_link's create-and-pin (the link pin's
/// removal detaches in-kernel — the unstrict contract); the legacy
/// ProgAttach + take_link + forget shape is gone with the pre-5.7
/// kernels it served (night-netrunner-1's 5.15.0 floor). A FREE
/// function, not a Limiter method: the attach
/// lane runs before any Limiter instance exists (the fire-and-forget
/// architecture — attach() drops the object before any write lane
/// runs), exactly the shape the recwn twin's inline lane rode inside
/// mod.rs.
pub(super) fn attach_pace_lane(bpf: &mut Ebpf) -> Result<()> {
    let prog: &mut SockOps = bpf
        .program_mut("zelynic_pace")
        .context(
            "BPF program 'zelynic_pace' not found — the embedded object \n             predates the pacing lane (schema v27); run \n             ./scripts/release/refresh-prebuilt.sh and rebuild",
        )?
        .try_into()?;
    load_with_verifier_verdict(|| prog.load(), "zelynic_pace")?;
    prog.pin(PIN_PROG_PACE)
        .context("Failed to pin zelynic_pace")?;
    let cgroup_file =
        File::open("/sys/fs/cgroup").context("Failed to open cgroup root directory")?;
    let prog_raw = prog
        .fd()
        .context("Failed to get zelynic_pace fd")?
        .as_fd()
        .as_raw_fd();
    create_and_pin_link(
        prog_raw,
        cgroup_file.as_raw_fd(),
        BPF_CGROUP_SOCK_OPS,
        PIN_LINK_PACE,
    )
    .context("Failed to create + pin zelynic_pace link")?;
    Ok(())
}
