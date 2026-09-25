// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the interposed-terminal lane of the emergency
//! reset (NIGHT-improve-31, the sudo `use_pty` gap): the discovery
//! that resolves the user's REAL terminal through a /proc fd
//! symlink, and the by-path apply that carries the termios layer
//! to it. Kept in the repo's single test/ tree (cosmostrix
//! Pattern C) and #[path]-wired from src/term_reset/outer.rs.
//!
//! What is pinned, and why each pin earns its place:
//! 1. The discovery discrimination: a candidate is accepted only
//!    when it is a LIVE tty that differs from the caller's own —
//!    the non-interposed sudo (no use_pty) must keep today's
//!    behavior, and a dead pty path or a non-tty fd (a pipe, a
//!    file) must never receive a rescue. The pins drive the pure
//!    resolver against a synthetic /proc root so no sudo and no
//!    live session is needed.
//! 2. The by-path apply, end to end on a real pty pair: a
//!    cfmakeraw-broken slave (the exact breakage class the owner's
//!    staircase screenshot shows — OPOST/ONLCR off, the LF-only
//!    newline) comes back fully cooked after one apply, proved by
//!    reading the termios back through an INDEPENDENT fd on the
//!    same tty (termios is per-terminal, not per-fd — the apply's
//!    own fd closing must not matter).
//! 3. The orphan's bounded budget: the poll slice, the hard cap,
//!    and the settle gap are all bounded and small — a rescue may
//!    never leave a process that spins, lingers, or holds a
//!    terminal hostage (the values are pinned, not just named, so
//!    a future edit that stretches them fails a test instead of
//!    shipping silently).
//!
//! The live sudo mechanics (the fork, the monitor wait, the
//! post-exit re-apply) are the live proof's lane — the guard's
//! precedent (boost-33): a unit harness owns no sudo to fork
//! against, and a synthetic one would pin the mock, not the
//! rescue. The pty precondition is checked LOUDLY below: a
//! pty-less environment fails the pin instead of silently
//! skipping it (a check that silently skips is a check that does
//! not exist).

use super::{apply_rescue_to_path, outer_tty_from_proc, POLL_BUDGET_MS, POLL_SLICE_MS, SETTLE_MS};

/// One allocated pty pair: the master fd plus the slave's device
/// path. The slave is opened separately by each pin (the apply
/// opens it BY PATH — that is the lane being pinned).
struct Pty {
    master: i32,
    slave_path: String,
}

impl Drop for Pty {
    fn drop(&mut self) {
        // SAFETY: close(2) the master — best-effort teardown.
        unsafe { libc::close(self.master) };
    }
}

/// Allocate a fresh pty pair, or fail the pin LOUDLY: these pins
/// exist to prove real termios state transitions, and an
/// environment without a pty allocator (no /dev/ptmx) cannot prove
/// them — a red test beats a green lie.
fn alloc_pty() -> Pty {
    // SAFETY: the posix_openpt/grantpt/unlockpt/ptsname_r dance —
    // the canonical pty allocation sequence, each step checked.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    assert!(master >= 0, "posix_openpt failed — no pty allocator?");
    assert_eq!(unsafe { libc::grantpt(master) }, 0, "grantpt failed");
    assert_eq!(unsafe { libc::unlockpt(master) }, 0, "unlockpt failed");
    let mut buf = [0u8; 64];
    assert_eq!(
        unsafe { libc::ptsname_r(master, buf.as_mut_ptr().cast(), buf.len()) },
        0,
        "ptsname_r failed"
    );
    let path = std::ffi::CStr::from_bytes_until_nul(&buf)
        .expect("ptsname_r output is NUL-terminated")
        .to_string_lossy()
        .into_owned();
    Pty {
        master,
        slave_path: path,
    }
}

/// Open one pty slave by path (O_NOCTTY: a test must never adopt a
/// controlling terminal) and return the raw fd — the caller owns
/// the close.
fn open_slave(path: &str) -> i32 {
    let c_path = std::ffi::CString::new(path).expect("pty paths carry no NUL");
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    assert!(fd >= 0, "opening the pty slave {path} failed");
    fd
}

/// Build a synthetic /proc root: `<root>/<pid>/fd/0` pointing at
/// `target` (a device path or any other string read_link can carry).
fn synthetic_proc(root: &std::path::Path, pid: i32, target: &str) {
    let fd_dir = root.join(pid.to_string()).join("fd");
    std::fs::create_dir_all(&fd_dir).expect("create synthetic fd dir");
    std::os::unix::fs::symlink(target, fd_dir.join("0")).expect("create synthetic fd/0 symlink");
}

// ── pin 1: the discovery discrimination ───────────────────────────────

/// A live, foreign tty IS the outer terminal: the synthetic
/// /proc's fd/0 resolves to a real pty that differs from the
/// caller's own — the interposed-sudo shape (SUDO_PID's fd 0 is
/// the user's real terminal, ours is the throwaway sudo pty).
#[test]
fn discovery_accepts_a_live_foreign_tty() {
    let tmp = std::env::temp_dir().join(format!("zny-outer-pin-{}-a", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("create tmp");
    let pty = alloc_pty();
    synthetic_proc(&tmp, 4242, &pty.slave_path);
    let found = outer_tty_from_proc(&tmp, 4242, Some("/dev/pts/999999"));
    assert_eq!(
        found.as_deref(),
        Some(std::path::Path::new(&pty.slave_path)),
        "a live foreign tty must be discovered as the outer terminal"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// The SAME tty is not interposition: when the candidate names the
/// caller's own terminal (the non-use_pty sudo shape — the
/// monitor's fd 0 IS our fd 0), the discovery declines and the
/// classic five layers stand alone.
#[test]
fn discovery_declines_the_own_terminal() {
    let tmp = std::env::temp_dir().join(format!("zny-outer-pin-{}-b", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("create tmp");
    let pty = alloc_pty();
    synthetic_proc(&tmp, 4242, &pty.slave_path);
    assert!(
        outer_tty_from_proc(&tmp, 4242, Some(&pty.slave_path)).is_none(),
        "the own terminal is not an outer terminal — no interposition"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// No own tty (a redirected stdin and no controlling terminal):
/// the candidate still stands — the rescue owes the REAL terminal
/// its fix even when it cannot name its own throwaway one.
#[test]
fn discovery_accepts_with_no_own_tty() {
    let tmp = std::env::temp_dir().join(format!("zny-outer-pin-{}-c", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("create tmp");
    let pty = alloc_pty();
    synthetic_proc(&tmp, 4242, &pty.slave_path);
    assert!(
        outer_tty_from_proc(&tmp, 4242, None).is_some(),
        "a live tty candidate stands even without an own-tty comparison base"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// A non-tty fd target (a pipe, a file — here /dev/null, the
/// canonical always-open non-tty) is never an outer terminal, and
/// a missing /proc entry simply resolves nothing: both must fall
/// back to the classic behavior, never invent a target.
#[test]
fn discovery_refuses_non_tty_and_missing_entries() {
    let tmp = std::env::temp_dir().join(format!("zny-outer-pin-{}-d", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("create tmp");
    synthetic_proc(&tmp, 4243, "/dev/null");
    assert!(
        outer_tty_from_proc(&tmp, 4243, Some("/dev/pts/999999")).is_none(),
        "a non-tty fd target must never be treated as the outer terminal"
    );
    assert!(
        outer_tty_from_proc(&tmp, 9999, Some("/dev/pts/999999")).is_none(),
        "a missing /proc entry resolves nothing"
    );
    assert!(
        outer_tty_from_proc(&tmp, 0, Some("/dev/pts/999999")).is_none(),
        "a non-positive pid resolves nothing"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

// ── pin 2: the by-path apply, end to end on a real tty ────────────────

/// The owner's live breakage class, reversed by one apply: a
/// cfmakeraw slave (OPOST/ONLCR off — the LF-only staircase;
/// ICANON/ECHO/ISIG off — the dead keyboard; VMIN/VTIME at 0/0 —
/// the busy-poll pair) comes back fully cooked, read through an
/// INDEPENDENT fd so the proof survives the apply's own fd close.
#[test]
fn by_path_apply_cooks_a_cfmakeraw_tty() {
    let pty = alloc_pty();
    let slave = open_slave(&pty.slave_path);

    // Break it exactly the way a violent TUI death leaves a tty.
    let mut broken: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::tcgetattr(slave, &mut broken) }, 0);
    unsafe { libc::cfmakeraw(&mut broken) };
    assert_eq!(unsafe { libc::tcsetattr(slave, libc::TCSANOW, &broken) }, 0);

    // The rescue's by-path apply — the same lane the interposed
    // main pass drives against the real terminal.
    apply_rescue_to_path(std::path::Path::new(&pty.slave_path));

    // Read the state back through the pin's own fd: termios is
    // per-terminal, so this sees the apply's work regardless of
    // which fd carried it.
    let mut after: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::tcgetattr(slave, &mut after) }, 0);
    assert!(
        after.c_oflag & libc::OPOST != 0 && after.c_oflag & libc::ONLCR != 0,
        "output post-processing must be back on (the anti-staircase pair)"
    );
    assert!(
        after.c_lflag & libc::ICANON != 0
            && after.c_lflag & libc::ECHO != 0
            && after.c_lflag & libc::ISIG != 0,
        "the line discipline must be cooked again (canonical, echo, signals)"
    );
    assert_eq!(
        after.c_cc[libc::VMIN],
        1,
        "reads must be blocking again (VMIN=1, the anti-busy-poll)"
    );
    assert_eq!(after.c_cc[libc::VTIME], 0);

    // SAFETY: close(2) the pin's slave fd.
    unsafe { libc::close(slave) };
}

// ── pin 3: the orphan's bounded budget ────────────────────────────────

/// The orphan must be small by construction: a poll slice at least
/// coarse enough to round its CPU cost to zero, a hard budget that
/// no healthy sudo exit can outlast by two orders of magnitude,
/// and a settle gap measured in fractions of a second — a rescue
/// that leaves a process spinning, lingering, or holding a
/// terminal hostage would trade one breakage class for a worse
/// one. The values are pinned so stretching them takes a
/// deliberate, test-breaking edit.
#[test]
fn orphan_budget_stays_bounded_and_small() {
    // black_box: the pin exists to FAIL when the constants change,
    // and clippy would otherwise read it as an always-true assert
    // on a constant (the lint's domain — not this pin's intent).
    let slice = std::hint::black_box(POLL_SLICE_MS);
    let budget = std::hint::black_box(POLL_BUDGET_MS);
    let settle = std::hint::black_box(SETTLE_MS);
    assert!(slice >= 1, "the poll slice must be at least 1 ms");
    assert!(slice <= 50, "the poll slice must stay coarse (no spin)");
    assert!(
        budget >= 1000,
        "the budget must outlast any healthy monitor exit"
    );
    assert!(
        budget <= 10_000,
        "the budget must stay bounded — no lingering rescue process"
    );
    assert!(
        settle <= 1000,
        "the settle gap is a chain-catch, not a wait"
    );
}
