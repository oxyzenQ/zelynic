// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The interposed-terminal lane of the emergency reset
//! (NIGHT-improve-31, the sudo `use_pty` gap): when the rescue runs
//! under sudo's interposed pseudo-terminal, every termios operation
//! the five layers perform lands on the WRONG terminal.
//!
//! The anatomy (the owner's live case: `sudo zelynic
//! --reset-terminal` leaves the screen staircased and misplaced
//! while the same command without sudo recovers it perfectly, and
//! cosmostrix's identical five layers pass only because that run
//! was never under sudo): sudo 1.9.14+ enables `use_pty` by
//! default, so sudo forks a monitor that keeps the USER'S real
//! terminal and allocates a NEW pseudo-terminal pair for the
//! command; the rescue's fd 0 is that interposed pty, not the
//! broken terminal the user is staring at. Layer 1's `tcsetattr`,
//! `stty sane`'s stdin, and `reset`'s termios fiddling all repair
//! the throwaway pty. The escape bytes alone survive — the monitor
//! relays them — which is why the screen looks half-fixed: the
//! emulator-side modes reset, the kernel-side termios of the real
//! terminal stays raw (the classic LF-without-CR staircase). And
//! the deepest trap: the monitor saves the real terminal's termios
//! when IT starts — on the already-broken terminal — and restores
//! that same broken snapshot when the command exits, so even a
//! correct in-flight fix of the real terminal is undone the
//! instant the rescue finishes. A fix that must outlive sudo has
//! to fire AFTER the monitor exits.
//!
//! Three moves close the gap, all root-best-effort (the sudo case
//! is root by construction; a non-root rescue keeps today's
//! behavior exactly — same user, same privilege, no boundary):
//!
//! 1. DISCOVER: the real terminal is the tty held by the sudo
//!    monitor, whose pid sudo reports in `SUDO_PID` — the parent
//!    fallback (euid-gated) covers a stripped-`SUDO_PID` policy
//!    and the plain parent-interposer shapes. A candidate is only
//!    accepted when its `/proc/<pid>/fd/0` resolves, opens, answers
//!    `isatty`, and names a DIFFERENT terminal than our own — the
//!    non-interposed sudo (no `use_pty`) fails that last check and
//!    today's behavior stands unchanged.
//! 2. APPLY DIRECT: the full rescue on the real terminal by path —
//!    the in-process termios restore (TCSAFLUSH, the input-queue
//!    flush the stuck-mode flood needs), both ANSI sequences, and
//!    the external layers with their stdin redirected onto the
//!    real terminal (`stty sane <real>`, `reset <real>`).
//! 3. RE-APPLY AFTER SUDO: a bounded orphan child that outlives
//!    the rescue process, waits for the sudo monitor to exit (the
//!    moment its broken-snapshot restore lands), and re-applies
//!    the termios layer plus the NON-destructive restore bytes to
//!    the real terminal — never the destructive clear, because by
//!    then the user's shell prompt has already drawn and wiping it
//!    would trade a readable staircase for an empty screen. A
//!    settle-gap second pass catches the nested-sudo chain (the
//!    inner monitor restores first, the outer one after).
//!
//! The orphan is the guard's discipline transplanted (boost-33):
//! forked after every other layer, renamed away from "zelynic" so
//! the owner's `pkill zelynic` reflex cannot kill the one process
//! that exists to finish the repair, parked in a bounded poll (no
//! spin: 5 ms slices, a hard 10 s budget), nothing but syscalls
//! after the fork (async-signal-safe — the helpers are the same
//! raw-fd primitives the violent-death guard child uses), and it
//! exits unconditionally at the budget so no rescue ever leaves a
//! lingering process behind.

use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use super::{restore_fd_flags, sane_cooked, set_fd_nonblocking, write_fd_best_effort};

// ── the discovery (pure over /proc, injectable for the pins) ──────────

/// The real terminal under an interposer: its stable path (reopened
/// by every later move — a path is the handle that survives fd
/// churn) plus the interposer pid the orphan waits on.
pub(crate) struct OuterTty {
    /// The terminal device path (e.g. `/dev/pts/3`).
    pub(crate) path: PathBuf,
    /// The pid whose exit the orphan waits for (the sudo monitor).
    sudo_pid: libc::pid_t,
}

/// Resolve one candidate outer terminal: read `/proc/<pid>/fd/0`,
/// open the target, and accept it only when it is a live tty that
/// differs from `own_tty` (the caller's own terminal, when it has
/// one). `proc_root` is injectable so the pins can point it at a
/// synthetic /proc; production passes the real one.
pub(crate) fn outer_tty_from_proc(
    proc_root: &Path,
    pid: libc::pid_t,
    own_tty: Option<&str>,
) -> Option<PathBuf> {
    if pid <= 0 {
        return None;
    }
    let link = proc_root.join(pid.to_string()).join("fd").join("0");
    let target = std::fs::read_link(&link).ok()?;
    // The candidate must be a live terminal: a dead pty path or a
    // non-tty fd (a pipe, a file) fails the open or the isatty
    // probe, and the rescue keeps its classic behavior.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&target)
        .ok()?;
    let fd = file.as_raw_fd();
    if unsafe { libc::isatty(fd) } != 1 {
        return None;
    }
    let name = ttyname_of_fd(fd)?;
    // The one discrimination that matters: under a NON-interposed
    // sudo (no use_pty), the monitor's fd 0 IS our own terminal —
    // same device, nothing to discover, today's five layers
    // already target the right tty.
    if let Some(own) = own_tty {
        if name == own {
            return None;
        }
    }
    Some(target)
}

/// The caller's own terminal name, when there is one: fd 0 when it
/// is the tty, else the controlling terminal via `/dev/tty` (the
/// same fallback shape layer 1 uses for a redirected stdin).
fn own_tty_name() -> Option<String> {
    if let Some(name) = ttyname_of_fd(0) {
        return Some(name);
    }
    if let Ok(tty) = std::fs::File::open("/dev/tty") {
        return ttyname_of_fd(tty.as_raw_fd());
    }
    None
}

/// `ttyname_r` on one fd, as an owned String (an empty or
/// over-long name is a failed probe).
fn ttyname_of_fd(fd: std::os::unix::io::RawFd) -> Option<String> {
    let mut buf = [0u8; 64];
    if unsafe { libc::ttyname_r(fd, buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return None;
    }
    let bytes = buf.split(|&b| b == 0).next()?;
    std::str::from_utf8(bytes).ok().map(str::to_owned)
}

/// Parse `SUDO_PID` (sudo sets it for every command it runs, after
/// any env_reset — only an explicit env_delete strips it, which the
/// parent fallback below then covers).
fn env_sudo_pid() -> Option<libc::pid_t> {
    std::env::var("SUDO_PID")
        .ok()?
        .trim()
        .parse()
        .ok()
        .filter(|&pid| pid > 0)
}

/// The production discovery: `SUDO_PID` first, the parent pid as
/// the euid-gated fallback (sudo with a stripped `SUDO_PID` still
/// interposes with the monitor as our parent; a plain non-root
/// context never walks, so tmux and `script` sessions keep the
/// classic behavior untouched).
pub(crate) fn discover() -> Option<OuterTty> {
    let own = own_tty_name();
    if let Some(pid) = env_sudo_pid() {
        let path = outer_tty_from_proc(Path::new("/proc"), pid, own.as_deref())?;
        return Some(OuterTty {
            path,
            sudo_pid: pid,
        });
    }
    if nix::unistd::geteuid().is_root() {
        let ppid = unsafe { libc::getppid() };
        if ppid > 0 {
            let path = outer_tty_from_proc(Path::new("/proc"), ppid, own.as_deref())?;
            return Some(OuterTty {
                path,
                sudo_pid: ppid,
            });
        }
    }
    None
}

// ── move 2: the direct apply on the real terminal ─────────────────────

/// Apply the rescue's in-process layers to one terminal BY PATH:
/// the termios restore (TCSAFLUSH — the flush drops the stuck-mode
/// input flood queued on the real terminal) plus both ANSI
/// sequences under a temporary O_NONBLOCK (the Termux lesson, same
/// as fd 1 in the parent). This is what the main pass runs against
/// the real terminal when interposition is discovered — the belt
/// for the monitors that do not mirror, and the visible fix for
/// the ones that do until their exit-restore undoes it.
pub(crate) fn apply_rescue_to_path(path: &Path) {
    let Ok(file) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
    else {
        return;
    };
    let fd = file.as_raw_fd();
    let mut buf: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut buf) } == 0 {
        sane_cooked(&mut buf);
        unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &buf) };
    }
    let prev_flags = unsafe { set_fd_nonblocking(fd) };
    unsafe {
        write_fd_best_effort(fd, super::TERMINAL_RESTORE_SEQUENCE.as_bytes());
        write_fd_best_effort(fd, super::TERMINAL_RESET_SEQUENCE.as_bytes());
        restore_fd_flags(fd, prev_flags);
    }
}

// ── move 3: the bounded orphan that outlives the monitor ──────────────

/// The poll slice (ms): fine enough that the re-apply lands within
/// a breath of the monitor's exit, coarse enough that the orphan's
/// CPU footprint rounds to zero (one wakeup every 5 ms, each a
/// single `kill(pid, 0)` liveness probe).
const POLL_SLICE_MS: libc::c_long = 5;

/// The hard poll budget (ms): a healthy sudo monitor exits within
/// milliseconds of the command, so ten seconds is two orders of
/// magnitude of slack — and the one residue the budget accepts is
/// documented: a monitor still alive at the cap gets one
/// best-effort re-apply and the orphan exits anyway (a rescue must
/// never leave a process behind; a wedged sudo is a bigger
/// problem than a staircased prompt).
const POLL_BUDGET_MS: libc::c_long = 10_000;

/// The settle gap (ms) between the orphan's two passes: the
/// nested-sudo chain restores in two waves (inner monitor first,
/// outer after), and one gap catches both without a third pass.
const SETTLE_MS: libc::c_long = 300;

/// The orphan's process name (prctl `PR_SET_NAME`): contains no
/// "zelynic", so `pkill zelynic` — the owner's own reflex — cannot
/// kill the one process finishing the repair (the guard child's
/// rule, boost-33, worn by its rescue twin). Fits the 15-char cap.
const ORPHAN_NAME: &[u8; 11] = b"zny-tresc\0\0";

/// Fork the post-sudo re-applier — the LAST move of the rescue,
/// after every other layer, so the orphan inherits a quiet fd
/// table (it closes stdio itself). The child waits for the sudo
/// monitor to exit (the instant its broken-snapshot termios
/// restore lands on the real terminal), then re-applies the
/// termios layer plus the NON-destructive restore bytes — twice,
/// settle-gap apart, for the nested-sudo chain — and exits
/// unconditionally at the budget.
pub(crate) fn spawn_post_sudo_reapplier(outer: &OuterTty) {
    // Everything the child touches, prepared before the fork:
    // async-signal-safety after fork means no allocation, so the
    // path rides in as a ready CString.
    let Ok(path_c) = std::ffi::CString::new(outer.path.as_os_str().as_encoded_bytes()) else {
        return;
    };
    let sudo_pid = outer.sudo_pid;
    // SAFETY: fork(2) — one-shot, in a single-threaded process
    // (the rescue runs before any thread exists), with only stdio
    // fds open (every layer's Files are closed by their drops).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // No orphan — the direct apply of move 2 already ran; the
        // fix simply will not outlive a monitor exit-restore.
        return;
    }
    if pid != 0 {
        // The parent: the orphan is deliberately NOT reaped — it
        // must outlive this process, so it is reparented to init
        // the moment we exit (the whole point of the move).
        return;
    }
    // ── the orphan child: nothing but syscalls from here ──
    // SAFETY: close(2) the interposed pty's fds — the orphan must
    // not hold the sudo session's terminal open, and nothing it
    // does legitimately touches them again.
    unsafe {
        libc::close(0);
        libc::close(1);
        libc::close(2);
        // setsid(2): leave the doomed session (the monitor's exit
        // takes the pty with it); a forked child is never a group
        // leader, so this cannot fail here.
        libc::setsid();
        // prctl(2) PR_SET_NAME — the anti-pkill rename.
        libc::prctl(libc::PR_SET_NAME, ORPHAN_NAME.as_ptr(), 0, 0, 0);
    }
    // The bounded wait: poll the monitor's liveness. `kill(pid, 0)`
    // answers 0 while it lives; ESRCH means gone (as root no other
    // answer is reachable for a dead userland pid; a REUSED pid
    // answers "alive" and merely burns budget to the same exit).
    let mut waited: libc::c_long = 0;
    // SAFETY: kill(2) liveness probe + nanosleep(2) poll slices.
    unsafe {
        while waited < POLL_BUDGET_MS && libc::kill(sudo_pid, 0) == 0 {
            libc::nanosleep(
                &libc::timespec {
                    tv_sec: 0,
                    tv_nsec: POLL_SLICE_MS * 1_000_000,
                },
                std::ptr::null_mut(),
            );
            waited += POLL_SLICE_MS;
        }
    }
    // Two settle-gap passes: the monitor's exit-restore has landed
    // (or the budget expired and one best-effort pass is owed);
    // the second catches the outer link of a nested-sudo chain.
    // Both passes are the NON-destructive shape only — termios +
    // the restore bytes — because the user's shell prompt has
    // drawn by now and the destructive clear would trade a
    // readable screen for an empty one.
    for pass in 0..2 {
        // SAFETY: open(2) the real terminal WITHOUT acquiring it
        // as a controlling terminal (O_NOCTTY — a setsid child
        // with no ctty would otherwise adopt the user's terminal,
        // exactly what a rescue must never do); the termios ioctl
        // pair and the non-blocking best-effort write are the
        // shared raw-fd helpers; close(2) between the passes keeps
        // the fd table flat.
        unsafe {
            let fd = libc::open(
                path_c.as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            );
            if fd >= 0 {
                let mut t: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(fd, &mut t) == 0 {
                    sane_cooked(&mut t);
                    libc::tcsetattr(fd, libc::TCSAFLUSH, &t);
                }
                let prev = set_fd_nonblocking(fd);
                write_fd_best_effort(fd, super::TERMINAL_RESTORE_SEQUENCE.as_bytes());
                restore_fd_flags(fd, prev);
                libc::close(fd);
            }
        }
        if pass == 0 {
            // SAFETY: nanosleep(2) the settle gap.
            unsafe {
                libc::nanosleep(
                    &libc::timespec {
                        tv_sec: 0,
                        tv_nsec: SETTLE_MS * 1_000_000,
                    },
                    std::ptr::null_mut(),
                );
            }
        }
    }
    // SAFETY: _exit(2) — never return from a forked child, and
    // never run the parent's atexit machinery from this one.
    unsafe { libc::_exit(0) };
}

// NIGHT-improve-31: the discovery and apply pins live under the
// single test/ tree (cosmostrix Pattern C), #[path]-wired exactly
// like the terminal tree's own pins; the fork/poll mechanics are
// the live proof's lane (the guard's precedent — a unit harness
// owns no sudo to fork against).
#[cfg(test)]
#[path = "../../test/terminal/outer_reset_tests.rs"]
mod outer_reset_tests;
