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
//! terminal stays raw (the classic LF-without-CR staircase).
//!
//! And the monitor holds the real terminal raw on PURPOSE while
//! the command runs (`sudo_term_raw`, sudo's lib/util/term.c: full
//! cfmakeraw, OPOST off — the relay's transparency), saving the
//! pre-run state first and restoring it at exit — with one guard
//! that NIGHT-improve-34 read in the source and the whole lane now
//! leans on: `sudo_term_restore` DECLINES to restore when the
//! terminal was "changed out from under us" (its INPUT/OUTPUT flag
//! masks no longer match the monitor's raw), so any in-flight fix
//! that touches OPOST — exactly what move 2 does — makes the
//! monitor leave the rescue's cooked state in place at exit.
//! A fix that must outlive sudo still has to fire AFTER the
//! monitor exits — for the shapes where nothing tripped the guard
//! (the in-flight apply failed) or there was no restore at all (a
//! monitor killed with its raw still holding the terminal) — but
//! it must fire DISCRIMINATED, never blanket: see move 3.
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
//! 3. RE-APPLY AFTER SUDO — DISCRIMINATED (NIGHT-improve-34, the
//!    re-shape): a bounded orphan child outlives the rescue
//!    process, waits for the sudo monitor to exit, and then READS
//!    the real terminal before touching it. The re-apply fires
//!    ONLY when the output lane is still broken
//!    ([`output_lane_broken`]: OPOST|ONLCR not both set — the
//!    staircase class), and the cure is the OUTPUT LANE ONLY
//!    ([`cure_output_lane`]: OPOST|ONLCR back on, every input,
//!    local, and control flag preserved) plus the non-destructive
//!    restore bytes. The WHY is two findings:
//!    - sudo's own exit-restore usually SKIPS: the monitor saves
//!      the real terminal's termios at start and restores it at
//!      exit, but `sudo_term_restore` (sudo's lib/util/term.c)
//!      declines when the output flags were "changed out from
//!      under us" — and move 2's in-flight apply sets OPOST, so
//!      the guard trips and the rescue's cooked state simply
//!      SURVIVES the monitor's exit. The orphan's cure is the belt
//!      for the shapes where nothing tripped the guard (the
//!      in-flight apply failed) or there was no restore at all (a
//!      monitor killed with its raw still on the terminal).
//!    - by the orphan's turn, the terminal's reader is the user's
//!      SHELL, and an interactive shell's line editor (zsh ZLE,
//!      bash readline) holds the terminal in ITS OWN raw mode —
//!      ICANON|ECHO off with OPOST left ON — managing echo itself.
//!      The improve-31 orphan re-applied the full cooked state
//!      (ICANON|ECHO on, TCSAFLUSH) under that live reader: the
//!      kernel's echo doubled every typed character and the flush
//!      ate queued input — the owner's fresh report (`sudo zelynic
//!      --reset-terminal` on a HEALTHY terminal left typing
//!      garbled: the typed line rendered twice, the prompt
//!      redrawed over it, the right-side prompt arrived without
//!      its left half). The discriminated cure cannot do that by
//!      construction: a healthy output lane means ZERO ioctls and
//!      ZERO bytes (a zle/readline reader is never disturbed), and
//!      a broken output lane gets exactly the two flags every
//!      shell's display needs, never the input flags a live reader
//!      owns. The one residue, documented: a NON-line-editor
//!      reader on a terminal whose input flags a dead monitor left
//!      raw gets the output cure but keeps blind typing — the
//!      plain `zelynic --reset-terminal` (no sudo: no monitor, no
//!      orphan, the classic five layers own the whole terminal)
//!      finishes that job.
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

// ── move 3: the discriminated re-apply after the monitor ────────────

/// The output-lane breakage signature (NIGHT-improve-34): the
/// terminal's output post-processing pair is not fully on. OPOST
/// off is the LF-without-CR staircase — the one flag whose absence
/// breaks EVERY shell's display (zle and readline raw both keep
/// OPOST on; sudo's monitor raw and a cfmakeraw death both clear
/// it), so it is the one honest discriminator between "the monitor
/// left its raw / restored a broken snapshot" and "the rescue's
/// fix survived / the snapshot was healthy": after the monitor
/// exits, an interactive shell may already be mid-prompt in its own
/// raw mode, and only the OUTPUT lane is both universally broken
/// by the monitor's residue and universally safe to cure (no line
/// editor's input contract touches OPOST|ONLCR). ONLCR rides the
/// same mask for the half-cured shape (a `stty -onlcr` residue:
/// OPOST on but newlines column-walk).
pub(crate) fn output_lane_broken(t: &libc::termios) -> bool {
    (t.c_oflag & (libc::OPOST | libc::ONLCR)) != (libc::OPOST | libc::ONLCR)
}

/// The output-lane cure (NIGHT-improve-34): OPOST|ONLCR back on —
/// and NOTHING else. Pure over the struct, so the lane purity is
/// unit-pinned: after the cure, c_iflag, c_lflag, c_cflag, and the
/// c_cc table are byte-identical to before (a live zle/readline
/// reader's input contract is never disturbed — the improve-31
/// orphan's full-cooked re-apply under a live ZLE was the owner's
/// fresh garbled-typing report, the exact regression this split
/// exists to make impossible). The caller applies it TCSANOW — no
/// TCSAFLUSH post-exit, never: the flush would eat whatever the
/// user is typing at the very moment the cure lands.
pub(crate) fn cure_output_lane(t: &mut libc::termios) {
    t.c_oflag |= libc::OPOST | libc::ONLCR;
}

/// The poll slice (ms): fine enough that the re-apply lands within
/// a breath of the monitor's exit, coarse enough that the orphan's
/// CPU footprint rounds to zero (one wakeup every 5 ms, each a
/// single `kill(pid, 0)` liveness probe).
const POLL_SLICE_MS: libc::c_long = 5;

/// The hard poll budget (ms): a healthy sudo monitor exits within
/// milliseconds of the command, so ten seconds is two orders of
/// magnitude of slack — and the one residue the budget accepts is
/// documented: a monitor still alive at the cap gets one
/// discriminated best-effort pass and the orphan exits anyway (a
/// rescue must never leave a process behind; a wedged sudo is a
/// bigger problem than a staircased prompt).
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
/// monitor to exit, then runs the DISCRIMINATED re-apply — twice,
/// settle-gap apart, for the nested-sudo chain — and exits
/// unconditionally at the budget. Each pass READS the real
/// terminal first: an output lane already healthy (the rescue's
/// in-flight fix survived — sudo's exit-restore SKIPS when the
/// output flags were changed out from under it — or the monitor
/// restored a healthy snapshot) means ZERO ioctls and ZERO bytes,
/// because by then the user's shell may be mid-prompt in its own
/// raw mode and only the monitor's OWN residue justifies touching
/// anything; an output lane still broken (the in-flight apply
/// failed, or a killed monitor left its raw holding the terminal)
/// gets the [`output_lane_broken`]/[`cure_output_lane`] pair: the
/// two flags every shell's display needs, TCSANOW (never a flush),
/// plus the non-destructive restore bytes.
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
    // Two settle-gap passes, each DISCRIMINATED (NIGHT-improve-34):
    // read the real terminal's termios first, and let the output
    // lane decide. Healthy (OPOST|ONLCR on — the in-flight fix
    // survived, or the monitor restored a healthy snapshot): touch
    // NOTHING, not one ioctl, not one byte — the user's shell may be
    // mid-prompt in its own raw mode by now, and the improve-31
    // blanket re-apply (full cooked + TCSAFLUSH under that live
    // reader: the kernel's echo doubling every typed character) is
    // the exact regression this discrimination exists to retire.
    // Broken (the monitor's raw still holding, or a restored
    // broken snapshot): the output-lane cure ONLY — the two flags
    // every shell's display needs, never the input/local flags a
    // live line editor owns — applied TCSANOW (a flush would eat
    // the user's in-flight typing), plus the NON-destructive
    // restore bytes (the mode belt, idempotent; never the
    // destructive clear — the shell prompt has drawn by now).
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
                if libc::tcgetattr(fd, &mut t) == 0 && output_lane_broken(&t) {
                    cure_output_lane(&mut t);
                    libc::tcsetattr(fd, libc::TCSANOW, &t);
                    let prev = set_fd_nonblocking(fd);
                    write_fd_best_effort(fd, super::TERMINAL_RESTORE_SEQUENCE.as_bytes());
                    restore_fd_flags(fd, prev);
                }
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
