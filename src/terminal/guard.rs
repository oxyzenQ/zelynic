// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The violent-death terminal guard (NIGHT-boost-33): the eagle-eyes
//! monitor's insurance against `kill -9`, `pkill`, and every death
//! that outruns its own Drop.
//!
//! The hazard: the monitor holds the terminal in raw mode, the alt
//! screen, and mouse tracking — all restored by `AltScreen::drop`
//! on every clean exit path (q, sink death, load failure). SIGKILL
//! runs no user code at all, and `pkill zelynic` (SIGTERM) dies in
//! default-action territory the same way: the process vanishes, the
//! terminal stays raw — echo off, ISIG off, the alt screen holding
//! the frame — and the owner types into a box that answers nothing.
//! For a root-held critical-infra tool that is the worst failure
//! shape after the one boost-28 closed: the machine is fine, the
//! enforcement is fine (the pinned maps survive by design, the
//! architecture's fail-safe), but the USER cannot see it.
//!
//! The mitigation is the classic watchdog shape, sized to zero:
//! [`TerminalGuard::arm`] forks a tiny child BEFORE the alt screen
//! takes the terminal (the child's inherited termios IS the shell's
//! canonical state). The child parks in one blocking `read(2)` on a
//! pipe — zero CPU, zero wakeups, no polling, nothing scheduled.
//! The kernel closes the parent's pipe write end the instant the
//! parent dies, ANY way it dies (SIGKILL included — fd teardown is
//! kernel truth, no signal can skip it), and the read returns EOF:
//! the child restores the termios, writes the exact `ALT_EXIT`
//! bytes, and exits. A clean exit tells the child to stand down
//! first (the parent's own Drop already restored), so the two
//! restorations never race.
//!
//! The child survives the very act that killed its parent: its
//! name is deliberately not "zelynic" (`pkill zelynic` must not
//! reach it), and it leaves the process group (`setsid`) so a
//! group kill cannot reach it either. It holds no BPF state, no
//! pins, no maps — enforcement continuity is the architecture's
//! own contract, never the guard's to touch.

use std::os::unix::io::RawFd;

// The restore bytes the guard child writes on a violent death are
// screen.rs's pinned ALT_EXIT — one constant, one contract: the
// guard restores EXACTLY what AltScreen::drop would have, so a
// SIGKILLed monitor leaves the terminal in the same state a `q`
// exit leaves it (mouse modes off, main screen, cursor visible).
use super::screen::ALT_EXIT as RESTORE;

/// The guard child's process name (prctl `PR_SET_NAME`): does NOT
/// contain "zelynic" on purpose — `pkill zelynic` is the owner's
/// own reflex and must never reach the guard (it would kill the
/// one process that exists to clean up). Fits the 15-char comm cap.
const GUARD_NAME: &[u8; 11] = b"zny-tguard\0";

/// The clean-exit byte: the parent's Drop writes it down the pipe
/// after `AltScreen::drop` restored the terminal, and the child
/// stands down without touching the tty — the parent's restore is
/// the authoritative one; a second one would race the shell's
/// prompt.
const CLEAN_EXIT: u8 = b'c';

/// The armed guard. The parent side is pure RAII: Drop writes the
/// clean-exit byte, reaps the child, closes the pipe. Drop ordering
/// matters and is owned by the caller: the [`crate::terminal::Monitor`]
/// field order drops `AltScreen` FIRST, then this guard — by then
/// the terminal is restored and the clean byte stands the child
/// down. The one exception is the open-failure path, where the
/// guard drops alone: [`TerminalGuard::note_alt_live`] is the flag
/// that separates the two.
pub(crate) struct TerminalGuard {
    /// The pipe's write end (the child's EOF sensor).
    write_fd: RawFd,
    /// The child's pid, reaped on Drop.
    child: libc::pid_t,
    /// Whether the alt screen was successfully entered — only then
    /// does the monitor's own Drop restore the terminal (field
    /// order), and only then may the child stand down. On the
    /// open-failure path (AltScreen::enter's error after raw mode
    /// landed, or before it) the child RESTORES: the parent never
    /// got the chance.
    alt_live: bool,
}

impl TerminalGuard {
    /// Arm the guard. MUST be called BEFORE `AltScreen::enter` —
    /// the forked child snapshots the shell's termios, which stops
    /// being the live state the moment raw mode lands. Returns
    /// `None` (and the monitor runs unguarded, exactly the
    /// pre-boost-33 behavior) when the terminal cannot be probed or
    /// the fork cannot be made: the guard is insurance, never a
    /// precondition.
    pub(crate) fn arm() -> Option<Self> {
        // The state to restore: the tty's pre-monitor termios, read
        // through the raw libc surface so the child can apply the
        // same C object it inherited (async-signal-safe after fork).
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: tcgetattr(2) on fd 0 into a valid termios struct.
        if unsafe { libc::tcgetattr(0, &mut original) } != 0 {
            return None;
        }
        let mut fds: [RawFd; 2] = [0; 2];
        // SAFETY: pipe(2) into a valid two-int array.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: fork(2) — one-shot, called before any thread
        // exists (the monitor loop has not started), in a process
        // whose only fds are stdio and the pipe.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            // SAFETY: close(2) both pipe ends on the failed fork.
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return None;
        }
        if pid == 0 {
            // ── the guard child: nothing but syscalls from here ──
            // SAFETY: close(2) the write end — the read end's EOF
            // is the parent-death sensor; keeping the write end
            // open here would deafen it.
            unsafe { libc::close(fds[1]) };
            // SAFETY: setsid(2) — leave the parent's process group
            // so a group kill (kill -9 -PGID) cannot reach the
            // guard. A forked child is never a group leader, so
            // this cannot fail here; a failure is ignored anyway.
            unsafe { libc::setsid() };
            // SAFETY: prctl(2) PR_SET_NAME with a NUL-terminated
            // name — evades `pkill zelynic` (comm match).
            unsafe { libc::prctl(libc::PR_SET_NAME, GUARD_NAME.as_ptr(), 0, 0, 0) };
            let mut byte = [0u8; 1];
            loop {
                // SAFETY: read(2) one byte from the pipe — the
                // park. Zero CPU: the kernel blocks until the byte
                // or the parent's death-closed EOF.
                let n = unsafe { libc::read(fds[0], byte.as_mut_ptr().cast(), 1) };
                if n == 1 {
                    // The parent's Drop spoke: the terminal is
                    // already restored. Stand down.
                    unsafe { libc::_exit(0) };
                }
                if n == 0 {
                    // EOF: the parent died without the clean byte —
                    // SIGKILL, pkill, a crash mid-flight. Restore
                    // exactly what AltScreen::drop would have: the
                    // shell's termios, then the exit bytes. Errors
                    // (a tty already gone) are the parent-of-none's
                    // problem: ignored, straight to exit.
                    // SAFETY: tcsetattr(2) fd 0 TCSANOW; write(2)
                    // the restore bytes to fd 1; _exit(2) — never
                    // return from a forked child.
                    unsafe {
                        libc::tcsetattr(0, libc::TCSANOW, &original);
                        libc::write(1, RESTORE.as_ptr().cast(), RESTORE.len());
                        libc::_exit(0);
                    }
                }
                // n < 0: EINTR retries (signals arrive, the pipe is
                // patient); any other error is the pipe's own death
                // — the guard cannot sense the parent anymore, exit
                // without touching the tty (never fight a monitor
                // that may still be alive).
                // SAFETY: read errno is only consulted by retrying.
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EINTR) {
                    unsafe { libc::_exit(0) };
                }
            }
        }
        // ── the parent: keep only the write end ──
        // SAFETY: close(2) the read end — the parent never reads.
        unsafe { libc::close(fds[0]) };
        Some(TerminalGuard {
            write_fd: fds[1],
            child: pid,
            alt_live: false,
        })
    }

    /// Mark the alt screen live (called right after
    /// `AltScreen::enter` succeeds): from here the monitor's own
    /// Drop owns the restore, and this guard's Drop stands the
    /// child down instead.
    pub(crate) fn note_alt_live(&mut self) {
        self.alt_live = true;
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // The field-order contract: on the monitor path AltScreen's
        // Drop has already restored the terminal (alt_live), so the
        // clean byte stands the child down and the reaping is the
        // whole job. On the open-failure path (alt still down) the
        // parent closes the pipe WITHOUT the byte: the child sees
        // EOF and restores — the parent never got its own chance.
        // A dead child (someone killed the guard) makes the write
        // fail — ignored, the reap still collects it. SIGPIPE is
        // already SIG_IGN in every Rust process, so the write
        // cannot kill this one.
        // SAFETY: write(2) one byte, best-effort (only when the
        // parent restored); waitpid(2) the child (it exits within
        // microseconds of the byte or the EOF); close(2) the end.
        unsafe {
            if self.alt_live {
                let byte = [CLEAN_EXIT];
                libc::write(self.write_fd, byte.as_ptr().cast(), 1);
            }
            libc::waitpid(self.child, std::ptr::null_mut(), 0);
            libc::close(self.write_fd);
        }
    }
}

#[cfg(test)]
// NIGHT-boost-33: the guard's pure pins — the restore bytes and the
// name choice. The fork/pipe/EOF mechanics are the live proof's
// lane (the CI kill-tui battery SIGKILLs a real monitor; a unit
// harness owns no tty to fork against), the guard_tests discipline.
#[path = "../../test/terminal/termguard_tests.rs"]
mod termguard_tests;
