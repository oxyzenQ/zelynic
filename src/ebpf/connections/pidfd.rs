// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The per-PID pidfd state machine (NIGHT-boost-26, split from the
//! parent walk at night-netrunner-4's 600-LOC law — the delta.rs /
//! parse.rs pure-move discipline): cookie discovery and the TCP deep
//! sample ride ONE duplicated foreign fd.
//!
//! Deliberately `Copy` with NO Drop impl, the fd released by the
//! explicit `close()` after each PID's fd scan. The first cut had a
//! Drop impl calling a close() that ASSIGNED `*self = Untried` — the
//! assignment dropped the still-Open old value, whose Drop called
//! close() again: re-entrant drop recursion that overflowed a 2MB
//! test stack in 22ms on the CI runners (invisible locally — no
//! process in the dev container holds a matched socket, so the
//! pidfd never left Untried; the regression pin
//! `pidfd_close_on_open_fd_terminates` reproduces the overflow on
//! the broken shape and holds the fixed contract). A Copy enum with
//! no destructor makes every assignment in close() a plain store —
//! recursion is structurally impossible; the one leaked-fd window
//! (a panic mid-scan unwinding past the explicit close) is the
//! walk's best-effort class, an fd reclaimed at process exit.

use super::TCP_INFO;
use super::types::{Proto, SocketInfo, TcpDeepSample};

/// Per-PID pidfd state for cookie discovery (NIGHT-boost-26): a
/// tri-state so one failed `pidfd_open` (locked-down host, kernel
/// without the syscall) never re-triggers per fd — the PID is
/// cookie-less for the whole scan, the honest graceful degradation.
#[derive(Clone, Copy)]
pub(super) enum PidFd {
    Untried,
    Open(i32),
    Failed,
}

impl PidFd {
    /// Resolve one fd's socket cookie and — for a TCP socket — its
    /// TCP_INFO deep sample (night-netrunner-4), opening the pidfd on
    /// first use. ONE pidfd_getfd duplication serves both reads: the
    /// SO_COOKIE read the walk already paid for, plus (TCP only) the
    /// one extra `getsockopt(TCP_INFO)` the Netrunner-3 audit
    /// measured at ~194 ns. Returns `(cookie, deep)`; either side is
    /// None on its own failure — cookie-less rows render without
    /// byte figures, sample-less rows render without deep figures,
    /// both absences honest (the walk's graceful degradation, never
    /// a fabricated zero).
    pub(super) fn sample_for(
        &mut self,
        pid: u32,
        fd_num: i32,
        proto: Proto,
    ) -> (Option<u64>, Option<TcpDeepSample>) {
        // Open (or remember the failure) exactly once per PID.
        if matches!(self, PidFd::Untried) {
            // SAFETY: SYS_pidfd_open takes the numeric pid and flags
            // — no pointers; the returned fd is this process's own
            // handle or the error the match below consumes.
            *self = match unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0u32) } {
                fd if fd >= 0 => PidFd::Open(fd as i32),
                _ => PidFd::Failed,
            };
        }
        let PidFd::Open(pidfd) = *self else {
            return (None, None);
        };
        // Duplicate the foreign fd into this process, read the
        // cookie (+ the TCP_INFO sample when the socket speaks TCP),
        // close the local copy — the price of the join (there is no
        // other userspace path from an inode or a /proc row to a
        // socket cookie).
        // SAFETY: pidfd is this process's own pidfd handle; the
        // syscall duplicates the foreign descriptor (fd_num) into
        // this process or fails — no pointer arguments, the result
        // is a fresh fd this method owns and closes below.
        let local = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, fd_num, 0u32) };
        if local < 0 {
            return (None, None);
        }
        let mut cookie: u64 = 0;
        let mut len = std::mem::size_of::<u64>() as libc::socklen_t;
        // SAFETY: getsockopt with a writable u64 slot and the exact
        // socklen for it; local is the fresh duplicate fd owned by
        // this method, SO_COOKIE writes at most that size.
        let rc = unsafe {
            libc::getsockopt(
                local as i32,
                libc::SOL_SOCKET,
                libc::SO_COOKIE,
                std::ptr::addr_of_mut!(cookie).cast(),
                &mut len,
            )
        };
        let cookie = if rc == 0 && len as usize == std::mem::size_of::<u64>() {
            Some(cookie)
        } else {
            None
        };
        // The deep sample rides the SAME duplicated fd (the audit's
        // Door 3): only for a TCP-family socket — the walk knows the
        // proto before it samples, so the failing UDP/raw call is
        // never made (audit 4.8.3). A failed read (MPTCP sockets
        // without a classic tcp_sock view, exotic stacks) is the
        // honest None, the same graceful class a refused dup gets.
        let deep = if matches!(proto, Proto::Tcp | Proto::Tcp6) {
            // SAFETY: zeroed() of a plain-old-data libc struct (all
            // fields are integers) — no references, no niches, the
            // exact shape getsockopt(TCP_INFO) fills below.
            let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
            let mut ilen = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
            // SAFETY: getsockopt with a writable tcp_info slot and
            // its exact socklen; local is the duplicate fd owned by
            // this method, TCP_INFO writes at most that size (the
            // kernel trims to its own struct length on older
            // kernels — the zeroed tail stays zero).
            let drc = unsafe {
                libc::getsockopt(
                    local as i32,
                    libc::IPPROTO_TCP,
                    TCP_INFO,
                    std::ptr::addr_of_mut!(info).cast(),
                    &mut ilen,
                )
            };
            let readable = drc == 0
                && ilen as usize >= std::mem::offset_of!(libc::tcp_info, tcpi_segs_out) + 4;
            readable.then_some(TcpDeepSample {
                rtt_us: info.tcpi_rtt,
                rttvar_us: info.tcpi_rttvar,
                total_retrans: info.tcpi_total_retrans,
                segs_out: info.tcpi_segs_out,
            })
        } else {
            None
        };
        // SAFETY: local is the fd this method just duplicated and
        // consumed via getsockopt; closing it releases exactly that
        // handle.
        unsafe { libc::close(local as i32) };
        (cookie, deep)
    }

    /// Release the pidfd, if one was opened.
    pub(super) fn close(&mut self) {
        if let PidFd::Open(fd) = *self {
            // SAFETY: fd is the pidfd this struct opened and owns;
            // the close runs exactly once (Untried resets after).
            unsafe { libc::close(fd) };
        }
        *self = PidFd::Untried;
    }
}

/// Nop re-export guard: the walk's fd-scan consumes exactly this
/// impl (the `SocketInfo` import keeps the module's type contract
/// visible beside the reads that fill it).
#[allow(dead_code)]
fn _contract() -> Option<SocketInfo> {
    None
}

#[cfg(test)]
mod tests {
    use super::PidFd;

    /// Regression pin for the CI stack overflow (the 02284dd
    /// incident): closing a pidfd that holds an OPEN fd must
    /// terminate. The first cut's close() assigned `*self =
    /// PidFd::Untried` while Drop called close() — the assignment
    /// dropped the still-Open old value, whose Drop called close()
    /// again: re-entrant drop recursion, a 2MB stack gone in 22ms on
    /// the CI runners (locally invisible — no process here holds a
    /// matched socket, so the pidfd never left Untried). The Copy
    /// redesign makes the assignment drop nothing; this pin holds
    /// that contract by EXERCISING the close path on an Open fd.
    #[test]
    fn pidfd_close_on_open_fd_terminates() {
        // SAFETY: open(2) of a fixed /dev/null path, read-only — the
        // returned descriptor is this test process's own handle, the
        // exact shape the close path under test owns.
        let devnull = unsafe { libc::open(c"/dev/null".as_ptr().cast(), libc::O_RDONLY) };
        assert!(devnull >= 0, "the pin needs a real fd");
        let mut pidfd = PidFd::Open(devnull);
        pidfd.close();
        assert!(matches!(pidfd, PidFd::Untried));
        // Idempotent: a second close is a no-op.
        pidfd.close();
    }
}
