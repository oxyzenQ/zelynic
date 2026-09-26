// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The emergency terminal reset (NIGHT-hunt-31, the cosmostrix
//! `--reset-terminal` skill transfer; hardened in NIGHT-improve-30):
//! the after-the-fact recovery for a terminal left broken by a violent
//! TUI death — the eagle-eyes monitor killed with `kill -9` (or any
//! terminal app that died between enabling a mode and restoring it).
//!
//! The breakage anatomy: the monitor holds the terminal in raw mode,
//! the alt screen, and mouse tracking — all restored by
//! `AltScreen::drop` on every clean exit, and by the violent-death
//! guard (guard.rs, NIGHT-boost-33) when the process dies without
//! running a Drop. The guard is insurance, not a precondition
//! (fail-open by design), and the SGR pen state a mid-frame death
//! leaves behind outlives the alt-screen switch — so the residual
//! holes (guard arm failed, guard child killed, pen linger, a foreign
//! app's modes) need ONE explicit recovery path that works from inside
//! the broken terminal: blind-type `zelynic --reset-terminal`, no
//! re-opening the terminal, no new window.
//!
//! The recovery is defense-in-depth, five layers (the cosmostrix
//! contract, ported to this crate's crossterm-free stack — raw ANSI
//! bytes + termios ioctls + the classic external utilities) — plus
//! the layer-0 interposed-terminal lane (NIGHT-improve-31, the
//! `outer` child module; its re-apply discriminated in
//! NIGHT-improve-34): under sudo's `use_pty` interposition fd 0
//! is a throwaway pty, so the rescue ALSO discovers the user's real
//! terminal through the sudo monitor, applies every layer to it
//! directly, and leaves a bounded orphan that — AFTER the monitor
//! exits — re-applies the fix ONLY when the terminal's output lane
//! is still broken (OPOST|ONLCR not both on: the staircase class),
//! and then only the output lane: the two flags every shell's
//! display needs, never the input flags a live line editor owns.
//! See `term_reset/outer.rs` for the full anatomy, including the
//! sudo-source finding the discrimination leans on (the monitor's
//! own exit-restore SKIPS when the output flags were changed out
//! from under it — which the in-flight apply does on purpose — so
//! the common case needs no post-exit touch at all, and a blanket
//! re-apply would only fight the user's shell).
//!
//! 1. The termios restore, in-process and FIRST (NIGHT-improve-30,
//!    the maturity the first port owed): `tcsetattr` of a sane cooked
//!    state on fd 0, or `/dev/tty` when stdin is redirected — the
//!    crossterm `disable_raw_mode()` slot of the reference, moved to
//!    the front. An ioctl is write-free and always completes (the
//!    guard's own hardening lesson), it is the ONE restore step the
//!    user's shell cannot live without, and with echo back the user
//!    SEES every later layer work. TCSAFLUSH also drops the pending
//!    input queue — a stuck mouse mode may have queued a flood of
//!    report bytes that would otherwise land in the shell as garbage
//!    commands the moment echo returns.
//! 2. The ANSI restore sequence — every optional mode off that a TUI
//!    may have left on (synchronized output 2026, bracketed paste
//!    2004, focus 1004, the full mouse family, alt screen 1049, kitty
//!    keyboard pop) plus the sane-defaults resets (SGR, scroll
//!    region, charset, autowrap, cursor visible).
//! 3. The ANSI reset sequence — the restore plus cursor home, clear
//!    screen, clear scrollback (the destructive layer; wipes the
//!    frozen frame AND the scrollback so the shell starts clean).
//! 4. `stty sane` — the external belt over layer 1 (the full
//!    canonical sane set, including the exotic flags layer 1
//!    deliberately does not guess at).
//! 5. `reset` + `tput reset` — the external full terminal resets
//!    (modes, tab stops, terminal init strings) for systems that
//!    carry them.
//!
//! The ANSI bytes ride fd 1 under a temporary O_NONBLOCK — the Termux
//! screen-lock lesson (the cosmostrix terminal_tty lineage, ported
//! with the guard in NIGHT-hunt-31): when a PTY's reader stops
//! draining, a blocking write parks the rescuer on a full buffer and
//! the rescue never reaches its own later layers. EAGAIN drops bytes
//! (a dropped escape is cosmetic; a wedged rescue is a terminal that
//! never recovers), and the original flags are restored afterward so
//! the shell keeps its blocking semantics. Every layer is best-effort
//! — the goal is maximum recovery probability, not perfection.
//!
//! No privileges required and none asked for: the reset touches only
//! the caller's own terminal (ANSI bytes out, termios via ioctl), and
//! a rescue that demanded root would fail in the one moment it is
//! needed (the broken-terminal user can barely type, let alone
//! authenticate).
//!
//! Module placement: a crate-root module — declared ungated in
//! main.rs, its file at src/term_reset/mod.rs per the src/ root
//! single-file policy (NIGHT-blade-15: src/ root holds only main.rs;
//! the module TREE position is what this rationale defends, and the
//! move changed the file path, not the tree) — not a child of the
//! ebpf-gated terminal tree (whose session machinery is the
//! eagle-eyes graph). The rescue owns no BPF machinery — ANSI bytes
//! + termios — and must exist in EVERY build: a featureless binary
//! can still rescue a terminal some other app broke. A plain module
//! declaration is also what the test-tree discipline expects: every
//! #[path] wiring under src/ resolves into test/, and this file's
//! own pins hang off it the ordinary way
//! (test/terminal/reset_tests.rs).
//!
//! Mode-direction contract (pinned in test/terminal/reset_tests.rs
//! and enforced by the mouse-contract source scan): every DEC
//! private mode this file touches is restored toward its DEFAULT
//! direction — modes whose default is OFF are only ever sent `l`
//! (2026 sync, 2004 paste, 1004 focus, the mouse family, 1049 alt
//! screen), and modes whose default is ON are only ever sent `h`
//! (25 cursor visible, 7 autowrap). The reset never ENABLES an
//! optional mode; it is pure restoration.

use std::io::IsTerminal;
use std::os::unix::io::AsRawFd;

// The interposed-terminal lane (NIGHT-improve-31): this module's
// child (term_reset/outer.rs) — the discovery, the direct apply, and
// the post-sudo orphan — kept in its own file so this one stays the
// five-layer contract it is pinned as (the LOC cap discipline).
mod outer;

// ── The raw-fd helpers (shared with the violent-death guard) ─────────
//
// The guard child (terminal/guard.rs) and this rescue both write to
// fd 1 from the wrong side of a possibly-jammed PTY, so the three
// primitives live here ONCE — crate-root, always compiled — and the
// guard imports them (NIGHT-improve-30: the rescue used to pay std
// stdout's blocking write for its ANSI layers; the guard's own
// hardening comment already explained why that is the one shape a
// recovery path must never take).

/// Flip `fd` to O_NONBLOCK; returns the previous status flags (-1 on
/// failure, which the caller treats as "nothing was changed").
///
/// # Safety
/// `fd` must be an open descriptor the process owns.
pub(crate) unsafe fn set_fd_nonblocking(fd: std::os::unix::io::RawFd) -> libc::c_int {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return -1;
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return -1;
        }
        flags
    }
}

/// Restore `fd`'s status flags after a [`set_fd_nonblocking`] round
/// trip (`prev` is the value it returned; -1 is the nothing-changed
/// sentinel and a no-op here).
///
/// # Safety
/// `fd` must be an open descriptor the process owns, and `prev` must
/// be a status-flags value previously returned by `fcntl(F_GETFL)`.
pub(crate) unsafe fn restore_fd_flags(fd: std::os::unix::io::RawFd, prev: libc::c_int) {
    if prev >= 0 {
        unsafe {
            libc::fcntl(fd, libc::F_SETFL, prev);
        }
    }
}

/// Best-effort raw-fd write — never blocks, never retries past the
/// first refusal. EAGAIN/EPIPE/EBADF drop the remainder silently: a
/// recovery path (the guard child moments from `_exit`, the rescue
/// with more layers still to run) prefers a partial restore over a
/// hung one.
///
/// # Safety
/// `fd` must be an open descriptor the process owns, and the caller
/// is expected to have set O_NONBLOCK first (without it this is just
/// a plain blocking write loop).
pub(crate) unsafe fn write_fd_best_effort(fd: std::os::unix::io::RawFd, bytes: &[u8]) {
    let mut off = 0usize;
    while off < bytes.len() {
        // SAFETY: write(2) on a numeric fd the process owns; n == 0
        // breaks like an error — retrying a zero-byte progress loop
        // would spin.
        let n = unsafe {
            libc::write(
                fd,
                bytes[off..].as_ptr().cast::<libc::c_void>(),
                bytes.len() - off,
            )
        };
        if n <= 0 {
            return;
        }
        off += n as usize;
    }
}

// ── Layer 1: the termios restore (NIGHT-improve-30) ───────────────────

/// Restore a termios snapshot toward the cooked sane state — the
/// inverse of the raw-mode class of breakage (this crate's monitor
/// turns off ICANON/ECHO/ISIG and parks VMIN/VTIME at 0/0; a
/// crossterm-style foreign TUI additionally strips the input and
/// output processing flags via cfmakeraw). Pure over the struct, so
/// the exact flag set is unit-pinned in test/terminal/reset_tests.rs.
///
/// Deliberately NOT a full `stty sane` clone: the exotic settings
/// (flow-control preferences, parity, character-size bits, the
/// special-character table) stay wherever the user's shell had them —
/// layer 4's `stty sane` owns the canonical reset, and guessing at
/// preferences from inside a rescue is how a rescue breaks a working
/// terminal. This layer restores exactly what a TUI raw mode breaks.
pub(crate) fn sane_cooked(t: &mut libc::termios) {
    // Input lane: cfmakeraw's clears (BRKINT, ICRNL) back on, its
    // sets (IGNBRK, ISTRIP, INLCR, IGNCR, IXOFF) back off. IXON stays
    // wherever the shell had it — flow control is a preference.
    t.c_iflag &= !(libc::IGNBRK | libc::ISTRIP | libc::INLCR | libc::IGNCR | libc::IXOFF);
    t.c_iflag |= libc::BRKINT | libc::ICRNL;
    // Output lane: post-processing back on — without OPOST|ONLCR
    // every newline the shell prints staircases down the screen, the
    // classic half-broken look after a violent TUI death.
    t.c_oflag |= libc::OPOST | libc::ONLCR;
    // Line discipline back to cooked: canonical buffering, echo (with
    // the erase/kill refinements a shell expects: ECHOE backspace-
    // erase, ECHOK, ^X control echo, kill-line erase), signals, and
    // extended input processing.
    t.c_lflag |= libc::ISIG
        | libc::ICANON
        | libc::ECHO
        | libc::ECHOE
        | libc::ECHOK
        | libc::ECHOCTL
        | libc::ECHOKE
        | libc::IEXTEN;
    // Blocking reads: VMIN=1/VTIME=0 (the monitor's 0/0 poll pair is
    // a busy-loop hazard in any reader that expects data to arrive).
    t.c_cc[libc::VMIN] = 1;
    t.c_cc[libc::VTIME] = 0;
}

/// Apply layer 1: a sane cooked termios on the real terminal.
///
/// fd 0 when it is the tty; `/dev/tty` when stdin is redirected (the
/// crossterm `disable_raw_mode` shape — the rescue still owes the
/// controlling terminal its restore when stdio carries something
/// else). TCSAFLUSH, not TCSANOW: the flush drops the pending input
/// queue, which after a stuck mouse-mode death holds report bytes
/// that would otherwise land in the user's shell as garbage commands
/// the instant echo returns.
fn restore_termios_cooked() {
    let mut buf: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(0, &mut buf) } == 0 {
        sane_cooked(&mut buf);
        unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &buf) };
        return;
    }
    if let Ok(tty) = std::fs::File::open("/dev/tty") {
        let fd = tty.as_raw_fd();
        if unsafe { libc::tcgetattr(fd, &mut buf) } == 0 {
            sane_cooked(&mut buf);
            unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &buf) };
        }
    }
}

// ── Layers 2-3: the ANSI sequences ────────────────────────────────────

/// The best-effort ANSI restore sequence: every optional mode off a
/// TUI may have left on, plus the sane-defaults resets. Non-destructive
/// — does NOT clear the screen or scrollback (that is
/// [`TERMINAL_RESET_SEQUENCE`], the nuclear tier).
///
/// Mode inventory and why each earns its byte:
/// - `\x1b[0m` — SGR reset (twice, bookending): a mid-frame death
///   leaves the pen mid-color/bold; the pen state is terminal-global
///   and survives the alt-screen switch, so without this the user's
///   shell prompt renders in the dead monitor's last color.
/// - `\x1b[?2026l` — synchronized output off. A stuck sync mode makes
///   the terminal buffer ALL output and render nothing: the exact
///   "frozen screen" breakage. The most valuable single byte pair a
///   modern rescue can send.
/// - `\x1b[?2004l` — bracketed paste off (vim/less kill leaves it on;
///   the shell then eats paste markers into commands).
/// - `\x1b[?1004l` — focus reporting off.
/// - `\x1b[?1006l\x1b[?1002l\x1b[?1003l\x1b[?1000l\x1b[?1015l` — the
///   full mouse family off: the monitor's trio (1000/1002/1006) plus
///   the two legacy encodings a foreign app may have taken (1003
///   any-motion, 1015 urxvt). A terminal stuck in 1003 floods stdin
///   with mouse-move reports on every pointer twitch.
/// - `\x1b[?1049l` — leave the alternate screen: the frozen frame
///   goes away, the user's real screen (and their shell prompt)
///   returns.
/// - `\x1b[<1u` — kitty keyboard protocol pop (one level). A no-op on
///   terminals that never pushed; inert bytes on non-compliant ones.
///   A dead kitty-protocol app otherwise turns every arrow key into
///   CSI-u garbage at the shell.
/// - `\x1b[r` — scroll region back to full screen (DECSTBM reset).
/// - `\x1b(B` — charset back to US ASCII.
/// - `\x1b[?7h` — autowrap ON (a TUI that disabled wrap leaves every
///   long line stamping over itself).
/// - `\x1b[?25h` — cursor visible again.
pub(crate) const TERMINAL_RESTORE_SEQUENCE: &str = concat!(
    "\x1b[0m",
    "\x1b[?2026l",
    "\x1b[?2004l",
    "\x1b[?1004l",
    "\x1b[?1006l\x1b[?1002l\x1b[?1003l\x1b[?1000l\x1b[?1015l",
    "\x1b[?1049l",
    "\x1b[<1u",
    "\x1b[r",
    "\x1b(B",
    "\x1b[?7h",
    "\x1b[?25h",
    "\x1b[0m",
);

/// The destructive terminal reset sequence (the nuclear tier):
/// [`TERMINAL_RESTORE_SEQUENCE`] plus cursor home, clear screen,
/// clear scrollback, cursor home again, SGR reset — wiping the
/// visible screen AND the scrollback buffer so the shell starts
/// clean. Used only by [`reset_terminal_emergency`] for a terminal
/// already known broken; the byte-repeat of the restore sequence is
/// deliberate (prefix-pinned in test/terminal/reset_tests.rs), the
/// cosmostrix shape.
pub(crate) const TERMINAL_RESET_SEQUENCE: &str = concat!(
    "\x1b[0m",
    "\x1b[?2026l",
    "\x1b[?2004l",
    "\x1b[?1004l",
    "\x1b[?1006l\x1b[?1002l\x1b[?1003l\x1b[?1000l\x1b[?1015l",
    "\x1b[?1049l",
    "\x1b[<1u",
    "\x1b[r",
    "\x1b(B",
    "\x1b[?7h",
    "\x1b[?25h",
    "\x1b[0m",
    "\x1b[H\x1b[2J\x1b[3J\x1b[H",
    "\x1b[0m",
);

// ── Layers 4-5: the external utilities ───────────────────────────

/// The rescue's fixed external-layer lookup path when running as
/// root (NIGHT-lts-1): the four canonical system directories every
/// mainstream distro packages stty/reset/tput into — usrmerge
/// layouts (/usr/bin) and pre-merge ones (/bin, /sbin) both covered,
/// Alpine's busybox symlinks included. sudo's secure_path normally
/// sanitizes the environment already; this is the defense-in-depth
/// belt for the configurations that do not (`sudo -E`,
/// `env_keep+=PATH`, legacy sudoers): a user-controlled directory
/// can never slide a binary under a root-run rescue — the same
/// class the CI env-var isolation closed for workflow scripts
/// (SAFETY_ANALYSIS Finding 2). A NON-root rescue keeps the
/// inherited PATH: same user, same privilege, no boundary to cross
/// (and NixOS's /run/current-system/sw/bin lookup keeps working —
/// the documented trade is that a root rescue on NixOS skips these
/// best-effort belts, layers 1-3 having already restored the
/// critical state).
const RESCUE_SYSTEM_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// Spawn one rescue utility, best-effort. When the rescue runs as
/// root, the spawn pins [`RESCUE_SYSTEM_PATH`] — see the const's
/// docs for the boundary and the trade. Under interposition
/// (NIGHT-improve-31) `stdin_tty` redirects the utility's stdin onto
/// the user's REAL terminal: `stty sane`, `reset`, and `tput reset`
/// all operate on their standard input, and the inherited fd 0 is
/// the throwaway sudo pty they would otherwise repair.
fn spawn_rescue_util(name: &str, arg: Option<&str>, stdin_tty: Option<&std::path::Path>) {
    let mut cmd = std::process::Command::new(name);
    if let Some(a) = arg {
        cmd.arg(a);
    }
    if let Some(tty) = stdin_tty {
        if let Ok(f) = std::fs::File::open(tty) {
            cmd.stdin(f);
        }
    }
    if nix::unistd::geteuid().is_root() {
        cmd.env("PATH", RESCUE_SYSTEM_PATH);
    }
    let _ = cmd.status();
}

/// Emergency terminal reset — the five-layer recovery behind
/// `zelynic --reset-terminal` (NIGHT-hunt-31; the layer-1 termios
/// restore and the non-blocking write hardening are NIGHT-improve-30,
/// the maturity debt the first port owed the cosmostrix reference;
/// the root-context PATH pin on the external layers is NIGHT-lts-1).
/// Silent by contract: the fixed terminal IS the feedback (the shell
/// prompt returning on a clean screen says more than any status line
/// could — and a line printed after `tput reset` would land on the
/// fresh screen as residue the user did not ask for).
pub(crate) fn reset_terminal_emergency() {
    // Layer 0 (NIGHT-improve-31): discover the REAL terminal when the
    // rescue runs interposed (sudo use_pty). Everything below keeps
    // its classic behavior — the layers still run against fd 0 and
    // fd 1 first (right for every non-interposed context, harmless
    // under the interposer, whose relay carries the escape bytes to
    // the real terminal anyway) — while the outer lane ALSO carries
    // the termios-class layers to the terminal the user is actually
    // staring at, which no fd-0/fd-1 operation can reach.
    let outer = outer::discover();

    // Layer 1: the termios restore — FIRST, before any byte. The
    // ioctl always completes (the guard's lesson), echo comes back so
    // the user sees the later layers work, and TCSAFLUSH drops the
    // stuck-mode input flood before it can reach the shell.
    restore_termios_cooked();

    // Layers 2-3: the ANSI restore + reset bytes, best-effort under a
    // temporary O_NONBLOCK on fd 1 (the Termux lesson — a jammed PTY
    // must not wedge the rescue before its external layers can run;
    // the flags go back afterward so the shell keeps blocking reads).
    // Raw fd writes, never std::io::stdout(): the rescue runs with no
    // threads of its own, but it owes the same lock-free discipline
    // the guard child pays for after fork.
    let prev_flags = unsafe { set_fd_nonblocking(1) };
    unsafe {
        write_fd_best_effort(1, TERMINAL_RESTORE_SEQUENCE.as_bytes());
        write_fd_best_effort(1, TERMINAL_RESET_SEQUENCE.as_bytes());
        restore_fd_flags(1, prev_flags);
    }

    // The interposed lane's direct apply (NIGHT-improve-31 move 2):
    // the same termios + ANSI layers, on the real terminal by path.
    // The belt for the monitors that do not mirror pty changes to
    // the real tty, and the in-flight fix for the ones that do —
    // until their exit-restore undoes it, which is what the orphan
    // below exists to outlive.
    if let Some(real) = &outer {
        outer::apply_rescue_to_path(&real.path);
    }

    // Layers 4-5: the external utilities, only where a terminal can
    // receive them, and — when the rescue runs as root — resolved
    // through the pinned system PATH (see [`RESCUE_SYSTEM_PATH`]).
    // `stty sane` is the canonical belt over layer 1 (the full sane
    // set, exotic flags included); `reset` and `tput reset` carry the
    // terminal's own init strings. Under interposition their stdin
    // is redirected onto the real terminal (NIGHT-improve-31) — all
    // three operate on stdin, which under use_pty is the throwaway
    // pty. All best-effort — a minimal container without ncurses
    // still leaves layers 1-3 done, which is the state the shell
    // needs.
    if std::io::stdin().is_terminal() || std::io::stdout().is_terminal() {
        let stdin_tty = outer.as_ref().map(|real| real.path.as_path());
        spawn_rescue_util("stty", Some("sane"), stdin_tty);
        // `reset`/`tput reset` run only with a TERM set: without one,
        // ncurses' tset prompts "Terminal type?" on the tty and WAITS
        // for an answer — a rescue that hangs is worse than one that
        // skips its two optional layers (NIGHT-improve-30; the
        // degenerate env is real: PID 1 and container inits run
        // TERM-less, exactly where the musl twin ships).
        let term = std::env::var_os("TERM");
        if term.is_some_and(|t| !t.is_empty()) {
            spawn_rescue_util("reset", None, stdin_tty);
            spawn_rescue_util("tput", Some("reset"), stdin_tty);
        }
    }

    // The interposed lane's last move (NIGHT-improve-31 move 3): the
    // bounded orphan that waits out the sudo monitor and re-applies
    // the fix AFTER its broken-snapshot restore lands. Forked LAST —
    // after every other layer — so the child inherits a quiet fd
    // table; never reaped, because it must outlive this process.
    if let Some(real) = &outer {
        outer::spawn_post_sudo_reapplier(real);
    }
}

// NIGHT-hunt-31: the reset pins live under the single test/ tree
// (cosmostrix Pattern C), #[path]-wired across trees exactly like
// the terminal tree's own pins.
#[cfg(test)]
#[path = "../../test/terminal/reset_tests.rs"]
mod reset_tests;
