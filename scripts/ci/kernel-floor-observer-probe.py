#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
"""The kernel-floor observer probe (NIGHT-improve-29).

Spawn eagle-eyes on a pty — supermassive-test-v2's _spawn_tui_on_pty
pattern — prove frames render under a live session, SIGKILL the
monitor mid-render (the violent death under test), then require the
violent-death guard child's ALT_EXIT restore bytes on the pty. One
probe, three 5.15 proofs: the observer object loads (its BPF_ATOMIC
counter updates since NIGHT-improve-29 are exactly the kind of thing
a floor probe must re-verify), the boost-33 guard fires on the
5.15 kernel, and — leg 3, NIGHT-improve-30 — the --reset-terminal
rescue recovers a DELIBERATELY re-broken pty (raw termios): both
the five-layer restore bytes and a cooked termios must come back,
proving layer 1's in-process ioctl on the floor kernel.

The restore constant is screen.rs's ALT_EXIT contract byte for byte
(the NIGHT-hunt-31 shape carries the leading SGR reset). It is
duplicated here on purpose: the probe runs inside the VM against the
SHIPPED binary — asserting the constant independently is the pin
(a shared definition could drift together with the code under test).
The mouse-contract source scan (test/terminal/mouse_contract_tests.rs)
exempts only src/term_reset.rs, so this file spells the bytes
without \\x1b[? literals' sanctioned-set tripwire ... which it cannot
trip: the scan walks src/ only, and every mode below is in the
monitor's sanctioned five anyway.

Usage: kernel-floor-observer-probe.py <zelynic-binary>
Exit 0 = frames + signal-9 death + guard restore + rescue all proven.
"""

import fcntl
import os
import pty
import signal
import struct
import subprocess
import sys
import termios
import time

# The ALT_EXIT contract (src/terminal/screen.rs), byte for byte:
# SGR reset, mouse SGR/press/drag off, main screen, cursor visible.
RESTORE_BYTES = b"\x1b[0m\x1b[?1006l\x1b[?1002l\x1b[?1000l\x1b[?1049l\x1b[?25h"

# The --reset-terminal rescue needles (src/term_reset.rs): the
# sync-output kill (the frozen-screen breakage), the alt-screen
# leave, the cursor show, and the destructive clear tail (screen +
# scrollback purge).
RESCUE_NEEDLES = (
    b"\x1b[?2026l",
    b"\x1b[?1049l",
    b"\x1b[?25h",
    b"\x1b[H\x1b[2J\x1b[3J\x1b[H",
)

# The cooked termios bits leg 3 requires back after the rescue: the
# line discipline the shell reads from (canonical, echo, signals).
COOKED_LFLAG_BITS = termios.ICANON | termios.ECHO | termios.ISIG

# Enough pty bytes to prove the render engine is producing frames
# under a live session (one 80x24 frame is ~1.4 KB; 200 bytes is a
# conservative "the first frame landed" bar).
RENDER_PROOF_BYTES = 200

# Budgets: 10 s for the first frames (the BPF load runs under the
# loading frame), 10 s to reap the kill, 3 s settle for the guard
# child's post-mortem write (it fires within microseconds; the
# margin is for a loaded VM).
FIRST_FRAME_BUDGET_S = 10.0
REAP_BUDGET_S = 10.0
GUARD_SETTLE_S = 3.0
RESCUE_BUDGET_S = 10.0


def drain(master, budget_s, stop_at_bytes=None):
    """Non-blocking pty drain: collect bytes for up to budget_s,
    returning early once stop_at_bytes (if set) is collected."""
    got = bytearray()
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline:
        if stop_at_bytes is not None and len(got) >= stop_at_bytes:
            break
        try:
            chunk = os.read(master, 65536)
        except BlockingIOError:
            time.sleep(0.05)
            continue
        except OSError:
            break  # pty closed under us — the child is gone
        got += chunk
    return bytes(got)


def rescue_probe(binary):
    """Leg 3 (NIGHT-improve-30): the --reset-terminal rescue proof.

    Break a fresh pty exactly the way a violent TUI death leaves one
    — the termios stripped to raw (canonical/echo/signals off, no
    output post-processing, VMIN=0/VTIME=0) — then run the shipped
    binary's --reset-terminal on it and require BOTH halves of the
    five-layer contract: the rescue escape bytes on the pty (sync
    output off, alt screen off, cursor visible, the clear tail) and
    a cooked termios afterward (layer 1's in-process ioctl, the
    kernel-side truth no escape byte reaches).

    Returns (rescue_bytes_ok, rescue_termios_ok, exit_code).
    """
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))

    # Break the pty: the crossterm-class raw shape. Python termios
    # rows: [iflag, oflag, cflag, lflag, ispeed, ospeed, cc].
    attrs = termios.tcgetattr(slave)
    vmin_idx = getattr(termios, "VMIN", 6)
    vtime_idx = getattr(termios, "VTIME", 5)
    broken = list(attrs)
    broken[0] &= ~(termios.BRKINT | termios.ICRNL)
    broken[1] &= ~termios.OPOST
    broken[3] &= ~(termios.ICANON | termios.ECHO | termios.ISIG | termios.IEXTEN)
    cc = list(broken[6])
    cc[vmin_idx] = 0
    cc[vtime_idx] = 0
    broken[6] = cc
    termios.tcsetattr(slave, termios.TCSANOW, broken)

    # The rescue must not depend on the two optional external layers
    # (the container userland may carry no ncurses): TERM unset also
    # proves the layers-4/5 prompt guard — a tset that cannot ask
    # "Terminal type?" must be skipped, never hung on.
    env = dict(os.environ)
    env.pop("TERM", None)
    proc = subprocess.Popen(
        [binary, "--reset-terminal"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=env,
    )
    os.close(slave)
    os.set_blocking(master, False)

    try:
        out = drain(master, RESCUE_BUDGET_S)
        rc = proc.wait(timeout=RESCUE_BUDGET_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        rc = proc.wait(timeout=REAP_BUDGET_S)

    rescue_bytes_ok = all(needle in out for needle in RESCUE_NEEDLES)
    lflag = termios.tcgetattr(master)[3]
    rescue_termios_ok = (lflag & COOKED_LFLAG_BITS) == COOKED_LFLAG_BITS
    os.close(master)
    return rescue_bytes_ok, rescue_termios_ok, rc


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <zelynic-binary>", file=sys.stderr)
        return 2
    binary = sys.argv[1]

    master, slave = pty.openpty()
    # The default geometry every terminal starts from (v2's contract).
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    proc = subprocess.Popen(
        [binary, "eagle-eyes", "--interval", "1s"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
    )
    os.close(slave)
    os.set_blocking(master, False)

    frames = drain(master, FIRST_FRAME_BUDGET_S, stop_at_bytes=RENDER_PROOF_BYTES)
    rendered = len(frames) >= RENDER_PROOF_BYTES

    proc.kill()  # SIGKILL: the violent death under test
    try:
        proc.wait(timeout=REAP_BUDGET_S)
    except subprocess.TimeoutExpired:
        pass  # unreapable child: surfaced by the returncode check below

    post_kill = drain(master, GUARD_SETTLE_S)
    os.close(master)

    restored = RESTORE_BYTES in post_kill
    killed_as_9 = proc.returncode == -signal.SIGKILL

    rescue_bytes, rescue_termios, rescue_rc = rescue_probe(binary)

    ok = rendered and restored and killed_as_9 and rescue_bytes and rescue_termios
    print(
        "FLOOR-OBSERVER: frames={} exit={} guard-restore={} "
        "rescue-bytes={} rescue-termios={} rescue-exit={}".format(
            rendered, proc.returncode, restored, rescue_bytes, rescue_termios, rescue_rc
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
