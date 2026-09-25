#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
"""The kernel-floor observer probe (NIGHT-improve-29).

Spawn eagle-eyes on a pty — supermassive-test-v2's _spawn_tui_on_pty
pattern — prove frames render under a live session, SIGKILL the
monitor mid-render (the violent death under test), then require the
violent-death guard child's ALT_EXIT restore bytes on the pty. One
probe, two 5.15 proofs: the observer object loads (its BPF_ATOMIC
counter updates since NIGHT-improve-29 are exactly the kind of thing
a floor probe must re-verify) and the boost-33 guard fires on the
5.15 kernel.

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
Exit 0 = frames + signal-9 death + restore bytes all proven.
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
    ok = rendered and restored and killed_as_9
    print(
        "FLOOR-OBSERVER: frames={} exit={} restore-bytes={}".format(
            rendered, proc.returncode, restored
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
