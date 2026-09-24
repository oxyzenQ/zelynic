#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Wrapper for supermassive-test-v2.py (NIGHT-improve-23; scope
# refocused in NIGHT-refactor-2) — the survival battery: everything
# that is NOT a limit measurement. The CLI input guards (bounds,
# typo rescue, dangerous blocklist, override), the brutal battery
# (SIGKILL of the live TUI mid-render, jittered SIGKILLs of one-shot
# writers inside the attach/pin/write window), the post-kill
# regression re-proof, and the crash-family teardown (recover,
# cleanup, dmesg). Python is the engine for the same reasons as
# supermassive-test.sh: subprocess control, pty mechanics, /proc
# parsing, and precise timing are things bash cannot do well.
#
# Usage:
#   sudo ./scripts/supermassive/supermassive-test-v2.sh               # survival battery (4+ min)
#   ./scripts/supermassive/supermassive-test-v2.sh --self-test         # engine smoke, no root
#   sudo ./scripts/supermassive/supermassive-test-v2.sh --json         # machine-readable
#
# Division of labor with v1 (NIGHT-refactor-2, the owner's call): v1
# owns every stage that measures a LIMIT — the loopback matrix, the
# measured rate change, the real-internet lane (which moved there
# from this harness). v2 owns the abuse family — the guards, the
# kills, the regression re-proof, the crash teardown. A machine green
# on v1 has a limiter that holds everywhere it claims; a machine
# green on v2 survives the day nothing goes right.
#
# Full design notes live in the .py header.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/supermassive-test-v2.py" "$@"
