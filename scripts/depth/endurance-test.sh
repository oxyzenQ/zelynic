#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Wrapper for endurance-test.py (NIGHT-blade-6) — the ultra-long-
# endurance audit harness. Python is the engine: pty control, /proc
# sampling, and subprocess churn are things bash cannot do well
# (same rationale as limiter-depth-test.sh wrapping its .py).
#
# Usage:
#   sudo ./scripts/depth/endurance-test.sh            # full run (~100s)
#   sudo ./scripts/depth/endurance-test.sh --quick    # fast pass (~40s)
#   sudo ./scripts/depth/endurance-test.sh --json     # machine-readable
#
# Full design notes live in the .py header.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/endurance-test.py" "$@"
