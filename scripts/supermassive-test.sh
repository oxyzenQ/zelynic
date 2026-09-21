#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Wrapper for supermassive-test.py (NIGHT-master-2; renamed from
# brutal-stress-test.sh in NIGHT-improve-11 / security-4) — the
# one-click supermassive test for the whole zelynic command surface.
# Python is the engine: subprocess control, /proc parsing, threaded
# traffic, and precise timing are things bash cannot do well (same
# rationale as limiter-depth-test.sh wrapping limiter-depth-test.py).
#
# Usage:
#   sudo ./scripts/supermassive-test.sh                # light (~2 min)
#   sudo ./scripts/supermassive-test.sh --heavy        # supermassive (5+ min)
#   ./scripts/supermassive-test.sh --self-test          # engine smoke, no root
#   sudo ./scripts/supermassive-test.sh --json          # machine-readable
#
# Full design notes live in the .py header. This script replaced the
# old stress-test.sh, which depended on an external speedtest server
# and asserted on a status format that no longer exists.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/supermassive-test.py" "$@"
