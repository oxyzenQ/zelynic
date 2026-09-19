#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Wrapper for limiter-depth-test.py (NIGHT-master-1) — the flagship
# cross-distro depth stress test for the zelynic limiter. Python is the
# engine: subprocess control, /proc parsing, threaded traffic, and
# precise timing are things bash cannot do well (same rationale as
# benchmarking.sh wrapping benchmarking.py).
#
# Usage:
#   sudo ./scripts/limiter-depth-test.sh            # full run (~2 min)
#   sudo ./scripts/limiter-depth-test.sh --quick    # fast pass (~45s)
#   sudo ./scripts/limiter-depth-test.sh --json     # machine-readable
#
# Full design notes live in the .py header.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/limiter-depth-test.py" "$@"
