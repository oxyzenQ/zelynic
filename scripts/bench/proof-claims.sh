#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Wrapper for proof-claims.py (NIGHT-boost-8) — the honesty harness:
# proves the four README headline claims LIVE (no daemon, pure eBPF,
# per-app per-cgroup, precision 0.00% with its honest live residual).
# Python is the engine: subprocess control, /proc parsing, threaded
# traffic, and precise timing are things bash cannot do well (same
# rationale as limiter-depth-test.sh wrapping limiter-depth-test.py).
#
# Usage:
#   sudo ./scripts/bench/proof-claims.sh               # full claims audit (~1 min)
#   sudo ./scripts/bench/proof-claims.sh --quick       # faster windows (~30s)
#   ./scripts/bench/proof-claims.sh --self-test         # engine smoke, no root
#   sudo ./scripts/bench/proof-claims.sh --json         # machine-readable
#
# Full design notes live in the .py header.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/proof-claims.py" "$@"
