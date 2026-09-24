#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Wrapper for supermassive-test.py (NIGHT-master-2; renamed from
# brutal-stress-test.sh in NIGHT-improve-11 / security-4) — the
# one-click limiter-scope supermassive test: every policy shape on
# the local loopback lane AND against the real internet
# (NIGHT-refactor-2). Python is the engine: subprocess control,
# /proc parsing, threaded traffic, and precise timing are things bash
# cannot do well (same rationale as limiter-depth-test.sh wrapping
# limiter-depth-test.py).
#
# Usage:
#   sudo ./scripts/supermassive/supermassive-test.sh                # supermassive (6+ min)
#   sudo ./scripts/supermassive/supermassive-test.sh --heavy        # the same, explicit
#   ./scripts/supermassive/supermassive-test.sh --self-test          # engine smoke, no root
#   sudo ./scripts/supermassive/supermassive-test.sh --json          # machine-readable
#
# One root intensity since NIGHT-improve-19: the light sweep was
# retired — the matrix is the default, and a mistyped flag
# (--self-tesss) gets a typo tip, --light gets its retirement
# message.
#
# NIGHT-refactor-2 scope split: the abuse family (rate guards, the
# SIGKILL batteries, the regression re-proof, the recover/dmesg
# teardown) moved to supermassive-test-v2.sh — this harness measures
# limits; that one survives violence. The internet lane moved the
# other way, from v2 to here: policing real traffic is limiter scope
# by definition.
#
# Full design notes live in the .py header. This script replaced the
# old stress-test.sh, which depended on an external speedtest server
# and asserted on a status format that no longer exists.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/supermassive-test.py" "$@"
