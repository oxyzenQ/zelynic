#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Wrapper for supermassive-test-v2.py (NIGHT-improve-23) — the
# end-to-end daily-use simulation: the four policy families (strict,
# limit, block, unstrict) in daily-session order, each proven on the
# deterministic local loopback lane AND against the real internet.
# Python is the engine for the same reasons as supermassive-test.sh:
# subprocess control, /proc parsing, threaded traffic, and precise
# timing are things bash cannot do well.
#
# Usage:
#   sudo ./scripts/supermassive/supermassive-test-v2.sh               # e2e simulation (4+ min)
#   ./scripts/supermassive/supermassive-test-v2.sh --self-test         # engine smoke, no root
#   sudo ./scripts/supermassive/supermassive-test-v2.sh --json         # machine-readable
#
# Division of labor with v1 (the owner's call): v1 keeps every
# "problems-use-zelynic" stage — kill-tui, kill-midflight, the
# regression battery, recover/cleanup/dmesg teardown, and the fatal
# CLI-usage refusals; v2 carries only what a real day of zelynic use
# exercises. A machine green on v2 is qualified for the daily driver;
# a machine green on v1 is qualified for a power outage.
#
# Full design notes live in the .py header.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/supermassive-test-v2.py" "$@"
