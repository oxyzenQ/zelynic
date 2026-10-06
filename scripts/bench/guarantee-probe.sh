#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# Wrapper for guarantee-probe.py (improve-40/improve-40-b follow-up) —
# the per-leaf floor/ceiling bracket's live proof: four REAL leaf
# cgroups under one bracketed target, every leaf blasted past the
# budget, the floor's promise and the ceiling's cap measured on the
# running kernel (the owner's root-gated-battery ask), plus the
# improve-40-b per-direction split's ledger row. Python is the engine
# (forked leaf children, pipe-synced blasts, per-leaf counted drains —
# the same rationale as every bench wrapper here).
#
# Usage:
#   sudo ./scripts/bench/guarantee-probe.sh               # live proof (~30s)
#   ./scripts/bench/guarantee-probe.sh --self-test         # instrument smoke, no root
#   sudo ./scripts/bench/guarantee-probe.sh --json         # machine-readable
#
# Full design notes live in the .py header.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/guarantee-probe.py" "$@"
