#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# Wrapper for supermassive-test-v4.py (NIGHT-improve-35) — the CLI
# depth battery. v1 owns every stage that measures a LIMIT; v2 owns
# the abuse family; v3 owns the container surface; v4 owns the CLI
# surface itself — every command, every flag, every alias, every
# color mode, every typo, every rate-explode shape, every removed
# command, and every hidden subcommand, end to end. Python is the
# engine for the same reasons as v1, v2, and v3: subprocess control
# and precise timeout discipline are things bash cannot do well.
#
# Usage:
#   ./scripts/supermassive/supermassive-test-v4.sh               # full CLI depth (rootless)
#   ./scripts/supermassive/supermassive-test-v4.sh --self-test   # engine smoke, no binary
#   ./scripts/supermassive/supermassive-test-v4.sh --json        # machine-readable
#   ./scripts/supermassive/supermassive-test-v4.sh --stages help,color  # run named stages
#
# Rootless by design: the CLI surface (help, version, alias routing,
# typo tips, rate validation, color modes) parses BEFORE the root
# check, so v4 runs on every host without sudo — the most CI-friendly
# supermassive test. The enforcement depth (root + eBPF) is v1/v2's
# domain; v4 is the surface contract. One honest exception: stage 9's
# three valid-rate shadow rows assert the root-refusal message, a
# needle only a non-root run produces — when the harness itself runs
# as root (the supermassive VM's init context), they SKIP without
# executing (v3's doctrine; and a valid rate past a passing gate is
# an enforcement attempt no v4 case makes). The rootless CI leg
# still carries all 121 rows on every push that touches the
# Rust/scripts surface (ci.yml is paths-filtered — NIGHT-hunt-32
# corrected the unqualified "every push").
#
# Full design notes live in the .py header.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/supermassive-test-v4.py" "$@"
