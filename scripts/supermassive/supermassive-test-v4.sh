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
# NIGHT-improve-42 adds the private-research-4 depth stages: the
# --during grammar ladder, the --floor/--ceil guarantee laws, the
# per-socket tier flags, and the persistence lane's privileged verb
# (restore — NIGHT-improve-55 retired the snapshot dump, so the
# table pins the survivor's privilege refusal and the retired
# spelling's redirect) — the owner's seven-feature audit pinned at
# the CLI surface each feature owns (the three automatic lanes —
# ECN-first, CAKE flow isolation, QUIC-aware — have no CLI surface;
# their depth lives in the Rust pins, the live probes, and v1's VM
# matrix).
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
# domain; v4 is the surface contract. One exception-shaped lane: stage
# 9's three valid-rate shadow rows assert the root-refusal message, a
# needle only a non-root run produces — when the harness itself runs
# as root (the supermassive VM's init context), they now re-execute
# through the real-user drop lane (NIGHT-improve-49: setpriv to uid
# 65534) instead of skipping: the gate refuses the dropped user
# exactly as it refuses a real one, and a dropped uid cannot pass
# the root gate, so no v4 case ever makes an enforcement attempt
# (only a host without setpriv keeps the honest SKIP). The rootless
# CI leg still carries all 155 rows on every push that touches the
# Rust/scripts surface (ci.yml is paths-filtered — NIGHT-hunt-32
# corrected the unqualified "every push").
#
# Full design notes live in the .py header.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/supermassive-test-v4.py" "$@"
