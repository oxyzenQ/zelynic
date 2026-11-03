#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# Wrapper for recwn-probe.py (night-spark-2 — RECWN, Receive Window
# Control, the quota saver's Layer 1) — the receive-window lane's
# live proof, the owner's own verification script: a 100 kb/s
# download limit applied to a real cgroup, a curl child moved INTO
# the cgroup downloading through the real internet, `ss -tip`
# sampling scoped to the curl child's own pid while it runs, and the
# three verdicts the
# task brief named — the advertised receive window clamped to the
# RECWN scale, the throughput riding the policy band, retransmits
# near zero. Python is the engine (a forked child that execs curl —
# the scoped pid IS the socket owner, the cgroup move, concurrent ss
# sampling, precise timing — the same rationale as every bench
# wrapper here).
#
# Usage:
#   sudo ./scripts/bench/recwn-probe.sh               # live proof (~1 min; every leg
#                                                     #  self-bounded, heartbeaten, and
#                                                     #  ^C aborts cleanly: scoped
#                                                     #  teardown, exit 130)
#   ./scripts/bench/recwn-probe.sh --self-test         # instrument smoke, no root
#   ./scripts/bench/recwn-probe.sh --ladder-check      # rootless walk of the mirror
#                                                       #  ladder (reachability only)
#   sudo ./scripts/bench/recwn-probe.sh --json         # machine-readable
#
# Full design notes live in the .py header.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/recwn-probe.py" "$@"
