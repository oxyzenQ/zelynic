#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# Wrapper for edt-probe.py (night-spark-5 — the quota saver's Layer 3,
# egress socket pacing, schema v27; hardened by night-spark-6 — the
# ss pacing token's two iproute2 dialects, the bps family's
# current/max pair read as the pinned-max exactness witness, and
# the fast-local proxy guard) — the EGRESS lane's live proof: a
# 100 kb/s upload policy on a real cgroup, the uploader joined into the
# policed cgroup the recwn way (fork, join cgroup.procs, execv — curl
# IS the cgroup member), `ss -tip` reading the kernel's own pacer on
# the lane's sockets at the policy's own rate (SO_MAX_PACING_RATE, the
# stack's internal pacer — no tc, no fq, no nftables anywhere), curl -T
# delivering at the lane's own byte rate, and `zelynic status
# --print-json` naming limits[].pacing_rate_bytes (the schema-v27
# column) with the ledger's dropped counters moving ZERO during the
# paced upload — quota saved without a loss event. Python is the engine
# (the cgroup join, the ss instrument, the throttle verdict and the
# ledger cross-check share one docstring contract — the same rationale
# as every bench wrapper here).
#
# Usage:
#   sudo ./scripts/bench/edt-probe.sh                # live proof (~1 min; the leg
#                                                    #  self-bounded; ^C aborts
#                                                    #  cleanly: teardown, exit 130)
#   ./scripts/bench/edt-probe.sh --self-test         # instrument lane, no root
#   sudo ./scripts/bench/edt-probe.sh --json         # machine-readable
#   sudo ./scripts/bench/edt-probe.sh --binary PATH  # drive a specific zelynic
#
# Full design notes — the sock_ops pacing lane's kernel truths (the
# cookie-keyed hint the egress hook primes, the TCP-only dispatch, the
# UDP/QUIC residue) — live in the .py header.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/edt-probe.py" "$@"
