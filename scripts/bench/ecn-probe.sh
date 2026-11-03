#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# Wrapper for ecn-probe.py (night-spark-4 — the quota saver's Layer 2,
# ECN CE-marking made readable, schema v26) — the CGROUP lanes' live
# proof: a 100 kb/s download policy on a real cgroup, the worker's
# ECT(0) UDP datagrams delivered CE-marked on the over-budget ones
# (the receiver's IP_RECVTOS cmsg reads 0x03), the control leg's
# non-ECT blast dropping the legacy way, `zelynic status --print-json`
# naming limits[].ce_marked_packets / .ce_marked_bytes inside the
# budget law's bound, tcpdump counting `ip[1] & 0x3 == 0x3` on the
# egress witness leg, the internet TCP leg under `net.ipv4.tcp_ecn=1`,
# and the QUIC leg (`curl --http3-only https://cloudflare-quic.com/`)
# — CE marks reaching an RFC 9002 congestion controller without a
# single dropped datagram (an honest SKIP when the local curl cannot
# speak HTTP/3). Python is the engine (the cgroup worker, the cmsg
# instrument, the tcpdump witness and the ledger cross-check share one
# docstring contract — the same rationale as every bench wrapper
# here).
#
# Usage:
#   sudo ./scripts/bench/ecn-probe.sh                # live proof (~1 min; every leg
#                                                    #  self-bounded; ^C aborts
#                                                    #  cleanly: teardown, exit 130)
#   ./scripts/bench/ecn-probe.sh --self-test         # instrument lane, no root
#   sudo ./scripts/bench/ecn-probe.sh --json         # machine-readable
#   sudo ./scripts/bench/ecn-probe.sh --binary PATH  # drive a specific zelynic
#
# Full design notes — the kernel truths about which witness can see an
# INGRESS mark on the 5.13-5.15 floor, and why the verdicts ride the
# cmsg and the v26 ledger instead — live in the .py header.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/ecn-probe.py" "$@"
