#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# The quota saver's A/B proof (night-netrunner-4, the final polish):
# the SAME real download (20 MB from the Cloudflare/Vultr-Singapore
# ladder) and the SAME real upload (Cloudflare's discard endpoint)
# run twice against one virtual 100 MB ledger — scenario A under a
# live zelynic limit (the report sibling's machinery: cgroup +
# strict + the status JSON read before and after, the Layer 4
# telemetry deltas), scenario B with no enforcement at all (the raw
# drop-based counterfactual, its cost read off the wire: curl's
# bytes plus the /proc/net/snmp retransmission deltas, printed as
# the labeled estimate they are).
#
# The verdict lines are the exact wire contract the task pins,
# printed once per leg — always scenario A's ledger:
#
#   test download results the internet kuota save total is X%
#   test upload results the internet kuota save total is Y%
#
# Python is the engine for the same reasons as the supermassive
# suite: subprocess control and precise timeout discipline are
# things bash cannot do well.
#
# Root + cgroup v2 + a full-life binary + curl are required — a
# missing prerequisite refuses with the reason on stderr (exit 2),
# never a fabricated line. Every zelynic side effect is cleaned up:
# each scenario A leg's limit is removed and its cgroup torn down on
# every exit path. The run starts from a MEASURED clean slate
# (night-netrunner-5): `sudo zelynic u --all` before scenario A,
# verified back to zero active rows — a pre-existing limit clamps
# the leg's sockets and the ledger reads a saving it did not earn
# (the 99.62% e2e anomaly).
#
# Usage:
#   ./scripts/bench/quota-saver-ab.sh                # both scenarios
#   ./scripts/bench/quota-saver-ab.sh --binary PATH  # explicit binary
#   ./scripts/bench/quota-saver-ab.sh --help         # the flags

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/quota-saver-ab.py" "$@"
