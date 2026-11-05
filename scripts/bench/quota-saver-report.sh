#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# The quota saver's measurement script (night-netrunner-4): a REAL
# download (3 MB from the Cloudflare/Vultr-Singapore ladder) and a
# REAL upload (Cloudflare's discard endpoint), each under a live
# zelynic limit, with `zelynic status --print-json` read before and
# after. The verdict lines are the exact wire contract the task pins,
# printed once per leg:
#
#   test download results the internet kuota save total is X%
#   test upload results the internet kuota save total is Y%
#
# The percentages come from the kernel's own Layer 4 telemetry: the
# bytes_saved_total delta (EDT pacing + ECN marks + the RECWN window
# counterfactual) against the bytes_allowed delta (what actually
# transferred). Python is the engine for the same reasons as the
# supermassive suite: subprocess control and precise timeout
# discipline are things bash cannot do well.
#
# Root + cgroup v2 + a full-life binary + curl are required — a
# missing prerequisite refuses with the reason on stderr (exit 2),
# never a fabricated line. Every zelynic side effect is cleaned up:
# each leg's limit is removed and its cgroup torn down on every exit
# path.
#
# Usage:
#   ./scripts/bench/quota-saver-report.sh               # both legs
#   ./scripts/bench/quota-saver-report.sh --binary PATH # explicit binary
#   ./scripts/bench/quota-saver-report.sh --help        # the flags

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/quota-saver-report.py" "$@"
