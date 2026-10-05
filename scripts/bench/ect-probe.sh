#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# Wrapper for ect-probe.py (NIGHT-private-research-4 follow-up) — the
# live ECN marking proof for the per-socket lane: real ECT(0) UDP
# traffic through a real --per-socket policy, the CE codepoint read
# back at the receiver, the debt cap's bite and the budget law's
# closed form measured on the running kernel. Python is the engine
# (recvmsg cmsg parsing, forked unpoliced sender, precise verdict
# bands — the same rationale as every bench wrapper here).
#
# Usage:
#   sudo ./scripts/bench/ect-probe.sh               # live proof (~30s)
#   ./scripts/bench/ect-probe.sh --self-test         # instrument smoke, no root
#   sudo ./scripts/bench/ect-probe.sh --json         # machine-readable
#
# Full design notes live in the .py header.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/ect-probe.py" "$@"
