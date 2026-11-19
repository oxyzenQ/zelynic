#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# Wrapper for verifier-budget-test.py (night-frontier-Z9) — the verifier
# budget ledger's census and gate: the enforcement estate's programs are
# priced live by the kernel's own verifier cost (bpf_prog_info
# .verified_insns, UAPI aba64c7da983) and held against the pinned budget
# table in scripts/supermassive/verifier-budget-ledger.json under three
# laws — the growth law (measured above budget fails; a raise names its
# number), the ratchet law (lowering is free), and the completeness law
# (a loaded program without a row fails). Python is the engine (the same
# rationale as every supermassive wrapper: subprocess control, JSON
# parsing, precise timing).
#
# Usage:
#   sudo ./scripts/supermassive/verifier-budget-test.sh \
#        --binary /opt/zelynic/zelynic          # the census + gate (root)
#   ./scripts/supermassive/verifier-budget-test.sh --self-test
#        # the ledger audit, no kernel (the schema and the history chain)
#
# The envelope is derived from the running kernel (uname -r 5.15.* = the
# floor, anything else = the dynamically resolved head); --envelope
# overrides it. The ledger carries the per-envelope budget rows; the
# census posture (armed:false) measures and prints MASS-CENSUS rows while
# the arming commit pins the numbers — no half-armed state exists.
#
# Full design notes live in the .py header.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/verifier-budget-test.py" "$@"
