#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# Wrapper for mmspa-vs-legacy-test.py (NIGHT-perf-1) — the one-click
# MMSPA-vs-pre-MMSPA subtree-coverage depth test: the same battery,
# the same fleet, the same traffic, run against the current MMSPA
# build AND the last pre-MMSPA stable (v11.0.0), with the >= 99%
# child-coverage delta as the verdict. Python is the engine (the
# same rationale as every supermassive wrapper: subprocess control,
# /proc parsing, threaded traffic, precise timing).
#
# Usage:
#   sudo ./scripts/supermassive/mmspa-vs-legacy-test.sh
#        (the legacy v11.0.0 side AUTO-DOWNLOADS from the canonical
#         release when no local candidate exists — sha512-sidecar-
#         verified, cached under TMPDIR; --legacy-binary overrides
#         everything)
#   ./scripts/supermassive/mmspa-vs-legacy-test.sh --self-test   # engine smoke, no root
#   ./scripts/supermassive/mmspa-vs-legacy-test.sh --json        # machine-readable
#   ./scripts/supermassive/mmspa-vs-legacy-test.sh --no-download # offline: local paths only
#
# The legacy side resolves from --legacy-binary, $ZELYNIC_LEGACY_BINARY,
# /opt/zelynic/legacy/zelynic (the path the supermassive CI legs
# stage it at), or the canonical auto-download — in that order. Without
# any of them the pair verdict SKIPs loudly — the proof never runs
# one-sided. The canonical source:
#   https://github.com/oxyzenQ/zelynic/releases/download/v11.0.0/
#     zelynic-v11.0.0-linux-amd64-v3-gnu.tar.gz
#
# Full design notes live in the .py header.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/mmspa-vs-legacy-test.py" "$@"
