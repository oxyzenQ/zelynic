#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Wrapper for ammsp-vs-legacy-test.py (NIGHT-perf-1) — the one-click
# AMMSP-vs-pre-AMMSP subtree-coverage depth test: the same battery,
# the same fleet, the same traffic, run against the current AMMSP
# build AND the last pre-AMMSP stable (v11.0.0), with the >= 99%
# child-coverage delta as the verdict. Python is the engine (the
# same rationale as every supermassive wrapper: subprocess control,
# /proc parsing, threaded traffic, precise timing).
#
# Usage:
#   sudo ./scripts/supermassive/ammsp-vs-legacy-test.sh \
#        --legacy-binary /path/to/v11.0.0/zelynic
#   ./scripts/supermassive/ammsp-vs-legacy-test.sh --self-test   # engine smoke, no root
#   ./scripts/supermassive/ammsp-vs-legacy-test.sh --json        # machine-readable
#
# The legacy side resolves from --legacy-binary, $ZELYNIC_LEGACY_BINARY,
# or /opt/zelynic/legacy/zelynic (the path the supermassive CI legs
# stage it at). Without it the pair verdict SKIPs loudly — the proof
# never runs one-sided. The canonical source:
#   https://github.com/oxyzenQ/zelynic/releases/download/v11.0.0/
#     zelynic-v11.0.0-linux-amd64-v3-gnu.tar.gz
#
# Full design notes live in the .py header.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/ammsp-vs-legacy-test.py" "$@"
