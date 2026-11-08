#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# ee-resource-bench.sh — measure the live eagle-eyes monitor's actual
# CPU, memory, thread count, and context switches over a fixed window.
# Like quota-saver-ab but for the monitor's idle cost. Needs root
# (eagle-eyes reads BPF maps).

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/ee-resource-bench.py" "$@"
