#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# Wrapper for supermassive-test-v3.py (NIGHT-improve-34) — the
# container depth battery. v1 owns every stage that measures a
# LIMIT; v2 owns the abuse family (the guards, the kills, the
# regression re-proof, the crash teardown); v3 owns the container
# surface — docker:// and k8s:// target resolution end to end, the
# URI grammar depth, the resolution error paths (no runtime, no
# socket, no poddir), the resolve-only contract (container targets
# ride the same strict-single machinery), and the real docker E2E
# lane (self-skips when no docker daemon is present, the same shape
# v1's realnet lane self-skips without an endpoint). Python is the
# engine for the same reasons as v1 and v2: subprocess control,
# /proc and /var/run socket probing, and precise timing are things
# bash cannot do well.
#
# Usage:
#   sudo ./scripts/supermassive/supermassive-test-v3.sh               # full container depth (root)
#   ./scripts/supermassive/supermassive-test-v3.sh --self-test        # engine smoke, no root
#   ./scripts/supermassive/supermassive-test-v3.sh --rootless         # help + privilege gate only
#   sudo ./scripts/supermassive/supermassive-test-v3.sh --json        # machine-readable
#   sudo ./scripts/supermassive/supermassive-test-v3.sh --docker-e2e  # force the docker E2E lane
#   sudo ./scripts/supermassive/supermassive-test-v3.sh --k8s-e2e     # force the k8s E2E lane
#
# Division of labor with v1 and v2 (NIGHT-improve-34, the owner's
# call): v1 measures limits; v2 survives violence; v3 resolves
# containers. A machine green on v1 has a limiter that holds; a
# machine green on v2 survives the day nothing goes right; a machine
# green on v3 names a workload by its container and enforces on the
# cgroup the name resolves to, clean on every error path the runtime
# absence and a hostile operator can produce.
#
# Full design notes live in the .py header.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/supermassive-test-v3.py" "$@"
