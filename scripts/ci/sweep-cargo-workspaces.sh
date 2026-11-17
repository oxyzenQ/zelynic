#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# night-deps-1: the workspace sweep the dependency-maintenance lane
# runs, in one reusable script. night-zen-1 made the weekly refresh
# walk EVERY committed Cargo.toml — the root crate and the detached
# ebpf/, proofs/, fuzz/ packages, plus any manifest a future test or
# audit subfolder adds anywhere under the tree — so a new workspace
# joins the weekly lane without touching the workflow. The walk used
# to live as byte-identical inline copies at two sites (the validate
# job's update step and the commit job's staging step): this script
# is the single source now, the twin-constant drift class closed the
# same way install-bpf-linker.sh closed the installer's.
#
# Discovery law: every Cargo.toml under the repo root whose directory
# is not a target tree (cache-restored build output can never join
# the walk), sorted for stable ordering across machines.
#
# Usage:
#   scripts/ci/sweep-cargo-workspaces.sh               # cargo update in each workspace
#   scripts/ci/sweep-cargo-workspaces.sh --print       # print each manifest path
#   scripts/ci/sweep-cargo-workspaces.sh --print-locks # print each workspace's Cargo.lock path
#   scripts/ci/sweep-cargo-workspaces.sh --check       # sweep nothing; exit 1 if a lock is stale
#
# The --check mode is the local twin of the weekly lane: it prints
# the lockfiles a sweep WOULD move (cargo update --dry-run per
# workspace) and fails when any is behind its registry — the same
# verdict the scheduled job commits, without touching a byte.

set -euo pipefail

MODE="${1:-sweep}"
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "${REPO_ROOT}"

# The walk: sorted, target-tree-free, one manifest per line.
manifests() {
	find . -name Cargo.toml -not -path '*/target/*' | sort
}

case "${MODE}" in
--print)
	manifests | sed 's|^\./||'
	;;
--print-locks)
	manifests | sed 's|^\./||; s|Cargo\.toml$|Cargo.lock|'
	;;
--check)
	stale=0
	while IFS= read -r manifest; do
		dir="$(dirname "${manifest}")"
		if ! pending="$(cd "${dir}" && cargo update --dry-run 2>&1)"; then
			echo "FAIL: cargo update --dry-run failed in ${dir}"
			echo "${pending}"
			stale=1
			continue
		fi
		moves="$(echo "${pending}" | grep -c 'Updating ' || true)"
		if [ "${moves}" -gt 0 ]; then
			echo "STALE ${dir}: ${moves} crate(s) behind the registry"
			stale=1
		else
			echo "CURRENT ${dir}"
		fi
	done < <(manifests)
	if [ "${stale}" -ne 0 ]; then
		echo "FAIL: a workspace's lockfile is behind its registry — run the sweep"
		exit 1
	fi
	echo "OK: every committed workspace lockfile is current"
	;;
sweep)
	while IFS= read -r manifest; do
		dir="$(dirname "${manifest}")"
		echo "Refreshing ${dir}"
		(
			cd "${dir}" && cargo update --verbose
		)
	done < <(manifests)
	;;
*)
	echo "usage: $0 [--print | --print-locks | --check]" >&2
	exit 2
	;;
esac
