#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# ZELYNIC COMMIT-TIME ACTIONS-PIN HEALTH CHECK (NIGHT-improve-40)
#
# The commit-time, contributor-seat arm of the actions-pin self-heal
# contract (NIGHT-improve-39 built the weekly arm). Three arms, one
# engine:
#   - weekly, server-side: .github/workflows/self-heal.yml — Dragon
#     Guard heals and pushes the estate on the Monday clock even
#     when nobody commits
#   - commit-time, contributor seat: THIS CHECK — every commit on a
#     wired clone (core.hooksPath=.githooks, self-installed by
#     gate-keepers.sh section 0) reads the pins' freshness against
#     upstream; current costs one line, behind prints the classified
#     table (MAJOR / MINOR / PATCH), never silently
#   - shared engine: scripts/ci/actions-version-sweep.sh --dry-run —
#     the same version truth and the same honesty rules, one
#     implementation; this script never duplicates that math
#
# Advisory by default, and that is a design decision, not softness:
# the prebuilt lane contract (check-commit-gate sections 1-2) fails
# closed because parity is a LOCAL fact this machine can always
# prove; pin freshness is a REMOTE fact that needs the network, the
# API's quota, and GitHub's answer right now. A gate that blocks a
# contributor's commit on facts it cannot reach would be a
# dishonest gate (the sweep's own precedent: a push the platform
# provably refuses is never attempted). Strict contributors opt in
# with git config zelynic.actionsHealthCheck strict — that blocks
# on a KNOWN-stale verdict, and only on a known one; every skip
# reason (offline, quota low, missing tool, overrun budget,
# indeterminate sweep) stays a skip, never a block.
#
# Speed contract: a commit must not wait on the network. The
# verdict is cached under $GIT_DIR/zelynic/ keyed on the workflows'
# content hash (any workflow edit re-checks) with a TTL (upstream
# releases re-check even without edits). A cold check runs the
# sweep under a timeout budget; a check that overruns the budget
# skips with a note while a background refresh (--refresh-cache,
# internal) writes the cache for the next commit. A cached hit
# costs zero API calls and needs no network at all.
#
# Output contract parsed from the sweep (stable since
# NIGHT-improve-39): the "sweep verdict: N healed, N kept, N
# skipped" line and the HEAL note lines "SWEEP: repo (file:line) —
# cur -> new ... HEAL". A verdict that does not parse is an honest
# skip, never a fake "current" — format drift fails safe.
#
# Modes (off | warn | strict; default warn):
#   ZELYNIC_ACTIONS_HEALTH           one-shot, beats the git config
#   git config zelynic.actionsHealthCheck   repo-local, persistent
#
# Tunables (env, optional):
#   ZELYNIC_ACTIONS_HEALTH_TTL       cache seconds (default 21600 = 6h)
#   ZELYNIC_ACTIONS_HEALTH_TIMEOUT   cold-sweep budget seconds (default 30)
#   GITHUB_TOKEN                     optional authenticated API reads
#                                    (the sweep picks it up too)
#
# Usage:
#   bash scripts/gates/check-actions-pins.sh                # the check
#   bash scripts/gates/check-actions-pins.sh --refresh-cache # internal

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

SWEEP_SCRIPT="scripts/ci/actions-version-sweep.sh"
API_ROOT="https://api.github.com"
DEFAULT_TTL=21600
DEFAULT_TIMEOUT=30
QUOTA_FLOOR=70

# ── output helpers ─────────────────────────────────────────────────────────

health() { echo "HEALTH: $*"; }
skip_check() {
	health "skipped — $*"
	exit 0
}

usage() {
	cat <<'EOF'
scripts/gates/check-actions-pins.sh — the commit-time actions-pin
health check (NIGHT-improve-40; the contract story lives in this
file's header and in scripts/gates/check-commit-gate.sh).

modes (off | warn | strict, default warn):
  ZELYNIC_ACTIONS_HEALTH=strict git commit ...        one-shot
  git config zelynic.actionsHealthCheck strict        repo-local

tunables (env):
  ZELYNIC_ACTIONS_HEALTH_TTL       cache seconds (default 21600)
  ZELYNIC_ACTIONS_HEALTH_TIMEOUT   cold-sweep budget (default 30s)
EOF
}

# ── environment readers ────────────────────────────────────────────────────

resolve_mode() {
	local mode
	if [ -n "${ZELYNIC_ACTIONS_HEALTH:-}" ]; then
		mode="$ZELYNIC_ACTIONS_HEALTH"
	else
		mode="$(git config --get zelynic.actionsHealthCheck 2>/dev/null || true)"
	fi
	case "$mode" in
	off | warn | strict) printf '%s' "$mode" ;;
	"") printf 'warn' ;;
	*)
		health "unknown mode '${mode}' — treating as warn"
		printf 'warn'
		;;
	esac
}

ttl_seconds() {
	local t="${ZELYNIC_ACTIONS_HEALTH_TTL:-$DEFAULT_TTL}"
	[[ $t =~ ^[0-9]+$ ]] || t="$DEFAULT_TTL"
	printf '%s' "$t"
}

timeout_seconds() {
	local t="${ZELYNIC_ACTIONS_HEALTH_TIMEOUT:-$DEFAULT_TIMEOUT}"
	[[ $t =~ ^[0-9]+$ ]] || t="$DEFAULT_TIMEOUT"
	printf '%s' "$t"
}

cache_file() {
	printf '%s/zelynic/actions-pins.cache' "$(git rev-parse --git-dir)"
}

workflows_hash() {
	local files
	files=(.github/workflows/*.yml)
	sha256sum "${files[@]}" | sha256sum | cut -d' ' -f1
}

# ── version math (classification only; the sweep owns the truth) ───────────

bump_class() {
	local cur="$1" new="$2"
	local c1 c2 c3 n1 n2 n3
	IFS='.' read -r c1 c2 c3 <<<"${cur#v}"
	IFS='.' read -r n1 n2 n3 <<<"${new#v}"
	[[ ${c1:-x} =~ ^[0-9]+$ && ${n1:-x} =~ ^[0-9]+$ ]] || {
		printf 'MOVE'
		return 0
	}
	if [ "${c1:-0}" -ne "${n1:-0}" ]; then
		printf 'MAJOR'
	elif [ "${c2:-0}" -ne "${n2:-0}" ]; then
		printf 'MINOR'
	elif [ "${c3:-0}" -ne "${n3:-0}" ]; then
		printf 'PATCH'
	else
		printf 'RE-PIN'
	fi
}

age_label() {
	local age="$1"
	if [ "$age" -lt 90 ]; then
		printf 'checked just now'
	elif [ "$age" -lt 5400 ]; then
		printf 'cache %dm old' "$(((age + 59) / 60))"
	else
		printf 'cache %dh old' "$(((age + 3599) / 3600))"
	fi
}

# ── verdict rendering ──────────────────────────────────────────────────────
#
# render_verdict <payload-file> <age-label> <mode>
#   returns 0 = current, 1 = behind, 2 = indeterminate

RE_HEAL='^SWEEP: ([^ ]+) \([^)]+\) — ([^ ,]+) -> ([^ ,]+)'
RE_VERDICT='^sweep verdict: ([0-9]+) healed, ([0-9]+) kept, ([0-9]+) skipped'

render_verdict() {
	local payload="$1" label="$2" mode="$3"
	local line repo cur new key uses cls
	healed=""
	kept=0
	skipped=0
	local -A seen=()
	local -a keys=()
	local major_n=0 minor_n=0 patch_n=0 repin_n=0 move_n=0 pin_n=0

	# Honesty first: any pin the sweep could not size up makes the
	# whole verdict unknown — "api unreachable" (quota, network) and
	# "unresolvable" (a release whose commit SHA would not resolve)
	# never read as "current".
	if grep -Eq 'api unreachable|unresolvable' "$payload"; then
		health "skipped — the sweep could not size up every pin (API unreachable mid-sweep); no verdict"
		return 2
	fi

	while IFS= read -r line; do
		if [[ $line =~ $RE_HEAL ]] && [[ $line == *" HEAL"* ]]; then
			repo="${BASH_REMATCH[1]}"
			cur="${BASH_REMATCH[2]}"
			new="${BASH_REMATCH[3]}"
			key="${repo}|${cur}|${new}"
			if [ -n "${seen[$key]:-}" ]; then
				seen[$key]=$((seen[$key] + 1))
			else
				seen[$key]=1
				keys+=("$key")
			fi
		elif [[ $line =~ $RE_VERDICT ]]; then
			healed="${BASH_REMATCH[1]}"
			kept="${BASH_REMATCH[2]}"
			skipped="${BASH_REMATCH[3]}"
		fi
	done <"$payload"

	if [ -z "$healed" ]; then
		health "skipped — the sweep's verdict line did not parse; no verdict"
		return 2
	fi
	if [ "$healed" -gt 0 ] && [ "${#keys[@]}" -eq 0 ]; then
		health "skipped — the sweep's HEAL lines did not parse; no verdict"
		return 2
	fi

	if [ "$healed" -eq 0 ]; then
		if [ "$((kept + skipped))" -gt 0 ]; then
			health "CI actions pins current — ${kept} kept, ${skipped} skipped-for-cause (${label})"
		else
			health "CI actions pins current — no version pins found (${label})"
		fi
		return 0
	fi

	# The classified table: one row per distinct pin move, with the
	# pin count when the same action is pinned in many files.
	local repo_w=0 cur_w=0 new_w=0 r c n
	for key in "${keys[@]}"; do
		IFS='|' read -r r c n <<<"$key"
		[ "${#r}" -gt "$repo_w" ] && repo_w="${#r}"
		[ "${#c}" -gt "$cur_w" ] && cur_w="${#c}"
		[ "${#n}" -gt "$new_w" ] && new_w="${#n}"
	done
	if [ "$mode" = "strict" ]; then
		health "FAIL — CI actions pins are behind upstream (strict mode; the commit is blocked):"
	else
		health "WARNING — CI actions pins are behind upstream (advisory mode; the commit proceeds):"
	fi
	echo ""
	for key in "${keys[@]}"; do
		IFS='|' read -r r c n <<<"$key"
		uses="${seen[$key]}"
		cls="$(bump_class "$c" "$n")"
		pin_n=$((pin_n + uses))
		move_n=$((move_n + 1))
		case "$cls" in
		MAJOR) major_n=$((major_n + 1)) ;;
		MINOR) minor_n=$((minor_n + 1)) ;;
		PATCH) patch_n=$((patch_n + 1)) ;;
		RE-PIN) repin_n=$((repin_n + 1)) ;;
		esac
		printf '    %-*s  %-*s -> %-*s  [%s]' "$repo_w" "$r" "$cur_w" "$c" "$new_w" "$n" "$cls"
		[ "$uses" -gt 1 ] && printf '  (%d pins)' "$uses"
		echo ""
	done
	local repin_note=""
	[ "$repin_n" -gt 0 ] && repin_note=" (+${repin_n} SHA re-pin)"
	echo ""
	health "${pin_n} pins behind across ${move_n} moves — ${major_n} MAJOR, ${minor_n} MINOR, ${patch_n} PATCH${repin_note}"
	if [ "$mode" = "strict" ]; then
		echo ""
		echo "    heal and re-commit:  scripts/ci/actions-version-sweep.sh --apply"
		echo "    or update first:     git pull (the weekly Dragon Guard may have healed them)"
		echo "    one-shot advisory:   ZELYNIC_ACTIONS_HEALTH=warn git commit ..."
		echo "    skip every hook:     git commit --no-verify"
	else
		echo ""
		echo "    heal locally:        scripts/ci/actions-version-sweep.sh --apply"
		echo "    or update first:     git pull (the weekly Dragon Guard may have healed them)"
		echo "    make it blocking:    git config zelynic.actionsHealthCheck strict"
		echo "    silence for once:    ZELYNIC_ACTIONS_HEALTH=off git commit ..."
	fi
	return 1
}

# ── network pre-flight ─────────────────────────────────────────────────────
#
# preflight: 0 = API reachable with quota, 1 = unreachable,
# 2 = quota below the floor. /rate_limit does not count against the
# core quota; the floor (70) covers a cold sweep's worst case
# (every distinct action repo costs a releases/latest read, a
# tags fallback, and one or two refs/tags SHA resolutions).

preflight() {
	local body status remaining
	local args=(-sS --connect-timeout 5 --max-time 8 -w '\n%{http_code}')
	args+=("${API_ROOT}/rate_limit")
	if [ -n "${GITHUB_TOKEN:-}" ]; then
		args+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
	fi
	body="$(curl "${args[@]}" 2>/dev/null || true)"
	status="${body##*$'\n'}"
	[ "$status" = "200" ] || return 1
	remaining="$(printf '%s' "${body%$'\n'*}" | jq -r '.resources.core.remaining // empty' 2>/dev/null || true)"
	[[ $remaining =~ ^[0-9]+$ ]] || return 0
	[ "$remaining" -ge "$QUOTA_FLOOR" ] || return 2
	return 0
}

# ── cache ──────────────────────────────────────────────────────────────────
#
# One file: a "epoch<TAB>workflows-hash" meta line, then the sweep
# payload. Writes are atomic (tmp + mv) so a background refresh
# never hands a reader a half-written verdict.

write_cache() {
	local payload="$1" epoch hash tmp
	epoch="$(date +%s)"
	hash="$(workflows_hash)"
	tmp="$(cache_file).tmp.$$"
	mkdir -p "$(dirname "$(cache_file)")"
	{
		printf '%s\t%s\n' "$epoch" "$hash"
		cat "$payload"
	} >"$tmp"
	mv "$tmp" "$(cache_file)"
}

# ── the background refresh (internal) ──────────────────────────────────────

refresh_cache() {
	local payload rc
	payload="$(mktemp /tmp/zelynic-health-refresh.XXXXXX)"
	trap 'rm -f "$payload"' EXIT
	preflight || exit 0
	rc=0
	bash "$SWEEP_SCRIPT" --dry-run >"$payload" 2>&1 || rc=$?
	if [ "$rc" -eq 0 ] && ! grep -Eq 'api unreachable|unresolvable' "$payload"; then
		write_cache "$payload"
	fi
	exit 0
}

# ── main ───────────────────────────────────────────────────────────────────

main() {
	local mode hash epoch c_hash age payload rc
	case "${1:-}" in
	--refresh-cache) refresh_cache ;;
	-h | --help)
		usage
		exit 0
		;;
	"") ;;
	*)
		echo "unknown argument: $1 (this gate takes none; --refresh-cache is internal)" >&2
		exit 2
		;;
	esac

	# Guards: every one of these is a skip, never a failure — a
	# contributor's commit never dies because a health probe could
	# not run.
	command -v git >/dev/null 2>&1 || skip_check "git not found"
	git rev-parse --git-dir >/dev/null 2>&1 || skip_check "not inside a git work tree"
	local tools_missing=""
	for tool in curl jq sha256sum timeout; do
		command -v "$tool" >/dev/null 2>&1 || tools_missing="${tools_missing} ${tool}"
	done
	[ -z "$tools_missing" ] || skip_check "missing tools:${tools_missing} (the check needs curl, jq, sha256sum, timeout)"
	[ -f "$SWEEP_SCRIPT" ] || skip_check "the sweep engine ${SWEEP_SCRIPT} is not in this tree"
	shopt -s nullglob
	local workflows=(.github/workflows/*.yml)
	shopt -u nullglob
	[ "${#workflows[@]}" -gt 0 ] || skip_check "no .github/workflows/*.yml in this tree"

	mode="$(resolve_mode)"
	[ "$mode" = "off" ] && exit 0

	# Cache hit: same workflows content, within the TTL. Costs zero
	# API calls and no network.
	hash="$(workflows_hash)"
	if [ -f "$(cache_file)" ]; then
		local meta
		meta="$(head -n 1 "$(cache_file)" 2>/dev/null || true)"
		epoch="${meta%%$'\t'*}"
		c_hash="${meta##*$'\t'}"
		if [[ $epoch =~ ^[0-9]+$ ]] && [ "$c_hash" = "$hash" ]; then
			age=$(($(date +%s) - epoch))
			if [ "$age" -lt "$(ttl_seconds)" ]; then
				payload="$(mktemp /tmp/zelynic-health-hit.XXXXXX)"
				trap 'rm -f "$payload"' EXIT
				tail -n +2 "$(cache_file)" >"$payload"
				rc=0
				render_verdict "$payload" "$(age_label "$age")" "$mode" || rc=$?
				if [ "$rc" -eq 1 ] && [ "$mode" = "strict" ]; then
					exit 1
				fi
				exit 0
			fi
		fi
	fi

	# Cold check: pre-flight, then the sweep under a budget.
	rc=0
	preflight || rc=$?
	if [ "$rc" -eq 1 ]; then
		skip_check "GitHub API unreachable (offline or blocked); pins unchecked"
	elif [ "$rc" -eq 2 ]; then
		skip_check "GitHub API quota below ${QUOTA_FLOOR} calls; pins unchecked (retry after the quota resets, or export GITHUB_TOKEN)"
	fi

	payload="$(mktemp /tmp/zelynic-health-cold.XXXXXX)"
	trap 'rm -f "$payload"' EXIT
	if timeout "$(timeout_seconds)" bash "$SWEEP_SCRIPT" --dry-run >"$payload" 2>&1; then
		rc=0
		render_verdict "$payload" "checked just now" "$mode" || rc=$?
		if [ "$rc" -eq 2 ]; then
			exit 0
		fi
		write_cache "$payload"
		if [ "$rc" -eq 1 ] && [ "$mode" = "strict" ]; then
			exit 1
		fi
		exit 0
	fi
	# Overran the budget (or the sweep itself failed): skip loudly,
	# refresh in the background so the next commit reads a verdict.
	health "skipped — the sweep overran its $(timeout_seconds)s budget; refreshing in the background, the next commit reads the verdict"
	mkdir -p "$(dirname "$(cache_file)")"
	nohup bash "$REPO_ROOT/scripts/gates/check-actions-pins.sh" --refresh-cache >/dev/null 2>&1 &
	exit 0
}

main "$@"
