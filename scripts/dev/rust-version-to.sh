#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). zelynic is a Linux-only tool.
#
# zelynic Rust Toolchain Version Bumper
#
# One command bumps the pinned Rust toolchain version in every structural
# source, with no manual editing:
#
#   ./scripts/dev/rust-version-to.sh 1.99.0
#
# Sources updated (structural — auto-edited):
#   1. rust-toolchain.toml      channel = "X.Y.Z" + header comment
#   2. Cargo.toml               rust-version = "X.Y" (MSRV)
#   3. .github/workflows/*.yml  RUST_VERSION: "X.Y.Z" (CI install pin)
#
# Sources audited (warned, NOT auto-edited):
#   - docs/ tree, README.md, CONTRIBUTING.md — narrative text (release
#     dates, rationale) needs editorial judgement, not mechanical replace.
#
# This is the write counterpart to the read-only verifier
# `scripts/gates/check-rust-version-sync.sh`, which runs as the final gate.
#
# USAGE:
#   ./scripts/dev/rust-version-to.sh <X.Y.Z>           Bump to X.Y.Z (e.g. 1.99.0)
#   ./scripts/dev/rust-version-to.sh --check <X.Y.Z>   Verify everything is at X.Y.Z
#   ./scripts/dev/rust-version-to.sh --allow-dirty <X.Y.Z>  Bump even on dirty tree
#   ./scripts/dev/rust-version-to.sh --help            Show this help
#
# Safety:
#   - Rejects channel aliases (stable/beta/nightly) — dormant-mode policy
#   - Refuses to run if git working tree has unrelated changes
#   - Does not commit, tag, or push automatically
#   - Idempotent: if already at target and in sync, exits 0

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
readonly REPO_ROOT
readonly TOOLCHAIN_TOML="${REPO_ROOT}/rust-toolchain.toml"
readonly CARGO_TOML="${REPO_ROOT}/Cargo.toml"
readonly SYNC_CHECK="${REPO_ROOT}/scripts/gates/check-rust-version-sync.sh"

# Workflows that pin RUST_VERSION (audit.yml skipped — security scanner,
# no build; see check-rust-version-sync.sh for the rationale).
readonly WORKFLOW_SKIP_SET=("audit.yml")

# Doc paths that may contain Rust version references — audited only.
readonly DOC_AUDIT_DIRS=("${REPO_ROOT}/docs")
readonly DOC_AUDIT_FILES=("${REPO_ROOT}/README.md" "${REPO_ROOT}/CONTRIBUTING.md")

# Colors (intentionally neutral escape codes; the [INFO]/[OK]/[WARN]/
# [ERROR] labels carry the semantic weight — ANSI colors break in CI logs
# and piped contexts).
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

log_info() { printf '%b[INFO]%b %s\n' "${BLUE}" "${NC}" "$*"; }
log_ok() { printf '%b[OK]%b %s\n' "${GREEN}" "${NC}" "$*"; }
log_warn() { printf '%b[WARN]%b %s\n' "${YELLOW}" "${NC}" "$*"; }
log_err() { printf '%b[ERROR]%b %s\n' "${RED}" "${NC}" "$*" >&2; }

show_help() {
	cat <<'HELP'
zelynic Rust Toolchain Version Bumper

USAGE:
    ./scripts/dev/rust-version-to.sh <X.Y.Z>                  Bump to X.Y.Z
    ./scripts/dev/rust-version-to.sh --check <X.Y.Z>          Verify pin is X.Y.Z
    ./scripts/dev/rust-version-to.sh --allow-dirty <X.Y.Z>   Bump even on dirty tree
    ./scripts/dev/rust-version-to.sh --help                   Show this help

EXAMPLES:
    ./scripts/dev/rust-version-to.sh 1.99.0           # Bump to 1.99.0
    ./scripts/dev/rust-version-to.sh --check 1.98.1   # Verify current pin

Updated (structural):
    rust-toolchain.toml            channel = "X.Y.Z" + header comment
    Cargo.toml                     rust-version = "X.Y" (MSRV)
    .github/workflows/*.yml        RUST_VERSION: "X.Y.Z" (CI install)

Audited only (warned, NOT auto-edited — narrative text):
    docs/ tree, README.md, CONTRIBUTING.md

Safety:
    - Refuses to run on a dirty git tree (use --allow-dirty to override)
    - Does not commit, tag, or push
    - Idempotent: if already at target and in sync, exits 0
HELP
}

# Accepts: X.Y.Z with digits only (e.g. 1.99.0). Rejects channel aliases
# (dormant-mode policy: a `stable` pin drifts) and pre-release suffixes.
validate_version() {
	local ver="$1"

	if [[ -z "${ver}" ]]; then
		log_err "Version argument is required"
		exit 1
	fi

	case "${ver}" in
	stable | beta | nightly | nightly-*)
		log_err "Channel alias '${ver}' is rejected under dormant-mode policy."
		log_err "Specify a concrete X.Y.Z release (e.g. 1.99.0)."
		exit 1
		;;
	esac

	if [[ "${ver}" == *-* ]]; then
		log_err "Pre-release suffixes are not supported: ${ver}"
		log_err "Expected stable Rust release: X.Y.Z (e.g. 1.99.0)"
		exit 1
	fi

	if ! [[ "${ver}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		log_err "Invalid version format: ${ver}"
		log_err "Expected stable Rust release: X.Y.Z (e.g. 1.99.0)"
		exit 1
	fi
}

# Derive MSRV (major.minor only) from a full X.Y.Z version — the form
# Cargo.toml `rust-version` uses per Rust convention.
derive_msrv() {
	local full="$1"
	echo "${full%.*}"
}

# Read current pinned Rust version from rust-toolchain.toml
# (the authoritative source per check-rust-version-sync.sh).
read_current_rust_version() {
	if [[ ! -f "${TOOLCHAIN_TOML}" ]]; then
		log_err "rust-toolchain.toml not found at ${TOOLCHAIN_TOML}"
		exit 1
	fi

	local ver
	ver="$(grep -E '^channel = ' "${TOOLCHAIN_TOML}" | head -1 |
		sed -E 's/^channel = "(.+)".*/\1/')"

	if [[ -z "${ver}" ]]; then
		log_err "Could not parse channel from ${TOOLCHAIN_TOML}"
		exit 1
	fi

	echo "${ver}"
}

# Safety: check git working tree is clean before editing files.
check_git_status() {
	if ! git -C "${REPO_ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
		log_warn "Not inside a git repository — skipping dirty check"
		return 0
	fi

	local dirty
	dirty="$(git -C "${REPO_ROOT}" status --porcelain 2>/dev/null || true)"

	if [[ -n "${dirty}" ]]; then
		if [[ "${ALLOW_DIRTY}" == "1" ]]; then
			log_warn "Working tree has uncommitted changes (--allow-dirty):"
			git -C "${REPO_ROOT}" status --short
			echo ""
		else
			log_err "Working tree has uncommitted changes. Commit or stash first,"
			log_err "or pass --allow-dirty to proceed anyway."
			echo ""
			git -C "${REPO_ROOT}" status --short
			exit 1
		fi
	fi
}

# Update rust-toolchain.toml: `channel = "X.Y.Z"` + header comments that
# mention the pinned version verbatim.
update_rust_toolchain_toml() {
	local old_full="$1"
	local new_full="$2"

	log_info "Updating rust-toolchain.toml: ${old_full} -> ${new_full}"

	if [[ ! -f "${TOOLCHAIN_TOML}" ]]; then
		log_err "rust-toolchain.toml not found"
		exit 1
	fi

	# 1. channel line (authoritative pin)
	sed -i -E "s|^channel = \"${old_full}\"|channel = \"${new_full}\"|" "${TOOLCHAIN_TOML}"

	# 2. header comment (mentions the pinned version verbatim)
	sed -i -E "s|pinned to ${old_full}|pinned to ${new_full}|g" "${TOOLCHAIN_TOML}"

	# Verify channel line
	local got
	got="$(grep -E '^channel = ' "${TOOLCHAIN_TOML}" | head -1 |
		sed -E 's/^channel = "(.+)".*/\1/')"
	if [[ "${got}" != "${new_full}" ]]; then
		log_err "rust-toolchain.toml channel update failed. Expected: ${new_full}, Got: ${got}"
		exit 1
	fi

	log_ok "rust-toolchain.toml updated: channel = \"${new_full}\""
}

# Update Cargo.toml `rust-version` (MSRV — major.minor form). Only the
# package-level entry; dependency rust-version lines are never touched.
update_cargo_toml() {
	local old_msrv="$1"
	local new_msrv="$2"

	log_info "Updating Cargo.toml: rust-version ${old_msrv} -> ${new_msrv}"

	if [[ ! -f "${CARGO_TOML}" ]]; then
		log_err "Cargo.toml not found"
		exit 1
	fi

	sed -i -E "s|^rust-version = \"${old_msrv}\"|rust-version = \"${new_msrv}\"|" "${CARGO_TOML}"

	local got
	got="$(grep -E '^rust-version = ' "${CARGO_TOML}" | head -1 |
		sed -E 's/^rust-version = "(.+)".*/\1/')"
	if [[ "${got}" != "${new_msrv}" ]]; then
		log_err "Cargo.toml rust-version update failed. Expected: ${new_msrv}, Got: ${got}"
		exit 1
	fi

	log_ok "Cargo.toml updated: rust-version = \"${new_msrv}\""
}

# Workflow skip predicate — mirrors check-rust-version-sync.sh.
workflow_should_skip() {
	local basename="$1"
	for skip in "${WORKFLOW_SKIP_SET[@]}"; do
		if [[ "${basename}" == "${skip}" ]]; then
			return 0
		fi
	done
	return 1
}

# Update .github/workflows/*.yml RUST_VERSION env var (top-level env
# block). Consumer references (`${{ env.RUST_VERSION }}`) are untouched.
update_workflows() {
	local old_full="$1"
	local new_full="$2"

	local wf_dir="${REPO_ROOT}/.github/workflows"
	if [[ ! -d "${wf_dir}" ]]; then
		log_warn ".github/workflows/ not found — skipping workflow updates"
		return 0
	fi

	local updated=0
	local skipped=0

	for wf in "${wf_dir}"/*.yml; do
		[[ -f "${wf}" ]] || continue

		local name
		name="$(basename "${wf}")"

		if workflow_should_skip "${name}"; then
			log_info "  ${name}: skipped (special workflow)"
			skipped=$((skipped + 1))
			continue
		fi

		# Only edit files that actually declare RUST_VERSION as an env var.
		if ! grep -qE '^[[:space:]]*RUST_VERSION:' "${wf}"; then
			log_info "  ${name}: no RUST_VERSION env — skipped"
			continue
		fi

		sed -i -E "s|(RUST_VERSION:[[:space:]]*)\"${old_full}\"|\1\"${new_full}\"|g" "${wf}"

		if grep -qE "RUST_VERSION:[[:space:]]*\"${new_full}\"" "${wf}"; then
			log_ok "  ${name}: RUST_VERSION = \"${new_full}\""
			updated=$((updated + 1))
		else
			log_err "  ${name}: RUST_VERSION update failed (expected ${new_full})"
			exit 1
		fi
	done

	log_info "Workflows: ${updated} updated, ${skipped} skipped"
}

# Audit docs for stale Rust version references. Warn only — narrative
# text (release dates, rationale) needs editorial review.
audit_docs() {
	local old_full="$1"
	local new_full="$2"
	local old_msrv
	old_msrv="$(derive_msrv "${old_full}")"
	local new_msrv
	new_msrv="$(derive_msrv "${new_full}")"

	log_info "Auditing docs/, README.md and CONTRIBUTING.md for stale Rust version references..."

	local audit_paths=()
	local p
	for p in "${DOC_AUDIT_DIRS[@]}" "${DOC_AUDIT_FILES[@]}"; do
		if [[ -e "${p}" ]]; then
			audit_paths+=("${p}")
		fi
	done
	local stale_count=0
	while IFS= read -r match; do
		# match format: "path:line:content"
		local file line content
		file="$(echo "${match}" | cut -d: -f1)"
		line="$(echo "${match}" | cut -d: -f2)"
		content="$(echo "${match}" | cut -d: -f3-)"

		log_warn "  ${file}:${line}: still references old version"
		log_warn "    ${content}"
		stale_count=$((stale_count + 1))
	done < <(grep -rnE "(${old_full}|[^0-9.]${old_msrv}[^.0-9])" "${audit_paths[@]}" 2>/dev/null || true)

	if [[ "${stale_count}" -gt 0 ]]; then
		echo ""
		log_warn "Found ${stale_count} stale doc reference(s) to ${old_full} / ${old_msrv}."
		log_warn "These contain narrative text and were NOT auto-edited. Update them"
		log_warn "by hand, then rerun: ./scripts/dev/rust-version-to.sh --check ${new_full}"
	else
		log_ok "No stale doc references found"
	fi
}

# Run the read-only sync checker as the final verification gate.
verify_sync() {
	local target_full="$1"

	echo ""
	log_info "=== Sync verification (check-rust-version-sync.sh) ==="

	if [[ ! -f "${SYNC_CHECK}" ]]; then
		log_err "scripts/gates/check-rust-version-sync.sh not found — cannot verify"
		return 1
	fi

	if bash "${SYNC_CHECK}"; then
		log_ok "All Rust version sources in sync at ${target_full}"
		return 0
	else
		log_err "Sync check failed — some sources still disagree"
		return 1
	fi
}

# Print summary + next steps.
print_summary() {
	local old_full="$1"
	local new_full="$2"
	shift 2
	local changed_files=("$@")

	echo ""
	echo "=========================================="
	echo " Rust toolchain bumped"
	echo "=========================================="
	echo "  old: ${old_full}"
	echo "  new: ${new_full}"
	echo ""
	echo "  Files changed:"
	for f in "${changed_files[@]}"; do
		echo "    - ${f}"
	done
	echo ""
	echo "Next (verify the new toolchain actually builds):"
	echo "  rustup toolchain install ${new_full}            # install the new toolchain"
	echo "  cargo fmt --all"
	echo "  cargo clippy --all-targets --all-features -- -D warnings"
	echo "  cargo test --features ebpf"
	echo "  ./scripts/build.sh check-all                  # full quality gate"
	echo "  ./scripts/gate-keepers.sh                     # non-code gates"
	echo "  git diff"
	echo "  git commit -s -m \"Internal research: bump pinned Rust toolchain to ${new_full}\""
	echo "  git push origin main"
	echo "=========================================="
}

# Check mode — verify everything is at target, no edits.
run_check_mode() {
	local target_full="$1"

	log_info "Check mode: verifying pin is at ${target_full}"
	echo ""

	local current_full
	current_full="$(read_current_rust_version)"

	if [[ "${current_full}" != "${target_full}" ]]; then
		log_err "rust-toolchain.toml channel = \"${current_full}\" — expected \"${target_full}\""
		exit 1
	fi
	log_ok "rust-toolchain.toml channel = \"${current_full}\""

	# Delegate deeper checks to the read-only sync checker.
	if bash "${SYNC_CHECK}" >/dev/null 2>&1; then
		log_ok "All Rust version sources in sync at ${target_full}"
		exit 0
	else
		log_err "Sources out of sync — rerun: ./scripts/dev/rust-version-to.sh ${target_full}"
		bash "${SYNC_CHECK}" || true
		exit 1
	fi
}

main() {
	local CHECK_MODE=0
	local ALLOW_DIRTY=0
	local TARGET_VERSION=""

	while [[ $# -gt 0 ]]; do
		case "$1" in
		--help | -h)
			show_help
			exit 0
			;;
		--check)
			CHECK_MODE=1
			shift
			;;
		--allow-dirty)
			ALLOW_DIRTY=1
			shift
			;;
		-*)
			log_err "Unknown option: $1"
			show_help
			exit 1
			;;
		*)
			if [[ -n "${TARGET_VERSION}" ]]; then
				log_err "Multiple version arguments provided: ${TARGET_VERSION} and $1"
				exit 1
			fi
			TARGET_VERSION="$1"
			shift
			;;
		esac
	done

	if [[ -z "${TARGET_VERSION}" ]]; then
		log_err "Version argument is required"
		echo ""
		show_help
		exit 1
	fi

	validate_version "${TARGET_VERSION}"

	local NEW_FULL="${TARGET_VERSION}"
	local NEW_MSRV
	NEW_MSRV="$(derive_msrv "${NEW_FULL}")"

	local OLD_FULL
	OLD_FULL="$(read_current_rust_version)"
	local OLD_MSRV
	OLD_MSRV="$(derive_msrv "${OLD_FULL}")"

	log_info "Current pin: ${OLD_FULL} (MSRV ${OLD_MSRV})"
	log_info "Target pin:  ${NEW_FULL} (MSRV ${NEW_MSRV})"
	echo ""

	# ── Check mode ──
	if [[ "${CHECK_MODE}" -eq 1 ]]; then
		run_check_mode "${NEW_FULL}"
	fi

	# Idempotent check — if already at target and in sync, exit 0.
	if [[ "${OLD_FULL}" == "${NEW_FULL}" ]]; then
		if bash "${SYNC_CHECK}" >/dev/null 2>&1; then
			log_info "Already at ${NEW_FULL} — all sources in sync"
			exit 0
		fi
		log_info "Pin is at ${NEW_FULL} but other sources out of sync — auto-syncing"
		echo ""
	fi

	# Safety: check git working tree
	check_git_status

	local changed_files=()

	# 1. rust-toolchain.toml (channel + header comment)
	update_rust_toolchain_toml "${OLD_FULL}" "${NEW_FULL}"
	changed_files+=("rust-toolchain.toml")

	# 2. Cargo.toml (rust-version MSRV)
	update_cargo_toml "${OLD_MSRV}" "${NEW_MSRV}"
	changed_files+=("Cargo.toml")

	# 3. .github/workflows/*.yml (RUST_VERSION env var)
	update_workflows "${OLD_FULL}" "${NEW_FULL}"
	local wf_dir="${REPO_ROOT}/.github/workflows"
	if [[ -d "${wf_dir}" ]]; then
		local wf name
		for wf in "${wf_dir}"/*.yml; do
			[[ -f "${wf}" ]] || continue
			name="$(basename "${wf}")"
			if workflow_should_skip "${name}"; then
				continue
			fi
			if ! git -C "${REPO_ROOT}" diff --quiet -- "${wf}" 2>/dev/null; then
				changed_files+=(".github/workflows/${name}")
			fi
		done
	fi

	# 4. Audit docs (warn only)
	audit_docs "${OLD_FULL}" "${NEW_FULL}"

	# 5. Run sync verifier as final gate
	if ! verify_sync "${NEW_FULL}"; then
		log_err "Sync verification failed — see output above"
		exit 1
	fi

	# 6. Print summary
	print_summary "${OLD_FULL}" "${NEW_FULL}" "${changed_files[@]}"
}

main "$@"
