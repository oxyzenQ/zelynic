#!/bin/bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# =============================================================================
# ZELYNIC BUILD AUTOMATION SCRIPT
# =============================================================================
# Optimized build script with intelligent core detection and advanced caching
# Author: rezky_nightky (oxyzenQ)
# Version: (read dynamically from Cargo.toml)

set -euo pipefail

# Source Rust environment if available
# shellcheck disable=SC1091
[ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Configuration with intelligent defaults
readonly PROJECT_NAME="zelynic"

# Read version from Cargo.toml (single source of truth)
ZELYNIC_VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/' || echo "unknown")
readonly ZELYNIC_VERSION

default_target() {
	if command -v rustc >/dev/null 2>&1; then
		local host
		host=$(rustc -vV 2>/dev/null | sed -n 's/^host: //p' || true)
		if [ -n "${host}" ]; then
			echo "${host}"
			return 0
		fi
	fi
	echo "x86_64-unknown-linux-gnu"
}

readonly TARGET="${ZELYNIC_TARGET:-$(default_target)}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

# Intelligent job calculation: 75% of cores, min 1, max 8 for heat control
calculate_jobs() {
	local cores
	cores=$(nproc 2>/dev/null || echo 4)
	local jobs=$((cores * 3 / 4))
	jobs=$((jobs < 1 ? 1 : jobs))
	jobs=$((jobs > 8 ? 8 : jobs))
	echo "$jobs"
}

MAX_JOBS="${ZELYNIC_JOBS:-$(calculate_jobs)}"
export MAKEFLAGS="-j${MAX_JOBS}"
export CARGO_BUILD_JOBS="${MAX_JOBS}"

# Rust optimization flags
export CARGO_TERM_COLOR=always

# =============================================================================
# Logging Functions
# =============================================================================

# NIGHT-boost-7: log_info/log_step are the banners and step
# headers — the lines -q suppresses. The verdict-bearing calls
# (log_success, log_warning, log_error) always emit: a quiet run
# still shows every per-check OK, every skip warning (a skipped
# gate must never look like a passed one), and every failure.
log_info() {
	if [ "${QUIET:-0}" -eq 0 ]; then
		echo -e "${BLUE}[INFO]${NC} $1"
	fi
}

log_success() {
	echo -e "${GREEN}[OK]${NC} $1"
}

log_warning() {
	echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
	echo -e "${RED}[FAIL]${NC} $1" >&2
}

log_step() {
	if [ "${QUIET:-0}" -eq 0 ]; then
		echo -e "${CYAN}[→]${NC} $1"
	fi
}

cargo_subcommand_available() {
	local subcommand="$1"
	cargo "${subcommand}" --version >/dev/null 2>&1
}

# =============================================================================
# Toolchain & Environment Setup
# =============================================================================

check_rust_toolchain() {
	log_step "Checking Rust toolchain..."

	if ! command -v rustup &>/dev/null; then
		log_error "rustup not installed. Install from: https://rustup.rs"
		exit 1
	fi

	if ! command -v rustc &>/dev/null; then
		log_error "rustc not available in PATH. Install a Rust toolchain with rustup."
		exit 1
	fi

	if [ -z "${TARGET}" ]; then
		log_error "Could not determine Rust host target (TARGET is empty)."
		exit 1
	fi

	# Ensure target is installed
	if ! rustup target list --installed | grep -q "^${TARGET}$"; then
		log_info "Installing target: ${TARGET}"
		rustup target add "${TARGET}"
	fi

	log_success "Rust toolchain ready"
}

setup_build_cache() {
	log_step "Configuring build acceleration..."

	# Check and setup sccache
	if command -v sccache &>/dev/null; then
		# Disable incremental compilation when using sccache (they conflict)
		export CARGO_INCREMENTAL=0
		export RUSTC_WRAPPER=sccache
		# Start sccache server if not running
		sccache --start-server 2>/dev/null || true
		log_success "sccache enabled (build caching active)"
	else
		# Enable incremental compilation when not using sccache
		export CARGO_INCREMENTAL=1
		log_warning "sccache not found. Install: cargo install sccache --locked"
	fi

	# Check for mold linker
	if command -v mold &>/dev/null; then
		export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-fuse-ld=mold"
		log_success "mold linker enabled (faster linking)"
	elif command -v lld &>/dev/null; then
		export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-fuse-ld=lld"
		log_success "lld linker enabled"
	else
		log_warning "Fast linker not found (mold/lld)."
	fi

	# Setup cargo-nextest if available
	if command -v cargo-nextest &>/dev/null; then
		NEXTEST_AVAILABLE=1
		log_success "cargo-nextest available (faster testing)"
	else
		NEXTEST_AVAILABLE=0
		log_warning "cargo-nextest not found. Install: cargo install cargo-nextest --locked"
	fi
}

show_system_info() {
	log_info "Build Configuration:"
	echo "  ├─ OS: $(uname -s) $(uname -m)"
	echo "  ├─ CPU Cores: $(nproc)"
	echo "  ├─ Build Jobs: ${MAX_JOBS}"
	echo "  ├─ Target: ${TARGET}"
	echo "  ├─ Rust: $(rustc --version)"
	echo "  ├─ Cargo: $(cargo --version)"
	echo "  ├─ Incremental: ${CARGO_INCREMENTAL:-1}"
	echo "  └─ Cache: ${RUSTC_WRAPPER:-none}"
}

# =============================================================================
# Dependency Management
# =============================================================================

update_dependencies() {
	log_step "Updating dependencies..."

	if ! cargo update --quiet; then
		log_error "Failed to update dependencies"
		return 1
	fi

	# Security audit
	if cargo_subcommand_available audit; then
		if cargo audit --quiet 2>/dev/null; then
			log_success "Security audit passed"
		else
			log_warning "Security vulnerabilities detected (run 'cargo audit' for details)"
		fi
	else
		log_warning "cargo-audit not installed. Install: cargo install cargo-audit --locked"
	fi

	log_success "Dependencies updated"
}

# =============================================================================
# Build Functions
# =============================================================================

build_debug() {
	log_step "Building debug binary..."

	if cargo build --profile dev --target "${TARGET}" --jobs "${MAX_JOBS}"; then
		local binary="target/${TARGET}/debug/${PROJECT_NAME}"
		local size
		size=$(du -h "$binary" 2>/dev/null | cut -f1 || echo "unknown")
		log_success "Debug build complete (${size})"
		echo "  └─ Binary: ${binary}"
	else
		log_error "Debug build failed"
		return 1
	fi
}

# =============================================================================
# Quality & Lint Functions
# =============================================================================

run_tests() {
	log_step "Running test suite..."

	# --locked (NIGHT-boost-7): CI and the owner's gate must never
	# drift — the lockfile is committed, so a test run that would
	# rewrite it fails instead of silently regenerating it.
	if [ "${NEXTEST_AVAILABLE:-0}" -eq 1 ]; then
		if cargo nextest run --locked --target "${TARGET}" --jobs "${MAX_JOBS}"; then
			log_success "All tests passed (nextest)"
		else
			log_error "Tests failed"
			return 1
		fi
	else
		if cargo test --locked --target "${TARGET}" --jobs "${MAX_JOBS}" -- --test-threads="${MAX_JOBS}"; then
			log_success "All tests passed"
		else
			log_error "Tests failed"
			return 1
		fi
	fi
}

run_clippy() {
	log_step "Running Clippy linter..."

	# --locked: same lockfile-freeze contract as run_tests above.
	if cargo clippy --locked --target "${TARGET}" --all-targets --all-features -- -D warnings; then
		log_success "Clippy checks passed"
	else
		log_error "Clippy found issues"
		return 1
	fi
}

run_fmt_check() {
	log_step "Checking code formatting..."

	if cargo fmt --all -- --check; then
		log_success "Code formatting is correct"
	else
		log_error "Formatting issues found. Run: cargo fmt --all"
		return 1
	fi
}

run_fmt_fix() {
	log_step "Formatting code..."
	cargo fmt --all
	log_success "Code formatted"
}

run_audit() {
	log_step "Running security audit..."

	if ! cargo_subcommand_available audit; then
		log_warning "cargo-audit not installed (skipping). Install: cargo install cargo-audit --locked"
		return 0
	fi

	if cargo audit; then
		log_success "Security audit passed"
	else
		log_warning "Security issues detected"
		return 1
	fi
}

run_deny_check() {
	log_step "Checking dependency policies..."

	if ! cargo_subcommand_available deny; then
		log_warning "cargo-deny not installed (skipping). Install: cargo install cargo-deny --locked"
		return 0
	fi

	if [ ! -f "deny.toml" ]; then
		log_warning "deny.toml not found (skipping cargo-deny). Add deny.toml to enforce policies."
		return 0
	fi

	if cargo deny check all; then
		log_success "Dependency policy checks passed"
	else
		log_error "Dependency policy violations found"
		return 1
	fi
}

run_policy_check() {
	log_step "Running repository policy checks..."

	if python3 scripts/gates/check-policy.py; then
		log_success "Repository policy checks passed"
	else
		log_error "Repository policy checks failed"
		return 1
	fi
}

run_version_anti_pattern_check() {
	log_step "Checking for hardcoded version-string anti-patterns..."

	if [ ! -f "scripts/gates/check-version-anti-patterns.sh" ]; then
		log_error "scripts/gates/check-version-anti-patterns.sh not found"
		return 1
	fi

	if bash scripts/gates/check-version-anti-patterns.sh; then
		log_success "Version anti-pattern check passed"
	else
		log_error "Version anti-pattern check failed (use env!(\"CARGO_PKG_VERSION\") instead)"
		return 1
	fi
}

run_comprehensive_check() {
	local failed=0

	if [ "${QUIET:-0}" -eq 0 ]; then
		echo ""
		log_info "=== Comprehensive Code Quality Check ==="
		echo ""
	fi

	check_rust_toolchain || ((failed++))
	run_fmt_check || ((failed++))
	run_clippy || ((failed++))
	run_tests || ((failed++))
	run_audit || ((failed++))
	run_deny_check || ((failed++))
	run_policy_check || ((failed++))
	run_version_anti_pattern_check || ((failed++))

	if [ "${QUIET:-0}" -eq 0 ]; then
		echo ""
	fi
	if [ $failed -eq 0 ]; then
		log_success "All quality checks passed!"
		return 0
	else
		log_error "$failed check(s) failed"
		return 1
	fi
}

run_quick_check() {
	log_step "Running quick checks..."
	run_fmt_check && run_clippy
}

# =============================================================================
# Utility Functions
# =============================================================================

clean_build() {
	log_step "Cleaning build artifacts..."
	cargo clean
	if command -v sccache &>/dev/null; then
		sccache --zero-stats 2>/dev/null || true
	fi
	log_success "Build artifacts cleaned"
}

show_cache_stats() {
	if command -v sccache &>/dev/null; then
		echo ""
		log_info "=== Build Cache Statistics ==="
		sccache --show-stats
	else
		log_warning "sccache not available"
	fi
}

# =============================================================================
# Help
# =============================================================================

show_help() {
	cat <<EOF
╔════════════════════════════════════════════════════════════════╗
║           Zelynic Build Script - v${ZELYNIC_VERSION}                  ║
║        Per-app network rate limiter for Linux                ║
╚════════════════════════════════════════════════════════════════╝

USAGE:
    ./scripts/build.sh [COMMAND] [OPTIONS]

COMMANDS:
    debug           Build debug version (default)
    test            Run test suite

    check           Quick checks (fmt + clippy)
    check-all       Recommended local quality gate (fmt + clippy + test
                    + audit + deny + policy + version anti-pattern)
    fmt             Format code
    clean           Clean build artifacts
    update          Update dependencies and audit

    stats           Show build cache statistics
    help            Show this help

PRODUCT BUILDS (NIGHT-cleanup-3): this script is the CHECK
orchestrator — release binaries do not come from here. Build with
./scripts/dev/bootstrap-ebpf.sh (dev, cargo pro-native-gnu) or
./scripts/install.sh (user install, pro-native gnu/musl). The old
basic-profile release/release-debug/ci/all/bench subcommands were
retired: nobody called them, cargo bench had zero [[bench]]
targets to run, and a plain --profile release path contradicts
the pro-native mandate.

OPTIONS:
    --no-cache      Disable build caching
    --verbose       Enable verbose output
    --quiet, -q     Essentials only: per-check OK / warning / failure
                    lines, no banners or step headers (the CI shape;
                    NIGHT-boost-7)

ENVIRONMENT VARIABLES:
    ZELYNIC_JOBS     Override CPU core limit (default: auto)
    ZELYNIC_TARGET   Override build target (default: rustc host target)
    RUST_BACKTRACE   Control backtrace verbosity (default: 1)

EXAMPLES:
    ./scripts/build.sh check-all                # Recommended before commits/PRs
    ./scripts/build.sh check-all -q             # Essentials only (CI shape)
    ./scripts/build.sh debug                    # Debugger-ready dev build
    ZELYNIC_JOBS=4 ./scripts/build.sh test      # Tests capped at 4 cores

TOOLS INTEGRATION:
    sccache   - Build caching (install: cargo install sccache)
    nextest   - Fast test runner (install: cargo install cargo-nextest)
    audit     - Security auditing (optional; missing tool warns/skips)
                install: cargo install cargo-audit --locked
    deny      - Dependency policies (optional; missing tool warns/skips)
                install: cargo install cargo-deny --locked

EOF
}

# =============================================================================
# Argument Parsing
# =============================================================================

VERBOSE=0
NO_CACHE=0
QUIET=0
COMMAND=""

ARGS=()
while [ $# -gt 0 ]; do
	case "$1" in
	--verbose | -v)
		VERBOSE=1
		export RUST_BACKTRACE=full
		shift
		;;
	--no-cache)
		NO_CACHE=1
		unset RUSTC_WRAPPER
		shift
		;;
	--quiet | -q)
		QUIET=1
		shift
		;;
	help | -h | --help)
		COMMAND="help"
		shift
		;;
	*)
		if [ -z "${COMMAND}" ]; then
			COMMAND="$1"
			shift
		else
			ARGS+=("$1")
			shift
		fi
		;;
	esac
done

if [ "${VERBOSE}" -eq 1 ]; then
	set -x
fi

# =============================================================================
# Main Execution
# =============================================================================

main() {
	# Ensure we're in a Rust project
	if [ ! -f "Cargo.toml" ]; then
		log_error "Not in a Rust project directory (Cargo.toml not found)"
		exit 1
	fi

	# Setup environment
	if [ $NO_CACHE -eq 0 ]; then
		setup_build_cache
	fi

	local command="${COMMAND:-debug}"

	if [ ${#ARGS[@]} -ne 0 ]; then
		log_error "Unexpected extra arguments: ${ARGS[*]}"
		echo ""
		show_help
		exit 1
	fi

	case "$command" in
	debug)
		check_rust_toolchain
		show_system_info
		build_debug
		;;
	test)
		check_rust_toolchain
		run_tests
		;;
	check)
		check_rust_toolchain
		run_quick_check
		;;
	check-all | --check-all)
		run_comprehensive_check
		;;
	fmt | format)
		run_fmt_fix
		;;
	clean)
		clean_build
		;;
	update)
		check_rust_toolchain
		update_dependencies
		;;
	stats)
		show_cache_stats
		;;
	help | -h | --help)
		show_help
		;;
	*)
		log_error "Unknown command: $command"
		echo ""
		show_help
		exit 1
		;;
	esac
}

# Execute with error handling
if main "$@"; then
	exit 0
else
	log_error "Build script failed"
	exit 1
fi
