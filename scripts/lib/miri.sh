# shellcheck shell=bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# ZELYNIC BUILD MODULE: miri (NIGHT-improve-75)
#
# Miri (the undefined-behavior detector) integration, cosmostrix's
# mature shape ported whole: the stamp file contract, the status
# banner shown on every build.sh invocation, and the nightly-driven
# runner scoped to the pure-Rust module families that are rootless by
# design (the #[path]-wired pin families in test/ — Pattern C).
#
# Why scoped, not whole-suite: miri interprets every instruction, so
# the full 900+ test suite would take 30+ minutes, and several test
# families spawn the real binary, touch cgroups/TTY, or need root +
# eBPF — shapes miri cannot run. The families below are the
# string/math/logic core the limiter's promises are written in; they
# are exactly where an unsafe-adjacent refactor would first lie.
#
# The admission law (the sibling zejtron containment, ported from the
# zylaxion night-dinner-6 miri incident — night-dragon-maintenance-1):
# on the sibling, a CI miri run hung past 30 minutes with 93% of its
# wall clock inside FIVE tests — two full-text README/CHANGELOG
# doc-assertion scans (~23 minutes interpreted) and three sample-loop
# render tests (~6 minutes). All five were pure safe code with no
# pointer/borrow surface: interpreter food, zero UB signal. The
# audited families are the pointer/alloc/UB surface, NOT the docs
# lane or a sample-loop stage. A test that full-text scans README/
# CHANGELOG, burns an unbounded numeric/render loop, or streams
# sample frames is useless work under an interpreter and must never
# enter the families below without
#   #[cfg_attr(miri, ignore = "<the reason>")]
# (the night-guard-1 pattern) — natively it still runs in every other
# lane, where ci.yml and the docs gates own the docs assertions and
# the math loops. zelynic's eight families carry no such test today
# (verified 2026-10-26, night-dragon-maintenance-1: zero README or
# CHANGELOG references in the whole test/ tree, no unbounded ranges
# in the family files); this law is what keeps it true.
#
# The measured record the fail-fast cap is sized against: 2026-10-26,
# nightly 1.101.0-nightly, both lanes (dormant + ebpf), 95 tests,
# 0 violations, 319.7s (~5.3 min) on an 8-core host — stamp
# target/miri-stamp, log target/miri-log.txt. The workflow's
# timeout-minutes carries the sizing story (the ~2.5-4x CI-shape
# headroom over this record); a future burden test that inflates the
# run past that boundary fails loudly inside the budget instead of
# hanging the runner for 30+ minutes.
#
# The structural containment (night-dragon-maintenance-4, the second
# half of the incident's lesson — the audit found the port held the
# families-level admission law but left two class-level doors open):
#   1. the lane invocations pass --tests, so the DOCTEST lane never
#      rides the interpreter — cargo miri test compiles and runs
#      rustdoc examples by default, and a future doc example is
#      exactly the docs/burden shape the sibling hung on (23 of its
#      33 hang-minutes were docs full-text scans). Today the repo
#      carries zero runnable doctests (verified: the one doc block is
#      ```text); --tests makes that an INVARIANT instead of an audit
#      fact. Doctests stay natively verified in every other lane,
#      where the docs gates own them.
#   2. every lane walk runs under a coreutils timeout budget
#      (MIRI_LANE_BUDGET, default 900s — ~5.6x the measured per-lane
#      record) so the containment holds on a LOCAL run too: the
#      workflow's timeout-minutes protects CI, but ./scripts/build.sh
#      miri used to hang a dev machine indefinitely on the same
#      burden shape. A budget expiry dies loudly with the incident
#      framing (rc 124/137), stamping FAILED — it can never read
#      like a pass.
#
# Scope (substring filters against the full test path):
#   - limiter::during::    the --during grammar, translation, verdict twin
#   - ebpf::display::      the status table + the ceil countdown pins
#   - display_json::       the --print-json document contract
#   - output::color::      the color ladder
#   - output::theme::      the theme catalog
#   - cli::ux::            the CLI UX contract pins (incl. the color law)
#   - cli::argv::          the argv pre-scan pins
#   - terminal::diff::     the frame differ
#
# Verification status is cached in target/miri-stamp (key=value format)
# so a build does not re-run miri; a banner at the start of every
# build.sh invocation reflects the stamp state:
#   - VERIFIED  — stamp commit == HEAD
#   - STALE     — stamp commit != HEAD (suggests a re-run)
#   - FAILED    — the last run had violations
#   - NEVER RUN — no stamp yet
#
# Sourced by scripts/build.sh — not a standalone executable (no main,
# no argument parsing; the entry script owns both).

# The runner's own defaults (the entry script's parser fills these).
MIRI_FILTER="${MIRI_FILTER:-}"
MIRI_NO_INSTALL="${MIRI_NO_INSTALL:-0}"
MIRI_FULL="${MIRI_FULL:-0}"
# The per-lane wall-clock budget in seconds (night-dragon-maintenance-4,
# the structural containment — see the header). 900s is ~5.6x the
# measured per-lane record (319.7s total / 2 lanes on an 8-core host,
# a 2-core box compiles ~2-3x slower and still fits). The CI job's
# timeout-minutes is the outer belt; this is the local-run belt.
MIRI_LANE_BUDGET="${MIRI_LANE_BUDGET:-900}"

readonly MIRI_STAMP_FILE="target/miri-stamp"
readonly MIRI_LOG_FILE="target/miri-log.txt"

# resolve_nightly_name — the toolchain name the runner addresses.
# Plain `nightly` wins (what CI installs and what +nightly resolves);
# a dated nightly (the eBPF lane's nightly-YYYY-MM-DD pin) is the
# fallback so a machine that never installed the moving tag still
# runs. Empty means: nothing nightly-shaped, the caller installs.
resolve_nightly_name() {
	rustup toolchain list 2>/dev/null | awk '$1 == "nightly" {print $1; exit}'
}

# The scope, split by compile lane (NIGHT-ask-2's split): each family
# runs on the lane where it lives, so no pin is interpreted twice and
# both lanes stay inside their time budget.
readonly MIRI_AUDIT_MODULES_DORMANT=(
	"output::color::"
	"output::theme::"
	"cli::ux::"
	"cli::argv::"
	"terminal::diff::"
)
readonly MIRI_AUDIT_MODULES_EBPF=(
	"limiter::during::"
	"ebpf::display::"
	"display_json::"
)

# show_miri_status — print the one-line stamp banner. Called from
# build.sh's main() on every build/test command; quiet under -q (the
# banner is informational status output, not a verdict — the same
# quiet law NIGHT-boost-7 set for the log_info family).
show_miri_status() {
	[ "${QUIET:-0}" -eq 1 ] && return 0

	local head head_short
	head=$(git rev-parse HEAD 2>/dev/null || echo "")
	head_short=$(git rev-parse --short HEAD 2>/dev/null || echo "")

	if [ ! -f "${MIRI_STAMP_FILE}" ]; then
		log_info "Miri: never run on this workspace. Run './scripts/build.sh miri' to verify (needs nightly, ~3-10 min)."
		return 0
	fi

	# Parse the stamp (key=value format, no jq dependency; the || true
	# guards a truncated stamp under the entry script's set -e).
	local stamp_commit stamp_short stamp_ts_iso stamp_status stamp_dur stamp_run stamp_fail
	stamp_commit=$(grep '^commit=' "${MIRI_STAMP_FILE}" | cut -d= -f2- || true)
	stamp_short=$(grep '^commit_short=' "${MIRI_STAMP_FILE}" | cut -d= -f2- || true)
	stamp_ts_iso=$(grep '^timestamp_iso=' "${MIRI_STAMP_FILE}" | cut -d= -f2- || true)
	stamp_status=$(grep '^status=' "${MIRI_STAMP_FILE}" | cut -d= -f2- || true)
	stamp_dur=$(grep '^duration_ms=' "${MIRI_STAMP_FILE}" | cut -d= -f2- || true)
	stamp_run=$(grep '^tests_run=' "${MIRI_STAMP_FILE}" | cut -d= -f2- || true)
	stamp_fail=$(grep '^tests_failed=' "${MIRI_STAMP_FILE}" | cut -d= -f2- || true)

	local dur_sec=""
	if [ -n "${stamp_dur}" ]; then
		dur_sec=$(awk -v ms="${stamp_dur}" 'BEGIN { printf "%.1f", ms/1000 }')
	fi

	case "${stamp_status}" in
	verified)
		if [ "${stamp_commit}" = "${head}" ]; then
			log_success "Miri VERIFIED at ${stamp_short} · ${stamp_ts_iso} · ${stamp_run} tests (${stamp_fail} fail) · ${dur_sec}s"
		else
			log_warning "Miri STALE — verified at ${stamp_short}, HEAD is ${head_short}. Run './scripts/build.sh miri' to refresh."
		fi
		;;
	failed)
		log_error "Miri FAILED at ${stamp_short} · ${stamp_ts_iso} · ${stamp_fail} violations. See ${MIRI_LOG_FILE}."
		;;
	skipped:*)
		local reason="${stamp_status#skipped:}"
		log_info "Miri SKIPPED (${reason}) at ${stamp_short}. Run './scripts/build.sh miri' to verify."
		;;
	*)
		log_info "Miri: unknown status '${stamp_status}' at ${stamp_short}."
		;;
	esac
}

# run_miri — run Miri verification on the pure-Rust module families
# and update the stamp file. Args (parsed by build.sh before main):
#   --filter <pat>  narrow the scope to one substring (a partial run;
#                   the stamp is NOT updated)
#   --no-install    never auto-install nightly/miri (CI's contract —
#                   the workflow installs its own pinned toolchain, so
#                   a missing component must fail loudly, not download)
#   --full          run the ENTIRE test suite on both lanes (slow;
#                   families that spawn the binary or need root will
#                   fail under miri)
run_miri() {
	local filter="${MIRI_FILTER}"
	local full="${MIRI_FULL}"

	# 1. rustup is required (nightly management is its job).
	if ! command -v rustup &>/dev/null; then
		log_error "rustup not installed. Miri requires nightly. Install from https://rustup.rs"
		exit 1
	fi

	# 2. Resolve (or install) the nightly toolchain the runner rides.
	local nightly_name
	nightly_name=$(resolve_nightly_name)
	if [ -z "${nightly_name}" ]; then
		nightly_name=$(rustup toolchain list 2>/dev/null | awk '$1 ~ /^nightly-/ {print $1; exit}')
	fi
	if [ -z "${nightly_name}" ]; then
		if [ "${MIRI_NO_INSTALL}" = "1" ]; then
			log_error "nightly toolchain not installed and --no-install given. Aborting."
			exit 1
		fi
		log_step "Installing nightly toolchain (rustup toolchain install nightly --profile minimal --component miri)..."
		rustup toolchain install nightly --profile minimal --component miri || {
			log_error "Failed to install nightly + miri. Try manually: rustup toolchain install nightly --component miri"
			exit 1
		}
		nightly_name="nightly"
	else
		# 3. Ensure the miri component is installed on that nightly. Modern
		#    rustup emits per-target lines (miri-x86_64-... (installed)),
		#    so the separator after `miri` can be a hyphen (newer) or a
		#    space (older) — match both.
		if ! rustup component list --toolchain "${nightly_name}" 2>/dev/null | grep -q '^miri[-[:space:]].*installed'; then
			if [ "${MIRI_NO_INSTALL}" = "1" ]; then
				log_error "miri component not installed on ${nightly_name} and --no-install given. Aborting."
				exit 1
			fi
			log_step "Installing miri component on ${nightly_name}..."
			rustup component add miri --toolchain "${nightly_name}" || {
				log_error "Failed to install miri component."
				exit 1
			}
		fi
	fi

	local nightly_ver miri_ver
	nightly_ver=$(rustc "+${nightly_name}" --version 2>/dev/null | head -1)
	miri_ver=$(cargo "+${nightly_name}" miri --version 2>/dev/null | head -1)
	log_info "Miri: ${miri_ver}"
	log_info "Nightly: ${nightly_ver}"

	# 4. One-time libstd setup, non-interactive (a prompt mid-run would
	#    hang CI and a piped local run alike).
	log_step "Ensuring the Miri sysroot is set up (cargo +nightly miri setup)..."
	cargo "+${nightly_name}" miri setup 2>&1 | tail -3 || true

	# 5. Build the test filter lists — one per lane. An explicit
	#    --filter rides BOTH lanes (a partial probe, no stamp update);
	#    the default scope walks each family on its own lane.
	local -a dormant_args=() ebpf_args=()
	if [ -n "${filter}" ]; then
		dormant_args=("${filter}")
		ebpf_args=("${filter}")
		log_step "Running Miri with filter on both lanes: ${filter}"
	elif [ "${full}" = "1" ]; then
		log_step "Running Miri on the FULL test suite on both lanes (slow; binary-spawning and root-gated families will fail under miri)..."
	else
		read -r -a dormant_args <<<"${MIRI_AUDIT_MODULES_DORMANT[*]}"
		read -r -a ebpf_args <<<"${MIRI_AUDIT_MODULES_EBPF[*]}"
		log_step "Scope: ${#dormant_args[@]} dormant families + ${#ebpf_args[@]} ebpf families (${dormant_args[*]} ${ebpf_args[*]})"
	fi

	# 6. Run Miri on BOTH feature lanes. --locked: the lockfile-freeze
	#    contract every other gate rides (NIGHT-boost-7). The pure core
	#    the scope names lives on two compile lanes (NIGHT-ask-2): the
	#    --during grammar, the status renderers, and --print-json sit
	#    inside src/ebpf/** — gated behind the `ebpf` feature — while
	#    the color/ux/argv/theme/diff pins ride the dormant lane. One
	#    lane alone would verify half the estate, so the runner walks
	#    both: dormant first (no prerequisites), then the full-feature
	#    lane, which in a git checkout drives build.rs's nested eBPF
	#    build and therefore needs the dated nightly + rust-src +
	#    bpf-linker stack (scripts/dev/bootstrap-ebpf.sh). A machine
	#    without that stack skips lane 2 with a loud warning and the
	#    stamp records what actually ran — a skip must never read like
	#    a pass (the NIGHT-boost-7 law).
	#    MIRIFLAGS disables isolation so the pure pins that read env
	#    vars, clocks, or temp paths do not fail spuriously. Test
	#    filters ride the harness argv (after --); the cargo options
	#    stay before it.
	run_miri_lane() {
		# $1: the lane selector ("dormant" or "ebpf"); $2..: harness
		# filters (may be empty). The feature spec is spelled HERE, not
		# at the call site — "--features ebpf" is two words, and a
		# half-arg call site would hand cargo a bare --features (the
		# failure the selector spelling can never produce).
		local lane="$1"
		shift
		local -a lane_args=()
		case "$lane" in
		dormant) lane_args=(--no-default-features) ;;
		ebpf) lane_args=(--features ebpf) ;;
		*)
			log_error "run_miri_lane: unknown lane '$lane'"
			exit 1
			;;
		esac
		local -a harness_args=("$@")
		# --tests (night-dragon-maintenance-4): the doctest lane never
		# rides the interpreter — the structural containment the header
		# documents. The audited families are unit/integration targets;
		# a future doc example cannot re-enter the run by shape.
		local -a miri_cmd=(cargo "+${nightly_name}" miri test --locked --tests "${lane_args[@]}")
		if [ "${#harness_args[@]}" -gt 0 ]; then
			miri_cmd+=(-- "${harness_args[@]}")
		fi
		# The per-lane wall-clock budget (night-dragon-maintenance-4):
		# the CI job's timeout-minutes is the outer belt; this is the
		# belt that also holds on a local run. A burden shape dies
		# loudly (rc 124 = budget, 137 = kill-after) instead of
		# hanging the runner or a dev machine indefinitely.
		local rc=0
		if command -v timeout >/dev/null 2>&1; then
			MIRIFLAGS="${MIRIFLAGS:--Zmiri-disable-isolation}" \
				timeout --kill-after=30s "${MIRI_LANE_BUDGET}" \
				"${miri_cmd[@]}" 2>&1 | tee -a "${MIRI_LOG_FILE}" || rc=$?
		else
			log_warning "coreutils timeout not found — the per-lane budget guard is off (the structural containment runs unbelted)"
			MIRIFLAGS="${MIRIFLAGS:--Zmiri-disable-isolation}" \
				"${miri_cmd[@]}" 2>&1 | tee -a "${MIRI_LOG_FILE}" || rc=$?
		fi
		if [ "${rc}" -eq 124 ] || [ "${rc}" -eq 137 ]; then
			log_error "the ${lane} lane hit its ${MIRI_LANE_BUDGET}s wall-clock budget (rc=${rc}) — a burden shape (a docs full-text scan, an unbounded loop) died the loud death the containment law promises instead of hanging the run. Inspect ${MIRI_LOG_FILE} for the last family alive."
		fi
		return "${rc}"
	}

	local start_ms end_ms duration_ms
	start_ms=$(date +%s%3N 2>/dev/null || date +%s)

	mkdir -p target
	rm -f "${MIRI_LOG_FILE}"
	local miri_exit=0 lanes_run="dormant"

	log_step "Lane 1/2: the dormant lane (--no-default-features), ${#dormant_args[@]} families..."
	run_miri_lane dormant "${dormant_args[@]}" || miri_exit=1

	local ebpf_stack=1
	rustup toolchain list 2>/dev/null | grep -q '^nightly-2026-09-18' || ebpf_stack=0
	command -v bpf-linker >/dev/null 2>&1 || ebpf_stack=0
	if [ "${ebpf_stack}" = "1" ]; then
		log_step "Lane 2/2: the full-feature lane (--features ebpf), ${#ebpf_args[@]} families..."
		if run_miri_lane ebpf "${ebpf_args[@]}"; then
			lanes_run="dormant+ebpf"
		else
			miri_exit=1
		fi
	else
		log_warning "ebpf lane skipped — the eBPF stack is missing (the nightly-2026-09-18 pin with rust-src, bpf-linker on PATH). Install: ./scripts/dev/bootstrap-ebpf.sh. The ${#ebpf_args[@]} ebpf-lane families went unverified; the stamp records the partial scope."
	fi

	end_ms=$(date +%s%3N 2>/dev/null || date +%s)
	duration_ms=$((end_ms - start_ms))

	# 7. Parse the result counts (summed across every test binary; the
	#    || true guards a compile-failure log that holds no summary).
	local tests_run=0 tests_failed=0
	tests_run=$(grep -oE '[0-9]+ passed' "${MIRI_LOG_FILE}" 2>/dev/null | awk '{s+=$1} END {print s+0}' || true)
	tests_failed=$(grep -oE '[0-9]+ failed' "${MIRI_LOG_FILE}" 2>/dev/null | awk '{s+=$1} END {print s+0}' || true)

	# 8. The verdict. A verified run that matched ZERO tests is a
	#    drift smell, not a pass — the scope list names module paths,
	#    and a rename would otherwise turn the gate green while
	#    checking nothing.
	local status
	if [ "${miri_exit}" = "0" ] && [ "${tests_failed}" = "0" ]; then
		status="verified"
		if [ "${tests_run}" = "0" ]; then
			log_warning "Miri matched 0 tests — a scope family may have drifted. Check MIRI_AUDIT_MODULES against the #[path] wiring."
		fi
		log_success "Miri verification PASSED (${tests_run} tests, 0 fail, ${duration_ms}ms)"
	else
		status="failed"
		log_error "Miri verification FAILED (${tests_failed} failures, ${duration_ms}ms). See ${MIRI_LOG_FILE}."
	fi

	# 9. Stamp file. Partial runs (--filter/--full) do not update it —
	#    they do not represent the audited scope.
	if [ -n "${filter}" ] || [ "${full}" = "1" ]; then
		log_info "Partial run — stamp file not updated. Run './scripts/build.sh miri' (no flags) to refresh."
	else
		local head head_short ts_iso ts_unix
		head=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
		head_short=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
		ts_unix=$(date +%s)
		ts_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)

		local modules
		modules=$(
			IFS=','
			echo "${MIRI_AUDIT_MODULES_DORMANT[*]} ${MIRI_AUDIT_MODULES_EBPF[*]}"
		)

		cat >"${MIRI_STAMP_FILE}" <<STAMP_EOF
# zelynic Miri verification stamp (generated by scripts/build.sh miri)
# Format: key=value. Parse with grep '^key=' | cut -d= -f2-
commit=${head}
commit_short=${head_short}
timestamp_unix=${ts_unix}
timestamp_iso=${ts_iso}
status=${status}
duration_ms=${duration_ms}
tests_run=${tests_run}
tests_failed=${tests_failed}
lanes_run=${lanes_run}
modules=${modules}
miri_version=${miri_ver}
nightly_version=${nightly_ver}
STAMP_EOF
		log_info "Stamp written to ${MIRI_STAMP_FILE} (lanes: ${lanes_run})"
		log_info "Log saved to ${MIRI_LOG_FILE}"
	fi

	if [ "${miri_exit}" != "0" ] || [ "${tests_failed}" != "0" ]; then
		exit 1
	fi
}
