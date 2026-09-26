#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). zelynic is a Linux-only tool.
#
# The zelynic CLI smoke battery (NIGHT-blade-10) — one command, every
# CLI surface, run as ROOT inside the sandbox micro-VM by
# scripts/sandbox/zelynic-sandbox.sh --smoke. It also runs anywhere
# root + eBPF work (a bare metal box, a CI runner): the only
# assumptions are cgroup v2 at /sys/fs/cgroup and loopback up.
#
# What it proves, one SANDBOX-RESULT row at a time:
#   * the surface verbs: -V/-h/doctor/list-apps/status/recover, the
#     strict/block/unstrict x single/multi/all matrix, eagle-eyes
#     --depth (text + JSON), the live monitor's interactive-stdio
#     gate, the global flags (--print-json scope, --color-mode, -v)
#   * the guards: invalid rates, the 1 KB/s floor, the dangerous
#     target blocklist (+ --force-this), unknown verbs, unknown
#     flags, the empty target — every refusal a clean non-zero exit,
#     never a panic
#   * real policing: a loopback transfer through a 500kb cap vs the
#     unlimited baseline — the limiter must actually slow the bytes
#   * leaks: zero BPF pins, zero /run/zelynic state, zero lingering
#     processes after unstrict-all + recover
#   * security: an unprivileged (uid 65534) invocation must be
#     refused cleanly — no partial application, no panic
#
# Rows print as SANDBOX-RESULT (the verdict contract the sandbox
# entrypoint greps); the FAILURES counter rides the exit code and the
# final SMOKE-VERDICT line (sandbox-init.sh owns the SANDBOX-VERDICT
# relay, so this script deliberately does not print one).

set -u

BIN="/opt/zelynic/zelynic"
CG_ROOT="/sys/fs/cgroup"
FLEET_A="${CG_ROOT}/zelynic-smoke-a"
FLEET_B="${CG_ROOT}/zelynic-smoke-b"
FLEET_C="${CG_ROOT}/zelynic-smoke-c"
TMP="$(mktemp -d /tmp/zelynic-smoke.XXXXXX)"
SRV_DIR="${TMP}/srv"
PORT=8765
FAILURES=0

# ── plumbing ────────────────────────────────────────────────────────────

row() {
	# row <name> <ok:0|1> [detail] — one SANDBOX-RESULT row.
	if [ "$2" -eq 0 ]; then
		echo "SANDBOX-RESULT: cli $1 — PASS"
	else
		echo "SANDBOX-RESULT: cli $1 — FAIL${3:+ ($3)}"
		FAILURES=$((FAILURES + 1))
	fi
}

run() {
	# run <cmd...> — capture stdout+stderr into OUT, rc into RC.
	OUT="$("$@" 2>&1)"
	RC=$?
}

expect_ok() {
	# expect_ok <name> <cmd...> — rc 0, no panic in the output.
	local name="$1"
	shift
	run "$@"
	if [ "$RC" -eq 0 ] && ! grep -q "panicked" <<<"$OUT"; then
		row "$name" 0
	else
		row "$name" 1 "rc=${RC}: $(head -c 120 <<<"$OUT")"
	fi
}

expect_refused() {
	# expect_refused <name> <pattern> <cmd...> — non-zero rc, the
	# pattern present, no panic (a refusal is a contract, a crash
	# is a bug).
	local name="$1" pattern="$2"
	shift 2
	run "$@"
	if [ "$RC" -ne 0 ] && ! grep -q "panicked" <<<"$OUT" && grep -qi "$pattern" <<<"$OUT"; then
		row "$name" 0
	else
		row "$name" 1 "rc=${RC}: $(head -c 120 <<<"$OUT")"
	fi
}

expect_refused_clean() {
	# expect_refused_clean <name> <cmd...> — non-zero rc, no panic,
	# no pattern pinned (for surfaces whose refusal wording is not a
	# stable contract yet).
	local name="$1"
	shift
	run "$@"
	if [ "$RC" -ne 0 ] && ! grep -q "panicked" <<<"$OUT"; then
		row "$name" 0
	else
		row "$name" 1 "rc=${RC}: $(head -c 120 <<<"$OUT")"
	fi
}

json_field() {
	# json_field <python-expr over doc> — stdin: one JSON document.
	python3 -c "
import json, sys
doc = json.load(sys.stdin)
print($1)
"
}

run_in_cgroup() {
	# run_in_cgroup <cgroup-path> <cmd...> — the harness pattern:
	# the worker moves ITSELF into the cgroup before exec, so the
	# first socket the command opens is already attributed.
	local cg="$1"
	shift
	bash -c 'echo $$ > "$1/cgroup.procs"; shift; exec "$@"' worker "$cg" "$@"
}

spawn_sleeper() {
	# spawn_sleeper <cgroup-path> <seconds> — a resident process for
	# the fleet cgroup (backgrounded).
	bash -c 'echo $$ > "$1/cgroup.procs"; shift; exec "$@"' worker "$1" sleep "$2" &
}

run_unprivileged() {
	# run_unprivileged <cmd...> — drop to uid/gid 65534 (nobody),
	# then exec; the child keeps no privilege.
	python3 - "$@" <<'PYEOF'
import os, sys
os.setgroups([])
os.setgid(65534)
os.setuid(65534)
os.execv(sys.argv[1], ['zelynic'] + sys.argv[2:])
PYEOF
}

# ── the fleet: three cgroups with resident sleepers ─────────────────────

fleet_setup() {
	mkdir -p "$FLEET_A" "$FLEET_B" "$FLEET_C" 2>/dev/null
	spawn_sleeper "$FLEET_A" 900
	spawn_sleeper "$FLEET_B" 900
	spawn_sleeper "$FLEET_C" 900
	sleep 1
	# The cgroup ID is the kernfs inode — the same number
	# bpf_skb_cgroup_id() reports; verify it against list-apps.
	CG_A="$(stat -c %i "$FLEET_A")"
	CG_B="$(stat -c %i "$FLEET_B")"
	CG_C="$(stat -c %i "$FLEET_C")"
	run "$BIN" list-apps --print-json
	if [ "$RC" -eq 0 ]; then
		SEEN=$(json_field "':'.join(str(a['cgroup_id']) for a in doc['apps'])" <<<"$OUT")
	else
		SEEN=""
	fi
	if [ -n "${SEEN:-}" ] && grep -q ":${CG_A}:" <<<":${SEEN}:"; then
		row "fleet (cgroup ids resolve: a=${CG_A} b=${CG_B} c=${CG_C})" 0
	else
		row "fleet (cgroup ids resolve: a=${CG_A} b=${CG_B} c=${CG_C})" 1 "list-apps saw: ${SEEN:-<nothing>}"
	fi
}

# ── group A: the surface verbs ──────────────────────────────────────────

surfaces() {
	run "$BIN" -V
	if [ "$RC" -eq 0 ] && grep -Eq "^zelynic:? v?[0-9]+\.[0-9]+" <<<"$OUT"; then
		row "-V (version string)" 0
	else
		row "-V (version string)" 1 "rc=${RC}: $(head -c 120 <<<"$OUT")"
	fi

	run "$BIN" -h
	if [ "$RC" -eq 0 ] && grep -q "strict-single" <<<"$OUT" && grep -q "eagle-eyes" <<<"$OUT"; then
		row "-h (help lists the verb families)" 0
	else
		row "-h (help lists the verb families)" 1 "rc=${RC}"
	fi

	expect_ok "doctor (bpf syscall answers)" "$BIN" doctor
	expect_ok "list-apps (text table)" "$BIN" list-apps
	expect_ok "list-apps --print-json (valid document)" \
		bash -c "\"$BIN\" list-apps --print-json | python3 -m json.tool >/dev/null"
	expect_ok "status (text surface)" "$BIN" status
	expect_ok "status --print-json (valid document)" \
		bash -c "\"$BIN\" status --print-json | python3 -m json.tool >/dev/null"
	expect_ok "recover (clean no-op)" "$BIN" recover
}

# ── group B: the enforcement matrix ─────────────────────────────────────

enforcement() {
	expect_ok "strict-single cg:A 500kb (both directions)" \
		"$BIN" strict-single "cg:${CG_A}" 500kb
	expect_ok "strict-single cg:B -d 300kb -u 400kb (per-direction)" \
		"$BIN" strict-single "cg:${CG_B}" -d 300kb -u 400kb
	expect_ok "status --print-json (two rows after two singles)" \
		bash -c "\"$BIN\" status --print-json | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d[\"active_limits\"] >= 2 else 1)'"
	expect_ok "unstrict-single cg:A" "$BIN" unstrict-single "cg:${CG_A}"
	expect_ok "unstrict-single cg:B" "$BIN" unstrict-single "cg:${CG_B}"

	expect_ok "strict-multi cg:A:cg:B 1mb (shared bucket)" \
		"$BIN" strict-multi "cg:${CG_A}:cg:${CG_B}" 1mb
	expect_ok "status (rows present under the multi policy)" \
		bash -c "\"$BIN\" status --print-json | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d[\"active_limits\"] >= 1 else 1)'"
	expect_ok "unstrict-multi cg:A:cg:B" "$BIN" unstrict-multi "cg:${CG_A}:cg:${CG_B}"

	expect_ok "strict-all --force-this (sweep, generous rate)" \
		"$BIN" strict-all --force-this 500kb
	expect_ok "unstrict-all (after strict-all)" "$BIN" unstrict-all

	expect_ok "block-single cg:B (zero-rate policy)" \
		"$BIN" block-single "cg:${CG_B}"
	expect_ok "block-multi cg:A:cg:B" "$BIN" block-multi "cg:${CG_A}:cg:${CG_B}"
	expect_ok "block-all --force-this" "$BIN" block-all --force-this
	expect_ok "unstrict-all (after the block matrix)" "$BIN" unstrict-all
	expect_ok "status --print-json (zero rows after teardown)" \
		bash -c "\"$BIN\" status --print-json | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d[\"active_limits\"] == 0 else 1)'"
}

# ── group C: the guards ─────────────────────────────────────────────────

guards() {
	expect_refused "invalid rate (clean refusal + tip)" "invalid rate" \
		"$BIN" strict-single "cg:${CG_A}" 10potatoes
	expect_refused "rate below the 1 KB/s floor" "below minimum" \
		"$BIN" strict-single "cg:${CG_A}" 500b
	expect_refused "dangerous target blocklist (kthreadd)" "system process" \
		"$BIN" strict-single kthreadd 1mb
	expect_ok "dangerous target + --force-this (override honored)" \
		"$BIN" strict-single kthreadd 1mb --force-this
	expect_ok "unstrict-all (drop the forced policy)" "$BIN" unstrict-all
	# An empty target resolves to a clean no-op ("No cgroup found,
	# nothing to limit", exit 0) — the idempotent-cleanup contract;
	# a crash or a silent success without the miss line would fail.
	run "$BIN" strict-single "" 1mb
	if ! grep -q "panicked" <<<"$OUT" &&
		{ [ "$RC" -ne 0 ] || grep -qi "No cgroup found" <<<"$OUT"; }; then
		row "empty target (clean miss, not a crash)" 0
	else
		row "empty target (clean miss, not a crash)" 1 "rc=${RC}: $(head -c 120 <<<"$OUT")"
	fi
	expect_refused_clean "unknown subcommand (redirect tip, not a crash)" \
		"$BIN" limit-single brave 1mb
	expect_refused_clean "unknown flag on a verb" \
		"$BIN" status --bogus-flag
	# doctor HONORS --print-json (it is a report surface — the v11
	# scripting API): the document must parse and exit 0.
	expect_ok "doctor --print-json (report surface: valid document)" \
		bash -c "\"$BIN\" doctor --print-json | python3 -m json.tool >/dev/null"
	expect_ok "--color-mode 0 (mono honored)" "$BIN" -V --color-mode 0
	expect_ok "--color-mode 24 (truecolor honored)" "$BIN" -V --color-mode 24
	expect_refused "--color-mode 7 (grammar enforced)" "invalid --color-mode" \
		"$BIN" -V --color-mode 7
	expect_ok "-v verbose flag (status still clean)" "$BIN" -v status
}

# ── group D: eagle-eyes ─────────────────────────────────────────────────

eagle() {
	expect_ok "ee cg:A --depth (one-shot text report)" \
		"$BIN" ee "cg:${CG_A}" --depth
	run "$BIN" ee "cg:${CG_A}" --depth
	if [ "$RC" -eq 0 ] && grep -qi "enforcement" <<<"$OUT"; then
		row "ee --depth report carries the enforcement verdict" 0
	else
		row "ee --depth report carries the enforcement verdict" 1 "rc=${RC}"
	fi
	expect_ok "ee cg:A --depth --print-json (valid document)" \
		bash -c "\"$BIN\" ee cg:${CG_A} --depth --print-json | python3 -m json.tool >/dev/null"
	# The depth document's root is {"targets": [...]} with UNTAGGED
	# entries — a resolved target IS the report object (cgroup_id
	# present), a miss carries a reason instead.
	expect_ok "ee --depth --print-json (targets[0] carries the report)" \
		bash -c "\"$BIN\" ee cg:${CG_A} --depth --print-json | python3 -c 'import json,sys; d=json.load(sys.stdin); t=d[\"targets\"][0]; sys.exit(0 if all(k in t for k in (\"target\",\"cgroup_id\",\"enforcement\")) else 1)'"
	# A missing target is a clean MISS (the report prints the reason
	# line and exits 0 — the miss contract), never a crash.
	run "$BIN" ee cg:4294967295 --depth
	if ! grep -q "panicked" <<<"$OUT" &&
		{ [ "$RC" -eq 0 ] || { [ "$RC" -ne 0 ] && ! grep -qi "error" <<<"$OUT"; }; }; then
		row "ee --depth on a missing target (clean miss)" 0
	else
		row "ee --depth on a missing target (clean miss)" 1 "rc=${RC}: $(head -c 120 <<<"$OUT")"
	fi
	# The live monitor owns the console: without a tty the stdio gate
	# must refuse (NIGHT-boost-28) — clean, named, non-zero.
	run "$BIN" ee </dev/null
	if [ "$RC" -ne 0 ] && grep -qi "not a terminal" <<<"$OUT" && ! grep -q "panicked" <<<"$OUT"; then
		row "ee live gate (refuses a non-tty stdio)" 0
	else
		row "ee live gate (refuses a non-tty stdio)" 1 "rc=${RC}: $(head -c 120 <<<"$OUT")"
	fi
	expect_refused_clean "ee --interval out of bounds refused" \
		"$BIN" ee --interval 0s </dev/null
}

# ── group E: real policing on loopback ──────────────────────────────────

policing() {
	# A 1 MiB blob served from the root cgroup; the download is
	# policed at the RECEIVER's ingress (loopback rule). 500kb cap =
	# 500,000 B/s -> the limited fetch must take >= ~1.5 s and beat
	# the unlimited baseline by a clear ratio.
	mkdir -p "$SRV_DIR"
	python3 - "$SRV_DIR" <<'PYEOF'
import os, sys
with open(os.path.join(sys.argv[1], "blob"), "wb") as fh:
    fh.write(b"x" * 1_000_000)
PYEOF
	cat >"${TMP}/client.py" <<'PYEOF'
import sys, time, urllib.request
t0 = time.monotonic()
with urllib.request.urlopen(sys.argv[1], timeout=90) as resp:
    size = len(resp.read())
elapsed_ms = int((time.monotonic() - t0) * 1000)
print(f"{elapsed_ms} {size}")
PYEOF
	(cd "$SRV_DIR" && exec python3 -m http.server "$PORT" --bind 127.0.0.1) >/dev/null 2>&1 &
	SRV_PID=$!
	sleep 2
	URL="http://127.0.0.1:${PORT}/blob"

	# Baseline: the payload's own (root, unlimited) cgroup fetches
	# the blob — no cgroup move needed, the fleet sleepers never
	# touch the wire.
	if python3 "${TMP}/client.py" "$URL" >"${TMP}/base.out" 2>"${TMP}/base.err"; then
		BASE_MS=$(awk '{print $1}' "${TMP}/base.out")
	else
		BASE_MS=""
	fi
	if [ -n "${BASE_MS:-}" ]; then
		row "policing baseline (unlimited fetch works: ${BASE_MS} ms)" 0
	else
		row "policing baseline (unlimited fetch works)" 1 "$(head -c 120 "${TMP}/base.err" 2>/dev/null)"
		BASE_MS=0
	fi

	run "$BIN" strict-single "cg:${CG_C}" 500kb
	if [ "$RC" -ne 0 ]; then
		row "policing (500kb cap applied to the client cgroup)" 1 "strict failed rc=${RC}"
		kill "$SRV_PID" 2>/dev/null
		return
	fi
	if run_in_cgroup "$FLEET_C" python3 "${TMP}/client.py" "$URL" >"${TMP}/lim.out" 2>"${TMP}/lim.err"; then
		LIM_MS=$(awk '{print $1}' "${TMP}/lim.out")
		LIM_BYTES=$(awk '{print $2}' "${TMP}/lim.out")
	else
		LIM_MS=""
	fi
	if [ -n "${LIM_MS:-}" ] && [ "${LIM_BYTES:-0}" -eq 1000000 ] &&
		[ "$LIM_MS" -ge 900 ] && [ "$LIM_MS" -ge $((BASE_MS * 5 / 2)) ]; then
		row "policing (limited fetch ${LIM_MS} ms vs baseline ${BASE_MS} ms)" 0
	else
		row "policing (limited fetch ${LIM_MS:-timeout} ms vs baseline ${BASE_MS:-?} ms)" 1 \
			"expected >= 900 ms and >= 2.5x baseline (burst allowance accounted)"
	fi
	"$BIN" unstrict-single "cg:${CG_C}" >/dev/null 2>&1
	kill "$SRV_PID" 2>/dev/null
}

# ── group F: leaks and security ─────────────────────────────────────────

leaks() {
	"$BIN" unstrict-all >/dev/null 2>&1
	"$BIN" recover >/dev/null 2>&1

	PINS="$(find /sys/fs/bpf -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"
	if [ "${PINS:-0}" -eq 0 ]; then
		row "leak: zero BPF pins after unstrict-all + recover" 0
	else
		row "leak: zero BPF pins after unstrict-all + recover" 1 "left: $(find /sys/fs/bpf -mindepth 1 -maxdepth 1 -printf '%f ' 2>/dev/null)"
	fi

	# /run/zelynic is the lock dir (0700, root). The lock FILE is
	# the flock anchor — it persists by design (an advisory lock is
	# held only while a command runs); anything ELSE inside is a
	# leak, and so is any second file.
	LEFT="$(find /run/zelynic -mindepth 1 -maxdepth 1 -printf '%f ' 2>/dev/null)"
	if [ ! -e /run/zelynic ] || [ "$LEFT" = "zelynic.lock " ] || [ -z "$LEFT" ]; then
		row "leak: /run/zelynic carries only the flock anchor" 0
	else
		row "leak: /run/zelynic carries only the flock anchor" 1 "left: ${LEFT}"
	fi
	if [ ! -e /tmp/zelynic.lock ]; then
		row "leak: legacy /tmp/zelynic.lock absent" 0
	else
		row "leak: legacy /tmp/zelynic.lock absent" 1 "file exists"
	fi

	LEFTOVER=0
	for proc in /proc/[0-9]*; do
		[ -r "${proc}/comm" ] || continue
		read -r comm <"${proc}/comm" 2>/dev/null || continue
		if [ "$comm" = "zelynic" ]; then
			LEFTOVER=$((LEFTOVER + 1))
		fi
	done
	if [ "$LEFTOVER" -eq 0 ]; then
		row "leak: zero lingering zelynic processes" 0
	else
		row "leak: zero lingering zelynic processes" 1 "${LEFTOVER} still alive"
	fi

	run "$BIN" status --print-json
	if [ "$RC" -eq 0 ]; then
		ZERO=$(json_field "1 if doc['active_limits'] == 0 else 0" <<<"$OUT")
	else
		ZERO=0
	fi
	if [ "$ZERO" = "1" ]; then
		row "leak: status reports zero active limits" 0
	else
		row "leak: status reports zero active limits" 1 "rc=${RC}"
	fi
}

security() {
	# kernel facts, informational (not verdicts)
	echo "SMOKE-INFO: kernel=$(uname -r) unprivileged_bpf_disabled=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo '?') kptr_restrict=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo '?')"

	# The unprivileged probes invoke the helper DIRECTLY (an indirect
	# call through run "$@" hides the target from static analysis and
	# blurs the rc provenance — here the rc is the capability gate's,
	# verbatim).
	# doctor as uid 65534 is a DIAGNOSTIC: it must run, name the
	# missing privilege in its warnings, and never crash — the
	# refusal contract belongs to the enforcement verbs.
	OUT="$(run_unprivileged "$BIN" doctor 2>&1)"
	UNPRIV_RC=$?
	if [ "$UNPRIV_RC" -eq 0 ] && ! grep -q "panicked" <<<"$OUT" && grep -qi "require root\|root required\|not running as root" <<<"$OUT"; then
		row "unprivileged doctor (diagnoses, names the privilege, exit 0)" 0
	else
		row "unprivileged doctor (diagnoses, names the privilege, exit 0)" 1 "rc=${UNPRIV_RC}: $(head -c 120 <<<"$OUT")"
	fi
	OUT="$(run_unprivileged "$BIN" strict-single "cg:${CG_A}" 1mb 2>&1)"
	UNPRIV_RC=$?
	if [ "$UNPRIV_RC" -ne 0 ] && ! grep -q "panicked" <<<"$OUT" && grep -qi "require root\|root required" <<<"$OUT"; then
		row "unprivileged strict refused (uid 65534)" 0
	else
		row "unprivileged strict refused (uid 65534)" 1 "rc=${UNPRIV_RC}: $(head -c 120 <<<"$OUT")"
	fi
	# No partial application: the refused write must leave zero rows.
	run "$BIN" status --print-json
	if [ "$RC" -eq 0 ]; then
		ZERO=$(json_field "1 if doc['active_limits'] == 0 else 0" <<<"$OUT")
	else
		ZERO=0
	fi
	if [ "$ZERO" = "1" ]; then
		row "security: refused write left zero policies" 0
	else
		row "security: refused write left zero policies" 1 "rc=${RC}"
	fi
}

# ── teardown ────────────────────────────────────────────────────────────

teardown() {
	"$BIN" unstrict-all >/dev/null 2>&1
	"$BIN" recover >/dev/null 2>&1
	for cg in "$FLEET_A" "$FLEET_B" "$FLEET_C"; do
		if [ -d "$cg" ]; then
			for pid in $(<"${cg}/cgroup.procs"); do
				kill "$pid" 2>/dev/null
			done
		fi
	done
	sleep 1
	rmdir "$FLEET_A" "$FLEET_B" "$FLEET_C" 2>/dev/null
	rm -rf "$TMP"
}

# ── main ────────────────────────────────────────────────────────────────

main() {
	while [ $# -gt 0 ]; do
		case "$1" in
		--binary)
			BIN="${2:?}"
			shift 2
			;;
		-h | --help)
			sed -n 's/^# //p' "${BASH_SOURCE[0]}" | sed -n '/^Usage:/,$p' | head -8
			exit 0
			;;
		*)
			echo "unknown flag: $1" >&2
			exit 2
			;;
		esac
	done
	if [ ! -x "$BIN" ]; then
		echo "SMOKE-VERDICT: FAIL (no binary at ${BIN})" >&2
		exit 1
	fi
	if [ "$(id -u)" -ne 0 ]; then
		echo "SMOKE-VERDICT: FAIL (the battery needs root — run it in the sandbox)" >&2
		exit 1
	fi

	fleet_setup
	surfaces
	enforcement
	guards
	eagle
	policing
	leaks
	security
	teardown

	if [ "$FAILURES" -eq 0 ]; then
		echo "SMOKE-VERDICT: PASS"
		exit 0
	fi
	echo "SMOKE-VERDICT: FAIL (${FAILURES} rows)"
	exit 1
}

main "$@"
