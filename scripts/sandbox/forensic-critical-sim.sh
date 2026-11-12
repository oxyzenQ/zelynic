#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# night-total-hardening-1: the critical-usage forensic simulation.
#
# The owner's mandate: "master depth audit and do run real use
# all/end to end zelynic as a forensic tools to verify complete,
# before landed on critical industry" — root lane, every CLI
# surface, JSON, a measured critical-usage simulation, and the
# regression pins for this session's fatal finds. Runs ROOT inside
# the sandbox micro-VM (zelynic-sandbox.sh --run) and in CI
# (.github/workflows/netrunner-night-C77.yml).
#
# What it proves, one FORENSIC-RESULT row at a time:
#   * THE REGRESSION PINS — the owner's live-run fatal finds, each
#     now refused the honest way: dead direct cgroup ids (s 889111,
#     b 1011::11), partial lists (b live::noexist — atomic refusal,
#     nothing applied), numeric targets past the 32-bit id space,
#     the valueless-flag JSON leak, the duplicated root warning,
#     and the unstrict list's no-limits accounting tail.
#   * THE RENDER BYTES — the verbose [host-caps] trace survives a
#     warning line intact (the owner's 'ost-caps]' find: forced
#     color on captured stderr, the exact bytes inspected).
#   * THE JSON CONTRACT — status, list-apps, doctor, eagle-eyes
#     --depth: every --print-json document parses and carries its
#     contract fields.
#   * THE CRITICAL SIMULATION — a real loopback workload, measured:
#     unlimited baseline, a 200kb cap enforced (measured against
#     both the baseline and the cap), a block that kills the flow,
#     the unstrict recovery, and a --during window that expires on
#     its own clock.
#   * THE LIVE MONITOR — the TUI driven on a real PTY (frames
#     render, the session lives until q, exit 0): the forensic
#     answer to the owner's blank-exit find.
#   * THE NON-ROOT LANE — every mutation verb refuses cleanly as
#     uid 65534 (the unprivileged contract, the e2e house law).
#
# Rows print as FORENSIC-RESULT; the FAILURES counter rides the
# exit code and the final FORENSIC-VERDICT line (the C77 workflow
# and the sandbox entrypoint grep these sentinels).
#
# Usage:
#   scripts/sandbox/forensic-critical-sim.sh [--binary /path/to/zelynic]
#   (root; zelynic-sandbox.sh --run drives it inside the micro-VM)

set -u

BIN="/opt/zelynic/zelynic"
CG_ROOT="/sys/fs/cgroup"
FLEET="${CG_ROOT}/zelynic-forensic"
TMP="$(mktemp -d /tmp/zelynic-forensic.XXXXXX)"
PORT=8791
FAILURES=0

# ── plumbing ────────────────────────────────────────────────────────────

row() {
	# row <name> <ok:0|1> [detail] — one FORENSIC-RESULT row.
	if [ "$2" -eq 0 ]; then
		echo "FORENSIC-RESULT: $1 — PASS"
	else
		echo "FORENSIC-RESULT: $1 — FAIL${3:+ ($3)}"
		FAILURES=$((FAILURES + 1))
	fi
}

run() {
	# run <cmd...> — capture stdout+stderr into OUT, rc into RC.
	OUT="$("$@" 2>&1)"
	RC=$?
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
		row "$name" 1 "rc=${RC}: $(head -c 160 <<<"$OUT")"
	fi
}

expect_ok() {
	# expect_ok <name> <cmd...> — rc 0, no panic in the output.
	local name="$1"
	shift
	run "$@"
	if [ "$RC" -eq 0 ] && ! grep -q "panicked" <<<"$OUT"; then
		row "$name" 0
	else
		row "$name" 1 "rc=${RC}: $(head -c 160 <<<"$OUT")"
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
	# run_in_cgroup <cgroup-path> <cmd...> — the worker moves ITSELF
	# into the cgroup before exec, so the first socket the command
	# opens is already attributed.
	local cg="$1"
	shift
	bash -c 'echo $$ > "$1/cgroup.procs"; shift; exec "$@"' worker "$cg" "$@"
}

spawn_sleeper() {
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

speed_of() {
	# speed_of <cgroup> — one loopback download's measured speed
	# (bytes/sec), the curl -w verdict. The workload server is the
	# unlimited baseline side; the curl rides INSIDE the cgroup.
	run_in_cgroup "$1" \
		curl -s -o /dev/null -w '%{speed_download}' \
		--max-time 30 "http://127.0.0.1:${PORT}/payload.bin"
}

# ── section 0: the environment ─────────────────────────────────────────

while [ "$#" -gt 0 ]; do
	case "$1" in
	--binary)
		BIN="$2"
		shift 2
		;;
	*)
		echo "usage: $0 [--binary /path/to/zelynic]" >&2
		exit 2
		;;
	esac
done

[ -x "$BIN" ] || {
	echo "FORENSIC-VERDICT: FAIL (binary not found: $BIN)"
	exit 1
}

run "$BIN" -V
row "environment (binary runs, $("$BIN" -V 2>/dev/null | head -1))" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"
expect_ok "environment (doctor: the bpf syscall answers)" "$BIN" doctor

# ── the fleet: one workload cgroup with a resident sleeper ──────────────

mkdir -p "$FLEET" 2>/dev/null
spawn_sleeper "$FLEET" 900
sleep 1
CG="$(stat -c %i "$FLEET")"
run "$BIN" list-apps --print-json
if [ "$RC" -eq 0 ] && grep -q "\"cgroup_id\": *${CG}\b" <<<"$OUT"; then
	row "fleet (the workload cgroup resolves: cg:${CG})" 0
else
	row "fleet (the workload cgroup resolves: cg:${CG})" 1 "list-apps saw: $(head -c 120 <<<"$OUT")"
fi

# ── section 1: the regression pins — the owner's fatal finds ───────────

expect_refused "regression: dead direct id refused (s 889111)" \
	"No cgroup found" "$BIN" s 889111 100kb --no-test
expect_refused "regression: dead cg: id refused (s cg:889111)" \
	"No cgroup found" "$BIN" s cg:889111 100kb --no-test
expect_refused "regression: dead id list refused (b 1011::11)" \
	"no cgroup" "$BIN" b 1011::11
expect_refused "regression: numeric target past 32 bits refused" \
	"too large for a cgroup id" "$BIN" s 100000000000000000 1mb --no-test
expect_refused "regression: numeric list member past 32 bits refused" \
	"too large for a cgroup id" "$BIN" s "brave::99999999999" 1mb --no-test

# The atomic refusal on a PARTIAL list: the live cgroup plus a typo
# must abort whole — and the status surface must prove nothing landed.
expect_refused "regression: partial list refused atomically (b cg-live::noexist)" \
	"atomic" "$BIN" b "${CG}::noexist"
run "$BIN" status --print-json
if [ "$RC" -eq 0 ]; then
	COUNT=$(json_field "doc['active_limits']" <<<"$OUT" 2>/dev/null || echo x)
else
	COUNT="x"
fi
if [ "$COUNT" = "0" ]; then
	row "regression: nothing was blocked behind the refusal (status: 0 rows)" 0
else
	row "regression: nothing was blocked behind the refusal (status: 0 rows)" 1 "active_limits=${COUNT}"
fi

# The JSON door for a valueless flag: the message must match the
# prose lane's "a value is required" verdict, never "invalid value ''".
run "$BIN" eagle-eyes "cg:${CG}" --print-json --focus
if [ "$RC" -ne 0 ] && grep -q "a value is required for '--focus <SECONDS>'" <<<"$OUT" && ! grep -q "invalid value ''" <<<"$OUT"; then
	row "regression: valueless --focus says 'value required' in JSON" 0
else
	row "regression: valueless --focus says 'value required' in JSON" 1 "rc=${RC}: $(head -c 160 <<<"$OUT")"
fi

# The root catch-all warns ONCE (the owner's duplicate-warning find)
# and the verbose [host-caps] trace renders INTACT behind it —
# forced color so the captured stderr bytes carry every escape the
# terminal would see, and the count check is byte-level, not
# display-level. (Forensic note, night-total-hardening-1: the
# session's "ost-caps]" scare was an agent-side display artifact —
# a tool layer eating the literal two bytes "[h" from grep/sed/cat
# views; od -c proved every file, test, and log byte-correct. The
# lesson rides here so the next audit checks bytes, not views.)
ERRCAP="${TMP}/root-warn-stderr.bin"
"$BIN" s 1 1mb --no-test -v --force-this --color-mode 24 2>"$ERRCAP" >/dev/null
ROOT_RC=$?
WARN_COUNT=$(grep -c "is the root cgroup" "$ERRCAP" || true)
CAPS_COUNT=$(grep -c "\[host-caps\]" "$ERRCAP" || true)
if [ "$ROOT_RC" -eq 0 ] && [ "$WARN_COUNT" -eq 1 ] && [ "$CAPS_COUNT" -eq 2 ]; then
	row "regression: the root catch-all warns once, host-caps renders intact (x2)" 0
else
	row "regression: the root catch-all warns once, host-caps renders intact (x2)" 1 \
		"rc=${ROOT_RC} warns=${WARN_COUNT} caps=${CAPS_COUNT}"
fi
"$BIN" u 1 >/dev/null 2>&1 || true

# The unstrict list's no-limits accounting: what matched is removed,
# what did not is NAMED (never silently skipped).
"$BIN" s "cg:${CG}" 100kb --no-test >/dev/null 2>&1
run "$BIN" u "cg:${CG}::noexist"
if [ "$RC" -eq 0 ] && grep -q "no active limits for 'noexist'" <<<"$OUT" && grep -q "Removed" <<<"$OUT"; then
	row "regression: unstrict names the no-limits members it skipped" 0
else
	row "regression: unstrict names the no-limits members it skipped" 1 "rc=${RC}: $(head -c 160 <<<"$OUT")"
fi

# ── section 2: the JSON contract, every surface ─────────────────────────

run bash -c "\"$BIN\" status --print-json | python3 -m json.tool >/dev/null"
row "json: status parses" "$RC"
run bash -c "\"$BIN\" list-apps --print-json | python3 -m json.tool >/dev/null"
row "json: list-apps parses" "$RC"
run bash -c "\"$BIN\" doctor --print-json | python3 -m json.tool >/dev/null"
row "json: doctor parses" "$RC"
run bash -c "\"$BIN\" eagle-eyes cg:${CG} --depth --focus 2 --print-json | python3 -m json.tool >/dev/null"
row "json: eagle-eyes --depth parses (live workload target)" "$RC"

# (The histogram lane check moved into section 3: it rides
# MID-TRAFFIC reads, night-verify-1's lesson — a read against a
# quiet cgroup is the honest absence, not a bug.)

# ── section 3: the critical-usage simulation, measured ─────────────────

# The workload server: an unlimited loopback origin.
mkdir -p "${TMP}/srv"
dd if=/dev/zero of="${TMP}/srv/payload.bin" bs=1M count=4 status=none
(cd "${TMP}/srv" && python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1) &
HTTP_PID=$!
sleep 1

# 3a. The unlimited baseline (the honest denominator).
# Wait for the workload server to ANSWER before measuring anything
# (the TCG boot's python http.server can take seconds to bind; a
# baseline measured against a dead port is 0/s and every later
# ratio lies).
SRV_READY=1
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
	if run_in_cgroup "$FLEET" curl -s -o /dev/null --max-time 4 \
		"http://127.0.0.1:${PORT}/payload.bin"; then
		SRV_READY=0
		break
	fi
	sleep 1
done
row "critical: the workload server answers (the honest denominator)" "$SRV_READY"

BASE="$(speed_of "$FLEET")"
BASE_OK=$(python3 -c "print(0 if ${BASE:-0} > 400000 else 1)" 2>/dev/null || echo 1)
row "critical: unlimited baseline measured ($(python3 -c "print(f'${BASE:-0:.0f}/s')" 2>/dev/null || echo '?') B/s)" "$BASE_OK"

# 3b. The cap: apply 200kb, then measure the SAME download.
"$BIN" s "cg:${CG}" 200kb --no-test >/dev/null 2>&1
CAPPED="$(run_in_cgroup "$FLEET" curl -s -o /dev/null -w '%{speed_download}' --max-time 8 "http://127.0.0.1:${PORT}/payload.bin")"
VERDICT=$(python3 -c "
base = ${BASE:-0}
capped = ${CAPPED:-0}
cap = 200000
# The honest bounds: the capped run must sit well under the baseline
# (enforcement, not noise) and inside a generous band around the cap
# (the token bucket's burst tolerance plus measurement slack).
print(0 if (base > 400000 and capped < base * 0.5 and capped < cap * 2.5) else 1)
" 2>/dev/null || echo 1)
row "critical: the 200kb cap holds ($(python3 -c "print(f'${CAPPED:-0:.0f}/s')" 2>/dev/null || echo '?') B/s vs baseline)" "$VERDICT"

# 3b-second. The depth report's eBPF histogram lane, read
# MID-TRAFFIC — and driven the way the sampling law demands: the
# histogram records 1 sample per 2^10 packets per CPU (the schema
# v34 constant), so the traffic must be thousands of REAL packets.
# A 4 MB loopback download folds into ~64 GSO segments and books
# nothing (the first run's honest absence); this leg streams
# 24000 x 100B chunks over TCP_NODELAY — 24k wire packets through
# the capped cgroup, the small-packet shape supermassive-verify's
# proven phase drives across a veth pair. The depth read rides the
# stream (night-verify-1's mid-traffic lesson), and the assertions
# carry that phase's full depth: samples > 0, non-zero buckets,
# the p50/p95/p99 quantiles.
HIST_PORT=$((PORT + 1))
python3 - "$HIST_PORT" <<'PYEOF' &
import socket, sys
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1])))
srv.listen(1)
conn, _ = srv.accept()
conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
chunk = b"x" * 100
for _ in range(24000):
    conn.sendall(chunk)
conn.close()
srv.close()
PYEOF
HIST_SRV_PID=$!
sleep 1
run_in_cgroup "$FLEET" python3 - "$HIST_PORT" <<'PYEOF' &
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=30)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
got = 0
while True:
    data = s.recv(4096)
    if not data:
        break
    got += len(data)
s.close()
PYEOF
HIST_CLIENT_PID=$!
sleep 3
# (stderr stays separate: the focus-window note and the sweep traces
# ride stderr by the pipe law — a JSON row parses stdout only.)
run bash -c "\"$BIN\" eagle-eyes cg:${CG} --depth --focus 2 --print-json 2>/dev/null"
if [ "$RC" -eq 0 ] && python3 -c '
import json, sys
doc = json.loads(sys.stdin.read())
targets = doc.get("targets", [])
assert targets, "the depth report resolved the target"
h = targets[0].get("histogram")
assert h, f"the histogram block is absent: {doc}"
assert h.get("sample_shift") == 10, h
dl = h.get("download") or {}
size = dl.get("size")
assert size and size["samples"] > 0, f"no size samples recorded: {h}"
nonzero = [c for c in size["buckets"] if c > 0]
assert nonzero, f"the buckets are all zero: {size}"
for q in ("p50", "p95", "p99"):
    assert size.get(q), f"{q} missing from the size half: {size}"
' <<<"$OUT"; then
	row "json: the depth report carries the eBPF histogram lane, read mid-traffic (night-verify-1)" 0
else
	row "json: the depth report carries the eBPF histogram lane, read mid-traffic (night-verify-1)" 1 \
		"rc=${RC}: $(head -c 200 <<<"$OUT")"
fi
kill "$HIST_CLIENT_PID" "$HIST_SRV_PID" 2>/dev/null || true

# 3c. The block: the flow dies.
"$BIN" b "cg:${CG}" >/dev/null 2>&1
BLOCKED="$(run_in_cgroup "$FLEET" \
	curl -s -o /dev/null -w '%{http_code} %{size_download}' \
	--max-time 8 "http://127.0.0.1:${PORT}/payload.bin" 2>/dev/null || true)"
BLOCK_OK=$(python3 -c "
out = '''${BLOCKED}'''.strip()
size = out.split()[-1] if out else '0'
print(0 if out in ('000', '') or size == '0' else 1)
" 2>/dev/null || echo 1)
row "critical: the block kills the flow (curl verdict: '${BLOCKED:-none}')" "$BLOCK_OK"

# 3d. The recovery: unstrict, then the flow returns.
"$BIN" u "cg:${CG}" >/dev/null 2>&1
RECOVERED="$(run_in_cgroup "$FLEET" curl -s -o /dev/null -w '%{speed_download}' --max-time 12 "http://127.0.0.1:${PORT}/payload.bin")"
RECOVER_OK=$(python3 -c "print(0 if ${RECOVERED:-0} > ${BASE:-1} * 0.5 else 1)" 2>/dev/null || echo 1)
row "critical: unstrict restores the flow ($(python3 -c "print(f'${RECOVERED:-0:.0f}/s')" 2>/dev/null || echo '?') B/s)" "$RECOVER_OK"

# 3e. The --during window: applies, reports its clock, expires on it.
"$BIN" s "cg:${CG}" 200kb --no-test --during 8s >/dev/null 2>&1
run "$BIN" status
DURING_SEEN=1
grep -q "window" <<<"$OUT" || DURING_SEEN=0
sleep 10
OUT="$( "$BIN" status --print-json 2>"${TMP}/during-sweep-trace.txt" )"
RC=$?
if [ "$RC" -eq 0 ]; then
	AFTER=$(json_field "doc['active_limits']" <<<"$OUT" 2>/dev/null || echo x)
else
	AFTER="x"
fi
if [ "$DURING_SEEN" -eq 1 ] && [ "$AFTER" = "0" ]; then
	row "critical: the --during window expires on its own clock" 0
else
	row "critical: the --during window expires on its own clock" 1 \
		"window_seen=${DURING_SEEN} after=${AFTER} rc=${RC}: $(head -c 200 <<<"$OUT")"
fi
"$BIN" u --all >/dev/null 2>&1 || true

# ── section 4: the live monitor on a real PTY ───────────────────────────

# The forensic answer to the owner's blank-exit find: a real PTY, a
# real target with live traffic, the frames must render and the
# session must LIVE until q (a blank instant exit is the bug).
tui_driver() {
	# tui_driver <wait-secs> <cmd...> — spawn on a pty, send q after
	# <wait-secs>, report: TUI-DRIVER: rc=<n> dur=<secs> bytes=<n>.
	python3 - "$@" <<'PYEOF'
import os, pty, select, sys, time

wait = float(sys.argv[1])
cmd = sys.argv[2:]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(cmd[0], cmd)
start = time.time()
out = b""
sent_q = False
rc = None
while time.time() - start < wait + 10:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            chunk = b""
        if not chunk:
            break
        out += chunk
    if not sent_q and time.time() - start >= wait:
        try:
            os.write(fd, b"q")
        except OSError:
            pass
        sent_q = True
    done, st = os.waitpid(pid, os.WNOHANG)
    if done == pid:
        rc = os.waitstatus_to_exitcode(st)
        # drain the last bytes
        while True:
            r, _, _ = select.select([fd], [], [], 0.3)
            if not r:
                break
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        break
if rc is None:
    os.kill(pid, 9)
    done, st = os.waitpid(pid, 0)
    rc = os.waitstatus_to_exitcode(st)
os.close(fd)
dur = time.time() - start
print(f"TUI-DRIVER: rc={rc} dur={dur:.1f} bytes={len(out)}")
sys.exit(0 if (rc == 0 and dur >= wait * 0.8 and len(out) > 500) else 1)
PYEOF
}

# Keep the traffic alive so the monitor has live endpoints to show.
(curl -s -o /dev/null --max-time 25 "http://127.0.0.1:${PORT}/payload.bin" >/dev/null 2>&1 &) 
run_in_cgroup "$FLEET" bash -c \
	"curl -s -o /dev/null --max-time 25 http://127.0.0.1:${PORT}/payload.bin" &
TRAFFIC_PID=$!

# The one-target focus view (the exact shape the owner's blank-exit
# find used: a NAME target with live traffic).
DRIVER_OUT="$(tui_driver 4 "$BIN" eagle-eyes "cg:${CG}" --interval 1 2>&1)"
if [ $? -eq 0 ]; then
	row "monitor: the focus view lives on a real PTY until q (the blank-exit pin)" 0
else
	row "monitor: the focus view lives on a real PTY until q (the blank-exit pin)" 1 "driver said: ${DRIVER_OUT:-<no verdict>}"
fi
# The NAME-target focus view — the exact shape of the owner's
# blank-exit find (`ee brave`: a name resolving through the /proc
# walk, not a direct id).
DRIVER_OUT="$(tui_driver 4 "$BIN" eagle-eyes sleep --interval 1 2>&1)"
if [ $? -eq 0 ]; then
	row "monitor: the name-target view lives on a real PTY until q (the ee <name> pin)" 0
else
	row "monitor: the name-target view lives on a real PTY until q (the ee <name> pin)" 1 "driver said: ${DRIVER_OUT:-<no verdict>}"
fi
# The no-target leaderboard.
DRIVER_OUT="$(tui_driver 4 "$BIN" eagle-eyes --interval 1 2>&1)"
if [ $? -eq 0 ]; then
	row "monitor: the leaderboard lives on a real PTY until q" 0
else
	row "monitor: the leaderboard lives on a real PTY until q" 1 "driver said: ${DRIVER_OUT:-<no verdict>}"
fi
kill "$TRAFFIC_PID" 2>/dev/null || true

# The interactive-stdio gate: a piped stdout must refuse loudly
# (never the silent pipe session).
GATE_OUT="${TMP}/gate-out.txt"
"$BIN" eagle-eyes "cg:${CG}" --interval 1 >"$GATE_OUT" 2>"${TMP}/gate-err.txt"
GATE_RC=$?
if [ "$GATE_RC" -ne 0 ] && grep -qi "interactive\|pipe\|tty" "$GATE_OUT" "${TMP}/gate-err.txt" && ! grep -q "panicked" "$GATE_OUT" "${TMP}/gate-err.txt"; then
	row "monitor: a redirected stdout refuses loudly (the interactive gate)" 0
else
	row "monitor: a redirected stdout refuses loudly (the interactive gate)" 1 "rc=${GATE_RC}: $(head -c 160 "$GATE_OUT" 2>/dev/null)$(head -c 80 "${TMP}/gate-err.txt" 2>/dev/null)"
fi

# ── section 5: the non-root lane (the unprivileged contract) ────────────

NONROOT_FAIL=0
for verb in "s sleep 100kb --no-test" "b sleep" "u sleep" "recover" "status"; do
	# shellcheck disable=SC2086
	if run_unprivileged "$BIN" $verb >/dev/null 2>&1; then
		NONROOT_FAIL=1
	fi
done
if [ "$NONROOT_FAIL" -eq 0 ]; then
	row "nonroot: every mutation verb refuses uid 65534 cleanly" 0
else
	row "nonroot: every mutation verb refuses uid 65534 cleanly" 1 "a verb exited 0 unprivileged"
fi
OUT_UNPRIV="$(run_unprivileged "$BIN" s sleep 100kb --no-test 2>&1)"
RC_UNPRIV=$?
if [ "$RC_UNPRIV" -ne 0 ] && grep -q "root required" <<<"$OUT_UNPRIV"; then
	row "nonroot: the refusal names the privilege ask" 0
else
	row "nonroot: the refusal names the privilege ask" 1 "rc=${RC_UNPRIV}: $(head -c 160 <<<"$OUT_UNPRIV")"
fi

# ── teardown and verdict ────────────────────────────────────────────────

"$BIN" u --all >/dev/null 2>&1 || true
"$BIN" recover >/dev/null 2>&1 || true
kill "$HTTP_PID" 2>/dev/null || true
pkill -f "http.server ${PORT}" 2>/dev/null || true
rmdir "$FLEET" 2>/dev/null || true
rm -rf "$TMP"

if [ "$FAILURES" -eq 0 ]; then
	echo "FORENSIC-VERDICT: PASS"
	exit 0
fi
echo "FORENSIC-VERDICT: FAIL (${FAILURES} rows failed)"
exit 1
