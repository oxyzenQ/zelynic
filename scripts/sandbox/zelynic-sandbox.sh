#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). zelynic is a Linux-only tool.
#
# zelynic sandbox (NIGHT-think-1) — the local KVM micro-VM that gives
# an agent (or an owner) ROOT INSIDE A THROWAWAY KERNEL for depth
# stresstesting, without waiting for CI and without touching the
# host: the supermassive batteries, the depth harnesses, any script
# that needs root — booted in seconds from a cached kernel and a
# rootless-built initramfs (scripts/sandbox/rootfs-pack.py: ubuntu
# 22.04 base + python3/iproute2/curl by real dependency resolution
# + the repo checkout + the static musl binary; no docker, no host
# root, no install into the host).
#
# The CI twin (.github/workflows/supermassive.yml) proves the same
# tree on hosted runners; this script makes the micro-VM a LOCAL
# instrument — the owner's ask: the agent sandbox cannot sudo, so
# give it a kernel of its own.
#
# Usage:
#   scripts/sandbox/zelynic-sandbox.sh --smoke                # one click: the full CLI depth battery, root, in the VM
#   scripts/sandbox/zelynic-sandbox.sh --battery             # both supermassive engines, root, in the VM
#   scripts/sandbox/zelynic-sandbox.sh --run <cmd...>        # any root-requiring command, in the VM
#   scripts/sandbox/zelynic-sandbox.sh --shell               # interactive root bash on the VM console
#   scripts/sandbox/zelynic-sandbox.sh --self-test           # rootless preflight + packer self-test
#
# Options:
#   --kernel floor|lts|latest|PATH  lts = the newest Ubuntu LTS
#                                suite's kernel across its
#                                main/updates/security pockets —
#                                the default (NIGHT-blade-10: the
#                                lane LTS users actually run);
#                                floor = impish 5.13 (the documented
#                                minimum, the CI low-specs lane);
#                                latest = the archive's newest
#                                kernel; PATH = a local vmlinuz
#   --binary PATH                the zelynic payload binary (default:
#                                the repo's musl builds probed in
#                                order — the v1-baseline static musl
#                                twin first, the safest under TCG)
#   --envelope low|best          low = quarter cores / eighth RAM
#                                (default, the CI low leg's math);
#                                best = every core / three quarters
#   --net                        user-mode networking (default OFF —
#                                the batteries are loopback-only, the
#                                CI VM contract)
#   --timeout SECONDS            outer VM budget (default 3600)
#   --keep                       keep the boot log at $CACHE/vm.log
#
# Requirements: qemu-system-x86_64, python3, curl, git. /dev/kvm is
# OPTIONAL: without it the VM boots under TCG software emulation
# (-cpu max) with a loud warning — slower, and arch-baseline v3/v4
# binaries may SIGILL under emulation, which is exactly why the
# default binary probe prefers the plain musl build.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CACHE="${ZELYNIC_SANDBOX_CACHE:-${HOME}/.cache/zelynic-sandbox}"

KERNEL="lts"
BINARY=""
ENVELOPE="low"
NET=0
TIMEOUT=3600
KEEP=0
MODE=""

note() { echo "[sandbox] $*"; }
die() {
	echo "[sandbox] FAIL: $*" >&2
	exit 1
}

usage() {
	# The usage block only — the copyright and design notes above
	# it are not CLI help (NIGHT-blade-10: the old head-40 sliced
	# the option table when the header grew).
	sed -n 's/^# //p' "${BASH_SOURCE[0]}" | sed -n '/^Usage:/,$p' | sed '/^$/d' | head -45
	exit "${1:-0}"
}

# ── arguments ───────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
	case "$1" in
	--battery)
		MODE="battery"
		shift
		;;
	--smoke)
		MODE="smoke"
		shift
		;;
	--shell)
		MODE="shell"
		shift
		;;
	--run)
		MODE="run"
		shift
		break
		;;
	--kernel)
		KERNEL="${2:?}"
		shift 2
		;;
	--binary)
		BINARY="${2:?}"
		shift 2
		;;
	--envelope)
		ENVELOPE="${2:?}"
		shift 2
		;;
	--net)
		NET=1
		shift
		;;
	--timeout)
		TIMEOUT="${2:?}"
		shift 2
		;;
	--keep)
		KEEP=1
		shift
		;;
	--self-test)
		MODE="selftest"
		shift
		;;
	-h | --help) usage 0 ;;
	*)
		echo "unknown flag: $1" >&2
		usage 2
		;;
	esac
done

# --run owns the rest of argv as ONE command line (NIGHT-blade-10:
# an empty --run used to pack a payload that ran nothing and still
# reported PASS).
if [ "${MODE}" = "run" ] && [ $# -eq 0 ]; then
	die "--run needs a command (e.g. --run ./zelynic status)"
fi

# ── self-test: rootless, no VM, no boot ─────────────────────────────────
if [ "$MODE" = "selftest" ]; then
	note "self-test (rootless: syntax, packer units, tool presence — no VM boot)"
	if bash -n "${BASH_SOURCE[0]}"; then
		note "entrypoint bash syntax" OK
	else
		die "entrypoint bash syntax"
	fi
	if bash -n "${SCRIPT_DIR}/sandbox-init.sh"; then
		note "init bash syntax" OK
	else
		die "init bash syntax"
	fi
	python3 "${SCRIPT_DIR}/rootfs-pack.py" self-test || die "packer self-test"
	for tool in qemu-system-x86_64 python3 curl git; do
		if command -v "$tool" >/dev/null 2>&1; then
			note "tool $tool present (OK)"
		else
			note "tool $tool MISSING — needed to boot (install qemu-system-x86 etc.)"
		fi
	done
	if [ -w /dev/kvm ]; then
		note "/dev/kvm usable — KVM acceleration"
	else
		note "/dev/kvm absent — TCG software emulation (slower; prefer the plain musl binary)"
	fi
	note "self-test done (all checks above are advisory; the packer units are the verdict)"
	exit 0
fi

# ── preflight ───────────────────────────────────────────────────────────
[ "$MODE" = "run" ] || [ "$MODE" = "shell" ] || [ "$MODE" = "battery" ] ||
	[ "$MODE" = "smoke" ] || usage 2

command -v qemu-system-x86_64 >/dev/null 2>&1 ||
	die "qemu-system-x86_64 not found — install it (Debian/Ubuntu: apt install qemu-system-x86)"
command -v python3 >/dev/null 2>&1 || die "python3 not found"
command -v git >/dev/null 2>&1 || die "git not found"

mkdir -p "${CACHE}"

# Acceleration: KVM host-passthrough when available (the CI contract
# — "native" is honest under -cpu host), else TCG with -cpu max and a
# loud warning (arch-baseline binaries may SIGILL under emulation).
ACCEL_FLAGS=(-machine "q35,accel=kvm" -cpu host)
if [ ! -w /dev/kvm ]; then
	note "WARNING: /dev/kvm not usable — falling back to TCG software emulation."
	note "         Slower, and v3/v4 arch-baseline binaries may SIGILL; the"
	note "         default binary probe prefers the plain musl build for this reason."
	ACCEL_FLAGS=(-machine "q35,accel=tcg" -cpu max)
fi

# ── the binary payload ──────────────────────────────────────────────────
if [ -z "${BINARY}" ]; then
	for candidate in \
		"${REPO_ROOT}/target/x86_64-unknown-linux-musl/pro-native-musl/zelynic" \
		"${REPO_ROOT}/target/x86_64-unknown-linux-musl/release/zelynic" \
		"${REPO_ROOT}/target/release/zelynic"; do
		if [ -x "${candidate}" ]; then
			BINARY="${candidate}"
			break
		fi
	done
fi
if [ -n "${BINARY}" ] && [ -x "${BINARY}" ]; then
	# Under TCG the v3/v4 arch-baseline glibc builds may SIGILL
	# (-cpu max emulates the ISA, not the host's speed). The
	# path-name heuristic stays, but a STATIC binary (the release
	# musl tarball extracted anywhere) never draws the warning —
	# ldd fails on static-pie, which is exactly the tell
	# (NIGHT-blade-10: the v11 musl release extracted to a path
	# without 'musl' tripped the old heuristic).
	if [ ! -w /dev/kvm ]; then
		case "${BINARY}" in
		*musl*) ;;
		*)
			if ldd "${BINARY}" >/dev/null 2>&1; then
				note "WARNING: ${BINARY} is a dynamic glibc build — under TCG the v3/v4 arch-baseline may SIGILL"
			fi
			;;
		esac
	fi
else
	die "no zelynic binary — build one (./scripts/setup.sh --skip-heavy --musl) or pass --binary PATH"
fi
note "binary: ${BINARY}"

# ── the kernel ──────────────────────────────────────────────────────────
case "${KERNEL}" in
floor | lts | latest)
	VMLINUZ="$(python3 "${SCRIPT_DIR}/rootfs-pack.py" kernel --suite "${KERNEL}" --cache "${CACHE}")" ||
		die "kernel resolution failed"
	;;
*)
	VMLINUZ="${KERNEL}"
	;;
esac
[ -f "${VMLINUZ}" ] || die "kernel not found: ${VMLINUZ}"
note "kernel: ${VMLINUZ}"

# ── the payload script (packed into the image; the init runs it) ────────
PAYLOAD="$(mktemp "${CACHE}/payload.XXXXXX.sh")"
trap 'rm -f "${PAYLOAD}"' EXIT
case "${MODE}" in
battery)
	cat >"${PAYLOAD}" <<'EOF'
#!/usr/bin/env bash
# The canonical batteries, root, inside the VM (the CI twin's order):
# v1 limiter matrix (server phase first, then the desktop matrix),
# then v2 survival battery. Each engine's exit code is a verdict row.
set -u
cd /opt/zelynic
python3 scripts/supermassive/supermassive-test.py --binary /opt/zelynic/zelynic
v1=$?
python3 scripts/supermassive/supermassive-test-v2.py --binary /opt/zelynic/zelynic
v2=$?
echo "SANDBOX-RESULT: supermassive v1 - limiter matrix" \
	$([ "$v1" -eq 0 ] && echo PASS || echo FAIL)
echo "SANDBOX-RESULT: supermassive v2 - survival battery" \
	$([ "$v2" -eq 0 ] && echo PASS || echo FAIL)
[ "$v1" -eq 0 ] && [ "$v2" -eq 0 ]
EOF
	;;
smoke)
	cat >"${PAYLOAD}" <<'EOF'
#!/usr/bin/env bash
# The one-click CLI depth battery (NIGHT-blade-10): every surface
# verb, every guard, the JSON documents, real policing on loopback,
# and the leak/security probes — one verdict. The battery itself is
# the tracked script the image already carries at
# scripts/sandbox/smoke-cli.sh (git archive HEAD); this payload only
# invokes it so the mode stays a one-liner.
set -u
cd /opt/zelynic
bash scripts/sandbox/smoke-cli.sh --binary /opt/zelynic/zelynic
EOF
	;;
shell)
	cat >"${PAYLOAD}" <<'EOF'
#!/usr/bin/env bash
# Interactive root shell on the serial console; exit to end the VM.
export TERM=linux
cd /opt/zelynic
echo "zelynic sandbox — root shell in a throwaway kernel ($(uname -r))"
echo "repo at /opt/zelynic, binary at /opt/zelynic/zelynic — exit ends the VM."
bash -i
EOF
	;;
run)
	{
		echo '#!/usr/bin/env bash'
		echo 'set -u'
		echo 'cd /opt/zelynic'
		# shellcheck disable=SC2016  # the payload expands TERM at ITS runtime
		echo 'export TERM=${TERM:-dumb}'
		# Each argument quoted verbatim — no eval, no shell parsing.
		quote() { printf '%q ' "$1"; }
		{ printf 'bash -c %s' "$(quote "$*")"; }
		echo
	} >"${PAYLOAD}"
	;;
esac
chmod +x "${PAYLOAD}"

# ── the initramfs (rootless build, cached debs make re-runs fast) ───────
INITRD="${CACHE}/initrd.gz"
note "building the initramfs (first run downloads ~60 MiB, cached afterwards)..."
python3 "${SCRIPT_DIR}/rootfs-pack.py" initrd \
	--cache "${CACHE}" \
	--repo "${REPO_ROOT}" \
	--binary "${BINARY}" \
	--init "${SCRIPT_DIR}/sandbox-init.sh" \
	--payload "${PAYLOAD}" || die "initramfs build failed"
[ "${KEEP}" -eq 1 ] || rm -f "${PAYLOAD}"
trap - EXIT
note "initramfs: ${INITRD}"

# ── the envelope (the CI dynamic math, NIGHT-improve-33) ────────────────
CORES="$(nproc)"
TOTAL_MB="$(free -m | awk '/^Mem:/{print $2}')"
case "${ENVELOPE}" in
low)
	SMP=$((CORES / 4))
	[ "$SMP" -lt 1 ] && SMP=1
	MEM=$((TOTAL_MB / 8))
	[ "$MEM" -lt 1024 ] && MEM=1024
	;;
best)
	SMP="$CORES"
	MEM=$((TOTAL_MB * 3 / 4))
	;;
*)
	die "unknown envelope: ${ENVELOPE} (low|best)"
	;;
esac
note "envelope: ${SMP} vCPU / ${MEM} MB (${ENVELOPE}, of ${CORES} cores / ${TOTAL_MB} MB)"

# ── boot ────────────────────────────────────────────────────────────────
NET_FLAGS=()
if [ "$NET" -eq 1 ]; then
	NET_FLAGS=(-netdev "user,id=n0" -device "virtio-net-pci,netdev=n0")
	note "user-mode networking ON (egress through the host)"
fi
VM_LOG="${CACHE}/vm.log"
note "booting the micro-VM (timeout ${TIMEOUT}s; serial console follows)..."
set +e
timeout "${TIMEOUT}" qemu-system-x86_64 \
	"${ACCEL_FLAGS[@]}" \
	-m "${MEM}" -smp "${SMP}" \
	-device isa-debug-exit,iobase=0xf4,iosize=0x04 \
	-kernel "${VMLINUZ}" \
	-initrd "${INITRD}" \
	-append "console=ttyS0 panic=-1" \
	"${NET_FLAGS[@]}" \
	-nographic -no-reboot 2>&1 | tee "${VM_LOG}"
QEMU_RC=${PIPESTATUS[0]}
set -e

# rc 0 = a natural poweroff; rc 1 = the guest's deliberate
# isa-debug-exit (the verdict rides the SANDBOX-* sentinel lines).
# Anything else — the timeout (124), a KVM init failure — fails HERE.
if [ "$QEMU_RC" -ne 0 ] && [ "$QEMU_RC" -ne 1 ]; then
	echo "[sandbox] FAIL: qemu exited ${QEMU_RC} — log tail:"
	tail -40 "${VM_LOG}"
	exit 1
fi

# ── the verdict (the sentinel lines are the contract) ───────────────────
echo "── sandbox verdicts ──"
grep -E '^SANDBOX-(RESULT|VERDICT)' "${VM_LOG}" || true
if grep -q '^SANDBOX-VERDICT: PASS' "${VM_LOG}"; then
	echo "[sandbox] OK: the payload ran green inside the VM"
	exit 0
fi
echo "[sandbox] FAIL: the VM did not report PASS (log: ${VM_LOG})"
exit 1
