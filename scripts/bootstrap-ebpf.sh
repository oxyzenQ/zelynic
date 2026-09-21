#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). zelynic is a Linux-only tool.
#
# Host bootstrap for the pure-Rust eBPF build (NIGHT-host-1).
#
# One command readies the WHOLE host for zelynic's one-click flow
# (NIGHT-improve-16): the two prerequisites below, the PATH fix that
# lets future shells (and this script's own build) see bpf-linker,
# and the flagship binary itself, built with the canonical native
# alias (cargo pro-native-gnu, lands in target/pro-native-gnu/zelynic).
# The contract is three commands total, nothing in between:
#   git clone ... && cd zelynic && ./scripts/bootstrap-ebpf.sh
#   sudo ./scripts/supermassive-test.sh
# The build step exists because "bootstrap done" must MEAN ready to
# test: the 2026-09-21 debian13 run had prerequisites installed but
# no binary (two failed builds, ~/.local/bin off PATH), so the
# supermassive harness silently fell through to a stale /usr/bin/
# zelynic v4.0.0-alpha and filed 12 decoy failures.
#
# The two prerequisites:
#   1. the dated nightly toolchain pinned by ebpf/rust-toolchain.toml
#      (minimal profile, with the rust-src + rustfmt components)
#   2. the bpf-linker 0.11.1 prebuilt static-musl binary, installed
#      into ~/.local/bin (no sudo, no system LLVM, no clang)
#
# The nightly pin is READ from ebpf/rust-toolchain.toml, so bumping
# the pin there re-targets this script automatically. Only the
# bpf-linker version lives here: the pin and the linker are a
# validated pair (rationale: docs/PURE_RUST_EVALUATION.md).
#
# The tar.zst release archive is extracted with whichever
# decompressor the host actually has: GNU tar with zstd support, a
# standalone zstd binary, or python3 with the zstandard module.
# None of them -> explicit manual instructions, never a silent skip.
#
# Idempotent: re-running skips whatever is already satisfied, and
# after any install the script re-probes everything it changed
# (verify, then trust); the build at the end is incremental, so an
# up-to-date tree finishes it in seconds. A listed-but-DAMAGED pin —
# an interrupted
# install (Ctrl-C, power loss, full disk) leaves the directory
# registered while its manifests are gone, and every rustup
# component operation then dies with "missing manifest" — is
# repaired automatically: removed and reinstalled from scratch, no
# manual rustup commands. CI does NOT use this script: the workflows
# install the same pair through dtolnay/rust-toolchain + sudo
# install to /usr/local/bin, which fits the ephemeral privileged
# runner better; this is the host path.
#
# Never silent: every long step announces itself before it starts,
# and the bpf-linker download shows a live progress bar when stderr
# is a terminal (curl --progress-bar / wget --show-progress). Piped
# or logged runs stay quiet — no megabytes of carriage-return spam
# in CI logs. The final line reports total wall-clock elapsed.
#
# Usage:
#   ./scripts/bootstrap-ebpf.sh          install whatever is missing,
#                                        fix PATH, build the flagship
#   ./scripts/bootstrap-ebpf.sh --check  report status only, change
#                                        nothing (exit 1 if something
#                                        is missing; never builds)

set -euo pipefail

BPF_LINKER_VERSION="0.11.1"
BPF_LINKER_URL_BASE="https://github.com/aya-rs/bpf-linker/releases/download/v${BPF_LINKER_VERSION}"
CHECK_ONLY=false

case "${1:-}" in
"") ;;
--check) CHECK_ONLY=true ;;
*)
	echo "Usage: $0 [--check]" >&2
	exit 1
	;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TOOLCHAIN_FILE="${REPO_ROOT}/ebpf/rust-toolchain.toml"
LOCAL_BIN="${HOME}/.local/bin"
TMP_DIR=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok() { echo -e "${GREEN}[bootstrap-ebpf]${NC} $1"; }
warn() { echo -e "${YELLOW}[bootstrap-ebpf]${NC} $1"; }
die() {
	echo -e "${RED}[bootstrap-ebpf]${NC} $1" >&2
	exit 1
}

cleanup() {
	if [[ -n "${TMP_DIR}" ]]; then
		rm -rf "${TMP_DIR}"
	fi
}
trap cleanup EXIT

# ── Resolve the dated nightly pin from the crate's own file ────────────────
[[ -f "${TOOLCHAIN_FILE}" ]] || die "ebpf/rust-toolchain.toml not found (${TOOLCHAIN_FILE}) — run from inside the zelynic repo."
command -v rustup >/dev/null 2>&1 || die "rustup is not installed — get it from https://rustup.rs first (this script drives it)."

EBPF_TOOLCHAIN="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${TOOLCHAIN_FILE}" | head -n 1)"
[[ -n "${EBPF_TOOLCHAIN}" ]] || die "could not read the toolchain channel from ${TOOLCHAIN_FILE}."

# ── Status probes (no side effects) ────────────────────────────────────────
# TOOLCHAIN_OK: the pin appears in `rustup toolchain list`. rustup prints
# one "<name>-<host-triple>" line per installed toolchain, so the probe
# anchors on "<pin>-" to reject lookalike pins sharing a prefix.
TOOLCHAIN_OK=false
TOOLCHAIN_BROKEN=false
COMPONENTS_OK=false
LINKER_OK=false
LINKER_RESOLVED=""
LINKER_VERSION_REPORTED=""

probe_all() {
	TOOLCHAIN_OK=false
	TOOLCHAIN_BROKEN=false
	if rustup toolchain list 2>/dev/null | grep -q "^${EBPF_TOOLCHAIN}-"; then
		TOOLCHAIN_OK=true
	fi

	COMPONENTS_OK=true
	# Components print either "rust-src (installed)" or a triple-suffixed
	# "rustfmt-x86_64-unknown-linux-gnu (installed)" — the pattern accepts
	# both shapes and rejects the uninstalled (marker-less) lines.
	if [[ "${TOOLCHAIN_OK}" != true ]]; then
		COMPONENTS_OK=false
	else
		# A listed pin can still be DAMAGED: an interrupted install
		# (Ctrl-C, power loss, full disk) leaves the directory
		# registered while its manifests are gone, and every rustup
		# component operation then dies with "missing manifest".
		# The component enumeration is the reliable detector — it is
		# the exact operation that fails, while `rustup run ... rustc`
		# still succeeds (the binaries are intact), so a run-based
		# probe would miss the damage. One enumeration feeds both
		# the damage verdict and the installed-marker greps.
		local listing
		if listing="$(rustup component list --toolchain "${EBPF_TOOLCHAIN}" 2>/dev/null)"; then
			for component in rust-src rustfmt; do
				if ! grep -qE "^${component}(-[^ ]*)?[[:space:]]+\(installed\)" <<<"${listing}"; then
					COMPONENTS_OK=false
				fi
			done
		else
			TOOLCHAIN_BROKEN=true
			COMPONENTS_OK=false
		fi
	fi

	LINKER_OK=false
	LINKER_ON_PATH=false
	LINKER_RESOLVED=""
	LINKER_VERSION_REPORTED=""
	if command -v bpf-linker >/dev/null 2>&1; then
		LINKER_RESOLVED="$(command -v bpf-linker)"
		LINKER_VERSION_REPORTED="$(bpf-linker --version 2>/dev/null || echo "unknown")"
		LINKER_ON_PATH=true
	elif [[ -x "${LOCAL_BIN}/bpf-linker" ]]; then
		# The script's own install target, present but not on PATH:
		# counts as installed (no pointless re-download on re-run), but
		# cargo cannot see it until PATH includes LOCAL_BIN — the
		# report and --check say exactly that.
		LINKER_RESOLVED="${LOCAL_BIN}/bpf-linker"
		LINKER_VERSION_REPORTED="$("${LOCAL_BIN}/bpf-linker" --version 2>/dev/null || echo "unknown")"
	fi
	if [[ "${LINKER_VERSION_REPORTED}" == *"${BPF_LINKER_VERSION}"* ]]; then
		LINKER_OK=true
	fi
}

report() {
	if [[ "${TOOLCHAIN_BROKEN}" == true ]]; then
		warn "nightly pin ${EBPF_TOOLCHAIN}: LISTED but DAMAGED (component manifests missing — an interrupted install needs a reinstall)"
	elif [[ "${TOOLCHAIN_OK}" == true && "${COMPONENTS_OK}" == true ]]; then
		ok "nightly pin ${EBPF_TOOLCHAIN}: installed (rust-src, rustfmt present)"
	else
		warn "nightly pin ${EBPF_TOOLCHAIN}: not fully installed"
	fi
	if [[ "${LINKER_OK}" == true && "${LINKER_ON_PATH}" == true ]]; then
		ok "bpf-linker ${BPF_LINKER_VERSION}: ${LINKER_RESOLVED}"
	elif [[ "${LINKER_OK}" == true ]]; then
		warn "bpf-linker ${BPF_LINKER_VERSION}: installed at ${LINKER_RESOLVED} but NOT on PATH"
	elif [[ -n "${LINKER_RESOLVED}" ]]; then
		warn "bpf-linker: ${LINKER_RESOLVED} reports '${LINKER_VERSION_REPORTED}', expected ${BPF_LINKER_VERSION}"
	else
		warn "bpf-linker: not on PATH"
	fi
}

probe_all

# ── bpf-linker download + install (definitions before use) ────────────────
install_bpf_linker() {
	local arch asset url archive extracted
	arch="$(uname -m)"
	case "${arch}" in
	x86_64)
		asset="bpf-linker-x86_64-unknown-linux-musl.tar.zst"
		;;
	aarch64)
		asset="bpf-linker-aarch64-unknown-linux-musl.tar.zst"
		;;
	*)
		die "no bpf-linker ${BPF_LINKER_VERSION} prebuilt for ${arch} — build it from source: https://github.com/aya-rs/bpf-linker"
		;;
	esac
	url="${BPF_LINKER_URL_BASE}/${asset}"

	TMP_DIR="$(mktemp -d)"
	archive="${TMP_DIR}/${asset}"
	extracted="${TMP_DIR}/extract"
	mkdir -p "${extracted}"

	# The one big fetch of this bootstrap (a ~100 MB tar.zst — the
	# slow step on slow links). Announce it, then show a live
	# progress bar so the script is never silent while it runs;
	# quiet when stderr is not a terminal (logs, CI capture).
	ok "downloading ${url} (~100 MB, the slow step — progress below)"
	local progress_ok=true
	if [[ ! -t 2 ]]; then
		progress_ok=false
	fi
	if command -v curl >/dev/null 2>&1; then
		if [[ "${progress_ok}" == true ]]; then
			curl -fSL --retry 3 --progress-bar -o "${archive}" "${url}" ||
				die "download failed — check network access, or fetch ${url} by hand and extract bpf-linker into ${LOCAL_BIN}"
		else
			curl -fsSL --retry 3 -o "${archive}" "${url}" ||
				die "download failed — check network access, or fetch ${url} by hand and extract bpf-linker into ${LOCAL_BIN}"
		fi
	elif command -v wget >/dev/null 2>&1; then
		if [[ "${progress_ok}" == true ]]; then
			wget -nv --show-progress -O "${archive}" "${url}" ||
				die "download failed — check network access, or fetch ${url} by hand and extract bpf-linker into ${LOCAL_BIN}"
		else
			wget -q -O "${archive}" "${url}" ||
				die "download failed — check network access, or fetch ${url} by hand and extract bpf-linker into ${LOCAL_BIN}"
		fi
	else
		die "neither curl nor wget is available — fetch ${url} by hand and extract bpf-linker into ${LOCAL_BIN}"
	fi
	[[ -s "${archive}" ]] || die "downloaded file is empty: ${archive}"

	extract_tar_zst "${archive}" "${extracted}"
	[[ -f "${extracted}/bpf-linker" ]] ||
		die "the archive did not contain a top-level bpf-linker binary — extract ${archive} manually and inspect it"

	mkdir -p "${LOCAL_BIN}"
	install -m755 "${extracted}/bpf-linker" "${LOCAL_BIN}/bpf-linker"
	local installed_version
	installed_version="$("${LOCAL_BIN}/bpf-linker" --version 2>/dev/null || echo "unknown")"
	[[ "${installed_version}" == *"${BPF_LINKER_VERSION}"* ]] ||
		die "installed bpf-linker reports '${installed_version}', expected ${BPF_LINKER_VERSION}"
	ok "bpf-linker ${installed_version} installed to ${LOCAL_BIN}/bpf-linker"

	if [[ -n "${LINKER_RESOLVED}" && "${LINKER_RESOLVED}" != "${LOCAL_BIN}/bpf-linker" ]]; then
		warn "PATH resolves bpf-linker to ${LINKER_RESOLVED} — make sure ${LOCAL_BIN} comes first in PATH to use the pinned ${BPF_LINKER_VERSION}."
	fi
}

# ── tar.zst extraction with host-available decompressors ───────────────────
# Order: (1) GNU tar with zstd support (needs the zstd binary on PATH —
# `tar --zstd` execs it; a tar that knows the flag but lacks the binary
# fails, which is why the probe tests the actual round trip), (2) python3
# with the zstandard module decompressing to .tar, then plain tar,
# (3) explicit manual instructions.
extract_tar_zst() {
	local archive="$1" dest="$2"
	if command -v zstd >/dev/null 2>&1 && tar --zstd -tf "$archive" >/dev/null 2>&1; then
		ok "extracting (tar --zstd)..."
		tar --zstd -xf "$archive" -C "$dest"
		return 0
	fi
	if command -v python3 >/dev/null 2>&1 && python3 -c 'import zstandard' >/dev/null 2>&1; then
		local tarfile="${archive%.tar.zst}.tar"
		ok "extracting (python3 zstandard, a few seconds)..."
		python3 - "$archive" "$tarfile" <<'PYEOF'
import sys

import zstandard

with open(sys.argv[1], "rb") as src, open(sys.argv[2], "wb") as dst:
    zstandard.ZstdDecompressor().copy_stream(src, dst)
PYEOF
		tar -xf "$tarfile" -C "$dest"
		return 0
	fi
	die "no zstd-capable extractor on this host (GNU tar with zstd, zstd binary, or python3 with the zstandard module) — extract ${archive} by hand into ${dest}"
}

# ── --check: report and exit, change nothing ───────────────────────────────
if [[ "${CHECK_ONLY}" == true ]]; then
	report
	if [[ "${TOOLCHAIN_OK}" == true && "${COMPONENTS_OK}" == true && "${LINKER_OK}" == true && "${LINKER_ON_PATH}" == true ]]; then
		exit 0
	fi
	die "--check: prerequisites not satisfied — run $0 (without --check) to install or repair, and make sure ${LOCAL_BIN} is on PATH."
fi

# ── Install mode ───────────────────────────────────────────────────────────
report

# The broken-toolchain branch comes FIRST: a damaged pin is listed
# (TOOLCHAIN_OK true) and fails the component probe (COMPONENTS_OK
# false), so the component-add path below would die on rustup's raw
# "missing manifest" error — the exact trap this branch removes.
if [[ "${TOOLCHAIN_BROKEN}" == true ]]; then
	warn "the ${EBPF_TOOLCHAIN} install is damaged (missing component manifests — rustup's own advice is to reinstall; this script does it automatically)"
	ok "removing the damaged toolchain..."
	rustup toolchain uninstall "${EBPF_TOOLCHAIN}"
	ok "reinstalling nightly ${EBPF_TOOLCHAIN} from scratch (minimal profile, rust-src + rustfmt)..."
	rustup toolchain install "${EBPF_TOOLCHAIN}" --profile minimal --component rust-src --component rustfmt
elif [[ "${TOOLCHAIN_OK}" != true ]]; then
	ok "installing nightly ${EBPF_TOOLCHAIN} (minimal profile, rust-src + rustfmt)..."
	rustup toolchain install "${EBPF_TOOLCHAIN}" --profile minimal --component rust-src --component rustfmt
elif [[ "${COMPONENTS_OK}" != true ]]; then
	ok "adding missing components to ${EBPF_TOOLCHAIN}..."
	rustup component add rust-src rustfmt --toolchain "${EBPF_TOOLCHAIN}"
fi

if [[ "${LINKER_OK}" != true ]]; then
	install_bpf_linker
fi

# ── Re-probe: verify what changed, then trust it ──────────────────────────
probe_all
report
if [[ "${TOOLCHAIN_OK}" != true || "${COMPONENTS_OK}" != true ]]; then
	die "the nightly pin ${EBPF_TOOLCHAIN} is still not fully installed — see the rustup output above (a reinstall that fails midway leaves the pin damaged again; re-running this script repairs it)."
fi
if [[ "${LINKER_OK}" != true ]]; then
	die "bpf-linker is still not resolvable at version ${BPF_LINKER_VERSION} — see the messages above."
fi

# Functional sanity: the pin must be able to run rustc at all (this is
# the exact entry build.rs uses for the nested cross-build).
RUSTC_VERSION_REPORTED="$(rustup run "${EBPF_TOOLCHAIN}" rustc --version 2>/dev/null || echo "unknown")"
[[ "${RUSTC_VERSION_REPORTED}" != "unknown" ]] || die "rustup run ${EBPF_TOOLCHAIN} rustc --version failed — the toolchain is listed but broken."
ok "sanity: ${RUSTC_VERSION_REPORTED}"

# ── PATH: persist for future shells, fix for this session ─────────────────
# bpf-linker lives in ~/.local/bin; cargo needs it on PATH at build
# time. The 2026-09-21 debian13 run hit exactly this: prerequisites
# installed, PATH missing ~/.local/bin, two failed builds, a pointless
# cargo clean — and still no binary at the end. The fix is now an
# ACTION, not a warning (NIGHT-improve-16): persist for bash login
# shells (~/.profile, idempotent), tell fish/zsh users the exact line
# (their shells never read ~/.profile), and fix this session's PATH
# regardless — the build below must not depend on the shell the user
# happened to invoke.
if [[ ":${PATH}:" != *":${LOCAL_BIN}:"* ]]; then
	if grep -q '\.local/bin' "${HOME}/.profile" 2>/dev/null; then
		ok "${HOME}/.profile already references ${LOCAL_BIN} — future login shells see bpf-linker."
	else
		printf '\n# added by zelynic scripts/bootstrap-ebpf.sh — bpf-linker lives here\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "${HOME}/.profile"
		ok "persisted 'export PATH=\"$HOME/.local/bin:$PATH\"' to ${HOME}/.profile (bash login shells)"
		warn "fish/zsh login shells do not read ~/.profile — add that export line to your shell config yourself."
	fi
fi
CARGO_BIN="${HOME}/.cargo/bin"
[[ ":${PATH}:" == *":${CARGO_BIN}:"* ]] || PATH="${CARGO_BIN}:${PATH}"
[[ ":${PATH}:" == *":${LOCAL_BIN}:"* ]] || PATH="${LOCAL_BIN}:${PATH}"
export PATH
command -v cargo >/dev/null 2>&1 || die "cargo is not on PATH (looked for ${CARGO_BIN}) — is rustup installed for this user?"

# ── the flagship build (NIGHT-improve-16: bootstrap ends READY) ────────────
# "bootstrap done" must mean "supermassive can run now". The canonical
# native alias builds the full flagship binary with --features ebpf;
# re-running is cheap (cargo is incremental, an up-to-date tree
# finishes in seconds). build.rs preflights the nightly pin and
# bpf-linker BEFORE any compile time is spent, so a prerequisite
# regression dies with its one-command fix, not a raw link error.
ok "building the flagship binary (cargo pro-native-gnu — first build ~1-3 min)..."
if ! (cd "${REPO_ROOT}" && cargo pro-native-gnu); then
	die "cargo pro-native-gnu failed — the prerequisites above are verified, so read the compiler output above it; this is a real compile error."
fi
BUILT_BIN="${REPO_ROOT}/target/pro-native-gnu/zelynic"
[[ -x "${BUILT_BIN}" ]] || die "cargo reported success but ${BUILT_BIN} is missing — inspect the cargo output above."
ok "flagship binary: $("${BUILT_BIN}" -V 2>/dev/null | head -n 1)"

ok "all eBPF build prerequisites are satisfied."
ok "bootstrap finished in ${SECONDS}s"
ok "next: sudo ./scripts/supermassive-test.sh         # light (~2 min)"
ok "      sudo ./scripts/supermassive-test.sh --heavy # supermassive (5+ min)"
