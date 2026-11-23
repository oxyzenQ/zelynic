#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# NIGHT-SOLID-DEFENSE-2 LIVE RIG: the end-to-end proof that the D5
# commit-signature depth is real, not a rendered claim. Three
# verdict branches, each driven through the ACTUAL shipped code path
# (build.rs verification -> compile-time stamp -> the sig ladder's
# D5 policy -> the rendered report), on a scratch copy of this tree:
#
#   branch 1  unsigned HEAD          -> D5 FAIL "carries NO GPG signature"
#   branch 2  foreign-signed HEAD    -> D5 FAIL "does not cover ... not the
#                                       maintainer's signature" (the MITM shape)
#   branch 3  pinned-key-signed HEAD -> D5 pass, SIGNATURE: AUTHENTIC 6/6
#                                       (the pinned pair swapped for a
#                                       throwaway key IN THE SCRATCH COPY —
#                                       the same mechanism, a stand-in
#                                       identity, clearly labeled)
#
# The throwaway key lives and dies inside the rig's temp dir; the
# owner's real key never rides this script. Requirements: bash, git,
# gpg, cargo with the repo's pinned toolchain (rustup obeys
# rust-toolchain.toml), and whatever the dormant build lane needs.
# Usage: bash scripts/labs-exp/verify-gpg-commit-binding.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

fail() {
	echo "RIG-FAIL: $*" >&2
	exit 1
}
note() { echo "RIG: $*"; }

for tool in git gpg cargo awk; do
	command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done

WORK="$(mktemp -d /tmp/zelynic-d5-rig-XXXX)"
SCRATCH="$WORK/tree"
KEYHOME="$WORK/throwaway-keyring"
cleanup() {
	git config --global --unset gpg.format >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

note "scratch tree at $SCRATCH (the real tree is never touched)"
mkdir -p "$SCRATCH"
tar -C "$REPO_ROOT" \
	--exclude='./target' --exclude='./.git' \
	--exclude='./ebpf-prebuilt' \
	-cf - . | tar -C "$SCRATCH" -xf -

# ── the throwaway signing identity ────────────────────────────────
gpgconf --kill all >/dev/null 2>&1 || true
sleep 1
mkdir -p "$KEYHOME" && chmod 700 "$KEYHOME"
gpg --homedir "$KEYHOME" --batch --pinentry-mode loopback --passphrase '' \
	--quick-gen-key "D5 Rig Throwaway <rig@example.invalid>" ed25519 sign 0 \
	>/dev/null 2>&1
gpgconf --kill all >/dev/null 2>&1 || true
sleep 1
RIG_FPR="$(gpg --homedir "$KEYHOME" --list-keys --with-colons |
	awk -F: '/^fpr/{print $10; exit}')"
[ "${#RIG_FPR}" -eq 40 ] || fail "throwaway key generation failed"
note "throwaway key: $RIG_FPR"

# ── branch 1: unsigned HEAD ───────────────────────────────────────
git -C "$SCRATCH" init -q -b main
git -C "$SCRATCH" add -A
git -C "$SCRATCH" -c user.name=rig -c user.email=rig@example.invalid \
	commit -q -m "rig branch 1: unsigned"

build_and_sig() {
	local label="$1"
	(cd "$SCRATCH" && cargo build --locked --no-default-features -q \
		>/dev/null 2>"$WORK/build.err") ||
		{
			cat "$WORK/build.err" >&2
			fail "$label: build failed"
		}
	"$SCRATCH/target/debug/zelynic" sig >"$WORK/sig.txt" 2>&1 || true
	note "$label sig verdict: $(grep '^verdict:' "$WORK/sig.txt")"
}

expect_d5() {
	local label="$1" want="$2"
	grep -q '^D5 commit-signature' "$WORK/sig.txt" ||
		fail "$label: no D5 row in $(cat "$WORK/sig.txt")"
	grep -q "$want" "$WORK/sig.txt" ||
		fail "$label: D5 row does not carry: $want
$(grep '^D5' "$WORK/sig.txt")"
	note "$label: D5 carries the expected verdict text"
}

build_and_sig "branch 1 (unsigned HEAD)"
expect_d5 "branch 1" "carries NO GPG signature"

# ── branch 2: signed by a FOREIGN key (the MITM shape) ────────────
# git's gpg child inherits the environment: the sign MUST run with
# GNUPGHOME on the throwaway keyring (the probe's own lesson —
# without it gpg looks in ~/.gnupg and answers "no secret key").
gpgconf --kill all >/dev/null 2>&1 || true
sleep 1
GNUPGHOME="$KEYHOME" git -C "$SCRATCH" \
	-c user.name=rig -c user.email=rig@example.invalid \
	-c user.signingkey="$RIG_FPR" -c commit.gpgsign=true \
	commit -q --allow-empty -m "rig branch 2: foreign signature"
build_and_sig "branch 2 (foreign-signed HEAD)"
expect_d5 "branch 2" "not the maintainer's signature"

# ── branch 3: the pinned pair swapped for the throwaway key ───────
# Same mechanism, stand-in identity: the scratch tree's pin now names
# the throwaway key, the HEAD signature from branch 2 becomes the
# "maintainer's" — the verified-pass branch, honestly simulated.
gpg --homedir "$KEYHOME" --armor --export "$RIG_FPR" \
	>"$SCRATCH/assets/gpg/maintainer-47A50AEF4B65AAC2.asc"
printf '%s' "$RIG_FPR" >"$SCRATCH/assets/gpg/pinned-maintainer-fpr.txt"
build_and_sig "branch 3 (pinned-key-signed HEAD)"
expect_d5 "branch 3" "by the pinned maintainer key"
grep -q "SIGNATURE: AUTHENTIC (6/6 depths verified)" "$WORK/sig.txt" ||
	fail "branch 3: the ladder must read AUTHENTIC 6/6:
$(cat "$WORK/sig.txt")"
note "branch 3: the full ladder reads AUTHENTIC 6/6"

echo
echo "RIG-PASS: all three D5 verdict branches proven through the real"
echo "code path (build.rs verification -> stamp -> sig ladder):"
echo "  unsigned        -> FAIL, named"
echo "  foreign signer  -> FAIL, named (the MITM shape)"
echo "  pinned signer   -> pass, AUTHENTIC 6/6"
