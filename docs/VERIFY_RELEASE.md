<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# Verifying Release Artifacts

Every release ships **three checksum files** plus a **detached GPG
signature** per archive. Verify at least one checksum + the GPG
signature before trusting a downloaded binary.

## 1. GPG Signature Verification (recommended)

### Import the maintainer's public key

The key is available on two public keyservers:

```bash
# Ubuntu keyserver (primary)
gpg --keyserver keyserver.ubuntu.com --recv-keys F5324E0967F104D58CE025F347A50AEF4B65AAC2

# openpgp.org (mirror)
gpg --keyserver keys.openpgp.org --recv-keys F5324E0967F104D58CE025F347A50AEF4B65AAC2
```

**Key fingerprint**:
`F532 4E09 67F1 04D5 8CE0  25F3 47A5 0AEF 4B65 AAC2`.
This is the maintainer's published master key (ed25519, Certify +
Sign, never expires) — the **same cosmic-dragon identity that signs
the cosmostrix releases**. One key, one identity, both projects:
users who already verified cosmostrix artifacts import nothing new.
The signing subkeys rotate on a bounded hygiene cycle; the keyserver
always carries the current set — trust it over any list printed here.
UID: `Rezky Cahya Sahputra (cosmic dragon)
<130107241+oxyzenQ@users.noreply.github.com>`.

### Verify the signature

```bash
# Download the archive + its .asc signature from the GitHub Release page
# e.g. zelynic-vX.Y.Z-linux-amd64-v3-gnu.tar.gz
#      zelynic-vX.Y.Z-linux-amd64-v3-gnu.tar.gz.asc

gpg --verify zelynic-vX.Y.Z-linux-amd64-v3-gnu.tar.gz.asc
```

Expected output contains:
`gpg: Good signature from "Rezky Cahya Sahputra (cosmic dragon) ..."`.
A `Good signature` line confirms authenticity. The
`WARNING: This key is not certified with a trusted signature` notice
is normal for first-time imports — verify the fingerprint matches
`F532 4E09 67F1 04D5 8CE0  25F3 47A5 0AEF 4B65 AAC2`.

### Signing key expiry policy

The signing subkeys carry a bounded expiry cycle for security
hygiene (the artifact-signing subkey runs a ~2-year cycle, the
tag-signing subkey a 5-year cycle). The master key generates a fresh
subkey before the current one expires and publishes it to the
keyservers. Signatures made before expiry remain cryptographically
valid forever — GPG verifies them against the public key as it stood
at signing time; expiry only blocks *new* signatures. GPG may print
`WARNING: signature key expired` alongside the `Good signature`
line — this is expected and safe; import the latest public key to
silence it. If GPG refuses to verify at all (very old GPG versions
only), fall back to checksum verification (section 2). CI monitors
key expiry weekly (the `gpg-key-check` job in maintenance.yml) and
warns 30 days before any subkey lapses.

## 2. Checksum Verification

### Checksum files

| File | Algorithm | Family | Quantum-safe? |
|------|-----------|--------|---------------|
| `*.sha512sum` | SHA-512 | SHA-2 | 256-bit (borderline) |
| `*.b2sum` | BLAKE2b-512 | BLAKE2 | 256-bit |
| `*.shake256` | SHAKE256 | SHA-3 XOF (NIST PQ) | 256-bit |

### How to verify

All three commands print `<filename>: OK` on success (or `FAILED` on
mismatch). No manual hash comparison needed.

```bash
# Classical (universal, every Linux has this)
sha512sum -c project-vX.Y.Z-linux-amd64-v3-gnu.tar.gz.sha512sum

# Quantum-resistant — BLAKE2b (fastest, in coreutils)
b2sum -c project-vX.Y.Z-linux-amd64-v3-gnu.tar.gz.b2sum

# Quantum-resistant — SHAKE256 (NIST PQ standard, via Python)
# openssl's -shake256 default output length varies by version/distro;
# Python hashlib.shake_256 is consistent (64 bytes = 128 hex chars)
COMPUTED=$(python3 -c "import hashlib; print(hashlib.shake_256(open('project-vX.Y.Z-linux-amd64-v3-gnu.tar.gz','rb').read()).hexdigest(64))")
EXPECTED=$(awk '{print $1}' project-vX.Y.Z-linux-amd64-v3-gnu.tar.gz.shake256)
[ "$COMPUTED" = "$EXPECTED" ] && echo "project-vX.Y.Z-linux-amd64-v3-gnu.tar.gz: OK" || echo "FAILED"
```

Replace `project-vX.Y.Z-linux-amd64-v3-gnu` with the actual archive
name. Releases are arch-baseline builds (NIGHT-improve-22): four
packages per tag — `v3` (AVX2/BMI2/FMA, any x86_64 CPU from ~2013
onward) and `v4` (AVX-512), each in `gnu` and `musl` (e.g.
`zelynic-v11.0.0-linux-amd64-v3-gnu`,
`zelynic-v11.0.0-linux-amd64-v4-musl`). The verification flow is
identical for all four.

## 3. Why both GPG + checksums

- **GPG signature** proves the artifact was produced by the maintainer
  (authenticity). An attacker who swaps the archive and its checksum
  files on a mirror cannot forge the `.asc`.
- **Checksums** prove the artifact was not corrupted during download
  (integrity).
- **Three hash families** (SHA-2, BLAKE2, SHA-3) provide defense in
depth — a future cryptanalytic break of any single family does not
invalidate verification via the other two.

## Verification tools required

- `sha512sum` — GNU coreutils (preinstalled on every Linux)
- `b2sum` — GNU coreutils ≥ 8.x (preinstalled on modern distros)
- `gpg` — GnuPG 2.x (preinstalled on every major distro; the GPG
  check in section 1 needs it, the checksum checks do not)

All three tools ship with Arch Linux, Debian, Ubuntu, Fedora, Alpine,
and macOS by default — no extra install needed.
<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `ebpf/src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
