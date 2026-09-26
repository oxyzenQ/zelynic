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
`zelynic-v11.0.0-linux-amd64-v4-musl`). Every package name carries
its libc leg (NIGHT-boost-36): the gnu flavors keep `-gnu` —
`zelynic-vX.Y.Z-linux-amd64-v3-gnu.tar.gz` — while the musl
flavors keep their `-musl` leg. The binary's embedded `Build:`
label is the same id (`linux-amd64-v3-gnu`): one string names what
the binary is and what you downloaded, so the two can never drift.
The verification flow is identical for all four.

## 3. Why both GPG + checksums

- **GPG signature** proves the artifact was produced by the maintainer
  (authenticity). An attacker who swaps the archive and its checksum
  files on a mirror cannot forge the `.asc`.
- **Checksums** prove the artifact was not corrupted during download
  (integrity).
- **Three hash families** (SHA-2, BLAKE2, SHA-3) provide defense in
depth — a future cryptanalytic break of any single family does not
invalidate verification via the other two.

## 4. crates.io channel (`cargo install zelynic`)

NIGHT-ask-1 opened the crates.io distribution lane (cosmostrix
crates-io.yml lineage). This section documents what the channel
installs, how to verify it, and the owner's manual for the first
publish — zelynic is a NEW crate on the registry, so the first upload
creates the name and cannot be automated from a cold start.

### What the channel installs — the full-featured lane

`cargo install zelynic` builds and installs the **full-featured
binary**: monitor and limiter, eBPF objects embedded, on a plain
**stable toolchain — no nightly, no bpf-linker, no bootstrap ever
touches the user's machine.** This is the NIGHT-ask-2 shape; the
structural fact that forced the design is unchanged (cargo's package
walk auto-excludes nested packages, so the detached `ebpf/` workspace
cannot ride a registry tarball — verified live, and `include` does
not override the rule), but the answer to it changed: **`ebpf-prebuilt/`**
— a plain directory, not a nested package — rides the tarball with
the two maintainer-built objects, and build.rs's registry lane stages
them for the now-default `ebpf` feature.

- The objects are the **same bytes the GitHub Release binaries embed**
  (sections 1-2 above verify those), generated through the repo's own
  validated build pipeline by `scripts/release/refresh-prebuilt.sh` —
  kernel compatibility is identical by construction, and every object
  re-passes the NIGHT-hunt-29 structural validation at the user's
  build time before it may be embedded.
- `zelynic -V` reports the lane — `eBPF objects: registry-prebuilt` —
  plus the exact source sha from `.cargo_vcs_info.json`; the
  provenance record (source-tree hash, toolchain, linker, per-object
  sha256) rides the tarball as `ebpf-prebuilt/manifest.toml`.
- The dormant lane (stable binary, eBPF surfaces answering their
  honest refusal) survives as the explicit opt-out:
  `cargo install zelynic --no-default-features`.
- The published ship set is curated by the manifest's `include`:
  sources, the test tree, `ebpf-prebuilt/`, the full docs tree, the
  governance docs (CLA / COMMERCIAL_LICENSE / TRADEMARK), and the
  one-command eBPF bootstrap pair (downstream source builders). CI,
  gates, harnesses, and assets stay repo-only.

### Keeping the prebuilt objects fresh (owner procedure)

The lane's freshness is enforced, not promised:
`scripts/gates/check-prebuilt-parity.sh` (gate #18 in
gate-keepers.sh) recomputes the sha256 over the sorted git-tracked
`ebpf/` file hashes and fails every push where it differs from
`ebpf-prebuilt/manifest.toml`'s pin — so after ANY change under
`ebpf/`, run the refresh and commit the lane in the same task:

```bash
./scripts/release/refresh-prebuilt.sh   # rebuild + restage + manifest
# review ebpf-prebuilt/ (git diff --stat ebpf-prebuilt) and commit it
```

The script builds through the repo's own validated pipeline (the
nested nightly cross-compile, the NIGHT-hunt-29 validation), copies
the two objects out of `ebpf/target/`, writes the provenance
manifest, and ends by running the parity gate itself — the generator
and the verifier must agree on every generation. A forced rebuild on
2026-09-27 produced byte-identical objects (bpf-linker 0.11.1 under
the dated pin is reproducible on this host), but the gate pins the
source-tree hash, which is deterministic everywhere: the shipped
objects can never silently fall behind the sources they claim to
carry.

### Verifying a crates.io install

- **Tarball integrity**: cargo itself verifies the crate tarball's
  SHA-256 against the crates.io index before extraction — a swapped
  mirror file fails before any code runs.
- **Dependency tree**: the publish is `cargo publish --locked`, so
  the published dependency set is exactly the tagged `Cargo.lock` —
  the same tree every other CI job validated, and the registry
  channel can never lag behind the GitHub Release (both trigger on
  the same `v*` tag).
- **Source revision**: build.rs's commit-sha chain (NIGHT-ask-1,
  cosmostrix lineage) reads `.cargo_vcs_info.json` when no `.git`
  directory exists, so a registry build's `zelynic -V` reports the
  exact short sha the crate was packed from — not `unknown`.
  Cross-check it against the tag on the GitHub Release page.

### Owner manual — first publish (one-time)

The crate name `zelynic` was unregistered at 2026-09-27 (verified
against the live registry API). The first publish creates it.

1. **Account**: sign in at <https://crates.io> with the GitHub
   account (oxyzenQ), confirm the email address, and enable 2FA —
   crates.io requires both before generating tokens.
2. **API token**: Account Settings → API Tokens → Generate, scope
   **publish-new** (enough to create the crate and upload versions;
   not delete-existing).
3. **CI lane (ongoing)**: add the token as the `CRATES_IO_TOKEN`
   repository secret (repo Settings → Secrets and variables →
   Actions). From then on every owner-pushed `v*` tag publishes via
   `.github/workflows/crates-io.yml` — gated on the branch CI of the
   exact SHA, idempotent against re-pushed tags.
4. **Manual first publish** (do this once, from the tagged commit —
   the workflow's own probe then reports "already published"):

   ```bash
   git checkout v11.0.0-beta.2            # the tag to publish
   cargo login                            # paste the API token
   cargo publish --locked --dry-run       # packs + verifies, no upload
   cargo publish --locked                 # the irreversible upload
   ```

5. **Verify**: `curl -A "zelynic-release-check"
   https://crates.io/api/v1/crates/zelynic` answers 200;
   `cargo install zelynic --locked` in a clean environment succeeds;
   `zelynic -V` reports the tagged short sha and `eBPF objects:
   registry-prebuilt`, and an enforcement command under a non-root
   account answers `root required` (not `eBPF not compiled`) — the
   installed binary is the full build.
6. **Recovery**: a bad version is `cargo yank --vers X.Y.Z` — yanked
   versions stay resolvable for existing lockfiles but vanish from
   new ones. crates.io never deletes a version; there is no re-upload
   for the same number, which is why the tag/version match check and
   the CI gate run before every upload.

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
