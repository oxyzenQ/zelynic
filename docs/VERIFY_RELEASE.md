<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

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
UIDs (primary first, the keyserver's list order):
`rezky_nightky (oxyzenQ) <oxyzenQ@proton.me>`,
`Rezky Cahya Sahputra (cosmic dragon)
<130107241+oxyzenQ@users.noreply.github.com>`.

### Verify the signature

```bash
# Download the archive + its .asc signature from the GitHub Release page
# e.g. zelynic-vX.Y.Z-linux-amd64-v3-musl.tar.gz
#      zelynic-vX.Y.Z-linux-amd64-v3-musl.tar.gz.asc

gpg --verify zelynic-vX.Y.Z-linux-amd64-v3-musl.tar.gz.asc
```

Expected output contains (the primary UID owns the `Good signature`
line, the second UID rides the `aka` line):

```text
gpg: Good signature from "rezky_nightky (oxyzenQ) <oxyzenQ@proton.me>" [ultimate]
gpg:                 aka "Rezky Cahya Sahputra (cosmic dragon) <130107241+oxyzenQ@users.noreply.github.com>" [ultimate]
```

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
| `*.b3sum` | BLAKE3 | BLAKE3 | 128-bit |
| `*.shake256` | SHAKE256 | SHA-3 XOF (NIST PQ) | 256-bit |

### How to verify

All three commands print `<filename>: OK` on success (or `FAILED` on
mismatch). No manual hash comparison needed.

```bash
# Classical (universal, every Linux has this)
sha512sum -c project-vX.Y.Z-linux-amd64-v3-musl.tar.gz.sha512sum

# The fast modern lane — BLAKE3 (the official b3sum utility)
b3sum -c project-vX.Y.Z-linux-amd64-v3-musl.tar.gz.b3sum

# Quantum-resistant — SHAKE256 (NIST PQ standard, via Python)
# openssl's -shake256 default output length varies by version/distro;
# Python hashlib.shake_256 is consistent (64 bytes = 128 hex chars)
COMPUTED=$(python3 -c "import hashlib; print(hashlib.shake_256(open('project-vX.Y.Z-linux-amd64-v3-musl.tar.gz','rb').read()).hexdigest(64))")
EXPECTED=$(awk '{print $1}' project-vX.Y.Z-linux-amd64-v3-musl.tar.gz.shake256)
[ "$COMPUTED" = "$EXPECTED" ] && echo "project-vX.Y.Z-linux-amd64-v3-musl.tar.gz: OK" || echo "FAILED"
```

Replace `project-vX.Y.Z-linux-amd64-v3-musl` with the actual archive
name. Releases are arch-baseline builds (NIGHT-improve-22), fully
static musl — the only libc shape (night-dragon-maintenance-6 retired
the gnu packages): two packages per tag — `v3` (AVX2/BMI2/FMA, any
x86_64 CPU from ~2013 onward) and `v4` (AVX-512), e.g.
`zelynic-v50.0.0-rc.1-linux-amd64-v3-musl`,
`zelynic-v50.0.0-rc.1-linux-amd64-v4-musl`. Every package name carries
its platform id (NIGHT-boost-36): the `-musl` leg names the libc
shape. The binary's embedded `Build:`
label is that platform id under the estate `pro-` prefix
(`pro-linux-amd64-v3-musl`, night-dragon-maintenance-T1): one
sentence names what the binary is and what you downloaded — the
tarball carries the id, the `Build:` line carries the same id with
the fixed `pro-` brand rung — so the two can never drift.
The verification flow is identical for both.

## 3. Why both GPG + checksums

- **GPG signature** proves the artifact was produced by the maintainer
  (authenticity). An attacker who swaps the archive and its checksum
  files on a mirror cannot forge the `.asc`.
- **Checksums** prove the artifact was not corrupted during download
  (integrity).
- **Three hash families** (SHA-2, BLAKE3, SHA-3) provide defense in
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
- `zelynic -V` reports the exact source sha from
  `.cargo_vcs_info.json` under the full-life Signature line ("Pure
  eBPF builtin", NIGHT-dinner-4); which lane produced the objects —
  `registry-prebuilt` — is `zelynic doctor`'s answer (Build line and
  JSON `ebpf_lane`); the provenance record (source-tree hash,
  toolchain, linker, per-object sha256) rides the tarball as
  `ebpf-prebuilt/manifest.toml`.
- The dormant lane (stable binary, eBPF surfaces answering their
  honest refusal) survives as the explicit opt-out:
  `cargo install zelynic --no-default-features`.
- The published ship set is curated by the manifest's `include`:
  sources, the test tree, `ebpf-prebuilt/`, the top-level docs tree
  (NIGHT-dinner-15: `docs/*.md` — the research/audits/archive subdirs
  stay repo-only, the cosmostrix exclude lineage), the governance
  docs (CLA / COMMERCIAL_LICENSE / TRADEMARK), and the one-command
  eBPF bootstrap pair (downstream source builders). CI, gates,
  harnesses, and assets stay repo-only.

### Keeping the prebuilt objects fresh (owner procedure)

The lane's freshness is enforced, not promised — at three separate
moments (NIGHT-dinner-1):

- **Commit time**: the first `./scripts/gate-keepers.sh` run on a
  clone self-installs `.githooks/pre-commit` (repo-local
  `core.hooksPath`), so every subsequent commit runs
  `scripts/gates/check-commit-gate.sh`: the parity check on the
  staged tree plus the pairing rule — a commit that stages `ebpf/`
  must also stage `ebpf-prebuilt/`. The "edited ebpf/, forgot the
  refresh" and "refreshed, forgot `git add ebpf-prebuilt`" mistakes
  die at commit creation, not at push time. (`git commit --no-verify`
  skips any local hook — that buys a WIP commit, never a shipment:
  the CI arms below still block the push and the publish.)
- **Push time**: `scripts/gates/check-prebuilt-parity.sh` (gate #18
  in gate-keepers.sh) recomputes the sha256 over the sorted
  git-tracked `ebpf/` file hashes and fails every push where it
  differs from `ebpf-prebuilt/manifest.toml`'s pin — the wholesale
  Dragon Guard workflow runs it unfiltered on every push and PR.
- **Ship time**: the crates.io publish waits for BOTH the ci.yml run
  AND the wholesale gate-keepers.yml run on the exact tagged SHA,
  then runs the parity check directly in the publish job before the
  irreversible upload; the release workflow runs the same check in
  each build leg before compiling (a stale lane would otherwise ship
  registry objects that differ from the release binaries' fresh
  rebuild, silently breaking the "same bytes" provenance contract).

So after ANY change under `ebpf/`, run the refresh and commit the
lane in the same task:

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
  Cross-check it against the tag on the GitHub Release page. The
  `unknown` degradation needs every lane to fail, and its realistic
  causes are all publish-time: packing outside a git checkout (no vcs
  document is written at all) or a document with no usable sha. The
  sibling-project incident that motivates the rule
  (night-dragon-maintenance-T1): a registry-installed binary printed
  `Build: linux-amd64-gnu (unknown)` — packed without the vcs
  document. zelynic's publish lanes (the `crates-io.yml` workflow and
  the manual procedure above) both run from a clean git checkout of
  the tagged commit, which is the standing rule: never `cargo
  publish` from a plain source export or a HEAD that is not the tag.
  The full incident record lives in docs/MAINTENANCE.md §7, "The
  unknown commit id class".

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
   Actions). Scope note (NIGHT-dinner-1): the crate has existed on
   the registry since 2026-09-27, so a **publish-update** scope
   token is exactly right — publish-new is only needed for the very
   first version, which already landed. From then on every
   owner-pushed `v*` tag publishes via
   `.github/workflows/crates-io.yml` — gated on the branch CI AND
   the wholesale gate-keepers run of the exact SHA, plus the direct
   prebuilt-parity check inside the publish job; idempotent against
   re-pushed tags.
4. **Manual first publish** (done once for v11.0.0-beta.3 on
   2026-09-27; kept as the reference procedure for any future
   manual publish, run from the tagged commit — the workflow's own
   probe then reports "already published"):

   ```bash
   git checkout v11.0.0-beta.2            # the tag to publish
   cargo login                            # paste the API token
   cargo publish --locked --dry-run       # packs + verifies, no upload
   cargo publish --locked                 # the irreversible upload
   ```

5. **Verify**: `curl -A "zelynic-release-check"
   https://crates.io/api/v1/crates/zelynic` answers 200;
   `cargo install zelynic --locked` in a clean environment succeeds;
   `zelynic -V` reports the tagged short sha under the full-life
   Signature line. The direct full-build probe is `zelynic doctor`
   (NIGHT-dinner-3): the `Build:` line names the binary's own flavor —
   `FULL-LIFE (eBPF objects: registry-prebuilt)` for the install above,
   `HALF-LIFE (eBPF objects: dormant (not compiled))` for a
   `--no-default-features` build (`zelynic doctor --print-json` carries
   the same verdict in the `build_flavor` / `ebpf_lane` fields; the
   version report itself answers only at brand level — "Pure eBPF
   builtin" vs "eBPF dormant", NIGHT-dinner-4). The older behavioral
   check still works: an enforcement command under a non-root account
   answers `root required` (not `eBPF not compiled`) — the installed
   binary is the full build.
6. **Recovery**: a bad version is `cargo yank --vers X.Y.Z` — yanked
   versions stay resolvable for existing lockfiles but vanish from
   new ones. crates.io never deletes a version; there is no re-upload
   for the same number, which is why the tag/version match check and
   the CI gate run before every upload.

## 5. Behavioral verification (the golden vectors)

The signature and the checksums attest the ARTIFACT: this binary
comes from the maintainer and arrived intact. The golden vectors
attest the BEHAVIOR: the binary's pure IP layer produces exactly the
verdicts the release's attestation appendix records — frozen
`/proc/net` rows in, byte-exact verdicts out, eighteen vectors plus
the state table, re-ratified by CI on every commit and every release
tag (night-frontier-Z5). The appendix lives at
[GOLDEN_VECTORS.md](GOLDEN_VECTORS.md); the one-line ratification
against any checkout is:

```bash
cargo test --locked golden_vectors
```

No root, no eBPF, no network — any host, offline. A tagged release
whose battery disagrees with the appendix cannot exist: the same
commit carries both, and the CI gate refuses the drift. What the
vectors do NOT cover (live kernel behavior) is attested by the
5.15-floor cross-distro matrix and the Supermassive battery — the
three proofs (artifact, behavior, kernel) compose into one
attestation.

The binary also seals itself: `zelynic sig` renders the six-depth
ladder — D0-D3 over the masked provenance layers and the running
image (night-signature-advanced-1), D4 object-integrity
(night-depth-hardening-Z2) re-hashing the embedded eBPF kernel
objects against the digests build.rs stamped into the binary, and D5
commit-signature (night-solid-defense-2) reporting the build-time
verification that the commit the binary claims is GPG-signed by the
same pinned maintainer key this document publishes (the repo carries
the public key at `assets/gpg/maintainer-47A50AEF4B65AAC2.asc` with
the fingerprint single-sourced in
`assets/gpg/pinned-maintainer-fpr.txt`, both files' bytes pinned by
the assets BLAKE3 sidecar — `b3sum -c assets/signature.b3sum` at the
repo root names a swapped key or fingerprint before import; build.rs
verifies against it in an isolated throwaway keyring, never the
building user's). The
camera the artifact plants is the camera its build pinned — an
object patched inside the artifact fails the depth by name and the
verdict goes TAMPERED (exit 1). A one-byte-flip tamper test runs
rootless in the CI test lane on every push.

With D5 the channel chain closes end to end: verify the SIGNED TAG
the release was cut from (`git tag -v v<version>` after importing
the key above — releases are cut from annotated tags signed by the
maintainer key), the tag names the commit, and the binary's own D5
row proves it was built from a commit signed by that same key. Key
→ tag → commit → binary: a binary swapped on the release channel
can no longer replay its claims unanswered, because the swap breaks
the D5 commit binding or the tag signature — one of the two must
give.

## 6. Reproducible builds (D4)

Sections 1-5 attest the ARTIFACT: this binary comes from the
maintainer, arrived intact, and behaves as attested. The D4 chain
(night-depth-hardening-Z1) attests the PROCESS: the published
artifact is what the source itself produces, byte for byte, on an
independent machine.

The recipe is fully pinned and committed:

- the Rust toolchain pin (`rust-toolchain.toml`, `1.98.1`) plus the
  dated eBPF nightly pin (`nightly-2026-09-18`) and the prebuilt
  bpf-linker `0.11.1`
- the committed `Cargo.lock` (`--locked` — never a fresh resolution)
- the release matrix's exact `RUSTFLAGS` (the per-platform
  `-C target-cpu` baseline plus `-C target-feature=+crt-static`)
- `SOURCE_DATE_EPOCH` pinned to the release commit's timestamp —
  build.rs derives the `-V` Build-time stamp from it, so the wall
  clock never enters the bytes (the reproducible-builds.org
  standard; a dev build without the pin keeps its honest local
  stamp)

Two independent CI hosts run the same recipe against the same commit
and their outputs are compared byte-for-byte by `cmp` — the Dragon
Guard - Reproducible Release (D4) lane
(`.github/workflows/reproducible.yml`), triggered on every `v*` tag,
on a weekly drift-watch clock, and on demand. A green run means the
published hash is rebuildable from source under the pinned recipe; a
red run prints both digests and names the drift — and the release's
provenance claim does not stand until the drift is explained. This
is the class of "modified build with no trace" killed permanently:
a rebuild that differs cannot hide.

Rebuild it yourself (any x86-64-v3 Linux host — the exact commands
the CI legs run):

```bash
git clone --depth=1 --branch v<VERSION> https://github.com/oxyzenQ/zelynic.git
cd zelynic
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct HEAD)"
export ZELYNIC_BUILD=pro-linux-amd64-v3-musl
export RUSTFLAGS="-D warnings -C target-cpu=x86-64-v3 -C target-feature=+crt-static"
cargo build --release --locked --target x86_64-unknown-linux-musl --features ebpf
sha256sum target/x86_64-unknown-linux-musl/release/zelynic
```

**What D4 claims, exactly.** The machine-checked contract is CI-host
to CI-host identity: two independent hosts, same recipe, same commit,
byte-identical outputs. A local rebuild is the best-effort lane, and
it carries one honest residual: the Rust toolchain embeds the
absolute registry path of each dependency's source
(`$CARGO_HOME/registry/src/...`) into panic location strings, so a
rebuild on a host whose toolchain layout differs from the build
runner's (`/home/runner/.cargo`) may hash differently while producing
the same program. That residual is a toolchain-wide property, not a
zelynic input — and it is exactly why the two-leg CI lane, not a
single local run, is the proof of record. The v3 flagship is the
shape the D4 matrix proves today; the v4 package differs from it only
in its `target-cpu` flag.

## Verification tools required

- `sha512sum` — GNU coreutils (preinstalled on every Linux)
- `b3sum` — the official BLAKE3 utility (not in coreutils):
  Debian 13+ and Ubuntu 24.04+ ship it as the `b3sum` package
  (`apt install b3sum`); anywhere with a Rust toolchain,
  `cargo install b3sum` builds the same binary
- `gpg` — GnuPG 2.x (preinstalled on every major distro; the GPG
  check in section 1 needs it, the checksum checks do not)

All three tools ship with Arch Linux, Debian, Ubuntu, Fedora, Alpine,
and macOS by default — the one exception is `b3sum`, a one-package
install where it is missing (see above); no other extra install
needed.

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
