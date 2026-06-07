# Release v3.0.1 — Post-Release Docs + Install Polish

**Status**: Patch release (hotfix)
**Baseline**: v3.0.0 release commit `0c2aac3`
**GitHub Release**: https://github.com/oxyzenQ/zelynic/releases/tag/v3.0.0

## Purpose

Post-release documentation and installation polish to improve the user
experience after the v3.0.0 release. This patch does NOT change runtime
behavior, JSON schema, CLI flags, or enforcement logic.

## What Changed

### Version Bump

- `Cargo.toml`: `3.0.0` -> `3.0.1`
- `Cargo.lock`: zelynic package `3.0.0` -> `3.0.1`

### README Improvements

1. **Install flow**: Replaced the one-liner `curl | tar xz` pattern with a
   full step-by-step install example showing:
   - Separate `curl -L -O` download for tarball and `.sha256` checksum
   - `sha256sum -c` checksum verification before extraction
   - Explicit `tar -xzf` extraction with directory name
   - `cd` into extracted directory, `./zelynic --version` verification
   - `sudo install -Dm755` system-wide install with post-install verification

2. **Tarball path clarity**: Added explicit note that the tarball extracts
   into `zelynic-v3.0.1-x86_64-linux/` with the binary at
   `zelynic-v3.0.1-x86_64-linux/zelynic`.

3. **Man page section**: Added a dedicated "Man Page" subsection explaining
   that the release tarball includes `man/zelynic.1.gz`, with examples for
   viewing from the extracted tarball and system-wide installation. Notes
   that minimal systems may need `man-db` or `mandoc`.

4. **jq scripting examples**: Added a "Scripting with jq" subsection with
   three concise examples for `usage --sample --delta --json` output:
   - Extract `.command` field
   - Extract `.totals.total_delta_combined_bytes`
   - Extract per-interface name and delta bytes

5. **Release naming**: Updated active release naming convention from v3.0.0
   to v3.0.1.

6. **Version example**: Updated `zelynic -V` example output from v3.0.0 to
   v3.0.1.

### CHANGELOG

- Added v3.0.1 release entry with summary of all documentation changes.
- Updated footer link references for v3.0.1.

### Manpage

- Man page is auto-generated from clap help text via `zelynic man`.
- No stale text found in man page output (verified: no "delta JSON is not yet
  implemented", no "text only" for delta mode).
- Man page includes correct `--delta` doc comment: "Use --json to output
  machine-readable delta JSON. Fixed 1-second delta wait. No loop/watch mode.
  Read-only /proc/net/dev only."

### Stale Text Audit

Searched all active docs, README, and source code for stale text:
- "delta JSON is not yet implemented": NOT found in active user-facing text.
  Only present in historical design docs (v3.0-phase-11, v3.0-phase-17,
  v3.0-live-read-only-usage-lab.md) documenting prior planned behavior.
- "text only" for delta: NOT found in active user-facing text. Only present
  in historical docs and test assertions that verify its absence.
- v2.9.0 active install/download examples: NOT found. All README references
  updated to v3.0.1.
- Historical v3.0.0 references in phase docs left intentionally unchanged.

## Validation Commands

```bash
# Format check
cargo fmt --all -- --check

# Lint
cargo clippy --all-targets --all-features -- -D warnings

# Test suites
cargo test --locked usage_delta_json
cargo test --locked usage_delta
cargo test --locked usage
cargo test --locked live_proc_net_dev
cargo test --locked accounting

# Full check-all
./build.sh check-all

# Release build
cargo build --release --locked

# Smoke tests
./target/release/zelynic --version
./target/release/zelynic -V
./target/release/zelynic usage --help
./target/release/zelynic usage --sample
./target/release/zelynic usage --sample --json
./target/release/zelynic usage --sample --delta
./target/release/zelynic usage --sample --delta --json
./target/release/zelynic usage --sample --delta --json | jq '.schema_version, .command, .sample_mode, .sample_count, .read_count, .error'

# Whitespace check
git diff --check
```

## Release Checklist

- [x] Version bumped to v3.0.1 in Cargo.toml and Cargo.lock
- [x] README download URLs updated for v3.0.1
- [x] README install instructions include checksum verification
- [x] README tarball extraction path and binary path documented
- [x] README man page usage note added
- [x] README jq scriptability examples added
- [x] README version example output updated to v3.0.1
- [x] CHANGELOG v3.0.1 release entry added
- [x] CHANGELOG footer links updated for v3.0.1
- [x] No stale text in active user-facing docs
- [x] No stale text in man page output
- [x] No runtime behavior change except version strings
- [x] No JSON schema change
- [x] No new CLI flags
- [x] No new dependencies
- [x] No enforcement behavior change
- [x] All files under 1000 LOC

## Explicit Constraints

- **No runtime behavior change** except version string (v3.0.0 -> v3.0.1)
- **No JSON schema change**
- **No new CLI flags**
- **No new dependencies**
- **No ledger persistence**
- **No app identity implementation**
- **No permission/block/allow mode**
- **No quota guard**
- **No eBPF**
- **No usage command behavior change**
- **No enforcement behavior change**
