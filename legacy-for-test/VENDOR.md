<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# The vendored legacy pair (the pre-MMSPA counterfactual)

This directory carries the EXACT release bytes of the last pre-MMSPA
stable — zelynic v11.0.0, the leaf-anchored datapath the MMSPA
subtree-coverage contract is measured against (NIGHT-perf-1) — so no
CI run and no local harness invocation ever fetches the
counterfactual from the network.

## Contents

| File | Provenance |
| --- | --- |
| `zelynic-v11.0.0-linux-amd64-v3-musl.tar.gz` | the v11.0.0 release asset, byte-identical (the musl static flavor — the same one the CI legs stage) |
| `zelynic-v11.0.0-linux-amd64-v3-musl.tar.gz.sha512sum` | the release's own sidecar, verbatim |
| `zelynic-v11.0.0-linux-amd64-v3-musl.tar.gz.b3sum` | BLAKE3 over the same bytes, computed at vendoring time against the sha512-verified tarball (the v11.0.0 release predates the b3sum sidecar era — its own sidecars are the b2/sha512/shake256 family) |

## Verification

```sh
cd legacy-for-test
sha512sum -c zelynic-v11.0.0-linux-amd64-v3-musl.tar.gz.sha512sum
b3sum -c zelynic-v11.0.0-linux-amd64-v3-musl.tar.gz.b3sum
```

`sha512sum` is coreutils; `b3sum` is the official BLAKE3 utility —
Ubuntu 24.04+ ships it as the `b3sum` package (`apt install b3sum`),
the same fast lane docs/VERIFY_RELEASE.md prescribes for the release
artifacts. The CI stage verifies BOTH digests before any micro-VM
boots; a missing file or a digest mismatch fails the leg on the
runner, where retries are cheap.

## Consumers

- `.github/workflows/supermassive.yml` — the stage step verifies the
  pair, then extracts the tarball into the micro-VM rootfs at
  `/opt/zelynic/legacy/` (the path the in-VM battery expects).
- `scripts/supermassive/mmspa-vs-legacy-test.py` — the vendored pair
  is the first no-network lane after the CI-staged binary: verified
  against both sidecars, then extracted into the TMPDIR cache.

## Packaging note

The directory is `export-ignore`d (see `.gitattributes`): `git
archive` trees — the micro-VM rootfs assembly among them — never
carry it. The stage step extracts the verified tarball explicitly,
so the guest sees only `/opt/zelynic/legacy/zelynic`, exactly the
shape it saw when the pair rode a per-run release fetch.

## Local extraction hygiene

A manual verify-then-run session extracts the tarball in place —
`tar xzf *.gz` lays down the release's own `README.md`, `LICENSE`
and the 2.2M `zelynic` binary next to the vendored pair. All three
are disposable products and ride `.gitignore`, so `git status`
stays clean after every test session (`git clean -fdx` sweeps them
when the next session wants a pristine floor). This directory's
own doc carries the `VENDOR.md` name for exactly that reason: the
tarball's README would clobber a tracked `README.md` on every
extraction, and a doc that fights its own test fixture is a doc
that loses.

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
