<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->
<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# The vendored legacy pair (the pre-MMSPA counterfactual)

This directory carries the last pre-MMSPA stable — zelynic v11.0.0,
the leaf-anchored datapath the MMSPA subtree-coverage contract is
measured against (NIGHT-perf-1) — so no CI run and no local harness
invocation ever fetches the counterfactual from the network. Since
the vendoring v2 refresh (night-remake-1) the tarball is no longer
byte-identical to the upstream release asset: exactly one content
modernization rides inside the bundled README (see Vendoring v2
below); the `zelynic` binary and `LICENSE` remain the original
release bytes, untouched.

## Contents

| File | Provenance |
| --- | --- |
| `zelynic-v11.0.0-linux-amd64-v3-musl.tar.gz` | the v11.0.0 release asset (the musl static flavor — the same one the CI legs stage), with the vendoring-v2 README contact modernization; binary and LICENSE bytes are the original release bytes |
| `zelynic-v11.0.0-linux-amd64-v3-musl.tar.gz.sha512sum` | sha512 over the vendored v2 bytes, re-pinned at vendoring v2 (originally the release's own sidecar) |
| `zelynic-v11.0.0-linux-amd64-v3-musl.tar.gz.b3sum` | BLAKE3 over the same bytes, computed at vendoring time against the sha512-verified tarball (the v11.0.0 release predates the b3sum sidecar era — its own sidecars are the b2/sha512/shake256 family) |

## Vendoring v2 (night-remake-1, the contact decontamination)

The v1 vendoring pinned the release asset byte-for-byte. Vendoring
v2 swaps exactly one line inside the tarball's bundled `README.md`
snapshot: the maintainer's retired contact address becomes the live
one (`oxyzenQ@proton.me`), mirroring the current tree's README
verbatim. Nothing else moved: the `zelynic` binary and `LICENSE`
members are byte-identical to the upstream v11.0.0 asset (verified
with `cmp` on extraction), the member order, modes, ownership and
mtimes are preserved, and the repack is deterministic (`gzip -n`).
Both digest sidecars were re-pinned over the v2 bytes and the CI
stage and the local battery verify against the re-pinned digests —
nothing hardcodes the old ones. The counterfactual's validity is
untouched: the MMSPA-vs-legacy comparison measures the v11 datapath
binary, which never carried the retired address.

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
