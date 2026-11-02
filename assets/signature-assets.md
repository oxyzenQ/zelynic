<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# signature assets

BLAKE3 signature checksums for every image under `assets/` — the
authenticity record for LTS usage. A logo that does not reproduce its
digest here is a fake, a duplicate, or a silent re-encode, and none of
those ships: the digests are the one command any release, mirror, or
fork page can run before trusting an image file.

The digests were computed with `b3sum` 1.8.7 (the BLAKE3 reference
tool — the same digest family gate 18's prebuilt-parity check pins)
over the tracked bytes at night-dragon-maintenance-X1 time, 2026-11-02.
The machine-readable sidecar is
[signature-assets.b3sum](signature-assets.b3sum), kept in `b3sum -c`
format so the check below is the whole protocol.

## signed images

| image | bytes | blake3 digest (b3sum) |
|-------|------:|-----------------------|
| assets/eagle-eyes-depth.png | 88,764 | `d1fbf606f0196565859221fdb5578a5006c8d70371c2d88e51ddf736fe0ddb23` |
| assets/eagle-eyes.png | 107,306 | `c83dd5a551adf185dbaedaab00e39c8220860a6f951be50736f6137a070c19d6` |
| assets/qr/bitcoin.png | 575 | `09ec09fcdc4815e23373cb266bb120aa4e1af140fb9d598e117d05478a791b47` |
| assets/qr/ethereum.png | 591 | `4eb520de0fe258d2c82ba07ccba8d9e48bafc63904d022a83cc42b59d1ed2ac7` |
| assets/qr/solana.png | 595 | `bca56b0a454daf06ff2d57fe401719553e28733e73479de2652a0740a9e87d1a` |
| assets/zelynic-original-logo-2026.png | 1,413,927 | `0e12f2a403b7a23ea637aa651b00d80bc58c2700321ab27ad386398eadbc944c` |

`assets/tools.md` is a documentation file, not an image, so it stays
outside the signed set.

## verify

From the repository root, with b3sum on PATH (Ubuntu 24.04 ships the
package; otherwise `cargo install b3sum --locked`):

    b3sum -c assets/signature-assets.b3sum

Every line prints OK, or the command exits non-zero naming the file
that failed or went missing — treat either verdict as a fake or
corrupted asset and do not ship it.

## extend

When an image under `assets/` is added, replaced, or re-encoded:

1. Regenerate the sidecar over the image set (png, webp, jpg, and any
   future raster format lands here the same way):

       find assets -type f \( -name '*.png' -o -name '*.webp' \
           -o -name '*.jpg' -o -name '*.jpeg' \) | sort | xargs b3sum \
           > assets/signature-assets.b3sum

2. Update the table above in the same commit — the doc and the sidecar
   must never disagree about the signed set.
3. State why the bytes changed in the commit message (new artwork,
   re-export, toolchain bump): a digest that moves without an
   explanation is the duplicate the signed set exists to catch.

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
