<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# signature assets

BLAKE3 signature checksums for every image under `assets/` and for
the D5 GPG trust anchors under `assets/gpg/` — the authenticity
record for LTS usage. A logo that does not reproduce its digest here
is a fake, a duplicate, or a silent re-encode, and none of those
ships: the digests are the one command any release, mirror, or fork
page can run before trusting an image file. The same run also pins
the maintainer key itself: a swapped or re-keyed
`maintainer-47A50AEF4B65AAC2.asc` fails by name before it can vouch
for anything.

The image digests were computed with `b3sum` 1.8.7 (the BLAKE3 reference
tool — the same digest family gate 18's prebuilt-parity check pins)
over the tracked bytes at night-dragon-maintenance-X1 time, 2026-11-02;
the two `assets/gpg/` anchors joined the signed set on 2026-11-23 as
the night-solid-defense-2 follow-up, same tool, same tracked-bytes
rule. The machine-readable sidecar is
[signature.b3sum](signature.b3sum), kept in `b3sum -c`
format so the check below is the whole protocol.

## signed set

| file | bytes | blake3 digest (b3sum) |
|------|------:|-----------------------|
| assets/eagle-eyes-depth.png | 113,395 | `5f1f2a834ebfd65dbe8e8900180930ca8b23358c90cba8bbdaacdef01c708c81` |
| assets/eagle-eyes.png | 106,092 | `4f0859d19ffbf5ca60f591a269f79c4038f9b2a59735ec4f91872ce89e038efa` |
| assets/gpg/maintainer-47A50AEF4B65AAC2.asc | 4,918 | `639b5d94603e14fa9022cad8e26efff7711bdaedd92f08723ffa96c0b2d90d77` |
| assets/gpg/pinned-maintainer-fpr.txt | 40 | `dc6108d809afdbbb41756c37ef3ce3eec4b674ed1c8c225678c0103c1e4cfa3b` |
| assets/qr/bitcoin.png | 575 | `09ec09fcdc4815e23373cb266bb120aa4e1af140fb9d598e117d05478a791b47` |
| assets/qr/ethereum.png | 591 | `4eb520de0fe258d2c82ba07ccba8d9e48bafc63904d022a83cc42b59d1ed2ac7` |
| assets/qr/solana.png | 595 | `bca56b0a454daf06ff2d57fe401719553e28733e73479de2652a0740a9e87d1a` |
| assets/zelynic-original-logo-2026.png | 1,356,237 | `c2021213610e6beb4bc73385aa7f54f2be51a48a56fee7844225b933eb3042ab` |

`assets/tools.md` and this file are documentation, not artifacts, so
they stay outside the signed set — and the sidecar can never cover
itself. The two `assets/gpg/` files are the deliberate exception:
not images, but trust anchors (`build/gpg.rs` imports the key and
`sig_commit_sig.rs` reads the pinned fingerprint through
`include_str!`), so their bytes belong in the record. One caveat
travels with the key: re-exporting the maintainer key with a new UID
or a pushed-out expiry changes the armored bytes and moves the
`.asc` digest — a legitimate change, but the commit message must say
so, same as a re-encoded logo.

## verify

From the repository root, with b3sum on PATH (Ubuntu 24.04 ships the
package; otherwise `cargo install b3sum --locked`):

    b3sum -c assets/signature.b3sum

Every line prints OK, or the command exits non-zero naming the file
that failed or went missing — treat either verdict as a fake or
corrupted asset and do not ship it.

## extend

When a file joins or leaves the signed set (new image, re-encode,
key re-export):

1. Regenerate the sidecar over the signed set (png, webp, jpg, and
   any future raster format lands here the same way; everything
   under `assets/gpg/` rides along as trust anchors):

       find assets -type f \( \( -name '*.png' -o -name '*.webp' \
           -o -name '*.jpg' -o -name '*.jpeg' \) \
           -o -path 'assets/gpg/*' \) | sort | xargs b3sum \
           > assets/signature.b3sum

2. Update the table above in the same commit — the doc and the sidecar
   must never disagree about the signed set.
3. State why the bytes changed in the commit message (new artwork,
   re-export, toolchain bump, key refresh): a digest that moves
   without an explanation is the duplicate the signed set exists to
   catch.

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
