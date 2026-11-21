<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# night-signature-advanced-1 — the masked provenance depth matrix: the identity leaves the artifact, the seal stays

Date: 2026-11-13. The owner's mandate, in shape: "master hardening,
for depth matrix signature" — an embedded depth signature built by
"rezky_nightky (oxyzenQ) 2026" on the `-V/--version` surface and a
depth report subcommand, aimed at theft, hacked binaries, and fake
rebrands. Then the owner's own research verdict on the old
night-signature-1 draft (the owner's verdict, translated from the
session's own words): pointless — writing the claim plainly in this
project means any malicious actor with grep or rg finds the wording
instantly and strips it. A plaintext identity in the binary hands the
thief the mark on a plate. The hardening: embed the claim as opaque
masked words, materialize it only at runtime, seal it with blake3,
and render the four-depth verification matrix — the cosmostrix
shape, the owner's cross-tool contract ("see cosmostrix reference
for consistency"), subcommand only (`zelynic sig`), no `--sig`
spelling.

## The night-signature-1 gap, named and closed

The tree carried FOUR plaintext identity seats in the artifact, and
the probe found every one:

1. The `Signature:` line literals (`SIGNATURE_LINE` /
   `SIGNATURE_DORMANT_LINE`, src/info/mod.rs) — the manifest the
   release pipeline itself grepped, which is how deep the plaintext
   went: the verification probe was built on top of the vulnerability.
2. The `COPYRIGHT` const — the authors string beside the License line.
3. The clap `author = "rezky_nightky (oxyzenQ)"` attribute
   (src/cli/root.rs) — a FIND beyond the owner's ask: a dead-weight
   attribute (the command disables clap's version flag and the custom
   `-V` owns identity, so nothing ever rendered the author string),
   but its bytes rode in `.rodata` all the same. Found by running the
   strings probe over the rebuilt flagship binary before committing —
   the hunt-more-than-the-owner-found rule, applied to the owner's own
   feature.
4. The engraving footer `"v<version> (<commit>) by oxyzenQ"`
   (src/output/mod.rs) — the status stamp and the eagle-eyes
   engraving, rendered on every frame, greppable in every artifact.

The post-fix probe on the rebuilt flagship: `strings | grep
rezky_nightky` returns ZERO hits; `oxyzenQ` survives only in the
public repository URLs (the `Source:` line and the update-check API
endpoints — pointers, not claims). The generic "Official Build by "
marker stays plaintext by design, cosmostrix's own rationale: it
carries no identity, and its bytes are sealed inside the masked
manifests' fingerprints.

## The scheme

Three masked layers, splitmix64 XOR masks keyed by per-layer seeds,
chunked little-endian u64 words — at rest, opaque integers (the
generator's invisibility assertion pins the longest printable run
across all masked words at 3, below strings(1)'s four-byte floor):

- D0: the full-life manifest ("Pure eBPF builtin — Official Build by
  rezky_nightky (oxyzenQ)" — 63 UTF-8 bytes today; the audit-date
  truths still carried a trailing " 2026" year slot, removed by
  night-ux-orion-3, see the amendment below) and the dormant manifest
  ("eBPF dormant — ...", 58 bytes today) — TWO manifests because the
  claims discipline (QA.md) is real: a dormant build must not claim
  objects it does not carry, and the anchor seals both lanes so a
  patched claim breaks on either.
- D1: the authors string ("rezky_nightky (oxyzenQ)").
- D2: the FNV-1a 64-bit fingerprints, const-evaluated at compile time
  directly from the masked words — the plaintext never exists as a
  literal anywhere in the module, not even in const context.
- D3: the blake3 anchor over the framed clear payload of all three
  layers (domain tag `zelynic/depth-matrix/v1`, length-prefixed
  layers) — embedded as an opaque `[u8; 32]`, recomputed at runtime
  through the blake3 crate.

The load-bearing invariants, carried from the cosmostrix lineage and
re-proven here: the single-pass materialization (one unmask per layer
feeds the display, the runtime fold, AND the anchor recompute —
whatever bytes the report shows are exactly the bytes the integrity
verifies; the night-signature-1 draft had the two-pass hole, found by
patching real binaries); the black_box barrier (the unmask reads the
artifact's real bytes — LLVM cannot fold a patched constant back into
a green verdict); the identity binding (the active manifest's identity
core must prefix the authors string — incoherent single-layer rebrands
fail).

## The surfaces

- `-V/--version`: the lane-honest Signature line materializes, the
  Depth-matrix line follows it (`fp=<fingerprint> status=verified
  anchor=b3:<blake3> layers=d0:masked-words,d1:masked-words,
  d2:dual-fingerprint,d3:blake3-anchor`) in the estate's status green
  — the one body line the owner's mark painted (the purple banner
  tier stays the `sig` surface's), and the estate-parity body law is
  amended, mechanically pinned: only the Depth-matrix line may carry
  ANSI escapes.
- `zelynic sig` (subcommand only): the four-depth verification ladder
  — D0 runtime-identity, D1 embedded-marker, D2 anchor-integrity, D3
  binary-self-hash — under the purple banner (the owner's mark:
  branding purple, the engraving tier), then the identity block
  (identity, fingerprint fnv1a64 dual-layer, anchor, commit,
  build-time), then the verdict line and the honest self-hash note.
  The self-hash CANNOT embed its own digest (the chicken-and-egg law
  of hashing) — it is the fingerprint to compare against a published
  release hash, and the report says exactly that. Exit 1 on any
  failed depth, so scripts gate on the verdict.

## The verification, all run live

- 1086 unit + 72 integration tests green, clippy `-D warnings` clean;
  the oracle suite pins materialization, strings-invisibility,
  const-vs-generator cross-checks, framing exactness (201 bytes,
  every offset), tamper simulations, binding, and both surfaces'
  shapes.
- The end-to-end tamper probes on the BUILT binary: one flipped byte
  in any masked word flips the Depth-matrix line to
  `status=tampered`; one flipped anchor byte fails D2 (TAMPERED,
  3/4); `zelynic sig` exits 1 on every tampered shape. The pristine
  build reports AUTHENTIC (4/4).
- The release contract inverted (night-signature-advanced-1): the v4
  legs' old positive grep — the Signature plaintext the pipeline
  verified — is replaced by the NEGATIVE probe: a positive identity
  grep over the shipped artifact FAILS the leg, because a plaintext
  seat returning means the masking regressed. The anti-theft property
  is now machine-enforced on every release run. The License literal
  keeps its NIGHT-blade-4 contiguous-byte contract (it claims no
  identity).

## Honest limits

This is provenance marking and tamper evidence, not DRM. It does not
resist memory forensics: once `-V` materializes the plaintext, the
string lives in process memory. It does not stop a determined
attacker who fully understands the module — they can regenerate the
masked words, the fingerprints, and the anchor (the generator and its
truth strings are the committed truth source, carrying the identity
in plaintext by design, exactly like NOTICE and TRADEMARK.md). The
defense targets the lazy grep-and-strip rebrand — the owner's stated
threat — and it closes it: there is nothing greppable to find, and a
rebrand that rewrites the visible branding still ships constants it
does not recognize, materializing the original owner. The legal layer
(NOTICE, TRADEMARK.md, AGPL) is the backstop.

## Amendment — night-ux-orion-3 (the manifests go yearless)

2026-11-21. The owner ruled the trailing year in the materialized
Signature line a wrong format (a year belongs at the front of the
copyright line, never dangling after the identity) and ordered it
removed from every output surface. The rotation ran through the
generator, per its own law (edit the truths, re-run, paste — never
hand-edit the words): the truths dropped the " 2026" suffix, the
masked words regenerated (one tail word changed per manifest), the
fingerprints and the blake3 anchor recomputed over the new clear
bytes. The full-life manifest is now 63 bytes (fp 247d2835ac8bde6a,
8 words), the dormant 58 bytes (fp d8bb2b18d03d2a40, 8 words); the
authors layer is untouched (43 bytes, fp 66771e5f273b9cae). The new
anchor is b3:acf8e138aae172fb2974448eb34fa19fce29909d5755b2c2dca2a611e862e657.
Consequence, honest: zelynic's manifest fingerprint no longer matches
zylaxion's (the sibling still carries the year) until that estate
rotates to the same yearless shape — the pre-amendment note above
about byte-identity with the sibling describes the audit-date state.
The strings-invisibility contract held through the rotation (the
generator's longest-printable-run assertion stayed at 3).

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
