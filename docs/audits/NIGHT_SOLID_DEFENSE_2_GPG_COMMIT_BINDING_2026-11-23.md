<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# night-solid-defense-2 — the claimed commit becomes a bound commit: D5 commit-signature

Date: 2026-11-23. Session scope: the owner's adversarial review
(the "D3 only as strong as its publication channel" finding) named
the one remaining hole in the depth matrix — the `sig` report CARRIES
a commit sha but nothing BINDS it: a binary swapped on the release
channel replays its own claims (self-hash included, which cannot
embed its own digest by construction) and the ladder had no row that
could disagree. The owner's verdict was one improvement, nothing
else: add Signed Git Tag / Signed Commit (GPG) verification to the
sig command. This session ships exactly that as the ladder's sixth
depth, D5 commit-signature, and verifies it complete — real
signatures, real verdicts, no gimmick.

Session context, first half: the musl "+3" from CI run #1550
(commit d90d0d7, `bench_floor::steady_state_frame_composition_
allocates_zero`, quietest of 32 windows = 3 on a loaded runner) was
diagnosed and closed by night-frontier-Z13-12's bounded walk
(commit 9a8a1a9) BEFORE this session started; this session's job was
the honest re-verification, and it is on the record below: the solo
musl run reads `quietest of 7 walked frames = 0 (floor 0)` and the
full parallel battery on the same target reads 1175 passed / 0
failed — the "+3" was parallel contamination of the global counting
allocator, never a cross-allocator regression, and CI #1551
(Musl Static Twin, ubuntu-26.04) is green on the fix.

## The hole, precisely

D0-D2 prove the ownership claim (masked layers, blake3 anchor), D3
fingerprints the whole image (a fingerprint TO COMPARE, honestly
documented), D4 seals the embedded kernel objects against build-time
digest stamps. But the report's `commit` line — the sha the binary
CLAIMS to be built from — was display text. The attack the owner's
review named: compromise the release channel (or the GitHub account),
swap the binary, recompute whatever sums the page carries; the
binary's own ladder cannot contradict its own claims. The missing
link is the one channel artifact a swapper cannot forge: a GPG
signature by the maintainer's key over the very commit the binary
claims. The maintainer identity already exists — the release
archives carry detached GPG signatures, the key
`F5324E0967F104D58CE025F347A50AEF4B65AAC2` (ed25519, long id
`47A50AEF4B65AAC2`, UID `oxyzenQ@proton.me`) sits on
keyserver.ubuntu.com, keys.openpgp.org, and the GitHub account —
only the COMMITS and the LADDER were not connected to it.

## The design: one stamp, two halves, one pin

- **The pin, single-sourced**: `assets/gpg/pinned-maintainer-fpr.txt`
  carries the 40-hex primary fingerprint (no trailing newline — the
  include IS the value); `assets/gpg/maintainer-47A50AEF4B65AAC2.asc`
  carries the armored public key, exported from the keyserver and
  re-imported into a sterile keyring as the acceptance check. Both
  sides read the SAME fingerprint file through `include_str!` —
  build/gpg.rs (the verifier) and src/commands/sig_commit_sig.rs
  (the reporter) cannot drift apart.
- **The build half** (`build/gpg.rs`, std-only, the vcs.rs spawn
  precedent): `git cat-file commit HEAD` answers the unsigned case
  without gpg at all (a `gpgsig` header is present or it is not);
  a present signature is verified by `git verify-commit --raw HEAD`
  inside an ISOLATED throwaway GNUPGHOME holding ONLY the pinned
  key — never the building user's keyring, which could vouch for
  anyone. The stamp grammar is `<state>[:<evidence-hex>]`:
  `verified:<primary-fpr>` / `wrong-key:<fpr>` / `no-key[:<fpr>]`
  (gpg NO_PUBKEY — the signature a swapped binary actually carries)
  / `bad-signature` / `unsigned` / `no-vcs` (registry tarball
  builds) / `unavailable` (git/gpg absent). Fail-closed is the law:
  a build that cannot state a verdict states the degraded state,
  never a silent pass (the D4 missing-stamp precedent).
- **The runtime half** (`src/commands/sig_commit_sig.rs`, pure over
  the stamp): only `verified:<pinned-fpr>` passes; every other state
  FAILS by name — the row names the commit, the foreign key when
  the evidence carries one, and the honest reason for every
  degraded state. The sig ladder's verdict line now reads x/6.

The out-of-band twin, documented in docs/VERIFY_RELEASE.md: the
consumer imports the maintainer key, verifies the SIGNED TAG the
release was cut from (`git tag -v`), the tag names the commit, and
D5 proves the binary was built from a commit signed by that same
key. Key → tag → commit → binary: the swap must break the tag
signature or the D5 binding — one of the two must give.

## The probe: gpg's status grammar, recorded live, not recalled

A throwaway-key probe (all under /tmp, never the maintainer key)
captured the three verdict-relevant shapes from `git verify-commit
--raw` on gpg 2.4.7 / git 2.56:

- verified (exit 0): `GOODSIG <keyid> <uid>` then `VALIDSIG
  <signer-fpr> <date> <ts> 0 4 0 22 10 00 <primary-fpr>` — the
  primary fpr rides the LAST field; a subkey signature carries the
  subkey in field one and the primary at the tail.
- foreign signer (exit 1): `ERRSIG <keyid> 22 10 00 <ts> 9
  <full-fpr>` then `NO_PUBKEY <keyid>` — the full foreign fpr is
  recoverable from ERRSIG's tail, so the no-key verdict can name it.
- unsigned: exit 1 with ZERO status lines (and no `gpgsig` header in
  the commit object — the short-circuit the build half takes).

Two engineering finds the probe and rig paid for, on the record:

1. **git's gpg child inherits the environment**: signing (and only
   signing) must run with GNUPGHOME on the signing key's homedir;
   without it gpg answers the keyring in ~/.gnupg and the sign dies
   "No secret key" naming a key that exists — the rig's branch 2
   tripped exactly this and the fix (env-scoped signing) is in the
   rig for the next verifier.
2. **The parser bug the rig caught**: gpg 2.4.7's VALIDSIG carries
   an extra field between sig-class and the primary fpr ("00" in the
   captured shape); an index-based read of the primary picked up the
   bare "00" and branch 3 read `verified:00` — a verdict that looked
   right and pinned nothing. The fix reads the primary by SHAPE (the
   last 40-hex token), version-fragile indexes gone. This is why the
   rig exists: the unit tests pin the policy, the rig drives the
   real gpg.

## Verification ledger

All numbers from this session's runs, nothing quoted from memory:

- The pinned assets: the .asc imports into a sterile keyring
  resolving exactly `F5324E0967F104D58CE025F347A50AEF4B65AAC2`;
  the fpr file is byte-exact 40 hex, and the pinned-tail test pins
  the long id the docs publish.
- Unit battery (default features, bin target): **1182 passed, 0
  failed** (1 ignored) — up from 1175 with the seven new D5 policy
  tests (pinned pass, foreign verified FAIL, wrong-key FAIL naming
  both keys, no-key with/without evidence, unsigned, the degraded
  states, and the pin-shape law).
- Integration battery: **74 passed, 0 failed** (3 ignored).
- Clippy `--all-targets --all-features -D warnings`: clean.
- The musl re-verification (session context above): solo
  `quietest of 7 = 0`, full parallel battery 1175/0 on
  x86_64-unknown-linux-musl.
- **The live rig** (`scripts/labs-exp/verify-gpg-commit-binding.sh`,
  runnable by anyone): a scratch copy of the tree, a throwaway
  ed25519 key, three HEAD states, three real builds, three real
  `zelynic sig` verdicts through the actual build.rs → stamp →
  ladder path:
  - branch 1, unsigned HEAD → `D5 commit-signature FAIL — commit
    carries NO GPG signature`, verdict TAMPERED 5/6;
  - branch 2, foreign-signed HEAD (the MITM shape) → `FAIL —
    carries a signature the pinned maintainer key does not cover
    (signed by <throwaway-fpr>) — not the maintainer's signature`,
    TAMPERED 5/6;
  - branch 3, the pinned pair swapped for the throwaway key IN THE
    SCRATCH COPY (the same mechanism, a stand-in identity, clearly
    labeled) → `pass — carries a GPG signature by the pinned
    maintainer key`, **SIGNATURE: AUTHENTIC (6/6 depths verified)**.
- CI at session start (the fix commit 9a8a1a9): 13/13 workflow
  runs green, Musl Static Twin green at job level — the tree this
  change lands on was itself verified first.

## What the owner holds after this (the honest boundary)

The ladder is complete the moment the owner signs: `git config
user.signingkey F5324E0967F104D58CE025F347A50AEF4B65AAC2` +
`git commit -S` makes every future HEAD read `verified:` on D5, and
cutting releases from signed tags (`git tag -s`) closes the
consumer's chain end to end. Until then, D5 does its job by FAILING
on an unsigned main — that is not a broken row, it is the row
telling the truth; the release chain is incomplete until commits
and tags carry the key, and the depth that cannot lie is the one
that says so. The row's remaining honest limit, stated plainly: the
stamp is the BUILD's verdict over the commit it saw — the consumer
still binds it to the key out-of-band (the tag verification), the
same way D3's fingerprint binds to the published hash. One row, one
truth, no channel left silently unwitnessed.

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
