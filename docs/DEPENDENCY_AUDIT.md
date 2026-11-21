<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Dependency Audit (NIGHT-hunt-6)

Owner mandate (2026-09-18): strict dependency usage because of supply
chain attack risk. Remove chrono in favor of the Howard Hinnant
civil-from-days clock (cosmostrix reference), then audit every direct
dependency and remove everything that is not strictly necessary.

This document is the standing record of that audit and the policy it
established. It is the first place to update whenever a dependency is
added, removed, trimmed, or accepted-as-risk.

## Headline results

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| Lockfile packages | 81 | 54 | -27 |
| Direct dependencies | 8 (+ 1 dev) | 7 | -2 |
| chrono call sites | 0 | 0 (removed) | supply-chain dead weight eliminated |
| nix compiled features | 6 | 3 | process/fs/signal surface dropped |
| cargo-deny CI coverage | non-eBPF subtree only | full tree (all-features) | aya chain now policy-checked |
| Release binary size | 1,777,928 B | 1,777,912 B | unchanged (unused deps never linked) |

The table is the NIGHT-hunt-6 (2026-09-18) snapshot, kept as recorded;
the current direct set is the re-audit table's verdict with blake3's
arrival folded in (night-depth-cleanup-1): seven across the workspace —
clap, anyhow, blake3, nix, libc at the root, aya behind the `ebpf`
feature, aya-ebpf inside the ebpf crate. The re-audit section's own
"six direct" verdict (2026-09-21) speaks for its date, before blake3
existed in the graph.

The supply-chain surface — crates downloaded, hashed, compiled, and
audited on every build — shrank by one third. Binary size did not move
because dead dependencies were never linked into the binary in the
first place; the risk was in the build pipeline, not the artifact.

## Re-audit (NIGHT-improve-11 / security-4, 2026-09-21)

The owner mandate for the improve-11 pass: audit dependencies again,
make the set peak-lean, remove anything unused even though the set is
already minimal. Verdict: **nothing removable — 7/7 direct dependencies
carry live call sites, the ebpf crate's 1 dependency is the program's
own framework, and every pinned feature is load-bearing.** The audit
itself is the deliverable this time; the standing record below is
updated so the next re-audit starts from fresh evidence, not from the
2026-09-18 snapshot.

| Dependency | Live call sites (grep evidence) | Verdict |
|------------|----------------------------------|---------|
| clap | src/cli/ (derive + 8 ux/suggestion files); the `suggestions` feature provably renders "tip: some similar subcommands exist" (verified live) | keep, features exact |
| anyhow | every module (`Result` + `Context` + `anyhow!`) | keep |
| blake3 | src/info/signature.rs (night-signature-advanced-1): the depth-matrix anchor recompute over the masked provenance layers + the `sig` report's streaming binary self-hash; features std+pure exactly as pinned (the "pure" feature skips every C/asm path in blake3's build.rs — no C toolchain in the graph) | keep, features exact |
| serde | **removed** (night-dragon-maintenance-T1 (S1)): the JSON lane is hand-written in src/json/ — the derive stack (serde, serde_core, serde_derive) left the graph; regressions blocked by the deny.toml ban | removed |
| serde_json | **removed** (S1): src/json/parse.rs (the Value tree, the docker lane's deserializer) + write.rs (the escape law) replace it; wire bytes verified byte-identical against the pre-S1 binary | removed |
| nix | features user/term/feature exactly as pinned (geteuid, termios, uname — update/mod.rs re-verified) | keep, features exact |
| libc | clock_gettime, TIOCGWINSZ, flock, termios constants (format.rs, terminal/, lock.rs) | keep |
| aya (optional) | the whole `ebpf` feature surface | keep |
| zelynic-ebpf: aya-ebpf | both BPF programs compile against it | keep |

Lockfile: untouched by this audit (nothing removed, nothing bumped —
version policy stays owner-only). The deny.toml chrono ban stays the
CI regression guard.

## Expert supply-chain audit (NIGHT-hunt-20, 2026-09-21)

The owner mandate: expert audit for supply-chain attack risk; remove
any dependency whose risk outweighs its gain; the project stays lean,
small, boring and silent. This pass goes beyond call-site liveness
(the improve-11 security-4 scope) into actual attack surface: what
code runs, from whom, with which tokens.

**Crates verdict: six direct dependencies, every one with live call
sites.** S1 (night-dragon-maintenance-T1, 2026-10-28) removed serde
and serde_json — the JSON lane is hand-written in src/json/ (the
zejtron peak-lean law: no crate exists only to move JSON), and the
locked graph dropped from 50 to 44 crates (serde, serde_core,
serde_derive, serde_json, itoa, zmij gone). The remaining six carry
live call sites (independently re-verified by grep this pass:
clap 12 sites, anyhow 42, aya 19, nix 13, libc 14; aya-ebpf in both
ebpf/ programs). `aya` 0.14.0 (the NIGHT-depthtest wave) has an
empty default feature set (its only non-default feature is the
development-only `test-helpers`, unused by zelynic) — there is no
compiled surface left to trim. `anyhow` and
`libc` add zero transitive crates. The set is already at the floor
the 2026-09-18 audit drove it to.

**Advisory state (both lockfiles, 1258 RustSec entries loaded):**

- `cargo audit` 0.22.2: root Cargo.lock (54 crates) and
  ebpf/Cargo.lock (31 crates) both exit 0 — zero vulnerabilities.
- `cargo deny` 0.20.2 `check all`: advisories ok, bans ok, licenses
  ok, sources ok over the full all-features tree.
- Root lockfile reachability verified: 48 crates reachable on Linux;
  the 4 non-reachable entries (anstyle-wincon, once_cell_polyfill,
  windows-link, windows-sys) are Windows-target-gated — resolved in
  the platform-independent lockfile, never downloaded or compiled
  for Linux builds. Not removable, not a Linux surface.

**New documented risk: the aya-build build-time chain (ebpf/).**
`aya-ebpf-bindings`, `aya-ebpf-cty`, and `aya-ebpf` itself declare
`aya-build` as a build-dependency, which pulls a 10-crate
build-time-execution surface (anyhow, cargo_metadata, camino,
cargo-platform, semver, serde + serde_derive + serde_core,
serde_json, which, rustc_version): third-party code that RUNS during
every eBPF compile. This is upstream aya framework design, not a
zelynic choice; it cannot be removed without leaving the framework.
Accepted as risk with three mitigations already in place: the
lockfile is committed (no fresh resolution), CI builds with
`--locked`, and this audit's RustSec scan covers the chain. It is
the surface to watch first when aya releases.

**The real exposure was CI, not Cargo.toml — hardened this pass:**

- Every workflow action is now SHA-pinned (NIGHT-hunt-20): all 13
  `dtolnay/rust-toolchain@stable` references (a mutable branch on a
  personal account, running in the maintenance job that holds a
  `contents: write` token — a compromised tag could have pushed code
  to main; the count grew from 11 to 13 when NIGHT-improve-20 gave
  the musl job its own stable + nightly installs), `Swatinem/rust-cache`,
  `softprops/action-gh-release`, and every
  `actions/checkout|cache|upload-artifact|download-artifact`
  reference. The single exception, documented in codeql.yml:
  `github/codeql-action` stays on its moving v4 tag because pinning
  it would freeze the security scanner itself.
- CI-installed scanner binaries are version-pinned
  (`cargo install cargo-deny --version 0.20.2 --locked`,
  cargo-audit 0.22.2, codespell 2.4.3): the RustSec advisory
  database still refreshes on every run, so a red result always
  means a new advisory, never a new scanner release overnight.
- The weekly `cargo update` auto-commit (maintenance.yml) makes the
  lockfile a living surface; the defense is that the update job
  itself runs the full test + deny + policy matrix before the commit
  job gets its write token — verified still wired that way.

## Finding 1: chrono (removed) — zero call sites, 27 crates of baggage

A repository-wide grep for `chrono::`, `DateTime`, `Utc`, `Local` and
`NaiveDate` across `src/`, `build.rs`, and `test/` returns zero
matches (the only "Local" hit is `LocalFlags` from libc termios).
chrono was declared in `Cargo.toml` with
`default-features = false, features = ["clock"]` and never used once.

The `clock` feature is the expensive part. It exists to provide
`chrono::Local`, which requires timezone lookup on every platform
chrono supports, so its dependency chain fans out per-target:

```text
zelynic -> chrono (UNUSED)
            -> iana-time-zone
                 -> android_system_properties      (Android)
                 -> core-foundation-sys             (Apple)
                 -> iana-time-zone-haiku -> cc      (Haiku, pulls a C
                     -> shlex, find-msvc-tools       compiler driver)
                 -> js-sys -> futures-util
                     -> futures-core, futures-task,
                        pin-project-lite, slab
                 -> wasm-bindgen
                     -> rustversion
                     -> wasm-bindgen-macro
                         -> wasm-bindgen-macro-support
                             -> bumpalo, wasm-bindgen-shared
                 -> windows-core
                     -> windows-implement,
                        windows-interface,
                        windows-result, windows-strings
            -> num-traits -> autocfg
```

Twenty-seven lockfile entries — a WebAssembly binding toolchain, a
Windows API crate family, Apple core-foundation bindings, an Android
properties crate, a futures stack, and a C compiler driver — kept
refreshing on every `cargo update`, every advisory-database scan, and
every `cargo audit` run, for a dependency the binary did not even
link. Removing the single unused edge deleted all of them.

The cosmostrix reference made the same drop earlier ("chrono dropped
(Hinnant-style)" tombstone in its `Cargo.toml`); its `clock` feature
cost "8 transitive crates" for two real call sites. zelynic's case was
stronger: zero call sites.

### The replacement: Howard Hinnant's civil_from_days

zelynic needs wall-clock formatting for exactly one thing — the
`Build-time:` line of the version report (`zelynic -V`), which
cosmostrix stamps and zelynic previously lacked. The stamp is now
computed inside `build.rs` by Howard Hinnant's `civil_from_days`
algorithm (<http://howardhinnant.github.io/date_algorithms.html>),
ported from cosmostrix `build.rs`:

- `build.rs::format_unix_secs_as_build_time()` — pure i64 arithmetic,
  proleptic Gregorian, leap-year correct, UTC only. Emits
  `YYYY-MM-DD HH:MMZ` (ISO 8601) via `cargo:rustc-env=ZELYNIC_BUILD_TIME`.
- `src/info/mod.rs::build_time()` — reads the compile-time stamp,
  degrades to `unknown` on an unreadable host clock.

No time crate, no timezone database, no `[build-dependencies]`, std
only. UTC-only is deliberate (cosmostrix LTS rationale): no DST
transitions, no tzdata drift, identical output across build hosts.

## Finding 2: cosmostrix reference carried latent wrong test constants

Running the ported build.rs test suite standalone
(`rustc --edition 2021 --test build.rs`) exposed that the cosmostrix
reference `build_time_format_matches_known_unix_epochs` test contains
two wrong epoch constants:

- `1_709_210_440` is asserted to render `2/29/2024 12:34 (UTC)` but
  is actually 2024-02-29 **12:40:40** UTC (verified via
  `date -u -d @1709210440`). The correct constant for 12:34:00 is
  `1_709_210_040`.
- `1_787_930_200` is asserted to render `8/4/2026 15:30 (UTC)` but
  is actually 2026-08-**28** 15:16:40 UTC. The correct constant is
  `1_785_857_400`.

The bugs were invisible because `cargo test` never executes
`#[cfg(test)]` code inside build scripts — the suite only runs when
compiled standalone. zelynic's port uses date-verified constants and
adds a truncation case; the standalone `rustc --test build.rs`
invocation is documented in the test header as the way to actually
run it. (cosmostrix should apply the same two-constant fix upstream.)

## Finding 3: the cargo-deny graph skipped the entire eBPF subtree

`deny.toml` was the untouched cargo-deny template. Its `[graph]`
section left `all-features = false` with no feature list, while
zelynic's default feature set is empty — so `cargo deny check all`
in CI only ever resolved the non-eBPF subtree. The aya chain (aya,
aya-obj, object, and everything beneath them) sat outside every
advisories/licenses/bans/sources check while being the largest and
most security-relevant part of the graph.

Fixed: `[graph] all-features = true`. Verified locally with
cargo-deny 0.20.2 — `advisories ok, bans ok, licenses ok, sources ok`
over the full tree.

Toolchain note: cargo-deny 0.18.2 cannot parse the current RustSec
advisory database (CVSS 4.0 entries) and its config parser rejects
`"AGPL-3.0-only"` in the license allow list. CI installs the latest
release, which handles both; the license list keeps the exact SPDX
form. If a local run hits the CVSS parse error, update cargo-deny.

## Finding 4: nix compiled three unused feature modules

`nix` was enabled with `["process", "fs", "feature", "user", "signal",
"term"]`. The source uses exactly three APIs:

| API | Call sites | Feature |
|-----|-----------|---------|
| `nix::unistd::geteuid()` | `capabilities/mod.rs`, `commands/mod.rs` | `user` (implies `feature`) |
| `nix::sys::utsname::uname()` | `src/ebpf/bpf_syscall.rs` (kernel >= 5.7 check) | `feature` |
| `nix::sys::termios` (raw mode) | `terminal/mod.rs` (alt screen guard) | `term` |

`process` (fork/exec/wait), `fs` (stat/at), and `signal` (kill) had
zero call sites — their modules were compiled into every build for
nothing. The feature list is now `["user", "term", "feature"]` with
the justification table mirrored in `Cargo.toml`.

Why keep nix at all: the three call sites would otherwise become
hand-written `unsafe` libc FFI (geteuid/uname/tcgetattr/tcsetattr).
nix adds no new transitive crates at this feature set (libc, bitflags
and cfg_aliases are already in the tree via aya), so the cost of the
safe wrapper is zero crates and the benefit is four fewer unsafe
blocks. Keeping it is the lower-risk option.

## The audited dependency table (post-NIGHT-hunt-6)

| Dependency | Verdict | Justification (live call sites) |
|-----------|---------|--------------------------------|
| `clap` 4 | keep | CLI parser; explicit feature set (std, color, help, usage, error-context, derive, suggestions) pinned so no default-feature creep |
| `anyhow` 1 | keep | error handling backbone, 20+ files |
| `serde` 1 + derive | **removed (S1)** | the JSON lane is hand-written in src/json/; the derive stack (serde, serde_core, serde_derive) left the graph; deny.toml bans re-adding it — widened X1 across all four serde-family names |
| `serde_json` 1 | **removed (S1)** | src/json/parse.rs (Value tree, docker-lane deserializer, 128-frame depth cap) + write.rs (escape law) replace it; doctor/list-apps wire bytes verified byte-identical |
| `nix` 0.31 | keep, trimmed | safe geteuid/uname/termios wrappers; features `user`+`term`+`feature` only |
| `libc` 0.2 | keep | flock (src/ebpf/lock.rs), raw BPF syscalls (src/ebpf/bpf_syscall.rs), termios constants |
| `aya` 0.16 (optional) | keep | the entire point of the project; gated behind the `ebpf` feature; NIGHT-depthtest rode the 0.14 wave, night-enhance-1 rode the 0.16 wave (the 2026-10-27/28 pair), the kernel half completed the pairing the same day (aya-ebpf 0.3.0, below) |
| `aya-ebpf` 0.3 (ebpf/ crate) | keep | both BPF programs compile against it; night-enhance-1's kernel half (2026-11-12) rode the same upstream wave — 0.2.1 at the port, 0.3.0 since; the satellite family rides upstream's own requirements (bindings 0.3.0, cty 0.4.0, macros 0.4.0) and `syn` + `proc-macro2-diagnostics` + `version_check` LEFT the ebpf lockfile (31 -> 28 crates) |
| `aya-obj` 0.6 (dev) | keep | test-tree parse lane (NIGHT-dinner-6 E1 rider): parse-only BPF ELF reader for the embedded-object pins — the exact parser crate compiled into aya 0.16.0, already in the locked graph as aya's own dependency, zero binary surface |
| `chrono` 0.4 | **removed** | zero call sites; 27-crate transitive chain (Finding 1) |
| `[dev-dependencies] serde` | **removed** | exact duplicate of the regular dependency entry; tests already see regular deps |

## Enforcement (how this stays true)

1. `deny.toml [bans]` denies `chrono` — re-adding it fails
   `cargo deny check all` in CI (the check job's `build.sh check-all`
   gate runs the deny step; NIGHT-boost-7 folded the hand-rolled
   steps into the script) and the weekly `audit.yml` observation run.
2. `deny.toml [graph] all-features = true` keeps the aya subtree
   inside every policy check (Finding 3).
3. `Cargo.toml` carries the dependency contract comment: every direct
   dependency must have a live call-site justification recorded in
   this file, feature lists must be trimmed to the modules used, and
   zero-call-site deps get removed.
4. CONTRIBUTING.md Coding Standard 8 requires updating this document
   with any dependency change, the same way LICENSE headers are not
   optional.
5. The serde/serde_json bans are LIVE-FIRE VERIFIED
   (night-verdict-closure-T8 (B2), 2026-10-29): the verdict's audit
   flagged that the ban had never been proven to fire. Proof, on a
   clean depth-1 clone at the S5 head: `cargo add --dev serde`
   (resolving serde 1.0.229 into the dev graph) makes
   `cargo deny check bans` fail with `error[banned]: crate
   'serde = 1.0.229' is explicitly banned`, quoting the deny.toml
   reason string; reverting the working tree restores `bans ok`. A
   prior `cargo deny` FETCH_HEAD timestamp failure on the owner's
   seat reproduced ZERO times here and traces to a damaged or
   .git-less workspace (cargo-deny probes git metadata; a healthy
   clone — even shallow — passes).
6. The X1 pass (night-dragon-maintenance-X1, 2026-11-02) widened the
   serde ban across the full derive stack: `serde_core` and
   `serde_derive` are banned names too. The S1 list pinned only the
   two facade names, leaving the derive crates a legal
   direct-dependency path around the gate; both ship only inside the
   serde monorepo, so the widened ban cannot collide with a
   legitimate third-party use. The root lockfile re-verified
   serde-family-free this pass (zero serde, serde_json, serde_core,
   serde_derive entries), and the ebpf/ nested crate's build-time
   aya-build chain stays outside the root `cargo deny check all`
   scan (accepted risk, documented above).

## Accepted risks (tracked, warn-level)

- Both historical duplicates RESOLVED (re-verified live by the X1
  pass, 2026-11-02, against the committed lockfile): `hashbrown` is
  now a single 0.17.1 entry (was 0.15.5 + 0.17.1 via the aya-obj /
  indexmap / object mix) and `syn` is a single entry shared by
  `clap_derive` and `thiserror-impl` 2.0.21 (was 2.x + 3.x while
  `serde_derive` still rode the graph — S1 removed that consumer).
  The warn-level `multiple-versions` policy stays as the tripwire;
  nothing to fork or patch.
- Neither entry involves a crate with an open RustSec advisory
  (`cargo deny check advisories` passes clean over the full tree).

## The proofs package (night-frontier-Z6, 2026-11-16)

night-frontier-Z6 (D1, the proven datapath) landed `proofs/` — a
detached nested package, the ebpf crate's own detachment shape —
holding the two verification instruments the proof layer rides. The
root manifest's dependency graph is untouched: no root entry moved,
the root lockfile gained nothing, and no proof dependency reaches any
shipped binary.

| Crate | Package | Verdict | Justification |
|-------|---------|---------|---------------|
| `proptest` 1 (dev) | proofs/ only | keep | the property-exhaustion instrument: 4096 shrinkable cases per law per run over the #[path]-included ebpf/src law files (the fuzz harnesses' include law). Dev-only, publish = false, never a binary input |
| `kani-verifier` 0.68.0 | proofs/ CI lane, no manifest entry | keep, pinned | the for-all tier's toolchain: cargo kani ships the harness support crate from its own sysroot, so nothing lands in any Cargo.toml. Pinned by version in .github/workflows/proofs.yml and proofs-night.yml, and by the toolchain cache key |
| `loom` 0.7 | **censused, NOT adopted** | signed NO | the interleaving checker has no location-backed atomics (no `AtomicU64::from_ptr` in 0.7.3 — verified against the build), and the datapath's CAS discipline is pointer-cast over raw map-value memory by design (math.rs's access primitives, the BPF ISA lesson). Expressing the protocol would mean restructuring the core-only law files for a test instrument; a harness-side reimplementation would be a model, not a proof of the kernel bytes. Reopens the day loom ships from_ptr semantics |

Scope notes, stated honestly:

- The proofs package sits OUTSIDE the root `cargo deny check all`
  scan (detached package, no workspace edge). Its two crates are
  dev-tooling only — `publish = false`, zero binary surface — and the
  lane pins both instruments by version; the supply-chain posture is
  the fuzz/ crate's own (the same detached-package shape, the same
  dev-only rule).
- The proptest regression store
  (proofs/proptest-regressions/) is committed per proptest's own
  convention: the Z6 instrument's first real catch (the fraction
  sanitize-on-read law's counterexample, shrunk to
  rate=0/burst=0/frac=NS_PER_SEC) replays before any novel case — the
  witness that sharpened the property to the exact documented law.

## Supply-chain incident response (2026-08-20 arrayref advisory, audited 2026-11-17, night-supply-1)

The Rust security response advisory (2026-08-20): a compromised
crates.io account published six malicious crates (`proc-macro1`,
`proc-macro-en`, `aovine`, `arone`, `aronenao`, `tinymember` — build
scripts that download a payload, any version malicious) and slipped
malicious republishes past three otherwise-benign crates the account
owns — `arrayref@0.3.10` (86 minutes online before deletion),
`internment@0.8.7` (90), `append-only-vec@0.1.9` (107). crates.io
deleted the versions, unyanked the good ones, and locked the account;
the crate author is a victim, not an actor.

Verdict for this estate: **unaffected, proven.** The evidence:

| Surface | Method | Result |
|---------|--------|--------|
| All four committed lockfiles (root, `proofs/`, `fuzz/`, `ebpf/`) | name + version grep over every `[[package]]` entry | zero hits across all nine names |
| The whole tree | grep over every `.toml`, `.rs`, `.md`, `.yml` | zero references, no vendored copy anywhere |
| This host's registry cache | the advisory's own `find(1)` command over `~/.cargo/registry/cache` | zero hits |

A transitive edge would have had to appear in a committed lockfile;
none did. The lean set (six at the root, seven across the workspace
with the ebpf crate's aya-ebpf — the audit table above) has no path
to any affected crate.

Tripwires added so a future pull-in fails loudly instead of
compiling a payload's build script:

- `deny.toml` `[bans]`: all nine ban at the name level. The six
  malicious names were minted malicious and never resolve
  legitimately; the three benign crates ban whole-name because the
  pinned cargo-deny 0.20.2 bans schema carries no version scope
  (crate/reason/wrappers only — a `version` key fails the config
  deserializer, caught live by `cargo deny check` before the commit),
  and the add-a-dependency policy makes any future need a documented
  justification that revisits the list first. Enforced by the ci.yml
  build.sh check-all lane (every push) and the weekly Dragon Guard
  audit.
- `.github/workflows/audit.yml`: the advisory scan widens from the
  root workspace to **all four lockfiles** (`cargo audit --file`
  for `proofs/`, `fuzz/`, `ebpf/`). The detachments that keep the
  sibling graphs out of the root deny check had also kept their
  lockfiles outside every advisory-DB scan; this incident is what
  closed that gap. The deny-graph half (licenses/bans over the
  detached trees) stays as the X1/Z6 scope notes above record it.

Re-audit cadence: the grep battery above re-runs as the first step
of any future dependency-incident response; the Monday clock
(10:07 WIB, 03:07 UTC) re-scans the advisory DB against all four
lockfiles standing.

## night-supply-2: the re-resolution vector closes (2026-11-19)

The night-supply-1 response banned the incident's nine crates and
widened the advisory scan to every lockfile — name-level tripwires
against the payload that shipped. night-supply-2 tightens the MECHANISM
the incident rode, not just its names: a compromised republish only
bites a graph that re-resolves against the index, so the estate stops
re-resolving silently and reviews the delta before it merges. Three
moves, verified against the cargo-deny schema before landing (the
schema moved severity out of `[advisories]` — a `vulnerability` key
now fails the deserializer, and the `unmaintained` / `unsound` keys
take a scan scope, not a level):

- `deny.toml` `[advisories]`: `yanked = "deny"` (the implicit default
  was warn — every deleted payload version is a yanked version, and a
  re-resolution that accepts yanked crates can pull the payload back),
  `unmaintained = "all"` and `unsound = "all"` spelled out explicitly
  so a cargo-deny default change can never silently loosen the policy.
  Vulnerability advisories need no key: they always emit errors.
- `deny.toml` `[bans]`: `wildcards = "allow"` became `"deny"`. A
  wildcard version requirement forces re-resolution on every build
  even with a committed lockfile — the exact window a malicious
  republish lands inside. The root workspace carries none today
  (verified across every manifest in the graph); from now on one
  cannot enter without failing the gate.
- `.github/workflows/ci.yml`: the `dependency-review` job, PR-only.
  The audit lane scans the resolved lockfiles AFTER merge; this job
  reviews the delta BEFORE it — every newly proposed crate named at
  review time with its vulnerability and license findings. The action
  is SHA-pinned per the NIGHT-hunt-20 estate rule.

Together with night-supply-1 the chain is: name tripwires (the nine
bans), post-merge DB scans (all four lockfiles, weekly and per-push),
pre-merge delta review (every PR), and re-resolution defenses (yanked
deny, wildcards deny). A repeat of the 2026-08-20 incident class now
has to cross four independent gates, not one.

## Policy for adding dependencies

Default answer is no. When a feature genuinely needs a new crate:

1. Prefer std, then libc, then an in-house algorithm (the Hinnant
   clock is the template) before any new dependency.
2. Justify the crate in this document: exact call sites, transitive
   footprint (`cargo tree -i <crate>`), license, maintenance status.
3. Pin `default-features = false` plus an explicit feature list
   mirroring the nix precedent, so accidental feature creep fails
   review.
4. Run `cargo deny check all` and `cargo audit` locally before the
   commit; CI re-runs both.

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
