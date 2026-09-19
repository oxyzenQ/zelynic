<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

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

The supply-chain surface — crates downloaded, hashed, compiled, and
audited on every build — shrank by one third. Binary size did not move
because dead dependencies were never linked into the binary in the
first place; the risk was in the build pipeline, not the artifact.

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
algorithm (http://howardhinnant.github.io/date_algorithms.html),
ported from cosmostrix `build.rs`:

- `build.rs::format_unix_secs_as_build_time()` — pure i64 arithmetic,
  proleptic Gregorian, leap-year correct, UTC only. Emits
  `M/D/YYYY HH:MM (UTC)` via `cargo:rustc-env=ZELYNIC_BUILD_TIME`.
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
`"GPL-3.0-only"` in the license allow list. CI installs the latest
release, which handles both; the license list keeps the exact SPDX
form. If a local run hits the CVSS parse error, update cargo-deny.

## Finding 4: nix compiled three unused feature modules

`nix` was enabled with `["process", "fs", "feature", "user", "signal",
"term"]`. The source uses exactly three APIs:

| API | Call sites | Feature |
|-----|-----------|---------|
| `nix::unistd::geteuid()` | `capabilities/mod.rs`, `commands/mod.rs` | `user` (implies `feature`) |
| `nix::sys::utsname::uname()` | `ebpf/bpf_syscall.rs` (kernel >= 5.7 check) | `feature` |
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
| `serde` 1 + derive | keep | JSON output structs (`--print-json`: capabilities, monitor, display) |
| `serde_json` 1 | keep | JSON serialization for the same three modules |
| `nix` 0.31 | keep, trimmed | safe geteuid/uname/termios wrappers; features `user`+`term`+`feature` only |
| `libc` 0.2 | keep | flock (ebpf/lock.rs), raw BPF syscalls (ebpf/bpf_syscall.rs), termios constants |
| `aya` 0.13 (optional) | keep | the entire point of the project; gated behind the `ebpf` feature |
| `chrono` 0.4 | **removed** | zero call sites; 27-crate transitive chain (Finding 1) |
| `[dev-dependencies] serde` | **removed** | exact duplicate of the regular dependency entry; tests already see regular deps |

## Enforcement (how this stays true)

1. `deny.toml [bans]` denies `chrono` — re-adding it fails
   `cargo deny check all` in CI (`ci.yml` "Check dependency policies")
   and the daily `audit.yml` observation run.
2. `deny.toml [graph] all-features = true` keeps the aya subtree
   inside every policy check (Finding 3).
3. `Cargo.toml` carries the dependency contract comment: every direct
   dependency must have a live call-site justification recorded in
   this file, feature lists must be trimmed to the modules used, and
   zero-call-site deps get removed.
4. CONTRIBUTING.md Coding Standard 8 requires updating this document
   with any dependency change, the same way LICENSE headers are not
   optional.

## Accepted risks (tracked, warn-level)

- `hashbrown` 0.15.5 + 0.17.1 duplicate: pulled by `aya-obj`,
  `indexmap`, `object` (upstream mix). Warn in `cargo deny check
  bans` (`multiple-versions = "warn"`). Resolves itself when aya's
  chain consolidates; not worth forking or patching.
- `syn` 2.0.119 + 3.0.5 duplicate: `clap_derive` moved to syn 3 while
  `serde_derive`/`thiserror-impl` remain on syn 2. Proc-macro only —
  never linked into the release binary. Same warn policy.
- Neither duplicate involves a crate with an open RustSec advisory
  (`cargo deny check advisories` passes clean over the full tree).

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
