# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The changelog is split into per-era files so this one stays navigable
(NIGHT-docs-1): the NIGHT research campaign that built the v11 line
moved verbatim to [CHANGELOG-V11-ERA.md](CHANGELOG-V11-ERA.md); this
file carries only the entries newer than that campaign. The pre-v11
release history (v2.0.0 through v10.0.0) is archived in git history
alone — the owner's NIGHT-hunt-18 call.

## [Unreleased]

### Release Engineering

- **ci: every runner pinned to ubuntu-24.04 — the ubuntu-latest label
  is a silent time bomb (NIGHT-hunt-26)** — every workflow carried
  GitHub's runner-images notice: "The ubuntu-latest label will migrate
  to Ubuntu 26 beginning October 19, 2026"
  (github.com/actions/runner-images#14748). On that date a floating
  `ubuntu-latest` silently starts resolving to a new OS image — new
  glibc, new kernel, new LLVM — under pipelines whose eBPF release
  build is exactly the kind of workload that breaks on environment
  drift. All 11 floating labels across the six workflows (ci, release,
  audit, codeql, docs-ci, maintenance) now pin `ubuntu-24.04`, the
  exact image ubuntu-latest resolves to today, so nothing about what
  the pipelines run changes — the environment is only frozen. The
  compatibility surface stays honestly covered: the ci.yml build
  matrix already builds on ubuntu-22.04 and ubuntu-24.04 explicitly,
  so a future move to Ubuntu 26 is a deliberate, matrix-first upgrade
  (add the label, watch it build, then repin) instead of a
  calendar-triggered surprise. Each workflow's first pinned job
  carries a four-line comment recording the rationale and the
  runner-images issue link for the next maintainer.

### Docs

- **docs: CHANGELOG split into lean active file plus a v11-era
  archive (NIGHT-docs-1)** — the active changelog had grown to a
  1.1k-line monolith where ~98% was the accumulated NIGHT research
  campaign; every future entry would keep making the file harder to
  navigate. Split: `CHANGELOG-V11-ERA.md` (new) carries the frozen
  campaign history of the v11 development line — the NIGHT research
  campaign, 2026-09-17 to 2026-09-19, every entry from the v10.0.0
  stable tag up to NIGHT-hunt-25 — moved VERBATIM (byte-identical,
  verified by diff against the pre-split commit 1026c1f; original
  order and section structure preserved). `CHANGELOG.md` is now a
  lean active file: header, a split note, `[Unreleased]` with only
  post-campaign entries, and a History pointer to the era file.
  Pre-v11 history (v2.0.0 through v10.0.0) stays archived in git
  history alone — the owner's NIGHT-hunt-18 call, unchanged.
  Frozen-record policy alignment mirrors the NIGHT-improve-4
  precedent: check-headers.sh, inject-disclaimer.sh, and the
  gate-keepers emoji sweep extend their CHANGELOG.md exclusions to
  the era file; check-policy.py and check-loc.sh already ignore .md
  files. Codespell coverage of the era content is unchanged (the
  moved body was already codespell-clean in the active file).

### Fixed

- **bootstrap: a damaged nightly toolchain is now repaired, not
  merely diagnosed (NIGHT-hunt-27)** — the owner's terminal showed
  the exact hole: bootstrap-ebpf.sh reported the pin as "not fully
  installed", tried `rustup component add`, and died on rustup's raw
  `error: missing manifest in toolchain 'nightly-2026-09-18-
  x86_64-unknown-linux-gnu'` with advice ("try reinstalling") that
  landed as a manual to-do. An interrupted install (Ctrl-C, power
  loss, full disk) leaves the toolchain directory registered while
  its manifests are gone — the pin stays LISTED, and
  `rustup run ... rustc` still succeeds because the binaries are
  intact, so the old probe said "listed" and the old script then
  walked straight into the component wall. The component enumeration
  is now the damage detector (it is the exact operation that fails):
  a listed-but-unenumerable pin is reported as "LISTED but DAMAGED",
  then removed and reinstalled from scratch automatically — every
  step announced, no manual rustup commands, and a reinstall that
  itself dies midway leaves a state the next run repairs again (the
  re-probe failure message says so). build.rs's preflight had the
  same blind spot one layer down: it verified the pin was listed but
  would have let a damaged one through, failing deep inside the
  nested nightly build as raw rustup or compiler errors far from
  the cause — it now runs the same manifest probe (a local metadata
  read, tens of milliseconds, only on the ebpf-feature path) and
  panics with the exact state and the same one-command repair
  before any compile time is spent. Verified: the damaged state
  reproduced deterministically against real rustup 1.29.1 (manifests
  deleted from the installed pin — byte-for-byte the owner's error
  text); a six-scenario functional matrix all green — fresh
  install, damaged → self-heal (including a heal run killed
  mid-reinstall that the next run finished from the resumed
  download), idempotent healthy re-run, --check on damaged exiting 1
  with nothing changed, --check on healthy exiting 0, and the
  component-add-only path untouched; the standalone build.rs suite
  (5 tests) plus a new ignored hermetic test that fakes a
  manifest-less RUSTUP_HOME and asserts the detector fires against
  real rustup; and a real `cargo check --features ebpf` on the
  damaged pin panicking with the new message in milliseconds, with
  the healed rerun passing the manifests probe and stopping exactly
  at the deliberately absent bpf-linker check.

  Benchmark: skipped — host tooling and preflight only; no
  render-path or runtime code touched.

## History

The frozen campaign history of the v11 development line — the NIGHT
research campaign, 2026-09-17 to 2026-09-19, every entry from the
v10.0.0 stable tag up to NIGHT-hunt-25 — lives in
[CHANGELOG-V11-ERA.md](CHANGELOG-V11-ERA.md), split out in
NIGHT-docs-1 to keep this file lean. Entries there are verbatim
historical records and are never rewritten.
