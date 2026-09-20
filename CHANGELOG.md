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

### Added

- **scripts: the one-click brutal stress test (NIGHT-master-2)** — the
  owner wanted "fast simple elegant flagship one click to brutal
  stresstest" over the whole command surface. `scripts/brutal-stress-test.sh`
  wraps `brutal-stress-test.py`: light mode (~2 min, basic limiting
  sweep) and `--heavy` (the complete brutal matrix, 5+ minutes long
  running until done). Coverage: strict-single / strict-multi /
  limit-all, block-single / block-multi, unstrict-single ("unlock") /
  unstrict-multi / unstrict-all, mixed concurrent policies on five
  dedicated cgroups, reload cycles, sustain windows, non-binding
  overhead, recover, list-apps — every rate verdict MEASURED (python
  client + real curl burst download and upload processes, the owner's
  manual-browser class of proof) and then proven in-kernel through the
  status JSON (bytes_allowed / packets_dropped). The rate ladder walks
  the parser's full span — 1kb (the minimum) through 10mb and 1gb up to
  1tb (the maximum), skipping any rung the hardware cannot feed
  (baseline < 2x rung), i.e. "up to 1 TB/s if hardware supports".
  Self-contained on the cross-distro minimum (python3 stdlib, curl
  optional — its stages SKIP, the rest keeps working); `--self-test`
  verifies the measurement engine alone (no root, no zelynic, no BPF)
  and runs in CI on every push. The legacy `scripts/stress-test.sh` is
  retired: it depended on an external speedtest server (flaky,
  metered, not reachable from many VMs) and asserted on a status
  output format that no longer exists.

### Changed

- **ebpf: observer counter maps raised 256 -> 1024 — the pure-Rust
  flagship's server-LTS audit (NIGHT-improve-8)** — the owner called
  the post-368c570 pure-Rust eBPF line peak-grade and asked for a
  stability/LTS audit for "desktop Linux, even server use". The
  deep audit verdict: the enforcement core is already at peak and
  needs no rework — the token-bucket math is overflow-safe by
  construction (the fill-detect branch bounds the exact-multiply
  product to < 2 x burst x 1e9 <= 2e17 with the userspace burst
  clamp at 100 MB; the fraction carry can never exceed one
  NS_PER_SEC), apply paths are all-or-nothing with a rollback
  ledger (NIGHT-hunt-20), the pin lifecycle predicate refuses
  half-attached states (NIGHT-hunt-19), the lock is crash-proof
  flock in a root-only directory, and schema migration is version-
  stamped. The ONE real gap found: the observer's counter maps
  held 256 entries per direction (the C twin's number, ported
  line-for-line) while the limiter's policy maps hold 1024 — on
  hosts with more than 256 live cgroups (Kubernetes nodes, systemd-
  heavy servers, container hosts) the maps filled silently and
  every further cgroup's traffic went UNCOUNTED: observe/top showed
  nothing for it, because the insert-failure path in the BPF
  program returns allow-and-skip. Fixed: both counter maps now
  share COUNTER_MAP_MAX_ENTRIES = 1024, the limiter's capacity
  class. The maps are unpinned and session-scoped (created fresh at
  every observe/top run), so the raise carries no pin or schema
  migration; kernel memory cost is 2 x 1024 x 24 B = 48 KiB per
  observe session, freed on exit. Documented as the third
  deliberate C-parity delta in docs/PURE_RUST_EVALUATION.md (the
  frozen port-time bpftool dumps stay verbatim at 256) and as
  honest limitation 11 in docs/USAGE.md. Deliberately NOT touched:
  the limiter's pinned map capacities (1024 policies, 256 group
  buckets) — those are pinned-map schema territory where a capacity
  change would take effect only after unstrict-all and desync from
  existing pins; a full map there already fails loudly with a full
  rollback (NIGHT-hunt-20), which is the correct LTS behavior.

- **monitor: box mode takes the pointer — copy/paste are disabled
  while observe/top run (NIGHT-improve-7)** — the owner reversed the
  NIGHT-strict-1 mouse clause: box mode is a live dashboard of
  private data (cgroup names, PIDs, remote endpoints) and none of
  it may be copyable while the box runs. The monitor now enables
  mouse tracking on enter — 1000 (press/release) + 1002 (button-drag)
  + 1006 (SGR encoding), the exact trio vim-class TUIs use — so
  click-drag selects nothing, Ctrl+Shift+C has no selection to copy,
  and middle-click never reaches the monitor's stdin; the drained
  mouse events are inert input under the q-only quit contract.
  ALT_EXIT restores every mode (mouse modes off first, reverse of
  the enter), verified by the pinned byte sequences. Any-motion
  1003 stays out (a stdin flood with no extra selection coverage),
  as do focus 1004 and bracketed paste 2004. The contract pins in
  test/terminal/mouse_contract_tests.rs flipped with the policy:
  the byte pins now assert the takeover, the mode allowlist is
  {1049, 25, 1000, 1002, 1006}, and the source-tree scan fails on
  anything else. Two honest caveats documented in USAGE.md: terminals
  still offer a Shift+click bypass (terminal-side, no escape
  sequence can switch it off), and a paste whose first byte is `q`
  still quits (NIGHT-hunt-16 contract unchanged).

### Fixed

- **build: the embedded eBPF objects are 8-byte aligned by
  construction — the `error parsing ELF data` blocker with a HEALTHY
  artifact was the buffer's address, not its bytes (NIGHT-hunt-30)**
  — after NIGHT-hunt-29 landed, the owner host still failed
  `strict-single`/`limit-all` with the identical error chain on a
  clean tree (`cargo clean` + full rebuild, no `cargo:warning`, the
  staging validator silent — the artifact was fine). The real root
  cause of the 2026-09-20..21 failures: aya hands the embedded bytes
  straight to the `object` crate, whose Pod casts (`from_bytes` /
  `slice_from_bytes`) read ELF64 structures directly out of the
  buffer and therefore require the buffer's ADDRESS to be 8-byte
  aligned. `include_bytes!` produces an align-1 static, so the
  required alignment was pure linker-layout luck — and it broke
  deterministically per host: every build on the owner host placed
  the limiter object at an unaligned address (different source-path
  strings, a different `ZELYNIC_BUILD` label, a different `.rodata`
  packing than the dev container's), while every build in the dev
  container happened to align — which is exactly why the hunt-29
  damage theory fit every symptom while fixing none of them.
  Reproduced character for character in the aya-0.13.1-exact
  load-probe by shifting a known-good object to `ptr % 8 != 0`: the
  parse dies on the very first header read, before any BPF-level
  interpretation — hence the error's total silence about maps and
  programs. Fix: both objects now ride inside `AlignedElf`
  (src/ebpf/embedded.rs) — `#[repr(C, align(8))]` makes every
  allocation of the type 8-aligned by contract (symbol alignment is
  honored by every linker: a property of the type, not of layout
  luck), and a fixed 8-byte guard field (the ASCII magic "ZELF-30"
  plus a NUL) keeps the allocation's content unique, because rustc's
  const interner dedups immutable allocations by bytes and IGNORES
  alignment — verified live in a release probe, where a wrapper
  static and a raw include of the same file MERGED onto one address;
  the guard makes that fold impossible. A load-path preflight
  (`misalignment` in both attach paths) and three test pins hold the
  contract: any future regression fails with a one-line "address is N
  bytes past an 8-byte boundary" diagnosis instead of a multi-day
  hunt through a healthy artifact. Also fixed en passant: the
  NIGHT-strict-1 source-tree scanner sliced a `&str` at byte
  indices around every backslash in prose — a doc comment quoting a
  NUL-terminated magic next to an em-dash panicked the scanner (the
  needle comparison is byte-level now). Verified: 156 unit +
  23 integration tests green, standalone build.rs suite 13 + 1
  ignored, gate-keepers 11/11, and on the exact `cargo
  pro-native-gnu` alias the binary's embedded objects sit at
  8-aligned vaddrs inside guard-led allocations, byte-identical to
  the staged artifacts, parsing clean in the aya-exact load-probe
  (both objects; the container's expected no-caps EPERM at map
  create is all that remains).
- **build: a damaged eBPF object is now detected and self-healed
  before it can ride into the binary (NIGHT-hunt-29)** — the
  2026-09-20 test session's `error parsing BPF object: error parsing
  ELF data` was a bpfel artifact damaged ON DISK after cargo had
  marked its build unit fresh (cargo's freshness is
  fingerprint-plus-existence, never output integrity — a truncated or
  partially written file stays "fresh" forever). The old staging
  check tested only the ELF magic, which a truncated file keeps (the
  header lives in the first 64 bytes), so the corpse was staged into
  OUT_DIR, embedded via include_bytes!, and died at load time on the
  user host, far from the cause — identical on a fresh build and an
  old one, because both embedded the same damaged artifact file.
  Reproduced end to end in a sandbox (a 1000-byte prefix of the
  5624-byte limiter, parsed by the exact aya 0.13.1 userspace pair,
  reproduces the owner's error character for character). build.rs now
  structurally validates both objects — ELF64/LSB/ET_REL/EM_BPF
  identity, the section header table inside the file (bpf-linker
  places it LAST, which makes this the truncation killer), every
  non-NOBITS section's span inside the file, and the section name
  string table index in range — and when validation fails, it
  self-heals instead of failing the build: every on-disk copy of the
  damaged object is deleted and the nested build is re-run once,
  forcing a real relink. Both copies matter (cargo 1.98 layout): the
  published `release/<name>` file is a HARDLINK of the canonical
  `build/zelynic-ebpf/<hash>/out/<name>` unit output — they share one
  inode, so damage through either name corrupts both, and deleting
  only the published name lets cargo see the canonical copy intact,
  declare the unit fresh, and silently re-publish the corpse (verified
  live: a 0.05s "Finished" with the damaged file resurrected, mtime
  untouched; only a missing canonical copy forces the relink). The
  repair is visible as a `cargo:warning` naming the exact structural
  violation; an object still damaged after the forced rebuild panics
  with both violation reports and the bpf-linker reinstall hint.

- **build: host-CPU rustflags no longer poison the nested eBPF build
  — `cargo pro-native-gnu` works on any host CPU (NIGHT-hunt-28)** —
  the aliases inject `-C target-cpu=native` via `--config
  build.rustflags`, and cargo exports its resolved rustflags to build
  scripts as `CARGO_ENCODED_RUSTFLAGS` (verified live on cargo
  1.98.1). The nested bpfel build inherited them, and rustc forwarded
  the resolved host CPU to bpf-linker as `--cpu znver3` — which
  bpf-linker hard-rejects (`invalid CPU`), killing both objects at
  the link step after ~4 minutes of compiling (reproduced on the
  owner's Zen 3 host; plain `cargo build --release --features ebpf`
  was unaffected because the root config's flags carry no host CPU).
  build.rs now strips host-poison rustflags (`target-cpu=`,
  `target-feature=`, `link-arg=` — the last also covers
  build.sh's `-C link-arg=-fuse-ld=mold` fast-linker export, a
  latent landmine on mold-equipped hosts) from both
  `CARGO_ENCODED_RUSTFLAGS` and `RUSTFLAGS` before spawning the
  nested build. Everything else survives byte-identically, so CI's
  `RUSTFLAGS="-D warnings"` contract still covers the ebpf crate —
  deliberately narrower than aya-build 0.2.0 upstream, which replaces
  the variable wholesale and discards the inherited contract. Clean
  values pass through untouched, which also preserves the nested
  build's artifact cache (the ebpf tree did not recompile after the
  change). Verified: the exact alias shape now finishes green where
  it previously died at the link step.

- **runtime errors now print their full cause chain (NIGHT-hunt-28)** —
  `main()` rendered errors with `format!("{e}")`, which shows only
  the outermost anyhow context: the first Dragon-architecture run on
  the owner's host failed as a bare "Failed to load BPF object" while
  the actual diagnosis (which map, which syscall, which errno) sat
  invisible in the dropped chain. The render now walks the
  `std::error::Error` source chain and emits one `caused by:` line
  per hop through the same line-aware branded renderer (white `tip:`
  lines unchanged). A load failure now self-describes: `error:
  Failed to load BPF object` + `caused by: failed to create map
  'X' with code -N` + the pin/EINVAL shape when that is the real
  cause (see the bpffs fix below).

- **doctor: the BPF-filesystem check verifies the mount, not the
  directory (NIGHT-hunt-28)** — `bpf_fs_mounted` was
  `Path::exists("/sys/fs/bpf")`, but the kernel creates that
  directory on every Linux — on hosts where nothing is mounted on it
  (an empty sysfs or tmpfs-backed directory), the doctor reported
  `BPF fs: YES` while every pin operation was about to fail EINVAL.
  The check now statfs()es the path and accepts only the real
  `BPF_FS_MAGIC`; the warning names the one-command fix
  (`sudo mount -t bpf bpf /sys/fs/bpf`). `Limiter::attach` gained
  the same preflight before any pin attempt, so a non-bpffs
  `/sys/fs/bpf` fails with the actionable mount message instead of a
  generic load error from deep inside `EbpfLoader::load`. The
  observer is deliberately NOT gated — its maps are unpinned, so
  `observe` works without bpffs, giving a natural diagnostic split:
  observe works + strict fails = the pin filesystem is missing.

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

- **docs: README flagship tidy — crypto donations moved from the
  masthead to a dedicated Support section (NIGHT-docs-6)** — the
  README opened with the raw three-address donation block at the
  very top (masthead), which is placement no flagship project uses:
  the reader meets wallet addresses before the first feature table.
  Aligned with the cosmostrix (owner's reference flagship) layout:
  the masthead keeps ONLY the Ko-fi badge; a `## Support` section
  now sits in the reader flow just before Intellectual Property &
  Trademark, carrying the maintainer line, the Ko-fi button, and
  `### Crypto donations` in the owner-verified format (network
  detail per asset, verification method prose, mismatch warning).
  The IP section gained the flagship "NOT for sale" clause. En
  passant: the `[Unreleased]` block had accumulated a duplicated
  `### Fixed` heading (hunt-27's entry appended after `### Docs`
  while hunt-30's sat in the first `### Fixed`) — the two sections
  are merged, restoring one heading per category (Fixed →
  Release Engineering → Docs). Benchmark: skipped — documentation
  only, no render-path or runtime code touched.

## History

The frozen campaign history of the v11 development line — the NIGHT
research campaign, 2026-09-17 to 2026-09-19, every entry from the
v10.0.0 stable tag up to NIGHT-hunt-25 — lives in
[CHANGELOG-V11-ERA.md](CHANGELOG-V11-ERA.md), split out in
NIGHT-docs-1 to keep this file lean. Entries there are verbatim
historical records and are never rewritten.
