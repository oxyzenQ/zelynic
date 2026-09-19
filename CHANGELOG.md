# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **research: pure-Rust eBPF prototype, phase 2 complete
  (NIGHT-improve-1 phase 2, pure-rust-prototype branch)** — the
  limiter port, executed per the stage-1 GO verdict, three
  micro-commits (port, measurements, docs sync). `ebpf/src/bin/
  limiter.rs` is the line-for-line aya-ebpf 0.2.1 port of
  `bpf/limiter.bpf.c` (396 lines vs 364, **0.93x code-only** — the
  first port where the Rust side has fewer code lines than the C
  twin; 1.09x total). Both programs (`enforce_dl` ingress,
  `enforce_ul` egress), the token-bucket core with fractional
  remainder tracking and the overflow-safe fill-detect path, and
  all nine maps carry over; every map declares PIN_BY_NAME
  (`HashMap::pinned` / `Array::pinned`), and that flag was
  verified from source to round-trip through aya-obj 0.2.1's
  legacy `bpf_map_def` parser and aya 0.13.1's `EbpfLoader` —
  policies pinned by the Rust object survive process exit exactly
  like the C twin's. Scratch-harness verified: sections, all nine
  map geometries, pins, GPL license, zero unexpected symbols
  (observer re-verified as a pinned=false regression baseline).
  Mainline untouched: gate-keepers 15/15, build.sh check-all
  green, benchmark skipped (detached crate, zero shipped-surface
  changes). Phase 3 remains HOLD pending stable-Rust aya-ebpf;
  the research artifact now covers BOTH production objects. Hunt
  findings recorded in `docs/PURE_RUST_EVALUATION.md`: a stale
  shellcheck reference in the codeql.yml comment (mainline
  scope), and the `Ebpf::load` default-pin-path footgun for
  hand-loading experiments.

- **research: pure-Rust eBPF prototype, stage 1 complete
  (NIGHT-improve-1, pure-rust-prototype branch)** — the
  owner-briefed evaluation of migrating the BPF side from C to
  aya-ebpf, executed exactly as the DeepSeek plan staged it, one
  micro-commit per task. Lives on the `pure-rust-prototype` branch
  (research artifact; mainline untouched by design): `ebpf/` is a
  detached nightly-only crate holding the line-for-line port of
  `bpf/observer.bpf.c` (269 lines vs 172, 1.27x code-only), and
  `docs/PURE_RUST_EVALUATION.md` is the full record — ecosystem
  state, toolchain requirements, the port contract, measurements,
  and the decision. Headlines: the Rust-built object is a verified
  drop-in for the pinned aya 0.13.1 userspace (identical program
  sections, map names, and geometry; zero userspace changes
  needed), the toolchain needs no clang/LLVM/sudo (rustup nightly +
  prebuilt bpf-linker), the stop criterion (>2x LOC AND nightly)
  is not met, the render-path A/B is metric-identical as expected
  (detached crate, shipped binary unchanged). Decision: stage 1
  SUCCESS, Phase 2 (limiter port — a strict-subset BPF surface) is
  a GO on the same branch, Phase 3 (dropping C from mainline) is a
  HOLD until aya-ebpf compiles on stable Rust, since a mainline
  nightly dependency would contradict the dormant-mode toolchain
  pin that gate 10 enforces. Hunt finding recorded for Phase 2:
  the observer's `events` ring buffer is written by the BPF side
  but never read by userspace.

### Changed

- **docs: src/RULES.md — the colocated source-tree rules
  (NIGHT-docs-4)** — the reminder of the rules that govern src/ and
  tests/, standing in the tree where contributors actually work (the
  cosmostrix src/RULES.md convention): directory discipline
  (subsystem directories with mod.rs owners, main.rs stays
  bootstrap, cohesion splits not function slices), the 500-line cap
  with its self-declared LOC_EXEMPT markers, where tests live (unit
  pins in-module or in a *_tests.rs sibling; cross-binary contract
  pins in tests/integration/), and the header/disclaimer
  requirements — all pointing at docs/RULES.md as the canonical
  policy. Stale references fixed while at it: docs/RULES.md's
  File Size scope and docs/USAGE.md's maintainer map still pointed
  at the monolithic tests/integration_test.rs path.

### Changed

- **fix: status never fabricates "no limits" from a failed read
  (NIGHT-hunt-22, status-display audit)** — the owner-named surface
  (stats.rs / monitor display reads) closed the last swallow family.
  `print_status`/`print_status_json` flattened every map-read failure
  into empty data via `unwrap_or_default()` — yet both are called
  only AFTER `handle_status` verified the enforcement pins are
  operational, so a failed read there is an anomaly by definition.
  The human path rendered "Active limits: none" and the JSON path
  emitted `{"active_limits": 0, "limits": []}` from a failed read —
  the hunt-20 honesty trap in its most user-facing form: `status` is
  the one surface owners use to check enforcement, and the JSON
  variant feeds scripts fabricated "nothing is limited". Read
  failures now propagate (non-zero exit, map path in the error);
  `read_watchdog` no longer converts a failed read into "not set"
  (the display-side twin of the hunt-20 delete conflation). The
  `--print-json` contract itself is now pinned: `status_json` was
  extracted as a pure builder and six unit pins hold the field
  names, the cgroup-count (not direction-count) semantics of
  `active_limits`, null-vs-zero direction rendering, stats joining,
  the three watchdog wordings, and the one honest zero state (empty
  maps after an orphan sweep). Verified along the way: every pin
  path constant matches its BPF map name one-to-one (no silent
  ENOENT from a wrong name), and the live observe/top loops keep
  their documented soft-read behavior (a transient read failure
  renders a zero frame and retries next tick — the task-7 decision,
  untouched).
- **fix: every policy-writing command runs the full attach ladder
  (NIGHT-hunt-21, apply-path discipline)** — the NIGHT-hunt-20 audit
  found `handle_strict_multi` and `handle_limit_all` pre-checking
  `if !is_pinned()` before calling `attach()`, which SKIPS the
  schema-version migration inside attach(): with healthy-looking but
  stale-schema pins (an upgraded binary, pins surviving since before
  the upgrade), strict-multi/limit-all would open the old-layout
  pinned maps and write new-layout `PolicyRaw` entries into them —
  strict-single and the whole block family already ran the ladder
  unconditionally, so the two pre-checks were both an outlier and a
  correctness gap. The pre-checks are gone: attach() is the ONE
  lifecycle ladder everywhere (operational-reuse check, schema
  migration, stale-pin cleanup), and with healthy current pins it
  costs a few stat()s plus one array read. The post-apply pin
  validation in both handlers is unchanged.
- **fix: policy apply/remove mid-flight error paths made honest —
  strict all-or-nothing apply, ENOENT-only "absent", verified-zero
  unpin (NIGHT-hunt-20, error-path audit)** — the owner-named audit
  surface (`policy.rs` apply/remove mid-flight) closed three real
  defects. (1) A mid-flight write failure (policy maps hold 1024
  entries — `limit-all`/`block-all` on cgroup-dense systemd desktops
  can hit that, plus ENOMEM or a map-open failure) propagated the
  error while the already-written policy prefix stayed ENFORCED with
  no mention — a command that "failed" while silently limiting, the
  inverse of the hunt-19 trap. Applies are now strict all-or-nothing:
  every write is ledgered, the first failure rolls the whole
  invocation back, and if a rollback delete itself fails the error
  names the exact surviving policies. (2) `delete_policy` mapped every
  remove error to "not found", so ENOENT was indistinguishable from
  ENOMEM/EACCES/EINVAL — `unstrict` could report "No active limits
  found" while limits stayed enforced and `recover` counted failed
  deletes as removed. Only ENOENT now classifies as absent (pure
  classifier, unit-pinned against the real errno set); everything else
  surfaces with cgroup + direction, and `recover` counts actual
  per-direction deletions instead of the orphan-cgroup count. (3)
  `count_remaining_policies` used `unwrap_or_default`, so a transient
  map-read failure counted as zero remaining policies — and zero is
  the auto-unpin trigger, meaning a failed read could tear down ALL
  enforcement during a single-target unstrict. The unpin zero must now
  be verified; on read failure the pins stay and a warning names
  `recover` as the repair tool. Along the way the duplicated
  ephemeral/pinned map-acquisition blocks in `write_policy` and
  `delete_policy` merged into one `with_policy_map` accessor, and the
  policy unit pins moved to `test/ebpf/limiter/policy_tests.rs`
  (NIGHT-hunt-17 layout) to hold the module under the 500-LOC cap.
  Evaluated and kept by design: best-effort removal with survivor
  reporting (all-or-nothing applies to apply, not cleanup), the
  `group_id` collision math (unreachable with real pid spaces), and
  the per-(cgroup, direction) map-open pattern (correctness-first).
- **fix: the operational pin check is link-aware — silent
  no-enforcement trap closed (NIGHT-hunt-19, error-path audit)** —
  the owner-approved audit of the loader/attach error paths found a
  real defect: `is_pinned()` (and `attach()`'s reuse decision) trusted
  the two PROGRAM pins alone. On bpf_link kernels (5.7+ — every
  supported kernel, the floor is 5.13) the attach sequence pins both
  programs FIRST and creates the cgroup links SECOND, so a failure in
  between (bpffs full, memlimit, SIGKILL mid-attach) leaves a
  half-attached state: programs pinned, nothing hooked to the cgroup.
  Every subsequent command then "reused" that state — strict wrote
  policies to maps no hook executes, reported success, passed its own
  post-apply pin validation, and status showed active limits while
  NOTHING enforced. The fix is one predicate everywhere
  (`pins_operational`, pure, unit-pinned): on bpf_link kernels both
  program pins AND both link pins are required; a half-attached state
  now reloads (unpin + fresh attach) or fails loudly instead of
  silently not enforcing. On pre-5.7 kernels — below the supported
  floor, defensive only — the legacy attach path never pins links, so
  program pins alone remain the operational contract there. Messages
  synced: recover's valid-state line and status's stale-pins line no
  longer misdescribe the state; unstrict-all's cleanup rationale
  covers partial states; SAFETY_ANALYSIS documents the link-aware
  invariant.
- **chore: the v10-and-older era removed entirely (NIGHT-hunt-18)** —
  owner rule: the legacy and deprecated era references are gone from
  the tree. Deleted: `CHANGELOG-V10-ERA.md` (the 243KB pre-v11
  history archive — git history is the only archive now) and
  `docs/MIGRATION_V4.md` (the v3.x-to-v4 migration guide). Scrubbed
  every era reference the hunt could find: the README, CONTRIBUTING,
  SECURITY, and DRAGON_ARCHITECTURE branch and support tables lost
  their legacy-branch rows; PERFORMANCE and CROSS_DISTRO_RESULTS
  dropped their version-era labels; VERIFY_RELEASE examples moved to
  the current format; KERNEL_COMPATIBILITY lost its v4.9+ qualifier;
  SAFETY_ANALYSIS dropped its "since v10" phrasing; USAGE's
  removed-surfaces note still documents the live usage errors without
  the era word; code and script comments (capabilities, ebpf mod,
  nonroot/leak suites, version-to usage examples, the anti-pattern
  rule example, the release tag-format guard comment) no longer
  narrate the old line. The era-file exclusions in check-headers.sh,
  inject-disclaimer.sh, and the gate-keepers emoji sweep shrank back
  to CHANGELOG.md only. Untouched on purpose: live kernel-API
  terminology ("legacy bpf_prog_attach" is the kernel's own name for
  the pre-5.7 attach path), the pre-v11 lock/pid remove-only hygiene
  (live upgrade safety), BPF map schema v1/v2/v3 (live contract),
  cgroup v2, and the Dragon Architecture "Why" rationale (current
  design documentation, not era archaeology). Docs and comments only
  — no production code change, the shipped binary is unchanged.
- **refactor: every .rs test file under the single test/ tree
  (NIGHT-hunt-17)** — the whole test surface now lives under one
  top-level directory, cosmostrix Pattern C: `tests/integration/`
  moved to `test/integration/` (still the one integration binary,
  now the only `[[test]]` target declared in Cargo.toml —
  `autotests = false` makes the old tests/ autodiscovery path inert
  for good), the diff-engine unit pins moved from
  `src/terminal/diff_tests.rs` to `test/terminal/diff_tests.rs`, and
  the A/B frame harness from `src/ebpf/render/bench.rs` to
  `test/ebpf/render/bench.rs` — both `#[path]`-wired back to their
  engines, so module paths, test names, and frame-bench.py's
  name-based invocation are unchanged. Tightened for the future with
  gate-keepers check 13 (test-tree discipline): no tests/ directory,
  no `*_tests.rs`/`*_test.rs` under src/, every `[[test]]` target
  and src/ `#[path]` wiring must resolve under test/. check-loc.sh
  now scans src/ AND test/, the CodeQL path filters follow, and
  RULES.md (docs/ and src/), CONTRIBUTING.md, USAGE.md, and
  DEPENDENCY_AUDIT.md point at the new tree. No production code
  touched — the shipped binary is unchanged.
- **feat: max rate ceiling raised to 1 TB/s — owner-approved option B
  (NIGHT-research-1)** — the documented maximum rate moves from
  100 GB/s (800-GbE class) to 1 TB/s (8-TbE class): a decade of
  hardware margin while staying far inside u64 and the BPF refill
  guard's exact-multiply bound. The Finding 2 (cybersecurity-1)
  fix's safety argument is rate-agnostic and needs no change: the
  fill-detect threshold engages after 200us of idle at the new
  ceiling, and the product bound 2 * burst * NS_PER_SEC stays
  <= 2e17 at the unchanged 100 MB burst clamp (~92x headroom under
  u64::MAX). The parser gains the `tb` suffix (1tb =
  1,000,000,000,000 B/s, decimal SI, consistent with kb/mb/gb)
  plus tb in the near-miss unit rescue; the old 1000gb spelling
  still parses identically. MIN_RATE is untouched (1 KB/s; 0 =
  block) and `--allow-dangerous` still lifts both bounds. Burst
  default stays 1 second of traffic clamped to 4 KB..100 MB.
  Synced: validate_rate message, --help rate reference, README
  rate table + bounds + safety row, USAGE strict section,
  SAFETY_ANALYSIS Finding 2 ceiling note, bpf/limiter.bpf.c
  ceiling comment. Tests: tb parse pin, new-bound validation pins
  (1 TB/s accepted, above rejected, 100 GB/s still valid),
  privilege ladder case moved to 2tb (also exercises the tb
  suffix end-to-end through the real binary). Version untouched:
  11.0.0-dev.1 (frozen-version policy).

- **perf: tall-regime render repair — scroll-free top-aligned
  emission and idle zero-emit at every height (NIGHT-improve-6)** —
  the improve-2 engine's fallback for frames meeting or exceeding
  the terminal height kept the pre-diff scrolling semantics. Every
  terminal at or under the render cap (27 rows — the classic 80x24
  included, plus piped monitors on the 80x24 probe fallback) ran a
  sequential regime that ended each frame with a bottom-row
  linefeed: the screen scrolled one line per refresh, the title bar
  drifted off, tall-to-short transitions misaligned against the
  scrolled screen, and the idle fast path was disabled there, so
  even a completely unchanged frame repainted in full every
  refresh. The emission is now top-aligned and clipped to
  min(rows, height) with no trailing linefeed; a `painted` row
  count marks clipped rows dirty, so a terminal that grows repaints
  exactly the rows it just revealed (never a stale gap); and the
  idle fast path covers the tall regime — an unchanged frame costs
  zero I/O at every height. The normal regime (rows < height) is
  byte-identical by construction (the `painted` term is inert there
  and the sequential/sparse paths are untouched); the 80x40 A/B
  benchmark confirms bit-equal emissions while the tall regime
  drops to zero bytes while idle. Five new engine pins (tall idle,
  no-trailing-LF, viewport clip, reveal-on-grow, transition stream
  contract — four proven failing against the old engine, the
  transition pin locks the contract on both). 131 unit + 23
  integration (ebpf), 25 + 21 (default), all pass. Docs synced:
  USAGE observe section, SAFETY_ANALYSIS render-path audit,
  DRAGON_ARCHITECTURE Layer 4, CONTRIBUTING module map. Two deferred
  ports from cosmostrix's dragon engine evaluated and rejected with
  architecture evidence: idle-resync (zelynic diffs the full frame
  every iteration — no dirty-tracking state can go stale) and
  style-run batching (zelynic rows are self-resetting styled lines —
  no SGR stream to cache). Version untouched: 11.0.0-dev.1
  (frozen-version policy).

- **refactor: LOC gate covers tests/ — the 770-line integration
  suite split by surface (NIGHT-docs-4)** — scripts/check-loc.sh now
  scans src/** AND tests/** (recursive) plus build.rs, per the
  owner's directive. That exposed the one file the old gate could
  not see: tests/integration_test.rs at 770 lines, 54% over the cap.
  Split into tests/integration/ (ONE test binary via main.rs — build
  time unchanged, no per-file link cost) by surface: main.rs (shared
  helpers zelynic_cmd/euid_is_root), smoke.rs (doctor, version,
  lifecycle), cli_ux.rs (flag/error UX + EPIPE pin), help_pins.rs
  (--help reference drift pins), surface_pins.rs (alias/removal
  wiring), privilege.rs (unprivileged contract + validation ladder
  + edge no-panic). All 26 tests preserved verbatim (23 run + 3
  ignored, both feature configs), every file under 156 lines.
  References updated everywhere they lived: docs/RULES.md,
  docs/USAGE.md's maintainer map, and both mentions in
  scripts/check-version-anti-patterns.sh now name
  tests/integration/smoke.rs::test_version. No src/ change — binary
  semantics identical, benchmark skipped per the docs-only rule.

- **perf: diff-based monitor rendering — the cosmic dragon engine
  adapted (NIGHT-improve-2)** — the monitor loop used to wipe the
  whole alt screen (ESC[2J) and reprint every line on every refresh:
  a full redraw per frame, one write+flush syscall PER LINE, and
  terminal-side full-screen rework even when nothing changed (the
  owner's wasted-energy/wasted-I/O complaint). Ported the diff-based
  render discipline from cosmostrix's cosmic dragon engine
  (github.com/oxyzenQ/cosmostrix) at line granularity, the honest
  fit for zelynic's styled text tables: a shadow of the previous
  frame, dirty-row runs repositioned with one MoveTo per run, a
  byte-exact crossover between sparse and sequential emission
  (cosmostrix's fixed 12.5% ratio assumed 1-char cells; rows here
  are 50-80 chars, so the exact costs are computed per frame), one
  write(2) per frame through a raw-fd writer, and an idle fast path
  that emits ZERO bytes when nothing changed. Resizes reset fully
  via one TIOCGWINSZ probe per frame. Renderers became line builders
  (render_observe_frame / render_observe_filtered / render_top_table
  fill a reusable Vec<String>; the engine swaps it with the shadow —
  zero per-frame cloning). Safety dividend: ESC[2J is never emitted
  anymore — on VTE terminals a 2J inside the alt screen can flag the
  main screen's scrollback for deletion on exit (documented in
  docs/SAFETY_ANALYSIS.md's render-path audit); resets use
  cursor-anchored ESC[H + ESC[J. Unicode-safe by construction (rows
  written whole, cursor only at row starts). Benchmark protocol
  extension: each captured frame now carries the logical content AND
  the engine's emitted byte count (###EMIT###), so pre-diff and
  post-diff captures compare honestly (emit == full frame for the
  old renderer). 11 unit pins on the engine (idle zero-emit, first
  frame reset, sparse repositioning, run joining, shrink tail-clear,
  resize reset, tall-frame sequential fallback, byte-exact crossover,
  style-byte parity, CJK rows, shadow swap) + renderer line-building
  pins. Degenerate tall-frame case (rows >= terminal height) keeps
  the pre-diff scrolling semantics via the sequential path.

- **refactor: one canonical /proc boundary (NIGHT-optimized-1)** —
  the pid-to-cgroup resolution and the sanitized comm read existed
  as THREE independent inline copies (identity walk, connection
  walk, resolve_target match walk) — the NIGHT-cybersecurity-1
  sanitize fix had to land three times in lockstep, and the next
  boundary fix would too. Consolidated into two canonical helpers
  in identity/mod.rs: pid_cgroup_id() (parse /proc/<pid>/cgroup,
  resolve via /sys/fs/cgroup, truncate to the u32 BPF key width)
  and pid_comm() (read + sanitize_comm in one place). All three
  walks route through them now, so a boundary fix lands once and
  can never drift between surfaces — display, JSON, matching, and
  the majority-vote tally all consume the same canonical reads.
  Callers keep their own fallback policy (tally: empty label;
  connection walk: "pid {n}"; match walk: case-insensitive
  compare). Pure dedupe: zero behavior change, zero test-count
  change (113 unit + 23 integration ebpf, 25 + 21 default, both
  pass), binary semantics identical.

### Security

- **security: comm-label terminal injection + BPF refill overflow
  (NIGHT-cybersecurity-1)** — second master audit, two real findings
  fixed. (1) prctl(PR_SET_NAME) lets any unprivileged process set a
  15-byte /proc comm containing ANSI/OSC escapes and newlines, and
  zelynic printed those labels raw on root-run surfaces (list-apps
  table, observe/top monitors, eagle-eyes detail, verbose trace) —
  OSC 52 can rewrite the admin's clipboard, newlines forge output
  lines (a fake cgroup-id row steers the admin toward the wrong
  target), escapes corrupt the alt screen. Fix: sanitize_comm()
  replaces every control char (C0, DEL, C1) with '?' at all three
  /proc read boundaries (identity walk, connection walk, the
  resolve_target match walk) — display, JSON, matching, and tally
  safe by construction; procps-ng does the same. The non-root depth
  suite gained a pure-shell comm spoofer (a copied binary's basename
  becomes its comm) asserting list-apps text and JSON never carry a
  raw ESC byte; unit pins cover the OSC-52, forged-row, DEL, C1, and
  clean-pass families. (2) The BPF token refill product elapsed_ns *
  rate_bps overflowed u64 at rates above ~18.4 GB/s (u64::MAX / 1s)
  with ~0.18s+ of idle — inside the documented 100 GB/s ceiling;
  the stale in-code comment assumed a 1 GB/s cap that never existed.
  Demonstrated: at 100gb after 184467441 ns idle the wrapped refill
  collapsed to 26 bytes vs the 100 MB burst cap (post-idle credit
  lost ~4,000,000x; no bypass — always capped at burst). Fix:
  fill-detect threshold (elapsed >= 2*burst*NS_PER_SEC/rate credits
  burst directly; below it the product is provably < 2e17) with an
  explicit rate>0 guard. Proven bit-identical to an __int128
  reference across 2,880 parameter combinations including the
  overflow edge and threshold boundaries (harness outside the repo).
  Audit sweep otherwise verified clean: rate parsing checked_mul
  (held), observer datapath pure counters, spoofed-comm resolution
  symmetric (self-DoS class, out of scope), cmdline/environ never
  read. Full detail in docs/SAFETY_ANALYSIS.md.

### Fixed

- **ci: eBPF Build red since NIGHT-cybersecurity-1 — the over-wrapped
  fill_ns line and the missing local C-side gate (NIGHT-ci-fix-1)** —
  both eBPF Build matrix jobs (ubuntu-22.04, ubuntu-24.04) failed at
  the "Check BPF C formatting" step on every run since the BPF refill
  overflow fix landed: the fill_ns assignment in bpf/limiter.bpf.c
  wrapped one line early even though the joined line fits the
  80-column limit exactly, so clang-format rejected the file on both
  runners before the compile steps ever ran. Joined the line — zero
  replacements verified with clang-format 18.1.8 and 14.0.6 (both CI
  images) under the exact CI invocation. The regression slipped
  through because gate-keepers.sh had no C-side gate: added check 12
  running `clang-format --dry-run --Werror bpf/*.c` (the exact eBPF
  Build command) with the standard missing-tool skip. Gate count
  references synced in CONTRIBUTING.md, docs/USAGE.md, and
  src/RULES.md (13 -> 14). No behavior change. Version untouched:
  11.0.0-dev.1 (frozen-version policy).

- **cli: unstrict-single is the canonical name, unstrict the shorthand
  (NIGHT-hunt-16)** — the strict family documents `strict-single` as
  canonical with `strict` the shorthand, but the unstrict family was
  mirror-inverted: `unstrict` was canonical and `unstrict-single` the
  alias (owner-found inconsistency). Flipped for strict/unstrict
  symmetry: the canonical always carries the `-single` suffix. The
  `unstrict` invocation still works (alias, like `strict`). --help
  synopsis, README commands table, USAGE grammar + sections +
  examples all teach the canonical form now;
  the nonroot depth suite gained a canonical-form refusal case; the
  integration drift pins assert the canonical synopsis AND that a bare
  `zelynic unstrict <target>` synopsis line never returns.

- **monitor: 'q' is the ONLY quit key (NIGHT-hunt-16)** — Ctrl+C
  (byte 0x03) no longer quits observe/top: raw mode disables ISIG, so
  the byte was silently swallowed as a quit path while every doc
  advertised "q or Ctrl+C" — an ambiguous two-key contract where the
  title bar only ever said "q quit". Now 'q' is the single documented
  and implemented exit (mainstream TUI convention: htop/vim/less treat
  Ctrl+C as an interrupt, not an exit); Ctrl+C, ESC, and all escape
  sequences are drained. The termios-failure fallback loop also honors
  q (previously it had no key handling at all — a quit-path
  inconsistency between the two render paths). If a wedged terminal
  ever swallows the 'q' byte, recovery is `pkill zelynic` + `stty
  sane` (documented in USAGE troubleshooting). --help, README, USAGE,
  and the CLI doc comments state the q-only contract; an integration
  drift pin forbids "Ctrl+C" from ever returning to --help.

### Docs

- **docs: crypto donation addresses on the README (owner)** — SOL /
  USDT (Solana network), ETH / USDT (Ethereum network), and BTC
  (Taproot) receive addresses added directly below the Ko-fi badge.
  Every address was cryptographically verified before publishing: the
  Solana address base58-decodes to a 32-byte Ed25519 pubkey; the
  Ethereum address passes the EIP-55 mixed-case checksum (keccak-256
  round-trip, implementation self-tested against the canonical EIP-55
  vector); the Bitcoin address passes the BIP-350 bech32m checksum
  with witness v1 and a 32-byte program — i.e. P2TR taproot (bech32m
  encoding, not native segwit's bech32/v0), confirming the owner's
  taproot label. Verification tooling kept outside the repo
  (scripts/verify-donation-addresses.py in the workspace).

### Security

- **docs: SECURITY.md — the security foundation (NIGHT-security-2)** —
  a GitHub-recognized policy file at the repo root: private reporting
  channel (GitHub vulnerability reporting / draft advisory — never a
  public issue), supported-versions table (v11 main supported, 10.x and
  the 3.x legacy branch unsupported), scope boundaries with reasoning
  (in: CLI + loader + datapath + release pipeline + the privilege UX
  contract; out: anything requiring the attacker to already be root,
  documented enforcement-model limits, self-DoS), the
  what-counts-as-a-vulnerability class table with current posture per
  class, the shipped-hardening inventory, and the
  easy-to-use-by-construction principle (no keys, no config, no new
  workflow steps — the one behavioral rule is a clear error message).
  README gains a Security section linking it; the USAGE maintainer's
  map binds security-relevant changes to SECURITY.md + SAFETY_ANALYSIS
  so they move together.

- **fix: operation lock moved out of the world-writable /tmp (NIGHT-hunt-14 /
  security-1)** — the flock guard lived at /tmp/zelynic.lock, which handed any
  local unprivileged user two primitives against the root-running tool: lock
  squatting (create the file and hold flock forever → every enforcement
  command fails with "another zelynic operation is in progress" until an
  admin intervenes) and a symlink-following open(O_WRONLY) as root. The lock
  now lives at /run/zelynic/zelynic.lock inside a root-owned 0700 directory
  created on first use (/run is a root-owned tmpfs — same trust class as
  /sys/fs/bpf; only root can create entries inside). A unit drift-pin keeps
  the path out of world-writable locations forever; the legacy /tmp file is
  removed opportunistically (unlink is symlink-safe); error wording and the
  non-blocking retry contract are unchanged. Full audit matrix — including
  the verified-clean verdicts (update.rs curl hardening inventory, panic
  hunt, path handling, arithmetic, u32 cgroup-ID width, blocklist scope) —
  documented in docs/SAFETY_ANALYSIS.md.

- **ci: event context reaches run: scripts only through env (NIGHT-hunt-14)**
  — ci.yml's change-detection step interpolated ${{ github.event.*.sha }}
  directly inside the script. The values are git-controlled SHAs (no
  attacker free text, so nothing was exploitable), but env-var isolation is
  the canonical defense-in-depth against the script-injection class and now
  applies to every event field the step reads. No workflow interpolates
  event context inside run: anymore; the PR trigger remains pull_request
  (never pull_request_target), so fork builds see no secrets.

### Added

- **test: non-root end-to-end depth suite (NIGHT-hunt-13)** —
  scripts/nonroot-depth-test.sh runs the full unprivileged contract
  matrix (70 cases): informational surfaces exit 0 with real output,
  all 16 enforcement forms refuse cleanly (exit 1, "root required" +
  sudo tip), input validation precedes the privilege guard (rate
  typo/bounds/minimum/maximum fire before root), removed surfaces
  (man, unblock, completions, info, -i, --live, --duration, --help-all,
  --no-color) fail as usage errors, and hostile edge inputs (empty
  target, u64-overflow numeric, path-shaped, spaces, negative, unicode
  rate) never panic — exit 101 and backtraces are asserted absent on
  every case. The --check-update probe is time-boxed and accepts either
  a rendered report or a clean mapped network error. Verified live as
  uid 1001: 70/70 PASS, zero fixes needed — the non-root surface was
  already clean; two owner-relevant facts pinned along the way: rate 0b
  is deliberately legal (block shorthand), and the colon-list routing
  tip is post-apply advice (root-only), both now contract tests.
  Integration pins added: 12-command root-refusal wording matrix
  (uid-gated so sudo cargo test stays green), the uid-independent
  fail-fast ladder (ebpf-gated), edge-input no-panic pins, and the
  default-build "eBPF not compiled" honesty wording.

- **docs: Complete Usage Guide (NIGHT-docs-2)** — docs/USAGE.md is the
  flagship usage reference: the cgroup mental model, every command
  documented with real behavior details (rate precedence, group buckets,
  block-as-zero-rate, non-blocking lock), discover-limit-verify-remove
  workflows, troubleshooting matrix, stable JSON shapes, exit codes,
  FAQ, and a maintainer's map tying every change type to the files and
  drift-pin tests that must move with it. Centerpiece: an honest
  limitations section, led by the owner's snapshot-semantics case —
  strict-single/limit-all rules apply to the cgroups resolved at
  command time; apps launched afterwards are not auto-limited and need
  a re-run (no daemon by design), while new processes joining an
  already-limited cgroup are covered. Also documented: limits do not
  survive reboot (bpffs pins + cgroup ID churn), name resolution needs
  a running app, one name can match several cgroups, decimal-SI rates,
  cumulative status counters, and the frozen v11 CLI surface. README
  links it from Quick Start and Documentation.

### Removed

- **feat: CLI surface diet (NIGHT-hunt-12)** — the `man` subcommand is
  removed totally, along with its troff renderer (~170 lines) and the
  release-pipeline step that piped it into `man/zelynic.1`: tarballs no
  longer ship a man page, `--help` is the single reference surface.
  Audit verdict on the rest of the owner's removal list: `-i/--info`,
  `completions`, and `unblock` (the unstrict duplicate) were already
  absent from the codebase — verified by grep, only historical
  changelog/migration records mention them. Typing `man` now exits 2
  with an unrecognized-subcommand error.

### Changed

- **feat: monitors are always live, quit with q (NIGHT-hunt-12)** —
  `observe` and `top` no longer carry `--live`/`--duration` timers: the
  box refreshes until the user quits, and top's former 10s snapshot mode
  is gone (one presentation, the live box; `TopMode` enum removed and
  `render_top_table` now takes the interval directly). The quit contract
  changed to q/Ctrl+C — the ESC quit is removed because a standalone ESC
  byte is indistinguishable from the head of every escape sequence
  (arrows, mouse, scroll), which made stray sequences a coin flip;
  title-bar hints and every doc now read "q quit". Removed flags fail as
  unknown arguments (exit 2), pinned by integration tests.

### Safety

- **fix: `--check-update` refuses to run as root** — the update check
  shells out to curl for a GitHub release tag, so `sudo zelynic
  --check-update` was a privileged network round-trip that bought
  nothing (curl inherits root's environment wholesale, and any future
  download step would plant root-owned files in the invoking user's
  home). euid 0 now exits with a branded error and a "re-run without
  sudo" tip before any network I/O happens (NIGHT-hunt-11). The full
  command-by-command privilege matrix is documented in
  docs/SAFETY_ANALYSIS.md: eBPF surfaces keep the inverse guard (fail
  fast with the sudo tip before touching BPF state), `--help`/`-V`/
  `man`/`doctor`/`list-apps` stay uid-agnostic pure-read surfaces, and
  the one network surface refuses root outright.

### Release Engineering

- **ci: pre-release channel contract** — release tags are validated in a
  fail-fast `validate` job before any build cost. Stable releases use plain
  `vX.Y.Z`; pre-release builds are restricted to the `dev`, `nightly`,
  `alpha`, and `beta` channels (e.g. `v11.0.0-dev.1`). Any other suffix
  (including the old `-stable.N` format) fails validation and no binary is
  built. Pre-releases now carry a "(Pre-Release)" title, never inherit the
  "latest" marker, and their changelog body spans from the previous build;
  stable bodies still span from the previous stable release.

- **docs: API stability contract is v11** — the README, CONTRIBUTING, and
  living architecture docs now state the stable-API and maintenance-mode
  contract from v11.0.0, matching the v11 line under
  development; the README documents the release-channel contract.

### CLI

- **feat: unstrict family completion + strict shorthand**
  (NIGHT-hunt-10) — `strict` is now the bare-verb shorthand for
  `strict-single` (the owner's `zelynic strict brave` used to die with
  "unrecognized subcommand 'strict'"), `unstrict-single` is the alias
  that mirrors the strict-single/strict-multi naming pair, and the new
  `unstrict-multi <a:b:c>` removes limits from several apps in one shot
  with strict-multi's colon syntax — bulk removal no longer needs
  repeated single calls or the unstrict-all sledgehammer. A colon list
  typed into the single-target slot now gets a routing tip
  ("colon-separated lists belong to strict-multi") instead of a bare
  no-match. --help and the man page document all three; the help/man
  drift pins grow from 15 to 18 commands.

- **fix: cgroup labels are majority-voted, not first-pid-wins**
  (NIGHT-hunt-10) — the identity walk named each cgroup after
  whichever process the /proc readdir happened to serve first, so a
  lone chrome_crashpad labeled the cgroup whose other ~30 processes
  were all brave. status showed the browser's actual traffic carrier
  as "cg:18526 (chrome_crashpad)"; `unstrict 18526` then silently
  removed brave's enforcement while the owner believed only a crash
  handler had been freed — the "limit not works" report. The
  representative is now the comm hosting the most live processes
  (ties break to the lowest PID; unreadable comms never outvote real
  ones; a fully-unreadable cgroup keeps the raw cg:{id} fallback so
  recover() still sees it alive). Same walk, one pass, still 10s TTL.

- **fix: unstrict counts policies, matching strict** — the apply side
  reported "4 policies" for a two-cgroup/two-direction limit while the
  remove side said "Removed 1 limit" for the same state (cgroups vs
  policies). Both sides now count policies (dl and ul each). When a
  name-based unstrict removes nothing while other policies are still
  live, a note points at `status` (lists them) and `recover` (removes
  dead-cgroup orphans) — the exact trap behind the owner's leftover
  limit confusion.

- **feat: single-tier help surface** — `--help-all` merged into `--help`
  (NIGHT-improve-3, cosmostrix v30-simplify lineage). `zelynic --help`,
  `zelynic -h`, and bare `zelynic` now print the one end-to-end reference
  (usage, commands, flags, rate/target formats, safety, examples). clap's
  auto-generated help flag, `-h`, and `help` subcommand are disabled at
  every level: `zelynic strict-single brave --help` (and any
  subcommand-position help) is a usage error that exits 2 with a tip
  pointing at `zelynic --help`; the removed `--help-all` flag gets the
  same guidance. Errors keep exactly one canonical
  "For more information, try '--help'." footer — now appended by the CLI
  UX bridge itself (clap can no longer render it without an
  ArgAction::Help argument), byte-identical to clap's own format.

- **fix: `zelynic man` existed in the release pipeline only** — release.yml
  has piped `zelynic man` into `man/zelynic.1` since the beginning, but
  the subcommand never existed and the swallowed failure shipped an empty
  gzipped man page in every tarball. The command now emits a real troff
  man page (NAME, SYNOPSIS, COMMANDS, GLOBAL FLAGS, RATE/TARGET FORMATS,
  SAFETY, EXAMPLES, SEE ALSO) from the same single help authority, and
  the release steps no longer swallow man-generation failures. Both
  outputs are drift-pinned by integration tests covering the full command
  set.

### Diagnostics

- **feat: `-v/--verbose` is a real diagnostic surface** (NIGHT-hunt-9) —
  audit verdict: the flag was not a pure gimmick (the BPF lifecycle lines
  were real), but it was silent on the exact questions debugging asks. It
  now traces: `/proc` target resolution (`[limiter] 'brave' resolved:
  cg:73386 (3 pids)` — the multi-pid-per-cgroup evidence behind the
  NIGHT-hunt-8 alacritty/curl confusion, plus a list-apps tip when
  nothing matches), every policy write (`cg:73386 download → 100.0 KB/s
  (burst 100.0 KB)`; `BLOCKED` for block commands, shared-bucket writes
  included), the attach strategy (`bpf_link supported — programs + links
  pinned (survive exit)` vs the pre-5.7 legacy leak path), the observer
  loader trace for observe/top (previously hard-quiet), and the pin-file
  listing in unstrict-all (previously the flag was discarded there).
  Trace goes to stderr only, so `--print-json` output stays clean; all
  wording is unit-pinned by drift tests. `--help` and `man` now describe
  the flag as what it is instead of "Debug output".

- **feat: `--help` groups commands by verb** (NIGHT-improve-5) — the
  Commands section now scans as six chunks instead of a flat 15-entry
  wall: `strict — apply rate limits` (strict-single, strict-multi),
  `limit — bulk rate limits` (limit-all), `block — cut internet access`
  (block-single, block-multi, block-all), `unstrict — remove limits &
  recover` (unstrict, unstrict-all, recover), `monitor — traffic
  visibility` (status, list-apps, observe, top), and `system — support`
  (doctor, man). Group headings render in the same brand purple as
  section headings; each synopsis sits on its own line with the
  description and examples indented below, replacing the former
  120-character mixed syntax+description lines. The man page mirrors
  the grouping with `.SS` subsections. All 15 commands, flags, and
  examples are unchanged in content; a new integration drift test pins
  the six group headings in both renderers.

