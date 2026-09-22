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

- **scripts: NIGHT-hunt-21 — the duplicate/hardcoded-verbose hunt**
  — five real findings, all fixed: (1) bootstrap-ebpf.sh printed
  its status report TWICE on a satisfied re-run (the install-mode
  flow reported before installing and again after the unconditional
  re-probe — "verify, then trust" had degenerated into duplicate
  output when there was nothing to verify); the re-probe + report
  now runs only when the run actually installed or repaired
  something (CHANGED tracking), verified live in a satisfied
  environment: one report, then sanity, then the build; (2) the
  bpf-linker version pin was a twin constant ("must mirror"
  comment, the documented drift class) between bootstrap-ebpf.sh
  and install-bpf-linker.sh — the pin now lives in
  install-bpf-linker.sh alone and bootstrap READS it (sed anchor
  on the exact assignment line, dies loudly if unreadable), the
  same read-from-source pattern the nightly pin already had;
  (3) the supermassive banner repeated the cgroup fleet mode
  byte-for-byte two lines above the environment block's
  "cgroups:" row (visible in the owner's pasted run), and
  limiter-depth's banner repeated its MODE the same way — the
  banners now carry only their unique facts, the env block owns
  the environment; (4) install-bpf-linker.sh hard-required the
  zstd binary (dying on Arch/Fedora/Nix hosts without it) while
  its sibling bootstrap-ebpf.sh has a three-way extraction ladder
  — the ladder is now mirrored (GNU tar --zstd, then python3
  zstandard, then explicit failure), and the apt install became
  best-effort; (5) the three colored root-run harnesses
  (crash-recovery, race-condition, reload) carried three drifting
  copies of the same helper block — and every color variable in
  all three was truncated to a bare ESC ('\033' with the CSI
  parameters lost), so each "colored" line ever printed carried a
  stray escape byte and no color, while check_root/check_binary
  error wording had already diverged between copies; the helpers
  (colors, counters, log_pass/log_fail/log_test, check_root,
  check_binary, BINARY resolution) now live in
  scripts/harness_lib.sh, sourced — the bash twin of
  zelynic_harness_lib.py (no shebang, 644 rule), with proper full
  color codes restored and the richest error wording unified;
  cleanup() stays harness-owned (script-specific teardown). The
  gate's shellcheck section now runs with -x so the sourced lib is
  checked in the harnesses' context too. All 29 .sh files
  bash -n + shellcheck -x + shfmt clean; bootstrap verified live;
  ruff + py_compile green on both touched harnesses.

- **ci: NIGHT-improve-13 — gate-keepers wholesale workflow split +
  python lint gate + CI consolidation (cosmostrix lineage)** — the
  reference project's strongest CI pattern applied end to end:
  (1) gate-keepers.sh gained section 15, python lint + format
  (ruff): ruff check with an EXPLICIT rule set (E4/E7/E9/F/I in
  .ruff.toml — never ruff's implicit defaults, which expand between
  releases; pinned findings only, the NIGHT-hunt-20 tool
  philosophy) plus ruff format --check at line-length 100, the
  scripts/ house style; the tree was brought under the gate — 3
  unused imports removed, a dead counter init removed, an
  ambiguous `l` comprehension variable renamed, 3 import blocks
  sorted, and 5 files canonicalized by ruff format (mechanical,
  the shfmt -w precedent); the supermassive self-test re-verified
  15/15 after the reformat; (2) the wholesale gatekeepers job
  moved out of ci.yml into its own UNFILTERED workflow
  (gate-keepers.yml, runs on every push and PR regardless of
  paths): a docs-only or workflow-only change never skips the
  gates that police it — the shell triad's section 12 (ebpf
  rustfmt) CI mirror therefore runs on exactly the same trigger
  set as before; (3) duplicated CI functions removed: docs-ci.yml
  deleted (its codespell-on-docs run is a strict subset of
  gate-keepers section 5, the cosmostrix "replaces the former
  docs-ci.yml" precedent), the ci.yml `changes` job deleted
  (fetch-depth: 0 full clone + a git-diff regex re-implementing
  GitHub's native paths filter — the surviving build/test jobs now
  carry the path filter directly, the cosmostrix
  NIGHT-enhanced-hunt-E precedent), and ebpf-build's "Check eBPF
  Rust formatting" step deleted (byte-identical duplicate of
  gate-keepers section 12 — one check, one place); (4) stability
  hardening across every workflow: workflow-level
  permissions: contents: read defaults where missing (ci.yml,
  release.yml, maintenance.yml), timeout-minutes on all ten jobs
  (5-45 by job weight, previously zero — a runaway job burned
  runner minutes silently), and concurrency cancel-in-progress on
  ci.yml + gate-keepers.yml (rapid pushes cancel the superseded
  run instead of queueing a duplicate full build). Docs synced:
  CONTRIBUTING's gate list (14 -> 15 sections, ruff entry, the
  wholesale workflow renamed), codeql.yml's gate reference.
  actionlint + yamllint clean on all six workflows; gate-keepers
  17/17 locally (first full ruff section execution).

- **render: improve-13 — the monitoring/status flagship style audit
  (compact, simple, elegant, precision), second pass over the SpaceX
  dashboard bar** — the first audit (precision tier) harmonized the
  formatter; this one audited the monitor/status surfaces as grids
  and found five real defects, all fixed with pins: (1) observe's
  footer was a run-on lowercase line ("total down X up Y N packets
  N cgroups") whose numbers sat at arbitrary offsets under a grid
  whose entire point is column alignment — it is now a
  column-aligned TOTAL row (label cell TOTAL, sums under the exact
  DOWNLOAD/UPLOAD/RATE slots they total, aggregate rate included)
  plus one bullet-separated meta line ("N packets · N cgroups");
  top gained the same TOTAL row over its existing packets line,
  with the footer-honesty contract (sums count every talker, not
  just the rows shown) preserved; (2) format_bytes tier-boundary
  promotion — a value that rounds to 1000.0 of its unit now renders
  in the next unit (999_950 B is "1.0 MB", never "1000.0 KB"): the
  four-digit cell was raggedness, AND "1000.0 KB/s" is 11 columns,
  which pushed the monitor's fixed 10-column RATE budget one column
  right exactly at the tier edge (integer threshold, no float
  boundary wobble); (3) the filtered monitor's "lifetime" row mixed
  horizons — per-poll download delta + lifetime upload — so the
  number shrank frame over frame on a 1s refresh; CgroupDelta
  gained ingress_total_bytes (the ingress map's cumulative counter,
  the exact twin of total_bytes) and lifetime now sums two lifetime
  counters, one horizon; (4) the status table was the last surface
  still packing two metrics per cell ("421 (1.4 MB)" in ALLOWED) —
  the render engine's own module docs ban per-cell packing; cells
  are now one metric (bytes; em dash for an absent direction
  policy), packets remain in --print-json; (5) top's "Limit it:"
  hint now renders in the documented suggestion tier (crystal
  white) instead of plain body text — the yellow arrow flags, the
  white line tells you what to do. list-apps' separator is computed
  from the same column widths as the table (the hardcoded 70
  overhung the 69-wide table by one). CHROME_LINES 7 -> 8 (one more
  chrome line buys totals that sit under their columns). Display-
  only plus one stats-field addition: no policy, enforcement, or
  kernel-map change; schema and JSON contracts untouched.

- **display: status/monitor style audit against the flagship bar —
  precision tier harmonized (one decimal everywhere, TB tier added,
  input-output unit symmetry)** — the audit walked every render
  surface (status table, observe, top) asking four questions:
  compact? simple? elegant? precise? The architecture already holds
  the owner's "boring but elegant flagship" contract — responsive
  degradation ladders (RATE drops before TOTAL, label absorbs the
  width), the 20-row firehose cap, honest footers (packets total
  counts every talker, not just the rows shown), right-aligned
  numerics, em-dash for absent policies, one TIOCGWINSZ probe per
  frame. Two precision defects were real: (1) the GB tier formatted
  with two decimals while KB/MB used one, so one aligned column
  could show "100.0 MB/s" above "1.00 GB/s" — significant-digit
  raggedness inside a single column; (2) there was no TB tier while
  the parser accepts 1tb (MAX_RATE = 1e12), so a max-rate policy set
  as `1tb` rendered back as "1000.00 GB/s" — the CLI spoke one unit
  and the status row answered in another. format_bytes now carries
  one decimal on every tier plus a TB tier; format_rate(1e12)
  renders "1.0 TB/s", the exact language the CLI accepts. New pins:
  the GB/GB-boundary/GB-exact/TB ladder, the input-output symmetry
  round-trip (parse "1tb" -> format "1.0 TB/s"), and the same
  contract mirrored in the harness engine's fmt_bps (its KB tier
  used one decimal while MB/GB used two — the opposite of the Rust
  side; verdict details are cross-read against status output, so
  the two surfaces now agree on digits and units). Display-only
  change: no policy, enforcement, or accounting path touched; the
  full suite (29 unit + 24 integration, fmt, clippy
  --all-features -D warnings with the nested eBPF build) is green.

- **harness: NIGHT-improve-12 — the supermassive stress now drives
  every limiter rate function: per-direction buckets, rate guards,
  and the dangerous-target blocklist** — the rocket-engine audit of
  the flagship harness asked one question per limiter function: is
  there a stage that makes THIS function run to depth and pass?
  Three families had no stage at all. New stages (both light and
  heavy): (1) download-only (-d 500kb) — the -u twin had a stage
  since the beginning, the -d flag never did: download bucket
  enforced in band, upload direction carries no policy row, kernel
  drop proof; (2) asymmetric -d 100kb -u 1mb — the exact flagship
  example printed in --help (`-d 1mb -u 500kb`) never had a test:
  both per-direction buckets measured in their own independent
  bands under ONE policy, status row pinned at 100000/1000000
  (no accounting row by design — the single status row's
  bytes_allowed spans both buckets, so the two band verdicts plus
  the drop proof carry the stage); (3) the rate-guard stage — five
  functions the CLI documents but nothing exercised: MIN_RATE
  refusal (999 -> "below minimum"), MAX_RATE refusal (2tb ->
  "above maximum"), the near-miss typo rescue (1MB -> tip suggests
  '1mb'), the dangerous-target blocklist (strict-single systemd
  1mb refused as "system process" without --force; the forced
  variant is deliberately NOT applied — it would limit the live
  machine's actual systemd, which is what the guard exists to
  stop), the plain-number parser branch (1000000 round-trips at
  full value through the status JSON), and the --allow-dangerous
  override (500 B/s applies with the warning, row 500/500). All
  refusals are fail-fast (argument validation fires before any
  privilege or BPF work). The rootless engine self-test gains the
  ladder-bounds pin (15 rows now): all 14 ladder rungs must sit
  inside the parser's MIN_RATE 1000 .. MAX_RATE 1e12 span, so a
  bounds drift is named in CI before a root run fails stage after
  stage for it. Engine self-test: 15/15 green locally; the new live
  stages run on the owner's root machine on the next
  supermassive-test invocation.

- **ci/build: NIGHT-improve-11 audit — release builds now --locked,
  ebpf-build gets a cache, the bpf-linker pin lives in one place**
  — the peak-stable pass over every workflow, .gitignore, and
  build.rs found the release pipeline carrying the repo's only two
  unlocked cargo builds: both release.yml binary builds (gnu +
  musl) resolved dependencies FRESH at tag time, silently
  overriding the committed lockfile exactly where reproducibility
  matters most — every other CI build already passed --locked.
  Both now build `--release --locked`. Speed: the ebpf-build
  matrix job (the one that compiles the BPF objects twice per
  push) had NO cache step at all, and the check/release/maintenance
  jobs cached only the root target/ while the nested eBPF build
  compiles into the detached crate's own ebpf/target tree — so the
  whole aya-ebpf chain rebuilt from scratch on every run of every
  job that touches --features ebpf or --all-features. ebpf/target
  is now in all four cache path lists (matrix key names the OS so
  ubuntu-22.04 and ubuntu-24.04 never cross-restore), and the
  ebpf-build job gained its own cache step. Consistency: the
  pinned bpf-linker 0.11.1 install block was byte-identical in
  four CI jobs — now one script (scripts/install-bpf-linker.sh,
  shellcheck/shfmt-gated like every other script, functionally
  tested locally: custom-prefix install, mkdir-on-demand, sudo
  only when the destination is not writable) called from all four
  call sites; scripts/bootstrap-ebpf.sh's richer local-user flow
  is deliberately untouched. Also: docs-ci.yml now uses the repo
  .codespellrc (its inline ignore list had silently diverged from
  the gate's — a latent docs-only red), codeql.yml's push/PR path
  filters dropped the scripts/** and root '*.py'/'*.sh' entries
  that only woke a rust-language scan on tooling-only diffs, and
  .gitignore learns dist/ (the release-artifact staging directory
  that materializes when the release flow runs outside CI).
  build.rs itself: audited, zero changes — the NIGHT-hunt-27/28/29
  hardening (preflight, poison-flag stripping, ELF validation,
  self-heal, 13-test standalone suite) is already peak-stable.

- **security: NIGHT-hunt-20 expert supply-chain audit — crates clean,
  the real exposure was CI actions, now SHA-pinned** — the crate set
  survives an attack-surface audit untouched: every one of the 7
  direct dependencies carries live call sites (independently
  re-verified: clap 12 sites, anyhow 42, aya 19, nix 13, libc 14,
  serde 3, serde_json 8), `cargo audit` 0.22.2 over both lockfiles
  (root 54 crates, ebpf 31) exits zero against 1258 loaded RustSec
  advisories, `cargo deny` reports advisories/bans/licenses/sources
  all ok, aya's default feature set is empty (nothing left to trim),
  and the 4 root-lock entries unreachable on Linux are
  Windows-target-gated (never downloaded or compiled here). What the
  audit exposed instead: (1) the ebpf crate carries a 10-crate
  build-time-execution chain (aya-build, pulled as a
  build-dependency by aya-ebpf-bindings/aya-ebpf-cty — upstream
  framework design, now documented as the accepted risk to watch
  first on every aya release), and (2) the actual attack vector with
  repo write access was never Cargo.toml — it was the 11 references
  to the mutable `dtolnay/rust-toolchain@stable` branch (a personal
  account) including inside the maintenance job that holds a
  `contents: write` token. Every workflow action is now SHA-pinned
  (dtolnay, Swatinem/rust-cache, softprops/action-gh-release, and
  all actions/checkout, cache, upload-artifact, download-artifact
  references; codeql.yml's checkout aligned from the v6 outlier to
  the v5 pin used everywhere else), with one deliberate documented
  exception: github/codeql-action stays on its moving v4 tag because
  pinning it would freeze the security scanner itself. CI-installed
  scanner binaries are now version-pinned too (cargo-deny 0.20.2,
  cargo-audit 0.22.2, codespell 2.4.3) — the RustSec database still
  refreshes every run, so red always means a new advisory, never a
  new scanner release. Full evidence trail recorded in
  docs/DEPENDENCY_AUDIT.md.

- **gates: wholesale CI mirror — the NIGHT-hunt-23 rot class closed
  permanently (owner-approved)** — CI mirrored only a hand-picked
  subset of gate-keepers sections as individually wired steps (shfmt,
  codespell, language, plus yamllint/actionlint under workflow lint);
  the rest (bash -n, shellcheck, TOML validation, SPDX headers,
  permissions, emoji, LOC, version sync, disclaimer, test-tree) ran
  nowhere on GitHub. That incremental-mirror pattern was itself the
  bug: every new gate needed a manual CI wiring step nobody
  remembered to add, so gates silently existed only on machines
  where the tools happened to be installed. The workflow_quality job
  is replaced by a single gatekeepers job that executes the ENTIRE
  scripts/gate-keepers.sh with the full pinned tool set (shellcheck
  v0.10.0, shfmt v3.10.0, yamllint 1.38.0, codespell 2.4.3,
  actionlint 1.7.7, plus the dated eBPF nightly for the rustfmt
  section): every current section — and every section added to the
  script from now on — runs on every push, no per-gate CI wiring
  ever again. Tool pins replace the unpinned `pip install` and
  `go install @latest` steps, so a red run always means the tree
  drifted, never that a linter released overnight. The local
  preflight (the first full 16-section execution in repo history —
  before it, shellcheck had never run anywhere) proved the class
  point before the job landed: shellcheck and shfmt both found real
  drift that every existing gate had missed, fixed in the same
  commit (an SC2016 disable comment on bootstrap-ebpf.sh's
  intentional literal .profile export line, plus the canonical
  `>>"$file"` redirect spacing the NIGHT-improve-16 patch had
  drifted).

- **gates: language discipline — the English-only rule gets a checker
  (NIGHT-hunt-19)** — the purge hunt itself came back clean: a
  twelve-dimension sweep (informal and formal Indonesian vocabulary,
  core particles, non-Latin scripts, fullwidth forms, Vietnamese
  diacritics, accented Latin, emoji blocks, unicode escape sequences,
  commit subjects and bodies) found zero non-English text in the
  living tree — every hit was the Gini coefficient metric name, an
  English idiom in quotes ("trust me bro", the documented "what the
  hell bro" Debian run), or intentional Unicode fixtures. The only
  real residue sits in the NIGHT-improve-1 commit body quoting the
  owner's mixed-language directive verbatim — frozen history, never
  rewritten (the same policy as the changelogs). What the hunt
  exposed instead is the enforcement gap: the emoji sweep (gate 8)
  blocks emoji codepoints, but nothing blocked non-Latin scripts or
  Indonesian prose — the English-only house rule had no checker. New
  scripts/check-language.sh (gate-keepers section 14, python3 stdlib
  only): a non-Latin script detector (CJK, kana, Hangul, Cyrillic,
  Greek, Arabic, Hebrew, Thai, Devanagari, Khmer, fullwidth forms,
  the zero-width joiner) where intentional Unicode coverage data
  self-declares via a `NON_LATIN_FIXTURE:` marker (the // LOC_EXEMPT
  discipline — no hardcoded allowlist, the exemption lives with the
  file), plus an Indonesian vocabulary detector: case-sensitive,
  word-bounded, a 141-word informal-register list curated for zero
  false positives on this tree (English-colliding words — gini the
  metric, label, bro as idiom, two-letter particles — deliberately
  excluded; no marker can exempt it, because fixtures are
  CJK/Cyrillic, never Indonesian). The three fixture carriers are
  now marked (identity sanitize CJK passthrough, terminal diff CJK
  double-width rows, the nonroot-depth-test Cyrillic invalid-rate
  case), and the gate is mirrored CI-side in the workflow_quality
  job (the NIGHT-hunt-23 lesson: a gate that only runs where tools
  are installed rots silently). Docs synced: RULES.md gains the
  Language Discipline section, CONTRIBUTING's gate inventory moves
  13 -> 14 sections plus a new coding standard. Verified: the gate
  passes the whole tree, and a spiked temp file (Indonesian line +
  unmarked CJK line) fails as designed before deletion. Gate/docs-
  only: no engine, CLI, schema, or map changes — no A/B benchmark
  (the same call as the other gates-only commits).

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

- **scripts: install/uninstall build pro-native and verify their
  postconditions (NIGHT-improve-15)** — the owner-directed audit of
  the install/uninstall pair, upgraded to the peak-stable contract.
  (1) install.sh source mode now builds through the canonical native
  alias (default `cargo pro-native-gnu --locked`; `--musl` opt-in for
  the static x86_64 build) instead of the plain
  `cargo build --release` — the binary lands at the profile's contract
  path (target/pro-native-gnu/ or
  target/x86_64-unknown-linux-musl/pro-native-musl/), never clobbers
  target/release/, and carries its build label in `-V`; `--musl`
  refuses on non-x86_64 hosts with the mirror-block pointer instead of
  cross-compiling a binary onto the wrong machine. (2) "built" now
  MEANS built: the post-build gate checks the binary exists at the
  contract path and answers `-V` as `zelynic: v...` before anything is
  installed; the pre-built path (a release-payload drop beside the
  script) gets the same `-V` gate and announces its no-build mode, so
  a damaged or foreign file fails at install time, not on the user's
  first command. (3) uninstall.sh clears kernel enforcement BEFORE
  removing files: when /sys/fs/bpf/zelynic still has pins it finds a
  zelynic binary and runs `unstrict-all` through it (escalating only
  in the sudo-sanctioned --system/--all modes; --user mode warns with
  the exact command and touches nothing), verifies the pin directory
  emptied, and prints the manual steps when no binary is left — the
  old order could delete the binary first and strand live limits in
  the kernel with no tool left to remove them. (4) every removal is
  verified gone afterwards and failures are counted into the exit
  status (a green run means clean); the legacy /tmp/zelynic.pid file
  is cleaned too, running instances are reported (they survive binary
  deletion and exit on their own), and the bootstrap host tools
  (bpf-linker in ~/.local/bin, the dated nightly pin) are deliberately
  left in place, named in the final note with their manual removal
  commands.

- **observer/connections: deep audit, four precision/harmony fixes
  (NIGHT-hunt-15)** — the owner-approved sweep of the whole monitor
  path (loader, connections, render, terminal loop, identity). (1)
  eagle-eyes UDP filter: /proc/net/udp reports state 07 (CLOSE) for
  connected AND unconnected sockets alike, so bound-only listeners
  (chronyd, systemd-resolved, mDNS) rendered as `udp 0.0.0.0:0`
  noise under their cgroup rows — displayable UDP now also requires
  a real remote (port != 0; a real endpoint never carries 0). Pinned
  by a chronyd-shape fixture whose expected detail output stays
  byte-identical. (2) top's "N packets total" footer counted only the
  rows the --limit/window budget could show — with 50 talkers at
  limit 10 the footer silently meant "the 10 shown"; it now sums
  every talker (unit-pinned: two talkers at limit 1 report both
  rows' packets). (3) parse_proc_net_line dropped a dead
  parse_endpoint(local) — the local endpoint was parsed, formatted,
  and discarded on every socket row (~thousands of allocations per
  3s refresh) with its Option ignored, so it never even validated the
  row. (4) TIOCGWINSZ consolidated: the same unsafe ioctl probe
  existed three times (limiter format.rs x2 through
  terminal_width/terminal_height, diff.rs once) — now ONE canonical
  probe in the ungated terminal layer (terminal/diff.rs::winsize)
  serves the limiter's terminal_width, the render engine's per-frame
  geometry (FrameGeometry::probe: 2 ioctls -> 1), and the diff
  engine's resize check; per-frame probes drop 3 -> 2. The now-dead
  terminal_height() was removed (zero call sites — the status table
  renders width-only), and SAFETY_ANALYSIS's unsafe inventory was
  re-synced to the new count (9 blocks + 4 aya::Pod markers).
  Audited and deliberately kept: the loader's saturating delta math
  and O(n<=1024) merge, the 3s/10s TTL refresh amortization, the
  deterministic sort ladders, the majority-vote identity and its
  canonical /proc boundary, the diff engine's run batching and
  tall-regime clip (all pinned by existing suites — peak for their
  scale; further change would be over-engineering). Verified: 174
  unit + 23 integration green with --features ebpf, fmt + clippy
  --all-targets --all-features -D warnings clean, gate-keepers 10/10.

- **help: the --help reference tells each example exactly once
  (NIGHT-hunt-15)** — the trailing Examples section repeated six of
  its nine entries verbatim from the per-command example lines the
  NIGHT-improve-5 grouping already carries (strict-single appeared
  three times on one screen, strict-multi/observe/top twice). The
  section now holds only the three workflows whose command blocks
  carry no example lines — status + jq scripting, recover, and the
  unstrict-all emergency reset — so the surface drops 143 -> 122
  lines with zero information lost (section headers, all 15 commands,
  verb grouping, and the pinned contracts untouched:
  test_help_lists_every_command still passes as-is). One stale
  example comment fixed in the same pass: "observe --interval 5s #
  calmer cadence + rate column" claimed the interval flag controls
  the RATE column — plan_observe_columns shows it is width-driven
  (>= 50 cols, verified); the interval only sets the cadence (and the
  RATE column's divisor).

- **docs: source-of-truth cross audit — twelve stale spots eliminated
  (NIGHT-hunt-15)** — every living-doc claim was re-verified against
  the code it describes (source code is the truth; the doc is wrong
  when they disagree). SAFETY_ANALYSIS: the "six audited unsafe
  blocks" inventory had drifted as later hunts added sites — recounted
  to the real ten blocks plus four aya::Pod marker impls (the missing
  three: the diff engine's one-write-per-frame libc::write, the
  doctor's two libc::statfs bpffs checks, and the second
  TIOCGWINSZ probe in the render layer). USAGE: limitation #5 said
  "both bounds overridable with --allow-dangerous (min)" —
  contradictory; rates.rs bypasses validate_rate for BOTH bounds under
  the flag, so the confusing "(min)" is gone. README: the "BSD/macOS
  source support OK" bullet contradicted the never-list and the FAQ
  two sections later — now "Linux-only at runtime, ebpf feature a
  no-op elsewhere". DRAGON_ARCHITECTURE: the observer prose claimed
  bpf_get_current_cgroup_id() (the task-context helper) where the
  program reads bpf_skb_cgroup_id() (socket-owner attribution), and
  described an egress-only observer where there are two programs and
  two counter maps; three serve-child-era roadmap rows told the dead
  child-process/watchdog-timeout story (reality: pinned maps +
  bpf_links, watchdog dormant and never armed); the future-policer
  rows pointed at bpf/policer.bpf.c, a path deleted with the C side —
  now the pure-Rust ebpf/src/bin location. SECURITY: the audit scope
  still listed the deleted `bpf/` directory. CONTRIBUTING: the project
  tree was missing limiter/reclaim.rs (NIGHT-improve-10) and
  ebpf/embedded.rs (NIGHT-hunt-29/30), and claimed "15 non-code
  gates" where gate-keepers.sh carries 13 sections. Verified clean and
  left alone: 57-name blocklist, 13 pin files, 1024/256 map
  capacities, 10s/3s identity/connection TTLs, 1kb..1tb parser span,
  7-deps/54-lockfile counts, brand color constants, NIGHT-label
  history in dated audit sections, and the deliberate "former C twin"
  provenance comments. Docs-only: no code, schema, or map changes.

- **supermassive-test: the 1gb rung's floor tracks the min-RTO cushion
  model (NIGHT-improve-15)** — the last heavy failure after 1e9fa80
  (ladder 1gb at 53.9% of configured, six-flow aggregate) was the same
  AIMD-under-a-dropper physics the improve-14 note mis-attributed to
  flow count: single-flow 55.7% vs six-flow 53.9% on the same machine —
  flow count is not the variable. default_burst banks "1 second of
  traffic, clamped 4KB-100MB" (format.rs); at 1gb the clamp leaves 0.1 s
  of tokens, and a cgroup policer DROPS instead of queueing —
  near-capacity flows burst-drain the cushion, lose whole 64 KiB
  loopback MSS at once (lo MTU 65536: one skb = one loss event), stall
  on Linux's 200 ms min-RTO, and the aggregate bottoms at
  cushion / min-RTO (~500 MB/s) while the cap is never exceeded and the
  drops + byte-accounting rows PASS on the same rung.
  `loopback_rate_floor` now returns that model — 0.0 below one GSO skb
  (unchanged), full band up to 100 MB/s (cushion still a full second),
  then cushion / min-RTO wherever the clamp binds (0.5 at 1gb) — the
  1gb row's note explains the physics, and the self-test pins the floor
  model rootlessly so a drift on either side (harness model or engine
  burst clamp) fails fast. The six-flow aggregate stays: six workers
  wanting ~4 GB/s yet landing at half of 1gb is the proof the shortfall
  is physics, not demand starvation. Real links (RTT in milliseconds)
  do not hit this regime; if near-capacity utilization ever matters on
  a real deployment the owner-side remedy is a default_burst cap bump
  (a schema-v6-sized change), not a harness fix. Harness-only: no eBPF,
  schema, or kernel-map changes.

- **supermassive-test: ladder rungs near the ceiling are measured as
  a 6-flow aggregate (NIGHT-improve-14)** — the heavy 1gb rung failed
  at 55.7% of configured on the 2026-09-21 nightpc run, but not from
  an enforcement miss: default_burst clamps at 100 MB, which at 100mb
  banks a full SECOND of tokens but at 1gb only 0.1 s, so every
  post-drop cwnd recovery dips below the refill rate and a single TCP
  flow through the dropper settles near half the configured rate
  without ever exceeding the cap — the kernel-drops and byte-
  accounting rows both PASSed on the same rung. Rungs at or above
  500 MB/s now run six concurrent python workers per window (the
  same one-worker-per-stream contract as curl burst and strict-multi)
  and the AGGREGATE carries the band verdict — staggered AIMD dips
  let it track the refill rate, restoring the row's meaning on any
  host whose baseline can feed the rung. Lower rungs keep the
  single-flow instrument.

- **docs: the cross-*.md duplicate-info sweep — every fact told
  once, in its canonical home (NIGHT-docs-8)** — the owner read the
  README and found usage info told twice and more: sections
  re-explaining what other sections (and other files) already said.
  Canonical homes are now explicit: USAGE.md owns command semantics,
  limitations, quit-key physics, troubleshooting; KERNEL_COMPATIBILITY
  owns requirements; VERIFY_RELEASE owns checksum commands;
  CROSS_DISTRO_RESULTS owns the validation record; CONTRIBUTING owns
  build/gates/standards; TRADEMARK owns fork policy; README owns the
  pitch, the feature table, the rate-format quick reference, the usage
  cheat block, and the branch table. Collapsed duplicates: README's
  limitations bullets (7 retold items -> one-breath summary +
  pointer), Safety Features (4 of 10 bullets re-told the feature
  table), Release Verification (three checksum commands -> one
  universal command + pointer), the dependency-policy bullets and the
  second Hinnant telling, Refresh Intervals + Inside-a-cgroup sections
  (merged into two-line pointers), Contributing gate-command block,
  and the fork-policy bullet list; CONTRIBUTING's build block and
  branch line, USAGE's maintainer's-map gate block and kernel-limit
  detail, KERNEL_COMPATIBILITY's test-coverage list,
  CROSS_DISTRO's future-runs paragraph, and src/RULES.md's re-told
  policy sections became pointers. Net -52 lines of retold prose (210
  deleted, 158 written, most of the insertions being the pointers
  themselves); line-level cross-file duplicate scan (excluding
  script-injected disclaimers and CHANGELOG history) is clean.

- **harnesses: every loopback stream is policed at exactly ONE hook,
  and a blocked connect is zero goodput instead of a harness kill
  (NIGHT-improve-12)** — the 2026-09-21 root run exposed three harness
  engine defects, all fixed in the shared lib + both twins. (1) The
  supermassive harness parked ITSELF inside target cgroup a, so the
  in-process traffic server shared the policed cgroup and every
  loopback download byte crossed a's egress hook (upload policy) AND
  its ingress hook (download policy) — the combined dl+ul stats map
  counted each byte twice and every "BPF accounting matches client
  bytes" row failed at ~200% (1359% at 1kb where headers dominate).
  The harness now lives in a sixth, never-policed zelynic-supermassive-hq
  cgroup while every measurement client — python workers and curls
  alike — is exec-moved into the target cgroup before its first socket
  exists; one stream, one policed hook, 1:1 accounting. (2) limiter-
  depth-test.py's rate stages apply -d-only policies for the same
  reason (its client and server are one process in one cgroup; the
  symmetric positional form stays covered by its policy-write stage).
  (3) A dropped SYN under block-* raised a bare TimeoutError out of
  create_connection and killed the harness at block-single — "harness
  error: timed out", every later stage unrecorded. Connect failures now
  return zero goodput in both twins, pinned by a new self-test check
  (6/6). Ladder rungs whose token bucket is smaller than one loopback
  GSO skb (rates below ~64 KB/s — 1kb/10kb) get a zero band floor and
  an accounting SKIP: under-delivery there is loopback physics, not an
  enforcement miss, and the kernel-drop proof carries the verdict.

- **harnesses: brutal-stress-test is renamed supermassive-test and
  the twin harnesses share one engine (NIGHT-improve-11 /
  security-4)** — scripts/brutal-stress-test.{sh,py} are now
  scripts/supermassive-test.{sh,py} (cgroup fleet renamed
  zelynic-supermassive-a..e to match; docs, README, CONTRIBUTING and
  both CI workflows swept). The fourteen engine helpers the two
  harnesses had copy-pasted — verdict recording, subprocess control,
  status-JSON reading, environment probes, binary resolution, band
  checks, doctor/dmesg stages, the final report — live once in
  scripts/zelynic_harness_lib.py and both import it. This is the
  drift-trap closer: the kernfs-inode fix (hunt-31) and the
  pro-native-gnu binary candidate each landed in one twin days
  before the other; now one fix lands in both the same day. The
  all-round scope also grows: the supermassive light mode exercises
  the human status table (a separate render path from the JSON
  every other stage consumes) while a limit is provably live.
  Engine self-test 5/5 at the time (6/6 since NIGHT-improve-12;
  python3 stdlib only, no root).

- **deps: full re-audit recorded — 7/7 direct dependencies live,
  nothing removable (NIGHT-improve-11 / security-4)** — the supply
  chain is already peak-lean after the 2026-09-18 hunt-6 audit
  (chrono dropped, nix features trimmed). The re-verified evidence
  per dependency, including a live check that clap's `suggestions`
  feature renders the subcommand tips, is recorded in
  docs/DEPENDENCY_AUDIT.md. Lockfile untouched; version policy stays
  owner-only.

- **schema: BPF schema version bumped v3 -> v4 (NIGHT-improve-10 /
  security-3)** — the enforcement-boundary sanitization changes no
  struct layout, but a pinned v3 program must not keep running the
  pre-hardening math: the existing mismatch path (unpin, reload,
  re-stamp) forces the swap on the first policy-writing command
  after upgrade. One-time cost, same as every prior schema bump:
  active limits are dropped — re-apply them once after upgrading
  (pins never survive reboot, so hosts that reboot skip the step
  entirely).

- **limiter: unstrict/recover touch three more maps than before
  (NIGHT-improve-10)** — cgroup_bucket_dl/ul and
  cgroup_limiter_stats now carry userspace delete paths for state
  reclamation (see the Fixed entry). The group bucket maps stay
  kernel-internal: their entries are shared by every cgroup of a
  strict-multi group.
- **monitor: the Shift+click hole is closed — a 100 ms selection
  guard rewrites the whole frame, so no terminal-side selection
  outlives one beat (NIGHT-improve-8)** — improve-7's pointer
  takeover left exactly one copy path open, the one the owner then
  hit: every mainstream terminal hands Shift-modified clicks to its
  own selection machinery, and no escape sequence can switch that
  off. The counter-physics is what `watch` has always relied on: a
  terminal clears a selection the moment its cells are rewritten.
  The monitor loop now runs a selection guard — on the TTY path
  only, never the pipe fallback (a pipe has no selection machinery,
  and the beats would only flood the benchmark harness and CI) —
  re-emitting the whole frame every 100 ms via
  `DiffScreen::force_repaint`: the shadow flipped back out plus
  `ever_drawn = false`, so the beat rides the exact same tested
  reset emission path a resize takes (HOME + erase-below + every
  row — which also erases below a short frame, killing selections
  there too). The beat is always WHOLE-frame on purpose: a partial
  rewrite would leave the unrewritten rows selectable, the owner's
  literal complaint ("still can copy some text"). The loop scheduler
  is a pure function (`next_beat`) so the contract pins hold it: a
  due render outranks a due guard (fresh content is also the
  strongest selection killer), the guard clock never resets on a
  render (a diff-only frame leaves the unchanged rows untouched —
  exactly the cells that must still die), and the beat value itself
  (100 ms — under the fastest deliberate human select-then-copy
  round trip of ~200 ms) is pinned like the ALT_ENTER bytes. Cost,
  quantified by the new diff pins: one whole-frame reset emission
  per beat (~1.4 KB on the classic 80x24 frame, ~14 KB/s while the
  box is live at 10 beats/s), zero effect on the render path (the
  A/B below). Honest physics boundaries, documented in USAGE and
  the module contract, not hidden: an X11-style terminal that
  mirrors a COMPLETED selection into the PRIMARY clipboard at
  button release can still catch what re-accumulates after the last
  beat, and a Select All + Copy fired inside a single beat lands
  before the next rewrite — both terminal-side, beyond any Linux
  application's reach. Verified: 164 unit + 23 integration green
  (8 new pins: six over the guard repaint engine — idle-path
  defeat, byte-identical reset stream, shadow-contract involution,
  beat idempotence, never-drawn no-op, tall-regime no-scroll — plus
  the beat value and the scheduler ordering; the six engine pins
  live in their own test/terminal/guard_tests.rs, #[path]-wired
  beside diff_tests after the block pushed that file past the
  500-LOC cap — one file per contract), gate-keepers 15/15,
  build.sh check-all green.

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

- **harness: the limit-all sleeper race closed with a residency
  barrier (NIGHT-improve-15 follow-up)** — the 2026-09-22 heavy run
  failed `limit-all --force: machine-wide sweep — fleet cgroup a row
  wrong: None`. Root cause: spawn_bg_in_cgroup was fire-and-forget,
  and limit-all walks /proc twice — the identity tally first, then
  the per-name resolution AFTER the BPF attach (a slow step: program
  load + pin). A bash sleeper caught between its `echo $$ >
  cgroup.procs` and its `exec` resolves as "bash" in the first walk
  and as nothing in the second (the exec finished meanwhile), so the
  fleet cgroups miss the machine-wide sweep entirely and the row
  check reports a mystery None. spawn_bg_in_cgroup now returns only
  once the child is provably resident (its pid appears in the
  target's cgroup.procs) AND settled (its /proc/<pid>/comm equals the
  final argv[0] basename, 15-char kernel truncation honored), with a
  5-second settle timeout, a dead-child short-circuit, and a kill on
  failure so nothing leaks. The sweep then refuses to run when any
  sleeper never settled, failing with a barrier-specific message
  instead of a mystery None row. Verified without root through a
  mock-cgroup harness: settle path 11 ms, dead-child path 10 ms, no
  leaks; the 17-check engine self-test stays green.

- **security: the update check's release tag is sanitized at the
  network boundary — the one terminal-injection surface the comm
  sanitizer did not cover (NIGHT-cybersecurity-2)** —
  `--check-update` prints the GitHub API's `tag_name` straight into
  the admin's terminal, and that string is untrusted network input:
  curl inherits the invoking user's proxy environment, so a MITM'd
  or compromised proxy response is in the threat model even over
  TLS (corporate proxies and stripped responses are real). The
  terminal-injection class is the exact one the repo already treats
  as a hard boundary on the /proc side (NIGHT-cybersecurity-1:
  OSC 52 clipboard rewrites, ANSI corruption, newline-forged
  output that impersonates zelynic's own verdict lines) — but the
  network boundary never got the same treatment: a forged
  `tag_name` reached `println_safe!` raw. The tag now passes
  `sanitize_comm` at the boundary (the same one-?-per-control-char
  contract, cross-module reuse), pinned by a forged-response unit
  test (OSC 52 payload + forged newline verdict, one ? each). The
  sanitizer itself relocated from the ebpf-gated identity module to
  the always-compiled output layer (src/output/sanitize.rs): the
  first push of this fix broke the CI "Lint & Test" job — the
  import resolved only under --features ebpf, and that job builds
  the default graph (the exact feature-graph trap the hunt-15
  terminal probe note warned about, caught by the runner minutes
  after push, fixed by the follow-up commit). Both feature graphs
  are now part of the local verification habit.
  The audit around it found the rest of the surfaces already
  closed, now verified and recorded in SECURITY.md's hardening
  posture: every /proc comm read flows through the single
  canonical `pid_comm` sanitizer (identity walk, connection walk,
  resolve_target match), /proc/net parsing is Option-based and
  panic-safe on malformed rows, cgroup paths are resolved by inode
  and never rendered (a hostile cgroup directory name cannot reach
  the screen), the lock file lives in the root-only 0700 /run
  directory with the world-writable-era /tmp path unlinked, the
  update check refuses euid 0 before any network I/O, and the eBPF
  map values are clamped at the kernel trust boundary
  (burst/tokens/frac — the schema-v6 triple, landed earlier
  tonight as depthbore-1's second half). 190 unit + 23 integration
  green, clippy -D warnings clean, gate-keepers 17/17.
- **limiter: the kernel-side enforcement math is now PROVABLE — and
  its last unclamped field is clamped (NIGHT-depthbore-1)** — two
  halves of one directive ("master peak high precision for limiter
  network"). (1) The refill arithmetic — fill-detect, fractional
  carry, cap, verdicts — moved out of the BPF program into
  ebpf/src/math.rs: pure `core`, zero aya dependencies, wired into
  the BPF object AND the userspace test tree via #[path], so the
  exact file the kernel runs is pinned by rootless unit tests
  (test/ebpf/limiter/math_tests.rs, 12 pins): fill-detect threshold
  equivalence (the branch is the overflow guard, not a behavior
  change — proven identical below, at, and above the threshold),
  the largest-legal-product corner at the MAX_ENFORCABLE_BURST
  bound (runs the multiply that would wrap if the guard ever
  regressed, under test overflow checks), long-run fractional
  exactness (1000 seconds at 7 B/s admits exactly 7000 bytes; a
  1,500,003 B/s second recovers every truncated byte — no 0.5-1%
  drift, which is frac_rem's documented reason to exist),
  steady-state exactness (one second at 1 MB/s admits exactly
  1,000,000 bytes, zero drops), conservation under 20k-event
  adversarial churn, drop-keeps-remainder (the silent-killer
  precision: refilled tokens survive a drop for the next smaller
  packet), and the elapsed cap's 1s bound. Before this, the
  sharpest arithmetic in the repo was testable only by root-run
  integration. (2) The extraction surfaced the real defect:
  `frac_rem` — the third persistent stored field of the bucket —
  was NEVER clamped. The v4 sanitization's own claim ("no stored
  map value can overflow the kernel arithmetic") was incomplete:
  burst and tokens were clamped, but a drifted or hostile
  frac_rem (any u64) could wrap `frac_rem + refill_frac` — silent
  garbage in the release BPF build, bounded to refill noise of ~1
  byte per packet by the burst cap, but a panic under the new test
  tree's overflow checks. Schema v6 sanitizes it on read (>= 1
  second of remainder is treated as the empty remainder — the
  same clamp-to-healthy-value contract), completing the
  burst/tokens/frac triple. No layout change; pinned v5 programs
  reload into the hardened object on the next policy write, the
  same one-time limit re-apply as every prior bump. SAFETY_ANALYSIS
  overflow audit extended; CONTRIBUTING module map updated;
  PERFORMANCE.md A/B recorded (all stream metrics 0.0% — the
  render path is untouched by construction; fps in the noise
  class, coupling explained). 189 unit + 23 integration green,
  clippy -D warnings clean, both-tree rustfmt exact, gate-keepers
  17/17.
- **harness: the two 2026-09-21 root-run rows that were ours, not the
  engine's — both fixed with the stage-measurement contracts they
  needed (2026-09-22 approved follow-up)** — (1) the asymmetric
  upload row tipped the band on bucket physics, not enforcement: a
  freshly attached bucket starts FULL (default_burst = 1 s of rate),
  so the first measured window after attach includes the whole
  cushion — rate * (1 + 1/window) = 1.33x at light's 3.0 s window vs
  1.25x at heavy's 4.0 s, straddling BAND_HI = 1.30 exactly where
  the run split (light "asymmetric upload 1mb 131.1%" FAIL, heavy
  the same stage 124.5% PASS — same engine, both under the bound;
  the cushion is engine contract, not over-delivery). The stage now
  drains the cushion into a discarded 0.5 s warm-up window before
  EACH measured direction (upload was the row that tipped, but the
  download row only stayed inside the band by AIMD luck — same
  physics): the measured windows see steady state, refill only, one
  band for both modes, and >30% is again a real over-delivery
  signal. (2) the overhead stage compared its single sample against
  the harness-START baseline measured minutes earlier — heavy filed
  "+30.0%" where light measured +2.1% on the same policy class:
  machine-load drift between harness start and the 20th stage, not
  policy cost. The stage is now PAIRED inside itself: a fresh
  baseline window (no policy live — the preceding stage ends
  clear_all() in both modes), then the non-binding 3x policy, then
  the measured window — seconds apart, same machine state; a 0 B/s
  fresh baseline now FAILs loudly (the improve-13 no-silent-zero
  rule) instead of dividing by silence, and the policy size follows
  the fresh rate, not the stale one. Two new rootless self-test rows
  pin both contracts by source (warm-up windows precede each
  measured window; the fresh baseline precedes the policy
  application — the improve-13 source-pin class), so a refactor
  cannot quietly drop either. Engine, eBPF, schema, and kernel maps
  untouched — harness-only, so no A/B benchmark (the
  NIGHT-improve-15 call).
- **harness + bootstrap: the one-click flow is real now — a checkout
  tests itself, never a stale distro install, and bootstrap ends
  ready to test (NIGHT-improve-16)** — the owner's 2026-09-21
  debian13 cross-distro run exposed both holes at once. Fresh clone
  there, build never succeeded (nightly pin missing, then bpf-linker
  off PATH), so every repo-local candidate was missing and
  resolve_binary fell through to `which zelynic` — a months-old
  /usr/bin/zelynic v4.0.0-alpha. The env banner PRINTED the wrong
  version and the harness ran anyway: 12 of 23 rows failed on decoy
  mismatches (v4 has no `block-single` subcommand, its 1 KB/s and
  1 GB/s rate guards reject v11 rungs, and the v4 status/doctor JSON
  has no rows the v11 schema expects) while the machine itself was
  perfectly healthy — every environment check green, cleanup clean,
  kernel 6.12.95 fully compatible. Three fixes, source of truth =
  the checkout: (1) resolve_binary's candidates are now ABSOLUTE and
  anchored at the repo root (CWD-independent), cover all four build
  outputs including the never-before-listed pro-native-musl path
  (target/x86_64-unknown-linux-musl/pro-native-musl/zelynic), and
  when several exist the NEWEST mtime wins — test what was just
  built, not what was built longest ago; (2) a version GATE: the
  resolved binary's `-V` token must equal the checkout's [package]
  version (parsed from Cargo.toml, stdlib-only) or resolution aborts
  BEFORE any test with the one-command fix — explicit
  --binary / ZELYNIC_BINARY choices pass the same gate: the harness
  tests THIS checkout, never a foreign one; (3) bootstrap-ebpf.sh now
  finishes the job it used to point at: it fixes its own session PATH
  (~/.cargo/bin + ~/.local/bin), persists the ~/.local/bin export to
  ~/.profile idempotently (fish/zsh login shells get told the exact
  line — they never read ~/.profile), and builds the flagship binary
  with the canonical `cargo pro-native-gnu`, printing the -V header
  as proof — re-running is incremental, seconds on an up-to-date
  tree. The whole flow is three commands: clone,
  `./scripts/bootstrap-ebpf.sh`, `sudo ./scripts/supermassive-test.sh`.
  Three new `--self-test` rows pin the gate rootlessly (both -V
  header shapes including the exact v4.0.0-alpha line, the
  repo-anchored candidate list, and stub binaries accepted/rejected
  end-to-end through the real resolve_binary — 14 rows total), plus
  a seven-scenario integration pass (debian13 trap refused, gnu
  over PATH, fresh musl over ancient gnu, CWD independence, env
  override honored and gated, one-command not-found advice). Engine
  and CLI untouched — harness/host-tooling only, so no A/B benchmark
  (the same call as NIGHT-improve-15).

- **limiter: blocked packets are now BOOKED into the stats map —
  block-* no longer kills every packet while reporting "0 packets
  dropped" (NIGHT-improve-14)** — the schema-v3 rate-0 verdict
  returned the drop BEFORE the stats lookup ever ran, so
  cgroup_limiter_stats stayed empty under block-single and
  block-multi: enforcement was total (zero goodput, the SYN never
  completes) yet completely invisible — `zelynic rates` and the
  supermassive "kernel drops engaged" proof both read zero. That row
  was the only light-mode failure and one of heavy's three on the
  2026-09-21 nightpc run (35P/1F light, 55P/3F heavy) after the
  improve-13 worker fixes landed. The block branch now runs the same
  packets_dropped/bytes_dropped accounting the enforce() drop branch
  keeps. BPF schema bumped v4 -> v5: the verdict is unchanged, but
  attach() reuses pinned programs while the pinned schema_version
  matches, so a live v4 pin would keep running the unbooked block
  path until unstrict — the bump forces the one-time reload (active
  limits are dropped once and re-applied, the same upgrade contract
  as the v3 -> v4 bump).

- **supermassive-test: the python worker clients were embedded in
  non-raw strings, so every root-mode rate row measured 0 B/s and the
  run died with "ValueError: embedded null byte" (NIGHT-improve-13)** —
  the NIGHT-improve-12 worker rewrite put its `python -c` client
  sources inside plain triple-quoted strings, so Python unescaped them
  at PARENT parse time and the children received corrupted source: the
  upload client's `\x00` blob escape became a literal NUL inside the
  argv — Popen refuses null bytes, which is the "harness error" that
  killed both light and heavy runs at the first upload stage and left
  every later stage unrecorded — and both clients' `\r\n` request-line
  escapes became real CR/LF inside the child's `b"..."` literals
  (SyntaxError, stderr on DEVNULL, stdout empty), which the discarded
  error half of `spawn_in_cgroup`'s return silently reported as a clean
  0 B/s in EVERY rate row — including a baseline "measurement ceiling"
  of 0 B/s that recorded PASS and, being falsy, silently defeated every
  "hardware ceiling" SKIP guard downstream (the owner's 2026-09-21
  nightpc run: 9P/7F light, 11P/18F heavy, all zeros, 3s/8s, one
  ValueError). Both constants are now RAW strings; worker failures are
  filed into a WORKER_FAULTS list printed above the verdict and in
  --json instead of reading as zero goodput; the baseline row FAILs
  when the engine itself moves no bytes; and the self-test gained four
  rootless pins — source-parse rows for both workers plus end-to-end
  worker rows that exec the real `python -c` argv — closing the
  rootless blind spot that let the improve-12 rewrite ship green.
  Harness-only change: no eBPF, kernel-map, or schema impact.

- **harnesses: the environment gate now checks the bpf FILESYSTEM
  MOUNT, not the zelynic pin directory — a fresh-but-healthy host
  no longer fails at the first gate (NIGHT-improve-11 / security-4)** —
  the check was labeled "BPF filesystem mounted" but tested
  os.path.isdir(/sys/fs/bpf/zelynic), the pin directory that only
  materializes after zelynic first attaches. On the owner's fresh
  nightpc (bpffs mounted, zelynic never run) the supermassive test
  died at "3 passed, 1 failed, 0s" having tested nothing — the
  "what the hell bro" run of 2026-09-21. Both harnesses now probe
  /proc/mounts for a bpf-type mount at /sys/fs/bpf (mirroring
  zelynic's own attach preflight, NIGHT-hunt-28), and the FAIL
  detail carries the one-line mount repair tip.

- **harnesses: repo-local builds now outrank the system PATH when
  resolving the zelynic binary (NIGHT-improve-11)** — the old order
  put `which zelynic` first, so a harness run from a fresh checkout
  tested the stale distro install (/usr/bin/zelynic) while the
  just-built target/pro-native-gnu/zelynic sat unused — the owner's
  2026-09-21 light run tested an old binary against a v11 working
  tree without knowing. Order now: --binary flag, ZELYNIC_BINARY
  env, repo-local candidates, PATH last; the env banner also prints
  the resolved binary's version line so a stale pick is visible at
  a glance.

- **limiter: the enforcement math is now total for ANY bytes the
  maps can hold — corrupt or drifted state can no longer overflow
  the kernel arithmetic (NIGHT-improve-10 / security-3)** — the
  refill math's overflow proofs (the NIGHT-cybersecurity-1
  fill-detect shape) were conditional on a contract only userspace
  enforced: burst <= 100 MB from `default_burst`. The maps are
  persistent kernel state that outlives every writer (pins survive
  process exit; the pin path is writable by any root process), so a
  `burst_bytes` of u64::MAX would wrap the fill-detect multiply and
  produce garbage enforcement — silent, verifier-invisible, and
  unobservable until a limit "doesn't feel right". Fix: the BPF
  program now clamps burst and tokens at the trust boundary to
  MAX_ENFORCABLE_BURST (u64::MAX / (2 * NS_PER_SEC) = 9,223,372,036
  — the exact mathematical ceiling under which every product the
  refill can form is representable); userspace write_policy applies
  the same mirror bound so the two halves can never disagree. The
  bound is pinned by value on both sides; the corrupt-adversary
  simulation test (u64::MAX burst + u64::MAX tokens + rates from 1
  to u64::MAX) asserts the math lands at burst, never garbage.
  Legitimate state is untouched: the userspace burst ceiling
  (100 MB) sits ~92x below the clamp, invisible for healthy input.
  Schema bumped v3 -> v4 (no layout change) so pinned v3 programs
  reload into the hardened object.

- **limiter: unstrict and recover now reclaim the per-cgroup bucket
  and stats entries a removal leaves behind — the 1024-slot maps
  stay proportional to live policies, not to history
  (NIGHT-improve-10)** — deleting a policy never deleted its bucket:
  on a long-lived host with container and session churn renumbering
  cgroup ids, the individual bucket maps marched toward 1024
  entries, at which point `get_bucket_ptr`'s insert starts failing
  and BPF silently returns UNLIMITED (fail-open by design — a full
  bookkeeping map must never brick the network, but that design
  turned "map full" into "limits stop applying" on exactly the LTS
  hosts that run longest). unstrict now deletes bucket entries per
  confirmed-gone direction and the stats entry when both directions
  are gone (ENOENT-only walks from crashed removals are reclaimed
  too); recover does the same for dead-cgroup orphans. Shared group
  buckets are deliberately untouched (no single removal may decide
  a strict-multi group's lifecycle). Failures warn, never fail the
  removal — reclamation is bookkeeping after the enforced contract
  is already gone.

- **CLI: `parse_time_duration` now rejects durations that overflow
  64-bit math instead of silently saturating to u64::MAX seconds
  (NIGHT-improve-10)** — `saturating_mul` returned ~585 billion
  years as a legitimate-looking value; every future consumer of the
  parser (watchdog arming, timeouts) would have treated overflow as
  infinity. Now the same contract as `parse_rate`: a hard error
  naming the overflow with the original input shown, never the
  saturated value. The only current consumer (monitor interval)
  already range-gated the value, so behavior there is unchanged.
- **harnesses: the cgroup ID was always the kernfs inode — the
  "cgroup.id file" never existed, and the brutal stress test now
  survives its first real machine (NIGHT-hunt-31)** — the owner's
  first live run of NIGHT-master-2 died at harness setup with
  "harness error: cgroup.id unreadable for the session cgroup"
  (0 passed, 0 failed, 0 skipped, 0s; the engine `--self-test` passed
  4/4 because the sandbox has no cgroup v2 — the resolution path was
  never exercised before the owner's box). Root cause: both python
  harnesses resolved cgroup IDs by reading a
  `/sys/fs/cgroup{path}/cgroup.id` file — a file that does not exist
  in ANY mainline kernel; the belief also lived in the Rust
  resolver's comments ("authoritative on kernel 5.13+") and seven
  documentation files. zelynic itself only worked because
  `cgroup_id_from_path` carried a `stat()` fallback under the phantom
  read; the harnesses copied the phantom without the fallback. The
  truth the kernel guarantees: `bpf_skb_cgroup_id()` returns
  `cgrp->kn->id`, and kernfs publishes that same node id as the
  directory's `st_ino` — `stat(2)` IS the resolution, and it is the
  numbering every verified kernel in the cross-distro matrix ran on.
  Fix: both harnesses (brutal-stress-test.py, limiter-depth-test.py)
  resolve IDs by `stat().st_ino & 0xFFFFFFFF` (the BPF maps' u32
  key), the Rust resolver drops the dead file read for the same
  one-line stat, and every phantom claim is gone from the docs
  (README, CONTRIBUTING, USAGE, SAFETY_ANALYSIS, DRAGON_ARCHITECTURE,
  KERNEL_COMPATIBILITY, CROSS_DISTRO_RESULTS — the kernel floor stays
  5.13+, now anchored on the real constraints: `bpf_link` 5.7+,
  observer events ringbuf 5.8+, 5.13 = oldest verified matrix kernel).
  Regression pins: the engine self-test creates a DECOY cgroup.id file
  and asserts the resolver still returns the inode (a phantom file
  can never win again), the same decoy pin exists as a Rust unit test,
  plus stat-equals-inode and missing-dir-is-None pins. En passant:
  limiter-depth-test.py's session fallback built its stat path with
  `os.path.join(CGROUP_ROOT, path)`, which silently DISCARDS the base
  on an absolute second argument (the fallback would have stat'ed a
  nonexistent path); the brutal harness also learns the owner's
  pro-native-gnu build dir as a zelynic-binary candidate.

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

- **release: the tarball is a flat three-file archive — the binary,
  the LICENSE, the README, nothing else (2026-09-22 owner directive,
  the cosmostrix release invariant)** — the v10-era tarball shipped a
  nested directory with install.sh, uninstall.sh, and eleven test/
  benchmark scripts alongside the binary. Two of those three groups
  stopped making sense in the v11 line: the pure-Rust eBPF objects
  are EMBEDDED in the binary (NIGHT-hunt-30's AlignedElf), so there
  is no BPF payload to install and no installer logic to run — and
  the harness scripts belong to the repo checkout they test (their
  resolve gate anchors to the checkout's Cargo.toml; a copied
  tarball copy can drift from the binary it validates). The
  packaging step now stages exactly `zelynic` + `README.md` +
  `LICENSE` at the archive root for BOTH variants (gnu and musl),
  with an invariant tripwire that fails the release if the tarball
  listing is not exactly those three entries — a future edit that
  adds a file or nesting cannot slip through silently. The checksum
  trio (SHA-512 + BLAKE2b-512 + SHAKE256) is unchanged and still
  records bare filenames for `sha512sum -c` at the download
  directory. README's install-from-release flow is now three lines
  (mkdir, tar -C, install -Dm755) with `rm` as the whole uninstall
  story; the source-build flow keeps scripts/install.sh +
  uninstall.sh in the repo, told once here. The bpf-linker confusion
  this directive answered: bpf-linker is a BUILD-time tool for
  source builds (it links the aya-ebpf objects that build.rs then
  embeds) — release users have never needed it and the flat tarball
  makes that visually obvious.
- **ci: all scheduled workflows run at the owner's morning — 00:00
  UTC (07:00 WIB), one clock for every cron (NIGHT-improve-9)** — the
  three scheduled triggers each kept their own clock: audit at
  `17 3 * * *` (03:17 UTC daily), CodeQL at `0 3 * * 1` (03:00 UTC
  Monday), and maintenance at `0 7 * * 1` (07:00 UTC Monday) — the
  last with a comment claiming "00:00 UTC (07:00 WIB)" that its own
  trigger contradicted by seven hours, the exact inconsistency behind
  the owner's "all consistency" call. Unified: every cron now fires at
  00:00 UTC = 07:00 WIB, the owner's morning (Asia/Jakarta, UTC+7);
  cadences untouched (audit daily, CodeQL and maintenance Monday);
  and each schedule comment names both clocks so the next reader
  never has to do the arithmetic.

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

- **docs: STABILITY.md — the nightly eBPF toolchain honestly
  documented as a quarantined limit (NIGHT-lts-1)** — the owner's
  question: the eBPF dependencies ride a nightly toolchain, which is
  unstable by nature; can zelynic still be production-stable, and can
  the project say so honestly? The answer is a new flagship doc plus
  a README section, both written to the "99% not perfect but useful"
  bar: (1) the layering contract — runtime needs only kernel 5.13+,
  cgroup v2, BPF fs, root, and the ONE self-contained binary (the
  eBPF objects are embedded at build time); release tarballs carry
  nothing else; building from source needs the stable 1.98.1 pin,
  the dated nightly-2026-09-18 pin (the eBPF objects only — the
  nested build in build.rs, fenced there precisely because aya-ebpf
  requires nightly feature gates), and bpf-linker 0.11.1, all
  installed by bootstrap-ebpf.sh. (2) Why the nightly is DATED, not
  floating: reproducibility — a regression cannot break every
  from-source build overnight, and the pin + linker form a validated,
  owner-bumped pair. (3) The LTS isolation contract: shipped binaries
  do not depend on any toolchain component continuing to exist —
  rustup, bpf-linker, or aya disappearing changes nothing for
  already-installed zelynic; the binary's lifetime is bounded by the
  kernels it runs on, and the embedded objects are identical across
  build profiles (NIGHT-hunt-28's rustflag stripping, now stated as
  an isolation property). (4) The honest-limit section, ranked:
  kernel verifier drift (mitigated by the cross-distro matrix +
  doctor preflight + loud cause-chained errors; fails closed, never
  silently), dated-nightly aging (bites from-source builds only,
  loudly, with the one-command repair), aya API evolution (minimal
  dependency surface, audited call sites), and measurement physics
  (GSO granularity and the min-RTO cushion — documented model
  limits, not toolchain). (5) A break-glass table: symptom → first
  command (doctor, recover, unstrict-all, bootstrap-ebpf.sh,
  uninstall's new enforcement-first guard). README's Limitations
  section gains "The nightly eBPF toolchain (honest)" pointing at
  the doc with the one-breath summary.

- **readme: usage deduplicated (NIGHT-docs-7)** — the owner read the
  README and saw the same usage data told twice: an annotated `### Usage`
  example block plus a `## Commands` syntax block, each command listed
  in both. Merged into ONE usage section where every command appears
  exactly once (flags live in `--help`, units in Rate Formats, workflows
  in docs/USAGE.md — each topic one home). Also deduplicated: the Quick
  Start teaser that re-stated three limitation rules verbatim (the
  honest-limitations section is the single home; the pointer stays),
  and the Safety Features min/max rate bullets that repeated the Rate
  Formats bounds (now one rate-bounds guard line linking there).

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
