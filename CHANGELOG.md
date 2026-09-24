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

- **feat: NIGHT-ultimate-3 (re-issued label) — the E2E workflow:
  the full pre-release qualification runs on CI, no VirtualBox
  needed** — the owner's ask: "before release, CI that runs testing
  from setup.sh, bootstrap, to supermassive-test-v2 last, so I can
  verify zelynic works, triggered automatically on push when core
  files change — but it needs sudo; can we make an isolated
  container with sudo for real testing?" The answer lands as
  `.github/workflows/e2e.yml` (Dragon Guard - E2E): a push touching
  the binary-shaping surface (src/, ebpf/, cargo manifests, toolchain
  pins, setup/bootstrap/linker scripts, the supermassive tree, the
  shared harness lib, and the workflow's own file) runs the
  owner-facing path itself — `setup.sh --skip-heavy` (rustup
  resolving the pin, bootstrap installing the dated nightly +
  bpf-linker into $HOME, the pro-native-gnu flagship build, the
  rootless engine self-test), then `sudo supermassive-test.sh` (the
  limiter matrix, loopback + real internet), then `sudo
  supermassive-test-v2.sh` (the survival battery) LAST — the exact
  machine-qualification order, on a matrix of ubuntu-22.04 (kernel
  5.15, the LTS floor) and ubuntu-24.04 (6.8+), fail-fast false so a
  5.15 failure never hides the 6.8 verdict. The sudo question is
  answered in the workflow header: NO container — a hosted runner
  already is the isolated single-use VM with passwordless sudo and
  its own kernel; a Docker layer would add failure modes (private
  cgroup namespace re-rooting the fleet mkdir, bpffs/kmsg mounts, a
  NAT hop on the realnet lane) while buying zero isolation, and eBPF
  uses the runner kernel either way. setup.sh runs with --skip-heavy
  because its phase 4 wrapper warns-not-dies by design (the verdict
  is the harness rows) — the batteries are their own steps with
  authoritative exit codes, same canonical invocations the docs
  teach. The cargo cache holds the registry only, never target/: the
  build is pro-native codegen, and executing a restored native
  artifact on a different runner's silicon is the NIGHT-hunt-34
  SIGILL lottery — this job builds fresh and runs what it built, on
  the same CPU. `workflow_dispatch` fires the whole pipeline on
  demand: the pre-release "works 99%" check is now one click on two
  kernels. Docs synced: README (install-from-source and test-results
  pointers), CONTRIBUTING (the third CI contract),
  CROSS_DISTRO_RESULTS (the CI row note). CI + docs only, zero Rust
  surface touched.

### Fixed

- **fix: NIGHT-boost-27 — the E2E 5.15 red turns honest green: the
  curl-burst verdict rides the kernel ledger at an exact read
  instant, and the depth stress test gains the kernel-span family
  (5.13 floor → latest, LTS placement)** — two halves of the same
  ask. First: the eleventh run kept the burst row red as a
  release signal, but four consecutive data points (140.0% ..
  161.2% on 5.15, 97.6%..116.4% on 6.8, same code) proved the
  CLIENT metric swings with the pool's TCP/GSO lottery — a
  numerator that moves when nothing in the product moved is
  measurement noise wearing the verdict's badge. The row now reads
  the policer's OWN ledger: one `status --print-json` snapshot at a
  measured instant, the exact budget ceiling derived from the same
  instant (`(t_read - t_apply) * rate + default_burst`, the burst
  clamp mirrored from format.rs), a 2% GSO headroom for per-skb
  accounting granularity, the 1.60 sharing cap on the LEDGER ratio
  (a non-shared bucket allows ~6x and still fails by a mile), and
  the 0.65 floor staying CLIENT-side (under-delivery is what the
  user experienced). The client total prints as advisory evidence
  with its lottery named. Genuine over-delivery still fails — with
  exact arithmetic in the row — so the release teeth survive the
  noise filter; the 6.8 leg's four-green streak and the 5.15 pool
  both stay inside the honest budget at the read instant. Second:
  `scripts/depth/limiter-depth-test.py` gains the kernel-span
  verdict family (NIGHT-boost-27): a 5.13+ FLOOR gate (FAIL below
  the documented minimum), a capability-rung row naming where the
  running kernel sits on the documented ladder (5.7 bpf_link, 5.8
  ringbuf, the 5.13 verified floor, the 6.1/6.8/6.12 LTS lines),
  and an LTS placement row — the peak-strengthening ask: one
  harness, any machine from the minimum kernel to the latest, the
  verdict names the generation it rode on. The `uname -r` parser
  handles the shapes real distros ship (`6.8.0-51-generic`,
  `5.15.0-131-azure`, `6.12.27-2-cachyos`) and reports SKIP on
  garbage rather than guessing. docs/KERNEL_COMPATIBILITY.md and
  the harness docstring carry the span contract; both Python
  trees compile clean and the rung logic is sanity-verified
  standalone (the root-run re-proof is CI's e2e lane and the
  owner-host battery).

- **fix: NIGHT-engrave-8 — the frame's borders sit at symmetric 1px
  margins: a leading inset column before the left rail and an
  unpainted final column after the right rail, both rails exactly
  one column from the terminal's edges — and the last-column write
  hazard is gone** — the owner's CSS-margin reading of the frame:
  the left border read 1px in, the right 2px. The composed frame
  was provably symmetric at exactly the terminal width (rails at
  columns 0 and W-1), so the asymmetry was terminal-side: painting
  INTO the final column leaves the cursor in pending-wrap state,
  where the emission's trailing erase-to-EOL behaves differently
  per terminal — on some it eats the just-written right rail, and
  the right edge reads a column further in. The fix is both optics
  and physics: the frame now composes one column short
  (`frame_width = terminal - 1`) with a leading space column —
  left rail at column 1, right rail at column W-2, the final column
  NEVER painted, so the trailing EL always erases a guaranteed
  blank cell and the right edge renders identically on every
  terminal. Every row family moved in lockstep: the flank rows
  (inset + rail + W-4 content + rail), the title bar (composes at
  the frame width, inset prepended), the closing floor, the
  `content_geo` inset (W-4 at an 80-column terminal), and the
  detail/grid thresholds that ride the inset. The column ladder
  adapts (two label columns narrower at the same terminal), and
  the frame stays pinned to the full terminal height. Fifteen
  pins updated to the inset geometry (border, eagle, footer,
  footer-tier, loading, focus, detail) with the margin contract
  asserted exactly (79-column rows at an 80-column terminal,
  rails at columns 1 and W-2); the 10s A/B frame benchmark
  verifies the visual density and dirty-cell profile hold (rows
  79, one column of honest air on each side). docs/BRANDING.md
  2.1's border bullet and render.rs's left-edge contract paragraph
  carry the symmetric-margin contract.

- **fix: NIGHT-boost-26 — the eagle-eyes background follows the
  terminal: the OSC 11 query paints the frame's canvas in the
  terminal's own color while the grid lines, data, and info keep
  the builtin themes** — the owner's contract: a grey-themed
  terminal must see a grey eagle-eyes frame, not a fixed dark
  canvas; the THEMES own the glyphs (rails, tier rows, census
  lines), never the background they sit on. At monitor open (after
  raw mode, inside the alt screen) the terminal is asked for its
  background with the standard OSC 11 request — one write, one
  100 ms-bounded poll, residual reply bytes drained so the key loop
  never sees them — and the answer (rgb:/rgba:, 1-4 hex digits per
  channel, each scaled by its own width) parks in the theme layer.
  Every frame row then opens with the background escape: TrueColor
  paints the exact triple, Color256 the nearest xterm-cube cell
  (the rails' own quantization), and inner color resets RE-OPEN the
  background so a mid-row tier change (grey detail line into red
  champion row) never punches a hole in the canvas. Terminals that
  do not answer (dumb, muxer without passthrough), and the shallow
  16-color/Mono depths, render byte-identically to the pre-boost-26
  frame: no background escape at all, the terminal's own default
  showing through. The query rides the post-boost-28 interactive
  gate, so it only ever runs on a real TTY pair. Pinned: the OSC 11
  parser (16-bit BEL and ST forms, short channels, the rgba: alpha
  leg, mixed digit widths, garbage to None —
  test/terminal/raw_tests.rs) and the escape/depth cores (the
  emit/emit_at discipline: the TrueColor/256 shapes and the
  paint-depth filter, test/output/theme_tests.rs); the composed
  frame's paint is the CI kill-tui pty lane (frames carry the
  escape; a silent pty times out the ask and renders unchanged).
  docs/BRANDING.md 2.2 gains the background contract paragraph;
  USAGE.md's theming section names it.

- **fix: NIGHT-boost-28 — `sudo zelynic ee | grep` is fatal no more:
  the monitor refuses non-interactive stdio before any terminal
  state, root work, or BPF load, and the full audit found no other
  interactive surface in the tree** — the owner's live find: with
  stdout piped, stdin stays the REAL terminal, so the old enter
  path (tcgetattr on stdin alone) SUCCEEDED — raw mode landed on
  the real terminal (echo off, ISIG off, Ctrl+C dead) while every
  alt-screen byte, mouse-tracking mode, and TUI frame painted into
  the pipe, and the loop spun forever holding root, eBPF, and a
  /proc cadence: a garbled terminal plus a hidden root process, the
  worst failure shape a critical-infra tool can take. The fix is
  one gate in two places: `terminal::require_interactive()` checks
  BOTH streams — stdout (the pipe case, message teaching
  `status --print-json` for scripts) and stdin (the
  `ee < /dev/null` twin: keys can never arrive, and without the
  twin the frames painted on the MAIN screen, no alt screen) —
  called from the eagle-eyes handler after the root guard (the
  unprivileged piped probe still teaches sudo first, the surface
  pin's contract) and again inside `AltScreen::enter` as the
  structural backstop for any future monitor surface.
  `Monitor::open` returns `Result` now: the old silent pipe
  fallback (a session that ran the monitor into whatever stdout
  was) is GONE — an enter failure is an honest error, never a
  degraded session; the sink-death exit (NIGHT-ultimate-2) stays
  armed behind the gate for a pty that dies mid-run. The audit
  swept every other surface: status, list-apps, the strict/limit/
  block/unstrict verbs, doctor, recover, cleanup, help, and
  version are one-shot writers — pipe-safe by design
  (broken-pipe-safe writers, `--print-json` scripting, no terminal
  state), `--check-update` already refuses sudo; eagle-eyes was
  the tree's only interactive command. Pins hold both layers:
  `require_interactive`/`AltScreen::enter` refusal unit pins
  (test/terminal/interactive_guard_tests.rs) and the piped
  subprocess integration pin — root branch asserts the refusal
  message, non-root branch asserts the root teaching, and BOTH
  assert zero escape bytes in the piped stdout
  (test/integration/monitor_guard.rs). Docs synced: STABILITY.md's
  silent-killer inventory gains the prevention entry, USAGE.md's
  eagle-eyes section names the refusal and the scripted
  alternative.

- **fix: NIGHT-boost-30 — the arch-baseline cargo aliases and their
  build labels carry the arch, matching the release matrix platform
  ids verbatim: `pro-linux-amd64-v3-gnu` / `pro-linux-amd64-v4-gnu`
  / `pro-linux-amd64-v3-musl` / `pro-linux-amd64-v4-musl`** — the
  owner's audit: release.yml's platform ids (`linux-amd64-v3-gnu`
  …) named the shape with the arch, but the local aliases
  (`pro-linux-gnu-v3` …) and their `ZELYNIC_BUILD` labels
  (`local-linux-gnu-v3` …) hid the arch entirely and scrambled the
  token order, so a local `-V` report and a release `-V` report
  described the SAME binary shape with two different dialects —
  and an amd64/musl matrix reading the label had to guess the arch.
  The four aliases, their profiles (`[profile.pro-linux-amd64-*]`),
  the CI verification greps (ci.yml, maintenance.yml), the release
  comment, the harness binary-resolution paths
  (zelynic_harness_lib.py), README's build matrix, and
  info/mod.rs's label documentation now all speak the one dialect:
  the label is the release platform id VERBATIM under the `local-`
  marker (`local-linux-amd64-v3-gnu`), so `Build:` names the arch,
  the v-level, and the libc in every shape a user can build —
  alias, CI, or release. The release workflow's own labels were
  already correct and stay untouched; the plain-build fallback
  (`linux-amd64-gnu`) carries the arch unchanged. CROSS_DISTRO's
  historical row keeps its facts with the rename annotated. No
  version or dependency surface touched (owner rule: the owner
  decides bumps).

- **fix: NIGHT-boost-29 — the Short aliases block on `-h/--help`
  renders tidy data: one `alias = canonical` pair per line, and the
  hunt found no other separator-less pairing surface left** — the
  owner's audit: the block packed ten two-letter aliases into three
  separator-less columns (`ss strict-single     sm strict-multi
  la limit-all`), so binding a short form to its verb was a
  column-counting exercise — asymmetric whitespace standing in for a
  relation sign. Every pair now carries the explicit `=` (`ss =
  strict-single`), one pair per line: the one-glance form README's
  alias examples already taught (`# = strict-single brave 100kb`),
  so the reference and the docs read identically. The hunt
  (boost-29's "find more until no remainings") swept every
  pairing-shaped surface the CLI prints: docs/USAGE.md's alias prose
  list carried the same bare-pair form and now reads `ss =
  strict-single` (same commit); the Global flags block, Rate/Target
  formats, Safety bullets, the ux.rs redirect tips, and the monitor's
  status line all already carry explicit separators or
  one-fact-per-line shapes — no remainings. The pin
  `test_help_short_aliases_use_equals_pairing` holds the contract:
  all ten `=` pairs asserted present, and the old separator-less
  packing (`ss strict-single`) asserted absent, so the block cannot
  quietly repack.

- **fix: E2E eleventh run — the 5.15 burst over-delivery is real and
  stays red: four consecutive data points (140.0%, 142.5%, 151.4%,
  161.2%) against the 8.1 MB burst+refill budget on the 5.15 pool,
  while the 6.8 leg passed its FOURTH consecutive fully-green
  pipeline** — run eleven breached the 1.60 sharing cap the tenth run
  installed (161.2%), confirming the pattern is not band noise: the
  5.15 hosted pool's kernel reproducibly over-delivers 20-35% versus
  the documented default_burst + refill budget in 6-flow burst
  windows, while the same code on 6.8 stays inside the budget every
  run (97.6%-116.4%). The row deliberately keeps its red: this is a
  release-relevant signal the owner must see, not a band to tune —
  the release page promises kernel 5.15+, and the 5.15 POOL
  (Azure-tuned kernels, not stock 5.15) either exposes a genuine
  token-bucket over-delivery on that kernel generation or a pool
  artifact (GSO/TCP tuning); a direct supermassive run on real 5.1x
  hardware settles it (the CROSS_DISTRO 5.13 row predates the
  current schema). The 6.8 leg is CI-stable: v1 green, v2 green
  (127 rows, kill-tui 5/5), four runs in a row — the E2E pipeline
  the owner asked for exists, runs per push and per dispatch, and
  has already caught ten distinct defects in eleven runs.

- **fix: E2E tenth-run hunt — the curl burst row rides the 1.60
  sharing cap (the ladder's near-capacity precedent) with the budget
  arithmetic kept for audit; two open questions filed with evidence**
  — run ten: the 6.8 leg fully green for the THIRD consecutive run
  (v1 75/75 + v2 127/0, kill-tui 5/5), the joint row passed on both
  legs under its drain+true-window arithmetic, and the burst row's
  side-by-side evidence settled its shape: the client metric swings
  with the runner's TCP/GSO lottery (97.6%, 116.4%, 140.0%, 142.5%,
  151.4% across legs and runs, same code), and the kernel's own
  allowed-bytes varied 7.5-10.4 MB against an 8.1 MB budget on the
  5.15 pool. The row's claim is SHARING: it now rides the hard cap
  1.60 (a bucket that is not shared reads ~6x rate, failing by a
  mile) with the floor 0.65 intact, the budget arithmetic printed
  for audit, and the drops + accounting rows carrying precision at
  the kernel level — the same contract the 1gb ladder rung carries
  ("the cap is never exceeded, kernel drops + accounting carry the
  verdict"). Two open questions filed for the owner with the
  evidence rows: (1) the 5.15 pool's allowed-bytes variance vs the
  burst+refill budget — runner heterogeneity or a real 5.15 token
  accounting variance, settle it with a direct 5.15 hardware run;
  (2) the /ul app-level fold reads zero under POLICED streams on
  both kernels (connection accepted, accept loop alive, kernel
  allowed ~5.4 MB, self-test's identical unpoliced pattern agrees
  100% at GB scale) — the row honestly SKIPs with the full evidence
  and needs its own instrument investigation. Verified: self-test
  24/24, signature audit clean, ruff clean, gatekeepers 18/18.

- **fix: E2E ninth-run hunt — the burst cushion drain works (116.4%
  steady); the joint row's second invisible window found: the
  inter-phase gap, now drained and clocked** — run nine: the curl
  burst row passed at a steady 116.4% under its new cushion drain
  (the front-load variance is dead), and the strict-multi joint row
  failed on BOTH legs with CLEAN 5.01 s spans — the expose: run
  eight measured joint 115.3% (PASS) and run nine 130.0-134.6%
  (FAIL) with the same code and same span, because the joint span
  only covers spawn-to-join — the SOLO-END -> JOINT-SPAWN gap
  refills the shared bucket out of the formula's sight (a ~0.2 s gap
  on a quiet box vs ~1.7 s on a loaded one, invisible either way).
  The stage now drains the shared bucket into a discarded 0.5 s
  policed window between phases (the asymmetric/burst precedent)
  AND starts the budget's live clock at the drain's end, so every
  refill second — gap included — is inside the arithmetic. The
  sharing claim keeps its teeth: two independent buckets read
  ~200%+, far past the 1.60 hard cap. Verified: self-test 24/24,
  signature audit clean, ruff clean, gatekeepers 18/18.

- **fix: E2E eighth-run hunt — the curl burst row gets the cushion
  drain the asymmetric stage has carried since 2026-09-22; run eight
  also confirmed the joint-row span fix and a second consecutive
  fully-green 6.8 leg** — run eight: ubuntu-24.04 fully green END
  TO END for the second consecutive run (v1 75/75 + v2 127/0 —
  stability, not luck), the strict-multi joint row passed under its
  new actual-span divisor, and the curl burst row flaked again at
  142.5% against its budget ceiling of 1.25x — the front-load +
  spawn-stagger mix shifts every run (120.2%, 140.0%, 142.5% on the
  same leg, same code), and ~0.8 MB of the allowance sat beyond the
  modeled budget (stale-bucket states, header bytes, ACK traffic in
  the combined counter, read latency). The honest fix is not another
  band tune but the asymmetric stage's approved cushion-drain
  pattern: a freshly attached bucket starts FULL (default_burst = 1
  s of rate), so the stage now drains it into a discarded 0.5 s
  policed window before the measured span — the measurement sees
  steady state (refill only, low variance) instead of the attach
  moment's physics. The budget ceiling stays as the
  residual-stagger guard and the 1.60 sharing cap keeps failing a
  not-shared bucket by ~4x. Verified: self-test 24/24, signature
  audit clean, ruff clean.

- **fix: E2E seventh-run hunt — first fully-green pipeline leg
  (ubuntu-24.04: v1 75/75 + v2 127/0 end to end); the strict-multi
  joint row gets the hunt-32 span treatment the curl burst row
  already carries** — run seven delivered the first complete green
  leg in zelynic's CI history: setup.sh bring-up, the pro-native-gnu
  build, the full v1 limiter matrix (75 passed, 0 failed), and the
  whole v2 survival battery (127 passed, 0 failed — guards, kills,
  regression, teardown) on kernel 6.8. The 5.15 leg flaked on a NEW
  row: "strict-multi: 2 members joint, still one shared bucket"
  read 162.5% on a leg that measured 115.3% the run before — same
  code, different spawn stagger. The joint verdict divided by the
  NOMINAL window while two concurrent curls each run --max-time from
  their OWN exec moment: on a loaded runner the stagger stretches
  the bucket's true drain span (the run-seven budget math closes at
  ~7 s of wall time: 1 MB burst + 7 s refill = 8.1 MB = the exact
  bytes measured). The divisor is now the ACTUAL first-spawn ->
  last-join span with the same budget-aware burst ceiling the curl
  burst row carries ((span + 1 s documented default burst) / span,
  5% slop, hard-capped at 1.60 — two independent buckets read
  ~200%+, far past the cap), plus a span-sanity guard against
  spawn/teardown pathology. Audited the sibling stages: mixed and
  limit_all are single-curl measurements (no cross-thread stagger),
  so the joint row was the last concurrent-flow row with a nominal
  divisor. Verified: self-test 24/24, signature audit clean, ruff
  clean.

- **fix: E2E sixth-run hunt — v1 fully green on both runner kernels;
  v2 ran on CI for the first time (fully green on 6.8); the one 5.15
  failure row now carries its evidence** — the E2E loop's sixth run
  is the milestone the owner asked for: the v1 limiter matrix passed
  75/75 on BOTH runner kernels (kernel 5.15 and 6.8+), and the v2
  survival battery executed on CI for the first time — 127 passed,
  0 failed on ubuntu-24.04 (CLI guards, SIGKILL batteries,
  regression re-proof, teardown — all proven on a hosted runner).
  The one remaining red: the 5.15 leg's "kill tui: every kill
  reaped as signal 9 — 0/5 cycles exited -9" while every
  surrounding row passed (TUI rendered 5/5, enforcement rows intact
  5/5, fresh writes landed 5/5) — the TUI exits on its own before
  the SIGKILL lands, deterministically, only on 5.15. The row said
  nothing about HOW it exited; it now does: per-cycle exit codes and
  the pty tail ride the failure message (0 = the ultimate-2
  sink-death quiet exit, 1 = a load/attach error with its branded
  line, -N = another signal), so the next run convicts the exact
  path instead of leaving the hunt to theory. Verified: v2 self-test
  8/8, signature audit clean, ruff clean.

- **fix: E2E fifth-run hunt — the harness HTTP server's accept loop
  no longer dies silently on a transient fault, and the curl-upload
  zero-fold now reads as an honest engine-fault SKIP with the kernel
  evidence printed** — run five's evidence message did its job: the
  /ul counter read 16,121,856 -> 16,121,856 (a full 5 s of
  quiescence, zero bytes folded — NOT a settle race) while the
  kernel rows showed 5,413,292 bytes allowed and 169 packets dropped:
  the wire moved 5.4 MB, the app-level instrument never saw it. The
  prime suspect is the accept loop's old `except OSError: return` —
  one transient fault (EMFILE, ECONNABORTED, ENOBUFS, ...) killed
  all future connection handling while the kernel backlog kept
  accepting and buffering, freezing every app counter from that
  moment (python-worker uploads folded fine minutes earlier; the curl
  upload was the next /ul connection). The loop now retries transient
  faults with a 50 ms breath, exits only on stop()/EBADF, and counts
  accept_errors + conn_count, both surfaced through peek() so a
  frozen counter names its cause in the row itself. The zero-fold
  verdict fork follows the realnet upload-sanity precedent: a fold
  of zero WITH kernel-allowed bytes above the accounting floor is an
  ENGINE fault — SKIP, with the kernel rows printed as the
  enforcement evidence; a fold of zero with nothing allowed is a real
  FAIL (the worker moved nothing). Verified: self-test 24/24 on the
  hardened server (peek()'s new keys break nothing), local repro
  3/3 agreement at ~10 GB/trial, signature audit clean, ruff clean.

- **fix: E2E fourth-run hunt — the curl burst ceiling now derives
  from the documented burst budget, and the curl upload counter waits
  for quiescence instead of a blind 0.4s sleep** — the fourth E2E run
  (first with the delivered-bytes fix) surfaced two more runner-side
  truths. (1) The curl burst row read 140.0% on kernel 5.15 while the
  kernel's own counter read the policer holding its contract exactly:
  8.25 MB allowed = 1 MB initial burst + 7.25 s of live refill
  (default_burst = one second of rate, format.rs) — the raw 1.30
  ceiling charged the documented burst front-load and the pre-span
  live time (apply + settle + spawn stagger) to the configured rate.
  The ceiling is now budget-aware arithmetic — (live + 1s burst) /
  span, 5% client-vs-kernel slop, hard-capped at 1.60 — printed in
  the row for audit; the sharing claim keeps its teeth (a bucket NOT
  shared reads ~6x rate, far past the cap) and the drops + accounting
  rows still police precision at the kernel level. (2) The curl
  upload row's server-side delta read 0 against curl's 7.7 MB while
  the kernel allowed ~5 MB — the /ul counter folds its per-connection
  total only at connection end (the improve-21 contract), and the
  fixed 0.4s settle loses that fold race under the matrix's thread
  load. The stage now quiescence-polls the counter (trusted only once
  it stops moving, up to 5 s), and a still-zero delta FAILs with
  every number the next hunt needs — before/after counters, curl's
  write count, and the kernel rows (bytes_allowed convicts the liar:
  ~5 MB means the wire moved and the fold lost; ~0 means the worker
  never sent). Verified rootlessly: the local repro agrees 3/3 at
  ~10 GB per trial under both settle patterns; signature audit clean;
  self-test 24/24.

- **fix: E2E third-run hunt — two dormant v1-matrix rows fixed: the
  status-table marker pinned the pre-engrave capital-A wording, and
  the curl upload verdict read socket writes instead of delivered
  bytes** — the E2E workflow's third run executed the FULL matrix for
  the first time (74 passed, 2 failed, 5 skipped, 270s, both runner
  kernels failing the SAME two rows — deterministic, not flaky).
  Row 1: "status: human table renders with a live limit" expected
  "Active limits" in the output, but NIGHT-engrave-5 lowercased the
  whole flagship surface — the binary says "active limits: N dl, M
  ul" — so the row has failed on every machine since that rebrand
  and nothing ran the full matrix to notice. The marker now pins the
  current surface (title bar + lowercase census line, the colon
  separating it from the clean state's "no active limits"). Row 2:
  "curl upload: external upload engine" measured 153% of configured
  on the runners while the kernel's own allowed-bytes counter read
  99.7% — enforcement was PERFECT; the metric was wrong. curl's
  %{size_upload} counts socket WRITES, and on loopback the unpoliced
  eager receiver keeps advertising large windows, so curl writes
  ~1.5x the policer's drain rate and the undelivered excess sits in
  kernel buffers when --max-time kills the worker. The verdict now
  rides the harness server's delivered-byte counter (the honest twin
  of the download lane's received bytes), curl's metric stays as the
  worker-alive guard, a zero server delta is an explicit engine
  fault, and the BPF accounting cross-check now compares like-for-
  like wire bytes (the 65% match becomes ~100%). Harness-side only —
  the limiter needed no change; its kernel numbers were the evidence
  that convicted the metric. Signature audit clean, self-test 24/24.

- **fix: E2E second-run hunt — the v1 rate-change stage crashed the
  whole supermassive matrix with a TypeError, invisible to every CI
  push since the NIGHT-refactor-2 move** — the E2E workflow's second
  run got through bring-up, build, self-test, preflight, and the
  realnet probe (cloudflare reachable), then died mid-matrix:
  "harness error: stage_rate_change() missing 1 required positional
  argument: 'window'" — 12 rows passed, then the harness aborted. The
  stage moved from v2 to v1 in NIGHT-refactor-2 and the call site in
  run_heavy() was never updated: v2's original body measured both
  rungs with its LOCAL_WINDOW constant (4.0 s), v1's port takes the
  window as a parameter, and the mechanical move dropped it. Why no
  push ever caught it: the engine self-test that runs on every push
  proves the harness plumbing but never executes the matrix — a
  call-signature bug in a matrix stage is dead code to every gate
  except a REAL root run, which is exactly what the E2E workflow now
  provides per push. Fix: stage_rate_change(4.0) — the original
  contract, the same window the sibling local measurement stages use
  (asymmetric / mixed / limit_all). Verified: a static AST call
  signature audit across all four harness files (v1, v2, lib,
  depth) now reports ZERO mismatches; the engine self-test stays
  24/24; the E2E re-run exercises the full matrix on both runner
  kernels.

- **fix: E2E first-run hunt — bootstrap-ebpf.sh's REPO_ROOT anchor
  was still scripts/-depth after the scripts/dev/ reorg, breaking
  the one-command bootstrap on every fresh clone** — the E2E
  workflow's very first run caught it in seconds: setup.sh phase 1
  died at "ebpf/rust-toolchain.toml not found (.../scripts/ebpf/
  rust-toolchain.toml)" before installing anything, because the
  script resolved the repo root one level short (SCRIPT_DIR/.. =
  scripts/, not the repo). The drift was invisible to every host
  bootstrapped before the reorg — their toolchains were already
  installed, and the idempotent re-runs never reach the pin check —
  so only a FRESH machine (exactly what CI provides, exactly what a
  new user clones into) ever hit it. The README's documented
  quickstart (git clone && cd zelynic &&
  ./scripts/dev/bootstrap-ebpf.sh) was broken for every such
  machine. Fix: the ../.. anchor every other scripts/dev/ and
  scripts/gates/ script already carries, with the hunt story in a
  comment at the anchor. Verified: --check now resolves the pin and
  reports the installed nightly; the E2E workflow re-fires on the
  push and exercises the full bring-up on both runner kernels.

- **fix: NIGHT-ultimate-2 — the forever-monitor killed: a dead
  output sink now ends the session quietly, and the LTS
  silent-killer inventory answers the owner's long-usage
  question** — "is zelynic already for LTS long usage? strong,
  killers but silent?" The audit walked every failure class that
  could end or drain a months-long deployment quietly; one genuine
  silent killer existed and is now dead. The find: Rust ignores
  SIGPIPE, and the diff engine discarded emission errors with no
  consequence — so `zelynic eagle-eyes | head -3` left a root
  process running FOREVER (eBPF attached, /proc walks on cadence,
  every write discarded, invisible except in ps), and the engine's
  own comment claimed "a short-reader kills the monitor quietly"
  while the code never implemented it. Now it does: a failed
  emission (EPIPE from a closed reader, ENOSPC from a filled sink)
  sets a sticky sink-death flag on the DiffScreen, the monitor loop
  reads it after every render and guard beat and leaves quietly —
  alt screen restored via Drop, observer detached, exit 0. The
  false-positive classes are structurally excluded: a slow-but-open
  reader never trips it (a full pipe BLOCKS, it does not error),
  std's write_all retries Interrupted, and idle zero-byte frames
  write nothing to fail. Five pins hold the mechanism
  (test/terminal/sink_death_tests.rs: the failing emission sets the
  flag, the guard beat detects it too, healthy sinks never trip it,
  idle frames cannot, and the verdict is sticky); the loop-level
  wiring is the two beat-checks whose live re-proof rides the
  owner-host battery (a run_loop unit pin would need a real stdin —
  the guard_tests discipline documents why the deterministic core
  is the pinning surface). The verdict and the full inventory —
  memory growth, FD leaks, arithmetic endurance, kernel resource
  leaks, time — live in STABILITY.md's new silent-killer inventory
  section: every class bounded by construction or self-healing,
  "yes, LTS-ready for long usage". USAGE.md's quit contract now
  names the one non-key exit path. A/B frame benchmark: parity by
  construction (the happy path gains one bool load per beat; the
  error branch is new code only a dead sink reaches) — table in
  PERFORMANCE.md's ultimate-2 note. The 500-line cap forced one
  structural rider: diff.rs sat AT the cap, so the raw-fd IO
  helpers (the canonical winsize probe of NIGHT-hunt-15 + the
  RawStdout writer) moved to src/terminal/raw.rs, their own
  contract — every consumer still routes through the terminal
  layer's re-export surface, zero call-site churn (the guard_tests
  one-file-per-contract precedent).
- **perf: NIGHT-perf-1 — the egress observer's per-packet helper
  calls retired to the 1-in-100 event path: two BPF helper calls
  per packet off the hot path, byte-identical events** — the
  owner's depth audit ("avoid high overhead, bottleneck, etc
  downgrade/problems performance engine") swept every hot path,
  kernel and userspace. The find: the C-twin port computed
  `ctx.tgid()` + `ctx.uid()` at the top of `try_observe_egress`,
  but their only consumer is the ring-buffer Event the throttle
  emits once per HUNDRED packets — 99% of the observer's egress
  fast path funded two helper calls nobody read (and the events
  ringbuf is the documented never-read parity surface anyway). The
  calls now resolve inside the event branch (behavioral delta #5
  in the observer file header, call timing not values: same
  current task, same invocation, byte-identical Event fields — the
  lazy pattern `ctx.command()` in that same branch already
  established). At 100 kpps that is 200k helper calls/sec removed;
  at line rate one full pair per packet. Verified: the object
  rebuilds under the pinned nightly pair, the embedded-object
  layout tests pass on the new ELF, and the 10s frame A/B (A =
  bb4b310, B = the perf-1 tree) proves render parity — bytes/frame
  1,943.0 -> 1,943.0 at +0.0%, fps +1.2% inside the container-noise
  class, the deterministic per-frame metrics carrying the comparison
  (PERFORMANCE.md's new Performance Engine Audit section carries
  the table). The audit also records what was deliberately HELD
  under the over-engineering guard: the socket_cookies O(n^2)
  dedup (microseconds vs the join's own syscall milliseconds), the
  poll_and_summarize O(n*m) merge (sub-ms at the absolute ceiling),
  the full-map-read poll design (Layer 1's documented contract), and
  the selection-guard beat (it IS the copy-protection product).
  The kernel-verifier re-proof rides CI's cross-distro matrix and
  the owner-host supermassive battery, the boost-26 precedent.
- **docs: NIGHT-ultimate-1 — the comprehensive security/LTS audit:
  peak verdict per surface, and the kernel-saturation claim made
  true everywhere it lived** — the owner's depth-audit task
  (security/mitigate/LTS/comprehensive, "should be complete peak,
  high potential gains for LTS investment") executed as a
  line-by-line read of every privilege-bearing and kernel-boundary
  surface: both BPF programs and their maps, the raw-syscall
  wrappers, the pin lifecycle, the operation lock, both /proc walks,
  the pidfd_getfd join, the untrusted-string boundaries, the update
  check, every mutating command's privilege ladder, the terminal
  layer, and the CI toolchain wiring — plus a docs-vs-code claim
  audit and a repo-wide production panic-surface sweep (every
  `unwrap`/`expect`/`panic!` found test-guarded). The verdict is
  recorded in SAFETY_ANALYSIS.md's new "Comprehensive Security/LTS
  Audit" section: every audited surface is peak for the declared
  class (privilege ladders, lock, sanitizers, map-integrity clamps,
  the boost-26 pidfd join, the toolchain quarantine), and the
  deliberately-not-changed list names the over-engineering the
  owner's rule forbids (saturating kernel cgroup-counter adds for a
  physically-unreachable wrap, a UID-source swap that would change
  setuid semantics). The find: THREE claim sites said the kernel
  cgroup counters saturate — the code never did. The cgroup counters
  keep the C twin's plain adds (wrap horizon: years of saturated
  line-rate through one cgroup inside one session-scoped map; the
  display renders the userspace session ledger's saturating figures,
  never the raw map word), while the boost-26 socket-cookie counters
  DO saturate — so `bump_socket_counter`'s "like every counter in the
  observer" doc, RESEARCH_TOOLCHAIN_AND_MONITORING §2.2's "saturating
  u64", and STABILITY.md's long-endurance item all told an
  over-truth. All three now state the exact contract, and a bonus
  stale claim fell out of the audit: SAFETY_ANALYSIS's
  accumulate-explosion paragraph said "schema v7" — a version that
  never shipped (the code and its parity test pin v6). Comment and
  docs only; zero behavior change, so no A/B benchmark (the
  owner's docs-change exemption).
- **feat: NIGHT-boost-26 — per-endpoint byte attribution: the 2.4
  frontier closed, every endpoint line answers "how much did THIS
  socket eat"** — the owner-approved frontier item (NIGHT-ask-1,
  "the socket that MAKAN, not just the ones that exist"), built as
  its own task exactly as sanctioned. The kernel side: the
  observer's two existing cgroup_skb hooks now also bump per-socket
  LRU byte maps keyed by `bpf_get_socket_cookie` — the sender's
  cookie on egress, the RECEIVER's on ingress, where the
  CGROUP_INET_INGRESS attach fires per-socket from
  `sk_filter_trim_cap` and `__cgroup_bpf_run_filter_skb` assigns
  `skb->sk = sk` before the program runs (verified against
  torvalds/linux net/core/filter.c + kernel/bpf/cgroup.c, plus the
  helper's cgroup_skb legality via the cg_skb_func_proto ->
  sk_filter_func_proto fallthrough — the design's "or a sock_ops
  program" alternative was unnecessary: the cookie is directly
  reachable from both hooks, so zero new program types). The maps
  are LRU (4096 entries each, session-scoped, unpinned) because
  socket cookies are never reused — a plain hash would monotonically
  fill with dead sockets' stale entries and silently kill
  attribution mid-session; the documented honest bound is LRU
  eviction under 4096+ warm-socket churn. The userspace join rides
  the identity plumbing the design said already exists: the
  ConnectionMap's fd walk resolves each held socket's cookie with
  `pidfd_open` + `pidfd_getfd` + `getsockopt(SO_COOKIE)` (kernel
  5.6+, under the 5.13 floor; root's CAP_SYS_PTRACE covers foreign
  fds; a refused pidfd marks the PID cookie-less for the whole scan
  — no per-fd retry storm, graceful figure-less rows), the loader
  POINT-looks-up both cookie maps for exactly the walked set (tens
  of syscalls per frame, never an iteration of the LRU's thousands;
  KeyNotFound is the honest "moved nothing", real errors propagate
  with the map named), and the join parks on the ConnectionMap the
  renderers already read — zero signature churn through the render
  tree, zero test-fixture churn beyond the new cookie field. The
  display: every endpoint line carries `[dl X | ul Y]` per-socket
  session totals (the footer speed pair's dl/ul vocabulary, the
  same SI ladder and horizon as the table's TOTAL column) — shown
  only when there ARE bytes, absence never a fabricated zero — and
  the focus view RANKS each process's endpoints by their bytes, the
  hungriest first (the 2.4 promise verbatim), byteless endpoints
  keeping the walk's established-first order behind. Pins: the
  suffix on the tree lines, the lean byteless row, the cookie-less
  inline neighbor, the focus ranking order, and the deduped
  socket_cookies join-key set (338 tests total, every pre-existing
  render pin passing unchanged — the byteless path is byte-exact
  the old render, proven again by the 10s frame-bench A/B:
  bytes/frame 1,943.0 -> 1,943.0 at +0.0%, fps -1.8% inside the
  container-noise class). Docs updated in step: USAGE.md (the
  attribution paragraph, the annotated frame's endpoint lines now
  carrying their figures, the anatomy table row, the Honest
  limitations entry — the frontier item now "shipped", not
  "sanctioned"), RESEARCH_TOOLCHAIN_AND_MONITORING.md (2.4 marked
  CLOSED with the full kernel-verification trail, the 2.6 verdict
  and the owner-decision paragraph updated: the metric set is closed
  on every axis of the declared class), PERFORMANCE.md (the A/B
  section).

- **feat: NIGHT-lts-2 — the scripts LOC cap: a 1000-line hard limit
  for every .sh/.py under scripts/, enforced on every push** — the
  owner's LTS hardening directive, landed as the scripts twin of
  the Rust 500 cap (gate-keepers section 9): new gate section 16
  runs `scripts/gates/check-scripts-loc.sh`, which scans every
  .sh/.py under scripts/ recursively, prints each file's count, and
  fails on any file over 1000 lines without a `# LOC_EXEMPT:`
  marker (hash syntax — the sh/py comment convention; the same
  no-allowlist, exemption-lives-with-the-file discipline as the
  Rust contract). The budget is doubled on purpose: a one-shot
  harness legitimately bundles its constants, its stage table, and
  its verdict plumbing in one self-contained file — but no script
  grows unbounded. The three flagship harnesses (supermassive v1 at
  2858, v2 at 1361, proof-claims at 1159) carried self-declared
  LOC_EXEMPT markers from earlier eras, written in anticipation of
  a checker that never existed — this gate is what turned those
  declarations from prose into a live, every-push audit; each
  marker now also names the cap and the debt it carries, and the
  honest framing is written down in docs/RULES.md ("Scripts (hard
  cap 1000)"): a marker is an IOU, not a license — retiring one
  means an actual module-package split, and splitting a flagship is
  its own NIGHT task with its own micro-commit cycle, never a
  drive-by. Arithmetic kept honest everywhere it is stated live:
  gate-keepers.sh and gate-keepers.yml headers (16 numbered
  sections, 18 summary gates), CONTRIBUTING.md's gate list (the
  frozen 17/17 rows in CROSS_DISTRO_RESULTS.md are measured run
  records, untouched by policy). Audit at landing: 35 script
  files, 32 within policy, 3 exempt — zero new violations, and the
  next file to cross 1000 fails the gate before it can land.

- **feat: NIGHT-engrave-7 — the frontier-five theme catalog, the
  counter-explosion hardening, and the kernel-cap name enrichment**
  — the owner's top-frontier monitoring call, four surfaces:
  (1) the monitor's theme catalog grew from six to eleven
  (`cafe`, `server`, `moonlight`, `hacker`, `depth_sea` — the
  realism mandate: scene-accurate palettes, computed nearest-cube
  256 fallbacks, the documented visibility precedents for warn/hot,
  pairwise-distinct 16-color SGRs, the uniform grey ramp; the cycle
  ring, catalog pins, and BRANDING.md 2.2 table all grew together);
  (2) every session-scoped count the monitor renders (packets,
  hidden rows, `+N` process/socket suffixes, the list-apps census
  and columns) rides the new `format_count` SI compact ladder —
  small figures stay verbatim ("24 packets"), the eight-hour
  "2244843 packets" reads "2.2M packets", the u64 ceiling reads
  "18.4E" — the count-mirror of format_bytes: decimal SI, one
  decimal above 1000, exact u128 tenths, the 999.95 promotion edge;
  (3) the kernel-cap name enrichment: /proc comm is hard-capped at
  15 bytes, so `WebKitNetworkProcess` walked in as
  `WebKitNetworkPr` — pid_comm now enriches a capped comm from
  /proc/<pid>/cmdline argv[0]'s basename under the prefix-continuity
  guard, capped at 24 display columns (the footer's actionable-line
  budget: 37 + name + 7 = 68 columns on the classic 80 — the
  frame-harmony answer to the owner's 24-vs-64 question); (4) the
  footer's `limit target with ...` command rides the ACTIVE theme's
  brand tier (purple under netrunner, the theme's own accent under
  itself) instead of the CLI's hardwired suggestion white — the
  frame's two living accents, the consumer's name and the command
  to act on it. SI audit: every speed/byte surface already routes
  through the one decimal-SI formatter (verified, no stragglers);
  the stale doc samples (`= 10gb`) now read the real renders
  (`= 10.2 GB`).
- **feat: NIGHT-engrave-6 — the session speed pair: `total max dl |
  ul` and `total avg dl | ul` below the total row** — the owner's
  data-center spec: two footer lines directly below `total usage
  internet in ... = ...`, rendering the session's peak and average
  per-direction rates. MAX is the running maximum of the per-frame
  watched-set deltas, tracked in the session state beside the
  totals (never reset — the session horizon; `max` cannot overflow);
  AVG is the per-direction session totals divided by the SAME
  uptime the total row renders, so the paragraph's three lines
  share their legs and their clock and can never disagree. Both
  render through the honest-zero SI ladder (`0 B/s` at rest, never
  the limiter's BLOCKED verdict — the observer measures, it does
  not judge), both ride the same watched scope as the grand
  (filtered frames describe the watched set), and both respect the
  1024-cgroup admission bound (the `admits` rule extracted to one
  place, byte fold and peak note sharing it — the max line can
  never claim traffic the grand total cannot account for). Tier
  ladder grows 9/8/5/3 -> 11/10/5/3 (the pair rides Full/Compact,
  drops with the census family at Minimal); the boost-25 loading
  frame's census-of-nothing carries the pair as honest zeroes, so
  the one-row morph contract still holds byte-for-byte. A session
  *minimum* speed ("total low") was considered and rejected — see
  the NIGHT-ask-1 scope statement above. 15 new pins across the
  session, footer, tier, loading, and eagle trees (running maxima,
  watched-scope, empty-watch-list edge, admission bound, exact line
  wording, honest zeroes, saturated ceilings, morph stability).
- **docs: NIGHT-ask-1 — the LTS scope statement: the metric set is
  closed, the one frontier gap is owner-approved** — the owner's
  question ("is the monitoring scope complete for LTS usage, and if
  so, document why so users are not confused") is now answered where
  users read it: USAGE.md "Honest limitations" entry 12 states the
  closed metric set (per-direction live rates, session totals,
  session max/avg speed statistics, the session census, kernel-named
  cgroup → process attribution with endpoint trees) and names every
  deliberate rejection with its reason — interface-level aggregates,
  per-connection quality metrics, DNS/SNI enrichment, persistence,
  and the session *minimum* speed ("total low": structurally ~0 at
  rest, no information — rejected). The per-endpoint byte
  attribution gap (the single axis where bandwhich/iftop lead) is
  flipped from "candidate, not committed" to owner-approved in
  docs/RESEARCH_TOOLCHAIN_AND_MONITORING.md 2.4: the socket-cookie
  byte map joined with the existing ConnectionMap is the sanctioned
  next frontier item, to be built as its own NIGHT task with its own
  micro-commit cycle.
- **test: NIGHT-improve-23 — supermassive-test-v2: the end-to-end
  daily-use simulation, strict / limit / block / unstrict on the
  local lane AND the real internet** — the owner's directive: v1
  proves the whole command surface survives supermassive stress
  (full parser span, kill/regression battery, fatal CLI-usage
  refusals); v2 simulates a real day of zelynic use before it
  lands on the daily driver, production grade. The four policy
  families run in daily-session order — strict (policy write,
  asymmetric -d/-u buckets, live rate change 1mb -> 2mb under an
  active policy, strict-multi group bucket), limit (limit-all
  --force sweep), block (block-single / block-multi zero goodput
  + kernel drops), unstrict (unlock restore, selective removal,
  unstrict-all teardown leaves no rows) — and each family is
  proven TWICE: on the deterministic loopback lane (v1's own
  stages) and against the real internet (curl workers inside the
  policed cgroup, real external processes, the same class of proof
  as the owner's manual browser tests). Zero engine duplication:
  v2 imports v1 whole (importlib; the dash in the filename defeats
  a plain import — v1's entrypoint is __main__-guarded) and drives
  its CgroupSet fleet, HttpServer, policy helpers, spawn_in_cgroup
  workers, band_check verdicts, and enforcement proofs, setting
  v1's module globals the same way v1's own main() does. The
  realnet lane is LTS-hard: a fallback chain of long-lived public
  endpoints (Cloudflare speed, then OVH, then Tele2), first
  reachable feeds the run, every miss reported; honest SKIP
  verdicts (never silent, never false FAILs) for no-egress
  machines, missing curl, slow baselines, and upload endpoints
  that refuse streaming bodies (an UNLIMITED sanity upload runs
  first — verify the instrument before measuring with it);
  realnet rate rows use a wider band floor (0.45 vs loopback's
  0.65 — slow-start and path-RTT patience) with the SAME 1.30
  policer-tripwire ceiling; the unstrict restore floor derives
  from a re-measured realnet baseline, not a configured number.
  CLI mirrors v1: --self-test (no root, no zelynic, no BPF, no
  network — engine import, endpoint registry, worker command
  contract), --binary, --json (realnet endpoint names + worker
  faults included), --band for the local lane; unknown flags exit
  2 with the known-options list. CI runs the v2 self-test on
  every push beside v1's, and ci.yml's consumer-scoped path filter
  learned the new script. README's test section documents the
  division of labor (green on v2 = qualified for the daily driver;
  green on v1 = qualified for a power outage) and
  CROSS_DISTRO_RESULTS invites the realnet rows for filing.

- **ci: NIGHT-improve-20 — musl CI parity: a first-class static twin
  job on the kernel 5.x LTS floor and the latest runner, every
  push** — the musl surface now gets the same every-push contract
  the gnu surface always had: a dedicated `musl` job in ci.yml
  running clippy (`--all-targets --all-features --target
  x86_64-unknown-linux-musl -D warnings`), the full test suite
  (`cargo test --locked --target x86_64-unknown-linux-musl` — the
  static test binaries execute natively on the glibc runner, so
  the suite runs inside the very artifact shape the release
  ships), a debug build with the ebpf feature plus its own `-V`
  execution gate, and the release build (the exact release.yml
  invocation, moved here from the gnu check job — one shape, one
  place). The matrix pins the kernel span the release page
  promises: ubuntu-22.04 (kernel 5.15, the oldest hosted runner
  still on a 5.x kernel — the LTS floor for the static packages)
  and ubuntu-24.04 (kernel 6.8+), fail-fast off. clippy aims at
  the musl target because lints are target-conditional — libc
  type layouts differ between musl and gnu (the statfs f_type
  E0308 that once escaped to a release tag is exactly the class
  of defect a per-target clippy catches). The gnu `check` job
  dropped its stapled-on musl release step and the musl target
  install accordingly; cache keys carry the musl + matrix-OS
  markers so the twin never cross-restores a gnu target tree.
  The nightly eBPF pin and the shared bpf-linker installer mirror
  the other compile jobs, since the ebpf feature graph compiles
  in both musl build shapes.

- **release: NIGHT-improve-22 — arch-baseline packages only: v3 and
  v4, gnu and musl, locally reproducible** — releases are now
  x86-64-v3 (AVX/AVX2/BMI1/BMI2/FMA, any x86_64 CPU from ~2013
  Haswell onward) and x86-64-v4 (AVX-512) builds in both libc
  flavors; the native v1 baseline is retired from release packages
  (cosmostrix pro-linux lineage, the owner directive). Four packages
  per tag, and only those four: linux-amd64-v3-gnu, -v4-gnu,
  -v3-musl, -v4-musl. The release workflow's build job is a
  four-entry matrix now (fail-fast off, one bad platform never
  cancels the other three): each entry carries its FULL RUSTFLAGS
  ("-D warnings" first — the NIGHT-strict-2 contract moved off the
  workflow env so a step-level env can never silently shadow it —
  then the baseline -C target-cpu, plus +crt-static on the musl
  pair), stamps ZELYNIC_BUILD with the package id so the binary's
  Build: line names its own shape, and a cosmostrix-parity tripwire
  step fails BEFORE any compile time when a platform's flag set
  drifts from its documented baseline. Verification split by
  executability: the v3 pair runs its own -V plus the Build: label
  check (every x86_64 runner since Haswell executes AVX2), the musl
  v3 twin keeps the improve-20 static proof (ldd must say "not a
  dynamic executable"); the v4 pair is verified WITHOUT execution —
  runners may lack AVX-512, so executing it could SIGILL — via the
  embedded build label and version-report literals read out with
  strings (grep -a fallback), the cosmostrix v4 contract. Packaging,
  three-family checksums, and GPG signing run per platform in the
  build-class jobs (the improve-14 least-privilege placement
  unchanged); the release job merges the four artifacts by pattern
  (download-artifact merge-multiple) and publishes. Local
  reproduction: four new cargo aliases — pro-linux-gnu-v3,
  pro-linux-gnu-v4, pro-linux-musl-v3, pro-linux-musl-v4 — each with
  its own profile (artifacts never clobber each other or
  target/release/zelynic) and a ZELYNIC_BUILD label naming the shape
  ("local-linux-gnu-v3" etc.), mirroring the release flags exactly;
  build.rs already strips the baseline flags from the nested eBPF
  build (NIGHT-hunt-28), so the bpfel objects stay identical across
  all six build shapes. The harness resolver learned the four alias
  outputs as binary candidates (newest-mtime rule), and its
  self-test pin now requires all four — one silently dropped means a
  freshly built release-shape binary stops outranking stale ones.
  Docs updated in step: README release + build sections (package
  names, v3/v4 eligibility one-liner, the new alias table),
  docs/VERIFY_RELEASE.md examples, CONTRIBUTING build pointers.

- **harness: NIGHT-improve-21 — the brutal battery: kill, race, and
  re-prove** — supermassive-test now ends its limiter matrix with the
  violent stages the owner asked for after the rate work is done.
  (1) kill top: five cycles of strict-multi enforcement on cgroups
  a:b:c with the live TUI (`zelynic top --interval 1s`) rendering on
  a real pseudo-terminal, each cycle SIGKILLed mid-render, reaped as
  signal 9, then proven to have left the pinned-map enforcement rows
  intact at the exact configured rates, the post-kill traffic still
  policed (kernel drops + byte accounting via the standard
  enforcement proofs), and a fresh policy write still landing — the
  pinned-map architecture's promise that a violent monitor death
  never costs enforcement continuity, now regression-pinned five
  times over with different rates. (2) kill mid-flight: twelve
  jittered SIGKILLs of one-shot strict-single invocations racing the
  attach/pin/write window (20-68 ms offsets, so early kills race the
  pin creation, late ones the row write, and some land after the CLI
  already finished — all legal outcomes); the invariant under test
  is that a killed writer never leaves a state the status surface
  cannot read back coherently (JSON parses, every limit row carries
  integral rates), and the stage ends with recover restoring the
  zero-pin state no matter where the kills landed. (3) the
  regression battery: after the kills, the four rate-guard refusals,
  three rapid policy round-trips across different cgroups, the
  doctor + list-apps JSON surfaces, and the -V version token are
  re-verified — nothing the battery broke may stay broken, and
  nothing that was refusing before may start accepting. The pty
  spawn/drain/reap mechanics are pinned rootlessly by --self-test
  (a dummy child on a real pty), so CI and containers catch an
  engine regression before any root run reaches the kill stages.
  The refuse() guard probe was hoisted to module level so the
  matrix's rate-guard stage and the battery run the IDENTICAL check.
  Hunt find folded in: the self-test's curl upload agreement row read
  the server counter without settle() — the HttpServer folds each
  connection's byte total into the shared state only after the
  connection ends, so a peek winning that race files a decoy FAIL
  (seen live once: upload 4.49 GB client vs 0 server, 0.0%, a
  container run on 2026-09-22; reproduced by timing shift, gone in
  three consecutive re-runs) — the row now settles first, the same
  contract the download row and peek()'s own docstring already
  demanded.

- **scripts: NIGHT-improve-18 — setup.sh, the lazy one-command
  bring-up** — for the owner who does not want to remember the
  order: `./scripts/setup.sh` runs the WHOLE pipeline —
  bootstrap-ebpf.sh (dated nightly pin + bpf-linker + the
  pro-native-gnu flagship build), an opt-in static
  pro-native-musl twin (`--musl`, x86_64 guard carried from
  install.sh), the rootless engine self-test, and the full
  supermassive matrix under sudo (elevating itself; `--skip-heavy`
  stops after the smoke) — then ends with the next-steps menu:
  install.sh for system-wide, uninstall.sh to remove it again,
  the built binary's --help / doctor / top / a starter
  strict-single, and the docs pointers. Every phase is idempotent
  (re-runs skip satisfied work: bootstrap re-checks in seconds,
  cargo rebuilds incrementally), each phase must pass before the
  next starts, and the matrix FAILING is reported as harness
  verdict rows, not swallowed — setup exits non-zero and tells
  you how to re-run the matrix alone. Guards: refuses to run as
  root (phases 1-3 install into $HOME; only the matrix phase
  elevates), PATH fixed for the current shell. README's
  Install-from-source section now opens with the lazy path
  before the manual order. (Task filed by the owner as
  NIGHT-improve-16; that ID was already taken by the 2026-09-21
  binary version gate — this lands as improve-18, next free.)

- **release: NIGHT-improve-14 — GPG-signed release artifacts (the
  cosmostrix lineage ported)** — every release tarball now ships a
  detached ASCII-armored signature (`.asc`) alongside its three
  checksums, proving authenticity, not just integrity. The port
  from the cosmostrix reference pipeline, with two deliberate
  zelynic deltas: (1) signing runs in the build job — which holds
  no `contents: write` token — so the private key never enters the
  environment of the job that publishes the release (least
  privilege for the pipeline's most sensitive secret); (2) a
  zelynic-style tripwire after signing: tarball count must equal
  signature count AND every `.asc` must `gpg --verify` clean before
  upload, so a release can never ship a broken or missing
  signature. Sign-off is graceful — with the `GPG_PRIVATE_KEY`
  secret unset both steps no-op and releases ship checksums-only
  (the pre-GPG state); nothing is blocked on configuration. The
  passphrase (when set) flows via `--passphrase-fd 0` from stdin,
  never the command line. A weekly `gpg-key-check` job in
  maintenance.yml fetches the maintainer's published master key
  (`F5324E09...`, the same cosmic-dragon identity that signs
  cosmostrix — one key, one identity, both projects) from the
  keyservers and warns 30 days before any signing subkey lapses,
  carrying the cosmostrix f7-field bugfix (creation-vs-expiry
  epoch confusion). User-facing verification docs rewritten in
  docs/VERIFY_RELEASE.md (import + verify + expiry policy) with
  the README pointer updated. The sign-and-tripwire logic was
  functionally verified locally: scratch key, both tarballs
  signed, `Good signature` verified, idempotent re-run, tamper
  detection; the expiry monitor was verified against the live
  keyserver key (3 subkeys, correct dates, no false expiry).
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

- **feat: NIGHT-boost-25 — the smooth open: eagle-eyes loading that
  is elegant, not flashy** — the owner's audit: starting
  `sudo zelynic ee` felt flashy and eye-straining, and the source
  confirmed why — the whole eBPF load ran on the MAIN screen (a
  blank frozen terminal for the verifier's duration), then the alt
  screen switched and the full bright frame painted in one burst.
  Dead air, then a flash. The fix inverts the order: a new
  `terminal::Monitor` session type opens the alt screen and paints
  a prelude frame the moment the command starts, and the BPF load,
  the identity walk, and the opening poll run UNDER that frame. The
  prelude (render/loading.rs `loading_frame`) is the live frame's
  own composition at t=0 with one row swapped: the eagle title bar,
  the breathing gap, a grey `loading observer…` note, and the
  pinned empty-session footer (census of nothing: `0 packets +
  0 cgroups`, `total usage internet in 0s = 0 B`, the status line,
  the stamp) — wrapped in the gradient rails, exactly
  terminal-height rows. When the observer comes up, the first live
  frame rewrites the prelude in place through the same DiffScreen:
  no clear, no blank flash, and the ONE visible change is the note
  row becoming `waiting for traffic…` — pinned by the morph test
  (the two frames are byte-identical except row 2). Honesty
  decisions pinned: the note says loading (never the idle-state
  line), the census claims no consumer and no limit suggestion (no
  champion exists yet), identities_unresolved is false (the walk
  has not RUN — not the same as having failed), and the title is
  the plain core (the target count is only known after the identity
  resolves). A load failure drops the session — ALT_EXIT restores
  the main screen and the branded error prints on it. `-v` keeps
  the trace-first sequence (the NIGHT-boost-6 contract: stderr
  writes during the live frame would garble it, so the attach trace
  prints on the main screen — the trace IS the loading feedback
  there). The pipe fallback (bench harness, CI) is unchanged: no
  prelude bytes into a pipe, the same loop, the same no-guard
  contract. `run_alt` retired — its only caller migrated; the loop
  lives on as the shared `run_loop` (the q-only quit, t theme, 50ms
  wake, resize-reactivity, and selection-guard contracts unchanged,
  still pinned by the mouse-contract and diff suites). 6 new pins
  (frame fills every terminal size, the byte-identical title row
  and floor, the loading note's honesty, the empty-session footer,
  THE morph, short-terminal survival). Verified: 285 ebpf + 67
  featureless unit tests, 32 + 29 integration, clippy and
  RUSTFLAGS=-D warnings clean both shapes, gate-keepers 17/17,
  build.sh check-all -q under the cap; benchmark A/B run per the
  owner rule (see PERFORMANCE.md).

- **ux: NIGHT-engrave-5 — the report-table family: `sudo zelynic
  status` restyled to the eagle-eyes contract (+
  list-apps, the hunt find)** — the owner's audit: the eagle-eyes
  style is finished, but the status output still did not match —
  uppercase headers (`CGROUP / DOWNLOAD / UPLOAD / ALLOWED /
  DROPPED`), a plain hyphen separator, bare sentence-case prose
  lines, a bare `No active limits.` branch. The status surface now
  renders the monitor's exact table family: lowercase purple column
  headers (cgroup / download / upload / allowed / dropped) over the
  monitor's own purple grid (render/footer.rs `grid_line`, promoted
  pub(crate) and re-exported — one border family across every
  zelynic table), full-width and flush with the left edge (the
  `|---` shape); data rows in status green (the eagle table's calm
  tier — every row is a live enforced limit, the affirmative
  state); the watchdog and census prose in grey lowercase
  (`watchdog: 30s remaining`, `active limits: N dl, N ul`, warn
  yellow only for the expired verdict); a breathing gap under the
  title bar; the leading blank line retired (the chrome opens the
  output). The branch states carry the same chrome through new pure
  builders (`status_clean_lines` / `status_stale_lines`): a clean
  system renders the frame with one grey `no active limits` line, a
  stale-pin state renders the warn-yellow finding with the recovery
  command in suggestion white — the same actionable-accent contract
  the monitor's limit suggestion carries. HUNT FIND: `zelynic
  list-apps` carried the exact same defect class (the old "━━━"
  pre-eagle banner, uppercase headers `PROCESS/PROCS/SOCKETS/
  CGROUP ID/UID`, a plain separator) — the discovery table joins
  the report family (flagship title bar, lowercase purple headers,
  the purple grid, green rows, the grey census line). The
  surface-class map is documented (BRANDING.md 2.1.1): flagship
  frames + report tables carry the eagle table contract; action
  prose (enforcement stderr) keeps sentence case; the reference
  surfaces (help, doctor, errors) keep their own idioms. Every
  builder is unit-pinned (6 new pins: lowercase headers on both
  tables, header alignment, row shape, the watchdog/census wording,
  the branch frames' chrome order); the `--print-json` documents
  are byte-identical (the v11 scripting contract untouched).
  Verified: 279 ebpf + 67 featureless unit tests, 32 + 29
  integration, clippy and -D warnings clean both feature shapes,
  gate-keepers 17/17, build.sh check-all -q under the 2-minute cap.

- **ux: NIGHT-boost-24 — the --print-json honesty audit: the silent
  no-op retired** — the owner's audit question: is the flag useless
  because it only works with `zelynic status`? The answer the source
  gives: it is NOT useless — THREE surfaces honor it (`status`,
  `list-apps`, `doctor`), and it parses at every level (global flag).
  But outside those three it was a SILENT no-op: the enforcement
  verbs, `eagle-eyes`, `-h`, `-V`, `--check-update` all accepted the
  flag and rendered text with no signal why — a user asking for
  machine-readable output got prose and no diagnosis. The fix follows
  the cosmostrix ignored-flag honesty contract (its
  "--json ignored (--bench-frames emits the text BENCH: format)"
  lineage): one stderr line, `--print-json ignored (JSON surface:
  status, list-apps, doctor)`, fires exactly once per invocation when
  the dispatched surface ignores the flag — warn yellow, stdout and
  exit codes untouched, so `status --print-json | jq` scripts are
  byte-identical to before. The surface list is per-build honest
  (the featureless dormant build names `doctor` alone — `status` and
  `list-apps` are eBPF surfaces that fail before output there). The
  flag's help text (clap doc + `--help` reference line + USAGE.md
  flag table) now names the surfaces instead of the vague "where
  applicable". Pinned three ways: unit pins hold the note's wording
  and the note/classification agreement (every surface the note
  names classifies true, and the help fallback / recover / eagle-eyes
  / strict-single classify false — the two tables cannot drift), and
  the integration pin holds the end-to-end contract on `-V` (exactly
  one note on stderr, version report and exit code unchanged) plus
  the honored side (doctor emits JSON, no note). No JSON document
  changed: the v11 scripting contract is untouched.

- **feat!: NIGHT-boost-14 — eagle-eyes: the masterclass engraving of
  the owner's style** — the ranked monitor becomes a PINNED
  composition, every clause of the owner's spec engraved and pinned
  by tests. (1) **Quit stays q-only** (the NIGHT-hunt-16 contract,
  now pinned at the byte level: `quit_from_chunk` — 'q' as the first
  drained byte quits; Ctrl+C, standalone ESC, every escape-sequence
  head, and 'q' buried inside a sequence never do). (2) **The blink
  is gone** — the takeover blink (hot_blink, the session state's
  rank-1 timing bookkeeping, TAKEOVER_BLINK, and note_rank1) is
  deleted entire: crowns read by color, never by animation, the
  owner's eye-strain call. (3) **Static traffic-light tiers**:
  rank 1 champion red, rank 2 warning yellow, rank 3 and below
  status GREEN (the former white) — a calm gradient down the board.
  (4) **Grey subordinates**: the subprocess usage lines under the
  rows and every footer line except the copyright render a new calm
  grey tier (#8B8B8B; 245 at 256 depth, bright black at 16) —
  context, not content. (5) **Purple grid**: the border under the
  PROCESS/DOWNLOAD/UPLOAD/TOTAL header and the two full-width lines
  framing the TOTAL row render brand purple, same source as the
  header text above them. (6) **A breathing blank line under the
  title** — the header used to sit too near the brand. (7) **The
  grip footer, the owner's exact spec**: the column-aligned TOTAL
  row framed by the two purple grids, then a blank, the census
  `N packets + M cgroups` (a `+` join, was a `·`) under its own
  GREY grip exactly as wide as its text, `Top consumer: <name>`
  (label grey, name GREEN) under its own grip, the
  `Limit it: sudo zelynic strict-single <name> 100kb` suggestion
  (grey, the suggestion-tier white retired on this surface), and
  the copyright last — version from env!(CARGO_PKG_VERSION), never
  hardcoded, purple as ever. (8) **The pin**: the frame spans the
  terminal height, the table floats, and the footer sits NEAR THE
  BOTTOM whatever the table does — measured blank padding absorbs
  the middle, and the pin is exact because the footer is BUILT
  first and its measured length fixes where content must stop.
  (9) **Dynamic resize**: the monitor loop probes the terminal
  geometry on every 50ms wake and forces a Render beat on change —
  resizing lands within one wake, not the next refresh tick (up to
  60s at `--interval 60`); next_beat grew a `resized` term, pinned.
  (10) **Adaptive compact (dynamic WxH)**: on narrow frames the
  subprocess detail hides entirely (below width 51, the same
  boundary where the TOTAL column itself drops) and every shown
  detail line is cut to the frame width with an ellipsis — a long
  process or endpoint string can never wrap the frame or shift the
  pinned footer; on short terminals the footer compresses through a
  tier ladder (blanks drop first, then the grips, then the discovery
  hints — census and copyright survive at every height; Full >= 16
  rows, Compact >= 14, Minimal >= 10, Tiny below). The focus view
  aligned too: the gap under its title, its process lines capped to
  the height with an honest "+N more hidden" note, and its copyright
  pinned. The render tree gained `render/footer.rs` (the tiers, the
  grips, the build — split by the cohesion discipline when the
  engraving pushed eagle.rs past the LOC cap) and
  `test/ebpf/render/footer_tests.rs` (the composition pins);
  EagleColumns + plan_eagle_columns moved to the render root, their
  documented home. The renderer grew a size-injectable core
  (`render_eagle_eyes_at`, the emit/emit_at discipline) so the
  ladder and the pin are pinnable at every WxH.

- **feat!: NIGHT-boost-1 — eagle-eyes: the observe + top pair merged
  into one unified live monitor** — the owner's read was blunt:
  observe and top were two views of the same observer with four
  flags between them (`--observe --cgroup --limit --interval`),
  bloat where one surface should be. `zelynic eagle-eyes`
  (`eagle-eye` shorthand) is that surface. No targets: every app
  RANKED by current consumption, rank 1 = whoever is eating the
  internet right now — the ranking IS the view, so `--top` is
  unnecessary. The row budget is the terminal height (the former
  `--limit` and the hard 20-row MAX_ROWS cap are gone): a short
  window shows the top few, a tall one spans the list down to the
  quiet apps, detail lines included in the budget. The positional
  TARGETS spec is autodetected per token (digits = cgroup ID, a
  name = process, same rule as strict/block) and re-resolved against
  the live identity map EVERY frame, so an app started mid-session
  appears on the next refresh: `eagle-eyes brave` watches one app
  (deep focus view — per-direction deltas, rate, both lifetime
  counters, uncapped socket endpoints; the old `observe --cgroup`
  depth, now automatic), `eagle-eyes 12345/brave/firefox` filters
  the ranked table to that set, `eagle-eyes --interval 3s` calms
  the cadence (kept: the one flag realtime precision needs, 1s
  default). Unresolved names render a note line (`no app named
  'x' — see 'zelynic list-apps'`) instead of a silently empty
  table. The render tree split honors the LOC cap: `render/eagle.rs`
  (ranked) + `render/focus.rs` (deep view) replace `observe.rs` +
  `top.rs`, sharing the existing detail.rs; the column ladder keeps
  the flagship degradation (RATE drops first below width 54), the
  improve-13 column-aligned TOTAL row (sums every candidate, not
  just the rows shown) and the NIGHT-hunt-8 "Top consumer" hint +
  strict-single suggestion ride the unfiltered frames, and the
  focus view keeps the lifetime-counter precision pin. Old muscle
  memory lands soft: `zelynic observe` / `zelynic top` fail as
  unrecognized subcommands whose tip redirects to `eagle-eyes`
  (clap's own SuggestedSubcommand slot, the --help-all redirect
  contract), and `--cgroup`/`--limit`/`--live`/`--duration` all
  fail as unexpected arguments. Tests follow the merge: help_pins
  documents the 14-command surface with the eagle-eyes synopsis and
  a no-stale-synopses pin, surface_pins rejects the removed
  subcommands (redirect pinned) and removed flags, privilege's
  matrix runs `eagle-eyes` + the `eagle-eye` alias, monitor's unit
  tests gain the empty-target-spec fail-fast ladder case
  (`eagle-eyes /` errors before the root guard), the frame bench
  harness is retargeted (`frame_bench_eagle`, same fixed-seed LCG
  data), and the supermassive kill stage spawns eagle-eyes on the
  pty (renamed kill-tui — command-agnostic stage name). Docs
  swept for the merge: README feature table + quick start +
  architecture diagram, USAGE monitor section (one eagle-eyes
  block), SAFETY_ANALYSIS command table, BRANDING monitor layout
  (height-is-the-budget contract), doctor's ready tip, and the
  nonroot-depth-test matrix rows. The removed-surfaces limitation
  list now names the merge explicitly.

- **ci: NIGHT-improve-22 — the Dragon Guard estate: every workflow
  carries its masterclass name, and a warning is a failure
  everywhere** — the cosmostrix naming lineage applied across the
  run list, codeql.yml having set the precedent: CI becomes
  "Dragon Guard - CI", Gate-keepers becomes "Dragon Guard -
  Gate-keepers", Audit becomes "Dragon Guard - Security Audit",
  "Maintenance deps weekly" becomes "Dragon Guard - Dependency
  Maintenance" (its job rows renamed "Dependency sweep validate" /
  "Dependency sweep commit" to match), Release becomes "Dragon
  Guard - Release" (cosmostrix's twin is "Cosmic Dragon Guard -
  Release"), and the CodeQL name sheds its quotes for estate-wide
  consistency. The run list now reads as one guarded estate instead
  of a pile of generic labels — at three in the morning, "Dragon
  Guard - Security Audit" is a findable tab and "Audit" is a
  search hit for the wrong thing. Job ids and job display names
  (Lint & Test, eBPF Build, Musl Static Twin) are untouched, so
  required-check references and branch protection keep resolving.
  The warning-is-failure contract closed its last gap in the same
  stroke: cargo audit now runs with --deny warnings (advisory-level
  findings — unmaintained dependencies, yanked versions — exit
  non-zero instead of scrolling past as yellow text; the
  observation-only posture lives in the job's continue-on-error,
  not in a silent exit code). Every other warning surface was
  audited and already strict: rustc via RUSTFLAGS=-D warnings in
  ci.yml and maintenance.yml, per-platform flag sets in release.yml,
  clippy -D warnings in every job that runs clippy, and the
  gate-keepers tooling (shellcheck, shfmt -d, yamllint, actionlint,
  codespell, ruff) each already fail on their findings.

- **ci: NIGHT-improve-21 — path filter scoped per consumer: docs,
  harness scripts, and lint configs stop buying the full Rust
  matrix** — the cosmostrix filter discipline, applied to the one
  place zelynic's trigger set was still paying for surface it
  cannot affect. The old ci.yml paths matched '**/*.py',
  'scripts/**', and '**/*.toml', so a comment tweak in
  benchmarking.py, a docstring in uninstall.sh, or a line in
  .ruff.toml triggered check + ebpf-build + both musl twins —
  forty-plus minutes of compile time per push with zero reachable
  effect. The set is now exactly what this workflow's jobs compile
  or execute: the Rust trees ('**/*.rs', build.rs), the cargo
  manifests ('**/Cargo.toml', Cargo.lock, deny.toml for the
  cargo-deny step), the toolchain pins (.cargo/**,
  rust-toolchain*, ebpf/**), and the three scripts its steps run
  (check-policy.py, supermassive-test.py, install-bpf-linker.sh).
  The safety contract is unchanged and restated in the workflow
  header: gate-keepers.yml still runs on EVERY push and PR with no
  filter, so a docs-only or scripts-only change is fully policed —
  it just stops renting four compilers to be told a docstring
  parses. CONTRIBUTING's CI paragraph now documents the
  consumer-scoped filter alongside the unfiltered gates contract.

- **ci: NIGHT-improve-20 — the release pipeline hardened after the
  v11.0.0-alpha.1 failure: musl compiled on every push, lean
  single-commit clones, an API-rendered changelog, and a re-tag
  concurrency guard** — four changes, one mission (a release tag
  must never be where a new class of failure is discovered).
  First, the fail-fast hole that let NIGHT-hunt-33 through: no CI
  job had ever compiled the musl target, so the release tag was
  the first musl compile in the project's CI history — the
  `check` job now builds the EXACT release.yml musl invocation
  (`--release --locked --target x86_64-unknown-linux-musl
  --features ebpf`) and runs the static binary's `-V` gate on
  every push (a static musl executable runs natively on the
  glibc runner, proving the artifact, not just the compile).
  Second, the clone bloat the 2026-09-22 owner audit called out:
  both release jobs cloned with `fetch-depth: 0`, pulling every
  branch (legacy, main, pure-rust-prototype) and all 23 tags plus
  full history — the build job now fetches exactly one commit
  (the tag's), and the release job drops its checkout entirely.
  Third, the release body: `git tag` + `git log` on a full clone
  is replaced by the GitHub REST API (tag list + compare), which
  needs zero bytes of repository and is more stable than
  `--sort=-creatordate` (that misorders re-pointed tags — the
  alpha.1 re-tag was live proof; semver ordering is
  deterministic), with merge commits filtered the same way and
  the 250-commit compare ceiling handled by an explicit
  truncation note. Fourth, a `concurrency` group per tag:
  re-pushing a MOVED tag now cancels the superseded in-flight
  run instead of racing it — the superseded build compiles a
  commit the tag no longer points at, so its artifacts are wrong
  by definition. Setup.sh stays a local bring-up tool and is
  deliberately NOT run by CI: its sudo matrix and interactive
  menu belong to a dev box, while the release job already
  mirrors its build contract (pinned toolchains, bpf-linker pin,
  `--locked`, pro-release profile) and adds gates a local box
  cannot have (tarball invariant, three-family checksums, GPG
  tripwires).

- **docs: NIGHT-improve-17 — Dragon Architecture renamed to Cosmic
  Dragon Architecture, with the architecture audit recorded** — the
  name was the last holdout from before the cosmic identity settled:
  the GPG signing identity is the cosmic dragon, the render engine
  lineage is the cosmic-dragon-engine (cosmostrix), the persona is
  dragonzen — the architecture is now the Cosmic Dragon Architecture
  too, one identity across everything. The rename is repo-wide and
  lockstep: docs/DRAGON_ARCHITECTURE.md →
  docs/COSMIC_DRAGON_ARCHITECTURE.md (git mv, history preserved),
  every "Dragon Architecture" term in docs and module headers, the
  README tagline ("The cosmic dragon counts every byte that leaves
  the den"), and — the one PRODUCT string — `zelynic -vV`'s
  "Architecture:" line now reads "Cosmic Dragon (pure eBPF)", with
  its pins updated in the same commit (test/integration/smoke.rs,
  scripts/nonroot-depth-test.sh's --version/-V expectations) so no
  suite ever sees the two eras mixed. The render-engine comments
  ("dragon engine" shorthand, cosmic-dragon-engine lineage) keep
  their names — that engine was always cosmic. The audit half of
  the task landed as a new Architecture audit section in the
  renamed doc, every claim import-verified: layer discipline holds
  (commands reach terminal only through its top-level surface; cli
  touches eBPF only through ebpf::limiter's public re-exports; the
  ebpf/ crate couples to userspace only via the #[path]-wired
  math.rs twin), 363 functions cross-referenced with zero dead,
  one acquisition path per resource class, symmetric error
  contracts, known limits documented — and the 775 lines of
  structure debt cleanup-2/3 retired this session.

- **harness: NIGHT-improve-19 — the light mode retired; one root
  intensity, CLI-grade flag typo rescue** — supermassive-test now
  has exactly two modes: the 5+ minute supermassive matrix (the
  default, and the only root mode) and --self-test (rootless
  engine smoke). The old light sweep ran a subset of the same
  stages with smaller windows, so a green light run said nothing
  the matrix does not say more strongly — while its tighter
  windows were the flakiness engine behind two real verdict
  failures: the 2026-09-21 asymmetric split (light 131.1% FAIL
  where heavy measured 124.5% PASS on the same engine) and the
  2026-09-22 curl burst 135% (hunt-32's divisor artifact,
  amplified by the light window's larger burst-to-window ratio).
  run_light, LADDER_LIGHT, and the mode branch are gone; --heavy
  remains accepted as the explicit spelling of the default.
  Unknown flags now get the SAME typo contract as the zelynic
  binary: a case-insensitive Jaro matcher at clap's own > 0.7
  confidence threshold (src/cli/suggestion.rs mirrored), so
  `--self-tesss` prints `tip: a similar option exists:
  '--self-test'` — and the retired `--light` gets a dedicated
  message naming its replacement instead of a misleading generic
  suggestion. Three new self-test rows pin the rescue rootlessly
  (near-miss suggestion, distant-input silence, retirement
  message); self-test is 20/20. Docs aligned: README,
  CONTRIBUTING, the wrapper header, and the bootstrap-ebpf.sh
  next-step hint.

- **core: NIGHT-optimized-2 — the redundancy master-audit for LTS**
  — a full pass over the 7k-LOC src/ tree (profiles, dead code,
  duplication, error-contract symmetry, hot paths). Findings and
  outcomes: (1) release + pro-native profiles already optimal (fat
  LTO, codegen-units 1, strip, documented panic-unwind constraint)
  — no change; (2) zero dead functions (the prior hunts cleaned the
  tree) — the cross-reference audit confirms it; (3) the map-reader
  cluster was the real redundancy: `read_counters` and
  `read_counters_ingress` were byte-identical except the map name —
  merged into one `read_stats_map(map_name)` whose error messages
  now name the failing map; the three limiter status readers
  (policies/stats/watchdog) each carried twin live/pin branches
  copy-paste modulo the MapData origin — each now has ONE typed
  path; and the `MapData::from_pin` + error-mapping dance existed
  at five call sites across three files — now one pair of helpers
  in `ebpf/pin.rs` (`open_pinned_hash_map` /
  `open_pinned_array_map`), adopted by the readers and the reclaim
  path, with a pin path named in every error. (4) The observer's
  ingress counter read swallowed errors (`unwrap_or_default`)
  while the egress read directly above propagated them — the
  hunt-22 "fabricated absence" anti-pattern, plus a hidden
  cumulative accounting bug: a swallowed ingress failure cleared
  `prev_stats_ingress` and re-inserted nothing, so the NEXT
  successful frame's download delta included the counter's entire
  lifetime total — in `top` mode that inflation persisted in the
  cumulative table forever. Both counter families now share one
  propagation contract; the unreachable-difference analysis (post-
  detach both fail identically; the embedded object always defines
  both maps) shows the lenient branch could only ever mask real
  corruption. (5) The monitor loop's one-frame
  `unwrap_or_default` (observe + top) is deliberate and correct —
  the opening poll hard-fails on any broken map, prev_stats only
  rewrites on success so a skipped frame's delta spans correctly —
  now documented at both call sites so the next audit does not
  re-flag it. (6) Hot paths audited: render/display/terminal carry
  near-zero clones and no lock smells; the poll-loop's O(cgroups²)
  ingress merge measured against a 1 Hz UI cadence stays
  deliberately readable. (7) DRAGON_ARCHITECTURE.md's layer-1 box
  named functions that no longer exist (`read_counters`, and
  `poll_events` — dead since the ring-buffer removal) — corrected.
  Verified in sandbox: all six project gates green, supermassive
  self-test 17/17, brace/width/reference structural checks clean;
  CI remains the compile authority for the Rust surface.
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

- **feat: NIGHT-boost-13 — the fatal-CLI-UX session: advice that
  fails when followed must not print, and the error shows the
  grammar of the command that failed** — the owner's live repro
  (`zelynic -v ss brave 550kb -i`, `-x`, then following the printed
  advice `-- -i`, `-- -x` into two more dead ends) exposed four
  gaps in the error bridge, all fixed in `src/cli/ux.rs` + the new
  `src/cli/argv.rs` forensics module (split from ux.rs per the LOC
  cap cohesion rule): (1) the escape-hatch honesty probe — clap
  injects "to pass '-i' as a value, use '-- -i'" whenever the
  failing command merely HAS positionals and cannot see the slots
  are full; the probe rebuilds argv with the advised splice and
  re-parses, keeping the tip only where following it actually
  parses (`ss brave -i` keeps it — the RATE slot is open; `ss brave
  550kb -i` drops it), extending the NIGHT-boost-8
  proof-before-printing discipline to every escape-hatch tip;
  unprovable tokens (short clusters report one char) pass through
  untouched — a tip is removed only when disproven. (2)
  Subcommand-scoped usage — the bridge used to replace clap's
  native usage context with the top-level render unconditionally,
  flattening every subcommand error onto "zelynic [OPTIONS]
  [COMMAND]"; the native line stays now (clap already renders the
  failing subcommand's own grammar, which is what makes the
  extra-positional dead ends self-explanatory), and only the
  suggestion-narrowed usage is regenerated — from the failing
  command, via an argv parser-descent walk that stops at the failing
  token and never crosses a double dash, rendered under the
  canonical bin name so regenerated and native lines agree
  byte-for-byte. (3) `zelynic help` — the muscle memory every clap
  tool trains — died tip-less as an unrecognized subcommand; the
  SUBCOMMAND_FLAG_REDIRECTS table now lands it on "to see the
  reference, run 'zelynic --help'". (4) `--json` — the convention
  everywhere else — died tip-less (jaro_ci 0.394 is too far under
  the 0.7 bar for the fuzzy engine); the FLAG_VOCABULARY_RESCUES
  table tips `--print-json`, and the latent one-tip contract break
  the hunt found (the fuzzy fallback injected SuggestedArg without
  dropping clap's native escape hatch, rendering two tips at once
  on `ss brave --VERBOS`) is fixed on every rescue path. Unit pins
  in `test/cli/argv_tests.rs` + `test/cli/ux_tests.rs` (33 CLI
  tests); USAGE.md troubleshooting/exit-codes/maintainer-map rows
  updated.

### Removed

- **scripts: NIGHT-cleanup-2 — distros-depth-test.sh and leak-test.sh
  retired, their functions live in the supermassive matrix** — the
  two old-generation depth tests whose contracts are fully covered
  by the current harnesses. distros-depth-test.sh (483 lines:
  detection, doctor, list-apps, basic/high limits, multi-connection,
  start/stop 100x, 10+ app limits, SIGKILL scenarios, network
  off/on, unload/reload, kernel log, orphan maps) predated the
  supermassive matrix and duplicated it stage-for-stage with weaker
  instruments (curl-speed eyeballing vs measured rate bands + BPF
  accounting proofs); its SIGKILL scenarios remain covered by
  crash-recovery-test.sh. leak-test.sh (200 lines: no orphan BPF
  maps after strict/unstrict/crash/reload) is subsumed by the
  matrix's end-of-run cleanup row — every op family in the surface
  runs before the final "zero BPF pins left" check, so a leak
  anywhere in the sweep fails that row — plus reload's 60 cycles
  and crash-recovery's stale-pins paths. Deliberately KEPT (the
  audit's surviving set, each holding an e2e contract nothing else
  covers): crash-recovery-test.sh (recover on STALE pins — the
  matrix's recover stage runs on clean state only), race-condition-
  test.sh (cross-process file lock under concurrent CLI
  invocations — lock.rs unit tests cover logic, not process-level
  concurrency), reload-test.sh (rate change during ACTIVE traffic,
  the no-gap combo the matrix's separate reload and sustain stages
  never produce), nonroot-depth-test.sh (referenced by the Rust
  test tree), benchmarking + frame-bench (docs and test tree
  consumers). Net: 683 lines of burden gone, zero coverage lost.

- **build: NIGHT-cleanup-3 — build.sh's five dead build subcommands
  retired; the whole-tree audit found the rest clean** — the
  all-files pass (docs, assets, workflows, Rust surface, scripts,
  root files) confirmed the tree tight: every doc is referenced,
  the src/RULES.md + docs/RULES.md twins are a deliberate
  colocated-reminder convention, the logo is used, no TODO/FIXME
  markers survive, CI's clippy -D warnings plus the
  NIGHT-optimized-2 dead-function cross-reference (0 dead of 363)
  cover the Rust surface, and every script path the living docs
  mention exists (the two grep hits — stress-test.sh and
  verify-bpf-refill.c — are intentional: a retirement note and
  an out-of-repo workspace harness SAFETY_ANALYSIS names
  explicitly). The one real finding: build.sh — which every
  consumer uses as the CHECK orchestrator (`build.sh check-all`)
  — still carried the pre-pro-native generation's build modes:
  release (plain `cargo build --profile release`, contradicting
  the pro-native mandate), release-debug, ci (check-all + basic
  release), all (fmt + clippy + debug + basic release + tests),
  and bench (cargo bench with zero [[bench]] targets to run —
  benchmarking lives in scripts/benchmarking.sh and frame-bench
  .py). No doc, workflow, or script invoked any of them; the
  real product builds were already two official entry points
  (bootstrap-ebpf.sh for dev, install.sh for users, both
  pro-native). All five subcommands and their functions are
  gone; the help text now states the contract: build.sh is the
  check orchestrator, product binaries come from the pro-native
  entry points. Kept: debug (debugger-ready dev builds), test,
  check, check-all, fmt, clean, update, stats, help.

### Fixed

- **fix: NIGHT-hunt-34 — the Musl ubuntu-22.04 SIGILL flake closed
  at the root (and its gnu twin preempted)** — the hunt-find from the
  refactor-2/ultimate-3 verification rounds: the Musl Static Twin
  job on ubuntu-22.04 intermittently died with "Illegal instruction
  (core dumped)" on `./pro-native-musl/zelynic -V`, while the same
  job was green on other commits and the build itself finished in
  ~21s. That 21s was the tell: three cold musl release profiles
  cannot compile that fast — the cache step had restored target/
  wholesale, cargo recompiled NOTHING, and the executed binary was
  compiled on a PREVIOUS runner's CPU. target-cpu=native bakes the
  build machine's exact ISA into the artifact (dependencies
  included), and GitHub pools heterogeneous silicon generations —
  executing a cache-restored native artifact is a lottery that
  SIGILLs the moment the previous runner was the newer machine. The
  considered alternatives, on the record: a step retry restores the
  SAME cache and only wins if the fresh runner lands on
  new-enough silicon (masking, not fixing, at runner-minute cost) —
  rejected; container/QEMU verification of the native twin buys
  minutes to prove a machine-specific binary runs on that machine —
  rejected as signal-free. The fix is the contract the v4 line in
  the same step already carries: the native pair (musl AND the gnu
  check job's native, same cache mechanism, same hazard class,
  fixed before it ever flakes) is now verified via its embedded
  ZELYNIC_BUILD label (`grep -aF "local-native-musl"` /
  `"local-native-gnu"`) with no execution. Nothing measurable was
  lost: the musl shape still executes natively three ways in the
  same job (test binaries, debug -V, v3 -V — all baseline-codegen,
  portable by construction), and the one gate retired is the one
  whose codegen target is a variable, so its execution never proved
  anything about any other machine. v3 keeps its execution gate
  (fixed baseline, pool-portable); v4 keeps its existing
  label-verify. Both step comments document the root cause, the
  evidence, and why retry was rejected, so the next SIGILL-shaped
  flake gets diagnosed in seconds, not hours. Second closure in the
  same commit: ci.yml's own `paths:` trigger now includes
  `.github/workflows/ci.yml` itself — a workflow edit used to be
  linted by gate-keepers but never EXECUTED by its own pipeline,
  so this very fix would have gone live untested until the next
  Rust-touching push tripped over it (the silently-skipped-run
  hazard NIGHT-boost-9 closed for scripts/). The workflow that can
  change its own contract owes itself a run; the push that carried
  this fix was its first self-triggered exercise.

- **fix: NIGHT-hunt-26 — the intermittent flicker on long-running
  eagle-eyes sessions** — two mechanisms, both structural:
  (1) the selection guard's 100ms whole-frame beat re-emitted
  through the RESET route (HOME + erase-below + every row) ten
  times per second; when a grown frame (full board, detail trees,
  widened counters after ~90s) crossed the pty write-chunking
  boundary, the terminal's frame clock could catch the erase before
  the rewrite — a one-frame blank window, the flash the owner
  reported. The guard now raises a REPAINT flag: every row goes out
  dirty through the sequential path with NO screen erase (the
  rewrite itself is the selection killer; identical content
  rewritten in place cannot flash). True resets (first frame, width
  change) keep their erase — an unknown or resized screen genuinely
  needs it. (2) a transient winsize probe failure (a mid-resize 0x0
  report) fell back to 80x24 on a painted screen, forcing a
  wrong-geometry reset plus a second one on recovery — the
  two-beat flash. DiffScreen::emit now reuses the last emitted
  geometry (sticky height field) and the monitor loop's force
  decision holds the last known geometry through a None probe; the
  pipe path keeps its stable 80x24, so harnesses and CI are
  unchanged. Pins: guard_repaint_is_the_reset_stream_minus_the_erase,
  guard_repaint_never_blanks_the_screen (both regimes),
  transient_probe_failure_reuses_last_geometry; the resize reset
  keeps its erase and stays pinned.

- **monitor: NIGHT-engrave-4 (second cut) — the footer dashboard
  rebuild: the missing lines restored in the owner's exact order** —
  the owner's audit: the footer showed only the total row, the
  status line, and the build stamp; the consumer headline, the
  packets+cgroups census, and the limit suggestion were missing.
  The block now reads in the owner's exact line order: `top consumer
  is curl` (the rank-1 cgroup's busiest process — the NIGHT-hunt-8
  autodetect restored: socket detail first, the label's comm second,
  the raw label last, so the headline never goes dark over an
  identity miss; the name brand purple, the engrave-1 contract),
  `478 packets + 1 cgroups` (SESSION packets since this pass — one
  accumulator in the session state, both directions, the same
  horizon as the bytes, where the pre-engrave-3 census mixed a
  per-frame packet count with a session cgroup count on adjacent
  words of one line), the total row (unchanged, engrave-3's
  `total usage internet in 1h:20s = 10gb`), `limit target with
  'sudo zelynic ss curl 100kb'` (the owner's engrave-4 wording:
  quoted command in suggestion crystal white, the `ss` short alias
  the CLI already carries, the 100kb a named documented constant —
  the one fixed suggestion value on a line whose every other fact
  is derived live), the status line, and the copyright. The census
  composition moved from the eagle renderer into the footer module
  (gathered where it renders — footer data lives with the footer);
  SessionAcc gains the saturating packet accumulator; the
  compression ladder re-cuts to 9/8/5/3 (the air above the status
  line drops first, the owner's copyright gap survives to Compact,
  the census and limit suggestion next, the consumer headline and
  the roof grid last — the total row, the status line, and the
  copyright remain the survivors at every height). Filtered frames
  carry their own census (the filtered board's story). The focus
  view's composition is untouched.

- **monitor: NIGHT-engrave-4 (first cut) — the symmetric rails: the
  table's border gaps made consistent, the way the owner audited
  them** — the TOTAL column's figures used to end flush against
  the right rail (zero columns of air — "too near the border, hard
  to see", the digits and the rail glyph fighting for the same
  column) while the `top process` title floated six columns off
  the left rail past the blank rank cell ("too distance from
  border"). Both edges now carry the same two columns of air: the
  column budget gains a RIGHT gutter that mirrors the left gutter
  every frame line starts with (the label column absorbs it, so a
  full row still composes to an exact width — two columns short of
  the content inset, where the border's fit() pads), and the
  header's process title now SPANS the identity region (rank cell
  + gap + label column) so it starts at the frame's canonical text
  column — the same line every footer and note row starts on.
  Boundary moves with the air it buys: the full layout (with the
  TOTAL column) starts at content width 53 (was 51), the
  no-TOTAL layout at 42 (was 40), and the subprocess-detail hide
  threshold now IS the column ladder (`cols.show_total`, one
  source of truth — the parallel `DETAIL_HIDE_BELOW` constant is
  retired before it could drift).

- **monitor: NIGHT-engrave-3 depth audit — the footer's leanest
  readable block, the frame's horizontals joined to its border** —
  the owner's seven-bullet engraving pass, delivered as one cut:
  the title bar's top-right hint pair (`t theme - q quit`) retired
  (the footer's status line is the legend's only home now — which
  is exactly why that row rides every compression tier); the
  footer's total row re-cut to `total usage internet in 1h:20s =
  10gb` (the two per-frame rates retired at the owner's "only
  total consume bandwidth" call); the line below the total row
  (the second grid), the `N packets + M cgroups` census, and the
  `Top consumer` + `Limit it` discovery pair all retired with their
  grips and their census math; one blank of air added above the
  copyright (the build stamp reads as its own quiet paragraph);
  and the grid lines now begin at column 0 — the owner's `|---`,
  never `| ---` — so the left rail reads as one integrated line,
  edge to edge with the right. The compression ladder re-cut for
  the trimmed block (6/5/4/3: the total-status gap drops first,
  then the copyright gap, then the roof grid; the total row, the
  status line, and the copyright survive at every height). The
  trim freed six Full-tier rows for the table on an 80x24 and
  retired two dead helpers with it (`comm_from_label`, whose last
  caller was the discovery autodetect, and `SessionState::len`,
  kept test-gated for the bound pins). Hunt find along the way:
  FOCUS_CHROME sat one below the focus view's real fixed overhead
  (title + gap + five key/value rows + footer), so a detail-full
  frame skipped the footer entirely and rendered short of the
  terminal height — the budget now counts every fixed row exactly.

- **ci: the plain (featureless) test build compiles under
  `-D warnings` again — the theme catalog's public face lost its
  only non-ebpf callers when NIGHT-engrave-2 retired the
  title-suffix pin** — three CI jobs (both Musl Static Twin
  entries and `build.sh check-all -q`) went red for six commits
  straight (d1cf883..bdfb961) on one root cause:
  `Theme::name()` (boost-18) and `Theme::brand_rgb()` (boost-20)
  carry `#[cfg(any(feature = "ebpf", test))]`, so the featureless
  TEST build compiles them — but their only callers live inside
  the monitor feature (the footer status line and the border
  gradient), and the pin that had kept `name()` alive was the
  title-suffix assertion engrave-2 deleted. Local gates never
  saw it because the local environment does not export
  `RUSTFLAGS: -D warnings` — the dead-code lint stayed a silent
  warning here and an error in CI. The fix follows the file's own
  idiom (`set`/`cycle`/`THEMES` are kept alive exactly the same
  way): a new catalog pin walks all six themes asserting
  `name()`/`brand_rgb()` against the BRANDING.md 2.2 palette
  table, that the TrueColor brand escape derives from the same
  RGB the gradient ramps, and that every name stays lowercase
  (the engraved status-line contract). Test-only change — the
  shipped binary is byte-identical — so no benchmark run.

- **capabilities: the release musl build compiles again —
  `statfs.f_type` is a u64 on musl, an i64 on glibc
  (NIGHT-hunt-33)** — the v11.0.0-alpha.1 release run died at the
  musl compile step with E0308 (`expected i64, found u64`) at
  `src/capabilities/mod.rs` while the gnu build was green on the
  very same tree: the two libcs disagree on the Rust-side type of
  the same kernel field (glibc types it `__fsword_t`, a signed
  long; musl types it `unsigned long`). The kernel ABI is
  identical either way — a full 64-bit filesystem magic on the
  wire — and every magic in linux/magic.h (BPF_FS_MAGIC
  0xcafe4a11 included) sits far below 2^63, so the fix widens the
  field into the function's i64 contract with a single `as i64`:
  a no-op on gnu, a lossless widening on musl, no panic path
  (the compiler-suggested `try_into().unwrap()` would have
  introduced one). The stale doc comment that caused the bug —
  "stored as i64 to match statfs.f_type, signed" — recorded a
  glibc-only assumption as if it were the libc contract; it now
  documents the divergence it papered over.

- **harness: the curl burst rate verdict now divides by the actual
  wall-clock span, not the nominal window (NIGHT-hunt-32)** — the
  2026-09-22 light run failed `curl burst: 4 parallel curls, one
  shared limit` at 135.0% against BAND_HI = 1.30 with a clean
  kernel-side proof in the same stage (BPF allowed 6,633,475 B =
  the 1 MB burst seed + 5.63 s of refill, and the accounting row
  matched client bytes at 98.3%). Root cause: N parallel curls
  each run `--max-time window` from their OWN exec moment, so
  staggered spawns (bash cgroup join + exec + TCP connect,
  magnified when the previous stage's teardown still loads the
  box) stretch the bucket's drain span past the nominal window by
  up to ~0.7 s — the nominal divisor charged that stagger, plus
  the one-time burst bonus, to the configured rate. Single-curl
  rows stay accurate because one curl's stagger is ~50 ms; only
  the burst row compounds it across clients, which is why the
  row passed the night before and flipped without any kernel or
  harness change on the enforcement path — flaky by construction.
  The verdict now divides the client total by the measured span
  (first spawn to last join) with a sanity guard (span must land
  in [window, window + 2.0 s] or the stage fails with a
  spawn/teardown-pathology message instead of dividing garbage),
  keeping BAND_HI a true policer tripwire: any over-delivery past
  the burst amortization still trips it, while the physical
  ceiling with the real divisor is ~1.2 for this stage shape.
  The span is recorded in the row detail for diagnosability.

- **repo: the two CI regressions from the last pushes closed at
  source** — the NIGHT-optimized-2 push landed with three
  map-reader chains in `src/ebpf/limiter/stats.rs` that rustfmt
  re-flows differently than written (the sandbox has no cargo, so
  CI was the compile authority and caught them in the Lint & Test
  job's Check formatting step), and the NIGHT-improve-14 push
  carried two GPG annotation lines in maintenance.yml past the
  yamllint 120-character cap (128 and 160), failing the
  Gate-keepers run. The chains now match the exact diff CI
  printed (semantics unchanged — pure re-flow), and the expired
  and expiring-subkey annotations are split into a short
  annotation line plus a plain-echo detail line carrying the warn
  window, so no information is lost and every line is under the
  cap. Verified locally: yamllint clean on all workflows, YAML
  parse OK, ruff and the 17-check self-test green, gate-keepers
  15/15 minus the cargo-dependent rustfmt step (absent toolchain
  in this sandbox; CI's eBPF Build jobs are the authority there
  and were already green on the same tree).

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

- **docs: NIGHT-docs-13 — the eagle-eyes frame, line by line: the
  annotated reference in USAGE.md** — the owner's masterclass
  documentation call: the eagle-eyes section carried every footer
  fact, but as one 60-line parenthetical paragraph a reader could
  not look anything up in. The new subsection ("The frame, line by
  line — the annotated reference") gives the mode a reference-grade
  anatomy instead: (1) an example frame that is byte-exact with the
  renderer — built against the real geometry (the classic 80x24,
  Full footer tier, plan_eagle_columns' 37-column label region, the
  exact 24-line row budget: 3 of 22 watched cgroups shown, the
  detail trees, the hidden note, the whole footer block), with
  coherent arithmetic (the avg legs are the grand's legs over the
  rendered uptime, the census counts every candidate not just the
  shown rows); (2) four lookup tables — the header block, the
  ranked table (rank semantics, the static traffic light, live
  rates vs em dashes, the detail-tree shapes, the hidden note), the
  pinned footer (every line the owner named — `top consumer is X`,
  `1.2K packets + 22 cgroups`, the total row, the max/avg speed
  pair, the limit suggestion, the status line, the build stamp, the
  rare identities note — each with its horizon, scope, and source
  of truth), and the compression tier ladder (11/10/5/3 with what
  drops at each height); (3) the colors paragraph and the
  five-second reading order (headline names the eater, census the
  scale, total row the story, speed pair the intensity, suggestion
  line the action). The design-rationale prose stays as the "why";
  a pointer sentence now bridges the two. Every claim in the tables
  was extracted from the render sources (footer.rs, eagle.rs,
  detail.rs, render.rs) and the pinned tests, not from memory.

- **docs: NIGHT-hunt-24 — stale-data sweep: every count, name, and
  consumer list re-verified against the tree after the improve-20..23
  landing** — the hunt the owner ordered, run with a verifier's eye
  (nothing deleted on suspicion; everything deleted or renumbered on
  evidence). DEPENDENCY_AUDIT's SHA-pinning claim said "all 11
  dtolnay/rust-toolchain references" — the musl job of
  NIGHT-improve-20 grew the real count to 13, and the claim now says
  13 with the growth reason named. The shared harness engine's
  contract still said "the two flagship harnesses" and "the single
  engine both import" — the family is three since improve-23, and
  both the zelynic_harness_lib.py docstring and v1's own header now
  name the v2 consumer (v1's header also states the new invariant:
  a stage fixed in v1 lands in v2's local lane with no second copy
  to drift). USAGE.md's BINARY GATE troubleshooting row listed two
  harness startups; v2 shares the same gate and is listed.
  STABILITY.md's "covered by the supermassive test suite" now names
  both suites and their division of labor. PERFORMANCE.md's map
  row claimed "(8+) pinned via LIBBPF_PIN_BY_NAME" — the source
  declares exactly nine maps on aya's PinningType::ByName (the C
  semantic), and the row now says so. Verified NOT stale and left
  alone: the 13-pin-file count (9 maps + 2 program pins + 2 link
  pins, confirmed in src/ebpf/limiter/mod.rs), the gate-keepers
  "15 numbered sections / 17 gates" arithmetic, the two intentional
  retirement mentions (stress-test.sh, verify-bpf-refill.c) that a
  prior hunt codified, and every "no longer" design note in src/
  (all explain live behavior; zero TODO/FIXME markers exist in the
  tree). ruff, codespell, the language gate, and both harness
  self-tests re-run green after the sweep.

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
