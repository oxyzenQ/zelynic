# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

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
  contract from v11.0.0 (previously v10.0.0), matching the v11 line under
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

### Repository

- **chore: changelog split into active file + v10-era archive**
  (NIGHT-improve-4) — the pre-v11 release history (development
  sections [1.0.0] through [7.0.0], the line up to the v10.x contract)
  moved verbatim to `CHANGELOG-V10-ERA.md`, leaving `CHANGELOG.md` a
  slim active file ([Unreleased] + a History pointer) instead of a
  3.5k-line monolith. Both files are frozen historical records
  for gate purposes: `check-headers.sh`, `inject-disclaimer.sh`, and
  the gate-keepers emoji sweep extend their CHANGELOG.md exclusion to
  the era file. No entry text was modified in the move.

## History

The frozen release history of the pre-v11 era (development sections
[1.0.0] through [7.0.0], the line up to the v10.x contract) lives in
[CHANGELOG-V10-ERA.md](CHANGELOG-V10-ERA.md) — split out in
NIGHT-improve-4 to keep this file small. Entries there are verbatim
historical records and are never rewritten.
