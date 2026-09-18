# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
