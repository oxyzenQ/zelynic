# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Distro support matrix**: Added `docs/distro-matrix.md` with distribution support status labels, required capabilities, and validation checklist for tracking which Linux distributions have been validated with Zelynic's strict limiter path.
- **Host fact collector**: Added `scripts/collect-host-facts.sh`, a non-mutating, no-sudo shell script that collects kernel, distro, cgroup, userspace tool, and default route information for host capability assessment.
- **Distro validation flow**: Added a structured two-step validation flow to `docs/validation.md` covering non-root read-only capability checks and privileged strict limiter validation with documentation guidance.
- **Validation report templates**: Added `docs/validation-reports/` with README, per-distro report template, and initial Arch/CachyOS validation report documenting the v2.0.0 strict limiter test results.

## [2.2.0] - 2026-06-03 - v2.2.0 Scope Prelude

### Added

- **Experimental run groundwork**: Added `zelynic run` planning for a future systemd wrapper workflow.
- **Dry-run systemd wrapper planning**: `zelynic run --dry-run ...` renders the planned launch command, attach target, PID discovery handoff, and launch-then-attach flow without launching a process or modifying nftables, tc, cgroups, or state.
- **User-scope-first planning**: Run planning now defaults to user scope and previews `systemd-run --user --scope` to avoid surprise system Polkit prompts for GUI/user applications.
- **Scope mode selection**: Added planning-only `--scope-mode <user|system>` so system-scope previews are explicit.
- **Execution preflight**: `zelynic run --execute ...` now prints a non-mutating preflight that explains why live limiting is blocked or future-only for the selected scope/privilege combination.
- **Resolved-PID attach groundwork**: Added an internal strict attach path for already-resolved PIDs, preparing future launch-then-attach integration without changing current strict behavior.
- **Release notes**: Added `docs/release-v2.2.0.md` with scope, caveats, and validation notes for this release.

### Changed

- **Systemd wrapper docs**: Clarified that the future v2.2 model is launch-then-attach, not a native systemd cgroup backend.
- **Module layout**: Split large systemd wrapper and capability modules, and slimmed limiter orchestration so core Rust files stay under 1000 LOC.
- **Run safety wording**: README and usage docs now consistently describe `run` as experimental groundwork and `dry-run` as the safe preview path.

### Fixed

- **Unstrict lifecycle cleanup**: Fixed a lifecycle bug where PIDs already inside Zelynic target cgroups could be recorded as their own original restore destination.
- **Target cgroup removal**: After unstrict, Zelynic now avoids restoring PIDs back into `/sys/fs/cgroup/zelynic/target_<target>`, falls back to `/sys/fs/cgroup/zelynic` when needed, and can remove the emptied target cgroup.

### Notes

- `zelynic run --execute` is still non-mutating in v2.2.0 and returns `Live systemd wrapper execution is not implemented yet.`
- v2.2.0 does not implement live `systemd-run` execution.
- `zelynic strict` remains the currently validated limiter path.
- Systemd wrapper/run mode remains experimental groundwork, not a supported active backend.

## [2.1.0] - 2026-06-02 - v2.1.0 Backend Doctor

### Added

- **Backend Doctor**: Added `zelynic backend doctor` and `zelynic backend doctor --json` for read-only host capability diagnostics and deterministic backend recommendations.
- **Refresh command**: Added `zelynic refresh <target>` to manually move reopened or respawned target PIDs into an existing active limit without duplicating nftables or tc rules.
- **Interface-change warning**: `zelynic status` now warns when active limits are attached to an interface that differs from the current default route.
- **Release notes**: Added `docs/release-v2.1.0.md` with validation notes and caveats for this release.

### Changed

- **Runtime namespace**: Migrated active runtime paths and identifiers from legacy `oxy` names to `zelynic`: `/run/zelynic`, `/run/zelynic/zelynic.nft`, `/sys/fs/cgroup/zelynic`, and `table inet zelynic`.
- **Limiter internals**: Split the limiter implementation into focused modules without intentionally changing strict backend behavior.
- **Supply-chain policy**: Hardened local dependency checks with documented `cargo audit`, `cargo deny`, and `./build.sh check-all` workflow.
- **Strict lifecycle docs**: Documented that `zelynic strict` applies to new connections after cgroup movement; already-running requests may need reload or restart.

### Fixed

- **Unstrict cgroup restore**: `zelynic unstrict` now records and restores original cgroups when safe, falls back conservatively, removes empty target cgroups, and explains kept cgroups.
- **Refresh state preservation**: Mistimed `zelynic refresh <target>` no longer deletes active target state when the app is not currently running.
- **Release wording**: Fixed release/version wording that could produce duplicate `v` prefixes in docs or release titles.

### Notes

- Strict limiting remains validated on tested modern cgroup v2 systems, not all Linux distributions.
- v2.0.0-era `oxy` runtime artifacts are treated as legacy cleanup targets only.
- See `docs/release-v2.1.0.md` for release validation notes.

## [2.0.0] - 2026-06-01 - v2.0.0 Renaissance

### Renaissance Notes

- **Rebrand**: Project renamed from Oxy to Zelynic.
- **Binary rename**: The command is now `zelynic`.
- **License change**: Project license changed to `GPL-3.0-only`.
- **Strict limiter breakthrough**: `zelynic strict` has been validated on tested modern cgroup v2 systems using the tc/nftables/cgroup backend.
- **Strict diagnostics**: `zelynic strict --diagnose` is kept for real-host troubleshooting and now reports selected PID match reasons alongside cgroup, nftables, and tc diagnostics.
- **Process resolver safety**: Fixed false positives where terminal or shell processes could be selected only because their full command line contained the target name.
- **Validated Brave limiting on CachyOS/Arch**:
  - kernel `6.18.33-1-cachyos-lts`
  - nftables `v1.1.6`
  - tc/iproute2 `7.0.0`
  - pure cgroup v2
  - interface `wlp1s0`
- **Real validation results**:
  - `500 KB/s` target produced about `3.1-3.9 Mbps` in browser speed tests.
  - `500 Kbit/s` target produced about `0.28-0.55 Mbps` in Fast.com and Speedtest.net.
- **Compatibility**: Legacy runtime paths and identifiers are intentionally preserved for this release: `/run/oxy`, `/sys/fs/cgroup/oxy`, and `table inet oxy`.
- **Scope**: This release is validated on tested modern cgroup v2 systems; it does not claim universal support across all Linux distributions.

### Added

- **TUI live dashboard** — Real-time bandwidth monitoring with ratatui
  - Braille sparklines for RX/TX history
  - Table scrolling (j/k, arrow keys)
  - Empty state message when no connections
  - Process count in header
  - Ctrl+C clean exit handler
- **`--iface` global flag** — Specify or list network interfaces
  - Auto-detects default interface
  - Validates against available interfaces
  - Works with all commands (`list`, `strict`, `qos`, `profile`, `auto`)
- **`--live N` shorthand** — `zelynic list --live 2` instead of `--live --interval 2`
- **Preset profiles** — `zelynic strict --preset gaming/streaming/background`
- **QoS priority shaping** — `zelynic qos high/low` with HTB priority tiers
- **Named profiles** — `zelynic profile save/apply/list/delete`
- **Auto-throttle daemon** — `zelynic auto` with download/upload thresholds
- **Bandwidth watch** — `zelynic watch --alert` with desktop notifications
- **Bandwidth history** — `zelynic log` with snapshots and rotation
- **Auto-cleanup on re-limit** — `zelynic strict` auto-removes old rules for same target
- **Shell completions** — Bash, Zsh, Fish, Elvish, PowerShell
- **Man page generation** — `zelynic man`
- **`zelynic backend`** — eBPF/tc support detection
- **`zelynic auto --status`** — Check auto-throttle daemon status
- **Strict diagnostics** — `zelynic strict --diagnose` for backend validation and troubleshooting
- **`--help-all`** — Comprehensive help with all commands and examples
- **`--no-color`** — Disable colored output (also respects `NO_COLOR=1`)
- **IPv6 support** — Correct parsing of `[::1]:443` bracket notation

### Changed

- **Breaking**: Version bump from 1.0.0 to 2.0.0
- **Branding**: Project, package, binary, docs, and public examples now use Zelynic/`zelynic`
- **License**: Project now uses GNU GPL v3 via `GPL-3.0-only`
- **Monitoring**: Uses `ss -tuneiH` with per-socket byte counters (kernel 4.6+)
- **Process resolution**: inode-based via `/proc/*/fd/` instead of `/proc/net/tcp`
- **Target resolution**: Process-name matching is now conservative and no longer scans full command-line arguments
- **Rate limiting**: cgroup v2 process grouping with nftables marking and tc HTB shaping for strict limits
- **State persistence**: `/run/oxy/state.json` with JSON-serialized limit records, intentionally kept as a legacy compatibility path
- **CI**: GitHub Actions with lint, test, build, security audit, MSRV check
- **Release**: Tag-triggered release workflow with tar.gz + SHA256 checksum

### Fixed

- IPv6 address parsing in verbose mode (broken for bracket notation)
- Column alignment in process table (truncate_str padding bug)
- Terminal corruption on TUI error (raw mode entered before validation)
- Class ID race condition with `flock(2)` file locking
- Panic hook properly restored after TUI exit
- `zelynic watch` no longer requires root (monitoring is read-only)
- Strict CLI validation — unknown interface names show error with available list
- `zelynic strict` process-name targets no longer select zelynic, sudo, shells, or terminal emulators just because their command line contains the requested target

### Removed

- 205-line legacy crossterm live display (replaced by ratatui TUI)
- Duplicate display function code (consolidated)
- Orphaned `format_rate()` function

## [1.0.0] - 2026-01-01

### Added

- Initial release with tc-based bandwidth limiting
- Process resolution via `/proc/net/tcp` and inode matching
- `zelynic list`, `zelynic strict`, `zelynic unstrict`, `zelynic status` commands
- Basic CLI interface with colored output

[Unreleased]: https://github.com/oxyzenq/zelynic/compare/v2.2.0...HEAD
[2.2.0]: https://github.com/oxyzenq/zelynic/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/oxyzenq/zelynic/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/oxyzenq/zelynic/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/oxyzenq/zelynic/releases/tag/v1.0.0
