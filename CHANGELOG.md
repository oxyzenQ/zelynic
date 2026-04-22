# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-04-21

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
- **`--live N` shorthand** — `oxy list --live 2` instead of `--live --interval 2`
- **Preset profiles** — `oxy strict --preset gaming/streaming/background`
- **QoS priority shaping** — `oxy qos high/low` with HTB priority tiers
- **Named profiles** — `oxy profile save/apply/list/delete`
- **Auto-throttle daemon** — `oxy auto` with download/upload thresholds
- **Bandwidth watch** — `oxy watch --alert` with desktop notifications
- **Bandwidth history** — `oxy log` with snapshots and rotation
- **Auto-cleanup on re-limit** — `oxy strict` auto-removes old rules for same target
- **Shell completions** — Bash, Zsh, Fish, Elvish, PowerShell
- **Man page generation** — `oxy man`
- **`oxy backend`** — eBPF/tc support detection
- **`oxy auto --status`** — Check auto-throttle daemon status
- **`--help-all`** — Comprehensive help with all commands and examples
- **`--no-color`** — Disable colored output (also respects `NO_COLOR=1`)
- **IPv6 support** — Correct parsing of `[::1]:443` bracket notation

### Changed

- **Breaking**: Version bump from 1.0.0 to 2.0.0
- **Monitoring**: Uses `ss -tuneiH` with per-socket byte counters (kernel 4.6+)
- **Process resolution**: inode-based via `/proc/*/fd/` instead of `/proc/net/tcp`
- **Rate limiting**: Per-UID cgroups on cgroup v2 for multi-process support
- **State persistence**: `/run/oxy/state.json` with JSON-serialized limit records
- **CI**: GitHub Actions with lint, test, build, security audit, MSRV check
- **Release**: Tag-triggered release workflow with tar.gz + SHA256 checksum

### Fixed

- IPv6 address parsing in verbose mode (broken for bracket notation)
- Column alignment in process table (truncate_str padding bug)
- Terminal corruption on TUI error (raw mode entered before validation)
- Class ID race condition with `flock(2)` file locking
- Panic hook properly restored after TUI exit
- `oxy watch` no longer requires root (monitoring is read-only)
- Strict CLI validation — unknown interface names show error with available list

### Removed

- 205-line legacy crossterm live display (replaced by ratatui TUI)
- Duplicate display function code (consolidated)
- Orphaned `format_rate()` function

## [1.0.0] - 2026-01-01

### Added

- Initial release with tc-based bandwidth limiting
- Process resolution via `/proc/net/tcp` and inode matching
- `oxy list`, `oxy strict`, `oxy unstrict`, `oxy status` commands
- Basic CLI interface with colored output

[Unreleased]: https://github.com/oxyzenq/oxy/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/oxyzenq/oxy/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/oxyzenq/oxy/releases/tag/v1.0.0
