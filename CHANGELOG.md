# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [6.0.0] - 2024-04-16

### Added

#### Core Features
- **Bandwidth limiting** (`oxy strict`) — Apply download/upload limits to processes using tc/cgroup
- **Bandwidth removal** (`oxy unstrict`) — Remove limits from processes
- **Status monitoring** (`oxy status`) — Show active bandwidth limits
- **Process listing** (`oxy list`) — List network bandwidth usage per process
- **Live monitoring** (`oxy list --live`) — Real-time TUI with ratatui, sparklines, colored bars
- **Verbose output** (`oxy list --verbose`) — Per-connection breakdown (IP, port, protocol, bytes)
- **JSON output** (`oxy list --json`) — Machine-readable output for scripting

#### QoS & Auto-throttle
- **QoS priority** (`oxy qos`) — HTB-based priority shaping (high/low priority tiers)
- **Auto-throttle** (`oxy auto`) — Background daemon for automatic bandwidth management
- **Bandwidth alerts** (`oxy watch --alert`) — Desktop notifications when thresholds exceeded

#### Profiles & Persistence
- **Named profiles** (`oxy profile`) — Save and apply reusable bandwidth profiles
- **Historical tracking** (`oxy log`) — Persist bandwidth snapshots with rotation
- **Orphan cleanup** (`oxy clean`) — Clean up stale limits and state

#### Distribution
- **Static binary** — musl-linked static binary with zero dependencies
- **Install script** — `install.sh` with arch detection and SHA256 verification
- **GitHub Releases CI** — Automated builds for x86_64 and aarch64

#### Developer Experience
- **Shell completions** — Bash, Zsh, Fish, PowerShell, Elvish via `oxy completions`
- **Man page** — Generated man page via `oxy man`
- **eBPF foundation** — Optional `--features ebpf` with kernel detection
- **Backend info** — `oxy backend` command to check eBPF support status

### Technical
- CGroups v2 support with fallback to v1 hybrid
- IFB (Intermediate Functional Block) for per-process download limiting
- Transactional tc command execution with rollback
- Process respawn handling with automatic re-limiting
- Rate parsing supporting: byte, kb, mb, gb, kbit, mbit

## [1.0.0] - 2024-01-01

### Added
- Initial release with basic tc-based bandwidth limiting
- Process resolution via /proc/net/tcp and inode matching
- Simple CLI interface

[Unreleased]: https://github.com/oxyzenq/oxy/compare/v6.0.0...HEAD
[6.0.0]: https://github.com/oxyzenq/oxy/compare/v1.0.0...v6.0.0
[1.0.0]: https://github.com/oxyzenq/oxy/releases/tag/v1.0.0
