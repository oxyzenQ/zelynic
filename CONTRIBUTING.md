# Contributing to zelynic

Thank you for your interest in contributing to zelynic! This document provides
guidelines and information for developers.

## Development Setup

### Prerequisites

- **Rust** 1.88.0 or later (see `rust-version` in `Cargo.toml`)
- **Linux** system (required for testing, as zelynic uses Linux-specific APIs)
- **Root access** (required for testing bandwidth limiting functionality)

### Clone and Build

```bash
git clone https://github.com/oxyzenq/zelynic.git
cd zelynic
cargo build --release
```

### Run Tests

```bash
# Run unit tests
cargo test

# Run all quality checks
./build.sh check-all
```

### Build with Features

```bash
# Default build (tc/cgroup backend only)
cargo build --release

# With eBPF support (requires kernel headers)
cargo build --release --features ebpf

# Static binary with musl
cargo build --release --target x86_64-unknown-linux-musl
```

## Code Style

### Formatting

Use `cargo fmt` to ensure consistent formatting:

```bash
cargo fmt --all
```

### Linting

All code must pass Clippy lints:

```bash
cargo clippy -- -D warnings
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types:
- `feat` — New feature
- `fix` — Bug fix
- `docs` — Documentation only
- `style` — Code style (formatting, no logic change)
- `refactor` — Code refactoring
- `perf` — Performance improvement
- `test` — Adding or fixing tests
- `chore` — Maintenance tasks

Examples:
```
feat(limiter): add cgroup v2 pure support
fix(monitor): handle missing /proc/net/tcp entries
docs(readme): update installation instructions
```

## Project Structure

```
src/
├── main.rs       # CLI entry point, command routing
├── cli.rs        # Clap CLI definitions
├── limiter.rs    # Bandwidth limiting (tc/cgroup)
├── monitor.rs    # Bandwidth monitoring (ss parsing)
├── ebpf.rs       # eBPF backend foundation
├── tui.rs        # ratatui TUI implementation
├── qos.rs        # QoS priority shaping
├── auto.rs       # Auto-throttle daemon
├── watch.rs      # Bandwidth watch/alert
├── log.rs        # Historical tracking
├── profile.rs    # Named profiles
├── info.rs       # Version and build info
└── units.rs      # Bandwidth unit parsing
```

## Testing

### Manual Testing

When testing bandwidth limiting, use `iperf3` or `curl` with `--limit-rate`:

```bash
# Terminal 1: Start iperf3 server
iperf3 -s

# Terminal 2: Limit a process
sudo ./target/release/zelynic strict -d 1mb iperf3

# Terminal 3: Run client (should be limited)
iperf3 -c localhost
```

### Testing Checklist

Before submitting a PR, verify:

- [ ] `cargo build --release` succeeds
- [ ] `cargo test` passes
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo fmt --all` produces no changes
- [ ] `./build.sh check-all` passes
- [ ] `zelynic --help` shows updated commands
- [ ] Man page generates correctly (`zelynic man`)

## Architecture

### Backend Selection

zelynic supports two backends:

1. **tc/cgroup** (default) — Works on all Linux systems, uses traffic control
2. **eBPF** (optional) — Lower overhead, requires kernel 5.2+ and CAP_BPF

The backend is auto-selected at runtime based on system capabilities.

### Bandwidth Limiting Flow

1. **Parse target** → Resolve process name to PID(s)
2. **Create cgroup** → Move process to new cgroup
3. **Setup tc** → Add HTB qdisc and class
4. **Apply filter** → Match cgroup classid to tc class
5. **Persist state** → Save to `/run/zelynic/state.json`

### Monitoring Flow

1. **Collect stats** → Parse `/proc/net/tcp`, `/proc/net/udp`, `ss -tan`
2. **Build inode cache** → Map socket inodes to PIDs via `/proc/*/fd/`
3. **Aggregate** → Sum bytes by process
4. **Display** → Render with ratatui or output as JSON

## Performance Considerations

- `/proc` scanning is the main overhead at high process counts
- Inode cache is rebuilt on each monitoring cycle (consider LRU caching)
- eBPF backend eliminates `/proc` scanning (future optimization)

## Security

- zelynic requires root for `tc`, `cgcreate`, and `/proc` access
- CAP_NET_ADMIN alone is insufficient for full functionality
- State files are stored in `/run/zelynic/` with 0755 permissions. Runtime cgroups and nftables identifiers also use the `zelynic` namespace.

## Release Process

1. Update `CHANGELOG.md` with new version
2. Update version in `Cargo.toml`
3. Run `./build.sh check-all` to verify
4. Tag release: `git tag v2.0.0`
5. Push tag: `git push origin v2.0.0`
6. GitHub Actions builds and uploads release artifacts

## Questions?

- Open an [issue](https://github.com/oxyzenq/zelynic/issues) for bugs
- Start a [discussion](https://github.com/oxyzenq/zelynic/discussions) for questions
- Read the [ROADMAP.md](ROADMAP.md) for future plans

## License

By contributing, you agree that your contributions will be licensed under
the GNU General Public License v3.0.
