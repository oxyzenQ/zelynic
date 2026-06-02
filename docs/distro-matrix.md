# Zelynic Distro Matrix

## Purpose

The distro matrix tracks which Linux distributions and environments have been
validated with Zelynic, which are candidates for future testing, and which are
known to have limitations that prevent full functionality. This document exists
to set honest expectations: Zelynic's strict limiter path requires specific
kernel and userspace capabilities that are not present on every Linux host.

This matrix is a living document. Status entries are updated only when
validation evidence exists in the repository or has been confirmed by a
contributor with reproducible steps.

## Status Labels

| Label | Meaning |
|-------|---------|
| **Validated** | Strict limiter path has been tested on a real host with documented results. Bandwidth limiting behaves as expected. |
| **Candidate** | Distribution is expected to work based on its kernel and userspace stack, but has not been explicitly validated yet. |
| **Partial** | Some capabilities are present but others are missing or constrained. Strict limiting may work in some configurations but is not fully validated. |
| **Unsupported** | Known to lack required capabilities (cgroup v2, nftables, tc, or writable cgroup hierarchy). Strict limiting is not expected to function. |
| **Not tested** | No validation attempt has been made. Status is unknown. |

## Current Matrix

| Environment | Status | Notes |
|-------------|--------|-------|
| **Arch Linux / CachyOS** | Validated | Modern pure cgroup v2 host. Kernel `6.18.33-1-cachyos-lts`, nftables `v1.1.6`, tc/iproute2 `7.0.0`, pure cgroup v2. Brave bandwidth limiting observed within expected ranges. |
| **Fedora** | Candidate | Fedora ships cgroup v2 by default since Fedora 31, includes nftables and modern tc. Strict limiting is expected to work but has not been explicitly validated. |
| **Ubuntu** | Candidate | Ubuntu 22.04+ enables cgroup v2 by default. Older Ubuntu releases use hybrid cgroup v1/v2 which may need manual configuration. Not yet validated. |
| **Debian** | Candidate | Debian 12 (Bookworm) and later default to cgroup v2. Earlier releases use hybrid or v1-only mode. Not yet validated. |
| **openSUSE Tumbleweed** | Candidate | Rolling release with modern kernel and cgroup v2. Expected to work but not tested. |
| **NixOS** | Candidate | Modern kernel with cgroup v2 support. System configuration differs from standard distributions; validation would need Nix-specific documentation. |
| **WSL (Windows Subsystem for Linux)** | Partial / Unsupported | WSL2 provides a Linux kernel but cgroup v2 support, nftables, and tc availability vary by WSL version and Windows build. `zelynic backend doctor` should be used to check capabilities before attempting strict limiting. Most WSL configurations lack the writable cgroup hierarchy and nftables socket matching required for per-process limiting. |
| **Containers (Docker, Podman, LXC)** | Partial / Unsupported | Container environments typically constrain cgroup, nftables, and tc privileges. The strict limiter path requires writable access to the cgroup hierarchy and the ability to load nftables rules and tc qdisc on the host network interface. Unprivileged containers will not have these capabilities. A privileged container on a cgroup v2 host may work but this is not validated and is not a recommended use case. |
| **Non-systemd init (Gentoo, Alpine, etc.)** | Not tested | Zelynic does not require systemd for the strict limiter path (which uses tc + nftables + cgroup v2 directly). However, `zelynic run` planning assumes systemd-run and has not been tested on non-systemd hosts. |

## Required Kernel and Runtime Capabilities

The strict limiter path depends on the following host capabilities:

### Mandatory

- **cgroup v2**: Zelynic places target PIDs in `/sys/fs/cgroup/zelynic/target_<name>` and uses `socket cgroupv2` matching in nftables. A pure cgroup v2 hierarchy is strongly preferred. Hybrid cgroup v1/v2 systems may work but are not validated.
- **nftables**: Required for packet marking via `socket cgroupv2` match (download limiting) and flow marking (upload limiting). The host must support `nft` with the `socket` expression family.
- **traffic control (tc) with HTB qdisc**: Used for egress shaping. Requires `tc` from iproute2 and kernel support for the `fw` filter and `htb` qdisc.
- **Writable cgroup hierarchy**: Zelynic must be able to write PIDs into cgroup v2 `cgroup.procs` files under `/sys/fs/cgroup/zelynic/`.
- **Root privileges**: Strict limiting requires root to write to cgroup files, load nftables rules, and configure tc qdiscs.

### For Monitoring (non-root)

- `ss` utility (iproute2) for socket statistics
- `/proc` filesystem access for process-to-socket mapping
- Kernel 4.6+ for per-socket byte counters

## Important Caveats

- **Strict path is validated where tested**: The `zelynic strict` command is the only limiter path that has been validated on real hardware. Other backends (systemd scope wrapper, eBPF, cgroup v1 legacy) are experimental or future.
- **Systemd wrapper live execution is not implemented**: `zelynic run --dry-run` is a safe, non-mutating planning preview. `zelynic run --execute` prints a preflight summary and returns a "not implemented yet" error. No live systemd-run execution occurs.
- **Dry-run planning is safe/non-mutating**: Running `zelynic run --dry-run` does not launch processes, modify nftables, tc, cgroups, or state files.
- **Do not overclaim**: Only mark a distribution as "Validated" when real strict limiting has been tested with documented results. Use "Candidate" for distributions that are expected to work based on their stack.

## Manual Validation Checklist Per Distro

Use this checklist when adding a new distribution to the validated set:

### 1. Non-Root Read-Only Checks

These checks require no privileges and can be run immediately:

```bash
# Collect host facts
bash scripts/collect-host-facts.sh

# Check backend capabilities
zelynic backend

# Full Backend Doctor report
zelynic backend doctor

# JSON export for archiving
zelynic backend doctor --json > backend-doctor-<distro>.json
```

Verify that the Backend Doctor reports:
- cgroup v2: yes
- nft socket cgroupv2: yes (or at least nftables available)
- tc HTB: likely/supported
- fw filter: likely/supported

### 2. Privileged Strict Limiter Checks

These checks require root and will modify nftables rules, tc state, and cgroups:

```bash
# Apply strict limit with diagnostics
sudo zelynic strict --diagnose -d 500kb -u 500kb <target>

# Check status
zelynic status

# Verify bandwidth with a speed test or download in the target application

# Clean up
sudo zelynic unstrict <target>
zelynic status
```

### 3. Documentation

After successful validation, record:
- Distribution name and version
- Kernel version (`uname -r`)
- nftables version (`nft -V`)
- tc/iproute2 version (`tc -V` or `ip -V`)
- cgroup mode (pure v2, hybrid, or v1)
- Network interface used
- Target application tested
- Observed bandwidth ranges
- Any caveats or workarounds needed

Update this matrix and `docs/validation.md` with the results.

## See Also

- [docs/validation.md](validation.md) — real-machine validation records
- [docs/strict-backend-design.md](strict-backend-design.md) — strict limiter architecture
- [docs/systemd-wrapper-design.md](systemd-wrapper-design.md) — systemd scope wrapper design
