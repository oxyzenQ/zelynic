# Zelynic v2.0.0 Validation

This document records the real-machine validation used for the v2.0.0 Renaissance release.

## Tested Environment

- Distribution family: CachyOS/Arch
- Kernel: `6.18.33-1-cachyos-lts`
- nftables: `v1.1.6`
- tc/iproute2: `7.0.0`
- Cgroup mode: pure cgroup v2
- Network interface: `wlp1s0`
- Target application: Brave

This is a validated modern cgroup v2 environment, not a claim that every Linux distribution behaves identically.

## Commands Used

Backend and host inspection:

```bash
zelynic backend
```

Strict limiting with diagnostics:

```bash
sudo RUST_LOG=debug target/debug/zelynic strict --diagnose -d 500kb -u 500kb brave
```

Bit-based strict limiting:

```bash
sudo RUST_LOG=debug target/debug/zelynic strict --diagnose -d 500kbit -u 500kbit brave
```

Status and cleanup:

```bash
zelynic status
sudo zelynic unstrict brave
```

## Expected Results

Observed browser speed-test ranges on the validated host:

| Target | Expected observed range | Notes |
|--------|-------------------------|-------|
| `500 KB/s` | about `3.1-3.9 Mbps` | Byte-based unit. `500 KB/s` is roughly `4 Mbps` before protocol and test variance. |
| `500 Kbit/s` | about `0.28-0.55 Mbps` | Bit-based unit. Fast.com and Speedtest.net may vary during ramp-up. |

Fast.com may show a short burst before stabilizing because browser tests ramp connections and report rolling estimates.

## KB/s vs Kbit/s

Zelynic accepts both byte-based and bit-based units:

- `kb` means kibibytes per second in Zelynic's parser, so `500kb` is approximately `500 KB/s`, or about `4 Mbps`.
- `kbit` means kilobits per second, so `500kbit` is about `0.5 Mbps`.

Use `kbit`, `mbit`, or `gbit` when you want network-provider style bit rates.

## Diagnostics

Use `zelynic strict --diagnose ...` when validating a new host. Diagnostics include:

- selected target PIDs and match reasons
- cgroup v2 mode and mount information
- target cgroup path and level
- PID cgroup membership before and after movement
- generated nftables ruleset path and contents
- nft preflight and apply command output
- tc command output
- persisted state file contents

## Known Caveats

- Runtime paths and identifiers now use the `zelynic` namespace. v2.0.0-era `oxy` paths are historical and should only appear during legacy cleanup.
- The strict backend is validated on tested modern cgroup v2 systems, not all Linux distributions.
- cgroup v2, nftables, and tc/iproute2 availability are required for strict limiting.
- Browser speed tests can briefly burst before stabilizing.
- Process-name matching is intentionally conservative; use a numeric PID when exact targeting is needed.

## Distro Validation Flow

See [docs/distro-matrix.md](distro-matrix.md) for the full distribution support matrix and status labels.

### Step 1: Non-Root Read-Only Checks (safe, no privileges)

Collect host facts and check capabilities without modifying anything:

```bash
# Gather kernel, distro, cgroup, and tool information
bash scripts/collect-host-facts.sh

# Check backend capabilities (read-only)
zelynic backend

# Full Backend Doctor report
zelynic backend doctor

# Export for record-keeping
zelynic backend doctor --json > backend-doctor-<distro>.json
```

These commands require no root privileges and make no changes to the system. They can be run on any Linux host to determine whether Zelynic's strict limiter path is likely to function.

### Step 2: Privileged Strict Limiter Checks (requires root, modifies state)

These commands will load nftables rules, configure tc qdiscs, write to cgroup files, and create state in `/run/zelynic/`. Run only on hosts where Step 1 confirmed the required capabilities:

```bash
# Apply strict limit with full diagnostics
sudo zelynic strict --diagnose -d 500kb -u 500kb <target>

# Check active limits
zelynic status

# Verify with a speed test or download in the target application

# Remove limits and clean up
sudo zelynic unstrict <target>
zelynic status
```

These are manual-only operations. Do not run them from automated scripts or CI pipelines unless the environment is specifically prepared for destructive cgroup/tc/nft testing.

### Documentation After Validation

When adding a new distribution to the validated set, record the following and update [docs/distro-matrix.md](distro-matrix.md):

- Distribution name and version
- Kernel version (`uname -r`)
- nftables and tc versions
- cgroup mode (pure v2, hybrid, or v1)
- Network interface used
- Target application and observed bandwidth ranges
- Any caveats or workarounds needed
