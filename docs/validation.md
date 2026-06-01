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
