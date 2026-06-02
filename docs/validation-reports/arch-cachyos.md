# Validation Report: Arch Linux / CachyOS

## Host Information

| Field | Value |
|-------|-------|
| Distro name | CachyOS (Arch-based) |
| Distro version | Not recorded |
| Kernel version | 6.18.33-1-cachyos-lts |
| Architecture | x86_64 |
| Install type | bare metal |
| cgroup mode | pure cgroup v2 |
| nftables version | v1.1.6 |
| tc / iproute2 version | 7.0.0 |
| systemd available | yes |
| systemd-run available | yes |
| Default interface | wlp1s0 |
| Zelynic version | v2.0.0+ |
| Zelynic commit | Not recorded |

## Read-Only Checks

### Host Fact Collector Output

Not recorded at the time of original validation. The host fact collector script
was added in a later release.

### Backend Doctor Result

Not recorded. The Backend Doctor command (`zelynic backend doctor`) was added
after the original v2.0.0 validation. However, the underlying capabilities are
known to be present based on the successful strict limiter tests.

**Capability summary:**

- cgroup v2: yes
- nft socket cgroupv2: yes
- tc HTB qdisc: yes
- fw filter: yes
- Recommended backend: strict (tc + nftables + cgroup v2)

### Read-Only Verdict

Pass — all required capabilities for the strict limiter path are present. The
host uses a pure cgroup v2 hierarchy with nftables and modern tc/iproute2.

## Privileged Strict Limiter Tests

### Strict Limiter Test

**Command used:**

```bash
sudo RUST_LOG=debug target/debug/zelynic strict --diagnose -d 500kb -u 500kb brave
sudo RUST_LOG=debug target/debug/zelynic strict --diagnose -d 500kbit -u 500kbit brave
```

**Target application:** Brave (browser)

**Observed bandwidth ranges:**

| Limit target | Observed range | Notes |
|-------------|----------------|-------|
| 500 KB/s | 3.1-3.9 Mbps | Byte-based unit. 500 KB/s is roughly 4 Mbps before protocol and test variance. |
| 500 Kbit/s | 0.28-0.55 Mbps | Bit-based unit. Fast.com and Speedtest.net may vary during ramp-up. |

Fast.com may show a short burst before stabilizing because browser tests ramp
connections and report rolling estimates.

**Result:** Pass — bandwidth limiting behaves as expected for both byte-based
and bit-based limits.

### Refresh Test

**Scenario tested:** Not explicitly recorded as a separate test during the
original v2.0.0 validation. The `refresh` command was added in v2.1.0 and has
unit-test coverage for state preservation, PID re-discovery, and deduplication.

**Result:** Not tested at validation time.

### Unstrict Cleanup Test

**Command used:**

```bash
sudo zelynic unstrict brave
zelynic status
```

**Result:** Pass — limits were removed and state was cleaned up successfully.
The unstrict lifecycle was further hardened in v2.1.0 and v2.2.0 to handle
cgroup restore and empty target cgroup removal.

## Known Caveats

- Runtime paths and identifiers use the `zelynic` namespace. Legacy `oxy`
  paths are historical and should only appear during legacy cleanup.
- Browser speed tests can briefly burst before stabilizing due to connection
  ramp-up behavior.
- Process-name matching is intentionally conservative. Use a numeric PID when
  exact targeting is needed.
- The systemd scope wrapper (`zelynic run --dry-run` / `--execute`) is
  experimental groundwork. Live systemd-run execution is not implemented.
- Validation was performed on a WiFi interface (`wlp1s0`). Interface switching
  (WiFi to Ethernet, VPN, tethering) requires re-applying strict limits.

## Final Status

| Field | Value |
|-------|-------|
| Status | Validated |
| Scope | strict limiter only |
| Notes | Strict limiter path validated with Brave on bare metal CachyOS/Arch host. Monitoring (list, watch) works without root. QoS, profile, and systemd-run paths not separately validated but share the same tc/nftables/cgroup infrastructure. |

## Metadata

| Field | Value |
|-------|-------|
| Date | 2026-06-01 (v2.0.0 Renaissance release) |
| Tester | rezky_nightky |
