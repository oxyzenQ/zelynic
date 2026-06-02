# Validation Report: <Distro Name> <Version>

> Fill in each section below. Use "Not recorded" for fields where data was not
> collected, and "Not applicable" for fields that do not apply to this
> environment.

## Host Information

| Field | Value |
|-------|-------|
| Distro name | |
| Distro version | |
| Kernel version | |
| Architecture | |
| Install type | bare metal / VM / container / WSL |
| cgroup mode | pure v2 / hybrid v1/v2 / v1 only |
| nftables version | |
| tc / iproute2 version | |
| systemd available | yes / no |
| systemd-run available | yes / no |
| Default interface | |
| Zelynic version | |
| Zelynic commit | |

## Read-Only Checks

### Host Fact Collector Output

```
<paste output of bash scripts/collect-host-facts.sh>
```

### Backend Doctor Result

```
<paste output of zelynic backend doctor>
```

**Capability summary:**

- cgroup v2: yes / no / partial
- nft socket cgroupv2: yes / no / unknown
- tc HTB qdisc: yes / no / unknown
- fw filter: yes / no / unknown
- Recommended backend: (from Backend Doctor output)

### Read-Only Verdict

Pass / Fail / Partial — explain.

## Privileged Strict Limiter Tests

> **Warning:** The following tests require root and modify nftables rules,
> tc qdisc state, cgroup membership, and runtime state. Run only on hosts
> where you accept these changes. Run only manually.

### Strict Limiter Test

**Command used:**

```bash
sudo zelynic strict --diagnose -d <rate> -u <rate> <target>
```

**Target application:**

**Observed bandwidth range:**

**Diagnostics output (key sections):**

```
<paste relevant diagnostic output>
```

**Result:** Pass / Fail — explain.

### Refresh Test

**Command used:**

```bash
sudo zelynic refresh <target>
```

**Scenario tested** (e.g., close and reopen target application):

**Result:** Pass / Fail / Not tested — explain.

### Unstrict Cleanup Test

**Command used:**

```bash
sudo zelynic unstrict <target>
zelynic status
```

**Post-cleanup state:**

**Result:** Pass / Fail / Not tested — explain.

## Known Caveats

- List any issues, workarounds, or unexpected behaviors observed during
  validation.
- Note any steps that required manual intervention.
- Note any features that were not tested.

## Final Status

| Field | Value |
|-------|-------|
| Status | Validated / Candidate / Partial / Unsupported / Not tested |
| Scope | strict limiter only / monitoring only / full / partial |
| Notes | |

## Metadata

| Field | Value |
|-------|-------|
| Date | |
| Tester | |
