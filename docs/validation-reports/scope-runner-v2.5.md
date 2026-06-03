# Validation Report: Scope Runner v2.5 (Live Probe + Attach Preview)

## Host Information

| Field | Value |
|-------|-------|
| Distro name | CachyOS (Arch-based) |
| Distro version | rolling |
| Kernel version | 6.18.33-1-cachyos-lts |
| Architecture | x86_64 |
| Install type | bare metal |
| cgroup mode | pure cgroup v2 |
| nftables version | v1.1.6 |
| tc / iproute2 version | 7.0.0 |
| systemd available | yes |
| systemd-run available | yes |
| Zelynic version | post-v2.4.0 / v2.5-prep |
| Zelynic commit | c51e7fe |
| Test date | 2026-06-03 |

## Scope

This report validates the v2.5 Scope Runner subsystem, which provides a controlled
live probe for system-scope transient systemd scope units, a non-mutating future
attach preview, and an explicit `--attach-live` gate that is hard-blocked. This is
not a full strict limiter validation report; it covers only the Scope Runner pipeline.

For the strict limiter validation on this host, see [arch-cachyos.md](arch-cachyos.md).

## Tested Commands and Results

### 1. Non-Root Normal Execute (Blocked)

**Command:**

```bash
zelynic run --execute -d 500kbit -u 500kbit -- sleep 5
```

**Result:** Blocked. Returns "Live systemd wrapper execution is not implemented yet."
No systemd scope launched, no mutation.

### 2. Non-Root System Execute (Blocked)

**Command:**

```bash
zelynic run --execute --scope-mode system -d 500kbit -u 500kbit -- sleep 5
```

**Result:** Blocked. Returns "Live systemd wrapper execution is not implemented yet."
No systemd scope launched, no mutation.

### 3. Non-Root User-Scope With --probe-live (Blocked)

**Command:**

```bash
zelynic run --execute --scope-mode user --probe-live -d 500kbit -u 500kbit -- sleep 5
```

**Result:** Blocked. Returns "User-scope live runner is not implemented."
No systemd scope launched, no mutation.

### 4. Non-Root System-Scope With --probe-live (Blocked)

**Command:**

```bash
zelynic run --execute --scope-mode system --probe-live -d 500kbit -u 500kbit -- sleep 5
```

**Result:** Blocked. Returns "Scope Runner live probe requires root (euid == 0)."
No systemd scope launched, no mutation.

### 5. Root System-Scope With --probe-live (Passed)

**Command:**

```bash
sudo target/debug/zelynic run --execute --scope-mode system --probe-live \
  -d 500kbit -u 500kbit -- sleep 5
```

**Result:** Passed. The Scope Runner:

- Launched a transient systemd scope (`systemd-run --scope --unit
  zelynic-probe-v250-sleep.scope -- sleep 5`).
- Queried the scope unit via `systemctl show`.
- Discovered **ControlGroup** path from systemd properties.
- Discovered **PID** from `cgroup.procs`.
- Rendered the **Future Attach Preview** section showing:
  - Discovered PID(s)
  - Future target cgroup path
  - Requested download/upload rates
  - Attach source label
  - Strict backend label
  - Status: "preview only; not applied"
- Printed safety disclaimers:
  - "No limiter attach was performed."
  - "No nftables, tc, Zelynic cgroup, or state changes were made."
  - "Bandwidth limiting is not active from this command yet."
- Documented the cleanup command.
- Unit ended inactive/dead after the child process exited.

**No mutation observed:**

- No PID was moved into any Zelynic target cgroup.
- No limiter attach was performed.
- No nftables rules were added or modified.
- No tc/qdisc/filter state was changed.
- No Zelynic cgroup directories were created.
- No Zelynic state files were written.
- Bandwidth limiting was not active.

### 6. Root System-Scope With --probe-live --attach-live (Hard-Blocked)

**Command:**

```bash
sudo target/debug/zelynic run --execute --scope-mode system --probe-live \
  --attach-live -d 500kbit -u 500kbit -- sleep 5
```

**Result:** Hard-blocked. Returns:

> Scope Runner live attach is not implemented yet. This build only supports
> live probe and attach preview.

The attach gate is reached only after the probe gate would otherwise succeed.
Even when all requirements (`--execute`, `--scope-mode system`, `--probe-live`,
`--attach-live`, root) are met, the command deliberately refuses.

**No mutation observed:**

- No PID was moved.
- No limiter attach was performed.
- No nftables, tc, cgroup, or state changes were made.

## Observed Results Summary

| Observation | Result |
|-------------|--------|
| Live probe launched systemd scope | Yes (root, system-scope, --probe-live) |
| ControlGroup discovered | Yes |
| PID discovered | Yes |
| Future Attach Preview rendered | Yes |
| No PID moved | Confirmed |
| No limiter attach | Confirmed |
| No nftables/tc changes | Confirmed |
| No Zelynic cgroup/state changes | Confirmed |
| Bandwidth limiting not active | Confirmed |
| Unit cleanup (inactive/dead) | Confirmed |
| --attach-live hard-blocked | Confirmed |

## Non-Root Gate Verification

All four non-root scenarios returned appropriate blocking messages without
attempting any mutation, privilege escalation, or systemd calls. The gating
model correctly distinguishes between missing flags, wrong scope mode, and
insufficient privileges.

## Final Status

| Field | Value |
|-------|-------|
| Status | Validated |
| Scope | Scope Runner live probe + attach preview |
| Notes | Live probe and attach preview work as designed on this host. Live limiter attach is not implemented and is hard-blocked via `--attach-live`. User-scope live runner remains blocked pending privilege/session handoff design. |
| Not implemented | Live limiter attach |
| Blocked | User-scope live runner |

## Metadata

| Field | Value |
|-------|-------|
| Date | 2026-06-03 |
| Tester | rezky_nightky |
