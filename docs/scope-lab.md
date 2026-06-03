# v2.4 Scope Lab: Systemd Scope PID Discovery Findings

This document captures manual probe findings from real systemd scope unit behavior
on an Arch/CachyOS host. These findings inform the ControlGroup-first PID discovery
design for the v2.4 Scope Lab phase.

## Host Environment

- **zelynic version**: 2.3.0
- **Kernel**: 6.18.33-1-cachyos-lts (Arch/CachyOS)
- **cgroup**: pure cgroup v2
- **nftables**: v1.1.6
- **tc/iproute2**: 7.0.0

## Non-Mutating Probes

All probes below were performed manually with `systemd-run --user --scope` and
`systemctl --user show`. No zelynic limits were applied during these probes.
No privileged operations were required for the user-scope commands.

### Foreground Probe: Too Short-Lived for Inspection

```bash
systemd-run --user --scope --unit zelynic-probe-user-sleep -- sleep 30
```

A plain foreground scope can become inactive before the inspection command runs.
The scope exits when the child process exits, and there may not be enough time
to query `systemctl --user show` before the unit transitions to inactive/dead.
This is a known limitation of foreground scope units for PID discovery.

### Backgrounded Probe: Active and Inspectable

```bash
systemd-run --user --scope --unit zelynic-probe-user-sleep-bg -- sleep 60 &
```

Backgrounding the scope launch gives enough time to inspect the unit while it
is still running. This is the intended discovery pattern for future live
implementation.

### Inspection While Alive

```bash
systemctl --user show zelynic-probe-user-sleep-bg.scope \
  --property MainPID \
  --property ControlGroup \
  --property ActiveState \
  --property SubState
```

Observed output:

| Property       | Value |
|----------------|-------|
| ActiveState    | active |
| SubState       | running |
| ControlGroup   | `/user.slice/user-1000.slice/user@1000.service/app.slice/zelynic-probe-user-sleep-bg.scope` |
| MainPID        | (present, diagnostic use) |

Key finding: the ControlGroup path is always available and specific. It points
to the exact cgroup location where the scope's processes live.

### Reading PIDs from cgroup.procs

```bash
cat /sys/fs/cgroup${ControlGroup}/cgroup.procs
```

Example:

```bash
cat /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/zelynic-probe-user-sleep-bg.scope/cgroup.procs
# Output: 3062691
```

The `cgroup.procs` file contained a valid PID that could be used for cgroup
attachment. This confirms that `ControlGroup + cgroup.procs` is a reliable
PID discovery path for scope units.

### Cleanup

```bash
systemctl --user stop zelynic-probe-user-sleep-bg.scope
```

After stopping:

| Property       | Value   |
|----------------|---------|
| ActiveState    | inactive |
| SubState       | dead    |

The scope transitions cleanly to inactive/dead after the stop command.

## Design Conclusion: ControlGroup-First Discovery

For systemd scope units, PID discovery should be **ControlGroup-first**.

### Why Not MainPID-First?

- `MainPID` may be `0` for some scope units, especially transient scopes.
- `MainPID` may be absent entirely in certain systemd versions or configurations.
- For scope units (as opposed to service units), the concept of a single "main"
  PID is less meaningful because scopes track external processes, not internally
  managed services.
- Even when `MainPID` is valid, scope units may have additional child processes
  that `MainPID` alone does not capture.

### Why ControlGroup + cgroup.procs?

- The ControlGroup path is always available for active scope units.
- It is a specific, validated path reported by systemd itself.
- `cgroup.procs` contains all PIDs in the scope, not just a single main PID.
- Reading `cgroup.procs` requires no special privileges beyond access to the
  cgroup filesystem (which is already needed for strict attach).
- This approach works consistently across user-scope and system-scope units.

### Intended Discovery Flow

1. Launch command in transient systemd scope (backgrounded).
2. Query ControlGroup path from `systemctl show <unit> --property ControlGroup`.
3. Read PID(s) from `/sys/fs/cgroup${ControlGroup}/cgroup.procs`.
4. Pass discovered PIDs to the existing Zelynic strict attach backend.
5. Enforce nftables + HTB limits on the Zelynic target cgroup.

### MainPID Role

`MainPID` remains a requested property in the `systemctl show` command for
diagnostic and logging purposes, but it is **not** the primary source of truth
for PID discovery. In the decision model:

- If ControlGroup is available (which it should be for active scopes):
  use `ScanControlGroup` via `cgroup.procs`.
- If only MainPID is available (no ControlGroup, unlikely for active scopes):
  use `UseMainPid` as a fallback.
- If neither is available: report `NoUsableDiscovery`.

## Live Execution Status

**Live execution is not implemented.** The current `zelynic run --execute` path:

- Builds a structured execution plan.
- Prints the plan with ControlGroup-first discovery wording.
- Returns `"Live systemd wrapper execution is not implemented yet."`
- Does not launch `systemd-run`, `systemctl`, or any process.
- Does not modify nftables, tc, cgroups, or state.

Live execution remains blocked until:

1. Privilege/session handoff is designed (user-scope launch + root attach).
2. Backgrounded scope launch and timing are handled robustly.
3. PID discovery and strict attach are integrated with proper error handling.

## Strict Attach Requirement

The strict attach backend (`zelynic strict`) continues to require root for:

- Creating cgroup directories under `/sys/fs/cgroup/zelynic/`.
- Writing nftables rules to the `inet zelynic` table.
- Configuring tc HTB classes and filters.

This requirement is unchanged by the Scope Lab findings. The launch-then-attach
model means: launch via user-scope (no root), discover PIDs (read-only cgroup),
then attach via strict backend (requires root). The privilege boundary is between
steps 3 and 4 of the discovery flow.

## Probe Caveats

- Findings are from a single Arch/CachyOS host. Other distributions may behave
  differently.
- systemd versions differ in transient scope behavior and property reporting.
- Containers and WSL may expose partial systemd/cgroup signals.
- No privileged operations were performed during these probes.
