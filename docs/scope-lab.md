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

## Launch / Discover / Attach Contract

The v2.4 Scope Lab phase 3 introduces a **design contract** that models the future
live run as a split, three-phase operation. This contract is a planning artifact,
not live execution. No code in this phase performs any mutation, systemd calls,
filesystem writes, or process launches.

### Contract Overview

The contract defines three sequential phases, each represented as a data-only
struct in `src/systemd_wrapper/contract.rs`:

| Phase | Description | Privilege | Implemented |
|-------|-------------|-----------|-------------|
| **Launch** | Create a transient systemd scope via `systemd-run` (user or system) | User manager (user scope) / system manager or root-or-polkit (system scope) | No |
| **Discover** | Read ControlGroup from scope unit, then read PID(s) from `cgroup.procs` | User manager (user scope) / system manager / root-or-polkit (system scope) | No |
| **Attach** | Move discovered PIDs into Zelynic target cgroup and apply nftables + tc HTB limits | Root | No |

The contract is **pure data**: no `std::process::Command`, no filesystem I/O,
no nftables/tc/cgroup mutation. It exists to make the launch-then-attach model
explicit in code before any live implementation begins.

### Phase Details

**Launch phase** creates a transient systemd scope:

- User scope: `systemd-run --user --scope --unit <unit> -- <command>`
- System scope: `systemd-run --scope --unit <unit> -- <command>`

The command is backgrounded for PID discovery inspection time. This phase runs
in the user's session context (for user scope), preserving Wayland/X11, DBus,
portal access, and desktop integration.

**Discover phase** uses the ControlGroup-first PID discovery model:

1. Read ControlGroup from `systemctl [--user] show <unit> --property ControlGroup`.
2. Read PID(s) from `/sys/fs/cgroup${ControlGroup}/cgroup.procs`.
3. MainPID is optional/diagnostic only; not the primary source of truth.

This phase requires no special privilege beyond cgroup filesystem read access.

**Attach phase** applies the existing Zelynic strict backend:

- Move discovered PID(s) into `/sys/fs/cgroup/zelynic/target_<target>`.
- Apply nftables rules to the `inet zelynic` table.
- Configure tc HTB classes and filters.

This phase **requires root**. The existing `zelynic strict` backend already
provides this capability for resolved PIDs. The contract simply describes the
handoff point.

### Safety Properties

- `live_execution_implemented` is always `false` in the contract.
- All three steps are marked `implemented: false`.
- Safety gates enumerate blockers: live execution not implemented, attach requires
  root while launch runs in user context.
- The contract model has no side effects: it is data-only, suitable for testing
  without mocking or sandboxing.

### Privilege and Session Implications

The launch/discover/attach contract makes the privilege boundary explicit:

- **Launch + Discover** (steps 1-2): run as the calling user, in the user's
  session context. No root required.
- **Attach** (step 3): requires root for cgroup management, nftables, and tc.

User-scope launch combined with root attach requires explicit privilege/session
handoff. None of the candidate designs from the [Privilege and Session
Handoff](#privilege-and-session-handoff) section have been implemented. Live
execution remains blocked until one of those designs (or an alternative) is
selected and implemented.

### Contract in Dry-Run and Execute Output

Both `zelynic run --dry-run` and `zelynic run --execute` now include a
"Future launch/discover/attach contract" section in their output. This section
lists the three phases with their implementation status, description, and
privilege requirements. The output is designed to be readable and not overly
noisy.

### Manual Probe Recipe

The v2.4 Scope Lab phase 4 adds a **manual probe recipe** to the `zelynic run
--dry-run` output. This recipe provides ready-to-copy/paste shell commands
that users can run manually to test the Scope Lab flow without Zelynic executing
anything. The recipe is clearly marked as manual-only and is not executed by
Zelynic itself.

The recipe appears only in `--dry-run` output (omitted from `--execute` to avoid
noise) and includes four steps:

1. **Start backgrounded scope**: Launches a transient systemd scope in the
   background so there is time to inspect it.
2. **Inspect scope unit**: Queries systemd for MainPID, ControlGroup,
   ActiveState, and SubState properties.
3. **Read PID(s) from cgroup.procs**: Reads the ControlGroup path from the
   scope unit, then reads `cgroup.procs` to discover the actual PIDs.
4. **Cleanup**: Stops the scope unit.

For **user scope**, the recipe uses `systemd-run --user --scope` and `systemctl
--user` commands. No privilege escalation is needed. The backgrounded scope runs
in the user's session context.

For **system scope**, the recipe includes a clear warning that system scope may
require root/sudo and that plain non-root system scope can trigger Polkit/floating
auth. The recipe prefixes `systemd-run` and `systemctl stop` with `sudo`. The
inspect and cgroup.procs read steps use plain `systemctl show` (read-only, no
privilege escalation needed).

The recipe uses the same scope unit name and description that `zelynic run`
would use, so users can directly compare the recipe output against Zelynic's
planned output.

## Live Execution Status

**Live execution is not implemented.** The current `zelynic run --execute` path:

- Builds a structured execution plan.
- Prints the plan with ControlGroup-first discovery wording.
- Returns `"Live systemd wrapper execution is not implemented yet."`
- Does not launch `systemd-run`, `systemctl`, or any process.
- Does not modify nftables, tc, cgroups, or state.

Live execution remains blocked until privilege/session handoff is designed and
implemented. See the [Privilege and Session Handoff](#privilege-and-session-handoff)
section below.

## Privilege and Session Handoff

The fundamental blocker for live `zelynic run` execution is a privilege boundary
problem: launching a command in a user session does not require root, but
attaching bandwidth limits requires root. These two operations must cooperate
without creating usability problems or security gaps.

### The Privilege Boundary

| Step | Operation | Privilege Required | Context |
|------|-----------|-------------------|---------|
| 1. Launch | `systemd-run --user --scope ...` | User (no root) | User manager, session |
| 2. Discover | `systemctl --user show ... --property ControlGroup` | User (no root) | User manager |
| 3. Read PIDs | `cat /sys/fs/cgroup/.../cgroup.procs` | User (no root) | Cgroup filesystem |
| 4. Attach | Move PIDs into `/sys/fs/cgroup/zelynic/target_*` | **Root** | System cgroup |
| 5. Enforce | nftables + tc HTB rules | **Root** | Network namespace |

Steps 1-3 run in the user's session context. Steps 4-5 require root. This
split means `zelynic run` cannot be a single monolithic process running as one
user.

### Why This Is Hard

**User-scope launch runs in the user manager/session.** When `systemd-run
--user --scope` launches a process, that process inherits the user's session
environment: Wayland/X11 display, DBus session bus, portal access, desktop
theme, and other session-specific resources. This is critical for GUI
applications like browsers. If zelynic were to launch the command as root, the
application would run in root's session and lose access to the user's desktop
integration.

**Strict attach currently requires root.** The existing `zelynic strict`
backend needs root to create cgroup directories under `/sys/fs/cgroup/zelynic/`,
write nftables rules to the `inet zelynic` table, and configure tc HTB classes
and filters on the network interface. There is no non-root path for these
operations on a standard Linux system.

**Root may not have direct access to the correct user session context.** Even if
zelynic runs as root, the root user's session is separate from the target user's
session. Root cannot trivially see or interact with the user's `systemd --user`
manager or its scope units without explicitly setting `XDG_RUNTIME_DIR`,
`DBUS_SESSION_BUS_ADDRESS`, and other session variables.

**Plain system scope can trigger Polkit/floating auth.** Running `systemd-run
--scope` (system scope, not user scope) from an unprivileged desktop session
can trigger a Polkit authentication prompt. This is unexpected and disruptive
for a bandwidth limiter tool. Zelynic deliberately avoids triggering Polkit
prompts in its current design.

**Sudo `systemd-run` can wait for password and get stuck in some shells.** If
zelynic were to internally call `sudo systemd-run ...`, the sudo password
prompt may conflict with the terminal state, pipe handling, or shell integration.
In some terminal emulators and shell configurations, sudo can hang waiting for
a password that never comes. This makes internal sudo invocation unreliable as
a default behavior.

### Candidate Future Designs

All designs below are **future work and not implemented**. They represent
potential paths that may be explored in later v2.4 phases or subsequent
versions.

**Design A: User launches scope, root helper attaches discovered PIDs.**

The unprivileged zelynic binary:
1. Calls `systemd-run --user --scope` to launch the command (no root).
2. Queries `systemctl --user show` for ControlGroup (no root).
3. Reads `cgroup.procs` for discovered PIDs (no root).
4. Sends the discovered PIDs to a privileged helper (via Unix socket, D-Bus,
   or setuid helper).

The privileged helper (running as root):
5. Moves the discovered PIDs into `/sys/fs/cgroup/zelynic/target_*`.
6. Applies nftables and tc HTB rules.

This preserves the user's session context for the launched application while
gaining root only for the attach step. The communication channel between the
unprivileged launcher and the privileged helper needs careful design to avoid
PID races (discovered PIDs may exit before the helper processes them) and to
ensure the helper only processes requests from legitimate zelynic invocations.

**Design B: Root launches system scope only with explicit sudo/root mode.**

The user runs `sudo zelynic run --execute ...`. The entire zelynic process runs
as root:
1. Calls `systemd-run --scope` (system scope, not user scope) to launch the
   command.
2. Queries `systemctl show` for ControlGroup.
3. Reads `cgroup.procs` for discovered PIDs.
4. Moves PIDs into the Zelynic target cgroup.
5. Applies nftables and tc HTB rules.

This avoids the user-session problem entirely by running as root, but it means
the launched application runs in root's context. For CLI tools and non-GUI
applications this may be acceptable, but for browsers and GUI apps this approach
loses desktop integration. This design would need an explicit `--sudo` or
root-detection mode to avoid surprising users.

**Design C: Split launch/attach command pair.**

Two separate invocations:
1. `zelynic run launch --dry-run/-d/-u -- <command>` launches the command in
   a user scope and prints the discovered PIDs and ControlGroup path.
2. `zelynic run attach --target <name>` (run as root) reads the stored PID
   metadata from a shared state file and moves the PIDs into the Zelynic cgroup,
   then applies limits.

This decouples launch from attach entirely. The user runs the launch command
normally, then runs the attach command with elevated privileges. No inter-process
communication or helper daemon is needed. The shared state file must be in a
location accessible to both the user and root (e.g., `/run/zelynic/` with
appropriate permissions).

### Current Decision: Blocked

None of these designs have been implemented. The `zelynic run --execute` path
remains non-mutating and returns "Live systemd wrapper execution is not
implemented yet." until one of these designs (or an alternative) is selected,
implemented, and validated.

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
