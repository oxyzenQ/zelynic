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

**Live execution is not implemented for the general run path.** The current
`zelynic run --execute` path:

- Builds a structured execution plan.
- Prints the plan with ControlGroup-first discovery wording.
- Returns `"Live systemd wrapper execution is not implemented yet."`
- Does not launch `systemd-run`, `systemctl`, or any process.
- Does not modify nftables, tc, cgroups, or state.

Live execution remains blocked until privilege/session handoff is designed and
implemented. See the [Privilege and Session Handoff](#privilege-and-session-handoff)
section below.

## Scope Runner Live Probe (v2.5)

The v2.5 phase adds an explicit, controlled live probe for system-scope
transient systemd scope units. This is **not** the final limiter backend — it
is a Scope Lab runner that validates the launch-discover pipeline without
applying any bandwidth limiting.

### What It Does

When invoked with `--execute --scope-mode system --probe-live`, the Scope
Runner:

1. Launches a real transient systemd scope via `systemd-run --scope --unit
   <unit> --description <desc> -- <command>` (backgrounded).
2. Queries the scope unit via `systemctl show <unit>.scope --property
   MainPID --property ControlGroup --property ActiveState --property SubState`.
3. Reads PID(s) from `/sys/fs/cgroup${ControlGroup}/cgroup.procs` if the
   ControlGroup was discovered.
4. Reports findings: scope unit name, ControlGroup, ActiveState, SubState,
   discovered PID(s).
5. Prints honest safety disclaimers (no limiter attach, no nftables/tc/cgroup
   changes, bandwidth not active).
6. Documents cleanup command: `sudo systemctl stop <unit>.scope`.

### What It Does NOT Do

- Does NOT run `zelynic strict`.
- Does NOT call limiter attach.
- Does NOT modify nftables.
- Does NOT modify tc/qdisc/filter.
- Does NOT create or move processes into Zelynic cgroups.
- Does NOT write Zelynic state files.
- Does NOT claim bandwidth limiting is active.

### Requirements (All Must Be True)

1. `--execute` flag is set.
2. `--scope-mode system` is set.
3. `--probe-live` flag is set.
4. Effective UID is 0 (root).

If any requirement is missing, the old behavior is preserved:
- Missing `--probe-live`: returns "Live systemd wrapper execution is not
  implemented yet."
- User scope with `--probe-live`: returns "User-scope live runner is not
  implemented." — user-scope live runner needs privilege/session handoff.
- System scope non-root with `--probe-live`: returns "Scope Runner live probe
  requires root (euid == 0)."

### CLI Syntax

```bash
sudo zelynic run --execute --scope-mode system --probe-live -d 500kbit -u 500kbit -- sleep 60
```

### Cleanup

The scope runs in the background. To stop it:

```bash
sudo systemctl stop zelynic-probe-v250-sleep.scope
```

### Implementation

The Scope Runner is implemented in `src/systemd_wrapper/scope_runner.rs`:

- `probe_gate()`: Gating logic (probe_live + system + root).
- `run_scope_probe()`: Live execution (systemd-run, systemctl show,
  cgroup.procs read).
- `render_scope_probe_output()`: Honest output rendering.
- `build_probe_systemd_run_plan()`: Plan builder with v2.5 naming
  (`zelynic-probe-v250-<sanitized_target>`).

### Unit Name Convention

Probe scope units use the naming pattern:
`zelynic-probe-v250-<sanitized_target>` to distinguish them from the future
run-mode units (`zelynic-run-<target>`). Target names are sanitized to
lowercase alphanumeric with underscore separators, matching the existing
sanitization logic.

### User-Scope Status

`--probe-live` with default/user scope remains blocked. The error message
explains that user-scope live runner needs privilege/session handoff, which is
not implemented. This gate is enforced in `probe_gate()` before any system
calls are made.

### Future Attach Preview

After a successful live probe discovery, the Scope Runner prints a non-mutating
"Future attach preview" section. This preview bridges the discovered PID(s)
from the scope probe to the future resolved-PID strict attach backend, without
performing any mutation.

The preview section displays:

- **discovered PID(s)**: PID(s) found in the scope's cgroup.procs, or "(none)"
  if no PIDs were discovered.
- **future target cgroup**: The Zelynic target cgroup path that would be used
  for attachment (e.g. `/sys/fs/cgroup/zelynic/target_sleep`). This cgroup is
  NOT created by the preview.
- **requested download/upload**: The bandwidth rates specified on the command
  line, formatted as display strings (e.g. "500 Kbit/s"), or "unlimited" if not
  specified.
- **attach source**: Label identifying where PIDs were discovered ("systemd
  scope probe").
- **strict backend**: Label describing the backend that would perform the
  future attach ("existing resolved-PID attach backend").
- **status**: Always "preview only; not applied".

After the preview fields, additional safety disclaimers are printed:

- "No PID was moved."
- "No limiter attach was performed."
- "No nftables, tc, Zelynic cgroup, or state changes were made."
- "Bandwidth limiting is not active from this command yet."

### Attach Safety Preflight (v2.6 Groundwork)

The v2.6 Attach Safety Lab adds an "Attach safety preflight" section below the
Future Attach Preview. This section is pure and non-mutating. It is a data model
and render step only; it does not read `/proc`, write files, move PIDs, create
cgroups, call nftables/tc, write Zelynic state, or call the limiter attach
execution path.

The preflight describes the checks that must exist before any future live attach
can be considered:

- **PID liveness**: Every discovered PID must be verified alive immediately
  before attach.
- **Original cgroup capture**: Every PID's current cgroup path must be captured
  before movement so rollback has a known destination.
- **Self-protection**: Zelynic must reject its own PID, dead PIDs, and PIDs
  already inside Zelynic-managed cgroups unless that case is explicitly
  supported later.
- **Rollback plan**: A future attach must be able to restore PID(s) to captured
  original cgroups, clean up the Zelynic target cgroup only when safe and empty,
  and remove nftables/tc state only when it was created by that attach
  operation.
- **Mutation ownership**: Any future cgroup, nftables, tc, or state changes must
  be owned by the attach operation so cleanup can be precise.

Current status remains:

- `mutation status: blocked`
- `live attach: not implemented`

The preflight does not enable `--attach-live`. The `--attach-live` gate remains
hard-blocked.

#### Original Cgroup Capture Preview

The v2.6 phase 2 lab adds a pure original-cgroup capture preview model for
future rollback planning. It parses sample `/proc/<pid>/cgroup` text in unit
tests and validates cgroup v2 paths before they could become rollback targets.

The parser/model accepts pure cgroup v2 lines such as:

```text
0::/user.slice/user-1000.slice/session-2.scope
0::/system.slice/example.scope
```

It rejects malformed input, empty cgroup paths, parent traversal (`..`), and
paths already under `/zelynic` because restoring into a Zelynic-managed target
cgroup would be unsafe.

#### Read-only original cgroup capture

The v2.6 phase 3 lab introduces a read-only live original cgroup capture to the
successful root system-scope `--probe-live` path. This reads `/proc/<pid>/cgroup`
only after a successful root system-scope probe discovers PIDs.

- **Read-only**: This capture is strictly read-only. It does NOT attach, move,
  or limit any processes.
- **Honest rollback targets**: The rollback target becomes known and is displayed
  only if the capture succeeds. If the process has already exited and its cgroup
  cannot be read, it is marked as `missing` with reason `original cgroup capture unavailable/stale`.
- **Blocked attach**: The live attach (`--attach-live`) remains blocked. This
  capture step is merely information gathering for a future safe rollback plan.

Live Scope Runner probe output now reports the actual captured path:

- `original cgroup capture: read-only capture completed`
- `PID <pid>: captured original cgroup: /system.slice/example.scope`
- `rollback target: /sys/fs/cgroup/system.slice/example.scope`

This keeps rollback planning visible and prepares the exact rollback destination
before any future attach path could move a PID.

#### Read-only PID liveness and self-protection checks

The v2.6 phase 4 lab introduces read-only PID liveness and self-protection
evaluations to the root system-scope `--probe-live` path. This is vital safety
groundwork. Before any future attach, Zelynic evaluates discovered PIDs to ensure
they are still alive and that they are not Zelynic itself or already in a
Zelynic-managed cgroup.

- **Read-only**: Liveness checks rely on non-intrusive lightweight reads, such as
  checking if `/proc/<pid>` exists.
- **Attach still blocked**: A normal successful status (e.g. `preflight ok; attach still blocked`)
  simply means the PID is eligible. It does NOT mean the PID was attached or limited.
- **Live attach blocked**: Live attach (`--attach-live`) remains hard-blocked.

Live Scope Runner probe output now includes:

```text
    PID safety checks:
      PID <pid>: liveness: alive
      PID <pid>: self-protection: allowed
      PID <pid>: future attach eligibility: preflight ok; attach still blocked
```

### Experimental Attach Gate (v2.7 Phase 1)

The v2.7 Experimental Attach Lab adds an explicit gate checklist for a future
single-PID, move-only attach experiment. This phase is still model-only and
non-mutating. It does not move PIDs, create cgroups, write `cgroup.procs`,
apply nftables/tc state, write Zelynic state, or call the limiter attach path.

The future experiment requires every existing Scope Runner gate plus three
additional explicit consent flags:

```bash
zelynic run --execute --scope-mode system --probe-live --attach-live \
  --experimental-single-pid-attach \
  --i-understand-this-moves-pids \
  --rollback-required \
  -d 500kbit -u 500kbit -- sleep 60
```

The checklist evaluates:

- `--execute`
- `--scope-mode system`
- `--probe-live`
- `--attach-live`
- root / `euid == 0`
- `--experimental-single-pid-attach`
- `--i-understand-this-moves-pids`
- `--rollback-required`
- exactly one discovered PID
- valid original cgroup capture and rollback target
- PID liveness
- self-protection
- model-only transaction plan
- move-only mutation mode
- nftables/tc/Zelynic state disabled

#### Move-only executor skeleton (v2.7 Phase 2)

The v2.7 phase 2 lab adds a pure move-only executor skeleton to the experimental
gate output. This skeleton models the exact future write order for the first
possible mutation experiment, but it executes nothing.

The modelled future sequence is intentionally narrow:

1. Verify the gate checklist is still valid.
2. Verify exactly one discovered PID.
3. Verify the original cgroup path was captured for rollback.
4. Verify the target cgroup is under `/sys/fs/cgroup/zelynic/`.
5. Prepare the Zelynic target cgroup.
6. Write the PID to the target `cgroup.procs`.
7. Verify the PID appears in the target cgroup.
8. Write the PID back to the original `cgroup.procs`.
9. Verify the PID was restored.
10. Remove the target cgroup only if it is safe and empty.

This is still model-only:

- PID movement is not implemented.
- nftables, tc, and Zelynic state remain disabled.
- The limiter attach path is not called.
- `--attach-live` remains hard-blocked after rendering the checklist.

#### Target cgroup environment preflight (v2.7 Phase 3)

The v2.7 phase 3 lab adds a target cgroup environment preflight to the
move-only executor skeleton. This preflight models the future filesystem paths
that a single-PID move experiment would need, but it does not inspect live
filesystem metadata and does not create anything.

The preflight checks and renders:

- target namespace: `/sys/fs/cgroup/zelynic`
- target cgroup path, such as `/sys/fs/cgroup/zelynic/target_sleep`
- future target `cgroup.procs` path
- future rollback `cgroup.procs` path from the captured original cgroup
- parent and target status as "not created by this probe; future creation needed"
- execution status: `blocked`

Unsafe paths are blocked in the model, including paths outside the Zelynic
namespace, paths containing parent traversal (`..`), and the cgroup filesystem
root. This phase still performs no `mkdir`, no `cgroup.procs` write, no PID
movement, no limiter attach, no nftables/tc operation, and no Zelynic state
write.

Even if every checklist item is `ok`, the final result remains:

```text
final: blocked
reason: experimental PID move is not implemented yet
```

This phase exists to make the future consent and safety boundary auditable
before any implementation can write cgroups. The `--attach-live` path remains
hard-blocked/non-mutating, and bandwidth limiting is not active from this
command.

#### What the Preview Does NOT Do

- Does NOT move any PID into any cgroup.
- Does NOT create Zelynic target cgroups.
- Does NOT modify nftables rules or chains.
- Does NOT modify tc/qdisc/filter state.
- Does NOT write Zelynic state files.
- Does NOT call `zelynic strict`.
- Does NOT call the limiter attach execution path.
- Does NOT say "attached", "limited", "enforced", or "active limiter".

#### Implementation

The preview is implemented as a pure data model (`AttachPreview` struct in
`scope_runner.rs`) with a builder function (`build_attach_preview`) and inline
rendering in `render_scope_probe_output_with_preview`. The builder uses the
same target name sanitization and bandwidth rate parsing as the dry-run/execute
planning path, ensuring consistency between preview and plan output.

The existing `render_scope_probe_output` function is preserved for backward
compatibility; it delegates to `render_scope_probe_output_with_preview(result,
None)`, producing identical output to the phase 1 format when no preview is
present.

#### Future Direction

The preview bridges discovered PIDs to the future resolved-PID strict attach
backend. The next step is the `--attach-live` flag — a separate, explicit
attach gate that would actually move PIDs into the Zelynic target cgroup and
apply limits. This would NOT be automatic — the user would need to explicitly
opt in with `--attach-live`. The Scope Runner probe itself remains non-mutating.

### Live Attach Gate (`--attach-live`)

The `--attach-live` flag is an explicit future gate for live limiter attach.
It is **hard-blocked** in this build — no attach operation is performed.

#### What `--attach-live` Does NOT Do

- Does NOT move any PID into any cgroup.
- Does NOT create Zelynic target cgroups.
- Does NOT modify nftables rules or chains.
- Does NOT modify tc/qdisc/filter state.
- Does NOT write Zelynic state files.
- Does NOT call `zelynic strict`.
- Does NOT call the limiter attach execution path.

#### Requirements (All Must Be True)

1. `--execute` flag is set.
2. `--scope-mode system` is set.
3. `--probe-live` flag is set.
4. `--attach-live` flag is set.
5. Effective UID is 0 (root).

Without the v2.7 experimental consent bundle, the attach gate preserves the
existing hard-blocked behavior and returns:

> "Scope Runner live attach is not implemented yet. This build only supports
> live probe and attach preview."

With the full v2.7 experimental consent bundle, the root system-scope probe may
render the Experimental Attach Gate checklist and still returns:

> "Experimental PID move is not implemented yet. This build only supports live
> probe, safety checks, and attach/rollback planning."

#### Gate Order

The gates are evaluated in strict order:

1. `--probe-live` must be set (Clap enforces `requires = "execute"` and
   `requires = "probe_live"` for `--attach-live`).
2. `--scope-mode system` is required (probe gate).
3. Root (euid == 0) is required (probe gate).
4. `--attach-live` without the full experimental consent bundle hard-blocks
   before the live probe runs.
5. `--attach-live` with the full experimental consent bundle may render the
   gate checklist after the live probe, then hard-blocks before any mutation.

This means the attach gate is reached only when the probe gate would otherwise
succeed. At that point, the attach gate deliberately refuses.

#### Current Supported Live Path

The only supported live path in this build is:

```
launch system scope → discover ControlGroup/PID → print attach preview
```

Live attach requires another explicit implementation step and is not
available in this build.

#### CLI Syntax (Hard-Blocked)

```bash
sudo zelynic run --execute --scope-mode system --probe-live --attach-live \
  -d 500kbit -u 500kbit -- sleep 60
# Error: Scope Runner live attach is not implemented yet.
# This build only supports live probe and attach preview.
```

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

## Validation Report

A dedicated validation report for the v2.5 Scope Runner (live probe, attach
preview, and `--attach-live` hard-block) is available at:

- [docs/validation-reports/scope-runner-v2.5.md](validation-reports/scope-runner-v2.5.md)

That report documents six tested command scenarios (four non-root blocked, root
probe passed, root attach-live hard-blocked), observed results, and final
status. The Scope Runner live probe and attach preview are validated; live
limiter attach is not implemented; user-scope live runner remains blocked.

## Release Checklist (Scope Runner Smoke Matrix)

Before cutting a release that includes the Scope Runner, verify the following
smoke tests on a real cgroup v2 host:

### Non-Root Gate Checks (No Privilege Required)

1. `zelynic run --execute -d 500kbit -- sleep 1`
   - Expected: "Live systemd wrapper execution is not implemented yet."
2. `zelynic run --execute --scope-mode system -d 500kbit -- sleep 1`
   - Expected: "Live systemd wrapper execution is not implemented yet."
3. `zelynic run --execute --scope-mode user --probe-live -d 500kbit -- sleep 1`
   - Expected: "User-scope live runner is not implemented."
4. `zelynic run --execute --scope-mode system --probe-live -d 500kbit -- sleep 1`
   - Expected: "Scope Runner live probe requires root (euid == 0)."

All four must return the expected blocking message. No systemd scope should be
launched, no mutation should occur, and no privilege escalation should be
attempted.

### Root Probe Smoke

5. `sudo zelynic run --execute --scope-mode system --probe-live -d 500kbit -u 500kbit -- sleep 5`
   - Expected: launches systemd scope, discovers ControlGroup and PID,
     renders Future Attach Preview, prints safety disclaimers.
   - Verify: no PID moved, no limiter attach, no nftables/tc changes, no
     Zelynic cgroup/state changes, bandwidth not active.
   - After completion: unit should be inactive/dead.

### Root Attach-Live Hard-Block Smoke

6. `sudo zelynic run --execute --scope-mode system --probe-live --attach-live -d 500kbit -u 500kbit -- sleep 5`
   - Expected: "Scope Runner live attach is not implemented yet. This build
     only supports live probe and attach preview."
   - Verify: no PID moved, no limiter attach, no nftables/tc changes, no
     Zelynic cgroup/state changes.

### Automated Validation

In addition to the manual smoke tests, run the full automated validation suite:

```bash
cargo fmt --all -- --check
cargo test --locked
cargo clippy --all-targets --all-features -- -D warnings
python3 scripts/check-policy.py
git diff --check
```

## Probe Caveats

- Findings are from a single Arch/CachyOS host. Other distributions may behave
  differently.
- systemd versions differ in transient scope behavior and property reporting.
- Containers and WSL may expose partial systemd/cgroup signals.
- No privileged operations were performed during these probes.
