# Strict-Run Wrapper Stable Command Design Contract

## Purpose

This document defines the design contract for a future stable wrapper command that
launches a process inside a Zelynic-managed cgroup before the child opens network
sockets, then applies bandwidth limits and shows traffic proof. The contract is based
on lessons learned from the experimental `strict-run-lab` command, which confirmed
that pre-launch cgroup placement via `CommandExt::pre_exec` produces nonzero nft
`socket cgroupv2` counters on a VPN/tunnel interface where the attach-after-socket
approach showed 0/0.

This is a design document only. It does NOT implement a stable command. It does NOT
promote `strict-run-lab` to stable. It does NOT change existing `strict` behavior.
It does NOT add eBPF, quotas, daemon mode, watch mode, persistence, ledger file I/O,
enforcement mutations, or version bumps.

## 1. Chosen Future Stable Command Shape

### Candidate Options Considered

Three candidate shapes were evaluated for the future stable wrapper command:

1. **`zelynic run --net-limit 100kb -- aria2c ...`**
   - Pro: Short and intuitive. "run" implies launching a process.
   - Pro: `--net-limit` is explicit about what is being limited.
   - Con: The existing `run` subcommand has a long history of experimental flags
     (dry-run, execute, probe-live, attach-live, etc.) that would conflict or
     create confusion.
   - Con: `--net-limit` is a new flag name that does not match the existing
     `-d`/`-u` convention used by `strict`.

2. **`zelynic run --strict -d 100kb -- aria2c ...`**
   - Pro: Reuses the existing `run` subcommand with a modifier.
   - Pro: Reuses the familiar `-d`/`-u` flags from `strict`.
   - Con: The existing `run` subcommand already has deeply nested experimental
     gates (5+ required flags before any real action). Adding `--strict` would
     create yet another layer of complexity on an already overloaded command.
   - Con: `--strict` as a flag on `run` is semantically ambiguous — does it
     mean "use strict mode" or "call the strict command"?

3. **`zelynic strict --run -d 100kb -- aria2c ...`** (preferred, not implemented)
   - Pro: Extends the familiar `strict` subcommand, which users already
     associate with bandwidth limiting. The `--run` flag clearly indicates
     "launch a new process instead of attaching to an existing one."
   - Pro: Reuses the `-d`/`-u` rate convention from `strict` with zero learning
     curve.
   - Pro: Semantically clear: `strict` = bandwidth limit, `--run` = launch mode.
     Users who know `zelynic strict -d 100kb firefox` (attach mode) will
     immediately understand `zelynic strict --run -d 100kb -- aria2c ...`
     (launch mode).
   - Pro: Does not conflict with the overloaded `run` subcommand at all.
   - Pro: Natural migration path: `strict` (attach, current behavior) gains a
     sibling `strict --run` (launch, future behavior) under the same parent.
   - Con: Slightly more characters than option 1, but the clarity outweighs
     the length.

### Chosen Shape: `zelynic strict --run -d 100kb -- aria2c ...`

The preferred future UX is:

```
zelynic strict --run -d <rate> [-u <rate>] [--iface <interface>] [-- <command> [args...]]
```

This shape is chosen because it:
- Extends the `strict` family rather than creating a new top-level command
- Preserves the `-d`/`-u` rate convention
- Uses `--run` as an unambiguous modifier that means "launch mode"
- Avoids the overloaded `run` subcommand entirely
- Provides a clear mental model: same limiting, different launch method

**This shape is NOT implemented. It is a design decision for future work.**

## 2. Safety Contract

The future stable wrapper command MUST satisfy all of the following safety
invariants. These are derived from the lessons learned during the `strict-run-lab`
experiment and the traffic proof honesty audit.

### 2.1 Pre-Exec Cgroup Placement

The child process MUST be placed in the target cgroup before `exec()` is called.
This is the fundamental improvement over the existing `strict` attach-after-socket
approach. The implementation MUST use `CommandExt::pre_exec` (or equivalent)
to write the child PID to `cgroup.procs` between `fork(2)` and `exec(3)`. The
pre_exec closure MUST only perform async-signal-safe operations: specifically,
a single `write(2)` to the `cgroup.procs` file. No memory allocation, no thread
creation, no mutable global state access.

### 2.2 Policy Installed Does Not Equal Traffic Proven

The output MUST distinguish between "policy was installed" and "traffic was
actually shaped". Installing nft/tc rules is necessary but not sufficient —
the traffic proof counters must be checked and reported. The output MUST NOT
say "limited" unless traffic proof counters show nonzero packet/byte counts.
This invariant was established by the traffic proof honesty audit, which found
that PID cgroup verification succeeds but nft counters can remain at 0/0.

### 2.3 Traffic Proof Counters Must Be Shown

After policy installation, the command MUST read and display the following
nft counter groups:
- Socket cgroupv2 match counter (packets and bytes)
- Conntrack mark propagation counter (packets and bytes)
- Download policer match counter (packets and bytes)
- Drop counter (packets and bytes)

These counters MUST be shown regardless of whether they are zero or nonzero.
The output MUST explicitly state whether traffic proof is active, not observed,
or inconclusive. See Section 3 for the full traffic proof contract.

### 2.4 Cleanup Must Run After Child Exit

When the child process exits (normally, via signal, or via Ctrl+C), cleanup
MUST be attempted. Cleanup includes:
- Removing the target cgroup directory
- Removing tc filters and classes for the target
- Removing the target from ZelynicState
- Optionally removing the nft table if no other limits remain

If cleanup partially fails, the error MUST be reported honestly to the user.
The command MUST NOT silently leave orphaned state.

### 2.5 No Daemon/Detach by Default

The command MUST block until the child exits. There MUST NOT be a daemon mode
or detach flag by default. If a detach mode is ever added in the future, it
MUST require an explicit opt-in flag and MUST guarantee cleanup even after
the parent process exits.

### 2.6 Explicit User Command Only

The command MUST require an explicit child command after `--`. It MUST NOT
launch a default or implicit process. The user MUST explicitly specify what
to run.

### 2.7 No Hidden Background Limit

The command MUST NOT install limits that persist after the child exits.
All nft/tc rules and cgroup state MUST be cleaned up when the child exits.
There MUST NOT be any background process or watcher that continues to enforce
limits after the wrapper exits.

### 2.8 No Persistence

The command MUST NOT write any data to disk beyond the transient cgroup/nft/tc
state that is cleaned up on exit. There MUST NOT be any ledger entries, log
files, or configuration changes that persist after cleanup.

### 2.9 No Quota

The command MUST NOT implement byte-count quotas, data caps, or usage limits.
It is a rate limiter only, using nft policer and tc HTB to enforce bandwidth
rates.

### 2.10 No eBPF

The command MUST NOT load or attach any eBPF programs. The shaping pipeline
uses nftables and tc only.

### 2.11 No Stable Claim Until Multi-Host Testing

The command MUST NOT be promoted to stable until it has been tested on at
least the following environments:
- Non-VPN physical interface (e.g., eth0, wlan0)
- VPN/tunnel interface (e.g., proton0, tun0, wg0)
- Single-connection download (e.g., curl, wget)
- Multi-connection download (e.g., aria2c with multiple connections)
- Browser process (e.g., firefox, brave, chromium)
- Various Linux kernel versions (at minimum 6.x)

See Section 6 for the full promotion checklist.

## 3. Traffic Proof Contract

### 3.1 Counter Groups

The traffic proof system MUST track four nft counter groups:

| Counter Group | What It Measures | Expected Behavior |
|--------------|-----------------|-------------------|
| **Socket cgroupv2 match** | Egress packets from sockets created in the target cgroup | Should be > 0 if pre-launch placement worked |
| **Conntrack mark propagation** | Reply (download) packets matching the conntrack mark set by the output chain | Should be > 0 if the full shaping pipeline is active |
| **Download policer match** | Download traffic matched by the policer rule | Should be > 0 if download shaping is active |
| **Drop counter** | Packets dropped by the policer for exceeding the rate limit | May be 0 if rate is high enough; > 0 confirms enforcement |

### 3.2 Proof States

The traffic proof MUST be classified into one of the following states:

| State | Meaning | Output Wording |
|-------|---------|---------------|
| **Not checked** | Counters were not read (e.g., diagnose not enabled) | "traffic proof not checked" |
| **Not observed** | Counters were read but all are zero | "no traffic proof observed -- counters remain at zero" |
| **Observed** | At least the cgroup match counter is nonzero | "traffic proof observed -- shaping appears active in this run" |
| **Inconclusive** | Some counters are zero, some are nonzero | "partial proof -- cgroup match observed but policer did not trigger" |

### 3.3 Honesty Requirement

The output MUST NOT say "limited", "shaped", or "enforcing" unless the
`Observed` state is reached (cgroup match AND policer match both nonzero).
If only cgroup match is nonzero but policer match is zero, the output MUST
say "partial proof" and NOT claim active shaping. If all counters are zero,
the output MUST say "no traffic proof observed" and NOT claim anything
about shaping effectiveness.

### 3.4 Known Proof Values

The following values were observed in the successful `strict-run-lab` experiment
on Linux 6.18 + ProtonVPN (proton0) + aria2c downloading Ubuntu ISO:

| Counter | Packets | Bytes |
|---------|---------|-------|
| Socket cgroupv2 | 1,800 | 210,054 |
| Conntrack mark | 1,971 | 286,838 |
| Download policer | 3,236 | 4,456,466 |
| Drop | 531 | 741,189 |

These values are documented for reproducibility but must NOT be treated as
normative. Different environments, processes, and traffic patterns will
produce different values. The contract requires nonzero values, not specific
values.

## 4. Cleanup Contract

### 4.1 Cleanup Sequence

After the child exits, the following cleanup sequence MUST be attempted
in order:

1. **Remove target cgroup directory**: `rmdir /sys/fs/cgroup/zelynic/target_<name>/`
   - If the directory is not empty (e.g., child left sub-cgroups), report the error
     but continue with remaining cleanup steps.
2. **Remove tc fw filters**: `tc filter del dev <iface> ...` for both IPv4 and IPv6
   - If the filter does not exist, silently continue.
3. **Remove tc HTB class**: `tc class del dev <iface> classid 1:<tid>`
   - If the class does not exist, silently continue.
4. **Remove ZelynicState entry**: Remove the target from the in-memory state.
   - If no other limits remain, remove the entire nft table.
5. **Remove nft table** (conditional): `nft delete table inet zelynic`
   - Only if ZelynicState has no remaining limits.

### 4.2 Error Handling

If any cleanup step fails, the error MUST be reported to the user. The
output MUST distinguish between:
- Clean removal ("removed target cgroup directory")
- Failed removal ("failed to remove cgroup dir: <error>")
- Non-existent object (silently skipped)

The command MUST NOT silently swallow cleanup errors. Orphaned state is a
serious problem that can affect subsequent `strict` operations.

### 4.3 Signal Handling

On Ctrl+C (SIGINT), the command MUST:
1. Forward the signal to the child process (or rely on the default process
   group behavior)
2. Wait for the child to exit
3. Run the full cleanup sequence
4. Report cleanup results

### 4.4 Exec Failure Cleanup

If the child exec fails (e.g., command not found), the command MUST still
attempt cleanup of any cgroup or nft/tc state that was created before the
launch attempt. The fork may have succeeded and written to `cgroup.procs`,
so the cgroup directory may need removal.

## 5. Compatibility Contract

### 5.1 Existing Strict Behavior Unchanged

The future stable wrapper command MUST NOT modify the existing `strict` command
behavior in any way. The existing `strict` command uses attach-after-socket:
it discovers running PIDs, moves them into the cgroup, and optionally forces
reconnection. This behavior MUST remain unchanged.

The wrapper command is a new mode (`strict --run`), not a replacement for the
existing attach mode (`strict <target>`).

### 5.2 Strict-Run-Lab Remains Hidden and Experimental

The `strict-run-lab` command MUST remain `#[command(hide = true)]` in clap.
Normal `zelynic --help` output MUST NOT contain "strict-run-lab". The command
MUST continue to show experimental warnings, disclaimers, and honesty caveats.

The wrapper design contract document you are reading does NOT change the
status of `strict-run-lab`.

### 5.3 v3.0 Usage JSON Schema Unchanged

The future stable wrapper command MUST NOT modify the v3.0 usage JSON schema
(`schema_version: 1`). Usage commands like `zelynic usage --sample --delta --json`
MUST continue to produce output with `schema_version: 1`, `command`, `sample_mode`,
`sample_count`, `read_count`, `error` fields exactly as they exist today.

### 5.4 No Ledger Behavior Affected

The future stable wrapper command MUST NOT interact with the ledger system.
No ledger entries should be created, modified, or read by the wrapper command.
The ledger remains a separate concern for identity/reporting workflows.

## 6. Required Before Stable Promotion

The following test scenarios MUST all pass before the wrapper command can be
promoted from experimental to stable:

### 6.1 Functional Tests (Require Root + Network)

| # | Test | Description | Expected Result |
|---|------|-------------|----------------|
| 1 | Non-VPN test | Run aria2c on a physical interface (eth0/wlan0) | Traffic proof active |
| 2 | VPN/tun test | Run aria2c on a VPN/tunnel interface (proton0/tun0/wg0) | Traffic proof active |
| 3 | Single connection | Run curl/wget with a single download connection | Traffic proof active |
| 4 | Multi-connection | Run aria2c with multiple connections (-x 4) | Traffic proof active |
| 5 | Browser process | Launch firefox/brave/chromium and browse | Traffic proof active |
| 6 | Child exit cleanup | Launch `sleep 1`, wait for exit, verify cleanup | No orphaned cgroup/tc/nft |
| 7 | Ctrl+C cleanup | Launch long-running process, send SIGINT, verify cleanup | No orphaned state |
| 8 | Failed exec cleanup | Launch non-existent command, verify cleanup attempt | Cleanup attempted |

### 6.2 Safety Tests (Require Root)

| # | Test | Description | Expected Result |
|---|------|-------------|----------------|
| 9 | No-root error | Run without root privileges | Clear error message, no state change |
| 10 | Interface mismatch | Specify wrong interface | Warning about interface mismatch |

### 6.3 Deterministic Tests (No Root Required)

| # | Test | Description | Expected Result |
|---|------|-------------|----------------|
| 11 | CI determinism | All unit tests pass without root | All tests green |
| 12 | Proof model | StrictRunLabProofState correctly classifies proof values | Correct classification |
| 13 | Cleanup model | StrictRunLabOutcome correctly tracks cleanup_attempted | True on all post-launch variants |

### 6.4 Environmental Matrix

Tests must pass on at least:
- Linux kernel 6.x (preferably multiple minor versions)
- At least 2 different network interfaces (physical + VPN/tunnel)
- At least 2 different download tools (curl, aria2c)
- At least 1 browser process

### 6.5 Current Status

As of the `strict-run-lab` experiment:
- Test 2 (VPN/tun test): PASSED (proton0, aria2c, all counters nonzero)
- All other tests: NOT YET RUN
- Deterministic tests 11-13: PASSED (71 tests in strict_run_lab module)

## 7. Relationship to Existing Commands

### 7.1 vs `strict` (existing)

The existing `strict` command attaches to already-running processes using an
attach-after-socket approach. The future wrapper command launches new processes
using a pre-launch cgroup approach. Both commands share the same nft/tc policy
installation infrastructure (`apply_limit_with_diagnostics`), traffic proof
diagnostics (`build_traffic_proof`, `render_strict_traffic_proof`), and cleanup
logic. The key difference is the timing of cgroup placement relative to socket
creation.

### 7.2 vs `strict-run-lab` (experimental)

The `strict-run-lab` command is the current experimental implementation of the
pre-launch cgroup concept. It is hidden, experimental, and not suitable for
production use. The future stable wrapper command will be based on the lessons
learned from `strict-run-lab` but will:
- Be visible in help output (not hidden)
- Have clearer, production-appropriate output wording
- Have a more ergonomic CLI interface (`strict --run` vs `strict-run-lab`)
- Have passed all promotion tests (Section 6)

### 7.3 vs `run` (existing experimental)

The existing `run` subcommand is an experimental systemd scope wrapper with
deeply nested consent gates. The future wrapper command is a separate concept
that uses cgroup placement instead of systemd scopes. The `run` subcommand
remains unchanged and independent.

## 8. Non-Goals

- This document does NOT implement the stable command
- This document does NOT promote `strict-run-lab` to stable
- This document does NOT change existing `strict` behavior
- This document does NOT define eBPF, quota, daemon, or watch features
- This document does NOT change the v3.0 usage JSON schema
- This document does NOT add persistence, ledger I/O, or identity resolution
- This document does NOT define version bumps, tags, releases, or publications
- This document does NOT claim the experiment is conclusive
- This document does NOT prove Zelynic shaping works in all environments

## 9. Design Decision Record

| Decision | Rationale | Date |
|----------|-----------|------|
| `strict --run` shape chosen over `run --net-limit` | Avoids overloaded `run` subcommand; reuses `strict` brand and `-d`/`-u` flags | 2026-06-10 |
| Pre-exec cgroup placement required | Attach-after-socket showed 0/0 counters; pre-launch showed nonzero counters | 2026-06-10 |
| No daemon mode by default | Prevents orphaned state and hidden background limits | 2026-06-10 |
| Policy installed != traffic proven | Traffic proof honesty audit showed PID verification is not proof of shaping | 2026-06-10 |
| Multi-host testing required before promotion | Single environment (Linux 6.18 + proton0) is not representative | 2026-06-10 |
