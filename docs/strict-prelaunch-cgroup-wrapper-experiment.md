# Strict Pre-Launch Cgroup Wrapper Experiment

## Purpose

This document describes the experimental `strict-run-lab` command, which tests the
hypothesis that launching a child process inside a Zelynic-managed cgroup BEFORE the
child opens network sockets will improve nft `socket cgroupv2` counter matching
compared to the existing attach-after-socket approach used by the stable `strict`
command.

This is a direct follow-up to the findings documented in
[strict-traffic-proof-honesty-audit.md](strict-traffic-proof-honesty-audit.md),
which showed that on Linux 6.18 + ProtonVPN/proton0, the existing `strict --diagnose`
approach produces 0 packets/0 bytes in both the nft cgroup match counters and the
download policer counters, even though PID cgroup verification succeeds.

## Hypothesis

The current `strict` command works by:
1. Discovering an already-running process by name or PID
2. Moving the PID into a Zelynic-managed cgroup (`/sys/fs/cgroup/zelynic/target_<name>/`)
3. Installing nft rules with `socket cgroupv2 level 2 "zelynic/target_<name>"`
4. Optionally forcing a brief egress drop to reconnect existing sockets

The problem is that sockets already created before the cgroup move retain their
original cgroup classification context. The nft `socket cgroupv2` expression matches
packets from sockets whose owning process was in the target cgroup at socket creation
time. Pre-existing sockets bypass this match entirely.

**Hypothesis**: If a child process is born inside the target cgroup before it opens
any network sockets, all sockets created by that process will be classified under the
target cgroup. This should cause nft `socket cgroupv2` counters to actually match
traffic, proving that the shaping policy is active.

## Command Interface

```
zelynic strict-run-lab [OPTIONS] -- <COMMAND> [ARGS...]
```

The command is hidden from help output (`hide = true` in clap). It is not stable and
must not be used in production.

### Options

| Flag | Description |
|------|-------------|
| `-d, --download <rate>` | Download speed limit (e.g., 500kb, 1mb) |
| `-u, --upload <rate>` | Upload speed limit (e.g., 500kb, 1mb) |
| `--diagnose` | Print backend diagnostics (always enabled in lab mode) |
| `--iface <interface>` | Network interface to use |

### Positional

The command to launch is specified after `--`:

```
zelynic strict-run-lab --iface proton0 -d 100kb -- aria2c -x 1 -s 1 https://example.com/file.iso
```

## Implementation Architecture

### Execution Flow

The `strict-run-lab` command follows a distinct execution flow from the stable
`strict` command, designed to place the child process in the cgroup before any
sockets are created:

1. **Root check**: Verify UID 0 (same as `strict`)
2. **Rate validation**: At least one of `-d` or `-u` required
3. **Interface resolution**: Default or explicit via `--iface`
4. **Cgroup pre-creation**: Create `/sys/fs/cgroup/zelynic/target_<name>/` BEFORE
   launching the child process
5. **Cgroup ID read**: Read the cgroup v2 ID from `cgroup.id` or fall back to
   directory inode number
6. **Pre-exec cgroup placement**: Fork+exec the child with a `pre_exec` closure
   that writes the child's own PID to `cgroup.procs` before `exec()` is called
7. **Cgroup verification**: After 100ms delay, verify the child PID is in the
   target cgroup via `/proc/<pid>/cgroup`
8. **Policy installation**: Delegate to `apply_limit_with_diagnostics()` which
   uses the existing strict infrastructure (nft rules, tc HTB class/fw filters)
9. **Traffic proof assessment**: Read nft counters and classify traffic proof
   status
10. **Wait for child exit**: Block until the child process terminates
11. **Cleanup**: Remove target cgroup, tc class/filters, state entry, and optionally
    the entire nft table if no limits remain

### Pre-Exec Safety

The `CommandExt::pre_exec` closure runs between `fork(2)` and `exec(3)`. This is an
`unsafe` Rust operation because only async-signal-safe functions may be called in
this context. The closure performs exactly one operation:

- Write the child's own PID (obtained via `std::process::id()`) to the
  `cgroup.procs` file of the target cgroup

The closure does NOT:
- Allocate memory (no `malloc`, no `String::new()`, no `Vec::push()`)
- Spawn threads
- Access mutable global state
- Call any non-async-signal-safe functions

The `fs::write()` call is a thin wrapper around `write(2)` to a pre-opened file
descriptor, which is async-signal-safe.

### Cleanup Strategy

The cleanup function `attempt_cleanup()` removes:
- The target cgroup directory
- TC fw filters (IPv4 and IPv6) for the target class ID
- TC HTB class for the target

Additionally, after the child exits, the handler removes the target from
`ZelynicState` and deletes the entire nft table if no other limits remain.

### Key Difference from `strict`

The stable `strict` command:
1. Discovers already-running PIDs
2. Moves them into the cgroup
3. Forces reconnection of existing sockets via brief egress drop

The `strict-run-lab` command:
1. Creates the cgroup first
2. Launches the child directly into the cgroup via `pre_exec`
3. No forced reconnection needed (child has no pre-existing sockets)

## Experimental Target

The primary manual experiment target is:

```
zelynic strict-run-lab --diagnose --iface proton0 -d 100kb -- aria2c -x 1 -s 1 https://releases.ubuntu.com/24.04/ubuntu-24.04-desktop-amd64.iso
```

### Expected Proof Criteria

For the pre-launch approach to be considered effective, the nft counters must show:

| Counter | Expected Value |
|---------|---------------|
| nft cgroup match | packets > 0, bytes > 0 |
| nft download policer | packets > 0, bytes > 0 |

### Live Proof Results (Hypothesis Confirmed)

The experiment was run successfully on Linux 6.18 + ProtonVPN (proton0) + aria2c.

**Command**: `zelynic strict-run-lab --diagnose --iface proton0 -d 100kb -- aria2c -x 1 -s 1 https://releases.ubuntu.com/24.04/ubuntu-24.04-desktop-amd64.iso`

**Observed nft Counter Values**:

| Counter | Packets | Bytes |
|---------|---------|-------|
| nft socket cgroupv2 match | 1,800 | 210,054 |
| nft ct mark | 1,971 | 286,838 |
| nft download policer | 3,236 | 4,456,466 |
| nft drop | 531 | 741,189 |

**Comparison with attach-after-socket**:

| Metric | Attach-After-Socket (strict) | Pre-Launch (strict-run-lab) |
|--------|-------------------------------|-----------------------------|
| PID cgroup verification | Success | Success |
| nft socket cgroupv2 pkts | 0 | **1,800** |
| nft socket cgroupv2 bytes | 0 | **210,054** |
| nft download policer pkts | 0 | **3,236** |
| nft download policer bytes | 0 | **4,456,466** |
| nft drop pkts | 0 | **531** |
| nft drop bytes | 0 | **741,189** |
| Traffic proof active | No | **Yes** |

**Conclusion**: The hypothesis is confirmed. Pre-launch cgroup placement via
`CommandExt::pre_exec` produces nonzero nft counters on a VPN/tunnel interface
where the attach-after-socket approach showed 0/0. All four counter groups show
active traffic matching, including policer drops confirming enforcement.

See [strict-run-lab-validation-freeze.md](strict-run-lab-validation-freeze.md) for
the full validation freeze with 13 deterministic invariant tests.

If both counters remain at 0 despite the child being verified in the cgroup,
the hypothesis is not supported. Possible explanations include:
- Kernel behavior with `socket cgroupv2` on tunnel interfaces
- ProtonVPN routing that bypasses the cgroup match path
- nftables `socket cgroupv2` implementation limitations on kernel 6.18

### Known Limitations

1. **VPN/tunnel interfaces**: proton0, tun0, wg0 and similar tunnel interfaces
   may still fail due to kernel/tunnel encapsulation. The `is_tunnel_interface()`
   detector warns about these.
2. **Single child only**: The command launches exactly one child process.
   It does not handle process trees or subprocess spawning.
3. **Non-detachable**: The command blocks until the child exits. It does not
   daemonize or detach from the terminal.
4. **Root required**: Same as `strict`, requires root privileges.

## Scope Constraints

The `strict-run-lab` command is intentionally constrained:

- It does NOT alter existing `strict` command semantics
- It does NOT add enforcement capabilities beyond what `strict` already provides
- It does NOT enable eBPF, quotas, daemon mode, or watch mode
- It does NOT modify the v3.0 usage JSON schema
- It does NOT add persistence, ledger file I/O, or identity resolution
- It does NOT change version numbers or create releases

## Tests

20 deterministic unit tests in `src/commands/strict_run_lab.rs`:

### Output Content (tests 1-4, 16-20)
- Banner contains "EXPERIMENTAL", "PRE-LAUNCH", "LAB"
- Banner mentions cgroup
- Banner says "not stable"
- Banner says "PID moved" and "traffic proven"
- Handler says "experimental", "lab", "policy installed", "pre-launch cgroup", "traffic proof"

### Functional (tests 5-7, 15)
- Tunnel detection works for proton0/tun0/wg0 (delegates to existing `is_tunnel_interface()`)
- Traffic proof model is reused from existing `StrictTrafficProof`
- Cleanup function exists and is callable
- Zero counters are not claimed as proven

### Safety Invariants (tests 8-14)
- No daemon code
- No watch code
- No quota code
- No eBPF code
- No ledger persistence references
- No usage JSON schema changes
- Cleanup called on error paths
- No detach or daemonize

## Files Modified

### Added
- `src/commands/strict_run_lab.rs` (handler + 20 tests, ~500 LOC)

### Modified (visibility changes only)
- `src/limiter/mod.rs`: Changed several `use` imports to `pub(crate) use` to
  expose needed types/functions for the lab handler: `verify_pid_in_cgroup`,
  `sanitize_target_name`, `print_strict_apply_summary`, `StrictApplySummary`,
  `ensure_conntrack`, `ensure_kernel_modules`, `ensure_htb_qdisc`,
  `target_class_id`, `TcTransaction`, and traffic_proof re-exports.
  Changed `mod traffic_proof` to `pub(crate) mod traffic_proof`.
- `src/limiter/tc.rs`: Changed `target_class_id` from `pub(super)` to `pub(crate)`,
  `TcTransaction` from `pub(super)` to `pub(crate)`, `ensure_htb_qdisc` from
  `pub(super)` to `pub(crate)`.
- `src/limiter/process.rs`: Changed `sanitize_target_name` from `pub(super)` to
  `pub(crate)`.
- `src/limiter/prereq.rs`: Changed `ensure_kernel_modules` and `ensure_conntrack`
  from `pub(super)` to `pub(crate)`.
- `src/limiter/output.rs`: Changed `print_strict_apply_summary` from `pub(super)` to
  `pub(crate)`.

### Pre-existing (already committed)
- `src/cli.rs`: `StrictRunLab` variant already in `Commands` enum (hidden)
- `src/commands/mod.rs`: Dispatch already wired
- `src/cli/tests.rs`: CLI parse tests already present

## Future Stable Wrapper Design

A design contract for a future stable wrapper command has been created in
[strict-run-wrapper-stable-contract.md](strict-run-wrapper-stable-contract.md).
The chosen shape is `zelynic strict --run -d <rate> -- <command>`, which extends
the `strict` family with a launch mode modifier. The contract defines safety,
traffic proof, cleanup, and compatibility requirements, plus a promotion
checklist of 10 required test scenarios. The design is documentation only and
does not implement any stable command.

## Non-Goals

- This is NOT a production feature
- This does NOT fix the VPN/tunnel limitation
- This does NOT add multi-process or process tree support
- This does NOT replace the stable `strict` command
- This does NOT claim to prove Zelynic shaping works in production
