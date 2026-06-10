# Strict-Run-Lab Ctrl+C Cleanup Audit

## Purpose

This document records the audit and fix of the Ctrl+C (SIGINT) cleanup
behavior in the hidden experimental `strict-run-lab` command. Prior to
this phase, pressing Ctrl+C while a child process was running under
strict-run-lab would terminate the zelynic parent process without running
cleanup, leaving orphaned cgroup directories, tc classes/filters, and nft
table entries behind. Manual cleanup via `zelynic unstrict` was required.

This phase implements a minimal runtime fix: a SIGINT handler that sets an
atomic flag, a polled wait loop that detects the signal, kills the child,
and runs the full cleanup sequence. No stable promotion. No new dependencies
(the implementation uses `libc::sigaction` which is already in the dependency
tree).

## SRL-MVM-001 Shaping Proof (Pre-Existing)

Before this cleanup audit phase, SRL-MVM-001 (non-VPN single-connection
aria2c) was manually tested and confirmed:

- Route was non-VPN via wlp1s0
- Child launched inside Zelynic cgroup before sockets
- Speed stabilized around 60-106 KiB/s for 100kb policy
- All four nft counter groups were nonzero:
  - nft socket cgroupv2: 3456 packets / 204716 bytes
  - nft ct mark: 3456 packets / 204716 bytes
  - nft download policer: 4154 packets / 6269850 bytes
  - nft drop: 66 packets / 98472 bytes
- Manual cleanup with `zelynic unstrict aria2c` succeeded
- Ctrl+C did **not** automatically trigger cleanup (the blocker this phase fixes)

## Problem Statement

Prior to this fix, strict-run-lab had the following Ctrl+C behavior:

1. The handler printed `"(Press Ctrl+C to stop the child and trigger cleanup)"`
   — this was a misleading claim; no signal handler existed.
2. The parent process blocked on `child.wait()`, a blocking call that does
   not check for signals.
3. When the user pressed Ctrl+C, SIGINT was delivered to the parent process.
   Since no handler was installed, the default action (process termination)
   occurred immediately.
4. The cleanup code (cgroup removal, tc cleanup, state cleanup, nft table
   removal) never ran.
5. The user was left with orphaned state that required manual `zelynic unstrict`
   or `zelynic clean --all` to resolve.

## Fix Design

### Approach: libc::sigaction + AtomicBool + Polled Wait Loop

The fix uses only existing dependencies (`libc` is already in Cargo.toml):

1. **Global `AtomicBool`**: `SIGINT_RECEIVED` is a `static AtomicBool`.
   This is the only data the signal handler writes to — lock-free and
   async-signal-safe.

2. **Signal handler**: A minimal C ABI function that sets
   `SIGINT_RECEIVED` to `true`. No memory allocation, no locks, no
   mutable global state access beyond the atomic store.

3. **Installation**: `install_sigint_handler()` uses `libc::sigaction` to
   install the handler with `SA_RESTART` flag. It saves the previous
   handler for restoration.

4. **Polled wait loop**: Replaces the blocking `child.wait()` with a loop
   that calls `child.try_wait()` every 50ms. If the child has exited,
   the loop breaks with the exit status. If `SIGINT_RECEIVED` is set,
   the child is killed, reaped, and the loop breaks.

5. **Cleanup after loop**: After the loop exits (regardless of whether
   the child exited normally or was killed), the cleanup sequence runs:
   - cgroup directory removal
   - tc filter/class removal
   - state entry removal
   - nft table removal (if no other limits)
   - cleanup status report

6. **Signal restoration**: `restore_sigint_handler()` restores the
   previous SIGINT handler and resets `SIGINT_RECEIVED` to `false`.

### What Was NOT Changed

- No new crate dependencies added
- No changes to existing `strict` command behavior
- No changes to enforcement semantics
- No changes to the nft/tc policy installation logic
- No changes to the cgroup placement logic (pre_exec)
- No changes to traffic proof diagnostics
- No version bump
- No stable promotion
- No eBPF, quota, daemon, watch, or ledger changes

### CleanupStatus Model

A new `CleanupStatus` enum tracks the result of cleanup attempts:

```
CleanupStatus::Succeeded          — All cleanup steps completed without error
CleanupStatus::PartialFailure(e)  — Some steps failed; errors recorded
CleanupStatus::NotAttempted       — Cleanup was not applicable
```

### Output Wording

After Ctrl+C:
```
SIGINT Ctrl+C received, stopping child (PID <pid>)...
Cleanup attempted after Ctrl+C.
  Cleanup: removed target cgroup directory.
  Cleanup: removed tc class and filters.
  Cleanup: succeeded
```

After normal child exit:
```
Cleanup attempted after child exit.
  Cleanup: removed target cgroup directory.
  Cleanup: removed tc class and filters.
  Cleanup: succeeded
```

On partial failure:
```
  Cleanup: failed to remove cgroup dir: <error>
  Cleanup: removed tc class and filters.
  Cleanup: partially failed
    failed to remove cgroup dir: <error>
```

## Validation Matrix Status Update

| Scenario | Status | Note |
|----------|--------|------|
| SRL-MVM-001 | PASS | Non-VPN shaping confirmed before this phase |
| SRL-MVM-007 | Pending re-test | Ctrl+C cleanup now implemented; needs manual re-test |
| SRL-MVM-008 | Pending re-test | Normal exit cleanup improved with status reporting |

## Scope Constraints

- strict-run-lab cleanup audit/fix only
- strict-run-lab remains experimental
- strict-run-lab remains hidden (`hide = true`)
- No stable `strict --run`
- Existing stable `strict` unchanged
- No eBPF
- No quota
- No daemon/watch
- No ledger persistence
- No v3.0 usage JSON schema change
- No version bump
- No tag
- No release
- No package publish
- No new dependencies (uses existing `libc` crate)
