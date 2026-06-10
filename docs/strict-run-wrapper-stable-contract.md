# Strict-Run Wrapper Stable Contract

**Status:** Design document (contract for future stable promotion)
**Last updated:** 2026-06-10

## 1. Chosen Future Stable Command Shape

```
zelynic strict --run -d <rate> [-u <rate>] [--iface <interface>] -- <command> [args...]
```

This shape was chosen over alternatives:

| Alternative | Rejected Because |
|-------------|-----------------|
| `run --net-limit -d <rate> -- <cmd>` | `run` subcommand is already overloaded with systemd scope experiments |
| `strict --run` | Reserved for future stable promotion; currently `--run-lab` is the hidden experimental gate |

## 2. Current Implementation (v3.0.1 + UX gate)

The working experimental path uses `--run-lab` (hidden):

```
zelynic strict --run-lab -d 100kb -- aria2c https://example.com/file.iso
```

This is equivalent to:
```
zelynic strict-run-lab -d 100kb -- aria2c https://example.com/file.iso
```

Both internally call `handle_strict_run_lab()`.

## 3. Safety Contract

When the stable `--run` flag is eventually promoted, it MUST satisfy:

1. **Pre-exec cgroup placement**: Child PID is written to `cgroup.procs` in `pre_exec`,
   before `exec()`, ensuring sockets are created inside the cgroup.
2. **Policy installed != traffic proven**: Installing nft/tc rules does not guarantee
   traffic is shaped. Traffic proof counters (socket cgroupv2, ct mark, download policer,
   drop) must be checked and displayed.
3. **Traffic proof counters shown**: When `--diagnose` is used, all four counter groups
   must be displayed with actual values.
4. **Cleanup after child exit**: Cgroup directory, tc class/filters, state entry, and
   optionally nft table must be removed.
5. **No daemon/detach**: The wrapper blocks until the child exits.
6. **Explicit user command only**: No background process management.
7. **No hidden background limit**: The user explicitly specifies the command to wrap.
8. **No persistence**: No state is written to disk between sessions.
9. **No quota**: No byte/count-based limits.
10. **No eBPF**: No eBPF program loading.
11. **No stable claim until multi-host testing**: Single-host proof is not sufficient.
12. **Output says experimental**: Until promoted, output must clearly say "experimental"
    and "not stable".

## 4. Traffic Proof Contract

Four nft counter groups must be checked:

1. **Socket cgroupv2 match**: `meta cgroupv2 ...` counter
2. **CT mark propagation**: `ct mark ...` counter
3. **Download policer**: `limit rate ...` counter
4. **Drop counter**: Derived from policer match

Proof states:
- `NotChecked`: diagnostics not requested
- `NoMatchObserved`: all counters at zero
- `CgroupMatchObserved`: cgroup match > 0 but policer = 0
- `PolicerMatchObserved`: both cgroup and policer > 0

## 5. Cleanup Contract

Cleanup sequence:
1. Kill child on SIGINT (if still running)
2. Wait for child exit (reap PID)
3. Remove target cgroup directory
4. Remove tc class and filters
5. Remove state entry
6. Remove nft table if no limits remain

## 6. Compatibility Contract

- Existing `strict -d <rate> <target>` (attach mode) remains unchanged.
- `strict-run-lab` hidden subcommand remains available.
- v3.0 usage JSON schema (`schema_version: 1`) is unchanged.
- No ledger behavior is affected.

## 7. Required Before Stable Promotion

Before `--run` can be promoted from hidden to visible:

1. Multi-host validation (non-VPN, VPN/tun, single/multi-connection)
2. Browser process wrapper smoke test
3. Failed exec cleanup verification
4. Ctrl+C cleanup verification
5. Child normal exit cleanup verification
6. Interface mismatch warning verification
7. No-root permission error verification
8. Existing attach-based strict regression test
9. Existing strict traffic proof honesty regression
10. No version bump until all above pass