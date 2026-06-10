# Strict-Run UX Simplification Gate

**Status:** Implemented (Option A: hidden experimental alias)
**Date:** 2026-06-10
**Scope:** CLI parsing, dispatch routing, tests, documentation only.

## Background

The existing `zelynic strict -d 100kb aria2c` command operates in **attach mode**: it discovers
an already-running process by name or PID, moves it into a Zelynic-managed cgroup, and installs
nft/tc policy. This approach is fundamentally unreliable for processes that already have open
network sockets, because sockets created before the PID is moved into the cgroup will not match
the nft `socket cgroupv2` rule.

The hidden `zelynic strict-run-lab` command works correctly because it launches the child
process inside the target cgroup **before** the child opens any sockets (using `pre_exec` to
write the child PID to `cgroup.procs` between `fork` and `exec`).

## Problem

The working `strict-run-lab` command path is too long and not user-friendly:
```
zelynic strict-run-lab --diagnose --iface proton0 -d 100kb -- aria2c -x 1 -s 1 https://example.com/file.iso
```

## Design Decision

Three options were considered:

| Option | Shape | Risk |
|--------|-------|------|
| A: Hidden alias | `strict --run-lab -d <rate> -- <cmd>` | Lowest - keeps stable UX unpromoted |
| B: Visible experimental | `strict --run -d <rate> -- <cmd>` | Medium - could be confused with stable |
| C: Docs-only | No code change | Zero risk, zero progress |

**Chosen: Option A** — hidden `--run-lab` flag on the existing `strict` subcommand.

### Rationale

- The existing `strict` command's CLI surface is preserved: `zelynic strict -d 100kb aria2c`
  still works exactly as before (attach mode, best-effort).
- No visible promotion of pre-launch mode. `--run-lab` is `hide = true` in clap, so it does
  not appear in `--help` output.
- The working path becomes shorter and easier to test:
  ```
  zelynic strict --run-lab -d 100kb -- aria2c https://example.com/file.iso
  ```
- Internally reuses the existing `handle_strict_run_lab()` handler — no new behavior code.
- All existing `strict-run-lab` behavior is preserved: experimental banner, traffic proof,
  Ctrl+C cleanup, honest output wording.

## Implementation

### CLI Change (`src/cli.rs`)

Added to the `Strict` variant:
- `run_lab: bool` — hidden flag (`hide = true`), default `false`.
- `target` changed from `String` to `Vec<String>` with `num_args = 1..` to support
  multi-arg child commands when `--run-lab` is used.

In normal mode, `target` must contain exactly one value (the process name/PID).
In `--run-lab` mode, `target` contains the full child command (name + args after `--`).

### Dispatch Change (`src/commands/mod.rs`)

When `run_lab` is `true`, the dispatch routes to `strict_run_lab::handle_strict_run_lab()`
with `target` as the command vec. When `false`, it validates that `target.len() == 1` and
routes to the existing `strict::handle_strict()` — preserving exact existing behavior.

### Safety Guarantees

1. `--run-lab` is hidden from normal `--help`.
2. Normal `strict -d 100kb aria2c` remains attach mode (unchanged semantics).
3. Extra positional args in normal mode are rejected at dispatch with a clear error.
4. No `--run` flag exists (only `--run-lab`).
5. No `run --net-limit` alias exists.
6. `strict-run-lab` hidden subcommand still works.
7. No version bump, no schema change, no eBPF/quota/daemon/watch/ledger.
8. All existing tests pass.