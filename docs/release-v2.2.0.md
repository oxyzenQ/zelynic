# Zelynic v2.2.0 Release Notes

Zelynic v2.2.0 "Scope Prelude" is a safe maintenance and groundwork release for
future systemd wrapper support. It does not implement live `systemd-run`
execution.

## Highlights

- Adds experimental `zelynic run` groundwork.
- Adds `zelynic run --dry-run` systemd wrapper planning.
- Defaults run planning to user scope to avoid surprise Polkit prompts.
- Adds planning-only `--scope-mode <user|system>`.
- Adds a non-mutating `zelynic run --execute` preflight boundary.
- Adds internal resolved-PID strict attach groundwork for future launch-then-attach.
- Fixes unstrict lifecycle cleanup so PIDs are not restored into Zelynic target cgroups.
- Keeps core Rust files under 1000 LOC with focused module splits.

## Run Mode Status

`zelynic run --dry-run ...` is a safe preview. It prints the future launch
command, PID discovery plan, Zelynic attach target, and planned flow without
launching a process or modifying nftables, tc, cgroups, or state.

`zelynic run --execute ...` is still non-mutating in v2.2.0. It prints the
execution plan and preflight decision, then returns:

```text
Live systemd wrapper execution is not implemented yet.
```

## Scope Planning

User scope is the default planning mode:

```bash
zelynic run --dry-run -d 500kbit -u 500kbit -- echo hello
```

System scope is explicit and planning-only:

```bash
zelynic run --dry-run --scope-mode system -d 500kbit -u 500kbit -- echo hello
```

Manual probing showed that `systemd-run --user --scope` worked for a user-scope
probe, while plain system scope can trigger Polkit/floating authentication and
timeout. Future live system-scope behavior should require root or explicit
opt-in.

## Validated Path

`zelynic strict` remains the currently validated limiter path. Backend Doctor
continues to report systemd wrapper/run mode as experimental groundwork and
dry-run/preflight only, not as an active supported backend.

## Release Compare

Use the previous stable release baseline:

```text
https://github.com/oxyzenQ/zelynic/compare/v2.1.0...v2.2.0
```
