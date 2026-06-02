# Systemd Wrapper Mode Design

This document captures the v2.2.0 groundwork for a future `zelynic run`
command. It is a design and dry-run path only; it does not change the current
strict backend.

## Problem

`zelynic strict` currently attaches already-running PIDs into a Zelynic cgroup.
That works for active processes, and browser tabs or child processes normally
stay limited while the process tree remains in the target cgroup. If an
application is closed completely and reopened, the new top-level process starts
in its normal systemd/user cgroup and needs `zelynic refresh <target>` or a new
strict apply.

## Goal

Launch a target command through systemd, discover the launched process IDs, and
then attach those PIDs with the existing Zelynic strict backend. This keeps the
runtime namespace under `/sys/fs/cgroup/zelynic/target_<target>` without
pretending that `systemd-run --scope` creates that cgroup directly.

Possible future commands:

```bash
sudo zelynic run -d 500kbit -u 500kbit -- helium
sudo zelynic run --target helium -d 500kbit -u 500kbit -- helium
zelynic run --dry-run -d 500kbit -u 500kbit -- helium
zelynic run --execute -d 500kbit -u 500kbit -- helium
```

## Current Dry Run

The current `run` command is intentionally gated. `--dry-run` parses rates,
target, and command arguments, then prints:

- planned transient systemd scope name
- planned scope mode
- command that would be launched
- preview-only `systemd-run` command line
- future Zelynic attach target cgroup path
- planned launch-then-attach flow
- future PID discovery method and preview commands
- confirmation that no process was launched
- confirmation that nftables, tc, cgroups, and state were not changed

This makes the future UX reviewable without introducing new privileged runtime
behavior.

`--execute` is now parseable as an explicit experimental opt-in, but live
execution is not implemented yet. It builds the same structured plan, prints a
concise execution preview, and returns a normal not-implemented error without
running `systemd-run`, `systemctl`, or modifying nftables, tc, cgroups, or
state. Running `zelynic run` without `--dry-run` or `--execute` errors clearly
so live behavior cannot be selected accidentally.

The displayed `systemd-run` command is for visibility only. Internally, Zelynic
keeps the command as structured argv; a future live implementation must execute
structured arguments directly and must not pass a rendered shell string to a
shell.

The dry-run default is `Scope mode: system`. That is only a planning default:
GUI applications may need user-scope or split root/user handling later so their
Wayland/X11, DBus, portal, and desktop session environment remains intact.

## Chosen v2.2 Model: Launch Then Attach

The likely v2.2 implementation path is:

1. launch the command in a transient systemd scope
2. discover the launched main PID and relevant child/scope PIDs
3. apply the existing Zelynic strict attach backend
4. enforce nftables + HTB limits against the Zelynic target cgroup

In this model, the systemd scope path and the Zelynic target cgroup are not the
same thing. `systemd-run --scope --unit zelynic-run-<target> ...` creates a
systemd-managed scope under system/user slices. Zelynic would then attach the
selected PIDs into `/sys/fs/cgroup/zelynic/target_<target>` using the same
cgroup/nft/tc backend used by `zelynic strict`.

An alternative native systemd cgroup backend would match nftables rules against
the systemd scope's relative cgroup path instead of the Zelynic target cgroup.
That requires backend abstraction work and is better treated as future major
backend design, not this v2.2 dry-run path.

## PID Discovery Handoff

After a future live launch, Zelynic needs a narrow handoff from systemd launch
state into the existing strict attach backend. The planned first check is:

```bash
systemctl show zelynic-run-<target>.scope --property MainPID --property ControlGroup --value
```

`MainPID` is the preferred direct PID when systemd reports one. `ControlGroup`
identifies the systemd launch scope location, not the Zelynic attach target.
If `MainPID` is missing, zero, or insufficient for a process tree, Zelynic can
scan the reported scope's process list:

```bash
cat /sys/fs/cgroup/<reported-control-group>/cgroup.procs
```

The `<reported-control-group>` segment is intentionally a placeholder in
dry-run output. Live code must use the ControlGroup reported by systemd and must
not guess a systemd cgroup path from the unit name.

For the current dry-run default, discovery previews system scope commands. A
future user-scope mode would need matching commands such as:

```bash
systemctl --user show zelynic-run-<target>.scope --property MainPID --property ControlGroup --value
```

Discovery must complete before applying strict attach. Once PIDs are known,
Zelynic should move only validated live PIDs into
`/sys/fs/cgroup/zelynic/target_<target>` and then reuse the existing nftables/tc
setup.

The parser accepts both normal `systemctl show` key/value output:

```text
MainPID=12345
ControlGroup=/system.slice/zelynic-run-helium.scope
```

and `--value` output in requested-property order:

```text
12345
/system.slice/zelynic-run-helium.scope
```

Discovery decisions are deterministic:

| Parsed metadata | Decision |
|-----------------|----------|
| valid `MainPID` + valid `ControlGroup` | use MainPID and optionally scan ControlGroup |
| valid `MainPID` only | use MainPID |
| valid `ControlGroup` only | scan ControlGroup |
| neither usable | no usable discovery |

`MainPID=0` is treated as no usable main PID. `ControlGroup` must be an absolute
systemd relative cgroup path, must not be `/`, and must not contain `..`. A
validated ControlGroup is only converted into a future path such as
`/sys/fs/cgroup/system.slice/zelynic-run-helium.scope/cgroup.procs`; dry-run code
does not read it.

## Integration With Strict

A live implementation should reuse the existing strict backend helpers for:

- rate parsing
- target cgroup naming
- nftables rules
- tc classes and filters
- state management
- unstrict cleanup

The wrapper should not create a parallel limiter backend. It should only change
how the first process is launched before Zelynic attaches it to the existing
target cgroup model.

The live execution boundary should remain narrow: build a structured
`systemd-run` argv, launch without a shell, read structured PID discovery data,
then hand validated PIDs to the existing attach backend. The current
`--execute` path deliberately stops before that boundary is crossed.

## Root And User Scope Tradeoffs

Root scope may be simpler for tc/nft/cgroup setup, but launching desktop GUI
apps as root is usually wrong. User scope is better for GUI session ownership,
but must preserve enough session context for Wayland/X11, DBus, portals, and
desktop integration.

Future implementation needs to decide whether the command is launched through:

- a system scope plus explicit user/session environment
- a user manager scope plus privileged limiter setup
- a split setup where Zelynic prepares rules as root and launches through the
  user manager

## State And Cleanup

Future state should keep the existing limit fields and may add optional scope
metadata, such as a scope name or launch mode. Old state files must continue to
parse.

`unstrict` should remove nftables/tc state as it does today. If Zelynic created
a transient scope, unstrict may release or stop that scope only when it can
prove the scope belongs to Zelynic and the target. It must not guess unrelated
systemd paths.

## Risks

- desktop launchers may fork, detach, or hand off to an existing instance
- GUI apps need the correct Wayland/X11 environment
- DBus session bus and portals must remain available
- child process inheritance must be verified across browsers and launchers
- `MainPID` may be `0` for some transient scopes
- the scope may exit before PID discovery completes
- commands may daemonize or hand off work to another process
- discovery must happen before applying strict attach
- systemd versions differ in transient scope behavior
- non-systemd distros need a different path or a clear unsupported result
- containers and WSL may expose partial systemd/cgroup signals

## Non-Goals For v2.2 Groundwork

- no eBPF backend
- no live daemon or watcher
- no automatic interface migration
- no conntrack flush or forced connection reset by default
- no replacement of the current strict backend
