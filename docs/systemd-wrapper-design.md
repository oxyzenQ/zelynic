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
zelynic run --dry-run -d 500kbit -u 500kbit -- helium
zelynic run --dry-run --scope-mode system -d 500kbit -- helium
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
concise execution preview with a non-mutating preflight decision, and returns a
normal not-implemented error without running `systemd-run`, `systemctl`, or
modifying nftables, tc, cgroups, or state. Running `zelynic run` without
`--dry-run` or `--execute` errors clearly so live behavior cannot be selected
accidentally.

The v2.5 Scope Runner adds `--probe-live` as an explicit gate for a controlled,
root-only, system-scope live probe. When `--execute --scope-mode system
--probe-live` is used with root, the Scope Runner actually launches a transient
systemd scope, discovers the ControlGroup and PID(s), reports findings, and
prints a non-mutating "Future attach preview" that bridges discovered PIDs to
the future resolved-PID strict attach backend — all without applying any
bandwidth limiting.

The v2.5 Scope Runner also adds `--attach-live` as an explicit future gate for
live limiter attach. It is **hard-blocked** in this build — even when all
requirements are met (execute + probe-live + system scope + root), the command
fails with "live attach is not implemented yet." No PID movement, no limiter
attach, no nftables/tc/cgroup/state changes are performed. See
`docs/scope-lab.md` for the full Scope Runner and Live Attach Gate design.

The v2.6 Attach Safety Lab adds a pure Attach Safety Preflight model to the
Future Attach Preview. It documents required PID liveness checks, original
cgroup capture, self-protection, rollback planning, and mutation ownership for a
future attach path. It does not enable live attach and does not perform any
mutation.

The v2.6 phase 2 original-cgroup capture preview adds a pure parser/model for
sample `/proc/<pid>/cgroup` content. The v2.6 phase 3 lab adds a read-only live
capture to the root system-scope `--probe-live` path, which actually reads
`/proc/<pid>/cgroup` for discovered PIDs. The live probe output reports the
honest exact rollback targets or marks them as unavailable/stale if the process
has exited. It remains strictly read-only and does not enable live attach.

The v2.6 phase 4 lab introduces read-only PID liveness and self-protection
evaluations to the root system-scope `--probe-live` path. This ensures PIDs are
still alive and that Zelynic does not attempt to attach itself or already-managed
cgroups. Live attach remains strictly blocked.

The v2.7 Experimental Attach Lab phase 1 adds explicit consent flags and a pure
gate checklist for a future single-PID, move-only attach experiment:
`--experimental-single-pid-attach`, `--i-understand-this-moves-pids`, and
`--rollback-required`. The checklist can report whether every future gate is
ready, but the final result is still blocked and no PID movement, nftables/tc
change, Zelynic cgroup change, or state write is performed.

The v2.7 phase 2 lab adds a move-only executor skeleton to that gate. It models
the future single-PID cgroup write order and immediate rollback verification,
but it remains skeleton-only: no `cgroup.procs` write, no target cgroup creation,
no limiter attach, and no nftables/tc/state mutation is performed.

The displayed `systemd-run` command is for visibility only. Internally, Zelynic
keeps the command as structured argv; a future live implementation must execute
structured arguments directly and must not pass a rendered shell string to a
shell.

The dry-run default is `Scope mode: user`. Manual probing showed that plain
system scope can trigger Polkit desktop authentication, while
`systemd-run --user --scope ...` worked for a user-scope probe. User scope is
therefore the safer v2.2 planning default for GUI/user applications. System
scope can still be previewed with `--scope-mode system`, but it remains
planning-only and should require root or explicit opt-in before any future live
implementation.

The execution preflight model is deliberately conservative:

| Scope mode | Current privilege | Decision |
|------------|-------------------|----------|
| user | non-root | blocked: user launch may work, but strict attach requires root |
| user | root | blocked: root can attach, but user-scope launch needs explicit user/session context |
| system | non-root | blocked: system scope requires root; Zelynic refuses accidental Polkit prompts |
| system | root | future-capable: possible implementation path, but live execution is still absent |

## Chosen Model: Launch Then Attach (ControlGroup-First)

The implementation path is:

1. launch the command in a transient systemd scope (backgrounded)
2. discover the ControlGroup path from the scope unit
3. read PID(s) from `cgroup.procs` under the discovered ControlGroup
4. apply the existing Zelynic strict attach backend
5. enforce nftables + HTB limits against the Zelynic target cgroup

This split is now formalized as the **launch/discover/attach contract** in
`src/systemd_wrapper/contract.rs`. The contract is a pure data model (no side
effects) that represents the three phases and their safety gates. Each phase is
explicitly marked as not implemented, and the privilege boundary between
user-context launch/discover and root-context attach is codified in the
contract's `StepPrivilege` field. This design contract does not implement live
execution; it exists to make the future model explicit before any
implementation begins.

In this model, the systemd scope path and the Zelynic target cgroup are not the
same thing. `systemd-run --user --scope --unit zelynic-run-<target> ...`
creates a systemd-managed scope under the user manager. Explicit system-scope
planning uses `systemd-run --scope --unit ...` and creates a scope under system
slices. In either case, Zelynic would then attach the selected PIDs into
`/sys/fs/cgroup/zelynic/target_<target>` using the same cgroup/nft/tc backend
used by `zelynic strict`.

An alternative native systemd cgroup backend would match nftables rules against
the systemd scope's relative cgroup path instead of the Zelynic target cgroup.
That requires backend abstraction work and is better treated as future major
backend design, not this v2.2 dry-run path.

## PID Discovery Handoff (ControlGroup-First)

After a future live launch, Zelynic needs a narrow handoff from systemd launch
state into the existing strict attach backend. Based on real probe findings
(documented in `docs/scope-lab.md`), PID discovery for scope units uses a
**ControlGroup-first** strategy.

The planned first check reads the ControlGroup property:

```bash
systemctl --user show zelynic-run-<target>.scope --property MainPID --property ControlGroup --value
```

`MainPID` is requested for diagnostic/logging purposes only. For scope units,
`MainPID` may be `0`, absent, or not useful because scopes track external
processes rather than internally managed services. `ControlGroup` is the
primary source of truth for PID discovery.

Once the ControlGroup path is known, Zelynic reads all PIDs from the scope's
cgroup:

```bash
cat /sys/fs/cgroup/<reported-control-group>/cgroup.procs
```

The `<reported-control-group>` segment is intentionally a placeholder in
dry-run output. Live code must use the ControlGroup reported by systemd and must
not guess a systemd cgroup path from the unit name.

For explicit system-scope planning, discovery previews the matching system
manager command:

```bash
systemctl show zelynic-run-<target>.scope --property MainPID --property ControlGroup --value
```

Discovery must complete before applying strict attach. Once PIDs are known,
Zelynic should move only validated live PIDs into
`/sys/fs/cgroup/zelynic/target_<target>` and then reuse the existing nftables/tc
setup.

The strict backend now has an internal resolved-PID attach path for that handoff:
future run mode can keep launch and PID discovery separate, then pass validated
PID metadata into the existing strict enforcement path instead of asking the
process-name resolver to rediscover the launched command.

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

Discovery decisions are deterministic (ControlGroup-first):

| Parsed metadata | Decision |
|-----------------|----------|
| valid `ControlGroup` (with or without `MainPID`) | scan ControlGroup via `cgroup.procs` |
| valid `MainPID` only (no ControlGroup) | use MainPID as fallback |
| neither usable | no usable discovery |

When both `MainPID` and `ControlGroup` are available, the decision is to scan
ControlGroup. This is the v2.4 ControlGroup-first model based on real probe
findings: scope units reliably report their ControlGroup path, while MainPID
may be 0, absent, or not representative of all processes in the scope.

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
then hand validated PIDs to the resolved-PID strict attach API. The current
`--execute` path deliberately stops before that boundary is crossed.

## Root And User Scope Tradeoffs

Root/system scope may be simpler for tc/nft/cgroup setup, but it can trigger
Polkit prompts when requested from an unprivileged desktop session, and
launching desktop GUI apps as root is usually wrong. User scope is better for
GUI session ownership and avoids surprise system authorization prompts, but it
must preserve enough session context for Wayland/X11, DBus, portals, and desktop
integration. It also does not remove the need for privileged cgroup/nft/tc
attach work.

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
- `MainPID` may be `0` or absent for some transient scope units; ControlGroup-first discovery is the intended design direction
- foreground scope may exit before PID discovery completes; backgrounded launch is preferred
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
