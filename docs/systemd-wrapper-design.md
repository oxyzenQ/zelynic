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

Launch a target command inside a Zelynic-controlled systemd scope so the initial
process and its children inherit the intended cgroup from the start.

Possible future commands:

```bash
sudo zelynic run -d 500kbit -u 500kbit -- helium
sudo zelynic run --target helium -d 500kbit -u 500kbit -- helium
zelynic run --dry-run -d 500kbit -u 500kbit -- helium
```

## Current Dry Run

The current `run` command is intentionally dry-run only. It parses rates,
target, and command arguments, then prints:

- planned systemd scope name
- command that would be launched
- planned Zelynic target cgroup path
- confirmation that no process was launched
- confirmation that nftables, tc, cgroups, and state were not changed

This makes the future UX reviewable without introducing new privileged runtime
behavior.

## Integration With Strict

A live implementation should reuse the existing strict backend helpers for:

- rate parsing
- target cgroup naming
- nftables rules
- tc classes and filters
- state management
- unstrict cleanup

The wrapper should not create a parallel limiter backend. It should only change
how the first process enters the target cgroup.

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
- systemd versions differ in transient scope behavior
- non-systemd distros need a different path or a clear unsupported result
- containers and WSL may expose partial systemd/cgroup signals

## Non-Goals For v2.2 Groundwork

- no eBPF backend
- no live daemon or watcher
- no automatic interface migration
- no conntrack flush or forced connection reset by default
- no replacement of the current strict backend
