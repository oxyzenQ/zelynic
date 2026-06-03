# Zelynic v2.5.0 Release Notes

Zelynic v2.5.0 "Scope Runner" introduces the first live systemd scope probe
capability and a non-mutating attach preview. When run as root with the correct
flags, Zelynic can now launch a real transient systemd scope, discover its
ControlGroup and PID(s), and render a preview of what a future attach would look
like. However, this release does NOT implement live bandwidth limiting from
`zelynic run`, does NOT move discovered PIDs into Zelynic cgroups, and does NOT
modify nftables or tc from the Scope Runner. The `--attach-live` flag exists
but is hard-blocked. `zelynic strict` remains the only validated active limiter
path.

## What Changed

### Scope Runner Live Probe (--probe-live)

- Added `--probe-live` flag to `zelynic run` for a controlled, root-only,
  system-scope live probe. When invoked as `sudo zelynic run --execute
  --scope-mode system --probe-live -- <command>`, Zelynic:
  - Launches a real transient systemd scope via `systemd-run --scope --unit
    <unit> --description <desc> -- <command>` (backgrounded).
  - Queries the scope unit via `systemctl show <unit>.scope --property
    MainPID --property ControlGroup --property ActiveState --property
    SubState`.
  - Reads PID(s) from `/sys/fs/cgroup${ControlGroup}/cgroup.procs` if the
    ControlGroup was discovered.
  - Reports findings: scope unit name, ControlGroup, ActiveState, SubState,
    discovered PID(s).
  - Prints honest safety disclaimers: no limiter attach, no nftables/tc changes,
    bandwidth not active.
  - Documents the cleanup command: `sudo systemctl stop <unit>.scope`.
- The probe requires all of `--execute`, `--scope-mode system`, `--probe-live`,
  and root (euid == 0). Missing any requirement falls back to existing blocking
  behavior.
- User-scope `--probe-live` returns "User-scope live runner is not implemented"
  because user-scope needs privilege/session handoff, which is not designed yet.
- Non-root system-scope `--probe-live` returns "Scope Runner live probe requires
  root (euid == 0)."

### Future Attach Preview

- After a successful live probe discovery, the Scope Runner prints a
  non-mutating "Future attach preview" section. The preview displays:
  - Discovered PID(s) from the scope's cgroup.procs.
  - Future target cgroup path that would be used for attachment (e.g.
    `/sys/fs/cgroup/zelynic/target_sleep`). This cgroup is NOT created.
  - Requested download/upload bandwidth rates formatted as display strings.
  - Attach source label ("systemd scope probe").
  - Strict backend label ("existing resolved-PID attach backend").
  - Status: "preview only; not applied."
- The preview is followed by safety disclaimers: no PID moved, no limiter
  attach performed, no nftables/tc/Zelynic cgroup/state changes made,
  bandwidth limiting not active.
- The preview does NOT move any PID, create any cgroup, modify nftables or tc,
  write any state file, or call `zelynic strict`.

### --attach-live Hard Block

- Added `--attach-live` flag to `zelynic run` as an explicit future gate for
  live limiter attach. Requires `--execute`, `--probe-live`, `--scope-mode
  system`, and root.
- This flag is **hard-blocked** in this build. Even when all requirements are
  met, the command returns: "Scope Runner live attach is not implemented yet.
  This build only supports live probe and attach preview."
- No PID movement, no limiter attach, no nftables/tc/cgroup/state changes are
  performed when `--attach-live` is supplied.
- Clap enforces `requires = "execute"` and `requires = "probe_live"` for
  `--attach-live` at parse time.

### Scope Runner Module Split

- Refactored `scope_runner.rs` (780 LOC) into focused modules to stay under
  the 1000 LOC policy limit:
  - `scope_runner.rs` (93 LOC) — orchestration and gate entrypoint.
  - `scope_probe.rs` (522 LOC) — probe execution, result model, output
    rendering, plan builder.
  - `attach_preview.rs` (263 LOC) — AttachPreview model, builder, preview
    rendering.
- No behavior change. Pure refactor/extraction.

### ControlGroup-First Discovery

- The Scope Runner uses the ControlGroup-first PID discovery model established in
  v2.4.0. ControlGroup is read from `systemctl show --property ControlGroup`,
  then PID(s) are read from `/sys/fs/cgroup${ControlGroup}/cgroup.procs`.
  MainPID is queried as a supplementary diagnostic field but is not the primary
  discovery source.

## Scope Runner Live Probe

The Scope Runner is the first part of `zelynic run` that performs real systemd
operations. It validates the launch-discover pipeline without applying any
bandwidth limiting.

CLI syntax:

```bash
sudo zelynic run --execute --scope-mode system --probe-live \
  -d 500kbit -u 500kbit -- sleep 60
```

After the child process exits, the scope unit transitions to inactive/dead. The
cleanup command is printed in the output:

```bash
sudo systemctl stop zelynic-probe-v250-sleep.scope
```

## What the Scope Runner Does NOT Do

- Does NOT run `zelynic strict`.
- Does NOT call limiter attach.
- Does NOT modify nftables.
- Does NOT modify tc/qdisc/filter.
- Does NOT create or move processes into Zelynic cgroups.
- Does NOT write Zelynic state files.
- Does NOT claim bandwidth limiting is active.
- Does NOT enable `--attach-live`.

## Future Attach Preview

The preview bridges discovered PIDs to the future resolved-PID strict attach
backend. It is a planning artifact rendered after a successful probe, showing
what a future attach would look like without performing any mutation. The next
implementation step is the `--attach-live` flag actually moving PIDs and applying
limits — but that step is not implemented in this build.

## Validation

This release passed all quality gates:

- `cargo fmt --all -- --check` — formatting clean
- `cargo test --locked` — 210 unit tests, 4 integration tests passed, 5 skipped
  (require root)
- `cargo clippy --all-targets --all-features -- -D warnings` — no warnings
- `python3 scripts/check-policy.py` — 60 files checked, all under 1000 LOC,
  all copyright/SPDX headers present
- `git diff --check` — no whitespace errors

Root smoke tests passed:

- `sudo zelynic run --execute --scope-mode system --probe-live -d 500kbit -u
  500kbit -- sleep 5` — launched transient systemd scope, discovered
  ControlGroup and PID, rendered Future Attach Preview, no PID moved, no
  limiter attach, no nftables/tc/Zelynic cgroup/state changes, unit cleanup
  inactive/dead.
- `sudo zelynic run --execute --scope-mode system --probe-live --attach-live
  -d 500kbit -u 500kbit -- sleep 5` — returned hard-blocked error: "Scope
  Runner live attach is not implemented yet. This build only supports live
  probe and attach preview."

Non-root smoke tests passed (all correctly blocked):

- `zelynic run --execute -d 500kbit -u 500kbit -- sleep 30` — "Live systemd
  wrapper execution is not implemented yet."
- `zelynic run --execute --scope-mode system -d 500kbit -u 500kbit -- sleep
  30` — "Live systemd wrapper execution is not implemented yet."
- `zelynic run --execute --probe-live -d 500kbit -u 500kbit -- sleep 30` —
  "User-scope live runner is not implemented."
- `zelynic run --execute --scope-mode system --probe-live -d 500kbit -u 500kbit
  -- sleep 30` — "Scope Runner live probe requires root (euid == 0)."
- `zelynic run --execute --scope-mode system --probe-live --attach-live -d
  500kbit -u 500kbit -- sleep 30` — "Scope Runner live probe requires root
  (euid == 0)."

A dedicated validation report is available at
[docs/validation-reports/scope-runner-v2.5.md](docs/validation-reports/scope-runner-v2.5.md).

## Safety and Honesty

This release adds live systemd scope probe capability while keeping strict
safety boundaries. The following statements are explicitly documented and
verified:

- **The Scope Runner probe is non-mutating for limiting:** It launches a systemd
  scope and discovers PIDs, but does NOT apply bandwidth limits, modify
  nftables, tc, Zelynic cgroups, or state. Bandwidth limiting is not active from
  the probe command.
- **`--attach-live` is hard-blocked:** Even with root, `--execute`,
  `--probe-live`, `--scope-mode system`, and `--attach-live` all set, the
  command returns a "not implemented yet" error. No PID movement or attach
  operation is performed.
- **User-scope live runner remains blocked:** `--probe-live` with user scope
  returns "User-scope live runner is not implemented." The privilege/session
  handoff design has not been resolved.
- **No PID movement:** The Scope Runner does not move discovered PIDs into any
  Zelynic target cgroup. The attach preview shows the future target cgroup
  path but does not create it or move PIDs into it.
- **Strict limiter remains the validated active path:** `zelynic strict` is the
  only backend that applies bandwidth limits. The Scope Runner is a probe and
  preview tool, not a limiter.
- **Honest output wording:** Scope Runner output states "Scope Runner live
  probe", "No limiter attach was performed", "No nftables, tc, Zelynic cgroup,
  or state changes were made", and "Bandwidth limiting is not active from this
  command yet."

## Known Caveats

- **Live limiter attach from `zelynic run` is not implemented:** The Scope
  Runner can probe and preview, but it does not attach bandwidth limits. The
  `--attach-live` flag is hard-blocked.
- **User-scope live runner remains blocked:** Launching a systemd scope in the
  user's session context and then attaching limits (which requires root) needs a
  privilege/session handoff design that has not been implemented.
- **Strict limiter validated on Arch/CachyOS only:** The `zelynic strict`
  command has been tested on a single modern cgroup v2 host (CachyOS/Arch, kernel
  `6.18.33-1-cachyos-lts`). Other distributions remain candidates pending
  explicit validation.
- **Fedora, Ubuntu, Debian are candidate/pending:** Expected to work based on
  their kernel and userspace stacks but not yet explicitly validated.
- **WSL and containers are partial/unsupported:** WSL2 and container
  environments typically lack writable cgroup hierarchies, nftables socket
  matching, or tc privileges.
- **`zelynic run` is a lab/probe tool, not a stable limiter:** The run mode
  provides scope probe and attach preview. For active bandwidth limiting, use
  `zelynic strict`.
- **Scope probe requires root and system scope:** The `--probe-live` flag only
  works with `--scope-mode system` and root. There is no non-root probe path.

## Upgrade Notes

- No configuration or state migration is needed for this release. Existing
  `zelynic strict` limits, profiles, and runtime state continue to work
  unchanged.
- The `--probe-live` and `--attach-live` flags are new additions to `zelynic
  run`. Existing `zelynic run --dry-run` and `zelynic run --execute` behavior
  is preserved.
- If you were using `zelynic run --execute` in scripts expecting the "not
  implemented yet" error, that behavior is unchanged. The probe path requires the
  additional `--probe-live` and `--scope-mode system` flags.

## Release Compare

Use the previous stable release baseline:

```text
https://github.com/oxyzenQ/zelynic/compare/v2.4.0...v2.5.0
```
