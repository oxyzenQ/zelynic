# Zelynic v2.4.0 Release Notes

Zelynic v2.4.0 "Scope Lab" is a design and planning release that builds the
groundwork for a future live systemd scope wrapper. It introduces a
ControlGroup-first PID discovery model, a launch/discover/attach contract,
scope-aware privilege labels, a manual probe recipe in dry-run output, and
splits the rendering module to stay under the project LOC policy limit. No live
systemd-run execution is implemented. `zelynic run --execute` remains
non-mutating. `zelynic strict` remains the only validated active limiter path.

## What Changed

### ControlGroup-First PID Discovery

- Refactored the systemd wrapper PID discovery model to prefer ControlGroup +
  cgroup.procs as the primary discovery path for scope units. MainPID is now
  optional/diagnostic only; scope units may report MainPID=0 or absent, which
  is normal for backgrounded processes.
- Updated dry-run and execute output to describe a 5-step planned flow:
  backgrounded scope launch, ControlGroup path discovery, cgroup.procs PID
  reading, existing strict attach backend application, and nftables + HTB limit
  enforcement.
- Added dedicated discovery tests verifying ControlGroup is preferred even when
  a valid MainPID is present, and that MainPID=0 with valid ControlGroup still
  uses the ControlGroup path.

### Scope-Aware Discovery Wording

- Fixed dry-run and execute plan output to render scope-mode-specific systemctl
  commands. User scope now correctly shows `systemctl --user show <unit>
  --property ControlGroup` in the PID discovery step. System scope shows
  `systemctl show <unit> --property ControlGroup`. Previously the wording was
  hardcoded to one form regardless of scope mode.
- Added scope-aware wording tests for both dry-run and execute paths covering
  user and system scope modes.

### Privilege and Session Handoff Design

- Documented the fundamental privilege boundary problem that blocks live
  execution: user-scope launch requires user privileges while strict attach
  requires root, and bridging this gap safely needs deliberate design.
- Added three candidate future designs (A: user-launch + root-helper, B:
  explicit sudo/root system scope, C: split launch/attach command pair) to
  `docs/scope-lab.md`. All designs are explicitly marked as future work, not
  implemented.

### Launch/Discover/Attach Contract Model

- Added `src/systemd_wrapper/contract.rs` as a pure, non-executing data model
  for the future live run. The contract defines three phases:
  - **Launch**: create transient systemd scope via systemd-run
  - **Discover**: read ControlGroup from systemctl, then read PIDs from
    cgroup.procs
  - **Attach**: move discovered PIDs into Zelynic target cgroup and apply
    nftables + tc HTB limits
- Each contract step has a privilege requirement (user manager, system
  manager / root-or-polkit, or root) and a safety gate. All phases are marked as
  not implemented.
- The contract is wired into dry-run and execute output as a "Future
  launch/discover/attach contract" section, keeping output readable without
  implying live implementation.

### Scope-Aware Contract Privilege Labels

- Fixed the contract model to use scope-mode-specific privilege labels for both
  the launch and discover steps. User scope shows "user manager"; system scope
  shows "system manager / root-or-polkit". Previously both launch and discover
  steps showed "user" regardless of scope mode, which was inaccurate for system
  scope where operations require root or trigger Polkit.
- Safety gate wording updated to distinguish user-scope (user manager context)
  from system-scope (requires root or triggers Polkit).

### Manual Probe Recipe

- Added a "Manual probe recipe" section to `zelynic run --dry-run` output that
  provides ready-to-copy/paste shell commands for manually testing the Scope Lab
  flow. The recipe includes four steps:
  1. Start a backgrounded scope with systemd-run
  2. Inspect the scope unit via systemctl show
  3. Read PIDs from cgroup.procs
  4. Cleanup via systemctl stop
- User scope recipe uses `systemd-run --user --scope` with `systemctl --user`
  inspect and cleanup commands. System scope recipe includes a prominent warning
  about root/sudo/Polkit and uses `sudo systemd-run --scope` with `sudo
  systemctl stop`.
- The recipe is clearly marked as "copy/paste only, not executed by Zelynic"
  and is omitted from `--execute` output.

### Module Split for LOC Policy Safety

- Split `src/systemd_wrapper/render.rs` (981 LOC, dangerously close to the
  1000 LOC policy limit) into focused modules:
  - `render.rs` (611 LOC) — dry-run and execute rendering orchestration,
    shared formatting utilities, and integration tests
  - `manual_probe.rs` (204 LOC) — manual probe recipe rendering and unit tests
  - `render_contract.rs` (125 LOC) — contract section rendering and unit tests
- Shared utilities (`push_line`, `shell_quote`) made `pub(super)` for sibling
  module access. No behavior change — pure refactor/extraction.

## Scope Lab Design

The Scope Lab is a deliberate design-first approach to building the future live
run feature. Instead of implementing execution first and fixing problems later,
v2.4.0 focuses on understanding the real systemd scope behavior through manual
probes, documenting the privilege boundaries, and building the data models and
output contracts that will guide future implementation.

Key design decisions documented in `docs/scope-lab.md`:

- **ControlGroup-first discovery**: Scope units expose their cgroup path via
  `ControlGroup` property, and `cgroup.procs` under that path contains all PIDs
  belonging to the scope. MainPID is unreliable for scope units because
  backgrounded processes may report MainPID=0.
- **Launch-then-attach model**: The likely future implementation is two-phase:
  first systemd starts the command in a transient scope, then Zelynic discovers
  the PIDs and attaches them with the existing strict backend.
- **Privilege boundary**: User-scope launch and root-required attach have
  fundamentally different privilege requirements. This is the core problem
  that must be solved before live execution can proceed safely.

## Manual Probe Recipe

The manual probe recipe is a non-mutating, copy/paste-only feature in dry-run
output. It provides the exact shell commands a user can run manually to test the
Scope Lab flow. Zelynic does not execute these commands. The recipe is designed
so that anyone can verify the systemd scope behavior on their own host without
Zelynic needing to run privileged operations.

User scope example (from `zelynic run --dry-run`):

```bash
# Step 1: start backgrounded scope
systemd-run --user --scope --unit zelynic-run-sleep --description 'Zelynic target sleep' -- sleep 30 &

# Step 2: inspect scope unit
systemctl --user show zelynic-run-sleep.scope --property MainPID --property ControlGroup --property ActiveState --property SubState

# Step 3: read PID(s) from cgroup.procs
cg=$(systemctl --user show zelynic-run-sleep.scope --property ControlGroup --value) && \
cat "/sys/fs/cgroup${cg}/cgroup.procs"

# Step 4: cleanup
systemctl --user stop zelynic-run-sleep.scope
```

System scope recipe includes `sudo` prefix and Polkit warnings. See the dry-run
output for the exact commands.

## Safety and Honesty

This release is Scope Lab groundwork, not stable live run support. The following
safety statements are explicitly documented and verified:

- **`zelynic run --execute` remains non-mutating:** It prints an execution
  preflight summary and returns "Live systemd wrapper execution is not
  implemented yet." No process is launched. No nftables, tc, cgroup, or state
  changes are made.
- **`zelynic run --dry-run` is planning-only:** It prints the planned launch
  command, PID discovery steps, contract section, and manual probe recipe without
  executing anything.
- **Manual probe recipe is copy/paste only:** Zelynic never executes the recipe
  commands. Users must manually copy and paste them into a shell if they want to
  probe the scope flow.
- **Strict limiter remains the validated active path:** `zelynic strict` is the
  only backend that has been tested and confirmed working. The systemd wrapper
  run mode is experimental groundwork.
- **MainPID is optional/diagnostic only:** The ControlGroup-first model treats
  MainPID as a supplementary diagnostic field. Scope units may report MainPID=0
  or absent, which is expected and handled correctly.
- **No privilege escalation in Zelynic code:** Zelynic does not run sudo,
  pkexec, or any privilege escalation mechanism. System scope commands in the
  manual probe recipe show `sudo` as a hint for the user, not as something
  Zelynic executes.

## Validation

This release passed all quality gates:

- `cargo fmt --all -- --check` — formatting clean
- `cargo test --locked` — 162 unit tests, 4 integration tests passed, 5 skipped
  (require root)
- `cargo clippy --all-targets --all-features -- -D warnings` — no warnings
- `python3 scripts/check-policy.py` — 57 files checked, all under 1000 LOC,
  all copyright/SPDX headers present
- `git diff --check` — no whitespace errors

Smoke tests passed:

- `zelynic run --dry-run -d 500kbit -u 500kbit -- sleep 30` — prints user scope
  dry-run with contract, probe recipe, and safety wording
- `zelynic run --dry-run --scope-mode system -d 500kbit -u 500kbit -- sleep 30`
  — prints system scope dry-run with Polkit warnings and sudo recipe
- `zelynic run --execute -d 500kbit -u 500kbit -- sleep 30` — prints execute
  plan with "Live systemd wrapper execution is not implemented yet."
- `zelynic --version` — prints `zelynic 2.4.0`

## Known Caveats

- **Live systemd-run execution is not implemented:** `zelynic run --execute`
  remains a non-mutating planning step. It prints the execution plan and returns
  an error. The privilege handoff design (how to safely bridge user-scope launch
  with root-required attach) has not been resolved.
- **Strict limiter validated on Arch/CachyOS only:** The `zelynic strict` command
  has been tested on a single modern cgroup v2 host (CachyOS/Arch, kernel
  `6.18.33-1-cachyos-lts`). Other distributions remain candidates pending
  explicit validation.
- **Fedora, Ubuntu, Debian are candidate/pending:** Expected to work based on
  their kernel and userspace stacks but not yet explicitly validated.
- **WSL and containers are partial/unsupported:** WSL2 and container
  environments typically lack writable cgroup hierarchies, nftables socket
  matching, or tc privileges.
- **`zelynic run` remains experimental groundwork:** The run mode is a planning
  and preview tool only. `--dry-run` is the safe path for understanding the scope
  flow. No live limiting through the run command is available.
- **No runtime limiter behavior changes:** The commits in this release are scope
  design, data model, output formatting, and code organization. No changes to
  the strict limiter, monitoring, QoS, profile, or auto-throttle behavior are
  intended or expected.

## Release Compare

Use the previous stable release baseline:

```text
https://github.com/oxyzenQ/zelynic/compare/v2.3.0...v2.4.0
```
