# Zelynic Validation Reports

## Purpose

This directory contains per-distribution validation reports for Zelynic. Each
report documents the results of testing Zelynic on a specific Linux distribution
or environment, recording what was tested, what worked, and what caveats were
observed. Reports serve as the evidence base for the status labels in the
[distro matrix](../distro-matrix.md).

Validation reports are not automatically generated. They are written or curated
by maintainers and contributors who have performed real testing on the target
environment. A report only exists when someone has actually run the validation
steps and recorded the results.

## Report Types

### Read-Only Host Capability Report

A read-only report collects host facts and checks capabilities without
modifying anything on the system. No root privileges are required and no
changes are made to nftables, tc, cgroups, systemd state, or runtime
directories. This type of report answers the question: "Can this host run
Zelynic's strict limiter in principle?"

Use the host fact collector script to gather the information needed for this
report:

```bash
bash scripts/collect-host-facts.sh
```

Then supplement with Zelynic's built-in capability checks:

```bash
zelynic backend
zelynic backend doctor
zelynic backend doctor --json > backend-doctor-<distro>.json
```

A read-only report can be filed for any host without risk. It is the first
step before considering privileged testing.

### Privileged Strict Limiter Validation Report

A privileged report documents the results of actually running Zelynic's strict
limiter on a host. This requires root privileges and will modify nftables
rules, tc qdisc state, cgroup membership, and runtime state in `/run/zelynic/`.
These tests are manual-only operations.

A privileged report covers:

- Applying strict bandwidth limits with diagnostics
- Verifying that bandwidth is actually constrained to the expected range
- Testing refresh behavior after process respawn
- Testing unstrict cleanup and state removal
- Recording any caveats or workarounds

**Warning:** Privileged tests must be run manually by maintainers or
contributors. Do not run them from automated CI pipelines unless the
environment is specifically prepared for destructive cgroup, tc, and nftables
testing. Do not run them on production hosts without understanding the
consequences.

## How to File a Report

1. Copy [template.md](template.md) to a new file named after the distribution:
   `docs/validation-reports/<distro-slug>.md` (e.g., `fedora-41.md`,
   `ubuntu-2404.md`).

2. Complete all fields in the template. For fields where data is not available,
   write "Not recorded" or "Not applicable" rather than leaving them blank.

3. Run the read-only checks first and record the results.

4. If read-only checks confirm that the required capabilities are present,
   proceed with privileged tests at your own discretion on a non-production
   host.

5. After completing the report, update the status in
   [docs/distro-matrix.md](../distro-matrix.md) and link to the new report.

## See Also

- [docs/distro-matrix.md](../distro-matrix.md) — distribution support matrix
  with status labels
- [docs/validation.md](../validation.md) — real-machine validation records
  and distro validation flow
- [scripts/collect-host-facts.sh](../../scripts/collect-host-facts.sh) —
  read-only host capability collector
