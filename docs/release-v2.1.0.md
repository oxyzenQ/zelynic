# Zelynic v2.1.0 Release Notes

Zelynic v2.1.0 builds on the Renaissance release with safer diagnostics,
cleanup, refresh, and release engineering polish. The strict backend remains the
same tc/nftables/cgroup v2 backend validated on tested modern cgroup v2 systems.

## Highlights

- Backend Doctor capability matrix via `zelynic backend doctor` and
  `zelynic backend doctor --json`.
- `zelynic refresh <target>` for manually moving reopened or respawned target
  PIDs into an existing active limit without duplicating nftables or tc rules.
- Runtime namespace migrated to `zelynic`: `/run/zelynic`,
  `/run/zelynic/zelynic.nft`, `/sys/fs/cgroup/zelynic`, and
  `table inet zelynic`.
- Supply-chain policy hardened with `cargo audit`, `cargo deny`, and documented
  `./build.sh check-all` workflow.
- Limiter internals split into focused modules while preserving strict backend
  behavior.
- `unstrict` records and restores original cgroups when safe, falls back
  conservatively, removes empty target cgroups, and explains kept cgroups.
- Active limit status warns when the stored interface differs from the current
  default route.
- Documentation now clarifies that strict applies to new connections after the
  target is moved into the cgroup; already-running requests may need reload or
  restart.
- Mistimed `refresh` now preserves active state if the target is not currently
  running.

## Validation Notes

- Validated on a modern Arch/CachyOS pure cgroup v2 host with nftables and
  tc/iproute2 available.
- `zelynic strict --diagnose -d 500kbit -u 500kbit helium` limits Helium while
  Brave remains full speed, confirming per-target isolation on the tested host.
- `zelynic refresh helium` moves reopened Helium PIDs into the existing target
  cgroup without creating duplicate nftables or tc objects.
- `zelynic unstrict helium` removes nftables state, clears persisted state, and
  restores or conservatively falls back cgroups.

This release does not claim universal support across all Linux distributions.
Use `zelynic backend doctor` and `zelynic strict --diagnose` when validating a
new host.
