<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# night-total-hardening-1 — the critical-usage forensic verification, and the CLI UX fatal finds it landed

Date: 2026-11-13. Owner's mandate, two asks in one session:
(1) the CLI UX bug paste ("so many bug ... agent ai continue should
find more than owner found and fix it 99% perfect cli UX ... focus
for maturing LTS usage, safety like don't allow danger input bigger
numeric"); (2) the E2E mandate — "master depth audit and do run
real use all/end to end zelynic as a forensic tools to verify
complete, before landed on critical industry ... run as root and
non root ... use all existing cli ... print json ... report ...
simulate critical usage zelynic end to end. after all passed
create a CI for special critical simulate same as above. with
name netrunner-night-C77".

## Find 1: the blind OK — dead cgroup ids answered as success

The owner's fatal find, three shapes of one lie: `s 889111`
answered OK. for a cgroup id that never existed (the next sweep
visit reaped the "success" it just printed — the verbose log's own
zombie-sweep rows were the death certificate), `b 1011::11` did
the same through a list, and `b zylaxion::...::noexist` silently
enforced the resolvable half while the misses vanished — a script
had no way to see it had configured half the fleet.

The fix is the apply-side liveness gate: a DIRECT cgroup-id target
is proved against the cgroupfs census (pathwalk's complete-tree
walk — the same kernel-proven death evidence the zombie sweep
reclaims by; an inconclusive census keeps the old fail-open).
`apply_single` answers Ok(0) for a dead id, riding the caller's
no-match error; `apply_group_atomic`'s pre-flight marks a dead
segment a MISS so the atomic refusal names it beside the resolvable
remainder. The block family joins the strict family's atomic
contract (the abort line's verb carries the family — "nothing was
blocked", never "limited"), and the best-effort `apply_group` died
with its last caller gone. The sweeps keep their best-effort
admission deliberately: a fleet snapshot must not abort on one
dead app.

## Find 2: the removal-side twin — the unstrict list claimed the whole list

`u zylaxion::kate::...::noexist` printed "Removed 30 policies
across 7 targets" while axa and noexist had nothing to remove —
the "across 7" claimed members that never matched, and a typo
could hide inside a green verdict. `unstrict_multi` now returns
the no-limits accounting; the success line counts only the targets
that actually had limits removed, and a grey tail names every
member that had none (removal stays safe-direction: what matched
is removed, what did not is NAMED, never silently dropped).

## Find 3: the duplicate root warning, the JSON leak, the help wall

- `s 1 --force-this` printed the identical root catch-all warning
  twice (the blocklist's id arm and the resolved-position check
  both answer the root). The force arm now warns once per process.
- `--print-json --focus` (no value) answered
  `{"error": "invalid value '' for '--focus <SECONDS>'"}` — a
  machine-facing lie about what the operator typed (they omitted
  the value; they did not pass an empty string). The JSON door now
  renders the prose lane's own "a value is required" verdict,
  byte-for-clap; a genuine non-empty value error keeps its own.
- `ee --help` carried nine paragraphs of NIGHT-* archaeology and
  an Examples block clap's paragraph wrapper joined onto ONE line;
  `ee -h` repeated the whole wall. The rewrite: one-sentence
  about, five tight paragraphs, a short first tier per option for
  -h with the detail tier for --help, the lineage keeping its home
  in docs/USAGE.md. The launcher's no-match error also learned its
  grammar: a '::'-shaped spec gets the '/' separator tip.
- The numeric safety audit (the owner's `--depth
  100000000000000000` class): an all-digit target past the 32-bit
  id space now refuses at the input boundary with the bound named,
  both spellings (bare and cg:-prefixed), single and list lanes.
  The other numeric doors were audited already-bounded:
  --interval 1s..60s, --focus 1s..30s, --during 1s..5y (checked
  mul), the rate grammar (u128 exact math, MAX_RATE ceiling).
- The LOC-cap law caught this session's own growth (safety.rs
  crossed 600) — the id door moved to safety_id.rs, a pure move.

## Find 4: the "ost-caps]" scare was the agent's own display, not the tool

Mid-session the audit "found" the owner's `[host-caps]` trace
rendering as `ost-caps]` in a dozen places — source literals, test
pins, VM logs, the owner's own paste. `od -c` proved every file,
test, and log byte-correct: an agent-side display layer was eating
the literal two bytes `[h` from grep/sed/cat views (the Read tool
and od showed the truth). The lesson is now load-bearing law in
the rig's own comment: check bytes, not views. The owner's
original paste — read with the honest tools — never contained a
broken prefix; the renders it DID flag (the JSON leak, the
duplicate warning) were real and are fixed above.

## The E2E forensic verification (the mandate, run whole)

Root lane: the local sandbox micro-VM (TCG — no /dev/kvm in the
agent sandbox, the documented fallback), the LTS-resolved kernel
(7.0.0-43-generic), the static musl payload, and the new rig —
scripts/sandbox/forensic-critical-sim.sh, one FORENSIC-RESULT row
per claim. Four VM boots drove the rig to green through its own
honest reds (each red was the rig's bug, named and fixed in its
commit: verdict inversion, a server-race baseline, pipe exit codes,
stale captures, stderr smothering the JSON parse, and the
histogram's 1-in-1024 packet sampling law — a 4 MB loopback
download folds into ~64 GSO segments and books nothing; the leg
now streams 24k x 100B chunks over TCP_NODELAY, the small-packet
shape supermassive-verify's proven veth phase drives).

Final verdict, 30/30 rows green: every regression pin; every JSON
surface parses; the measured critical simulation (29.5 MB/s
unlimited baseline, 218 KB/s under the 200kb cap — real measured
enforcement — the block killing the flow, unstrict restoring
30.9 MB/s, the --during window expiring on its own clock); the
eBPF histogram lane read mid-traffic with samples, non-zero
buckets, and the p50/p95/p99 quantiles (night-verify-1's
innovation verified again, this time from the depth surface); the
live monitor on a real PTY — the focus view, the name-target view
(the owner's blank-exit find's exact shape), and the leaderboard
all rendering and living until q; the interactive-stdio gate
refusing a redirected stdout loudly; and the non-root lane (uid
65534, every mutation verb refused cleanly, the refusal naming
the privilege ask).

Non-root lane beside the VM: the full nonroot depth battery,
107/107 (one pin updated to the new numeric-boundary contract —
the same ladder move dinner-16 made for the empty target).

## The C77 lane

.netrunner-night-C77 (.github/workflows/netrunner-night-c77.yml):
the same simulation as a per-push CI lane — a stage job builds
the release-tier pro-linux-amd64-v3-musl payload (the from-source
law, label-verified), resolves the archive's latest kernel with
the e2e lane's own dynamic resolver, and assembles the rootfs
with scripts/sandbox/sandbox-init.sh as PID 1 and the forensic
rig packed as its payload; the simulation job boots the micro-VM
on KVM (verified present, the e2e lane's own loud-fail posture),
runs the rig, and the verdict step holds the FORENSIC-VERDICT:
PASS sentinel as the authority — a log without it is a red, never
a silent green. No schedule (night-verify-1's law), the estate's
one-group concurrency, the watch summary in the step log.

## The blank-exit find, answered honestly

The rig proves the TUI lives on a real PTY for direct-id,
name-target, and leaderboard shapes — the exact monitor paths the
owner's `ee brave` / `ee brave/electron` sessions took. The
blank exits on the owner's host did not reproduce in the VM; the
remaining suspects are host-side (the terminal's alt-screen
interaction with the copy that produced the paste). The honest
state: verified alive under CI conditions on every input shape;
the owner's host observation stands unreproduced, and the new
build (which also changed the warning-path bytes) is the retry
vehicle.

<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `ebpf/src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
