<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-improve-48 round 2 audit — the supermassive completeness question, answered from run 229's own logs with the full skip inventory

> Audit date: 2026-10-07 (NIGHT-improve-48, round 2). Scope: the
> owner's standing suspicion, verbatim intent — "supermassive test
> is still not complete, owner see missing like test proof-claim
> 0.00%, and others missing need depth audit too" — re-audited
> AFTER the round-1 fix (the starved-window discriminator, commit
> 6e80916) with its own CI proof in hand. Method: the GitHub
> Actions API logs for run 229 (the fix commit's own run, all four
> legs, downloaded and read row by row), every SKIP row in every
> battery classified by class, and each class judged closable vs
> environmental. Audited at 6e80916 (v20.0.0-era tree). Status: the
> named claim is NOT missing — the precision 0.00% LIVE row runs
> green on all four legs of the fix commit's own run — but the
> owner's instinct was still right at a deeper layer: 23 of the 47
> skips each VM leg carries are a closable class the round-1 audit
> under-weighted (the fake-rootless rows and the claims battery's
> tool-absent rows). This audit is their inventory and closure map;
> the closures land as NIGHT-improve-49 (the real-user drop lane)
> and this task's own rootfs-tools closure.

## 1. The mandate

Round 1 (2026-10-06, the precision-row audit) closed the red lane
the owner watched fail: the starved-window discriminator, the
honest adaptation, the honest SKIP. Run 229 — the fix commit's own
supermassive run — then went green on all four legs. The owner's
suspicion did not retire with it, and this audit treats that as
the signal it is: re-pull the freshest evidence, re-count what
each battery actually runs, and classify every row that does not
execute. "Complete" is a measurable property here — the share of
a leg's rows that genuinely ran — not a feeling.

## 2. The evidence — run 229, all four legs, green

Run 229 (commit 6e80916, created 2026-10-06T16:19:22Z, completed
success): every leg PASS. The per-battery verdict lines, read from
the downloaded job logs:

| leg | kernel | v1 matrix | MMSPA A/B | v2 survival | v3 container | v4 CLI | claims proof | verdict |
|---|---|---|---|---|---|---|---|---|
| low specs gnu | 5.13.0-52 | PASS | PASS | 155/0/0 (57s) | 25/0/3 | 136/0/19 | 26/0/3 (43s) | PASS |
| low specs musl | 5.13.0-52 | PASS | PASS | 155/0/0 (57s) | 25/0/3 | 136/0/19 | 26/0/3 (43s) | PASS |
| best specs gnu | 7.3.0-8 | PASS | PASS | 155/0/0 (86s) | 25/0/3 | 136/0/19 | 26/0/3 (59s) | PASS |
| best specs musl | 7.3.0-8 | PASS | PASS | 155/0/0 (86s) | 25/0/3 | 136/0/19 | 26/0/3 (45s) | PASS |

## 3. The named claim — "test proof-claim 0.00%" — is present and live

The claims battery runs LIVE in the VM on every leg
(`proof-claims.py --quick`, the NIGHT-lts-6 mandate), and the
precision row the owner named is in it, green on all four legs of
run 229:

| leg | precision residual (bound 12.0%) |
|---|---|
| low specs gnu | 4.553% — admitted 954892506 B over 10.0s |
| low specs musl | 6.772% — admitted 1069372713 B over 10.0s |
| best specs gnu | 9.691% after a 13.068% first window (the same-rate re-attempt) |
| best specs musl | 8.431% on the first window |

The claim was missing-green exactly once in the estate's history —
runs 219/221/224/228's best-specs legs — and round 1 root-caused
that to the instrument's starved window, not a missing test, and
closed it. What the owner was actually pointing at, read fresh:
not an absent row, but the rows that DO skip. Those are next.

## 4. The real inventory — every SKIP in a VM leg, classified

Run 229's logs carry 47 skipped rows per leg. Each one, by class:

| class | rows/leg | where | verdict | why |
|---|---|---|---|---|
| fake-rootless (rootless-lane rows skipped because the harness itself runs as root) | 19 | v4: 2 verb rows (snapshot/restore), 8 during rows, 4 guarantee rows, 2 tier rows, 3 shadow rows | CLOSABLE — NIGHT-improve-49 | the rows assert the root-refusal message a real user sees; as root they cannot fire, so the VM leg — which labels the battery "(full, rootless)" — never actually runs the user experience |
| fake-rootless, v3's own shape (the privilege-gate stage) | 1 | v3 stage 2 | CLOSABLE — NIGHT-improve-49 | same class: the gate row skips when the harness is root |
| tool-absent (the claims battery's diagnostic probes) | 3 | claims proof: nft ruleset snapshot, bpftool prog/link show, bpftool footprint run-time row | CLOSABLE — this task's rootfs closure | the VM rootfs ships no nftables and no bpftool; a real user's machine has both one apt away, so the rows that prove "no netfilter path" and "kernel run time" go unproven in the VM leg |
| container-runtime-absent | 2 | v3 docker-e2e, k8s-e2e | stays | the VM ships no docker daemon and no kubelet by design; the container workflow carries both E2E lanes on runners with real runtimes |
| realnet-absent | 9 | v1 real-internet lanes | stays | the guest is loopback-only by design (the offline-VM contract); the realnet verdict belongs to the owner's local run |
| physics (hardware ceiling, GSO granularity, diagnostic floors) | 13 | v1: 4 ladder rows the 5.1 GB/s baseline cannot feed, 2 accounting-floor rows, 7 MMSPA diagnostic/advisory rows | stays | the honest instrument bounds round 1 already documented |

The honest arithmetic: 47 skips per leg, 24 environmental or
physical and honest about it, 23 closable — and every closable row
is the same root cause family: the VM leg runs everything as root
(rootfs root, init as PID 1), so every row whose contract is "what
a real user sees" either skips (the 20 fake-rootless rows) or runs
on a rootfs missing the tools a real user has (the 3 claims rows).

## 5. The closure map

Two closures land from this finding, both sized to the evidence:

1. **NIGHT-improve-49, the real-user drop lane.** The harness
   gains a privilege-drop helper (setpriv to an unprivileged uid,
   the shared lib's own probe with an honest fallback), and the
   20 fake-rootless rows (v4's 19 + v3's gate) execute through it
   when the harness itself is root: the gate refuses the dropped
   user exactly as it refuses a real one, the refusal needle
   asserts, and the row's verdict becomes a genuine PASS/FAIL
   instead of a SKIP. The safety doctrine is unchanged — the gate
   refuses BEFORE any enforcement attempt, which is the same
   reason the rows are safe on the rootless CI leg today.
2. **The rootfs tools closure (this task).** The VM rootfs gains
   nftables and a staged bpftool, so the claims battery's three
   tool-absent rows run for real on every leg: the nft ruleset
   snapshot, the bpftool prog/link visibility row, and the
   footprint row's kernel run-time numbers.

## 6. The verdict

The named claim — the precision 0.00% proof — was never the
missing thing on this tree: it runs live and green on all four
legs of the fix commit's own run. What the owner's suspicion
caught instead, and what this round adds to the record, is the
completeness ledger above: 23 of 47 skips per leg are a closable
class, all one root cause, and the closures are mapped. The
supermassive battery after both closures reads the honest
arithmetic: the v4 leg 155 passed, 0 skipped (the 136 that always
ran plus the 19 dropped rows), the v3 leg 30 passed, 0 failed, 2
skipped (the gate stage's five refusal rows replace the single
stage-level SKIP; only the two runtime-absent E2E rows stay, the
container workflow carrying them), the claims proof 29 passed, 0
skipped — with every remaining skip environmental, physical, or
runtime-boundary, each naming its carrier lane in its own detail
line. That is the honest definition of complete the estate can
hold: nothing skips that could run, and everything that skips
says why, where it runs instead, and does not lie about either.

## 7. The live proof — run 232, all four legs, the closures green

in the VM logs

The closures landed (improve-49 commit f89521e, the rootfs-tools
fixpass 5720ad0 after run 231's staging lesson) and supermassive
run 232 (the fixpass commit's own run, 2026-10-06) carried the
verdict:

| leg | v3 | v4 | claims proof | verdict |
|---|---|---|---|---|
| low specs gnu (5.13) | 30/0/2 | 155/0/0 | 29/0/0 (43s) | PASS |
| low specs musl (5.13) | 30/0/2 | 155/0/0 | 29/0/0 | PASS |
| best specs gnu (7.3) | 30/0/2 | 155/0/0 | 29/0/0 (59s, precision 9.041%) | PASS |
| best specs musl (7.3) | 30/0/2 | 155/0/0 | 29/0/0 (45s) | PASS |

Every number matches the closure map's arithmetic exactly: v4's
155 with zero skips (the 19 rootless-lane rows each stamped
"real-user drop (uid 65534)" — the setpriv lane refusing the
dropped user on the VM's own root legs), v3's 30 with only the
two runtime-absent E2E skips (the gate stage's five refusal rows
running through the same drop), the claims proof's 29 with zero
skips (the nft ruleset snapshot comparing structure before and
during enforcement, bpftool's prog/link visibility showing the 2
cgroup_skb programs and 4 cgroup links, the footprint's kernel
run-time row printing real per-program numbers — 1293-2425 ns
per attached-prog run across the legs, bound 20,000).

The honest footnote: run 232's first attempt failed its two
best-specs legs on exactly the measurement rows round 1
documented as the shared-runner's busy-hour class (the per-app
row at 60.7% under its 65% floor, the precision row at
13.728%/24.850% with refusals — the starved window deepening,
attempts worsening on the re-sample), the same wall-clock hour
on both legs, the same shapes runs 219/221/224/228 carried; the
re-run of the two failed jobs on fresh runners passed everything
(attempt 2, the table above) — the code, rootfs, and batteries
identical between attempts, the only variable the runner's hour.
That residual is the round-1 closure's own documented limit, not
a regression: the policer's contract is pinned by the same legs'
green rows in quieter hours, and the discriminator's refusal
side did its job (an under-band window WITH refusals stays red —
the signature the row exists to catch, even when the host is the
culprit).
<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every .md — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `ebpf/src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
