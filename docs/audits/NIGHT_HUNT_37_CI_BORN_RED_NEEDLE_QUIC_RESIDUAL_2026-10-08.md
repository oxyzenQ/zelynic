<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-hunt-37 audit — the born-red CI needle, and the QUIC residual closed

> Audit date: 2026-10-08 (NIGHT-hunt-37). Scope: the owner's two
> asks — the supermassive CI "keep failed" on b39ba05 (four legs
> red at the Verdict step), and the hunt-36 residual the owner
> approved closing (a live N-HTTP/3-connections QUIC row needs a
> QUIC client in the VM rootfs). Method: the CI logs pulled leg by
> leg through the Actions API, the failing rows traced to their
> births in git history, the regression window bisected by the run
> list; then the QUIC lane built the harness family's way — the
> shape validated rootless end to end before it ever rides a VM.
> Audited and fixed at b39ba05 (hunt-36's tree).

## 1. The CI find (fixed): a row born red, not a regression in code

**The symptom.** All four supermassive legs (best/low x gnu/musl)
fail identically at the Verdict step with the same pair of rows:

```
X  cli depth: --no-test parses on strict (scripted apply) — expected wording 'root required' missing
X  cli depth: full-sweep invariant (111 cases, zero hangs, zero panics) — 110/111
```

The second row is the first row's shadow (the invariant counts the
table's failures), so one root cause. Everything else in all four
legs is green — v1, v3, v4, the claims battery, the rig suites.

**The diagnosis.** The row was added by improve-54 (37f4af3) to
prove the renamed `--no-test` flag parses on the strict verb —
with the needle `root required`, the wording a NON-root invocation
produces. But the v2 survival battery runs as root (the table's
own law: the `--check-update refuses root (the harness IS root)`
section says it out loud, and sibling rows prove it — the fleet
cgroup rows APPLY real policies mid-sweep). As root, `strict brave
1mb --no-test` walks the whole ladder — parse, rate, target
validation, the root guard, attach, resolve — and dies at the
no-match hard error instead: `No cgroup found for 'brave'`, exit
1. The needle could never appear. The row was born red and stayed
red: every supermassive run from improve-54's push until
ee1cfe6's first uncancelled battery failed on it (the run list
between a75e4966 — the last green — and b39ba05 is a wall of
`cancelled`, each newer push superseding the last before the VM
legs finished; the needle never once got a green run).

**The fix.** The needle moves to the wording a ROOT harness
deterministically owns: `No cgroup found for 'brave'`. The parse
proof is unchanged and stronger than the old one's intent: an
unknown flag dies at clap's exit-2 `unexpected argument` rung and
never reaches target resolution, so REACHING the no-match ladder
IS the flag parsing — the full apply ladder accepted `--no-test`
through parse, rate, target, dangerous-check, root, attach, and
resolve. The real scripted apply (rc 0 + the JSON row at the
rate) already rides the rate guard's `--no-test` rows above the
sweep (its two live applies), which is where the flag's effect
actually belongs. The table stays 106 cases; the size pin and
the self-test are untouched; the full-sweep invariant heals with
the row (110/111 → 111/111 by construction).

## 2. The residual closed: the QUIC client rides the rootfs

**The gap, as hunt-36 recorded it.** The QUIC-aware attribution
(schema v22) carried its pure-core pins (quic_tests — the header
laws, the learn/confirm lifecycle, the key oracle) and the
QUIC-shaped bench probes (ect-probe, guarantee-probe), but no
live lane ever drove REAL QUIC through the limiter: "a live
N-HTTP/3-connections row would need a QUIC client in the VM
rootfs, an owner-scope call recorded here, not silently
skipped." The owner approved the call; this audit closes it.

**The client.** aioquic 1.3.0 rides the rootfs assembly (both
suites' interpreters covered by its cp310-abi3 wheel — jammy's
3.10 and noble's 3.12), staged through the container's own python
so the compiled wheels (pylsqpack, cryptography) match the guest
ABI, pip installed and purged so only the ~10 MB of QUIC
libraries ride the RAM-resident cpio. The PEP 668 split is
spoken by the `||` fallback (jammy installs plain, noble needs
`--break-system-packages`), and a staging failure FAILS the leg
on the runner where retries are cheap — the improve-48 bpftool
law: the in-VM row must never silently skip its proof. The
import is verified twice, before and after pip's purge.

**The row.** `test_quic_connections` in the v1 matrix, wired
after its TCP twin `test_per_socket_burst`. The SHAPE is the
discriminating one — the server twin of the browser shape the
schema docs name: N real HTTP/3 connections (aioquic client +
h3 GET, full TLS 1.3 handshake, 1-RTT data) demultiplexed
through ONE listening UDP socket inside the policed cgroup. One
socket means one socket cookie: the cookie-only lane the v22
flow-key refined would book all N connections into ONE
per-socket bucket, while the QUIC-aware lane keys each by its
8-byte connection ID (aioquic's default CID class — the same
class the key oracle pins, `cookie XOR mix64(cid prefix)`, a
collision sharing a bucket at 2^-64 odds). The verdicts are the
per-socket row's own arithmetic on the CID-keyed shape:

- **scale-up**: ledger / (rate x span) >= 2.5 — N CID buckets
  flowing; the cookie-collapsed lane caps at 1.60 (the burst
  row's sharing cap), so the gap discriminates by construction.
- **per-connection cap, measured per client**: each client
  <= (rate x (window + its own handshake lag) + burst) x 1.25 —
  the lag is MEASURED, not assumed, because a connection's
  bucket accrues from its own first packet and a slow envelope's
  staggered handshakes hand the late connections more headroom.
- **per-connection floor**: each client >= 0.50 x rate x window.
- **the enforcement proofs**: drops engaged and the kernel-vs-
  client accounting band, both at the hunt-36 margins.

**The supply law (the engineering the row lives on).** The
server paces each connection at QUIC_SUPPLY (1.35) x rate — a
smooth overfeed, never a loopback blast. Three laws hold it
together:

1. **Drift-free pacing.** The prototype's naive
   `sleep(interval)` loop measured 7.5% under nominal on an
   IDLE box — asyncio's sleep overshoot accumulates, and a
   loaded 1-vCPU leg shaves more. The shipped pump schedules
   every quantum at an absolute instant (`start + sent /
   target-rate`), so overshoot never accumulates; a schedule
   behind by at most one tick catches up immediately, a
   schedule behind by more RESYNCS (the debt is forgiven, never
   blasted — a catch-up burst is the congestion-collapse shape
   the lane refuses). Post-fix, the rootless validation measured
   10.81 MB delivered against 10.80 nominal over the 8s window:
   100.1%, drift-free.
2. **Drops guaranteed by arithmetic.** At the canonical geometry
   (1mb rate, 8s window, 1s burst bank, 0.5s settle) the offered
   load (10.8 MB) exceeds the per-connection budget line
   (9.5 MB) from t ~ 5s on: the policer MUST trim, the drops
   row has real counters without congestion chaos, and the loss
   ratio stays single-digit percent (reno is never perturbed
   into collapse). The engine self-test pins the law rootless:
   `supply x window > settle + window + burst` and the CC bound.
3. **Caps hold by construction.** Delivered <= admitted <=
   budget per connection (kernel-enforced), and the cap verdict
   is budget x 1.25 with the measured lag — the only way it
   breaks is a real over-admission, which is the thing it
   exists to catch.

**The lane's own TLS.** A throwaway self-signed EC P-256
certificate, generated in-row by the cryptography stack aioquic
already rides (no openssl dependency, no persistent state); the
client verifies nothing — the lane proves attribution, not
identity. The module-level stdlib-only law is untouched: the
aioquic imports live inside the row's scope, a lane without the
stack SKIPs honestly with the pip hint (the sandbox and the
owner's local lanes), and the VM rootfs never carries that skip
(the staging fails the leg instead).

**The engine pins.** The v1 self-test grows to 35 rows: the
embedded h3 server compiles (a syntax slip would otherwise
surface only inside a root VM run, as an opaque server-death
FAIL), the supply-vs-budget law and the CC bound hold at the
canonical geometry, and the 1-second burst bank assumption
(`default_burst(1mb) == 1mb`) the budget arithmetic rides.

## 3. The verdict

The CI's four red legs were one row born red — a needle written
against a non-root reality the root-required v2 harness never
had, red since its first uncancelled run and finally given a
green path by the wording its own context owns. The QUIC-aware
lane's last recorded residual is closed the honest way: a real
QUIC client in the VM rootfs, a real N-connections row in the
matrix, verdicts anchored in the kernel's own admission
arithmetic. The residuals that remain are the standing ones:
the row's live green belongs to the next supermassive VM run
(this push carries it — the same lane that proved every other
new row), and the QUIC residues the core documents (CID
rotation mid-flight, the >8-byte prefix share, the GSO
super-packet's first-segment attribution) stay stated in
ebpf/src/quic.rs, one class coarser, never wrong.

Empirical, fresh on this tree: gates 17/17, check-all green,
both harness self-tests green (v1 35/0/0, v2 10/0/0), the
embedded lane validated rootless end to end (6/6 real HTTP/3
connections, drift-free pacing at 100.1% of nominal); the
A/B frame bench is byte-identical where it counts (bytes/frame
+0.0%, emit/dirty/entropy within host noise) — the scripts
never touch the render path.
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
