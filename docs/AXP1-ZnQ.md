<!--
  SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
  SPDX-License-Identifier: AGPL-3.0-only OR Commercial
-->

# AXP1-ZnQ (Architect's eXecution Protocol 1)

The maintenance bot's one protocol: no CI lane marries a hardcoded
server again. The owner named the bottleneck on
night-learning-into-darkness-1: the estate's kernel-fetch and apt
seats pointed at one hardcoded archive address, so a single bad hour
(timeout, unable-to-connect, not-found) reddened lanes that had
nothing wrong with their own code — and every "fix" would have been
another hardcoded address waiting for its own bad hour. The answer is
a tested address pool the bot curates, not a hardcoded default the
tree prays for.

Identity: **AXP1-ZnQ** stands for **Architect's eXecution Protocol 1**
— the expansion rides every mention of the name across the docs, the
workflows and the scripts, by the owner's standing law. The name was
adopted by night-solid-defense-1 for the Sunday sentinel; this task
adds the protocol's second half, the address catalog. This document
is the protocol's front door.

## The catalog (repos-for-ci/*.txt)

`repos-for-ci/` at the repo root holds one `.txt` per address family
(`apt-mirrors.txt` ships today). The law of every catalog file:

- one candidate address per line, the whole trimmed line IS the
  address (no trailing comments — a comment occupies its own line,
  starting with `#`);
- `https://archive.ubuntu.com/ubuntu` — an HTTP(S) address, probed
  with a real GET, TLS verified with the runner's own CA store (a
  cert failure is DOWN, never ignored);
- `dns.example.com:53` — a host:port address, probed with a socket
  connect (the DNS-resolver catalog rides this kind when its lane
  adopts the resolver);
- the authored order is the owner's trust ranking — canonical archive
  first, the runner-native azure mirror second, then the wide
  mirrors. It is never a latency leaderboard; see the write law;
- bounded: 10 to 100 active lines per file, the owner's min and max
  — both halves enforced (the refresher prunes tombstones at the
  100-line file cap and warns when the alive pool drops under
  `--min-lines`, default 10, `0` disables);
- the shipped seed was probe-verified (12 of 12 candidates answered
  the noble InRelease GET with HTTP 200 and a fresh index, age 0d,
  from the authoring sandbox on 2026-11-27, and the jammy InRelease
  probe path was spot-checked on three lines the same day). A
  runner-region difference is exactly what the weekly curation
  exists to reconcile.

## The two commands

Both live in `scripts/dev/`, stdlib-only Python (urllib, socket,
concurrent.futures — no third-party dependency joins the maintenance
surface, the LTS law), and share one probe core
(`scripts/dev/axp1znq_probe.py`) so a mirror the resolver picks and a
mirror the refresher keeps are measured the same way.

**The resolver — `axp1znq_resolve.py`** — is the failover half, the
consumer CI lanes call:

```
python3 scripts/dev/axp1znq_resolve.py \
  --file repos-for-ci/apt-mirrors.txt \
  --probe-path dists/jammy/InRelease \
  --first
```

It walks the catalog top to bottom, probes each address, narrates
every verdict to stderr (line number, reason, milliseconds — the CI
log keeps the audit trail), prints the first ALIVE address to stdout
and exits 0. Line 1 down, the lane moves on; line 5 answering is the
one the lane uses — the owner's scenario, verbatim. A catalog with no
live address is exit 1: a lane must never silently fall back to a
dead default. Freshness is reported in the narration but never blocks
the pick — a minutes-old index still serves the lane; curation is the
refresher's job. Report mode (no `--first`) prints the whole table or
`--json` for machines.

The probe path is per-seat by law: a lane probes the suite it
actually consumes. The jammy floor legs probe `dists/jammy/InRelease`
(a mirror that cannot serve jammy is DOWN before apt ever rides it),
the noble family leg and the latest-head walkers probe
`dists/noble/InRelease`. The Sunday refresher probes the whole
catalog through `dists/noble/InRelease` — curation judges the mirror
pool itself, suite-agnostic; seat precision happens at resolve time.

**The refresher — `axp1znq_refresh.py`** — is the catalog half, the
Sunday pass the maintenance lane runs:

```
python3 scripts/dev/axp1znq_refresh.py \
  --root repos-for-ci \
  --probe-path dists/noble/InRelease \
  --note-file "${RUNNER_TEMP}/axp1-address-note.txt"
```

It probes every catalog concurrently, keeps an address only when it
answers AND serves a fresh index (the InRelease file's own `Date:`
header is the freshness witness; older than `--max-age-days`, default
14, is STALE — the owner asked for repos that are updated AND connect
stably, and alive-but-frozen is a lie the catalog must not keep), and
writes the survivors back. The write law:

- survivors keep their authored order — the catalog's shape is the
  owner's trust ranking, never a weekly reshuffle a noisy runner
  would churn;
- a dead or stale address becomes a dated tombstone in place
  (`# down 2026-11-27 (unreachable ...) - https://...`), readable
  history the owner can revive by deleting one line;
- the 100-line cap prunes the OLDEST tombstones first; an active
  address is never pruned;
- the never-empty guard: zero live addresses means the file is NOT
  rewritten (a flaky runner probe must never erase the owner's pool)
  — the lane warns (`::warning::` in CI) and the note names CALL THE
  OWNER, the one critical the refresher escalates;
- the duplicate-honesty law (rev 3): duplicate lines name ONE
  address, so they get ONE probe and ONE shared verdict — a flaky
  second read can never split the verdicts and write a zero-active
  catalog past the guard;
- the atomic-write law (rev 3): the rewrite lands through a
  same-directory temp file and `os.replace` — a mid-write failure
  can never leave the pool partial or empty for the diff gate to
  ship;
- idempotent: unchanged catalog, unchanged file — no write, no
  commit-note, no churn;
- `--dry-run` reports the verdicts and writes nothing.

The probe's own contract carries the rev-3 laws too: a malformed
HTTP conversation (a garbage status line, an oversized header — the
TLS-terminating-middlebox failure shape, `http.client.HTTPException`,
which is not an `OSError` subclass) is a DOWN verdict with a narrated
reason, never an escaped exception that could crash the caller's
pool; a 2xx with no parsable `Date` header is STALE under the
refresher's freshness contract (no witness, no PASS — alive-but-
unwitnessed is the lie the catalog must not keep) while the resolver
rides unchanged (freshness never blocks the pick); and the tcp kind
refuses out-of-range ports as DOWN instead of letting the socket
layer silently wrap them. The full law set is pinned by the nine-law
local harness (`scripts/dev/axp1znq_edge_proof.py`: the stale
refusal, the resolve-despite-age pick, the all-dead exit 1, the fresh
survivor, the malformed-HTTP DOWN, the `--first` stdout purity, the
index-404 DOWN, the witness law, and duplicate-honesty-atomic-write).

## The wiring (the Sunday cadence)

The maintenance lane (`Dragon Guard - AXP1-ZnQ Supply-Chain
Sentinel`, cron `0 3 * * 0` — Sunday 03:00 UTC = 10:00 WIB) runs the
refresher as the step directly after `Update dependencies` and before
the supply-chain verdict, gated on `scan_only != true` like every
ship step. The owner's sequencing law: the address refresh rides
AFTER the dependency update finishes, and the one weekly commit
carries deps AND addresses. This estate's lane is the two-job shape
(validate → commit with the out-of-tree artifact handoff), so the
changed catalog rides the validated lane artifact
(`repos-for-ci/**` in the upload path) to the commit job, which
mirrors it over the checkout the same rsync way as the prebuilt lane;
the allowed-diff gates in both jobs admit `repos-for-ci/` beside the
lockfiles and the prebuilt lane; the staging wall's explicit-path law
holds (`git add repos-for-ci`, never a glob — the 9708883 leak
class); and the refresher's note rides its own optional artifact into
the commit body. The refresher never blocks the ship lane: it exits 0
with warnings recorded; the red stays the verdict step's (AXP1-ZnQ —
Architect's eXecution Protocol 1 — and its own exit-1 law).

Every apt fallback lane in the CI estate walks the resolver: no apt
seat points at a hardcoded archive address anymore. The first port
landed all six seats over three workflows: `netrunner-night-c77.yml`
(the latest-kernel envelope's suite walk, its per-suite Release reads
and its apt source lines), `supermassive.yml` (the jammy 5.15.0 floor
leg and the best-specs latest-kernel seat, including its diagnostic
discovery curl) and `supermassive-e2e.yml` (the jammy floor leg, the
best-specs latest-kernel seat and the noble 6.8 family leg). Each
seat swaps its hardcoded address for one resolver call — no new
machinery needed, that is the point of the pool — and fails loud when
nothing alive answers, never a dead default.

The open adoption surface, named honestly: the pinned
cloud-images.ubuntu.com URL in `supermassive-server.yml` (an image
mirror seat, a different address family than the apt archive pool),
the archive constants in `scripts/sandbox/rootfs-pack.py` (a dev-side
sandbox builder, not a CI lane), and the mirror latency table in
`scripts/supermassive/supermassive-test.py` (measurement fixture data
by design — those addresses are the thing being measured, not a
source being consumed). A lane adopts by swapping its address for a
resolver call, so these move when their wiring wants it.

The probe laws are proven, not claimed:
`scripts/dev/axp1znq_edge_proof.py` serves a loopback InRelease whose
`Date:` header the harness controls and walks the verdict paths end
to end — the stale refusal (a frozen index fails the max-age law, the
never-empty guard keeps the catalog untouched, the lane calls the
owner), the failover pick ignoring a reported-but-nonblocking age,
the all-dead exit-1 loud, and the fresh survivor written back. The
harness doubles as the probe core's regression gate: any future probe
change must keep all four green.

## The honest edges

- Probe verdicts are network-relative: the authoring sandbox verified
  12 of the 12 shipped lines, while the sister production line's
  runner found one of the same mirrors dark from the runner network
  (mirrors.kernel.org, 2026-11-27) — a runner-region difference is
  exactly what the weekly curation exists to reconcile, and the
  first Sunday pass writes the runner's own truth into the catalog.
- The refresher's fresh-index probe path is `dists/noble/InRelease` —
  the noble LTS the runner fleet runs. When the fleet moves to the
  next LTS, the probe path moves with it (one flag, both commands;
  the per-seat probe paths follow the suites their lanes consume).
- `--first` worst case on a dead-first catalog is bounded by attempts
  x timeout per address (both are flags); an HTTP probe rides the
  whole-request timeout alone (urllib's one-socket law), the connect
  timeout binds only the host:port kind, and on proxied networks the
  total timeout is what bites.
- The resolver proves an address answers; it cannot prove the apt
  transaction will never fail behind it — the apt retry contract
  (`Acquire::Retries=5`, the curl retry walk) stays in place and a
  catalog-cured address still fails loud when it misbehaves mid-run.

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
