#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
"""zelynic AMMSP-vs-legacy depth test (NIGHT-perf-1) — the subtree
contract proven as a DELTA between two real binaries.

The owner's ask: "create a script to depth test zelynic AMMSP vs non
AMMSP (using old v11 stable), verify and proof the AMMSP works 99%
or not" — turned into a permanent harness the supermassive legs run
on the kernel floor AND the latest head (the low/best pair).

The two sides are the two REAL builds, nothing simulated:

  * CURRENT — this checkout's AMMSP build (schema v10+, the subtree
    walk + the generation-stamped memo since NIGHT-perf-0), resolved
    exactly the way every other harness resolves it (the version
    gate included: this side IS this checkout).
  * LEGACY — the last pre-AMMSP stable release, v11.0.0 (schema v9,
    leaf-anchored lookups: a socket born in a child cgroup simply
    missed the policy map and ran UNLIMITED). The legacy side comes
    from --legacy-binary, $ZELYNIC_LEGACY_BINARY, the canonical
    release tarball staged by CI (/opt/zelynic/legacy/zelynic), or
    the canonical AUTO-DOWNLOAD (the owner's ask: the sha512-sidecar-
    verified fetch into a TMPDIR cache, never the repo tree;
    --no-download keeps resolution local). Without any of them the
    pair verdict SKIPs loudly — never a silent pass, never a false
    fail.

Both sides run the IDENTICAL battery under the same fleet, the same
server, the same traffic workers, the same bands — the only variable
is the binary. The battery is the subtree depth sweep the AMMSP
design promised:

  1. a strict-single on the PARENT cgroup at 100kb;
  2. seven leaf children measured one by one — a three-level depth
     chain (parent/sub, parent/sub/sub2, parent/sub/sub2/sub3), three
     direct siblings, and one child created AFTER the apply (the
     owner's eagle-eyes scenario, the exact hole AMMSP exists to
     close);
  3. one leaf deliberately pre-poisoned with an UNLIMITED download
     BEFORE the apply (the memo AMMSP must invalidate);
  4. a shared-budget probe: two leaves downloading CONCURRENTLY must
     sum to ONE 100kb budget, not two;
  5. a nested-root probe: a 50kb strict on the chain's first level —
     the leaves under it must resolve to the NEAREST root.

Each leaf lands one of three classes: POLICED (inside the measured
band), ESCAPED (at or beyond 2.6x configured — the line-rate class),
or GRAY (between — counted as not-policed, reported honestly). The
coverage rate is policed/total per side, and the headline verdict is
the DELTA: the AMMSP side must cover >= 99% of the leaves, the legacy
side must cover none of them (every measured leaf lives in a CHILD
cgroup — the pre-AMMSP datapath never policed one), and the gap must
be >= 99 points. That is the "does AMMSP work 99% or not" question,
answered with numbers from both kernels of the low/best pair.

Division of labor with v1/v2: this harness owns the A/B DELTA only.
The AMMSP tree's own functional battery (band verdicts, stats
roll-up, generation-stamp behavior) lives in supermassive-test.py's
test_ammsp_subtree; v2 owns the abuse family. What only a
two-binary comparison can prove — the counterfactual, "what the same
machine, same fleet, same traffic would have leaked on the old
stable" — is the one row this script exists for.

Engine reuse (the v2 precedent, zero duplication): v1 is imported
whole via importlib — the CgroupSet fleet, the in-process HttpServer,
the cgroup-spawned workers, the band machinery. The side under test
is switched by rebinding lib.BINARY between sides (run_zel resolves
it at call time), each side starts from a recovered, pin-clean state
so the two schemas never see each other's pins — and the current
side's path is captured BY VALUE before the first side runs, because
the rebind is exactly the thing that must never leak into the second
side's invocation (the run-253 CI lesson, pinned in the self-test).
"""

import argparse
import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request

# The shared engine lib lives in scripts/lib/ — bound by ABSOLUTE path so
# the harness works from any CWD, through the wrapper, or via importlib.
_HERE = os.path.dirname(os.path.abspath(__file__))
_LIB_DIR = os.path.join(_HERE, "..", "lib")
for _p in (_LIB_DIR, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import zelynic_harness_lib as lib  # noqa: E402 - needs the lib/ path bootstrap above
from zelynic_harness_lib import (  # noqa: E402 - needs the lib/ path bootstrap above
    BAND_HI,
    RESULTS,
    final_report,
    fmt_bps,
    out,
    record,
)

# v1 imported whole (the dash in its filename defeats a plain import —
# the v2 precedent). CgroupSet, HttpServer, spawn_in_cgroup_path, the
# download worker, and the fleet constants all come from there, so a
# fix to any of them lands here the same day.
_SPEC = importlib.util.spec_from_file_location(
    "supermassive_test_v1", os.path.join(_HERE, "supermassive-test.py")
)
sm1 = importlib.util.module_from_spec(_SPEC)
sys.modules["supermassive_test_v1"] = sm1
_SPEC.loader.exec_module(sm1)

# The battery's numbers. RATE = the strict on the parent; NESTED = the
# stricter strict on the chain's first level; WINDOW = per-leaf measured
# span (band_check wants a window long enough for loopback steady state
# under a policed bucket — v1's stages use 4.0 for the same class).
RATE_BPS = 100_000
RATE_STR = "100kb"
NESTED_BPS = 50_000
NESTED_STR = "50kb"
WINDOW = 4.0

# The ESCAPED threshold: at or beyond 2.6x configured is the line-rate
# class (band_hi is 1.30 — twice it leaves no ambiguity between "slow
# because policed" and "fast because unlimited"). Between band_hi and
# this line is GRAY: counted as not-policed (it is), reported as its
# own class (never hidden in a pass).
ESCAPED_FACTOR = 2.6

# The legacy side's canonical provenance: the last pre-AMMSP stable
# release (verified: the v11.0.0 tree's ebpf/src/bin/limiter.rs carries
# zero ammsp references). The tarball carries the binary at its ROOT
# (verified against the release archive itself), with the sha512sum
# sidecar beside it — the pair the auto-download fetches and the CI
# rootfs step stages.
LEGACY_VERSION = "v11.0.0"
LEGACY_TARBALL = "zelynic-v11.0.0-linux-amd64-v3-gnu.tar.gz"
LEGACY_URL = (
    f"https://github.com/oxyzenQ/zelynic/releases/download/{LEGACY_VERSION}/{LEGACY_TARBALL}"
)
LEGACY_SHA512_EXT = ".sha512sum"
LEGACY_INNER = "zelynic"
LEGACY_CACHE = os.path.join(
    os.environ.get("TMPDIR") or "/tmp", "zelynic-ammsp-legacy", LEGACY_VERSION.lstrip("v")
)


def verify_sha512(path, expected_hex):
    """Streaming sha512 over a file — the same arithmetic the CI rootfs
    step's `sha512sum -c` runs, held by one implementation here so
    the auto-download and the CI lane cannot drift apart. Pure and
    rootless: the self-test pins it with matching and tampered shapes
    on a local file, no network, no root.
    """
    digest = hashlib.sha512()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 16), b""):
            digest.update(block)
    return digest.hexdigest() == expected_hex.lower()


def fetch_legacy():
    """The canonical auto-download lane (the owner's ask: 'should
    automatic download').

    The CI rootfs assembly stages the v11.0.0 release tarball into
    /opt/zelynic/legacy before the VM boots (a fetch failure fails
    the leg), and local runs get the same provenance here: the
    canonical tarball plus its sha512sum sidecar, verified, the one
    binary member extracted into a per-version cache under TMPDIR
    (never the repo tree — the checkout stays clean), the executable
    bit restored (the tarfile data filter drops archive modes), and
    the -V gate left to resolve_legacy's candidate loop — the same
    validation every other candidate gets. A cached, executable
    extraction is reused without a refetch: /tmp lives one boot and
    the -V gate revalidates it every run anyway.

    Returns (path, note) on success, or (None, reason) when the
    network, the checksum, or the archive shape refuses — the
    caller falls through to the loud SKIP with the reason attached.
    """
    os.makedirs(LEGACY_CACHE, exist_ok=True)
    tarball = os.path.join(LEGACY_CACHE, LEGACY_TARBALL)
    inner = os.path.join(LEGACY_CACHE, LEGACY_INNER)
    if not (os.path.isfile(inner) and os.access(inner, os.X_OK)):
        sidecar = tarball + LEGACY_SHA512_EXT
        try:
            for dest, url in (
                (tarball, LEGACY_URL),
                (sidecar, LEGACY_URL + LEGACY_SHA512_EXT),
            ):
                with urllib.request.urlopen(url, timeout=60) as r, open(dest, "wb") as f:
                    shutil.copyfileobj(r, f)
        except OSError as e:
            return None, f"canonical fetch failed ({e})"
        with open(sidecar, encoding="ascii") as f:
            line = f.read().strip()
        expected = line.split()[0] if line else ""
        if not verify_sha512(tarball, expected):
            return None, "canonical tarball failed its sha512sum sidecar"
        try:
            with tarfile.open(tarball) as tf:
                # getmember by the literal inner name: the extraction
                # cannot walk out of the cache dir by construction.
                member = tf.getmember(LEGACY_INNER)
                tf.extract(member, LEGACY_CACHE, filter="data")
        except (tarfile.TarError, OSError) as e:
            return None, f"canonical tarball extraction failed ({e})"
        os.chmod(inner, 0o755)
    return inner, f"{LEGACY_URL} — sha512 sidecar verified, cached at {inner}"


def classify(measured_bps, configured_bps):
    """One leaf's verdict class: 'policed', 'escaped', or 'gray'.

    Pure arithmetic so the self-test pins it without root, without
    traffic, without a server: the coverage verdict below is exactly
    this table applied to whatever the workers measured.
    """
    if measured_bps <= BAND_HI * configured_bps:
        return "policed"
    if measured_bps >= ESCAPED_FACTOR * configured_bps:
        return "escaped"
    return "gray"


def coverage_verdict(ammsp_counts, legacy_counts):
    """The headline DELTA computation (pure, self-test-pinned).

    Each side's counts is a dict of class -> leaves. AMMSP works at
    the 99% bar when: its policed share is >= 99% of its measured
    leaves, the legacy side polices none of the child leaves (every
    pre-AMMSP child escaped — the counterfactual), and the gap is
    >= 99 points. Anything else FAILs with the numbers attached —
    the verdict never rounds a single escaped leaf up to a pass.
    """
    ammsp_total = sum(ammsp_counts.values())
    legacy_total = sum(legacy_counts.values())
    ammsp_cov = ammsp_counts.get("policed", 0) / ammsp_total if ammsp_total else 0.0
    legacy_cov = legacy_counts.get("policed", 0) / legacy_total if legacy_total else 0.0
    delta = ammsp_cov - legacy_cov
    ok = ammsp_cov >= 0.99 and legacy_cov <= 0.01 and delta >= 0.99 and ammsp_total > 0
    detail = (
        f"AMMSP {ammsp_counts.get('policed', 0)}/{ammsp_total} leaf cgroups policed "
        f"({ammsp_cov:.0%}), legacy {legacy_counts.get('policed', 0)}/{legacy_total} "
        f"({legacy_cov:.0%}) — the {delta:.0%} gap is the counterfactual proof"
    )
    return ok, detail, ammsp_cov, legacy_cov


def side_verdict(cls, is_current):
    """One row's verdict, side-aware (pure, self-test-pinned).

    THE DELTA row owns the headline pass/fail — but the per-leaf rows
    also carry verdicts, and the harness's EXIT rides any FAIL row.
    The 1a25f91 CI lesson: a perfect proof (AMMSP 7/7 policed, legacy
    0/7, THE DELTA row OK) still exited 1 because the legacy side's
    ESCAPES were recorded as FAIL rows — nine of them — and the
    supermassive legs went red on the counterfactual doing exactly
    what it exists to do. The fix is the honest reading of a row's
    verdict per side: the current side is JUDGED (policed is the only
    pass — an escaped or gray leaf is a real finding against the 99%
    claim and the DELTA row fails with it), while the legacy side is
    the CONTROL (escaping is the expected pre-AMMSP shape; a POLICED
    legacy child is the measurement bug the proof refuses). The row
    detail keeps the class either way — nothing is hidden, only the
    verdict column learns which side it is on.
    """
    if is_current:
        return "PASS" if cls == "policed" else "FAIL"
    return "FAIL" if cls == "policed" else "PASS"


def run_side_binary(binary, args, timeout=30):
    """run_zel's shape for an EXPLICIT binary — the A/B needs two of
    them, so the side under test is always passed by path (the lib's
    module-global BINARY is rebound between sides for the v1 helpers
    that read it; this helper keeps direct calls equally honest)."""
    try:
        p = subprocess.run([binary] + args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except OSError as e:
        return 127, "", str(e)


def _legacy_banner(cand):
    """The -V usability gate: (banner, None) for a usable zelynic,
    (None, reason) when it exists but does not answer like one."""
    rc, stdout, _ = run_side_binary(cand, ["-V"])
    if rc != 0:
        return None, f"{cand}: -V exited {rc} — not a usable zelynic"
    first = (stdout or "").strip().splitlines()
    first = first[0] if first else ""
    if "zelynic" not in first.lower() and "version" not in first.lower():
        return None, f"{cand}: -V output not a zelynic banner ({first[:60]})"
    return first, None


def resolve_legacy(explicit, download=True):
    """The LEGACY side: --legacy-binary, then $ZELYNIC_LEGACY_BINARY,
    then the canonical release tarball staged by CI (/opt/zelynic/
    legacy/zelynic — the rootfs assembly step fetches it), then the
    canonical AUTO-DOWNLOAD as the last lane (the owner's ask: the
    sha512-verified fetch into a TMPDIR cache; --no-download keeps
    resolution local). A file that exists but does not execute is a
    hard FAIL, not a skip: a broken legacy binary would turn the
    delta proof into a one-sided claim.
    Returns (path, banner) on success, (path, reason) when a candidate
    EXISTS but is not a healthy executable zelynic (the hard-FAIL
    marker — NIGHT-hunt-32 finally enforces the sentence above: the
    caller FAILs instead of SKIP-exit-0, which CI's [ -x ] + exit-code
    guard used to read as PASS), or (None, reason) for the loud SKIP
    when nothing was found at all."""
    candidates = []
    if explicit:
        candidates.append(explicit)
    env = os.environ.get("ZELYNIC_LEGACY_BINARY")
    if env:
        candidates.append(env)
    candidates.append("/opt/zelynic/legacy/zelynic")
    for cand in candidates:
        if not cand or not os.path.isfile(cand):
            continue
        if not os.access(cand, os.X_OK):
            return cand, f"{cand}: exists but is not executable"
        first, reason = _legacy_banner(cand)
        if reason:
            return cand, reason
        return cand, first
    # Nothing local — the auto-download is the last lane (CI never
    # reaches it: the rootfs step stages the binary and the loop
    # above already returned).
    fetch_note = "auto-download disabled (--no-download)"
    if download:
        fetched, fetch_note = fetch_legacy()
        if fetched:
            first, reason = _legacy_banner(fetched)
            if reason is None:
                return fetched, first
            # Fetched but broken — the same hard-FAIL marker: it exists.
            return fetched, reason
    hint = explicit or env or LEGACY_URL
    return (
        None,
        f"no legacy binary (tried --legacy-binary / $ZELYNIC_LEGACY_BINARY / "
        f"/opt/zelynic/legacy/zelynic / the canonical auto-download ({fetch_note}); "
        f"canonical source: {hint})",
    )


def battery_order(current, legacy):
    """The two sides as (label, binary, is_current) triples, frozen by
    value.

    Legacy first, current second — the counterfactual runs before the
    tree under test, and the teardown between sides leaves the fleet
    clean either way. Both paths are PLAIN ARGUMENTS because
    run_battery_side rebinds lib.BINARY as its first act: a caller
    that reads the module global after a side has run gets that side's
    binary instead of its own. That is the run-253 CI lesson — the
    current side executed the legacy binary, AMMSP coverage read
    0/7, and all four supermassive legs failed on a harness aliasing
    bug, not an AMMSP regression. The third element names the side for
    the side-aware row verdicts; the self-test pins the discipline
    rootlessly by rebinding the global between capture and use.
    """
    return (
        ("legacy (pre-AMMSP)", legacy, False),
        ("current (AMMSP)", current, True),
    )


def leaf_bytes(path, win, idle=0.0):
    """One leaf's download through the shared engine: a worker
    exec-moved into the child cgroup BEFORE its first socket exists
    (deterministic attribution — v1's spawn contract), reading the
    in-process loopback server for `win` seconds. Returns body bytes.
    idle > 0 switches the worker to v1's starve-limited drain shape
    (see _PY_DL_CLIENT) — the cushion drains ride it so the client
    count spans what the connection delivered."""
    metric, err = sm1.spawn_in_cgroup_path(
        path,
        [sys.executable, "-c", sm1._PY_DL_CLIENT, str(sm1.SERVER.port), str(win), str(idle)],
        win + 20,
    )
    if metric is None:
        record("ammsp-vs-legacy: leaf worker", "FAIL", err)
    return metric or 0


def concurrent_leaves_sum(paths, win):
    """Two leaves downloading at the same time — the shared-budget
    probe. Each worker is its own process in its own child cgroup, so
    the sum is what ONE root budget must cover. Returns total bytes."""
    results = [0, 0]

    def one(i, path):
        got = leaf_bytes(path, win)
        results[i] = got

    threads = [threading.Thread(target=one, args=(i, p)) for i, p in enumerate(paths)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(win + 30)
    return sum(results)


def mkdir_quiet(path):
    """Best-effort cgroup mkdir; returns True when the cgroup exists."""
    try:
        os.mkdir(path)
        return True
    except FileExistsError:
        return True
    except OSError as e:
        record(f"ammsp-vs-legacy: create {os.path.basename(path)}", "FAIL", str(e))
        return False


def rmdir_quiet(path):
    """Best-effort cgroup rmdir (empty cgroups only; workers already
    exited). Between-side hygiene, never a verdict."""
    try:
        os.rmdir(path)
    except OSError:
        pass


def measure_line_rate(win=2.0):
    """The unpoliced loopback floor, measured once before either side
    runs: a scratch child of the never-policed fleet bed "b", one
    download, gone again. The same gate v1's test_ammsp_subtree holds
    (a 100kb band is meaningless when the machine cannot feed 2x it) —
    measured, never assumed."""
    scratch = f"{sm1.CG.paths['b']}/av-baseline"
    if not mkdir_quiet(scratch):
        return 0.0
    try:
        return leaf_bytes(scratch, win) / win
    finally:
        rmdir_quiet(scratch)


def nested_apply_argv(chain1_id, probe_supported):
    """The nested-root row's strict-single argv, built side-aware.

    The probe flag rides the current side only: the legacy v11.0.0
    binary predates --no-probe and exits 2 on it. The ff8e73dc CI
    find: rider C's toggle fix converted v1's apply_single (and
    wrote the toggle to the wrong module — see rebind_side) but
    missed this direct run_side_binary call site, so every
    supermassive leg went red on the legacy side's exit 2. Building
    the argv through one helper makes the side-awareness
    structural — a future call site cannot regress it silently.
    """
    argv = ["strict-single", str(chain1_id), NESTED_STR]
    if probe_supported:
        argv.append("--no-probe")
    return argv


def rebind_side(binary, is_current):
    """Rebind the two module globals the side owns — the 501ab20
    lesson (rider I's close): the toggle must land on the module
    that READS it.

    lib.BINARY is read by run_zel at call time (the zelynic_
    harness_lib module — the run-253 lesson's rebind target).
    PROBE_FLAG_SUPPORTED is a supermassive-test (sm1) module global
    read by apply_single's own body. Rider C flipped it as
    lib.PROBE_FLAG_SUPPORTED — a fresh attribute on a module that
    never defines the name, read by nobody — so the toggle never
    flipped, apply_single kept appending --no-probe for the legacy
    v11.0.0 side, and every supermassive leg failed on its exit 2
    for THREE pushes while the tree claimed the fix at the source.
    One helper, both rebinds, the structural target: a future side
    switch cannot write the toggle to the wrong module again.
    """
    lib.BINARY = binary
    sm1.PROBE_FLAG_SUPPORTED = is_current


def run_battery_side(label, binary, is_current=False):
    """One side of the A/B: the identical battery under `binary`.

    The fleet, server, and cgroup spawn engine are v1's; the side is
    switched by rebinding the two globals the side owns through
    rebind_side — lib.BINARY (run_zel resolves it at call time, and
    v1's apply helpers ride run_zel) and sm1.PROBE_FLAG_SUPPORTED
    (apply_single's own module global, the 501ab20 wrong-module
    lesson). Each side starts from a recovered pin-clean state —
    the two schemas never see each other's pins — and ends with
    unstrict + recover so the next side starts equally clean. Row
    verdicts are SIDE-AWARE (side_verdict): the current side is
    judged, the legacy side is the control whose escapes are the
    expected counterfactual.

    Returns the leaf class counts for the coverage delta, or None
    when the side could not run at all (already recorded).
    """
    out(f"── side: {label} ({binary}) " + "─" * max(0, 44 - len(label) - len(binary)))
    # Both globals the side owns, through the one structural helper:
    # lib.BINARY for run_zel, sm1.PROBE_FLAG_SUPPORTED for
    # apply_single (the 501ab20 wrong-module lesson).
    rebind_side(binary, is_current)

    # Clean slate: recover tolerates an already-clean pin dir.
    rc, _, err = run_side_binary(binary, ["recover"])
    if rc != 0:
        record(f"ammsp-vs-legacy: {label} recover", "FAIL", err.strip()[:160])
        return None

    parent = sm1.CG.paths["a"]
    chain = [f"{parent}/av-sub", f"{parent}/av-sub/av-deep2", f"{parent}/av-sub/av-deep2/av-deep3"]
    sibs = [f"{parent}/av-sib1", f"{parent}/av-sib2", f"{parent}/av-sib3"]
    made = []

    def mk(paths):
        for p in paths:
            if mkdir_quiet(p):
                made.append(p)

    counts = {"policed": 0, "escaped": 0, "gray": 0}
    details = []
    try:
        # The seven measured leaves: the depth chain plus the siblings.
        # The late-born child joins them AFTER the apply below.
        leaves = chain + sibs
        if not all(mkdir_quiet(p) for p in leaves):
            return None
        made += [p for p in leaves if p not in made]
        # Pre-poison one sibling with an UNLIMITED window: the AMMSP
        # side memoizes the negative (and the perf-0 generation stamp
        # must retire it after the apply); the legacy side has no
        # memo — this is just a pre-apply baseline download there.
        leaf_bytes(sibs[0], 1.0)

        ok, payload = sm1.apply_single("a", RATE_STR, RATE_BPS, RATE_BPS)
        if not ok:
            record(f"ammsp-vs-legacy: {label} strict-single on the parent", "FAIL", payload)
            return None
        record(
            f"ammsp-vs-legacy: {label} strict-single on the parent",
            "PASS",
            f"{RATE_STR} on cgroup a — the subtree contract is now the question",
        )

        # Cushion drain: a fresh bucket banks one second of rate; pay
        # it out at line rate so the measured windows see steady state
        # (v1's approved warm-up pattern — retrying and starve-limited
        # now: a stalled warm-up worker reads a silent zero and the
        # cushion leaks into the first measured leaf, the 0b0a8f5
        # lesson; a wall-deadlined one can exit mid-blast and skew the
        # accounting, the 1a25f91 lesson).
        lib.drain_cushion(lambda: leaf_bytes(sibs[1], 4.0, idle=0.5), lib.default_burst(RATE_BPS))

        # The late-born child: created AFTER the apply — the owner's
        # eagle-eyes scenario, the exact shape the legacy datapath
        # never covered and AMMSP exists to cover.
        late = f"{parent}/av-late"
        if mkdir_quiet(late):
            made.append(late)
            leaves = leaves + [late]

        # Per-leaf measurement, sequential: each leaf's class is its
        # own verdict line (the depth sweep the owner asked for).
        for p in leaves:
            got = leaf_bytes(p, WINDOW)
            measured = got / WINDOW
            cls = classify(measured, RATE_BPS)
            counts[cls] += 1
            details.append(f"{os.path.basename(p)}={cls}")
            record(
                f"ammsp-vs-legacy: {label} leaf {os.path.basename(p)}",
                side_verdict(cls, is_current),
                f"{fmt_bps(measured)} measured vs {RATE_STR} configured — {cls}",
            )

        # The shared-budget probe: two concurrent leaves must sum to
        # ONE budget. The legacy side escapes at ~2x line rate — the
        # expected control shape, side_verdict keeps it a PASS there
        # while the class stays in the row's detail.
        #
        # NIGHT-total-lts-1 rider 2: the discarded warm-up drain
        # before the measured pair — the lts-8 approved pattern
        # (supermassive-test.py's drain_cushion lineage), applied
        # here for the same reason it was applied there: "a BAND_HI
        # fail that is attach-moment physics, not enforcement". The
        # shared root bucket starts with its 64 KiB burst credit;
        # at this trickle rate that credit is 16% of the pair's
        # whole 4 s window budget (400 KB), and the epoch refill's
        # skew adds its few percent on top — the 7d78049 best-musl
        # leg read the healthy pair at 131.1 KB/s against the 1.30
        # BAND_HI, one point past the band, with every single-leaf
        # row policed at 64-90 KB/s and THE DELTA itself green
        # (7/7 vs 0/7): the cushion, not the law. The observed
        # history without the drain: sums 73.8-121.9 KB/s across
        # fifteen healthy draws, then 131.1 — the band's edge IS
        # the cushion's edge. One discarded warm-up window through
        # the first sibling pays the credit out first (draining
        # 64 KiB on loopback takes microseconds, lts-8), so the
        # measured pair sees steady state and the BAND_HI verdict
        # judges the sharing law, not the attach moment. The band
        # itself is NOT widened: a real double-budget regression
        # (each leaf its own bucket) reads toward 2x and must
        # still trip, and on the control side the escape shape is
        # untouched (the drain is a trickle against line rate).
        leaf_bytes(sibs[0], 1.0)  # discarded warm-up: pay the burst credit
        total = concurrent_leaves_sum([sibs[0], sibs[2]], WINDOW)
        shared_bps = total / WINDOW
        shared_cls = classify(shared_bps, RATE_BPS)
        record(
            f"ammsp-vs-legacy: {label} two concurrent leaves share ONE budget",
            side_verdict(shared_cls, is_current),
            f"sum {fmt_bps(shared_bps)} across two child cgroups vs {RATE_STR} — {shared_cls}",
        )

        # The nested-root probe: a stricter strict on the chain's first
        # level — leaves under it must resolve NEAREST-root (the deep
        # chain's second level reads the 50kb, not the parent's 100kb).
        chain1_id = sm1.CgroupSet._read_id(chain[0])
        if chain1_id is not None:
            rc, _, err = run_side_binary(binary, nested_apply_argv(chain1_id, is_current))
            if rc != 0:
                record(f"ammsp-vs-legacy: {label} nested-root apply", "FAIL", err.strip()[:160])
            else:
                # The fresh nested bucket starts FULL (the 64 KiB GSO
                # burst floor binds at this rate). v1's own nested-root
                # stage drains it first — the approved pattern; without
                # the drain the 4s window straddles the band edge
                # (128..133% of 50kb, cushion plus entitlement) and the
                # row flips between policed and gray on GSO timing
                # alone. The drain rides through the measured leaf so
                # the tokens it pulls are the nested bucket's own, in
                # the starve-limited shape.
                lib.drain_cushion(
                    lambda: leaf_bytes(chain[1], 4.0, idle=0.5),
                    lib.default_burst(NESTED_BPS),
                )
                got = leaf_bytes(chain[1], WINDOW)
                measured = got / WINDOW
                nested_cls = classify(measured, NESTED_BPS)
                record(
                    f"ammsp-vs-legacy: {label} grandchild resolves the NEAREST root",
                    side_verdict(nested_cls, is_current),
                    f"{fmt_bps(measured)} under a {NESTED_STR} root inside a "
                    f"{RATE_STR} subtree — {nested_cls}",
                )

        out(f"  {label} leaf sweep: {' '.join(details)}")
        return counts
    finally:
        # Side teardown: drop the policies with the side's own binary,
        # then recover the pins. The next side (or the next harness)
        # starts from the same clean state this one did.
        run_side_binary(binary, ["unstrict-all"], timeout=60)
        run_side_binary(binary, ["recover"])
        for p in reversed(made):
            rmdir_quiet(p)


def self_test():
    """The rootless engine smoke (the repo's cross-distro minimum):
    the classifier table, the coverage/delta verdict at its exact
    thresholds, the legacy resolver's failure shape, and the report
    plumbing — python3 stdlib only, no root, no zelynic, no BPF."""
    out("zelynic ammsp-vs-legacy depth test — engine self-test (NIGHT-perf-1)")
    out()
    t0 = time.perf_counter()

    # The classifier table: every class boundary, both rates.
    assert classify(100_000, RATE_BPS) == "policed", "on-rate is policed"
    assert classify(65_000, RATE_BPS) == "policed", "band_lo floor is policed"
    assert classify(130_000, RATE_BPS) == "policed", "band_hi ceiling is policed"
    assert classify(130_001, RATE_BPS) == "gray", "past band_hi is gray"
    assert classify(259_999, RATE_BPS) == "gray", "before the escape line is gray"
    assert classify(260_000, RATE_BPS) == "escaped", "the escape line is escaped"
    assert classify(90_000_000, RATE_BPS) == "escaped", "line rate is escaped"
    assert classify(50_000, NESTED_BPS) == "policed", "nested rate polices at its own band"
    record("self: leaf classifier table", "PASS", "policed / gray / escaped boundaries pinned")

    # The delta verdict at its exact thresholds.
    ok, detail, a_cov, l_cov = coverage_verdict(
        {"policed": 7, "escaped": 0, "gray": 0}, {"policed": 0, "escaped": 7, "gray": 0}
    )
    assert ok and a_cov == 1.0 and l_cov == 0.0, "7/7 vs 0/7 must be the clean proof"
    record("self: delta verdict — the clean proof", "PASS", detail)

    ok, detail, a_cov, l_cov = coverage_verdict(
        {"policed": 6, "escaped": 1, "gray": 0}, {"policed": 0, "escaped": 7, "gray": 0}
    )
    assert not ok, "6/7 (86%) is below the 99% bar — one escape fails the proof"
    record("self: delta verdict — one escape fails", "PASS", f"correctly rejected: {detail}")

    ok, detail, a_cov, l_cov = coverage_verdict(
        {"policed": 7, "escaped": 0, "gray": 0}, {"policed": 1, "escaped": 6, "gray": 0}
    )
    assert not ok, "a policed LEGACY child is a measurement bug, not a pass"
    record("self: delta verdict — a policed legacy child fails", "PASS", "counterfactual guarded")

    ok, _, _, _ = coverage_verdict({"policed": 0, "escaped": 0, "gray": 0}, {"policed": 1})
    assert not ok, "an empty AMMSP sweep is no proof at all"
    record("self: delta verdict — empty sweep fails", "PASS", "zero leaves is zero evidence")

    # The legacy resolver's SKIP shape (no legacy binary on this host
    # path set, offline): a missing explicit path must resolve to None
    # with a reason that names the canonical source, never a crash.
    # download=False keeps the self-test hermetic — no network in the
    # engine smoke, same as no root and no BPF.
    path, note = resolve_legacy("/nonexistent/zelynic-legacy", download=False)
    assert path is None and "canonical source" in note, f"resolver shape: {note}"
    record("self: legacy resolver SKIP shape", "PASS", note[:100])

    # The run helper's timeout + missing-binary shapes.
    rc, _, err = run_side_binary("/nonexistent/zelynic", ["-V"])
    assert rc == 127 and err, "a missing binary is exit 127 with the OS error"
    record("self: side-binary runner error shape", "PASS", f"exit {rc}: {err[:60]}")

    # The run-253 CI lesson, pinned as a shape: the current side's
    # binary is captured BEFORE the legacy side rebinds lib.BINARY —
    # reading the module global after the first side returns would
    # run the legacy binary on BOTH sides (AMMSP 0/7, THE DELTA
    # failing as a harness bug). battery_order() takes both paths as
    # plain arguments, so the rebind discipline is structural: the
    # captured value survives a module-global mutation untouched.
    captured = "/checkout/zelynic"
    order = battery_order(captured, "/opt/zelynic/legacy/zelynic")
    lib.BINARY = "/opt/zelynic/legacy/zelynic"  # what the first side leaves behind
    assert order[0][0] == "legacy (pre-AMMSP)" and order[0][1] == "/opt/zelynic/legacy/zelynic"
    assert order[0][2] is False, "the legacy side names itself the control"
    assert order[1][0] == "current (AMMSP)" and order[1][1] == captured, (
        "the current side must be the captured path, never the post-rebind global"
    )
    assert order[1][2] is True, "the current side names itself the judged side"
    record(
        "self: battery order — current side captured by value",
        "PASS",
        "the legacy rebind can never leak into the current side's invocation",
    )

    # The ff8e73dc lesson, pinned as a shape: the nested-root row
    # passed --no-probe to the legacy v11.0.0 binary (exit 2, every
    # supermassive leg red) because the toggle fix converted v1's
    # apply_single but missed this direct run_side_binary call site.
    # The argv must ride the toggle: the current side carries the
    # flag, the legacy side never sees it.
    argv_now = nested_apply_argv(4242, True)
    assert argv_now == ["strict-single", "4242", NESTED_STR, "--no-probe"], argv_now
    argv_old = nested_apply_argv(4242, False)
    assert argv_old == ["strict-single", "4242", NESTED_STR], argv_old
    record(
        "self: nested-root argv rides the side-aware probe toggle",
        "PASS",
        "the legacy binary never sees --no-probe",
    )

    # The 501ab20 lesson, pinned as the module identity (rider I's
    # close): rider C flipped the toggle on the WRONG MODULE —
    # lib.PROBE_FLAG_SUPPORTED wrote a fresh attribute on
    # zelynic_harness_lib that nothing reads, while apply_single
    # resolves PROBE_FLAG_SUPPORTED in sm1's own globals — so the
    # toggle never flipped, the legacy v11.0.0 side kept receiving
    # --no-probe, and every supermassive leg failed on its exit 2
    # for three pushes while the tree claimed the fix at the source.
    # The rebind helper must land BOTH globals on the modules that
    # read them: flip, read back, restore.
    saved_binary = lib.BINARY
    saved_toggle = sm1.PROBE_FLAG_SUPPORTED
    try:
        rebind_side("/opt/zelynic/legacy/zelynic", False)
        assert sm1.PROBE_FLAG_SUPPORTED is False, "the legacy side must flip sm1's toggle"
        assert lib.BINARY == "/opt/zelynic/legacy/zelynic", "run_zel's binary follows the side"
        rebind_side("/opt/zelynic/zelynic", True)
        assert sm1.PROBE_FLAG_SUPPORTED is True, "the current side must flip sm1's toggle"
        assert lib.BINARY == "/opt/zelynic/zelynic"
        assert "PROBE_FLAG_SUPPORTED" in sm1.apply_single.__code__.co_names, (
            "apply_single must resolve the toggle in its own module's globals"
        )
    finally:
        sm1.PROBE_FLAG_SUPPORTED = saved_toggle
        lib.BINARY = saved_binary
    record(
        "self: side rebind lands on the module that reads each global",
        "PASS",
        "lib.BINARY for run_zel, sm1.PROBE_FLAG_SUPPORTED for apply_single",
    )

    # The 1a25f91 lesson, pinned as the verdict table: the legacy
    # side's escapes are the EXPECTED counterfactual (a FAIL row for
    # one would make a perfect proof exit 1 — the exit contract rides
    # any FAIL row, and nine expected escapes failed four CI legs),
    # while a policed legacy child is the measurement bug the proof
    # refuses. The current side stays judged: only policed passes.
    assert side_verdict("policed", True) == "PASS"
    assert side_verdict("escaped", True) == "FAIL"
    assert side_verdict("gray", True) == "FAIL"
    assert side_verdict("escaped", False) == "PASS", "the control's escape is the point"
    assert side_verdict("gray", False) == "PASS", "the control's gray is still not-policed"
    assert side_verdict("policed", False) == "FAIL", "a policed legacy child is a measurement bug"
    record(
        "self: side-aware row verdicts",
        "PASS",
        "the counterfactual's escapes pass, the judged side's misses fail, the delta owns the headline",
    )

    # The auto-download's verifier, pinned rootlessly: the streaming
    # sha512 against a local file, the matching and the tampered
    # shape. The network fetch itself is CI's lane (and any run with
    # network); the arithmetic is the part a regression could
    # silently weaken, so it is the part the self-test owns.
    with tempfile.TemporaryDirectory() as td:
        probe = os.path.join(td, "probe.bin")
        with open(probe, "wb") as f:
            f.write(b"zelynic legacy probe")
        digest = hashlib.sha512(b"zelynic legacy probe").hexdigest()
        assert verify_sha512(probe, digest), "a matching digest verifies"
        assert not verify_sha512(probe, "0" * 128), "a tampered digest refuses"
        record("self: canonical sha512 verifier", "PASS", "match + tamper shapes pinned")

    final_report(
        t0,
        "self-test",
        "engine verified: classifier, delta verdict, resolver, runner, downloader",
    )


def main():
    ap = argparse.ArgumentParser(
        prog="ammsp-vs-legacy-test",
        description="zelynic AMMSP vs pre-AMMSP (v11.0.0) subtree-coverage "
        "depth test (NIGHT-perf-1) — the 99% delta proof",
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="verify the harness engine only — no root, no zelynic, no BPF",
    )
    ap.add_argument(
        "--binary",
        default="",
        help="the CURRENT (AMMSP) zelynic under test (default: the repo's "
        "own resolution, newest build first)",
    )
    ap.add_argument(
        "--legacy-binary",
        default="",
        help="the pre-AMMSP legacy zelynic (v11.0.0) for the counterfactual "
        "side (also $ZELYNIC_LEGACY_BINARY, /opt/zelynic/legacy/zelynic "
        "as staged by the supermassive CI legs, or the canonical "
        "auto-download — in that order)",
    )
    ap.add_argument(
        "--no-download",
        action="store_true",
        help="never touch the network for the legacy side — resolution stays "
        "local and the pair SKIPs loudly when no candidate exists",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="machine-readable verdict lines (the CI note shape)",
    )
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    if os.geteuid() != 0:
        out("FAIL: this harness drives real BPF enforcement — run it as root")
        out("  (sudo ./scripts/supermassive/ammsp-vs-legacy-test.sh)")
        out("  The engine alone can be verified rootlessly: --self-test")
        return 1

    if not lib.resolve_binary(args.binary, "ammsp-vs-legacy-test.sh"):
        return 1
    # The current side is captured BY VALUE the moment resolution
    # succeeds: run_battery_side rebinds lib.BINARY for every side it
    # runs, so reading the module global after the legacy side returns
    # would hand the harness the LEGACY binary for its "current
    # (AMMSP)" side (the run-253 lesson — both sides pre-AMMSP, the
    # delta failing as a harness bug). battery_order() freezes the
    # pair; the self-test pins the discipline.
    current = lib.BINARY
    legacy, legacy_note = resolve_legacy(args.legacy_binary, download=not args.no_download)
    if legacy is None:
        # The pair cannot run — a loud SKIP, never a silent pass and
        # never a false fail (the same honest-SKIP contract the realnet
        # lane holds). CI stages the legacy binary, so on the super-
        # massive legs this row is live, not skipped.
        record("ammsp-vs-legacy: legacy side resolved", "SKIP", legacy_note)
        out()
        out("  The delta proof needs the legacy pair. The auto-download")
        out("  already tried the canonical release (or --no-download")
        out("  held it back). Stage it by hand:")
        out(f"    curl -LO {LEGACY_URL}")
        out(f"    curl -LO {LEGACY_URL}{LEGACY_SHA512_EXT}")
        out(
            f"    tar xzf {LEGACY_TARBALL} -C <dir> && "
            f"export ZELYNIC_LEGACY_BINARY=<dir>/{LEGACY_INNER}"
        )
        final_report(time.perf_counter(), "root", "skipped — no legacy binary")
        return 0
    if legacy_note is not None:
        # NIGHT-hunt-32: the resolver's own docstring contract, finally
        # enforced — a candidate that EXISTS but is not a healthy
        # executable legacy zelynic is a hard FAIL, never a skip: the
        # one-sided delta is exactly what this harness exists to
        # forbid, and a SKIP-exit-0 used to read as PASS through
        # supermassive-init's [ -x ] + exit-code guard.
        record("ammsp-vs-legacy: legacy side resolved", "FAIL", legacy_note)
        out()
        out("  The legacy candidate exists but is not a healthy zelynic")
        out("  legacy binary — the delta proof refuses to run one-sided.")
        out("  Re-stage it (the sha512-verified fetch) and re-run:")
        out(f"    curl -LO {LEGACY_URL}")
        out(f"    curl -LO {LEGACY_URL}{LEGACY_SHA512_EXT}")
        out(
            f"    tar xzf {LEGACY_TARBALL} -C <dir> && "
            f"export ZELYNIC_LEGACY_BINARY=<dir>/{LEGACY_INNER}"
        )
        final_report(time.perf_counter(), "root", "failed — broken legacy binary")
        return 1
    record("ammsp-vs-legacy: legacy side resolved", "PASS", legacy_note)

    # The shared engine boot (the v2 precedent): fleet first, then the
    # in-process server, then the harness-in-hq isolation contract.
    sm1.CG = sm1.CgroupSet()
    mode = sm1.CG.setup()
    sm1.MODE = mode
    sm1.SERVER = sm1.HttpServer()

    out(f"zelynic ammsp-vs-legacy depth test (NIGHT-perf-1) — AMMSP vs {LEGACY_VERSION}, {mode}")
    out(f"  current: {current}")
    out(f"  legacy:  {legacy}")
    out()

    # The loopback baseline gate: a 100kb band is meaningless under a
    # floor too low to feed it (the same gate v1's stages hold — the
    # SKIP is honest, never a false pass).
    if not sm1.CG.dedicated:
        record("ammsp-vs-legacy: dedicated fleet", "SKIP", "no cgroup lane — child leaves need one")
        final_report(time.perf_counter(), "root", "skipped — no dedicated cgroup fleet")
        return 0
    baseline = measure_line_rate()
    if baseline < 2_000_000:
        record(
            "ammsp-vs-legacy: loopback baseline",
            "SKIP",
            f"{fmt_bps(baseline)} — too low to feed a {RATE_STR} band",
        )
        final_report(time.perf_counter(), "root", "skipped — baseline too low")
        return 0
    record("ammsp-vs-legacy: loopback baseline", "PASS", f"{fmt_bps(baseline)} unpoliced floor")

    (legacy_label, legacy_path, _), (current_label, current_path, _) = battery_order(
        current, legacy
    )
    legacy_counts = run_battery_side(legacy_label, legacy_path, is_current=False)
    ammsp_counts = run_battery_side(current_label, current_path, is_current=True)

    ok, detail, ammsp_cov, legacy_cov = coverage_verdict(ammsp_counts or {}, legacy_counts or {})
    record(
        "ammsp-vs-legacy: THE DELTA — AMMSP polices >= 99% of child leaves, legacy none",
        "PASS" if ok else "FAIL",
        detail,
    )

    final_report(
        time.perf_counter(),
        "root",
        f"AMMSP subtree coverage {ammsp_cov:.0%} vs legacy {legacy_cov:.0%} — "
        "the 99% proof is the delta",
    )
    failed = any(r["verdict"] == "FAIL" for r in RESULTS)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
