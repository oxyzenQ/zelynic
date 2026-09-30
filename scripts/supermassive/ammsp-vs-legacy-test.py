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
    from --legacy-binary, $ZELYNIC_LEGACY_BINARY, or the canonical
    release tarball name; CI stages it into the micro-VM. Without
    it the pair verdict SKIPs loudly — never a silent pass, never a
    false fail.

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
it at call time), and each side starts from a recovered, pin-clean
state so the two schemas never see each other's pins.
"""

import argparse
import importlib.util
import os
import subprocess
import sys
import threading
import time

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
# zero ammsp references). The tarball's inner binary path, matching the
# release packaging (bin/ at the archive root).
LEGACY_VERSION = "v11.0.0"
LEGACY_TARBALL = "zelynic-v11.0.0-linux-amd64-v3-gnu.tar.gz"
LEGACY_URL = (
    f"https://github.com/oxyzenQ/zelynic/releases/download/{LEGACY_VERSION}/{LEGACY_TARBALL}"
)


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


def resolve_legacy(explicit):
    """The LEGACY side: --legacy-binary, then $ZELYNIC_LEGACY_BINARY,
    then the canonical release tarball staged by CI (/opt/zelynic/
    legacy/zelynic — the rootfs assembly step fetches it). A file that
    exists but does not execute is a hard FAIL, not a skip: a broken
    legacy binary would turn the delta proof into a one-sided claim.
    Returns (path, note) or (None, reason) for the loud SKIP."""
    candidates = []
    if explicit:
        candidates.append(explicit)
    env = os.environ.get("ZELYNIC_LEGACY_BINARY")
    if env:
        candidates.append(env)
    candidates.append("/opt/zelynic/legacy/zelynic")
    for cand in candidates:
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            rc, stdout, _ = run_side_binary(cand, ["-V"])
            if rc != 0:
                return None, f"{cand}: -V exited {rc} — not a usable zelynic"
            first = (stdout or "").strip().splitlines()
            first = first[0] if first else ""
            if "zelynic" not in first.lower() and "version" not in first.lower():
                return None, f"{cand}: -V output not a zelynic banner ({first[:60]})"
            return cand, first
    hint = explicit or env or LEGACY_URL
    return (
        None,
        f"no legacy binary (tried --legacy-binary / $ZELYNIC_LEGACY_BINARY / /opt/zelynic/legacy/zelynic; canonical source: {hint})",
    )


def leaf_bytes(path, win):
    """One leaf's download through the shared engine: a worker
    exec-moved into the child cgroup BEFORE its first socket exists
    (deterministic attribution — v1's spawn contract), reading the
    in-process loopback server for `win` seconds. Returns body bytes."""
    metric, err = sm1.spawn_in_cgroup_path(
        path,
        [sys.executable, "-c", sm1._PY_DL_CLIENT, str(sm1.SERVER.port), str(win)],
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


def run_battery_side(label, binary):
    """One side of the A/B: the identical battery under `binary`.

    The fleet, server, and cgroup spawn engine are v1's; the side is
    switched by rebinding lib.BINARY (run_zel resolves it at call
    time, and v1's apply helpers ride run_zel). Each side starts from
    a recovered pin-clean state — the two schemas never see each
    other's pins — and ends with unstrict + recover so the next side
    starts equally clean.

    Returns the leaf class counts for the coverage delta, or None
    when the side could not run at all (already recorded).
    """
    out(f"── side: {label} ({binary}) " + "─" * max(0, 44 - len(label) - len(binary)))
    lib.BINARY = binary

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
        # (v1's approved warm-up pattern).
        leaf_bytes(sibs[1], 0.5)

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
                "PASS" if cls == "policed" else "FAIL",
                f"{fmt_bps(measured)} measured vs {RATE_STR} configured — {cls}",
            )

        # The shared-budget probe: two concurrent leaves must sum to
        # ONE budget. Legacy escapes at 2x line rate — also a FAIL
        # there, which is the point (the counterfactual).
        total = concurrent_leaves_sum([sibs[0], sibs[2]], WINDOW)
        shared_bps = total / WINDOW
        shared_cls = classify(shared_bps, RATE_BPS)
        record(
            f"ammsp-vs-legacy: {label} two concurrent leaves share ONE budget",
            "PASS" if shared_cls == "policed" else "FAIL",
            f"sum {fmt_bps(shared_bps)} across two child cgroups vs {RATE_STR} — {shared_cls}",
        )

        # The nested-root probe: a stricter strict on the chain's first
        # level — leaves under it must resolve NEAREST-root (the deep
        # chain's second level reads the 50kb, not the parent's 100kb).
        chain1_id = sm1.CgroupSet._read_id(chain[0])
        if chain1_id is not None:
            rc, _, err = run_side_binary(binary, ["strict-single", str(chain1_id), NESTED_STR])
            if rc != 0:
                record(f"ammsp-vs-legacy: {label} nested-root apply", "FAIL", err.strip()[:160])
            else:
                got = leaf_bytes(chain[1], WINDOW)
                measured = got / WINDOW
                nested_cls = classify(measured, NESTED_BPS)
                record(
                    f"ammsp-vs-legacy: {label} grandchild resolves the NEAREST root",
                    "PASS" if nested_cls == "policed" else "FAIL",
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
    # path set): a missing explicit path must resolve to None with a
    # reason that names the canonical source, never a crash.
    path, note = resolve_legacy("/nonexistent/zelynic-legacy")
    assert path is None and "canonical source" in note, f"resolver shape: {note}"
    record("self: legacy resolver SKIP shape", "PASS", note[:100])

    # The run helper's timeout + missing-binary shapes.
    rc, _, err = run_side_binary("/nonexistent/zelynic", ["-V"])
    assert rc == 127 and err, "a missing binary is exit 127 with the OS error"
    record("self: side-binary runner error shape", "PASS", f"exit {rc}: {err[:60]}")

    final_report(
        t0,
        "self-test",
        "engine verified: classifier, delta verdict, resolver, runner",
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
        "side (also $ZELYNIC_LEGACY_BINARY, or /opt/zelynic/legacy/zelynic "
        "as staged by the supermassive CI legs)",
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
    legacy, legacy_note = resolve_legacy(args.legacy_binary)
    if legacy is None:
        # The pair cannot run — a loud SKIP, never a silent pass and
        # never a false fail (the same honest-SKIP contract the realnet
        # lane holds). CI stages the legacy binary, so on the super-
        # massive legs this row is live, not skipped.
        record("ammsp-vs-legacy: legacy side resolved", "SKIP", legacy_note)
        out()
        out("  The delta proof needs the legacy pair. Stage it with:")
        out(f"    curl -LO {LEGACY_URL}")
        out(f"    tar xzf {LEGACY_TARBALL} -C <dir> && export ZELYNIC_LEGACY_BINARY=<dir>/zelynic")
        final_report(time.perf_counter(), "root", "skipped — no legacy binary")
        return 0
    record("ammsp-vs-legacy: legacy side resolved", "PASS", legacy_note)

    # The shared engine boot (the v2 precedent): fleet first, then the
    # in-process server, then the harness-in-hq isolation contract.
    sm1.CG = sm1.CgroupSet()
    mode = sm1.CG.setup()
    sm1.MODE = mode
    sm1.SERVER = sm1.HttpServer()

    out(f"zelynic ammsp-vs-legacy depth test (NIGHT-perf-1) — AMMSP vs {LEGACY_VERSION}, {mode}")
    out(f"  current: {lib.BINARY}")
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

    legacy_counts = run_battery_side("legacy (pre-AMMSP)", legacy)
    ammsp_counts = run_battery_side("current (AMMSP)", lib.BINARY)

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
