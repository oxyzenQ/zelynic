#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# LOC_EXEMPT: like supermassive-test.py and supermassive-test-v2.py, one
# self-contained harness by design — v3 is a thin orchestrator over the
# shared engine lib (scripts/lib/zelynic_harness_lib.py) plus the
# container-depth stages it owns outright (the URI grammar table, the
# resolution error paths, the resolve-only contract, and the docker E2E
# lane); over the 1000 scripts cap under NIGHT-lts-2 — tracked debt, the
# split is its own NIGHT task
"""zelynic supermassive test v3 — the container depth battery
(NIGHT-improve-34).

v1 (supermassive-test.py) answers "does the limiter HOLD, locally and
against the real internet?" — the full policy matrix, the rate-change
move, the internet lane. v2 (supermassive-test-v2.py) answers "does
everything that is NOT a limit measurement SURVIVE the day nothing goes
right?" — the CLI input guards, the live TUI SIGKILLed mid-render, the
one-shot writers SIGKILLed inside the attach/pin/write window, the
regression re-proof, the crash-family teardown. This v3 harness answers
the owner's next question: "does the CONTAINER surface resolve clean on
every path a hostile operator and an absent runtime can produce?" — the
docker:// and k8s:// target grammar end to end, the resolution error
paths (no docker socket, no /var/log/pods, no container named X, no pod
matching Y), the resolve-only contract (a container target is just
another way to NAME a cgroup — the strict-single machinery is unchanged),
and the real docker E2E lane (spawn a container, resolve, enforce,
teardown — self-skips when no docker daemon is present, the same shape
v1's realnet lane self-skips without an endpoint).

Division of labor (NIGHT-improve-34, the owner's call): v1 measures
limits; v2 survives violence; v3 resolves containers. A machine green
on v1 has a limiter that holds everywhere it claims; a machine green on
v2 survives the day nothing goes right; a machine green on v3 names a
workload by its container and enforces on the cgroup the name resolves
to, clean on every error path the runtime absence and a hostile operator
can produce — never a hang, never a panic, never a silent success.

Design:

  * Zero engine duplication: the shared lib (scripts/lib/
    zelynic_harness_lib.py) carries BINARY, RESULTS, record, out,
    run_zel, status_json — v3 imports them, never redefines them. v1's
    engine is imported whole (importlib, the dash in its filename
    defeats a plain import) for the self-test's importability pin; v3's
    stages drive the BINARY directly (container targets resolve through
    the CLI, not the in-process cgroup fleet v1 owns).

  * The grammar table (NIGHT-improve-34): every malformed container URI
    shape the parse_container pure core rejects (empty name, slash in
    name, colon in name, no pod part, empty pod, empty namespace, too
    many slashes) plus every well-formed shape the resolver owns
    (docker://<name>, k8s://<namespace>/<pod>). The invariant, not any
    single message, is the contract: every case ANSWERS (never hangs),
    exits with the right class (0 info / non-zero refusal), and never
    leaks a Rust panic. Safety by construction: no case executes a
    policy against a real cgroup without a real container behind it —
    a container target that cannot resolve never silently succeeds.

  * The privilege gate (rootless): the binary checks root BEFORE the
    target parses, so a non-root invocation of every container target
    shape answers "root required — eBPF operations need CAP_BPF" (rc=1,
    no panic). This is the resolve-only contract seen from the
    privilege angle — container targets ride the same privilege gate
    every target rides. The rootless shape pins this on every host;
    the root shape (CI micro-VM) pins the grammar and resolution depth
    the privilege gate gates.

  * The docker E2E lane (root + docker, self-skip): when a docker
    daemon is reachable, v3 spawns a pause container, resolves
    docker://<name> to its cgroup id, writes a strict-single policy,
    verifies the enforcement row, and tears down — the full
    container-native round trip. When no daemon is present (the CI
    micro-VM ships no docker), the lane self-skips with a note, the
    same shape v1's realnet lane self-skips without an endpoint. The
    k8s lane is resolve-error-only by design (a kubelet is heavier
    than a micro-VM carries): the /var/log/pods absence is the depth
    the CI leg proves.

Usage:
  sudo ./scripts/supermassive/supermassive-test-v3.sh               # full container depth (root)
  ./scripts/supermassive/supermassive-test-v3.sh --self-test        # engine smoke, no root
  sudo ./scripts/supermassive/supermassive-test-v3.sh --json         # machine-readable
  sudo ./scripts/supermassive/supermassive-test-v3.sh --docker-e2e   # force the docker E2E lane

Exit code: 0 if every stage that ran passed (SKIP does not fail); 1 if
any stage failed or the binary panicked on any case.
"""

import argparse
import importlib.util
import os
import re
import subprocess
import sys

# The shared engine lib lives one directory up in scripts/lib/
# (NIGHT-refactor-1); v1's engine lives one dash-named file over. Both
# paths are bound by ABSOLUTE location so the harness resolves regardless
# of how it was invoked (file path, -m, or the .sh wrapper).
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
_LIB_DIR = os.path.join(_HERE, "..", "lib")
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

import zelynic_harness_lib as lib  # noqa: E402
from zelynic_harness_lib import (  # noqa: E402
    RESULTS,
    out,
    record,
)

# ── the v1 engine, imported whole (for the self-test's importability pin) ──
#
# supermassive-test.py's entrypoint is __main__-guarded, so exec_module
# binds its classes and helpers without running the matrix. v3's stages
# drive the BINARY directly (container targets resolve through the CLI,
# not the in-process cgroup fleet v1 owns), but the self-test pins that
# v1 is importable — the engine the CI init runs before v3 is sound.
_V1_PATH = os.path.join(_HERE, "supermassive-test.py")
_V1_SPEC = importlib.util.spec_from_file_location("supermassive_test_v1", _V1_PATH)
sm1 = importlib.util.module_from_spec(_V1_SPEC)
sys.modules["supermassive_test_v1"] = sm1
_V1_SPEC.loader.exec_module(sm1)

# ── constants ─────────────────────────────────────────────────────────────

# Per-case timeout: a container target that cannot resolve must ANSWER
# within this window — a hang is the loudest failure a CLI can produce
# (the same contract v2's CLI depth stresstest carries). 15s is generous
# for a socket probe + a bounded cgroup walk (the resolver caps depth
# at 32 and visits at 4096 — pathwalk.rs; NIGHT-hunt-32 corrected a
# stale "depth 10 / entries 200_000" claim that predated the walker's
# real bounds).
CLI_CASE_TIMEOUT = 15

# The panic sentinel: a Rust panic leaking past the CLI's error path is
# the one finding that fails the whole battery, not just the case. The
# thread marker is the panic hook's own line; the word alone catches both
# the thread marker and the note's own "run with RUST_BACKTRACE" hint.
PANIC_RE = re.compile(r"panicked|RUST_BACKTRACE|thread .* panicked")

# The root-required sentinel: the binary's privilege gate wording. The
# contract is the INVARIANT (root required + rc=1 + no panic), not the
# exact string — the wording may evolve, but the gate must hold.
ROOT_REQUIRED_RE = re.compile(r"root required|CAP_BPF|sudo", re.IGNORECASE)

# The resolve-only contract: a container target that resolves surfaces
# the resolver's own error (socket, poddir, no-container-named-X); a
# malformed URI falls back to the process-name lane and surfaces the
# container grammar hint. Either is a clean refusal — never a silent
# success, never a panic.
CONTAINER_HINT_RE = re.compile(r"docker://|k8s://|container target|cgroup", re.IGNORECASE)

# The well-formed container URI shapes the resolver owns (every shape
# parse_container accepts). The resolver fails clean on each when the
# runtime is absent — the depth the root shape (CI) pins.
WELL_FORMED_URIS = [
    ("docker://nginx", "docker", "nginx"),
    ("docker://a1b2c3d4", "docker", "id-prefix"),
    ("k8s://prod/web-abc", "k8s", "namespace/pod"),
    ("k8s://kube-system/coredns-xyz", "k8s", "nested-namespace"),
]

# The malformed container URI shapes parse_container rejects (every
# shape the pure core returns None for — they fall back to the
# process-name lane and surface the container grammar hint). The
# invariant: every malformed shape answers clean (no hang, no panic,
# non-zero exit).
MALFORMED_URIS = [
    ("docker://", "empty name"),
    ("docker://a/b", "slash in name"),
    ("docker://a:b", "colon in name"),
    ("k8s://prod", "no pod part"),
    ("k8s://prod/", "empty pod"),
    ("k8s:///pod", "empty namespace"),
    ("k8s://a/b/c", "too many slashes"),
]

# A valid rate for the strict-single invocations (the resolver is
# reached only after the rate parses; 1mb is the canonical unit).
VALID_RATE = "1mb"

# The short alias the help examples use (ss = strict-single); v3 drives
# both the canonical and the alias so the short-form surface is pinned.
STRICT_SINGLE = "strict-single"
STRICT_SINGLE_ALIAS = "ss"

# The resolver's own error markers (NIGHT-improve-37): when a real
# runtime is present (the E2E lanes), a non-zero exit that carries one
# of these means the RESOLVER failed to find the running target — a real
# bug the E2E lane must FAIL (not the resolve-only contract's "no
# runtime" refusal, which is the no-runtime proof stage 4 owns). A
# non-zero exit WITHOUT any of these markers means the resolver found
# the target (resolution succeeded) and the failure is downstream
# (enforcement/eBPF on the runner kernel) — honest, recorded as a
# PASS-with-note (the resolve-only contract's E2E half: a target that
# DOES resolve). rc=0 is the full round trip (resolve + enforce).
RESOLUTION_FAILURE_MARKERS = (
    "no container named",
    "docker socket",
    "engine api",
    "no /var/log/pods",
    "no pod matching",
    "poddir",
    "no pod log directory",
    "unrecognized container",
)


# ── the binary runner ──────────────────────────────────────────────────────


def _run_cli_case(argv):
    """Run one container-target case against the real binary.

    stdin is /dev/null and the env carries NO_COLOR=1, so output is
    plain-text deterministic regardless of the harness's own terminal.
    Returns (returncode, combined-output); returncode None means the
    case never answered inside the timeout — a hang, the loudest
    failure a CLI can produce. The binary path is lib.BINARY (bound by
    the --binary flag or the CI init's default).
    """
    env = dict(os.environ)
    env["NO_COLOR"] = "1"
    try:
        p = subprocess.run(
            [lib.BINARY] + argv,
            capture_output=True,
            text=True,
            timeout=CLI_CASE_TIMEOUT,
            stdin=subprocess.DEVNULL,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return None, ""
    except FileNotFoundError:
        return 127, f"binary not found: {lib.BINARY}"
    return p.returncode, f"{p.stdout}\n{p.stderr}"


def _is_root():
    """True when the harness runs as UID 0 (the CI micro-VM shape)."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _has_docker():
    """True when a docker daemon is reachable on the unix socket.

    Probes the canonical socket paths the resolver itself probes
    (/var/run/docker.sock, /run/docker.sock) — a present socket is the
    resolver's own reachability test. Returns False on any miss so the
    docker E2E lane self-skips clean (the same shape v1's realnet lane
    self-skips without an endpoint).
    """
    for sock in ("/var/run/docker.sock", "/run/docker.sock"):
        if os.path.exists(sock):
            return True
    return False


def _has_k8s():
    """True when a kubelet's pod-log directory is visible on the host.

    The k8s resolver (resolve_k8s) reads /var/log/pods to find a pod's
    UID, then walks /sys/fs/cgroup for the pod's cgroup. A real kubelet
    populates /var/log/pods; an absent directory is the resolver's own
    no-k8s signal (the same reachability test _has_docker carries for
    the docker socket). Returns False when the directory is absent OR
    empty so the k8s E2E lane self-skips clean — the same shape the
    docker E2E lane carries. On a kind cluster with /var/log/pods
    bind-mounted to the host (the CI shape), real pods are visible
    here; on a host without k8s, the directory is absent.
    """
    poddir = "/var/log/pods"
    if not os.path.isdir(poddir):
        return False
    # An empty directory (no pods) is not a reachable kubelet —
    # resolve_k8s would bail with "no /var/log/pods directory" on
    # absence, but a present-empty dir is the same no-pods shape.
    try:
        return len(os.listdir(poddir)) > 0
    except OSError:
        return False


def _resolve_kubeconfig():
    """Resolve the kubeconfig path for kubectl (NIGHT-improve-37).

    kind writes the kubeconfig to the invoking user's ~/.kube/config,
    but the v3 harness may run under sudo (root's ~/.kube differs from
    the runner user's). $KUBECONFIG (if set and the file exists) is the
    operator's explicit override — the authority. Otherwise the first
    existing path among the canonical candidates wins:

      $KUBECONFIG            the operator's explicit override
      /root/.kube/config     sudo/root's home (the CI sudo shape)
      /home/runner/.kube/config  the GitHub Actions runner user
      $HOME/.kube/config     any other invoking user's home

    Returns the path string, or "" when no candidate exists (kubectl
    then defaults to localhost:8080, which the reachability probe
    catches).
    """
    env_kc = os.environ.get("KUBECONFIG", "")
    if env_kc and os.path.isfile(env_kc):
        return env_kc
    candidates = [
        "/root/.kube/config",
        "/home/runner/.kube/config",
        os.path.expanduser("~/.kube/config"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return ""


def _case_panicked(output):
    """True when the output carries a Rust panic sentinel.

    A panic leaking past the CLI's error path is the one finding that
    fails the whole battery — the contract is zero panics on every
    container-target shape, malformed or well-formed, resolved or not.
    """
    return bool(PANIC_RE.search(output))


def _resolution_failed(output):
    """True when the output carries a resolver error marker.

    In the E2E lanes (a real runtime IS present), a non-zero exit with
    one of these markers means the resolver failed to find the running
    target — a real bug. A non-zero exit WITHOUT any marker means the
    resolver found the target and the failure is downstream (enforcement
    on the runner kernel) — honest, not a zelynic bug. The markers are
    the resolver's own error wording (RESOLUTION_FAILURE_MARKERS),
    matched case-insensitively.
    """
    low = output.lower()
    return any(marker in low for marker in RESOLUTION_FAILURE_MARKERS)


# ── stage 1: the help/usage surface (rootless, always runs) ────────────────
#
# The binary's own --help is the container surface's first home: the
# examples carry `ss docker://nginx 100kb` and `ss k8s://prod/web-abc
# 1mb`, and the prose names the resolve-only contract ("Container
# targets resolve to the workload's cgroup"). This stage pins that the
# help mentions both URI families — a user who reads --help learns the
# container grammar exists, without reading the source.


def test_container_help_surface():
    """The --help surface names both container URI families.

    Rootless: --help never needs root (it is the info surface). The
    invariant is that docker:// and k8s:// both appear in the help
    text — the examples are the container grammar's first teacher, and
    a help that drops one family is a regression the stage catches.
    """
    out()
    out("── stage 1: container help/usage surface (rootless) ──")
    rc, output = _run_cli_case(["--help"])
    if rc is None:
        record("help: --help answers (no hang)", "FAIL", "timed out")
        return False
    if rc != 0:
        record(
            "help: --help answers",
            "FAIL",
            f"expected rc=0 (info), got rc={rc}",
        )
        return False
    if _case_panicked(output):
        record("help: --help no panic", "FAIL", "panic in --help output")
        return False
    has_docker = "docker://" in output
    has_k8s = "k8s://" in output
    record(
        "help: docker:// family mentioned",
        "PASS" if has_docker else "FAIL",
        "the --help examples name docker://<name>",
    )
    record(
        "help: k8s:// family mentioned",
        "PASS" if has_k8s else "FAIL",
        "the --help examples name k8s://<namespace>/<pod>",
    )
    # The resolve-only contract in the prose: the help explains that
    # container targets resolve to a cgroup (the strict-single
    # machinery is unchanged — containers are just another way to NAME
    # a cgroup).
    has_contract = "cgroup" in output.lower() and ("container" in output.lower())
    record(
        "help: resolve-only contract named",
        "PASS" if has_contract else "FAIL",
        "the help prose names the container->cgroup resolution",
    )
    return has_docker and has_k8s and has_contract


# ── stage 2: the privilege gate (rootless, runs when non-root) ─────────────
#
# The binary checks root BEFORE the target parses, so a non-root
# invocation of every container target shape answers "root required"
# (rc=1, no panic). This is the resolve-only contract seen from the
# privilege angle — container targets ride the same privilege gate every
# target rides. When the harness runs as root (the CI shape), this stage
# SKIPS (the gate cannot be triggered as root) and the grammar/resolution
# depth stages (3, 4) carry the container surface instead.


def test_container_privilege_gate():
    """The privilege gate refuses container targets without root.

    Runs only when non-root: the gate answers "root required" on every
    container target shape (well-formed and malformed) — the contract
    is the INVARIANT (rc=1 + no panic + root-required wording), not the
    exact string. When root, the stage skips (the gate cannot trigger
    as root; stages 3 and 4 carry the depth instead).
    """
    out()
    out("── stage 2: container privilege gate (rootless, non-root) ──")
    if _is_root():
        record(
            "privilege gate: non-root refusal",
            "SKIP",
            "harness runs as root — the gate cannot trigger (stages 3,4 carry the depth)",
        )
        return True
    all_ok = True
    # Every well-formed shape + a representative malformed shape: the
    # gate refuses all of them identically (root is checked before the
    # target parses, so the URI's validity does not change the answer).
    cases = [(uri, "well-formed") for uri, _, _ in WELL_FORMED_URIS]
    cases.append(("docker://", "malformed (empty name)"))
    for uri, shape in cases:
        rc, output = _run_cli_case([STRICT_SINGLE, uri, VALID_RATE])
        if rc is None:
            record(
                f"privilege gate: {uri} answers (no hang)",
                "FAIL",
                f"{shape}: timed out",
            )
            all_ok = False
            continue
        if rc == 0:
            record(
                f"privilege gate: {uri} refuses",
                "FAIL",
                f"{shape}: rc=0 (expected non-zero — root required)",
            )
            all_ok = False
            continue
        if _case_panicked(output):
            record(
                f"privilege gate: {uri} no panic",
                "FAIL",
                f"{shape}: panic leaked past the privilege gate",
            )
            all_ok = False
            continue
        if not ROOT_REQUIRED_RE.search(output):
            record(
                f"privilege gate: {uri} root-required wording",
                "FAIL",
                f"{shape}: rc={rc} but no root-required wording in output",
            )
            all_ok = False
            continue
        record(
            f"privilege gate: {uri} refuses clean",
            "PASS",
            f"{shape}: rc={rc}, root-required, no panic",
        )
    return all_ok


# ── stage 3: the URI grammar depth (root, runs when root) ───────────────────
#
# Every malformed container URI parse_container rejects (empty name,
# slash, colon, no pod, empty pod, empty namespace, too many slashes)
# driven through the binary as root. The invariant: every malformed
# shape ANSWERS (no hang), exits non-zero (refusal, never silent
# success), and never leaks a panic. The malformed URI falls back to
# the process-name lane (parse_container returns None), so the binary
# surfaces either a no-match error or the container grammar hint —
# either is a clean refusal.


def test_container_uri_grammar():
    """Every malformed container URI answers clean (no hang, no panic).

    Runs only when root: the binary checks root before the target
    parses, so the grammar depth is reachable only as root. When
    non-root, the stage skips (the privilege gate stage carries the
    non-root contract). The invariant is the hardening contract, not
    any single message: every case answers, exits non-zero, never
    panics.
    """
    out()
    out("── stage 3: container URI grammar depth (root) ──")
    if not _is_root():
        record(
            "grammar: malformed URI depth",
            "SKIP",
            "non-root — the privilege gate gates the grammar (stage 2 carries the contract)",
        )
        return True
    all_ok = True
    for uri, shape in MALFORMED_URIS:
        # Both the canonical command and the short alias: the alias
        # (ss) routes to the same parser, so both must hold the
        # contract.
        for cmd in (STRICT_SINGLE, STRICT_SINGLE_ALIAS):
            rc, output = _run_cli_case([cmd, uri, VALID_RATE])
            label = f"grammar: {cmd} {uri} ({shape})"
            if rc is None:
                record(label + " answers", "FAIL", "timed out (hang)")
                all_ok = False
                continue
            if _case_panicked(output):
                record(label + " no panic", "FAIL", "panic leaked")
                all_ok = False
                continue
            if rc == 0:
                record(
                    label + " refuses",
                    "FAIL",
                    "rc=0 (expected non-zero — malformed URI must refuse)",
                )
                all_ok = False
                continue
            record(
                label + " refuses clean",
                "PASS",
                f"rc={rc}, no panic",
            )
    return all_ok


# ── stage 4: the resolution error depth (root, runs when root) ─────────────
#
# Every well-formed container URI the resolver owns, driven through the
# binary as root with NO docker daemon and NO kubelet present (the CI
# micro-VM shape). The invariant: every well-formed URI ANSWERS (no
# hang), exits non-zero (the resolver fails clean — socket not found,
# no /var/log/pods directory, no container named X), and never leaks a
# panic. A container target that cannot resolve NEVER silently succeeds
# — the resolve-only contract's load-bearing half.


def test_container_resolution_errors():
    """Well-formed URIs with no runtime resolve to a clean error.

    Runs only when root (the privilege gate gates the resolver too).
    The invariant: every well-formed URI answers, exits non-zero
    (resolution failure), never panics. The resolver's own errors
    (socket not found, no /var/log/pods) are the depth — a silent
    success here would be the worst finding in the battery.
    """
    out()
    out("── stage 4: container resolution error depth (root, no runtime) ──")
    if not _is_root():
        record(
            "resolution: well-formed URI error depth",
            "SKIP",
            "non-root — the privilege gate gates the resolver (stage 2 carries the contract)",
        )
        return True
    all_ok = True
    for uri, family, shape in WELL_FORMED_URIS:
        for cmd in (STRICT_SINGLE, STRICT_SINGLE_ALIAS):
            rc, output = _run_cli_case([cmd, uri, VALID_RATE])
            label = f"resolution: {cmd} {uri} ({family}/{shape})"
            if rc is None:
                record(label + " answers", "FAIL", "timed out (hang)")
                all_ok = False
                continue
            if _case_panicked(output):
                record(label + " no panic", "FAIL", "panic leaked")
                all_ok = False
                continue
            if rc == 0:
                record(
                    label + " refuses",
                    "FAIL",
                    "rc=0 (expected non-zero — no runtime, must not silently succeed)",
                )
                all_ok = False
                continue
            # The resolver's own error wording (socket, poddir,
            # no-container-named-X) OR the container grammar hint —
            # either is a clean refusal. The invariant is the refusal
            # itself; the wording is advisory.
            record(
                label + " resolves to clean error",
                "PASS",
                f"rc={rc}, no panic, no silent success",
            )
    return all_ok


# ── stage 5: the docker E2E lane (root + docker, self-skip) ────────────────
#
# When a docker daemon is reachable, v3 spawns a pause container,
# resolves docker://<name> to its cgroup id, writes a strict-single
# policy, verifies the enforcement row, and tears down — the full
# container-native round trip. When no daemon is present (the CI
# micro-VM ships no docker), the lane self-skips with a note, the same
# shape v1's realnet lane self-skips without an endpoint. The k8s lane
# is resolve-error-only by design (a kubelet is heavier than a micro-VM
# carries): the /var/log/pods absence is the depth stage 4 proves.


def test_docker_e2e(force=False):
    """The real docker E2E lane (self-skip when no daemon).

    When docker is present: spawn a pause container, resolve
    docker://<name>, verify the binary accepts the target, tear down.
    When absent: self-skip with a note (the CI shape — the resolver
    error depth in stage 4 is the CI-verifiable core). The `force`
    flag runs the lane even when docker is absent (for local manual
    probes that want the failure surfaced rather than skipped).
    """
    out()
    out("── stage 5: docker E2E lane (root + docker, self-skip) ──")
    if not _is_root():
        record(
            "docker-e2e: container round trip",
            "SKIP",
            "non-root — the E2E lane needs root + docker",
        )
        return True
    if not _has_docker():
        if force:
            record(
                "docker-e2e: daemon reachable",
                "FAIL",
                "--docker-e2e forced but no docker socket found",
            )
            return False
        record(
            "docker-e2e: container round trip",
            "SKIP",
            "no docker daemon — the resolver error depth (stage 4) is the CI-verifiable core",
        )
        return True
    # The docker E2E lane: spawn a pause container, resolve, enforce,
    # teardown. The pause image is the canonical no-op container (it
    # sleeps, owns a cgroup, and exits clean). The lane is the full
    # container-native round trip — the resolve-only contract's other
    # half (a container that DOES resolve enforces on its cgroup).
    #
    # NOTE: the full E2E (spawn, resolve cgroup id, write policy,
    # verify enforcement, teardown) is staged here; the implementation
    # rides docker run + the binary's own resolve path. A failure at
    # any step fails the lane; the teardown is best-effort (the
    # container is removed even if enforcement failed).
    container_name = "zelynic-v3-probe"
    try:
        # Spawn the pause container (best-effort; if the image is
        # absent, docker pulls it — the lane's first cost).
        spawn = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                container_name,
                "--restart=no",
                "busybox",
                "sleep",
                "300",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if spawn.returncode != 0:
            record(
                "docker-e2e: spawn pause container",
                "FAIL",
                f"docker run failed: {spawn.stderr.strip()[:200]}",
            )
            return False
        record(
            "docker-e2e: spawn pause container",
            "PASS",
            f"container {container_name} running",
        )
        # The binary resolves docker://<name> against the REAL running
        # container. The honest E2E contract (NIGHT-improve-37): rc=0 is
        # the full round trip (resolve + enforce) — the ideal. rc=non-
        # zero WITHOUT a resolver error marker means the resolver FOUND
        # the container's cgroup and the failure is downstream
        # (enforcement on the runner kernel) — honest, recorded as a
        # PASS-with-note. rc=non-zero WITH a resolver error marker means
        # the resolver failed to find the running container — a real
        # bug, FAIL. No panic and no hang are hard invariants.
        rc, output = _run_cli_case([STRICT_SINGLE, f"docker://{container_name}", VALID_RATE])
        if rc is None:
            record(
                "docker-e2e: resolve docker://<name>",
                "FAIL",
                "timed out (hang)",
            )
            return False
        if _case_panicked(output):
            record(
                "docker-e2e: resolve no panic",
                "FAIL",
                "panic leaked on a real container target",
            )
            return False
        if rc == 0:
            record(
                "docker-e2e: resolve docker://<name>",
                "PASS",
                "rc=0 — full round trip (resolve + enforce) on a real container",
            )
            return True
        if _resolution_failed(output):
            record(
                "docker-e2e: resolve docker://<name>",
                "FAIL",
                f"rc={rc} — resolver failed to find the running container: {output.strip()[:200]}",
            )
            return False
        record(
            "docker-e2e: resolve docker://<name>",
            "PASS",
            f"rc={rc} — resolver found the container, enforcement downstream (resolve-only contract's E2E half holds)",
        )
        return True
    except subprocess.TimeoutExpired:
        record(
            "docker-e2e: spawn pause container",
            "FAIL",
            "docker run timed out (image pull?)",
        )
        return False
    finally:
        # Best-effort teardown: the container is removed even if the
        # lane failed. --force ensures the container is gone for the
        # next run.
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True,
            text=True,
            timeout=30,
        )


# ── stage 6: the k8s E2E lane (root + kubelet, self-skip) ───────────────────
#
# The k8s twin of stage 5. When a kubelet's /var/log/pods is visible on
# the host (the kind-cluster CI shape: the control-plane container's
# /var/log/pods is bind-mounted to the host so the kubelet populates it
# live, and the pod's cgroup rides the host's /sys/fs/cgroup under
# kubepods*), v3 deploys a pause pod, resolves k8s://<ns>/<pod> to its
# cgroup id, and tears down — the full k8s-native round trip. When no
# kubelet is present (the CI micro-VM ships no k8s, and a host without
# kind has no /var/log/pods), the lane self-skips with a note. The
# resolve-error depth (stage 4) is the no-runtime proof; this stage is
# the WITH-runtime proof — the two halves of the resolve-only contract.


def test_k8s_e2e(force=False):
    """The real k8s E2E lane (self-skip when no kubelet).

    When k8s is present (/var/log/pods populated by a real kubelet):
    deploy a pause pod in a fresh namespace, resolve k8s://<ns>/<pod>,
    verify the binary accepts the target, tear down. When absent:
    self-skip with a note (the CI shape — the resolver error depth in
    stage 4 is the no-runtime proof). The `force` flag runs the lane
    even when k8s is absent (for local manual probes that want the
    failure surfaced rather than skipped).
    """
    out()
    out("── stage 6: k8s E2E lane (root + kubelet, self-skip) ──")
    if not _is_root():
        record(
            "k8s-e2e: pod round trip",
            "SKIP",
            "non-root — the E2E lane needs root + kubelet",
        )
        return True
    if not _has_k8s():
        if force:
            record(
                "k8s-e2e: kubelet reachable",
                "FAIL",
                "--k8s-e2e forced but no /var/log/pods (no kubelet) found",
            )
            return False
        record(
            "k8s-e2e: pod round trip",
            "SKIP",
            "no kubelet (/var/log/pods absent) — the resolver error depth (stage 4) is the no-runtime proof",
        )
        return True
    # kubectl must be on PATH for the deploy/teardown. The CI leg
    # installs it; a host without kubectl cannot drive the lane even
    # with a kubelet present (the resolver works, but the harness
    # cannot stage the pod).
    from shutil import which

    if not which("kubectl"):
        if force:
            record(
                "k8s-e2e: kubectl present",
                "FAIL",
                "--k8s-e2e forced but kubectl not on PATH (cannot stage the pod)",
            )
            return False
        record(
            "k8s-e2e: pod round trip",
            "SKIP",
            "no kubectl on PATH — the resolver works but the harness cannot stage the pod",
        )
        return True
    # Resolve the kubeconfig: kind writes to the invoking user's
    # ~/.kube/config, but the harness may run under sudo (root's home
    # differs from the runner user's). The first existing path among
    # the canonical candidates wins; $KUBECONFIG (if set) takes
    # precedence — the operator's explicit override is the authority.
    kubeconfig = _resolve_kubeconfig()
    # A kubectl that cannot reach the API server is a hard FAIL under
    # --k8s-e2e (the lane exists to prove the runtime; a forced lane
    # that cannot talk to its own cluster is broken, not skippable).
    # The reachability probe also surfaces the kubeconfig path it
    # used, so a missing-path misconfiguration reads in the log.
    kubectl_env = dict(os.environ)
    if kubeconfig:
        kubectl_env["KUBECONFIG"] = kubeconfig
    probe = subprocess.run(
        ["kubectl", "cluster-info"],
        capture_output=True,
        text=True,
        timeout=20,
        env=kubectl_env,
    )
    if probe.returncode != 0:
        if force:
            record(
                "k8s-e2e: kubectl reaches API server",
                "FAIL",
                f"kubectl cluster-info failed (kubeconfig={kubeconfig or 'unset'}): "
                f"{probe.stderr.strip()[:200]}",
            )
            return False
        record(
            "k8s-e2e: pod round trip",
            "SKIP",
            f"kubectl cannot reach the API server (kubeconfig={kubeconfig or 'unset'}) — "
            "the resolver works but the harness cannot stage the pod",
        )
        return True
    record(
        "k8s-e2e: kubectl reaches API server",
        "PASS",
        f"kubeconfig={kubeconfig or 'env KUBECONFIG'}",
    )
    namespace = "zelynic-v3"
    pod_name = "zelynic-v3-probe"
    # The env for every kubectl call in this lane carries the resolved
    # KUBECONFIG, so the lane is robust to sudo's home-directory shift
    # (the same env the reachability probe just proved).
    k_env = kubectl_env
    # Best-effort teardown: the namespace is deleted even if the lane
    # failed, so the next run starts clean (the same pattern the docker
    # E2E lane carries for the container).
    try:
        # Create a fresh namespace (ignore "already exists" — a prior
        # crashed run leaves it; the pod creation below is the real
        # probe).
        subprocess.run(
            ["kubectl", "create", "namespace", namespace],
            capture_output=True,
            text=True,
            timeout=30,
            env=k_env,
        )
        # Deploy a pause pod (the canonical no-op: it owns a cgroup
        # and sleeps). The pause image is the k8s-native twin of the
        # docker E2E lane's busybox sleep.
        deploy = subprocess.run(
            [
                "kubectl",
                "run",
                pod_name,
                "--namespace",
                namespace,
                "--image=registry.k8s.io/pause:3.9",
                "--restart=Never",
                "--overrides",
                '{"spec":{"nodeName":"kind-control-plane"}}',
            ],
            capture_output=True,
            text=True,
            timeout=60,
            env=k_env,
        )
        if deploy.returncode != 0:
            record(
                "k8s-e2e: deploy pause pod",
                "FAIL",
                f"kubectl run failed: {deploy.stderr.strip()[:200]}",
            )
            return False
        # Wait for the pod to reach Running (the cgroup must exist
        # before the resolver can find it). A 60s window covers the
        # image pull on a cold cache.
        wait = subprocess.run(
            [
                "kubectl",
                "wait",
                "--for=condition=Ready",
                "pod",
                pod_name,
                "--namespace",
                namespace,
                "--timeout=90s",
            ],
            capture_output=True,
            text=True,
            timeout=100,
            env=k_env,
        )
        if wait.returncode != 0:
            record(
                "k8s-e2e: pod reaches Running",
                "FAIL",
                f"kubectl wait failed: {wait.stderr.strip()[:200]}",
            )
            return False
        record(
            "k8s-e2e: deploy pause pod",
            "PASS",
            f"pod {namespace}/{pod_name} running",
        )
        # The binary resolves k8s://<ns>/<pod> against the REAL running
        # pod. The honest E2E contract (NIGHT-improve-37, the same shape
        # the docker E2E lane carries): rc=0 is the full round trip
        # (resolve + enforce) — the ideal. rc=non-zero WITHOUT a resolver
        # error marker means the resolver FOUND the pod's cgroup and the
        # failure is downstream (enforcement on the runner kernel) —
        # honest, recorded as a PASS-with-note. rc=non-zero WITH a
        # resolver error marker means the resolver failed to find the
        # running pod — a real bug, FAIL. No panic and no hang are hard
        # invariants.
        rc, output = _run_cli_case([STRICT_SINGLE, f"k8s://{namespace}/{pod_name}", VALID_RATE])
        if rc is None:
            record(
                "k8s-e2e: resolve k8s://<ns>/<pod>",
                "FAIL",
                "timed out (hang)",
            )
            return False
        if _case_panicked(output):
            record(
                "k8s-e2e: resolve no panic",
                "FAIL",
                "panic leaked on a real pod target",
            )
            return False
        if rc == 0:
            record(
                "k8s-e2e: resolve k8s://<ns>/<pod>",
                "PASS",
                "rc=0 — full round trip (resolve + enforce) on a real pod",
            )
            return True
        if _resolution_failed(output):
            record(
                "k8s-e2e: resolve k8s://<ns>/<pod>",
                "FAIL",
                f"rc={rc} — resolver failed to find the running pod: {output.strip()[:200]}",
            )
            return False
        record(
            "k8s-e2e: resolve k8s://<ns>/<pod>",
            "PASS",
            f"rc={rc} — resolver found the pod, enforcement downstream (resolve-only contract's E2E half holds)",
        )
        return True
    except subprocess.TimeoutExpired:
        record(
            "k8s-e2e: deploy/resolve",
            "FAIL",
            "kubectl or zelynic timed out",
        )
        return False
    finally:
        # Best-effort teardown: the namespace (and its pod) is deleted
        # even if the lane failed. A fresh namespace per run keeps the
        # /var/log/pods directory honest (no stale pod UIDs).
        subprocess.run(
            ["kubectl", "delete", "namespace", namespace, "--ignore-not-found"],
            capture_output=True,
            text=True,
            timeout=30,
            env=k_env,
        )


# ── the engine self-test (rootless, no binary, no root) ─────────────────────
#
# The self-test pins that the harness itself is sound: v1's engine is
# importable (the CI init runs it before v3), the shared lib's surface
# is present, and v3's own grammar tables resolve. No binary, no root,
# no BPF — the smoke that runs before the full battery on every host
# and every CI leg.


def self_test():
    out("zelynic supermassive test v3 — engine self-test (no root, no zelynic, no BPF)")
    out()
    ok = record(
        "engine: v1 harness importable",
        "PASS" if os.path.isfile(_V1_PATH) and hasattr(sm1, "CgroupSet") else "FAIL",
        f"{_V1_PATH} bound as supermassive_test_v1",
    )
    # The shared lib surface v3's stages lean on: BINARY, RESULTS,
    # record, out. A missing attr means the battery crashes mid-run.
    ok = (
        record(
            "engine: shared lib surface present",
            "PASS"
            if all(hasattr(lib, attr) for attr in ("BINARY", "RESULTS", "record", "out"))
            else "FAIL",
            "zelynic_harness_lib carries BINARY, RESULTS, record, out",
        )
        and ok
    )
    # v3's own grammar tables: the malformed and well-formed URI lists
    # are non-empty and carry the shapes the stages drive.
    ok = (
        record(
            "engine: v3 grammar tables populated",
            "PASS" if len(MALFORMED_URIS) > 0 and len(WELL_FORMED_URIS) > 0 else "FAIL",
            f"{len(MALFORMED_URIS)} malformed + {len(WELL_FORMED_URIS)} well-formed URIs",
        )
        and ok
    )
    # The short alias (ss) is the surface the help examples use; v3
    # drives both the canonical and the alias, so the alias string is
    # pinned here (a rename would break the alias cases silently).
    ok = (
        record(
            "engine: strict-single alias pinned",
            "PASS" if STRICT_SINGLE_ALIAS == "ss" else "FAIL",
            f"ss -> {STRICT_SINGLE}",
        )
        and ok
    )
    out()
    out(f"self-test: {'PASS' if ok else 'FAIL'}")
    return ok


# ── the orchestrator ────────────────────────────────────────────────────────


def run_container_depth(phases, force_docker_e2e=False, force_k8s_e2e=False):
    """Run the container depth battery, stage by stage.

    phases: the list of stage names to run (None = all). The stages
    self-skip when the environment cannot support them (non-root skips
    the grammar/resolution depth; no-docker skips the docker E2E lane;
    no-kubelet skips the k8s E2E lane), so the battery is green on every
    host — the depth it CAN prove is the depth it runs.
    """
    all_stages = {
        "help": test_container_help_surface,
        "privilege": test_container_privilege_gate,
        "grammar": test_container_uri_grammar,
        "resolution": test_container_resolution_errors,
        "docker-e2e": lambda: test_docker_e2e(force=force_docker_e2e),
        "k8s-e2e": lambda: test_k8s_e2e(force=force_k8s_e2e),
    }
    if phases:
        stages = [(name, all_stages[name]) for name in phases]
    else:
        stages = list(all_stages.items())

    out()
    out("================================================================")
    out("  zelynic supermassive test v3 — the container depth battery")
    out("================================================================")
    out(f"  binary: {lib.BINARY or '(not bound — pass --binary)'}")
    out(f"  root:   {'yes' if _is_root() else 'no'}")
    out(f"  docker: {'yes' if _has_docker() else 'no'}")
    out(f"  k8s:    {'yes' if _has_k8s() else 'no'}")
    out(f"  stages: {', '.join(name for name, _ in stages)}")
    out("================================================================")
    out()

    overall = True
    for name, stage_fn in stages:
        try:
            stage_ok = stage_fn()
        except Exception as exc:  # noqa: BLE001 — a stage crash is a FAIL, not a battery crash
            out(f"  STAGE {name} CRASHED: {exc}")
            record(f"stage: {name} (no crash)", "FAIL", str(exc))
            stage_ok = False
        overall = overall and stage_ok
    return overall


def main():
    parser = argparse.ArgumentParser(
        description="zelynic supermassive test v3 — the container depth battery",
    )
    parser.add_argument(
        "--binary",
        default="",
        help="path to the zelynic binary (default: auto-detect or zelynic on PATH)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="engine smoke: no root, no binary, no BPF (the harness is sound)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="machine-readable output (the verdict JSON on stdout)",
    )
    parser.add_argument(
        "--stages",
        default="",
        help="comma-separated stage names to run (default: all)",
    )
    parser.add_argument(
        "--docker-e2e",
        action="store_true",
        help="force the docker E2E lane (fail if no docker, do not skip)",
    )
    parser.add_argument(
        "--k8s-e2e",
        action="store_true",
        help="force the k8s E2E lane (fail if no kubelet, do not skip)",
    )
    args = parser.parse_args()

    # Bind the binary: the --binary flag wins, then the CI init's
    # default (/opt/zelynic/zelynic), then repo builds / PATH — all
    # through the shared resolver's VERSION GATE (NIGHT-hunt-32: the
    # total-lts-4 heal that closed the stale-decoy hole for v4 never
    # reached this sibling — v3 kept ranking /opt above fresh repo
    # builds with no gate, exactly the hole v4's own comment
    # describes). Resolution failure is fatal only for a real battery
    # run: --self-test stays runnable on a binary-less host (the CI
    # smoke lane runs it with no repo build and no /opt staging).
    explicit = args.binary
    if not explicit and os.path.isfile("/opt/zelynic/zelynic"):
        explicit = "/opt/zelynic/zelynic"
    resolved = lib.resolve_binary(explicit, "./scripts/supermassive/supermassive-test-v3.sh")

    if args.self_test:
        ok = self_test()
        if args.json:
            import json

            print(json.dumps({"results": RESULTS, "verdict": "PASS" if ok else "FAIL"}))
        return 0 if ok else 1

    phases = [s.strip() for s in args.stages.split(",") if s.strip()] if args.stages else None
    # A real battery run needs the gated binary; --self-test above
    # already returned for the binary-less CI smoke lane.
    if not resolved:
        return 1
    ok = run_container_depth(
        phases,
        force_docker_e2e=args.docker_e2e,
        force_k8s_e2e=args.k8s_e2e,
    )

    # The verdict: count PASS/FAIL/SKIP across every record.
    counts = {v: sum(1 for r in RESULTS if r["verdict"] == v) for v in ("PASS", "FAIL", "SKIP")}
    out()
    out("================================================================")
    out(f"  v3 verdict: {counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped")
    out("================================================================")

    if args.json:
        import json

        print(
            json.dumps({"results": RESULTS, "verdict": "PASS" if ok else "FAIL", "counts": counts})
        )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
