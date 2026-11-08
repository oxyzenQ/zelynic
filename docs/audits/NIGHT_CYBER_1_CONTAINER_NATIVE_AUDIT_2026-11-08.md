<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# NIGHT-CYBER-1 — The Container-Native Surface Audit (2026-11-08)

The four questions a container-native operator actually asks, asked of
zelynic's container support (`docker://<name>`, `k8s://<namespace>/<pod>`)
under the peak-skip protocol: is it PEAK NATIVE, is it RELIABLE, is it
EFFICIENT, is it LTS. The surface has shipped for multiple releases, has a
dedicated E2E battery (`scripts/supermassive/supermassive-test-v3.sh`, the
v3 container depth battery) and a CI kind lane
(`.github/workflows/supermassive-container.yml`); it had never been formally
audited. This record audits it. Verdict up front: **peak, native, reliable,
efficient, LTS — confirmed on all four; no gap proven; peak-skip applied;
zero code changes shipped.**

## The four questions (verbatim)

- **Q1. PEAK NATIVE** — is the grammar genuinely native (a real resolver
  against the runtime's own contract), or a shim that half-works?
- **Q2. RELIABLE** — does it handle the shapes that break naively-written
  resolvers: docker daemon down, kubelet down, container stopped, pod
  restarted, pod rescheduled, stale log dirs, UID changes?
- **Q3. EFFICIENT** — does container resolution add cost to the hot path,
  or is it one-shot at apply time?
- **Q4. LTS** — do the two resolution substrates (Docker Engine API, the
  kubelet's /var/log/pods directory convention) have stable enough contracts
  that zelynic can rely on them for a decade?

## Phase 1 — the inventory

| Module | Owns | file:line |
|---|---|---|
| `src/ebpf/identity/container/mod.rs` | The dispatch (`resolve`), the `ContainerRef` grammar (`docker://`, `k8s://`), the k8s resolver (log-dir read + cgroup walk), the bounded cgroup DFS, the kernfs-inode cgroup-id read, the error shapes | mod.rs:49-67 (ref), :77-102 (parse), :109-114 (dispatch), :122-158 (pure log-dir cores), :165-238 (k8s resolver), :245-250 (pod cgroup matcher), :255-288 (bounded walk), :293-296 (cgroup id) |
| `src/ebpf/identity/container/docker.rs` | The Docker Engine API client (unix socket, HTTP/1.0, 2 s deadlines, 4 MiB reply cap), the entry/match/liveness pure cores, the resolve walk, both cgroup-driver matchers | docker.rs:25-30 (endpoint + sockets), :62-79 (state parse), :89-95 (stopped line), :104-161 (match verdicts), :165-171 (socket candidates), :177-201 (socket GET), :216-258 (reply parse + sanitize choke), :261-330 (resolve), :336-349 (driver matcher) |
| `src/ebpf/limiter/resolve.rs` | The resolve-only handoff: `Target::Container` → `container::resolve` → cgroup ids → the single lane | resolve.rs:50-56 (single), :113-115 (batched twin) |
| `src/ebpf/limiter/types.rs` | The target grammar: `parse_container` tried FIRST, then `cg:`, then numeric id, else process name | types.rs:371-383 |
| `src/commands/target_grammar.rs` | The `::` list law: routing test, the `://`-in-list refusal, member validation | target_grammar.rs:34-36 (routing), :71-143 (list grammar, refusal at :77-83) |
| `src/commands/safety.rs` | The guard boundary: container targets exempt from the root catch-all and the dangerous-target blocklist | safety.rs:341, :389 |
| `test/ebpf/identity/container_tests.rs` | 10 pure-core pins: URI parse/reject, round-trip, `Target::parse` routing, UUID shape, log-dir names, pod-cgroup matchers, walk bounds, inode id | container_tests.rs:22-273 |
| `test/ebpf/identity/docker_tests.rs` | 10 docker pins: name/id-prefix match, match verdicts, liveness carry, sanitize choke, char-boundary safety, ambiguity, state shapes, stopped line, both driver shapes, nested-tree walk | docker_tests.rs:50-340 |
| `scripts/supermassive/supermassive-test-v3.sh` / `-v3.py` | The container E2E battery: 6 stages — help surface, privilege gate, URI grammar depth, resolution error depth, docker E2E, k8s E2E (the last two self-skip without a runtime) | v3.py:374, :439, :523, :585, :648, :801 |
| `.github/workflows/supermassive-container.yml` | The two CI legs: `docker-e2e` (native docker on the ubuntu-24.04 runner) and `k8s-e2e` (a kind cluster with `/var/log/pods` bind-mounted to the host) | yml:87-167 (docker), :170-296 (kind) |
| `docs/USAGE.md` | The operator contract: grammar, both substrates, both driver shapes, the specific errors, the snapshot semantics, the list refusal, the guard boundary | USAGE.md:539-585 |

Inputs and outputs, per resolver: the docker lane reads the Engine API
container list (id, names, State) over the daemon's unix socket and the
`/sys/fs/cgroup` tree; it produces ONE cgroup id (u32, the kernfs inode).
The k8s lane reads `/var/log/pods` directory names and the same cgroup
tree; it produces ONE pod-cgroup id. Error shapes are specific sentences
(quoted in Phase 3), never the generic process-name no-match — the input
was a well-formed reference whose infrastructure answered
(container/mod.rs:104-108). Fallback when the runtime is absent: a clean,
specific refusal (exit 1) — never a silent success, never a panic (pinned
by the battery's stage 4, v3.py:585-646).

## Phase 2 — Q1: peak native

**1. Docker: real socket read, no shell-out — PEAK.** The client is a
hand-written HTTP-over-unix-socket GET: `UnixStream::connect` (docker.rs:179),
`GET /v1.24/containers/json?all=1 HTTP/1.0` written to that socket
(docker.rs:25, :183), the reply read to a 4 MiB cap (docker.rs:26, :193-198)
with 2 s read/write deadlines (docker.rs:180-181). Zero `docker inspect`,
zero `Command`, zero shell — the only subprocess in the whole container
lane is the E2E BATTERY's own `docker run` fixture staging (v3.py:670-682),
which is the harness, not the resolver. The reply parses through the
repo's hand-written JSON lane (`crate::json`, docker.rs:236), status line
must be 200 (docker.rs:223-232), and every daemon-supplied string passes
the sanitize choke (docker.rs:207-215, night-hunt-40).

**2. Kubernetes: direct directory read, no kubectl — PEAK.** The resolver
reads `/var/log/pods` with `std::fs::read_dir` (container/mod.rs:166-172)
and parses the directory NAMES (`<namespace>_<pod>_<uid>`, mod.rs:136-146,
the UUID-shape filter at :122-129). Zero `kubectl`, zero API server, zero
kubelet-written file parsing — the only kubectl in the tree is the E2E
battery's pod staging (v3.py:886-941).

**3. Both Docker cgroup driver shapes — PEAK.** `docker_cgroup_matches`
(docker.rs:336-349) accepts systemd's `docker-<full-id>.scope` (exact
name, any slice depth — rootless included) AND cgroupfs's `<full-id>`
directory whose PARENT is named `docker`. Pinned rootlessly:
`docker_cgroup_matches_both_drivers` (docker_tests.rs:275) and
`walk_finds_docker_scope_in_nested_tree` (docker_tests.rs:328). The k8s
lane carries the same pair: `kubepods[-<qos>]-pod<uid>.slice` suffix match
and the exact `pod<uid>` (container/mod.rs:245-250, pinned at
container_tests.rs:171).

**4. The resolve-only contract — PEAK.** `resolve` returns cgroup ids and
nothing else (container/mod.rs:109-114); the limiter's `resolve_target`
Container arm is one call (resolve.rs:50-56) whose output feeds the SAME
policy write + probe + status machinery every other target rides
(policy.rs:58, atomic.rs:158). No container-specific apply path, no
container state, no daemon. The battery's E2E lanes encode exactly this
contract: rc=non-zero WITHOUT a resolver-error marker means the resolver
FOUND the cgroup and the failure is downstream enforcement — recorded as
the resolve-only contract's E2E half (v3.py:696-712, :1002-1020).

**5. The grammar parse order — PEAK, no collision.** Three rungs, in
order: (a) the `::` routing test is a plain substring test — container
URIs carry single colons only and cannot trip it
(target_grammar.rs:34-36, the rationale at :30-33); (b) the list grammar
refuses ANY `://` in a list BEFORE splitting
(target_grammar.rs:77-83); (c) `Target::parse` tries
`parse_container` FIRST (types.rs:373), so `docker://nginx` is a
Container and never reaches the `cg:`/numeric/name rungs. A container URI
is a single target only — `docker://nginx` contains no `::` byte
sequence, and a URI inside a `::` list dies at rung (b) with the fix
named. Pinned: `parse_docker_uri`, `parse_rejects_malformed_uris`,
`target_parse_routes_container_uris` (container_tests.rs:22, :42, :90).

## Phase 3 — Q2: reliable (the shapes that break naive resolvers)

Docker scenarios (all wording verbatim from the source):

| Scenario | Behavior | Error (verbatim) | Verdict |
|---|---|---|---|
| Daemon down, no socket file | Probe order `/var/run/docker.sock` → `/run/docker.sock` → `$XDG_RUNTIME_DIR/docker.sock` (docker.rs:165-171), none exists → refuse before any IO | `docker socket not found — is the docker daemon running?\n  tried: /var/run/docker.sock, /run/docker.sock, $XDG_RUNTIME_DIR/docker.sock` (docker.rs:266-269) | peak |
| Socket exists, permission denied (not in docker group) | `UnixStream::connect` fails with the OS error, surfaced with its message | `docker socket connect failed (Permission denied (os error 13))` (docker.rs:179) | peak |
| Container name does not exist | The `?all=1` list (running AND stopped) matched zero entries | `no container named '{name}' — checked running and stopped containers` (docker.rs:281) | peak |
| ID prefix matches multiple containers | `DockerMatch::Ambiguous` carries the labels; ambiguity is only reachable via a too-short id prefix (names are daemon-unique, docker.rs:97-100) | `'{name}' matches {N} containers ({labels}) — use the full 64-char id or the exact name` (docker.rs:283-289) | peak |
| Container stopped | The list's `State` verdict refuses BEFORE the cgroup walk (charger-core-2d, docker.rs:292-310); unknown state keeps the walk — never a guess (docker.rs:39-42) | `container '{name}' is not running (docker status: {status}) — the container's cgroup is torn down at exit, so there is no live workload to target\n  tip: if a policy against its dead cgroup lingers, 'zelynic recover' removes it` (docker.rs:89-95) | peak |
| Container restarted (new id, new cgroup) | The old policy's root loses both life signals (no identity entry, no ring traffic) and the hunt-43 zombie sweep collects it on the next mutation-capable visit — the sweep is cgroup-keyed, indifferent to how the root was named (zombie.rs:31-60; USAGE.md:571-578); the new container needs a re-apply (the documented snapshot semantics, USAGE.md:71, :1965) | n/a — automatic collection | peak |

Kubernetes scenarios:

| Scenario | Behavior | Error (verbatim) | Verdict |
|---|---|---|---|
| Kubelet absent / never wrote `/var/log/pods` | `read_dir` fails → refuse with the substrate named | `no /var/log/pods directory — k8s:// resolves pods through the kubelet's pod log dirs, and this host has none (not a kubelet node?)` (container/mod.rs:167-172) | peak |
| Pod does not exist in the namespace | Log-dir census parsed, zero matches for (ns, pod) | `no pod '{pod}' in namespace '{namespace}' under /var/log/pods\n  tip: ls /var/log/pods lists this node's pods as namespace_podname_uid` (mod.rs:180-184) | peak |
| Pod restarted, stale log dir remains (UID change) | Every candidate uid is probed against the cgroup tree; only the LIVE pod owns a `pod<uid>` directory, the single survivor wins, stale dirs are skipped with a verbose note (mod.rs:187-219) | success (the live uid); note: `k8s://{ns}/{pod}: {N} stale log dir(s) skipped, live uid {chosen}` (mod.rs:214-218) | peak |
| Multiple LIVE uids (tie) | Honest ambiguity, the fix named | `pod '{namespace}/{pod}' matches {N} live uids ({uids}) — target the cgroup directly: zelynic list-apps` (mod.rs:204-211) | peak |
| Pod Pending / CrashLoopBackOff | Log dir exists but no live `pod<uid>` cgroup → the live filter comes back empty | `pod '{namespace}/{pod}' has log dirs but no live pod cgroup — the pod is not running on this node` (mod.rs:199-202) | peak |
| Pod rescheduled to another node | This node's `/var/log/pods` has no dir for it → the no-pod refusal (same as row 2) | `no pod '{pod}' in namespace '{namespace}' under /var/log/pods ...` (mod.rs:180-184) | peak |
| Pod deleted (log dir persists) | Log dir present, cgroup gone → live filter empty | `pod '{namespace}/{pod}' has log dirs but no live pod cgroup — the pod is not running on this node` (mod.rs:199-202) | peak |

Cross-scenario contracts:

| Contract | Behavior | Verdict |
|---|---|---|
| Atomic `::` list with one unresolvable container | Unreachable BY GRAMMAR: a `://` in any list is refused before split (target_grammar.rs:77-83); for the process/cg lists the atomic law holds anyway — `apply_group_atomic` resolves EVERY segment before the first map write and `?` aborts the whole apply (atomic.rs:148-158, resolve.rs:89-131) | peak |
| Container URI inside a `::` list | Refused with the fix named | `container targets (docker://<name>, k8s://<namespace>/<pod>) do not ride lists — the group lane shares one bucket\n  tip: apply each container on its own: one target, no '::' separator` (target_grammar.rs:78-82) | peak |
| Stale policy after the container dies | The hunt-43 two-signal walk (no identity entry AND no ring traffic for the horizon) is keyed on the cgroup root, not the target spelling — container cgroups are collected identically to process cgroups; `zelynic recover` stays the manual override (zombie.rs:31-60; USAGE.md:571-578) | peak |

## Phase 4 — Q3: efficient

1. **Zero container-specific BPF — PROVEN.** A case-insensitive grep of
   `ebpf/src/` for container/docker/k8s/kubelet returns six hits, all
   prose comments about cgroup churn and map sizing (ebpf/src/mmspa.rs:71
   is the sizing note); zero container-specific program, hook, or map. The
   datapath is cgroup-attributed (`bpf_skb_cgroup_id`) and the container's
   traffic flows through the same hook class as everyone's.
2. **One-shot at apply time — PROVEN.** The complete caller census of
   `container::resolve`: limiter/resolve.rs:55 (strict/block/unstrict
   single), :114 (the batched group twin), commands/probe.rs:134 (the
   apply's own verification probe), commands/eagle.rs:350 (the `--depth`
   ONE-SHOT report, which exits after printing). ZERO calls in
   `src/ebpf/render/*` — the live board's per-frame resolver explicitly
   declines to resolve containers and renders the URI as an unresolved
   note instead (render/targets.rs:80-86), the honest bound documented at
   the arm. Zero resolver calls per-packet, per-poll, or per-frame.
3. **Snapshot semantics — code matches the documented contract.** A
   restart = a new cgroup id = re-apply; the document says so
   (USAGE.md:71 "resolution is a snapshot", :1965 the rules-are-a-snapshot
   law) and the code has no refresh path — `resolve` is only ever called
   by the census in item 2.
4. **Caching — no container cache exists, and none is needed.** The
   identity walk (`IdentityMap`) is /proc-only (identity/mod.rs:59-62
   declares the container family; the walk never reads the docker socket
   or `/var/log/pods`), so `status` and `list-apps` pay ZERO container
   resolution. The docker lane reads one socket GET per apply (2 s
   deadline, 4 MiB cap); the k8s lane reads one directory + one bounded
   cgroup DFS per apply (depth 10, 200 000 entries, mod.rs:44-45). The
   uncached per-invocation cost is bounded and off the hot path — peak.

## Phase 5 — Q4: LTS

**Substrate A — the Docker Engine API.** The exact contract zelynic
depends on: a unix socket at `/var/run/docker.sock` or `/run/docker.sock`
(canonical since 2013; the same file where /var/run is the symlink) or the
rootless `$XDG_RUNTIME_DIR/docker.sock` (docker.rs:27-30, :165-171); the
`GET /v1.24/containers/json?all=1` endpoint (docker.rs:25); the reply
fields `Id`, `Names`, `State` (docker.rs:242-255). **Version pinning: the
client pins the API FLOOR, `/v1.24/` — the versioning contract Docker has
honored since API 1.12/2016 (daemons keep serving old `/v1.X/` prefixes);
1.24 (Docker 1.11, 2016) is the floor the ecosystem treats as always
available.** Failure on an unparsable reply is clean at every rung:
non-200 → `docker API answered non-200: {status line}`
(docker.rs:227-232), non-JSON → `docker API reply is not JSON: {e}`
(docker.rs:236), odd `State` → `None` = "unknown, never a guess"
(docker.rs:39-42, :62-79), oversized → the 4 MiB refusal
(docker.rs:193-198). A daemon that changes the shape degrades to a
specific error, never a wrong limit. Contract churn risk in a decade: the
socket path and the versioned-list endpoint are the two most-frozen
surfaces in the Docker ecosystem — LTS-ready. Verified version range:
every green CI run of the docker-e2e leg (Docker Engine as shipped on
ubuntu-24.04 runners; latest green: run #396, 2026-11-08).

**Substrate B — the kubelet pod-log directory convention.** The exact
contract: `/var/log/pods/<namespace>_<pod>_<uid>/` directory NAMES read
with `read_dir` (mod.rs:166-178) — the resolver never opens or parses a
kubelet-written file, so the kubelet's internal file formats are outside
the dependency surface entirely (the LTS-stable shape the task names).
The UID is the kubelet's own pod-restart disambiguator, and zelynic adds
the cgroup tree as the LIVE-ness truth (`pod<uid>` exists under the pod's
slice — mod.rs:187-229), so stale dirs cannot lie. The convention has
shipped in every kubelet since 1.6 (2017) and is the substrate `kubectl
logs --previous` itself reads; it has never been removed. Verified
version range: the kind lane installs the CURRENT stable kubelet on every
run (yml:216-230) — the battery tracks upstream continuously rather than
pinning one release, and the latest green is run #396 (kind v0.24.0 +
stable kubelet, 2026-11-08). Failure mode if the convention ever moved:
the substrate-absence refusal (`no /var/log/pods directory ...`), loud and
same-day diagnosable — the honest decade failure, not a silent wrong
limit. LTS-ready.

**The boundary (design, not gap):**

- **Rootless Docker — code-supported, E2E-untested.** The socket probe
  includes `$XDG_RUNTIME_DIR/docker.sock` (docker.rs:165-171) and the
  systemd matcher accepts the rootless slice depth ("any slice depth",
  docker.rs:333-335). The battery stages the rootless grammar stages
  unprivileged but the docker E2E lane runs the root daemon only — the
  rootless resolve+enforce round trip is named, not CI-proven (Phase 8
  coverage note).
- **Podman / containerd / CRI-O / nerdctl — not runtimes zelynic
  supports.** The grammar is `docker://` and `k8s://` only (no new
  namespaces, per the task law). The honest compatibility statement: the
  resolver speaks the Docker Engine API over a unix socket, so any
  runtime exposing a Docker-API-compatible socket AT ONE OF THE THREE
  PROBED PATHS works — Podman's rootless service defaults to
  `$XDG_RUNTIME_DIR/podman/podman.sock`, which zelynic does NOT probe, so
  podman works only when the operator exposes the Docker-compatible API
  at a probed path (a symlink is the operator's one-liner). containerd and
  CRI-O speak different APIs and do not work — stated, not hidden.

## Phase 6 — the gaps

**None — peak confirmed on all four questions.** No fix commit, peak-skip
applied. Three report-only observations recorded, none rising to a gap:

1. **Battery header comment cites the wrong walker's bounds**
   (supermassive-test-v3.py:138-141): the timeout rationale says "the
   resolver caps depth at 32 and visits at 4096 — pathwalk.rs" — those are
   the IDENTITY walk's bounds (identity/pathwalk.rs:41-47, NIGHT-hunt-32);
   the container walk has its own documented bounds of depth 10 /
   200 000 entries (container/mod.rs:40-45). Cosmetic drift inside a
   do-not-touch file; both bound sets are safe; no change made.
2. **Rootless docker resolve+enforce is code-supported but not E2E-proven**
   (see Phase 5 boundary + Phase 8) — a future campaign, not a defect.
3. **The eagle-eyes spec grammar refuses container URIs via the slash
   rule** (`parse_target_spec` splits on `/`, eagle.rs:63-75, so
   `ee docker://nginx` dies as "empty target ... check the slashes").
   Container URIs are not advertised for eagle-eyes (USAGE.md teaches
   them for strict/block/unstrict only), the refusal is honest and
   non-crashing, and the render family documents the bound at the arm
   (render/targets.rs:80-86). Recorded as the observed boundary; any
   `ee docker://` support is feature work this task forbids.

## Phase 7 — the audit record

This document is the record; the `docs/README.md` audits index carries the
one-row summary. No other file changed.

## Phase 8 — the E2E battery still covers what the audit names

| Audit claim | Battery / CI evidence | Coverage |
|---|---|---|
| `docker://` and `k8s://` resolve + enforce | v3 stages 5-6 spawn a real busybox container / a real kind pause pod, resolve the URI, drive the apply (v3.py:648-800, :801-1044); CI legs force both lanes (yml:166-167, :291-293) | tested — CI run #396 green on both legs |
| The daemon-down refusal (honest, no crash) | Stage 4 drives every well-formed URI with the runtime absent and pins non-zero + no panic + no silent success (v3.py:585-646); the micro-VM lane (supermassive.yml) runs it with no runtime present | tested |
| Malformed URI grammar depth | Stage 3, all seven malformed shapes, both spellings (v3.py:523-583, fixtures :170-184) | tested |
| The resolve-only contract | The E2E verdict ladder encodes it — rc=non-zero WITHOUT a resolver-error marker records the resolver FOUND the cgroup, enforcement downstream (v3.py:696-712, :1002-1020); the privilege stage proves the gate reaches the resolver | tested |
| Stopped-container shape | NOT E2E-tested — the battery spawns only running fixtures; the logic is pinned rootlessly (`docker_match_carries_the_liveness_state`, `stopped_container_line_names_the_real_cause`, docker_tests.rs:113, :252) | named, not E2E-tested — future campaign |
| Ambiguous-UID / ambiguity shapes | NOT E2E-tested — no stale-log-dir or multi-match fixture is staged live; the verdicts are pinned rootlessly (`docker_match_verdicts`, `ambiguous_verdict_survives_a_multibyte_id`, `pod_uid_matches_filters_namespace_and_pod`, docker_tests.rs:75, :187, container_tests.rs:155) | named, not E2E-tested — future campaign |

Per the task law the battery itself was not touched; the two untested
shapes are recorded here as coverage notes, not defects — the pure cores
that own both verdicts are pinned.

## Phase 9 — the gates

Run live on the audited tree (2026-11-08): `cargo test --features ebpf
--locked` green (1035 + 72 passed, 0 failed); `./scripts/gate-keepers.sh`
26/0/0; `./scripts/build.sh check-all -q` exit 0. The container E2E
battery itself needs a docker daemon or a kind cluster — the sandbox has
neither, stated honestly; the CI lane is the proof: **Dragon Guard -
Supermassive Container E2E run #396** (head `3a1d40b9c`, 2026-11-08,
success — both `Container E2E - docker (native)` and
`Container E2E - k8s (kind)` legs green with the forced full battery),
<https://github.com/oxyzenQ/zelynic/actions/runs/42506806585>.

## Sources

Every claim's file:line is inline above. Primary: container/mod.rs,
container/docker.rs, limiter/resolve.rs, limiter/types.rs, limiter/zombie.rs,
limiter/atomic.rs, commands/target_grammar.rs, commands/safety.rs,
commands/eagle.rs, commands/monitor.rs, commands/probe.rs,
ebpf/render/targets.rs, ebpf/identity/pathwalk.rs, identity/mod.rs,
test/ebpf/identity/container_tests.rs, test/ebpf/identity/docker_tests.rs,
scripts/supermassive/supermassive-test-v3.py, supermassive-test-v3.sh,
.github/workflows/supermassive-container.yml, docs/USAGE.md.

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
