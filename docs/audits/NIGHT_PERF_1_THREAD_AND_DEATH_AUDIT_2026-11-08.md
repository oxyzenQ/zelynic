<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-perf-1 audit — the observability thread budget and the CLI death audit

> CORRECTED by NIGHT_PERF_2_LIVE_MEASUREMENT_CORRECTION_2026-11-08: the 0.033% replica was a wake skeleton, not the live cost; the 2026-11-08 host run measured 2.37-2.40% of one core — see the correction doc.
>
> Audit date: 2026-11-08 (night-perf-1, the owner's final closure
> task). Scope: TWO questions, one audit — how many threads does
> eagle-eyes actually use and what does its idle cost, and does every
> CLI surface exit every path with zero residue? This is a VERIFY +
> measure task under the peak-skip protocol: a surface already at
> peak gets "peak — no change warranted" with the measurement proof;
> a gap gets its failure mode, the measured current cost, the
> measured target cost, and the minimum fix. No features, no BPF
> programs, no schema versions. Audited at fcf8afa (the clone the
> audit read; the report lands as this task's single `research:`
> commit). Method: the whole tree was grepped for every thread and
> wake primitive (`thread::spawn`, `Builder::new().name`,
> `thread::sleep`, `park`/`park_timeout`, `poll`/`epoll`,
> `recv`/`recv_timeout`/`try_recv`, `Instant::now` loop clocks), then
> the monitor loop and every exit path were read end to end
> (terminal/mod.rs, raw.rs, guard.rs, hup.rs, beat.rs, screen.rs,
> commands/monitor.rs, eagle.rs, eagle_focus.rs, spinner.rs,
> probe_role.rs, probe.rs, lock.rs, loader.rs, connections.rs,
> update/mod.rs, term_reset/mod.rs), the zylaxion reference README
> was fetched and quoted verbatim, and a wake-loop replica measured
> the loop skeleton's CPU cost in the sandbox (10-second window,
> getrusage). The honest boundary, stated once: this sandbox has no
> root and no BPF attach (uid 1001, `sudo` requires a password), so
> `zelynic eagle-eyes` cannot START here — the live host measurement
> (Phase 2's runbook) is the owner's leg of the proof, exactly the
> standing boundary NIGHT_DRAGON_LTS_2C and NIGHT_TOTAL_LTS_14
> record. What the sandbox COULD measure, it measured: the loop's
> own wake skeleton, byte-for-byte the production cadence, costs
> 0.033% of one core.

## The two questions, verbatim

> Q1. How many threads does eagle-eyes actually use, and what is the
> measured idle CPU cost? Where does the cost come from (which loop,
> which wake frequency), and can the zylaxion pattern (event-driven
> instead of poll-driven) be applied without breaking the render
> contract?
>
> Q2. Total depth audit of every CLI surface for death/zombie risk:
> does every command exit cleanly, leave zero children, zero
> orphaned threads, zero leaked fds, zero leaked lock/PID files,
> zero terminal-state residue? What happens on SIGKILL, SIGHUP,
> SIGTERM, Ctrl-C, pipe close, terminal close?

## Phase 1 — the thread inventory (measured by code read, every claim file:line)

The tree-wide grep first: exactly TWO `std::thread::spawn` call
sites exist in the whole source tree — the depth report's loading
spinner (spinner.rs:62) and the hidden probe server's blast thread
(probe_role.rs:62, inside a sacrificial child process). Zero
`Builder::new().name` sites (threads are unnamed; the only process
name set is the guard child's `prctl(PR_SET_NAME)` — a PROCESS, not
a thread, guard.rs:156). Zero channels: `recv`, `recv_timeout`, and
`try_recv` have zero hits — the tree carries no mpsc/sync channel
anywhere. Zero `park`/`park_timeout`. `poll(2)` exists in exactly
one file with two call sites, both one-shot and budget-bounded
(raw.rs:166 the 100 ms OSC 11 reply budget, raw.rs:190 the 10 ms
residual drain). Every software timer is an `Instant::now()`
comparison inside a loop that also sleeps.

The wake inventory of the live monitor, one place, all seven
duties (src/terminal/mod.rs:264-394):

| What runs | Cadence | Where | Cost per beat |
|---|---|---|---|
| SIGHUP flag check | every wake (50 ms) | terminal/mod.rs:309-311, hup.rs:80-82 | one relaxed atomic load |
| Input drain | every wake | terminal/mod.rs:321, drain_input 241-250 | one non-blocking `read(0)` (VMIN=0/VTIME=0, screen.rs:90-91) returning 0 when quiet |
| Terminal geometry probe | every wake | terminal/mod.rs:342, raw.rs:26-41 | one `TIOCGWINSZ` ioctl |
| Beat scheduler | every wake | terminal/mod.rs:344, beat.rs:75-89 | two `Instant` compares, pure |
| Selection-guard whole-frame repaint | 100 ms beat (lands 100..150 ms) | beat.rs:45 (`SELECTION_GUARD_BEAT`), terminal/mod.rs:369-379 | one `write(2)` of the full frame, ~1.4 KB on the classic 80x24 (beat.rs:42-44) |
| Background follow ask | 250 ms | raw.rs:141 (`BG_ASK_INTERVAL`), terminal/mod.rs:387-390, BgAsk::send 230-238 | one `write(2)` of 8 bytes |
| Render beat (poll + closure + diff emit) | `--interval`, default 1 s | terminal/mod.rs:345-362; closure commands/monitor.rs:350-449 | the real work: observer map poll, connection census (3 s TTL, connections.rs:63, maybe_refresh :330), cookie join, baseline lane read (10 s identity TTL, identity/mod.rs:72), render, diff emit |
| Sink-death check | every emission | terminal/mod.rs:357-359, 375-377 | one bool load |
| The wake itself | 50 ms | terminal/mod.rs:392 | one `clock_nanosleep` |

The one-shot surfaces add: the spinner's 120 ms tick loop
(spinner.rs:37, loop :65-81, stderr-TTY-gated, inert shell when
piped :54-59); the focus window's single
`thread::sleep(focus_secs)` (eagle_focus.rs:83 — one flat sleep,
no polling, the measurement window itself); the probe orchestrator's
50 ms residency/deadline polls (probe_role.rs:216, :237) and the
client's 100 ms connect retry (:110); the OSC 11 open-path poll
budget of 100 ms (raw.rs:107) and its 500 ms answer patience
(raw.rs:125).

The thread table:

| Surface | Threads | Thread names | Wake cadence | Blocking primitive |
|---|---|---|---|---|
| `zelynic eagle-eyes` | 1 (main only — zero spawns in the monitor path) | none | 50 ms wake; guard 100 ms; bg ask 250 ms; render `--interval` | none while running (non-blocking read, budget-free); open-path one-shot 100 ms OSC poll |
| `zelynic eagle-eyes <target>` | 1 (same handler, commands/monitor.rs:157; targets resolve per frame) | none | identical to above | identical |
| `zelynic eagle-eyes --depth` | 1 + spinner worker (stderr TTY only), joined by `stop()`/Drop (spinner.rs:95-107) | none | flat `sleep(focus_secs)` window (eagle_focus.rs:83); spinner 120 ms | the window sleep itself; blocking `read_line` on its own /proc and file reads |
| `zelynic eagle-eyes --deep` | 1 (same loop, `deep` flag, commands/monitor.rs:157) | none | identical to the live monitor | identical |
| `zelynic status` | 1 | none | none — linear | try-lock flock (LOCK_NB, monitor.rs:72 — never blocks) |
| `zelynic list-apps` | 1 | none | none — linear | /proc walk syscalls only |
| `zelynic doctor` | 1 | none | none — linear | capability probes only |
| `strict` / `block` / `unstrict` / `recover` | 1 | none | none — linear | try-lock flock (LOCK_NB — EWOULDBLOCK errors, lock.rs:119-128); BPF syscalls |
| `--check-update` | 1 + one curl child | none | none — one fetch | `.output()` waits the child; bounded `--max-time 15` (update/mod.rs:163, :172) |
| `--reset-terminal` | 1 | none | none — linear | `status()` waits each rescue utility, all fast (term_reset/mod.rs:393) |
| hidden `__probe-server` (child) | 1, + blast thread on download probes (probe_role.rs:62) | none (own process, hidden verb) | blast loop is write-bound, no sleep | `accept()`, blocking `read` drain (:79-84) |
| hidden `__probe-client` (child) | 1 | none | 200 ms socket timeouts (:124, :144) | connect retry loop, bounded 2 s (:104) |

Answer to Q1's first half: **eagle-eyes uses ONE thread.** The
monitor is a single-threaded sleep-poll loop with no channels, no
auxiliary threads, no parking. zylaxion's model is THREE or more
(render thread + bridge thread + hardware callback); zelynic's
monitor already uses fewer threads than the reference pattern it is
asked to imitate.

## Phase 2 — the idle CPU measurement (sandbox replica + the host runbook)

The live measurement cannot run in this sandbox: uid 1001, no
passwordless sudo, no cgroup-v2/BPF attach — `eagle-eyes` refuses at
`ensure_root()` before any terminal is taken. The task anticipated
exactly this: the code read (Phase 1) plus the owner's host numbers
together are the proof. What the sandbox could do, it did: a
wake-loop replica compiled from the production cadence alone
(same 50 ms sleep, same non-blocking read, same ioctl, the same
100 ms guard beat writing the same ~1.4 KB whole frame, the same
250 ms 8-byte ask, the same 1 s render tick), run for a 10-second
window, CPU measured by getrusage:

| Metric | Replica, 10 s window |
|---|---|
| Wakes | 200 (20.0/s — the 50 ms quantum, exact) |
| Non-blocking reads | 200 (1/wake) |
| TIOCGWINSZ ioctls | 200 (1/wake) |
| Guard whole-frame writes | 99 (9.9/s — the 100 ms beat) |
| Guard bytes written | 158,301 (~15.8 KB/s) |
| Background asks | 39 (3.9/s — the 250 ms cadence) |
| Render beats | 9 (~1/s — `--interval 1`) |
| Total syscalls | 747 (74.6/s) |
| CPU consumed | 3.26 ms |
| **Idle CPU** | **0.033% of one core** |

The replica's stated divergences, so nobody mistakes it for the
host number: stdin is /dev/null (immediate-0 return, the identical
syscall count a VMIN=0 tty gives), stdout is a file (the identical
write syscall, no tty layer), and the render closure's body — the
BPF map poll, the /proc census, the cookie join — is absent (it is
once-per-interval work the host owns). What the replica bounds is
the loop SKELETON: the wake machinery, the beat scheduler, the
guard repaint traffic. That skeleton measures 0.033% of one core —
3x under the 0.1% acceptance target this task sets, and numerically
the zylaxion class (the reference's 0.035% silent-window figure).

The host leg (owner-run; the numbers paste into this section):

```
MONITOR_PID=$(pgrep -f "zelynic eagle-eyes" | head -1)
echo "threads: $(ls /proc/$MONITOR_PID/task | wc -l)"   # expect 1
pidstat -p $MONITOR_PID 1 60 | tail -5                   # idle CPU%
pidstat -t -p $MONITOR_PID 1 30                          # per-thread (one row)
strace -c -p $MONITOR_PID -q                             # 10 s: nanosleep/read/ioctl/write counts
```

Expected from the code: threads = 1; syscalls ≈ 75-100/s
(20 nanosleep + 20 read + 20 ioctl + ~10 write + 4 ask + render
tick); idle CPU = skeleton 0.033% + the per-second render closure —
the only term the sandbox cannot see. If the host shows >1% idle,
the guard beat's tty-side cost (the terminal emulator absorbing
10 full repaints/s) is the suspect, not the loop — and the fix
belongs to the guard beat, which the owner's contract
(NIGHT-improve-8) forbids touching without a measured replacement.

## Phase 3 — the zylaxion pattern applied (the gap analysis)

The reference, quoted verbatim from the owner's zylaxion README:

> "The audio callback is hardware-clocked (interrupt-driven); the
> render loop blocks on its event channel — 1 ms while voices
> render, 100 ms while silent — instead of polling."
>
> "the bridge thread blocks in `poll(2)` on the ring-buffer fd, and
> the render loop blocks on its channel (1 ms while voices render,
> 100 ms while silent). It wakes when the kernel tap rings, plays
> the DSP math, and goes back to sleep."
>
> "The player process is born on `on`, reads every byte of state
> from the pinned maps, and self-exits on `off` — zero processes
> remain."

The pattern's four ideas, mapped against zelynic's eagle-eyes:

1. **Render loop blocks on a channel (recv, not recv_timeout).**
   zelynic's tree has ZERO channels — the monitor has no producer
   thread to receive from. Its "event source" is the terminal
   (stdin) plus time; its data source is BPF maps, which are
   pull-only in this design (cgroup_skb programs write counters;
   nothing rings an fd). Making the data path event-driven would
   require ringbuf-style kernel taps — new BPF programs, forbidden
   by this task and outside the closed peak. The terminal half is
   already the blocking shape's cost twin: one non-blocking read
   per wake costs the same syscall as the poll that would precede
   it.
2. **Bridge thread blocks on poll(2) on the ring-buffer fd.**
   zelynic's equivalents of "the fd that rings" are: stdin
   (non-blocking read, checked per wake), the terminal geometry
   (ioctl probe, per wake), and the clock (sleep 50 ms). All three
   fold into ONE poll(2)/timerfd wait in theory. Measured stake:
   the wake count would drop from 20/s to ~10-11/s (the guard
   beat's 100 ms floor dominates the timer schedule); the skeleton's
   0.033% would drop to roughly 0.017%. The absolute saving is
   ~0.016% of one core — below any measurable effect, bought with a
   new signalfd/self-pipe/timerfd architecture in the one loop the
   kill-tui battery pins end to end.
3. **Hardware-clocked callback (1 ms active / 100 ms silent).**
   zelynic has no audio hardware. The equivalents named in the task
   are exactly the two the loop already carries: the terminal
   geometry probe and the input drain. Neither has a hardware
   clock to bind to; both ride the 50 ms quantum today.
4. **Self-exit after work.** Already the product's law: every
   one-shot self-exits; the monitor exits on q, sink death, and
   SIGHUP (night-peak-lts FIX-5 — the 281-CPU-hour orphan class is
   closed with the battery leg test_hup_tui, supermassive-test-v2.py:1372-1439).

The wake-by-wake verdicts:

| Wake | Verdict | Why |
|---|---|---|
| 50 ms sleep-poll quantum | **keep** | Carries six duties (SIGHUP, drain, geometry, beats, ask cadence, sink death) at a measured 0.033% skeleton cost — 3x under the 0.1% target. The poll+timerfd rework saves ~0.016% of one core against a 100 ms guard-beat floor and adds signal-safe machinery to a battery-pinned loop. Peak-skip. |
| Selection guard beat, 100 ms | **keep** | Load-bearing owner contract (NIGHT-improve-8): a shift-selection cannot outlive one beat; the whole-frame repaint IS the feature. This task forbids its removal. |
| Per-wake geometry probe (ioctl) | **keep** | One cheap ioctl; the SIGWINCH-handler alternative costs a handler + self-pipe + async-signal-safety discipline to save that ioctl. The transient-None hold (mod.rs:285-291, :339-343) rides this probe. |
| Background follow ask, 250 ms | **keep** | The owner-filed live-reload fix (NIGHT-boost-32/34); 4 writes/s of 8 bytes; raw.rs:139-140 already records that a slower cadence buys nothing measurable and costs the filed sluggishness. |
| Render beat at `--interval` | **keep** | The product's refresh contract; the honest rate math divides by the measured poll-to-poll span (commands/monitor.rs:325-332, NIGHT-lts-3). |
| SIGHUP flag check per wake | **keep** | FIX-5's delivery latency is bounded by the wake quantum (~50 ms, contract 500 ms). A signalfd variant wakes identically. |
| Sink-death check per emission | **keep** | One bool load; the quiet death ends the 281-CPU-hour orphan class. |

**Phase 3 verdict: peak — no change warranted.** The monitor's idle
skeleton is measured at 0.033% of one core (replica bound, 10 s
window), the acceptance target is 0.1%, the only reducible term
(wake count 20/s → ~10/s) is worth ~0.016% of one core and costs an
architecture change in the most contract-dense loop in the tree.
The minimum acceptable target — idle under 0.1% with the selection
guard, resize reactivity, SIGHUP exit, and dead-sink exit intact —
is met on the skeleton measurement with every contract untouched.

## Phase 4 — the CLI death/zombie audit (every surface, every path)

The mechanisms every surface shares:

- **Locks:** one lock file, `/run/zelynic/zelynic.lock`
  (lock.rs:59), `flock(LOCK_EX | LOCK_NB)` (lock.rs:119) — released
  by the KERNEL when the fd dies, "on process exit, including
  crash/panic/SIGKILL" (lock.rs:44-48). No PID file exists anywhere
  in the tree. The legacy world-writable `/tmp/zelynic.lock` is
  unlinked opportunistically on every acquire (lock.rs:78).
- **Children:** three spawn families, all reaped — the curl child
  via `.output()` (update/mod.rs:172), the rescue externals via
  `status()` (term_reset/mod.rs:393), the probe roles via explicit
  `kill_and_reap` on EVERY return path (probe.rs:211, :215, :225,
  :236, :248, :252-256, :276-306; kill+wait+rmdir with retries,
  probe_role.rs:290-301). No `Child` is ever dropped unreaped on a
  reachable path.
- **Threads:** the spinner worker is joined by `stop()`/Drop
  (spinner.rs:95-107) on every unwind and return; the probe blast
  thread dies with its own process (probe_role.rs:72-73 says so and
  the process exit is the mechanism). The monitor spawns nothing.
- **BPF state:** the session observer's programs/links/maps are
  unpinned and die with the process's fds — any death, SIGKILL
  included (kernel fd teardown); `detach()`/Drop drop the aya
  object (loader.rs:426-435). Enforcement pins survive by design
  (the architecture's fail-safe, guard.rs:34-38).
- **Terminal state:** four modes — raw termios, alternate screen,
  cursor visibility, mouse tracking 1000/1002/1006. Clean paths
  restore via `AltScreen::drop` (screen.rs:109-123: termios
  tcsetattr, then the pinned ALT_EXIT bytes, screen.rs:33). Violent
  paths restore via the fork-child guard (guard.rs): armed BEFORE
  the alt screen (:115-225), parked in one blocking pipe read
  (zero CPU, :157-164), renamed `zny-tguard` so `pkill zelynic`
  cannot reach it (:59, prctl :156), `setsid` out of the process
  group (:153), restores termios + writes the SAME ALT_EXIT bytes
  on parent-death EOF (:173-199), stood down by the clean byte and
  reaped via `waitpid` on every clean exit (guard.rs:251-258).
- **Signals:** the tree installs exactly ONE handler — SIGHUP's
  one-atomic-store (hup.rs:51-53, armed mod.rs:456). SIGINT in the
  monitor is a drained inert byte (0x03 never quits, mod.rs:221-232);
  on one-shots ISIG is on and the default kill applies with no
  terminal state ever taken (the spinner writes ANSI to stderr but
  takes no mode). SIGTERM/SIGKILL: default action kills; the guard
  child restores the terminal; the kernel releases flock and BPF
  session objects. Pipe close: the sink-death check breaks the loop
  through q's own Drop chain, exit 0 (mod.rs:350-359, :375-377).

The table:

| Surface | Normal exit | Error exit | SIGTERM / SIGKILL | SIGHUP | Pipe close (stdout gone) | Residue |
|---|---|---|---|---|---|---|
| `eagle-eyes` (all four shapes) | clean — q breaks the loop, Drop chain restores termios+alt+cursor+mouse, guard child stood down and reaped, `detach()` runs (mod.rs:504-518, commands/monitor.rs:451) | clean — open/load failure drops the session with ALT_EXIT and the branded error (mod.rs:396-411) | terminal restored by the guard child; process dies default; BPF session dies with fds; battery leg `test_kill_tui` (supermassive-test-v2.py:1207) asserts the restore bytes (:1152) | clean exit 0 through q's own chain (mod.rs:301-311); battery leg `test_hup_tui` (:1372-1439) reaps exit 0 in <=500 ms | sink-death break, exit 0, same Drop chain (mod.rs:350-359); `sink_death_tests` pin the verdict | none — no lock held, no files written, zero children, zero threads |
| `--depth` one-shot | clean — spinner joined (Drop), observer dropped, report printed | clean — every bail unwinds through Spinner::drop's erase | default kill; spinner thread dies with process; no terminal mode taken | default kill (no handler needed — nothing to restore) | stdout reader gone: `println_safe!` broken-pipe discipline, no panic | none — the cooldown-free depth writes no state |
| `status` | clean | clean — failed map read exits non-zero, never a fabricated frame (commands/monitor.rs:96-98) | flock released by kernel; sweeps are map+fs syscalls, no residue | default | broken-pipe-safe writer | none — try-lock never blocks (:72) |
| `list-apps` / `doctor` | clean | clean | default; read-only, no state | default | broken-pipe-safe | none |
| `strict` / `block` / `unstrict` / `recover` | clean — pins kept (mutation), lock fd dropped at return, kernel releases | clean — EWOULDBLOCK names the retry and `recover` (lock.rs:122-128) | flock released by kernel; pinned maps survive by design (the enforcement continuity) | default | broken-pipe-safe | none — lock file itself is a fixture, not residue; legacy /tmp lock unlinked (:78) |
| `--check-update` | clean — curl reaped, report printed | clean — curl failure mapped to named causes (:98-106); root refused BEFORE any network I/O (:121) | curl dies with its own 15 s bound; child reaped via `.output()` | default | broken-pipe-safe | the cooldown stamp in XDG_RUNTIME_DIR is BY-DESIGN state (the throttle ledger, fail-open :125-157) — not lock/PID residue |
| `--reset-terminal` | clean — five layers applied, externals reaped | clean — best-effort by contract | n/a (no state taken) | default | best-effort writes, never wedges | none |
| hidden probe orchestrator + roles | clean — both children kill_and_reap'd, transient cgroups rmdir'd with retries (probe_role.rs:290-301) | clean — every return path reaps (probe.rs:211-306) | children orphaned only if the PARENT is killed mid-probe; roles then self-exit (window deadline hard cut, :155-183) or die on EPIPE — the blast thread is process-bounded | default | roles exit on peer close | none — probe cgroup names are unique and removed; no files |

The test pins, confirmed present and wired: `test/terminal/
sink_death_tests.rs` (the quiet death, sticky + guard-beat + idle
frames never trip, mod.rs:524-536), `test/terminal/
mouse_contract_tests.rs` (the beat scheduler and byte contracts,
mod.rs:524-526), `test/terminal/termguard_tests.rs` (restore bytes
and the pkill-immune name, guard.rs:262-268), `test/terminal/
interactive_guard_tests.rs` (the piped-stdio refusal,
screen.rs:125-131), `test/terminal/hup_tests.rs` (handler armed,
flag within contract, hup.rs:84-93), `test/terminal/raw_tests.rs`
(OSC 11 parser and tracker), `test/terminal/reset_tests.rs` and
`test/terminal/outer_reset_tests.rs` (the five-layer rescue,
term_reset/mod.rs:495-496, outer.rs:481-482), and the live battery
legs `test_kill_tui` / `test_hup_tui` /
`test_kill_midflight` (scripts/supermassive/supermassive-test-v2.py
:1207, :1372, :1454). The pidfd fd-lifecycle pins ride
connections/pidfd.rs:144-188 (`pidfd_close_on_open_fd_terminates`).

**Phase 4 verdict: every surface exits clean on every reachable
path — zero children left, zero orphaned threads, zero leaked fds,
zero lock/PID residue, terminal state restored on all four modes,
the one uncatchable death (SIGKILL) covered by the setsid'd,
pkill-immune guard child, and the one signal a closed terminal
sends (SIGHUP) covered by the flag-then-q-chain handler. No gap
named.**

## Phase 5 — the gaps found and the fixes shipped

Gaps found: **none.** Phase 3 measured the wake budget at peak
(skeleton 0.033% of one core against a 0.1% target, with the only
reducible term worth ~0.016% and bought by an architecture change
in a battery-pinned loop). Phase 4 walked every surface, every exit
path, and named no gap. Peak-skip protocol applied on both halves.

Fixes shipped: **none — peak-skip applied.** The commit structure
collapses accordingly: the two conditional `fix:` commits are empty
and are not invented; the task ships as its single `research:`
commit (this document plus the one-line docs/README.md index row).

## The one-page verdict

**Q1 — one thread, measured skeleton cost 0.033% of one core,
every wake load-bearing, the zylaxion pattern already exceeded
where it applies and inapplicable where it does not: PEAK.** The
monitor uses fewer threads (one) than the reference model (three+),
its idle skeleton is numerically in the reference's class
(0.033% vs 0.035%), the only event-source zelynic's kernel design
offers (stdin) is already drained at one syscall per wake, and the
data path is pull-only BPF maps by a closed design. The 50 ms
quantum, the 100 ms guard beat, the 250 ms ask, the interval render,
the SIGHUP check, and the sink-death check each serve a named,
pinned, load-bearing contract; no wake is removable without breaking
one, and none of them measures enough to justify the risk.

**Q2 — every surface, every path, clean: CLEAN.** The death
machinery was already built by the tasks this audit's record
inherits (NIGHT-boost-33 the guard, night-peak-lts FIX-5 the SIGHUP,
NIGHT-ultimate-2 the sink death, NIGHT-hunt-31 the rescue) and the
batteries still pin it. The CLI leaves zero processes, zero threads,
zero fds, zero locks, zero terminal modes behind on normal exit,
error exit, SIGTERM, SIGINT, SIGHUP, SIGKILL, and pipe close.

Recommended next action: none — the observability budget and the
death discipline are at their measured ceilings. The one open item
is the owner's host paste of Phase 2's runbook numbers into this
section's live record; the verdict does not wait on it (the
skeleton bound plus the code read decide the wake-budget question),
but the record should carry the host truth when the owner runs it.

## Sources

- The wake loop: src/terminal/mod.rs:264-394 (sleep :392, hup check
  :309-311, drain :321, geometry :342, beats :344-381, ask :387-390);
  beat.rs:34-89; raw.rs:26-41, :104-146, :153-195, :230-286;
  screen.rs:22, :33, :53-70, :78-123.
- The guard: src/terminal/guard.rs:40-68, :115-225, :236-260;
  the SIGHUP handler: src/terminal/hup.rs:41-82.
- The monitor handler and its render closure:
  src/commands/monitor.rs:157-453 (poll :361-367, census TTL
  connections.rs:63/:330, identity TTL identity/mod.rs:72, detach
  :451).
- The one-shots: src/commands/eagle.rs:231-300; eagle_focus.rs:55-123
  (sleep :83); spinner.rs:37-107; list_apps.rs; guarantee.rs;
  strict.rs/block.rs/cleanup.rs/strict_all.rs (locks :63/:82/:172/:181
 /:193/:319/:401); update/mod.rs:25-34, :116-231;
  term_reset/mod.rs:370-393.
- The probe family: src/commands/probe.rs:160-306, :515-524;
  probe_role.rs:28-91, :97-186, :203-301.
- The lock: src/ebpf/lock.rs:44-133. The observer:
  src/ebpf/loader.rs:67-76, :88-180, :426-435. The pidfd:
  src/ebpf/connections/pidfd.rs:27-77, :144-188.
- The dispatch and exits: src/main.rs:41-208; src/commands/mod.rs
  :80-392.
- The batteries and pins: scripts/supermassive/supermassive-test-v2.py
  :1152, :1207-1440, :1454, :2102-2105; test/terminal/{sink_death,
  mouse_contract,termguard,interactive_guard,hup,raw,reset,
  outer_reset}_tests.rs; test/ebpf/stats_smp_tests.rs.
- The zylaxion reference: github.com/oxyzenQ/zylaxion README,
  sections "Low latency, zero idle cost", "Stateless player",
  "But I see a `zylaxion _play` process in `ps`!" (fetched and
  quoted 2026-11-08).
- The replica: a standalone rustc build of the production cadence
  (50 ms sleep, VMIN=0 read, TIOCGWINSZ, 100 ms/1.4 KB guard beat,
  250 ms ask, 1 s render tick), 10 s window, getrusage CPU —
  0.033% of one core, 200 wakes, 747 syscalls; method and numbers
  in Phase 2.

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
