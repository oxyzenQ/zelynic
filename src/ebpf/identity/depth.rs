// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Per-pid deep facts for `eagle-eyes --depth` (NIGHT-master-1).
//!
//! The identity walk answers "which cgroup is this and what is it
//! called" (comm + uid, majority vote). The owner's depth question is
//! bigger: WHO is this cgroup — which user launched it, from which
//! binary, is that binary a script or an ELF, what are its
//! permissions, where does it run from, how long has it been alive.
//! This module extends the identity family with that per-pid layer:
//! one /proc walk per target cgroup collecting [`ProcessFacts`] for
//! every live member plus the cgroup's own v2 path (whose basename is
//! the package-name fallback when no comm resolved — the owner's
//! "unknown/cat-test" ladder).
//!
//! Every read is best-effort: a process that exits mid-walk yields
//! partial facts (readable fields render, the rest stay None/zero,
//! never an error), matching the identity and connection walks'
//! degradation contract. Every string that flows to a display surface
//! is sanitized at the boundary (NIGHT-cybersecurity-1: argv is
//! attacker-controlled exactly the way comm is, and /proc readlink
//! results can carry control bytes in hostile filenames).
//!
//! NIGHT-blade-7 (the sharpness audit) tightened three boundaries
//! here: the perm column now carries the special bits (a setuid-root
//! binary renders "4755", not the anonymous "755" the 0o777 mask
//! left); the exe readlink's " (deleted)" suffix is CAPTURED instead
//! of stripped (a running binary whose on-disk file was replaced or
//! removed is a first-class triage fact, not noise); and the argv
//! shebang probe opens with O_NONBLOCK — a root-invoked report must
//! never block on an attacker-controlled path (a FIFO planted in the
//! target's cwd used to hang the whole one-shot walk).
//!
//! Time math (std-only, the build-stamp discipline): process start is
//! /proc/<pid>/stat field 22 (clock ticks since boot) converted with
//! the host's CLK_TCK; the elapsed age subtracts it from
//! /proc/uptime; the wall-clock start anchors it to /proc/stat's
//! btime. No time crate.

use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

use super::{pid_cgroup_id, pid_comm};
use crate::output::sanitize_comm;

/// One live process's deep facts. Unreadable fields are None, never
/// fabricated values.
#[derive(Debug, Clone, Default)]
pub struct ProcessFacts {
    pub pid: u32,
    pub comm: String,
    pub uid: u32,
    /// The uid's account name from /etc/passwd (None unreadable).
    pub user: Option<String>,
    pub ppid: u32,
    /// Process state as /proc/<pid>/status words it ("S (sleeping)").
    pub state: String,
    pub threads: usize,
    pub rss_kb: u64,
    /// Executable path from /proc/<pid>/exe (clean of the kernel's
    /// " (deleted)" suffix — the suffix itself rides `exe_deleted`).
    pub exe: Option<String>,
    /// NIGHT-blade-7: the kernel appended " (deleted)" to the exe
    /// readlink — the on-disk binary was replaced or removed after
    /// the process started (an upgrade mid-run, or a self-deleting
    /// loader). Stripped from `exe`, surfaced here.
    pub exe_deleted: bool,
    /// "binary" (ELF) or "script" (shebang probe) — None unreadable.
    pub kind: Option<&'static str>,
    /// The script source when kind is "script" via an interpreter.
    pub script: Option<String>,
    /// Executable permission bits as octal ("755") — None unreadable.
    pub mode: Option<String>,
    /// Working directory from /proc/<pid>/cwd.
    pub cwd: Option<String>,
    /// argv joined with spaces (kernel threads: None).
    pub cmdline: Option<String>,
    /// Seconds since the process started (None when inputs unread).
    pub started_ago_secs: Option<u64>,
    /// Wall-clock start, epoch seconds (None when inputs unread).
    pub started_epoch: Option<u64>,
}

/// Everything one /proc walk learned about a target cgroup.
#[derive(Debug, Clone, Default)]
pub struct CgroupDepth {
    /// The cgroup's v2 path relative to the mount ("/cat-test"), from
    /// the first member whose /proc/<pid>/cgroup line parsed.
    pub rel_path: Option<String>,
    /// The cgroup controller's own resource facts (NIGHT-blade-5):
    /// the two counters the v2 filesystem owns that no /proc walk
    /// can give — resident memory and accumulated CPU time. Read
    /// from the cgroup's own directory, best-effort (None when the
    /// controller file is absent or unreadable — a cgroupv1-only
    /// host, or a path the walker could not resolve).
    pub resources: CgroupResources,
    /// Deep facts for every live member, ascending pid.
    pub procs: Vec<ProcessFacts>,
}

/// The cgroup v2 controller's own view of one cgroup (NIGHT-blade-5,
/// the depth upgrade's resource layer). The per-process census
/// answers "who runs here"; these two answer "what it costs the
/// machine" — the controller's aggregated truth, not a sum the
/// walker re-derives from members (a cgroup's memory.current
/// includes page-cache and kernel-side charges no /proc read can
/// reconstruct, and cpu.stat's usage_usec is the scheduler's own
/// accounting across every task that ever ran in the cgroup,
/// including the ones that already exited).
#[derive(Debug, Clone, Default)]
pub struct CgroupResources {
    /// Resident memory in bytes from the controller's `memory.current`
    /// (None when the file is absent or unreadable).
    pub memory_current_bytes: Option<u64>,
    /// Accumulated CPU time in microseconds from the controller's
    /// `cpu.stat` `usage_usec` line (None unreadable).
    pub cpu_usage_usec: Option<u64>,
}

/// Walk /proc once and collect deep facts for every process living in
/// `cgroup_id`, plus the cgroup's own v2 path. Membership routes
/// through the ONE canonical pid-to-cgroup boundary
/// (NIGHT-optimized-1) — the same resolver the identity, connection,
/// and target-match walks use, so boundary fixes land here too.
pub fn deep_collect(cgroup_id: u32) -> CgroupDepth {
    let mut out = CgroupDepth::default();
    let hz = clock_ticks();
    let uptime = uptime_secs();
    let btime = boot_epoch();

    let Ok(entries) = fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if pid_cgroup_id(pid) != Some(cgroup_id) {
            continue;
        }
        if out.rel_path.is_none() {
            out.rel_path = pid_cgroup_rel_path(pid);
        }
        out.procs.push(process_facts(pid, hz, uptime, btime));
    }
    // The controller's own resource view (NIGHT-blade-5) needs only
    // the resolved path — a cgroup with live members but an
    // unresolvable path still reports the census, just without the
    // controller layer (best-effort, the family contract).
    out.resources = cgroup_resources(out.rel_path.as_deref());
    out
}

/// Read the cgroup controller's own resource facts for one resolved
/// v2 path (NIGHT-blade-5). Pure plumbing over two best-effort file
/// reads; the parsers are pure and pinned separately.
pub fn cgroup_resources(rel_path: Option<&str>) -> CgroupResources {
    let Some(rel) = rel_path else {
        return CgroupResources::default();
    };
    let dir = format!("/sys/fs/cgroup{rel}");
    CgroupResources {
        memory_current_bytes: fs::read_to_string(format!("{dir}/memory.current"))
            .ok()
            .and_then(|c| parse_memory_current(&c)),
        cpu_usage_usec: fs::read_to_string(format!("{dir}/cpu.stat"))
            .ok()
            .and_then(|c| parse_cpu_usage_usec(&c)),
    }
}

/// The controller's `memory.current` payload: one number, optional
/// newline (pure).
pub fn parse_memory_current(content: &str) -> Option<u64> {
    content.trim().parse().ok()
}

/// The controller's `cpu.stat` payload: the `usage_usec <n>` line
/// wins (pure). The file's exact shape is `usage_usec N` possibly
/// followed by `user_usec`/`system_usec`/`nr_periods`/`nr_throttled`
/// lines depending on kernel config — a `usage_usec` prefix match is
/// the one stable contract across them all.
pub fn parse_cpu_usage_usec(content: &str) -> Option<u64> {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("usage_usec ") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Resolve a user id to its account name from /etc/passwd content
/// (pure — the io wrapper below feeds it, the pins drive it).
pub fn user_name_from(passwd: &str, uid: u32) -> Option<String> {
    for line in passwd.lines() {
        let mut fields = line.split(':');
        if let (Some(name), Some(id)) = (fields.next(), fields.nth(2)) {
            if id.parse::<u32>() == Ok(uid) {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// The display permission string for a st_mode value (pure,
/// NIGHT-blade-7): three octal digits for the plain rwx bits, FOUR
/// when any special bit is set — setuid 4755, setgid 2751, sticky
/// 1755 — the same convention `stat`/`ls` use, because the special
/// bits are exactly what a triage eye scans for and the old 0o777
/// mask rendered a setuid-root binary as an anonymous "755".
#[must_use]
pub fn perm_string(mode: u32) -> String {
    if mode & 0o7000 != 0 {
        format!("{:o}", mode & 0o7777)
    } else {
        format!("{:o}", mode & 0o777)
    }
}

/// Split a sanitized readlink result from its possible
/// " (deleted)" suffix (pure, NIGHT-blade-7): the kernel appends the
/// marker when the linked file was replaced or removed after the
/// process started, so the marker is a FACT to carry, not formatting
/// to discard. A path legitimately ending in " (deleted)"
/// indistinguishably reports true — the same ambiguity stat(2) carries.
#[must_use]
pub fn split_deleted_suffix(link: &str) -> (String, bool) {
    match link.strip_suffix(" (deleted)") {
        Some(clean) => (clean.to_string(), true),
        None => (link.to_string(), false),
    }
}

/// The ELF magic test (pure slice predicate over a read magic head).
fn is_elf(magic: &[u8]) -> bool {
    magic.starts_with(&[0x7f, b'E', b'L', b'F'])
}

/// The shebang test — a script source starts with `#!`.
fn is_shebang(magic: &[u8]) -> bool {
    magic.starts_with(b"#!")
}

/// Seconds since boot (pure): clock ticks divided by the tick rate,
/// clamped at zero so a process that started inside the uptime read's
/// skew never reports a negative age.
fn elapsed_secs(starttime_ticks: u64, uptime_secs: f64, hz: f64) -> Option<u64> {
    if hz <= 0.0 {
        return None;
    }
    Some((uptime_secs - starttime_ticks as f64 / hz).max(0.0) as u64)
}

/// Wall-clock start in epoch seconds (pure): boot time plus the
/// tick-converted process start.
fn started_epoch(btime_secs: u64, starttime_ticks: u64, hz: f64) -> Option<u64> {
    if hz <= 0.0 {
        return None;
    }
    Some(btime_secs + (starttime_ticks as f64 / hz) as u64)
}

/// (ppid, starttime) from a /proc/<pid>/stat line (pure). The comm
/// field may contain spaces and parens, so fields are counted AFTER
/// the LAST closing paren: state is index 0, ppid index 1, starttime
/// (field 22) index 19 there.
fn parse_proc_stat(stat: &str) -> Option<(u32, u64)> {
    let rest = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let ppid = fields.get(1)?.parse().ok()?;
    let starttime = fields.get(19)?.parse().ok()?;
    Some((ppid, starttime))
}

/// argv from a raw /proc/<pid>/cmdline buffer (NUL-separated), each
/// element sanitized — argv is attacker-controlled the way comm is
/// (NIGHT-cybersecurity-1) and flows to the depth report's table.
pub fn cmdline_argv(raw: &[u8]) -> Vec<String> {
    raw.split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| sanitize_comm(&String::from_utf8_lossy(s)))
        .collect()
}

/// The display string for argv: elements joined with spaces, None for
/// the empty argv of kernel threads and zombies.
pub fn cmdline_string(argv: &[String]) -> Option<String> {
    if argv.is_empty() {
        None
    } else {
        Some(argv.join(" "))
    }
}

/// Classify what a process executes (NIGHT-master-1, the owner's
/// "binary/scripts" field). /proc/<pid>/exe is always the ELF the
/// kernel last exec'd — for a shebang script that is the INTERPRETER,
/// so the script truth needs one more step: probe the first two argv
/// arguments after argv[0] for a readable file that itself starts
/// with `#!` (relative arguments resolve against the process's own
/// cwd). A hit classifies "script" and carries the source path; no
/// hit stays the honest "binary" of the ELF exe.
pub fn classify_exe(
    exe: Option<&str>,
    cwd: Option<&str>,
    argv: &[String],
) -> (Option<&'static str>, Option<String>) {
    let Some(exe) = exe else {
        return (None, None);
    };
    match read_magic(exe) {
        Some(magic) if is_elf(&magic) => {
            for arg in argv.iter().skip(1).take(2) {
                let candidate = if arg.starts_with('/') {
                    Some(arg.clone())
                } else {
                    cwd.map(|c| format!("{c}/{arg}"))
                };
                if let Some(path) = candidate {
                    if let Some(head) = read_magic(&path) {
                        if is_shebang(&head) {
                            return (Some("script"), Some(path));
                        }
                    }
                }
            }
            (Some("binary"), None)
        }
        Some(magic) if is_shebang(&magic) => (Some("script"), Some(exe.to_string())),
        _ => (None, None),
    }
}

/// A path's first bytes (at most 4) — the magic head for the ELF and
/// shebang predicates. Best-effort: unreadable yields None.
/// NIGHT-blade-7: the probe opens with O_NONBLOCK. The argv shebang
/// classification feeds this function paths derived from
/// ATTACKER-CONTROLLED argv while zelynic runs as root — a planted
/// FIFO made the plain open block forever (open blocks until a
/// writer appears), hanging the one-shot report. Nonblocking turns
/// that into an immediate EAGAIN read miss: the FIFO is skipped, the
/// walk never stalls. Regular files ignore O_NONBLOCK entirely, so
/// the ELF/shebang probes are unchanged.
fn read_magic(path: &str) -> Option<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let mut head = [0u8; 4];
    let n = file.read(&mut head).ok()?;
    Some(head[..n].to_vec())
}

/// A sanitized readlink result with its " (deleted)" suffix split
/// off (control bytes in hostile filenames never reach the report
/// lines; the deletion marker rides the boolean, NIGHT-blade-7).
fn read_link_split_deleted(path: &str) -> Option<(String, bool)> {
    let linked = fs::read_link(path).ok()?;
    let text = sanitize_comm(&linked.to_string_lossy());
    Some(split_deleted_suffix(&text))
}

/// The host clock-tick rate (CLK_TCK). The sysconf fallback of 100
/// matches every mainstream Linux build; the None path in the pure
/// helpers keeps a refused sysconf honest rather than wrong.
fn clock_ticks() -> f64 {
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks > 0 {
        ticks as f64
    } else {
        100.0
    }
}

/// Seconds since boot from /proc/uptime's first field.
fn uptime_secs() -> Option<f64> {
    let content = fs::read_to_string("/proc/uptime").ok()?;
    content.split_whitespace().next()?.parse::<f64>().ok()
}

/// Boot time in epoch seconds from /proc/stat's btime line.
fn boot_epoch() -> Option<u64> {
    let content = fs::read_to_string("/proc/stat").ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// The cgroup v2 path of a pid ("/cat-test"), mirroring the parsing
/// pid_cgroup_id owns — called only for pids already proven to be
/// members, so the double read stays on the rare path.
fn pid_cgroup_rel_path(pid: u32) -> Option<String> {
    let content = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let path = content.lines().next()?.split("::").nth(1)?.trim();
    if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    }
}

/// The /proc/<pid>/status facts the depth report shows (uid, state
/// words, thread count, resident memory), one parse over one read.
fn parse_status(content: &str) -> (Option<u32>, Option<String>, Option<usize>, Option<u64>) {
    let mut uid = None;
    let mut state = None;
    let mut threads = None;
    let mut rss_kb = None;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        } else if let Some(rest) = line.strip_prefix("State:") {
            state = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Threads:") {
            threads = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("VmRSS:") {
            rss_kb = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        }
    }
    (uid, state, threads, rss_kb)
}

/// Collect one member process's facts. Field reads are independent
/// and best-effort — a process exiting between reads keeps whatever
/// was still readable, the same tolerance the connection walk gives
/// its fd scan.
fn process_facts(pid: u32, hz: f64, uptime: Option<f64>, btime: Option<u64>) -> ProcessFacts {
    let mut facts = ProcessFacts {
        pid,
        comm: pid_comm(pid).unwrap_or_default(),
        ..ProcessFacts::default()
    };

    if let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) {
        let (uid, state, threads, rss_kb) = parse_status(&status);
        facts.uid = uid.unwrap_or(0);
        facts.user = user_name(facts.uid);
        facts.state = state.unwrap_or_default();
        facts.threads = threads.unwrap_or(0);
        facts.rss_kb = rss_kb.unwrap_or(0);
    }

    if let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) {
        if let Some((ppid, starttime)) = parse_proc_stat(&stat) {
            facts.ppid = ppid;
            if let Some(up) = uptime {
                facts.started_ago_secs = elapsed_secs(starttime, up, hz);
            }
            if let Some(boot) = btime {
                facts.started_epoch = started_epoch(boot, starttime, hz);
            }
        }
    }

    let exe_link = format!("/proc/{pid}/exe");
    if let Ok(meta) = fs::metadata(&exe_link) {
        // NIGHT-blade-7: the special bits ride along (setuid 4755,
        // setgid 2751, sticky 1755) — a privilege-elevation binary
        // must not hide behind the plain 0o777 mask.
        facts.mode = Some(perm_string(meta.mode()));
    }
    let (exe, exe_deleted) =
        read_link_split_deleted(&exe_link).map_or((None, false), |(p, d)| (Some(p), d));
    facts.exe = exe;
    facts.exe_deleted = exe_deleted;
    // cwd's deletion marker carries no triage weight (a deleted cwd
    // is common under /tmp launchers) — the path alone rides the facts.
    facts.cwd = read_link_split_deleted(&format!("/proc/{pid}/cwd")).map(|(p, _)| p);

    if let Ok(raw) = fs::read(format!("/proc/{pid}/cmdline")) {
        let argv = cmdline_argv(&raw);
        facts.cmdline = cmdline_string(&argv);
        let (kind, script) = classify_exe(facts.exe.as_deref(), facts.cwd.as_deref(), &argv);
        facts.kind = kind;
        facts.script = script;
    }

    facts
}

/// The account name for a uid on THIS host (the io wrapper over
/// [`user_name_from`]).
pub fn user_name(uid: u32) -> Option<String> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    user_name_from(&passwd, uid)
}

// The depth pins live under the single test/ tree (cosmostrix Pattern
// C), #[path]-wired exactly like the identity pins.
#[cfg(test)]
#[path = "../../../test/ebpf/identity/depth_tests.rs"]
mod tests;
