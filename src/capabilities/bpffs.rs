// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The bpffs + cgroup mount detection lane (the NIGHT-improve-44
//! LOC-cap split: the doctor's statfs core moved here from mod.rs —
//! the mount facts belong beside the syscalls that read them).
//!
//! Two facts the capability report rides:
//! - is `/sys/fs/bpf` an actually-mounted bpf filesystem (statfs
//!   magic, never bare path existence — NIGHT-hunt-28)?
//! - where is cgroup v2 mounted (/proc/mounts scan)?

use std::ffi::CString;

/// `linux/magic.h` `BPF_FS_MAGIC` — the statfs type of a mounted bpf
/// filesystem. Stored as i64, the common denominator of the two libc
/// `f_type` flavors: glibc types the field `__fsword_t` (signed long)
/// while musl types it `unsigned long` — [`statfs_type`] bridges the
/// divergence (NIGHT-hunt-33), so every comparison site stays cast-free
/// against this signed constant.
pub(super) const BPF_FS_MAGIC: i64 = 0xcafe4a11;

/// NIGHT-hunt-28: is `path` on an actually-mounted bpf filesystem?
///
/// The old check was bare path existence — but the kernel creates the
/// `/sys/fs/bpf` mountpoint directory on every Linux, so on hosts
/// where nothing is mounted there the doctor still reported
/// `bpf_fs_mounted: true` (an empty sysfs or tmpfs-backed directory
/// looks identical to `Path::exists`). The failure then surfaced far
/// from the cause: the limiter's map pinning gets EINVAL from
/// `BPF_OBJ_PIN` deep inside the object load, which the error chain of
/// the time rendered as a bare "Failed to load BPF object". statfs()
/// reports the real filesystem type; only `BPF_FS_MAGIC` counts.
pub fn bpffs_mounted_at(path: &str) -> bool {
    fs_type_is_bpf(statfs_type(path))
}

/// statfs(2) filesystem type of `path`, or None when the call fails
/// (no such path, permission, ...). A local helper over `libc::statfs`
/// so the crate keeps its zero-new-dependency posture — `libc` is
/// already a direct dependency.
///
/// NIGHT-hunt-33: `statfs.f_type` is NOT one type across libcs — glibc
/// declares it `__fsword_t` (i64 on LP64) but musl declares it
/// `unsigned long` (u64), so the v11.0.0-alpha.1 release musl build
/// died with E0308 (expected i64, found u64) while the gnu build was
/// green: the two libcs disagree on the Rust-side type of the same
/// kernel field. The kernel ABI is identical either way — a full
/// 64-bit magic on the wire — and every filesystem magic in
/// linux/magic.h (BPF 0xcafe4a11 included) sits far below 2^63, so
/// widening the musl u64 into this i64 contract is lossless for every
/// real-world filesystem; a value with bit 63 set would not be a known
/// magic anyway. The `as i64` is therefore a no-op on gnu and a
/// lossless widening on musl.
fn statfs_type(path: &str) -> Option<i64> {
    let c_path = CString::new(path).ok()?;
    // SAFETY: zeroed() is valid for libc::statfs — an all-zero byte
    // pattern is a sound initial value for the POD struct (no
    // references, no niches the kernel reads before statfs writes).
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: c_path is a valid NUL-terminated string and buf is a
    // valid, properly-aligned statfs buffer of the expected size.
    let rc = unsafe { libc::statfs(c_path.as_ptr(), &mut buf) };
    if rc == 0 {
        // glibc: f_type is already i64 (no-op cast); musl: u64 -> i64
        // lossless widening for every real filesystem magic (see the
        // doc comment on this function).
        Some(buf.f_type as i64)
    } else {
        None
    }
}

/// The testable core of [`bpffs_mounted_at`]: does a statfs-reported
/// type identify a bpf filesystem? None (statfs failed) is a firm no.
fn fs_type_is_bpf(f_type: Option<i64>) -> bool {
    f_type == Some(BPF_FS_MAGIC)
}

/// Find cgroup v2 mount point by parsing /proc/mounts.
pub(super) fn find_cgroup2_mount() -> Option<String> {
    let mounts = std::fs::read_to_string("/proc/mounts").ok()?;
    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[2] == "cgroup2" {
            return Some(parts[1].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIGHT-hunt-28: the magic-number discrimination is the heart of
    /// the fixed doctor — a directory existing at /sys/fs/bpf must not
    /// count as mounted, only the real BPF filesystem magic does.
    /// Constants cross-checked against linux/magic.h.
    #[test]
    fn fs_type_discriminates_bpf_from_sysfs_tmpfs_and_failure() {
        assert!(fs_type_is_bpf(Some(BPF_FS_MAGIC)));
        // SYSFS_MAGIC 0x62656572 — the fs type /sys/fs/bpf shows when
        // the kernel mountpoint exists but nothing is mounted on it.
        assert!(!fs_type_is_bpf(Some(0x6265_6572)));
        // TMPFS_MAGIC 0x01021994 — a tmpfs backed /sys/fs/bpf passes
        // the old existence check too, and fails pins just the same.
        assert!(!fs_type_is_bpf(Some(0x0102_1994)));
        // statfs failure is a firm no, never a maybe.
        assert!(!fs_type_is_bpf(None));
    }

    /// statfs on a always-mounted live path must report a type (never
    /// panic, never None) — and the root filesystem of any normal
    /// machine is not a bpf filesystem, so the composed helper says
    /// no where the old existence check said yes for anything.
    #[test]
    fn statfs_reports_a_real_type_for_the_root_mount() {
        let t = statfs_type("/");
        assert!(t.is_some(), "statfs on / cannot fail on a live system");
        assert_ne!(t, Some(BPF_FS_MAGIC));
        assert!(!bpffs_mounted_at("/"));
    }
}
