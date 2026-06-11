// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Optional read-only eBPF snapshot adapter for the Intergalaxion Engine.

use std::ffi::CStr;
use std::fs;
use std::path::Path;

use super::capability::EbpfCapabilitySnapshot;

const CAP_SYS_ADMIN_BIT: u8 = 21;
const CAP_BPF_BIT: u8 = 39;

/// Build a best-effort snapshot from read-only host facts.
pub fn read_live_ebpf_capability_snapshot() -> EbpfCapabilitySnapshot {
    let (cap_bpf_effective, cap_sys_admin_effective) =
        read_effective_caps("/proc/self/status").unwrap_or((None, None));

    EbpfCapabilitySnapshot {
        kernel_release: read_kernel_release(),
        bpf_fs_mounted: Some(Path::new("/sys/fs/bpf").is_dir()),
        btf_vmlinux_available: Some(Path::new("/sys/kernel/btf/vmlinux").is_file()),
        cap_bpf_effective,
        cap_sys_admin_effective,
        unprivileged_bpf_disabled: read_u8_file("/proc/sys/kernel/unprivileged_bpf_disabled"),
        aya_available_at_compile_time: cfg!(feature = "ebpf"),
    }
}

fn read_effective_caps(path: &str) -> Option<(Option<bool>, Option<bool>)> {
    let status = fs::read_to_string(path).ok()?;
    let cap_eff = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))?
        .trim();
    let bits = u64::from_str_radix(cap_eff, 16).ok()?;

    Some((
        Some(cap_bit_is_set(bits, CAP_BPF_BIT)),
        Some(cap_bit_is_set(bits, CAP_SYS_ADMIN_BIT)),
    ))
}

fn cap_bit_is_set(bits: u64, bit: u8) -> bool {
    bits & (1u64 << bit) != 0
}

fn read_u8_file(path: &str) -> Option<u8> {
    fs::read_to_string(path).ok()?.trim().parse::<u8>().ok()
}

fn read_kernel_release() -> Option<String> {
    let mut uts = std::mem::MaybeUninit::<libc::utsname>::uninit();
    let rc = unsafe { libc::uname(uts.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }

    let uts = unsafe { uts.assume_init() };
    let release = unsafe { CStr::from_ptr(uts.release.as_ptr()) };
    release.to_str().ok().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_bit_helper_reads_expected_bits() {
        let bits = (1u64 << CAP_BPF_BIT) | (1u64 << CAP_SYS_ADMIN_BIT);
        assert!(cap_bit_is_set(bits, CAP_BPF_BIT));
        assert!(cap_bit_is_set(bits, CAP_SYS_ADMIN_BIT));
        assert!(!cap_bit_is_set(bits, 0));
    }
}
