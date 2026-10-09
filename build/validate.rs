// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// NIGHT-improve-31 phase 1, executed by NIGHT-improve-44: the ELF
// structural validators (NIGHT-hunt-29) — read_validated_ebpf_object,
// validate_ebpf_object, the little-endian readers — plus the tests
// that pin them.

/// NIGHT-hunt-29: read one staged eBPF object and structurally
/// validate it. The Err text is user-facing (it rides the
/// cargo:warning and the panic of the self-heal path), so it names
/// the exact violation instead of a bare "corrupt".
pub(crate) fn read_validated_ebpf_object(path: &std::path::Path) -> Result<Vec<u8>, String> {
    let data = std::fs::read(path).map_err(|e| format!("not readable: {e}"))?;
    validate_ebpf_object(&data)?;
    Ok(data)
}

/// NIGHT-hunt-29: structural validation of one staged eBPF object —
/// enough ELF law to catch every on-disk damage mode that would make
/// aya's parser reject the bytes, without pulling an ELF crate into
/// this build script (zero build-dependencies; see the LOC_EXEMPT
/// note at the top of the file).
///
/// The failure being fenced out, reproduced end to end on the exact
/// alias shape: a bpfel object damaged on disk AFTER cargo marked its
/// build unit fresh — cargo's freshness is fingerprint-plus-existence,
/// never output integrity, so a truncated or partially written
/// artifact stays "fresh" forever and every later build re-embeds the
/// corpse. The old magic-only assert could not see it: the ELF header
/// lives in the first 64 bytes, so any truncation past byte 64 keeps
/// a valid magic. The bytes then rode into the binary via
/// include_bytes! and the failure surfaced on the user host at load
/// time, far from the cause, as an opaque "error parsing BPF object:
/// error parsing ELF data" (the 2026-09-20 test session's blocker —
/// identical on a fresh build and an old one, because both embedded
/// the same damaged artifact file).
///
/// What is checked, and why each row is load-bearing for the aya-obj
/// parser that will consume the bytes: identity (magic, ELFCLASS64,
/// little-endian, EV_CURRENT — bytes 0..16), ET_REL + EM_BPF (the
/// only shape bpf-linker emits), a section header table that exists,
/// uses 64-byte entries, and lies fully inside the file (bpf-linker
/// places it LAST, which makes this the truncation killer), every
/// non-NOBITS section's offset+size inside the file (catches a cut
/// that stops at the table edge while the .text or .shstrtab behind
/// it is gone), and a section-name string table index in range (aya
/// finds programs by section NAME). Deliberately not checked:
/// semantic content — programs, maps, relocations — that is aya's own
/// job at load time, where the NIGHT-hunt-28 error chain now names
/// any residual failure precisely.
fn validate_ebpf_object(data: &[u8]) -> Result<(), String> {
    if data.len() < 64 {
        return Err(format!(
            "too short to hold an ELF64 header: {} bytes",
            data.len()
        ));
    }
    if !data.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return Err("ELF magic missing (not an ELF file)".to_string());
    }
    if data[4] != 2 {
        return Err(format!("not ELFCLASS64 (EI_CLASS={})", data[4]));
    }
    if data[5] != 1 {
        return Err(format!("not little-endian (EI_DATA={})", data[5]));
    }
    if data[6] != 1 {
        return Err(format!("bad ELF version (EI_VERSION={})", data[6]));
    }
    let e_type = u16_le(data, 16);
    if e_type != 1 {
        return Err(format!(
            "not a relocatable object (e_type={e_type}, want ET_REL=1)"
        ));
    }
    let e_machine = u16_le(data, 18);
    if e_machine != 247 {
        return Err(format!(
            "not an eBPF object (e_machine={e_machine}, want EM_BPF=247)"
        ));
    }
    let phoff = u64_le(data, 32);
    let shoff = u64_le(data, 40);
    let phentsize = u16_le(data, 54);
    let phnum = u16_le(data, 56);
    let shentsize = u16_le(data, 58);
    let shnum = u16_le(data, 60);
    let shstrndx = u16_le(data, 62);
    if phnum > 0 {
        let end = phoff.checked_add(u64::from(phentsize) * u64::from(phnum));
        if end.is_none_or(|e| e > data.len() as u64) {
            return Err(format!(
                "program header table out of bounds ({phnum} entries)"
            ));
        }
    }
    if shnum == 0 || shoff == 0 {
        return Err("no section header table".to_string());
    }
    if shentsize != 64 {
        return Err(format!(
            "bad section header size (e_shentsize={shentsize}, want 64)"
        ));
    }
    let table_out_of_bounds = shoff
        .checked_add(u64::from(shnum) * u64::from(shentsize))
        .is_none_or(|e| e > data.len() as u64);
    if table_out_of_bounds {
        return Err(format!(
            "truncated: section header table ({shnum} x {shentsize} at {shoff}) \
             exceeds the {}-byte file",
            data.len()
        ));
    }
    // Every section the table indexes must lie inside the file, with
    // one carve-out: SHT_NOBITS (8) describes bytes the file does not
    // carry, so its span is not bounds-checked.
    let table = shoff as usize; // <= data.len() (checked above)
    for i in 0..usize::from(shnum) {
        let sh = &data[table + i * 64..][..64];
        let sh_type = u32_le(sh, 4);
        if sh_type == 8 {
            continue; // SHT_NOBITS
        }
        let sh_offset = u64_le(sh, 24);
        let sh_size = u64_le(sh, 32);
        if sh_offset
            .checked_add(sh_size)
            .is_none_or(|e| e > data.len() as u64)
        {
            return Err(format!(
                "truncated: section {i} spans {sh_offset}..{} but the file is {} bytes",
                sh_offset.saturating_add(sh_size),
                data.len()
            ));
        }
    }
    if shstrndx == 0 || usize::from(shstrndx) >= usize::from(shnum) {
        return Err(format!(
            "section name string table index out of range (e_shstrndx={shstrndx}, \
             e_shnum={shnum})"
        ));
    }
    Ok(())
}

/// Little-endian u16 at `at` — ELF64 is LE for the bpfel target.
fn u16_le(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

/// Little-endian u32 at `at`.
fn u32_le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Little-endian u64 at `at`.
fn u64_le(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

/// NIGHT-hunt-28: remove host-CPU and host-linker rustflags from the
/// environment handed to the nested eBPF build.
///
/// The leak path (verified live on cargo 1.98.1 with a build script
/// dumping its own environment): the parent cargo exports its
/// RESOLVED rustflags to build scripts as `CARGO_ENCODED_RUSTFLAGS`
/// (0x1F-separated — `--config build.rustflags=["-C","target-cpu=native"]`
/// arrives here as `-C\u{1f}target-cpu=native`), and a user- or
/// CI-exported `RUSTFLAGS` (space-separated) is inherited the same
/// way. Host-tuning flags in that inheritance are poison for the
/// bpfel cross-build: rustc cannot apply them to the BPF target but
/// still forwards the resolved CPU to bpf-linker as `--cpu znver3`
/// (any host arch lands here), which bpf-linker hard-rejects with
/// `invalid CPU` — reproduced on the owner's Zen 3 host, where
/// `cargo pro-native-gnu` died in the link step of both objects
/// after ~4 minutes of compiling. The same family:
/// `scripts/build.sh`'s fast-linker export `-C
/// link-arg=-fuse-ld=mold` reaches bpf-linker's command line as an
/// unknown argument (latent — only on hosts with mold installed).
///

#[cfg(test)]
mod tests {
    use super::*;

    /// NIGHT-hunt-29: a minimal structurally-valid eBPF ELF — every
    /// field at its ELF-64 spec offset, the exact layout the shipped
    /// objects use (verified against the real bpf-linker output:
    /// class 2, data 1, version 1, ET_REL, machine 247, 64-byte
    /// section headers). Bytes: [Ehdr][Shdr0 null][Shdr1 strtab][one
    /// strtab byte]. Semantically empty on purpose — the validator is
    /// structural, and the fixtures below damage structure only.
    fn synthetic_ebpf_elf() -> Vec<u8> {
        let mut v = vec![0u8; 193];
        v[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        v[4] = 2; // ELFCLASS64
        v[5] = 1; // ELFDATA2LSB
        v[6] = 1; // EV_CURRENT
        v[16..18].copy_from_slice(&1u16.to_le_bytes()); // e_type = ET_REL
        v[18..20].copy_from_slice(&247u16.to_le_bytes()); // e_machine = EM_BPF
        v[40..48].copy_from_slice(&64u64.to_le_bytes()); // e_shoff = 64
        v[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        v[60..62].copy_from_slice(&2u16.to_le_bytes()); // e_shnum = 2
        v[62..64].copy_from_slice(&1u16.to_le_bytes()); // e_shstrndx = 1
        // Shdr1 at 64 + 64 = 128: SHT_STRTAB (3) spanning 192..193.
        v[128 + 4..128 + 8].copy_from_slice(&3u32.to_le_bytes());
        v[128 + 24..128 + 32].copy_from_slice(&192u64.to_le_bytes());
        v[128 + 32..128 + 40].copy_from_slice(&1u64.to_le_bytes());
        v
    }

    #[test]
    fn ebpf_object_validator_accepts_the_minimal_structural_shape() {
        assert!(validate_ebpf_object(&synthetic_ebpf_elf()).is_ok());
    }

    #[test]
    fn ebpf_object_validator_rejects_a_cut_section_table() {
        // The owner's exact failure shape: a real bpf-linker object
        // keeps its section table LAST, so ANY truncation cuts it —
        // the sandbox reproduction was a 1000-byte prefix of the
        // 5624-byte limiter, mirrored here by cutting inside the
        // table. The old magic-only assert waved this through.
        let broken = &synthetic_ebpf_elf()[..100];
        let err = validate_ebpf_object(broken).unwrap_err();
        assert!(err.contains("section header table"), "got: {err}");
    }

    #[test]
    fn ebpf_object_validator_rejects_a_section_cut_off_behind_the_table() {
        // A truncation that stops exactly at the table edge leaves
        // the table in bounds while a section it indexes is gone — the
        // per-section span check is what catches this one.
        let broken = &synthetic_ebpf_elf()[..192];
        let err = validate_ebpf_object(broken).unwrap_err();
        assert!(err.contains("section 1 spans"), "got: {err}");
    }

    #[test]
    fn ebpf_object_validator_rejects_wrong_identity_fields() {
        let mut host_binary = synthetic_ebpf_elf();
        host_binary[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86-64
        assert!(
            validate_ebpf_object(&host_binary)
                .unwrap_err()
                .contains("not an eBPF object")
        );

        let mut class32 = synthetic_ebpf_elf();
        class32[4] = 1;
        assert!(
            validate_ebpf_object(&class32)
                .unwrap_err()
                .contains("ELFCLASS64")
        );

        let mut executable = synthetic_ebpf_elf();
        executable[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        assert!(
            validate_ebpf_object(&executable)
                .unwrap_err()
                .contains("relocatable")
        );

        let mut no_strtab_index = synthetic_ebpf_elf();
        no_strtab_index[62..64].copy_from_slice(&0u16.to_le_bytes());
        assert!(
            validate_ebpf_object(&no_strtab_index)
                .unwrap_err()
                .contains("string table index")
        );
    }

    #[test]
    fn ebpf_object_validator_rejects_garbage_and_emptiness() {
        assert!(validate_ebpf_object(b"").unwrap_err().contains("too short"));
        assert!(
            validate_ebpf_object(b"hello build")
                .unwrap_err()
                .contains("too short")
        );
        // Magic present, everything else zeroed: rejected by the first
        // identity row — never waved through on magic alone.
        let mut magic_only = vec![0u8; 64];
        magic_only[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        assert!(validate_ebpf_object(&magic_only).is_err());
    }

    #[test]
    fn ebpf_object_validator_allows_nobits_to_overhang_the_file() {
        // SHT_NOBITS is the one section type that legitimately
        // describes bytes the file does not carry (bss-style); its
        // span must not be bounds-checked against the file length.
        // The fixture is structurally valid, semantically silly —
        // which is exactly the contract.
        let mut v = synthetic_ebpf_elf();
        v.resize(257, 0); // room for Shdr2 at 64 + 2*64 = 192
        v[60..62].copy_from_slice(&3u16.to_le_bytes()); // e_shnum = 3
        v[192 + 4..192 + 8].copy_from_slice(&8u32.to_le_bytes()); // SHT_NOBITS
        v[192 + 24..192 + 32].copy_from_slice(&1_000u64.to_le_bytes());
        v[192 + 32..192 + 40].copy_from_slice(&0xffff_ffffu64.to_le_bytes());
        assert!(validate_ebpf_object(&v).is_ok());
    }
}
