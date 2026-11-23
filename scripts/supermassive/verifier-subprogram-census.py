#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.

"""verifier-subprogram-census.py — the bpf2bpf subprogram population census
(night-frontier-Z13, measurement-first).

The hole: the ledger's mirror entry says "the B2B subprogram shape cannot
dedup on a loader that ships no func_info", and its reopen condition names
"the hand-rolled loader ships program func_info (BTF-driven B2B dedup)" as
a future headroom rung. Neither sentence is pinned by a number: nothing in
the tree counts the bpf2bpf subprogram population of the two embedded
objects, and nothing records whether program func_info actually rides the
load path (today the loader is aya 0.16, not the old raw-syscall walker —
the two audit sentences date from different loader eras).

The census answers both with raw ELF facts, no kernel needed:

  1. BTF_FUNC kinds        — every named function the object declares
                             (linkage: static 0 / global 1 / extern 2).
  2. .BTF.ext func_info    — the function records the ELF carries for the
                             loader; what the verifier receives at
                             BPF_PROG_LOAD depends on the loader forwarding
                             them (aya does; measured against the aya tree,
                             recorded in the ledger entry, not asserted here).
  3. call instructions     — opcode 0x85 split by src_reg: 0 helper,
                             1 BPF_PSEUDO_CALL (bpf2bpf), 2 BPF_PSEUDO_FUNC
                             (global func pointer, e.g. bpf_loop callbacks),
                             3 BPF_PSEUDO_KFUNC_CALL (kfunc).
  4. R_BPF_64_32 relocs    — call-site relocations against STT_FUNC
                             symbols: the relocatable spelling of a b2b
                             call in a not-yet-linked object.
  5. STT_FUNC symbols      — the symbol-table population, per section.

Verdict rule (recorded in docs/INNOVATIONS.md, night-frontier-Z13): the
B2B dedup rung is DEAD BY MEASUREMENT when both pseudo-call instructions
and R_BPF_64_32 call relocs are zero across both objects — there is no
subprogram shape for func_info dedup to act on, whatever the loader ships.

Usage:
    python3 scripts/supermassive/verifier-subprogram-census.py \
        ebpf-prebuilt/zelynic-limiter.o ebpf-prebuilt/zelynic-observer.o

Exit code 0 when the census completes (a census reports, it does not
gate); any parse failure exits 2 with the reason.
"""

import json
import struct
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile

# BTF type kinds (UAPI bpf.h enum btf_kind) and record tail sizes.
# Tails: bytes following struct btf_type (12 bytes) for each kind,
# fully determined by kind and vlen — this is what makes the type array
# walkable without a full parser.
BTF_KIND_INT = 1
BTF_KIND_PTR = 2
BTF_KIND_ARRAY = 3
BTF_KIND_FUNC = 12
BTF_KIND_FUNC_PROTO = 13

BTF_KIND_TAIL = {
    "int": 4,  # btf_int
    "ptr": 0,
    "array": 12,  # btf_array
    "struct": 12,  # btf_member, times vlen
    "union": 12,  # btf_member, times vlen
    "enum": 8,  # btf_enum, times vlen
    # btf_enum64 is 12 bytes (name_off, val_lo32, val_hi32).
    "fwd": 0,
    "typedef": 0,
    "volatile": 0,
    "const": 0,
    "restrict": 0,
    "func": 0,  # vlen carries linkage, no tail
    # FUNC_PROTO: the btf_type union IS the return type (already inside the
    # 12-byte record); only the vlen btf_param entries (8 bytes each) trail.
    "func_proto": 8,  # btf_param, times vlen
    "var": 4,  # btf_var
    "datasec": 12,  # btf_var_secinfo, times vlen
    "float": 0,
    "decl_tag": 0,
    "type_tag": 0,
    "enum64": 12,  # btf_enum64, times vlen
}

BTF_MAGIC = 0xEB9F

# BPF call opcode and the src_reg spellings of interest (arch-independent).
BPF_OP_CALL = 0x85
CALL_SRC_MEANING = {
    0: "helper",
    1: "pseudo_call_bpf2bpf",
    2: "pseudo_func_global_ptr",
    3: "pseudo_kfunc",
}

# The bpf-linker spelling of a not-yet-relocated b2b call on disk:
# opcode 0x85, imm = -1 (placeholder), the true target arriving through an
# R_BPF_64_32 relocation (the loader rewrites it to BPF_PSEUDO_CALL with
# the callee's byte offset at BPF_PROG_LOAD time).
RELOC_CALL_IMM = -1
RELOC_CALL_MEANING = "reloc_call_bpf2bpf"

# Relocation type R_BPF_64_32: applied to the imm of a call instruction,
# the relocatable spelling of a b2b call in a linked object.
R_BPF_64_32 = 10


def kind_tail(kind: int, vlen: int, kind_flag: bool) -> int:
    """Tail size in bytes after struct btf_type for one type record."""
    if kind == BTF_KIND_INT:
        return BTF_KIND_TAIL["int"]
    if kind == BTF_KIND_PTR:
        # kind_flag on a pointer means __sized BTF type (btf_type with size),
        # not a size change of the record itself.
        return BTF_KIND_TAIL["ptr"]
    if kind == BTF_KIND_ARRAY:
        return BTF_KIND_TAIL["array"]
    if kind in (4, 5):
        return BTF_KIND_TAIL["struct"] * vlen
    if kind == 6:
        return BTF_KIND_TAIL["enum"] * vlen
    if kind in (7, 8, 9, 10, 11):
        return 0
    if kind == BTF_KIND_FUNC:
        return BTF_KIND_TAIL["func"]
    if kind == BTF_KIND_FUNC_PROTO:
        return BTF_KIND_TAIL["func_proto"] * vlen
    if kind == 14:
        return BTF_KIND_TAIL["var"]
    if kind == 15:
        return BTF_KIND_TAIL["datasec"] * vlen
    if kind == 16:
        return BTF_KIND_TAIL["float"]
    if kind == 17:
        # btf_decl_tag carries one component_idx word.
        return 4
    if kind == 18:
        return 0
    if kind == 19:
        return BTF_KIND_TAIL["enum64"] * vlen

    raise ValueError(f"unknown BTF kind {kind} (flag {kind_flag}) — extend the walker")


def parse_btf(btf_bytes: bytes) -> dict:
    """Parse the raw .BTF section: kind histogram plus every FUNC record.

    Returns the funcs keyed by their type-array index (that is the
    reference bpf_func_info.type_id carries), the kind histogram, and a
    string resolver bound to the section's own string table.
    """
    magic, version, _flags, hdr_len = struct.unpack_from("<HBBI", btf_bytes, 0)
    if magic != BTF_MAGIC or version != 1:
        raise ValueError(f"unexpected BTF magic/version: {magic:#x}/{version}")
    type_off, type_len, str_off, str_len = struct.unpack_from("<IIII", btf_bytes, 8)
    # UAPI: every offset in the header is relative to the END of the header
    # (hdr_len), so the string table starts at hdr_len + str_off — NOT after
    # the type section (str_off already accounts for it).
    strings_base = hdr_len + str_off
    str_blob = btf_bytes[strings_base : strings_base + str_len]

    def string_at(name_off: int) -> str:
        end = str_blob.index(b"\x00", name_off)
        return str_blob[name_off:end].decode("utf-8", errors="replace")

    kinds = {}
    func_by_index = {}
    func_protos = 0
    pos = hdr_len + type_off
    end_of_types = pos + type_len
    index = 0
    while pos < end_of_types:
        name_off, info = struct.unpack_from("<II", btf_bytes, pos)
        vlen = info & 0xFFFF
        kind = (info >> 24) & 0x7F
        kind_flag = bool(info & 0x80000000)
        kinds[kind] = kinds.get(kind, 0) + 1
        if kind == BTF_KIND_FUNC:
            # BTF type ids start at 1 (id 0 is void, implicit), so the
            # array position plus one is the id func_info entries carry.
            func_by_index[index + 1] = {
                "name": string_at(name_off),
                # vlen of FUNC carries the linkage (UAPI btf_func_linkage).
                "linkage": {0: "static", 1: "global", 2: "extern"}.get(vlen, f"raw_{vlen}"),
            }
        elif kind == BTF_KIND_FUNC_PROTO:
            func_protos += 1
        pos += 12 + kind_tail(kind, vlen, kind_flag)
        index += 1
    return {
        "type_count": index,
        "kinds": kinds,
        "func_by_index": func_by_index,
        "func_protos": func_protos,
        "string_at": string_at,
    }


def parse_func_info(ext_bytes: bytes, btf: dict) -> list:
    """Parse .BTF.ext func_info: per program section, the FUNC records the
    object ships for the loader. The bpf-linker spelling measured here:
    one record-size word (8, struct bpf_func_info), then per section a
    (sec_name_off, num_info) header and num_info records of
    (insn_off, type_id) — insn_off a BYTE offset into the section, type_id
    indexing the .BTF type array."""
    magic, version, _flags, hdr_len = struct.unpack_from("<HBBI", ext_bytes, 0)
    if magic != BTF_MAGIC or version != 1:
        raise ValueError(f"unexpected .BTF.ext magic/version: {magic:#x}/{version}")
    func_info_off, func_info_len = struct.unpack_from("<II", ext_bytes, 8)
    string_at = btf["string_at"]
    func_by_index = btf["func_by_index"]
    sections = []
    pos = hdr_len + func_info_off
    rec_size = struct.unpack_from("<I", ext_bytes, pos)[0]
    if rec_size != 8:
        raise ValueError(f"unexpected func_info record size {rec_size}")
    pos += 4
    end = hdr_len + func_info_off + func_info_len
    while pos < end:
        sec_name_off, num_info = struct.unpack_from("<II", ext_bytes, pos)
        pos += 8
        names = []
        for _ in range(num_info):
            insn_off, type_id = struct.unpack_from("<II", ext_bytes, pos)
            pos += rec_size
            names.append(func_by_index.get(type_id, {}).get("name", f"type_id_{type_id}"))
        sections.append({"section": string_at(sec_name_off), "entries": num_info, "funcs": names})
    return sections


def census_object(path: Path) -> dict:
    """Full census of one eBPF ELF object. Raw facts only, no verdicts here."""
    with path.open("rb") as handle:
        elf = ELFFile(handle)
        btf_bytes = elf.get_section_by_name(".BTF").data()
        ext_bytes = elf.get_section_by_name(".BTF.ext").data()
        btf = parse_btf(btf_bytes)
        func_info = parse_func_info(ext_bytes, btf)

        func_symbols = []
        symtab = elf.get_section_by_name(".symtab")
        if symtab is not None:
            for sym in symtab.iter_symbols():
                if sym["st_info"]["type"] == "STT_FUNC":
                    func_symbols.append(
                        {
                            "name": sym.name,
                            "section": str(sym["st_shndx"]),
                            "value": sym["st_value"],
                            "size": sym["st_size"],
                        }
                    )

        # Call instructions per PROGBITS code section: the bpf-linker
        # output keeps program code in .text (targets named by symbols).
        calls = []
        for section in elf.iter_sections():
            if section["sh_type"] != "SHT_PROGBITS":
                continue
            name = section.name
            if name.startswith(
                (
                    ".rel",
                    ".debug",
                    ".BTF",
                    ".comment",
                    ".strtab",
                    ".shstrtab",
                    ".symtab",
                    ".note",
                    ".llvm",
                )
            ):
                continue
            data = section.data()
            count = len(data) // 8
            if count == 0:
                continue
            per_section = {"section": name, "insns": count, "calls": {}, "pseudo_sites": []}
            for i in range(count):
                code = data[i * 8]
                if code != BPF_OP_CALL:
                    continue
                src_reg = data[i * 8 + 1] & 0x0F
                imm = struct.unpack_from("<i", data, i * 8 + 4)[0]
                if imm == RELOC_CALL_IMM and src_reg == 0:
                    meaning = RELOC_CALL_MEANING
                else:
                    meaning = CALL_SRC_MEANING.get(src_reg, f"src_{src_reg}")
                per_section["calls"][meaning] = per_section["calls"].get(meaning, 0) + 1
                if src_reg in (1, 2, 3) or meaning == RELOC_CALL_MEANING:
                    per_section["pseudo_sites"].append({"insn": i, "src": src_reg, "imm": imm})
            if per_section["calls"]:
                calls.append(per_section)

        # Relocations against call sites (R_BPF_64_32 = b2b spelling).
        # STT_SECTION symbols carry no name: resolve them to their section
        # (the callee is whatever FUNC lives at section+0 in the object).
        b2b_relocs = []
        section_names = {index: section.name for index, section in enumerate(elf.iter_sections())}
        for section in elf.iter_sections():
            if section["sh_type"] not in ("SHT_REL", "SHT_RELA"):
                continue
            target = section.name.replace(".rel.", ".").replace(".rela.", ".")
            for reloc in section.iter_relocations():
                if reloc["r_info_type"] == R_BPF_64_32:
                    sym_idx = reloc["r_info_sym"]
                    if symtab is not None:
                        sym = symtab.get_symbol(sym_idx)
                        sym_name = (
                            sym.name
                            or f"<{section_names.get(sym['st_shndx'], sym['st_shndx'])}+{sym['st_value']}>"
                        )
                    else:
                        sym_name = f"sym_{sym_idx}"
                    b2b_relocs.append(
                        {"section": target, "offset": reloc["r_offset"], "symbol": sym_name}
                    )

        return {
            "object": path.name,
            "bytes": path.stat().st_size,
            "btf": {
                "type_count": btf["type_count"],
                "kinds": btf["kinds"],
                "funcs": btf["func_by_index"],
                "func_protos": btf["func_protos"],
            },
            "func_info_sections": func_info,
            "func_symbols": func_symbols,
            "call_sections": calls,
            "r_bpf_64_32_relocs": b2b_relocs,
        }


def main() -> int:
    args = sys.argv[1:]
    if not args:
        root = Path(__file__).resolve().parents[2]
        args = [
            str(root / "ebpf-prebuilt" / "zelynic-limiter.o"),
            str(root / "ebpf-prebuilt" / "zelynic-observer.o"),
        ]
    report = []
    for arg in args:
        path = Path(arg)
        if not path.is_file():
            print(f"census: object not found: {path}", file=sys.stderr)
            return 2
        report.append(census_object(path))
    for entry in report:
        pseudo_calls = sum(
            cs["calls"].get("pseudo_call_bpf2bpf", 0) + cs["calls"].get(RELOC_CALL_MEANING, 0)
            for cs in entry["call_sections"]
        )
        relocs = len(entry["r_bpf_64_32_relocs"])
        print("=" * 72)
        print(f"object              : {entry['object']} ({entry['bytes']} bytes)")
        print(f"BTF types           : {entry['btf']['type_count']}")
        print(
            f"BTF_FUNC kinds      : {len(entry['btf']['funcs'])} "
            f"(protos {entry['btf']['func_protos']})"
        )
        for index, func in sorted(entry["btf"]["funcs"].items()):
            print(f"    func[{index}]      : {func['name']} ({func['linkage']})")
        for fi in entry["func_info_sections"]:
            print(
                f"func_info section    : {fi['section']} entries={fi['entries']} "
                f"funcs={','.join(fi['funcs']) or '-'}"
            )
        for sym in entry["func_symbols"]:
            print(
                f"STT_FUNC symbol      : {sym['name']} section={sym['section']} "
                f"value={sym['value']} size={sym['size']}"
            )
        for cs in entry["call_sections"]:
            print(f"code section         : {cs['section']} insns={cs['insns']} calls={cs['calls']}")
            for site in cs["pseudo_sites"]:
                print(
                    f"    pseudo call site : insn={site['insn']} "
                    f"src={site['src']} imm={site['imm']}"
                )
        for reloc in entry["r_bpf_64_32_relocs"]:
            print(
                f"R_BPF_64_32 reloc    : {reloc['section']}+{reloc['offset']} -> {reloc['symbol']}"
            )
        verdict = (
            "bpf2bpf subprogram population: "
            f"{pseudo_calls} call sites (in-reloc + pseudo) "
            f"backed by {relocs} R_BPF_64_32 relocs"
        )
        if pseudo_calls == 0 and relocs == 0:
            verdict += " — ZERO subprogram shape (dead rung by measurement)"
        print(verdict)
    print("=" * 72)
    print(json.dumps({"census": "verifier-subprogram-census", "objects": len(report)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
