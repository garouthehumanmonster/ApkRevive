"""
elf_surgeon.py - 16KB ELF Segment Rewriter enforcing Android 15+ 16KB (0x4000) linker invariants.
Operates strictly on 64-bit ELF shared objects (EM_AARCH64=183, EM_X86_64=62).
Preserves 32-bit binaries (ELFCLASS32) untouched.
"""

import os
import struct
import zipfile
from typing import Dict, Any, List

from apkrevive.security.zip_guard import validate_zip_archive

ELF_MAGIC = b"\x7fELF"
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1

EM_X86_64 = 62
EM_AARCH64 = 183

PT_LOAD = 1
PAGE_16KB = 0x4000  # 16384 bytes


def rewrite_elf_16kb(data: bytes) -> bytes:
    """
    Rewrites a 64-bit ELF shared library (EM_AARCH64 or EM_X86_64) to enforce:
    1. p_align >= 0x4000 (16384 bytes) for all PT_LOAD segments.
    2. Modulo congruence: p_vaddr % 0x4000 == p_offset % 0x4000 for all PT_LOAD segments.

    Inserts zero-padding before segments when delta = (p_vaddr - p_offset) % 0x4000 != 0,
    shifting subsequent segment offsets, section header offsets, and ELF header pointers.
    Returns original bytes for 32-bit ELFs, non-targeted architectures, or unparseable headers.
    """
    if len(data) < 64 or not data.startswith(ELF_MAGIC):
        return data

    ei_class = data[4]
    if ei_class == ELFCLASS32:
        return data  # 32-bit ELF binaries untouched and marked exempt
    if ei_class != ELFCLASS64:
        return data

    ei_data = data[5]
    endian = "<" if ei_data == ELFDATA2LSB else ">"

    e_machine = struct.unpack_from(f"{endian}H", data, 0x12)[0]
    if e_machine not in (EM_AARCH64, EM_X86_64):
        return data  # Target only 64-bit ARM64 and x86_64

    e_phoff = struct.unpack_from(f"{endian}Q", data, 0x20)[0]
    e_shoff = struct.unpack_from(f"{endian}Q", data, 0x28)[0]
    e_phentsize = struct.unpack_from(f"{endian}H", data, 0x36)[0]
    e_phnum = struct.unpack_from(f"{endian}H", data, 0x38)[0]
    e_shentsize = struct.unpack_from(f"{endian}H", data, 0x3A)[0]
    e_shnum = struct.unpack_from(f"{endian}H", data, 0x3C)[0]

    if e_phoff == 0 or e_phnum == 0 or e_phentsize < 56:
        return data

    # Parse Program Headers
    phdrs: List[Dict[str, Any]] = []
    for i in range(e_phnum):
        off = e_phoff + (i * e_phentsize)
        if off + 56 > len(data):
            return data
        p_type, p_flags = struct.unpack_from(f"{endian}II", data, off)
        p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
            f"{endian}QQQQQQ", data, off + 8
        )
        phdrs.append({
            "index": i,
            "p_type": p_type,
            "p_flags": p_flags,
            "p_offset": p_offset,
            "p_vaddr": p_vaddr,
            "p_paddr": p_paddr,
            "p_filesz": p_filesz,
            "p_memsz": p_memsz,
            "p_align": p_align,
        })

    # Parse Section Headers
    shdrs: List[Dict[str, Any]] = []
    if e_shoff != 0 and e_shnum > 0 and e_shentsize >= 64:
        for i in range(e_shnum):
            off = e_shoff + (i * e_shentsize)
            if off + 64 > len(data):
                break
            sh_name, sh_type = struct.unpack_from(f"{endian}II", data, off)
            sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(f"{endian}QQQQ", data, off + 8)
            sh_link, sh_info = struct.unpack_from(f"{endian}II", data, off + 40)
            sh_addralign, sh_entsize = struct.unpack_from(f"{endian}QQ", data, off + 48)
            shdrs.append({
                "index": i,
                "sh_name": sh_name,
                "sh_type": sh_type,
                "sh_flags": sh_flags,
                "sh_addr": sh_addr,
                "sh_offset": sh_offset,
                "sh_size": sh_size,
                "sh_link": sh_link,
                "sh_info": sh_info,
                "sh_addralign": sh_addralign,
                "sh_entsize": sh_entsize,
            })

    buf = bytearray(data)

    # Process PT_LOAD segments ordered by file offset
    load_indices = [i for i, p in enumerate(phdrs) if p["p_type"] == PT_LOAD]
    load_indices.sort(key=lambda idx: phdrs[idx]["p_offset"])

    for idx in load_indices:
        ph = phdrs[idx]
        cur_offset = ph["p_offset"]
        cur_vaddr = ph["p_vaddr"]

        # Ensure p_align >= 0x4000
        if ph["p_align"] < PAGE_16KB:
            ph["p_align"] = PAGE_16KB

        # Calculate shift required for modulo congruence: p_vaddr % 0x4000 == p_offset % 0x4000
        delta = (cur_vaddr - cur_offset) % PAGE_16KB
        if delta > 0 and cur_offset > 0:
            insert_pos = cur_offset
            # Insert zero-padding bytes before segment payload
            buf[insert_pos:insert_pos] = b"\x00" * delta

            # Shift program header offsets
            for p in phdrs:
                if p["p_offset"] >= insert_pos:
                    p["p_offset"] += delta

            # Shift section header offsets
            for s in shdrs:
                if s["sh_offset"] >= insert_pos:
                    s["sh_offset"] += delta

            # Shift ELF header pointers if after insertion point
            if e_shoff >= insert_pos:
                e_shoff += delta
            if e_phoff >= insert_pos:
                e_phoff += delta

    # Final pass: enforce p_align >= PAGE_16KB on all PT_LOAD segments
    for idx in load_indices:
        if phdrs[idx]["p_align"] < PAGE_16KB:
            phdrs[idx]["p_align"] = PAGE_16KB

    # Write back ELF header offsets
    struct.pack_into(f"{endian}Q", buf, 0x20, e_phoff)
    struct.pack_into(f"{endian}Q", buf, 0x28, e_shoff)

    # Write back Program Headers
    for i, p in enumerate(phdrs):
        ph_off = e_phoff + (i * e_phentsize)
        if ph_off + 56 <= len(buf):
            struct.pack_into(f"{endian}II", buf, ph_off, p["p_type"], p["p_flags"])
            struct.pack_into(
                f"{endian}QQQQQQ",
                buf,
                ph_off + 8,
                p["p_offset"],
                p["p_vaddr"],
                p["p_paddr"],
                p["p_filesz"],
                p["p_memsz"],
                p["p_align"],
            )

    # Write back Section Headers
    for i, s in enumerate(shdrs):
        sh_off = e_shoff + (i * e_shentsize)
        if sh_off + 64 <= len(buf):
            struct.pack_into(f"{endian}II", buf, sh_off, s["sh_name"], s["sh_type"])
            struct.pack_into(
                f"{endian}QQQQ",
                buf,
                sh_off + 8,
                s["sh_flags"],
                s["sh_addr"],
                s["sh_offset"],
                s["sh_size"],
            )
            struct.pack_into(f"{endian}II", buf, sh_off + 40, s["sh_link"], s["sh_info"])
            struct.pack_into(f"{endian}QQ", buf, sh_off + 48, s["sh_addralign"], s["sh_entsize"])

    return bytes(buf)


def rewrite_apk_elfs_16kb(apk_path: str, output_path: str) -> bool:
    """
    Scans an APK and rewrites all 64-bit ELF shared libraries (.so) to enforce 16KB alignment.
    Returns True if any native library was modified, False otherwise.
    """
    validate_zip_archive(apk_path)
    modified = False

    with zipfile.ZipFile(apk_path, "r") as zin, zipfile.ZipFile(output_path, "w") as zout:
        for item in zin.infolist():
            content = zin.read(item.filename)
            if item.filename.endswith(".so") and (
                "arm64-v8a" in item.filename or "x86_64" in item.filename
            ):
                rewritten = rewrite_elf_16kb(content)
                if rewritten != content:
                    content = rewritten
                    modified = True
            zout.writestr(item, content)

    return modified
