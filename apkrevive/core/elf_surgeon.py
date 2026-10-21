"""
elf_surgeon.py - 16KB ELF alignment rewriter and Bionic Linker DT_NEEDED patcher.
Enforces Android 15+ 16KB (0x4000) linker invariants and renames private platform
libraries (libcrypto.so, libssl.so, libcutils.so) in dynamic string tables,
bundling fallback shared objects.
"""

import os
import struct
import zipfile
from typing import Dict, List, Optional, Tuple, Set

from apkrevive.core import elf16k

ELF_MAGIC = b"\x7fELF"
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1

EM_386 = 3
EM_ARM = 40
EM_X86_64 = 62
EM_AARCH64 = 183

PT_LOAD = 1
PT_DYNAMIC = 2

PAGE_4KB = 0x1000
PAGE_16KB = 0x4000

DEFAULT_BIONIC_RENAME_MAP = {
    "libcrypto.so": "libcrypt0.so",
    "libssl.so": "libss1.so",
    "libcutils.so": "libcutil0.so",
    "libutils.so": "libutil0.so",
    "libgui.so": "libgu1.so",
    "libandroid_runtime.so": "libandroid_runtim0.so",
}


def get_stub_so(soname: str, abi: str) -> bytes:
    """
    Retrieves fallback shared object bytes for the given soname and ABI.
    1. Checks local tool stubs in apkrevive/stubs/<abi>/<soname> or stubs/<abi>/<soname>.
    2. Falls back to generating a minimal 16KB-aligned ELF shared object via make_fallback_so.
    """
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(pkg_dir, "..", "stubs", abi, soname),
        os.path.join(os.getcwd(), "stubs", abi, soname),
    ]
    for path in candidates:
        if os.path.isfile(path):
            with open(path, "rb") as f:
                return f.read()

    return make_fallback_so(soname, abi)


from apkrevive.core.align import validate_zip_archive


def rewrite_elf_16kb(data: bytes) -> bytes:
    """
    Evaluates and safely fixes a 64-bit ELF shared library using elf16k.fix().
    If fix() returns remaining problems (e.g. 4KB-linked library requiring binary relink),
    leaves the library byte-identical and unmutated.
    """
    fixed, problems = elf16k.fix(data)
    if problems:
        return data
    return fixed


def make_fallback_so(soname: str, abi: str) -> bytes:
    """
    Generates a minimal valid, 16KB-aligned (or 4KB for 32-bit) ELF shared library (.so)
    with DT_SONAME matching soname for the given ABI.
    """
    is_64 = abi in ("arm64-v8a", "x86_64")

    if abi == "arm64-v8a":
        e_machine = EM_AARCH64
    elif abi == "x86_64":
        e_machine = EM_X86_64
    elif abi == "armeabi-v7a":
        e_machine = EM_ARM
    elif abi == "x86":
        e_machine = EM_386
    else:
        raise ValueError(f"Unsupported ABI: {abi}")

    soname_bytes = soname.encode("ascii") + b"\x00"
    strtab = b"\x00" + soname_bytes
    soname_idx = 1

    if is_64:
        page_size = PAGE_16KB
        ehdr_size = 64
        num_phdrs = 2

        dyn_offset = 0x100
        dyn_entries = [
            (14, soname_idx),   # DT_SONAME
            (5, 0x200),         # DT_STRTAB
            (10, len(strtab)),  # DT_STRSZ
            (0, 0),             # DT_NULL
        ]
        dyn_data = b"".join(struct.pack("<QQ", tag, val) for tag, val in dyn_entries)
        dyn_size = len(dyn_data)

        strtab_offset = 0x200
        filesz = strtab_offset + len(strtab)
        memsz = filesz

        p0 = struct.pack("<IIQQQQQQ", PT_LOAD, 6, 0, 0, 0, filesz, memsz, page_size)
        p1 = struct.pack("<IIQQQQQQ", PT_DYNAMIC, 6, dyn_offset, dyn_offset, dyn_offset, dyn_size, dyn_size, 8)

        e_ident = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
        ehdr = struct.pack(
            "<16sHHIQQQIHHHHHH",
            e_ident,
            3,  # ET_DYN
            e_machine,
            1,  # EV_CURRENT
            0,
            ehdr_size,
            0,
            0,
            ehdr_size,
            56,
            num_phdrs,
            0, 0, 0,
        )

        blob = bytearray(ehdr + p0 + p1)
        blob.extend(b"\x00" * (dyn_offset - len(blob)))
        blob.extend(dyn_data)
        blob.extend(b"\x00" * (strtab_offset - len(blob)))
        blob.extend(strtab)
        return bytes(blob)
    else:
        page_size = PAGE_4KB
        ehdr_size = 52
        num_phdrs = 2

        dyn_offset = 0x80
        dyn_entries = [
            (14, soname_idx),
            (5, 0x100),
            (10, len(strtab)),
            (0, 0),
        ]
        dyn_data = b"".join(struct.pack("<II", tag, val) for tag, val in dyn_entries)
        dyn_size = len(dyn_data)

        strtab_offset = 0x100
        filesz = strtab_offset + len(strtab)
        memsz = filesz

        p0 = struct.pack("<IIIIIIII", PT_LOAD, 0, 0, 0, filesz, memsz, 6, page_size)
        p1 = struct.pack("<IIIIIIII", PT_DYNAMIC, dyn_offset, dyn_offset, dyn_offset, dyn_size, dyn_size, 6, 4)

        e_ident = b"\x7fELF\x01\x01\x01\x00" + (b"\x00" * 8)
        ehdr = struct.pack(
            "<16sHHIIIIIHHHHHH",
            e_ident,
            3,  # ET_DYN
            e_machine,
            1,
            0,
            ehdr_size,
            0,
            0,
            ehdr_size,
            32,
            num_phdrs,
            0, 0, 0,
        )

        blob = bytearray(ehdr + p0 + p1)
        blob.extend(b"\x00" * (dyn_offset - len(blob)))
        blob.extend(dyn_data)
        blob.extend(b"\x00" * (strtab_offset - len(blob)))
        blob.extend(strtab)
        return bytes(blob)


def patch_elf_dt_needed(data: bytes, rename_map: Dict[str, str]) -> Tuple[bytes, List[str]]:
    """
    Scans DT_NEEDED entries in ELF dynamic section (both 32-bit and 64-bit).
    Renames entries matching rename_map in the dynamic string table.
    Supports in-place replacement (shorter/equal) and table relocation (longer).
    Returns (modified_elf_bytes, list_of_renamed_lib_descriptions).
    """
    if len(data) < 52 or not data.startswith(ELF_MAGIC):
        return data, []

    ei_class = data[4]
    ei_data = data[5]
    endian = "<" if ei_data == ELFDATA2LSB else ">"
    is_64 = (ei_class == ELFCLASS64)

    if is_64:
        if len(data) < 64:
            return data, []
        e_phoff = struct.unpack_from(f"{endian}Q", data, 0x20)[0]
        e_phentsize = struct.unpack_from(f"{endian}H", data, 0x36)[0]
        e_phnum = struct.unpack_from(f"{endian}H", data, 0x38)[0]
        ph_sz = 56
    else:
        e_phoff = struct.unpack_from(f"{endian}I", data, 0x1C)[0]
        e_phentsize = struct.unpack_from(f"{endian}H", data, 0x2A)[0]
        e_phnum = struct.unpack_from(f"{endian}H", data, 0x2C)[0]
        ph_sz = 32

    if e_phoff == 0 or e_phnum == 0 or e_phentsize < ph_sz:
        return data, []

    pt_loads: List[Tuple[int, int, int, int, int]] = []  # (vaddr, memsz, offset, filesz, phdr_file_off)
    dyn_off: Optional[int] = None
    dyn_sz: Optional[int] = None
    last_load_idx: Optional[int] = None
    max_vaddr = -1

    for i in range(e_phnum):
        off = e_phoff + (i * e_phentsize)
        if off + ph_sz > len(data):
            break
        p_type = struct.unpack_from(f"{endian}I", data, off)[0]
        if p_type == PT_LOAD:
            if is_64:
                p_offset = struct.unpack_from(f"{endian}Q", data, off + 8)[0]
                p_vaddr = struct.unpack_from(f"{endian}Q", data, off + 16)[0]
                p_filesz = struct.unpack_from(f"{endian}Q", data, off + 32)[0]
                p_memsz = struct.unpack_from(f"{endian}Q", data, off + 40)[0]
            else:
                p_offset = struct.unpack_from(f"{endian}I", data, off + 4)[0]
                p_vaddr = struct.unpack_from(f"{endian}I", data, off + 8)[0]
                p_filesz = struct.unpack_from(f"{endian}I", data, off + 16)[0]
                p_memsz = struct.unpack_from(f"{endian}I", data, off + 20)[0]
            pt_loads.append((p_vaddr, p_memsz, p_offset, p_filesz, off))
            if p_vaddr >= max_vaddr:
                max_vaddr = p_vaddr
                last_load_idx = len(pt_loads) - 1
        elif p_type == PT_DYNAMIC:
            if is_64:
                dyn_off = struct.unpack_from(f"{endian}Q", data, off + 8)[0]
                dyn_sz = struct.unpack_from(f"{endian}Q", data, off + 32)[0]
            else:
                dyn_off = struct.unpack_from(f"{endian}I", data, off + 4)[0]
                dyn_sz = struct.unpack_from(f"{endian}I", data, off + 16)[0]

    if dyn_off is None or dyn_sz is None or not pt_loads or last_load_idx is None:
        return data, []

    def vaddr_to_offset(vaddr: int) -> Optional[int]:
        for p_vaddr, p_memsz, p_offset, p_filesz, _ in pt_loads:
            if p_vaddr <= vaddr < p_vaddr + p_memsz:
                return p_offset + (vaddr - p_vaddr)
        if vaddr < len(data):
            return vaddr
        return None

    strtab_tag_off: Optional[int] = None
    strtab_vaddr: Optional[int] = None
    strsz_tag_off: Optional[int] = None
    strsz_val: Optional[int] = None
    needed_entries: List[Tuple[int, int]] = []

    entry_sz = 16 if is_64 else 8
    fmt = f"{endian}QQ" if is_64 else f"{endian}II"
    curr = dyn_off
    while curr + entry_sz <= dyn_off + dyn_sz and curr + entry_sz <= len(data):
        tag, val = struct.unpack_from(fmt, data, curr)
        if tag == 0:
            break
        elif tag == 1:  # DT_NEEDED
            needed_entries.append((curr, val))
        elif tag == 5:  # DT_STRTAB
            strtab_tag_off = curr
            strtab_vaddr = val
        elif tag == 10:  # DT_STRSZ
            strsz_tag_off = curr
            strsz_val = val
        curr += entry_sz

    if strtab_vaddr is None or strsz_val is None or strtab_tag_off is None or strsz_tag_off is None:
        return data, []

    strtab_off = vaddr_to_offset(strtab_vaddr)
    if strtab_off is None or strtab_off + strsz_val > len(data):
        return data, []

    strtab = data[strtab_off : strtab_off + strsz_val]
    matches: List[Tuple[int, int, str, str]] = []  # (entry_off, str_off, old_n, new_n)

    for entry_off, str_off in needed_entries:
        if str_off < len(strtab):
            null_pos = strtab.find(b"\x00", str_off)
            if null_pos != -1:
                name = strtab[str_off:null_pos].decode("utf-8", errors="replace")
                if name in rename_map:
                    matches.append((entry_off, str_off, name, rename_map[name]))

    if not matches:
        return data, []

    out = bytearray(data)
    renamed: List[str] = []

    can_fit_in_place = all(len(new_n.encode("utf-8")) <= len(old_n.encode("utf-8")) for _, _, old_n, new_n in matches)

    if can_fit_in_place:
        for _, str_off, old_n, new_n in matches:
            new_bytes = new_n.encode("utf-8") + b"\x00"
            pad_len = (len(old_n.encode("utf-8")) + 1) - len(new_bytes)
            pos = strtab_off + str_off
            out[pos : pos + len(new_bytes)] = new_bytes
            if pad_len > 0:
                out[pos + len(new_bytes) : pos + len(new_bytes) + pad_len] = b"\x00" * pad_len
            renamed.append(f"{old_n}->{new_n}")
        return bytes(out), renamed

    # Longer replacement: append new string table to end of file, extend last PT_LOAD
    new_strtab = bytearray(strtab)
    for entry_off, _, old_n, new_n in matches:
        new_off = len(new_strtab)
        new_strtab.extend(new_n.encode("utf-8") + b"\x00")
        if is_64:
            struct.pack_into(f"{endian}Q", out, entry_off + 8, new_off)
        else:
            struct.pack_into(f"{endian}I", out, entry_off + 4, new_off)
        renamed.append(f"{old_n}->{new_n}")

    last_vaddr, last_memsz, last_offset, _, phdr_off = pt_loads[last_load_idx]
    align = 16
    append_file_off = (len(out) + (align - 1)) & ~(align - 1)
    new_strtab_vaddr = last_vaddr + (append_file_off - last_offset)

    out.extend(b"\x00" * (append_file_off - len(out)))
    out.extend(new_strtab)

    new_filesz = len(out) - last_offset
    new_memsz = max(last_memsz, new_filesz)

    if is_64:
        struct.pack_into(f"{endian}Q", out, phdr_off + 32, new_filesz)
        struct.pack_into(f"{endian}Q", out, phdr_off + 40, new_memsz)
        struct.pack_into(f"{endian}Q", out, strtab_tag_off + 8, new_strtab_vaddr)
        struct.pack_into(f"{endian}Q", out, strsz_tag_off + 8, len(new_strtab))
    else:
        struct.pack_into(f"{endian}I", out, phdr_off + 16, new_filesz)
        struct.pack_into(f"{endian}I", out, phdr_off + 20, new_memsz)
        struct.pack_into(f"{endian}I", out, strtab_tag_off + 4, new_strtab_vaddr)
        struct.pack_into(f"{endian}I", out, strsz_tag_off + 4, len(new_strtab))

    return bytes(out), renamed


def patch_apk_native_libs(
    apk_path: str,
    output_path: str,
    rename_map: Optional[Dict[str, str]] = None,
) -> Tuple[bool, List[str]]:
    """
    Scans all .so shared libraries in the APK:
    1. Enforces 16KB alignment on 64-bit binaries.
    2. Patches DT_NEEDED entries for private bionic system libraries.
    3. Bundles precompiled fallback shared libraries into lib/<abi>/ for any renamed libraries.
    Returns (modified_flag, list_of_remediations).
    """
    validate_zip_archive(apk_path)
    rename_map = rename_map or DEFAULT_BIONIC_RENAME_MAP
    modified = False
    remediations: List[str] = []
    renamed_sos: Set[str] = set()
    found_abis: Set[str] = set()
    existing_entries: Set[str] = set()

    with zipfile.ZipFile(apk_path, "r") as zin, zipfile.ZipFile(output_path, "w") as zout:
        for item in zin.infolist():
            existing_entries.add(item.filename)
            content = zin.read(item.filename)

            if item.filename.startswith("lib/") and item.filename.endswith(".so"):
                parts = item.filename.split("/")
                if len(parts) >= 3:
                    found_abis.add(parts[1])

                # 1. 16KB alignment fix for 64-bit ELFs
                if "arm64-v8a" in item.filename or "x86_64" in item.filename:
                    rewritten = rewrite_elf_16kb(content)
                    if rewritten != content:
                        content = rewritten
                        modified = True
                        remediations.append(f"16KB_ALIGN:{item.filename}")

                # 2. DT_NEEDED patch
                patched, names = patch_elf_dt_needed(content, rename_map)
                if names:
                    content = patched
                    modified = True
                    for n in names:
                        remediations.append(f"DT_NEEDED:{item.filename}:{n}")
                        new_lib_name = n.split("->")[-1]
                        renamed_sos.add(new_lib_name)

            zout.writestr(item, content)

        # 3. Inject fallback .so libraries for any renamed dependencies
        for new_lib in sorted(renamed_sos):
            for abi in sorted(found_abis):
                target_path = f"lib/{abi}/{new_lib}"
                if target_path not in existing_entries:
                    try:
                        fallback_bytes = get_stub_so(new_lib, abi)
                        zout.writestr(target_path, fallback_bytes)
                        existing_entries.add(target_path)
                        modified = True
                        remediations.append(f"INJECT_FALLBACK:{target_path}")
                    except ValueError:
                        pass

        # 4. Check for 32-bit only native library presence
        if found_abis:
            has_64bit = any(abi in ("arm64-v8a", "x86_64") for abi in found_abis)
            has_32bit = any(abi in ("armeabi", "armeabi-v7a", "x86") for abi in found_abis)
            if has_32bit and not has_64bit:
                abi_str = ", ".join(sorted(found_abis))
                first_abi = sorted(found_abis)[0]
                warning_msg = (
                    f"WARN_32BIT_ONLY: APK contains only 32-bit native libraries ({abi_str}). "
                    "Target device must support 32-bit execution, or installation requires: "
                    f"'adb install --abi {first_abi} --bypass-low-target-sdk-block'"
                )
                remediations.append(warning_msg)

    return modified, remediations


def rewrite_apk_elfs_16kb(apk_path: str, output_path: str) -> bool:
    """Legacy compatibility alias for 16KB ELF rewriting."""
    modified, _ = patch_apk_native_libs(apk_path, output_path)
    return modified


__all__ = [
    "rewrite_elf_16kb",
    "patch_elf_dt_needed",
    "make_fallback_so",
    "get_stub_so",
    "patch_apk_native_libs",
    "rewrite_apk_elfs_16kb",
    "validate_zip_archive",
    "DEFAULT_BIONIC_RENAME_MAP",
]
