"""
elf_surgeon.py - 16KB ELF alignment rewriter and Bionic Linker dependency auditor.
Enforces Android 15+ 16KB (0x4000) linker invariants and audits private platform
libraries (libcrypto.so, libssl.so, libcutils.so, libandroid_runtime.so, libgui.so).
"""

import struct
import zipfile
from typing import List, Optional, Tuple, Set

from apkrevive.core import elf16k
from apkrevive.core.align import validate_zip_archive

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

PRIVATE_BIONIC_LIBS = {
    "libcrypto.so",
    "libssl.so",
    "libcutils.so",
    "libandroid_runtime.so",
    "libgui.so",
}


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


def audit_elf_16kb(data: bytes) -> Tuple[bool, List[str]]:
    """
    Audits an ELF binary for 16KB (0x4000) page alignment:
    - 32-bit ELFs (EM_ARM, EM_386) are exempt.
    - 64-bit ELFs (EM_AARCH64, EM_X86_64) must satisfy:
      1. Modulo congruence: (p_vaddr % 0x4000 == p_offset % 0x4000) for all PT_LOAD segments.
      2. No adjacent PT_LOAD page collisions: adjacent segments cannot share the same 16KB virtual page.
    Returns (is_compliant, list_of_issues).
    """
    if len(data) < 52 or not data.startswith(ELF_MAGIC):
        return False, ["Not a valid ELF binary"]

    ei_class = data[4]
    ei_data = data[5]
    endian = "<" if ei_data == ELFDATA2LSB else ">"

    if ei_class == ELFCLASS32:
        return True, ["32-bit ELF (exempt from 16KB alignment)"]

    if ei_class != ELFCLASS64 or len(data) < 64:
        return False, [f"Invalid or unsupported ELF class: {ei_class}"]

    e_machine = struct.unpack_from(f"{endian}H", data, 0x12)[0]
    if e_machine not in (EM_AARCH64, EM_X86_64):
        return True, [f"Non-targeted 64-bit architecture (EM={e_machine})"]

    e_phoff = struct.unpack_from(f"{endian}Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from(f"{endian}H", data, 0x36)[0]
    e_phnum = struct.unpack_from(f"{endian}H", data, 0x38)[0]

    if e_phoff == 0 or e_phnum == 0 or e_phentsize < 56:
        return False, ["Invalid program header table"]

    segments: List[Tuple[int, int, int, int, int]] = []  # (index, p_offset, p_vaddr, p_filesz, p_memsz)
    for i in range(e_phnum):
        off = e_phoff + (i * e_phentsize)
        if off + 56 > len(data):
            return False, [f"Program header {i} out of bounds"]
        p_type = struct.unpack_from(f"{endian}I", data, off)[0]
        if p_type == PT_LOAD:
            p_offset, p_vaddr, _, p_filesz, p_memsz, p_align = struct.unpack_from(
                f"{endian}QQQQQQ", data, off + 8
            )
            segments.append((i, p_offset, p_vaddr, p_filesz, p_memsz))

    if not segments:
        return False, ["No PT_LOAD segments found"]

    issues: List[str] = []
    # 1. Modulo congruence check
    for idx, p_offset, p_vaddr, p_filesz, p_memsz in segments:
        if (p_vaddr % PAGE_16KB) != (p_offset % PAGE_16KB):
            issues.append(
                f"PT_LOAD segment {idx} incongruent: p_vaddr 0x{p_vaddr:X} % 0x4000 != p_offset 0x{p_offset:X} % 0x4000"
            )

    # 2. Adjacent PT_LOAD page collisions
    sorted_segs = sorted(segments, key=lambda s: s[2])
    for i in range(len(sorted_segs) - 1):
        s1 = sorted_segs[i]
        s2 = sorted_segs[i + 1]
        s1_page_end = (s1[2] + s1[4] + PAGE_16KB - 1) // PAGE_16KB
        s2_page_start = s2[2] // PAGE_16KB
        if s2_page_start < s1_page_end:
            issues.append(
                f"PT_LOAD segments {s1[0]} (vaddr 0x{s1[2]:X}..0x{s1[2]+s1[4]:X}) "
                f"and {s2[0]} (vaddr 0x{s2[2]:X}) collide inside the same 16KB page boundary"
            )

    return (len(issues) == 0, issues)


def get_elf_needed(data: bytes) -> List[str]:
    """
    Parses DT_NEEDED library names from the ELF dynamic section.
    Supports both 32-bit (EM_ARM, EM_386) and 64-bit (EM_AARCH64, EM_X86_64) binaries.
    """
    if len(data) < 52 or not data.startswith(ELF_MAGIC):
        return []

    ei_class = data[4]
    ei_data = data[5]
    endian = "<" if ei_data == ELFDATA2LSB else ">"
    is_64 = (ei_class == ELFCLASS64)

    if is_64:
        if len(data) < 64:
            return []
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
        return []

    pt_loads: List[Tuple[int, int, int]] = []  # (vaddr, memsz, offset)
    dyn_off: Optional[int] = None
    dyn_sz: Optional[int] = None

    for i in range(e_phnum):
        off = e_phoff + (i * e_phentsize)
        if off + ph_sz > len(data):
            break
        p_type = struct.unpack_from(f"{endian}I", data, off)[0]
        if p_type == PT_LOAD:
            if is_64:
                p_offset = struct.unpack_from(f"{endian}Q", data, off + 8)[0]
                p_vaddr = struct.unpack_from(f"{endian}Q", data, off + 16)[0]
                p_memsz = struct.unpack_from(f"{endian}Q", data, off + 40)[0]
            else:
                p_offset = struct.unpack_from(f"{endian}I", data, off + 4)[0]
                p_vaddr = struct.unpack_from(f"{endian}I", data, off + 8)[0]
                p_memsz = struct.unpack_from(f"{endian}I", data, off + 20)[0]
            pt_loads.append((p_vaddr, p_memsz, p_offset))
        elif p_type == PT_DYNAMIC:
            if is_64:
                dyn_off = struct.unpack_from(f"{endian}Q", data, off + 8)[0]
                dyn_sz = struct.unpack_from(f"{endian}Q", data, off + 32)[0]
            else:
                dyn_off = struct.unpack_from(f"{endian}I", data, off + 4)[0]
                dyn_sz = struct.unpack_from(f"{endian}I", data, off + 16)[0]

    if dyn_off is None or dyn_sz is None or not pt_loads:
        return []

    def vaddr_to_offset(vaddr: int) -> Optional[int]:
        for p_vaddr, p_memsz, p_offset in pt_loads:
            if p_vaddr <= vaddr < p_vaddr + p_memsz:
                return p_offset + (vaddr - p_vaddr)
        if vaddr < len(data):
            return vaddr
        return None

    entry_sz = 16 if is_64 else 8
    fmt = f"{endian}QQ" if is_64 else f"{endian}II"
    curr = dyn_off
    needed_offsets: List[int] = []
    strtab_vaddr: Optional[int] = None
    strsz_val: Optional[int] = None

    while curr + entry_sz <= dyn_off + dyn_sz and curr + entry_sz <= len(data):
        tag, val = struct.unpack_from(fmt, data, curr)
        if tag == 0:
            break
        elif tag == 1:  # DT_NEEDED
            needed_offsets.append(val)
        elif tag == 5:  # DT_STRTAB
            strtab_vaddr = val
        elif tag == 10:  # DT_STRSZ
            strsz_val = val
        curr += entry_sz

    if strtab_vaddr is None or strsz_val is None:
        return []

    strtab_off = vaddr_to_offset(strtab_vaddr)
    if strtab_off is None or strtab_off + strsz_val > len(data):
        return []

    strtab = data[strtab_off : strtab_off + strsz_val]
    needed_libs: List[str] = []
    for str_off in needed_offsets:
        if str_off < len(strtab):
            null_pos = strtab.find(b"\x00", str_off)
            if null_pos != -1:
                name = strtab[str_off:null_pos].decode("utf-8", errors="replace")
                if name:
                    needed_libs.append(name)

    return needed_libs


def patch_apk_native_libs(
    apk_path: str,
    output_path: str,
) -> Tuple[bool, List[str]]:
    """
    Inspects all .so shared libraries in the APK:
    1. Enforces 16KB alignment rewriting on 64-bit binaries.
    2. Detects private Bionic platform libraries (libcrypto, libssl, libcutils, etc.)
       and emits honest remediation warnings without injecting fake stubs.
    3. Emits 32-bit only APK warning when no 64-bit native libraries exist.
    Returns (modified_flag, list_of_remediations).
    """
    validate_zip_archive(apk_path)
    modified = False
    remediations: List[str] = []
    found_abis: Set[str] = set()

    with zipfile.ZipFile(apk_path, "r") as zin, zipfile.ZipFile(output_path, "w") as zout:
        for item in zin.infolist():
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

                # 2. Detect private Bionic DT_NEEDED libraries
                needed = get_elf_needed(content)
                for lib_name in needed:
                    if lib_name in PRIVATE_BIONIC_LIBS:
                        remediations.append(
                            f"Bionic Linker: Private dependency {lib_name} detected in {item.filename} "
                            "(non-NDK platform library blocked on API 24+)"
                        )

            zout.writestr(item, content)

        # 3. Check for 32-bit only native library presence
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
    "rewrite_apk_elfs_16kb",
    "patch_apk_native_libs",
    "audit_elf_16kb",
    "get_elf_needed",
    "validate_zip_archive",
    "PRIVATE_BIONIC_LIBS",
]
