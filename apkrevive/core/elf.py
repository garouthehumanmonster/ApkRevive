"""
elf.py - 64-bit ELF parser extracting PT_LOAD segment alignment (p_align).
"""

import os
import struct
import zipfile
from typing import Optional, List, Tuple

from apkrevive.core.elf_surgeon import rewrite_elf_16kb, rewrite_apk_elfs_16kb

ELF_MAGIC = b"\x7fELF"
EI_CLASS_32 = 1
EI_CLASS_64 = 2
EI_DATA_LSB = 1
PT_LOAD = 1
PT_DYNAMIC = 2
DT_TEXTREL = 22
DT_FLAGS = 30
DF_TEXTREL = 0x4


def parse_elf_load_align(data: bytes) -> Optional[int]:
    """
    Parses a 64-bit ELF binary and returns the minimum p_align of all PT_LOAD segments.
    """
    if len(data) < 64 or not data.startswith(ELF_MAGIC):
        return None

    ei_class = data[4]
    if ei_class != EI_CLASS_64:
        return None

    ei_data = data[5]
    endian = "<" if ei_data == EI_DATA_LSB else ">"

    e_phoff = struct.unpack_from(f"{endian}Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from(f"{endian}H", data, 0x36)[0]
    e_phnum = struct.unpack_from(f"{endian}H", data, 0x38)[0]

    if e_phoff == 0 or e_phnum == 0 or e_phentsize < 56:
        return None

    load_alignments: List[int] = []

    for i in range(e_phnum):
        ph_offset = e_phoff + (i * e_phentsize)
        if ph_offset + 56 > len(data):
            break

        p_type = struct.unpack_from(f"{endian}I", data, ph_offset)[0]
        if p_type == PT_LOAD:
            p_align = struct.unpack_from(f"{endian}Q", data, ph_offset + 0x30)[0]
            load_alignments.append(p_align)

    if not load_alignments:
        return None

    return min(load_alignments)


from apkrevive.core import elf16k


def validate_elf_segments(data: bytes) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    Validates 64-bit ELF segment layout using elf16k.check().
    Detects fake header patches where p_align was inflated but vaddrs collide on 16KB pages.
    Returns (is_valid, min_p_align, error_message).
    """
    if len(data) < 64 or not data.startswith(ELF_MAGIC):
        return True, None, None

    ei_class = data[4]
    if ei_class != EI_CLASS_64:
        return True, None, None

    rep = elf16k.check(data)
    if rep.status == elf16k.Elf16kStatus.UNSAFE:
        err = "; ".join(rep.reasons) if rep.reasons else "Invalid ELF segment layout"
        return False, rep.min_align, err

    return True, rep.min_align, None


def inspect_apk_elf_details(apk_path: str) -> Tuple[Optional[int], bool, Optional[str]]:
    """
    Scans 64-bit native libraries in an APK (lib/arm64-v8a/*.so or lib/x86_64/*.so)
    using elf16k.check() and returns (min_align, has_invalid_layout, elf_16kb_status).
    elf_16kb_status is one of: ALIGNED, COMPAT_ONLY, UNSAFE, or None if no 64-bit libs.
    """
    valid_aligns: List[int] = []
    all_aligns: List[int] = []
    has_invalid_layout = False
    statuses: List[str] = []

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                if name.endswith(".so") and (name.startswith("lib/arm64-v8a/") or name.startswith("lib/x86_64/")):
                    so_bytes = zf.read(name)
                    rep = elf16k.check(so_bytes)
                    statuses.append(rep.status.value)
                    if rep.status == elf16k.Elf16kStatus.UNSAFE:
                        has_invalid_layout = True
                    if rep.min_align > 0:
                        all_aligns.append(rep.min_align)
                        if rep.status != elf16k.Elf16kStatus.UNSAFE:
                            valid_aligns.append(rep.min_align)
    except Exception:
        return None, False, None

    if not statuses:
        return None, False, None

    min_align = min(valid_aligns) if valid_aligns else (min(all_aligns) if all_aligns else None)
    if "UNSAFE" in statuses or has_invalid_layout:
        overall_status = "UNSAFE"
    elif "COMPAT_ONLY" in statuses:
        overall_status = "COMPAT_ONLY"
    elif "ALIGNED" in statuses:
        overall_status = "ALIGNED"
    elif "EXEMPT" in statuses:
        overall_status = "EXEMPT"
    else:
        overall_status = "ALIGNED"

    return min_align, has_invalid_layout, overall_status


def inspect_apk_elf_align(apk_path: str) -> Optional[int]:
    """
    Scans 64-bit native libraries in an APK (lib/arm64-v8a/*.so or lib/x86_64/*.so)
    and returns the minimum PT_LOAD p_align found.
    If any 64-bit ELF has invalid layout or align < 16384, returns the lowest valid align
    or 4096 if layout is invalid.
    """
    min_align, has_invalid_layout, status = inspect_apk_elf_details(apk_path)
    if min_align is None:
        return None
    if status == "UNSAFE" or has_invalid_layout:
        return min_align if min_align < 4096 else 4096
    return min_align

def check_elf_textrel(so_bytes: bytes) -> bool:
    """
    Parses ELF PT_DYNAMIC section for both 32-bit (EI_CLASS=1) and 64-bit (EI_CLASS=2) ELF binaries.
    Checks for DT_TEXTREL (tag 22) or DT_FLAGS (tag 30) with flag DF_TEXTREL (val & 0x4).
    Returns True if text relocations are present.
    """
    if len(so_bytes) < 52 or not so_bytes.startswith(ELF_MAGIC):
        return False

    ei_class = so_bytes[4]
    ei_data = so_bytes[5]
    endian = "<" if ei_data == EI_DATA_LSB else ">"

    if ei_class == EI_CLASS_32:
        if len(so_bytes) < 52:
            return False
        e_phoff = struct.unpack_from(f"{endian}I", so_bytes, 0x1C)[0]
        e_phentsize = struct.unpack_from(f"{endian}H", so_bytes, 0x2A)[0]
        e_phnum = struct.unpack_from(f"{endian}H", so_bytes, 0x2C)[0]

        if e_phoff == 0 or e_phnum == 0 or e_phentsize < 32:
            return False

        dyn_off = None
        dyn_sz = None

        for i in range(e_phnum):
            off = e_phoff + (i * e_phentsize)
            if off + 32 > len(so_bytes):
                break
            p_type = struct.unpack_from(f"{endian}I", so_bytes, off)[0]
            if p_type == PT_DYNAMIC:
                dyn_off = struct.unpack_from(f"{endian}I", so_bytes, off + 4)[0]
                dyn_sz = struct.unpack_from(f"{endian}I", so_bytes, off + 16)[0] or struct.unpack_from(f"{endian}I", so_bytes, off + 20)[0]
                break

        if dyn_off is None or dyn_sz is None:
            return False

        curr = dyn_off
        end = min(dyn_off + dyn_sz, len(so_bytes))
        while curr + 8 <= end:
            tag, val = struct.unpack_from(f"{endian}II", so_bytes, curr)
            if tag == 0:  # DT_NULL
                break
            if tag == DT_TEXTREL:
                return True
            if tag == DT_FLAGS and bool(val & DF_TEXTREL):
                return True
            curr += 8

        return False

    elif ei_class == EI_CLASS_64:
        if len(so_bytes) < 64:
            return False
        e_phoff = struct.unpack_from(f"{endian}Q", so_bytes, 0x20)[0]
        e_phentsize = struct.unpack_from(f"{endian}H", so_bytes, 0x36)[0]
        e_phnum = struct.unpack_from(f"{endian}H", so_bytes, 0x38)[0]

        if e_phoff == 0 or e_phnum == 0 or e_phentsize < 56:
            return False

        dyn_off = None
        dyn_sz = None

        for i in range(e_phnum):
            off = e_phoff + (i * e_phentsize)
            if off + 56 > len(so_bytes):
                break
            p_type = struct.unpack_from(f"{endian}I", so_bytes, off)[0]
            if p_type == PT_DYNAMIC:
                dyn_off = struct.unpack_from(f"{endian}Q", so_bytes, off + 8)[0]
                dyn_sz = struct.unpack_from(f"{endian}Q", so_bytes, off + 32)[0] or struct.unpack_from(f"{endian}Q", so_bytes, off + 40)[0]
                break

        if dyn_off is None or dyn_sz is None:
            return False

        curr = dyn_off
        end = min(dyn_off + dyn_sz, len(so_bytes))
        while curr + 16 <= end:
            tag, val = struct.unpack_from(f"{endian}QQ", so_bytes, curr)
            if tag == 0:  # DT_NULL
                break
            if tag == DT_TEXTREL:
                return True
            if tag == DT_FLAGS and bool(val & DF_TEXTREL):
                return True
            curr += 16

        return False

    return False


def inspect_apk_elf_textrel(apk_path: str) -> List[str]:
    """
    Scans all .so files inside the APK (under lib/) and returns list of .so library names
    that have text relocations.
    """
    textrel_libs: List[str] = []
    if not os.path.exists(apk_path):
        return textrel_libs

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                if name.startswith("lib/") and name.endswith(".so"):
                    try:
                        so_bytes = zf.read(name)
                        if check_elf_textrel(so_bytes):
                            lib_name = os.path.basename(name)
                            if lib_name not in textrel_libs:
                                textrel_libs.append(lib_name)
                    except Exception:
                        pass
    except Exception:
        pass

    return sorted(textrel_libs)


__all__ = [
    "check_elf_textrel",
    "inspect_apk_elf_textrel",
    "parse_elf_load_align",
    "validate_elf_segments",
    "inspect_apk_elf_details",
    "inspect_apk_elf_align",
    "rewrite_elf_16kb",
    "rewrite_apk_elfs_16kb",
]
