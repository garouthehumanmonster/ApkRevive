"""
elf.py - 64-bit ELF parser extracting PT_LOAD segment alignment (p_align).
"""

import struct
import zipfile
from typing import Optional, List, Tuple

from apkrevive.core.elf_surgeon import rewrite_elf_16kb, rewrite_apk_elfs_16kb

ELF_MAGIC = b"\x7fELF"
EI_CLASS_64 = 2
EI_DATA_LSB = 1
PT_LOAD = 1


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

__all__ = [
    "parse_elf_load_align",
    "validate_elf_segments",
    "inspect_apk_elf_details",
    "inspect_apk_elf_align",
    "rewrite_elf_16kb",
    "rewrite_apk_elfs_16kb",
]
