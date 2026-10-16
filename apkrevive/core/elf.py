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


def validate_elf_segments(data: bytes) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    For 64-bit ELF, parse PT_LOAD program headers.
    Check alignment congruence: for each PT_LOAD segment, if p_align > 1, check
    (p_vaddr % p_align) == (p_offset % p_align).
    If p_align >= 16384 but (p_vaddr % p_align) != (p_offset % p_align), return
    (False, p_align, "Segment layout incongruent with p_align (header patched without page-aligned layout)").
    If all valid, return (True, min_p_align, None).
    """
    if len(data) < 64 or not data.startswith(ELF_MAGIC):
        return True, None, None

    ei_class = data[4]
    if ei_class != EI_CLASS_64:
        return True, None, None

    ei_data = data[5]
    endian = "<" if ei_data == EI_DATA_LSB else ">"

    e_phoff = struct.unpack_from(f"{endian}Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from(f"{endian}H", data, 0x36)[0]
    e_phnum = struct.unpack_from(f"{endian}H", data, 0x38)[0]

    if e_phoff == 0 or e_phnum == 0 or e_phentsize < 56:
        return True, None, None

    load_alignments: List[int] = []

    for i in range(e_phnum):
        ph_offset = e_phoff + (i * e_phentsize)
        if ph_offset + 56 > len(data):
            break

        p_type = struct.unpack_from(f"{endian}I", data, ph_offset)[0]
        if p_type == PT_LOAD:
            p_offset = struct.unpack_from(f"{endian}Q", data, ph_offset + 0x08)[0]
            p_vaddr = struct.unpack_from(f"{endian}Q", data, ph_offset + 0x10)[0]
            p_align = struct.unpack_from(f"{endian}Q", data, ph_offset + 0x30)[0]
            load_alignments.append(p_align)

            if p_align > 1:
                if (p_vaddr % p_align) != (p_offset % p_align):
                    if p_align >= 16384:
                        return False, p_align, "Segment layout incongruent with p_align (header patched without page-aligned layout)"

    if not load_alignments:
        return True, None, None

    return True, min(load_alignments), None


def inspect_apk_elf_details(apk_path: str) -> Tuple[Optional[int], bool]:
    """
    Scans 64-bit native libraries in an APK (lib/arm64-v8a/*.so or lib/x86_64/*.so)
    and returns (min_align, has_invalid_layout).
    """
    valid_aligns: List[int] = []
    all_aligns: List[int] = []
    has_invalid_layout = False
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                if name.endswith(".so") and (name.startswith("lib/arm64-v8a/") or name.startswith("lib/x86_64/")):
                    so_bytes = zf.read(name)
                    valid, align, err = validate_elf_segments(so_bytes)
                    if not valid:
                        has_invalid_layout = True
                    if align is not None:
                        all_aligns.append(align)
                        if valid:
                            valid_aligns.append(align)
    except Exception:
        return None, False

    if not all_aligns:
        return None, False

    min_align = min(valid_aligns) if valid_aligns else min(all_aligns)
    return min_align, has_invalid_layout


def inspect_apk_elf_align(apk_path: str) -> Optional[int]:
    """
    Scans 64-bit native libraries in an APK (lib/arm64-v8a/*.so or lib/x86_64/*.so)
    and returns the minimum PT_LOAD p_align found.
    If any 64-bit ELF has invalid layout or align < 16384, returns the lowest valid align
    or 4096 if layout is invalid.
    """
    min_align, has_invalid_layout = inspect_apk_elf_details(apk_path)
    if min_align is None:
        return None
    if has_invalid_layout:
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
