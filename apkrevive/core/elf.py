"""
elf.py - 64-bit ELF parser extracting PT_LOAD segment alignment (p_align).
"""

import struct
import zipfile
from typing import Optional, List


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


def inspect_apk_elf_align(apk_path: str) -> Optional[int]:
    """
    Scans 64-bit native libraries in an APK (lib/arm64-v8a/*.so or lib/x86_64/*.so)
    and returns the minimum PT_LOAD p_align found.
    """
    min_align: Optional[int] = None
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                if name.endswith(".so") and (name.startswith("lib/arm64-v8a/") or name.startswith("lib/x86_64/")):
                    so_bytes = zf.read(name)
                    align = parse_elf_load_align(so_bytes)
                    if align is not None:
                        if min_align is None or align < min_align:
                            min_align = align
    except Exception:
        return None
    return min_align
