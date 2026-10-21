"""
elf16k.py - 16KB (0x4000) ELF verification and classification engine for Android 15+.
Evaluates 64-bit ELF binaries (EM_AARCH64, EM_X86_64) into three truthful states:
- ALIGNED: Native 16KB alignment (p_align >= 16KB, 16KB congruence, non-overlapping 16KB pages).
- COMPAT_ONLY: Standard 4KB-linked library (valid 4KB alignment, requires pageSizeCompat backcompat).
- UNSAFE: Incongruent offsets, fake header-patched sharing 16KB pages, or corrupt layouts.
"""

from dataclasses import dataclass, field
from enum import Enum
import struct
from typing import List, Tuple

ELF_MAGIC = b"\x7fELF"
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1

EM_X86_64 = 62
EM_AARCH64 = 183

PT_LOAD = 1
PAGE_4KB = 0x1000   # 4096 bytes
PAGE_16KB = 0x4000  # 16384 bytes


class Elf16kStatus(str, Enum):
    ALIGNED = "ALIGNED"
    COMPAT_ONLY = "COMPAT_ONLY"
    UNSAFE = "UNSAFE"
    EXEMPT = "EXEMPT"


@dataclass(frozen=True)
class LoadSegment:
    index: int
    p_offset: int
    p_vaddr: int
    p_filesz: int
    p_memsz: int
    p_align: int
    p_flags: int


@dataclass(frozen=True)
class Elf16kReport:
    status: Elf16kStatus
    min_align: int
    is_64bit: bool
    reasons: List[str] = field(default_factory=list)
    segments: List[LoadSegment] = field(default_factory=list)


def check(data: bytes) -> Elf16kReport:
    """
    Analyzes an ELF shared object and returns an Elf16kReport with one of three states:
    ALIGNED, COMPAT_ONLY, or UNSAFE.
    """
    if len(data) < 64 or not data.startswith(ELF_MAGIC):
        return Elf16kReport(
            status=Elf16kStatus.UNSAFE,
            min_align=0,
            is_64bit=False,
            reasons=["Not a valid ELF binary or shorter than 64 bytes"],
        )

    ei_class = data[4]
    if ei_class == ELFCLASS32:
        return Elf16kReport(
            status=Elf16kStatus.EXEMPT,
            min_align=4096,
            is_64bit=False,
            reasons=["32-bit ELF; 16KB page alignment checks apply only to 64-bit binaries"],
        )

    if ei_class != ELFCLASS64:
        return Elf16kReport(
            status=Elf16kStatus.UNSAFE,
            min_align=0,
            is_64bit=False,
            reasons=[f"Unsupported ELF class: {ei_class}"],
        )

    ei_data = data[5]
    endian = "<" if ei_data == ELFDATA2LSB else ">"

    e_machine = struct.unpack_from(f"{endian}H", data, 0x12)[0]
    if e_machine not in (EM_AARCH64, EM_X86_64):
        return Elf16kReport(
            status=Elf16kStatus.EXEMPT,
            min_align=4096,
            is_64bit=True,
            reasons=[f"Non-targeted 64-bit ELF machine architecture: {e_machine}; 16KB page alignment checks apply only to 64-bit binaries"],
        )

    e_phoff = struct.unpack_from(f"{endian}Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from(f"{endian}H", data, 0x36)[0]
    e_phnum = struct.unpack_from(f"{endian}H", data, 0x38)[0]

    if e_phoff == 0 or e_phnum == 0 or e_phentsize < 56:
        return Elf16kReport(
            status=Elf16kStatus.UNSAFE,
            min_align=0,
            is_64bit=True,
            reasons=["Invalid or missing ELF program header table"],
        )

    segments: List[LoadSegment] = []
    for i in range(e_phnum):
        off = e_phoff + (i * e_phentsize)
        if off + 56 > len(data):
            return Elf16kReport(
                status=Elf16kStatus.UNSAFE,
                min_align=0,
                is_64bit=True,
                reasons=[f"Program header {i} extends beyond file length"],
            )
        p_type, p_flags = struct.unpack_from(f"{endian}II", data, off)
        p_offset, p_vaddr, _, p_filesz, p_memsz, p_align = struct.unpack_from(
            f"{endian}QQQQQQ", data, off + 8
        )
        if p_type == PT_LOAD:
            segments.append(
                LoadSegment(
                    index=i,
                    p_offset=p_offset,
                    p_vaddr=p_vaddr,
                    p_filesz=p_filesz,
                    p_memsz=p_memsz,
                    p_align=p_align,
                    p_flags=p_flags,
                )
            )

    if not segments:
        return Elf16kReport(
            status=Elf16kStatus.UNSAFE,
            min_align=0,
            is_64bit=True,
            reasons=["No PT_LOAD segments found in 64-bit ELF"],
        )

    min_align = min(s.p_align for s in segments)
    reasons: List[str] = []

    # Check 1: Internal congruence: (p_vaddr % p_align) == (p_offset % p_align)
    for seg in segments:
        if seg.p_align > 1 and (seg.p_vaddr % seg.p_align) != (seg.p_offset % seg.p_align):
            reasons.append(
                f"Segment layout incongruent with p_align: segment {seg.index} "
                f"(vaddr 0x{seg.p_vaddr:X} % 0x{seg.p_align:X} != offset 0x{seg.p_offset:X} % 0x{seg.p_align:X})"
            )

    if reasons:
        return Elf16kReport(
            status=Elf16kStatus.UNSAFE,
            min_align=min_align,
            is_64bit=True,
            reasons=reasons,
            segments=segments,
        )

    # Check 2: 16KB requirements (p_align >= 0x4000, 16KB congruence, distinct 16KB pages)
    is_16kb_aligned = min_align >= PAGE_16KB
    congruent_16kb = all((s.p_vaddr % PAGE_16KB) == (s.p_offset % PAGE_16KB) for s in segments)

    # Check for 16KB virtual address page collisions
    # On 16KB kernels, bionic mmaps each segment at page boundaries. If two segments share
    # a 16KB page, the second MAP_FIXED call overwrites the first.
    sorted_by_vaddr = sorted(segments, key=lambda s: s.p_vaddr)
    has_page_collision = False
    for i in range(len(sorted_by_vaddr) - 1):
        s1 = sorted_by_vaddr[i]
        s2 = sorted_by_vaddr[i + 1]
        s1_page_end = (s1.p_vaddr + s1.p_memsz + PAGE_16KB - 1) // PAGE_16KB
        s2_page_start = s2.p_vaddr // PAGE_16KB
        if s2_page_start < s1_page_end:
            has_page_collision = True
            reasons.append(
                f"PT_LOAD segments {s1.index} (vaddr 0x{s1.p_vaddr:X}..0x{s1.p_vaddr+s1.p_memsz:X}) "
                f"and {s2.index} (vaddr 0x{s2.p_vaddr:X}) collide inside the same 16KB page boundary"
            )

    if is_16kb_aligned and congruent_16kb and not has_page_collision:
        return Elf16kReport(
            status=Elf16kStatus.ALIGNED,
            min_align=min_align,
            is_64bit=True,
            reasons=[],
            segments=segments,
        )

    if has_page_collision and is_16kb_aligned:
        # Fake header patch detected: p_align raised to 16KB without vaddr spacing
        return Elf16kReport(
            status=Elf16kStatus.UNSAFE,
            min_align=min_align,
            is_64bit=True,
            reasons=reasons,
            segments=segments,
        )

    # Valid 4KB-linked library
    compat_reasons = [
        f"ELF is 4KB-linked (min_p_align={min_align}); cannot run natively on 16KB kernel without pageSizeCompat backcompat mode"
    ]
    return Elf16kReport(
        status=Elf16kStatus.COMPAT_ONLY,
        min_align=min_align,
        is_64bit=True,
        reasons=compat_reasons,
        segments=segments,
    )


def fix(data: bytes) -> Tuple[bytes, List[str]]:
    """
    Attempts to fix a 64-bit ELF for 16KB execution.
    If the library cannot be soundly fixed in-place without binary relinking (which is true
    for all 4KB-linked binaries with collided vaddrs), leaves the library untouched byte-identical
    and returns the remaining problems explaining why.
    """
    report = check(data)
    if report.status in (Elf16kStatus.ALIGNED, Elf16kStatus.EXEMPT):
        return data, []

    if report.status == Elf16kStatus.COMPAT_ONLY:
        # 4KB-linked ELFs require relocation of virtual addresses and patching of cross-segment references.
        # Android 15+ provides pageSizeCompat backcompat mode; leave lib byte-identical.
        return data, [
            "4KB-linked ELF cannot have virtual addresses shifted without binary relinking; "
            "Android 15+ pageSizeCompat backcompat mode required"
        ]

    # UNSAFE layout
    return data, [
        f"Unsafe ELF layout cannot be repaired: {'; '.join(report.reasons)}"
    ]
