"""
elf_surgeon.py - 16KB ELF Segment Rewriter enforcing Android 15+ 16KB (0x4000) linker invariants.
Operates strictly on 64-bit ELF shared objects (EM_AARCH64=183, EM_X86_64=62).
Preserves 32-bit binaries (ELFCLASS32) untouched.
"""

import zipfile

from apkrevive.security.zip_guard import validate_zip_archive

ELF_MAGIC = b"\x7fELF"
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1

EM_X86_64 = 62
EM_AARCH64 = 183

from apkrevive.core import elf16k

PT_LOAD = 1
PAGE_16KB = 0x4000  # 16384 bytes


def rewrite_elf_16kb(data: bytes) -> bytes:
    """
    Evaluates and safely fixes a 64-bit ELF shared library using elf16k.fix().
    If fix() returns remaining problems (e.g. 4KB-linked library requiring binary relink),
    leaves the library byte-identical and unmutated.
    """
    fixed, problems = elf16k.fix(data)
    if problems:
        # In-place 16KB vaddr shifting is impossible without relink; preserve bytes
        return data
    return fixed



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
