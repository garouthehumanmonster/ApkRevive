"""
tests/test_elf_extended.py - Extended unit tests for apkrevive.core.elf covering 32-bit/64-bit ELF parsing, textrel tags, and corrupt headers.
"""

from __future__ import annotations

import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from apkrevive.core.elf import (
    check_elf_textrel,
    inspect_apk_elf_align,
    inspect_apk_elf_details,
    inspect_apk_elf_textrel,
    parse_elf_load_align,
    validate_elf_segments,
)


def make_minimal_elf32(has_textrel_tag=False, has_textrel_flags=False) -> bytes:
    """Builds a minimal valid 32-bit ELF with PT_DYNAMIC section."""
    # ELF header 52 bytes
    endian = "<"
    e_ident = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8
    e_type = 3  # ET_DYN
    e_machine = 40  # EM_ARM
    e_version = 1
    e_entry = 0x1000
    e_phoff = 52
    e_shoff = 0
    e_flags = 0
    e_ehsize = 52
    e_phentsize = 32
    e_phnum = 1
    e_shentsize = 0
    e_shnum = 0
    e_shstrndx = 0

    ehdr = struct.pack(
        f"{endian}16sHHIIIIIHHHHHH",
        e_ident, e_type, e_machine, e_version, e_entry,
        e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize,
        e_phnum, e_shentsize, e_shnum, e_shstrndx,
    )

    # Dynamic section with tags
    dyn_entries = []
    if has_textrel_tag:
        dyn_entries.append((22, 0))  # DT_TEXTREL
    if has_textrel_flags:
        dyn_entries.append((30, 0x4))  # DT_FLAGS, DF_TEXTREL
    dyn_entries.append((0, 0))  # DT_NULL

    dyn_bytes = b"".join(struct.pack(f"{endian}II", tag, val) for tag, val in dyn_entries)
    dyn_offset = 52 + 32  # right after phdr
    dyn_size = len(dyn_bytes)

    # Program header: PT_DYNAMIC = 2
    # p_type (4B), p_offset (4B), p_vaddr (4B), p_paddr (4B), p_filesz (4B), p_memsz (4B), p_flags (4B), p_align (4B)
    phdr = struct.pack(f"{endian}IIIIIIII", 2, dyn_offset, 0x2000, 0x2000, dyn_size, dyn_size, 6, 4)

    return ehdr + phdr + dyn_bytes


def make_minimal_elf64(has_textrel_tag=False, has_textrel_flags=False, load_p_align=16384) -> bytes:
    """Builds a minimal valid 64-bit ELF with PT_LOAD and PT_DYNAMIC."""
    endian = "<"
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    e_type = 3  # ET_DYN
    e_machine = 183  # EM_AARCH64
    e_version = 1
    e_entry = 0x1000
    e_phoff = 64
    e_shoff = 0
    e_flags = 0
    e_ehsize = 64
    e_phentsize = 56
    e_phnum = 2  # 1 PT_LOAD + 1 PT_DYNAMIC
    e_shentsize = 0
    e_shnum = 0
    e_shstrndx = 0

    ehdr = struct.pack(
        f"{endian}16sHHIQQQIHHHHHH",
        e_ident, e_type, e_machine, e_version, e_entry,
        e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize,
        e_phnum, e_shentsize, e_shnum, e_shstrndx,
    )

    # Dynamic entries
    dyn_entries = []
    if has_textrel_tag:
        dyn_entries.append((22, 0))  # DT_TEXTREL
    if has_textrel_flags:
        dyn_entries.append((30, 0x4))  # DT_FLAGS, DF_TEXTREL
    dyn_entries.append((0, 0))  # DT_NULL

    dyn_bytes = b"".join(struct.pack(f"{endian}QQ", tag, val) for tag, val in dyn_entries)
    dyn_offset = 64 + (56 * 2)
    dyn_size = len(dyn_bytes)

    # PT_LOAD (type=1, flags=5, offset=0, vaddr=0x10000, paddr=0x10000, filesz=0x1000, memsz=0x1000, align=load_p_align)
    phdr_load = struct.pack(
        f"{endian}IIQQQQQQ",
        1, 5, 0, 0x10000, 0x10000, 0x1000, 0x1000, load_p_align,
    )

    # PT_DYNAMIC (type=2, flags=6, offset=dyn_offset, vaddr=0x20000, paddr=0x20000, filesz=dyn_size, memsz=dyn_size, align=8)
    phdr_dyn = struct.pack(
        f"{endian}IIQQQQQQ",
        2, 6, dyn_offset, 0x20000, 0x20000, dyn_size, dyn_size, 8,
    )

    return ehdr + phdr_load + phdr_dyn + dyn_bytes


class TestElfExtended(unittest.TestCase):
    def test_parse_elf_load_align_edge_cases(self):
        # 1. Short or invalid magic
        self.assertIsNone(parse_elf_load_align(b"short"))
        self.assertIsNone(parse_elf_load_align(b"\x00" * 64))

        # 2. 32-bit ELF class (ei_class = 1)
        elf32 = make_minimal_elf32()
        self.assertIsNone(parse_elf_load_align(elf32))

        # 3. Invalid phdr offset or size
        corrupt_ph = bytearray(make_minimal_elf64())
        struct.pack_into("<Q", corrupt_ph, 0x20, 0)  # e_phoff = 0
        self.assertIsNone(parse_elf_load_align(bytes(corrupt_ph)))

        # 4. Program headers truncated before length
        truncated = make_minimal_elf64()[:70]
        self.assertIsNone(parse_elf_load_align(truncated))

        # 5. Valid 64-bit ELF with PT_LOAD
        elf64 = make_minimal_elf64(load_p_align=16384)
        self.assertEqual(parse_elf_load_align(elf64), 16384)

        elf64_4k = make_minimal_elf64(load_p_align=4096)
        self.assertEqual(parse_elf_load_align(elf64_4k), 4096)

    def test_validate_elf_segments_edge_cases(self):
        # Short / 32-bit returns (True, None, None)
        self.assertEqual(validate_elf_segments(b"short"), (True, None, None))
        self.assertEqual(validate_elf_segments(make_minimal_elf32()), (True, None, None))

        # 64-bit valid
        valid, align, err = validate_elf_segments(make_minimal_elf64())
        self.assertTrue(valid)
        self.assertEqual(align, 16384)

    def test_inspect_apk_elf_details_and_align(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = Path(tmp_dir) / "test.apk"

            # 1. Non-existent file
            min_align, invalid, status = inspect_apk_elf_details(str(apk_path))
            self.assertIsNone(min_align)
            self.assertFalse(invalid)
            self.assertIsNone(status)
            self.assertIsNone(inspect_apk_elf_align(str(apk_path)))

            # 2. APK without 64-bit libs
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("lib/armeabi-v7a/libtest.so", make_minimal_elf32())
            min_align, invalid, status = inspect_apk_elf_details(str(apk_path))
            self.assertIsNone(min_align)
            self.assertFalse(invalid)
            self.assertIsNone(status)
            self.assertIsNone(inspect_apk_elf_align(str(apk_path)))

            # 3. APK with 64-bit 16KB aligned lib
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("lib/arm64-v8a/libtest.so", make_minimal_elf64(load_p_align=16384))
            min_align, invalid, status = inspect_apk_elf_details(str(apk_path))
            self.assertEqual(min_align, 16384)
            self.assertFalse(invalid)
            self.assertEqual(status, "ALIGNED")
            self.assertEqual(inspect_apk_elf_align(str(apk_path)), 16384)

    def test_check_elf_textrel(self):
        # 1. Invalid or short
        self.assertFalse(check_elf_textrel(b"bad"))
        self.assertFalse(check_elf_textrel(b"\x7fELF" + b"\x00" * 40))

        # 2. Unknown class (e.g. 99)
        bad_class = b"\x7fELF\x63" + b"\x00" * 60
        self.assertFalse(check_elf_textrel(bad_class))

        # 3. 32-bit ELF without textrel
        self.assertFalse(check_elf_textrel(make_minimal_elf32()))
        # 32-bit with DT_TEXTREL
        self.assertTrue(check_elf_textrel(make_minimal_elf32(has_textrel_tag=True)))
        # 32-bit with DT_FLAGS DF_TEXTREL
        self.assertTrue(check_elf_textrel(make_minimal_elf32(has_textrel_flags=True)))

        # 4. 64-bit ELF without textrel
        self.assertFalse(check_elf_textrel(make_minimal_elf64()))
        # 64-bit with DT_TEXTREL
        self.assertTrue(check_elf_textrel(make_minimal_elf64(has_textrel_tag=True)))
        # 64-bit with DT_FLAGS DF_TEXTREL
        self.assertTrue(check_elf_textrel(make_minimal_elf64(has_textrel_flags=True)))

    def test_inspect_apk_elf_textrel(self):
        # 1. Non-existent APK
        self.assertEqual(inspect_apk_elf_textrel("nonexistent_apk.apk"), [])

        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = Path(tmp_dir) / "textrel_test.apk"

            # 2. Zip with textrel .so
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("lib/armeabi-v7a/libtextrel.so", make_minimal_elf32(has_textrel_tag=True))
                zf.writestr("lib/arm64-v8a/libclean.so", make_minimal_elf64())
                zf.writestr("assets/ignored.so", make_minimal_elf32(has_textrel_tag=True))

            libs = inspect_apk_elf_textrel(str(apk_path))
            self.assertEqual(libs, ["libtextrel.so"])


if __name__ == "__main__":
    unittest.main()
