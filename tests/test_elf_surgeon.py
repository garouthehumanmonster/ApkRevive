"""
test_elf_surgeon.py - Unit tests for 16KB ELF Segment Rewriter.
Validates 16KB alignment and modulo congruence on synthetic 64-bit ELFs, 32-bit ELF exemption,
and real 64-bit ELFs (e.g. test_4k.so).
"""

import os
import struct
import tempfile
import unittest
import zipfile

from apkrevive.core.elf_surgeon import rewrite_elf_16kb, rewrite_apk_elfs_16kb
from apkrevive.core.elf import validate_elf_segments, parse_elf_load_align


def make_synthetic_64bit_elf(
    p_offset: int = 0x1D30,
    p_vaddr: int = 0x2D30,
    p_align: int = 4096,
    machine: int = 183,  # EM_AARCH64
) -> bytes:
    """Builds a minimal synthetic 64-bit ELF binary with 2 PT_LOAD segments."""
    endian = "<"
    ident = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
    header = struct.pack(
        f"{endian}HHIQQQIHHHHHH",
        3, machine, 1, 0x1000, 64, 0, 0, 64, 56, 2, 64, 0, 0
    )
    elf_hdr = ident + header

    ph0 = struct.pack(f"{endian}IIQQQQQQ", 1, 5, 0, 0, 0, 0x1000, 0x1000, p_align)
    ph1 = struct.pack(f"{endian}IIQQQQQQ", 1, 6, p_offset, p_vaddr, p_vaddr, 0x500, 0x500, p_align)

    data = bytearray(elf_hdr + ph0 + ph1)
    required_len = p_offset + 0x500
    if len(data) < required_len:
        data.extend(b"\x00" * (required_len - len(data)))

    return bytes(data)


class TestElfSurgeon(unittest.TestCase):
    def test_synthetic_64bit_elf_congruence_and_alignment(self):
        elf_incongruent = make_synthetic_64bit_elf(p_offset=0x1D30, p_vaddr=0x2D30, p_align=4096)
        valid, align, err = validate_elf_segments(elf_incongruent)
        self.assertEqual(align, 4096)

        elf_rewritten = rewrite_elf_16kb(elf_incongruent)
        self.assertNotEqual(elf_rewritten, elf_incongruent)

        valid, align, err = validate_elf_segments(elf_rewritten)
        self.assertTrue(valid, f"Rewritten ELF failed segment validation: {err}")
        self.assertGreaterEqual(align, 16384)

        min_align = parse_elf_load_align(elf_rewritten)
        self.assertGreaterEqual(min_align, 16384)

    def test_32bit_elf_exemption(self):
        elf32 = b"\x7fELF\x01\x01\x01\x00" + (b"\x00" * 40)
        rewritten = rewrite_elf_16kb(elf32)
        self.assertEqual(rewritten, elf32)

    def test_real_test_4k_so_if_present(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        test_4k_path = os.path.join(repo_root, "test_4k.so")

        if os.path.exists(test_4k_path):
            with open(test_4k_path, "rb") as f:
                data = f.read()

            rewritten = rewrite_elf_16kb(data)
            valid, align, err = validate_elf_segments(rewritten)
            self.assertTrue(valid, f"test_4k.so rewritten failed validation: {err}")
            self.assertGreaterEqual(align, 16384)

    def test_rewrite_apk_elfs(self):
        elf_4k = make_synthetic_64bit_elf(p_offset=0x1D30, p_vaddr=0x2D30, p_align=4096)
        with tempfile.TemporaryDirectory() as tmp_dir:
            in_apk = os.path.join(tmp_dir, "input.apk")
            out_apk = os.path.join(tmp_dir, "output.apk")

            with zipfile.ZipFile(in_apk, "w") as zf:
                zf.writestr("lib/arm64-v8a/libfoo.so", elf_4k)
                zf.writestr("assets/note.txt", b"Hello")

            modified = rewrite_apk_elfs_16kb(in_apk, out_apk)
            self.assertTrue(modified)

            with zipfile.ZipFile(out_apk, "r") as zf_out:
                rewritten_so = zf_out.read("lib/arm64-v8a/libfoo.so")
                valid, align, err = validate_elf_segments(rewritten_so)
                self.assertTrue(valid)
                self.assertGreaterEqual(align, 16384)
                self.assertEqual(zf_out.read("assets/note.txt"), b"Hello")


if __name__ == "__main__":
    unittest.main()
