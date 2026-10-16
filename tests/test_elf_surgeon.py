"""
test_elf_surgeon.py - Unit tests for 16KB ELF Segment Rewriter and elf16k integration.
Validates:
- 4KB-linked ELFs evaluate to COMPAT_ONLY (never ALIGNED) and rewrite_elf_16kb leaves them byte-identical.
- ALIGNED ELFs evaluate to ALIGNED and remain untouched.
- UNSAFE ELFs (fake header patches sharing 16KB pages, incongruent offsets) are flagged and not claimed fixed.
- 32-bit ELFs are exempt and untouched.
"""

import os
import struct
import tempfile
import unittest
import zipfile

from apkrevive.core.elf16k import check, fix, Elf16kStatus
from apkrevive.core.elf_surgeon import rewrite_elf_16kb, rewrite_apk_elfs_16kb
from apkrevive.core.elf import validate_elf_segments


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


def make_aligned_16kb_elf() -> bytes:
    """Builds a truly 16KB-aligned synthetic 64-bit ELF on distinct 16KB pages."""
    endian = "<"
    ident = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
    header = struct.pack(
        f"{endian}HHIQQQIHHHHHH",
        3, 183, 1, 0x1000, 64, 0, 0, 64, 56, 2, 64, 0, 0
    )
    elf_hdr = ident + header

    ph0 = struct.pack(f"{endian}IIQQQQQQ", 1, 5, 0x0000, 0x0000, 0x0000, 0x1000, 0x1000, 16384)
    ph1 = struct.pack(f"{endian}IIQQQQQQ", 1, 6, 0x4000, 0x4000, 0x4000, 0x1000, 0x1000, 16384)

    data = bytearray(elf_hdr + ph0 + ph1)
    if len(data) < 0x5000:
        data.extend(b"\x00" * (0x5000 - len(data)))
    return bytes(data)


class TestElfSurgeon(unittest.TestCase):
    def test_synthetic_64bit_elf_congruence_and_alignment(self):
        # 4KB-linked synthetic ELF
        elf_4k = make_synthetic_64bit_elf(p_offset=0x1D30, p_vaddr=0x2D30, p_align=4096)
        rep = check(elf_4k)
        # Evaluates to COMPAT_ONLY, never ALIGNED
        self.assertEqual(rep.status, Elf16kStatus.COMPAT_ONLY)
        self.assertNotEqual(rep.status, Elf16kStatus.ALIGNED)

        # Calling rewrite_elf_16kb leaves the .so byte-identical
        elf_rewritten = rewrite_elf_16kb(elf_4k)
        self.assertEqual(elf_rewritten, elf_4k)

        # fix() reports remaining problems explaining why relinking cannot be done in-place
        fixed, problems = fix(elf_4k)
        self.assertEqual(fixed, elf_4k)
        self.assertTrue(len(problems) > 0)
        self.assertTrue(any("relink" in p.lower() or "compat" in p.lower() for p in problems))

    def test_aligned_16kb_elf_untouched(self):
        elf_aligned = make_aligned_16kb_elf()
        rep = check(elf_aligned)
        self.assertEqual(rep.status, Elf16kStatus.ALIGNED)

        rewritten = rewrite_elf_16kb(elf_aligned)
        self.assertEqual(rewritten, elf_aligned)

        valid, align, err = validate_elf_segments(rewritten)
        self.assertTrue(valid)
        self.assertGreaterEqual(align, 16384)

    def test_unsafe_fake_header_patch(self):
        # Fake patch: p_align claimed 16KB, but segment 0 (0x0) and segment 1 (0x2D30) share page 0
        elf_fake = make_synthetic_64bit_elf(p_offset=0x2D30, p_vaddr=0x2D30, p_align=16384)
        rep = check(elf_fake)
        self.assertEqual(rep.status, Elf16kStatus.UNSAFE)

        valid, align, err = validate_elf_segments(elf_fake)
        self.assertFalse(valid)

        # rewrite_elf_16kb leaves it untouched and uncorrupted
        rewritten = rewrite_elf_16kb(elf_fake)
        self.assertEqual(rewritten, elf_fake)

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

            rep = check(data)
            self.assertEqual(rep.status, Elf16kStatus.COMPAT_ONLY)
            self.assertNotEqual(rep.status, Elf16kStatus.ALIGNED)

            # Leaves byte-identical
            rewritten = rewrite_elf_16kb(data)
            self.assertEqual(rewritten, data)

    def test_rewrite_apk_elfs(self):
        elf_4k = make_synthetic_64bit_elf(p_offset=0x1D30, p_vaddr=0x2D30, p_align=4096)
        with tempfile.TemporaryDirectory() as tmp_dir:
            in_apk = os.path.join(tmp_dir, "input.apk")
            out_apk = os.path.join(tmp_dir, "output.apk")

            with zipfile.ZipFile(in_apk, "w") as zf:
                zf.writestr("lib/arm64-v8a/libfoo.so", elf_4k)
                zf.writestr("assets/note.txt", b"Hello")

            modified = rewrite_apk_elfs_16kb(in_apk, out_apk)
            # 4KB-linked libraries are left untouched (not modified)
            self.assertFalse(modified)

            with zipfile.ZipFile(out_apk, "r") as zf_out:
                out_so = zf_out.read("lib/arm64-v8a/libfoo.so")
                self.assertEqual(out_so, elf_4k)
                self.assertEqual(zf_out.read("assets/note.txt"), b"Hello")


if __name__ == "__main__":
    unittest.main()
