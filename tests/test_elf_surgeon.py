"""
test_elf_surgeon.py - Unit tests for 16KB ELF Segment Rewriter and elf16k integration.
Validates:
- 4KB-linked ELFs evaluate to COMPAT_ONLY (never ALIGNED) and rewrite_elf_16kb leaves them byte-identical.
- ALIGNED ELFs evaluate to ALIGNED and remain untouched.
- UNSAFE ELFs (fake header patches sharing 16KB pages, incongruent offsets) are flagged and not claimed fixed.
- 32-bit ELFs are exempt and untouched.
- audit_elf_16kb accurately detects modulo congruence and page collisions.
- get_elf_needed parses DT_NEEDED libraries in 32-bit and 64-bit ELFs.
- patch_apk_native_libs reports private Bionic dependencies honestly without injecting fake stubs.
"""

import os
import struct
import tempfile
import unittest
import zipfile

from apkrevive.core.elf16k import check, fix, Elf16kStatus
from apkrevive.core.elf_surgeon import (
    rewrite_elf_16kb,
    rewrite_apk_elfs_16kb,
    patch_apk_native_libs,
    audit_elf_16kb,
    get_elf_needed,
    PRIVATE_BIONIC_LIBS,
)
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
        self.assertEqual(align, 16384)

    def test_unsafe_header_patched_elf_rejected(self):
        # Both segments share the same 16KB page [0, 0x4000)
        endian = "<"
        ident = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
        header = struct.pack(
            f"{endian}HHIQQQIHHHHHH",
            3, 183, 1, 0x1000, 64, 0, 0, 64, 56, 2, 64, 0, 0
        )
        elf_hdr = ident + header

        ph0 = struct.pack(f"{endian}IIQQQQQQ", 1, 5, 0x0000, 0x0000, 0x0000, 0x1000, 0x1000, 16384)
        ph1 = struct.pack(f"{endian}IIQQQQQQ", 1, 6, 0x2000, 0x2000, 0x2000, 0x0800, 0x0800, 16384)

        data = bytearray(elf_hdr + ph0 + ph1)
        if len(data) < 0x2800:
            data.extend(b"\x00" * (0x2800 - len(data)))
        elf_unsafe = bytes(data)

        rep = check(elf_unsafe)
        self.assertNotEqual(rep.status, Elf16kStatus.ALIGNED)
        self.assertEqual(rep.status, Elf16kStatus.UNSAFE)

        rewritten = rewrite_elf_16kb(elf_unsafe)
        self.assertEqual(rewritten, elf_unsafe)

    def test_32bit_elf_exempt(self):
        endian = "<"
        ident = b"\x7fELF\x01\x01\x01\x00" + (b"\x00" * 8)
        header = struct.pack(
            f"{endian}HHIIIIIHHHHHH",
            3, 40, 1, 0x1000, 52, 0, 0, 52, 32, 2, 0, 0, 0  # EM_ARM
        )
        elf_hdr = ident + header

        ph0 = struct.pack(f"{endian}IIIIIIII", 1, 0, 0, 0, 0x800, 0x800, 5, 4096)
        ph1 = struct.pack(f"{endian}IIIIIIII", 1, 0x800, 0x800, 0x800, 0x400, 0x400, 6, 4096)

        data = bytearray(elf_hdr + ph0 + ph1)
        if len(data) < 0xC00:
            data.extend(b"\x00" * (0xC00 - len(data)))
        elf_32 = bytes(data)

        rep = check(elf_32)
        self.assertEqual(rep.status, Elf16kStatus.EXEMPT)

        rewritten = rewrite_elf_16kb(elf_32)
        self.assertEqual(rewritten, elf_32)

    def test_audit_elf_16kb(self):
        # 64-bit aligned ELF passes audit
        elf_aligned = make_aligned_16kb_elf()
        ok, issues = audit_elf_16kb(elf_aligned)
        self.assertTrue(ok)
        self.assertEqual(issues, [])

        # 64-bit incongruent ELF fails audit
        elf_4k = make_synthetic_64bit_elf(p_offset=0x1D30, p_vaddr=0x2D30, p_align=4096)
        ok, issues = audit_elf_16kb(elf_4k)
        self.assertFalse(ok)
        self.assertTrue(any("incongruent" in iss for iss in issues))

        # 32-bit ELF is exempt
        endian = "<"
        ident = b"\x7fELF\x01\x01\x01\x00" + (b"\x00" * 8)
        header = struct.pack(f"{endian}HHIIIIIHHHHHH", 3, 40, 1, 0, 52, 0, 0, 52, 32, 1, 0, 0, 0)
        ph = struct.pack(f"{endian}IIIIIIII", 1, 0, 0, 0, 0x100, 0x100, 5, 4096)
        elf_32 = bytes(ident + header + ph)
        ok, issues = audit_elf_16kb(elf_32)
        self.assertTrue(ok)
        self.assertTrue(any("exempt" in iss for iss in issues))

    def test_get_elf_needed_64bit_and_32bit(self):
        # 64-bit ELF with DT_NEEDED for libcrypto.so and libc.so
        strtab = b"\x00libcrypto.so\x00libc.so\x00"
        dyn_entries = [(1, 1), (1, 14), (5, 0x300), (10, len(strtab)), (0, 0)]
        dyn_data = b"".join(struct.pack("<QQ", t, v) for t, v in dyn_entries)
        filesz = 0x300 + len(strtab)
        p0 = struct.pack("<IIQQQQQQ", 1, 6, 0, 0, 0, filesz, filesz, 0x4000)
        p1 = struct.pack("<IIQQQQQQ", 2, 6, 0x100, 0x100, 0x100, len(dyn_data), len(dyn_data), 8)
        ehdr = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01\x00" + b"\x00"*8, 3, 183, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        blob = bytearray(ehdr + p0 + p1)
        blob.extend(b"\x00" * (0x100 - len(blob)))
        blob.extend(dyn_data)
        blob.extend(b"\x00" * (0x300 - len(blob)))
        blob.extend(strtab)
        needed_64 = get_elf_needed(bytes(blob))
        self.assertEqual(needed_64, ["libcrypto.so", "libc.so"])

        # 32-bit ELF with DT_NEEDED for libssl.so
        strtab32 = b"\x00libssl.so\x00"
        dyn_entries32 = [(1, 1), (5, 0x180), (10, len(strtab32)), (0, 0)]
        dyn_data32 = b"".join(struct.pack("<II", t, v) for t, v in dyn_entries32)
        filesz32 = 0x180 + len(strtab32)
        p0_32 = struct.pack("<IIIIIIII", 1, 0, 0, 0, filesz32, filesz32, 6, 0x1000)
        p1_32 = struct.pack("<IIIIIIII", 2, 0x80, 0x80, 0x80, len(dyn_data32), len(dyn_data32), 6, 4)
        ehdr32 = struct.pack("<16sHHIIIIIHHHHHH", b"\x7fELF\x01\x01\x01\x00" + b"\x00"*8, 3, 40, 1, 0, 52, 0, 0, 52, 32, 2, 0, 0, 0)
        blob32 = bytearray(ehdr32 + p0_32 + p1_32)
        blob32.extend(b"\x00" * (0x80 - len(blob32)))
        blob32.extend(dyn_data32)
        blob32.extend(b"\x00" * (0x180 - len(blob32)))
        blob32.extend(strtab32)
        needed_32 = get_elf_needed(bytes(blob32))
        self.assertEqual(needed_32, ["libssl.so"])

    def test_patch_apk_native_libs_bionic_audit_and_warning(self):
        # Build 64-bit ELF needing libcrypto.so
        strtab = b"\x00libcrypto.so\x00"
        dyn_entries = [(1, 1), (5, 0x300), (10, len(strtab)), (0, 0)]
        dyn_data = b"".join(struct.pack("<QQ", t, v) for t, v in dyn_entries)
        filesz = 0x300 + len(strtab)
        p0 = struct.pack("<IIQQQQQQ", 1, 6, 0, 0, 0, filesz, filesz, 0x4000)
        p1 = struct.pack("<IIQQQQQQ", 2, 6, 0x100, 0x100, 0x100, len(dyn_data), len(dyn_data), 8)
        ehdr = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01\x00" + b"\x00"*8, 3, 183, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        blob = bytearray(ehdr + p0 + p1)
        blob.extend(b"\x00" * (0x100 - len(blob)))
        blob.extend(dyn_data)
        blob.extend(b"\x00" * (0x300 - len(blob)))
        blob.extend(strtab)
        orig_so = bytes(blob)

        with tempfile.TemporaryDirectory() as tmp_dir:
            in_apk = os.path.join(tmp_dir, "test_input.apk")
            out_apk = os.path.join(tmp_dir, "test_output.apk")

            with zipfile.ZipFile(in_apk, "w") as zf:
                zf.writestr("lib/arm64-v8a/libmain.so", orig_so)

            modified, remediations = patch_apk_native_libs(in_apk, out_apk)
            # Private Bionic library reported truthfully
            self.assertTrue(any("libcrypto.so" in r for r in remediations))
            self.assertTrue(any("Bionic Linker" in r for r in remediations))

            # No fake stubs injected
            with zipfile.ZipFile(out_apk, "r") as zf_out:
                entries = zf_out.namelist()
                self.assertNotIn("lib/arm64-v8a/libkrypto.so", entries)


if __name__ == "__main__":
    unittest.main()
