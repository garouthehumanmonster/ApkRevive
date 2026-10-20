"""
test_elf16k.py - Unit tests for 16KB ELF verification and three-state classification.
Enforces:
- ALIGNED: p_align >= 16KB, 16KB congruence, distinct 16KB pages.
- COMPAT_ONLY: valid 4KB-linked ELF, leaves binary byte-identical, requires pageSizeCompat.
- UNSAFE: incongruent, corrupted, or fake header-patched sharing 16KB pages.
"""

import os
import shutil
import struct
import subprocess
import tempfile
import unittest
import pytest

from apkrevive.core.elf16k import check, fix, Elf16kStatus, Elf16kReport
from apkrevive.core.elf_surgeon import rewrite_elf_16kb


def build_synthetic_elf(
    segments,
    machine: int = 183,  # EM_AARCH64
) -> bytes:
    """
    segments: list of dicts with:
      p_offset, p_vaddr, p_filesz, p_memsz, p_align, p_flags
    """
    endian = "<"
    ident = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8)
    e_phnum = len(segments)
    e_phentsize = 56
    e_phoff = 64
    header = struct.pack(
        f"{endian}HHIQQQIHHHHHH",
        3, machine, 1, 0x1000, e_phoff, 0, 0, 64, e_phentsize, e_phnum, 64, 0, 0
    )
    elf_hdr = ident + header

    ph_bytes = bytearray()
    max_offset = e_phoff + (e_phnum * e_phentsize)

    for seg in segments:
        p_type = 1  # PT_LOAD
        p_flags = seg.get("p_flags", 5)
        p_offset = seg["p_offset"]
        p_vaddr = seg["p_vaddr"]
        p_paddr = p_vaddr
        p_filesz = seg.get("p_filesz", 0x1000)
        p_memsz = seg.get("p_memsz", p_filesz)
        p_align = seg.get("p_align", 4096)
        ph_bytes.extend(
            struct.pack(
                f"{endian}IIQQQQQQ",
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align
            )
        )
        if p_offset + p_filesz > max_offset:
            max_offset = p_offset + p_filesz

    data = bytearray(elf_hdr + ph_bytes)
    if len(data) < max_offset:
        data.extend(b"\x00" * (max_offset - len(data)))
    return bytes(data)


def find_c_compiler():
    """Finds a C compiler that produces 64-bit ELF shared libraries."""
    # Check for Android NDK clang first
    candidates = [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk") if os.environ.get("LOCALAPPDATA") else None,
        os.path.expanduser("~/Library/Android/sdk"),
        os.path.expanduser("~/Android/Sdk"),
    ]
    for c in candidates:
        if c and os.path.isdir(c):
            ndk_dir = os.path.join(c, "ndk")
            if os.path.isdir(ndk_dir):
                for v in sorted(os.listdir(ndk_dir), reverse=True):
                    llvm_bin = os.path.join(ndk_dir, v, "toolchains", "llvm", "prebuilt", "windows-x86_64", "bin")
                    if os.path.isdir(llvm_bin):
                        clang_cand = os.path.join(llvm_bin, "x86_64-linux-android35-clang.cmd")
                        if os.path.isfile(clang_cand):
                            return clang_cand
                        clang_cand2 = os.path.join(llvm_bin, "x86_64-linux-android35-clang")
                        if os.path.isfile(clang_cand2):
                            return clang_cand2

    # Check system gcc / clang
    for name in ["gcc", "clang"]:
        p = shutil.which(name)
        if p:
            return p
    return None


class TestElf16k(unittest.TestCase):
    def test_4k_linked_so_evaluates_compat_only_never_aligned(self):
        # 4KB-linked ELF: segments separated by 4KB, p_align = 4096
        so_4k = build_synthetic_elf([
            {"p_offset": 0x0000, "p_vaddr": 0x0000, "p_filesz": 0x0800, "p_memsz": 0x0800, "p_align": 4096, "p_flags": 5},
            {"p_offset": 0x1000, "p_vaddr": 0x1000, "p_filesz": 0x0400, "p_memsz": 0x0400, "p_align": 4096, "p_flags": 6},
        ])
        rep = check(so_4k)
        self.assertIsInstance(rep, Elf16kReport)
        self.assertEqual(rep.status, Elf16kStatus.COMPAT_ONLY)
        self.assertNotEqual(rep.status, Elf16kStatus.ALIGNED)

        # Calling fix() leaves such a .so byte-identical and reports why
        fixed, problems = fix(so_4k)
        self.assertEqual(fixed, so_4k)
        self.assertTrue(len(problems) > 0)
        self.assertTrue(any("relink" in p.lower() or "compat" in p.lower() for p in problems))

        # rewrite_elf_16kb leaves it byte-identical
        rewritten = rewrite_elf_16kb(so_4k)
        self.assertEqual(rewritten, so_4k)

    def test_16k_aligned_so_evaluates_aligned_and_untouched(self):
        # 16KB-aligned ELF: segments start on distinct 16KB pages, p_align = 16384
        so_16k = build_synthetic_elf([
            {"p_offset": 0x0000, "p_vaddr": 0x0000, "p_filesz": 0x2000, "p_memsz": 0x2000, "p_align": 16384, "p_flags": 5},
            {"p_offset": 0x4000, "p_vaddr": 0x4000, "p_filesz": 0x1000, "p_memsz": 0x1000, "p_align": 16384, "p_flags": 6},
        ])
        rep = check(so_16k)
        self.assertEqual(rep.status, Elf16kStatus.ALIGNED)
        self.assertEqual(len(rep.reasons), 0)

        fixed, problems = fix(so_16k)
        self.assertEqual(fixed, so_16k)
        self.assertEqual(len(problems), 0)

        rewritten = rewrite_elf_16kb(so_16k)
        self.assertEqual(rewritten, so_16k)

    def test_unsafe_fake_16kb_header_patch_with_shared_page(self):
        # Unsafe fake patch: p_align raised to 16KB, but segment 0 (0x0) and segment 1 (0x2000)
        # share the same 16KB page [0x0, 0x4000). On a 16KB kernel, MAP_FIXED collides.
        so_fake_patch = build_synthetic_elf([
            {"p_offset": 0x0000, "p_vaddr": 0x0000, "p_filesz": 0x1000, "p_memsz": 0x1000, "p_align": 16384, "p_flags": 5},
            {"p_offset": 0x2000, "p_vaddr": 0x2000, "p_filesz": 0x0800, "p_memsz": 0x0800, "p_align": 16384, "p_flags": 6},
        ])
        rep = check(so_fake_patch)
        self.assertEqual(rep.status, Elf16kStatus.UNSAFE)
        self.assertTrue(any("page" in r.lower() or "collide" in r.lower() or "overlap" in r.lower() for r in rep.reasons))

        fixed, problems = fix(so_fake_patch)
        self.assertEqual(fixed, so_fake_patch)
        self.assertTrue(len(problems) > 0)

    def test_unsafe_incongruent_elf(self):
        # Unsafe incongruent: (p_vaddr % p_align) != (p_offset % p_align)
        so_incongruent = build_synthetic_elf([
            {"p_offset": 0x1000, "p_vaddr": 0x2500, "p_filesz": 0x0500, "p_memsz": 0x0500, "p_align": 4096, "p_flags": 5},
        ])
        rep = check(so_incongruent)
        self.assertEqual(rep.status, Elf16kStatus.UNSAFE)

    def test_32bit_elf_untouched(self):
        elf32 = b"\x7fELF\x01\x01\x01\x00" + (b"\x00" * 40)
        fixed, problems = fix(elf32)
        self.assertEqual(fixed, elf32)

    @pytest.mark.integration
    def test_real_compiled_4k_so_if_compiler_available(self):
        compiler = find_c_compiler()
        if not compiler:
            self.skipTest("No suitable C compiler / NDK clang found")

        with tempfile.TemporaryDirectory() as td:
            c_file = os.path.join(td, "libfoo.c")
            with open(c_file, "w") as f:
                f.write("int foo(int x) { return x * 2; }\n")

            so_path = os.path.join(td, "libfoo.so")
            cmd = [compiler, "-shared", "-fPIC", "-Wl,-z,max-page-size=4096", c_file, "-o", so_path]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0:
                self.skipTest(f"Compiler failed to build shared object: {res.stderr}")

            so_bytes = open(so_path, "rb").read()
            if not so_bytes.startswith(b"\x7fELF"):
                self.skipTest("Target compiler produced non-ELF binary (e.g. PE/COFF)")

            rep = check(so_bytes)
            self.assertEqual(rep.status, Elf16kStatus.COMPAT_ONLY)
            self.assertNotEqual(rep.status, Elf16kStatus.ALIGNED)

            fixed, problems = fix(so_bytes)
            self.assertEqual(fixed, so_bytes)
            self.assertTrue(len(problems) > 0)


if __name__ == "__main__":
    unittest.main()
