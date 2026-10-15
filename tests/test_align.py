"""
test_align.py - Tests 16KB boundary alignment and ELF p_align parser.
"""

import os
import struct
import tempfile
import unittest
import zipfile
from apkrevive.core.elf import parse_elf_load_align
from apkrevive.core.align import align_apk, verify_apk_alignment


class TestAlign(unittest.TestCase):
    def test_elf_parser_4kb_and_16kb(self):
        def make_elf(align: int) -> bytes:
            hdr = bytearray(b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8))
            hdr += struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x4000, 0x40, 0, 0, 64, 56, 1, 0, 0, 0)
            ph = struct.pack("<IIQQQQQQ", 1, 7, 0, 0x4000, 0x4000, 0x1000, 0x1000, align)
            return bytes(hdr + ph)

        self.assertEqual(parse_elf_load_align(make_elf(4096)), 4096)
        self.assertEqual(parse_elf_load_align(make_elf(16384)), 16384)

    def test_zip_alignment(self):
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f_in, tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f_out:
            in_path = f_in.name
            out_path = f_out.name

        with zipfile.ZipFile(in_path, "w") as zf:
            zf.writestr(zipfile.ZipInfo("resources.arsc"), b"DATA" * 500)
            zf.writestr(zipfile.ZipInfo("lib/arm64-v8a/libtest.so"), b"ELF_DATA" * 500)

        align_apk(in_path, out_path)
        res = verify_apk_alignment(out_path)
        self.assertTrue(res["aligned"])
        self.assertEqual(res["entries"]["resources.arsc"]["required_align"], 4096)
        self.assertEqual(res["entries"]["lib/arm64-v8a/libtest.so"]["required_align"], 16384)

    def test_zip_alignment_streamed_chunking(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            in_path = os.path.join(tmp_dir, "input.apk")
            out_path = os.path.join(tmp_dir, "output.apk")

            # Entry exceeding 64KB (tests multiple CHUNK_SIZE iterations)
            large_so_data = b"V8A_SO_" * (25 * 1024)  # ~175KB
            x86_so_data = b"X86_SO_" * (10 * 1024)   # ~70KB
            v7a_so_data = b"V7A_SO_" * 1000          # ~7KB
            arsc_data = b"ARSC_DATA" * 1000          # ~9KB
            deflated_data = b"COMPRESSED_PAYLOAD_" * 5000

            with zipfile.ZipFile(in_path, "w") as zf:
                # 64-bit arm64-v8a .so uncompressed (16KB aligned)
                zinfo_arm64 = zipfile.ZipInfo("lib/arm64-v8a/liblarge.so")
                zinfo_arm64.compress_type = zipfile.ZIP_STORED
                zf.writestr(zinfo_arm64, large_so_data)

                # 64-bit x86_64 .so uncompressed (16KB aligned)
                zinfo_x86_64 = zipfile.ZipInfo("lib/x86_64/libx86.so")
                zinfo_x86_64.compress_type = zipfile.ZIP_STORED
                zf.writestr(zinfo_x86_64, x86_so_data)

                # 32-bit armeabi-v7a .so uncompressed (4KB aligned)
                zinfo_v7a = zipfile.ZipInfo("lib/armeabi-v7a/libv7a.so")
                zinfo_v7a.compress_type = zipfile.ZIP_STORED
                zf.writestr(zinfo_v7a, v7a_so_data)

                # resources.arsc uncompressed (4KB aligned)
                zinfo_arsc = zipfile.ZipInfo("resources.arsc")
                zinfo_arsc.compress_type = zipfile.ZIP_STORED
                zf.writestr(zinfo_arsc, arsc_data)

                # Deflated entry (4-byte aligned, skipped in 4KB/16KB align checks)
                zf.writestr("assets/compressed.dat", deflated_data, compress_type=zipfile.ZIP_DEFLATED)

            align_apk(in_path, out_path)

            res = verify_apk_alignment(out_path)
            self.assertTrue(res["aligned"])
            self.assertEqual(res["entries"]["lib/arm64-v8a/liblarge.so"]["required_align"], 16384)
            self.assertEqual(res["entries"]["lib/x86_64/libx86.so"]["required_align"], 16384)
            self.assertEqual(res["entries"]["lib/armeabi-v7a/libv7a.so"]["required_align"], 4096)
            self.assertEqual(res["entries"]["resources.arsc"]["required_align"], 4096)

            for name, entry in res["entries"].items():
                self.assertTrue(entry["aligned"], f"{name} is not aligned")
                self.assertEqual(entry["offset"] % entry["required_align"], 0)

            with zipfile.ZipFile(out_path, "r") as zf_out:
                self.assertIsNone(zf_out.testzip())
                self.assertEqual(zf_out.read("lib/arm64-v8a/liblarge.so"), large_so_data)
                self.assertEqual(zf_out.read("lib/x86_64/libx86.so"), x86_so_data)
                self.assertEqual(zf_out.read("lib/armeabi-v7a/libv7a.so"), v7a_so_data)
                self.assertEqual(zf_out.read("resources.arsc"), arsc_data)
                self.assertEqual(zf_out.read("assets/compressed.dat"), deflated_data)

    def test_empty_zip_handling(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            empty_path = os.path.join(tmp_dir, "empty.apk")
            with open(empty_path, "wb"):
                pass
            with self.assertRaises(ValueError):
                align_apk(empty_path, os.path.join(tmp_dir, "out.apk"))
            with self.assertRaises(ValueError):
                verify_apk_alignment(empty_path)

    def test_verify_unaligned_entry(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "unaligned.apk")
            with zipfile.ZipFile(apk_path, "w") as zf:
                zinfo = zipfile.ZipInfo("resources.arsc")
                zinfo.compress_type = zipfile.ZIP_STORED
                zf.writestr(zinfo, b"DATA")
            res = verify_apk_alignment(apk_path)
            self.assertFalse(res["aligned"])
            self.assertFalse(res["entries"]["resources.arsc"]["aligned"])


if __name__ == "__main__":
    unittest.main()
