"""
test_align.py - Tests 16KB boundary alignment and ELF p_align parser.
"""

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


if __name__ == "__main__":
    unittest.main()
