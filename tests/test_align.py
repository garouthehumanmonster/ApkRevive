"""
test_align.py - Tests 16KB boundary alignment and ELF p_align parser.
"""

import io
import os
import struct
import tempfile
import unittest
import zipfile
from apkrevive.core.elf import parse_elf_load_align
from apkrevive.core.align import align_apk, verify_apk_alignment, UnsupportedZip64Error


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

    def test_align_preserves_archive_comment(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            in_path = os.path.join(tmp_dir, "input.apk")
            out_path = os.path.join(tmp_dir, "output.apk")
            with zipfile.ZipFile(in_path, "w") as zf:
                zinfo = zipfile.ZipInfo("resources.arsc")
                zinfo.compress_type = zipfile.ZIP_STORED
                zf.writestr(zinfo, b"DATA" * 50)
                zf.comment = b"archive_comment_test"

            align_apk(in_path, out_path)
            with zipfile.ZipFile(out_path, "r") as zf_out:
                self.assertEqual(zf_out.comment, b"archive_comment_test")
            res = verify_apk_alignment(out_path)
            self.assertTrue(res["aligned"])

    def test_align_preserves_lfh_extra_field(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            in_path = os.path.join(tmp_dir, "input.apk")
            out_path = os.path.join(tmp_dir, "output.apk")
            custom_extra = struct.pack("<HH", 0x7075, 5) + b"test1"
            with zipfile.ZipFile(in_path, "w") as zf:
                zinfo = zipfile.ZipInfo("resources.arsc")
                zinfo.compress_type = zipfile.ZIP_STORED
                zinfo.extra = custom_extra
                zf.writestr(zinfo, b"SAMPLE_PAYLOAD_FOR_ALIGNMENT" * 10)

            align_apk(in_path, out_path)

            with open(out_path, "rb") as f_out:
                out_buf = f_out.read()

            self.assertEqual(out_buf[:4], b"PK\x03\x04")
            fn_len, ef_len = struct.unpack_from("<HH", out_buf, 26)
            lfh_extra = out_buf[30 + fn_len : 30 + fn_len + ef_len]

            self.assertIn(custom_extra, lfh_extra)
            self.assertIn(struct.pack("<H", 0xD935), lfh_extra)

            with zipfile.ZipFile(out_path, "r") as zf_out:
                self.assertIsNone(zf_out.testzip())
                self.assertEqual(zf_out.read("resources.arsc"), b"SAMPLE_PAYLOAD_FOR_ALIGNMENT" * 10)
            res = verify_apk_alignment(out_path)
            self.assertTrue(res["aligned"])

    def test_align_data_descriptor_survives(self):
        class NonSeekableStream(io.RawIOBase):
            def __init__(self):
                self.buf = bytearray()

            def write(self, b):
                self.buf.extend(b)
                return len(b)

            def seekable(self):
                return False

            def writable(self):
                return True

        with tempfile.TemporaryDirectory() as tmp_dir:
            in_path = os.path.join(tmp_dir, "input.apk")
            out_path = os.path.join(tmp_dir, "output.apk")

            stream = NonSeekableStream()
            with zipfile.ZipFile(stream, "w") as zf:
                zinfo = zipfile.ZipInfo("resources.arsc")
                zinfo.compress_type = zipfile.ZIP_STORED
                zf.writestr(zinfo, b"STORED_DATA_WITH_DESCRIPTOR" * 20)
                zf.writestr("compressed.txt", b"COMPRESSED_DATA" * 50, compress_type=zipfile.ZIP_DEFLATED)

            data = bytes(stream.buf)
            flags = struct.unpack_from("<H", data, 6)[0]
            self.assertTrue(flags & 0x0008)
            self.assertIn(b"PK\x07\x08", data)

            with open(in_path, "wb") as f_in:
                f_in.write(data)

            align_apk(in_path, out_path)

            with zipfile.ZipFile(out_path, "r") as zf_out:
                self.assertIsNone(zf_out.testzip())
                self.assertEqual(zf_out.read("resources.arsc"), b"STORED_DATA_WITH_DESCRIPTOR" * 20)
                self.assertEqual(zf_out.read("compressed.txt"), b"COMPRESSED_DATA" * 50)

            res = verify_apk_alignment(out_path)
            self.assertTrue(res["aligned"])

    def test_align_rejects_zip64(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            locator_path = os.path.join(tmp_dir, "zip64_locator.apk")
            out_path = os.path.join(tmp_dir, "out.apk")

            bio = io.BytesIO()
            with zipfile.ZipFile(bio, "w") as zf:
                zf.writestr("test.txt", b"hello zip64")
            raw = bytearray(bio.getvalue())
            eocd_pos = raw.rfind(b"PK\x05\x06")
            cd_count, cd_size, cd_offset = struct.unpack_from("<HII", raw, eocd_pos + 10)
            zip64endrec = struct.pack("<4sQ2H2I4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, cd_count, cd_count, cd_size, cd_offset)
            zip64locrec = struct.pack("<4sIQI", b"PK\x06\x07", 0, eocd_pos, 1)
            data_locator = raw[:eocd_pos] + zip64endrec + zip64locrec + raw[eocd_pos:]

            with open(locator_path, "wb") as f:
                f.write(data_locator)

            with self.assertRaises(UnsupportedZip64Error):
                align_apk(locator_path, out_path)

            with self.assertRaises(UnsupportedZip64Error):
                verify_apk_alignment(locator_path)

            entries_path = os.path.join(tmp_dir, "zip64_entries.apk")
            data_entries = bytearray(data_locator)
            eocd_new_pos = data_entries.rfind(b"PK\x05\x06")
            struct.pack_into("<H", data_entries, eocd_new_pos + 8, 0xFFFF)
            struct.pack_into("<H", data_entries, eocd_new_pos + 10, 0xFFFF)

            with open(entries_path, "wb") as f:
                f.write(data_entries)

            with self.assertRaises(UnsupportedZip64Error):
                align_apk(entries_path, out_path)

            with self.assertRaises(UnsupportedZip64Error):
                verify_apk_alignment(entries_path)

    def test_verify_alignment_fails_closed_on_truncated(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            trunc_lfh_path = os.path.join(tmp_dir, "trunc_lfh.apk")
            bio = io.BytesIO()
            with zipfile.ZipFile(bio, "w") as zf:
                zinfo = zipfile.ZipInfo("resources.arsc")
                zinfo.compress_type = zipfile.ZIP_STORED
                zf.writestr(zinfo, b"DATA" * 50)
            data = bytearray(bio.getvalue())
            eocd_pos = data.rfind(b"PK\x05\x06")
            cd_offset = struct.unpack_from("<I", data, eocd_pos + 16)[0]
            struct.pack_into("<I", data, cd_offset + 42, len(data) + 100)
            with open(trunc_lfh_path, "wb") as f:
                f.write(data)

            with self.assertRaises(ValueError) as ctx:
                verify_apk_alignment(trunc_lfh_path)
            self.assertEqual(str(ctx.exception), "Truncated ZIP archive entry")

            trunc_file_path = os.path.join(tmp_dir, "trunc_file.apk")
            with open(trunc_file_path, "wb") as f:
                f.write(bio.getvalue()[: len(bio.getvalue()) - 10])

            with self.assertRaises(ValueError) as ctx:
                verify_apk_alignment(trunc_file_path)
            self.assertTrue(str(ctx.exception).startswith("Truncated ZIP archive entry"))


if __name__ == "__main__":
    unittest.main()
