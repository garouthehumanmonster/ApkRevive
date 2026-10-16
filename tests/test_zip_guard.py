"""test_zip_guard.py - Dedicated unit test suite for Zero-Trust ZIP Guard.

Tests:
1. Non-existent and empty files.
2. Zip Slip variations: relative path traversal (../), leading slash (/), backslash (\\),
   drive letters (C:), and embedded null bytes (\\0).
3. Symlink entry rejection (S_IFLNK 0o120000).
4. Zip bomb detection:
   - High compression ratio (>100x on >10MB payload).
   - Single file size limit (>500MB).
   - Total uncompressed archive size limit.
5. Corrupted / truncated ZIP headers.
6. Clean valid APK archive passes with zero errors.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from apkrevive.security.zip_guard import validate_zip_archive


class TestZipGuard(unittest.TestCase):
    def test_nonexistent_file_raises_filenotfound(self):
        with self.assertRaises(FileNotFoundError):
            validate_zip_archive("non_existent_archive_12345.apk")

    def test_empty_file_raises_valueerror(self):
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tf:
            tf_path = tf.name
        try:
            with self.assertRaises(ValueError) as ctx:
                validate_zip_archive(tf_path)
            self.assertIn("empty", str(ctx.exception).lower())
        finally:
            if os.path.exists(tf_path):
                os.unlink(tf_path)

    def test_zip_slip_relative_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "slip_relative.apk")
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("../../etc/cron.d/evil", b"malicious")
            with self.assertRaises(ValueError) as ctx:
                validate_zip_archive(apk_path)
            self.assertIn("Zip-slip path traversal detected", str(ctx.exception))

    def test_zip_slip_leading_forward_slash(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "slip_leading_slash.apk")
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("/root/.ssh/authorized_keys", b"malicious")
            with self.assertRaises(ValueError) as ctx:
                validate_zip_archive(apk_path)
            self.assertIn("Zip-slip path traversal detected", str(ctx.exception))

    def test_zip_slip_leading_backslash(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "slip_backslash.apk")
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("\\Windows\\System32\\cmd.exe", b"malicious")
            with self.assertRaises(ValueError) as ctx:
                validate_zip_archive(apk_path)
            self.assertIn("Zip-slip path traversal detected", str(ctx.exception))

    def test_zip_slip_windows_drive_letter(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "slip_drive.apk")
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("C:evil.txt", b"malicious")
            with self.assertRaises(ValueError) as ctx:
                validate_zip_archive(apk_path)
            self.assertIn("Zip-slip path traversal detected", str(ctx.exception))

    def test_zip_slip_null_byte(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "slip_null.apk")
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("safe.txt", b"malicious")
            fake_entry = zipfile.ZipInfo()
            fake_entry.filename = "safe.txt\x00evil.exe"
            with patch("zipfile.ZipFile.infolist", return_value=[fake_entry]):
                with self.assertRaises(ValueError) as ctx:
                    validate_zip_archive(apk_path)
                self.assertIn("Zip-slip path traversal detected", str(ctx.exception))

    def test_symlink_entry_forbidden(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "symlink.apk")
            with zipfile.ZipFile(apk_path, "w") as zf:
                zinfo = zipfile.ZipInfo("lib/arm64-v8a/liblink.so")
                # 0o120777 sets S_IFLNK (symlink file type)
                zinfo.external_attr = 0o120777 << 16
                zf.writestr(zinfo, b"/system/lib64/libc.so")
            with self.assertRaises(ValueError) as ctx:
                validate_zip_archive(apk_path)
            self.assertIn("Zip symlink entry forbidden", str(ctx.exception))

    def test_zip_bomb_high_compression_ratio(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "bomb_ratio.apk")
            with zipfile.ZipFile(apk_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                # 11MB of zeros compresses to a few hundred bytes (>1000x ratio)
                payload = b"\x00" * (11 * 1024 * 1024)
                zf.writestr("big_zeroes.bin", payload)
            with self.assertRaises(ValueError) as ctx:
                validate_zip_archive(apk_path)
            self.assertIn("high compression ratio", str(ctx.exception))

    def test_zip_bomb_single_file_exceeds_max(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "bomb_single_file.apk")
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("huge_file.dat", b"x")
            # Patch central directory header to claim 501MB size with 1.0 compression ratio
            with open(apk_path, "r+b") as f:
                data = bytearray(f.read())
                cd_idx = data.find(b"PK\x01\x02")
                import struct
                struct.pack_into("<I", data, cd_idx + 20, 501 * 1024 * 1024)
                struct.pack_into("<I", data, cd_idx + 24, 501 * 1024 * 1024)
                f.seek(0)
                f.write(data)
            with self.assertRaises(ValueError) as ctx:
                validate_zip_archive(apk_path)
            self.assertIn("exceeds maximum permitted size", str(ctx.exception))

    def test_zip_bomb_total_uncompressed_ceiling(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "bomb_total.apk")
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("part1.dat", b"x")
                zf.writestr("part2.dat", b"y")
            # Patch both entries to claim 60KB uncompressed and 60KB compressed
            with open(apk_path, "r+b") as f:
                data = bytearray(f.read())
                cd_idx1 = data.find(b"PK\x01\x02")
                cd_idx2 = data.find(b"PK\x01\x02", cd_idx1 + 4)
                import struct
                struct.pack_into("<I", data, cd_idx1 + 20, 60 * 1024)
                struct.pack_into("<I", data, cd_idx1 + 24, 60 * 1024)
                struct.pack_into("<I", data, cd_idx2 + 20, 60 * 1024)
                struct.pack_into("<I", data, cd_idx2 + 24, 60 * 1024)
                f.seek(0)
                f.write(data)

            # Validate with tiny 100KB max ceiling (total = 120KB)
            with self.assertRaises(ValueError) as ctx:
                validate_zip_archive(apk_path, max_uncompressed_bytes=100 * 1024)
            self.assertIn("total uncompressed size exceeds limit", str(ctx.exception))

    def test_corrupted_truncated_archive(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "corrupt.apk")
            with open(apk_path, "wb") as f:
                f.write(b"PK\x03\x04" + os.urandom(15))
            with self.assertRaises(ValueError) as ctx:
                validate_zip_archive(apk_path)
            self.assertIn("Truncated ZIP archive", str(ctx.exception))

    def test_valid_archive_passes(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "clean.apk")
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("AndroidManifest.xml", b"<manifest/>")
                zf.writestr("classes.dex", b"dex\n035\0")
                zf.writestr("res/values/strings.xml", b"<resources/>")
            # Should pass cleanly without raising
            validate_zip_archive(apk_path)


if __name__ == "__main__":
    unittest.main()
