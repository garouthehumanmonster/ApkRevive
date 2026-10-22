"""
test_verify.py - Unit and integration tests for verify.py post-patch verification engine.
"""

import io
import json
import os
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib
import hashlib

from apkrevive.core.axml import AxmlSurgeon, AxmlNode
from apkrevive.core.align import align_apk
from apkrevive.core.verify import (
    verify_apk_integrity,
)
from apkrevive.cli import main, format_verification_report


def create_synthetic_dex(class_descriptors: list) -> bytes:
    """Creates a valid, conforming Dalvik Executable (DEX) binary containing class definitions."""
    magic = b"dex\n035\x00"
    num_classes = len(class_descriptors)

    header_size = 0x70  # 112 bytes
    string_ids_off = header_size
    string_ids_size = num_classes
    type_ids_off = string_ids_off + (num_classes * 4)
    type_ids_size = num_classes
    class_defs_off = type_ids_off + (num_classes * 4)
    class_defs_size = num_classes
    data_off = class_defs_off + (num_classes * 32)

    string_data_items = []
    for s in class_descriptors:
        s_bytes = s.encode("utf-8")
        uleb = bytes([len(s)])
        string_data_items.append(uleb + s_bytes + b"\x00")

    string_data_offsets = []
    curr_str_off = data_off
    for s_item in string_data_items:
        string_data_offsets.append(curr_str_off)
        curr_str_off += len(s_item)

    file_size = curr_str_off
    data_size = file_size - data_off

    buf = bytearray(file_size)

    for i, off in enumerate(string_data_offsets):
        struct.pack_into("<I", buf, string_ids_off + i * 4, off)

    for i in range(num_classes):
        struct.pack_into("<I", buf, type_ids_off + i * 4, i)

    for i in range(num_classes):
        c_off = class_defs_off + i * 32
        struct.pack_into(
            "<IIIIIIII",
            buf,
            c_off,
            i,          # class_idx
            0x0001,     # access_flags
            0xFFFFFFFF, # superclass_idx
            0,          # interfaces_off
            0xFFFFFFFF, # source_file_idx
            0,          # annotations_off
            0,          # class_data_off
            0,          # static_values_off
        )

    for off, s_item in zip(string_data_offsets, string_data_items):
        buf[off : off + len(s_item)] = s_item

    buf[0:8] = magic
    struct.pack_into("<I", buf, 0x20, file_size)
    struct.pack_into("<I", buf, 0x24, header_size)
    struct.pack_into("<I", buf, 0x28, 0x12345678)
    struct.pack_into("<II", buf, 0x38, string_ids_size, string_ids_off)
    struct.pack_into("<II", buf, 0x40, type_ids_size, type_ids_off)
    struct.pack_into("<II", buf, 0x60, class_defs_size, class_defs_off)
    struct.pack_into("<II", buf, 0x68, data_size, data_off)

    sha1 = hashlib.sha1(buf[32:]).digest()
    buf[12:32] = sha1

    adler = zlib.adler32(buf[12:]) & 0xFFFFFFFF
    struct.pack_into("<I", buf, 8, adler)

    return bytes(buf)


def add_synthetic_signing_block(raw_zip_bytes: bytes) -> bytes:
    """
    Appends an APK Signing Block with Verity Padding (0x42726577)
    and ensures the Central Directory is 4096-byte aligned.
    """
    eocd_pos = raw_zip_bytes.rfind(b"PK\x05\x06")
    if eocd_pos == -1:
        raise ValueError("Invalid ZIP: EOCD not found")
    cd_entries, cd_size, cd_offset = struct.unpack_from("<HII", raw_zip_bytes, eocd_pos + 10)

    entries_part = raw_zip_bytes[:cd_offset]
    cd_part = raw_zip_bytes[cd_offset:eocd_pos]
    eocd_part = bytearray(raw_zip_bytes[eocd_pos:])

    current_end = len(entries_part)
    min_target = current_end + 44
    target_cd = ((min_target + 4095) // 4096) * 4096
    total_block_len = target_cd - current_end
    payload_pairs_len = total_block_len - 32
    value_len = payload_pairs_len - 12

    pair_bytes = struct.pack("<QI", value_len + 4, 0x42726577) + (b"\x00" * value_len)
    block_size = len(pair_bytes) + 24

    sig_block = (
        struct.pack("<Q", block_size)
        + pair_bytes
        + struct.pack("<Q", block_size)
        + b"APK Sig Block 42"
    )

    struct.pack_into("<I", eocd_part, 16, target_cd)
    return entries_part + sig_block + cd_part + bytes(eocd_part)


def build_test_apk(
    path: str,
    manifest_bytes: bytes = None,
    dex_map: dict = None,
    stored_entries: dict = None,
    with_align: bool = True,
    with_signature: bool = True,
) -> None:
    """Builds a test APK archive with customizable manifest, DEX entries, and signing."""
    if manifest_bytes is None:
        manifest = AxmlNode(tag="manifest")
        manifest.set_attr("package", "com.apkrevive.testapp", ns="")
        app = AxmlNode(tag="application")
        manifest.children.append(app)
        manifest_bytes = AxmlSurgeon.serialize(manifest)

    if dex_map is None:
        dex_map = {
            "classes.dex": ["Lcom/apkrevive/testapp/MainActivity;"],
            "classes2.dex": ["Lcom/apkrevive/testapp/Helper;"],
        }

    raw_buf = io.BytesIO()
    with zipfile.ZipFile(raw_buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_bytes)
        for dex_name, classes in dex_map.items():
            if isinstance(classes, bytes):
                zf.writestr(dex_name, classes)
            else:
                zf.writestr(dex_name, create_synthetic_dex(classes))
        if stored_entries:
            for name, content in stored_entries.items():
                zinfo = zipfile.ZipInfo(name)
                zinfo.compress_type = zipfile.ZIP_STORED
                zf.writestr(zinfo, content)

    raw_data = raw_buf.getvalue()

    if with_align:
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f_tmp:
            tmp_unaligned = f_tmp.name
        with open(tmp_unaligned, "wb") as f:
            f.write(raw_data)
        aligned_path = path + ".aligned.tmp"
        align_apk(tmp_unaligned, aligned_path)
        with open(aligned_path, "rb") as f:
            aligned_data = f.read()
        os.remove(tmp_unaligned)
        os.remove(aligned_path)
        final_data = aligned_data
    else:
        final_data = raw_data

    if with_signature:
        final_data = add_synthetic_signing_block(final_data)

    with open(path, "wb") as f:
        f.write(final_data)


class TestVerify(unittest.TestCase):

    def test_verify_passes_on_valid_apk(self):
        """Creates a synthetic aligned, signed, contiguous-dex APK and asserts verify returns is_valid=True and exit code 0."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "valid.apk")
            build_test_apk(apk_path, with_align=True, with_signature=True)

            with patch("apkrevive.core.verify.verify_apk_certs", return_value=(True, "Verified signature")):
                report = verify_apk_integrity(apk_path)
                self.assertTrue(report.is_valid)
                self.assertTrue(report.checks["alignment"])
                self.assertTrue(report.checks["signature"])
                self.assertTrue(report.checks["axml"])
                self.assertTrue(report.checks["dex"])
                self.assertEqual(report.errors, [])

                code = main(["verify", apk_path])
                self.assertEqual(code, 0)

    def test_verify_fails_on_unaligned_so(self):
        """Unaligned .so causes check['alignment'] = False, returns exit code 1."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "unaligned.apk")
            stored_entries = {"lib/arm64-v8a/libnative.so": b"ELF_DATA" * 50}
            build_test_apk(apk_path, stored_entries=stored_entries, with_align=False, with_signature=True)

            with patch("apkrevive.core.verify.verify_apk_certs", return_value=(True, "Verified signature")):
                report = verify_apk_integrity(apk_path)
                self.assertFalse(report.is_valid)
                self.assertFalse(report.checks["alignment"])
                self.assertTrue(any("alignment" in e.lower() for e in report.errors))

                code = main(["verify", apk_path])
                self.assertEqual(code, 1)

    def test_verify_unsigned_valid_apk(self):
        """Unsigned valid APK with 4KB CD alignment produces is_valid=True, is_unsigned=True, and [PASS (UNSIGNED)] in format."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "unsigned.apk")
            build_test_apk(apk_path, with_align=True, with_signature=False)

            report = verify_apk_integrity(apk_path)
            self.assertTrue(report.is_valid)
            self.assertTrue(report.is_unsigned)
            self.assertTrue(report.checks["signature"])
            self.assertEqual(report.errors, [])

            out = format_verification_report(report)
            self.assertIn("[PASS (UNSIGNED)]", out)
            self.assertIn("[PASS (UNSIGNED)] V2/V3 APK Signing Block (4KB CD alignment)", out)
            self.assertIn("Container is unsigned. Installation on Android 12+ requires signing", out)

            code = main(["verify", apk_path])
            self.assertEqual(code, 0)

    def test_verify_fails_on_unsigned_unaligned_cd(self):
        """Unsigned APK with unaligned Central Directory causes check['signature'] = False and exit code 1."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "unaligned_cd.apk")
            build_test_apk(apk_path, with_align=False, with_signature=False)

            # Ensure CD offset is not 4KB aligned
            with open(apk_path, "rb") as f:
                data = f.read()
            eocd_pos = data.rfind(b"PK\x05\x06")
            cd_offset = struct.unpack_from("<I", data, eocd_pos + 16)[0]
            if cd_offset % 4096 == 0:
                # Add 1 byte of padding before CD to break alignment
                data = data[:cd_offset] + b"X" + data[cd_offset:eocd_pos] + data[eocd_pos:]
                new_eocd = data.rfind(b"PK\x05\x06")
                data_ba = bytearray(data)
                struct.pack_into("<I", data_ba, new_eocd + 16, cd_offset + 1)
                data = bytes(data_ba)
                with open(apk_path, "wb") as f:
                    f.write(data)

            report = verify_apk_integrity(apk_path)
            self.assertFalse(report.is_valid)
            self.assertTrue(report.is_unsigned)
            self.assertFalse(report.checks["signature"])
            self.assertTrue(any("Central Directory is not 4KB aligned" in e for e in report.errors))

            code = main(["verify", apk_path])
            self.assertEqual(code, 1)

    def test_verify_fails_on_non_contiguous_dex(self):
        """Missing classes2.dex between classes.dex and classes3.dex causes check['dex'] = False, error describes gap."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "gap_dex.apk")
            dex_map = {
                "classes.dex": ["Lcom/example/A;"],
                "classes3.dex": ["Lcom/example/B;"],
            }
            build_test_apk(apk_path, dex_map=dex_map, with_align=True, with_signature=True)

            with patch("apkrevive.core.verify.verify_apk_certs", return_value=(True, "Verified signature")):
                report = verify_apk_integrity(apk_path)
                self.assertFalse(report.is_valid)
                self.assertFalse(report.checks["dex"])
                self.assertTrue(any("classes2.dex" in e for e in report.errors))

                code = main(["verify", apk_path])
                self.assertEqual(code, 1)

    def test_verify_fails_on_duplicate_class_in_multidex(self):
        """Same class descriptor defined in two dex files causes check['dex'] = False, error describes collision."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "collision_dex.apk")
            dex_map = {
                "classes.dex": ["Lcom/example/DuplicateClass;", "Lcom/example/OtherClass;"],
                "classes2.dex": ["Lcom/example/DuplicateClass;"],
            }
            build_test_apk(apk_path, dex_map=dex_map, with_align=True, with_signature=True)

            with patch("apkrevive.core.verify.verify_apk_certs", return_value=(True, "Verified signature")):
                report = verify_apk_integrity(apk_path)
                self.assertFalse(report.is_valid)
                self.assertFalse(report.checks["dex"])
                self.assertTrue(any("Duplicate class descriptor 'Lcom/example/DuplicateClass;'" in e for e in report.errors))

                code = main(["verify", apk_path])
                self.assertEqual(code, 1)

    def test_verify_fails_on_corrupt_axml(self):
        """Corrupt AndroidManifest.xml causes check['axml'] = False."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "corrupt_axml.apk")
            build_test_apk(apk_path, manifest_bytes=b"CORRUPT_NOT_AXML", with_align=True, with_signature=True)

            with patch("apkrevive.core.verify.verify_apk_certs", return_value=(True, "Verified signature")):
                report = verify_apk_integrity(apk_path)
                self.assertFalse(report.is_valid)
                self.assertFalse(report.checks["axml"])
                self.assertTrue(any("axml" in e.lower() or "manifest" in e.lower() for e in report.errors))

                code = main(["verify", apk_path])
                self.assertEqual(code, 1)

    def test_verify_cli_json_output(self):
        """Verifies JSON report format."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "valid.apk")
            build_test_apk(apk_path, with_align=True, with_signature=True)

            with patch("apkrevive.core.verify.verify_apk_certs", return_value=(True, "Verified signature")):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    code = main(["verify", apk_path, "--json"])
                    self.assertEqual(code, 0)
                    out = mock_stdout.getvalue()
                    data = json.loads(out)
                    self.assertEqual(data["apk_path"], apk_path)
                    self.assertTrue(data["is_valid"])
                    self.assertIn("alignment", data["checks"])
                    self.assertIn("signature", data["checks"])
                    self.assertIn("axml", data["checks"])
                    self.assertIn("dex", data["checks"])
                    self.assertEqual(data["errors"], [])


if __name__ == "__main__":
    unittest.main()
