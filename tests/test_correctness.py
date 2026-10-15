"""
test_correctness.py - Comprehensive Milestone 3 Correctness Test Suite for ApkRevive.
Covers ELF validation, triage verdict on incongruent layouts, idempotent revive,
Zip-Slip protection, Zip bomb detection, truncated archive handling, multi-dex
shim injection, and Split APK rejection.
"""

import argparse
import io
import os
import shutil
import struct
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from apkrevive.core.align import align_apk, validate_zip_archive
from apkrevive.core.axml import AxmlSurgeon, AxmlNode
from apkrevive.core.elf import validate_elf_segments
from apkrevive.core.extractor import inspect_apk
from apkrevive.core.models import ApkMetadata, DeviceProfile, TriageSignal, Verdict
from apkrevive.core.triage import evaluate_triage
from apkrevive.cli import triage_cmd, revive_cmd


def make_synthetic_elf(p_offset: int, p_vaddr: int, p_align: int) -> bytes:
    """Constructs a minimal 64-bit ELF binary with specified PT_LOAD offset, vaddr, and p_align."""
    hdr = bytearray(b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8))
    hdr += struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x4000, 0x40, 0, 0, 64, 56, 1, 0, 0, 0)
    ph = struct.pack("<IIQQQQQQ", 1, 7, p_offset, p_vaddr, p_vaddr, 0x1000, 0x1000, p_align)
    return bytes(hdr + ph)


def make_minimal_manifest(pkg: str = "com.apkrevive.test", split: str = None) -> bytes:
    """Constructs a serialized AndroidManifest.xml."""
    manifest = AxmlNode(tag="manifest")
    manifest.set_attr("package", pkg, ns="")
    if split:
        manifest.set_attr("split", split, ns="")
    app = AxmlNode(tag="application")
    manifest.children.append(app)
    return AxmlSurgeon.serialize(manifest)


class TestCorrectness(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # 1. ELF validation: valid 16KB segment vs header-only patched
    def test_elf_validation_congruence(self):
        # Valid 16KB segment: (0 % 16384 == 0x4000 % 16384 == 0)
        valid_elf = make_synthetic_elf(p_offset=0, p_vaddr=0x4000, p_align=16384)
        is_valid, min_align, err = validate_elf_segments(valid_elf)
        self.assertTrue(is_valid)
        self.assertEqual(min_align, 16384)
        self.assertIsNone(err)

        # Header-only patched: p_align=16384, but offset is 0x1000 (4096), vaddr is 0x4000 (16384)
        # (0x4000 % 16384 = 0 != 0x1000 % 16384 = 4096)
        patched_elf = make_synthetic_elf(p_offset=0x1000, p_vaddr=0x4000, p_align=16384)
        is_valid, min_align, err = validate_elf_segments(patched_elf)
        self.assertFalse(is_valid)
        self.assertEqual(min_align, 16384)
        self.assertIn("Segment layout incongruent with p_align", err)

    # 2. Triage verdict on header-only patched ELF (RED on API 35, YELLOW on API 36)
    def test_triage_verdict_on_header_patched_elf(self):
        apk = ApkMetadata(
            package_name="com.test.incongruent",
            target_sdk=28,
            abis=["arm64-v8a"],
            elf_load_align_64bit=16384,
            has_invalid_elf_layout=True,
            size_bytes=5_000_000,
        )

        # On API 35 (Android 15): Must be RED
        dev_35 = DeviceProfile(os_api_level=35, page_size_bytes=16384)
        res_35 = evaluate_triage(apk, dev_35)
        self.assertEqual(res_35["verdict"], Verdict.RED.value)
        self.assertEqual(res_35["reason"], TriageSignal.INCOMPATIBLE_PAGE_SIZE.value)
        self.assertIn("64-bit ELF has invalid or <16KB segment alignment", res_35["details"])

        # On API 36 (Android 16): Must be YELLOW with PAGE_SIZE_COMPAT
        dev_36 = DeviceProfile(os_api_level=36, page_size_bytes=16384)
        res_36 = evaluate_triage(apk, dev_36)
        self.assertEqual(res_36["verdict"], Verdict.YELLOW.value)
        self.assertEqual(res_36["reason"], TriageSignal.MODIFICATION_REQUIRED.value)
        self.assertIn("PAGE_SIZE_COMPAT", res_36["required_transforms"])

    # 3. Idempotent revive: running revive twice produces same dex count and identical manifest
    def test_idempotent_revive(self):
        apk_path = os.path.join(self.tmp_dir, "base_app.apk")
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", make_minimal_manifest("com.test.idempotent"))
            zf.writestr("classes.dex", b"DEX\n035\x00" + b"\x00" * 100)

        revived1_apk = os.path.join(self.tmp_dir, "revived1.apk")
        args1 = argparse.Namespace(
            apk=apk_path,
            output=revived1_apk,
            enable_60hz=True,
            enable_cutout=False,
            ks=None,
            ks_pass=None,
            ks_alias=None,
            key_pass=None,
        )
        with patch("apkrevive.cli.sign_apk", return_value=True):
            code1 = revive_cmd(args1)
        self.assertEqual(code1, 0)

        # Run revive again on revived1
        revived2_apk = os.path.join(self.tmp_dir, "revived2.apk")
        args2 = argparse.Namespace(
            apk=revived1_apk,
            output=revived2_apk,
            enable_60hz=True,
            enable_cutout=False,
            ks=None,
            ks_pass=None,
            ks_alias=None,
            key_pass=None,
        )
        with patch("apkrevive.cli.sign_apk", return_value=True):
            code2 = revive_cmd(args2)
        self.assertEqual(code2, 0)

        with zipfile.ZipFile(revived1_apk, "r") as z1, zipfile.ZipFile(revived2_apk, "r") as z2:
            dex1 = [n for n in z1.namelist() if n.endswith(".dex")]
            dex2 = [n for n in z2.namelist() if n.endswith(".dex")]
            self.assertEqual(sorted(dex1), sorted(dex2), "Dex count or names differ between passes")

            manifest1 = z1.read("AndroidManifest.xml")
            manifest2 = z2.read("AndroidManifest.xml")
            self.assertEqual(manifest1, manifest2, "Manifest differs after second revive")

    # 4. Zip-Slip: archive with ../evil.so rejected
    def test_zip_slip_rejected(self):
        slip_apk = os.path.join(self.tmp_dir, "slip.apk")
        with zipfile.ZipFile(slip_apk, "w") as zf:
            zf.writestr("../evil.so", b"ATTACK_PAYLOAD")

        with self.assertRaises(ValueError) as ctx:
            validate_zip_archive(slip_apk)
        self.assertIn("Zip-slip path traversal detected", str(ctx.exception))

        args = argparse.Namespace(apk=slip_apk)
        with self.assertRaises(ValueError):
            triage_cmd(args)

    # 5. Zip bomb: archive with high compression ratio rejected
    def test_zip_bomb_rejected(self):
        bomb_apk = os.path.join(self.tmp_dir, "bomb.apk")
        # 12MB of uncompressed zeroes compresses to ~12KB with DEFLATE (ratio > 100x)
        with zipfile.ZipFile(bomb_apk, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("zeroes.bin", b"\x00" * (12 * 1024 * 1024))

        with self.assertRaises(ValueError) as ctx:
            validate_zip_archive(bomb_apk)
        self.assertIn("Zip bomb detected", str(ctx.exception))

    # 6. Truncated archive: truncated ZIP rejected with ValueError cleanly
    def test_truncated_archive_rejected(self):
        valid_apk = os.path.join(self.tmp_dir, "valid.apk")
        with zipfile.ZipFile(valid_apk, "w") as zf:
            zf.writestr("test.txt", b"hello world")

        with open(valid_apk, "rb") as f:
            valid_bytes = f.read()

        truncated_apk = os.path.join(self.tmp_dir, "truncated.apk")
        with open(truncated_apk, "wb") as f:
            f.write(valid_bytes[:len(valid_bytes) // 2])

        with self.assertRaises(ValueError):
            validate_zip_archive(truncated_apk)

        align_out = os.path.join(self.tmp_dir, "aligned.apk")
        with self.assertRaises(ValueError):
            align_apk(truncated_apk, align_out)

    # 7. Multi-dex: archive with classes.dex and classes2.dex injects classes3.dex
    def test_multidex_shim_injection_and_idempotency(self):
        multidex_apk = os.path.join(self.tmp_dir, "multidex.apk")
        with zipfile.ZipFile(multidex_apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", make_minimal_manifest("com.test.multidex"))
            zf.writestr("classes.dex", b"DEX\n035\x00" + b"\x00" * 100)
            zf.writestr("classes2.dex", b"DEX\n035\x00" + b"\x00" * 100)

        # First revive injects classes3.dex
        revived1_apk = os.path.join(self.tmp_dir, "multi_revived1.apk")
        args1 = argparse.Namespace(
            apk=multidex_apk,
            output=revived1_apk,
            enable_60hz=True,
            enable_cutout=False,
            ks=None,
            ks_pass=None,
            ks_alias=None,
            key_pass=None,
        )
        with patch("apkrevive.cli.sign_apk", return_value=True):
            code1 = revive_cmd(args1)
        self.assertEqual(code1, 0)

        with zipfile.ZipFile(revived1_apk, "r") as z1:
            names1 = z1.namelist()
            self.assertIn("classes.dex", names1)
            self.assertIn("classes2.dex", names1)
            self.assertIn("classes3.dex", names1)
            self.assertNotIn("classes4.dex", names1)

        # Second revive does NOT inject classes4.dex
        revived2_apk = os.path.join(self.tmp_dir, "multi_revived2.apk")
        args2 = argparse.Namespace(
            apk=revived1_apk,
            output=revived2_apk,
            enable_60hz=True,
            enable_cutout=False,
            ks=None,
            ks_pass=None,
            ks_alias=None,
            key_pass=None,
        )
        with patch("apkrevive.cli.sign_apk", return_value=True):
            code2 = revive_cmd(args2)
        self.assertEqual(code2, 0)

        with zipfile.ZipFile(revived2_apk, "r") as z2:
            names2 = z2.namelist()
            self.assertIn("classes.dex", names2)
            self.assertIn("classes2.dex", names2)
            self.assertIn("classes3.dex", names2)
            self.assertNotIn("classes4.dex", names2)

    # 8. Split APK: archive with split="config.arm64_v8a" rejected in triage and revive
    def test_split_apk_rejected(self):
        split_apk = os.path.join(self.tmp_dir, "split.apk")
        manifest_bytes = make_minimal_manifest("com.test.splitapp", split="config.arm64_v8a")
        with zipfile.ZipFile(split_apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", manifest_bytes)
            zf.writestr("classes.dex", b"DEX\n035\x00" + b"\x00" * 100)

        meta = inspect_apk(split_apk)
        self.assertTrue(meta.is_split_apk)

        dev = DeviceProfile()
        res = evaluate_triage(meta, dev)
        self.assertEqual(res["verdict"], Verdict.RED.value)
        self.assertEqual(res["reason"], TriageSignal.SPLIT_APK_UNSUPPORTED.value)
        self.assertEqual(res["details"], "Split APKs cannot be modernized independently. Modernize the base APK.")

        out_apk = os.path.join(self.tmp_dir, "split_revived.apk")
        args = argparse.Namespace(
            apk=split_apk,
            output=out_apk,
            enable_60hz=False,
            enable_cutout=False,
            ks=None,
            ks_pass=None,
            ks_alias=None,
            key_pass=None,
        )
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            code = revive_cmd(args)
        self.assertEqual(code, 1)
        self.assertIn("ERROR: Split APK detected. Split APKs cannot be modernized independently.", stderr_buf.getvalue())


if __name__ == "__main__":
    unittest.main()
