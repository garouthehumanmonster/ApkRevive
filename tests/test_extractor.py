"""
test_extractor.py - Unit test suite for automated APK metadata extraction.
Verifies inspect_apk against synthetic APKs and built canary fixtures.
"""

import os
import io
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
import argparse

from apkrevive.core.axml import AxmlSurgeon, AxmlNode
from apkrevive.core.extractor import inspect_apk, get_elf_needed
from apkrevive.cli import triage_cmd

CANARIES_BUILD = Path(__file__).resolve().parent.parent / "canaries" / "build"


def make_synthetic_elf(align: int = 16384) -> bytes:
    hdr = bytearray(b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8))
    hdr += struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x4000, 0x40, 0, 0, 64, 56, 1, 0, 0, 0)
    ph = struct.pack("<IIQQQQQQ", 1, 7, 0, 0x4000, 0x4000, 0x1000, 0x1000, align)
    return bytes(hdr + ph)


class TestExtractor(unittest.TestCase):
    def test_synthetic_apk_full_extraction(self):
        # 1. Build manifest
        manifest = AxmlNode(tag="manifest")
        manifest.set_attr("package", "com.test.synthetic", ns="")
        manifest.set_attr("versionCode", 105)

        uses_sdk = AxmlNode(tag="uses-sdk")
        uses_sdk.set_attr("minSdkVersion", 21)
        uses_sdk.set_attr("targetSdkVersion", 30)
        manifest.children.append(uses_sdk)

        app = AxmlNode(tag="application")
        app.set_attr("hasCode", False)
        app.set_attr("resizeableActivity", False)

        uses_lib = AxmlNode(tag="uses-library")
        uses_lib.set_attr("name", "org.apache.http.legacy")
        app.children.append(uses_lib)
        manifest.children.append(app)

        manifest_bytes = AxmlSurgeon.serialize(manifest)

        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            apk_path = tmp.name

        try:
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("AndroidManifest.xml", manifest_bytes)
                zf.writestr("classes.dex", b"DEX\n035\x00...Lorg/apache/http/client/HttpClient;...")
                zinfo = zipfile.ZipInfo("lib/arm64-v8a/libtest.so")
                zinfo.compress_type = zipfile.ZIP_STORED
                zf.writestr(zinfo, make_synthetic_elf(16384))

            meta = inspect_apk(apk_path)

            self.assertEqual(meta.package_name, "com.test.synthetic")
            self.assertEqual(meta.version_code, 105)
            self.assertEqual(meta.min_sdk, 21)
            self.assertEqual(meta.target_sdk, 30)
            self.assertFalse(meta.has_code)
            self.assertTrue(meta.is_non_resizeable)
            self.assertEqual(meta.abis, ["arm64-v8a"])
            self.assertEqual(meta.elf_load_align_64bit, 16384)
            self.assertGreater(meta.size_bytes, 0)
            # uses_apache_http should be False because <uses-library> is already declared
            self.assertFalse(meta.uses_apache_http)
        finally:
            if os.path.exists(apk_path):
                os.remove(apk_path)

    def test_synthetic_apk_fallback_and_apache_detection(self):
        manifest = AxmlNode(tag="manifest")
        manifest.set_attr("package", "com.test.fallback", ns="")

        uses_sdk = AxmlNode(tag="uses-sdk")
        uses_sdk.set_attr("minSdkVersion", 19)
        # targetSdkVersion absent -> should fallback to min_sdk (19)
        manifest.children.append(uses_sdk)

        app = AxmlNode(tag="application")
        # hasCode absent -> should default to True
        manifest.children.append(app)

        manifest_bytes = AxmlSurgeon.serialize(manifest)

        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            apk_path = tmp.name

        try:
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("AndroidManifest.xml", manifest_bytes)
                zf.writestr("classes.dex", b"DEX\n035\x00org/apache/http/Header")
                zf.writestr("lib/arm64-v8a/lib1.so", b"ELF")
                zf.writestr("lib/armeabi-v7a/lib2.so", b"ELF")
                zf.writestr("lib/x86_64/lib3.so", b"ELF")

            meta = inspect_apk(apk_path)

            self.assertEqual(meta.package_name, "com.test.fallback")
            self.assertEqual(meta.min_sdk, 19)
            self.assertEqual(meta.target_sdk, 19)
            self.assertTrue(meta.has_code)
            self.assertEqual(meta.abis, ["arm64-v8a", "armeabi-v7a", "x86_64"])
            # uses_apache_http is True because classes.dex has org/apache/http and no uses-library
            self.assertTrue(meta.uses_apache_http)
        finally:
            if os.path.exists(apk_path):
                os.remove(apk_path)

    def test_canary_extraction_if_present(self):
        floor_ctrl = CANARIES_BUILD / "canary_install_floor_control.apk"
        if floor_ctrl.exists():
            meta = inspect_apk(str(floor_ctrl))
            self.assertEqual(meta.package_name, "com.apkrevive.canary.installfloor.control")
            self.assertEqual(meta.target_sdk, 24)
            self.assertEqual(meta.version_code, 100)
            self.assertTrue(meta.has_code)

        apache_fail = CANARIES_BUILD / "canary_apache_http_failing.apk"
        if apache_fail.exists():
            meta = inspect_apk(str(apache_fail))
            self.assertEqual(meta.target_sdk, 28)
            self.assertTrue(meta.uses_apache_http)

        page_ctrl = CANARIES_BUILD / "canary_page_size_control.apk"
        if page_ctrl.exists():
            meta = inspect_apk(str(page_ctrl))
            self.assertEqual(meta.elf_load_align_64bit, 16384)

        page_fail = CANARIES_BUILD / "canary_page_size_failing.apk"
        if page_fail.exists():
            meta = inspect_apk(str(page_fail))
            self.assertEqual(meta.elf_load_align_64bit, 4096)

        code_fail = CANARIES_BUILD / "canary_has_code_failing.apk"
        if code_fail.exists():
            meta = inspect_apk(str(code_fail))
            self.assertFalse(meta.has_code)

    def test_cli_triage_with_disk_inspection_and_overrides(self):
        apache_fail = CANARIES_BUILD / "canary_apache_http_failing.apk"
        if not apache_fail.exists():
            self.skipTest("Canaries build directory not present")

        # 1. Unmodified canary triage should result in YELLOW (code 2 in Milestone 5)
        args = argparse.Namespace(
            apk=str(apache_fail),
            device_api=35,
            device_abis="arm64-v8a",
            page_size=16384,
            device_floor=24,
            target_sdk=None,
            apk_abis=None,
            uses_apache_http=None,
            json=False,
        )
        with patch("sys.stdout", new_callable=io.StringIO):
            code = triage_cmd(args)
        self.assertEqual(code, 2)

        # 2. Flag override --target-sdk 22 should override and result in GREEN (code 0)
        args_override = argparse.Namespace(
            apk=str(apache_fail),
            device_api=35,
            device_abis="arm64-v8a",
            page_size=16384,
            device_floor=24,
            target_sdk=22,
            apk_abis=None,
            uses_apache_http=None,
        )
        with patch("sys.stdout", new_callable=io.StringIO):
            code_override = triage_cmd(args_override)
        self.assertEqual(code_override, 0)

    def test_cleartext_and_tls_extraction(self):
        # 1. Manifest with usesCleartextTraffic="false" and networkSecurityConfig attribute
        manifest1 = AxmlNode(tag="manifest")
        manifest1.set_attr("package", "com.test.cleartext.manifest", ns="")
        app1 = AxmlNode(tag="application")
        app1.set_attr("usesCleartextTraffic", False)
        app1.set_attr("networkSecurityConfig", "@xml/network_security_config")
        manifest1.children.append(app1)
        manifest1_bytes = AxmlSurgeon.serialize(manifest1)

        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp1:
            apk1_path = tmp1.name

        try:
            with zipfile.ZipFile(apk1_path, "w") as zf:
                zf.writestr("AndroidManifest.xml", manifest1_bytes)
                # DEX containing cleartext URL and legacy TLS tokens
                dex_bytes = (
                    b"DEX\n035\x00"
                    b"http://insecure.example.com/api\x00"
                    b"http://service.test.net\x00"
                    b"SSLv3\x00TLSv1.0\x00TrustAll\x00"
                )
                zf.writestr("classes.dex", dex_bytes)

            meta1 = inspect_apk(apk1_path)
            # Manifest attribute extraction
            self.assertIs(meta1.uses_cleartext_traffic, False)
            self.assertTrue(meta1.has_network_security_config)
            # Bytecode "http://" scanning should NOT flag has_cleartext_http
            self.assertFalse(meta1.has_cleartext_http)
            # Legacy TLS tokens detected from DEX
            self.assertIn("SSLv3", meta1.legacy_tls_protocols)
            self.assertIn("TLSv1.0", meta1.legacy_tls_protocols)
            self.assertIn("TrustAll", meta1.legacy_tls_protocols)
        finally:
            if os.path.exists(apk1_path):
                os.remove(apk1_path)

        # 2. Manifest WITHOUT networkSecurityConfig attribute, but res/xml/network_security_config.xml in zip
        manifest2 = AxmlNode(tag="manifest")
        manifest2.set_attr("package", "com.test.cleartext.res", ns="")
        app2 = AxmlNode(tag="application")
        app2.set_attr("usesCleartextTraffic", True)
        manifest2.children.append(app2)
        manifest2_bytes = AxmlSurgeon.serialize(manifest2)

        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp2:
            apk2_path = tmp2.name

        try:
            with zipfile.ZipFile(apk2_path, "w") as zf:
                zf.writestr("AndroidManifest.xml", manifest2_bytes)
                zf.writestr("res/xml/network_security_config.xml", b"<network-security-config/>")

            meta2 = inspect_apk(apk2_path)
            self.assertIs(meta2.uses_cleartext_traffic, True)
            self.assertTrue(meta2.has_network_security_config)
            self.assertFalse(meta2.has_cleartext_http)
            self.assertEqual(meta2.legacy_tls_protocols, [])
        finally:
            if os.path.exists(apk2_path):
                os.remove(apk2_path)

    def test_get_elf_needed_vaddr_translation(self):
        """Tests that get_elf_needed translates DT_STRTAB virtual address via PT_LOAD segment headers."""
        # Build a 64-bit ELF where p_vaddr (0x10000) != p_offset (0x1000)
        hdr = bytearray(b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8))
        hdr += struct.pack("<HHIQQQIHHHHHH", 2, 0xB7, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        self.assertEqual(len(hdr), 64)

        # Program Header 0: PT_LOAD at file offset 0x1000, mapped to vaddr 0x10000
        ph_load = struct.pack("<IIQQQQQQ", 1, 7, 0x1000, 0x10000, 0x10000, 0x1000, 0x1000, 0x1000)
        # Program Header 1: PT_DYNAMIC at file offset 0x1000
        ph_dynamic = struct.pack("<IIQQQQQQ", 2, 6, 0x1000, 0x10000, 0x10000, 48, 48, 8)

        file_bytes = bytearray(hdr + ph_load + ph_dynamic)
        if len(file_bytes) < 0x1000:
            file_bytes += b"\x00" * (0x1000 - len(file_bytes))

        # Dynamic section at file offset 0x1000
        # Entry 1: DT_NEEDED (tag=1), strtab offset 1
        # Entry 2: DT_STRTAB (tag=5), virtual address 0x10040 (translates to file offset 0x1040)
        # Entry 3: DT_NULL (tag=0)
        dyn_sec = struct.pack("<QQ", 1, 1) + struct.pack("<QQ", 5, 0x10040) + struct.pack("<QQ", 0, 0)
        file_bytes += dyn_sec

        # Pad to strtab offset 0x1040
        file_bytes += b"\x00" * (0x1040 - len(file_bytes))
        file_bytes += b"\x00libcustom_translated.so\x00"

        needed = get_elf_needed(bytes(file_bytes))
        self.assertEqual(needed, ["libcustom_translated.so"])


if __name__ == "__main__":
    unittest.main()
