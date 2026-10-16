"""
test_cli_diff.py - Test suite for visual binary diff, SARIF v2.1.0 telemetry, and TUI components.
"""

import io
import json
import os
import struct
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from apkrevive.cli import main, diff_cmd, triage_cmd, revive_cmd
from apkrevive.cli.diff import compute_apk_diff, render_apk_diff
from apkrevive.cli.sarif import triage_to_sarif, diff_to_sarif
from apkrevive.cli.tui import (
    render_verdict_banner,
    render_triage_table,
    render_alignment_ladder,
)
from apkrevive.core.axml import AxmlSurgeon, AxmlNode
from apkrevive.core.align import align_apk
from apkrevive.core.models import PatchReport


def make_test_elf(align: int = 16384) -> bytes:
    hdr = bytearray(b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 8))
    hdr += struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x4000, 0x40, 0, 0, 64, 56, 1, 0, 0, 0)
    ph = struct.pack("<IIQQQQQQ", 1, 7, 0, 0x4000, 0x4000, 0x1000, 0x1000, align)
    return bytes(hdr + ph)


def build_synthetic_apk_pair():
    # 1. Original APK: TargetSdk 22, hasCode False, unaligned ELF, no shim
    orig_manifest = AxmlNode(tag="manifest")
    orig_manifest.set_attr("package", "com.example.diffapp", ns="")
    orig_uses_sdk = AxmlNode(tag="uses-sdk")
    orig_uses_sdk.set_attr("minSdkVersion", 19)
    orig_uses_sdk.set_attr("targetSdkVersion", 22)
    orig_manifest.children.append(orig_uses_sdk)
    orig_app = AxmlNode(tag="application")
    orig_app.set_attr("hasCode", False)
    orig_manifest.children.append(orig_app)
    orig_raw_manifest = AxmlSurgeon.serialize(orig_manifest)

    # 2. Revived APK: TargetSdk 22, hasCode True, resizeable, pageSizeCompat, uses-library, shim
    rev_manifest = AxmlNode(tag="manifest")
    rev_manifest.set_attr("package", "com.example.diffapp", ns="")
    rev_uses_sdk = AxmlNode(tag="uses-sdk")
    rev_uses_sdk.set_attr("minSdkVersion", 19)
    rev_uses_sdk.set_attr("targetSdkVersion", 22)
    rev_manifest.children.append(rev_uses_sdk)
    rev_app = AxmlNode(tag="application")
    rev_app.set_attr("hasCode", True)
    rev_app.set_attr("resizeableActivity", True)
    rev_app.set_attr("pageSizeCompat", "enabled")
    rev_uses_lib = AxmlNode(tag="uses-library")
    rev_uses_lib.set_attr("name", "org.apache.http.legacy")
    rev_app.children.append(rev_uses_lib)
    rev_prov = AxmlNode(tag="provider")
    rev_prov.set_attr("name", "apkrevive.shim.ApkReviveInitProvider")
    rev_app.children.append(rev_prov)
    rev_manifest.children.append(rev_app)
    rev_raw_manifest = AxmlSurgeon.serialize(rev_manifest)

    t_dir = tempfile.mkdtemp()
    orig_path = os.path.join(t_dir, "orig.apk")
    rev_temp_path = os.path.join(t_dir, "rev_temp.apk")
    rev_path = os.path.join(t_dir, "revived.apk")

    with zipfile.ZipFile(orig_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", orig_raw_manifest)
        zf.writestr("classes.dex", b"DEX\n035\x00ORIGINAL_DEX_BYTES")
        zinfo_arsc = zipfile.ZipInfo("resources.arsc")
        zinfo_arsc.compress_type = zipfile.ZIP_STORED
        zf.writestr(zinfo_arsc, b"ARSC_UNALIGNED_DATA")
        zinfo_so = zipfile.ZipInfo("lib/arm64-v8a/libdemo.so")
        zinfo_so.compress_type = zipfile.ZIP_STORED
        zf.writestr(zinfo_so, make_test_elf(4096))

    with zipfile.ZipFile(rev_temp_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", rev_raw_manifest)
        zf.writestr("classes.dex", b"DEX\n035\x00ORIGINAL_DEX_BYTES")
        zf.writestr("classes2.dex", b"DEX\n035\x00ApkReviveInitProvider")
        zinfo_arsc = zipfile.ZipInfo("resources.arsc")
        zinfo_arsc.compress_type = zipfile.ZIP_STORED
        zf.writestr(zinfo_arsc, b"ARSC_ALIGNED_DATA")
        zinfo_so = zipfile.ZipInfo("lib/arm64-v8a/libdemo.so")
        zinfo_so.compress_type = zipfile.ZIP_STORED
        zf.writestr(zinfo_so, make_test_elf(16384))

    align_apk(rev_temp_path, rev_path)
    if os.path.exists(rev_temp_path):
        os.remove(rev_temp_path)

    return orig_path, rev_path


class TestCliDiff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.orig_apk, cls.rev_apk = build_synthetic_apk_pair()

    @classmethod
    def tearDownClass(cls):
        for p in (cls.orig_apk, cls.rev_apk):
            if os.path.exists(p):
                os.remove(p)

    def test_compute_apk_diff_structure(self):
        diff_data = compute_apk_diff(self.orig_apk, self.rev_apk)

        # 1. Manifest Diff Assertions
        m_diff = diff_data["manifest_diff"]
        self.assertTrue(m_diff["has_code"]["changed"])
        self.assertFalse(m_diff["has_code"]["before"])
        self.assertTrue(m_diff["has_code"]["after"])

        self.assertTrue(m_diff["resizeable_activity"]["changed"])
        self.assertTrue(m_diff["page_size_compat"]["changed"])
        self.assertIn("org.apache.http.legacy", m_diff["uses_libraries"]["added"])
        self.assertIn("apkrevive.shim.ApkReviveInitProvider", m_diff["providers"]["added"])

        # 2. DEX Diff Assertions
        d_diff = diff_data["dex_diff"]
        self.assertEqual(d_diff["orig_dex_count"], 1)
        self.assertEqual(d_diff["revived_dex_count"], 2)
        self.assertTrue(d_diff["shim_injected"])
        self.assertFalse(d_diff["orig_has_shim"])
        self.assertTrue(d_diff["revived_has_shim"])

        # 3. Alignment Ladder Assertions
        ladder = diff_data["alignment_ladder"]
        self.assertGreaterEqual(len(ladder), 2)
        entries_by_name = {e["entry"]: e for e in ladder}
        self.assertIn("resources.arsc", entries_by_name)
        self.assertIn("lib/arm64-v8a/libdemo.so", entries_by_name)
        self.assertIn("lib/arm64-v8a/libdemo.so (PT_LOAD)", entries_by_name)

        pt_load_entry = entries_by_name["lib/arm64-v8a/libdemo.so (PT_LOAD)"]
        self.assertEqual(pt_load_entry["status"], "FIXED")

    def test_render_apk_diff_output(self):
        diff_data = compute_apk_diff(self.orig_apk, self.rev_apk)
        rendered = render_apk_diff(diff_data)
        self.assertIn("ApkRevive Visual Binary Diff", rendered)
        self.assertIn("Manifest Changes", rendered)
        self.assertIn("DEX & Shim Changes", rendered)
        self.assertIn("Byte-Alignment Ladder", rendered)
        self.assertIn("has_code", rendered)
        self.assertIn("ApkReviveInitProvider", rendered)

    def test_cli_diff_invocation_text(self):
        with patch("sys.argv", ["apkrevive", "diff", self.orig_apk, self.rev_apk]):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                code = main()
                self.assertEqual(code, 0)
                out = mock_out.getvalue()
                self.assertIn("ApkRevive Visual Binary Diff", out)
                self.assertIn("Byte-Alignment Ladder", out)

    def test_cli_diff_invocation_json(self):
        with patch("sys.argv", ["apkrevive", "diff", self.orig_apk, self.rev_apk, "--json"]):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                code = main()
                self.assertEqual(code, 0)
                data = json.loads(mock_out.getvalue())
                self.assertIn("manifest_diff", data)
                self.assertIn("dex_diff", data)
                self.assertIn("alignment_ladder", data)

    def test_cli_diff_invocation_sarif(self):
        with patch("sys.argv", ["apkrevive", "diff", self.orig_apk, self.rev_apk, "--sarif"]):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                code = main()
                self.assertEqual(code, 0)
                sarif = json.loads(mock_out.getvalue())
                self.assertEqual(sarif["$schema"], "https://json.schemastore.org/sarif-2.1.0.json")
                self.assertEqual(sarif["version"], "2.1.0")
                self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "ApkRevive")
                results = sarif["runs"][0]["results"]
                self.assertGreater(len(results), 0)
                rule_ids = {r["ruleId"] for r in results}
                self.assertIn("MANIFEST_MODIFIED", rule_ids)
                self.assertIn("DEX_SHIM_INJECTED", rule_ids)
                self.assertIn("ALIGNMENT_FIXED", rule_ids)

    def test_cli_diff_missing_file_error(self):
        with patch("sys.argv", ["apkrevive", "diff", "nonexistent.apk", self.rev_apk]):
            with patch("sys.stderr", new_callable=io.StringIO):
                code = main()
                self.assertEqual(code, 1)

    def test_cli_triage_sarif_invocation(self):
        with patch("sys.argv", ["apkrevive", "triage", self.orig_apk, "--sarif"]):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                code = main()
                # Triage returns exit code for verdict (e.g. 0 for GREEN or 2 for YELLOW)
                self.assertIn(code, (0, 1, 2, 3))
                sarif = json.loads(mock_out.getvalue())
                self.assertEqual(sarif["$schema"], "https://json.schemastore.org/sarif-2.1.0.json")
                self.assertEqual(sarif["version"], "2.1.0")
                self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "ApkRevive")
                self.assertIn("results", sarif["runs"][0])

    def test_cli_revive_dry_run_sarif(self):
        with patch("sys.argv", ["apkrevive", "revive", self.orig_apk, "--dry-run", "--sarif"]):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                code = main()
                self.assertIn(code, (0, 1, 2, 3))
                sarif = json.loads(mock_out.getvalue())
                self.assertEqual(sarif["version"], "2.1.0")
                self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "ApkRevive")

    def test_tui_render_verdict_banner(self):
        # Plain text
        banner_plain = render_verdict_banner("GREEN", "RUNNABLE_UNMODIFIED", "DIRECT_INSTALL", force_rich=False)
        self.assertIn("VERDICT: GREEN", banner_plain)
        self.assertIn("RUNNABLE_UNMODIFIED", banner_plain)
        self.assertIn("DIRECT_INSTALL", banner_plain)

        # Rich text
        banner_rich = render_verdict_banner("RED", "INCOMPATIBLE_PAGE_SIZE", force_rich=True)
        self.assertIn("RED", banner_rich)
        self.assertIn("INCOMPATIBLE_PAGE_SIZE", banner_rich)

    def test_tui_render_triage_table(self):
        rep = PatchReport(
            timestamp="2026-10-15T00:00:00",
            apk_path="/test/app.apk",
            package_name="com.test.app",
            target_sdk=22,
            verdict="YELLOW",
            reason="MODIFICATION_REQUIRED",
            install_method="BYPASS_LOW_TARGET_SDK_BLOCK",
            required_transforms=["INJECT_USES_LIBRARY_APACHE_HTTP"],
            warnings=["WARN_CLEARTEXT: Cleartext HTTP blocked"],
            details="Transforms required.",
            output_apk="/test/app.revived.apk",
            transform_risks={"INJECT_USES_LIBRARY_APACHE_HTTP": "LOW"},
        )
        table_plain = render_triage_table(rep, force_rich=False)
        self.assertIn("com.test.app", table_plain)
        self.assertIn("INJECT_USES_LIBRARY_APACHE_HTTP", table_plain)
        self.assertIn("WARN_CLEARTEXT", table_plain)

        table_rich = render_triage_table(rep.to_dict(), force_rich=True)
        self.assertIn("com.test.app", table_rich)
        self.assertIn("INJECT_USES_LIBRARY_APACHE_HTTP", table_rich)

    def test_tui_render_alignment_ladder_empty_and_populated(self):
        self.assertIn("No byte-alignment", render_alignment_ladder([]))

        single_entries = [
            {"entry": "lib/arm64-v8a/liba.so", "type": "ZIP", "required_align": 16384, "offset": 0x4000, "aligned": True},
            {"entry": "resources.arsc", "type": "ZIP", "required_align": 4096, "offset": 0x1234, "aligned": False},
        ]
        ladder_plain = render_alignment_ladder(single_entries, force_rich=False)
        self.assertIn("lib/arm64-v8a/liba.so", ladder_plain)
        self.assertIn("resources.arsc", ladder_plain)
        self.assertIn("PASS", ladder_plain)
        self.assertIn("FAIL", ladder_plain)


if __name__ == "__main__":
    unittest.main()