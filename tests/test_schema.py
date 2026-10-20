"""
tests/test_schema.py - Structural verification test for JSON schemas across ApkRevive.

Validates:
- Every programmatic JSON emitter includes schema_version == "1.0.0".
- All recorded receipts and results on disk conform to schema_version == "1.0.0".
- Documentation artifacts (docs/SCHEMA.md and docs/LIMITS.md) exist and cover mandatory topics.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from apkrevive import SCHEMA_VERSION
from apkrevive.adb.probe import probe_install_floor
from apkrevive.cli.diff import compute_apk_diff
from apkrevive.core.doctor import run_doctor
from apkrevive.core.models import ApkMetadata, DeviceProfile, PatchReport
from apkrevive.core.obb import validate_obb_delivery
from apkrevive.core.triage import evaluate_triage
from scripts.make_receipt import create_receipt, validate_receipt

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestSchemaVersion(unittest.TestCase):
    def test_schema_version_constant(self):
        """Root SCHEMA_VERSION constant is semantic version 1.0.0."""
        self.assertEqual(SCHEMA_VERSION, "1.0.0")

    def test_triage_schema_version(self):
        """evaluate_triage outputs schema_version 1.0.0 on all decision branches."""
        dev = DeviceProfile()

        # Branch 1: GREEN runnable unmodified
        apk_green = ApkMetadata(target_sdk=28)
        res_green = evaluate_triage(apk_green, dev)
        self.assertEqual(res_green.get("schema_version"), "1.0.0")

        # Branch 2: RED split apk
        apk_split = ApkMetadata(target_sdk=28, is_split_apk=True)
        res_split = evaluate_triage(apk_split, dev)
        self.assertEqual(res_split.get("schema_version"), "1.0.0")

        # Branch 3: RED incompatible ABI
        apk_abi = ApkMetadata(target_sdk=28, abis=["mips"])
        res_abi = evaluate_triage(apk_abi, dev)
        self.assertEqual(res_abi.get("schema_version"), "1.0.0")

        # Branch 4: YELLOW modification required
        apk_yellow = ApkMetadata(target_sdk=28, uses_apache_http=True)
        res_yellow = evaluate_triage(apk_yellow, dev)
        self.assertEqual(res_yellow.get("schema_version"), "1.0.0")

    def test_patch_report_schema_version(self):
        """PatchReport dataclass to_dict() contains schema_version 1.0.0."""
        report = PatchReport(
            timestamp="2026-10-20T00:00:00Z",
            apk_path="test.apk",
            package_name="com.test.app",
            target_sdk=22,
            verdict="YELLOW",
            reason="MODIFICATION_REQUIRED",
        )
        report_dict = report.to_dict()
        self.assertEqual(report_dict.get("schema_version"), "1.0.0")

    def test_diff_schema_version(self):
        """compute_apk_diff emits schema_version 1.0.0."""
        res = compute_apk_diff("nonexistent1.apk", "nonexistent2.apk")
        self.assertEqual(res.get("schema_version"), "1.0.0")

    def test_doctor_schema_version(self):
        """run_doctor emits schema_version 1.0.0."""
        res = run_doctor()
        self.assertEqual(res.get("schema_version"), "1.0.0")

    def test_probe_schema_version(self):
        """probe_install_floor emits schema_version 1.0.0."""
        bridge = MagicMock()
        bridge.get_prop.side_effect = lambda prop: "35" if prop == "ro.build.version.sdk" else "24"
        res = probe_install_floor(bridge)
        self.assertEqual(res.get("schema_version"), "1.0.0")

    def test_obb_schema_version(self):
        """validate_obb_delivery emits schema_version 1.0.0."""
        res_valid = validate_obb_delivery("main.10.com.example.app.obb", "com.example.app", 10)
        self.assertEqual(res_valid.get("schema_version"), "1.0.0")

        res_invalid = validate_obb_delivery("invalid_name.obb", "com.example.app", 10)
        self.assertEqual(res_invalid.get("schema_version"), "1.0.0")

    def test_make_receipt_schema_version(self):
        """create_receipt generates receipts with schema_version 1.0.0."""
        receipt = create_receipt(
            model="sdk_gphone16k_x86_64",
            api=37,
            abi="x86_64",
            page_size=16384,
            script="scripts/survey.py",
            date="2026-10-20",
        )
        self.assertEqual(receipt.get("schema_version"), "1.0.0")
        validate_receipt(receipt)

    def test_receipt_files_on_disk(self):
        """All *.json files in receipts/ contain schema_version == '1.0.0'."""
        receipts_dir = REPO_ROOT / "receipts"
        self.assertTrue(receipts_dir.exists())
        receipt_files = list(receipts_dir.glob("*.json"))
        self.assertGreater(len(receipt_files), 0, "No receipt files found in receipts/")
        for rf in receipt_files:
            data = json.loads(rf.read_text(encoding="utf-8"))
            self.assertEqual(
                data.get("schema_version"),
                "1.0.0",
                f"Receipt {rf.name} missing schema_version 1.0.0",
            )

    def test_result_files_on_disk(self):
        """All *.json files in results/ (including survey/) contain schema_version == '1.0.0'."""
        results_dir = REPO_ROOT / "results"
        self.assertTrue(results_dir.exists())
        result_files = list(results_dir.rglob("*.json"))
        self.assertGreater(len(result_files), 0, "No result files found in results/")
        for rf in result_files:
            data = json.loads(rf.read_text(encoding="utf-8"))
            self.assertEqual(
                data.get("schema_version"),
                "1.0.0",
                f"Result file {rf.relative_to(REPO_ROOT)} missing schema_version 1.0.0",
            )

    def test_docs_exist_and_complete(self):
        """docs/SCHEMA.md and docs/LIMITS.md exist and cover core sections."""
        limits_doc = REPO_ROOT / "docs" / "LIMITS.md"
        schema_doc = REPO_ROOT / "docs" / "SCHEMA.md"

        self.assertTrue(limits_doc.exists(), "docs/LIMITS.md does not exist")
        self.assertTrue(schema_doc.exists(), "docs/SCHEMA.md does not exist")

        limits_text = limits_doc.read_text(encoding="utf-8")
        self.assertIn("32-Bit-Only Binaries on 64-Bit-Only Hardware", limits_text)
        self.assertIn("Dead Google SDKs", limits_text)
        self.assertIn("DRM, Anti-Tamper & Integrity Attestation", limits_text)
        self.assertIn("Re-Signing Consequences", limits_text)
        self.assertIn("Target SDK Bumps & Runtime Permissions", limits_text)

        schema_text = schema_doc.read_text(encoding="utf-8")
        self.assertIn("schema_version", schema_text)
        self.assertIn("1.0.0", schema_text)
        self.assertIn("Triage Output Schema", schema_text)
        self.assertIn("Revive Patch Report Schema", schema_text)
        self.assertIn("Visual Binary Diff Schema", schema_text)
        self.assertIn("Doctor Diagnostic Report Schema", schema_text)
        self.assertIn("Verification Receipt Schema", schema_text)


if __name__ == "__main__":
    unittest.main()
