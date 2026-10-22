"""
test_survey_receipt.py - Unit tests covering scripts/make_receipt.py and scripts/survey.py.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from apkrevive.core.axml import AxmlNode, AxmlSurgeon
import scripts.make_receipt as make_receipt
import scripts.survey as survey


def create_minimal_test_apk(
    pkg: str = "com.test.survey",
    target_sdk: int = 28,
    min_sdk: int = 14,
    abis: list[str] | None = None,
) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        root = AxmlNode(tag="manifest")
        root.set_attr("package", pkg, ns="")
        uses_sdk = AxmlNode(tag="uses-sdk")
        uses_sdk.set_attr("targetSdkVersion", target_sdk)
        uses_sdk.set_attr("minSdkVersion", min_sdk)
        root.children.append(uses_sdk)
        app = AxmlNode(tag="application")
        app.set_attr("hasCode", True)
        root.children.append(app)
        zf.writestr("AndroidManifest.xml", AxmlSurgeon.serialize(root))
        zf.writestr("classes.dex", b"dex\n035\x00dummy_dex_data_content")
        if abis:
            for abi in abis:
                zf.writestr(f"lib/{abi}/libtest.so", b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 60)
    return buf.getvalue()


class TestMakeReceipt(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.apk_path = Path(self.temp_dir.name) / "test_app.apk"
        self.apk_path.write_bytes(create_minimal_test_apk("com.test.receipt", target_sdk=28))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_compute_file_hashes(self):
        test_file = Path(self.temp_dir.name) / "hash_sample.bin"
        test_file.write_bytes(b"ApkRevive Test Data 12345")
        hashes = make_receipt.compute_file_hashes(str(test_file))
        self.assertIn("sha256", hashes)
        self.assertIn("sha1", hashes)
        self.assertIn("md5", hashes)
        self.assertEqual(len(hashes["sha256"]), 64)
        self.assertEqual(len(hashes["sha1"]), 40)
        self.assertEqual(len(hashes["md5"]), 32)

    def test_generate_receipt_basic(self):
        receipt = make_receipt.generate_receipt(
            apk_path=str(self.apk_path),
            device_api=35,
            page_size=16384,
            simulated=False,
            device_abi="x86_64",
        )
        self.assertEqual(receipt["verification_type"], "apk_verification_receipt")
        self.assertEqual(receipt["api_level"], 35)
        self.assertEqual(receipt["page_size"], 16384)
        self.assertFalse(receipt["simulated"])
        self.assertIn("hashes", receipt)
        self.assertIn("sha256", receipt["hashes"])
        self.assertEqual(receipt["metadata"]["package_name"], "com.test.receipt")
        self.assertEqual(receipt["metadata"]["target_sdk"], 28)
        self.assertIn("alignment", receipt)
        self.assertIn("signing", receipt)
        self.assertIn("verification", receipt)
        self.assertIn("status", receipt)

    def test_generate_receipt_simulated(self):
        receipt = make_receipt.generate_receipt(
            apk_path=str(self.apk_path),
            device_api=36,
            page_size=16384,
            simulated=True,
        )
        self.assertTrue(receipt["simulated"])
        self.assertEqual(receipt["api_level"], 36)

    def test_generate_receipt_file_not_found(self):
        non_existent = str(Path(self.temp_dir.name) / "does_not_exist.apk")
        with self.assertRaises(FileNotFoundError):
            make_receipt.generate_receipt(non_existent)

    def test_make_receipt_cli_stdout(self):
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            exit_code = make_receipt.main([str(self.apk_path), "--simulated"])
            self.assertEqual(exit_code, 0)
            output = mock_stdout.getvalue()
            data = json.loads(output)
            self.assertEqual(data["verification_type"], "apk_verification_receipt")
            self.assertTrue(data["simulated"])

    def test_make_receipt_cli_output_file(self):
        out_json = Path(self.temp_dir.name) / "receipt_out.json"
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            exit_code = make_receipt.main([
                str(self.apk_path),
                "-o", str(out_json),
                "--device-api", "37",
                "--page-size", "16384",
                "--abi", "arm64-v8a",
            ])
            self.assertEqual(exit_code, 0)
            self.assertIn("[+] Wrote verification receipt to:", mock_stdout.getvalue())
            self.assertTrue(out_json.exists())
            data = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(data["api_level"], 37)
            self.assertEqual(data["abi"], "arm64-v8a")

    def test_make_receipt_cli_missing_arg(self):
        with self.assertRaises(SystemExit) as cm:
            make_receipt.main([])
        self.assertNotEqual(cm.exception.code, 0)


class TestSurvey(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.corpus_dir = Path(self.temp_dir.name) / "corpus"
        self.corpus_dir.mkdir(parents=True, exist_ok=True)

        # 1. Clean modern APK (pure DEX, targetSdk 28) -> GREEN
        apk1 = self.corpus_dir / "app_clean.apk"
        apk1.write_bytes(create_minimal_test_apk("com.test.clean", target_sdk=28))

        # 2. 32-bit only APK on 64-bit device profile -> RED
        apk2 = self.corpus_dir / "app_32bit.apk"
        apk2.write_bytes(create_minimal_test_apk("com.test.legacy32", target_sdk=19, abis=["armeabi-v7a"]))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_run_survey_directory(self):
        res = survey.run_survey(
            apk_dir=str(self.corpus_dir),
            device_api=35,
            page_size=16384,
            device_abis=["arm64-v8a"],
            device_floor=24,
        )
        self.assertEqual(res["total_apks"], 2)
        self.assertGreaterEqual(res["verdict_counts"]["GREEN"], 1)
        self.assertGreaterEqual(res["verdict_counts"]["RED"], 1)
        self.assertIn("INCOMPATIBLE_DEVICE_ABI", res["signals_breakdown"])
        self.assertEqual(len(res["per_apk_records"]), 2)
        self.assertIn("verdict_percentages", res)
        self.assertAlmostEqual(
            res["verdict_percentages"]["GREEN"] + res["verdict_percentages"]["RED"],
            100.0,
            places=1,
        )

    def test_run_survey_empty_directory(self):
        empty_dir = Path(self.temp_dir.name) / "empty"
        empty_dir.mkdir()
        res = survey.run_survey(str(empty_dir))
        self.assertEqual(res["total_apks"], 0)
        self.assertEqual(res["verdict_counts"]["GREEN"], 0)
        self.assertEqual(res["verdict_percentages"]["GREEN"], 0.0)

    def test_run_survey_corrupted_apk(self):
        corrupt_apk = self.corpus_dir / "corrupt.apk"
        corrupt_apk.write_bytes(b"NOT_A_VALID_ZIP_FILE_AT_ALL")
        res = survey.run_survey(str(self.corpus_dir))
        self.assertEqual(res["total_apks"], 3)
        self.assertIn("CORRUPTED_OR_UNREADABLE", res["signals_breakdown"])

    def test_run_survey_not_found(self):
        with self.assertRaises(FileNotFoundError):
            survey.run_survey(str(Path(self.temp_dir.name) / "non_existent"))

    def test_run_survey_not_a_directory(self):
        some_file = Path(self.temp_dir.name) / "some_file.txt"
        some_file.write_text("hello", encoding="utf-8")
        with self.assertRaises(NotADirectoryError):
            survey.run_survey(str(some_file))

    def test_format_survey_report(self):
        res = survey.run_survey(str(self.corpus_dir))
        formatted = survey.format_survey_report(res)
        self.assertIn("ApkRevive Legacy Compatibility Survey Report", formatted)
        self.assertIn("Verdict Summary:", formatted)
        self.assertIn("Triage Signals Breakdown:", formatted)
        self.assertIn("GREEN", formatted)
        self.assertIn("RED", formatted)

    def test_survey_cli_text_stdout(self):
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            code = survey.main([str(self.corpus_dir)])
            self.assertEqual(code, 0)
            output = mock_stdout.getvalue()
            self.assertIn("ApkRevive Legacy Compatibility Survey Report", output)
            self.assertIn("Total APKs:         2", output)

    def test_survey_cli_json_stdout(self):
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            code = survey.main([str(self.corpus_dir), "--json"])
            self.assertEqual(code, 0)
            output = mock_stdout.getvalue()
            data = json.loads(output)
            self.assertEqual(data["total_apks"], 2)
            self.assertIn("verdict_counts", data)

    def test_survey_cli_output_file(self):
        out_txt = Path(self.temp_dir.name) / "survey_report.txt"
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            code = survey.main([
                str(self.corpus_dir),
                "-o", str(out_txt),
                "--device-api", "37",
            ])
            self.assertEqual(code, 0)
            self.assertIn("[+] Wrote survey report to:", mock_stdout.getvalue())
            self.assertTrue(out_txt.exists())
            content = out_txt.read_text(encoding="utf-8")
            self.assertIn("Android API 37", content)

    def test_survey_cli_missing_arg(self):
        with self.assertRaises(SystemExit) as cm:
            survey.main([])
        self.assertNotEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
