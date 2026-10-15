"""
test_cli_ux.py - Unit test suite for CLI UX & CI enhancements (Milestone 5).
"""

import argparse
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from apkrevive.cli import triage_cmd, revive_cmd, doctor_cmd, VERDICT_EXIT_CODES
from apkrevive.core.axml import AxmlNode, AxmlSurgeon
from apkrevive.core.doctor import run_doctor, format_doctor_report


class TestCliUx(unittest.TestCase):

    def test_triage_exit_codes_per_verdict(self):
        """Verifies triage exit codes per verdict: GREEN=0, RED=1, YELLOW=2, NEEDS_USER_INPUT=3."""
        for verdict, expected_code in [("GREEN", 0), ("RED", 1), ("YELLOW", 2), ("NEEDS_USER_INPUT", 3)]:
            with self.subTest(verdict=verdict):
                with patch("apkrevive.cli.evaluate_triage") as mock_triage:
                    mock_triage.return_value = {
                        "verdict": verdict,
                        "reason": f"MOCK_{verdict}",
                        "install_method": "DIRECT_INSTALL" if verdict == "GREEN" else None,
                        "required_transforms": ["DUMMY_TRANSFORM"] if verdict == "YELLOW" else [],
                        "warnings": ["Mock warning"],
                        "details": f"Mock details for {verdict}",
                    }
                    args = argparse.Namespace(
                        apk="nonexistent_test.apk",
                        device_api=35,
                        device_abis="arm64-v8a",
                        page_size=16384,
                        device_floor=24,
                        target_sdk=28,
                        apk_abis="",
                        uses_apache_http=False,
                        json=False,
                    )
                    with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                        code = triage_cmd(args)
                    self.assertEqual(code, expected_code)
                    output = mock_stdout.getvalue()
                    self.assertIn(f"Verdict: {verdict}", output)
                    self.assertIn("ApkRevive Triage Summary", output)

    def test_revive_dry_run(self):
        """Verifies revive --dry-run produces a report, returns verdict exit code, and creates no output APK."""
        manifest = AxmlNode(tag="manifest")
        manifest.set_attr("package", "com.apkrevive.dryrun", ns="")
        app = AxmlNode(tag="application")
        manifest.children.append(app)
        raw_manifest = AxmlSurgeon.serialize(manifest)

        with tempfile.TemporaryDirectory() as tmp_dir:
            in_apk = os.path.join(tmp_dir, "input.apk")
            out_apk = os.path.join(tmp_dir, "output_must_not_exist.apk")

            with zipfile.ZipFile(in_apk, "w") as zf:
                zf.writestr("AndroidManifest.xml", raw_manifest)
                zf.writestr("classes.dex", b"DEX\n035\x00")

            args = argparse.Namespace(
                apk=in_apk,
                output=out_apk,
                dry_run=True,
                enable_60hz=True,
                enable_cutout=True,
                ks=None,
                ks_pass=None,
                ks_alias=None,
                key_pass=None,
                json=False,
            )

            stdout_buf = io.StringIO()
            with patch("sys.stdout", stdout_buf):
                code = revive_cmd(args)

            # Output file must NOT be created
            self.assertFalse(os.path.exists(out_apk))
            self.assertEqual(code, VERDICT_EXIT_CODES["GREEN"])
            stdout_text = stdout_buf.getvalue()
            self.assertIn("ApkRevive Patch Report", stdout_text)
            self.assertIn("Dry run", stdout_text)

    def test_global_json_flag(self):
        """Verifies that --json flag outputs valid parseable JSON across triage, revive, and doctor."""
        manifest = AxmlNode(tag="manifest")
        manifest.set_attr("package", "com.apkrevive.jsonflag", ns="")
        app = AxmlNode(tag="application")
        manifest.children.append(app)
        raw_manifest = AxmlSurgeon.serialize(manifest)

        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "test.apk")
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("AndroidManifest.xml", raw_manifest)
                zf.writestr("classes.dex", b"DEX\n035\x00")

            # 1. triage --json
            triage_args = argparse.Namespace(
                apk=apk_path,
                device_api=35,
                device_abis="arm64-v8a",
                page_size=16384,
                device_floor=24,
                target_sdk=28,
                apk_abis="",
                uses_apache_http=False,
                json=True,
            )
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                triage_cmd(triage_args)
            triage_json = json.loads(mock_out.getvalue())
            self.assertIn("verdict", triage_json)

            # 2. revive --dry-run --json
            revive_args = argparse.Namespace(
                apk=apk_path,
                output=os.path.join(tmp_dir, "unused.apk"),
                dry_run=True,
                enable_60hz=False,
                enable_cutout=False,
                ks=None,
                ks_pass=None,
                ks_alias=None,
                key_pass=None,
                json=True,
            )
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                revive_cmd(revive_args)
            revive_json = json.loads(mock_out.getvalue())
            self.assertIn("package_name", revive_json)
            self.assertIn("dry run", revive_json.get("details", "").lower())

            # 3. doctor --json
            doc_args = argparse.Namespace(json=True)
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                doctor_cmd(doc_args)
            doc_json = json.loads(mock_out.getvalue())
            self.assertIn("status", doc_json)
            self.assertIn("checks", doc_json)

    def test_doctor_structure_and_exit_codes(self):
        """Verifies run_doctor dictionary structure, badges, and doctor_cmd exit code semantics."""
        res = run_doctor()
        self.assertIsInstance(res, dict)
        self.assertIn("status", res)
        self.assertIn("pass", res)
        self.assertIn("warn", res)
        self.assertIn("fail", res)
        self.assertIn("checks", res)
        self.assertIn(res["status"], ("PASS", "WARN", "FAIL"))

        report_text = format_doctor_report(res)
        self.assertIn("ApkRevive Doctor Report", report_text)
        self.assertTrue(any(b in report_text for b in ("[PASS]", "[WARN]", "[FAIL]")))

        # When status is PASS or WARN -> exit 0
        with patch("apkrevive.cli.run_doctor", return_value={"status": "PASS", "checks": {}}):
            code_pass = doctor_cmd(argparse.Namespace(json=False))
            self.assertEqual(code_pass, 0)

        with patch("apkrevive.cli.run_doctor", return_value={"status": "WARN", "checks": {}}):
            code_warn = doctor_cmd(argparse.Namespace(json=False))
            self.assertEqual(code_warn, 0)

        # When status is FAIL -> exit 1
        with patch("apkrevive.cli.run_doctor", return_value={"status": "FAIL", "checks": {}}):
            code_fail = doctor_cmd(argparse.Namespace(json=False))
            self.assertEqual(code_fail, 1)

    def test_pyproject_toml_configuration(self):
        """Verifies pyproject.toml contains dev optional dependencies and all required tool configurations."""
        root_dir = Path(__file__).resolve().parent.parent
        pyproject_path = root_dir / "pyproject.toml"
        self.assertTrue(pyproject_path.exists())
        content = pyproject_path.read_text(encoding="utf-8")

        self.assertIn("[project.optional-dependencies]", content)
        self.assertIn("ruff", content)
        self.assertIn("mypy", content)
        self.assertIn("coverage", content)

        self.assertIn("[tool.ruff]", content)
        self.assertIn("line-length = 120", content)
        self.assertIn('target-version = "py39"', content)

        self.assertIn("[tool.mypy]", content)
        self.assertTrue('python_version = "3.10"' in content or 'python_version = "3.9"' in content)
        self.assertIn("ignore_missing_imports = true", content)

        self.assertIn("[tool.coverage.run]", content)
        self.assertIn('source = ["apkrevive"]', content)
        self.assertIn("branch = true", content)

        self.assertIn("[tool.coverage.report]", content)
        self.assertIn("fail_under = 80", content)
        self.assertIn("show_missing = true", content)


if __name__ == "__main__":
    unittest.main()
