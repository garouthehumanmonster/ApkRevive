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

from apkrevive.cli import triage_cmd, revive_cmd, doctor_cmd, VERDICT_EXIT_CODES, main
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

    @patch("apkrevive.cli.sign_apk", return_value=True)
    def test_revive_enable_resizable_opt_in(self, mock_sign):
        """Verifies:
        1. revive without --enable-resizable defaults to minimal changes and does NOT inject resizeableActivity="true".
        2. revive with --enable-resizable injects resizeableActivity="true"."""
        manifest = AxmlNode(tag="manifest")
        manifest.set_attr("package", "com.apkrevive.resizable", ns="")
        app = AxmlNode(tag="application")
        app.set_attr("resizeableActivity", False)
        manifest.children.append(app)
        raw_manifest = AxmlSurgeon.serialize(manifest)

        with tempfile.TemporaryDirectory() as tmp_dir:
            in_apk = os.path.join(tmp_dir, "input.apk")
            with zipfile.ZipFile(in_apk, "w") as zf:
                zf.writestr("AndroidManifest.xml", raw_manifest)
                zf.writestr("classes.dex", b"DEX\n035\x00")

            # 1. revive without --enable-resizable
            out_apk_default = os.path.join(tmp_dir, "out_default.apk")
            args_default = argparse.Namespace(
                apk=in_apk,
                output=out_apk_default,
                dry_run=False,
                enable_60hz=False,
                enable_cutout=False,
                enable_resizable=False,
                ks=None,
                ks_pass=None,
                ks_alias=None,
                key_pass=None,
                json=False,
            )
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                code_default = revive_cmd(args_default)
            self.assertEqual(code_default, VERDICT_EXIT_CODES["YELLOW"])
            self.assertIn("Skipped EXPAND_ASPECT_RATIO (opt-in requires --enable-resizable)", mock_out.getvalue())

            # Verify resizeableActivity is NOT set to true in output APK
            with zipfile.ZipFile(out_apk_default, "r") as zf_out:
                out_manifest = zf_out.read("AndroidManifest.xml")
            node = AxmlSurgeon.parse(out_manifest)
            app_out = node.find_child("application")
            self.assertIsNotNone(app_out)
            assert app_out is not None
            resiz_attr = app_out.get_attr("resizeableActivity")
            self.assertIsNotNone(resiz_attr)
            assert resiz_attr is not None
            self.assertFalse(resiz_attr.get_value())

            # 2. revive with --enable-resizable
            out_apk_optin = os.path.join(tmp_dir, "out_optin.apk")
            args_optin = argparse.Namespace(
                apk=in_apk,
                output=out_apk_optin,
                dry_run=False,
                enable_60hz=False,
                enable_cutout=False,
                enable_resizable=True,
                ks=None,
                ks_pass=None,
                ks_alias=None,
                key_pass=None,
                json=False,
            )
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                code_optin = revive_cmd(args_optin)
            self.assertEqual(code_optin, VERDICT_EXIT_CODES["YELLOW"])
            self.assertNotIn("Skipped EXPAND_ASPECT_RATIO (opt-in requires --enable-resizable)", mock_out.getvalue())

            # Verify resizeableActivity IS injected as true in output APK
            with zipfile.ZipFile(out_apk_optin, "r") as zf_out:
                out_manifest_optin = zf_out.read("AndroidManifest.xml")
            node_optin = AxmlSurgeon.parse(out_manifest_optin)
            app_optin = node_optin.find_child("application")
            self.assertIsNotNone(app_optin)
            assert app_optin is not None
            resiz_attr_optin = app_optin.get_attr("resizeableActivity")
            self.assertIsNotNone(resiz_attr_optin)
            assert resiz_attr_optin is not None
            self.assertTrue(resiz_attr_optin.get_value())

    def test_triage_and_revive_risk_levels_output(self):
        """Verifies triage and revive outputs (both text and JSON) display risk levels (LOW, MEDIUM, HIGH) for each transform."""
        manifest = AxmlNode(tag="manifest")
        manifest.set_attr("package", "com.apkrevive.risks", ns="")
        uses_sdk = AxmlNode(tag="uses-sdk")
        uses_sdk.set_attr("targetSdkVersion", 28)
        manifest.children.append(uses_sdk)
        app = AxmlNode(tag="application")
        app.set_attr("hasCode", False)
        app.set_attr("resizeableActivity", False)
        manifest.children.append(app)
        raw_manifest = AxmlSurgeon.serialize(manifest)

        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "risks_test.apk")
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("AndroidManifest.xml", raw_manifest)
                zf.writestr("classes.dex", b"DEX\n035\x00org/apache/http/client/HttpClient")

            # 1. Triage human-readable text output
            triage_args_text = argparse.Namespace(
                apk=apk_path,
                device_api=35,
                device_abis="arm64-v8a",
                page_size=16384,
                device_floor=24,
                target_sdk=28,
                apk_abis="arm64-v8a",
                uses_apache_http=True,
                json=False,
            )
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                triage_cmd(triage_args_text)
            text_out = mock_out.getvalue()
            self.assertIn("Required Transforms (", text_out)
            self.assertIn("INJECT_USES_LIBRARY_APACHE_HTTP [Risk: LOW]", text_out)
            self.assertIn("SET_HAS_CODE_TRUE [Risk: MEDIUM]", text_out)
            self.assertIn("EXPAND_ASPECT_RATIO [Risk: HIGH]", text_out)

            # 2. Triage JSON output
            triage_args_json = argparse.Namespace(
                apk=apk_path,
                device_api=35,
                device_abis="arm64-v8a",
                page_size=16384,
                device_floor=24,
                target_sdk=28,
                apk_abis="arm64-v8a",
                uses_apache_http=True,
                json=True,
            )
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                triage_cmd(triage_args_json)
            json_res = json.loads(mock_out.getvalue())
            self.assertIn("transform_risks", json_res)
            self.assertEqual(json_res["transform_risks"]["INJECT_USES_LIBRARY_APACHE_HTTP"], "LOW")
            self.assertEqual(json_res["transform_risks"]["SET_HAS_CODE_TRUE"], "MEDIUM")
            self.assertEqual(json_res["transform_risks"]["EXPAND_ASPECT_RATIO"], "HIGH")

            # 3. Revive text output (dry-run)
            revive_args_text = argparse.Namespace(
                apk=apk_path,
                output=os.path.join(tmp_dir, "unused.apk"),
                dry_run=True,
                enable_60hz=True,
                enable_cutout=False,
                enable_resizable=False,
                ks=None,
                ks_pass=None,
                ks_alias=None,
                key_pass=None,
                json=False,
            )
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                revive_cmd(revive_args_text)
            revive_text = mock_out.getvalue()
            self.assertIn("Required Transforms (", revive_text)
            self.assertIn("INJECT_USES_LIBRARY_APACHE_HTTP [Risk: LOW]", revive_text)
            self.assertIn("SET_HAS_CODE_TRUE [Risk: MEDIUM]", revive_text)
            self.assertIn("LOCK_60HZ_DISPLAY_MODE [Risk: MEDIUM]", revive_text)
            self.assertIn("EXPAND_ASPECT_RATIO [Risk: HIGH]", revive_text)
            self.assertIn("Skipped EXPAND_ASPECT_RATIO (opt-in requires --enable-resizable)", revive_text)

            # 4. Revive JSON output (dry-run)
            revive_args_json = argparse.Namespace(
                apk=apk_path,
                output=os.path.join(tmp_dir, "unused.apk"),
                dry_run=True,
                enable_60hz=True,
                enable_cutout=False,
                enable_resizable=False,
                ks=None,
                ks_pass=None,
                ks_alias=None,
                key_pass=None,
                json=True,
            )
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                revive_cmd(revive_args_json)
            revive_json = json.loads(mock_out.getvalue())
            self.assertIn("transform_risks", revive_json)
            self.assertEqual(revive_json["transform_risks"]["INJECT_USES_LIBRARY_APACHE_HTTP"], "LOW")
            self.assertEqual(revive_json["transform_risks"]["SET_HAS_CODE_TRUE"], "MEDIUM")
            self.assertEqual(revive_json["transform_risks"]["LOCK_60HZ_DISPLAY_MODE"], "MEDIUM")
            self.assertEqual(revive_json["transform_risks"]["EXPAND_ASPECT_RATIO"], "HIGH")

    def test_revive_parser_has_enable_resizable_argument(self):
        """Verifies that the revive argument parser recognizes --enable-resizable."""
        with patch("sys.argv", ["apkrevive", "revive", "--help"]):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                with self.assertRaises(SystemExit) as cm:
                    main()
                self.assertEqual(cm.exception.code, 0)
                help_text = mock_out.getvalue()
                self.assertIn("--enable-resizable", help_text)
                self.assertIn("resizeableActivity=true", help_text)

    def test_page_size_compat_unverified_guard_cli(self):
        """Verifies triage and revive CLI mark PAGE_SIZE_COMPAT as UNVERIFIED when no API 36 16KB PASS result exists."""
        manifest = AxmlNode(tag="manifest")
        manifest.set_attr("package", "com.apkrevive.pagesize", ns="")
        app = AxmlNode(tag="application")
        manifest.children.append(app)
        raw_manifest = AxmlSurgeon.serialize(manifest)

        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "pagesize_test.apk")
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("AndroidManifest.xml", raw_manifest)
                zf.writestr("classes.dex", b"DEX\n035\x00")
                # Add an unaligned 64-bit ELF
                elf_data = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
                elf_data += (2).to_bytes(2, "little")  # ET_EXEC
                elf_data += (183).to_bytes(2, "little")  # EM_AARCH64
                elf_data += (1).to_bytes(4, "little")  # version
                elf_data += (0x4000).to_bytes(8, "little")  # entry
                elf_data += (64).to_bytes(8, "little")  # phoff
                elf_data += (0).to_bytes(8, "little")  # shoff
                elf_data += (0).to_bytes(4, "little")  # flags
                elf_data += (64).to_bytes(2, "little")  # ehsize
                elf_data += (56).to_bytes(2, "little")  # phentsize
                elf_data += (1).to_bytes(2, "little")  # phnum
                elf_data += (0).to_bytes(2, "little")
                elf_data += (0).to_bytes(2, "little")
                elf_data += (0).to_bytes(2, "little")
                # Program header PT_LOAD with 4096 align
                ph = (1).to_bytes(4, "little")  # PT_LOAD
                ph += (5).to_bytes(4, "little")  # PF_R | PF_X
                ph += (0).to_bytes(8, "little")  # offset
                ph += (0x1000).to_bytes(8, "little")  # vaddr
                ph += (0x1000).to_bytes(8, "little")  # paddr
                ph += (0x100).to_bytes(8, "little")  # filesz
                ph += (0x100).to_bytes(8, "little")  # memsz
                ph += (4096).to_bytes(8, "little")  # align: 4KB (< 16KB)
                elf_data += ph
                zf.writestr("lib/arm64-v8a/libtest.so", bytes(elf_data))

            # 1. Triage human-readable text output (unverified)
            triage_args_text = argparse.Namespace(
                apk=apk_path,
                device_api=36,
                device_abis="arm64-v8a",
                page_size=16384,
                device_floor=24,
                target_sdk=28,
                apk_abis="arm64-v8a",
                uses_apache_http=False,
                json=False,
            )
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                code = triage_cmd(triage_args_text)
            self.assertEqual(code, VERDICT_EXIT_CODES["YELLOW"])
            text_out = mock_out.getvalue()
            self.assertIn("Verdict: YELLOW (UNVERIFIED)", text_out)
            self.assertIn("PAGE_SIZE_COMPAT [Risk: HIGH] (UNVERIFIED)", text_out)
            self.assertIn("pageSizeCompat mode is unverified; no API 36 16KB device result in results/", text_out)

            # 2. Triage JSON output (unverified)
            triage_args_json = argparse.Namespace(
                apk=apk_path,
                device_api=36,
                device_abis="arm64-v8a",
                page_size=16384,
                device_floor=24,
                target_sdk=28,
                apk_abis="arm64-v8a",
                uses_apache_http=False,
                json=True,
            )
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                code = triage_cmd(triage_args_json)
            self.assertEqual(code, VERDICT_EXIT_CODES["YELLOW"])
            json_res = json.loads(mock_out.getvalue())
            self.assertEqual(json_res["verdict"], "YELLOW")
            self.assertEqual(json_res["verdict_display"], "YELLOW (UNVERIFIED)")
            self.assertFalse(json_res["page_size_compat_verified"])
            self.assertIn("PAGE_SIZE_COMPAT", json_res["required_transforms"])

            # 3. Revive dry-run text output (unverified)
            revive_args_text = argparse.Namespace(
                apk=apk_path,
                output=os.path.join(tmp_dir, "unused.apk"),
                dry_run=True,
                enable_60hz=False,
                enable_cutout=False,
                enable_resizable=False,
                device_api=36,
                page_size=16384,
                ks=None,
                ks_pass=None,
                ks_alias=None,
                key_pass=None,
                json=False,
            )
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                code = revive_cmd(revive_args_text)
            self.assertEqual(code, VERDICT_EXIT_CODES["YELLOW"])
            revive_text = mock_out.getvalue()
            self.assertIn("Verdict: YELLOW (UNVERIFIED)", revive_text)
            self.assertIn("PAGE_SIZE_COMPAT [Risk: HIGH] (UNVERIFIED)", revive_text)

            # 4. Revive dry-run JSON output (unverified)
            revive_args_json = argparse.Namespace(
                apk=apk_path,
                output=os.path.join(tmp_dir, "unused.apk"),
                dry_run=True,
                enable_60hz=False,
                enable_cutout=False,
                enable_resizable=False,
                device_api=36,
                page_size=16384,
                ks=None,
                ks_pass=None,
                ks_alias=None,
                key_pass=None,
                json=True,
            )
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                revive_cmd(revive_args_json)
            revive_json = json.loads(mock_out.getvalue())
            self.assertEqual(revive_json["verdict"], "YELLOW")
            self.assertEqual(revive_json["verdict_display"], "YELLOW (UNVERIFIED)")
            self.assertFalse(revive_json["page_size_compat_verified"])

            # 5. Mock verification returning True (verified)
            with patch("apkrevive.core.triage.is_page_size_compat_verified", return_value=True):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                    triage_cmd(triage_args_text)
                verified_text = mock_out.getvalue()
                self.assertIn("Verdict: YELLOW", verified_text)
                self.assertNotIn("Verdict: YELLOW (UNVERIFIED)", verified_text)
                self.assertIn("PAGE_SIZE_COMPAT [Risk: HIGH]", verified_text)
                self.assertNotIn("(UNVERIFIED)", verified_text)

                with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                    triage_cmd(triage_args_json)
                verified_json = json.loads(mock_out.getvalue())
                self.assertEqual(verified_json["verdict"], "YELLOW")
                self.assertTrue(verified_json["page_size_compat_verified"])

                with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                    revive_cmd(revive_args_text)
                revive_verified_text = mock_out.getvalue()
                self.assertIn("Verdict: YELLOW", revive_verified_text)
                self.assertNotIn("(UNVERIFIED)", revive_verified_text)

                with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                    revive_cmd(revive_args_json)
                revive_verified_json = json.loads(mock_out.getvalue())
                self.assertEqual(revive_verified_json["verdict"], "YELLOW")
                self.assertTrue(revive_verified_json["page_size_compat_verified"])


if __name__ == "__main__":
    unittest.main()
