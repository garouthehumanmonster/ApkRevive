"""
test_doctor.py - Tests for host environment prerequisite diagnostics engine (doctor.py).
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, mock_open
import argparse

from apkrevive.core.doctor import (
    check_python,
    check_jdk,
    check_android_sdk,
    check_build_tools,
    check_adb,
    check_keystore_dir,
    check_shim_dex,
    run_doctor,
    format_doctor_report,
    EXPECTED_SHIM_DEX_SHA256,
)
from apkrevive.cli import doctor_cmd


class TestDoctor(unittest.TestCase):
    def test_check_python_pass(self):
        res = check_python()
        self.assertEqual(res["status"], "PASS")
        self.assertIn("Python", res["details"])

    def test_check_python_fail(self):
        from collections import namedtuple
        VInfo = namedtuple("VInfo", ["major", "minor", "micro", "releaselevel", "serial"])
        with patch.object(sys, "version_info", VInfo(3, 8, 0, "final", 0)):
            res = check_python()
            self.assertEqual(res["status"], "FAIL")
            self.assertIn("<3.9", res["details"])

    def test_check_jdk_both_in_path(self):
        with patch("shutil.which", side_effect=lambda x: f"/bin/{x}"):
            res = check_jdk()
            self.assertEqual(res["status"], "PASS")
            self.assertIn("keytool", res["details"])
            self.assertIn("javac", res["details"])

    def test_check_jdk_in_java_home(self):
        with patch("shutil.which", return_value=None), \
             patch.dict("os.environ", {"JAVA_HOME": "/opt/jdk"}, clear=True), \
             patch.object(Path, "is_file", return_value=True):
            res = check_jdk()
            self.assertEqual(res["status"], "PASS")

    def test_check_jdk_partial_warn(self):
        with patch("shutil.which", side_effect=lambda cmd: "/bin/keytool" if cmd == "keytool" else None), \
             patch.dict("os.environ", {}, clear=True):
            res = check_jdk()
            self.assertEqual(res["status"], "WARN")
            self.assertIn("missing javac", res["details"])

    def test_check_jdk_none_warn(self):
        with patch("shutil.which", return_value=None), \
             patch.dict("os.environ", {}, clear=True):
            res = check_jdk()
            self.assertEqual(res["status"], "WARN")
            self.assertIn("Neither keytool nor javac found", res["details"])

    def test_check_android_sdk_pass(self):
        with patch.dict("os.environ", {"ANDROID_HOME": "/opt/sdk"}, clear=True), \
             patch("os.path.isdir", return_value=True):
            res = check_android_sdk()
            self.assertEqual(res["status"], "PASS")

    def test_check_android_sdk_warn(self):
        with patch.dict("os.environ", {}, clear=True):
            res = check_android_sdk()
            self.assertEqual(res["status"], "WARN")

    def test_check_build_tools_all_in_path(self):
        with patch("shutil.which", side_effect=lambda x: f"/bin/{x}"):
            res = check_build_tools()
            self.assertEqual(res["status"], "PASS")

    def test_check_build_tools_in_sdk(self):
        with patch("shutil.which", return_value=None), \
             patch.dict("os.environ", {"ANDROID_HOME": "/opt/sdk"}, clear=True), \
             patch("os.path.exists", return_value=True), \
             patch("os.listdir", return_value=["34.0.0"]):
            res = check_build_tools()
            self.assertEqual(res["status"], "PASS")

    def test_check_build_tools_partial_warn(self):
        with patch("shutil.which", side_effect=lambda x: f"/bin/{x}" if x == "zipalign" else None), \
             patch.dict("os.environ", {}, clear=True):
            res = check_build_tools()
            self.assertEqual(res["status"], "WARN")
            self.assertIn("missing", res["details"])

    def test_check_build_tools_none_warn(self):
        with patch("shutil.which", return_value=None), \
             patch.dict("os.environ", {}, clear=True):
            res = check_build_tools()
            self.assertEqual(res["status"], "WARN")
            self.assertIn("None of", res["details"])

    def test_check_adb_in_path(self):
        with patch("shutil.which", return_value="/bin/adb"):
            res = check_adb()
            self.assertEqual(res["status"], "PASS")

    def test_check_adb_in_sdk(self):
        with patch("shutil.which", return_value=None), \
             patch.dict("os.environ", {"ANDROID_HOME": "/opt/sdk"}, clear=True), \
             patch.object(Path, "is_file", return_value=True):
            res = check_adb()
            self.assertEqual(res["status"], "PASS")

    def test_check_adb_missing_warn(self):
        with patch("shutil.which", return_value=None), \
             patch.dict("os.environ", {}, clear=True):
            res = check_adb()
            self.assertEqual(res["status"], "WARN")

    def test_check_keystore_dir_pass(self):
        with patch.object(Path, "mkdir", return_value=None):
            res = check_keystore_dir()
            self.assertEqual(res["status"], "PASS")

    def test_check_keystore_dir_warn_on_error(self):
        with patch.object(Path, "mkdir", side_effect=PermissionError("Permission denied")):
            res = check_keystore_dir()
            self.assertEqual(res["status"], "WARN")
            self.assertIn("Permission denied", res["details"])

    def test_check_shim_dex_missing_fail(self):
        with patch.object(Path, "is_file", return_value=False):
            res = check_shim_dex()
            self.assertEqual(res["status"], "FAIL")
            self.assertIn("missing", res["details"])

    def test_check_shim_dex_hash_match(self):
        with patch.object(Path, "is_file", return_value=True), \
             patch("builtins.open", mock_open(read_data=b"test_content")), \
             patch("hashlib.sha256") as mock_sha:
            mock_sha.return_value.hexdigest.return_value = EXPECTED_SHIM_DEX_SHA256
            res = check_shim_dex()
            self.assertEqual(res["status"], "PASS")

    def test_check_shim_dex_hash_mismatch(self):
        with patch.object(Path, "is_file", return_value=True), \
             patch("builtins.open", mock_open(read_data=b"test_content")), \
             patch("hashlib.sha256") as mock_sha:
            mock_sha.return_value.hexdigest.return_value = "bad_hash_value"
            res = check_shim_dex()
            self.assertEqual(res["status"], "FAIL")
            self.assertIn("SHA256 mismatch", res["details"])

    def test_check_shim_dex_read_error(self):
        with patch.object(Path, "is_file", return_value=True), \
             patch("builtins.open", side_effect=IOError("Read error")):
            res = check_shim_dex()
            self.assertEqual(res["status"], "FAIL")
            self.assertIn("Error reading shim DEX", res["details"])

    def test_run_doctor_overall_pass_warn_fail(self):
        # Case 1: All PASS
        with patch("apkrevive.core.doctor.check_python", return_value={"status": "PASS", "details": ""}), \
             patch("apkrevive.core.doctor.check_jdk", return_value={"status": "PASS", "details": ""}), \
             patch("apkrevive.core.doctor.check_android_sdk", return_value={"status": "PASS", "details": ""}), \
             patch("apkrevive.core.doctor.check_build_tools", return_value={"status": "PASS", "details": ""}), \
             patch("apkrevive.core.doctor.check_adb", return_value={"status": "PASS", "details": ""}), \
             patch("apkrevive.core.doctor.check_keystore_dir", return_value={"status": "PASS", "details": ""}), \
             patch("apkrevive.core.doctor.check_shim_dex", return_value={"status": "PASS", "details": ""}):
            res = run_doctor()
            self.assertEqual(res["status"], "PASS")

        # Case 2: One WARN
        with patch("apkrevive.core.doctor.check_python", return_value={"status": "PASS", "details": ""}), \
             patch("apkrevive.core.doctor.check_jdk", return_value={"status": "WARN", "details": ""}), \
             patch("apkrevive.core.doctor.check_android_sdk", return_value={"status": "PASS", "details": ""}), \
             patch("apkrevive.core.doctor.check_build_tools", return_value={"status": "PASS", "details": ""}), \
             patch("apkrevive.core.doctor.check_adb", return_value={"status": "PASS", "details": ""}), \
             patch("apkrevive.core.doctor.check_keystore_dir", return_value={"status": "PASS", "details": ""}), \
             patch("apkrevive.core.doctor.check_shim_dex", return_value={"status": "PASS", "details": ""}):
            res = run_doctor()
            self.assertEqual(res["status"], "WARN")

        # Case 3: One FAIL
        with patch("apkrevive.core.doctor.check_python", return_value={"status": "PASS", "details": ""}), \
             patch("apkrevive.core.doctor.check_jdk", return_value={"status": "FAIL", "details": ""}), \
             patch("apkrevive.core.doctor.check_android_sdk", return_value={"status": "PASS", "details": ""}), \
             patch("apkrevive.core.doctor.check_build_tools", return_value={"status": "PASS", "details": ""}), \
             patch("apkrevive.core.doctor.check_adb", return_value={"status": "PASS", "details": ""}), \
             patch("apkrevive.core.doctor.check_keystore_dir", return_value={"status": "PASS", "details": ""}), \
             patch("apkrevive.core.doctor.check_shim_dex", return_value={"status": "PASS", "details": ""}):
            res = run_doctor()
            self.assertEqual(res["status"], "FAIL")

    def test_format_doctor_report(self):
        mock_res = {
            "status": "PASS",
            "checks": {
                "python": {"status": "PASS", "details": "Python 3.10"},
                "adb": {"status": "PASS", "details": "ADB found"},
            }
        }
        report = format_doctor_report(mock_res)
        self.assertIn("ApkRevive Doctor Report", report)
        self.assertIn("[PASS]   Python Version: Python 3.10", report)
        self.assertIn("Overall Status: [PASS]", report)

    def test_cli_doctor_cmd_pass_and_json(self):
        args_text = argparse.Namespace(json=False)
        with patch("apkrevive.cli.run_doctor", return_value={"status": "PASS", "checks": {}}), \
             patch("sys.stdout"):
            code = doctor_cmd(args_text)
            self.assertEqual(code, 0)

        args_json = argparse.Namespace(json=True)
        with patch("apkrevive.cli.run_doctor", return_value={"status": "PASS", "checks": {}}), \
             patch("sys.stdout"):
            code = doctor_cmd(args_json)
            self.assertEqual(code, 0)

        args_fail = argparse.Namespace(json=False)
        with patch("apkrevive.cli.run_doctor", return_value={"status": "FAIL", "checks": {}}), \
             patch("sys.stdout"):
            code = doctor_cmd(args_fail)
            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
