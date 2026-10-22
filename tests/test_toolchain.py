"""
test_toolchain.py - Comprehensive tests for toolchain discovery, resolution, and 'apkrevive doctor'.
"""

import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from apkrevive.core.toolchain import (
    find_jdk_tool,
    find_sdk_tool,
    diagnose_tools,
    run_doctor,
)
from apkrevive.cli import main
from apkrevive.core.signer import ensure_keystore, get_apksigner_cmd
from apkrevive.core.verify import get_aapt2_cmd
from apkrevive.shim.build_shim import resolve_tool


class TestToolchainDiscovery(unittest.TestCase):

    def test_find_jdk_tool_shutil_which(self):
        with patch("shutil.which", return_value="/mock/bin/keytool"):
            self.assertEqual(find_jdk_tool("keytool"), "/mock/bin/keytool")

    def test_find_jdk_tool_java_home(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            jh = Path(tmp_dir) / "jdk"
            bin_dir = jh / "bin"
            bin_dir.mkdir(parents=True)
            tool_name = "keytool.exe" if sys.platform == "win32" else "keytool"
            fake_tool = bin_dir / tool_name
            fake_tool.write_text("fake binary")

            with patch("shutil.which", return_value=None), \
                 patch.dict(os.environ, {"JAVA_HOME": str(jh)}):
                res = find_jdk_tool("keytool")
                self.assertIsNotNone(res)
                self.assertEqual(Path(res).resolve(), fake_tool.resolve())

    def test_find_jdk_tool_from_javac_symlink(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            bin_dir = Path(tmp_dir) / "bin"
            bin_dir.mkdir(parents=True)
            javac_name = "javac.exe" if sys.platform == "win32" else "javac"
            keytool_name = "keytool.exe" if sys.platform == "win32" else "keytool"
            fake_javac = bin_dir / javac_name
            fake_keytool = bin_dir / keytool_name
            fake_javac.write_text("javac")
            fake_keytool.write_text("keytool")

            with patch("shutil.which", side_effect=lambda name: str(fake_javac) if "javac" in name else None), \
                 patch.dict(os.environ, {}, clear=True):
                res = find_jdk_tool("keytool")
                self.assertIsNotNone(res)
                self.assertEqual(Path(res).resolve(), fake_keytool.resolve())

    def test_find_jdk_tool_common_jvm_roots(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_root = Path(tmp_dir) / "Program Files" / "Java" / "jdk-17" / "bin"
            fake_root.mkdir(parents=True)
            fake_binary = fake_root / ("keytool.exe" if sys.platform == "win32" else "keytool")
            fake_binary.write_text("fake")

            with patch("shutil.which", return_value=None), \
                 patch.dict(os.environ, {"JAVA_HOME": ""}), \
                 patch("glob.glob", return_value=[str(fake_binary)]):
                res = find_jdk_tool("keytool")
                self.assertEqual(res, str(fake_binary))

    def test_find_jdk_tool_not_found(self):
        with patch("shutil.which", return_value=None), \
             patch.dict(os.environ, {}, clear=True), \
             patch("glob.glob", return_value=[]):
            self.assertIsNone(find_jdk_tool("nonexistent_tool_xyz"))

    def test_find_sdk_tool_build_tools_dir(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            bt = Path(tmp_dir) / "build-tools" / "35.0.0"
            bt.mkdir(parents=True)
            cand_name = "apksigner.bat" if sys.platform == "win32" else "apksigner"
            fake_tool = bt / cand_name
            fake_tool.write_text("fake")

            res = find_sdk_tool("apksigner", build_tools_dir=bt)
            self.assertEqual(res, str(fake_tool))

    def test_find_sdk_tool_shutil_which(self):
        with patch("shutil.which", return_value="/mock/android/apksigner"):
            self.assertEqual(find_sdk_tool("apksigner"), "/mock/android/apksigner")

    def test_find_sdk_tool_sdk_roots_build_tools(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sdk = Path(tmp_dir) / "AndroidSdk"
            bt34 = sdk / "build-tools" / "34.0.0"
            bt35 = sdk / "build-tools" / "35.0.0"
            bt34.mkdir(parents=True)
            bt35.mkdir(parents=True)
            cand_name = "d8.bat" if sys.platform == "win32" else "d8"
            (bt34 / cand_name).write_text("34")
            tool35 = bt35 / cand_name
            tool35.write_text("35")

            with patch("shutil.which", return_value=None), \
                 patch.dict(os.environ, {"ANDROID_HOME": str(sdk)}):
                res = find_sdk_tool("d8")
                self.assertEqual(res, str(tool35))

    def test_find_sdk_tool_platform_tools(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sdk = Path(tmp_dir) / "AndroidSdk"
            pt = sdk / "platform-tools"
            pt.mkdir(parents=True)
            cand_name = "adb.exe" if sys.platform == "win32" else "adb"
            fake_adb = pt / cand_name
            fake_adb.write_text("adb")

            with patch("shutil.which", return_value=None), \
                 patch.dict(os.environ, {"ANDROID_HOME": str(sdk)}):
                res = find_sdk_tool("adb")
                self.assertEqual(res, str(fake_adb))

    def test_find_sdk_tool_not_found(self):
        with patch("shutil.which", return_value=None), \
             patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(find_sdk_tool("nonexistent_sdk_tool"))

    def test_diagnose_tools_structure(self):
        diag = diagnose_tools()
        expected_tools = ["python", "keytool", "javac", "d8", "aapt2", "apksigner", "adb"]
        for t in expected_tools:
            self.assertIn(t, diag)
            self.assertIn("path", diag[t])
            self.assertIn("found", diag[t])
            self.assertIn("required_for_signing", diag[t])
            self.assertIn("hint", diag[t])

        self.assertTrue(diag["python"]["found"])
        self.assertTrue(diag["keytool"]["required_for_signing"])
        self.assertTrue(diag["apksigner"]["required_for_signing"])
        self.assertFalse(diag["javac"]["required_for_signing"])
        self.assertFalse(diag["d8"]["required_for_signing"])
        self.assertFalse(diag["aapt2"]["required_for_signing"])
        self.assertFalse(diag["adb"]["required_for_signing"])

    def test_run_doctor_exit_codes(self):
        # Case 1: Both signing tools present -> exit 0
        mock_diag_ok = {
            "python": {"path": "/usr/bin/python3", "found": True, "required_for_signing": False, "hint": ""},
            "keytool": {"path": "/usr/bin/keytool", "found": True, "required_for_signing": True, "hint": "jdk hint"},
            "javac": {"path": "/usr/bin/javac", "found": True, "required_for_signing": False, "hint": "jdk hint"},
            "d8": {"path": "/sdk/d8", "found": True, "required_for_signing": False, "hint": "bt hint"},
            "aapt2": {"path": "/sdk/aapt2", "found": True, "required_for_signing": False, "hint": "bt hint"},
            "apksigner": {"path": "/sdk/apksigner", "found": True, "required_for_signing": True, "hint": "bt hint"},
            "adb": {"path": "/sdk/adb", "found": True, "required_for_signing": False, "hint": "pt hint"},
        }
        with patch("apkrevive.core.toolchain.diagnose_tools", return_value=mock_diag_ok):
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                code = run_doctor()
                self.assertEqual(code, 0)
                self.assertIn("[OK]", out.getvalue())
                self.assertIn("Toolchain check passed", out.getvalue())

        # Case 2: keytool or apksigner missing -> exit 1
        mock_diag_missing = dict(mock_diag_ok)
        mock_diag_missing["apksigner"] = {
            "path": None,
            "found": False,
            "required_for_signing": True,
            "hint": "Install Android SDK build-tools via sdkmanager 'build-tools;35.0.0'",
        }
        with patch("apkrevive.core.toolchain.diagnose_tools", return_value=mock_diag_missing):
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                code = run_doctor()
                self.assertEqual(code, 1)
                self.assertIn("[MISSING]", out.getvalue())
                self.assertIn("Toolchain check failed", out.getvalue())
                self.assertIn("Install Android SDK build-tools", out.getvalue())

    def test_cli_doctor_subcommand(self):
        with patch("apkrevive.cli.run_doctor", return_value=0) as mock_doc:
            code = main(["doctor"])
            self.assertEqual(code, 0)
            mock_doc.assert_called_once()

    def test_cli_patch_fail_fast_on_missing_signing_tools(self):
        with patch("apkrevive.cli.find_jdk_tool", return_value=None), \
             patch("apkrevive.cli.find_sdk_tool", return_value=None):
            stderr_buf = io.StringIO()
            with patch("sys.stderr", stderr_buf):
                code = main(["patch", "dummy.apk"])
                self.assertEqual(code, 1)
                err = stderr_buf.getvalue()
                self.assertIn("Missing required signing tool(s)", err)
                self.assertIn("apkrevive doctor", err)

    def test_cli_patch_no_sign_bypasses_check(self):
        with patch("apkrevive.cli.run_patch") as mock_run:
            mock_run.return_value.to_dict.return_value = {}
            with patch("apkrevive.cli.format_patch_report", return_value="OK"):
                code = main(["patch", "--no-sign", "dummy.apk"])
                self.assertEqual(code, 0)
                self.assertTrue(mock_run.called)

    def test_signer_ensure_keystore_missing_keytool_raises_runtime_error(self):
        with tempfile.TemporaryDirectory() as tmp_home:
            with patch("pathlib.Path.home", return_value=Path(tmp_home)), \
                 patch("apkrevive.core.signer.find_jdk_tool", return_value=None):
                with self.assertRaises(RuntimeError) as ctx:
                    ensure_keystore(keystore_path=None)
                self.assertIn("keytool binary not found", str(ctx.exception))
                self.assertIn("apkrevive doctor", str(ctx.exception))

    def test_signer_get_apksigner_cmd_uses_find_sdk_tool(self):
        with patch("apkrevive.core.signer.find_sdk_tool", return_value="/resolved/path/apksigner"):
            self.assertEqual(get_apksigner_cmd(), "/resolved/path/apksigner")

    def test_verify_get_aapt2_cmd_uses_find_sdk_tool(self):
        with patch("apkrevive.core.verify.find_sdk_tool", return_value="/resolved/path/aapt2"):
            self.assertEqual(get_aapt2_cmd(), "/resolved/path/aapt2")

    def test_build_shim_resolve_tool_uses_discovery(self):
        with patch("apkrevive.shim.build_shim.find_jdk_tool", return_value="/resolved/javac"):
            self.assertEqual(resolve_tool("javac"), "/resolved/javac")
        with patch("apkrevive.shim.build_shim.find_sdk_tool", return_value="/resolved/d8"):
            self.assertEqual(resolve_tool("d8"), "/resolved/d8")


if __name__ == "__main__":
    unittest.main()
