"""
test_adb.py - Tests for ADB bridge, device probing, and target SDK floor active detection.
"""

import subprocess
import unittest
from unittest.mock import patch, MagicMock

from apkrevive.adb.bridge import find_adb, AdbBridge
from apkrevive.adb.probe import probe_install_floor, AOSP_ERROR_REGEX


class TestFindAdb(unittest.TestCase):
    def test_custom_path_existing(self):
        with patch("os.path.exists", return_value=True):
            res = find_adb("/custom/path/adb")
            self.assertEqual(res, "/custom/path/adb")

    def test_custom_path_nonexistent_fallback_to_which(self):
        with patch("os.path.exists", return_value=False), \
             patch("shutil.which", return_value="/usr/bin/adb"):
            res = find_adb("/bad/path/adb")
            self.assertEqual(res, "/usr/bin/adb")

    def test_which_adb_found(self):
        with patch("shutil.which", return_value="/usr/local/bin/adb"):
            res = find_adb("adb")
            self.assertEqual(res, "/usr/local/bin/adb")

    def test_env_sdk_root_discovery(self):
        with patch("shutil.which", return_value=None), \
             patch.dict("os.environ", {"ANDROID_HOME": "/mock/android/sdk"}, clear=True), \
             patch("os.path.exists", side_effect=lambda p: "platform-tools" in str(p)):
            res = find_adb("adb")
            self.assertIn("platform-tools", res)

    def test_fallback_default(self):
        with patch("shutil.which", return_value=None), \
             patch.dict("os.environ", {}, clear=True), \
             patch("os.path.exists", return_value=False):
            res = find_adb("adb")
            self.assertEqual(res, "adb")


class TestAdbBridge(unittest.TestCase):
    def setUp(self):
        with patch("apkrevive.adb.bridge.find_adb", return_value="mock_adb"):
            self.bridge_no_serial = AdbBridge(adb_path="mock_adb")
            self.bridge_with_serial = AdbBridge(adb_path="mock_adb", serial="device-1234")

    @patch("subprocess.run")
    def test_cmd_without_serial(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["mock_adb", "version"], returncode=0, stdout="Android Debug Bridge 1.0.41\n", stderr=""
        )
        code, out, err = self.bridge_no_serial._cmd(["version"])
        self.assertEqual(code, 0)
        self.assertIn("Android Debug Bridge", out)
        mock_run.assert_called_once_with(
            ["mock_adb", "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

    @patch("subprocess.run")
    def test_cmd_with_serial(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["mock_adb", "-s", "device-1234", "get-serialno"], returncode=0, stdout="device-1234\n", stderr=""
        )
        code, out, err = self.bridge_with_serial._cmd(["get-serialno"])
        self.assertEqual(code, 0)
        mock_run.assert_called_once_with(
            ["mock_adb", "-s", "device-1234", "get-serialno"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

    @patch.object(AdbBridge, "_cmd")
    def test_get_serial(self, mock_cmd):
        mock_cmd.return_value = (0, "emulator-5554\n", "")
        self.assertEqual(self.bridge_no_serial.get_serial(), "emulator-5554")

        mock_cmd.return_value = (1, "", "error")
        self.assertEqual(self.bridge_no_serial.get_serial(), "")

    @patch.object(AdbBridge, "_cmd")
    def test_get_prop(self, mock_cmd):
        mock_cmd.return_value = (0, "35\n", "")
        self.assertEqual(self.bridge_no_serial.get_prop("ro.build.version.sdk"), "35")

        mock_cmd.return_value = (1, "", "error")
        self.assertEqual(self.bridge_no_serial.get_prop("ro.build.version.sdk"), "")

    @patch.object(AdbBridge, "_cmd")
    def test_uninstall(self, mock_cmd):
        mock_cmd.return_value = (0, "Success\n", "")
        self.assertTrue(self.bridge_no_serial.uninstall("com.example.app"))

        mock_cmd.return_value = (1, "Failure [DELETE_FAILED_INTERNAL_ERROR]\n", "")
        self.assertFalse(self.bridge_no_serial.uninstall("com.example.app"))

        mock_cmd.return_value = (0, "Failure\n", "")
        self.assertFalse(self.bridge_no_serial.uninstall("com.example.app"))

    def test_uninstall_malformed_package_name_raises_value_error(self):
        malformed_packages = [
            "-k evil.pkg",
            "not_a_package",
            "com..invalid",
            "; rm -rf /",
            "com.example;evil",
            "",
            ".com.startdot",
        ]
        for pkg in malformed_packages:
            with self.subTest(pkg=pkg):
                with self.assertRaises(ValueError) as ctx:
                    self.bridge_no_serial.uninstall(pkg)
                self.assertIn("Invalid Android package name", str(ctx.exception))

    def test_install_lifecycle_malformed_package_name_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            self.bridge_no_serial.install_lifecycle("dummy.apk", "-k evil.pkg", 28, 24)
        self.assertIn("Invalid Android package name", str(ctx.exception))

    @patch.object(AdbBridge, "_cmd")
    def test_install_without_bypass(self, mock_cmd):
        mock_cmd.return_value = (0, "Success\n", "")
        success, log = self.bridge_no_serial.install("/path/to/app.apk", bypass_low_target_sdk=False)
        self.assertTrue(success)
        self.assertEqual(log, "Success\n")
        mock_cmd.assert_called_with(["install", "/path/to/app.apk"])

    @patch.object(AdbBridge, "_cmd")
    def test_install_with_bypass(self, mock_cmd):
        mock_cmd.return_value = (0, "Success\n", "")
        success, log = self.bridge_no_serial.install("/path/to/app.apk", bypass_low_target_sdk=True)
        self.assertTrue(success)
        mock_cmd.assert_called_with(["install", "--bypass-low-target-sdk-block", "/path/to/app.apk"])

    @patch.object(AdbBridge, "install")
    @patch.object(AdbBridge, "uninstall")
    def test_install_lifecycle_success_first_try(self, mock_uninstall, mock_install):
        mock_install.return_value = (True, "Success\n")
        success, log = self.bridge_no_serial.install_lifecycle("app.apk", "com.test", 28, 24)
        self.assertTrue(success)
        self.assertEqual(log, "Success\n")
        mock_uninstall.assert_called_once_with("com.test")
        mock_install.assert_called_once_with("app.apk", bypass_low_target_sdk=False)

    @patch.object(AdbBridge, "install")
    @patch.object(AdbBridge, "uninstall")
    def test_install_lifecycle_retry_with_bypass(self, mock_uninstall, mock_install):
        mock_install.side_effect = [
            (False, "Failure [INSTALL_FAILED_DEPRECATED_SDK_VERSION: App must target >= 24]"),
            (True, "Success\n"),
        ]
        success, log = self.bridge_no_serial.install_lifecycle("app.apk", "com.test", 21, 24)
        self.assertTrue(success)
        self.assertEqual(log, "Success\n")
        self.assertEqual(mock_uninstall.call_count, 2)
        self.assertEqual(mock_install.call_count, 2)

    @patch.object(AdbBridge, "install")
    @patch.object(AdbBridge, "uninstall")
    def test_install_lifecycle_non_sdk_failure(self, mock_uninstall, mock_install):
        mock_install.return_value = (False, "Failure [INSTALL_FAILED_INVALID_APK]")
        success, log = self.bridge_no_serial.install_lifecycle("app.apk", "com.test", 28, 24)
        self.assertFalse(success)
        self.assertEqual(mock_uninstall.call_count, 1)
        self.assertEqual(mock_install.call_count, 1)


class TestProbeInstallFloor(unittest.TestCase):
    def setUp(self):
        self.bridge = MagicMock(spec=AdbBridge)

    def test_future_api_level(self):
        self.bridge.get_prop.side_effect = lambda prop: "36" if prop == "ro.build.version.sdk" else ""
        res = probe_install_floor(self.bridge)
        self.assertEqual(res["floor"], "UNKNOWN")
        self.assertEqual(res["status"], "UNKNOWN_FUTURE_API")
        self.assertEqual(res["sdk"], 36)

    def test_confirmed_via_prop(self):
        def mock_get_prop(prop):
            if prop == "ro.build.version.sdk":
                return "35"
            if prop == "ro.build.version.min_supported_target_sdk":
                return "24"
            return ""

        self.bridge.get_prop.side_effect = mock_get_prop
        res = probe_install_floor(self.bridge)
        self.assertEqual(res["floor"], 24)
        self.assertEqual(res["status"], "CONFIRMED_VIA_PROP")
        self.assertEqual(res["sdk"], 35)

    def test_probe_apk_success_no_floor(self):
        def mock_get_prop(prop):
            if prop == "ro.build.version.sdk":
                return "35"
            return ""

        self.bridge.get_prop.side_effect = mock_get_prop
        self.bridge.install.return_value = (True, "Success\n")

        res = probe_install_floor(self.bridge, probe_apk_path="/path/to/probe.apk")
        self.assertEqual(res["floor"], "NONE")
        self.assertEqual(res["status"], "SUCCESS_NO_FLOOR")
        self.assertEqual(res["sdk"], 35)
        self.bridge.uninstall.assert_called_once_with("com.apkrevive.probe")

    def test_probe_apk_failure_aosp_regex_match(self):
        def mock_get_prop(prop):
            if prop == "ro.build.version.sdk":
                return "35"
            return ""

        self.bridge.get_prop.side_effect = mock_get_prop
        err_msg = (
            "Failure [INSTALL_FAILED_DEPRECATED_SDK_VERSION: "
            "App package must target at least SDK version 24, but found 21]"
        )
        self.bridge.install.return_value = (False, err_msg)

        res = probe_install_floor(self.bridge, probe_apk_path="/path/to/probe.apk")
        self.assertEqual(res["floor"], 24)
        self.assertEqual(res["status"], "DETECTED_VIA_AOSP_ERROR")
        self.assertEqual(res["sdk"], 35)

    def test_probe_apk_failure_no_regex_fallback_to_baseline(self):
        def mock_get_prop(prop):
            if prop == "ro.build.version.sdk":
                return "35"
            return ""

        self.bridge.get_prop.side_effect = mock_get_prop
        self.bridge.install.return_value = (False, "Failure [INSTALL_PARSE_FAILED_NOT_APK]")

        res = probe_install_floor(self.bridge, probe_apk_path="/path/to/probe.apk")
        self.assertEqual(res["floor"], 24)
        self.assertEqual(res["status"], "STANDARD_BASELINE")
        self.assertEqual(res["sdk"], 35)

    def test_baseline_standard_floor_sdk35(self):
        self.bridge.get_prop.side_effect = lambda prop: "35" if prop == "ro.build.version.sdk" else ""
        res = probe_install_floor(self.bridge)
        self.assertEqual(res["floor"], 24)
        self.assertEqual(res["status"], "STANDARD_BASELINE")
        self.assertEqual(res["sdk"], 35)

    def test_baseline_standard_floor_sdk34(self):
        self.bridge.get_prop.side_effect = lambda prop: "34" if prop == "ro.build.version.sdk" else ""
        res = probe_install_floor(self.bridge)
        self.assertEqual(res["floor"], 23)
        self.assertEqual(res["status"], "STANDARD_BASELINE")
        self.assertEqual(res["sdk"], 34)

    def test_baseline_standard_floor_sdk33(self):
        self.bridge.get_prop.side_effect = lambda prop: "33" if prop == "ro.build.version.sdk" else ""
        res = probe_install_floor(self.bridge)
        self.assertEqual(res["floor"], 1)
        self.assertEqual(res["status"], "STANDARD_BASELINE")
        self.assertEqual(res["sdk"], 33)

    def test_non_digit_sdk_defaults_to_35(self):
        self.bridge.get_prop.side_effect = lambda prop: "unknown" if prop == "ro.build.version.sdk" else ""
        res = probe_install_floor(self.bridge)
        self.assertEqual(res["floor"], 24)
        self.assertEqual(res["status"], "STANDARD_BASELINE")
        self.assertEqual(res["sdk"], 35)

    def test_aosp_error_regex_direct(self):
        text = "App package must target at least SDK version 24, but found 21"
        m = AOSP_ERROR_REGEX.search(text)
        self.assertIsNotNone(m)
        if m:
            self.assertEqual(m.group(1), "24")
            self.assertEqual(m.group(2), "21")


if __name__ == "__main__":
    unittest.main()
