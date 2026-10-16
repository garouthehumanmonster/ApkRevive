"""
test_cli.py - Comprehensive CLI test suite for ApkRevive v0.3.3.
"""

import io
import os
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from apkrevive.cli import triage_cmd, push_obb_cmd, probe_cmd, revive_cmd, main
from apkrevive.core.axml import AxmlSurgeon, AxmlNode
import argparse


class TestCli(unittest.TestCase):
    def test_cli_triage_green(self):
        args = argparse.Namespace(apk="test.apk", device_api=35, device_abis="arm64-v8a", page_size=16384, target_sdk=28, apk_abis="", uses_apache_http=False)
        with patch("sys.stdout", new_callable=io.StringIO):
            code = triage_cmd(args)
        self.assertEqual(code, 0)

    def test_cli_triage_red(self):
        args = argparse.Namespace(apk="test.apk", device_api=35, device_abis="arm64-v8a", page_size=16384, target_sdk=22, apk_abis="armeabi-v7a", uses_apache_http=False)
        with patch("sys.stdout", new_callable=io.StringIO):
            code = triage_cmd(args)
        self.assertEqual(code, 1)

    def test_cli_push_obb_valid(self):
        args = argparse.Namespace(obb="main.100.com.example.game.obb", package="com.example.game", current_apk_version=150)
        with patch("sys.stdout", new_callable=io.StringIO):
            code = push_obb_cmd(args)
        self.assertEqual(code, 0)

    def test_cli_push_obb_invalid(self):
        args = argparse.Namespace(obb="../../evil.obb", package="com.example.game", current_apk_version=150)
        with patch("sys.stdout", new_callable=io.StringIO):
            code = push_obb_cmd(args)
        self.assertEqual(code, 1)

    @patch("apkrevive.cli.probe_install_floor")
    def test_cli_probe(self, mock_probe):
        mock_probe.return_value = {"floor": 24, "status": "CONFIRMED_VIA_PROP", "sdk": 35}
        args = argparse.Namespace(device=None)
        with patch("sys.stdout", new_callable=io.StringIO):
            code = probe_cmd(args)
        self.assertEqual(code, 0)

    @patch("apkrevive.cli.sign_apk")
    def test_cli_revive(self, mock_sign):
        mock_sign.return_value = True
        manifest = AxmlNode(tag="manifest")
        manifest.set_attr("package", "com.test.revive", ns="")
        app = AxmlNode(tag="application")
        manifest.children.append(app)
        raw_manifest = AxmlSurgeon.serialize(manifest)

        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f_in, tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f_out:
            in_apk = f_in.name
            out_apk = f_out.name

        with zipfile.ZipFile(in_apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", raw_manifest)
            zf.writestr("classes.dex", b"DEX\n035\x00")

        args = argparse.Namespace(apk=in_apk, output=out_apk, enable_60hz=True, enable_cutout=True)
        with patch("sys.stdout", new_callable=io.StringIO):
            code = revive_cmd(args)

        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(out_apk))
        with zipfile.ZipFile(out_apk, "r") as zf_revived:
            names = zf_revived.namelist()
            self.assertIn("AndroidManifest.xml", names)
            self.assertIn("classes.dex", names)
            self.assertIn("classes2.dex", names)

    def test_cli_version(self):
        import apkrevive
        with patch("sys.argv", ["apkrevive", "--version"]):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                with self.assertRaises(SystemExit) as cm:
                    main()
                self.assertEqual(cm.exception.code, 0)
                self.assertIn(f"apkrevive {apkrevive.__version__}", mock_stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
