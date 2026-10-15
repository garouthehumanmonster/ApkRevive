"""
test_signer.py - Tests PKCS12 keystore manager, per-user isolation, apksigner bridge, and CLI signature warnings.
"""

import getpass
import io
import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
import argparse

from apkrevive.core.signer import (
    get_default_user_keystore,
    ensure_keystore,
    sign_apk,
    verify_apk,
    get_apksigner_cmd
)
from apkrevive.cli import revive_cmd, main
from apkrevive.core.axml import AxmlSurgeon, AxmlNode


def create_synthetic_apk(path: str):
    """Creates a minimal valid synthetic APK suitable for signing."""
    manifest = AxmlNode(tag="manifest")
    manifest.set_attr("package", "com.apkrevive.testsign", ns="")
    app = AxmlNode(tag="application")
    manifest.children.append(app)
    manifest_bytes = AxmlSurgeon.serialize(manifest)

    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_bytes)
        zf.writestr("classes.dex", b"DEX\n035\x00" + b"\x00" * 100)


class TestSigner(unittest.TestCase):

    def test_per_user_keystore_isolation(self):
        """Tests that get_default_user_keystore() generates user-isolated paths and persistent password."""
        with tempfile.TemporaryDirectory() as tmp_home:
            with patch("pathlib.Path.home", return_value=Path(tmp_home)):
                ks_path, password, alias = get_default_user_keystore()
                username = getpass.getuser().lower().replace(" ", "_")

                expected_ks = Path(tmp_home) / ".apkrevive" / f"user_{username}.p12"
                self.assertEqual(ks_path, expected_ks)
                self.assertEqual(alias, f"apkrevive_{username}")

                pwd_path = Path(tmp_home) / ".apkrevive" / f"user_{username}.pwd"
                self.assertTrue(pwd_path.is_file())
                self.assertEqual(pwd_path.read_text(encoding="utf-8").strip(), password)
                self.assertGreaterEqual(len(password), 16)

                ks2, pwd2, alias2 = get_default_user_keystore()
                self.assertEqual(ks_path, ks2)
                self.assertEqual(password, pwd2)
                self.assertEqual(alias, alias2)

                with patch("getpass.getuser", return_value="alice"):
                    ks_alice, pwd_alice, alias_alice = get_default_user_keystore()
                with patch("getpass.getuser", return_value="bob"):
                    ks_bob, pwd_bob, alias_bob = get_default_user_keystore()

                self.assertNotEqual(ks_alice, ks_bob)
                self.assertNotEqual(alias_alice, alias_bob)
                self.assertNotEqual(pwd_alice, pwd_bob)
                self.assertIn("user_alice.p12", str(ks_alice))
                self.assertIn("user_bob.p12", str(ks_bob))

    def test_custom_keystore_path_handling(self):
        """Tests ensure_keystore with missing vs existing custom keystore paths."""
        with self.assertRaises(FileNotFoundError):
            ensure_keystore(keystore_path="nonexistent_keystore_12345.p12")

        with tempfile.NamedTemporaryFile(suffix=".p12", delete=False) as f:
            custom_path = f.name
        try:
            ks, pwd, alias = ensure_keystore(
                keystore_path=custom_path,
                keystore_pass="custom_pass",
                key_alias="custom_alias"
            )
            self.assertEqual(ks, custom_path)
            self.assertEqual(pwd, "custom_pass")
            self.assertEqual(alias, "custom_alias")
        finally:
            if os.path.exists(custom_path):
                os.remove(custom_path)

    def test_sign_and_verify_synthetic_apk(self):
        """Tests signing a synthetic APK and verifying it with verify_apk(verbose=True)."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "test_unsigned.apk")
            create_synthetic_apk(apk_path)

            apksigner_cmd = get_apksigner_cmd()
            keytool = shutil.which("keytool")

            if apksigner_cmd == "apksigner" and not shutil.which("apksigner"):
                self.skipTest("apksigner is not available in environment")
            if not keytool:
                self.skipTest("keytool is not available in environment")

            sign_success = sign_apk(apk_path)
            self.assertTrue(sign_success, "sign_apk failed on synthetic APK")

            res = verify_apk(apk_path, verbose=True)
            self.assertTrue(res["verified"], f"verify_apk failed: {res.get('output')}")
            self.assertIn("Verified using", res.get("output", ""))

    def test_revive_cmd_prints_data_loss_warning(self):
        """Tests that revive_cmd writes prominent re-signing data-loss warning to sys.stderr."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            in_apk = os.path.join(tmp_dir, "input.apk")
            out_apk = os.path.join(tmp_dir, "output.apk")
            create_synthetic_apk(in_apk)

            args = argparse.Namespace(
                apk=in_apk,
                output=out_apk,
                enable_60hz=False,
                enable_cutout=False,
                ks=None,
                ks_pass=None,
                ks_alias=None,
                key_pass=None
            )

            stderr_buf = io.StringIO()
            stdout_buf = io.StringIO()

            with patch("sys.stderr", stderr_buf), patch("sys.stdout", stdout_buf), patch("apkrevive.cli.sign_apk", return_value=True):
                code = revive_cmd(args)

            self.assertEqual(code, 0)
            stderr_output = stderr_buf.getvalue()
            expected_warning = (
                "WARNING: APK signature has changed. Re-signing requires uninstalling the existing application "
                "on device, which will permanently delete all existing user data."
            )
            self.assertIn(expected_warning, stderr_output)

    def test_cli_revive_keystore_args(self):
        """Tests that --ks, --ks-pass, --ks-alias, and --key-pass are passed correctly from CLI."""
        with patch("sys.argv", [
            "apkrevive", "revive", "dummy.apk",
            "--ks", "custom.p12",
            "--ks-pass", "secret123",
            "--ks-alias", "mykey",
            "--key-pass", "keysecret"
        ]), patch("apkrevive.cli.revive_cmd") as mock_revive:
            main()
            self.assertTrue(mock_revive.called)
            args = mock_revive.call_args[0][0]
            self.assertEqual(args.ks, "custom.p12")
            self.assertEqual(args.ks_pass, "secret123")
            self.assertEqual(args.ks_alias, "mykey")
            self.assertEqual(args.key_pass, "keysecret")

    @patch("subprocess.run")
    @patch("apkrevive.core.signer.ensure_keystore")
    def test_sign_apk_passes_passwords_via_env(self, mock_ensure, mock_run):
        """Verifies that sign_apk passes env:APKREVIVE_KS_PASS / env:APKREVIVE_KEY_PASS in argv and passwords in env dict."""
        mock_ensure.return_value = ("/mock/test.p12", "mock_ks_pwd", "mock_alias")
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        success = sign_apk("dummy.apk", keystore_pass="mock_ks_pwd", key_pass="mock_key_pwd")
        self.assertTrue(success)

        self.assertTrue(mock_run.called)
        call_args = mock_run.call_args
        cmd = call_args[0][0]
        kwargs = call_args[1]

        self.assertIn("--ks-pass", cmd)
        ks_idx = cmd.index("--ks-pass")
        self.assertEqual(cmd[ks_idx + 1], "env:APKREVIVE_KS_PASS")

        self.assertIn("--key-pass", cmd)
        key_idx = cmd.index("--key-pass")
        self.assertEqual(cmd[key_idx + 1], "env:APKREVIVE_KEY_PASS")

        for arg in cmd:
            self.assertNotIn("mock_ks_pwd", arg)
            self.assertNotIn("mock_key_pwd", arg)

        env = kwargs.get("env")
        self.assertIsNotNone(env)
        self.assertEqual(env.get("APKREVIVE_KS_PASS"), "mock_ks_pwd")
        self.assertEqual(env.get("APKREVIVE_KEY_PASS"), "mock_key_pwd")


if __name__ == "__main__":
    unittest.main()
