"""
test_cli.py - CLI test suite for ApkRevive inspect and patch commands.
"""

import io
import json
import os
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from apkrevive.cli import run_inspect, run_patch, main
from apkrevive.core.axml import AxmlSurgeon, AxmlNode


def make_test_apk(
    pkg: str = "com.apkrevive.test",
    target_sdk: int = 28,
    has_code: bool = True,
    dex_classes: int = 1,
) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        root = AxmlNode(tag="manifest")
        root.set_attr("package", pkg, ns="")
        uses_sdk = AxmlNode(tag="uses-sdk")
        uses_sdk.set_attr("targetSdkVersion", target_sdk)
        uses_sdk.set_attr("minSdkVersion", 14)
        root.children.append(uses_sdk)
        app = AxmlNode(tag="application")
        app.set_attr("hasCode", has_code)
        root.children.append(app)
        zf.writestr("AndroidManifest.xml", AxmlSurgeon.serialize(root))

        for i in range(1, dex_classes + 1):
            name = f"classes{i}.dex" if i > 1 else "classes.dex"
            zf.writestr(name, b"dex\n035\x00dummy_dex_data")

    return buf.getvalue()


class TestCli(unittest.TestCase):
    def test_inspect_clean_apk(self):
        apk_bytes = make_test_apk("com.example.clean", target_sdk=28)
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(apk_bytes)
            f.flush()
            temp_path = f.name

        try:
            report = run_inspect(temp_path)
            self.assertEqual(report.package_name, "com.example.clean")
            self.assertEqual(report.target_sdk, 28)
            self.assertEqual(len(report.fatal_blockers), 0)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_inspect_fatal_32bit_only(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            root = AxmlNode(tag="manifest")
            root.set_attr("package", "com.example.arm32", ns="")
            app = AxmlNode(tag="application")
            root.children.append(app)
            zf.writestr("AndroidManifest.xml", AxmlSurgeon.serialize(root))
            zf.writestr("lib/armeabi-v7a/libfoo.so", b"\x7fELF\x01" + b"\x00" * 100)
            zf.writestr("classes.dex", b"dex\n035\x00data")

        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(buf.getvalue())
            f.flush()
            temp_path = f.name

        try:
            report = run_inspect(temp_path)
            self.assertTrue(report.is_32bit_only)
            self.assertTrue(any("32-bit only" in b for b in report.fatal_blockers))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_inspect_private_bionic_dependencies_remediable(self):
        apk_bytes = make_test_apk("com.example.bionic", target_sdk=24)
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(apk_bytes)
            f.flush()
            temp_path = f.name

        try:
            with patch("apkrevive.cli.inspect_apk") as mock_inspect:
                from apkrevive.core.models import ApkMetadata
                mock_inspect.return_value = ApkMetadata(
                    package_name="com.example.bionic",
                    target_sdk=24,
                    min_sdk=14,
                    abis=["arm64-v8a"],
                    private_libs=["libcrypto.so"],
                )
                report = run_inspect(temp_path)
                self.assertIn("libcrypto.so", report.private_bionic_libs)
                self.assertTrue(any("Private Bionic linker dependencies" in r for r in report.remediable_issues))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_inspect_cli_json(self):
        apk_bytes = make_test_apk("com.example.json", target_sdk=22)
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(apk_bytes)
            f.flush()
            temp_path = f.name

        try:
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                code = main(["inspect", "--json", temp_path])
            self.assertEqual(code, 0)
            out = json.loads(mock_stdout.getvalue())
            self.assertEqual(out["package_name"], "com.example.json")
            self.assertTrue(out["install_floor_blocked"])
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_patch_cli_execution(self):
        apk_bytes = make_test_apk("com.example.patchme", target_sdk=19, dex_classes=1)
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fin, \
             tempfile.NamedTemporaryFile(suffix="_revived.apk", delete=False) as fout:
            fin.write(apk_bytes)
            fin.flush()
            in_path = fin.name
            out_path = fout.name

        try:
            with patch("sys.stdout", new_callable=io.StringIO):
                code = main(["patch", "--no-sign", in_path, "-o", out_path])
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(out_path))
            self.assertGreater(os.path.getsize(out_path), 0)

            # Verify contents of patched APK
            with zipfile.ZipFile(out_path, "r") as zf:
                names = zf.namelist()
                self.assertIn("AndroidManifest.xml", names)
                # Next classes index should be classes2.dex
                self.assertIn("classes2.dex", names)
                manifest_data = zf.read("AndroidManifest.xml")
                root = AxmlSurgeon.parse(manifest_data)
                app = root.find_child("application")
                self.assertIsNotNone(app)
                # ApkReviveInitProvider should be injected
                provider = (
                    app.find_child("provider", "name", "com.apkrevive.shim.ApkReviveInitProvider")
                    or app.find_child("provider", "name", "com.apkrevive.runtime.ApkReviveInitProvider")
                    or app.find_child("provider", "name", "apkrevive.shim.ApkReviveInitProvider")
                )
                self.assertIsNotNone(provider)
        finally:
            for p in (in_path, out_path):
                if os.path.exists(p):
                    os.remove(p)

    def test_patch_fails_when_signing_fails(self):
        apk_bytes = make_test_apk("com.example.signfail")
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f_in, \
             tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f_out:
            f_in.write(apk_bytes)
            f_in.flush()
            in_path = f_in.name
            out_path = f_out.name

        try:
            with patch("apkrevive.cli.sign_apk", return_value=False):
                with self.assertRaises(RuntimeError) as ctx:
                    run_patch(in_path, out_path, no_sign=False)
                self.assertIn("Failed to sign output APK", str(ctx.exception))
        finally:
            for p in (in_path, out_path):
                if os.path.exists(p):
                    os.remove(p)

    def test_patch_forwards_keystore_credentials(self):
        apk_bytes = make_test_apk("com.example.credforward")
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f_in, \
             tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f_out:
            f_in.write(apk_bytes)
            f_in.flush()
            in_path = f_in.name
            out_path = f_out.name

        try:
            with patch("apkrevive.cli.sign_apk", return_value=True) as mock_sign:
                run_patch(
                    in_path,
                    out_path,
                    keystore_path="my_ks.p12",
                    keystore_pass="ks_secret",
                    key_alias="custom_alias",
                    key_pass="key_secret",
                )
                mock_sign.assert_called_once_with(
                    out_path,
                    keystore_path="my_ks.p12",
                    keystore_pass="ks_secret",
                    key_alias="custom_alias",
                    key_pass="key_secret",
                )
        finally:
            for p in (in_path, out_path):
                if os.path.exists(p):
                    os.remove(p)

    def test_doctor_json_output_success(self):
        fake_diag = {
            "keytool": {"found": True, "required_for_signing": True, "hint": "h1"},
            "apksigner": {"found": True, "required_for_signing": True, "hint": "h2"},
        }
        with patch("apkrevive.cli.diagnose_tools", return_value=fake_diag):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                code = main(["doctor", "--json"])
                self.assertEqual(code, 0)
                data = json.loads(mock_out.getvalue())
                self.assertIn("keytool", data)
                self.assertTrue(data["keytool"]["found"])

    def test_doctor_json_output_missing_signing(self):
        fake_diag = {
            "keytool": {"found": False, "required_for_signing": True, "hint": "h1"},
            "apksigner": {"found": True, "required_for_signing": True, "hint": "h2"},
        }
        with patch("apkrevive.cli.diagnose_tools", return_value=fake_diag):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                code = main(["doctor", "--json"])
                self.assertEqual(code, 1)
                data = json.loads(mock_out.getvalue())
                self.assertFalse(data["keytool"]["found"])


if __name__ == "__main__":
    unittest.main()
