"""
test_coverage_boost.py - Unit tests boosting branch coverage for weakest modules.
Targets:
  - apkrevive/__init__.py
  - apkrevive/__main__.py
  - apkrevive/cli/__main__.py
  - apkrevive/cli/__init__.py
  - apkrevive/core/verify.py
  - apkrevive/shim/build_shim.py
  - apkrevive/core/extractor.py
"""

import argparse
import io
import os
from pathlib import Path
import runpy
import struct
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import zipfile

from apkrevive.core.axml import AxmlNode, AxmlSurgeon
from apkrevive.core.models import ApkMetadata, InspectionReport, PatchReport
from apkrevive.core.verify import (
    VerificationReport,
    _read_uleb128,
    get_aapt2_cmd,
    parse_dex_class_descriptors,
    verify_apk_integrity,
)
from apkrevive.cli import (
    format_inspection_report,
    format_patch_report,
    format_verification_report,
    main,
    revive_cmd,
    run_inspect,
    run_patch,
    triage_cmd,
)
from apkrevive.shim.build_shim import (
    CANONICAL_SHIM_SHA256,
    find_build_tools,
    find_platform_dir,
    find_sdk_root,
    main as shim_main,
    resolve_tool,
)


def make_minimal_apk(
    pkg: str = "com.test.boost",
    target_sdk: int = 28,
    min_sdk: int = 15,
    has_code: bool = True,
    extra_files: dict = None,
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
        app.set_attr("hasCode", has_code)
        root.children.append(app)
        zf.writestr("AndroidManifest.xml", AxmlSurgeon.serialize(root))
        zf.writestr("classes.dex", b"dex\n035\x00dummy_dex_data_content")

        if extra_files:
            for name, content in extra_files.items():
                zf.writestr(name, content)
    return buf.getvalue()


class TestInitAndMainCoverage(unittest.TestCase):
    def test_init_version_fallbacks(self):
        from apkrevive import _resolve_version
        from importlib.metadata import PackageNotFoundError

        # 1. Non-existent pyproject file path
        non_existent = Path(tempfile.gettempdir()) / "non_existent_pyproject_for_test.toml"
        with patch("importlib.metadata.version", side_effect=PackageNotFoundError("not found")):
            ver = _resolve_version(non_existent)
            self.assertEqual(ver, "0.5.0a1")

        # 2. File exists but regex doesn't match
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as tf:
            tf.write("foo = 'bar'\n")
            tmp_path = Path(tf.name)
        try:
            with patch("importlib.metadata.version", return_value="1.2.3"):
                ver = _resolve_version(tmp_path)
                self.assertEqual(ver, "1.2.3")
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

        # 3. File exists with valid version match
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as tf:
            tf.write('version = "2.3.4"\n')
            tmp_path2 = Path(tf.name)
        try:
            ver = _resolve_version(tmp_path2)
            self.assertEqual(ver, "2.3.4")
        finally:
            if tmp_path2.exists():
                tmp_path2.unlink()

    def test_main_module_entrypoints(self):
        with patch("apkrevive.cli.main", return_value=0), patch("sys.exit") as mock_exit:
            runpy.run_module("apkrevive", run_name="__main__")
            mock_exit.assert_called_with(0)

        with patch("apkrevive.cli.main", return_value=0), patch("sys.exit") as mock_exit:
            runpy.run_module("apkrevive.cli", run_name="__main__")
            mock_exit.assert_called_with(0)


class TestCliReportsAndCommands(unittest.TestCase):
    def test_format_inspection_report_variants(self):
        # 1. Clean app
        clean_rep = InspectionReport(
            apk_path="test.apk",
            package_name="com.clean",
            target_sdk=28,
            min_sdk=21,
            version_code=1,
            abis=["arm64-v8a"],
            page_size_16kb_status="VERIFIED_16KB",
            fatal_blockers=[],
            remediable_issues=[],
            warnings=[],
        )
        out = format_inspection_report(clean_rep)
        self.assertIn("already modern and compatible", out)
        self.assertIn("16KB Page Size: VERIFIED_16KB", out)

        # 2. Fatal blockers
        fatal_rep = InspectionReport(
            apk_path="test.apk",
            package_name="com.fatal",
            target_sdk=28,
            min_sdk=21,
            version_code=1,
            abis=["armeabi-v7a"],
            page_size_16kb_status=None,
            fatal_blockers=["32-bit only native library"],
            remediable_issues=["targetSdk < 23"],
            warnings=["Legacy storage path"],
        )
        out = format_inspection_report(fatal_rep)
        self.assertIn("FATAL BLOCKERS", out)
        self.assertIn("REMEDIABLE RUNTIME ISSUES", out)
        self.assertIn("WARNINGS", out)
        self.assertIn("Verdict: BLOCKED", out)

        # 3. Remediable only
        remed_rep = InspectionReport(
            apk_path="test.apk",
            package_name="com.remed",
            target_sdk=22,
            min_sdk=15,
            version_code=1,
            abis=[],
            page_size_16kb_status=None,
            fatal_blockers=[],
            remediable_issues=["targetSdk < 23"],
            warnings=[],
        )
        out = format_inspection_report(remed_rep)
        self.assertIn("Verdict: REMEDIABLE", out)

    def test_format_patch_report(self):
        prep = PatchReport(
            timestamp="2026-01-01T00:00:00Z",
            apk_path="in.apk",
            package_name="com.test",
            target_sdk=28,
            verdict="GREEN",
            reason="Success",
            output_apk="out.apk",
            remediations=["Injected Apache HTTP", "Aligned 16KB"],
            required_transforms=["TRANSFORM_A"],
        )
        out = format_patch_report(prep)
        self.assertIn("ApkRevive Patch Execution Complete", out)
        self.assertIn("Injected Apache HTTP", out)

    def test_format_verification_report(self):
        vrep_pass = VerificationReport(
            apk_path="ok.apk",
            is_valid=True,
            checks={"alignment": True, "signature": True, "axml": True, "dex": True},
            errors=[],
            details={"package_name": "com.test", "total_classes_found": 10},
        )
        out_v = format_verification_report(vrep_pass, verbose=True)
        self.assertIn("[PASS]", out_v)
        self.assertIn("package_name: com.test", out_v)

        vrep_fail = VerificationReport(
            apk_path="bad.apk",
            is_valid=False,
            checks={"alignment": False, "signature": True, "axml": False, "dex": True},
            errors=["Alignment error", "AXML error"],
            details={},
        )
        out_f = format_verification_report(vrep_fail, verbose=False)
        self.assertIn("[FAIL]", out_f)
        self.assertIn("Errors:", out_f)

    def test_run_inspect_error_and_branches(self):
        with self.assertRaises(FileNotFoundError):
            run_inspect("non_existent_file_boost.apk")

        # Create APK with various triggers
        fake_meta = ApkMetadata(
            package_name="com.test.branches",
            target_sdk=22,
            min_sdk=15,
            version_code=100,
            abis=["armeabi-v7a"],
            elf_load_align_64bit=4096,
            has_invalid_elf_layout=False,
            elf_16kb_status="UNSAFE",
            is_split_apk=False,
            private_libs=["libcrypto.so"],
            uses_apache_http=True,
            has_code=True,
            is_non_resizeable=True,
            has_fixed_physics=False,
            size_bytes=1000,
            permissions=[],
            uses_cleartext_traffic=True,
            has_network_security_config=False,
            legacy_tls_protocols=[],
            has_cleartext_http=False,
            hidden_api_reflections=[],
            accesses_scoped_storage_paths=True,
            has_obb=False,
            uses_gles1=False,
            dead_sdks=[],
            textrel_libs=["libtextrel.so"],
            has_textrel=True,
            has_request_legacy_external_storage=False,
        )

        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(make_minimal_apk())
            apk_path = f.name

        try:
            with patch("apkrevive.cli.inspect_apk", return_value=fake_meta):
                rep = run_inspect(apk_path)
                self.assertTrue(any("32-bit only" in b for b in rep.fatal_blockers))
                self.assertTrue(any("Text relocations" in b for b in rep.fatal_blockers))
                self.assertTrue(any("Private Bionic" in r for r in rep.remediable_issues))
                self.assertTrue(any("targetSdk=" in r for r in rep.remediable_issues))
                self.assertTrue(any("org.apache.http.legacy" in r for r in rep.remediable_issues))
                self.assertTrue(any("Hardcoded legacy" in w for w in rep.warnings))
                self.assertTrue(any("non-resizeable" in r for r in rep.remediable_issues))
        finally:
            if os.path.exists(apk_path):
                os.remove(apk_path)

    def test_run_patch_native_libs_and_alignment(self):
        # 1. 32-bit only APK with resources.arsc
        extra_32 = {
            "lib/armeabi-v7a/libtest.so": b"\x7fELF" + b"\x00" * 100,
            "resources.arsc": b"TABLE_DATA",
        }
        apk_32 = make_minimal_apk(extra_files=extra_32)
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f_in, \
             tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f_out:
            f_in.write(apk_32)
            f_in.flush()
            in_p = f_in.name
            out_p = f_out.name
        try:
            with patch("apkrevive.cli.sign_apk", return_value=True):
                rep = run_patch(in_p, out_p, no_sign=True, bump_target_sdk=30)
                self.assertTrue(any("32-bit only" in r for r in rep.remediations))
                self.assertTrue(any("Bumped targetSdkVersion" in r for r in rep.remediations))
        finally:
            for p in (in_p, out_p):
                if os.path.exists(p):
                    os.remove(p)

        # 2. 64-bit APK with unaligned ELF and private bionic lib
        extra_64 = {
            "lib/arm64-v8a/libtest64.so": b"\x7fELF" + b"\x00" * 100,
        }
        apk_64 = make_minimal_apk(extra_files=extra_64)
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f_in, \
             tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f_out:
            f_in.write(apk_64)
            f_in.flush()
            in_p = f_in.name
            out_p = f_out.name
        try:
            with patch("apkrevive.cli.sign_apk", return_value=True), \
                 patch("apkrevive.cli.rewrite_elf_16kb", return_value=b"REWRITTEN_16KB"), \
                 patch("apkrevive.cli.get_elf_needed", return_value=["libcutils.so"]):
                rep64 = run_patch(in_p, out_p, no_sign=True)
                self.assertTrue(any("16KB boundaries" in r for r in rep64.remediations))
                self.assertTrue(any("libcutils.so" in r for r in rep64.remediations))
        finally:
            for p in (in_p, out_p):
                if os.path.exists(p):
                    os.remove(p)
        split_meta = ApkMetadata(
            package_name="com.split",
            target_sdk=28,
            min_sdk=21,
            version_code=1,
            abis=[],
            elf_load_align_64bit=None,
            has_invalid_elf_layout=False,
            elf_16kb_status=None,
            is_split_apk=True,
            private_libs=[],
            uses_apache_http=False,
            has_code=True,
            is_non_resizeable=False,
            has_fixed_physics=False,
            size_bytes=100,
            permissions=[],
            uses_cleartext_traffic=False,
            has_network_security_config=False,
            legacy_tls_protocols=[],
            has_cleartext_http=False,
            hidden_api_reflections=[],
            accesses_scoped_storage_paths=False,
            has_obb=False,
            uses_gles1=False,
            dead_sdks=[],
            textrel_libs=[],
            has_textrel=False,
            has_request_legacy_external_storage=False,
        )
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(make_minimal_apk())
            apk_path = f.name
        try:
            with patch("apkrevive.cli.inspect_apk", return_value=split_meta):
                with self.assertRaises(ValueError):
                    run_patch(apk_path, "out.apk")
        finally:
            if os.path.exists(apk_path):
                os.remove(apk_path)

    def test_main_cli_routing(self):
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(make_minimal_apk())
            apk_path = f.name

        try:
            # 1. Inspect json
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                ret = main(["inspect", apk_path, "--json"])
                self.assertEqual(ret, 0)
                self.assertIn("package_name", mock_out.getvalue())

            # 2. Inspect formatted output
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                ret = main(["inspect", apk_path])
                self.assertEqual(ret, 0)
                self.assertIn("ApkRevive Inspection Report", mock_out.getvalue())

            # 3. Inspect missing file error handling
            with patch("sys.stderr", new_callable=io.StringIO):
                ret = main(["inspect", "non_existent_boost.apk"])
                self.assertEqual(ret, 2)

            # 4. Patch error handling
            with patch("sys.stderr", new_callable=io.StringIO):
                ret = main(["patch", "non_existent_boost.apk"])
                self.assertEqual(ret, 2)

            # 5. Patch success with json
            out_apk = apk_path.replace(".apk", ".patched.apk")
            with patch("apkrevive.cli.sign_apk", return_value=True), patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                ret = main(["patch", apk_path, "-o", out_apk, "--json", "--no-sign"])
                self.assertEqual(ret, 0)
                self.assertIn("remediations", mock_out.getvalue())
            if os.path.exists(out_apk):
                os.remove(out_apk)

            # 6. Verify command json and regular
            fake_vrep_ok = VerificationReport(apk_path=apk_path, is_valid=True, checks={}, errors=[], details={})
            with patch("apkrevive.cli.run_verify", return_value=fake_vrep_ok), patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                ret = main(["verify", apk_path, "--json"])
                self.assertEqual(ret, 0)
                self.assertIn("is_valid", mock_out.getvalue())

            fake_vrep_fail = VerificationReport(apk_path=apk_path, is_valid=False, checks={}, errors=[], details={})
            with patch("apkrevive.cli.run_verify", return_value=fake_vrep_fail), patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                ret = main(["verify", apk_path])
                self.assertEqual(ret, 1)

            # 7. Verify file not found
            with patch("sys.stderr", new_callable=io.StringIO):
                ret = main(["verify", "non_existent_boost.apk"])
                self.assertEqual(ret, 2)

            # 8. Triage command
            with patch("apkrevive.core.triage.evaluate_triage", return_value={"verdict": "GREEN"}):
                args = argparse.Namespace(apk=apk_path, device_api=34, page_size=16384, sarif=False)
                ret = triage_cmd(args)
                self.assertEqual(ret, 0)

            # 8b. Triage command with SARIF and YELLOW
            with patch("apkrevive.core.triage.evaluate_triage", return_value={"verdict": "YELLOW", "reason": "APACHE_HTTP", "details": "warning"}):
                args_sarif = argparse.Namespace(apk=apk_path, device_api=35, page_size=16384, sarif=True, target_sdk=28, apk_abis="arm64-v8a", uses_apache_http=True)
                with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                    ret = triage_cmd(args_sarif)
                    self.assertEqual(ret, 2)
                    self.assertIn("APACHE_HTTP", mock_out.getvalue())

            # 8c. Triage command with RED and no-file fallback
            with patch("apkrevive.core.triage.evaluate_triage", return_value={"verdict": "RED", "reason": "PAGE_SIZE", "details": "error"}):
                args_red = argparse.Namespace(apk="non_existent_triage.apk", target_sdk=22, sarif=False)
                ret = triage_cmd(args_red)
                self.assertEqual(ret, 3)

            # 9. Revive command with split APK error
            args_revive = argparse.Namespace(apk=apk_path, output=None, ks=None, no_sign=True, json=True)
            with patch("apkrevive.cli.inspect_apk") as mock_insp:
                mock_insp.return_value = MagicMock(is_split_apk=True)
                with patch("sys.stderr", new_callable=io.StringIO):
                    ret = revive_cmd(args_revive)
                    self.assertEqual(ret, 1)

        finally:
            if os.path.exists(apk_path):
                os.remove(apk_path)


class TestCoreVerifyCoverage(unittest.TestCase):
    def test_uleb128_exceptions(self):
        # Shift overflow (>= 35)
        bad_uleb = b"\x80\x80\x80\x80\x80\x80"
        with self.assertRaises(ValueError) as ctx:
            _read_uleb128(bad_uleb, 0)
        self.assertIn("shift overflow", str(ctx.exception))

        # Truncated sequence
        bad_trunc = b"\x80\x80"
        with self.assertRaises(ValueError) as ctx:
            _read_uleb128(bad_trunc, 0)
        self.assertIn("Truncated ULEB128", str(ctx.exception))

    def test_parse_dex_class_descriptors_corruptions(self):
        # len < 112
        with self.assertRaises(ValueError):
            parse_dex_class_descriptors(b"dex\n035\x00short")

        # invalid magic
        with self.assertRaises(ValueError) as ctx:
            parse_dex_class_descriptors(b"BADMAGIC" + b"\x00" * 120)
        self.assertIn("Invalid DEX magic", str(ctx.exception))

        # endian tag mismatch
        buf = bytearray(128)
        buf[:8] = b"dex\n035\x00"
        struct.pack_into("<III", buf, 0x20, 128, 112, 0x11223344)
        with self.assertRaises(ValueError) as ctx:
            parse_dex_class_descriptors(bytes(buf))
        self.assertIn("Unsupported DEX endian tag", str(ctx.exception))

        # header_size < 112
        struct.pack_into("<III", buf, 0x20, 128, 100, 0x12345678)
        with self.assertRaises(ValueError) as ctx:
            parse_dex_class_descriptors(bytes(buf))
        self.assertIn("Invalid DEX header_size", str(ctx.exception))

        # file_size > len(data)
        struct.pack_into("<III", buf, 0x20, 5000, 112, 0x12345678)
        with self.assertRaises(ValueError) as ctx:
            parse_dex_class_descriptors(bytes(buf))
        self.assertIn("exceeds actual payload length", str(ctx.exception))

        # string_ids out of bounds
        struct.pack_into("<III", buf, 0x20, 128, 112, 0x12345678)
        struct.pack_into("<II", buf, 0x38, 100, 120)  # 120 + 400 > 128
        with self.assertRaises(ValueError) as ctx:
            parse_dex_class_descriptors(bytes(buf))
        self.assertIn("string_ids table extends beyond", str(ctx.exception))

    def test_get_aapt2_cmd(self):
        # Found in path
        with patch("shutil.which", return_value="/bin/aapt2"):
            self.assertEqual(get_aapt2_cmd(), "/bin/aapt2")

        # Win32 fallback
        with patch("shutil.which", side_effect=lambda x: "C:\\aapt2.exe" if "exe" in x else None):
            with patch("sys.platform", "win32"):
                self.assertEqual(get_aapt2_cmd(), "C:\\aapt2.exe")

        # Fallback to None
        with patch("shutil.which", return_value=None), patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(get_aapt2_cmd())

    def test_verify_apk_integrity_failures(self):
        with self.assertRaises(FileNotFoundError):
            verify_apk_integrity("non_existent_boost_verify.apk")

        # APK without AndroidManifest.xml
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("dummy.txt", b"hello")
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(buf.getvalue())
            bad_apk = f.name
        try:
            report = verify_apk_integrity(bad_apk)
            self.assertFalse(report.is_valid)
            self.assertFalse(report.checks["axml"])

            # Exception in alignment check
            with patch("apkrevive.core.verify.verify_apk_alignment", side_effect=Exception("align boom")):
                rep_boom = verify_apk_integrity(bad_apk)
                self.assertFalse(rep_boom.checks["alignment"])
                self.assertTrue(any("align boom" in e for e in rep_boom.errors))

            # Exception in signing check
            with patch("apkrevive.core.verify.verify_signing_block_padding", side_effect=Exception("sig boom")):
                rep_sig = verify_apk_integrity(bad_apk)
                self.assertFalse(rep_sig.checks["signature"])
                self.assertTrue(any("sig boom" in e for e in rep_sig.errors))

        finally:
            if os.path.exists(bad_apk):
                os.remove(bad_apk)

        # APK with manifest but missing <application>
        root_no_app = AxmlNode(tag="manifest")
        root_no_app.set_attr("package", "com.noapp", ns="")
        buf_no_app = io.BytesIO()
        with zipfile.ZipFile(buf_no_app, "w") as zf:
            zf.writestr("AndroidManifest.xml", AxmlSurgeon.serialize(root_no_app))
            zf.writestr("classes.dex", b"corrupt_dex_header")
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(buf_no_app.getvalue())
            no_app_apk = f.name
        try:
            rep_no_app = verify_apk_integrity(no_app_apk)
            self.assertFalse(rep_no_app.checks["axml"])
            self.assertFalse(rep_no_app.checks["dex"])
            self.assertTrue(any("Missing <application>" in e for e in rep_no_app.errors))
            self.assertTrue(any("DEX parser error" in e for e in rep_no_app.errors))
        finally:
            if os.path.exists(no_app_apk):
                os.remove(no_app_apk)


class TestBuildShimCoverage(unittest.TestCase):
    def test_find_sdk_and_tools(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            sdk_mock = tmp / "mock_sdk"
            bt_mock = sdk_mock / "build-tools" / "35.0.0"
            plat_mock = sdk_mock / "platforms" / "android-35"
            bt_mock.mkdir(parents=True)
            plat_mock.mkdir(parents=True)

            with patch.dict(os.environ, {"ANDROID_HOME": str(sdk_mock)}):
                self.assertEqual(find_sdk_root(), sdk_mock)
                self.assertEqual(find_build_tools(sdk_mock), bt_mock)
                self.assertEqual(find_platform_dir(sdk_mock), plat_mock)

    def test_resolve_tool(self):
        with patch("shutil.which", return_value="/usr/bin/d8"):
            self.assertEqual(resolve_tool("d8"), "/usr/bin/d8")

        with patch("shutil.which", return_value=None):
            with tempfile.TemporaryDirectory() as tmp_str:
                bt_dir = Path(tmp_str)
                fake_tool = bt_dir / "d8.bat"
                fake_tool.touch()
                with patch("sys.platform", "win32"):
                    res = resolve_tool("d8", build_tools_dir=bt_dir)
                    self.assertEqual(res, str(fake_tool))

    def test_shim_main_verify(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            mock_shim_path = Path(tmp_str) / "shim.dex"
            with patch("apkrevive.shim.build_shim.SHIM_DEX_PATH", mock_shim_path):
                # Missing file
                ret = shim_main(["--verify"])
                self.assertEqual(ret, 1)

                # Matching digest
                with patch("hashlib.sha256") as mock_hash:
                    mock_hash.return_value.hexdigest.return_value = CANONICAL_SHIM_SHA256
                    mock_shim_path.write_bytes(b"mock_shim_data")
                    ret = shim_main(["--verify"])
                    self.assertEqual(ret, 0)

                # Force mode build
                with patch("apkrevive.shim.build_shim.build_shim", return_value=b"new_dex_bytes"):
                    with patch("hashlib.sha256") as mock_hash:
                        mock_hash.return_value.hexdigest.return_value = "new_hash_123"
                        ret = shim_main(["--force"])
                        self.assertEqual(ret, 0)


class TestExtractorCoverage(unittest.TestCase):
    def test_extractor_missing_manifest_and_obb(self):
        from apkrevive.core.extractor import inspect_apk, _attr_to_int, _attr_to_bool
        from apkrevive.core.axml import AxmlAttribute

        # Attribute parsing branches
        self.assertEqual(_attr_to_int(None, 42), 42)
        attr_int = AxmlAttribute(ns="", name="intAttr", raw_value=None, data_type=0x10, data=123)
        self.assertEqual(_attr_to_int(attr_int), 123)
        attr_str = AxmlAttribute(ns="", name="strAttr", raw_value="456", data_type=0x03, data=0)
        self.assertEqual(_attr_to_int(attr_str), 456)
        attr_bad_str = AxmlAttribute(ns="", name="badStr", raw_value="invalid_int", data_type=0x03, data=0)
        self.assertEqual(_attr_to_int(attr_bad_str, 99), 99)

        self.assertEqual(_attr_to_bool(None, True), True)
        attr_bool = AxmlAttribute(ns="", name="bAttr", raw_value=None, data_type=0x12, data=1)
        self.assertEqual(_attr_to_bool(attr_bool), True)
        attr_bstr = AxmlAttribute(ns="", name="bStr", raw_value="false", data_type=0x03, data=0)
        self.assertEqual(_attr_to_bool(attr_bstr), False)

        # 1. Missing AndroidManifest.xml (returns default empty metadata)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("classes.dex", b"dex\n035\x00")
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(buf.getvalue())
            no_manifest_path = f.name
        try:
            meta = inspect_apk(no_manifest_path)
            self.assertEqual(meta.package_name, "")
        finally:
            if os.path.exists(no_manifest_path):
                os.remove(no_manifest_path)

        # 2. Obb and GLES 1.0 detection
        extra = {
            "main.100.com.test.boost.obb": b"OBB_CONTENT",
            "lib/arm64-v8a/libGLESv1_CM.so": b"\x7fELF" + b"\x00" * 100,
        }
        apk_obb = make_minimal_apk(extra_files=extra)
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(apk_obb)
            obb_path = f.name
        try:
            meta = inspect_apk(obb_path)
            self.assertTrue(meta.has_obb)
            self.assertTrue(meta.uses_gles1)
        finally:
            if os.path.exists(obb_path):
                os.remove(obb_path)


class TestTriageCoverage(unittest.TestCase):
    def test_evaluate_triage_branches(self):
        from apkrevive.core.triage import evaluate_triage
        from apkrevive.core.models import DeviceProfile, Verdict

        dev_prof = DeviceProfile(
            os_api_level=34,
            supported_abis=["arm64-v8a"],
            install_floor=24,
            page_size_bytes=16384,
            is_widescreen=True,
            is_high_refresh=True,
        )

        # 1. Dict input conversion
        apk_dict = {
            "package_name": "com.triage.dict",
            "target_sdk": 28,
            "min_sdk": 21,
            "version_code": 1,
            "abis": ["arm64-v8a"],
            "elf_load_align_64bit": 16384,
            "has_invalid_elf_layout": False,
            "elf_16kb_status": "VERIFIED_16KB",
            "is_split_apk": False,
            "private_libs": [],
            "uses_apache_http": False,
            "has_code": True,
            "is_non_resizeable": False,
            "has_fixed_physics": False,
            "size_bytes": 1000,
            "permissions": [],
            "uses_cleartext_traffic": False,
            "has_network_security_config": True,
            "legacy_tls_protocols": [],
            "has_cleartext_http": False,
            "hidden_api_reflections": ["android.os.SystemProperties"],
            "accesses_scoped_storage_paths": False,
            "has_obb": False,
            "uses_gles1": True,
            "dead_sdks": ["Google Maps v1"],
            "textrel_libs": ["libbad.so"],
            "has_textrel": True,
            "has_request_legacy_external_storage": False,
        }
        res = evaluate_triage(apk_dict, dev_prof.to_dict())
        self.assertEqual(res["verdict"], Verdict.RED.value)
        self.assertTrue(any("WARN_HIDDEN_API_REFLECTION" in w for w in res.get("warnings", [])))
        self.assertTrue(any("WARN_GLES1_DEPRECATED" in w for w in res.get("warnings", [])))
        self.assertTrue(any("WARN_DEAD_SDKS" in w for w in res.get("warnings", [])))

        # 2. Split APK branch
        split_dict = dict(apk_dict)
        split_dict["is_split_apk"] = True
        res_split = evaluate_triage(split_dict, dev_prof)
        self.assertEqual(res_split["verdict"], Verdict.RED.value)


if __name__ == "__main__":
    unittest.main()
