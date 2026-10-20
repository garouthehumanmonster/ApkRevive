"""
tests/test_build_shim.py - Comprehensive unit tests for apkrevive.shim.build_shim.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from apkrevive.shim.build_shim import (
    CANONICAL_SHIM_SHA256,
    build_shim,
    find_build_tools,
    find_platform_dir,
    find_sdk_root,
    main,
    resolve_tool,
)


class TestBuildShim(unittest.TestCase):
    def test_find_sdk_root_with_env(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            with patch.dict(os.environ, {"ANDROID_HOME": tmp_dir, "ANDROID_SDK_ROOT": ""}):
                sdk = find_sdk_root()
                self.assertEqual(sdk, Path(tmp_dir))

    def test_find_build_tools_with_versions(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sdk = Path(tmp_dir)
            bt_dir = sdk / "build-tools"
            bt_dir.mkdir()
            (bt_dir / "34.0.0").mkdir()
            (bt_dir / "35.0.0").mkdir()

            found = find_build_tools(sdk)
            self.assertEqual(found, bt_dir / "35.0.0")

            # Without 35.0.0
            (bt_dir / "35.0.0").rmdir()
            found_34 = find_build_tools(sdk)
            self.assertEqual(found_34, bt_dir / "34.0.0")

    def test_find_platform_dir_with_versions(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sdk = Path(tmp_dir)
            plat_dir = sdk / "platforms"
            plat_dir.mkdir()
            (plat_dir / "android-34").mkdir()
            (plat_dir / "android-35").mkdir()

            found = find_platform_dir(sdk)
            self.assertEqual(found, plat_dir / "android-35")

            # Without android-35
            (plat_dir / "android-35").rmdir()
            found_34 = find_platform_dir(sdk)
            self.assertEqual(found_34, plat_dir / "android-34")

    def test_resolve_tool(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            bt_dir = Path(tmp_dir)
            tool_name = "custom_tool.bat" if os.name == "nt" else "custom_tool"
            custom_bin = bt_dir / tool_name
            custom_bin.write_text("echo test", encoding="utf-8")

            resolved = resolve_tool("custom_tool", bt_dir)
            self.assertEqual(Path(resolved), custom_bin)

    def test_resolve_tool_javac_via_java_home(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            jh = Path(tmp_dir) / "jdk"
            bin_dir = jh / "bin"
            bin_dir.mkdir(parents=True)
            javac_file = bin_dir / ("javac.exe" if os.name == "nt" else "javac")
            javac_file.write_text("echo javac", encoding="utf-8")

            with patch("shutil.which", return_value=None):
                with patch.dict(os.environ, {"JAVA_HOME": str(jh)}):
                    res = resolve_tool("javac")
                    self.assertEqual(Path(res), javac_file)

    def test_resolve_tool_fallback_paths(self):
        with patch("shutil.which", return_value=None):
            with patch.dict(os.environ, {"JAVA_HOME": ""}):
                res = resolve_tool("javac")
                self.assertIn("javac", res)

            # d8 fallback
            bt = Path("nonexistent_bt")
            res_d8 = resolve_tool("d8", bt)
            self.assertIn("d8", res_d8)

    def test_build_shim_missing_source(self):
        with patch("apkrevive.shim.build_shim.SHIM_JAVA_PATH", Path("nonexistent/ApkReviveInitProvider.java")):
            with self.assertRaises(FileNotFoundError):
                build_shim()

    def test_build_shim_missing_android_jar(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sdk = Path(tmp_dir)
            with patch("apkrevive.shim.build_shim.find_sdk_root", return_value=sdk):
                with patch("apkrevive.shim.build_shim.find_platform_dir", return_value=sdk / "platforms" / "android-35"):
                    with self.assertRaises(FileNotFoundError) as ctx:
                        build_shim()
                    self.assertIn("android.jar not found", str(ctx.exception))

    def test_build_shim_javac_failure(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sdk = Path(tmp_dir)
            plat_dir = sdk / "platforms" / "android-35"
            plat_dir.mkdir(parents=True)
            (plat_dir / "android.jar").write_bytes(b"PK\x03\x04")

            with patch("apkrevive.shim.build_shim.find_sdk_root", return_value=sdk), \
                 patch("apkrevive.shim.build_shim.find_platform_dir", return_value=plat_dir), \
                 patch("subprocess.run", return_value=MagicMock(returncode=1, stderr="javac syntax error")):
                with self.assertRaises(RuntimeError) as ctx:
                    build_shim()
                self.assertIn("javac compilation failed", str(ctx.exception))

    def test_build_shim_no_class_files(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sdk = Path(tmp_dir)
            plat_dir = sdk / "platforms" / "android-35"
            plat_dir.mkdir(parents=True)
            (plat_dir / "android.jar").write_bytes(b"PK\x03\x04")

            with patch("apkrevive.shim.build_shim.find_sdk_root", return_value=sdk), \
                 patch("apkrevive.shim.build_shim.find_platform_dir", return_value=plat_dir), \
                 patch("subprocess.run", return_value=MagicMock(returncode=0, stderr="")):
                with self.assertRaises(RuntimeError) as ctx:
                    build_shim()
                self.assertIn("No .class files", str(ctx.exception))

    def test_build_shim_d8_failure(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sdk = Path(tmp_dir)
            plat_dir = sdk / "platforms" / "android-35"
            plat_dir.mkdir(parents=True)
            (plat_dir / "android.jar").write_bytes(b"PK\x03\x04")

            def mock_run(cmd, *args, **kwargs):
                if "javac" in str(cmd[0]):
                    # Simulate javac writing a .class file
                    d_idx = cmd.index("-d")
                    out_dir = Path(cmd[d_idx + 1])
                    (out_dir / "ApkReviveInitProvider.class").write_bytes(b"\xca\xfe\xba\xbe")
                    return MagicMock(returncode=0, stderr="")
                elif "d8" in str(cmd[0]):
                    return MagicMock(returncode=1, stderr="d8 error")
                return MagicMock(returncode=0)

            with patch("apkrevive.shim.build_shim.find_sdk_root", return_value=sdk), \
                 patch("apkrevive.shim.build_shim.find_platform_dir", return_value=plat_dir), \
                 patch("subprocess.run", side_effect=mock_run):
                with self.assertRaises(RuntimeError) as ctx:
                    build_shim()
                self.assertIn("d8 translation failed", str(ctx.exception))

    def test_build_shim_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sdk = Path(tmp_dir)
            plat_dir = sdk / "platforms" / "android-35"
            plat_dir.mkdir(parents=True)
            (plat_dir / "android.jar").write_bytes(b"PK\x03\x04")

            def mock_run(cmd, *args, **kwargs):
                if "javac" in str(cmd[0]):
                    d_idx = cmd.index("-d")
                    out_dir = Path(cmd[d_idx + 1])
                    (out_dir / "ApkReviveInitProvider.class").write_bytes(b"\xca\xfe\xba\xbe")
                    return MagicMock(returncode=0, stderr="")
                elif "d8" in str(cmd[0]):
                    out_idx = cmd.index("--output")
                    dex_out = Path(cmd[out_idx + 1])
                    (dex_out / "classes.dex").write_bytes(b"dex\n035\x00corrupt")
                    return MagicMock(returncode=0, stderr="")
                return MagicMock(returncode=0)

            with patch("apkrevive.shim.build_shim.find_sdk_root", return_value=sdk), \
                 patch("apkrevive.shim.build_shim.find_platform_dir", return_value=plat_dir), \
                 patch("subprocess.run", side_effect=mock_run):
                with self.assertRaises(ValueError) as ctx:
                    build_shim()
                self.assertIn("Compiled shim.dex SHA256 mismatch", str(ctx.exception))

    def test_build_shim_success(self):
        canonical_bytes = (Path(__file__).resolve().parent.parent / "apkrevive" / "shim" / "shim.dex").read_bytes()
        self.assertEqual(hashlib.sha256(canonical_bytes).hexdigest(), CANONICAL_SHIM_SHA256)

        with tempfile.TemporaryDirectory() as tmp_dir:
            sdk = Path(tmp_dir)
            plat_dir = sdk / "platforms" / "android-35"
            plat_dir.mkdir(parents=True)
            (plat_dir / "android.jar").write_bytes(b"PK\x03\x04")
            out_dex = Path(tmp_dir) / "output" / "shim.dex"

            def mock_run(cmd, *args, **kwargs):
                if "javac" in str(cmd[0]):
                    d_idx = cmd.index("-d")
                    out_dir = Path(cmd[d_idx + 1])
                    (out_dir / "ApkReviveInitProvider.class").write_bytes(b"\xca\xfe\xba\xbe")
                    return MagicMock(returncode=0, stderr="")
                elif "d8" in str(cmd[0]):
                    out_idx = cmd.index("--output")
                    dex_out = Path(cmd[out_idx + 1])
                    (dex_out / "classes.dex").write_bytes(canonical_bytes)
                    return MagicMock(returncode=0, stderr="")
                return MagicMock(returncode=0)

            with patch("apkrevive.shim.build_shim.find_sdk_root", return_value=sdk), \
                 patch("apkrevive.shim.build_shim.find_platform_dir", return_value=plat_dir), \
                 patch("subprocess.run", side_effect=mock_run):
                dex = build_shim(output_dex_path=out_dex)
                self.assertEqual(dex, canonical_bytes)
                self.assertTrue(out_dex.is_file())
                self.assertEqual(out_dex.read_bytes(), canonical_bytes)

    def test_main_cli_match_and_mismatch(self):
        canonical_bytes = (Path(__file__).resolve().parent.parent / "apkrevive" / "shim" / "shim.dex").read_bytes()

        # Success path
        with patch("apkrevive.shim.build_shim.build_shim", return_value=canonical_bytes):
            code = main()
            self.assertEqual(code, 0)

        # Mismatch path
        with patch("apkrevive.shim.build_shim.build_shim", return_value=b"bad_dex"):
            code = main()
            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
