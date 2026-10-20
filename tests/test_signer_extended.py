"""
tests/test_signer_extended.py - Extended unit tests for apkrevive.core.signer covering edge cases and error handling.
"""

from __future__ import annotations

import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from apkrevive.core.signer import (
    ensure_keystore,
    get_apksigner_cmd,
    sign_apk,
    verify_apk,
    verify_apk_certs,
    verify_signing_block_padding,
)


class TestSignerExtended(unittest.TestCase):
    def test_get_apksigner_cmd_with_sdk_roots(self):
        # 1. When which returns None, but SDK root has build-tools
        with tempfile.TemporaryDirectory() as tmp_dir:
            bt_dir = Path(tmp_dir) / "build-tools" / "35.0.0"
            bt_dir.mkdir(parents=True)
            tool_name = "apksigner.bat" if os.name == "nt" else "apksigner"
            (bt_dir / tool_name).write_text("echo test", encoding="utf-8")

            with patch("shutil.which", return_value=None):
                with patch.dict(os.environ, {"ANDROID_HOME": tmp_dir, "ANDROID_SDK_ROOT": ""}):
                    cmd = get_apksigner_cmd()
                    self.assertIn("35.0.0", cmd)

        # 2. Complete fallback
        with patch("shutil.which", return_value=None):
            with patch.dict(os.environ, {"ANDROID_HOME": "", "ANDROID_SDK_ROOT": "", "LOCALAPPDATA": ""}):
                cmd = get_apksigner_cmd()
                self.assertEqual(cmd, "apksigner")

    def test_ensure_keystore_with_env(self):
        with tempfile.NamedTemporaryFile(suffix=".p12", delete=False) as f:
            f.write(b"dummy_p12")
            env_path = f.name
        try:
            with patch.dict(os.environ, {"APKREVIVE_KEYSTORE": env_path}):
                ks, pwd, alias = ensure_keystore()
                self.assertEqual(ks, env_path)
                self.assertEqual(pwd, "android")
                self.assertEqual(alias, "apkrevive")
        finally:
            if os.path.exists(env_path):
                os.remove(env_path)

    def test_ensure_keystore_resolves_keytool_from_java_home(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_home = Path(tmp_dir) / "home"
            jh = Path(tmp_dir) / "jdk"
            bin_dir = jh / "bin"
            bin_dir.mkdir(parents=True)
            kt_file = bin_dir / ("keytool.exe" if os.name == "nt" else "keytool")
            kt_file.write_text("echo keytool", encoding="utf-8")

            with patch("pathlib.Path.home", return_value=tmp_home), \
                 patch("shutil.which", return_value=None), \
                 patch.dict(os.environ, {"JAVA_HOME": str(jh), "APKREVIVE_KEYSTORE": ""}), \
                 patch("subprocess.run") as mock_run:
                # Mock keytool generating keystore file
                def side_effect(cmd, *args, **kwargs):
                    ks_idx = cmd.index("-keystore")
                    Path(cmd[ks_idx + 1]).write_bytes(b"dummy_ks_content")
                    return MagicMock(returncode=0)

                mock_run.side_effect = side_effect
                ks, pwd, alias = ensure_keystore()
                self.assertTrue(Path(ks).is_file())
                self.assertEqual(mock_run.call_args[0][0][0], str(kt_file))

    def test_ensure_keystore_keytool_failure(self):
        with tempfile.TemporaryDirectory() as tmp_home:
            with patch("pathlib.Path.home", return_value=Path(tmp_home)):
                with patch("shutil.which", return_value="keytool"):
                    with patch("subprocess.run", return_value=MagicMock(returncode=1, stderr="keytool error")):
                        with self.assertRaises(RuntimeError) as ctx:
                            ensure_keystore()
                        self.assertIn("keytool failed to generate keystore", str(ctx.exception))

    def test_sign_apk_exceptions(self):
        # Exception in ensure_keystore
        with patch("apkrevive.core.signer.ensure_keystore", side_effect=Exception("Keystore exploded")):
            res = sign_apk("sample.apk")
            self.assertFalse(res)

        # Exception in subprocess.run
        with patch("apkrevive.core.signer.ensure_keystore", return_value=("ks.p12", "pass", "alias")):
            with patch("subprocess.run", side_effect=OSError("apksigner missing")):
                res = sign_apk("sample.apk")
                self.assertFalse(res)

    def test_verify_apk_exception(self):
        with patch("subprocess.run", side_effect=OSError("apksigner verify crashed")):
            res = verify_apk("sample.apk")
            self.assertFalse(res["verified"])
            self.assertIn("apksigner verify crashed", res["output"])

    def test_verify_apk_certs_execution_error(self):
        with patch("apkrevive.core.signer.get_apksigner_cmd", return_value="apksigner"), \
             patch("shutil.which", return_value="apksigner"), \
             patch("subprocess.run", side_effect=RuntimeError("apksigner timeout")):
            ok, msg = verify_apk_certs("sample.apk")
            self.assertFalse(ok)
            self.assertIn("apksigner execution error", msg)

    def test_verify_signing_block_padding_edge_cases(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            fpath = Path(tmp_dir) / "empty.apk"

            # 1. Empty file (no EOCD)
            fpath.write_bytes(b"")
            res = verify_signing_block_padding(str(fpath))
            self.assertFalse(res["valid"])
            self.assertFalse(res["has_signing_block"])

            # 2. Synthetic file with EOCD but no signing block magic
            # EOCD: magic (4B), disk (2B), start_disk (2B), entries_disk (2B), cd_entries_total (2B), cd_size (4B), cd_offset (4B), comment_len (2B) = 22 bytes
            cd_offset = 64
            eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, 32, cd_offset, 0)
            data = b"\x00" * cd_offset + b"dummy_cd_data_32_bytes_long_here" + eocd
            fpath.write_bytes(data)
            res2 = verify_signing_block_padding(str(fpath))
            self.assertFalse(res2["has_signing_block"])
            self.assertEqual(res2["cd_offset"], cd_offset)

            # 3. Synthetic file with signing block magic but invalid size header
            # Put b"APK Sig Block 42" right before cd_offset
            magic_pos = cd_offset - 16
            size_pos = cd_offset - 24
            data_arr = bytearray(data)
            data_arr[magic_pos:cd_offset] = b"APK Sig Block 42"
            struct.pack_into("<Q", data_arr, size_pos, 99999)  # Huge block_size causes start_offset < 0
            fpath.write_bytes(bytes(data_arr))
            res3 = verify_signing_block_padding(str(fpath))
            self.assertFalse(res3["has_signing_block"])

            # 4. Valid synthetic signing block with verity padding
            # cd_offset at 4096 so cd_aligned_4k is True!
            cd_offset_4k = 4096
            block_size = 64
            start_offset = cd_offset_4k - block_size - 8
            full_data = bytearray(b"\x00" * (cd_offset_4k + 64))

            # Start size
            struct.pack_into("<Q", full_data, start_offset, block_size)
            # End size and magic
            struct.pack_into("<Q", full_data, cd_offset_4k - 24, block_size)
            full_data[cd_offset_4k - 16 : cd_offset_4k] = b"APK Sig Block 42"

            # Inside block: one pair with Verity padding ID (0x42726577)
            # pair: size (8B uint64), id (4B uint32), data
            pair_offset = start_offset + 8
            pair_size = 12
            struct.pack_into("<QI", full_data, pair_offset, pair_size, 0x42726577)

            # Append EOCD at the end
            eocd_4k = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, 32, cd_offset_4k, 0)
            full_data.extend(eocd_4k)

            fpath.write_bytes(bytes(full_data))
            res4 = verify_signing_block_padding(str(fpath))
            self.assertTrue(res4["has_signing_block"])
            self.assertTrue(res4["cd_aligned_4k"])
            self.assertTrue(res4["has_verity_padding"])
            self.assertTrue(res4["valid"])
            self.assertIn(0x42726577, res4["block_ids"])


if __name__ == "__main__":
    unittest.main()
