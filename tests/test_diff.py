"""
test_diff.py - Unit and integration tests for apkrevive diff and revive CLI subcommands.
"""

import io
import json
import os
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib
import hashlib

from apkrevive.cli import main, run_diff, format_diff_report, diff_to_sarif, revive_cmd
from apkrevive.core.axml import AxmlSurgeon, AxmlNode
from apkrevive.core.align import align_apk
from apkrevive.core.diff import compare_apks, BoolDict


def create_synthetic_dex(class_descriptors: list) -> bytes:
    """Creates a valid conforming DEX binary containing given class descriptors."""
    magic = b"dex\n035\x00"
    num_classes = len(class_descriptors)

    header_size = 0x70  # 112 bytes
    string_ids_off = header_size
    string_ids_size = num_classes
    type_ids_off = string_ids_off + (num_classes * 4)
    type_ids_size = num_classes
    class_defs_off = type_ids_off + (num_classes * 4)
    class_defs_size = num_classes
    data_off = class_defs_off + (num_classes * 32)

    string_data_items = []
    for s in class_descriptors:
        s_bytes = s.encode("utf-8")
        uleb = bytes([len(s)])
        string_data_items.append(uleb + s_bytes + b"\x00")

    string_data_offsets = []
    curr_str_off = data_off
    for s_item in string_data_items:
        string_data_offsets.append(curr_str_off)
        curr_str_off += len(s_item)

    file_size = curr_str_off
    data_size = file_size - data_off

    buf = bytearray(file_size)

    for i, off in enumerate(string_data_offsets):
        struct.pack_into("<I", buf, string_ids_off + i * 4, off)

    for i in range(num_classes):
        struct.pack_into("<I", buf, type_ids_off + i * 4, i)

    for i in range(num_classes):
        c_off = class_defs_off + i * 32
        struct.pack_into(
            "<IIIIIIII",
            buf,
            c_off,
            i,          # class_idx
            0x0001,     # access_flags
            0xFFFFFFFF, # superclass_idx
            0,          # interfaces_off
            0xFFFFFFFF, # source_file_idx
            0,          # annotations_off
            0,          # class_data_off
            0,          # static_values_off
        )

    for off, s_item in zip(string_data_offsets, string_data_items):
        buf[off : off + len(s_item)] = s_item

    buf[0:8] = magic
    struct.pack_into("<I", buf, 0x20, file_size)
    struct.pack_into("<I", buf, 0x24, header_size)
    struct.pack_into("<I", buf, 0x28, 0x12345678)
    struct.pack_into("<II", buf, 0x38, string_ids_size, string_ids_off)
    struct.pack_into("<II", buf, 0x40, type_ids_size, type_ids_off)
    struct.pack_into("<II", buf, 0x60, class_defs_size, class_defs_off)
    struct.pack_into("<II", buf, 0x68, data_size, data_off)

    sha1 = hashlib.sha1(buf[32:]).digest()
    buf[12:32] = sha1

    adler = zlib.adler32(buf[12:]) & 0xFFFFFFFF
    struct.pack_into("<I", buf, 8, adler)

    return bytes(buf)


def add_synthetic_signing_block(raw_zip_bytes: bytes) -> bytes:
    """Appends an APK Signing Block with Verity Padding and ensures CD is 4096-aligned."""
    eocd_pos = raw_zip_bytes.rfind(b"PK\x05\x06")
    if eocd_pos == -1:
        raise ValueError("Invalid ZIP: EOCD not found")
    cd_entries, cd_size, cd_offset = struct.unpack_from("<HII", raw_zip_bytes, eocd_pos + 10)

    entries_part = raw_zip_bytes[:cd_offset]
    cd_part = raw_zip_bytes[cd_offset:eocd_pos]
    eocd_part = bytearray(raw_zip_bytes[eocd_pos:])

    current_end = len(entries_part)
    min_target = current_end + 44
    target_cd = ((min_target + 4095) // 4096) * 4096
    total_block_len = target_cd - current_end
    payload_pairs_len = total_block_len - 32
    value_len = payload_pairs_len - 12

    pair_bytes = struct.pack("<QI", value_len + 4, 0x42726577) + (b"\x00" * value_len)
    block_size = len(pair_bytes) + 24

    sig_block = (
        struct.pack("<Q", block_size)
        + pair_bytes
        + struct.pack("<Q", block_size)
        + b"APK Sig Block 42"
    )

    struct.pack_into("<I", eocd_part, 16, target_cd)
    return entries_part + sig_block + cd_part + bytes(eocd_part)


def build_diff_test_apk(
    path: str,
    pkg: str = "com.apkrevive.testapp",
    target_sdk: int = 19,
    min_sdk: int = 14,
    has_shim: bool = False,
    has_apache: bool = False,
    native_libs: dict = None,
    dex_classes: dict = None,
    with_align: bool = False,
    with_signature: bool = False,
) -> None:
    """Builds test APK file with specific attributes for diff testing."""
    root = AxmlNode(tag="manifest")
    root.set_attr("package", pkg, ns="")

    uses_sdk = AxmlNode(tag="uses-sdk")
    uses_sdk.set_attr("minSdkVersion", min_sdk)
    uses_sdk.set_attr("targetSdkVersion", target_sdk)
    root.children.append(uses_sdk)

    app = AxmlNode(tag="application")
    app.set_attr("hasCode", True)

    if has_apache:
        uses_lib = AxmlNode(tag="uses-library")
        uses_lib.set_attr("name", "org.apache.http.legacy")
        uses_lib.set_attr("required", False)
        app.children.append(uses_lib)

    if has_shim:
        provider = AxmlNode(tag="provider")
        provider.set_attr("name", "com.apkrevive.shim.ApkReviveInitProvider")
        provider.set_attr("authorities", f"{pkg}.apkrevive.init")
        provider.set_attr("exported", False)
        app.children.append(provider)

    root.children.append(app)
    manifest_bytes = AxmlSurgeon.serialize(root)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_bytes)

        if dex_classes is None:
            dex_classes = {"classes.dex": ["Lcom/apkrevive/testapp/MainActivity;"]}

        for dex_name, classes in dex_classes.items():
            zf.writestr(dex_name, create_synthetic_dex(classes))

        if native_libs:
            for lib_name, (content, compress_type) in native_libs.items():
                zinfo = zipfile.ZipInfo(lib_name)
                zinfo.compress_type = compress_type
                zf.writestr(zinfo, content)

    raw_data = buf.getvalue()

    if with_align:
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f_tmp:
            tmp_unaligned = f_tmp.name
        with open(tmp_unaligned, "wb") as f:
            f.write(raw_data)
        aligned_path = path + ".aligned.tmp"
        align_apk(tmp_unaligned, aligned_path)
        with open(aligned_path, "rb") as f:
            raw_data = f.read()
        os.remove(tmp_unaligned)
        os.remove(aligned_path)

    if with_signature:
        raw_data = add_synthetic_signing_block(raw_data)

    with open(path, "wb") as f:
        f.write(raw_data)


class TestDiff(unittest.TestCase):
    def setUp(self):
        self.temp_files = []

    def tearDown(self):
        for p in self.temp_files:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass

    def _get_temp_path(self, suffix=".apk") -> str:
        f = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        f.close()
        self.temp_files.append(f.name)
        return f.name

    def test_compare_apks_comprehensive(self):
        orig_apk = self._get_temp_path()
        rev_apk = self._get_temp_path()

        so_content = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 200

        # Original: targetSdk=19, deflated unaligned .so, 1 DEX, unsigned
        build_diff_test_apk(
            orig_apk,
            pkg="com.apkrevive.sample",
            target_sdk=19,
            min_sdk=14,
            has_shim=False,
            has_apache=False,
            native_libs={"lib/arm64-v8a/libnative.so": (so_content, zipfile.ZIP_DEFLATED)},
            dex_classes={"classes.dex": ["Lcom/apkrevive/sample/MainActivity;"]},
            with_align=False,
            with_signature=False,
        )

        # Revived: targetSdk=24, stored 16KB aligned .so, 2 DEX (with shim), signed
        build_diff_test_apk(
            rev_apk,
            pkg="com.apkrevive.sample",
            target_sdk=24,
            min_sdk=14,
            has_shim=True,
            has_apache=True,
            native_libs={"lib/arm64-v8a/libnative.so": (so_content, zipfile.ZIP_STORED)},
            dex_classes={
                "classes.dex": ["Lcom/apkrevive/sample/MainActivity;"],
                "classes2.dex": ["Lcom/apkrevive/shim/ApkReviveInitProvider;"],
            },
            with_align=True,
            with_signature=True,
        )

        diff = compare_apks(orig_apk, rev_apk)

        # 1. Manifest
        m = diff["manifest"]
        self.assertEqual(m["package_name"]["original"], "com.apkrevive.sample")
        self.assertEqual(m["package_name"]["revived"], "com.apkrevive.sample")
        self.assertFalse(m["package_name"]["changed"])

        self.assertEqual(m["target_sdk"]["original"], 19)
        self.assertEqual(m["target_sdk"]["revived"], 24)
        self.assertTrue(m["target_sdk"]["changed"])

        self.assertEqual(m["min_sdk"]["original"], 14)
        self.assertEqual(m["min_sdk"]["revived"], 14)
        self.assertFalse(m["min_sdk"]["changed"])

        self.assertTrue(m["injected_shim"])
        self.assertEqual(m["injected_shim"], True)
        self.assertTrue(m["injected_shim"]["injected"])

        # 2. Native Libs
        nl = diff["native_libs"]
        self.assertIn("arm64-v8a", nl["abis"]["revived"])
        self.assertIn("lib/arm64-v8a/libnative.so", nl["libraries"])
        lib_diff = nl["libraries"]["lib/arm64-v8a/libnative.so"]
        self.assertEqual(lib_diff["original"]["compression"], "deflated")
        self.assertEqual(lib_diff["revived"]["compression"], "stored")
        self.assertTrue(lib_diff["compression_changed"])
        self.assertTrue(lib_diff["revived"]["is_16k_aligned"])

        # 3. DEX
        dex = diff["dex"]
        self.assertEqual(dex["dex_count"]["original"], 1)
        self.assertEqual(dex["dex_count"]["revived"], 2)
        self.assertTrue(dex["dex_count"]["changed"])
        self.assertIn("Lcom/apkrevive/shim/ApkReviveInitProvider;", dex["injected_classes"])

        # 4. Signature
        sig = diff["signature"]
        self.assertFalse(sig["has_signing_block"]["original"])
        self.assertTrue(sig["has_signing_block"]["revived"])
        self.assertTrue(sig["cd_aligned_4k"]["revived"])

        # 5. Container
        cnt = diff["container"]
        self.assertIn("classes2.dex", cnt["files_added"])
        self.assertIn("AndroidManifest.xml", cnt["files_modified"])
        self.assertIsInstance(cnt["size_delta"], int)

    def test_compare_apks_pure_dex(self):
        orig_apk = self._get_temp_path()
        rev_apk = self._get_temp_path()

        build_diff_test_apk(orig_apk, native_libs=None)
        build_diff_test_apk(rev_apk, native_libs=None)

        diff = run_diff(orig_apk, rev_apk)
        self.assertEqual(diff["native_libs"]["abis"]["original"], [])
        self.assertEqual(diff["native_libs"]["libraries"], {})

    def test_compare_apks_missing_files_raises(self):
        real_apk = self._get_temp_path()
        build_diff_test_apk(real_apk)

        with self.assertRaises(FileNotFoundError):
            compare_apks("nonexistent_orig.apk", real_apk)

        with self.assertRaises(FileNotFoundError):
            compare_apks(real_apk, "nonexistent_rev.apk")

    def test_format_diff_report(self):
        orig_apk = self._get_temp_path()
        rev_apk = self._get_temp_path()

        build_diff_test_apk(orig_apk, target_sdk=19, native_libs={"lib/arm64-v8a/libfoo.so": (b"ELF", zipfile.ZIP_DEFLATED)})
        build_diff_test_apk(rev_apk, target_sdk=24, has_shim=True, native_libs={"lib/arm64-v8a/libfoo.so": (b"ELF", zipfile.ZIP_STORED)}, with_align=True, with_signature=True)

        diff = compare_apks(orig_apk, rev_apk)
        rep = format_diff_report(diff)

        self.assertIn("ApkRevive Modernization Diff Report", rep)
        self.assertIn("Manifest Changes:", rep)
        self.assertIn("Native Libraries:", rep)
        self.assertIn("Dalvik Executable (DEX):", rep)
        self.assertIn("Signature & Integrity:", rep)
        self.assertIn("Container Delta:", rep)
        self.assertIn("19 -> 24", rep)
        self.assertIn("Injected (com.apkrevive.shim.ApkReviveInitProvider)", rep)

    def test_diff_to_sarif_schema(self):
        orig_apk = self._get_temp_path()
        rev_apk = self._get_temp_path()

        build_diff_test_apk(
            orig_apk,
            target_sdk=19,
            has_shim=False,
            has_apache=False,
            native_libs={"lib/arm64-v8a/libx.so": (b"ELF", zipfile.ZIP_DEFLATED)},
        )
        build_diff_test_apk(
            rev_apk,
            target_sdk=24,
            has_shim=True,
            has_apache=True,
            native_libs={"lib/arm64-v8a/libx.so": (b"ELF", zipfile.ZIP_STORED)},
            dex_classes={
                "classes.dex": ["Lcom/apkrevive/testapp/MainActivity;"],
                "classes2.dex": ["Lcom/apkrevive/shim/ApkReviveInitProvider;"],
            },
            with_align=True,
            with_signature=True,
        )

        diff = compare_apks(orig_apk, rev_apk)
        sarif = diff_to_sarif(diff)

        self.assertEqual(sarif["$schema"], "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json")
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"]), 1)
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "apkrevive")
        self.assertIsInstance(run["results"], list)
        self.assertGreater(len(run["results"]), 0)

        rule_ids = {r["ruleId"] for r in run["results"]}
        self.assertIn("MODERNIZED_TARGET_SDK", rule_ids)
        self.assertIn("MODERNIZED_SHIM_INJECTED", rule_ids)
        self.assertIn("MODERNIZED_NATIVE_16KB_ALIGNMENT", rule_ids)
        self.assertIn("MODERNIZED_DEX_EXPANSION", rule_ids)
        self.assertIn("MODERNIZED_SIGNATURE_4KB", rule_ids)

    def test_cli_diff_text_output(self):
        orig_apk = self._get_temp_path()
        rev_apk = self._get_temp_path()
        build_diff_test_apk(orig_apk)
        build_diff_test_apk(rev_apk)

        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            code = main(["diff", orig_apk, rev_apk])

        self.assertEqual(code, 0)
        self.assertIn("ApkRevive Modernization Diff Report", mock_out.getvalue())

    def test_cli_diff_json_output(self):
        orig_apk = self._get_temp_path()
        rev_apk = self._get_temp_path()
        build_diff_test_apk(orig_apk, target_sdk=19)
        build_diff_test_apk(rev_apk, target_sdk=24)

        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            code = main(["diff", orig_apk, rev_apk, "--json"])

        self.assertEqual(code, 0)
        parsed = json.loads(mock_out.getvalue())
        self.assertEqual(parsed["manifest"]["target_sdk"]["original"], 19)
        self.assertEqual(parsed["manifest"]["target_sdk"]["revived"], 24)

    def test_cli_diff_sarif_output(self):
        orig_apk = self._get_temp_path()
        rev_apk = self._get_temp_path()
        build_diff_test_apk(orig_apk)
        build_diff_test_apk(rev_apk)

        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            code = main(["diff", orig_apk, rev_apk, "--sarif"])

        self.assertEqual(code, 0)
        parsed = json.loads(mock_out.getvalue())
        self.assertEqual(parsed["version"], "2.1.0")
        self.assertEqual(parsed["runs"][0]["tool"]["driver"]["name"], "apkrevive")

    def test_cli_diff_missing_file_exit_2(self):
        real_apk = self._get_temp_path()
        build_diff_test_apk(real_apk)

        with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            code = main(["diff", "nonexistent.apk", real_apk])

        self.assertEqual(code, 2)
        self.assertIn("File not found", mock_err.getvalue())

    def test_revive_cli_command(self):
        in_apk = self._get_temp_path()
        out_apk = self._get_temp_path()
        build_diff_test_apk(in_apk, target_sdk=19)

        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            code = main(["revive", "--no-sign", in_apk, "-o", out_apk])

        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(out_apk))
        self.assertIn("ApkRevive Patch Execution Complete", mock_out.getvalue())

        # Verify revived APK contains injected classes2.dex
        with zipfile.ZipFile(out_apk, "r") as zf:
            self.assertIn("classes2.dex", zf.namelist())

    def test_revive_cli_missing_signing_tools_fails_fast(self):
        in_apk = self._get_temp_path()
        out_apk = self._get_temp_path()
        build_diff_test_apk(in_apk)

        with patch("apkrevive.core.signer.subprocess.run", side_effect=FileNotFoundError("apksigner missing")):
            with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
                code = main(["revive", in_apk, "-o", out_apk])

        self.assertEqual(code, 1)
        self.assertIn("Missing required signing tool", mock_err.getvalue())
        self.assertIn("apkrevive doctor", mock_err.getvalue())

    def test_revive_cmd_direct_with_bump_target_sdk_and_json(self):
        in_apk = self._get_temp_path()
        out_apk = self._get_temp_path()
        build_diff_test_apk(in_apk, target_sdk=19)

        class MockArgs:
            apk = in_apk
            output = out_apk
            bump_target_sdk = 31
            no_sign = True
            json = True

        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            code = revive_cmd(MockArgs())

        self.assertEqual(code, 0)
        out_data = json.loads(mock_out.getvalue())
        self.assertEqual(out_data["target_sdk"], 31)

    def test_bool_dict_behavior(self):
        bd_true = BoolDict(True, original=False, revived=True, injected=True)
        self.assertTrue(bd_true)
        self.assertEqual(bd_true, True)
        self.assertEqual(bd_true["revived"], True)
        self.assertEqual(bd_true["original"], False)

        bd_false = BoolDict(False, original=False, revived=False, injected=False)
        self.assertFalse(bd_false)
        self.assertEqual(bd_false, False)


if __name__ == "__main__":
    unittest.main()
