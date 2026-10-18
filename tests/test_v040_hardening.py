"""
test_v040_hardening.py - Comprehensive unit test suite for ApkRevive v0.4.0 hardening tasks.
"""

import io
import os
import struct
import tempfile
import unittest
import zipfile
from typing import Optional
from unittest.mock import patch

from apkrevive.core.axml import AxmlSurgeon, AxmlNode, KNOWN_RESOURCE_IDS
from apkrevive.core.align import align_apk, verify_apk_alignment
from apkrevive.core.signer import verify_signing_block_padding
from apkrevive.core.split_merger import merge_split_apks
from apkrevive.core.models import DeviceProfile, ApkMetadata
from apkrevive.core.triage import evaluate_triage
from apkrevive.cli import main


def create_apk_with_signing_block(path: str, pairs, cd_offset_align: int = 4096, input_apk: Optional[str] = None):
    if input_apk and os.path.exists(input_apk):
        with open(input_apk, "rb") as f_in:
            raw_zip = f_in.read()
    else:
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"MINIMAL_MANIFEST")
            zf.writestr("classes.dex", b"MINIMAL_DEX")
        raw_zip = bio.getvalue()

    eocd_pos = raw_zip.rfind(b"PK\x05\x06")
    cd_entries_total, cd_size, cd_offset = struct.unpack_from("<HII", raw_zip, eocd_pos + 10)

    pre_cd_data = raw_zip[:cd_offset]
    cd_data = raw_zip[cd_offset:eocd_pos]
    eocd_data = raw_zip[eocd_pos:]

    pairs_list = list(pairs)
    if cd_offset_align > 1:
        has_verity = any(pid == 0x42726577 for pid, _ in pairs_list)
        current_pairs_len = sum(12 + len(v) for _, v in pairs_list)
        fixed_overhead = len(pre_cd_data) + current_pairs_len + 32
        rem = fixed_overhead % cd_offset_align
        if rem != 0:
            pad_needed = cd_offset_align - rem
            if pad_needed < 12:
                pad_needed += cd_offset_align
            if has_verity:
                new_list = []
                for pid, v in pairs_list:
                    if pid == 0x42726577:
                        new_list.append((pid, v + (b"\x00" * pad_needed)))
                    else:
                        new_list.append((pid, v))
                pairs_list = new_list
            else:
                pairs_list.append((0x42726577, b"\x00" * (pad_needed - 12)))

    pairs_bytes = bytearray()
    for pair_id, val in pairs_list:
        pair_size = 4 + len(val)
        pairs_bytes.extend(struct.pack("<QI", pair_size, pair_id))
        pairs_bytes.extend(val)

    block_size = len(pairs_bytes) + 24
    sig_block = (
        struct.pack("<Q", block_size)
        + bytes(pairs_bytes)
        + struct.pack("<Q", block_size)
        + b"APK Sig Block 42"
    )

    final_cd_offset = len(pre_cd_data) + len(sig_block)

    new_eocd = bytearray(eocd_data)
    struct.pack_into("<II", new_eocd, 12, cd_size, final_cd_offset)

    with open(path, "wb") as f:
        f.write(pre_cd_data)
        f.write(sig_block)
        f.write(cd_data)
        f.write(new_eocd)



class TestV040Hardening(unittest.TestCase):

    def test_1_ascending_resource_id_attribute_ordering(self):
        """Test 1: Ascending resource-ID attribute ordering in mutated binary AndroidManifest.xml chunks."""
        manifest = AxmlNode(tag="manifest")
        manifest.set_attr("package", "com.test.sortorder")
        app = AxmlNode(tag="application")

        # Deliberately add attributes in reverse / non-sorted order
        app.set_attr("isSplitRequired", True)          # 0x01010591
        app.set_attr("extractNativeLibs", False)       # 0x010104EA
        app.set_attr("resizeableActivity", True)       # 0x010104E1
        app.set_attr("hasCode", True)                  # 0x0101000C
        app.set_attr("name", "com.test.MyApplication") # 0x01010003
        app.set_attr("custom_no_res_id", "custom_val") # No resource ID (0)

        manifest.children.append(app)
        serialized = AxmlSurgeon.serialize(manifest)

        # Parse serialized binary back and verify attribute sequence
        root = AxmlSurgeon.parse(serialized)
        app_node = root.find_child("application")
        self.assertIsNotNone(app_node)

        res_ids = []
        for a in app_node.attributes:
            base_name = a.name.split(":")[-1]
            rid = KNOWN_RESOURCE_IDS.get(a.name, KNOWN_RESOURCE_IDS.get(base_name, 0))
            res_ids.append(rid)

        valid_res_ids = [r for r in res_ids if r > 0]
        zero_res_ids = [r for r in res_ids if r == 0]

        # Valid resource IDs must be strictly sorted ascending
        self.assertEqual(valid_res_ids, sorted(valid_res_ids))
        self.assertEqual(len(valid_res_ids), len(set(valid_res_ids)))

        # Attributes without resource ID (0) must appear after all valid resource IDs
        self.assertEqual(res_ids, valid_res_ids + zero_res_ids)

    def test_2_unique_provider_authority_and_init_order(self):
        """Test 2: Unique <package>.apkrevive.init provider authority and initOrder='2147483647' across multiple packages."""
        packages = ["com.alpha.app", "org.beta.game", "net.gamma.tool"]
        authorities = []

        for pkg in packages:
            manifest = AxmlNode(tag="manifest")
            manifest.set_attr("package", pkg)
            app = AxmlNode(tag="application")
            manifest.children.append(app)
            raw = AxmlSurgeon.serialize(manifest)

            patched = AxmlSurgeon.patch_manifest(raw, transforms=[], options={"standalone_install": True})
            root = AxmlSurgeon.parse(patched)
            app_node = root.find_child("application")
            self.assertIsNotNone(app_node)

            prov = app_node.find_child("provider", "name", "apkrevive.shim.ApkReviveInitProvider")
            self.assertIsNotNone(prov, f"Provider missing for {pkg}")

            auth = prov.get_attr("authorities").get_value()
            init_order = prov.get_attr("initOrder").get_value()
            exported = prov.get_attr("exported").get_value()

            self.assertEqual(auth, f"{pkg}.apkrevive.init")
            self.assertEqual(init_order, 2147483647)
            self.assertFalse(exported)
            authorities.append(auth)

        # Authorities must be unique across all packages
        self.assertEqual(len(authorities), len(set(authorities)))
        self.assertEqual(len(authorities), 3)

    def test_3_16kb_alignment_invariance_after_signing(self):
        """Test 3: End-to-end 16KB alignment invariance (offset % 16384 == 0 for all STORED .so files) after signing."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            unaligned_apk = os.path.join(tmp_dir, "unaligned.apk")
            aligned_apk = os.path.join(tmp_dir, "aligned.apk")
            signed_apk = os.path.join(tmp_dir, "signed.apk")

            with zipfile.ZipFile(unaligned_apk, "w") as zf:
                zf.writestr("AndroidManifest.xml", b"MINIMAL_MANIFEST")
                zf.writestr("classes.dex", b"MINIMAL_DEX")

                z_arm64 = zipfile.ZipInfo("lib/arm64-v8a/libtest.so")
                z_arm64.compress_type = zipfile.ZIP_STORED
                zf.writestr(z_arm64, b"\x7fELF" + b"\x00" * 4096)

                z_x86_64 = zipfile.ZipInfo("lib/x86_64/libtest.so")
                z_x86_64.compress_type = zipfile.ZIP_STORED
                zf.writestr(z_x86_64, b"\x7fELF" + b"\x00" * 4096)

                z_v7a = zipfile.ZipInfo("lib/armeabi-v7a/libtest.so")
                z_v7a.compress_type = zipfile.ZIP_STORED
                zf.writestr(z_v7a, b"\x7fELF" + b"\x00" * 2048)

                z_arsc = zipfile.ZipInfo("resources.arsc")
                z_arsc.compress_type = zipfile.ZIP_STORED
                zf.writestr(z_arsc, b"ARSC_DATA" * 50)

            align_apk(unaligned_apk, aligned_apk, page_align_64bit=16384)
            res_before = verify_apk_alignment(aligned_apk)
            self.assertTrue(res_before["aligned"])
            self.assertEqual(res_before["entries"]["lib/arm64-v8a/libtest.so"]["offset"] % 16384, 0)
            self.assertEqual(res_before["entries"]["lib/x86_64/libtest.so"]["offset"] % 16384, 0)
            self.assertEqual(res_before["entries"]["lib/armeabi-v7a/libtest.so"]["offset"] % 4096, 0)
            self.assertEqual(res_before["entries"]["resources.arsc"]["offset"] % 4096, 0)

            # Insert APK Signing Block (simulating signing) before Central Directory
            pairs = [(0x7109871a, b"v2_signature_bytes")]
            create_apk_with_signing_block(signed_apk, pairs, cd_offset_align=4096, input_apk=aligned_apk)

            # Verify LFH and uncompressed entry offsets remain 16KB-invariant
            res_after = verify_apk_alignment(signed_apk)
            self.assertTrue(res_after["aligned"])
            self.assertEqual(res_after["entries"]["lib/arm64-v8a/libtest.so"]["offset"] % 16384, 0)
            self.assertEqual(res_after["entries"]["lib/x86_64/libtest.so"]["offset"] % 16384, 0)
            self.assertEqual(res_after["entries"]["lib/armeabi-v7a/libtest.so"]["offset"] % 4096, 0)
            self.assertEqual(res_after["entries"]["resources.arsc"]["offset"] % 4096, 0)

    def test_4_string_pool_with_styles_preservation(self):
        """Test 4: String pool with styleCount > 0 and stylesStart > 0 style table preservation, shifting stylesStart, 4-byte padding, and span index validity."""
        # Construct synthetic StringPool with styleCount=1, UTF-8 flag, and style span data
        orig_string = "<b>Hello</b>"
        s_enc = orig_string.encode("utf-8")
        s_entry = bytes([len(orig_string), len(s_enc)]) + s_enc + b"\x00"
        pad = (4 - (len(s_entry) % 4)) % 4
        padded_str_data = s_entry + (b"\x00" * pad)

        style_span = struct.pack("<III", 0, 0, 4) + struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF)
        style_pad = (4 - (len(style_span) % 4)) % 4
        padded_style_data = style_span + (b"\x00" * style_pad)

        str_count = 1
        style_count = 1
        flags = 0x0100  # UTF-8
        str_start = 28 + 4 + 4  # header (28) + str_offsets (4) + style_offsets (4) = 36
        styles_start = str_start + len(padded_str_data)
        total_size = styles_start + len(padded_style_data)

        header = struct.pack(
            "<HHI IIIII",
            0x0001, 28, total_size,
            str_count, style_count, flags,
            str_start, styles_start
        )
        sp_chunk = (
            header
            + struct.pack("<I", 0)  # str_offset[0]
            + struct.pack("<I", 0)  # style_offset[0]
            + padded_str_data
            + padded_style_data
        )

        appended = AxmlSurgeon.append_string_to_pool(sp_chunk, ["appended_entry1", "appended_entry2"])

        c_type, c_hsize, c_size = struct.unpack_from("<HHI", appended, 0)
        new_str_count, new_style_count, new_flags, new_str_start, new_styles_start = struct.unpack_from("<IIIII", appended, 8)

        self.assertEqual(c_type, 0x0001)
        self.assertEqual(new_str_count, 3)
        self.assertEqual(new_style_count, 1)
        self.assertGreater(new_styles_start, styles_start)
        self.assertEqual(new_styles_start % 4, 0)
        self.assertEqual(c_size % 4, 0)

        # Style span data must be preserved intact at new_styles_start
        span_slice = appended[new_styles_start : new_styles_start + len(style_span)]
        self.assertEqual(span_slice, style_span)

    def test_5_split_lock_stripping(self):
        """Test 5: Split-lock stripping of requiredSplitTypes, splitTypes, com.android.vending.splits, and com.android.vending.derived.apk.id."""
        manifest = AxmlNode(tag="manifest")
        manifest.set_attr("package", "com.test.splitlocks")
        manifest.set_attr("split", "config.arm64_v8a")
        manifest.set_attr("configForSplit", "arm64_v8a")
        manifest.set_attr("requiredSplitTypes", "base__abi")
        manifest.set_attr("splitTypes", "base__abi")

        app = AxmlNode(tag="application")
        app.set_attr("isSplitRequired", True)
        app.set_attr("requiredSplitTypes", "base__abi")
        app.set_attr("splitTypes", "base__abi")

        for meta_name in [
            "com.android.vending.splits.required",
            "com.android.vending.splits",
            "com.android.vending.derived.apk.id",
        ]:
            meta = AxmlNode(tag="meta-data")
            meta.set_attr("name", meta_name)
            meta.set_attr("value", "true")
            app.children.append(meta)

        normal_meta = AxmlNode(tag="meta-data")
        normal_meta.set_attr("name", "preserved_metadata")
        normal_meta.set_attr("value", "important_value")
        app.children.append(normal_meta)

        manifest.children.append(app)
        raw = AxmlSurgeon.serialize(manifest)

        stripped = AxmlSurgeon.strip_split_locks(raw)
        root = AxmlSurgeon.parse(stripped)

        self.assertIsNone(root.get_attr("split"))
        self.assertIsNone(root.get_attr("configForSplit"))
        self.assertIsNone(root.get_attr("requiredSplitTypes"))
        self.assertIsNone(root.get_attr("splitTypes"))

        app_node = root.find_child("application")
        self.assertIsNotNone(app_node)
        self.assertIsNone(app_node.get_attr("isSplitRequired"))
        self.assertIsNone(app_node.get_attr("requiredSplitTypes"))
        self.assertIsNone(app_node.get_attr("splitTypes"))

        self.assertIsNone(app_node.find_child("meta-data", "name", "com.android.vending.splits.required"))
        self.assertIsNone(app_node.find_child("meta-data", "name", "com.android.vending.splits"))
        self.assertIsNone(app_node.find_child("meta-data", "name", "com.android.vending.derived.apk.id"))
        self.assertIsNotNone(app_node.find_child("meta-data", "name", "preserved_metadata"))

    def test_6_bump_target_sdk_and_standalone_install_cli_and_warnings(self):
        """Test 6: --bump-target-sdk and --standalone-install CLI flags and dangerous permissions triage warning."""
        apk_meta = ApkMetadata(
            target_sdk=22,
            abis=["arm64-v8a"],
            permissions=[
                "android.permission.CAMERA",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.INTERNET",
            ],
        )
        dev = DeviceProfile(os_api_level=35, supported_abis=["arm64-v8a"])

        res = evaluate_triage(apk_meta, dev, bump_target_sdk=24)
        warnings = res.get("warnings", [])
        bump_warns = [w for w in warnings if w.startswith("WARN_RUNTIME_PERMISSIONS_ON_BUMP:")]
        self.assertEqual(len(bump_warns), 1)
        self.assertIn("targetSdkVersion bumped to 24 (>= 23)", bump_warns[0])
        self.assertIn("android.permission.CAMERA", bump_warns[0])
        self.assertIn("android.permission.READ_EXTERNAL_STORAGE", bump_warns[0])
        self.assertNotIn("android.permission.INTERNET", bump_warns[0])

        with patch("sys.argv", ["apkrevive", "triage", "dummy.apk", "--bump-target-sdk", "26", "--standalone-install"]), \
             patch("apkrevive.cli.triage_cmd") as mock_triage:
            main()
            self.assertTrue(mock_triage.called)
            args = mock_triage.call_args[0][0]
            self.assertEqual(args.bump_target_sdk, 26)
            self.assertTrue(args.standalone_install)

        with patch("sys.argv", ["apkrevive", "revive", "dummy.apk", "--bump-target-sdk", "28", "--standalone-install"]), \
             patch("apkrevive.cli.revive_cmd") as mock_revive:
            main()
            self.assertTrue(mock_revive.called)
            args = mock_revive.call_args[0][0]
            self.assertEqual(args.bump_target_sdk, 28)
            self.assertTrue(args.standalone_install)

    def test_7_signing_block_verity_padding_and_cd_alignment(self):
        """Test 7: 4KB Verity padding block (0x42726577) and CD alignment verification in signer.py."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # 1. Plain APK without signing block
            plain_apk = os.path.join(tmp_dir, "plain.apk")
            with zipfile.ZipFile(plain_apk, "w") as zf:
                zf.writestr("AndroidManifest.xml", b"MINIMAL")
                zf.writestr("classes.dex", b"DEX")

            res_plain = verify_signing_block_padding(plain_apk)
            self.assertFalse(res_plain["has_signing_block"])
            self.assertFalse(res_plain["has_verity_padding"])
            self.assertEqual(res_plain["block_ids"], [])
            self.assertEqual(res_plain["signing_block_size"], 0)

            # 2. APK with signing block containing 0x42726577 (Verity padding) and 4KB CD alignment
            aligned_apk = os.path.join(tmp_dir, "aligned.apk")
            pairs = [
                (0x42726577, b"\x00" * 32),
                (0x7109871a, b"v2_signature_bytes"),
            ]
            create_apk_with_signing_block(aligned_apk, pairs, cd_offset_align=4096)

            res_aligned = verify_signing_block_padding(aligned_apk)
            self.assertTrue(res_aligned["has_signing_block"])
            self.assertTrue(res_aligned["has_verity_padding"])
            self.assertIn(0x42726577, res_aligned["block_ids"])
            self.assertIn(0x7109871a, res_aligned["block_ids"])
            self.assertTrue(res_aligned["cd_aligned_4k"])
            self.assertTrue(res_aligned["valid"])
            self.assertGreater(res_aligned["signing_block_size"], 0)

            # 3. APK with signing block without 0x42726577
            no_verity_apk = os.path.join(tmp_dir, "no_verity.apk")
            create_apk_with_signing_block(no_verity_apk, [(0x7109871a, b"v2_signature_bytes")], cd_offset_align=1)

            res_no_verity = verify_signing_block_padding(no_verity_apk)
            self.assertTrue(res_no_verity["has_signing_block"])
            self.assertFalse(res_no_verity["has_verity_padding"])

    def test_8_split_merger_stored_native_libs_and_resource_warning(self):
        """Test 8: split_merger with native libraries written ZIP_STORED, extractNativeLibs=False synchronized, and resource split warning."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            base_apk = os.path.join(tmp_dir, "base.apk")
            split_arm64 = os.path.join(tmp_dir, "split_config.arm64_v8a.apk")
            split_res = os.path.join(tmp_dir, "split_config.xxhdpi.apk")
            output_apk = os.path.join(tmp_dir, "merged.apk")

            # 1. Base APK with split locks
            manifest = AxmlNode(tag="manifest")
            manifest.set_attr("package", "com.example.merge")
            manifest.set_attr("split", "base")
            app = AxmlNode(tag="application")
            app.set_attr("isSplitRequired", True)
            manifest.children.append(app)
            base_axml = AxmlSurgeon.serialize(manifest)

            with zipfile.ZipFile(base_apk, "w") as zf:
                zf.writestr("AndroidManifest.xml", base_axml)
                zf.writestr("classes.dex", b"DEX_BASE")
                zf.writestr("resources.arsc", b"BASE_ARSC")

            # 2. Config split with arm64 native library (written with DEFLATED in split)
            with zipfile.ZipFile(split_arm64, "w") as zf:
                zinfo = zipfile.ZipInfo("lib/arm64-v8a/libfoo.so")
                zinfo.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(zinfo, b"NATIVE_CODE_ARM64" * 100)

            # 3. Config split with separate resources.arsc
            with zipfile.ZipFile(split_res, "w") as zf:
                zf.writestr("resources.arsc", b"SPLIT_ARSC")
                zf.writestr("res/drawable-xxhdpi/icon.png", b"PNG_DATA")

            warnings = []
            merge_split_apks([base_apk, split_arm64, split_res], output_apk, warnings=warnings)

            self.assertTrue(os.path.exists(output_apk))

            # Verify resource split warning
            self.assertEqual(len(warnings), 1)
            expected_warn = (
                "WARN_SPLIT_RESOURCE_TABLE_MERGE: Split APK contains separate resources.arsc "
                "(split_config.xxhdpi.apk); non-colliding res/ files merged without deep table unification."
            )
            self.assertEqual(warnings[0], expected_warn)

            # Verify native library written ZIP_STORED and extractNativeLibs=False synchronized
            with zipfile.ZipFile(output_apk, "r") as zout:
                namelist = zout.namelist()
                self.assertIn("lib/arm64-v8a/libfoo.so", namelist)
                so_info = zout.getinfo("lib/arm64-v8a/libfoo.so")
                self.assertEqual(so_info.compress_type, zipfile.ZIP_STORED)

                manifest_bytes = zout.read("AndroidManifest.xml")
                root = AxmlSurgeon.parse(manifest_bytes)
                app_node = root.find_child("application")
                self.assertIsNotNone(app_node)
                extract_attr = app_node.get_attr("extractNativeLibs")
                self.assertIsNotNone(extract_attr)
                self.assertEqual(extract_attr.get_value(), False)

            # Verify 16KB alignment
            align_res = verify_apk_alignment(output_apk)
            self.assertTrue(align_res["aligned"])
            self.assertEqual(align_res["entries"]["lib/arm64-v8a/libfoo.so"]["offset"] % 16384, 0)


if __name__ == "__main__":
    unittest.main()
