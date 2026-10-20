"""
test_split_merger.py - Tests Split APK Merger and split-lock stripping.
"""

import os
import tempfile
import unittest
import zipfile
from typing import List, Optional

from apkrevive.core.axml import AxmlSurgeon, AxmlNode
from apkrevive.core.split_merger import merge_split_apks, UnsupportedSplitMerge
from apkrevive.core.align import verify_apk_alignment


def _make_dummy_manifest(package: str = "com.example.splitapp", split: Optional[str] = None) -> bytes:
    manifest = AxmlNode(tag="manifest")
    manifest.set_attr("package", package)
    if split is not None:
        manifest.set_attr("split", split)
    app = AxmlNode(tag="application")
    manifest.children.append(app)
    return AxmlSurgeon.serialize(manifest)


class TestSplitMerger(unittest.TestCase):
    def test_merge_splits_and_strip_locks(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base_apk = os.path.join(tmp_dir, "base.apk")
            split_arm64 = os.path.join(tmp_dir, "split_config.arm64_v8a.apk")
            split_feature = os.path.join(tmp_dir, "split_feature.apk")
            output_apk = os.path.join(tmp_dir, "merged.apk")

            # 1. Base APK manifest with split-lock attributes
            manifest = AxmlNode(tag="manifest")
            manifest.set_attr("package", "com.example.splitapp")
            manifest.set_attr("split", "base")
            app = AxmlNode(tag="application")
            app.set_attr("isSplitRequired", True)
            meta = AxmlNode(tag="meta-data")
            meta.set_attr("name", "com.android.vending.splits.required")
            meta.set_attr("value", "true")
            app.children.append(meta)
            manifest.children.append(app)
            base_axml = AxmlSurgeon.serialize(manifest)

            with zipfile.ZipFile(base_apk, "w") as zf:
                zf.writestr("AndroidManifest.xml", base_axml)
                zf.writestr("classes.dex", b"DEX_BASE_PAYLOAD")
                zf.writestr("resources.arsc", b"ARSC_PAYLOAD")

            # 2. Config split: arm64 native library
            with zipfile.ZipFile(split_arm64, "w") as zf:
                zinfo_so = zipfile.ZipInfo("lib/arm64-v8a/libnative.so")
                zinfo_so.compress_type = zipfile.ZIP_STORED
                zf.writestr(zinfo_so, b"SO_PAYLOAD" * 50)

            # 3. Feature split: secondary DEX and assets
            with zipfile.ZipFile(split_feature, "w") as zf:
                zf.writestr("classes.dex", b"DEX_FEATURE_PAYLOAD")
                zf.writestr("assets/config.json", b'{"key": "value"}')

            # Execute merge
            merge_split_apks([base_apk, split_arm64, split_feature], output_apk)

            self.assertTrue(os.path.exists(output_apk))

            with zipfile.ZipFile(output_apk, "r") as zout:
                namelist = zout.namelist()

                # Verify DEX sequential renumbering
                self.assertIn("classes.dex", namelist)
                self.assertIn("classes2.dex", namelist)
                self.assertEqual(zout.read("classes.dex"), b"DEX_BASE_PAYLOAD")
                self.assertEqual(zout.read("classes2.dex"), b"DEX_FEATURE_PAYLOAD")

                # Verify native library merged
                self.assertIn("lib/arm64-v8a/libnative.so", namelist)

                # Verify assets merged
                self.assertIn("assets/config.json", namelist)
                self.assertEqual(zout.read("assets/config.json"), b'{"key": "value"}')

                # Verify manifest stripped of split-locks
                merged_axml = zout.read("AndroidManifest.xml")
                root = AxmlSurgeon.parse(merged_axml)
                self.assertIsNone(root.get_attr("split"))
                self.assertIsNone(root.get_attr("configForSplit"))

                app_node = root.find_child("application")
                self.assertIsNotNone(app_node)
                self.assertIsNone(app_node.get_attr("isSplitRequired"))
                lock_meta = app_node.find_child("meta-data", "name", "com.android.vending.splits.required")
                self.assertIsNone(lock_meta)

            # Verify alignment of merged APK
            align_res = verify_apk_alignment(output_apk)
            self.assertTrue(align_res["aligned"])

    def test_split_merger_compression_modes(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base_apk = os.path.join(tmp_dir, "base.apk")
            split_apk = os.path.join(tmp_dir, "split_config.arm64_v8a.apk")
            output_apk = os.path.join(tmp_dir, "merged.apk")

            base_manifest = _make_dummy_manifest()
            with zipfile.ZipFile(base_apk, "w") as zf:
                zf.writestr("AndroidManifest.xml", base_manifest)
                # Store classes.dex with ZIP_STORED in input to verify it gets forced to ZIP_DEFLATED
                zinfo_dex = zipfile.ZipInfo("classes.dex")
                zinfo_dex.compress_type = zipfile.ZIP_STORED
                zf.writestr(zinfo_dex, b"DEX_DATA_PAYLOAD" * 20)
                # Store resources.arsc with ZIP_DEFLATED in input to verify it gets forced to ZIP_STORED
                zinfo_arsc = zipfile.ZipInfo("resources.arsc")
                zinfo_arsc.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(zinfo_arsc, b"ARSC_DATA_PAYLOAD" * 20)
                # Asset with ZIP_STORED in input to verify it gets forced to ZIP_DEFLATED
                zinfo_asset = zipfile.ZipInfo("assets/config.json")
                zinfo_asset.compress_type = zipfile.ZIP_STORED
                zf.writestr(zinfo_asset, b'{"hello": "world"}')

            split_manifest = _make_dummy_manifest(split="config.arm64_v8a")
            with zipfile.ZipFile(split_apk, "w") as zf:
                zf.writestr("AndroidManifest.xml", split_manifest)
                # lib/**/*.so with ZIP_DEFLATED in input to verify it gets forced to ZIP_STORED
                zinfo_so = zipfile.ZipInfo("lib/arm64-v8a/libfoo.so")
                zinfo_so.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(zinfo_so, b"SO_CODE_BYTES" * 50)
                zinfo_sub_so = zipfile.ZipInfo("lib/arm64-v8a/sub/libnested.so")
                zinfo_sub_so.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(zinfo_sub_so, b"SO_SUB_BYTES" * 50)
                # res file with ZIP_STORED to verify it gets forced to ZIP_DEFLATED
                zinfo_res = zipfile.ZipInfo("res/raw/sample.bin")
                zinfo_res.compress_type = zipfile.ZIP_STORED
                zf.writestr(zinfo_res, b"RAW_DATA_123456")

            merge_split_apks([base_apk, split_apk], output_apk)
            self.assertTrue(os.path.exists(output_apk))

            with zipfile.ZipFile(output_apk, "r") as zout:
                # lib/**/*.so and resources.arsc must be ZIP_STORED
                self.assertEqual(zout.getinfo("lib/arm64-v8a/libfoo.so").compress_type, zipfile.ZIP_STORED)
                self.assertEqual(zout.getinfo("lib/arm64-v8a/sub/libnested.so").compress_type, zipfile.ZIP_STORED)
                self.assertEqual(zout.getinfo("resources.arsc").compress_type, zipfile.ZIP_STORED)

                # All other entries must be ZIP_DEFLATED
                self.assertEqual(zout.getinfo("AndroidManifest.xml").compress_type, zipfile.ZIP_DEFLATED)
                self.assertEqual(zout.getinfo("classes.dex").compress_type, zipfile.ZIP_DEFLATED)
                self.assertEqual(zout.getinfo("assets/config.json").compress_type, zipfile.ZIP_DEFLATED)
                self.assertEqual(zout.getinfo("res/raw/sample.bin").compress_type, zipfile.ZIP_DEFLATED)

    def test_split_merger_base_detection_from_manifest(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            # 1. Base detected from manifest without "base" in filename
            apk_main = os.path.join(tmp_dir, "custom_main_app.apk")
            apk_split = os.path.join(tmp_dir, "split_config.arm64_v8a.apk")
            out_apk = os.path.join(tmp_dir, "out_main.apk")

            with zipfile.ZipFile(apk_main, "w") as zf:
                zf.writestr("AndroidManifest.xml", _make_dummy_manifest(split=None))
                zf.writestr("classes.dex", b"MAIN_DEX_BYTES")
            with zipfile.ZipFile(apk_split, "w") as zf:
                zf.writestr("AndroidManifest.xml", _make_dummy_manifest(split="config.arm64_v8a"))
                zf.writestr("lib/arm64-v8a/libtest.so", b"NATIVE_BYTES")

            merge_split_apks([apk_main, apk_split], out_apk)
            self.assertTrue(os.path.exists(out_apk))
            with zipfile.ZipFile(out_apk, "r") as zf:
                self.assertIn("classes.dex", zf.namelist())
                self.assertEqual(zf.read("classes.dex"), b"MAIN_DEX_BYTES")
                self.assertIn("lib/arm64-v8a/libtest.so", zf.namelist())

            # 2. 0 base candidates -> ValueError
            apk_split1 = os.path.join(tmp_dir, "split_one.apk")
            apk_split2 = os.path.join(tmp_dir, "split_two.apk")
            with zipfile.ZipFile(apk_split1, "w") as zf:
                zf.writestr("AndroidManifest.xml", _make_dummy_manifest(split="split_one"))
            with zipfile.ZipFile(apk_split2, "w") as zf:
                zf.writestr("AndroidManifest.xml", _make_dummy_manifest(split="split_two"))

            with self.assertRaises(ValueError) as cm_zero:
                merge_split_apks([apk_split1, apk_split2], os.path.join(tmp_dir, "err_zero.apk"))
            self.assertIn("No base APK found in split sources (all candidates declare split attribute)", str(cm_zero.exception))

            # 3. >1 ambiguous base candidates (neither contains "base" in filename) -> ValueError
            apk_ambig1 = os.path.join(tmp_dir, "alpha_app.apk")
            apk_ambig2 = os.path.join(tmp_dir, "beta_app.apk")
            with zipfile.ZipFile(apk_ambig1, "w") as zf:
                zf.writestr("AndroidManifest.xml", _make_dummy_manifest())
            with zipfile.ZipFile(apk_ambig2, "w") as zf:
                zf.writestr("AndroidManifest.xml", _make_dummy_manifest())

            with self.assertRaises(ValueError) as cm_ambig:
                merge_split_apks([apk_ambig1, apk_ambig2], os.path.join(tmp_dir, "err_ambig.apk"))
            self.assertIn("Ambiguous split sources: multiple base APK candidates found", str(cm_ambig.exception))

            # 4. >1 ambiguous candidates resolved by tie-breaker using "base" in filename
            apk_tie_base = os.path.join(tmp_dir, "base_app.apk")
            out_tie = os.path.join(tmp_dir, "out_tie.apk")
            with zipfile.ZipFile(apk_tie_base, "w") as zf:
                zf.writestr("AndroidManifest.xml", _make_dummy_manifest())
                zf.writestr("classes.dex", b"BASE_TIE_DEX")

            merge_split_apks([apk_ambig1, apk_tie_base], out_tie)
            self.assertTrue(os.path.exists(out_tie))
            with zipfile.ZipFile(out_tie, "r") as zf:
                self.assertEqual(zf.read("classes.dex"), b"BASE_TIE_DEX")

    def test_split_merger_fails_on_split_resources_without_flag(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base_apk = os.path.join(tmp_dir, "base.apk")
            split_res = os.path.join(tmp_dir, "split_config.xxhdpi.apk")
            out_apk = os.path.join(tmp_dir, "merged_fail.apk")

            with zipfile.ZipFile(base_apk, "w") as zf:
                zf.writestr("AndroidManifest.xml", _make_dummy_manifest())
                zf.writestr("classes.dex", b"BASE_DEX")
                zf.writestr("resources.arsc", b"BASE_ARSC")

            with zipfile.ZipFile(split_res, "w") as zf:
                zf.writestr("AndroidManifest.xml", _make_dummy_manifest(split="config.xxhdpi"))
                zf.writestr("resources.arsc", b"SPLIT_ARSC")
                zf.writestr("res/drawable-xxhdpi/icon.png", b"SPLIT_ICON")

            with self.assertRaises(UnsupportedSplitMerge) as cm:
                merge_split_apks([base_apk, split_res], out_apk, allow_resource_table_loss=False)

            self.assertIn("Split APKs contain separate resources.arsc (split_config.xxhdpi.apk)", str(cm.exception))
            self.assertIn("pass allow_resource_table_loss=True to force merge.", str(cm.exception))

    def test_split_merger_warns_dex_renumber_and_duplicate_entries(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base_apk = os.path.join(tmp_dir, "base.apk")
            split_res = os.path.join(tmp_dir, "split_config.xxhdpi.apk")
            out_apk = os.path.join(tmp_dir, "merged_warn.apk")

            with zipfile.ZipFile(base_apk, "w") as zf:
                zf.writestr("AndroidManifest.xml", _make_dummy_manifest())
                zf.writestr("classes.dex", b"BASE_DEX")
                zf.writestr("resources.arsc", b"BASE_ARSC")
                zf.writestr("assets/common.json", b'{"source": "base"}')

            with zipfile.ZipFile(split_res, "w") as zf:
                zf.writestr("AndroidManifest.xml", _make_dummy_manifest(split="config.xxhdpi"))
                zf.writestr("classes.dex", b"SPLIT_DEX")
                zf.writestr("resources.arsc", b"SPLIT_ARSC")
                zf.writestr("assets/common.json", b'{"source": "split"}')
                zf.writestr("res/drawable-xxhdpi/icon.png", b"ICON_PNG")

            warnings: List[str] = []
            merge_split_apks([base_apk, split_res], out_apk, warnings=warnings, allow_resource_table_loss=True)

            self.assertTrue(os.path.exists(out_apk))

            # 1. Verify WARN_SPLIT_RESOURCE_TABLE_LOSS
            warn_res = [w for w in warnings if w.startswith("WARN_SPLIT_RESOURCE_TABLE_LOSS:")]
            self.assertEqual(len(warn_res), 1)
            self.assertIn("Resource table from splits (split_config.xxhdpi.apk) discarded", warn_res[0])
            self.assertIn("Lost qualifiers: xxhdpi", warn_res[0])

            # 2. Verify WARN_DEX_RENUMBERED
            warn_dex = [w for w in warnings if w.startswith("WARN_DEX_RENUMBERED:")]
            self.assertEqual(len(warn_dex), 1)
            self.assertIn("classes.dex->classes2.dex", warn_dex[0])

            # 3. Verify WARN_DROPPED_DUPLICATE_ENTRIES
            warn_dup = [w for w in warnings if w.startswith("WARN_DROPPED_DUPLICATE_ENTRIES:")]
            self.assertEqual(len(warn_dup), 1)
            self.assertIn("Dropped", warn_dup[0])
            self.assertIn("resources.arsc", warn_dup[0])

            with zipfile.ZipFile(out_apk, "r") as zout:
                namelist = zout.namelist()
                self.assertIn("classes.dex", namelist)
                self.assertIn("classes2.dex", namelist)
                self.assertEqual(zout.read("classes.dex"), b"BASE_DEX")
                self.assertEqual(zout.read("classes2.dex"), b"SPLIT_DEX")
                self.assertEqual(zout.read("assets/common.json"), b'{"source": "base"}')
                self.assertEqual(zout.read("resources.arsc"), b"BASE_ARSC")


if __name__ == "__main__":
    unittest.main()
