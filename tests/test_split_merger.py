"""
test_split_merger.py - Tests Split APK Merger and split-lock stripping.
"""

import os
import tempfile
import unittest
import zipfile

from apkrevive.core.axml import AxmlSurgeon, AxmlNode
from apkrevive.core.split_merger import merge_split_apks
from apkrevive.core.align import verify_apk_alignment


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


if __name__ == "__main__":
    unittest.main()
