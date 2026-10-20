"""
test_behavior_changes.py - Unit test suite for Android Platform Behavior Table (Item 1).
Verifies positive trigger and negative non-trigger conditions across (targetSdk, deviceApi)
for every row in BEHAVIOR_CHANGES.
"""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from apkrevive.core.models import ApkMetadata, DeviceProfile
from apkrevive.core.behavior_changes import (
    BEHAVIOR_CHANGES,
    PlatformBehaviorChange,
    get_applicable_behavior_changes,
    is_page_size_compat_verified,
)


class TestBehaviorChangesTable(unittest.TestCase):

    def setUp(self):
        self.change_map = {c.id: c for c in BEHAVIOR_CHANGES}

    def test_table_structure_and_dataclass(self):
        """Verifies that all 9 required platform behavior changes are defined with full metadata."""
        expected_ids = [
            "CLEARTEXT_HTTP_DEFAULT_BLOCK",
            "APACHE_HTTP_LEGACY_REMOVAL",
            "SCOPED_STORAGE_ENFORCEMENT",
            "RAW_OBB_DATA_PATH_RESTRICTION",
            "16KB_PAGE_SIZE_KERNEL",
            "TARGET_SDK_INSTALL_FLOOR_API34",
            "TARGET_SDK_INSTALL_FLOOR_API35",
            "BIONIC_NAMESPACE_ISOLATION",
            "HIDDEN_API_REFLECTION_RESTRICTION",
        ]
        self.assertEqual(len(BEHAVIOR_CHANGES), 9)
        for change_id in expected_ids:
            self.assertIn(change_id, self.change_map)
            item = self.change_map[change_id]
            self.assertIsInstance(item, PlatformBehaviorChange)
            self.assertTrue(len(item.title) > 0)
            self.assertTrue(len(item.doc_url) > 0)
            self.assertTrue(item.doc_url.startswith("https://developer.android.com/"))
            self.assertIn(item.rule_type, ("TRANSFORM", "WARNING", "BLOCK", "INFO"))
            self.assertIn(item.risk_level, ("LOW", "MEDIUM", "HIGH"))
            self.assertTrue(len(item.description) > 0)
            self.assertTrue(callable(item.condition))

            d = item.to_dict()
            self.assertEqual(d["id"], item.id)
            self.assertEqual(d["rule_type"], item.rule_type)

    def test_01_cleartext_http_default_block(self):
        """Row 1: CLEARTEXT_HTTP_DEFAULT_BLOCK (min_target_sdk=28, min_device_api=28)."""
        rule_id = "CLEARTEXT_HTTP_DEFAULT_BLOCK"
        self.assertEqual(self.change_map[rule_id].action_or_signal, "WARN_CLEARTEXT")

        # Positive: targetSdk 28 on API 28, cleartext not enabled (uses_cleartext_traffic=None)
        apk_pos = ApkMetadata(target_sdk=28, uses_cleartext_traffic=None)
        dev_pos = DeviceProfile(os_api_level=28)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos, dev_pos)]
        self.assertIn(rule_id, applicable)
        self.assertTrue(self.change_map[rule_id].condition(apk_pos, dev_pos))

        # Positive: targetSdk 30 on API 34, uses_cleartext_traffic=False
        apk_pos2 = ApkMetadata(target_sdk=30, uses_cleartext_traffic=False)
        dev_pos2 = DeviceProfile(os_api_level=34)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos2, dev_pos2)]
        self.assertIn(rule_id, applicable)

        # Negative: targetSdk 27 on API 28 (targetSdk < 28 should not trigger default block)
        apk_neg_target = ApkMetadata(target_sdk=27, uses_cleartext_traffic=None)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_neg_target, dev_pos)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_neg_target, dev_pos))

        # Negative: targetSdk 28 on API 27 (device API < 28)
        dev_neg_api = DeviceProfile(os_api_level=27)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos, dev_neg_api)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_pos, dev_neg_api))

        # Negative: targetSdk 28 on API 28, cleartext IS enabled (uses_cleartext_traffic=True)
        apk_neg_enabled = ApkMetadata(target_sdk=28, uses_cleartext_traffic=True)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_neg_enabled, dev_pos)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_neg_enabled, dev_pos))

        # Negative: targetSdk 28 on API 28 with network_security_config declared
        apk_neg_nsc = ApkMetadata(target_sdk=28, uses_cleartext_traffic=None, has_network_security_config=True)
        applicable_nsc = [c.id for c in get_applicable_behavior_changes(apk_neg_nsc, dev_pos)]
        self.assertNotIn(rule_id, applicable_nsc)
        self.assertFalse(self.change_map[rule_id].condition(apk_neg_nsc, dev_pos))

    def test_02_apache_http_legacy_removal(self):
        """Row 2: APACHE_HTTP_LEGACY_REMOVAL (min_target_sdk=28, min_device_api=28)."""
        rule_id = "APACHE_HTTP_LEGACY_REMOVAL"

        # Positive: targetSdk 28 on API 28 with uses_apache_http=True
        apk_pos = ApkMetadata(target_sdk=28, uses_apache_http=True)
        dev_pos = DeviceProfile(os_api_level=28)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos, dev_pos)]
        self.assertIn(rule_id, applicable)
        self.assertTrue(self.change_map[rule_id].condition(apk_pos, dev_pos))

        # Negative: targetSdk 27 on API 28 with uses_apache_http=True (platform auto-injects on targetSdk <= 27)
        apk_neg_target = ApkMetadata(target_sdk=27, uses_apache_http=True)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_neg_target, dev_pos)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_neg_target, dev_pos))

        # Negative: targetSdk 28 on API 27 with uses_apache_http=True (bootclasspath intact on API < 28)
        dev_neg_api = DeviceProfile(os_api_level=27)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos, dev_neg_api)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_pos, dev_neg_api))

        # Negative: targetSdk 28 on API 28 without uses_apache_http
        apk_neg_no_apache = ApkMetadata(target_sdk=28, uses_apache_http=False)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_neg_no_apache, dev_pos)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_neg_no_apache, dev_pos))

    def test_03_scoped_storage_enforcement(self):
        """Row 3: SCOPED_STORAGE_ENFORCEMENT (min_target_sdk=30, min_device_api=30)."""
        rule_id = "SCOPED_STORAGE_ENFORCEMENT"

        # Positive: targetSdk 30 on API 30 requesting WRITE_EXTERNAL_STORAGE
        apk_pos = ApkMetadata(target_sdk=30, permissions=["android.permission.WRITE_EXTERNAL_STORAGE"])
        dev_pos = DeviceProfile(os_api_level=30)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos, dev_pos)]
        self.assertIn(rule_id, applicable)
        self.assertTrue(self.change_map[rule_id].condition(apk_pos, dev_pos))

        # Negative: targetSdk 29 on API 30 with storage perms (legacy storage compat mode)
        apk_neg_target = ApkMetadata(target_sdk=29, permissions=["android.permission.WRITE_EXTERNAL_STORAGE"])
        applicable = [c.id for c in get_applicable_behavior_changes(apk_neg_target, dev_pos)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_neg_target, dev_pos))

        # Negative: targetSdk 30 on API 29
        dev_neg_api = DeviceProfile(os_api_level=29)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos, dev_neg_api)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_pos, dev_neg_api))

        # Negative: targetSdk 30 on API 30 without storage permissions
        apk_neg_no_perm = ApkMetadata(target_sdk=30, permissions=["android.permission.INTERNET"])
        applicable = [c.id for c in get_applicable_behavior_changes(apk_neg_no_perm, dev_pos)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_neg_no_perm, dev_pos))

    def test_04_raw_obb_data_path_restriction(self):
        """Row 4: RAW_OBB_DATA_PATH_RESTRICTION (min_target_sdk=None, min_device_api=30)."""
        rule_id = "RAW_OBB_DATA_PATH_RESTRICTION"

        # Positive A: accesses_scoped_storage_paths on API 30 regardless of targetSdk (even targetSdk 22)
        apk_pos_paths = ApkMetadata(target_sdk=22, accesses_scoped_storage_paths=True)
        dev_pos = DeviceProfile(os_api_level=30)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos_paths, dev_pos)]
        self.assertIn(rule_id, applicable)
        self.assertTrue(self.change_map[rule_id].condition(apk_pos_paths, dev_pos))

        # Positive B: has_obb on API 30 regardless of targetSdk
        apk_pos_obb = ApkMetadata(target_sdk=22, has_obb=True)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos_obb, dev_pos)]
        self.assertIn(rule_id, applicable)
        self.assertTrue(self.change_map[rule_id].condition(apk_pos_obb, dev_pos))

        # Negative: device API < 30 (raw paths allowed on API 29)
        dev_neg_api = DeviceProfile(os_api_level=29)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos_paths, dev_neg_api)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_pos_paths, dev_neg_api))

        # Negative: Neither raw paths nor OBB
        apk_neg_clean = ApkMetadata(target_sdk=22, accesses_scoped_storage_paths=False, has_obb=False)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_neg_clean, dev_pos)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_neg_clean, dev_pos))

    def test_05_16kb_page_size_kernel(self):
        """Row 5: 16KB_PAGE_SIZE_KERNEL (min_target_sdk=None, min_device_api=35)."""
        rule_id = "16KB_PAGE_SIZE_KERNEL"

        # Positive: 64-bit native lib with elf_load_align_64bit < 16384 on 16KB kernel (API 35)
        apk_pos = ApkMetadata(abis=["arm64-v8a"], elf_load_align_64bit=4096)
        dev_pos = DeviceProfile(os_api_level=35, page_size_bytes=16384)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos, dev_pos)]
        self.assertIn(rule_id, applicable)
        self.assertTrue(self.change_map[rule_id].condition(apk_pos, dev_pos))

        # Positive: 64-bit native lib with invalid ELF layout
        apk_pos_layout = ApkMetadata(abis=["arm64-v8a"], elf_load_align_64bit=16384, has_invalid_elf_layout=True)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos_layout, dev_pos)]
        self.assertIn(rule_id, applicable)

        # Negative: 4KB kernel (page_size_bytes == 4096)
        dev_neg_pagesize = DeviceProfile(os_api_level=35, page_size_bytes=4096)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos, dev_neg_pagesize)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_pos, dev_neg_pagesize))

        # Negative: device API < 35 (API 34)
        dev_neg_api = DeviceProfile(os_api_level=34, page_size_bytes=16384)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos, dev_neg_api)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_pos, dev_neg_api))

        # Negative: 32-bit only APK (not 64-bit)
        apk_neg_32bit = ApkMetadata(abis=["armeabi-v7a"], elf_load_align_64bit=4096)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_neg_32bit, dev_pos)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_neg_32bit, dev_pos))

        # Negative: Properly aligned 16KB ELF with valid layout
        apk_neg_aligned = ApkMetadata(abis=["arm64-v8a"], elf_load_align_64bit=16384, has_invalid_elf_layout=False)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_neg_aligned, dev_pos)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_neg_aligned, dev_pos))

    def test_06_target_sdk_install_floor_api34(self):
        """Row 6: TARGET_SDK_INSTALL_FLOOR_API34 (min_target_sdk=None, min_device_api=34, max_device_api=34)."""
        rule_id = "TARGET_SDK_INSTALL_FLOOR_API34"

        # Positive: targetSdk 22 on API 34
        apk_pos = ApkMetadata(target_sdk=22)
        dev_pos = DeviceProfile(os_api_level=34)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos, dev_pos)]
        self.assertIn(rule_id, applicable)
        self.assertTrue(self.change_map[rule_id].condition(apk_pos, dev_pos))

        # Negative: targetSdk 23 on API 34 (API 34 floor is 23; 23 installs directly)
        apk_neg_target = ApkMetadata(target_sdk=23)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_neg_target, dev_pos)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_neg_target, dev_pos))

        # Negative: device API != 34 (e.g. API 33 or API 35)
        dev_neg_33 = DeviceProfile(os_api_level=33)
        dev_neg_35 = DeviceProfile(os_api_level=35)
        self.assertNotIn(rule_id, [c.id for c in get_applicable_behavior_changes(apk_pos, dev_neg_33)])
        self.assertNotIn(rule_id, [c.id for c in get_applicable_behavior_changes(apk_pos, dev_neg_35)])
        self.assertFalse(self.change_map[rule_id].condition(apk_pos, dev_neg_35))

    def test_07_target_sdk_install_floor_api35(self):
        """Row 7: TARGET_SDK_INSTALL_FLOOR_API35 (min_target_sdk=None, min_device_api=35)."""
        rule_id = "TARGET_SDK_INSTALL_FLOOR_API35"

        # Positive: targetSdk 23 on API 35 (API 35 floor is 24; 23 requires bypass)
        apk_pos = ApkMetadata(target_sdk=23)
        dev_pos = DeviceProfile(os_api_level=35)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos, dev_pos)]
        self.assertIn(rule_id, applicable)
        self.assertTrue(self.change_map[rule_id].condition(apk_pos, dev_pos))

        # Negative: targetSdk 24 on API 35 (floor is 24; 24 installs directly)
        apk_neg_target = ApkMetadata(target_sdk=24)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_neg_target, dev_pos)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_neg_target, dev_pos))

        # Negative: device API < 35 (API 34)
        dev_neg_api = DeviceProfile(os_api_level=34)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos, dev_neg_api)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_pos, dev_neg_api))

    def test_08_bionic_namespace_isolation(self):
        """Row 8: BIONIC_NAMESPACE_ISOLATION (min_target_sdk=24, min_device_api=24)."""
        rule_id = "BIONIC_NAMESPACE_ISOLATION"

        # Positive: targetSdk 24 on API 24 linking private platform library (e.g. libcrypto.so)
        apk_pos = ApkMetadata(target_sdk=24, private_libs=["libcrypto.so"])
        dev_pos = DeviceProfile(os_api_level=24)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos, dev_pos)]
        self.assertIn(rule_id, applicable)
        self.assertTrue(self.change_map[rule_id].condition(apk_pos, dev_pos))

        # Negative: targetSdk 23 on API 24 (bionic namespace isolation does not block greylist on targetSdk < 24)
        apk_neg_target = ApkMetadata(target_sdk=23, private_libs=["libcrypto.so"])
        applicable = [c.id for c in get_applicable_behavior_changes(apk_neg_target, dev_pos)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_neg_target, dev_pos))

        # Negative: targetSdk 24 on API 23 (device API < 24)
        dev_neg_api = DeviceProfile(os_api_level=23)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos, dev_neg_api)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_pos, dev_neg_api))

        # Negative: targetSdk 24 on API 24 linking only public NDK libraries
        apk_neg_public = ApkMetadata(target_sdk=24, private_libs=["libc.so", "liblog.so"])
        applicable = [c.id for c in get_applicable_behavior_changes(apk_neg_public, dev_pos)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_neg_public, dev_pos))

    def test_09_hidden_api_reflection_restriction(self):
        """Row 9: HIDDEN_API_REFLECTION_RESTRICTION (min_target_sdk=None, min_device_api=28)."""
        rule_id = "HIDDEN_API_REFLECTION_RESTRICTION"

        # Positive: hidden API reflections detected on API 28+
        apk_pos = ApkMetadata(target_sdk=22, hidden_api_reflections=["android.os.SystemProperties"])
        dev_pos = DeviceProfile(os_api_level=28)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos, dev_pos)]
        self.assertIn(rule_id, applicable)
        self.assertTrue(self.change_map[rule_id].condition(apk_pos, dev_pos))

        # Negative: device API < 28 (hidden API policy was introduced in API 28)
        dev_neg_api = DeviceProfile(os_api_level=27)
        applicable = [c.id for c in get_applicable_behavior_changes(apk_pos, dev_neg_api)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_pos, dev_neg_api))

        # Negative: no hidden API reflections detected
        apk_neg_clean = ApkMetadata(target_sdk=28, hidden_api_reflections=[])
        applicable = [c.id for c in get_applicable_behavior_changes(apk_neg_clean, dev_pos)]
        self.assertNotIn(rule_id, applicable)
        self.assertFalse(self.change_map[rule_id].condition(apk_neg_clean, dev_pos))


class TestPageSizeCompatVerification(unittest.TestCase):
    def test_default_repo_results_unverified_without_target_api(self):
        """is_page_size_compat_verified() returns False when target_api is None."""
        self.assertFalse(is_page_size_compat_verified())

    def test_repo_receipts_verified(self):
        """Verifies that repo receipts/ directory verifies API 37 and API 35 for x86_64."""
        self.assertTrue(is_page_size_compat_verified(target_api=37, target_abi="x86_64"))
        self.assertTrue(is_page_size_compat_verified(target_api=35, target_abi="x86_64"))
        self.assertFalse(is_page_size_compat_verified(target_api=36, target_abi="x86_64"))
        self.assertFalse(is_page_size_compat_verified(target_api=37, target_abi="arm64-v8a"))

    def test_receipt_present(self):
        """Present: matching api, abi, 16384 page_size, simulated=False returns True."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            receipt = {
                "device_model": "test_device",
                "api_level": 37,
                "abi": "x86_64",
                "page_size": 16384,
                "date": "2026-10-18",
                "script": "scripts/test.py",
                "simulated": False,
            }
            Path(tmp_dir, "receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
            self.assertTrue(is_page_size_compat_verified(tmp_dir, target_api=37, target_abi="x86_64"))
            self.assertTrue(is_page_size_compat_verified(Path(tmp_dir), target_api=37, target_abi="x86_64"))

    def test_receipt_absent(self):
        """Absent: requested api or abi not found returns False."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            receipt = {
                "device_model": "test_device",
                "api_level": 35,
                "abi": "x86_64",
                "page_size": 16384,
                "date": "2026-10-18",
                "script": "scripts/test.py",
                "simulated": False,
            }
            Path(tmp_dir, "receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
            self.assertFalse(is_page_size_compat_verified(tmp_dir, target_api=36, target_abi="x86_64"))
            self.assertFalse(is_page_size_compat_verified(tmp_dir, target_api=None))

    def test_receipt_simulated_ignored(self):
        """Simulated: receipt matching api/abi but simulated=True returns False."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            receipt = {
                "device_model": "test_device",
                "api_level": 37,
                "abi": "x86_64",
                "page_size": 16384,
                "date": "2026-10-18",
                "script": "scripts/test.py",
                "simulated": True,
            }
            Path(tmp_dir, "simulated.json").write_text(json.dumps(receipt), encoding="utf-8")
            self.assertFalse(is_page_size_compat_verified(tmp_dir, target_api=37, target_abi="x86_64"))

    def test_receipt_wrong_abi(self):
        """Wrong ABI: receipt with matching api but different abi returns False."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            receipt = {
                "device_model": "test_device",
                "api_level": 37,
                "abi": "arm64-v8a",
                "page_size": 16384,
                "date": "2026-10-18",
                "script": "scripts/test.py",
                "simulated": False,
            }
            Path(tmp_dir, "arm64.json").write_text(json.dumps(receipt), encoding="utf-8")
            self.assertFalse(is_page_size_compat_verified(tmp_dir, target_api=37, target_abi="x86_64"))
            self.assertTrue(is_page_size_compat_verified(tmp_dir, target_api=37, target_abi="arm64-v8a"))

    def test_receipt_non_16k_or_fail(self):
        """4KB page size or fail status does not verify."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            receipt_4k = {
                "device_model": "test_device",
                "api_level": 37,
                "abi": "x86_64",
                "page_size": 4096,
                "simulated": False,
            }
            receipt_fail = {
                "device_model": "test_device",
                "api_level": 37,
                "abi": "x86_64",
                "page_size": 16384,
                "pass_fail": "FAIL",
                "simulated": False,
            }
            Path(tmp_dir, "4k.json").write_text(json.dumps(receipt_4k), encoding="utf-8")
            Path(tmp_dir, "fail.json").write_text(json.dumps(receipt_fail), encoding="utf-8")
            self.assertFalse(is_page_size_compat_verified(tmp_dir, target_api=37, target_abi="x86_64"))

    def test_nonexistent_or_empty_or_corrupt_dir(self):
        """Non-existent dir, empty dir, or malformed JSON returns False."""
        self.assertFalse(is_page_size_compat_verified("nonexistent_dir_9999", target_api=37))
        with tempfile.TemporaryDirectory() as tmp_dir:
            self.assertFalse(is_page_size_compat_verified(tmp_dir, target_api=37))
            corrupt = Path(tmp_dir, "bad.json")
            corrupt.write_text("{corrupt json content", encoding="utf-8")
            self.assertFalse(is_page_size_compat_verified(tmp_dir, target_api=37))

    def test_list_input_and_type_coercion_edge_cases(self):
        """Test list of entries in JSON, invalid kernel_page_size type, and API level keys."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            f_list = os.path.join(tmp_dir, "multi.json")
            with open(f_list, "w", encoding="utf-8") as f:
                json.dump([
                    "string_not_dict",
                    {"pass_fail": "PASS", "kernel_page_size": "not_an_int"},
                    {"pass_fail": "PASS", "kernel_page_size": 16384, "os_api_level": "not_an_int", "android_build": "no_match"},
                    {"pass_fail": "PASS", "kernel_page_size": 16384, "os_api_level": 37, "abi": "x86_64", "simulated": False},
                ], f)
            self.assertTrue(is_page_size_compat_verified(tmp_dir, target_api=37, target_abi="x86_64"))

    def test_default_cwd_fallback(self):
        """Test cwd fallback when repo_receipts does not exist."""
        with mock.patch("pathlib.Path.is_dir") as mock_is_dir:
            mock_is_dir.return_value = False
            self.assertFalse(is_page_size_compat_verified(None, target_api=37))

    def test_public_system_libraries_parity(self):
        """Asserts that Python, Kotlin, and Web Hub copies of PUBLIC_SYSTEM_LIBRARIES match exactly."""
        import re
        from apkrevive.core.behavior_changes import PUBLIC_SYSTEM_LIBRARIES as PY_BEHAVIOR
        from apkrevive.core.extractor import PUBLIC_SYSTEM_LIBRARIES as PY_EXTRACTOR

        self.assertEqual(PY_BEHAVIOR, PY_EXTRACTOR)

        # Parse Kotlin set
        repo_root = Path(__file__).resolve().parent.parent
        kt_path = repo_root / "apkrevive-android" / "app" / "src" / "main" / "java" / "com" / "apkrevive" / "core" / "TriageEvaluator.kt"
        kt_content = kt_path.read_text(encoding="utf-8")
        kt_match = re.search(r"val PUBLIC_SYSTEM_LIBRARIES\s*=\s*setOf\((.*?)\)", kt_content, re.DOTALL)
        self.assertIsNotNone(kt_match, "Could not find PUBLIC_SYSTEM_LIBRARIES in TriageEvaluator.kt")
        kt_libs = set(re.findall(r'"([^"]+)"', kt_match.group(1)))
        self.assertEqual(PY_BEHAVIOR, kt_libs, f"Kotlin libraries differ from Python: {PY_BEHAVIOR ^ kt_libs}")

        # Parse JS set
        js_path = repo_root / "web" / "app.js"
        js_content = js_path.read_text(encoding="utf-8")
        js_match = re.search(r"const PUBLIC_SYSTEM_LIBRARIES\s*=\s*new Set\(\[(.*?)\]\);", js_content, re.DOTALL)
        self.assertIsNotNone(js_match, "Could not find PUBLIC_SYSTEM_LIBRARIES in web/app.js")
        js_libs = set(re.findall(r'"([^"]+)"', js_match.group(1)))
        self.assertEqual(PY_BEHAVIOR, js_libs, f"Web JS libraries differ from Python: {PY_BEHAVIOR ^ js_libs}")


if __name__ == "__main__":
    unittest.main()

