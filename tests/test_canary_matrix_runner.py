"""test_canary_matrix_runner.py - Unit & integration test suite for Canary Matrix Runner.

Covers:
1. Tier detection from DeviceProfile and mock ADB getprop.
2. Dual positive/negative verification functions for each of the 8 canaries.
3. --simulate execution across all 4 AVD tiers.
4. JSON output schema validation against scripts/generate_matrix.py.
5. CLI argument handling (--simulate, --tier, --write-results, --update-docs).
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from apkrevive.core.models import DeviceProfile
from apkrevive.adb.bridge import AdbBridge
from scripts.generate_matrix import validate_result_schema, SCHEMA_FIELD_TYPES

from scripts.verify_canary_matrix import (
    TIERS,
    tier_from_device_profile,
    detect_device_tier,
    run_tier_verification,
    build_receipt_dict,
    verify_canary_install_floor,
    verify_canary_apache_http,
    verify_canary_page_size,
    verify_canary_physics_tick,
    verify_canary_aspect_ratio,
    verify_canary_bionic_greylist,
    verify_canary_has_code,
    verify_canary_obb_version,
    parse_args,
    main,
    CANARIES_BUILD,
)


class TestCanaryMatrixRunner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        hashes_file = Path(__file__).resolve().parent.parent / "canaries" / "canary_hashes.json"
        apks = list(CANARIES_BUILD.glob("*.apk")) if CANARIES_BUILD.exists() else []
        if len(apks) < 16 or not hashes_file.exists():
            from canaries.build_canaries import build_all
            build_all()

    # 1. Tier Detection and Mapping
    def test_tier_from_device_profile(self):
        dev19 = DeviceProfile(os_api_level=19)
        dev28 = DeviceProfile(os_api_level=28)
        dev34 = DeviceProfile(os_api_level=34)
        dev35 = DeviceProfile(os_api_level=35)
        dev36 = DeviceProfile(os_api_level=36)

        self.assertEqual(tier_from_device_profile(dev19), "19")
        self.assertEqual(tier_from_device_profile(dev28), "28")
        self.assertEqual(tier_from_device_profile(dev34), "34")
        self.assertEqual(tier_from_device_profile(dev35), "35")
        self.assertEqual(tier_from_device_profile(dev36), "35")

    def test_detect_device_tier_mock_adb(self):
        bridge = AdbBridge()

        # Mock API 19 x86
        def mock_getprop_19(prop):
            mapping = {
                "ro.build.version.sdk": "19",
                "ro.build.version.min_supported_target_sdk": "1",
                "ro.product.cpu.abilist": "x86",
                "ro.boot.page_size": "4096",
                "ro.product.model": "KitKat AVD",
                "ro.build.display.id": "KK-01",
            }
            return mapping.get(prop, "")

        with patch.object(bridge, "get_prop", side_effect=mock_getprop_19):
            tier_id, prof, props = detect_device_tier(bridge)
            self.assertEqual(tier_id, "19")
            self.assertEqual(prof.os_api_level, 19)
            self.assertEqual(prof.install_floor, 1)
            self.assertEqual(prof.page_size_bytes, 4096)
            self.assertEqual(props["model"], "KitKat AVD")

        # Mock API 35 16KB ps16k
        def mock_getprop_35(prop):
            mapping = {
                "ro.build.version.sdk": "35",
                "ro.build.version.min_supported_target_sdk": "24",
                "ro.product.cpu.abilist": "x86_64,arm64-v8a",
                "ro.boot.page_size": "16384",
                "ro.product.model": "sdk_gphone64_ps16k_x86_64",
                "ro.build.display.id": "VanillaIceCream",
            }
            return mapping.get(prop, "")

        with patch.object(bridge, "get_prop", side_effect=mock_getprop_35):
            tier_id, prof, props = detect_device_tier(bridge)
            self.assertEqual(tier_id, "35")
            self.assertEqual(prof.os_api_level, 35)
            self.assertEqual(prof.install_floor, 24)
            self.assertEqual(prof.page_size_bytes, 16384)

    # 2. Dual Positive/Negative Assertions for All 8 Canaries
    def test_dual_assertions_install_floor(self):
        tier34 = TIERS["34"]
        res = verify_canary_install_floor(CANARIES_BUILD, tier34.profile)
        self.assertEqual(res.canary_id, "canary_install_floor")
        self.assertTrue(res.control_passed)
        self.assertTrue(res.revived_passed)
        self.assertEqual(res.pass_fail, "PASS")

    def test_dual_assertions_apache_http(self):
        tier28 = TIERS["28"]
        res = verify_canary_apache_http(CANARIES_BUILD, tier28.profile)
        self.assertEqual(res.canary_id, "canary_apache_http")
        self.assertTrue(res.control_passed)
        self.assertTrue(res.revived_passed)
        self.assertEqual(res.pass_fail, "PASS")

    def test_dual_assertions_page_size(self):
        tier35 = TIERS["35"]
        res = verify_canary_page_size(CANARIES_BUILD, tier35.profile)
        self.assertEqual(res.canary_id, "canary_page_size")
        self.assertTrue(res.control_passed)
        self.assertTrue(res.revived_passed)
        self.assertEqual(res.pass_fail, "PASS")

    def test_dual_assertions_physics_tick(self):
        tier35 = TIERS["35"]
        res = verify_canary_physics_tick(CANARIES_BUILD, tier35.profile)
        self.assertEqual(res.canary_id, "canary_physics_tick")
        self.assertTrue(res.control_passed)
        self.assertTrue(res.revived_passed)
        self.assertEqual(res.pass_fail, "PASS")

    def test_dual_assertions_aspect_ratio(self):
        tier35 = TIERS["35"]
        res = verify_canary_aspect_ratio(CANARIES_BUILD, tier35.profile)
        self.assertEqual(res.canary_id, "canary_aspect_ratio")
        self.assertTrue(res.control_passed)
        self.assertTrue(res.revived_passed)
        self.assertEqual(res.pass_fail, "PASS")

    def test_dual_assertions_bionic_greylist(self):
        tier35 = TIERS["35"]
        res = verify_canary_bionic_greylist(CANARIES_BUILD, tier35.profile)
        self.assertEqual(res.canary_id, "canary_bionic_greylist")
        self.assertTrue(res.control_passed)
        self.assertTrue(res.revived_passed)
        self.assertEqual(res.pass_fail, "PASS")

    def test_dual_assertions_has_code(self):
        tier19 = TIERS["19"]
        res = verify_canary_has_code(CANARIES_BUILD, tier19.profile)
        self.assertEqual(res.canary_id, "canary_has_code")
        self.assertTrue(res.control_passed)
        self.assertTrue(res.revived_passed)
        self.assertEqual(res.pass_fail, "PASS")

    def test_dual_assertions_obb_version(self):
        tier28 = TIERS["28"]
        res = verify_canary_obb_version(CANARIES_BUILD, tier28.profile)
        self.assertEqual(res.canary_id, "canary_obb_version")
        self.assertTrue(res.control_passed)
        self.assertTrue(res.revived_passed)
        self.assertEqual(res.pass_fail, "PASS")

    # 3. Simulate Execution Across All 4 Tiers
    def test_simulate_all_tiers(self):
        for tier_id in ["19", "28", "34", "35"]:
            with self.subTest(tier=tier_id):
                tier = TIERS[tier_id]
                records = run_tier_verification(tier, CANARIES_BUILD)
                self.assertEqual(len(records), 8)
                for r in records:
                    self.assertTrue(r.control_passed, f"Control failed for {r.canary_id} on Tier {tier_id}")
                    self.assertTrue(r.revived_passed, f"Revived failed for {r.canary_id} on Tier {tier_id}")
                    self.assertEqual(r.pass_fail, "PASS")

    # 4. JSON Output Schema Validation
    def test_receipt_schema_conformance(self):
        tier = TIERS["35"]
        records = run_tier_verification(tier, CANARIES_BUILD)
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        for r in records:
            receipt = build_receipt_dict(
                record=r,
                tier=tier,
                device_model="Local Verification Rig",
                emulator_or_hardware="local_host",
                android_build="Host Python Harness",
                git_commit="20778b3",
                date_str=date_str,
                simulated=True,
            )
            validate_result_schema(receipt, f"test_{r.canary_id}.json")
            for field, expected_type in SCHEMA_FIELD_TYPES.items():
                self.assertIn(field, receipt)
                self.assertIsInstance(receipt[field], expected_type)
            self.assertIn(receipt["emulator_or_hardware"], {"emulator", "hardware", "local_host"})
            self.assertIn(receipt["pass_fail"], {"PASS", "FAIL"})

    # 5. CLI Argument Handling & End-to-End
    def test_cli_parsing(self):
        args_sim = parse_args(["--simulate", "--tier", "35", "--write-results"])
        self.assertTrue(args_sim.simulate)
        self.assertEqual(args_sim.tier, "35")
        self.assertTrue(args_sim.write_results)

        args_dev = parse_args(["--device", "emulator-5554", "--tier", "all"])
        self.assertEqual(args_dev.device, "emulator-5554")
        self.assertEqual(args_dev.tier, "all")

    def test_main_simulate_with_write_results(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            code = main(["--simulate", "--tier", "34", "--write-results", "--results-dir", str(tmp_path)])
            self.assertEqual(code, 0)

            json_files = list(tmp_path.glob("*.json"))
            self.assertEqual(len(json_files), 8)
            for f in json_files:
                with open(f, "r", encoding="utf-8") as jf:
                    data = json.load(jf)
                validate_result_schema(data, f)
                self.assertEqual(data["pass_fail"], "PASS")

    def test_main_single_canary_filter(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            code = main([
                "--simulate",
                "--tier", "35",
                "--canary", "canary_page_size",
                "--write-results",
                "--results-dir", str(tmp_path)
            ])
            self.assertEqual(code, 0)
            json_files = list(tmp_path.glob("*.json"))
            self.assertEqual(len(json_files), 1)
            self.assertIn("canary_page_size", json_files[0].name)


if __name__ == "__main__":
    unittest.main()
