"""test_golden_triage.py - Exact golden-file assertion test suite for ApkRevive triage evaluation."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from typing import Any, Dict

from apkrevive.core.models import ApkMetadata, DeviceProfile
from apkrevive.core.triage import evaluate_triage

GOLDENS_DIR = Path(__file__).resolve().parent / "goldens" / "triage"

GOLDEN_SCENARIOS: Dict[str, Dict[str, Any]] = {
    "scenario_01_clean_app": {
        "apk": ApkMetadata(
            package_name="com.example.cleanapp",
            target_sdk=28,
            min_sdk=21,
            version_code=100,
            abis=[],
            size_bytes=5000000,
            uses_cleartext_traffic=True,
        ),
        "device": DeviceProfile(
            os_api_level=35,
            install_floor=24,
            supported_abis=["arm64-v8a"],
            page_size_bytes=16384,
            is_widescreen=True,
            is_high_refresh=False,
        ),
    },
    "scenario_02_install_floor_blocked": {
        "apk": ApkMetadata(
            package_name="com.example.legacyapp",
            target_sdk=22,
            min_sdk=15,
            version_code=10,
            abis=[],
            size_bytes=5000000,
            uses_cleartext_traffic=True,
        ),
        "device": DeviceProfile(
            os_api_level=35,
            install_floor=24,
            supported_abis=["arm64-v8a"],
            page_size_bytes=16384,
            is_widescreen=True,
            is_high_refresh=False,
        ),
    },
    "scenario_03_page_size_16kb_incompatible_api35": {
        "apk": ApkMetadata(
            package_name="com.example.native4k",
            target_sdk=28,
            min_sdk=21,
            version_code=1,
            abis=["arm64-v8a"],
            elf_load_align_64bit=4096,
            size_bytes=25000000,
            uses_cleartext_traffic=True,
        ),
        "device": DeviceProfile(
            os_api_level=35,
            install_floor=24,
            supported_abis=["arm64-v8a"],
            page_size_bytes=16384,
            is_widescreen=True,
            is_high_refresh=False,
        ),
    },
    "scenario_04_page_size_16kb_android16_compat": {
        "apk": ApkMetadata(
            package_name="com.example.nativecompat",
            target_sdk=28,
            min_sdk=21,
            version_code=1,
            abis=["arm64-v8a"],
            elf_load_align_64bit=4096,
            size_bytes=25000000,
            uses_cleartext_traffic=True,
        ),
        "device": DeviceProfile(
            os_api_level=36,
            install_floor=24,
            supported_abis=["arm64-v8a"],
            page_size_bytes=16384,
            is_widescreen=True,
            is_high_refresh=False,
        ),
    },
    "scenario_05_gles1_deprecated": {
        "apk": ApkMetadata(
            package_name="com.example.gles1app",
            target_sdk=28,
            min_sdk=16,
            version_code=1,
            abis=[],
            size_bytes=8000000,
            uses_gles1=True,
            uses_cleartext_traffic=True,
        ),
        "device": DeviceProfile(
            os_api_level=35,
            install_floor=24,
            supported_abis=["arm64-v8a"],
            page_size_bytes=16384,
            is_widescreen=True,
            is_high_refresh=False,
        ),
    },
    "scenario_06_dead_sdks": {
        "apk": ApkMetadata(
            package_name="com.example.deadsdkapp",
            target_sdk=28,
            min_sdk=16,
            version_code=1,
            abis=[],
            size_bytes=8000000,
            dead_sdks=["com.google.android.maps", "com.android.vending.licensing.ILicensingService"],
            uses_cleartext_traffic=True,
        ),
        "device": DeviceProfile(
            os_api_level=35,
            install_floor=24,
            supported_abis=["arm64-v8a"],
            page_size_bytes=16384,
            is_widescreen=True,
            is_high_refresh=False,
        ),
    },
    "scenario_07_textrel": {
        "apk": ApkMetadata(
            package_name="com.example.textrelapp",
            target_sdk=28,
            min_sdk=16,
            version_code=1,
            abis=["arm64-v8a"],
            elf_load_align_64bit=16384,
            has_textrel=True,
            textrel_libs=["liblegacy_engine.so"],
            size_bytes=10000000,
            uses_cleartext_traffic=True,
        ),
        "device": DeviceProfile(
            os_api_level=35,
            install_floor=24,
            supported_abis=["arm64-v8a"],
            page_size_bytes=16384,
            is_widescreen=True,
            is_high_refresh=False,
        ),
    },
    "scenario_08_cleartext_http": {
        "apk": ApkMetadata(
            package_name="com.example.cleartextapp",
            target_sdk=28,
            min_sdk=21,
            version_code=1,
            abis=[],
            size_bytes=5000000,
            uses_cleartext_traffic=False,
        ),
        "device": DeviceProfile(
            os_api_level=35,
            install_floor=24,
            supported_abis=["arm64-v8a"],
            page_size_bytes=16384,
            is_widescreen=True,
            is_high_refresh=False,
        ),
    },
    "scenario_09_scoped_storage": {
        "apk": ApkMetadata(
            package_name="com.example.storageapp",
            target_sdk=30,
            min_sdk=21,
            version_code=1,
            abis=[],
            size_bytes=5000000,
            permissions=["android.permission.WRITE_EXTERNAL_STORAGE"],
            uses_cleartext_traffic=True,
        ),
        "device": DeviceProfile(
            os_api_level=35,
            install_floor=24,
            supported_abis=["arm64-v8a"],
            page_size_bytes=16384,
            is_widescreen=True,
            is_high_refresh=False,
        ),
    },
    "scenario_10_apache_http_legacy": {
        "apk": ApkMetadata(
            package_name="com.example.apacheapp",
            target_sdk=28,
            min_sdk=21,
            version_code=1,
            abis=[],
            uses_apache_http=True,
            size_bytes=8000000,
            uses_cleartext_traffic=True,
        ),
        "device": DeviceProfile(
            os_api_level=35,
            install_floor=24,
            supported_abis=["arm64-v8a"],
            page_size_bytes=16384,
            is_widescreen=True,
            is_high_refresh=False,
        ),
    },
    "scenario_11_unresolvable_private_lib": {
        "apk": ApkMetadata(
            package_name="com.example.privatelibapp",
            target_sdk=26,
            min_sdk=21,
            version_code=1,
            abis=["arm64-v8a"],
            elf_load_align_64bit=16384,
            private_libs=["libgui.so"],
            size_bytes=10000000,
            uses_cleartext_traffic=True,
        ),
        "device": DeviceProfile(
            os_api_level=35,
            install_floor=24,
            supported_abis=["arm64-v8a"],
            page_size_bytes=16384,
            is_widescreen=True,
            is_high_refresh=False,
        ),
    },
    "scenario_12_has_code_false_shim": {
        "apk": ApkMetadata(
            package_name="com.example.hascodefalseapp",
            target_sdk=22,
            min_sdk=15,
            version_code=1,
            abis=[],
            has_code=False,
            has_fixed_physics=True,
            size_bytes=10000000,
            uses_cleartext_traffic=True,
        ),
        "device": DeviceProfile(
            os_api_level=35,
            install_floor=24,
            supported_abis=["arm64-v8a"],
            page_size_bytes=16384,
            is_high_refresh=True,
            is_widescreen=True,
        ),
    },
}


def serialize_canonical_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


class TestGoldenTriage(unittest.TestCase):
    def setUp(self):
        self.update_goldens = os.environ.get("UPDATE_GOLDENS") == "1"
        self.empty_results_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.empty_results_dir.cleanup()

    def test_all_scenarios_match_canonical_goldens(self):
        GOLDENS_DIR.mkdir(parents=True, exist_ok=True)

        for scenario_name, fixture in GOLDEN_SCENARIOS.items():
            with self.subTest(scenario=scenario_name):
                golden_file = GOLDENS_DIR / f"{scenario_name}.json"
                actual_result = evaluate_triage(
                    apk_meta=fixture["apk"],
                    device_profile=fixture["device"],
                    results_dir=Path(self.empty_results_dir.name),
                )
                actual_json = serialize_canonical_json(actual_result)

                if self.update_goldens or not golden_file.exists():
                    golden_file.write_text(actual_json, encoding="utf-8")

                expected_json = golden_file.read_text(encoding="utf-8")
                self.assertEqual(
                    actual_json,
                    expected_json,
                    f"Golden mismatch for scenario '{scenario_name}'. Run with UPDATE_GOLDENS=1 to refresh.",
                )


if __name__ == "__main__":
    unittest.main()
