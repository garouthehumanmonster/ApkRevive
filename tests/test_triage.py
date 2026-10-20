"""
test_triage.py - 16-vector compliance test suite for ApkRevive v3.3.
"""

import unittest
from apkrevive.core.models import ApkMetadata, DeviceProfile
from apkrevive.core.triage import evaluate_triage

VECTORS = [
  {"id": "vector_01_pure_java_targetsdk28", "input": {"apk": {"target_sdk": 28, "abis": [], "size_bytes": 5000000}, "device": {"os_api_level": 35, "install_floor": 24, "supported_abis": ["arm64-v8a"], "page_size_bytes": 16384}}, "expected": {"verdict": "GREEN", "reason": "RUNNABLE_UNMODIFIED", "install_method": "DIRECT_INSTALL"}},
  {"id": "vector_02_pure_java_targetsdk22", "input": {"apk": {"target_sdk": 22, "abis": [], "size_bytes": 5000000}, "device": {"os_api_level": 35, "install_floor": 24, "supported_abis": ["arm64-v8a"], "page_size_bytes": 16384}}, "expected": {"verdict": "GREEN", "reason": "RUNNABLE_UNMODIFIED", "install_method": "BYPASS_LOW_TARGET_SDK_BLOCK"}},
  {"id": "vector_03_arm32_on_64bit_only", "input": {"apk": {"target_sdk": 22, "abis": ["armeabi-v7a"], "size_bytes": 15000000}, "device": {"os_api_level": 35, "install_floor": 24, "supported_abis": ["arm64-v8a"], "page_size_bytes": 16384}}, "expected": {"verdict": "RED", "reason": "INCOMPATIBLE_DEVICE_ABI"}},
  {"id": "vector_04_arm32_on_32bit_capable", "input": {"apk": {"target_sdk": 22, "abis": ["armeabi-v7a"], "size_bytes": 15000000}, "device": {"os_api_level": 33, "install_floor": 1, "supported_abis": ["arm64-v8a", "armeabi-v7a"], "page_size_bytes": 4096}}, "expected": {"verdict": "GREEN", "reason": "RUNNABLE_UNMODIFIED", "install_method": "DIRECT_INSTALL"}},
  {"id": "vector_05_apache_http_targetsdk22_control", "input": {"apk": {"target_sdk": 22, "abis": [], "uses_apache_http": True, "size_bytes": 8000000}, "device": {"os_api_level": 35, "install_floor": 24, "supported_abis": ["arm64-v8a"], "page_size_bytes": 16384}}, "expected": {"verdict": "GREEN", "reason": "RUNNABLE_UNMODIFIED", "install_method": "BYPASS_LOW_TARGET_SDK_BLOCK"}},
  {"id": "vector_06_apache_http_targetsdk28_failing", "input": {"apk": {"target_sdk": 28, "abis": [], "uses_apache_http": True, "size_bytes": 8000000}, "device": {"os_api_level": 35, "install_floor": 24, "supported_abis": ["arm64-v8a"], "page_size_bytes": 16384}}, "expected": {"verdict": "YELLOW", "reason": "MODIFICATION_REQUIRED", "required_transforms": ["INJECT_USES_LIBRARY_APACHE_HTTP"]}},
  {"id": "vector_07_elf_4kb_on_16kb_android15", "input": {"apk": {"target_sdk": 28, "abis": ["arm64-v8a"], "elf_load_align_64bit": 4096, "size_bytes": 25000000}, "device": {"os_api_level": 35, "install_floor": 24, "supported_abis": ["arm64-v8a"], "page_size_bytes": 16384}}, "expected": {"verdict": "RED", "reason": "INCOMPATIBLE_PAGE_SIZE"}},
  {"id": "vector_08_elf_4kb_on_16kb_android16", "input": {"apk": {"target_sdk": 28, "abis": ["arm64-v8a"], "elf_load_align_64bit": 4096, "size_bytes": 25000000}, "device": {"os_api_level": 36, "install_floor": 24, "supported_abis": ["arm64-v8a"], "page_size_bytes": 16384}}, "expected": {"verdict": "GREEN", "reason": "RUNNABLE_UNMODIFIED"}},
  {"id": "vector_09_private_lib_greylisted_targetsdk22", "input": {"apk": {"target_sdk": 22, "abis": ["arm64-v8a"], "elf_load_align_64bit": 16384, "private_libs": ["libcrypto.so"], "size_bytes": 10000000}, "device": {"os_api_level": 35, "install_floor": 24, "supported_abis": ["arm64-v8a"], "page_size_bytes": 16384}}, "expected": {"verdict": "GREEN", "reason": "RUNNABLE_UNMODIFIED"}},
  {"id": "vector_10_private_lib_greylisted_targetsdk26", "input": {"apk": {"target_sdk": 26, "abis": ["arm64-v8a"], "elf_load_align_64bit": 16384, "private_libs": ["libcrypto.so"], "size_bytes": 10000000}, "device": {"os_api_level": 35, "install_floor": 24, "supported_abis": ["arm64-v8a"], "page_size_bytes": 16384}}, "expected": {"verdict": "RED", "reason": "UNRESOLVABLE_SYSTEM_LIBRARY"}},
  {"id": "vector_11_private_lib_non_greylisted", "input": {"apk": {"target_sdk": 22, "abis": ["arm64-v8a"], "elf_load_align_64bit": 16384, "private_libs": ["libgui.so"], "size_bytes": 10000000}, "device": {"os_api_level": 35, "install_floor": 24, "supported_abis": ["arm64-v8a"], "page_size_bytes": 16384}}, "expected": {"verdict": "RED", "reason": "UNRESOLVABLE_SYSTEM_LIBRARY"}},
  {"id": "vector_12_drm_detected_warning", "input": {"apk": {"target_sdk": 28, "abis": [], "has_drm": True, "size_bytes": 12000000}, "device": {"os_api_level": 35, "install_floor": 24, "supported_abis": ["arm64-v8a"], "page_size_bytes": 16384}}, "expected": {"verdict": "GREEN", "reason": "RUNNABLE_UNMODIFIED"}},
  {"id": "vector_13_exceeds_2gb_unmodified", "input": {"apk": {"target_sdk": 28, "abis": [], "size_bytes": 2684354560}, "device": {"os_api_level": 35, "install_floor": 24, "supported_abis": ["arm64-v8a"], "page_size_bytes": 16384}}, "expected": {"verdict": "GREEN", "reason": "RUNNABLE_UNMODIFIED"}},
  {"id": "vector_14_exceeds_2gb_modified", "input": {"apk": {"target_sdk": 28, "abis": [], "uses_apache_http": True, "size_bytes": 2684354560}, "device": {"os_api_level": 35, "install_floor": 24, "supported_abis": ["arm64-v8a"], "page_size_bytes": 16384}}, "expected": {"verdict": "RED", "reason": "EXCEEDS_2GB_LIMIT_FOR_REPACKING"}},
  {"id": "vector_15_self_signature_check_with_modification", "input": {"apk": {"target_sdk": 28, "abis": [], "uses_apache_http": True, "has_self_sig_check": True, "size_bytes": 15000000}, "device": {"os_api_level": 35, "install_floor": 24, "supported_abis": ["arm64-v8a"], "page_size_bytes": 16384}}, "expected": {"verdict": "NEEDS_USER_INPUT", "reason": "SIGNATURE_VERIFICATION_DETECTED"}},
  {"id": "vector_16_has_code_false_with_shim", "input": {"apk": {"target_sdk": 22, "abis": [], "has_code": False, "has_fixed_physics": True, "size_bytes": 10000000}, "device": {"os_api_level": 35, "install_floor": 24, "supported_abis": ["arm64-v8a"], "page_size_bytes": 16384, "is_high_refresh": True}}, "expected": {"verdict": "YELLOW", "reason": "MODIFICATION_REQUIRED", "required_transforms": ["SET_HAS_CODE_TRUE", "LOCK_60HZ_DISPLAY_MODE"]}}
]


class TestTriage(unittest.TestCase):
    def test_all_16_vectors(self):
        for vec in VECTORS:
            with self.subTest(vector_id=vec["id"]):
                apk = ApkMetadata.from_dict(vec["input"]["apk"])
                dev = DeviceProfile.from_dict(vec["input"]["device"])
                res = evaluate_triage(apk, dev)
                exp = vec["expected"]

                self.assertEqual(res["verdict"], exp["verdict"])
                self.assertEqual(res["reason"], exp["reason"])
                if "install_method" in exp:
                    self.assertEqual(res.get("install_method"), exp["install_method"])
                if "required_transforms" in exp:
                    self.assertEqual(sorted(res.get("required_transforms", [])), sorted(exp["required_transforms"]))


    def test_elf_16kb_exempt_returns_green_with_advisory(self):
        apk = ApkMetadata(
            package_name="com.example.arm32",
            target_sdk=28,
            abis=["armeabi-v7a"],
            elf_16kb_status="EXEMPT",
        )
        dev = DeviceProfile(
            os_api_level=35,
            install_floor=24,
            supported_abis=["arm64-v8a", "armeabi-v7a"],
            page_size_bytes=16384,
        )
        res = evaluate_triage(apk, dev)
        self.assertEqual(res["verdict"], "GREEN")
        self.assertTrue(any("WARN_ELF_EXEMPT" in w for w in res["warnings"]))

    def test_verified_flag_api37_x86_64_only(self):
        """Verifies that 16KB page_size_compat_verified is True ONLY when API == 37 AND device ABI is x86_64."""
        apk = ApkMetadata(
            package_name="com.example.native4k",
            target_sdk=28,
            abis=["arm64-v8a", "x86_64"],
            elf_load_align_64bit=4096,
        )

        # 1. API 37 with x86_64 -> VERIFIED
        dev_37_x86 = DeviceProfile(
            os_api_level=37,
            install_floor=24,
            supported_abis=["x86_64"],
            page_size_bytes=16384,
        )
        res_37_x86 = evaluate_triage(apk, dev_37_x86)
        self.assertEqual(res_37_x86["verdict"], "GREEN")
        self.assertTrue(res_37_x86["page_size_compat_verified"])
        self.assertNotIn("verdict_display", res_37_x86)

        # 2. API 37 with arm64-v8a only -> UNVERIFIED
        dev_37_arm = DeviceProfile(
            os_api_level=37,
            install_floor=24,
            supported_abis=["arm64-v8a"],
            page_size_bytes=16384,
        )
        res_37_arm = evaluate_triage(apk, dev_37_arm)
        self.assertEqual(res_37_arm["verdict"], "GREEN")
        self.assertFalse(res_37_arm["page_size_compat_verified"])
        self.assertEqual(res_37_arm.get("verdict_display"), "GREEN (UNVERIFIED)")

        # 3. API 36 with x86_64 -> UNVERIFIED
        dev_36_x86 = DeviceProfile(
            os_api_level=36,
            install_floor=24,
            supported_abis=["x86_64"],
            page_size_bytes=16384,
        )
        res_36_x86 = evaluate_triage(apk, dev_36_x86)
        self.assertEqual(res_36_x86["verdict"], "GREEN")
        self.assertFalse(res_36_x86["page_size_compat_verified"])
        self.assertEqual(res_36_x86.get("verdict_display"), "GREEN (UNVERIFIED)")


if __name__ == "__main__":
    unittest.main()
