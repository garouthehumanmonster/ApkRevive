"""
test_canaries.py - Canary verification suite for ApkRevive v3.3 Deliverable E.
Verifies all 8 canaries (Control and Failing variants) against:
- evaluate_triage
- parse_elf_load_align / inspect_apk_elf_align
- validate_obb_delivery
- Binary AXML metadata and apksigner verification
"""

import os
import struct
import unittest
import zipfile
from pathlib import Path

from apkrevive.core.models import ApkMetadata, DeviceProfile, Verdict, TriageSignal
from apkrevive.core.triage import evaluate_triage
from apkrevive.core.elf import parse_elf_load_align, inspect_apk_elf_align
from apkrevive.core.obb import validate_obb_delivery
from apkrevive.core.signer import verify_apk
from apkrevive.core.axml import AxmlSurgeon

CANARIES_BUILD = Path(__file__).resolve().parent.parent / "canaries" / "build"


def get_elf_needed(so_bytes: bytes) -> list:
    """Extracts DT_NEEDED entries from 64-bit ELF shared library."""
    if len(so_bytes) < 64 or not so_bytes.startswith(b"\x7fELF"):
        return []
    e_phoff = struct.unpack_from("<Q", so_bytes, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", so_bytes, 0x36)[0]
    e_phnum = struct.unpack_from("<H", so_bytes, 0x38)[0]
    dyn_off = None
    dyn_sz = None
    for i in range(e_phnum):
        off = e_phoff + (i * e_phentsize)
        if struct.unpack_from("<I", so_bytes, off)[0] == 2:  # PT_DYNAMIC
            dyn_off = struct.unpack_from("<Q", so_bytes, off + 8)[0]
            dyn_sz = struct.unpack_from("<Q", so_bytes, off + 32)[0]
            break
    if dyn_off is None:
        return []
    needed_offsets = []
    strtab_off = None
    curr = dyn_off
    while curr < dyn_off + dyn_sz:
        tag, val = struct.unpack_from("<QQ", so_bytes, curr)
        if tag == 0:
            break
        elif tag == 1:
            needed_offsets.append(val)
        elif tag == 5:
            strtab_off = val
        curr += 16
    needed = []
    if strtab_off is not None:
        for noff in needed_offsets:
            p = strtab_off + noff
            end = so_bytes.find(b"\x00", p)
            if end != -1:
                needed.append(so_bytes[p:end].decode("utf-8"))
    return needed


class TestCanaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ensure canary APKs are built
        apks = list(CANARIES_BUILD.glob("*.apk")) if CANARIES_BUILD.exists() else []
        if len(apks) < 16:
            from canaries.build_canaries import build_all
            build_all()

    # 1. canary_install_floor
    def test_canary_01_install_floor(self):
        # Triage evaluation
        dev = DeviceProfile(os_api_level=35, install_floor=24)

        # Control: targetSdk 24
        meta_ctrl = ApkMetadata(target_sdk=24)
        triage_ctrl = evaluate_triage(meta_ctrl, dev)
        self.assertEqual(triage_ctrl["verdict"], Verdict.GREEN.value)
        self.assertEqual(triage_ctrl["reason"], TriageSignal.RUNNABLE_UNMODIFIED.value)
        self.assertEqual(triage_ctrl["install_method"], "DIRECT_INSTALL")

        # Failing: targetSdk 22
        meta_fail = ApkMetadata(target_sdk=22)
        triage_fail = evaluate_triage(meta_fail, dev)
        self.assertEqual(triage_fail["verdict"], Verdict.GREEN.value)
        self.assertEqual(triage_fail["reason"], TriageSignal.RUNNABLE_UNMODIFIED.value)
        self.assertEqual(triage_fail["install_method"], "BYPASS_LOW_TARGET_SDK_BLOCK")

        # Manifest verification in built APKs
        apk_ctrl = CANARIES_BUILD / "canary_install_floor_control.apk"
        apk_fail = CANARIES_BUILD / "canary_install_floor_failing.apk"

        with zipfile.ZipFile(apk_ctrl, "r") as zf:
            root = AxmlSurgeon.parse(zf.read("AndroidManifest.xml"))
            uses_sdk = root.find_child("uses-sdk")
            self.assertEqual(uses_sdk.get_attr("targetSdkVersion").get_value(), 24)
            log_line = zf.read("assets/canary_logcat.txt").decode().strip()
            self.assertEqual(log_line, "ApkReviveCanary: canary_install_floor variant=control targetSdk=24")

        with zipfile.ZipFile(apk_fail, "r") as zf:
            root = AxmlSurgeon.parse(zf.read("AndroidManifest.xml"))
            uses_sdk = root.find_child("uses-sdk")
            self.assertEqual(uses_sdk.get_attr("targetSdkVersion").get_value(), 22)
            log_line = zf.read("assets/canary_logcat.txt").decode().strip()
            self.assertEqual(log_line, "ApkReviveCanary: canary_install_floor variant=failing targetSdk=22")

    # 2. canary_apache_http
    def test_canary_02_apache_http(self):
        dev = DeviceProfile(os_api_level=35, install_floor=24)

        # Control: targetSdk 22, uses_apache_http=True -> unmodified bypass
        meta_ctrl = ApkMetadata(target_sdk=22, uses_apache_http=True)
        triage_ctrl = evaluate_triage(meta_ctrl, dev)
        self.assertEqual(triage_ctrl["verdict"], Verdict.GREEN.value)
        self.assertEqual(triage_ctrl["install_method"], "BYPASS_LOW_TARGET_SDK_BLOCK")

        # Failing: targetSdk 28, uses_apache_http=True -> needs uses-library injection
        meta_fail = ApkMetadata(target_sdk=28, uses_apache_http=True)
        triage_fail = evaluate_triage(meta_fail, dev)
        self.assertEqual(triage_fail["verdict"], Verdict.YELLOW.value)
        self.assertEqual(triage_fail["reason"], TriageSignal.MODIFICATION_REQUIRED.value)
        self.assertIn("INJECT_USES_LIBRARY_APACHE_HTTP", triage_fail["required_transforms"])

        # Built APK manifest verification
        apk_fail = CANARIES_BUILD / "canary_apache_http_failing.apk"
        with zipfile.ZipFile(apk_fail, "r") as zf:
            root = AxmlSurgeon.parse(zf.read("AndroidManifest.xml"))
            app = root.find_child("application")
            # Verify no uses-library org.apache.http.legacy exists in failing APK
            self.assertIsNone(app.find_child("uses-library", "name", "org.apache.http.legacy"))

    # 3. canary_page_size (native)
    def test_canary_03_page_size(self):
        apk_ctrl = str(CANARIES_BUILD / "canary_page_size_control.apk")
        apk_fail = str(CANARIES_BUILD / "canary_page_size_failing.apk")

        # ELF segment parser inspection
        align_ctrl = inspect_apk_elf_align(apk_ctrl)
        align_fail = inspect_apk_elf_align(apk_fail)
        self.assertEqual(align_ctrl, 16384)
        self.assertEqual(align_fail, 4096)

        # Direct bytes parse_elf_load_align
        with zipfile.ZipFile(apk_ctrl, "r") as zf:
            self.assertEqual(parse_elf_load_align(zf.read("lib/arm64-v8a/libcanary_page_size.so")), 16384)
        with zipfile.ZipFile(apk_fail, "r") as zf:
            self.assertEqual(parse_elf_load_align(zf.read("lib/arm64-v8a/libcanary_page_size.so")), 4096)

        # Triage evaluation
        dev16k_api35 = DeviceProfile(os_api_level=35, page_size_bytes=16384, supported_abis=["arm64-v8a"])
        dev16k_api36 = DeviceProfile(os_api_level=36, page_size_bytes=16384, supported_abis=["arm64-v8a"])

        meta_ctrl = ApkMetadata(abis=["arm64-v8a"], elf_load_align_64bit=16384, target_sdk=28)
        triage_ctrl = evaluate_triage(meta_ctrl, dev16k_api35)
        self.assertEqual(triage_ctrl["verdict"], Verdict.GREEN.value)

        meta_fail = ApkMetadata(abis=["arm64-v8a"], elf_load_align_64bit=4096, target_sdk=28)
        triage_fail_35 = evaluate_triage(meta_fail, dev16k_api35)
        self.assertEqual(triage_fail_35["verdict"], Verdict.RED.value)
        self.assertEqual(triage_fail_35["reason"], TriageSignal.INCOMPATIBLE_PAGE_SIZE.value)

        triage_fail_36 = evaluate_triage(meta_fail, dev16k_api36)
        self.assertEqual(triage_fail_36["verdict"], Verdict.YELLOW.value)
        self.assertIn("PAGE_SIZE_COMPAT", triage_fail_36["required_transforms"])

    # 4. canary_physics_tick
    def test_canary_04_physics_tick(self):
        dev_high_refresh = DeviceProfile(is_high_refresh=True)

        # Control: has_fixed_physics=False
        meta_ctrl = ApkMetadata(has_fixed_physics=False, target_sdk=28)
        triage_ctrl = evaluate_triage(meta_ctrl, dev_high_refresh)
        self.assertEqual(triage_ctrl["verdict"], Verdict.GREEN.value)

        # Failing: has_fixed_physics=True (free running)
        meta_fail = ApkMetadata(has_fixed_physics=True, target_sdk=28)
        triage_fail = evaluate_triage(meta_fail, dev_high_refresh)
        self.assertEqual(triage_fail["verdict"], Verdict.YELLOW.value)
        self.assertIn("LOCK_60HZ_DISPLAY_MODE", triage_fail["required_transforms"])

        # Manifest check: control has meta-data lock, failing does not
        apk_ctrl = CANARIES_BUILD / "canary_physics_tick_control.apk"
        apk_fail = CANARIES_BUILD / "canary_physics_tick_failing.apk"

        with zipfile.ZipFile(apk_ctrl, "r") as zf:
            root = AxmlSurgeon.parse(zf.read("AndroidManifest.xml"))
            app = root.find_child("application")
            meta = app.find_child("meta-data", "name", "apkrevive.enable_60hz_lock")
            self.assertIsNotNone(meta)
            self.assertTrue(meta.get_attr("value").get_value())

        with zipfile.ZipFile(apk_fail, "r") as zf:
            root = AxmlSurgeon.parse(zf.read("AndroidManifest.xml"))
            app = root.find_child("application")
            meta = app.find_child("meta-data", "name", "apkrevive.enable_60hz_lock")
            self.assertIsNone(meta)

    # 5. canary_aspect_ratio
    def test_canary_05_aspect_ratio(self):
        dev_widescreen = DeviceProfile(is_widescreen=True)

        # Control: is_non_resizeable=False
        meta_ctrl = ApkMetadata(is_non_resizeable=False, target_sdk=28)
        triage_ctrl = evaluate_triage(meta_ctrl, dev_widescreen)
        self.assertEqual(triage_ctrl["verdict"], Verdict.GREEN.value)

        # Failing: is_non_resizeable=True
        meta_fail = ApkMetadata(is_non_resizeable=True, target_sdk=28)
        triage_fail = evaluate_triage(meta_fail, dev_widescreen)
        self.assertEqual(triage_fail["verdict"], Verdict.YELLOW.value)
        self.assertIn("EXPAND_ASPECT_RATIO", triage_fail["required_transforms"])

        # Manifest checks
        apk_ctrl = CANARIES_BUILD / "canary_aspect_ratio_control.apk"
        apk_fail = CANARIES_BUILD / "canary_aspect_ratio_failing.apk"

        with zipfile.ZipFile(apk_ctrl, "r") as zf:
            root = AxmlSurgeon.parse(zf.read("AndroidManifest.xml"))
            app = root.find_child("application")
            self.assertTrue(app.get_attr("resizeableActivity").get_value())

        with zipfile.ZipFile(apk_fail, "r") as zf:
            root = AxmlSurgeon.parse(zf.read("AndroidManifest.xml"))
            app = root.find_child("application")
            self.assertFalse(app.get_attr("resizeableActivity").get_value())
            meta = app.find_child("meta-data", "name", "android.max_aspect")
            self.assertIsNotNone(meta)

    # 6. canary_bionic_greylist (native)
    def test_canary_06_bionic_greylist(self):
        dev = DeviceProfile(page_size_bytes=16384, supported_abis=["arm64-v8a"])

        # Control: targetSdk 22, libcrypto.so (BIONIC_GREYLIST permitted on targetSdk < 24)
        meta_ctrl = ApkMetadata(target_sdk=22, abis=["arm64-v8a"], elf_load_align_64bit=16384, private_libs=["libcrypto.so"])
        triage_ctrl = evaluate_triage(meta_ctrl, dev)
        self.assertEqual(triage_ctrl["verdict"], Verdict.GREEN.value)

        # Failing: targetSdk 28, libgui.so (Blocked private system library)
        meta_fail = ApkMetadata(target_sdk=28, abis=["arm64-v8a"], elf_load_align_64bit=16384, private_libs=["libgui.so"])
        triage_fail = evaluate_triage(meta_fail, dev)
        self.assertEqual(triage_fail["verdict"], Verdict.RED.value)
        self.assertEqual(triage_fail["reason"], TriageSignal.UNRESOLVABLE_SYSTEM_LIBRARY.value)

        # DT_NEEDED verification in built binaries
        apk_ctrl = CANARIES_BUILD / "canary_bionic_greylist_control.apk"
        apk_fail = CANARIES_BUILD / "canary_bionic_greylist_failing.apk"

        with zipfile.ZipFile(apk_ctrl, "r") as zf:
            so_ctrl = zf.read("lib/arm64-v8a/libcanary_bionic.so")
            needed_ctrl = get_elf_needed(so_ctrl)
            self.assertIn("libcrypto.so", needed_ctrl)

        with zipfile.ZipFile(apk_fail, "r") as zf:
            so_fail = zf.read("lib/arm64-v8a/libcanary_bionic.so")
            needed_fail = get_elf_needed(so_fail)
            self.assertIn("libgui.so", needed_fail)

    # 7. canary_has_code
    def test_canary_07_has_code(self):
        dev_high_refresh = DeviceProfile(is_high_refresh=True)

        # Control: has_code=True
        meta_ctrl = ApkMetadata(has_code=True, target_sdk=28)
        triage_ctrl = evaluate_triage(meta_ctrl, dev_high_refresh)
        self.assertEqual(triage_ctrl["verdict"], Verdict.GREEN.value)

        # Failing: has_code=False requiring transform (has_fixed_physics=True)
        meta_fail = ApkMetadata(has_code=False, has_fixed_physics=True, target_sdk=28)
        triage_fail = evaluate_triage(meta_fail, dev_high_refresh)
        self.assertEqual(triage_fail["verdict"], Verdict.YELLOW.value)
        self.assertIn("SET_HAS_CODE_TRUE", triage_fail["required_transforms"])
        self.assertIn("LOCK_60HZ_DISPLAY_MODE", triage_fail["required_transforms"])

        # Manifest verification
        apk_ctrl = CANARIES_BUILD / "canary_has_code_control.apk"
        apk_fail = CANARIES_BUILD / "canary_has_code_failing.apk"

        with zipfile.ZipFile(apk_ctrl, "r") as zf:
            root = AxmlSurgeon.parse(zf.read("AndroidManifest.xml"))
            app = root.find_child("application")
            self.assertTrue(app.get_attr("hasCode").get_value())
            self.assertIn("classes.dex", zf.namelist())

        with zipfile.ZipFile(apk_fail, "r") as zf:
            root = AxmlSurgeon.parse(zf.read("AndroidManifest.xml"))
            app = root.find_child("application")
            self.assertFalse(app.get_attr("hasCode").get_value())

    # 8. canary_obb_version
    def test_canary_08_obb_version(self):
        # Control: APK vCode=150, OBB vCode=100
        ctrl_obb = "main.100.com.apkrevive.canary.obbversion.control.obb"
        res_ctrl = validate_obb_delivery(ctrl_obb, "com.apkrevive.canary.obbversion.control", 150)
        self.assertTrue(res_ctrl["valid"])
        self.assertIsNone(res_ctrl.get("warning"))
        self.assertEqual(res_ctrl["obb_version"], 100)
        self.assertEqual(res_ctrl["obb_type"], "main")

        # Failing: APK vCode=100, OBB vCode=200 (version ahead of APK)
        fail_obb = "main.200.com.apkrevive.canary.obbversion.failing.obb"
        res_fail = validate_obb_delivery(fail_obb, "com.apkrevive.canary.obbversion.failing", 100)
        self.assertTrue(res_fail["valid"])
        self.assertIsNotNone(res_fail.get("warning"))
        self.assertIn("EXPANSION_VERSION_AHEAD_OF_APK", res_fail["warning"])
        self.assertEqual(res_fail["obb_version"], 200)

        # OBB files exist on disk
        self.assertTrue((CANARIES_BUILD / ctrl_obb).exists())
        self.assertTrue((CANARIES_BUILD / fail_obb).exists())

    # Verify signatures and logcat lines across all 16 APKs
    def test_all_16_apks_signed_and_valid(self):
        expected_canary_names = [
            "canary_install_floor_control.apk", "canary_install_floor_failing.apk",
            "canary_apache_http_control.apk", "canary_apache_http_failing.apk",
            "canary_page_size_control.apk", "canary_page_size_failing.apk",
            "canary_physics_tick_control.apk", "canary_physics_tick_failing.apk",
            "canary_aspect_ratio_control.apk", "canary_aspect_ratio_failing.apk",
            "canary_bionic_greylist_control.apk", "canary_bionic_greylist_failing.apk",
            "canary_has_code_control.apk", "canary_has_code_failing.apk",
            "canary_obb_version_control.apk", "canary_obb_version_failing.apk"
        ]

        for apk_name in expected_canary_names:
            with self.subTest(apk=apk_name):
                apk_path = CANARIES_BUILD / apk_name
                self.assertTrue(apk_path.exists(), f"Missing APK: {apk_name}")

                # Signature verification
                ver = verify_apk(str(apk_path))
                self.assertTrue(ver["verified"], f"Signature verification failed for {apk_name}: {ver.get('output')}")

                # Canonical logcat line format check
                with zipfile.ZipFile(apk_path, "r") as zf:
                    self.assertIn("assets/canary_logcat.txt", zf.namelist())
                    log_line = zf.read("assets/canary_logcat.txt").decode("utf-8").strip()
                    self.assertTrue(log_line.startswith("ApkReviveCanary: canary_"), f"Malformed logcat: {log_line}")


if __name__ == "__main__":
    unittest.main()
