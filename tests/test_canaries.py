"""
test_canaries.py - Canary verification suite for ApkRevive v3.3 Deliverable E.
Verifies all 8 canaries (Control and Failing variants) against:
- evaluate_triage
- parse_elf_load_align / inspect_apk_elf_align
- validate_obb_delivery
- Binary AXML metadata and apksigner verification
"""

import hashlib
import json
import os
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from apkrevive.core.models import ApkMetadata, DeviceProfile, Verdict, TriageSignal
from apkrevive.core.triage import evaluate_triage
from apkrevive.core.elf import parse_elf_load_align, inspect_apk_elf_align
from apkrevive.core.obb import validate_obb_delivery
from apkrevive.core.signer import verify_apk
from apkrevive.core.axml import AxmlSurgeon
from apkrevive.core.extractor import inspect_apk
from apkrevive.adb.bridge import AdbBridge

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
        # Ensure canary APKs and hashes are built
        hashes_file = Path(__file__).resolve().parent.parent / "canaries" / "canary_hashes.json"
        apks = list(CANARIES_BUILD.glob("*.apk")) if CANARIES_BUILD.exists() else []
        if len(apks) < 16 or not hashes_file.exists():
            try:
                from canaries.build_canaries import build_all
                build_all()
                apks = list(CANARIES_BUILD.glob("*.apk")) if CANARIES_BUILD.exists() else []
            except Exception as e:
                if os.environ.get("APKREVIVE_REQUIRE_ARTIFACTS") == "1":
                    raise AssertionError(f"Required artifact failure: canary suite build failed: {e}")
                raise unittest.SkipTest(f"Canary build tools unavailable: {e}")
        if len(apks) < 16:
            if os.environ.get("APKREVIVE_REQUIRE_ARTIFACTS") == "1":
                raise AssertionError("Required artifact failure: expected canary APKs in canaries/build")
            raise unittest.SkipTest("No canary APKs in canaries/build")

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
        self.assertEqual(triage_fail_36["verdict"], Verdict.GREEN.value)
        self.assertTrue(any("WARN_PAGE_SIZE_COMPAT_ADVISORY" in w for w in triage_fail_36["warnings"]))

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

    # Verify signatures and logcat lines across all canary APKs
    def test_all_16_apks_signed_and_valid(self):
        from canaries.build_canaries import CANARY_DEFINITIONS
        expected_canary_names = sorted(list(set(f"{d['id']}_{d['variant']}.apk" for d in CANARY_DEFINITIONS)))

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

    def test_canary_hashes_json_recorded(self):
        hashes_path = Path(__file__).resolve().parent.parent / "canaries" / "canary_hashes.json"
        self.assertTrue(hashes_path.exists(), f"canary_hashes.json not found at {hashes_path}")

        with open(hashes_path, "r", encoding="utf-8") as f:
            recorded_hashes = json.load(f)

        from canaries.build_canaries import CANARY_DEFINITIONS
        expected_canary_names = sorted(list(set(f"{d['id']}_{d['variant']}.apk" for d in CANARY_DEFINITIONS)))

        self.assertEqual(len(recorded_hashes), len(expected_canary_names))
        for apk_name in expected_canary_names:
            self.assertIn(apk_name, recorded_hashes, f"Missing {apk_name} in canary_hashes.json")
            apk_path = CANARIES_BUILD / apk_name
            self.assertTrue(apk_path.exists(), f"Missing APK {apk_name} in build directory")
            with open(apk_path, "rb") as f:
                actual_hash = hashlib.sha256(f.read()).hexdigest()
            self.assertEqual(recorded_hashes[apk_name], actual_hash, f"Hash mismatch for {apk_name}")

    def test_failing_canaries_demonstrate_fail_and_pass(self):
        dev_api35 = DeviceProfile(os_api_level=35, install_floor=24)

        # 1. canary_apache_http_failing.apk
        # Before patching: triage requires INJECT_USES_LIBRARY_APACHE_HTTP
        apk_apache = CANARIES_BUILD / "canary_apache_http_failing.apk"
        meta_apache_before = inspect_apk(str(apk_apache))
        self.assertTrue(meta_apache_before.uses_apache_http)
        triage_apache_before = evaluate_triage(meta_apache_before, dev_api35)
        self.assertEqual(triage_apache_before["verdict"], Verdict.YELLOW.value)
        self.assertIn("INJECT_USES_LIBRARY_APACHE_HTTP", triage_apache_before["required_transforms"])

        # After patching with AxmlSurgeon to inject org.apache.http.legacy, triage evaluates to GREEN
        with zipfile.ZipFile(apk_apache, "r") as zf:
            orig_apache_manifest = zf.read("AndroidManifest.xml")
        patched_apache_manifest = AxmlSurgeon.patch_manifest(
            orig_apache_manifest, ["INJECT_USES_LIBRARY_APACHE_HTTP"]
        )

        root_apache_patched = AxmlSurgeon.parse(patched_apache_manifest)
        app_apache_patched = root_apache_patched.find_child("application")
        self.assertIsNotNone(app_apache_patched)
        assert app_apache_patched is not None
        lib_node = app_apache_patched.find_child("uses-library", "name", "org.apache.http.legacy")
        self.assertIsNotNone(lib_node)
        assert lib_node is not None
        self.assertFalse(lib_node.get_attr("required").get_value())

        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            patched_apache_apk = tmp.name
        try:
            with zipfile.ZipFile(apk_apache, "r") as zin, zipfile.ZipFile(patched_apache_apk, "w") as zout:
                for item in zin.infolist():
                    if item.filename == "AndroidManifest.xml":
                        zout.writestr(item, patched_apache_manifest)
                    else:
                        zout.writestr(item, zin.read(item.filename))
            meta_apache_after = inspect_apk(patched_apache_apk)
            self.assertFalse(meta_apache_after.uses_apache_http)
            triage_apache_after = evaluate_triage(meta_apache_after, dev_api35)
            self.assertEqual(triage_apache_after["verdict"], Verdict.GREEN.value)
            self.assertEqual(triage_apache_after["reason"], TriageSignal.RUNNABLE_UNMODIFIED.value)
        finally:
            if os.path.exists(patched_apache_apk):
                os.remove(patched_apache_apk)

        # 2. canary_install_floor_failing.apk: direct install fails on API 35; bypass flag succeeds
        apk_floor = CANARIES_BUILD / "canary_install_floor_failing.apk"
        meta_floor = inspect_apk(str(apk_floor))
        self.assertEqual(meta_floor.target_sdk, 22)
        self.assertLess(meta_floor.target_sdk, dev_api35.install_floor)

        triage_floor = evaluate_triage(meta_floor, dev_api35)
        self.assertEqual(triage_floor["verdict"], Verdict.GREEN.value)
        self.assertEqual(triage_floor["install_method"], "BYPASS_LOW_TARGET_SDK_BLOCK")
        self.assertNotEqual(triage_floor["install_method"], "DIRECT_INSTALL")

        bridge = AdbBridge(adb_path="adb")
        def mock_cmd(args):
            if "install" in args and "--bypass-low-target-sdk-block" not in args:
                return 1, "Failure [INSTALL_FAILED_DEPRECATED_SDK_VERSION: App target sdk 22 < min 24]", ""
            if "install" in args and "--bypass-low-target-sdk-block" in args:
                return 0, "Success", ""
            if "uninstall" in args:
                return 0, "Success", ""
            return 0, "", ""

        with patch.object(bridge, "_cmd", side_effect=mock_cmd):
            ok_direct, out_direct = bridge.install(str(apk_floor), bypass_low_target_sdk=False)
            self.assertFalse(ok_direct)
            self.assertIn("INSTALL_FAILED_DEPRECATED_SDK_VERSION", out_direct)

            ok_bypass, out_bypass = bridge.install(str(apk_floor), bypass_low_target_sdk=True)
            self.assertTrue(ok_bypass)
            self.assertIn("Success", out_bypass)

            ok_lifecycle, _ = bridge.install_lifecycle(
                str(apk_floor), meta_floor.package_name, meta_floor.target_sdk, dev_api35.install_floor
            )
            self.assertTrue(ok_lifecycle)

        # 3. canary_page_size_failing.apk: RED on API 35 16KB; with pageSizeCompat="enabled" passes on API 36
        apk_page = CANARIES_BUILD / "canary_page_size_failing.apk"
        meta_page = inspect_apk(str(apk_page))
        self.assertEqual(meta_page.elf_load_align_64bit, 4096)

        dev_16k_api35 = DeviceProfile(os_api_level=35, page_size_bytes=16384, supported_abis=["arm64-v8a"])
        dev_16k_api36 = DeviceProfile(os_api_level=36, page_size_bytes=16384, supported_abis=["arm64-v8a"])

        triage_page_35 = evaluate_triage(meta_page, dev_16k_api35)
        self.assertEqual(triage_page_35["verdict"], Verdict.RED.value)
        self.assertEqual(triage_page_35["reason"], TriageSignal.INCOMPATIBLE_PAGE_SIZE.value)

        triage_page_36 = evaluate_triage(meta_page, dev_16k_api36)
        self.assertEqual(triage_page_36["verdict"], Verdict.YELLOW.value)
        self.assertNotIn("PAGE_SIZE_COMPAT", triage_page_36["required_transforms"])
        self.assertTrue(any("WARN_PAGE_SIZE_COMPAT_ADVISORY" in w for w in triage_page_36["warnings"]))

        with zipfile.ZipFile(apk_page, "r") as zf:
            orig_page_manifest = zf.read("AndroidManifest.xml")
        patched_page_manifest = AxmlSurgeon.patch_manifest(orig_page_manifest, ["PAGE_SIZE_COMPAT"])
        root_page = AxmlSurgeon.parse(patched_page_manifest)
        app_page = root_page.find_child("application")
        self.assertIsNotNone(app_page)
        assert app_page is not None
        attr_compat = app_page.get_attr("pageSizeCompat")
        self.assertIsNotNone(attr_compat)
        assert attr_compat is not None
        self.assertEqual(attr_compat.get_value(), "enabled")

        # 4. canary_has_code_failing.apk: before patching hasCode="false"; after patching hasCode="true"
        apk_code = CANARIES_BUILD / "canary_has_code_failing.apk"
        meta_code_before = inspect_apk(str(apk_code))
        self.assertFalse(meta_code_before.has_code)

        with zipfile.ZipFile(apk_code, "r") as zf:
            orig_code_manifest = zf.read("AndroidManifest.xml")
        root_code_before = AxmlSurgeon.parse(orig_code_manifest)
        app_code_before = root_code_before.find_child("application")
        self.assertIsNotNone(app_code_before)
        assert app_code_before is not None
        attr_has_code = app_code_before.get_attr("hasCode")
        self.assertIsNotNone(attr_has_code)
        assert attr_has_code is not None
        self.assertFalse(attr_has_code.get_value())

        patched_code_manifest = AxmlSurgeon.patch_manifest(orig_code_manifest, ["SET_HAS_CODE_TRUE"])
        root_code_after = AxmlSurgeon.parse(patched_code_manifest)
        app_code_after = root_code_after.find_child("application")
        self.assertIsNotNone(app_code_after)
        assert app_code_after is not None
        attr_has_code_after = app_code_after.get_attr("hasCode")
        self.assertIsNotNone(attr_has_code_after)
        assert attr_has_code_after is not None
        self.assertTrue(attr_has_code_after.get_value())

        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            patched_code_path = tmp.name
        try:
            with zipfile.ZipFile(apk_code, "r") as zin, zipfile.ZipFile(patched_code_path, "w") as zout:
                for item in zin.infolist():
                    if item.filename == "AndroidManifest.xml":
                        zout.writestr(item, patched_code_manifest)
                    else:
                        zout.writestr(item, zin.read(item.filename))
            meta_code_after = inspect_apk(patched_code_path)
            self.assertTrue(meta_code_after.has_code)
        finally:
            if os.path.exists(patched_code_path):
                os.remove(patched_code_path)

        # 5. canary_aspect_ratio_failing.apk: before patching is_non_resizeable=True; after patching with resizeableActivity="true", is_non_resizeable=False
        apk_aspect = CANARIES_BUILD / "canary_aspect_ratio_failing.apk"
        meta_aspect_before = inspect_apk(str(apk_aspect))
        self.assertTrue(meta_aspect_before.is_non_resizeable)

        with zipfile.ZipFile(apk_aspect, "r") as zf:
            orig_aspect_manifest = zf.read("AndroidManifest.xml")
        root_aspect_before = AxmlSurgeon.parse(orig_aspect_manifest)
        app_aspect_before = root_aspect_before.find_child("application")
        self.assertIsNotNone(app_aspect_before)
        assert app_aspect_before is not None
        attr_resize = app_aspect_before.get_attr("resizeableActivity")
        self.assertIsNotNone(attr_resize)
        assert attr_resize is not None
        self.assertFalse(attr_resize.get_value())

        patched_aspect_manifest = AxmlSurgeon.patch_manifest(orig_aspect_manifest, ["EXPAND_ASPECT_RATIO"])
        root_aspect_after = AxmlSurgeon.parse(patched_aspect_manifest)
        app_aspect_after = root_aspect_after.find_child("application")
        self.assertIsNotNone(app_aspect_after)
        assert app_aspect_after is not None
        attr_resize_after = app_aspect_after.get_attr("resizeableActivity")
        self.assertIsNotNone(attr_resize_after)
        assert attr_resize_after is not None
        self.assertTrue(attr_resize_after.get_value())

        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            patched_aspect_path = tmp.name
        try:
            with zipfile.ZipFile(apk_aspect, "r") as zin, zipfile.ZipFile(patched_aspect_path, "w") as zout:
                for item in zin.infolist():
                    if item.filename == "AndroidManifest.xml":
                        zout.writestr(item, patched_aspect_manifest)
                    else:
                        zout.writestr(item, zin.read(item.filename))
            meta_aspect_after = inspect_apk(patched_aspect_path)
            self.assertFalse(meta_aspect_after.is_non_resizeable)
        finally:
            if os.path.exists(patched_aspect_path):
                os.remove(patched_aspect_path)

        # 6. canary_physics_tick_failing.apk: before patching has_fixed_physics=True; after patching with 60Hz metadata/shim, has_fixed_physics=False
        apk_physics = CANARIES_BUILD / "canary_physics_tick_failing.apk"
        meta_physics_before = inspect_apk(str(apk_physics))
        self.assertTrue(meta_physics_before.has_fixed_physics)

        with zipfile.ZipFile(apk_physics, "r") as zf:
            orig_physics_manifest = zf.read("AndroidManifest.xml")
        root_physics_before = AxmlSurgeon.parse(orig_physics_manifest)
        app_physics_before = root_physics_before.find_child("application")
        self.assertIsNotNone(app_physics_before)
        assert app_physics_before is not None
        self.assertIsNone(app_physics_before.find_child("meta-data", "name", "apkrevive.enable_60hz_lock"))

        patched_physics_manifest = AxmlSurgeon.patch_manifest(
            orig_physics_manifest,
            ["LOCK_60HZ_DISPLAY_MODE"],
            options={"enable_60hz": True}
        )
        root_physics_after = AxmlSurgeon.parse(patched_physics_manifest)
        app_physics_after = root_physics_after.find_child("application")
        self.assertIsNotNone(app_physics_after)
        assert app_physics_after is not None
        meta_60 = app_physics_after.find_child("meta-data", "name", "apkrevive.enable_60hz_lock")
        self.assertIsNotNone(meta_60)
        assert meta_60 is not None
        self.assertTrue(meta_60.get_attr("value").get_value())
        prov_node = app_physics_after.find_child("provider", "name", "apkrevive.shim.ApkReviveInitProvider")
        self.assertIsNotNone(prov_node)

        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            patched_physics_path = tmp.name
        try:
            with zipfile.ZipFile(apk_physics, "r") as zin, zipfile.ZipFile(patched_physics_path, "w") as zout:
                for item in zin.infolist():
                    if item.filename == "AndroidManifest.xml":
                        zout.writestr(item, patched_physics_manifest)
                    else:
                        zout.writestr(item, zin.read(item.filename))
            meta_physics_after = inspect_apk(patched_physics_path)
            self.assertFalse(meta_physics_after.has_fixed_physics)
        finally:
            if os.path.exists(patched_physics_path):
                os.remove(patched_physics_path)

        # 7. canary_bionic_greylist_failing.apk: triggers UNRESOLVABLE_SYSTEM_LIBRARY on API 35
        apk_bionic = CANARIES_BUILD / "canary_bionic_greylist_failing.apk"
        meta_bionic = inspect_apk(str(apk_bionic))
        self.assertIn("libgui.so", meta_bionic.private_libs)
        triage_bionic = evaluate_triage(meta_bionic, dev_api35)
        self.assertEqual(triage_bionic["verdict"], Verdict.RED.value)
        self.assertEqual(triage_bionic["reason"], TriageSignal.UNRESOLVABLE_SYSTEM_LIBRARY.value)

        # 8. canary_obb_version_failing.apk: OBB ahead of APK version triggers warning
        obb_failing = "main.200.com.apkrevive.canary.obbversion.failing.obb"
        res_obb_fail = validate_obb_delivery(
            obb_failing, "com.apkrevive.canary.obbversion.failing", current_apk_version=100
        )
        self.assertIn("EXPANSION_VERSION_AHEAD_OF_APK", res_obb_fail.get("warning", ""))
        res_obb_pass = validate_obb_delivery(
            obb_failing, "com.apkrevive.canary.obbversion.failing", current_apk_version=200
        )
        self.assertIsNone(res_obb_pass.get("warning"))


if __name__ == "__main__":
    unittest.main()
