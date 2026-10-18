"""
test_phase3_triage_checks.py - Comprehensive Unit Test Suite for Phase 3 Triage Checks.
Verifies all 6 canary pairs (Control clean vs Failing trigger):
1. Hidden-API reflection use (WARN_HIDDEN_API_REFLECTION)
2. GLES 1.x dependency (WARN_GLES1_DEPRECATED)
3. Known-dead SDKs (WARN_DEAD_SDKS)
4. TEXTREL native libs (WARN_TEXTREL)
5. Cleartext / TLS risks (WARN_CLEARTEXT / WARN_LEGACY_TLS)
6. Scoped-storage assumptions (WARN_SCOPED_STORAGE_OBB)
"""

import os
import tempfile
import unittest
import zipfile
from typing import Optional, Dict
from apkrevive.core.axml import AxmlSurgeon, AxmlNode
from apkrevive.core.models import DeviceProfile
from apkrevive.core.extractor import inspect_apk
from apkrevive.core.triage import evaluate_triage
from canaries.build_canaries import create_arm64_elf_so


def build_synthetic_apk(
    manifest_node: AxmlNode,
    dex_bytes: bytes = b"DEX\n035\x00CleanBytecode",
    native_libs: Optional[Dict[str, bytes]] = None,
) -> str:
    """Helper to build a temporary synthetic APK with binary AXML manifest and entries."""
    manifest_bytes = AxmlSurgeon.serialize(manifest_node)
    tmp = tempfile.NamedTemporaryFile(suffix=".apk", delete=False)
    apk_path = tmp.name
    tmp.close()

    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_bytes)
        if dex_bytes:
            zf.writestr("classes.dex", dex_bytes)
        if native_libs:
            for arcname, data in native_libs.items():
                zinfo = zipfile.ZipInfo(arcname)
                zinfo.compress_type = zipfile.ZIP_STORED
                zf.writestr(zinfo, data)

    return apk_path


class TestPhase3TriageChecks(unittest.TestCase):

    def test_check1_hidden_api_reflection_canary_pair(self):
        # 1. Control variant: clean manifest & clean DEX
        m_ctrl = AxmlNode(tag="manifest")
        m_ctrl.set_attr("package", "com.apkrevive.canary.hiddenapi.control", ns="")
        uses_sdk_ctrl = AxmlNode(tag="uses-sdk")
        uses_sdk_ctrl.set_attr("minSdkVersion", 21)
        uses_sdk_ctrl.set_attr("targetSdkVersion", 28)
        m_ctrl.children.append(uses_sdk_ctrl)
        app_ctrl = AxmlNode(tag="application")
        m_ctrl.children.append(app_ctrl)

        apk_ctrl = build_synthetic_apk(m_ctrl, dex_bytes=b"DEX\n035\x00CleanActivityCode")
        try:
            meta_ctrl = inspect_apk(apk_ctrl)
            self.assertEqual(meta_ctrl.hidden_api_reflections, [])
            res_ctrl = evaluate_triage(meta_ctrl, DeviceProfile(os_api_level=28))
            self.assertFalse(any("WARN_HIDDEN_API_REFLECTION" in w for w in res_ctrl["warnings"]))
        finally:
            if os.path.exists(apk_ctrl):
                os.remove(apk_ctrl)

        # 2. Failing variant: contains hidden API reflection in DEX
        m_fail = AxmlNode(tag="manifest")
        m_fail.set_attr("package", "com.apkrevive.canary.hiddenapi.failing", ns="")
        uses_sdk_fail = AxmlNode(tag="uses-sdk")
        uses_sdk_fail.set_attr("minSdkVersion", 21)
        uses_sdk_fail.set_attr("targetSdkVersion", 28)
        m_fail.children.append(uses_sdk_fail)
        app_fail = AxmlNode(tag="application")
        m_fail.children.append(app_fail)

        dex_fail = b"DEX\n035\x00android/app/ActivityThread\x00android/os/SystemProperties"
        apk_fail = build_synthetic_apk(m_fail, dex_bytes=dex_fail)
        try:
            meta_fail = inspect_apk(apk_fail)
            self.assertIn("android/app/ActivityThread", meta_fail.hidden_api_reflections)
            self.assertIn("android/os/SystemProperties", meta_fail.hidden_api_reflections)

            res_fail = evaluate_triage(meta_fail, DeviceProfile(os_api_level=28))
            warns = [w for w in res_fail["warnings"] if "WARN_HIDDEN_API_REFLECTION" in w]
            self.assertEqual(len(warns), 1)
            self.assertIn("Remediation", warns[0])
            self.assertIn("Replace non-SDK reflection with public AndroidX/Jetpack APIs", warns[0])
        finally:
            if os.path.exists(apk_fail):
                os.remove(apk_fail)

    def test_check2_gles1_dependency_canary_pair(self):
        # 1. Control variant: GLES 2.0 feature
        m_ctrl = AxmlNode(tag="manifest")
        m_ctrl.set_attr("package", "com.apkrevive.canary.gles1.control", ns="")
        uses_sdk_ctrl = AxmlNode(tag="uses-sdk")
        uses_sdk_ctrl.set_attr("minSdkVersion", 21)
        uses_sdk_ctrl.set_attr("targetSdkVersion", 28)
        m_ctrl.children.append(uses_sdk_ctrl)
        feature_ctrl = AxmlNode(tag="uses-feature")
        feature_ctrl.set_attr("glEsVersion", 0x00020000)
        m_ctrl.children.append(feature_ctrl)

        apk_ctrl = build_synthetic_apk(m_ctrl, dex_bytes=b"DEX\n035\x00GLES20Pipeline")
        try:
            meta_ctrl = inspect_apk(apk_ctrl)
            self.assertFalse(meta_ctrl.uses_gles1)
            res_ctrl = evaluate_triage(meta_ctrl, DeviceProfile(os_api_level=35))
            self.assertFalse(any("WARN_GLES1_DEPRECATED" in w for w in res_ctrl["warnings"]))
        finally:
            if os.path.exists(apk_ctrl):
                os.remove(apk_ctrl)

        # 2. Failing variant: GLES 1.0 feature and libGLESv1_CM.so
        m_fail = AxmlNode(tag="manifest")
        m_fail.set_attr("package", "com.apkrevive.canary.gles1.failing", ns="")
        uses_sdk_fail = AxmlNode(tag="uses-sdk")
        uses_sdk_fail.set_attr("minSdkVersion", 21)
        uses_sdk_fail.set_attr("targetSdkVersion", 28)
        m_fail.children.append(uses_sdk_fail)
        feature_fail = AxmlNode(tag="uses-feature")
        feature_fail.set_attr("glEsVersion", 0x00010000)
        m_fail.children.append(feature_fail)

        app_fail = AxmlNode(tag="application")
        lib_decl = AxmlNode(tag="uses-library")
        lib_decl.set_attr("name", "libGLESv1_CM.so")
        app_fail.children.append(lib_decl)
        m_fail.children.append(app_fail)

        so_bytes = create_arm64_elf_so(p_align=16384, needed_libs=[])
        native_map = {"lib/arm64-v8a/libGLESv1_CM.so": so_bytes}
        dex_fail = b"DEX\n035\x00Landroid/opengl/GLES10;\x00javax.microedition.khronos.opengles.GL10"

        apk_fail = build_synthetic_apk(m_fail, dex_bytes=dex_fail, native_libs=native_map)
        try:
            meta_fail = inspect_apk(apk_fail)
            self.assertTrue(meta_fail.uses_gles1)

            res_fail = evaluate_triage(meta_fail, DeviceProfile(os_api_level=35))
            warns = [w for w in res_fail["warnings"] if "WARN_GLES1_DEPRECATED" in w]
            self.assertEqual(len(warns), 1)
            self.assertIn("Remediation", warns[0])
            self.assertIn("Migrate rendering pipeline to OpenGL ES 2.0+", warns[0])
        finally:
            if os.path.exists(apk_fail):
                os.remove(apk_fail)

    def test_check3_known_dead_sdks_canary_pair(self):
        # 1. Control variant: clean
        m_ctrl = AxmlNode(tag="manifest")
        m_ctrl.set_attr("package", "com.apkrevive.canary.deadsdks.control", ns="")
        uses_sdk_ctrl = AxmlNode(tag="uses-sdk")
        uses_sdk_ctrl.set_attr("minSdkVersion", 21)
        uses_sdk_ctrl.set_attr("targetSdkVersion", 28)
        m_ctrl.children.append(uses_sdk_ctrl)

        apk_ctrl = build_synthetic_apk(m_ctrl, dex_bytes=b"DEX\n035\x00ModernSdkUsage")
        try:
            meta_ctrl = inspect_apk(apk_ctrl)
            self.assertEqual(meta_ctrl.dead_sdks, [])
            res_ctrl = evaluate_triage(meta_ctrl, DeviceProfile(os_api_level=35))
            self.assertFalse(any("WARN_DEAD_SDKS" in w for w in res_ctrl["warnings"]))
        finally:
            if os.path.exists(apk_ctrl):
                os.remove(apk_ctrl)

        # 2. Failing variant: contains Maps v1 in manifest + LVL / Legacy Billing / AdMob in DEX
        m_fail = AxmlNode(tag="manifest")
        m_fail.set_attr("package", "com.apkrevive.canary.deadsdks.failing", ns="")
        uses_sdk_fail = AxmlNode(tag="uses-sdk")
        uses_sdk_fail.set_attr("minSdkVersion", 21)
        uses_sdk_fail.set_attr("targetSdkVersion", 28)
        m_fail.children.append(uses_sdk_fail)
        app_fail = AxmlNode(tag="application")
        maps_lib = AxmlNode(tag="uses-library")
        maps_lib.set_attr("name", "com.google.android.maps")
        app_fail.children.append(maps_lib)
        m_fail.children.append(app_fail)

        dex_fail = (
            b"DEX\n035\x00com/android/vending/licensing/ILicensingService\x00"
            b"com/android/vending/billing/IInAppBillingService\x00"
            b"com/google/ads/AdView\x00com/airpush\x00com/millennialmedia"
        )
        apk_fail = build_synthetic_apk(m_fail, dex_bytes=dex_fail)
        try:
            meta_fail = inspect_apk(apk_fail)
            self.assertIn("Google Maps v1", meta_fail.dead_sdks)
            self.assertIn("Google LVL (Licensing)", meta_fail.dead_sdks)
            self.assertIn("Legacy In-App Billing", meta_fail.dead_sdks)
            self.assertIn("Legacy AdMob (Standalone)", meta_fail.dead_sdks)

            res_fail = evaluate_triage(meta_fail, DeviceProfile(os_api_level=35))
            warns = [w for w in res_fail["warnings"] if "WARN_DEAD_SDKS" in w]
            self.assertEqual(len(warns), 1)
            self.assertIn("Remediation", warns[0])
            self.assertIn("Remove obsolete SDK dependencies", warns[0])
        finally:
            if os.path.exists(apk_fail):
                os.remove(apk_fail)

    def test_check4_textrel_canary_pair(self):
        # 1. Control variant: clean 64-bit ELF without DT_TEXTREL
        m_ctrl = AxmlNode(tag="manifest")
        m_ctrl.set_attr("package", "com.apkrevive.canary.textrel.control", ns="")
        uses_sdk_ctrl = AxmlNode(tag="uses-sdk")
        uses_sdk_ctrl.set_attr("minSdkVersion", 21)
        uses_sdk_ctrl.set_attr("targetSdkVersion", 28)
        m_ctrl.children.append(uses_sdk_ctrl)

        so_clean = create_arm64_elf_so(p_align=16384, needed_libs=[], has_textrel=False)
        apk_ctrl = build_synthetic_apk(
            m_ctrl,
            native_libs={"lib/arm64-v8a/libcanary_clean.so": so_clean},
        )
        try:
            meta_ctrl = inspect_apk(apk_ctrl)
            self.assertFalse(meta_ctrl.has_textrel)
            self.assertEqual(meta_ctrl.textrel_libs, [])
            res_ctrl = evaluate_triage(meta_ctrl, DeviceProfile(os_api_level=35))
            self.assertFalse(any("WARN_TEXTREL" in w for w in res_ctrl["warnings"]))
        finally:
            if os.path.exists(apk_ctrl):
                os.remove(apk_ctrl)

        # 2. Failing variant: 64-bit ELF with DT_TEXTREL (tag 22)
        m_fail = AxmlNode(tag="manifest")
        m_fail.set_attr("package", "com.apkrevive.canary.textrel.failing", ns="")
        uses_sdk_fail = AxmlNode(tag="uses-sdk")
        uses_sdk_fail.set_attr("minSdkVersion", 21)
        uses_sdk_fail.set_attr("targetSdkVersion", 28)
        m_fail.children.append(uses_sdk_fail)

        so_textrel = create_arm64_elf_so(p_align=16384, needed_libs=[], has_textrel=True)
        apk_fail = build_synthetic_apk(
            m_fail,
            native_libs={"lib/arm64-v8a/libcanary_textrel.so": so_textrel},
        )
        try:
            meta_fail = inspect_apk(apk_fail)
            self.assertTrue(meta_fail.has_textrel)
            self.assertIn("libcanary_textrel.so", meta_fail.textrel_libs)

            res_fail = evaluate_triage(meta_fail, DeviceProfile(os_api_level=35))
            warns = [w for w in res_fail["warnings"] if "WARN_TEXTREL" in w]
            self.assertEqual(len(warns), 1)
            self.assertIn("Remediation", warns[0])
            self.assertIn("Recompile native code with -fPIC", warns[0])
        finally:
            if os.path.exists(apk_fail):
                os.remove(apk_fail)

    def test_check5_cleartext_and_tls_canary_pair(self):
        # 1. Control variant: usesCleartextTraffic="true"
        m_ctrl = AxmlNode(tag="manifest")
        m_ctrl.set_attr("package", "com.apkrevive.canary.cleartext.control", ns="")
        uses_sdk_ctrl = AxmlNode(tag="uses-sdk")
        uses_sdk_ctrl.set_attr("minSdkVersion", 21)
        uses_sdk_ctrl.set_attr("targetSdkVersion", 28)
        m_ctrl.children.append(uses_sdk_ctrl)
        app_ctrl = AxmlNode(tag="application")
        app_ctrl.set_attr("usesCleartextTraffic", True)
        m_ctrl.children.append(app_ctrl)

        apk_ctrl = build_synthetic_apk(m_ctrl, dex_bytes=b"DEX\n035\x00https://api.example.com")
        try:
            meta_ctrl = inspect_apk(apk_ctrl)
            self.assertTrue(meta_ctrl.uses_cleartext_traffic)
            res_ctrl = evaluate_triage(meta_ctrl, DeviceProfile(os_api_level=28))
            self.assertFalse(any("WARN_CLEARTEXT" in w for w in res_ctrl["warnings"]))
            self.assertFalse(any("WARN_LEGACY_TLS" in w for w in res_ctrl["warnings"]))
        finally:
            if os.path.exists(apk_ctrl):
                os.remove(apk_ctrl)

        # 2. Failing variant: usesCleartextTraffic="false" with cleartext HTTP + legacy TLS in DEX
        m_fail = AxmlNode(tag="manifest")
        m_fail.set_attr("package", "com.apkrevive.canary.cleartext.failing", ns="")
        uses_sdk_fail = AxmlNode(tag="uses-sdk")
        uses_sdk_fail.set_attr("minSdkVersion", 21)
        uses_sdk_fail.set_attr("targetSdkVersion", 28)
        m_fail.children.append(uses_sdk_fail)
        app_fail = AxmlNode(tag="application")
        app_fail.set_attr("usesCleartextTraffic", False)
        m_fail.children.append(app_fail)

        dex_fail = b"DEX\n035\x00http://insecure.endpoint.com/api\x00SSLv3\x00TLSv1.0"
        apk_fail = build_synthetic_apk(m_fail, dex_bytes=dex_fail)
        try:
            meta_fail = inspect_apk(apk_fail)
            self.assertFalse(meta_fail.uses_cleartext_traffic)
            self.assertIn("SSLv3", meta_fail.legacy_tls_protocols)
            self.assertIn("TLSv1.0", meta_fail.legacy_tls_protocols)

            res_fail = evaluate_triage(meta_fail, DeviceProfile(os_api_level=28))
            cleartext_warns = [w for w in res_fail["warnings"] if "WARN_CLEARTEXT" in w]
            self.assertEqual(len(cleartext_warns), 1)
            self.assertIn("Remediation", cleartext_warns[0])

            tls_warns = [w for w in res_fail["warnings"] if "WARN_LEGACY_TLS" in w]
            self.assertEqual(len(tls_warns), 1)
            self.assertIn("Remediation", tls_warns[0])
        finally:
            if os.path.exists(apk_fail):
                os.remove(apk_fail)

    def test_check6_scoped_storage_canary_pair(self):
        # 1. Control variant: targetSdk 28, no raw external storage paths
        m_ctrl = AxmlNode(tag="manifest")
        m_ctrl.set_attr("package", "com.apkrevive.canary.scopedstorage.control", ns="")
        uses_sdk_ctrl = AxmlNode(tag="uses-sdk")
        uses_sdk_ctrl.set_attr("minSdkVersion", 21)
        uses_sdk_ctrl.set_attr("targetSdkVersion", 28)
        m_ctrl.children.append(uses_sdk_ctrl)
        app_ctrl = AxmlNode(tag="application")
        m_ctrl.children.append(app_ctrl)

        apk_ctrl = build_synthetic_apk(m_ctrl, dex_bytes=b"DEX\n035\x00InternalFileStorageAccess")
        try:
            meta_ctrl = inspect_apk(apk_ctrl)
            self.assertFalse(meta_ctrl.has_request_legacy_external_storage)
            self.assertFalse(meta_ctrl.accesses_scoped_storage_paths)
            res_ctrl = evaluate_triage(meta_ctrl, DeviceProfile(os_api_level=30))
            self.assertFalse(any("WARN_SCOPED_STORAGE_OBB" in w for w in res_ctrl["warnings"]))
        finally:
            if os.path.exists(apk_ctrl):
                os.remove(apk_ctrl)

        # 2. Failing variant: targetSdk 30, requestLegacyExternalStorage="true", WRITE_EXTERNAL_STORAGE
        m_fail = AxmlNode(tag="manifest")
        m_fail.set_attr("package", "com.apkrevive.canary.scopedstorage.failing", ns="")
        uses_sdk_fail = AxmlNode(tag="uses-sdk")
        uses_sdk_fail.set_attr("minSdkVersion", 21)
        uses_sdk_fail.set_attr("targetSdkVersion", 30)
        m_fail.children.append(uses_sdk_fail)

        perm = AxmlNode(tag="uses-permission")
        perm.set_attr("name", "android.permission.WRITE_EXTERNAL_STORAGE")
        m_fail.children.append(perm)

        app_fail = AxmlNode(tag="application")
        app_fail.set_attr("requestLegacyExternalStorage", True)
        m_fail.children.append(app_fail)

        dex_fail = b"DEX\n035\x00Environment.getExternalStorageDirectory\x00Android/data/my.app"
        apk_fail = build_synthetic_apk(m_fail, dex_bytes=dex_fail)
        try:
            meta_fail = inspect_apk(apk_fail)
            self.assertTrue(meta_fail.has_request_legacy_external_storage)
            self.assertTrue(meta_fail.accesses_scoped_storage_paths)
            self.assertIn("android.permission.WRITE_EXTERNAL_STORAGE", meta_fail.permissions)

            res_fail = evaluate_triage(meta_fail, DeviceProfile(os_api_level=30))
            warns = [w for w in res_fail["warnings"] if "WARN_SCOPED_STORAGE_OBB" in w]
            self.assertEqual(len(warns), 1)
            self.assertIn("Remediation", warns[0])
            self.assertIn("Adopt Storage Access Framework (SAF)", warns[0])
        finally:
            if os.path.exists(apk_fail):
                os.remove(apk_fail)


if __name__ == "__main__":
    unittest.main()
