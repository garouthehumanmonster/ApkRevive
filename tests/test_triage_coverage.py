"""
test_triage_coverage.py - Unit test suite for Milestone 4 (Triage Coverage).
Verifies remediation warnings for:
1. 32-bit apps on 64-bit devices
2. Scoped storage & OBB access on Android 11+
3. Hidden API reflections
4. Cleartext HTTP & legacy TLS protocols
5. Deprecated permissions mapping
6. Full synthetic APK extraction and triage integration
"""

import os
import tempfile
import unittest
import zipfile

from apkrevive.core.axml import AxmlSurgeon, AxmlNode
from apkrevive.core.extractor import inspect_apk
from apkrevive.core.models import ApkMetadata, DeviceProfile, Verdict, TriageSignal
from apkrevive.core.triage import evaluate_triage, DEPRECATED_PERMISSIONS


class TestTriageCoverage(unittest.TestCase):

    def test_01_32bit_only_on_64bit_device(self):
        """Test 1: 32-bit app on 64-bit-only device produces WARN_32BIT_ONLY_ON_64BIT and RED verdict."""
        apk = ApkMetadata(
            target_sdk=28,
            abis=["armeabi-v7a"],
        )
        dev = DeviceProfile(
            os_api_level=35,
            supported_abis=["arm64-v8a"],
        )
        res = evaluate_triage(apk, dev)
        self.assertEqual(res["verdict"], Verdict.RED.value)
        self.assertEqual(res["reason"], TriageSignal.INCOMPATIBLE_DEVICE_ABI.value)

        warns = [w for w in res["warnings"] if "WARN_32BIT_ONLY_ON_64BIT" in w]
        self.assertEqual(len(warns), 1)
        warn_text = warns[0]
        self.assertIn("Remediation:", warn_text)
        self.assertIn("Recompile native libraries with 64-bit support (arm64-v8a)", warn_text)
        self.assertIn("provide a 32-bit translation layer", warn_text)

    def test_02_scoped_storage_and_obb_android11_plus(self):
        """Test 2: Scoped storage & OBB on Android 11+ produces WARN_SCOPED_STORAGE_OBB with remediation text."""
        # Case A: External storage permission on device_sdk 30+ for targetSdk >= 30
        apk_perm = ApkMetadata(
            target_sdk=30,
            permissions=["android.permission.WRITE_EXTERNAL_STORAGE"],
        )
        dev = DeviceProfile(os_api_level=30)
        res_perm = evaluate_triage(apk_perm, dev)
        warns_perm = [w for w in res_perm["warnings"] if "WARN_SCOPED_STORAGE_OBB" in w]
        self.assertEqual(len(warns_perm), 1)
        self.assertIn("Remediation: Adopt Storage Access Framework (SAF) / MediaStore API", warns_perm[0])

        # Scoped storage general warning must NOT be emitted for apps with targetSdk < 30
        apk_perm_29 = ApkMetadata(
            target_sdk=29,
            permissions=["android.permission.WRITE_EXTERNAL_STORAGE"],
        )
        res_perm_29 = evaluate_triage(apk_perm_29, dev)
        self.assertFalse(any("WARN_SCOPED_STORAGE_OBB" in w for w in res_perm_29["warnings"]))

        # Case B: Scoped storage paths in DEX
        apk_paths = ApkMetadata(
            target_sdk=30,
            accesses_scoped_storage_paths=True,
        )
        res_paths = evaluate_triage(apk_paths, dev)
        self.assertTrue(any("WARN_SCOPED_STORAGE_OBB" in w for w in res_paths["warnings"]))

        # Case C: Application bundles or references OBB
        apk_obb = ApkMetadata(
            target_sdk=30,
            has_obb=True,
        )
        res_obb = evaluate_triage(apk_obb, dev)
        self.assertTrue(any("WARN_SCOPED_STORAGE_OBB" in w for w in res_obb["warnings"]))

    def test_03_hidden_api_reflection(self):
        """Test 3: Hidden API reflection produces WARN_HIDDEN_API_REFLECTION with remediation text."""
        apk = ApkMetadata(
            target_sdk=28,
            hidden_api_reflections=["android.os.SystemProperties", "android/app/ActivityThread"],
        )
        dev = DeviceProfile(os_api_level=35)
        res = evaluate_triage(apk, dev)
        warns = [w for w in res["warnings"] if "WARN_HIDDEN_API_REFLECTION" in w]
        self.assertEqual(len(warns), 1)
        warn_text = warns[0]
        self.assertIn("android.os.SystemProperties", warn_text)
        self.assertIn("android/app/ActivityThread", warn_text)
        self.assertIn("Remediation:", warn_text)
        self.assertIn("Replace non-SDK reflection with public AndroidX/Jetpack APIs", warn_text)
        self.assertIn("HiddenApiBypass", warn_text)

    def test_04_cleartext_http_and_legacy_tls(self):
        """Test 4: Cleartext HTTP and legacy TLS produce WARN_CLEARTEXT_LEGACY_TLS with remediation text."""
        # Case A: Cleartext HTTP URL found
        apk_ct = ApkMetadata(
            target_sdk=28,
            has_cleartext_http=True,
        )
        dev = DeviceProfile(os_api_level=35)
        res_ct = evaluate_triage(apk_ct, dev)
        warns_ct = [w for w in res_ct["warnings"] if "WARN_CLEARTEXT_LEGACY_TLS" in w]
        self.assertEqual(len(warns_ct), 1)
        self.assertIn("Remediation: Enforce HTTPS using TLS 1.2+", warns_ct[0])
        self.assertIn('android:usesCleartextTraffic="true"', warns_ct[0])

        # Case B: Legacy TLS protocol references found
        apk_tls = ApkMetadata(
            target_sdk=28,
            legacy_tls_protocols=["TLSv1.0", "SSLv3"],
        )
        res_tls = evaluate_triage(apk_tls, dev)
        self.assertTrue(any("WARN_CLEARTEXT_LEGACY_TLS" in w for w in res_tls["warnings"]))

        # Case C: Explicitly declares usesCleartextTraffic="true"
        apk_uct = ApkMetadata(
            target_sdk=28,
            uses_cleartext_traffic=True,
        )
        res_uct = evaluate_triage(apk_uct, dev)
        self.assertTrue(any("WARN_CLEARTEXT_LEGACY_TLS" in w for w in res_uct["warnings"]))

        # Case D: target_sdk < 28 without network_security_config must NOT emit cleartext warning unless usesCleartextTraffic is False
        apk_legacy_sdk = ApkMetadata(
            target_sdk=22,
            uses_cleartext_traffic=None,
            has_network_security_config=False,
        )
        res_legacy_sdk = evaluate_triage(apk_legacy_sdk, dev)
        self.assertFalse(any("WARN_CLEARTEXT_LEGACY_TLS" in w for w in res_legacy_sdk["warnings"]))

        # Case E: target_sdk < 28 with uses_cleartext_traffic=False DOES emit warning
        apk_legacy_disabled = ApkMetadata(
            target_sdk=22,
            uses_cleartext_traffic=False,
        )
        res_legacy_disabled = evaluate_triage(apk_legacy_disabled, dev)
        self.assertTrue(any("WARN_CLEARTEXT_LEGACY_TLS" in w for w in res_legacy_disabled["warnings"]))

    def test_05_deprecated_permissions(self):
        """Test 5: Deprecated permissions produce WARN_DEPRECATED_PERMISSIONS with remediation text."""
        deprecated_list = list(DEPRECATED_PERMISSIONS.keys())
        apk = ApkMetadata(
            target_sdk=28,
            permissions=deprecated_list,
        )
        dev = DeviceProfile(os_api_level=35)
        res = evaluate_triage(apk, dev)
        warns = [w for w in res["warnings"] if "WARN_DEPRECATED_PERMISSIONS" in w]
        self.assertEqual(len(warns), 1)
        warn_text = warns[0]

        for perm, advice in DEPRECATED_PERMISSIONS.items():
            self.assertIn(perm, warn_text)
            self.assertIn(advice, warn_text)

    def test_06_full_apk_parsing_integration(self):
        """Test 6: Full APK parsing integration with manifest & DEX fixtures."""
        manifest = AxmlNode(tag="manifest")
        manifest.set_attr("package", "com.test.triage.coverage", ns="")

        uses_sdk = AxmlNode(tag="uses-sdk")
        uses_sdk.set_attr("minSdkVersion", 21)
        uses_sdk.set_attr("targetSdkVersion", 29)
        manifest.children.append(uses_sdk)

        perm1 = AxmlNode(tag="uses-permission")
        perm1.set_attr("name", "android.permission.WRITE_EXTERNAL_STORAGE")
        manifest.children.append(perm1)

        perm2 = AxmlNode(tag="uses-permission")
        perm2.set_attr("name", "android.permission.READ_PHONE_STATE")
        manifest.children.append(perm2)

        app = AxmlNode(tag="application")
        app.set_attr("usesCleartextTraffic", True)
        app.set_attr("networkSecurityConfig", "@xml/network_security_config")
        manifest.children.append(app)

        manifest_bytes = AxmlSurgeon.serialize(manifest)

        dex_content = (
            b"DEX\n035\x00"
            b"Class.forName(\"android.os.SystemProperties\")\x00"
            b"getMethod(\"get\", String.class)\x00"
            b"com/android/internal/os/RuntimeInit\x00"
            b"Android/data/com.test.app/files\x00"
            b"Environment.getExternalStorageDirectory\x00"
            b"http://insecure-api.example.com/v1/sync\x00"
            b"http://schemas.android.com/apk/res/android\x00"
            b"SSLv3\x00TLSv1.0\x00TrustAll\x00"
        )

        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            apk_path = tmp.name

        try:
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("AndroidManifest.xml", manifest_bytes)
                zf.writestr("classes.dex", dex_content)
                zf.writestr("assets/main.100.com.test.triage.coverage.obb", b"OBBDATA")

            meta = inspect_apk(apk_path)

            # Metadata extraction assertions
            self.assertEqual(meta.package_name, "com.test.triage.coverage")
            self.assertEqual(meta.target_sdk, 29)
            self.assertIn("android.permission.WRITE_EXTERNAL_STORAGE", meta.permissions)
            self.assertIn("android.permission.READ_PHONE_STATE", meta.permissions)
            self.assertTrue(meta.uses_cleartext_traffic)
            self.assertTrue(meta.has_network_security_config)
            self.assertTrue(meta.has_obb)
            self.assertTrue(meta.accesses_scoped_storage_paths)
            self.assertTrue(meta.has_cleartext_http)
            self.assertIn("android.os.SystemProperties", meta.hidden_api_reflections)
            self.assertIn("com/android/internal/", meta.hidden_api_reflections)
            self.assertTrue(any(p in meta.legacy_tls_protocols for p in ["SSLv3", "TLSv1.0", "TrustAll"]))

            # Triage evaluation assertions
            dev = DeviceProfile(os_api_level=35)
            res = evaluate_triage(meta, dev)

            warning_prefixes = [w.split(":")[0] for w in res["warnings"]]
            self.assertIn("WARN_SCOPED_STORAGE_OBB", warning_prefixes)
            self.assertIn("WARN_HIDDEN_API_REFLECTION", warning_prefixes)
            self.assertIn("WARN_CLEARTEXT_LEGACY_TLS", warning_prefixes)
            self.assertIn("WARN_DEPRECATED_PERMISSIONS", warning_prefixes)
        finally:
            if os.path.exists(apk_path):
                os.remove(apk_path)


if __name__ == "__main__":
    unittest.main()
