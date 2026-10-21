"""
tests/test_dex_surgeon.py - Unit tests for dex_surgeon.py (Engine 2).
"""

import io
import os
import tempfile
import unittest
import zipfile

from apkrevive.core.axml import AxmlSurgeon, AxmlNode
from apkrevive.core.dex_surgeon import (
    CANONICAL_PROVIDER_CLASS,
    LEGACY_PROVIDER_CLASS,
    load_canonical_shim,
    is_shim_dex,
    scan_apk_dex_entries,
    has_shim_in_apk,
    get_next_multidex_name,
    inject_dex_shim,
)


def make_dummy_apk(dex_files: list[str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        root = AxmlNode(tag="manifest")
        root.set_attr("package", "com.example.testapp", ns="")
        app = AxmlNode(tag="application")
        root.children.append(app)
        zf.writestr("AndroidManifest.xml", AxmlSurgeon.serialize(root))

        for name in dex_files:
            zf.writestr(name, b"dex\n035\x00dummy_bytecode_data")
    return buf.getvalue()


class TestDexSurgeon(unittest.TestCase):
    def test_load_canonical_shim_integrity(self):
        shim = load_canonical_shim()
        self.assertTrue(len(shim) > 0)
        self.assertTrue(shim.startswith(b"dex\n"))
        self.assertTrue(is_shim_dex(shim))

    def test_is_shim_dex_recognition(self):
        shim = load_canonical_shim()
        self.assertTrue(is_shim_dex(shim))
        dummy = b"dex\n035\x00random_bytes_without_shim"
        self.assertFalse(is_shim_dex(dummy))
        short_bytes = b"dex"
        self.assertFalse(is_shim_dex(short_bytes))

    def test_get_next_multidex_name(self):
        self.assertEqual(get_next_multidex_name([]), "classes.dex")
        self.assertEqual(get_next_multidex_name(["classes.dex"]), "classes2.dex")
        self.assertEqual(get_next_multidex_name(["classes.dex", "classes2.dex"]), "classes3.dex")
        self.assertEqual(get_next_multidex_name(["classes.dex", "classes2.dex", "classes3.dex"]), "classes4.dex")
        # Non-contiguous
        self.assertEqual(get_next_multidex_name(["classes.dex", "classes5.dex"]), "classes6.dex")
        # Missing primary classes.dex
        self.assertEqual(get_next_multidex_name(["classes2.dex"]), "classes.dex")

    def test_inject_dex_shim_clean_and_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            in_apk = os.path.join(tmp_dir, "input.apk")
            out_apk = os.path.join(tmp_dir, "output.apk")
            out_apk2 = os.path.join(tmp_dir, "output2.apk")

            with open(in_apk, "wb") as f:
                f.write(make_dummy_apk(["classes.dex"]))

            # Initial injection
            injected, dex_name = inject_dex_shim(in_apk, out_apk)
            self.assertTrue(injected)
            self.assertEqual(dex_name, "classes2.dex")

            # Check output APK entries
            dex_entries = scan_apk_dex_entries(out_apk)
            self.assertEqual(dex_entries, ["classes.dex", "classes2.dex"])
            self.assertTrue(has_shim_in_apk(out_apk))

            # Idempotency check: injecting again into out_apk
            injected2, reason = inject_dex_shim(out_apk, out_apk2)
            self.assertFalse(injected2)
            self.assertEqual(reason, "ALREADY_PRESENT")

    def test_axml_provider_registration_attributes(self):
        root = AxmlNode(tag="manifest")
        root.set_attr("package", "com.example.testapp", ns="")
        app = AxmlNode(tag="application")
        app.set_attr("hasCode", False)
        root.children.append(app)
        raw_manifest = AxmlSurgeon.serialize(root)

        patched = AxmlSurgeon.patch_manifest(raw_manifest, inject_shim=True)
        parsed = AxmlSurgeon.parse(patched)
        app_node = parsed.find_child("application")
        self.assertIsNotNone(app_node)

        # Invariant: hasCode forced to True
        has_code_attr = app_node.get_attr("hasCode")
        self.assertIsNotNone(has_code_attr)
        self.assertTrue(has_code_attr.get_value())

        # Provider registered
        prov_node = app_node.find_child("provider")
        self.assertIsNotNone(prov_node)

        name_attr = prov_node.get_attr("name")
        self.assertIsNotNone(name_attr)
        self.assertIn(name_attr.get_value(), (CANONICAL_PROVIDER_CLASS, LEGACY_PROVIDER_CLASS))

        auth_attr = prov_node.get_attr("authorities")
        self.assertIsNotNone(auth_attr)
        self.assertEqual(auth_attr.get_value(), "com.example.testapp.apkreviveinit")

        order_attr = prov_node.get_attr("initOrder")
        self.assertIsNotNone(order_attr)
        self.assertEqual(order_attr.get_value(), 999999999)

        export_attr = prov_node.get_attr("exported")
        self.assertIsNotNone(export_attr)
        self.assertFalse(export_attr.get_value())


if __name__ == "__main__":
    unittest.main()
