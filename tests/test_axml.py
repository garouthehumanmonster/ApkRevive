"""
test_axml.py - Tests AXML parsing, transformation, and strict idempotency AXML(N) == AXML(N+1).
"""

import unittest
from apkrevive.core.axml import AxmlSurgeon, AxmlNode


class TestAxml(unittest.TestCase):
    def setUp(self):
        # Create minimal synthetic manifest AST
        manifest = AxmlNode(tag="manifest")
        manifest.set_attr("package", "com.test.app", ns="")
        app = AxmlNode(tag="application")
        app.set_attr("hasCode", False)
        manifest.children.append(app)
        self.initial_bytes = AxmlSurgeon.serialize(manifest)

    def test_parse_and_serialize_roundtrip(self):
        node = AxmlSurgeon.parse(self.initial_bytes)
        self.assertEqual(node.tag, "manifest")
        app = node.find_child("application")
        self.assertIsNotNone(app)
        self.assertEqual(app.get_attr("hasCode").get_value(), False)

    def test_mutation(self):
        patched = AxmlSurgeon.patch_manifest(self.initial_bytes, ["SET_HAS_CODE_TRUE", "INJECT_USES_LIBRARY_APACHE_HTTP", "EXPAND_ASPECT_RATIO"])
        node = AxmlSurgeon.parse(patched)
        app = node.find_child("application")
        self.assertEqual(app.get_attr("hasCode").get_value(), True)
        self.assertEqual(app.get_attr("resizeableActivity").get_value(), True)
        self.assertIsNotNone(app.find_child("uses-library", "name", "org.apache.http.legacy"))
        self.assertIsNotNone(app.find_child("meta-data", "name", "android.max_aspect"))

    def test_idempotency(self):
        transforms = ["SET_HAS_CODE_TRUE", "INJECT_USES_LIBRARY_APACHE_HTTP", "EXPAND_ASPECT_RATIO"]
        opts = {"enable_60hz": True, "enable_cutout": True}
        pass1 = AxmlSurgeon.patch_manifest(self.initial_bytes, transforms, opts)
        pass2 = AxmlSurgeon.patch_manifest(pass1, transforms, opts)
        self.assertEqual(pass1, pass2, "AXML Surgeon failed strict idempotency: pass1 != pass2")


if __name__ == "__main__":
    unittest.main()
