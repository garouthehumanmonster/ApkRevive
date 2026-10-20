"""
test_axml.py - Tests AXML parsing, transformation, and strict idempotency AXML(N) == AXML(N+1).
"""

import unittest
import struct
from apkrevive.core.axml import (
    AxmlSurgeon,
    AxmlNode,
    AxmlAttribute,
    UnsupportedAxmlChunk,
    ANDROID_NS,
)


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

    def test_axml_string_attr_without_raw_does_not_dangle(self):
        """Attribute with data_type=0x03 and raw_value=None emits 0xFFFFFFFF in serialized bytes."""
        manifest = AxmlNode(tag="manifest")
        manifest.set_attr("package", "com.test.app", ns="")
        app = AxmlNode(tag="application")
        app.attributes.append(AxmlAttribute(
            ns="",
            name="custom_empty_string",
            raw_value=None,
            data_type=0x03,
            data=0x1234,  # previously leaked into serialized data_val
            resource_id=0,
        ))
        manifest.children.append(app)
        raw = AxmlSurgeon.serialize(manifest)

        parsed = AxmlSurgeon.parse(raw)
        parsed_app = parsed.find_child("application")
        self.assertIsNotNone(parsed_app)
        attr = parsed_app.get_attr("custom_empty_string")
        self.assertIsNotNone(attr)
        self.assertEqual(attr.data_type, 0x03)
        self.assertIsNone(attr.raw_value)
        self.assertEqual(attr.data, 0xFFFFFFFF)
        self.assertIn(b"\xff\xff\xff\xff\x08\x00\x00\x03\xff\xff\xff\xff", raw)

    def test_axml_preserves_extra_namespaces(self):
        """Parse AXML with xmlns:tools or custom namespace, serialize, verify both namespaces survive and are present in output."""
        manifest = AxmlNode(tag="manifest")
        manifest.set_attr("package", "com.test.app", ns="")
        tools_uri = "http://schemas.android.com/tools"
        manifest._orig_namespaces = [("android", ANDROID_NS), ("tools", tools_uri)]
        app = AxmlNode(tag="application")
        app.attributes.append(AxmlAttribute(
            ns=tools_uri,
            name="tools:targetApi",
            raw_value="31",
            data_type=0x03,
            data=0,
            resource_id=0,
        ))
        manifest.children.append(app)

        raw = AxmlSurgeon.serialize(manifest)
        parsed = AxmlSurgeon.parse(raw)
        self.assertEqual(len(parsed._orig_namespaces), 2)
        self.assertEqual(parsed._orig_namespaces[0], ("android", ANDROID_NS))
        self.assertEqual(parsed._orig_namespaces[1], ("tools", tools_uri))

        # Clear raw source cache to force re-serialization from AST
        parsed._raw_source_bytes = None
        re_serialized = AxmlSurgeon.serialize(parsed)
        re_parsed = AxmlSurgeon.parse(re_serialized)
        self.assertEqual(len(re_parsed._orig_namespaces), 2)
        self.assertEqual(re_parsed._orig_namespaces[0], ("android", ANDROID_NS))
        self.assertEqual(re_parsed._orig_namespaces[1], ("tools", tools_uri))
        self.assertEqual(raw, re_serialized)

    def test_axml_rejects_unknown_chunk(self):
        """Inject unknown chunk (e.g. 0x0104 CDATA or 0x9999), verify parse() raises UnsupportedAxmlChunk."""
        cdata_chunk = struct.pack("<HHI II", 0x0104, 16, 16, 1, 0xFFFFFFFF)
        _, _, sp_size = struct.unpack_from("<HHI", self.initial_bytes, 8)
        insert_offset = 8 + sp_size
        corrupted = (
            self.initial_bytes[:insert_offset]
            + cdata_chunk
            + self.initial_bytes[insert_offset:]
        )
        new_size = len(corrupted)
        corrupted = struct.pack("<HHI", 0x0003, 8, new_size) + corrupted[8:]

        with self.assertRaises(UnsupportedAxmlChunk) as ctx:
            AxmlSurgeon.parse(corrupted)
        self.assertIn("Unsupported AXML chunk type: 0x0104", str(ctx.exception))
        self.assertIsInstance(ctx.exception, ValueError)

        unknown_chunk = struct.pack("<HHI", 0x9999, 8, 8)
        corrupted9999 = (
            self.initial_bytes[:insert_offset]
            + unknown_chunk
            + self.initial_bytes[insert_offset:]
        )
        corrupted9999 = struct.pack("<HHI", 0x0003, 8, len(corrupted9999)) + corrupted9999[8:]
        with self.assertRaises(UnsupportedAxmlChunk) as ctx:
            AxmlSurgeon.parse(corrupted9999)
        self.assertIn("Unsupported AXML chunk type: 0x9999", str(ctx.exception))

    def test_axml_declared_size_exceeds_buffer(self):
        """file_size > len(data) raises ValueError."""
        corrupted = bytearray(self.initial_bytes)
        struct.pack_into("<I", corrupted, 4, len(corrupted) + 50)
        with self.assertRaises(ValueError) as ctx:
            AxmlSurgeon.parse(bytes(corrupted))
        self.assertIn("exceeds buffer", str(ctx.exception))

    def test_axml_truncated_attributes_raises(self):
        """truncated attribute chunk raises ValueError."""
        offset = 8
        corrupted = bytearray(self.initial_bytes)
        while offset < len(corrupted):
            c_type, c_hsize, c_size = struct.unpack_from("<HHI", corrupted, offset)
            if c_type == 0x0102:
                struct.pack_into("<H", corrupted, offset + 28, 50)
                break
            offset += c_size

        with self.assertRaises(ValueError) as ctx:
            AxmlSurgeon.parse(bytes(corrupted))
        self.assertIn("Truncated AXML attribute list", str(ctx.exception))

    def test_axml_aspect_ratio_overwrites_restrictive(self):
        """Manifest with android.max_aspect="1.8" gets updated to "2.5"."""
        manifest = AxmlNode(tag="manifest")
        manifest.set_attr("package", "com.test.app", ns="")
        app = AxmlNode(tag="application")
        app.set_attr("hasCode", True)
        aspect_meta = AxmlNode(tag="meta-data")
        aspect_meta.set_attr("name", "android.max_aspect")
        aspect_meta.set_attr("value", "1.8")
        app.children.append(aspect_meta)
        manifest.children.append(app)
        raw = AxmlSurgeon.serialize(manifest)

        patched = AxmlSurgeon.patch_manifest(raw, ["EXPAND_ASPECT_RATIO"])
        parsed = AxmlSurgeon.parse(patched)
        app_parsed = parsed.find_child("application")
        self.assertIsNotNone(app_parsed)
        self.assertEqual(app_parsed.get_attr("resizeableActivity").get_value(), True)
        self.assertEqual(app_parsed.get_attr("maxAspectRatio").get_value(), "2.5")

        meta = app_parsed.find_child("meta-data", "name", "android.max_aspect")
        self.assertIsNotNone(meta)
        self.assertEqual(meta.get_attr("value").get_value(), "2.5")

        meta_count = sum(
            1 for ch in app_parsed.children
            if ch.tag == "meta-data" and any(
                (a.name in ("name", "android:name") or a.name.split(":")[-1] == "name")
                and (a.raw_value == "android.max_aspect" or a.get_value() == "android.max_aspect")
                for a in ch.attributes
            )
        )
        self.assertEqual(meta_count, 1)

    def test_axml_fuzz_roundtrip(self):
        """Hypothesis test asserting parse(serialize(parse(x))) stability."""
        try:
            from hypothesis import given, strategies as st, settings
            has_hyp = True
        except ImportError:
            has_hyp = False

        if has_hyp:
            attr_names = ["hasCode", "name", "value", "authorities", "exported", "resizeableActivity", "maxAspectRatio"]

            @settings(max_examples=50, deadline=None)
            @given(
                package_name=st.from_regex(r"[a-z]{3,8}\.[a-z]{3,8}\.[a-z]{3,8}", fullmatch=True),
                attr_name=st.sampled_from(attr_names),
                attr_val=st.one_of(
                    st.booleans(),
                    st.integers(min_value=0, max_value=100000),
                    st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789.", min_size=1, max_size=20),
                ),
                has_tools_ns=st.booleans(),
            )
            def _fuzz_ast(package_name, attr_name, attr_val, has_tools_ns):
                manifest = AxmlNode(tag="manifest")
                manifest.set_attr("package", package_name, ns="")
                if has_tools_ns:
                    manifest._orig_namespaces = [("android", ANDROID_NS), ("tools", "http://schemas.android.com/tools")]
                app = AxmlNode(tag="application")
                app.set_attr(attr_name, attr_val)
                manifest.children.append(app)

                raw1 = AxmlSurgeon.serialize(manifest)
                p1 = AxmlSurgeon.parse(raw1)
                p1._raw_source_bytes = None  # Force full serialization
                raw2 = AxmlSurgeon.serialize(p1)
                p2 = AxmlSurgeon.parse(raw2)
                p2._raw_source_bytes = None
                raw3 = AxmlSurgeon.serialize(p2)

                self.assertEqual(raw2, raw3)
                self.assertEqual(p1.tree_signature(), p2.tree_signature())

            _fuzz_ast()
        else:
            for val in [True, False, 42, "hello.world"]:
                manifest = AxmlNode(tag="manifest")
                manifest.set_attr("package", "com.example.app", ns="")
                app = AxmlNode(tag="application")
                app.set_attr("hasCode", val)
                manifest.children.append(app)

                raw1 = AxmlSurgeon.serialize(manifest)
                p1 = AxmlSurgeon.parse(raw1)
                p1._raw_source_bytes = None
                raw2 = AxmlSurgeon.serialize(p1)
                p2 = AxmlSurgeon.parse(raw2)
                p2._raw_source_bytes = None
                raw3 = AxmlSurgeon.serialize(p2)

                self.assertEqual(raw2, raw3)
                self.assertEqual(p1.tree_signature(), p2.tree_signature())


if __name__ == "__main__":
    unittest.main()
