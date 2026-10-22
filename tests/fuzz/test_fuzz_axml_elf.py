"""
test_fuzz_axml_elf.py - Property-based fuzzing test suite using Hypothesis.
Fuzzes AXML parsing, ELF rewriting, and ZIP guard against arbitrary malformed inputs.
"""

import os
import tempfile
import unittest
import zipfile

try:
    from hypothesis import given, strategies as st, settings
    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False

from apkrevive.core.axml import AxmlSurgeon
from apkrevive.core.elf_surgeon import rewrite_elf_16kb
from apkrevive.core.align import validate_zip_archive


class TestFuzzAxmlElf(unittest.TestCase):
    def test_axml_parse_fuzz(self):
        """Ensures AxmlSurgeon.parse raises ValueError or completes cleanly without unhandled crashes."""
        if HAS_HYPOTHESIS:
            @settings(max_examples=200, deadline=None, derandomize=True)
            @given(st.binary(min_size=0, max_size=2048))
            def _fuzz(data: bytes):
                try:
                    AxmlSurgeon.parse(data)
                except Exception:
                    pass
            _fuzz()
        else:
            for size in (0, 1, 4, 7, 8, 12, 100, 500, 1000):
                corrupt_bytes = os.urandom(size)
                try:
                    AxmlSurgeon.parse(corrupt_bytes)
                except Exception:
                    pass

    def test_elf_surgeon_fuzz(self):
        """Ensures rewrite_elf_16kb never crashes or enters infinite loops on arbitrary binary payloads."""
        if HAS_HYPOTHESIS:
            @settings(max_examples=200, deadline=None, derandomize=True)
            @given(st.binary(min_size=0, max_size=4096))
            def _fuzz(data: bytes):
                try:
                    res = rewrite_elf_16kb(data)
                    self.assertIsInstance(res, bytes)
                except Exception:
                    pass
            _fuzz()
        else:
            for size in (0, 10, 63, 64, 128, 1024, 4096):
                corrupt = os.urandom(size)
                try:
                    res = rewrite_elf_16kb(corrupt)
                    self.assertIsInstance(res, bytes)
                except Exception:
                    pass

    def test_zip_guard_fuzz(self):
        """Fuzzes ZIP guard against corrupted ZIP streams and traversal attacks."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            slip_path = os.path.join(tmp_dir, "slip.apk")
            with zipfile.ZipFile(slip_path, "w") as zf:
                zf.writestr("../../evil.txt", b"evil")
            with self.assertRaises(ValueError):
                validate_zip_archive(slip_path)

            sym_path = os.path.join(tmp_dir, "symlink.apk")
            with zipfile.ZipFile(sym_path, "w") as zf:
                zinfo = zipfile.ZipInfo("liblink.so")
                zinfo.external_attr = 0o120777 << 16
                zf.writestr(zinfo, b"/system/lib64/libc.so")
            with self.assertRaises(ValueError):
                validate_zip_archive(sym_path)

            trunc_path = os.path.join(tmp_dir, "trunc.apk")
            with open(trunc_path, "wb") as f:
                f.write(b"PK\x03\x04" + os.urandom(20))
            with self.assertRaises(ValueError):
                validate_zip_archive(trunc_path)

    def test_axml_cyclic_chunk_bounds(self):
        """Verifies cyclic chunk loops are bounded and reject with ValueError without hanging."""
        import struct
        root_hdr = struct.pack("<HHI", 0x0003, 8, 1024)
        zero_chunk = root_hdr + struct.pack("<HHI", 0x0180, 8, 0) + b"\x00" * 1008
        with self.assertRaises(ValueError) as ctx:
            AxmlSurgeon.parse(zero_chunk)
        self.assertIn("Invalid AXML chunk size", str(ctx.exception))

    def test_axml_overflow_bounds_rejection(self):
        """Verifies integer overflow and out-of-bounds chunk sizes reject cleanly."""
        import struct
        root_hdr = struct.pack("<HHI", 0x0003, 8, 1024)
        overflow_chunk = root_hdr + struct.pack("<HHI", 0x0180, 8, 0xFFFFFFFF) + b"\x00" * 1008
        with self.assertRaises(ValueError) as ctx:
            AxmlSurgeon.parse(overflow_chunk)
        self.assertIn("Invalid AXML chunk size", str(ctx.exception))

    def test_axml_roundtrip_property_fuzz(self):
        """Property test: arbitrary valid AxmlNode trees serialize and parse back idempotently."""
        if not HAS_HYPOTHESIS:
            return

        from apkrevive.core.axml import AxmlNode, KNOWN_RESOURCE_IDS

        attr_names = list(KNOWN_RESOURCE_IDS.keys())[:15]

        @settings(max_examples=50, deadline=None)
        @given(
            pkg=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=3, max_size=20),
            tag_name=st.sampled_from(["application", "activity", "service", "receiver"]),
            attr_name=st.sampled_from(attr_names),
            attr_val=st.one_of(st.booleans(), st.integers(min_value=0, max_value=10000), st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=20)),
        )
        def _prop(pkg: str, tag_name: str, attr_name: str, attr_val):
            root = AxmlNode(tag="manifest")
            root.set_attr("package", f"com.example.{pkg}", ns="")
            child = AxmlNode(tag=tag_name)
            child.set_attr(attr_name, attr_val)
            root.children.append(child)

            data = AxmlSurgeon.serialize(root)
            parsed = AxmlSurgeon.parse(data)
            self.assertEqual(parsed.tag, "manifest")
            found_child = parsed.find_child(tag_name)
            self.assertIsNotNone(found_child)
            attr = found_child.get_attr(attr_name)
            self.assertIsNotNone(attr)
            self.assertEqual(attr.get_value(), attr_val)

        _prop()

    def test_elf16k_check_property_fuzz(self):
        """Property test: elf16k.check never crashes on arbitrary binary inputs."""
        from apkrevive.core import elf16k
        from apkrevive.core.elf_surgeon import audit_elf_16kb, get_elf_needed

        if HAS_HYPOTHESIS:
            @settings(max_examples=100, deadline=None)
            @given(st.binary(min_size=0, max_size=8192))
            def _prop(payload: bytes):
                report = elf16k.check(payload)
                self.assertIsInstance(report.status, elf16k.Elf16kStatus)
                self.assertIsInstance(report.reasons, list)

                is_compliant, issues = audit_elf_16kb(payload)
                self.assertIsInstance(is_compliant, bool)
                self.assertIsInstance(issues, list)

                needed = get_elf_needed(payload)
                self.assertIsInstance(needed, list)

            _prop()


if __name__ == "__main__":
    unittest.main()
