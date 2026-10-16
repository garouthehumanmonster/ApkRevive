"""
test_dex_trampoline.py - Tests Dalvik multi-dex trampoline injector and header verification.
"""

import struct
import unittest

from apkrevive.core.dex_trampoline import (
    patch_primary_dex_trampoline,
    verify_dex_checksums,
    recalculate_dex_checksums,
    DALVIK_TRAMPOLINE_TAG,
)


def make_minimal_dex() -> bytes:
    """Builds a minimal valid DEX 035 file of 112 bytes."""
    buf = bytearray(112)
    buf[:8] = b"dex\n035\x00"
    struct.pack_into("<I", buf, 0x20, 112)       # file_size
    struct.pack_into("<I", buf, 0x24, 112)       # header_size
    struct.pack_into("<I", buf, 0x28, 0x12345678) # endian_tag
    struct.pack_into("<I", buf, 0x68, 0)         # data_size
    struct.pack_into("<I", buf, 0x6C, 112)       # data_off
    recalculate_dex_checksums(buf)
    return bytes(buf)


class TestDexTrampoline(unittest.TestCase):
    def test_minimal_dex_checksum_verification(self):
        dex = make_minimal_dex()
        self.assertTrue(verify_dex_checksums(dex))

    def test_patch_primary_dex_trampoline(self):
        dex = make_minimal_dex()
        patched = patch_primary_dex_trampoline(dex)

        self.assertIn(DALVIK_TRAMPOLINE_TAG, patched)

        new_file_size = struct.unpack_from("<I", patched, 0x20)[0]
        self.assertEqual(new_file_size, len(patched))
        self.assertTrue(verify_dex_checksums(patched))

    def test_idempotent_patching(self):
        dex = make_minimal_dex()
        pass1 = patch_primary_dex_trampoline(dex)
        pass2 = patch_primary_dex_trampoline(pass1)
        self.assertEqual(pass1, pass2, "Trampoline injection must be idempotent")

    def test_corrupt_header_rejection(self):
        with self.assertRaises(ValueError):
            patch_primary_dex_trampoline(b"NOT_A_DEX_FILE")

        with self.assertRaises(ValueError):
            patch_primary_dex_trampoline(b"dex\n035\x00\x00\x00")


if __name__ == "__main__":
    unittest.main()
