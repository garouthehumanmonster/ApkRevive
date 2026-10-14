"""
test_shim.py - Tests canonical shim.dex byte compilation and cryptographic hash verification.
"""

import hashlib
import unittest
from pathlib import Path
from apkrevive.shim.build_shim import build_shim, CANONICAL_SHIM_SHA256, SHIM_DEX_PATH


class TestShim(unittest.TestCase):
    def test_committed_shim_sha256(self):
        self.assertTrue(SHIM_DEX_PATH.exists(), f"shim.dex not found at {SHIM_DEX_PATH}")
        content = SHIM_DEX_PATH.read_bytes()
        actual_hash = hashlib.sha256(content).hexdigest()
        self.assertEqual(
            actual_hash,
            CANONICAL_SHIM_SHA256,
            f"Committed shim.dex SHA256 mismatch. Expected {CANONICAL_SHIM_SHA256}, got {actual_hash}"
        )

    def test_build_shim_deterministic(self):
        built_bytes = build_shim()
        committed_bytes = SHIM_DEX_PATH.read_bytes()
        self.assertEqual(
            built_bytes,
            committed_bytes,
            "build_shim() output does not match committed shim.dex byte-for-byte"
        )
        actual_hash = hashlib.sha256(built_bytes).hexdigest()
        self.assertEqual(actual_hash, CANONICAL_SHIM_SHA256)


if __name__ == "__main__":
    unittest.main()
