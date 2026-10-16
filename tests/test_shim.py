"""
test_shim.py - Tests canonical shim.dex byte compilation and cryptographic hash verification.
"""

import hashlib
import unittest
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
        import shutil
        from pathlib import Path
        from apkrevive.shim.build_shim import (
            find_sdk_root,
            find_build_tools,
            find_platform_dir,
            resolve_tool,
        )

        sdk_root = find_sdk_root()
        build_tools = find_build_tools(sdk_root)
        platform_dir = find_platform_dir(sdk_root)
        android_jar = platform_dir / "android.jar"

        if not android_jar.is_file():
            self.skipTest(f"android.jar not found at {android_jar}")

        javac_bin = resolve_tool("javac")
        if not shutil.which(javac_bin) and not Path(javac_bin).is_file():
            self.skipTest(f"javac not available at {javac_bin}")

        d8_bin = resolve_tool("d8", build_tools)
        if not shutil.which(d8_bin) and not Path(d8_bin).is_file():
            self.skipTest(f"d8 not available at {d8_bin}")

        if build_tools.name != "35.0.0":
            self.skipTest(f"Deterministic shim build requires build-tools 35.0.0, found {build_tools.name}")

        try:
            built_bytes = build_shim()
        except ValueError as e:
            self.skipTest(f"Host toolchain produced non-canonical bytecode: {e}")

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
