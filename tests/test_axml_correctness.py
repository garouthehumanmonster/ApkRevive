"""
test_axml_correctness.py - Phase 2 AXML Round-Trip & Verification tests.
"""

import glob
import os
import shutil
import subprocess
import tempfile
import zipfile
import pytest

from apkrevive.core.axml import AxmlSurgeon


def test_canary_manifests_unmutated_roundtrip():
    """
    Test that for every canary APK manifest in canaries/*.apk,
    parsing and then serializing without mutation yields exact byte-identical output:
    AxmlSurgeon.serialize(AxmlSurgeon.parse(raw)) == raw.
    """
    canary_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "canaries", "build")
    canary_apks = glob.glob(os.path.join(canary_dir, "*.apk"))
    assert len(canary_apks) > 0, "No canary APKs found in canaries/ directory"

    checked_count = 0
    for apk_path in canary_apks:
        with zipfile.ZipFile(apk_path, "r") as zf:
            if "AndroidManifest.xml" in zf.namelist():
                raw = zf.read("AndroidManifest.xml")
                parsed = AxmlSurgeon.parse(raw)
                serialized = AxmlSurgeon.serialize(parsed)
                assert serialized == raw, (
                    f"Round-trip failed for {os.path.basename(apk_path)}: "
                    f"expected {len(raw)} bytes, got {len(serialized)} bytes"
                )
                checked_count += 1

    assert checked_count >= 16, f"Expected at least 16 canaries to be checked, found {checked_count}"


def find_aapt2():
    which_cmd = shutil.which("aapt2")
    if which_cmd:
        return which_cmd
    sdk_roots = [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk"),
        os.path.expanduser("~/Library/Android/sdk"),
        os.path.expanduser("~/Android/Sdk"),
    ]
    for root in sdk_roots:
        if not root or not os.path.exists(root):
            continue
        build_tools_dir = os.path.join(root, "build-tools")
        if os.path.exists(build_tools_dir):
            versions = sorted(os.listdir(build_tools_dir), reverse=True)
            for ver in versions:
                for candidate in ["aapt2.exe", "aapt2"]:
                    cand_path = os.path.join(build_tools_dir, ver, candidate)
                    if os.path.exists(cand_path):
                        return cand_path
    return None


def test_mutated_manifest_aapt2_dump():
    """
    Test comparing mutated output against aapt2 dump xmltree:
    Runs aapt2 dump xmltree on the mutated APK/manifest, asserts exit code is 0,
    and verifies injected elements (uses-library, pageSizeCompat) appear in the dumped tree.
    """
    aapt2 = find_aapt2()
    if not aapt2:
        pytest.skip("aapt2 not available")

    canary_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "canaries", "build")
    canary_apks = sorted(glob.glob(os.path.join(canary_dir, "*.apk")))
    if not canary_apks:
        pytest.skip("No canary APKs found")

    with zipfile.ZipFile(canary_apks[0], "r") as zf:
        raw_manifest = zf.read("AndroidManifest.xml")

    mutated = AxmlSurgeon.patch_manifest(
        raw_manifest,
        ["INJECT_USES_LIBRARY_APACHE_HTTP", "PAGE_SIZE_COMPAT"],
    )

    with tempfile.TemporaryDirectory() as tmp_dir:
        test_apk = os.path.join(tmp_dir, "test_mutated.apk")
        with zipfile.ZipFile(test_apk, "w") as zout:
            zout.writestr("AndroidManifest.xml", mutated)

        res = subprocess.run(
            [aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", test_apk],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert res.returncode == 0, f"aapt2 dump xmltree failed (code {res.returncode}): {res.stderr}"
        output = res.stdout
        assert "org.apache.http.legacy" in output or "uses-library" in output, (
            "Expected uses-library org.apache.http.legacy in aapt2 dump output"
        )
        assert "pageSizeCompat" in output, (
            "Expected pageSizeCompat in aapt2 dump output"
        )
