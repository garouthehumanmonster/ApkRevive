"""
test_axml_correctness.py - Phase 2 AXML Round-Trip & Verification tests.
"""

import glob
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile
import pytest

from apkrevive.core.axml import AxmlSurgeon, AxmlNode, AxmlAttribute


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


def test_unknown_attribute_fails_closed():
    """Verifies that an unknown android: attribute without a resource ID raises ValueError."""
    node = AxmlNode(tag="application")
    node.attributes.append(AxmlAttribute(
        ns="http://schemas.android.com/apk/res/android",
        name="android:completelyUnknownNonexistentAttr",
        raw_value="true",
        data_type=0x12,
        data=0xFFFFFFFF,
        resource_id=0
    ))
    manifest = AxmlNode(tag="manifest")
    manifest.children.append(node)
    with pytest.raises(ValueError, match="Unknown Android manifest attribute"):
        AxmlSurgeon.serialize(manifest)


def parse_aapt2_tree(lines):
    root = None
    stack = []
    for line in lines:
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if stripped.startswith("E: "):
            tag = stripped.split()[1]
            node = {"tag": tag, "attrs": {}, "children": []}
            while stack and stack[-1][0] >= indent:
                stack.pop()
            if stack:
                stack[-1][1]["children"].append(node)
            else:
                root = node
            stack.append((indent, node))
        elif stripped.startswith("A: ") and stack:
            parts = stripped[3:].split("=", 1)
            attr_name = parts[0].strip()
            attr_val = parts[1].strip() if len(parts) > 1 else ""
            stack[-1][1]["attrs"][attr_name] = attr_val
    return root


def test_corpus_manifest_aapt2_dump_xmltree_diff():
    """
    Diffs aapt2 dump xmltree of original vs revived manifest for every corpus APK.
    Asserts exit code 0 and verifies that only expected transformations differ.
    """
    aapt2 = find_aapt2()
    if not aapt2:
        pytest.skip("aapt2 not available")

    corpus_dir = Path(__file__).resolve().parent / "corpus" / "apks"
    corpus_apks = sorted(corpus_dir.glob("*.apk"))
    if not corpus_apks:
        pytest.skip("No corpus APKs found in tests/corpus/apks")

    for apk_path in corpus_apks:
        with zipfile.ZipFile(apk_path, "r") as zf:
            orig_manifest = zf.read("AndroidManifest.xml")

        patched_manifest = AxmlSurgeon.patch_manifest(
            orig_manifest,
            ["INJECT_USES_LIBRARY_APACHE_HTTP"],
            options={"bump_target_sdk": 24, "enable_60hz": True}
        )

        with tempfile.TemporaryDirectory() as td:
            apk_orig = os.path.join(td, "orig.apk")
            apk_revived = os.path.join(td, "revived.apk")

            with zipfile.ZipFile(apk_path, "r") as zin, zipfile.ZipFile(apk_orig, "w") as zout:
                for item in zin.infolist():
                    zout.writestr(item, zin.read(item.filename))

            with zipfile.ZipFile(apk_path, "r") as zin, zipfile.ZipFile(apk_revived, "w") as zout:
                for item in zin.infolist():
                    if item.filename == "AndroidManifest.xml":
                        zout.writestr(item, patched_manifest)
                    else:
                        zout.writestr(item, zin.read(item.filename))

            res1 = subprocess.run([aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", apk_orig], capture_output=True, text=True)
            res2 = subprocess.run([aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", apk_revived], capture_output=True, text=True)

            assert res1.returncode == 0, f"aapt2 failed on original {apk_path.name}: {res1.stderr}"
            assert res2.returncode == 0, f"aapt2 failed on revived {apk_path.name}: {res2.stderr}"

            r1 = parse_aapt2_tree(res1.stdout.splitlines())
            r2 = parse_aapt2_tree(res2.stdout.splitlines())

            assert r1 is not None and r2 is not None
            assert r1["tag"] == r2["tag"] == "manifest"

            app1 = [c for c in r1["children"] if c["tag"] == "application"][0]
            app2 = [c for c in r2["children"] if c["tag"] == "application"][0]

            # Exactly 3 added elements inside <application>: uses-library, meta-data, provider
            assert len(app2["children"]) == len(app1["children"]) + 3, (
                f"Expected exactly 3 added children in <application> for {apk_path.name}"
            )

            # Assert added children are the expected transforms
            added_tags = [c["tag"] for c in app2["children"][len(app1["children"]):]]
            assert added_tags == ["uses-library", "meta-data", "provider"], (
                f"Unexpected added tags in {apk_path.name}: {added_tags}"
            )

            # Assert targetSdkVersion was bumped to 24 in uses-sdk
            uses_sdk2 = [c for c in r2["children"] if c["tag"] == "uses-sdk"]
            assert len(uses_sdk2) > 0
            target_sdk_attr = [v for k, v in uses_sdk2[0]["attrs"].items() if "targetSdkVersion" in k]
            assert any("24" in v for v in target_sdk_attr), f"targetSdkVersion not bumped to 24 in {apk_path.name}"

