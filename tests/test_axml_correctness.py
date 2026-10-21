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


@pytest.mark.integration
def test_canary_manifests_unmutated_roundtrip():
    """
    Test that for every canary APK manifest in canaries/*.apk,
    parsing and then serializing without mutation yields exact byte-identical output:
    AxmlSurgeon.serialize(AxmlSurgeon.parse(raw)) == raw.
    """
    canary_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "canaries", "build")
    canary_apks = glob.glob(os.path.join(canary_dir, "*.apk"))
    if not canary_apks:
        if os.environ.get("APKREVIVE_REQUIRE_ARTIFACTS") == "1":
            pytest.fail("Required artifacts missing: no canary APKs found in canaries/build. Run 'python canaries/build_canaries.py'.")
        pytest.skip("No canary APKs found in canaries/build. Run 'python canaries/build_canaries.py'.")

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
        "/usr/local/lib/android/sdk",
        "/usr/lib/android-sdk",
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


@pytest.mark.integration
def test_mutated_manifest_aapt2_dump():
    """
    Test comparing mutated output against aapt2 dump xmltree:
    Runs aapt2 dump xmltree on the mutated APK/manifest, asserts exit code is 0,
    and verifies injected elements (uses-library, pageSizeCompat) appear in the dumped tree.
    """
    aapt2 = find_aapt2()
    if not aapt2:
        if os.environ.get("APKREVIVE_REQUIRE_ARTIFACTS") == "1":
            pytest.fail("Required tool missing: aapt2 not available on PATH or Android SDK build-tools.")
        pytest.skip("aapt2 not available")

    canary_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "canaries", "build")
    canary_apks = sorted(glob.glob(os.path.join(canary_dir, "*.apk")))
    if not canary_apks:
        if os.environ.get("APKREVIVE_REQUIRE_ARTIFACTS") == "1":
            pytest.fail("Required artifacts missing: no canary APKs found in canaries/build.")
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


@pytest.mark.integration
def test_corpus_manifest_aapt2_dump_xmltree_diff():
    """
    Diffs aapt2 dump xmltree of original vs revived manifest for every corpus APK.
    Asserts exit code 0 and verifies that only expected transformations differ.
    """
    aapt2 = find_aapt2()
    if not aapt2:
        if os.environ.get("APKREVIVE_REQUIRE_ARTIFACTS") == "1":
            pytest.fail("Required tool missing: aapt2 not available.")
        pytest.skip("aapt2 not available")

    corpus_dir = Path(__file__).resolve().parent / "corpus" / "apks"
    corpus_apks = sorted(corpus_dir.glob("*.apk"))
    if not corpus_apks:
        if os.environ.get("APKREVIVE_REQUIRE_ARTIFACTS") == "1":
            pytest.fail("Required artifacts missing: no corpus APKs found in tests/corpus/apks. Run 'python scripts/download_corpus.py'.")
        pytest.skip("No corpus APKs found in tests/corpus/apks. Run 'python scripts/download_corpus.py'.")

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


def test_strictly_ascending_resource_ids_all_corpus_and_canaries_and_resource_only():
    """
    Assert that for every corpus APK and every canary, after patching,
    every element's resource-ID attributes are strictly ascending.
    Includes a resource-only (hasCode=false) case that must still work after the fix.
    """
    def check_node_ascending(node: AxmlNode, context: str):
        valid_rids = [a.resource_id for a in node.attributes if a.resource_id > 0]
        assert valid_rids == sorted(valid_rids), (
            f"Resource IDs not strictly ascending in {context} elem <{node.tag}>:\n"
            f"Observed: {[hex(r) for r in valid_rids]}\n"
            f"Expected: {[hex(r) for r in sorted(valid_rids)]}"
        )
        assert len(valid_rids) == len(set(valid_rids)), (
            f"Duplicate resource IDs in {context} elem <{node.tag}>: {[hex(r) for r in valid_rids]}"
        )
        for child in node.children:
            check_node_ascending(child, context)

    # 1. Resource-only (hasCode=false) case - pure hermetic execution
    res_manifest = AxmlNode(tag="manifest")
    res_manifest.set_attr("package", "com.resource.only.theme")
    app_node = AxmlNode(tag="application")
    app_node.set_attr("hasCode", False)
    app_node.set_attr("theme", "@0x7f0b0001")
    app_node.set_attr("label", "Resource Only")
    app_node.set_attr("icon", "@0x7f020000")
    res_manifest.children.append(app_node)

    raw_bytes = AxmlSurgeon.serialize(res_manifest)
    patched_res = AxmlSurgeon.patch_manifest(
        raw_bytes,
        transforms=["PAGE_SIZE_COMPAT"],
        options={"bump_target_sdk": 24},
    )
    parsed_res = AxmlSurgeon.parse(patched_res)
    check_node_ascending(parsed_res, "ResourceOnly")
    parsed_app = parsed_res.find_child("application")
    assert parsed_app is not None
    assert parsed_app.get_attr("hasCode").get_value() is False
    assert parsed_app.get_attr("theme") is not None
    theme_rid = parsed_app.get_attr("theme").resource_id
    has_code_rid = parsed_app.get_attr("hasCode").resource_id
    assert theme_rid == 0x01010000
    assert has_code_rid == 0x0101000C
    # theme (0x01010000) must precede hasCode (0x0101000C)
    app_rids = [a.resource_id for a in parsed_app.attributes if a.resource_id > 0]
    assert app_rids.index(0x01010000) < app_rids.index(0x0101000C)

    # 2. Corpus APKs (artifact-dependent)
    corpus_dir = Path(__file__).resolve().parent / "corpus" / "apks"
    corpus_apks = list(corpus_dir.glob("*.apk"))
    if not corpus_apks:
        if os.environ.get("APKREVIVE_REQUIRE_ARTIFACTS") == "1":
            pytest.fail("Required artifacts missing: expected at least 6 corpus APKs in tests/corpus/apks. Run 'python scripts/download_corpus.py'.")
    else:
        assert len(corpus_apks) >= 6, f"Expected at least 6 corpus APKs, found {len(corpus_apks)}"
        for apk_path in corpus_apks:
            with zipfile.ZipFile(apk_path, "r") as zf:
                orig = zf.read("AndroidManifest.xml")
            patched = AxmlSurgeon.patch_manifest(
                orig,
                transforms=["SET_HAS_CODE_TRUE", "PAGE_SIZE_COMPAT"],
                options={"bump_target_sdk": 24, "enable_60hz": True, "enable_cutout": True},
            )
            root = AxmlSurgeon.parse(patched)
            check_node_ascending(root, f"Corpus {apk_path.name}")

    # 3. Canary APKs (artifact-dependent)
    canary_dir = Path(__file__).resolve().parent.parent / "canaries" / "build"
    canary_apks = list(canary_dir.glob("*.apk"))
    if not canary_apks:
        if os.environ.get("APKREVIVE_REQUIRE_ARTIFACTS") == "1":
            pytest.fail("Required artifacts missing: expected at least 16 canary APKs in canaries/build. Run 'python canaries/build_canaries.py'.")
    else:
        assert len(canary_apks) >= 16, f"Expected at least 16 canary APKs, found {len(canary_apks)}"
        for apk_path in canary_apks:
            with zipfile.ZipFile(apk_path, "r") as zf:
                orig = zf.read("AndroidManifest.xml")
            patched = AxmlSurgeon.patch_manifest(
                orig,
                transforms=["INJECT_USES_LIBRARY_APACHE_HTTP", "PAGE_SIZE_COMPAT"],
                options={"bump_target_sdk": 24},
            )
            root = AxmlSurgeon.parse(patched)
            check_node_ascending(root, f"Canary {apk_path.name}")


