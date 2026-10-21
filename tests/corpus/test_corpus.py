"""
test_corpus.py - Test harness for real legacy APK corpus from F-Droid archives.
Tests real API 8, API 15, and API 22 legacy APKs with inspect and patch pipeline.
Download/caching is optional via env var APKREVIVE_DOWNLOAD_CORPUS=1.
"""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import urllib.request
import zipfile
import pytest

from apkrevive.cli import run_inspect, run_patch
from apkrevive.core.axml import AxmlSurgeon
from apkrevive.core.align import verify_apk_alignment

CORPUS_DIR = Path(__file__).resolve().parent
CORPUS_JSON_PATH = CORPUS_DIR / "corpus.json"
APKS_DIR = CORPUS_DIR / "apks"


def load_corpus_entries():
    if not CORPUS_JSON_PATH.is_file():
        return []
    with open(CORPUS_JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("apks", [])


def ensure_corpus_apk(entry) -> Path:
    """Returns local path to corpus APK, downloading if APKREVIVE_DOWNLOAD_CORPUS=1."""
    APKS_DIR.mkdir(parents=True, exist_ok=True)
    target = APKS_DIR / entry["filename"]

    if target.is_file() and target.stat().st_size > 0:
        return target

    should_download = os.environ.get("APKREVIVE_DOWNLOAD_CORPUS") == "1"
    if not should_download:
        pytest.skip(f"Corpus APK {entry['filename']} not downloaded (set APKREVIVE_DOWNLOAD_CORPUS=1 to download)")

    url = entry["url"]
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ApkRevive-Corpus-Runner/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp, open(target, "wb") as f:
            data = resp.read()
            f.write(data)

        # Verify SHA-256 if specified
        expected_sha = entry.get("sha256")
        if expected_sha:
            actual_sha = hashlib.sha256(target.read_bytes()).hexdigest()
            if actual_sha.lower() != expected_sha.lower():
                target.unlink(missing_ok=True)
                pytest.fail(f"SHA-256 mismatch for downloaded {entry['filename']}: {actual_sha} != {expected_sha}")

        return target
    except Exception as e:
        target.unlink(missing_ok=True)
        pytest.skip(f"Failed to download corpus APK {entry['filename']} from {url}: {e}")


@pytest.mark.parametrize("entry", load_corpus_entries(), ids=lambda e: e.get("id", e.get("filename")))
def test_corpus_apk_lifecycle(entry):
    """Verifies that real legacy APKs from API 8, 15, and 22 inspect and patch cleanly."""
    apk_path = ensure_corpus_apk(entry)

    # 1. Inspection
    report = run_inspect(str(apk_path))
    assert report.package_name == entry["package_name"]
    assert report.target_sdk == entry["target_sdk"]

    # 2. Patching in temporary directory
    with tempfile.NamedTemporaryFile(suffix="_revived.apk", delete=False) as f_out:
        out_path = f_out.name

    try:
        rep = run_patch(str(apk_path), out_path, no_sign=True, bump_target_sdk=24)
        assert rep.verdict == "GREEN"
        assert os.path.exists(out_path)
        assert os.path.getsize(out_path) > 0

        # 3. Alignment Verification
        align_info = verify_apk_alignment(out_path)
        assert align_info["aligned"] is True

        # 4. Manifest Integrity
        with zipfile.ZipFile(out_path, "r") as zf:
            manifest_bytes = zf.read("AndroidManifest.xml")
            root = AxmlSurgeon.parse(manifest_bytes)
            assert root.tag == "manifest"
            app = root.find_child("application")
            assert app is not None
            # Verify injected shim provider
            provider = (
                app.find_child("provider", "name", "com.apkrevive.shim.ApkReviveInitProvider")
                or app.find_child("provider", "name", "com.apkrevive.runtime.ApkReviveInitProvider")
            )
            assert provider is not None
    finally:
        if os.path.exists(out_path):
            os.remove(out_path)
