"""test_corpus.py - Tests for corpus manifest, download checksum logic, and triage evaluation."""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from apkrevive.core.models import ApkMetadata, DeviceProfile, Verdict
from apkrevive.core.triage import evaluate_triage
from scripts.download_corpus import (
    load_manifest,
    compute_file_sha256,
    download_and_verify,
    verify_existing_file,
    main as downloader_main,
)

MANIFEST_PATH = Path(__file__).resolve().parent / "corpus" / "corpus.json"
CORPUS_APKS_DIR = Path(__file__).resolve().parent / "corpus" / "apks"


class TestCorpusManifest(unittest.TestCase):
    def test_manifest_loads_and_has_valid_schema(self):
        self.assertTrue(MANIFEST_PATH.is_file(), f"Manifest file missing: {MANIFEST_PATH}")
        manifest = load_manifest(MANIFEST_PATH)
        self.assertIn("packages", manifest)
        self.assertIsInstance(manifest["packages"], list)
        self.assertGreaterEqual(len(manifest["packages"]), 4)

    def test_manifest_entries_conform_to_contract(self):
        manifest = load_manifest(MANIFEST_PATH)
        allowed_licenses = {"Apache-2.0", "GPL-3.0", "MIT", "GPL-2.0"}

        for pkg in manifest["packages"]:
            pkg_id = pkg.get("id")
            self.assertIsInstance(pkg_id, str)
            self.assertTrue(pkg.get("package_name"))
            self.assertTrue(pkg.get("version"))
            self.assertTrue(pkg.get("url", "").startswith("https://f-droid.org/archive/"))
            self.assertTrue(pkg.get("url", "").endswith(".apk"))

            sha256 = pkg.get("sha256", "")
            self.assertEqual(len(sha256), 64, f"SHA-256 string length invalid for {pkg_id}")
            int(sha256, 16)

            self.assertIn(pkg.get("license"), allowed_licenses)
            self.assertIsInstance(pkg.get("target_sdk"), int)
            self.assertGreater(pkg.get("target_sdk"), 0)


class TestChecksumAndDownloaderLogic(unittest.TestCase):
    def test_compute_file_sha256(self):
        payload = b"ApkRevive hermetic test payload"
        expected_hash = hashlib.sha256(payload).hexdigest()

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(payload)
            temp_path = Path(tf.name)

        try:
            computed = compute_file_sha256(temp_path)
            self.assertEqual(computed, expected_hash)
            self.assertTrue(verify_existing_file(temp_path, expected_hash))
            self.assertFalse(verify_existing_file(temp_path, "0" * 64))
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_download_and_verify_success(self):
        payload = b"Valid APK binary stream content"
        hasher = __import__("hashlib").sha256(payload)
        correct_hash = hasher.hexdigest()

        mock_resp = MagicMock()
        mock_resp.read.side_effect = [payload, b""]
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None

        with tempfile.TemporaryDirectory() as tmp_dir:
            dest_file = Path(tmp_dir) / "sample.apk"
            with patch("urllib.request.urlopen", return_value=mock_resp):
                ok = download_and_verify(
                    url="https://f-droid.org/archive/sample.apk",
                    dest_path=dest_file,
                    expected_sha256=correct_hash,
                )
            self.assertTrue(ok)
            self.assertTrue(dest_file.is_file())
            self.assertEqual(dest_file.read_bytes(), payload)

    def test_download_and_verify_rejects_corrupted_stream(self):
        payload = b"Corrupted stream content"
        mismatched_hash = "a" * 64

        mock_resp = MagicMock()
        mock_resp.read.side_effect = [payload, b""]
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None

        with tempfile.TemporaryDirectory() as tmp_dir:
            dest_file = Path(tmp_dir) / "corrupt.apk"
            with patch("urllib.request.urlopen", return_value=mock_resp):
                ok = download_and_verify(
                    url="https://f-droid.org/archive/corrupt.apk",
                    dest_path=dest_file,
                    expected_sha256=mismatched_hash,
                )
            self.assertFalse(ok)
            self.assertFalse(dest_file.exists())
            self.assertFalse(dest_file.with_suffix(".apk.tmp").exists())

    def test_verify_only_cli_with_missing_files(self):
        with tempfile.TemporaryDirectory() as empty_dir:
            args = ["--dest-dir", empty_dir, "--verify-only"]
            with patch("sys.stderr", new_callable=io.StringIO):
                code = downloader_main(args)
            self.assertEqual(code, 1)


class TestHermeticCorpusTriage(unittest.TestCase):
    def setUp(self):
        self.device_api35 = DeviceProfile(
            os_api_level=35,
            install_floor=24,
            supported_abis=["arm64-v8a", "x86_64"],
            page_size_bytes=16384,
            is_widescreen=True,
            is_high_refresh=False,
        )
        self.device_api33 = DeviceProfile(
            os_api_level=33,
            install_floor=1,
            supported_abis=["arm64-v8a", "x86_64"],
            page_size_bytes=4096,
            is_widescreen=True,
            is_high_refresh=False,
        )

    def test_synthetic_manifest_vectors_pass_hermetically(self):
        manifest = load_manifest(MANIFEST_PATH)
        for pkg in manifest["packages"]:
            with self.subTest(package_id=pkg["id"]):
                meta = ApkMetadata(
                    package_name=pkg["package_name"],
                    target_sdk=pkg["target_sdk"],
                    min_sdk=pkg.get("min_sdk", 1),
                    version_code=pkg.get("version_code", 1),
                    abis=pkg.get("abis", []),
                    size_bytes=5_000_000,
                    uses_cleartext_traffic=True,
                )

                res_35 = evaluate_triage(meta, self.device_api35)
                self.assertEqual(res_35["verdict"], Verdict.GREEN.value)
                self.assertEqual(res_35["reason"], "RUNNABLE_UNMODIFIED")
                expected_install_35 = (
                    "BYPASS_LOW_TARGET_SDK_BLOCK"
                    if pkg["target_sdk"] < self.device_api35.install_floor
                    else "DIRECT_INSTALL"
                )
                self.assertEqual(res_35["install_method"], expected_install_35)
                self.assertEqual(res_35["required_transforms"], [])

                res_33 = evaluate_triage(meta, self.device_api33)
                self.assertEqual(res_33["verdict"], Verdict.GREEN.value)
                self.assertEqual(res_33["reason"], "RUNNABLE_UNMODIFIED")
                self.assertEqual(res_33["install_method"], "DIRECT_INSTALL")

    def test_live_downloaded_apks_if_present(self):
        if not CORPUS_APKS_DIR.is_dir():
            self.skipTest("tests/corpus/apks directory does not exist.")

        downloaded_apks = list(CORPUS_APKS_DIR.glob("*.apk"))
        if not downloaded_apks:
            self.skipTest("No downloaded corpus APKs present in tests/corpus/apks/.")

        from apkrevive.core.extractor import inspect_apk

        manifest = load_manifest(MANIFEST_PATH)
        manifest_map = {p["url"].split("/")[-1]: p for p in manifest["packages"]}

        for apk_path in downloaded_apks:
            with self.subTest(apk_name=apk_path.name):
                manifest_entry = manifest_map.get(apk_path.name)
                if manifest_entry:
                    self.assertTrue(
                        verify_existing_file(apk_path, manifest_entry["sha256"]),
                        f"Checksum mismatch for live file: {apk_path.name}",
                    )

                meta = inspect_apk(str(apk_path))
                res = evaluate_triage(meta, self.device_api35)
                if meta.abis and not any(a in self.device_api35.supported_abis for a in meta.abis):
                    self.assertEqual(res["verdict"], Verdict.RED.value)
                elif meta.elf_16kb_status == "COMPAT_ONLY" and self.device_api35.page_size_bytes == 16384:
                    # On API 35 with 16KB kernel, 4KB ELF cannot run (requires API 36+ for PAGE_SIZE_COMPAT)
                    self.assertEqual(res["verdict"], Verdict.RED.value)
                    self.assertEqual(res["reason"], "INCOMPATIBLE_PAGE_SIZE")
                    # Verify on API 36 16KB it becomes YELLOW with PAGE_SIZE_COMPAT transform
                    dev_36_16k = DeviceProfile(os_api_level=36, page_size_bytes=16384, supported_abis=["arm64-v8a", "x86_64"])
                    res_36 = evaluate_triage(meta, dev_36_16k)
                    self.assertEqual(res_36["verdict"], Verdict.YELLOW.value)
                    self.assertIn("PAGE_SIZE_COMPAT", res_36["required_transforms"])
                    # Verify on API 35 with 4KB kernel it is runnable unmodified
                    dev_35_4k = DeviceProfile(os_api_level=35, page_size_bytes=4096, supported_abis=["arm64-v8a", "x86_64"])
                    res_4k = evaluate_triage(meta, dev_35_4k)
                    self.assertEqual(res_4k["verdict"], Verdict.GREEN.value)
                else:
                    self.assertIn(res["verdict"], [Verdict.GREEN.value, Verdict.YELLOW.value])


if __name__ == "__main__":
    unittest.main()
