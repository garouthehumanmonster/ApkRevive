#!/usr/bin/env python3
"""
download_corpus.py - Downloads and verifies the legacy F-Droid APK corpus.
Caches APKs in tests/corpus/apks/ and validates SHA-256 digests.
"""

import hashlib
import json
from pathlib import Path
import sys
import urllib.request

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_JSON = REPO_ROOT / "tests" / "corpus" / "corpus.json"
APKS_DIR = REPO_ROOT / "tests" / "corpus" / "apks"


def download_corpus() -> int:
    if not CORPUS_JSON.is_file():
        sys.stderr.write(f"Error: Corpus manifest not found at {CORPUS_JSON}\n")
        return 1

    try:
        with open(CORPUS_JSON, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        sys.stderr.write(f"Error reading {CORPUS_JSON}: {e}\n")
        return 1

    entries = data.get("apks", [])
    if not entries:
        sys.stderr.write(f"Error: No APK entries found in {CORPUS_JSON}\n")
        return 1

    APKS_DIR.mkdir(parents=True, exist_ok=True)
    failed = False

    for entry in entries:
        filename = entry.get("filename")
        url = entry.get("url")
        expected_sha = entry.get("sha256", "").lower()

        if not filename or not url:
            sys.stderr.write(f"Error: Invalid entry in corpus manifest: {entry}\n")
            failed = True
            continue

        target = APKS_DIR / filename

        # Check existing file
        if target.is_file() and target.stat().st_size > 0:
            actual_sha = hashlib.sha256(target.read_bytes()).hexdigest().lower()
            if actual_sha == expected_sha:
                print(f"[CACHED] {filename} (SHA-256: {actual_sha[:16]}...)")
                continue
            else:
                print(f"[WARN] Hash mismatch for cached {filename}, re-downloading...")
                target.unlink(missing_ok=True)

        print(f"[DOWNLOADING] {filename} from {url}...")
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "ApkRevive-Corpus-Runner/1.0"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                content = resp.read()

            target.write_bytes(content)

            actual_sha = hashlib.sha256(content).hexdigest().lower()
            if actual_sha != expected_sha:
                target.unlink(missing_ok=True)
                sys.stderr.write(
                    f"Error: SHA-256 mismatch for {filename}\n"
                    f"  Expected: {expected_sha}\n"
                    f"  Actual:   {actual_sha}\n"
                )
                failed = True
                continue

            print(f"[OK] Downloaded and verified {filename} ({len(content)} bytes)")
        except Exception as e:
            target.unlink(missing_ok=True)
            sys.stderr.write(f"Error downloading {filename} from {url}: {e}\n")
            failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(download_corpus())
