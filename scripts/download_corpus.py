"""
scripts/download_corpus.py - Download and verify real legacy APKs from committed corpus.json manifest.
Reads tests/corpus/corpus.json, downloads each APK, verifies sha256, and fails loudly on mismatch.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import urllib.request
from typing import Dict, Any, List, Union

MANIFEST_PATH = Path(__file__).resolve().parent.parent / "tests" / "corpus" / "corpus.json"
DEFAULT_DEST_DIR = Path(__file__).resolve().parent.parent / "tests" / "corpus" / "apks"


def load_manifest(path: Union[Path, str] = MANIFEST_PATH) -> Dict[str, Any]:
    target = Path(path)
    with open(target, "r", encoding="utf-8") as f:
        return json.load(f)


def compute_file_sha256(filepath: Union[Path, str]) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower()


def verify_existing_file(filepath: Union[Path, str], expected_hash: str) -> bool:
    target = Path(filepath)
    if not target.is_file():
        return False
    return compute_file_sha256(target) == expected_hash.lower()


def download_and_verify(url: str, dest_path: Union[Path, str], expected_sha256: str) -> bool:
    dest = Path(dest_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    urls_to_try = [url]
    if "/archive/" in url:
        urls_to_try.append(url.replace("/archive/", "/repo/"))
    elif "/repo/" in url:
        urls_to_try.append(url.replace("/repo/", "/archive/"))

    success = False
    for candidate_url in urls_to_try:
        try:
            req = urllib.request.Request(candidate_url, headers={"User-Agent": "ApkRevive-Corpus-Runner/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp, open(dest, "wb") as out:
                while chunk := resp.read(65536):
                    out.write(chunk)
            success = True
            break
        except Exception:
            if dest.exists():
                dest.unlink()

    if not success:
        sys.stderr.write(f"[-] Download failed for {url} (all candidate URLs exhausted)\n")
        return False

    actual_hash = compute_file_sha256(dest)
    if actual_hash != expected_sha256.lower():
        sys.stderr.write(f"[-] Checksum mismatch for {dest.name}!\n")
        sys.stderr.write(f"    Expected: {expected_sha256.lower()}\n")
        sys.stderr.write(f"    Observed: {actual_hash}\n")
        if dest.exists():
            dest.unlink()
        return False

    return True


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Download and verify F-Droid corpus APKs")
    parser.add_argument("--manifest", default=str(MANIFEST_PATH), help="Path to corpus manifest JSON")
    parser.add_argument("--dest-dir", default=str(DEFAULT_DEST_DIR), help="Destination directory for APKs")
    parser.add_argument("--verify-only", action="store_true", help="Only verify existing APKs, do not download")
    args = parser.parse_args(argv)

    manifest_file = Path(args.manifest)
    if not manifest_file.exists():
        sys.stderr.write(f"ERROR: Corpus manifest not found at {manifest_file}\n")
        return 1

    manifest = load_manifest(manifest_file)
    entries: List[Dict[str, Any]] = manifest.get("packages") or manifest.get("apks") or []
    if not entries:
        sys.stderr.write("ERROR: No package entries in manifest.\n")
        return 1

    dest_dir = Path(args.dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    all_ok = True

    for item in entries:
        name = item.get("apk_name") or f"{item.get('id')}.apk"
        url = item["url"]
        expected_sha = item["sha256"].lower()
        dest_file = dest_dir / name

        if verify_existing_file(dest_file, expected_sha):
            print(f"[+] CACHED & VERIFIED: {name} (SHA-256 matches)")
            continue

        if args.verify_only:
            sys.stderr.write(f"[-] MISSING or INVALID in verify-only mode: {name}\n")
            all_ok = False
            continue

        print(f"[*] DOWNLOADING: {name} from {url} ...")
        success = download_and_verify(url, dest_file, expected_sha)
        if success:
            print(f"[+] VERIFIED: {name} ({dest_file.stat().st_size} bytes, SHA-256 matches)")
        else:
            print(f"[-] FAILED: {name}")
            all_ok = False

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
