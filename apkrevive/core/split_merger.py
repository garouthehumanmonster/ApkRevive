"""
split_merger.py - Split APK Merger for unified standalone APK reassembly.
Ingests split APK directories, .apks, or .xapk files (e.g. base.apk + split_config.*.apk).
Merges native libraries (lib/*), DEX files sequentially (classes.dex, classes2.dex, ...),
assets, and resources. Strips split-lock attributes using AxmlSurgeon.
"""

import os
import re
import tempfile
import zipfile
from typing import List, Set, Tuple, Optional

from apkrevive.core.axml import AxmlSurgeon
from apkrevive.core.align import align_apk
from apkrevive.security.zip_guard import validate_zip_archive


def _resolve_split_sources(sources: List[str], extract_dir: str) -> List[str]:
    apk_paths: List[str] = []
    for src in sources:
        if os.path.isdir(src):
            for root, _, files in os.walk(src):
                for f in sorted(files):
                    if f.lower().endswith(".apk"):
                        apk_paths.append(os.path.join(root, f))
        elif os.path.isfile(src):
            ext = os.path.splitext(src)[1].lower()
            if ext in (".apks", ".xapk", ".zip"):
                validate_zip_archive(src)
                with zipfile.ZipFile(src, "r") as zf:
                    for item in zf.infolist():
                        if item.filename.lower().endswith(".apk"):
                            target_dest = os.path.join(extract_dir, os.path.basename(item.filename))
                            with open(target_dest, "wb") as f_out:
                                f_out.write(zf.read(item.filename))
                            apk_paths.append(target_dest)
            elif ext == ".apk":
                validate_zip_archive(src)
                apk_paths.append(src)

    if not apk_paths:
        raise ValueError(f"No valid APK files found in split sources: {sources}")
    return apk_paths


def _strip_split_locks_from_manifest(manifest_bytes: bytes) -> bytes:
    stripped_bytes = AxmlSurgeon.strip_split_locks(manifest_bytes)
    root = AxmlSurgeon.parse(stripped_bytes)
    app_node = root.find_child("application")
    if app_node:
        app_node.set_attr("extractNativeLibs", False)
    return AxmlSurgeon.serialize(root)


def merge_split_apks(split_sources: List[str], output_apk: str, warnings: Optional[List[str]] = None) -> str:
    """
    Ingests split APK sources (directories, .apks, .xapk, or list of .apk files).
    Unifies all splits into a single standalone APK:
    - Merges native libraries (lib/*) across all splits.
    - Merges DEX files sequentially (classes.dex, classes2.dex, classes3.dex, ...).
    - Merges assets and resource files cleanly.
    - Strips split-lock attributes (isSplitRequired, com.android.vending.splits.required).
    - Aligns final APK to 16KB boundaries.
    Returns the path to the output APK.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        apks = _resolve_split_sources(split_sources, tmp_dir)

        # Distinguish base APK from config/feature splits
        base_apk: str = apks[0]
        split_apks: List[str] = []

        for apk in apks:
            fname = os.path.basename(apk).lower()
            if "base" in fname:
                base_apk = apk
                break

        for apk in apks:
            if apk != base_apk:
                split_apks.append(apk)

        ordered_apks = [base_apk] + split_apks

        # Detect when any non-base split contains resources.arsc
        detected_splits: List[str] = []
        for apk in split_apks:
            with zipfile.ZipFile(apk, "r") as zin:
                if "resources.arsc" in zin.namelist():
                    detected_splits.append(os.path.basename(apk))

        if detected_splits:
            warn_msg = (
                f"WARN_SPLIT_RESOURCE_TABLE_MERGE: Split APK contains separate resources.arsc "
                f"({', '.join(detected_splits)}); non-colliding res/ files merged without deep table unification."
            )
            if warnings is not None:
                warnings.append(warn_msg)

        # Collect DEX files in order: base first, then splits
        dex_files_ordered: List[Tuple[str, bytes]] = []
        lib_entries: Set[str] = set()
        seen_zip_entries: Set[str] = set()

        temp_merged_path = os.path.join(tmp_dir, "merged_unaligned.apk")

        with zipfile.ZipFile(temp_merged_path, "w") as zout:
            for apk_idx, apk_path in enumerate(ordered_apks):
                is_base = (apk_idx == 0)
                with zipfile.ZipFile(apk_path, "r") as zin:
                    for item in zin.infolist():
                        fname = item.filename

                        # Strip old signature artifacts
                        if fname.startswith("META-INF/") and (
                            fname.endswith(".SF")
                            or fname.endswith(".RSA")
                            or fname.endswith(".DSA")
                            or fname.endswith(".EC")
                            or fname.endswith(".MF")
                        ):
                            continue

                        # DEX files: collect and renumber sequentially later
                        if re.fullmatch(r"classes\d*\.dex", fname):
                            dex_bytes = zin.read(fname)
                            dex_files_ordered.append((fname, dex_bytes))
                            continue

                        # AndroidManifest.xml: only process from base APK
                        if fname == "AndroidManifest.xml":
                            if is_base:
                                raw_manifest = zin.read(fname)
                                stripped_manifest = _strip_split_locks_from_manifest(raw_manifest)
                                zout.writestr("AndroidManifest.xml", stripped_manifest)
                            continue

                        # Native libraries (lib/*)
                        if fname.startswith("lib/"):
                            if fname not in lib_entries:
                                lib_entries.add(fname)
                                if fname.endswith(".so"):
                                    zinfo = zipfile.ZipInfo(fname)
                                    zinfo.compress_type = zipfile.ZIP_STORED
                                    zout.writestr(zinfo, zin.read(fname))
                                else:
                                    zout.writestr(item, zin.read(fname))
                            continue

                        # Assets, resources, and others: avoid duplicate path collisions
                        if fname not in seen_zip_entries:
                            seen_zip_entries.add(fname)
                            zout.writestr(item, zin.read(fname))

            # Renumber and write all DEX files sequentially
            for idx, (_, dex_bytes) in enumerate(dex_files_ordered):
                dex_name = "classes.dex" if idx == 0 else f"classes{idx + 1}.dex"
                zout.writestr(dex_name, dex_bytes)

        # Ensure output directory exists and align merged APK to 16KB boundaries
        out_dir = os.path.dirname(os.path.abspath(output_apk))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        align_apk(temp_merged_path, output_apk, page_align_64bit=16384)

    return output_apk
