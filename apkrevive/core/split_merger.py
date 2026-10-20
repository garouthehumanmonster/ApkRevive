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


class UnsupportedSplitMerge(ValueError):
    pass


__all__ = ["merge_split_apks", "UnsupportedSplitMerge"]


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


def _write_entry(zout: zipfile.ZipFile, fname: str, data: bytes) -> None:
    is_stored = (fname.startswith("lib/") and fname.endswith(".so")) or (fname == "resources.arsc")
    zinfo = zipfile.ZipInfo(fname)
    zinfo.compress_type = zipfile.ZIP_STORED if is_stored else zipfile.ZIP_DEFLATED
    zout.writestr(zinfo, data)


def merge_split_apks(
    split_sources: List[str],
    output_apk: str,
    warnings: Optional[List[str]] = None,
    allow_resource_table_loss: bool = False,
) -> str:
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

        # Distinguish base APK from config/feature splits using manifest
        base_candidates: List[str] = []
        for apk in apks:
            with zipfile.ZipFile(apk, "r") as zin:
                if "AndroidManifest.xml" in zin.namelist():
                    raw_manifest = zin.read("AndroidManifest.xml")
                    root = AxmlSurgeon.parse(raw_manifest)
                    split_attr = root.get_attr("split")
                    is_base = (split_attr is None or split_attr.get_value() in ("", "base"))
                    if is_base:
                        base_candidates.append(apk)

        if len(base_candidates) == 0:
            raise ValueError("No base APK found in split sources (all candidates declare split attribute)")
        elif len(base_candidates) == 1:
            base_apk = base_candidates[0]
        else:
            tie_broken = [a for a in base_candidates if "base" in os.path.basename(a).lower()]
            if len(tie_broken) == 1:
                base_apk = tie_broken[0]
            else:
                raise ValueError(
                    f"Ambiguous split sources: multiple base APK candidates found ({[os.path.basename(a) for a in base_candidates]})"
                )

        split_apks = [apk for apk in apks if apk != base_apk]
        ordered_apks = [base_apk] + split_apks

        # Detect when any non-base split contains resources.arsc
        detected_splits: List[str] = []
        for apk in split_apks:
            with zipfile.ZipFile(apk, "r") as zin:
                if "resources.arsc" in zin.namelist():
                    detected_splits.append(os.path.basename(apk))

        if detected_splits:
            if not allow_resource_table_loss:
                raise UnsupportedSplitMerge(
                    f"Split APKs contain separate resources.arsc ({', '.join(detected_splits)}). "
                    "Resource table merging is not supported without risking Resources$NotFoundException; "
                    "pass allow_resource_table_loss=True to force merge."
                )
            qualifiers: List[str] = []
            for split_name in detected_splits:
                m = re.search(r"split_config\.([a-zA-Z0-9_-]+)\.apk", split_name, re.IGNORECASE)
                if m:
                    qualifiers.append(m.group(1))
                else:
                    qualifiers.append(split_name)
            warn_msg = (
                f"WARN_SPLIT_RESOURCE_TABLE_LOSS: Resource table from splits ({', '.join(detected_splits)}) discarded. "
                f"Lost qualifiers: {', '.join(qualifiers)}"
            )
            if warnings is not None:
                warnings.append(warn_msg)

        # Collect DEX files in order: base first, then splits
        dex_files_ordered: List[Tuple[str, bytes]] = []
        lib_entries: Set[str] = set()
        seen_zip_entries: Set[str] = set()
        dropped_duplicates: List[str] = []

        temp_merged_path = os.path.join(tmp_dir, "merged_unaligned.apk")

        with zipfile.ZipFile(temp_merged_path, "w", compression=zipfile.ZIP_DEFLATED) as zout:
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
                                _write_entry(zout, "AndroidManifest.xml", stripped_manifest)
                            continue

                        # Native libraries (lib/*)
                        if fname.startswith("lib/"):
                            if fname in lib_entries:
                                dropped_duplicates.append(fname)
                                continue
                            lib_entries.add(fname)
                            _write_entry(zout, fname, zin.read(fname))
                            continue

                        # Assets, resources, and others: avoid duplicate path collisions
                        if fname in seen_zip_entries:
                            dropped_duplicates.append(fname)
                            continue
                        seen_zip_entries.add(fname)
                        _write_entry(zout, fname, zin.read(fname))

            # Renumber and write all DEX files sequentially
            renamed_pairs: List[str] = []
            for idx, (orig_name, dex_bytes) in enumerate(dex_files_ordered):
                dex_name = "classes.dex" if idx == 0 else f"classes{idx + 1}.dex"
                if orig_name != dex_name:
                    renamed_pairs.append(f"{orig_name}->{dex_name}")
                _write_entry(zout, dex_name, dex_bytes)

            if renamed_pairs:
                warn_msg = (
                    f"WARN_DEX_RENUMBERED: DEX files renumbered: {', '.join(renamed_pairs)}. "
                    f"Note: DexClassLoader lookup by name may break."
                )
                if warnings is not None:
                    warnings.append(warn_msg)

            if dropped_duplicates:
                warn_msg = (
                    f"WARN_DROPPED_DUPLICATE_ENTRIES: Dropped {len(dropped_duplicates)} colliding entries: "
                    f"{', '.join(dropped_duplicates[:10])}{'...' if len(dropped_duplicates) > 10 else ''}"
                )
                if warnings is not None:
                    warnings.append(warn_msg)

        # Ensure output directory exists and align merged APK to 16KB boundaries
        out_dir = os.path.dirname(os.path.abspath(output_apk))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        align_apk(temp_merged_path, output_apk, page_align_64bit=16384)

    return output_apk
