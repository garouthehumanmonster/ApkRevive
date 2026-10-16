"""
diff.py - Visual binary diff engine comparing original and revived APKs.
Compares AndroidManifest attributes, DEX shim changes, and ELF/ZIP byte alignments.
"""

import mmap
import os
import re
import struct
import zipfile
from typing import Any, Dict, List, Optional

from apkrevive.cli.tui import render_alignment_ladder
from apkrevive.core.axml import AxmlSurgeon
from apkrevive.core.elf import parse_elf_load_align


def _parse_manifest_ast(manifest_bytes: bytes) -> Dict[str, Any]:
    pkg: str = ""
    target_sdk: Optional[int] = None
    min_sdk: Optional[int] = None
    has_code: bool = True
    resizeable_activity: Optional[bool] = None
    page_size_compat: Optional[str] = None
    uses_libraries: List[str] = []
    providers: List[str] = []
    meta_data: Dict[str, Any] = {}

    if not manifest_bytes:
        return {
            "package": pkg,
            "target_sdk": target_sdk,
            "min_sdk": min_sdk,
            "has_code": has_code,
            "resizeable_activity": resizeable_activity,
            "page_size_compat": page_size_compat,
            "uses_libraries": uses_libraries,
            "providers": providers,
            "meta_data": meta_data,
        }
    try:
        root = AxmlSurgeon.parse(manifest_bytes)
        pkg_attr = root.get_attr("package")
        if pkg_attr:
            pkg = str(pkg_attr.get_value() or pkg_attr.raw_value or "")

        uses_sdk = root.find_child("uses-sdk")
        if uses_sdk:
            target_attr = uses_sdk.get_attr("targetSdkVersion")
            if target_attr:
                target_sdk = target_attr.get_value()
            min_attr = uses_sdk.get_attr("minSdkVersion")
            if min_attr:
                min_sdk = min_attr.get_value()

        app = root.find_child("application")
        if app:
            has_code_attr = app.get_attr("hasCode")
            if has_code_attr is not None:
                val = has_code_attr.get_value()
                has_code = bool(val)

            resiz_attr = app.get_attr("resizeableActivity")
            if resiz_attr is not None:
                resizeable_activity = bool(resiz_attr.get_value())

            psc_attr = app.get_attr("pageSizeCompat")
            if psc_attr is not None:
                val_psc = psc_attr.get_value()
                page_size_compat = str(val_psc) if val_psc is not None else str(psc_attr.raw_value or "")

            for ch in app.children:
                if ch.tag == "uses-library":
                    name_attr = ch.get_attr("name") or ch.get_attr("android:name")
                    if name_attr:
                        v = name_attr.get_value() or name_attr.raw_value
                        if v and str(v) not in uses_libraries:
                            uses_libraries.append(str(v))
                elif ch.tag == "provider":
                    name_attr = ch.get_attr("name") or ch.get_attr("android:name")
                    if name_attr:
                        v = name_attr.get_value() or name_attr.raw_value
                        if v and str(v) not in providers:
                            providers.append(str(v))
                elif ch.tag == "meta-data":
                    name_attr = ch.get_attr("name") or ch.get_attr("android:name")
                    val_attr = ch.get_attr("value") or ch.get_attr("android:value")
                    if name_attr:
                        k = str(name_attr.get_value() or name_attr.raw_value)
                        v_meta = val_attr.get_value() if val_attr else True
                        meta_data[k] = v_meta
    except Exception:
        pass

    return {
        "package": pkg,
        "target_sdk": target_sdk,
        "min_sdk": min_sdk,
        "has_code": has_code,
        "resizeable_activity": resizeable_activity,
        "page_size_compat": page_size_compat,
        "uses_libraries": uses_libraries,
        "providers": providers,
        "meta_data": meta_data,
    }


def _inspect_zip_offsets(apk_path: str) -> Dict[str, Dict[str, Any]]:
    """
    Parses an APK archive directly to find exact data offsets for .so and resources.arsc.
    """
    entries: Dict[str, Dict[str, Any]] = {}
    if not os.path.exists(apk_path):
        return entries

    try:
        with open(apk_path, "rb") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as buf:
                buf_len = len(buf)
                eocd_pos = buf.rfind(b"PK\x05\x06")
                if eocd_pos == -1 or eocd_pos + 22 > buf_len:
                    return entries

                cd_entries_total, cd_size, cd_offset = struct.unpack_from("<HII", buf, eocd_pos + 10)
                if cd_offset + cd_size > buf_len:
                    return entries

                cd_ptr = cd_offset
                for _ in range(cd_entries_total):
                    if cd_ptr + 46 > buf_len or buf[cd_ptr : cd_ptr + 4] != b"PK\x01\x02":
                        break
                    method = struct.unpack_from("<H", buf, cd_ptr + 10)[0]
                    fn_len, ef_len, comm_len = struct.unpack_from("<HHH", buf, cd_ptr + 28)
                    lfh_offset = struct.unpack_from("<I", buf, cd_ptr + 42)[0]
                    if cd_ptr + 46 + fn_len > buf_len:
                        break
                    fn = buf[cd_ptr + 46 : cd_ptr + 46 + fn_len].decode("utf-8", errors="replace")

                    if fn.endswith(".so") or fn == "resources.arsc":
                        if lfh_offset + 30 <= buf_len:
                            lfh_fn_len, lfh_ef_len = struct.unpack_from("<HH", buf, lfh_offset + 26)
                            data_offset = lfh_offset + 30 + lfh_fn_len + lfh_ef_len

                            req_align = 4096
                            if fn.endswith(".so") and ("arm64-v8a" in fn or "x86_64" in fn):
                                req_align = 16384

                            aligned = (method == 0) and (data_offset % req_align == 0)
                            entries[fn] = {
                                "offset": data_offset,
                                "method": method,
                                "required_align": req_align,
                                "aligned": aligned,
                            }

                    cd_ptr += 46 + fn_len + ef_len + comm_len
    except Exception:
        pass
    return entries


def compute_apk_diff(orig_apk: str, revived_apk: str) -> Dict[str, Any]:
    """
    Compares two APK files (original vs revived) and returns a structured diff dictionary:
    - manifest_diff: target_sdk, hasCode, resizeableActivity, pageSizeCompat, uses-library, providers, meta-data
    - dex_diff: classes.dex count, additions, and shim injection status
    - alignment_ladder: side-by-side ZIP and ELF PT_LOAD byte alignments
    """
    orig_manifest_bytes = b""
    orig_dex_list: List[str] = []
    orig_has_shim = False
    orig_elf_aligns: Dict[str, Optional[int]] = {}

    if os.path.exists(orig_apk):
        with zipfile.ZipFile(orig_apk, "r") as zf:
            for item in zf.namelist():
                if item == "AndroidManifest.xml":
                    orig_manifest_bytes = zf.read(item)
                elif re.fullmatch(r"classes\d*\.dex", item):
                    orig_dex_list.append(item)
                    dex_data = zf.read(item)
                    if b"ApkReviveInitProvider" in dex_data:
                        orig_has_shim = True
                elif item.endswith(".so") and ("arm64-v8a" in item or "x86_64" in item):
                    so_bytes = zf.read(item)
                    orig_elf_aligns[item] = parse_elf_load_align(so_bytes)

    rev_manifest_bytes = b""
    rev_dex_list: List[str] = []
    rev_has_shim = False
    rev_elf_aligns: Dict[str, Optional[int]] = {}

    if os.path.exists(revived_apk):
        with zipfile.ZipFile(revived_apk, "r") as zf:
            for item in zf.namelist():
                if item == "AndroidManifest.xml":
                    rev_manifest_bytes = zf.read(item)
                elif re.fullmatch(r"classes\d*\.dex", item):
                    rev_dex_list.append(item)
                    dex_data = zf.read(item)
                    if b"ApkReviveInitProvider" in dex_data:
                        rev_has_shim = True
                elif item.endswith(".so") and ("arm64-v8a" in item or "x86_64" in item):
                    so_bytes = zf.read(item)
                    rev_elf_aligns[item] = parse_elf_load_align(so_bytes)

    # 1. Manifest Diff
    om = _parse_manifest_ast(orig_manifest_bytes)
    rm = _parse_manifest_ast(rev_manifest_bytes)

    manifest_diff = {
        "target_sdk": {
            "before": om["target_sdk"],
            "after": rm["target_sdk"],
            "changed": om["target_sdk"] != rm["target_sdk"],
        },
        "min_sdk": {
            "before": om["min_sdk"],
            "after": rm["min_sdk"],
            "changed": om["min_sdk"] != rm["min_sdk"],
        },
        "has_code": {
            "before": om["has_code"],
            "after": rm["has_code"],
            "changed": om["has_code"] != rm["has_code"],
        },
        "resizeable_activity": {
            "before": om["resizeable_activity"],
            "after": rm["resizeable_activity"],
            "changed": om["resizeable_activity"] != rm["resizeable_activity"],
        },
        "page_size_compat": {
            "before": om["page_size_compat"],
            "after": rm["page_size_compat"],
            "changed": om["page_size_compat"] != rm["page_size_compat"],
        },
        "uses_libraries": {
            "before": om["uses_libraries"],
            "after": rm["uses_libraries"],
            "added": [x for x in rm["uses_libraries"] if x not in om["uses_libraries"]],
            "removed": [x for x in om["uses_libraries"] if x not in rm["uses_libraries"]],
        },
        "providers": {
            "before": om["providers"],
            "after": rm["providers"],
            "added": [x for x in rm["providers"] if x not in om["providers"]],
            "removed": [x for x in om["providers"] if x not in rm["providers"]],
        },
        "meta_data": {
            "before": om["meta_data"],
            "after": rm["meta_data"],
            "added": {k: v for k, v in rm["meta_data"].items() if k not in om["meta_data"]},
            "removed": {k: v for k, v in om["meta_data"].items() if k not in rm["meta_data"]},
        },
    }

    # 2. DEX Diff
    dex_diff = {
        "orig_dex": sorted(orig_dex_list),
        "revived_dex": sorted(rev_dex_list),
        "orig_dex_count": len(orig_dex_list),
        "revived_dex_count": len(rev_dex_list),
        "added_dex": sorted([x for x in rev_dex_list if x not in orig_dex_list]),
        "removed_dex": sorted([x for x in orig_dex_list if x not in rev_dex_list]),
        "orig_has_shim": orig_has_shim,
        "revived_has_shim": rev_has_shim,
        "shim_injected": (not orig_has_shim and rev_has_shim),
    }

    # 3. Alignment Ladder (ZIP offsets and ELF PT_LOAD)
    orig_zip_align = _inspect_zip_offsets(orig_apk)
    rev_zip_align = _inspect_zip_offsets(revived_apk)

    all_zip_keys = sorted(list(set(orig_zip_align.keys()).union(set(rev_zip_align.keys()))))
    alignment_ladder: List[Dict[str, Any]] = []

    for k in all_zip_keys:
        o_info = orig_zip_align.get(k)
        r_info = rev_zip_align.get(k)
        req = r_info["required_align"] if r_info else (o_info["required_align"] if o_info else 4096)

        if o_info and r_info:
            if not o_info["aligned"] and r_info["aligned"]:
                st = "FIXED"
            elif o_info["aligned"] and r_info["aligned"]:
                st = "PASS"
            elif not r_info["aligned"]:
                st = "FAIL"
            else:
                st = "PASS"
        elif r_info:
            st = "PASS" if r_info["aligned"] else "FAIL"
        else:
            st = "REMOVED"

        alignment_ladder.append({
            "entry": k,
            "type": "ZIP",
            "required_align": req,
            "before": {"offset": o_info["offset"], "aligned": o_info["aligned"]} if o_info else None,
            "after": {"offset": r_info["offset"], "aligned": r_info["aligned"]} if r_info else None,
            "status": st,
        })

    # ELF PT_LOAD segment alignment for 64-bit .so
    all_elf_keys = sorted(list(set(orig_elf_aligns.keys()).union(set(rev_elf_aligns.keys()))))
    for k in all_elf_keys:
        o_align = orig_elf_aligns.get(k)
        r_align = rev_elf_aligns.get(k)
        req = 16384

        o_aligned = (o_align is not None and o_align >= req)
        r_aligned = (r_align is not None and r_align >= req)

        if o_align is not None and r_align is not None:
            if not o_aligned and r_aligned:
                st = "FIXED"
            elif o_aligned and r_aligned:
                st = "PASS"
            else:
                st = "FAIL"
        elif r_align is not None:
            st = "PASS" if r_aligned else "FAIL"
        else:
            st = "REMOVED"

        alignment_ladder.append({
            "entry": f"{k} (PT_LOAD)",
            "type": "PT_LOAD",
            "required_align": req,
            "before": {"p_align": o_align, "aligned": o_aligned} if o_align is not None else None,
            "after": {"p_align": r_align, "aligned": r_aligned} if r_align is not None else None,
            "status": st,
        })

    return {
        "original_apk": orig_apk,
        "revived_apk": revived_apk,
        "manifest_diff": manifest_diff,
        "dex_diff": dex_diff,
        "alignment_ladder": alignment_ladder,
    }


def render_apk_diff(diff_data: Dict[str, Any]) -> str:
    """
    Renders side-by-side manifest diff, DEX shim changes, and the ASCII byte-alignment ladder.
    """
    lines: List[str] = [
        "=" * 76,
        "ApkRevive Visual Binary Diff",
        "=" * 76,
        f"Original APK: {diff_data.get('original_apk', 'N/A')}",
        f"Revived APK:  {diff_data.get('revived_apk', 'N/A')}",
        "",
        "1. Manifest Changes",
        "-------------------",
    ]

    m_diff = diff_data.get("manifest_diff", {})
    manifest_rows = []
    for k in ("target_sdk", "min_sdk", "has_code", "resizeable_activity", "page_size_compat"):
        info = m_diff.get(k)
        if info:
            b_val = str(info.get("before"))
            a_val = str(info.get("after"))
            ch = "[MODIFIED]" if info.get("changed") else "[UNCHANGED]"
            manifest_rows.append(f"  - {k:<22} : {b_val:<12} -> {a_val:<12} {ch}")

    uses_libs = m_diff.get("uses_libraries", {})
    if uses_libs.get("added"):
        manifest_rows.append(f"  - uses-library (added)   : {uses_libs.get('added')}")

    providers = m_diff.get("providers", {})
    if providers.get("added"):
        manifest_rows.append(f"  - providers (added)      : {providers.get('added')}")

    meta_data = m_diff.get("meta_data", {})
    if meta_data.get("added"):
        manifest_rows.append(f"  - meta-data (added)      : {meta_data.get('added')}")

    if manifest_rows:
        lines.extend(manifest_rows)
    else:
        lines.append("  No manifest modifications detected.")

    # DEX changes
    lines.extend([
        "",
        "2. DEX & Shim Changes",
        "---------------------",
    ])
    d_diff = diff_data.get("dex_diff", {})
    orig_cnt = d_diff.get("orig_dex_count", 0)
    rev_cnt = d_diff.get("revived_dex_count", 0)
    added_dex = d_diff.get("added_dex", [])
    shim_injected = d_diff.get("shim_injected", False)

    lines.append(f"  - DEX File Count         : {orig_cnt} -> {rev_cnt}")
    if added_dex:
        lines.append(f"  - Injected DEX Files     : {added_dex}")
    shim_status = "INJECTED (ApkReviveInitProvider)" if shim_injected else (
        "PRESENT (Pre-existing)" if d_diff.get("revived_has_shim") else "NOT INJECTED"
    )
    lines.append(f"  - Compatibility Shim     : {shim_status}")

    # Alignment ladder
    lines.extend([
        "",
        "3. Byte-Alignment Ladder",
        "------------------------",
    ])
    ladder_str = render_alignment_ladder(diff_data.get("alignment_ladder", []))
    lines.append(ladder_str)

    return "\n".join(lines)
