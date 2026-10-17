"""
sarif.py - SARIF v2.1.0 telemetry emitter for ApkRevive triage and diff workflows.
Adheres strictly to the SARIF 2.1.0 schema (https://json.schemastore.org/sarif-2.1.0.json).
"""

import os
from pathlib import Path
from typing import Any, Dict, List

from apkrevive import __version__

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

BASE_RULES = [
    {
        "id": "INCOMPATIBLE_PAGE_SIZE",
        "name": "IncompatiblePageSize",
        "shortDescription": {"text": "64-bit ELF shared library not aligned to 16KB page boundary."},
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "INCOMPATIBLE_DEVICE_ABI",
        "name": "IncompatibleDeviceAbi",
        "shortDescription": {"text": "APK native ABIs are incompatible with target device supported ABIs."},
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "UNRESOLVABLE_SYSTEM_LIBRARY",
        "name": "UnresolvableSystemLibrary",
        "shortDescription": {"text": "Application links against private platform native libraries restricted by Bionic."},
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "EXCEEDS_2GB_LIMIT_FOR_REPACKING",
        "name": "Exceeds2GbLimit",
        "shortDescription": {"text": "APK archive size exceeds 2GB container repacker limit."},
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "SPLIT_APK_UNSUPPORTED",
        "name": "SplitApkUnsupported",
        "shortDescription": {"text": "Split APKs cannot be modernized independently."},
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "MODIFICATION_REQUIRED",
        "name": "ModificationRequired",
        "shortDescription": {"text": "Application requires compatibility bytecode/manifest shims or repacking to run."},
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id": "SIGNATURE_VERIFICATION_DETECTED",
        "name": "SignatureVerificationDetected",
        "shortDescription": {"text": "APK contains self-signature verification checks; repacking alters signature fingerprint."},
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id": "TARGET_SDK_INSTALL_FLOOR",
        "name": "TargetSdkInstallFloor",
        "shortDescription": {"text": "APK targetSdkVersion is below host OS installation floor."},
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id": "APACHE_HTTP_LEGACY_REMOVAL",
        "name": "ApacheHttpLegacyRemoval",
        "shortDescription": {"text": "Application uses Apache HTTP client removed from bootclasspath in Android 9+."},
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id": "INJECT_USES_LIBRARY_APACHE_HTTP",
        "name": "InjectUsesLibraryApacheHttp",
        "shortDescription": {"text": "Inject org.apache.http.legacy into AndroidManifest.xml uses-library."},
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id": "PAGE_SIZE_COMPAT",
        "name": "PageSizeCompat",
        "shortDescription": {"text": "Inject android:pageSizeCompat='enabled' to enable 16KB compat mode."},
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id": "LOCK_60HZ_DISPLAY_MODE",
        "name": "Lock60HzDisplayMode",
        "shortDescription": {"text": "Inject display refresh rate lock shim for fixed-physics games."},
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id": "CUTOUT_SHORT_EDGES",
        "name": "CutoutShortEdges",
        "shortDescription": {"text": "Inject display cutout layout attribute to fill tall screens."},
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id": "EXPAND_ASPECT_RATIO",
        "name": "ExpandAspectRatio",
        "shortDescription": {"text": "Inject resizeableActivity=true to prevent pillarboxing on widescreen devices."},
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id": "SET_HAS_CODE_TRUE",
        "name": "SetHasCodeTrue",
        "shortDescription": {"text": "Set android:hasCode='true' in AndroidManifest.xml for shim execution."},
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id": "RUNNABLE_UNMODIFIED",
        "name": "RunnableUnmodified",
        "shortDescription": {"text": "APK is compatible without modification or repacking."},
        "defaultConfiguration": {"level": "note"},
    },
    # Diff-specific rules
    {
        "id": "MANIFEST_MODIFIED",
        "name": "ManifestModified",
        "shortDescription": {"text": "AndroidManifest.xml attributes or elements altered during modernization."},
        "defaultConfiguration": {"level": "note"},
    },
    {
        "id": "DEX_SHIM_INJECTED",
        "name": "DexShimInjected",
        "shortDescription": {"text": "Compatibility initialization provider shim injected into DEX entries."},
        "defaultConfiguration": {"level": "note"},
    },
    {
        "id": "ALIGNMENT_FIXED",
        "name": "AlignmentFixed",
        "shortDescription": {"text": "Entry alignment adjusted to meet 16KB/4KB boundary requirements."},
        "defaultConfiguration": {"level": "note"},
    },
    {
        "id": "ALIGNMENT_MISMATCH",
        "name": "AlignmentMismatch",
        "shortDescription": {"text": "Entry does not satisfy required 16KB/4KB page alignment boundary."},
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "DIFF_NO_CHANGES",
        "name": "DiffNoChanges",
        "shortDescription": {"text": "No differences detected between original and revived APK."},
        "defaultConfiguration": {"level": "note"},
    },
    {
        "id": "WARN_RUNTIME_PERMISSIONS_ON_BUMP",
        "name": "WarnRuntimePermissionsOnBump",
        "shortDescription": {"text": "Target SDK bumped to >= 23 activates runtime permissions for requested dangerous permissions."},
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id": "WARN_SPLIT_RESOURCE_TABLE_MERGE",
        "name": "WarnSplitResourceTableMerge",
        "shortDescription": {"text": "Split APK contains separate resources.arsc; non-colliding res/ files merged without deep table unification."},
        "defaultConfiguration": {"level": "warning"},
    },
]


def _to_uri(file_path: str) -> str:
    try:
        p = Path(file_path).resolve()
        return p.as_uri()
    except Exception:
        norm = file_path.replace(os.sep, "/")
        return f"file:///{norm.lstrip('/')}"


def triage_to_sarif(triage_res: Dict[str, Any], apk_path: str) -> Dict[str, Any]:
    """
    Emits SARIF v2.1.0 telemetry for APK triage evaluation results.
    """
    if hasattr(triage_res, "to_dict"):
        res = triage_res.to_dict()
    else:
        res = dict(triage_res)

    verdict = res.get("verdict", "UNKNOWN")
    reason = res.get("reason", "RUNNABLE_UNMODIFIED")
    details = res.get("details", "")
    transforms = res.get("required_transforms", []) or []
    transform_risks = res.get("transform_risks", {}) or {}
    warnings = res.get("warnings", []) or []

    level_map = {
        "RED": "error",
        "YELLOW": "warning",
        "NEEDS_USER_INPUT": "warning",
        "GREEN": "note",
    }
    primary_level = level_map.get(verdict, "note")
    apk_uri = _to_uri(apk_path)

    known_rule_ids = {r["id"] for r in BASE_RULES}
    active_rules: List[Dict[str, Any]] = list(BASE_RULES)

    def ensure_rule(rid: str, lvl: str, desc: str):
        if rid not in known_rule_ids:
            active_rules.append({
                "id": rid,
                "name": rid.replace("_", " ").title().replace(" ", ""),
                "shortDescription": {"text": desc},
                "defaultConfiguration": {"level": lvl},
            })
            known_rule_ids.add(rid)

    results: List[Dict[str, Any]] = []

    # Primary triage result
    primary_msg = f"{reason}: {details}" if details else f"Triage verdict {verdict}: {reason}"
    ensure_rule(reason, primary_level, primary_msg)
    results.append({
        "ruleId": reason,
        "level": primary_level,
        "message": {"text": primary_msg},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": apk_uri}
                }
            }
        ],
    })

    # Transform results
    for t in transforms:
        risk = transform_risks.get(t, "MEDIUM")
        msg = f"Required transform: {t} (Risk: {risk})"
        ensure_rule(t, "warning", msg)
        results.append({
            "ruleId": t,
            "level": "warning",
            "message": {"text": msg},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": apk_uri}
                    }
                }
            ],
        })

    # Warning results
    for w in warnings:
        warn_code = w.split(":")[0].strip() if ":" in w else "TRIAGE_WARNING"
        ensure_rule(warn_code, "warning", w)
        results.append({
            "ruleId": warn_code,
            "level": "warning",
            "message": {"text": w},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": apk_uri}
                    }
                }
            ],
        })

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ApkRevive",
                        "version": __version__ or "0.3.3",
                        "rules": active_rules,
                    }
                },
                "results": results,
            }
        ],
    }


def diff_to_sarif(diff_data: Dict[str, Any], orig_path: str, revived_path: str) -> Dict[str, Any]:
    """
    Emits SARIF v2.1.0 telemetry for visual binary diff between original and revived APKs.
    """
    revived_uri = _to_uri(revived_path)
    results: List[Dict[str, Any]] = []

    manifest_diff = diff_data.get("manifest_diff", {})
    dex_diff = diff_data.get("dex_diff", {})
    alignment_ladder = diff_data.get("alignment_ladder", [])

    # Manifest modifications
    for attr, info in manifest_diff.items():
        if isinstance(info, dict):
            if info.get("changed"):
                b = info.get("before")
                a = info.get("after")
                results.append({
                    "ruleId": "MANIFEST_MODIFIED",
                    "level": "note",
                    "message": {"text": f"Manifest attribute '{attr}' updated from '{b}' to '{a}'."},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": revived_uri}}}],
                })
            elif info.get("added"):
                results.append({
                    "ruleId": "MANIFEST_MODIFIED",
                    "level": "note",
                    "message": {"text": f"Manifest '{attr}' added: {info.get('added')}."},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": revived_uri}}}],
                })
            elif info.get("removed"):
                results.append({
                    "ruleId": "MANIFEST_MODIFIED",
                    "level": "note",
                    "message": {"text": f"Manifest '{attr}' removed: {info.get('removed')}."},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": revived_uri}}}],
                })

    # DEX shim injection
    if dex_diff.get("shim_injected"):
        results.append({
            "ruleId": "DEX_SHIM_INJECTED",
            "level": "note",
            "message": {"text": "ApkReviveInitProvider shim DEX was injected into revived APK."},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": revived_uri}}}],
        })

    # Alignment ladder telemetry
    for entry in alignment_ladder:
        st = entry.get("status")
        target = entry.get("entry")
        etype = entry.get("type", "ZIP")
        req = entry.get("required_align", 4096)
        if st == "FIXED":
            results.append({
                "ruleId": "ALIGNMENT_FIXED",
                "level": "note",
                "message": {"text": f"Entry '{target}' ({etype}) aligned to {req} bytes."},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": revived_uri}}}],
            })
        elif st in ("FAIL", "MISALIGNED"):
            results.append({
                "ruleId": "ALIGNMENT_MISMATCH",
                "level": "error",
                "message": {"text": f"Entry '{target}' ({etype}) is misaligned (requires {req} bytes)."},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": revived_uri}}}],
            })

    if not results:
        results.append({
            "ruleId": "DIFF_NO_CHANGES",
            "level": "note",
            "message": {"text": "Original and revived APKs are identical in manifest, DEX, and alignment."},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": revived_uri}}}],
        })

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ApkRevive",
                        "version": __version__ or "0.3.3",
                        "rules": BASE_RULES,
                    }
                },
                "results": results,
            }
        ],
    }
