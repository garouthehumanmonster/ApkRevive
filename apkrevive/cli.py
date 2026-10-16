"""
cli.py - Main entrypoint for ApkRevive modernizer CLI.
"""

import argparse
import json
import sys
import os
import re
import zipfile
from datetime import datetime
from typing import Dict, Any

# Enable cli/ subpackage discovery for tui, sarif, and diff submodules
__path__ = [os.path.join(os.path.dirname(__file__), "cli")]

from apkrevive.core.models import DeviceProfile, ApkMetadata, PatchReport
from apkrevive.core.triage import evaluate_triage
from apkrevive.core.axml import AxmlSurgeon
from apkrevive.core.align import align_apk, validate_zip_archive
from apkrevive.core.signer import sign_apk
from apkrevive.core.behavior_changes import TRANSFORM_RISK_LEVELS
from apkrevive.core.obb import validate_obb_delivery
from apkrevive.core.extractor import inspect_apk
from apkrevive.core.doctor import run_doctor, format_doctor_report
from apkrevive.adb.bridge import AdbBridge
from apkrevive.adb.probe import probe_install_floor
from apkrevive import __version__

from apkrevive.cli.tui import (
    HAS_RICH,
    _is_interactive,
    render_verdict_banner,
    render_triage_table,
)
from apkrevive.cli.sarif import triage_to_sarif, diff_to_sarif
from apkrevive.cli.diff import compute_apk_diff, render_apk_diff

VERDICT_EXIT_CODES = {
    "GREEN": 0,
    "RED": 1,
    "YELLOW": 2,
    "NEEDS_USER_INPUT": 3,
}


def format_triage_summary(res: Dict[str, Any]) -> str:
    verdict = res.get("verdict", "UNKNOWN")
    reason = res.get("reason", "N/A")
    install_method = res.get("install_method", "N/A")
    transforms = res.get("required_transforms", [])
    transform_risks = res.get("transform_risks", {})
    warnings = res.get("warnings", [])
    details = res.get("details", "")

    is_page_size_unverified = (
        "PAGE_SIZE_COMPAT" in transforms and not res.get("page_size_compat_verified", True)
    )
    verdict_str = (res.get("verdict_display") or f"{verdict} (UNVERIFIED)") if is_page_size_unverified else verdict

    lines = [
        "ApkRevive Triage Summary",
        "========================",
        f"Verdict: {verdict_str}",
        f"Reason: {reason}",
        f"Install Method: {install_method}",
    ]
    if transforms:
        lines.append(f"Required Transforms ({len(transforms)}):")
        for t in transforms:
            risk_level = transform_risks.get(t, TRANSFORM_RISK_LEVELS.get(t, "MEDIUM"))
            if t == "PAGE_SIZE_COMPAT" and is_page_size_unverified:
                lines.append(f"  - {t} [Risk: {risk_level}] (UNVERIFIED)")
            else:
                lines.append(f"  - {t} [Risk: {risk_level}]")
    else:
        lines.append("Required Transforms: None")

    if warnings:
        lines.append(f"Warnings ({len(warnings)}):")
        for w in warnings:
            lines.append(f"  - {w}")
    else:
        lines.append("Warnings: None")

    if details:
        lines.append(f"Details: {details}")

    return "\n".join(lines)


def format_patch_report(report: PatchReport) -> str:
    is_page_size_unverified = (
        "PAGE_SIZE_COMPAT" in report.required_transforms
        and not getattr(report, "page_size_compat_verified", True)
    )
    verdict_str = (
        getattr(report, "verdict_display", None) or f"{report.verdict} (UNVERIFIED)"
        if is_page_size_unverified
        else report.verdict
    )
    lines = [
        "ApkRevive Patch Report",
        "======================",
        f"Timestamp: {report.timestamp}",
        f"Package Name: {report.package_name}",
        f"Target SDK: {report.target_sdk}",
        f"Verdict: {verdict_str}",
        f"Reason: {report.reason}",
        f"Install Method: {report.install_method or 'N/A'}",
    ]
    if report.required_transforms:
        lines.append(f"Required Transforms ({len(report.required_transforms)}):")
        for t in report.required_transforms:
            risk_level = report.transform_risks.get(t, TRANSFORM_RISK_LEVELS.get(t, "MEDIUM"))
            if t == "PAGE_SIZE_COMPAT" and is_page_size_unverified:
                lines.append(f"  - {t} [Risk: {risk_level}] (UNVERIFIED)")
            else:
                lines.append(f"  - {t} [Risk: {risk_level}]")
    else:
        lines.append("Required Transforms: None")

    lines.append(f"Output APK: {report.output_apk or 'None'}")

    if report.warnings:
        lines.append(f"Warnings ({len(report.warnings)}):")
        for w in report.warnings:
            lines.append(f"  - {w}")
    else:
        lines.append("Warnings: None")
    if report.details:
        lines.append(f"Details: {report.details}")
    return "\n".join(lines)


def triage_cmd(args):
    abis = args.device_abis.split(",") if getattr(args, "device_abis", None) else ["arm64-v8a"]
    device_floor = getattr(args, "device_floor", 24)
    dev = DeviceProfile(
        os_api_level=getattr(args, "device_api", 35),
        install_floor=device_floor,
        supported_abis=abis,
        page_size_bytes=getattr(args, "page_size", 16384),
    )

    if os.path.exists(args.apk):
        validate_zip_archive(args.apk)
        apk = inspect_apk(args.apk)
        if getattr(args, "target_sdk", None) is not None:
            apk.target_sdk = args.target_sdk
        if getattr(args, "apk_abis", None):
            apk.abis = [a.strip() for a in args.apk_abis.split(",") if a.strip()]
        if getattr(args, "uses_apache_http", None):
            apk.uses_apache_http = True
    else:
        apk_target_sdk = getattr(args, "target_sdk", None)
        if apk_target_sdk is None:
            apk_target_sdk = 28
        apk_abis_str = getattr(args, "apk_abis", "") or ""
        apk_abis_list = [a.strip() for a in apk_abis_str.split(",") if a.strip()]
        apk = ApkMetadata(
            target_sdk=apk_target_sdk,
            abis=apk_abis_list,
            uses_apache_http=bool(getattr(args, "uses_apache_http", False)),
        )

    if getattr(args, "enable_60hz", False):
        apk.has_fixed_physics = True
        dev.is_high_refresh = True
    if getattr(args, "enable_cutout", False):
        dev.is_widescreen = True

    res = evaluate_triage(apk, dev)

    if getattr(args, "sarif", False):
        sarif_data = triage_to_sarif(res, getattr(args, "apk", "unknown.apk"))
        print(json.dumps(sarif_data, indent=2))
    elif getattr(args, "json", False):
        print(json.dumps(res, indent=2))
    elif HAS_RICH and _is_interactive():
        banner = render_verdict_banner(
            res.get("verdict", "UNKNOWN"),
            res.get("reason", "N/A"),
            res.get("install_method"),
        )
        table = render_triage_table(res)
        print(banner)
        print(table)
    else:
        print(format_triage_summary(res))

    return VERDICT_EXIT_CODES.get(res["verdict"], 1)


def revive_cmd(args):
    input_path = args.apk
    if os.path.exists(input_path):
        validate_zip_archive(input_path)
    output_path = args.output or input_path.replace(".apk", ".revived.apk")

    meta = inspect_apk(input_path)
    if meta.is_split_apk:
        sys.stderr.write("ERROR: Split APK detected. Split APKs cannot be modernized independently.\n")
        return 1

    dev = DeviceProfile(
        os_api_level=getattr(args, "device_api", 35),
        page_size_bytes=getattr(args, "page_size", 16384),
    ) if (hasattr(args, "device_api") or hasattr(args, "page_size")) else DeviceProfile()
    triage = evaluate_triage(meta, dev)

    transforms = list(triage.get("required_transforms", []))
    if getattr(args, "enable_60hz", False) and "LOCK_60HZ_DISPLAY_MODE" not in transforms:
        transforms.append("LOCK_60HZ_DISPLAY_MODE")
    if getattr(args, "enable_cutout", False) and "CUTOUT_SHORT_EDGES" not in transforms:
        transforms.append("CUTOUT_SHORT_EDGES")
    if getattr(args, "enable_resizable", False) and "EXPAND_ASPECT_RATIO" not in transforms:
        transforms.append("EXPAND_ASPECT_RATIO")

    skipped_aspect = False
    active_transforms = list(transforms)
    if "EXPAND_ASPECT_RATIO" in active_transforms and not getattr(args, "enable_resizable", False):
        active_transforms.remove("EXPAND_ASPECT_RATIO")
        skipped_aspect = True

    transform_risks = {t: TRANSFORM_RISK_LEVELS.get(t, "MEDIUM") for t in transforms}
    skip_note = "Skipped EXPAND_ASPECT_RATIO (opt-in requires --enable-resizable)"

    dry_run = getattr(args, "dry_run", False)
    if dry_run:
        dry_run_details = "Dry run: planned transformations without creating output APK or signing."
        if skipped_aspect:
            dry_run_details = f"{dry_run_details} {skip_note}."
        report = PatchReport(
            timestamp=datetime.now().isoformat(),
            apk_path=input_path,
            package_name=meta.package_name,
            target_sdk=meta.target_sdk,
            verdict=triage.get("verdict", "YELLOW"),
            reason=triage.get("reason", "MODIFICATION_REQUIRED"),
            install_method=triage.get("install_method"),
            required_transforms=transforms,
            warnings=triage.get("warnings", []),
            details=dry_run_details,
            output_apk=None,
            transform_risks=transform_risks,
            page_size_compat_verified=triage.get("page_size_compat_verified", True),
            verdict_display=triage.get("verdict_display"),
        )
        if getattr(args, "sarif", False):
            sarif_data = triage_to_sarif(report.to_dict(), input_path)
            print(json.dumps(sarif_data, indent=2))
        elif getattr(args, "json", False):
            print(json.dumps(report.to_dict(), indent=2))
        elif HAS_RICH and _is_interactive():
            banner = render_verdict_banner(report.verdict, report.reason, report.install_method)
            table = render_triage_table(report)
            print(banner)
            print(table)
        else:
            print(format_patch_report(report))
        return VERDICT_EXIT_CODES.get(triage.get("verdict", "YELLOW"), 0)

    with zipfile.ZipFile(input_path, "r") as zf:
        manifest_data = zf.read("AndroidManifest.xml")

    enable_60hz = getattr(args, "enable_60hz", False) or ("LOCK_60HZ_DISPLAY_MODE" in active_transforms)
    enable_cutout = getattr(args, "enable_cutout", False) or ("CUTOUT_SHORT_EDGES" in active_transforms)
    patched_axml = AxmlSurgeon.patch_manifest(
        manifest_data,
        active_transforms,
        options={"enable_60hz": enable_60hz, "enable_cutout": enable_cutout}
    )

    dex_indices = []
    has_shim_provider = False
    temp_apk = output_path + ".tmp"
    with zipfile.ZipFile(input_path, "r") as zin, zipfile.ZipFile(temp_apk, "w") as zout:
        for item in zin.infolist():
            if item.filename.startswith("META-INF/") and (
                item.filename.endswith(".SF") or item.filename.endswith(".RSA") or
                item.filename.endswith(".DSA") or item.filename.endswith(".EC") or
                item.filename.endswith(".MF")
            ):
                continue

            data = zin.read(item.filename)

            m = re.fullmatch(r"classes(\d*)\.dex", item.filename)
            if m:
                idx_str = m.group(1)
                idx = int(idx_str) if idx_str else 1
                dex_indices.append(idx)
                if b"ApkReviveInitProvider" in data:
                    has_shim_provider = True

            if item.filename == "AndroidManifest.xml":
                zout.writestr(item, patched_axml)
            else:
                zout.writestr(item, data)

        if (enable_60hz or enable_cutout) and not has_shim_provider:
            shim_path = os.path.join(os.path.dirname(__file__), "shim", "shim.dex")
            if os.path.exists(shim_path):
                next_idx = max(dex_indices) + 1 if dex_indices else 1
                shim_dex_name = f"classes{next_idx}.dex" if next_idx > 1 else "classes.dex"
                with open(shim_path, "rb") as sf:
                    zout.writestr(shim_dex_name, sf.read())

    align_apk(temp_apk, output_path)
    if os.path.exists(temp_apk):
        os.remove(temp_apk)

    sys.stderr.write(
        "WARNING: APK signature has changed. Re-signing requires uninstalling the existing "
        "application on device, which will permanently delete all existing user data.\n"
    )
    sys.stderr.flush()

    ks = getattr(args, "ks", None)
    ks_pass = getattr(args, "ks_pass", None)
    ks_alias = getattr(args, "ks_alias", None)
    key_pass = getattr(args, "key_pass", None)
    if not sign_apk(output_path, keystore_path=ks, keystore_pass=ks_pass, key_alias=ks_alias, key_pass=key_pass):
        return 1

    details = triage.get("details", "")
    if skipped_aspect:
        if details:
            details = f"{details}. {skip_note}."
        else:
            details = skip_note

    report = PatchReport(
        timestamp=datetime.now().isoformat(),
        apk_path=input_path,
        package_name=meta.package_name,
        target_sdk=meta.target_sdk,
        verdict=triage.get("verdict", "YELLOW"),
        reason=triage.get("reason", "MODIFICATION_REQUIRED"),
        install_method=triage.get("install_method"),
        required_transforms=transforms,
        warnings=triage.get("warnings", []),
        details=details,
        output_apk=output_path,
        transform_risks=transform_risks,
        page_size_compat_verified=triage.get("page_size_compat_verified", True),
        verdict_display=triage.get("verdict_display"),
    )
    if getattr(args, "sarif", False):
        sarif_data = triage_to_sarif(report.to_dict(), input_path)
        print(json.dumps(sarif_data, indent=2))
    elif getattr(args, "json", False):
        print(json.dumps(report.to_dict(), indent=2))
    elif HAS_RICH and _is_interactive():
        banner = render_verdict_banner(report.verdict, report.reason, report.install_method)
        table = render_triage_table(report)
        print(banner)
        print(table)
    else:
        print(format_patch_report(report))
    return VERDICT_EXIT_CODES.get(triage.get("verdict", "YELLOW"), 0)


def diff_cmd(args):
    orig = args.original_apk
    revived = args.revived_apk
    if not os.path.exists(orig):
        sys.stderr.write(f"ERROR: Original APK not found: {orig}\n")
        return 1
    if not os.path.exists(revived):
        sys.stderr.write(f"ERROR: Revived APK not found: {revived}\n")
        return 1

    diff_data = compute_apk_diff(orig, revived)
    if getattr(args, "sarif", False):
        sarif_data = diff_to_sarif(diff_data, orig, revived)
        print(json.dumps(sarif_data, indent=2))
    elif getattr(args, "json", False):
        print(json.dumps(diff_data, indent=2))
    else:
        print(render_apk_diff(diff_data))
    return 0


def probe_cmd(args):
    bridge = AdbBridge(serial=args.device)
    res = probe_install_floor(bridge)
    if getattr(args, "json", False):
        print(json.dumps(res, indent=2))
    else:
        print(json.dumps(res, indent=2))
    return 0


def push_obb_cmd(args):
    res = validate_obb_delivery(os.path.basename(args.obb), args.package, args.current_apk_version)
    if getattr(args, "json", False):
        print(json.dumps(res, indent=2))
    else:
        print(json.dumps(res, indent=2))
    return 0 if res["valid"] else 1


def doctor_cmd(args):
    res = run_doctor()
    if getattr(args, "json", False):
        print(json.dumps(res, indent=2))
    else:
        print(format_doctor_report(res))
    return 0 if res["status"] in ("PASS", "WARN") else 1


def main():
    parser = argparse.ArgumentParser(description="ApkRevive Modernizer CLI")
    parser.add_argument("--version", "-v", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    sub = parser.add_subparsers(dest="command")

    p_triage = sub.add_parser("triage", help="Triage APK compatibility")
    p_triage.add_argument("apk", help="Path to APK file")
    p_triage.add_argument("--device-api", type=int, default=35)
    p_triage.add_argument("--device-abis", default="arm64-v8a")
    p_triage.add_argument("--page-size", type=int, default=16384)
    p_triage.add_argument("--device-floor", type=int, default=24)
    p_triage.add_argument("--target-sdk", type=int, default=None)
    p_triage.add_argument("--apk-abis", default=None)
    p_triage.add_argument("--uses-apache-http", action="store_true", default=None)
    p_triage.add_argument("--enable-60hz", action="store_true", help="Include 60Hz display lock shim transform")
    p_triage.add_argument("--enable-cutout", action="store_true", help="Include display cutout layout transform")
    p_triage.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    p_triage.add_argument("--sarif", action="store_true", help="Output SARIF v2.1.0 telemetry")

    p_revive = sub.add_parser("revive", help="Modernize, patch, align and sign APK")
    p_revive.add_argument("apk", help="Path to APK file")
    p_revive.add_argument("--output", help="Output path")
    p_revive.add_argument("--dry-run", action="store_true", help="Perform triage and plan transforms without writing files or signing")
    p_revive.add_argument("--enable-60hz", action="store_true")
    p_revive.add_argument("--enable-cutout", action="store_true")
    p_revive.add_argument("--enable-resizable", action="store_true", help="Opt-in: inject resizeableActivity=true (Caution: may distort 2D canvas/HUD scaling)")
    p_revive.add_argument("--device-api", type=int, default=35)
    p_revive.add_argument("--page-size", type=int, default=16384)
    p_revive.add_argument("--ks", dest="ks", help="Path to PKCS12 keystore file")
    p_revive.add_argument("--ks-pass", dest="ks_pass", help="Keystore password")
    p_revive.add_argument("--ks-alias", dest="ks_alias", help="Key alias name")
    p_revive.add_argument("--key-pass", dest="key_pass", help="Key password (if different from keystore)")
    p_revive.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    p_revive.add_argument("--sarif", action="store_true", help="Output SARIF v2.1.0 telemetry")

    p_diff = sub.add_parser("diff", help="Visual binary diff between original and revived APK")
    p_diff.add_argument("original_apk", help="Path to original APK")
    p_diff.add_argument("revived_apk", help="Path to revived APK")
    p_diff.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    p_diff.add_argument("--sarif", action="store_true", help="Output SARIF v2.1.0 telemetry")

    p_probe = sub.add_parser("probe", help="Probe connected ADB device install floor")
    p_probe.add_argument("--device", help="Device serial")
    p_probe.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    p_obb = sub.add_parser("push-obb", help="Validate OBB delivery")
    p_obb.add_argument("obb", help="OBB file")
    p_obb.add_argument("package", help="Target package name")
    p_obb.add_argument("--current-apk-version", type=int, default=100)
    p_obb.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    p_doctor = sub.add_parser("doctor", help="Check host environment and prerequisites")
    p_doctor.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    args = parser.parse_args()
    if args.command == "triage": return triage_cmd(args)
    elif args.command == "revive": return revive_cmd(args)
    elif args.command == "diff": return diff_cmd(args)
    elif args.command == "probe": return probe_cmd(args)
    elif args.command == "push-obb": return push_obb_cmd(args)
    elif args.command == "doctor": return doctor_cmd(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
