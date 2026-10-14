"""
cli.py - Main entrypoint for ApkRevive modernizer CLI.
"""

import argparse
import json
import sys
import os
import zipfile
from datetime import datetime
from apkrevive.core.models import DeviceProfile, ApkMetadata, PatchReport
from apkrevive.core.triage import evaluate_triage
from apkrevive.core.axml import AxmlSurgeon
from apkrevive.core.align import align_apk
from apkrevive.core.signer import sign_apk
from apkrevive.core.obb import validate_obb_delivery
from apkrevive.core.extractor import inspect_apk
from apkrevive.adb.bridge import AdbBridge
from apkrevive.adb.probe import probe_install_floor
from apkrevive import __version__


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

    res = evaluate_triage(apk, dev)
    print(json.dumps(res, indent=2))
    return 0 if res["verdict"] == "GREEN" else 1


def revive_cmd(args):
    input_path = args.apk
    output_path = args.output or input_path.replace(".apk", ".revived.apk")

    # Dynamically extract APK metadata and evaluate triage verdict
    meta = inspect_apk(input_path)
    triage = evaluate_triage(meta, DeviceProfile())

    # Build active transforms from triage and CLI overrides
    transforms = list(triage.get("required_transforms", []))
    if getattr(args, "enable_60hz", False) and "LOCK_60HZ_DISPLAY_MODE" not in transforms:
        transforms.append("LOCK_60HZ_DISPLAY_MODE")
    if getattr(args, "enable_cutout", False) and "CUTOUT_SHORT_EDGES" not in transforms:
        transforms.append("CUTOUT_SHORT_EDGES")

    # Read AndroidManifest.xml from input APK
    with zipfile.ZipFile(input_path, "r") as zf:
        manifest_data = zf.read("AndroidManifest.xml")

    # Mutate AXML with active transforms and options
    enable_60hz = getattr(args, "enable_60hz", False) or ("LOCK_60HZ_DISPLAY_MODE" in transforms)
    enable_cutout = getattr(args, "enable_cutout", False) or ("CUTOUT_SHORT_EDGES" in transforms)
    patched_axml = AxmlSurgeon.patch_manifest(
        manifest_data,
        transforms,
        options={"enable_60hz": enable_60hz, "enable_cutout": enable_cutout}
    )

    has_shim_provider = False
    temp_apk = output_path + ".tmp"
    with zipfile.ZipFile(input_path, "r") as zin, zipfile.ZipFile(temp_apk, "w") as zout:
        existing_files = set()
        for item in zin.infolist():
            # Strip stale signature artifacts so re-signing succeeds without digest conflict
            if item.filename.startswith("META-INF/") and (
                item.filename.endswith(".SF") or item.filename.endswith(".RSA") or
                item.filename.endswith(".DSA") or item.filename.endswith(".EC") or
                item.filename.endswith(".MF")
            ):
                continue
            existing_files.add(item.filename)
            data = zin.read(item.filename)
            # Detect whether ApkReviveInitProvider already exists in bytecode
            if item.filename.endswith(".dex") and b"ApkReviveInitProvider" in data:
                has_shim_provider = True

            if item.filename == "AndroidManifest.xml":
                zout.writestr(item, patched_axml)
            else:
                zout.writestr(item, data)

        # Inject shim only if requested and not already present in existing DEX
        if (enable_60hz or enable_cutout) and not has_shim_provider:
            shim_path = os.path.join(os.path.dirname(__file__), "shim", "shim.dex")
            if os.path.exists(shim_path):
                dex_idx = 1
                while (f"classes{dex_idx if dex_idx > 1 else ''}.dex") in existing_files:
                    dex_idx += 1
                shim_dex_name = f"classes{dex_idx}.dex"
                with open(shim_path, "rb") as sf:
                    zout.writestr(shim_dex_name, sf.read())

    align_apk(temp_apk, output_path)
    if os.path.exists(temp_apk):
        os.remove(temp_apk)

    # Abort with non-zero exit code if signing fails
    if not sign_apk(output_path):
        return 1

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
        details=triage.get("details", ""),
        output_apk=output_path
    )
    print(json.dumps(report.to_dict(), indent=2))
    return 0


def probe_cmd(args):
    bridge = AdbBridge(serial=args.device)
    res = probe_install_floor(bridge)
    print(json.dumps(res, indent=2))
    return 0


def push_obb_cmd(args):
    res = validate_obb_delivery(os.path.basename(args.obb), args.package, args.current_apk_version)
    print(json.dumps(res, indent=2))
    return 0 if res["valid"] else 1


def main():
    parser = argparse.ArgumentParser(description="ApkRevive Modernizer CLI")
    parser.add_argument("--version", "-v", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_triage = sub.add_parser("triage")
    p_triage.add_argument("apk", help="Path to APK file")
    p_triage.add_argument("--device-api", type=int, default=35)
    p_triage.add_argument("--device-abis", default="arm64-v8a")
    p_triage.add_argument("--page-size", type=int, default=16384)
    p_triage.add_argument("--device-floor", type=int, default=24)
    p_triage.add_argument("--target-sdk", type=int, default=None)
    p_triage.add_argument("--apk-abis", default=None)
    p_triage.add_argument("--uses-apache-http", action="store_true", default=None)

    p_revive = sub.add_parser("revive")
    p_revive.add_argument("apk", help="Path to APK file")
    p_revive.add_argument("--output", help="Output path")
    p_revive.add_argument("--enable-60hz", action="store_true")
    p_revive.add_argument("--enable-cutout", action="store_true")

    p_probe = sub.add_parser("probe")
    p_probe.add_argument("--device", help="Device serial")

    p_obb = sub.add_parser("push-obb")
    p_obb.add_argument("obb", help="OBB file")
    p_obb.add_argument("package", help="Target package name")
    p_obb.add_argument("--current-apk-version", type=int, default=100)

    args = parser.parse_args()
    if args.command == "triage": return triage_cmd(args)
    elif args.command == "revive": return revive_cmd(args)
    elif args.command == "probe": return probe_cmd(args)
    elif args.command == "push-obb": return push_obb_cmd(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
