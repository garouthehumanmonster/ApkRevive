"""
cli.py - Main entrypoint for ApkRevive inspect and patch CLI.
"""

import argparse
import json
import mmap
import os
import re
import struct
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from typing import Any, List, Optional, Set

from apkrevive import __version__
from apkrevive.core.models import (
    InspectionReport,
    PatchReport,
    DeviceProfile,
)
from apkrevive.core.extractor import inspect_apk
from apkrevive.core.axml import AxmlSurgeon
from apkrevive.core.align import align_apk, validate_zip_archive
from apkrevive.core.signer import sign_apk, verify_apk_certs as verify_apk_certs
from apkrevive.core.verify import verify_apk_integrity, VerificationReport
from apkrevive.core.toolchain import find_jdk_tool, find_sdk_tool, run_doctor
from apkrevive.core.diff import (
    run_diff,
    format_diff_report,
    diff_to_sarif,
)
from apkrevive.core.elf_surgeon import (
    rewrite_elf_16kb,
    get_elf_needed,
    PRIVATE_BIONIC_LIBS,
)
from apkrevive.core.dex_surgeon import (
    get_next_multidex_name,
)

KNOWN_64BIT_ABIS = {"arm64-v8a", "x86_64", "riscv64"}
KNOWN_32BIT_ABIS = {"armeabi", "armeabi-v7a", "x86", "mips", "mips64"}


def run_inspect(apk_path: str) -> InspectionReport:
    """Evaluates an APK and returns an InspectionReport detailing fatal blockers and remediations."""
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")
    validate_zip_archive(apk_path)

    meta = inspect_apk(apk_path)

    fatal_blockers: List[str] = []
    remediable_issues: List[str] = []
    warnings: List[str] = []

    # 1. 32-bit only native library check
    has_native_libs = bool(meta.abis)
    has_64bit = any(abi in KNOWN_64BIT_ABIS for abi in meta.abis)
    is_32bit_only = has_native_libs and not has_64bit

    if is_32bit_only:
        fatal_blockers.append(
            f"32-bit only native libraries ({', '.join(meta.abis)}): incompatible with 64-bit-only devices (Android 14+ / Pixel 7+)"
        )

    # 2. Private Bionic Libraries (libcrypto, libssl, libcutils, etc.)
    private_bionic_found = [
        lib for lib in meta.private_libs
        if lib in PRIVATE_BIONIC_LIBS or "libcrypto" in lib or "libssl" in lib or "libcutils" in lib
    ]
    if private_bionic_found:
        remediable_issues.append(
            f"Private Bionic linker dependencies: {', '.join(private_bionic_found)} (blocked by namespace isolation on API 24+)"
        )

    # 3. targetSdk < 23 (Install floor & runtime permissions)
    install_floor_blocked = meta.target_sdk < 23
    if install_floor_blocked:
        remediable_issues.append(
            f"targetSdk={meta.target_sdk} < 23: blocked by install floor on Android 14+ (API 34+) and lacks runtime permission model"
        )
    elif meta.target_sdk < 28:
        warnings.append(
            f"targetSdk={meta.target_sdk} < 28: subject to hidden API reflection restrictions on Android 9+ (API 28+)"
        )

    # 4. Missing Apache HTTP legacy library
    if meta.uses_apache_http:
        remediable_issues.append(
            "Missing org.apache.http.legacy declaration: crashes with NoClassDefFoundError on API 28+"
        )

    # 5. 16KB Page Size Alignment (for 64-bit native libraries)
    if has_64bit:
        if meta.elf_16kb_status in ("UNSAFE", "COMPAT_ONLY") or (
            meta.elf_load_align_64bit is not None and meta.elf_load_align_64bit < 16384
        ):
            remediable_issues.append(
                f"64-bit ELF shared libraries not 16KB aligned (align={meta.elf_load_align_64bit}, status={meta.elf_16kb_status}): crashes on Android 15+ 16KB devices"
            )

    # 6. Legacy storage / hardcoded paths
    if meta.accesses_scoped_storage_paths:
        warnings.append(
            "Hardcoded legacy external storage paths (/sdcard, /storage) detected: crashes on API 30+ without runtime shim"
        )

    # 7. Non-resizeable / aspect ratio
    if meta.is_non_resizeable:
        remediable_issues.append(
            "Legacy non-resizeable activity: letterboxed / pillarboxed on modern tall aspect ratio displays"
        )

    # 8. TEXTREL detection
    if meta.has_textrel:
        fatal_blockers.append(
            f"Text relocations (TEXTREL) in {', '.join(meta.textrel_libs)}: forbidden by linker on Android 6.0+ (API 23+)"
        )

    return InspectionReport(
        apk_path=apk_path,
        package_name=meta.package_name,
        version_code=meta.version_code,
        min_sdk=meta.min_sdk,
        target_sdk=meta.target_sdk,
        abis=meta.abis,
        fatal_blockers=fatal_blockers,
        warnings=warnings,
        remediable_issues=remediable_issues,
        page_size_16kb_status=meta.elf_16kb_status,
        private_bionic_libs=private_bionic_found,
        is_32bit_only=is_32bit_only,
        needs_apache_http=meta.uses_apache_http,
        install_floor_blocked=install_floor_blocked,
    )


def format_inspection_report(rep: InspectionReport) -> str:
    lines = [
        "============================================================",
        f"  ApkRevive Inspection Report: {os.path.basename(rep.apk_path)}",
        "============================================================",
        f"  Package Name:   {rep.package_name}",
        f"  Version Code:   {rep.version_code}",
        f"  Target SDK:     {rep.target_sdk}  (minSdk: {rep.min_sdk})",
        f"  Native ABIs:    {', '.join(rep.abis) if rep.abis else 'None (pure DEX)'}",
    ]
    if rep.page_size_16kb_status:
        lines.append(f"  16KB Page Size: {rep.page_size_16kb_status}")

    lines.append("")
    if rep.fatal_blockers:
        lines.append("[!] FATAL BLOCKERS (Cannot run on target architecture):")
        for b in rep.fatal_blockers:
            lines.append(f"    - {b}")
        lines.append("")

    if rep.remediable_issues:
        lines.append("[*] REMEDIABLE RUNTIME ISSUES (Fixable via 'apkrevive patch'):")
        for r in rep.remediable_issues:
            lines.append(f"    - {r}")
        lines.append("")

    if rep.warnings:
        lines.append("[?] WARNINGS:")
        for w in rep.warnings:
            lines.append(f"    - {w}")
        lines.append("")

    if not rep.fatal_blockers and not rep.remediable_issues:
        lines.append("[+] Status: App is already modern and compatible.")
    elif rep.fatal_blockers:
        lines.append("[-] Verdict: BLOCKED. Fatal unresolvable blockers prevent execution on modern 64-bit devices.")
    else:
        lines.append("[+] Verdict: REMEDIABLE. Run 'apkrevive patch' to apply compatibility shims.")

    return "\n".join(lines)


def run_patch(
    input_apk: str,
    output_apk: str,
    bump_target_sdk: Optional[int] = None,
    no_sign: bool = False,
    keystore_path: Optional[str] = None,
    keystore_pass: Optional[str] = None,
    key_alias: Optional[str] = None,
    key_pass: Optional[str] = None,
    quiet: bool = False,
) -> PatchReport:
    """Executes the binary mutation pipeline to revive a legacy APK."""
    validate_zip_archive(input_apk)
    meta = inspect_apk(input_apk)
    if meta.is_split_apk:
        sys.stderr.write("ERROR: Split APK detected. Split APKs cannot be modernized independently.\n")
        raise ValueError("Split APK detected. Split APKs cannot be modernized independently.")

    remediations: List[str] = []
    transforms: List[str] = [
        "SET_HAS_CODE_TRUE",
        "PAGE_SIZE_COMPAT",
        "EXPAND_ASPECT_RATIO",
        "INJECT_USES_LIBRARY_APACHE_HTTP",
    ]

    remediations.append("AXML: Injected org.apache.http.legacy <uses-library>")
    remediations.append("AXML: Set extractNativeLibs='true' and requestLegacyExternalStorage='true'")

    target_sdk_to_set = bump_target_sdk if bump_target_sdk is not None else meta.target_sdk
    if bump_target_sdk is not None and bump_target_sdk != meta.target_sdk:
        remediations.append(f"AXML: Bumped targetSdkVersion {meta.target_sdk} -> {target_sdk_to_set}")
    elif meta.target_sdk < 24:
        remediations.append(
            f"AXML: Preserved low targetSdkVersion {meta.target_sdk} (prevents modern runtime permission & storage crashes; "
            f"install via: 'adb install --bypass-low-target-sdk-block')"
        )

    remediations.append("AXML: Injected ApkReviveInitProvider lifecycle shim with pageSizeCompat and aspect ratio expansion")

    temp_unaligned = tempfile.NamedTemporaryFile(suffix="_unaligned.apk", delete=False).name
    temp_aligned = tempfile.NamedTemporaryFile(suffix="_aligned.apk", delete=False).name

    try:
        # Step 1: Read AndroidManifest.xml and perform AXML surgery
        with zipfile.ZipFile(input_apk, "r") as zin:
            if "AndroidManifest.xml" not in zin.namelist():
                raise ValueError("AndroidManifest.xml missing from input APK")
            raw_manifest = zin.read("AndroidManifest.xml")

        patched_manifest = AxmlSurgeon.patch_manifest(
            raw_manifest,
            transforms=transforms,
            options={
                "bump_target_sdk": target_sdk_to_set,
                "inject_shim": True,
                "enable_60hz": True,
                "enable_cutout": True,
            },
        )

        # Step 2: Repack APK with patched manifest, rewritten ELFs, and injected shim.dex
        shim_dex_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "shim", "shim.dex")
        if not os.path.exists(shim_dex_path):
            raise FileNotFoundError(f"Runtime shim bytecode missing at {shim_dex_path}. Run build_shim.py first.")

        with open(shim_dex_path, "rb") as sf:
            shim_dex_bytes = sf.read()

        dex_indices: List[int] = []
        has_shim_provider = False
        found_abis: Set[str] = set()
        existing_filenames: Set[str] = set()

        with zipfile.ZipFile(input_apk, "r") as zin, zipfile.ZipFile(temp_unaligned, "w") as zout:
            for item in zin.infolist():
                filename = item.filename
                existing_filenames.add(filename)

                # Track DEX indices
                m = re.fullmatch(r"classes(\d*)\.dex", filename)
                if m:
                    idx_str = m.group(1)
                    idx = int(idx_str) if idx_str else 1
                    dex_indices.append(idx)

                # Skip old signatures and manifest (will be replaced)
                if filename == "AndroidManifest.xml":
                    continue
                if filename.startswith("META-INF/") and (
                    filename.endswith(".SF")
                    or filename.endswith(".RSA")
                    or filename.endswith(".DSA")
                    or filename.endswith(".EC")
                    or filename == "META-INF/MANIFEST.MF"
                ):
                    continue

                content = zin.read(filename)

                if filename.endswith(".dex") and b"ApkReviveInitProvider" in content:
                    has_shim_provider = True

                # Native library patching (DT_NEEDED audit and 16KB alignment)
                if filename.startswith("lib/") and filename.endswith(".so"):
                    item.compress_type = zipfile.ZIP_STORED
                    parts = filename.split("/")
                    if len(parts) >= 3:
                        found_abis.add(parts[1])

                    # 16KB alignment for 64-bit ELFs
                    if "arm64-v8a" in filename or "x86_64" in filename:
                        rewritten = rewrite_elf_16kb(content)
                        if rewritten != content:
                            content = rewritten
                            remediations.append(f"ELF 16KB: Aligned {filename} to 16KB boundaries")

                    # DT_NEEDED audit
                    needed = get_elf_needed(content)
                    for lib in needed:
                        if lib in PRIVATE_BIONIC_LIBS:
                            remediations.append(
                                f"Bionic Linker: Private dependency {lib} detected in {filename} "
                                "(non-NDK platform library blocked on API 24+)"
                            )

                elif filename == "resources.arsc":
                    item.compress_type = zipfile.ZIP_STORED

                zout.writestr(item, content)

            # Write mutated manifest
            zout.writestr("AndroidManifest.xml", patched_manifest)

            # Inject ApkReviveInitProvider bytecode shim as next classesN.dex (if not already present)
            if not has_shim_provider:
                existing_dex_names = [f"classes{i}.dex" if i > 1 else "classes.dex" for i in dex_indices]
                shim_dex_name = get_next_multidex_name(existing_dex_names)
                zout.writestr(shim_dex_name, shim_dex_bytes)
                remediations.append(f"DEX Shim: Injected {shim_dex_name} containing ApkReviveInitProvider (Hidden API + StrictMode)")

            # Warn on 32-bit only APKs
            if found_abis:
                has_64bit = any(abi in KNOWN_64BIT_ABIS for abi in found_abis)
                has_32bit = any(abi in KNOWN_32BIT_ABIS for abi in found_abis)
                if has_32bit and not has_64bit:
                    abi_str = ", ".join(sorted(found_abis))
                    first_abi = sorted(found_abis)[0]
                    remediations.append(
                        f"Warning: 32-bit only APK ({abi_str}). Target device must support 32-bit execution, "
                        f"or installation requires: 'adb install --abi {first_abi} --bypass-low-target-sdk-block'"
                    )

        # Step 3: 16KB Zipalign
        align_apk(temp_unaligned, temp_aligned, page_align_64bit=16384)
        remediations.append("Zipalign: 16KB (0x4000) alignment applied to uncompressed entries")

        # Step 4: Output and Signing
        import shutil
        shutil.copyfile(temp_aligned, output_apk)
        if not no_sign:
            signed = sign_apk(
                output_apk,
                keystore_path=keystore_path,
                keystore_pass=keystore_pass,
                key_alias=key_alias,
                key_pass=key_pass,
            )
            if not signed:
                raise RuntimeError(f"Failed to sign output APK {output_apk} with apksigner.")
            remediations.append("Signer: Applied APK Signature Scheme v2/v3")
        else:
            remediations.append("Signer: Signing skipped (--no-sign)")

        # Step 5: Post-signing 16KB data_offset verification check
        with open(output_apk, "rb") as f_out:
            with mmap.mmap(f_out.fileno(), 0, access=mmap.ACCESS_READ) as apk_buf:
                eocd_pos = apk_buf.rfind(b"PK\x05\x06")
                if eocd_pos == -1:
                    raise AssertionError("Invalid output APK: missing EOCD")
                cd_count, cd_size, cd_off = struct.unpack_from("<HII", apk_buf, eocd_pos + 10)
                curr = cd_off
                for _ in range(cd_count):
                    method, = struct.unpack_from("<H", apk_buf, curr + 10)
                    fn_len, ef_len, comm_len = struct.unpack_from("<HHH", apk_buf, curr + 28)
                    lfh_off, = struct.unpack_from("<I", apk_buf, curr + 42)
                    fname = apk_buf[curr + 46 : curr + 46 + fn_len].decode("utf-8", errors="replace")
                    if method == 0 and ((fname.startswith("lib/") and fname.endswith(".so")) or fname.endswith(".so") or fname == "resources.arsc"):
                        lfh_fn_len, lfh_ef_len = struct.unpack_from("<HH", apk_buf, lfh_off + 26)
                        data_off = lfh_off + 30 + lfh_fn_len + lfh_ef_len
                        assert data_off % 16384 == 0, f"Uncompressed entry {fname} not aligned to 16KB (offset: 0x{data_off:x})"
                    curr += 46 + fn_len + ef_len + comm_len

    finally:
        for p in (temp_unaligned, temp_aligned):
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass

    return PatchReport(
        timestamp=datetime.now(timezone.utc).isoformat(),
        apk_path=input_apk,
        package_name=meta.package_name,
        target_sdk=target_sdk_to_set,
        verdict="GREEN",
        reason="Successfully patched and modernised legacy APK",
        output_apk=output_apk,
        remediations=remediations,
        required_transforms=transforms,
        is_signed=not no_sign,
    )


def format_patch_report(report: PatchReport) -> str:
    lines = [
        "============================================================",
        "  ApkRevive Patch Execution Complete",
        "============================================================",
        f"  Input APK:   {report.apk_path}",
        f"  Output APK:  {report.output_apk}",
        f"  Package:     {report.package_name} (targetSdk={report.target_sdk})",
        "",
        "  Applied Remediations:",
    ]
    for rem in report.remediations:
        lines.append(f"    [+] {rem}")
    lines.append("")
    if not getattr(report, "is_signed", True):
        lines.append("  App is revived (UNSIGNED). Signing was skipped.")
        lines.append("  To install on Android 12+, sign the APK via 'apksigner' or rerun without '--no-sign'.")
    else:
        lines.append("  App is revived and ready for installation on modern Android devices.")
    return "\n".join(lines)


def run_verify(apk_path: str, verbose: bool = False) -> VerificationReport:
    """Runs post-patch verification battery on an APK and returns a VerificationReport."""
    return verify_apk_integrity(apk_path, verbose=verbose)


def format_verification_report(report: VerificationReport, verbose: bool = False) -> str:
    """Formats human-readable terminal output for VerificationReport."""
    if report.is_valid:
        overall_str = "[PASS (UNSIGNED)]" if getattr(report, "is_unsigned", False) else "[PASS]"
    else:
        overall_str = "[FAIL]"
    sig_str = "PASS (UNSIGNED)" if getattr(report, "is_unsigned", False) else ("PASS" if report.checks.get("signature") else "FAIL")

    lines = [
        "============================================================",
        "  ApkRevive Post-Patch Verification",
        "============================================================",
        f"  APK Path:  {report.apk_path}",
        f"  Overall:   {overall_str}",
        "",
        "  Checks:",
        f"    [{'PASS' if report.checks.get('alignment') else 'FAIL'}] 16KB Container Alignment",
        f"    [{sig_str}] V2/V3 APK Signing Block (4KB CD alignment)",
        f"    [{'PASS' if report.checks.get('axml') else 'FAIL'}] AndroidManifest.xml Binary AXML Parsing",
        f"    [{'PASS' if report.checks.get('dex') else 'FAIL'}] Contiguous Multidex & No Class Collisions",
    ]
    if getattr(report, "is_unsigned", False):
        lines.append("")
        lines.append("  Notice:\n    [*] Container is unsigned. Installation on Android 12+ requires signing via 'apkrevive patch' or 'apksigner'.")
    if report.errors:
        lines.append("")
        lines.append("  Errors:")
        for err in report.errors:
            lines.append(f"    [!] {err}")
    if verbose and report.details:
        lines.append("")
        lines.append("  Details:")
        for k, v in report.details.items():
            lines.append(f"    - {k}: {v}")
    lines.append("============================================================")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="apkrevive",
        description=f"ApkRevive {__version__} - Android Legacy APK Modernizer & Compatibility Shims",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: inspect
    p_inspect = subparsers.add_parser(
        "inspect",
        help="Inspect APK for fatal blockers (32-bit only, private bionic symbols, targetSdk < 23, Apache HTTP)",
    )
    p_inspect.add_argument("apk", help="Path to input APK file")
    p_inspect.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # Subcommand: triage
    p_triage = subparsers.add_parser(
        "triage",
        help="Triage APK against target Android device profile and behavior changes",
    )
    p_triage.add_argument("apk", help="Path to input APK file")
    p_triage.add_argument("--device-api", type=int, default=35, help="Target device OS API level")
    p_triage.add_argument("--device-abis", default="arm64-v8a", help="Comma-separated target device supported ABIs")
    p_triage.add_argument("--page-size", type=int, default=16384, help="Target device page size in bytes")
    p_triage.add_argument("--device-floor", type=int, default=24, help="Target device minimum install floor API level")
    p_triage.add_argument("--target-sdk", type=int, default=None, help="Override APK targetSdkVersion")
    p_triage.add_argument("--apk-abis", default=None, help="Override APK native ABIs (comma-separated)")
    p_triage.add_argument("--uses-apache-http", action="store_true", default=None, help="Override Apache HTTP usage")
    p_triage.add_argument("--json", action="store_true", help="Output raw JSON format")
    p_triage.add_argument("--sarif", action="store_true", help="Output SARIF 2.1.0 telemetry format")

    # Subcommand: patch
    p_patch = subparsers.add_parser(
        "patch",
        aliases=["revive"],
        help="Execute binary mutation pipeline (AXML surgery, Bionic DT_NEEDED patching, DEX shim injection, 16KB zipalign, V2/V3 signing)",
    )
    p_patch.add_argument("apk", help="Path to input APK file")
    p_patch.add_argument("-o", "--output", default=None, help="Path for output revived APK")
    p_patch.add_argument("--bump-target-sdk", type=int, default=None, help="Override targetSdkVersion")
    p_patch.add_argument("--no-sign", action="store_true", help="Skip APK V2/V3 signing step")
    p_patch.add_argument("--keystore", default=None, help="Path to custom PKCS12 keystore")
    p_patch.add_argument("--ks", default=None, help=argparse.SUPPRESS)
    p_patch.add_argument("--ks-pass", default=None, help=argparse.SUPPRESS)
    p_patch.add_argument("--ks-alias", default=None, help=argparse.SUPPRESS)
    p_patch.add_argument("--key-pass", default=None, help=argparse.SUPPRESS)
    p_patch.add_argument("--json", action="store_true", help="Output machine-readable JSON report")

    # Subcommand: verify
    p_verify = subparsers.add_parser(
        "verify",
        help="Run comprehensive post-patch verification battery",
    )
    p_verify.add_argument("apk", help="Path to APK to verify")
    p_verify.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    p_verify.add_argument("--verbose", action="store_true", help="Verbose diagnostics")

    # Subcommand: doctor
    subparsers.add_parser(
        "doctor",
        help="Check and diagnose JDK and Android SDK toolchain prerequisites",
    )

    # Subcommand: diff
    p_diff = subparsers.add_parser(
        "diff",
        help="Compare original and revived APKs across manifest, native libs, DEX, and signing",
    )
    p_diff.add_argument("original_apk", help="Path to original input APK")
    p_diff.add_argument("revived_apk", help="Path to modernized/revived APK")
    p_diff.add_argument("--json", action="store_true", help="Output machine-readable JSON diff")
    p_diff.add_argument("--sarif", action="store_true", help="Output SARIF 2.1.0 telemetry diff")

    args = parser.parse_args(argv)

    if args.command == "doctor":
        return run_doctor()

    if args.command == "diff":
        try:
            diff_res = run_diff(args.original_apk, args.revived_apk)
            if getattr(args, "sarif", False):
                print(json.dumps(diff_to_sarif(diff_res), indent=2))
            elif getattr(args, "json", False):
                print(json.dumps(diff_res, indent=2))
            else:
                print(format_diff_report(diff_res))
            return 0
        except FileNotFoundError as e:
            sys.stderr.write(f"File not found: {e}\n")
            return 2
        except Exception as e:
            sys.stderr.write(f"Error comparing APKs: {e}\n")
            return 2

    if args.command in ("inspect", "triage"):
        if args.command == "triage":
            return triage_cmd(args)
        try:
            report = run_inspect(args.apk)
            if args.json:
                print(json.dumps(report.to_dict(), indent=2))
            else:
                print(format_inspection_report(report))
            return 1 if report.fatal_blockers else 0
        except Exception as e:
            sys.stderr.write(f"Error inspecting APK: {e}\n")
            return 2

    elif args.command in ("patch", "revive"):
        if not getattr(args, "no_sign", False):
            missing_signing = []
            if not find_jdk_tool("keytool"):
                missing_signing.append("keytool")
            if not find_sdk_tool("apksigner"):
                missing_signing.append("apksigner")
            if missing_signing:
                sys.stderr.write(
                    f"Error: Missing required signing tool(s): {', '.join(missing_signing)}.\n"
                    "APK signing requires JDK (keytool) and Android SDK build-tools (apksigner).\n"
                    "Run 'apkrevive doctor' to diagnose your environment or use '--no-sign' to skip signing.\n"
                )
                return 1

        if args.command == "revive":
            return revive_cmd(args)
        try:
            out_apk = args.output or args.apk.replace(".apk", ".revived.apk")
            ks_path = args.keystore or getattr(args, "ks", None)
            rep = run_patch(
                input_apk=args.apk,
                output_apk=out_apk,
                bump_target_sdk=args.bump_target_sdk,
                no_sign=args.no_sign,
                keystore_path=ks_path,
                keystore_pass=getattr(args, "ks_pass", None),
                key_alias=getattr(args, "ks_alias", None),
                key_pass=getattr(args, "key_pass", None),
            )
            if args.json:
                print(json.dumps(rep.to_dict(), indent=2))
            else:
                print(format_patch_report(rep))
            return 0
        except Exception as e:
            sys.stderr.write(f"Error patching APK: {e}\n")
            return 2

    elif args.command == "verify":
        try:
            vreport = run_verify(args.apk, verbose=args.verbose)
            if args.json:
                print(json.dumps(vreport.to_dict(), indent=2))
            else:
                print(format_verification_report(vreport, verbose=args.verbose))
            return 0 if vreport.is_valid else 1
        except FileNotFoundError as e:
            sys.stderr.write(f"File not found: {e}\n")
            return 2
        except Exception as e:
            sys.stderr.write(f"Error verifying APK: {e}\n")
            return 2

    return 0


# Legacy CLI compatibility wrappers for test suites
def triage_cmd(args: Any) -> int:
    from apkrevive.core.triage import evaluate_triage

    apk_path = getattr(args, "apk", "")
    if apk_path and os.path.exists(apk_path):
        validate_zip_archive(apk_path)
        meta = inspect_apk(apk_path)
        meta_dict = meta.to_dict()
    else:
        apk_target_sdk = getattr(args, "target_sdk", None)
        if apk_target_sdk is None:
            apk_target_sdk = 28
        apk_abis_str = getattr(args, "apk_abis", "") or ""
        apk_abis = [a.strip() for a in apk_abis_str.split(",") if a.strip()]
        meta_dict = {
            "target_sdk": apk_target_sdk,
            "abis": apk_abis,
            "uses_apache_http": bool(getattr(args, "uses_apache_http", False)),
        }

    # Apply overrides to metadata dict before evaluation
    if getattr(args, "target_sdk", None) is not None:
        meta_dict["target_sdk"] = int(args.target_sdk)
    if getattr(args, "apk_abis", None) is not None:
        meta_dict["abis"] = [a.strip() for a in str(args.apk_abis).split(",") if a.strip()]
    if getattr(args, "uses_apache_http", None) is not None:
        meta_dict["uses_apache_http"] = bool(args.uses_apache_http)

    dev_abis_str = getattr(args, "device_abis", "arm64-v8a") or "arm64-v8a"
    dev_abis = [a.strip() for a in str(dev_abis_str).split(",") if a.strip()]
    dev = DeviceProfile(
        os_api_level=int(getattr(args, "device_api", 35) or 35),
        supported_abis=dev_abis,
        install_floor=int(getattr(args, "device_floor", None) or 0),
        page_size_bytes=int(getattr(args, "page_size", 16384) or 16384),
    )

    res = evaluate_triage(meta_dict, dev)

    verdict = str(res.get("verdict", ""))
    if verdict == "GREEN":
        code = 0
    elif verdict == "YELLOW":
        code = 2
    else:
        code = 3

    if getattr(args, "sarif", False):
        level_map = {
            "YELLOW": "warning",
            "RED": "error",
            "GREEN": "none",
        }
        sarif_level = level_map.get(verdict, "warning")
        rule_id = str(res.get("reason") or verdict)
        details = str(res.get("details") or f"Triage verdict: {verdict}")
        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "apkrevive",
                            "version": __version__,
                            "rules": [
                                {
                                    "id": rule_id,
                                    "shortDescription": {
                                        "text": rule_id,
                                    },
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": rule_id,
                            "level": sarif_level,
                            "message": {
                                "text": details,
                            },
                        }
                    ],
                }
            ],
        }
        print(json.dumps(sarif_doc, indent=2))
    else:
        print(json.dumps(res, indent=2))

    return code


def revive_cmd(args: Any) -> int:
    if not getattr(args, "no_sign", False):
        missing_signing = []
        if not find_jdk_tool("keytool"):
            missing_signing.append("keytool")
        if not find_sdk_tool("apksigner"):
            missing_signing.append("apksigner")
        if missing_signing:
            sys.stderr.write(
                f"Error: Missing required signing tool(s): {', '.join(missing_signing)}.\n"
                "APK signing requires JDK (keytool) and Android SDK build-tools (apksigner).\n"
                "Run 'apkrevive doctor' to diagnose your environment or use '--no-sign' to skip signing.\n"
            )
            return 1

    input_path = getattr(args, "apk", "")
    output_path = getattr(args, "output", None) or input_path.replace(".apk", ".revived.apk")
    if os.path.exists(input_path):
        meta = inspect_apk(input_path)
        if meta.is_split_apk:
            sys.stderr.write("ERROR: Split APK detected. Split APKs cannot be modernized independently.\n")
            return 1
    sys.stderr.write(
        "WARNING: APK signature has changed. Re-signing breaks Google Play updates, "
        "signature-based licensing (Google LVL), and anti-tamper DRM checks. "
        "Installing the revived APK requires uninstalling the existing application "
        "on device, which will permanently delete all existing user data.\n"
    )
    ks = getattr(args, "ks", None) or getattr(args, "keystore", None)
    rep = run_patch(
        input_apk=input_path,
        output_apk=output_path,
        bump_target_sdk=getattr(args, "bump_target_sdk", None),
        keystore_path=ks,
        keystore_pass=getattr(args, "ks_pass", None),
        key_alias=getattr(args, "ks_alias", None),
        key_pass=getattr(args, "key_pass", None),
        no_sign=getattr(args, "no_sign", False),
    )
    if getattr(args, "json", False):
        print(json.dumps(rep.to_dict(), indent=2))
    else:
        print(format_patch_report(rep))
    return 0


__all__ = [
    "run_inspect",
    "run_patch",
    "run_verify",
    "run_doctor",
    "run_diff",
    "format_diff_report",
    "diff_to_sarif",
    "format_inspection_report",
    "format_patch_report",
    "format_verification_report",
    "main",
    "triage_cmd",
    "revive_cmd",
]
if __name__ == "__main__":
    sys.exit(main())
