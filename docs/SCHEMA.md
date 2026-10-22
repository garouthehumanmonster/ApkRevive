# ApkRevive Machine-Readable Output Schemas

This document provides authoritative schema specifications and concrete JSON representations for all machine-readable outputs produced by **ApkRevive** (v0.5.0).

---

## Table of Contents
1. [`apkrevive inspect --json` (InspectionReport)](#1-inspectionreport-apkrevive-inspect---json)
2. [`apkrevive triage --json` (Triage Evaluation Output)](#2-triage-evaluation-output-apkrevive-triage---json)
3. [`apkrevive patch --json` (PatchReport)](#3-patchreport-apkrevive-patch---json)
4. [`apkrevive verify --json` (VerificationReport)](#4-verificationreport-apkrevive-verify---json)
5. [`apkrevive diff --json` (DiffReport)](#5-diffreport-apkrevive-diff---json)
6. [`apkrevive diff --sarif` / `triage --sarif` (SARIF 2.1.0)](#6-sarif-210-document-apkrevive-diff---sarif--triage---sarif)
7. [`apkrevive doctor --json` (Doctor Diagnostics Report)](#7-doctor-diagnostics-report-apkrevive-doctor---json)
8. [Emulator Verification Receipts (`receipt_emulator_*.json`)](#8-emulator-verification-receipts-receipt_emulator_json)

---

## 1. InspectionReport (`apkrevive inspect --json`)

Emitted by `apkrevive inspect <apk> --json` and `InspectionReport.to_dict()` defined in `apkrevive.core.models`.

Evaluates an APK archive to identify package metadata, fatal binary blockers, remediable runtime issues, and advisory warnings prior to patching.

### Fields
| Field | Type | Description |
|---|---|---|
| `apk_path` | `string` | Absolute or relative path to the inspected APK file. |
| `package_name` | `string` | Extracted Android package identifier (e.g. `com.example.app`). |
| `version_code` | `integer` | Declared `android:versionCode` integer. |
| `min_sdk` | `integer` | Minimum supported Android SDK level (`android:minSdkVersion`). |
| `target_sdk` | `integer` | Declared target Android SDK level (`android:targetSdkVersion`). |
| `abis` | `list[string]` | List of CPU architectures present in `lib/<abi>/` (e.g. `["arm64-v8a", "armeabi-v7a"]`), or empty for pure DEX. |
| `fatal_blockers` | `list[string]` | Unresolvable platform obstacles preventing execution on 64-bit devices (e.g. 32-bit only native code, TEXTREL relocations). |
| `remediable_issues` | `list[string]` | Issues resolvable via binary surgery and shims (e.g. missing Apache HTTP, unaligned 16KB ELFs, low targetSdk). |
| `warnings` | `list[string]` | Advisory notices (e.g. hidden API reflection on API 28+, scoped storage path usage). |
| `page_size_16kb_status`| `string \| null` | 16KB page alignment status: `"ALIGNED"`, `"COMPAT_ONLY"`, `"UNSAFE"`, or `null`. |
| `private_bionic_libs` | `list[string]` | Non-NDK private Bionic shared libraries referenced by DT_NEEDED entries. |
| `is_32bit_only` | `boolean` | `true` if native libraries exist but none support 64-bit architectures (`arm64-v8a`, `x86_64`, `riscv64`). |
| `needs_apache_http` | `boolean` | `true` if classes reference legacy Apache HTTP classes without declared `<uses-library>`. |
| `install_floor_blocked`| `boolean` | `true` if `target_sdk < 23`, blocked by default on Android 14+ (API 34+). |

### Example
```json
{
  "apk_path": "canaries/canary_legacy_32bit.apk",
  "package_name": "com.example.legacygame",
  "version_code": 100,
  "min_sdk": 14,
  "target_sdk": 19,
  "abis": [
    "armeabi-v7a"
  ],
  "fatal_blockers": [
    "32-bit only native libraries (armeabi-v7a): incompatible with 64-bit-only devices (Android 14+ / Pixel 7+)"
  ],
  "warnings": [
    "targetSdk=19 < 28: subject to hidden API reflection restrictions on Android 9+ (API 28+)"
  ],
  "remediable_issues": [
    "targetSdk=19 < 23: blocked by install floor on Android 14+ (API 34+) and lacks runtime permission model"
  ],
  "page_size_16kb_status": null,
  "private_bionic_libs": [],
  "is_32bit_only": true,
  "needs_apache_http": false,
  "install_floor_blocked": true
}
```

---

## 2. Triage Evaluation Output (`apkrevive triage --json`)

Emitted by `apkrevive triage <apk> --json` and `evaluate_triage()` in `apkrevive.core.triage`.

Triages an APK against a target device profile (OS API level, supported ABIs, memory page size, install floor) to determine an executable compatibility verdict.

### Fields
| Field | Type | Description |
|---|---|---|
| `schema_version` | `string` | Triage schema version (`"2.1.0"`). |
| `verdict` | `string` | High-level verdict: `"GREEN"`, `"YELLOW"`, `"RED"`, or `"NEEDS_USER_INPUT"`. |
| `reason` | `string` | Canonical `TriageSignal` identifier (e.g. `"RUNNABLE_UNMODIFIED"`, `"MODIFICATION_REQUIRED"`, `"INCOMPATIBLE_DEVICE_ABI"`). |
| `install_method` | `string` | Recommended install invocation: `"DIRECT_INSTALL"`, `"BYPASS_LOW_TARGET_SDK_BLOCK"`, or `"CANNOT_INSTALL"`. |
| `details` | `string` | Human-readable explanation and operational guidance. |
| `warnings` | `list[string]` | Non-fatal behavioral change warnings. |
| `required_transforms` | `list[string]` | List of required AXML, ELF, or DEX transforms to revive the APK. |
| `transform_risks` | `dict[string, string]` | Risk classification per required transform (`"LOW"`, `"MEDIUM"`, `"HIGH"`). |
| `page_size_compat_verified` | `boolean` | `true` if 16KB `pageSizeCompat` execution is proven by a committed emulator/hardware receipt. |
| `verdict_display` | `string \| null` | Formatted verdict display string (e.g. `"YELLOW (UNVERIFIED)"`) if unverified. |

### Example
```json
{
  "schema_version": "2.1.0",
  "verdict": "YELLOW",
  "reason": "MODIFICATION_REQUIRED",
  "install_method": "BYPASS_LOW_TARGET_SDK_BLOCK",
  "details": "Requires transforms: ['PAGE_SIZE_COMPAT', 'INJECT_USES_LIBRARY_APACHE_HTTP', 'EXPAND_ASPECT_RATIO']",
  "warnings": [
    "WARN_SCOPED_STORAGE: Target SDK < 30 accesses legacy external storage; requires requestLegacyExternalStorage."
  ],
  "required_transforms": [
    "PAGE_SIZE_COMPAT",
    "INJECT_USES_LIBRARY_APACHE_HTTP",
    "EXPAND_ASPECT_RATIO"
  ],
  "transform_risks": {
    "PAGE_SIZE_COMPAT": "LOW",
    "INJECT_USES_LIBRARY_APACHE_HTTP": "LOW",
    "EXPAND_ASPECT_RATIO": "LOW"
  },
  "page_size_compat_verified": true,
  "verdict_display": null
}
```

---

## 3. PatchReport (`apkrevive patch --json`)

Emitted by `apkrevive patch <apk> -o <out.apk> --json` (or `apkrevive revive ...`) and `PatchReport.to_dict()` in `apkrevive.core.models`.

Reports the execution status and applied binary mutations following manifest surgery, Bionic patching, shim injection, 16KB zipalignment, and V2/V3 signing.

### Fields
| Field | Type | Description |
|---|---|---|
| `schema_version` | `string` | Schema version (`"2.1.0"`). |
| `timestamp` | `string` | ISO-8601 UTC execution timestamp. |
| `apk_path` | `string` | Path to original input APK. |
| `output_apk` | `string \| null` | Path to generated modernized APK. |
| `package_name` | `string` | Extracted Android package name. |
| `target_sdk` | `integer` | Final `targetSdkVersion` set in output APK. |
| `verdict` | `string` | Execution outcome verdict (`"GREEN"` or `"RED"`). |
| `reason` | `string` | Summary explanation of patching outcome. |
| `install_method` | `string \| null` | Recommended installation method. |
| `required_transforms` | `list[string]` | Planned transforms requested for execution. |
| `remediations` | `list[string]` | Human-readable log of applied mutations and injected shims. |
| `warnings` | `list[string]` | Runtime notices and installation caveats. |
| `details` | `string` | Operational detail narrative. |
| `transform_risks` | `dict[string, string]` | Risk level per applied transform. |
| `page_size_compat_verified` | `boolean` | Verification status flag. |
| `verdict_display` | `string \| null` | Optional display suffix. |
| `is_signed` | `boolean` | `true` if APK Signature Scheme v2/v3 was applied; `false` if `--no-sign` was passed. |

### Example
```json
{
  "schema_version": "2.1.0",
  "timestamp": "2026-10-22T07:25:30.123456+00:00",
  "apk_path": "canaries/canary_install_floor_failing.apk",
  "package_name": "com.apkrevive.canary.floor",
  "target_sdk": 19,
  "verdict": "GREEN",
  "reason": "Successfully patched and modernised legacy APK",
  "install_method": null,
  "required_transforms": [
    "SET_HAS_CODE_TRUE",
    "PAGE_SIZE_COMPAT",
    "EXPAND_ASPECT_RATIO",
    "INJECT_USES_LIBRARY_APACHE_HTTP"
  ],
  "warnings": [],
  "details": "",
  "output_apk": "canaries/canary_install_floor_failing.revived.apk",
  "transform_risks": {},
  "page_size_compat_verified": true,
  "verdict_display": null,
  "remediations": [
    "AXML: Injected org.apache.http.legacy <uses-library>",
    "AXML: Set extractNativeLibs='true' and requestLegacyExternalStorage='true'",
    "AXML: Preserved low targetSdkVersion 19 (prevents modern runtime permission & storage crashes; install via: 'adb install --bypass-low-target-sdk-block')",
    "AXML: Injected ApkReviveInitProvider lifecycle shim with pageSizeCompat and aspect ratio expansion",
    "DEX Shim: Injected classes2.dex containing ApkReviveInitProvider (Hidden API + StrictMode)",
    "Zipalign: 16KB (0x4000) alignment applied to uncompressed entries",
    "Signer: Applied APK Signature Scheme v2/v3"
  ],
  "is_signed": true
}
```

---

## 4. VerificationReport (`apkrevive verify --json`)

Emitted by `apkrevive verify <apk> --json` and `VerificationReport.to_dict()` in `apkrevive.core.verify`.

Provides binary verification receipts validating 16KB alignment, signing block integrity, Central Directory 4KB alignment, AXML parsing, and multidex class uniqueness.

### Fields
| Field | Type | Description |
|---|---|---|
| `apk_path` | `string` | Path to verified APK container. |
| `is_valid` | `boolean` | `true` if all mandatory container invariants pass. |
| `checks` | `dict[string, bool]` | Boolean status of each discrete verification check: `alignment`, `signature`, `axml`, `dex`. |
| `errors` | `list[string]` | Detailed diagnostic error messages for failed checks. |
| `details` | `dict[string, Any]` | Diagnostic telemetry: alignment entry offsets, signature scheme versions, AXML manifest tree, and DEX count. |
| `is_unsigned` | `boolean` | `true` if the container is intentionally unsigned (`--no-sign`). |

### Example
```json
{
  "apk_path": "canaries/canary_install_floor_failing.revived.apk",
  "is_valid": true,
  "checks": {
    "alignment": true,
    "signature": true,
    "axml": true,
    "dex": true
  },
  "errors": [],
  "details": {
    "alignment": {
      "aligned": true,
      "entries_checked": 6
    },
    "signature": {
      "has_signing_block": true,
      "cd_aligned_4k": true,
      "v2_v3_valid": true
    },
    "axml": {
      "package": "com.apkrevive.canary.floor",
      "target_sdk": 19,
      "has_application": true
    },
    "dex": {
      "dex_count": 2,
      "classes_count": 48
    }
  },
  "is_unsigned": false
}
```

---

## 5. DiffReport (`apkrevive diff --json`)

Emitted by `apkrevive diff <original_apk> <revived_apk> --json` and `compare_apks()` in `apkrevive.core.diff`.

Produces a deep, 5-dimensional binary comparison across Manifest, Native Libraries, DEX, Signature/Integrity, and Container structures.

### Fields
| Section | Field | Type | Description |
|---|---|---|---|
| Root | `original_apk` | `string` | Baseline APK path. |
| Root | `revived_apk` | `string` | Modernized APK path. |
| `manifest` | `package_name` | `dict` | `{"original": str, "revived": str, "changed": bool}` |
| `manifest` | `target_sdk` | `dict` | `{"original": int, "revived": int, "changed": bool}` |
| `manifest` | `min_sdk` | `dict` | `{"original": int, "revived": int, "changed": bool}` |
| `manifest` | `uses_apache_http` | `dict` | `{"original": bool, "revived": bool, "changed": bool}` |
| `manifest` | `injected_shim` | `dict` | `{"original": bool, "revived": bool, "injected": bool}` |
| `manifest` | `shim_injected` | `boolean` | `true` if `ApkReviveInitProvider` is declared in revived manifest. |
| `native_libs`| `abis` | `dict` | `{"original": list[str], "revived": list[str], "changed": bool}` |
| `native_libs`| `libraries` | `dict` | Mapping of library filenames to per-file compression, 16KB alignment, and data offsets. |
| `dex` | `dex_count` | `dict` | `{"original": int, "revived": int, "changed": bool}` |
| `dex` | `injected_classes` | `list[str]` | Descriptors of classes injected into revived DEX files. |
| `signature` | `has_signing_block`| `dict` | `{"original": bool, "revived": bool, "changed": bool}` |
| `signature` | `cd_aligned_4k` | `dict` | `{"original": bool, "revived": bool, "changed": bool}` |
| `signature` | `signature_valid` | `dict` | `{"original": bool, "revived": bool, "changed": bool}` |
| `signature` | `is_valid` | `dict` | `{"original": bool, "revived": bool, "changed": bool}` |
| `container` | `original_size` | `integer` | Size in bytes of original APK. |
| `container` | `revived_size` | `integer` | Size in bytes of revived APK. |
| `container` | `size_delta` | `integer` | Byte delta (`revived_size - original_size`). |
| `container` | `files_added` | `list[str]` | Entry names present in revived but absent in original. |
| `container` | `files_removed` | `list[str]` | Entry names stripped (e.g. old signature files). |
| `container` | `files_modified`| `list[str]` | Entry names with altered CRC32 hashes. |

### Example
```json
{
  "original_apk": "canaries/canary_install_floor_failing.apk",
  "revived_apk": "canaries/canary_install_floor_failing.revived.apk",
  "manifest": {
    "package_name": {
      "original": "com.apkrevive.canary.floor",
      "revived": "com.apkrevive.canary.floor",
      "changed": false
    },
    "target_sdk": {
      "original": 19,
      "revived": 19,
      "changed": false
    },
    "min_sdk": {
      "original": 14,
      "revived": 14,
      "changed": false
    },
    "uses_apache_http": {
      "original": false,
      "revived": true,
      "changed": true
    },
    "injected_shim": {
      "original": false,
      "revived": true,
      "injected": true
    },
    "shim_injected": true
  },
  "native_libs": {
    "abis": {
      "original": ["x86_64"],
      "revived": ["x86_64"],
      "changed": false
    },
    "libraries": {
      "lib/x86_64/libnative.so": {
        "abi": "x86_64",
        "original": {
          "path": "lib/x86_64/libnative.so",
          "abi": "x86_64",
          "compression": "deflated",
          "data_offset": 8192,
          "is_16k_aligned": false
        },
        "revived": {
          "path": "lib/x86_64/libnative.so",
          "abi": "x86_64",
          "compression": "stored",
          "data_offset": 16384,
          "is_16k_aligned": true
        },
        "compression_changed": true,
        "alignment_changed": true
      }
    }
  },
  "dex": {
    "dex_count": {
      "original": 1,
      "revived": 2,
      "changed": true
    },
    "classes_dex_count": {
      "original": 1,
      "revived": 2,
      "changed": true
    },
    "injected_classes": [
      "Lcom/apkrevive/shim/ApkReviveInitProvider;"
    ]
  },
  "signature": {
    "has_signing_block": {
      "original": false,
      "revived": true,
      "changed": true
    },
    "cd_aligned_4k": {
      "original": false,
      "revived": true,
      "changed": true
    },
    "signature_valid": {
      "original": false,
      "revived": true,
      "changed": true
    },
    "is_valid": {
      "original": false,
      "revived": true,
      "changed": true
    }
  },
  "container": {
    "original_size": 24576,
    "revived_size": 49152,
    "size_delta": 24576,
    "file_size_delta": 24576,
    "files_added": [
      "classes2.dex"
    ],
    "files_removed": [
      "META-INF/CERT.RSA",
      "META-INF/CERT.SF",
      "META-INF/MANIFEST.MF"
    ],
    "files_modified": [
      "AndroidManifest.xml",
      "lib/x86_64/libnative.so"
    ],
    "files": {
      "added": ["classes2.dex"],
      "removed": ["META-INF/CERT.RSA", "META-INF/CERT.SF", "META-INF/MANIFEST.MF"],
      "modified": ["AndroidManifest.xml", "lib/x86_64/libnative.so"]
    }
  }
}
```

---

## 6. SARIF 2.1.0 Document (`apkrevive diff --sarif` / `triage --sarif`)

Emitted by `apkrevive diff ... --sarif` via `diff_to_sarif()` in `apkrevive.core.diff`, and by `apkrevive triage ... --sarif` in `apkrevive.cli`.

Produces standard Static Analysis Results Interchange Format (SARIF) v2.1.0 output compliant with OASIS specifications and GitHub Code Scanning / Security Advisories.

### Structure
- **Root Object:**
  - `$schema`: `"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"`
  - `version`: `"2.1.0"`
  - `runs`: Array of analysis run objects.
- **Run Driver (`runs[].tool.driver`):**
  - `name`: `"apkrevive"`
  - `version`: Installed version (e.g. `"0.5.0"`).
  - `rules`: Array of rule definitions (`id`, `shortDescription`).
- **Results (`runs[].results`):**
  - `ruleId`: Identifier of detected modernization rule or triage blocker.
  - `level`: Severity level: `"none"`, `"note"`, `"warning"`, or `"error"`.
  - `message`: Diagnostic message text.
  - `locations`: Physical location specifying the APK file artifact URI.

### Standard Rule Identifiers
- `MODERNIZED_TARGET_SDK`: Target SDK bumped for platform compliance.
- `MODERNIZED_APACHE_HTTP`: Injected legacy Apache HTTP library.
- `MODERNIZED_SHIM_INJECTED`: Injected runtime lifecycle compatibility shim.
- `MODERNIZED_NATIVE_16KB_ALIGNMENT`: 64-bit ELF 16KB alignment and uncompressed storage.
- `MODERNIZED_DEX_EXPANSION`: Multidex container expanded.
- `MODERNIZED_SIGNATURE_4KB`: Central Directory 4KB alignment and V2/V3 signing block.

### Example
```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "apkrevive",
          "version": "0.5.0",
          "rules": [
            {
              "id": "MODERNIZED_APACHE_HTTP",
              "shortDescription": {
                "text": "Apache HTTP legacy library dependency injected"
              }
            },
            {
              "id": "MODERNIZED_SHIM_INJECTED",
              "shortDescription": {
                "text": "ApkReviveInitProvider runtime compatibility shim injected"
              }
            },
            {
              "id": "MODERNIZED_NATIVE_16KB_ALIGNMENT",
              "shortDescription": {
                "text": "64-bit native library 16KB boundary aligned and stored uncompressed"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "MODERNIZED_APACHE_HTTP",
          "level": "note",
          "message": {
            "text": "Injected org.apache.http.legacy <uses-library> declaration into AndroidManifest.xml"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "canaries/canary_install_floor_failing.revived.apk"
                }
              }
            }
          ]
        },
        {
          "ruleId": "MODERNIZED_SHIM_INJECTED",
          "level": "note",
          "message": {
            "text": "Injected ApkReviveInitProvider lifecycle provider for StrictMode laxing and hidden API bypass"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "canaries/canary_install_floor_failing.revived.apk"
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

---

## 7. Doctor Diagnostics Report (`apkrevive doctor --json`)

Emitted by `apkrevive doctor --json` and `diagnose_tools()` in `apkrevive.core.toolchain`.

Audits the host runtime environment for required JDK binaries (`javac`, `keytool`) and Android SDK build/platform tools (`apksigner`, `aapt2`, `d8`, `adb`).

### Structure
A JSON dictionary keyed by tool name (`"python"`, `"keytool"`, `"javac"`, `"d8"`, `"aapt2"`, `"apksigner"`, `"adb"`).

### Fields per Tool
| Field | Type | Description |
|---|---|---|
| `path` | `string \| null` | Resolved filesystem path to the tool binary, or `null` if unlocated. |
| `found` | `boolean` | `true` if the binary was located and executable. |
| `required_for_signing`| `boolean` | `true` if this binary is mandatory for APK signing (`keytool`, `apksigner`). |
| `hint` | `string` | Remediation instructions and install commands if missing. |

### Example
```json
{
  "python": {
    "path": "C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python313\\python.exe",
    "found": true,
    "required_for_signing": false,
    "hint": "Python runtime"
  },
  "keytool": {
    "path": "C:\\Program Files\\Java\\jdk-17\\bin\\keytool.exe",
    "found": true,
    "required_for_signing": true,
    "hint": "Install OpenJDK (e.g. 'apt install openjdk-17-jdk' or 'brew install openjdk')"
  },
  "javac": {
    "path": "C:\\Program Files\\Java\\jdk-17\\bin\\javac.exe",
    "found": true,
    "required_for_signing": false,
    "hint": "Install OpenJDK (e.g. 'apt install openjdk-17-jdk' or 'brew install openjdk')"
  },
  "d8": {
    "path": "C:\\Android\\Sdk\\build-tools\\35.0.0\\d8.bat",
    "found": true,
    "required_for_signing": false,
    "hint": "Install Android SDK build-tools via sdkmanager 'build-tools;35.0.0'"
  },
  "aapt2": {
    "path": "C:\\Android\\Sdk\\build-tools\\35.0.0\\aapt2.exe",
    "found": true,
    "required_for_signing": false,
    "hint": "Install Android SDK build-tools via sdkmanager 'build-tools;35.0.0'"
  },
  "apksigner": {
    "path": "C:\\Android\\Sdk\\build-tools\\35.0.0\\apksigner.bat",
    "found": true,
    "required_for_signing": true,
    "hint": "Install Android SDK build-tools via sdkmanager 'build-tools;35.0.0'"
  },
  "adb": {
    "path": "C:\\Android\\Sdk\\platform-tools\\adb.exe",
    "found": true,
    "required_for_signing": false,
    "hint": "Install Android SDK platform-tools via sdkmanager 'platform-tools'"
  }
}
```

---

## 8. Emulator Verification Receipts (`receipt_emulator_*.json`)

Written to `results/` by `scripts/verify_emulator_e2e.py` and generated via `scripts/make_receipt.py`.

Records concrete verification evidence on 16KB Android emulators and devices, proving install-floor bypass, 16KB container alignment, Central Directory 4KB alignment, V2/V3 signing, and runtime shim execution.

### Fields
| Field | Type | Description |
|---|---|---|
| `verification_type` | `string` | Type identifier (`"emulator_e2e_16kb"` or `"apk_verification_receipt"`). |
| `timestamp` | `string` | ISO-8601 UTC timestamp of execution. |
| `date` | `string` | Execution date in `YYYY-MM-DD` format. |
| `simulated` | `boolean` | `false` if verified against a live emulator/device; `true` if executed in dry-run mode. |
| `pass_fail` | `string` | Final outcome: `"PASS"` or `"FAIL"`. |
| `api_level` | `integer` | Android OS API level (e.g. `35`). |
| `os_api_level` | `integer` | Alias of `api_level`. |
| `abi` | `string` | Target architecture (e.g. `"x86_64"`, `"arm64-v8a"`). |
| `device_abi` | `string` | Device ABI. |
| `device_model` | `string` | Connected device model or emulator descriptor. |
| `page_size` | `integer` | Memory page size in bytes (`16384` for 16KB). |
| `kernel_page_size` | `integer` | Kernel page size in bytes. |
| `script` | `string` | Generating verification script. |
| `target_apk` | `string` | Target APK basename. |
| `revived_apk` | `string` | Modernized revived APK basename. |
| `alignment` | `dict` | Alignment status: `aligned_16kb` (`bool`), `entries_checked` (`int`), `cd_aligned_4k` (`bool`). |
| `signing` | `dict` | Signing status: `has_signing_block` (`bool`), `cd_aligned_4k` (`bool`). |
| `runtime_verification`| `dict` | Live runtime checks (install-floor blocked unpatched, install-floor passed revived, StrictMode laxing, hidden API bypass, process active). |
| `status` | `string` | Overall operational status (`"SUCCESS"` or `"FAILED"`). |

### Example
```json
{
  "verification_type": "emulator_e2e_16kb",
  "timestamp": "2026-10-22T07:27:10.123384+00:00",
  "date": "2026-10-22",
  "simulated": true,
  "pass_fail": "PASS",
  "api_level": 35,
  "os_api_level": 35,
  "abi": "x86_64",
  "arch": "x86_64",
  "device_abi": "x86_64",
  "device_model": "Android SDK built for x86_64 (emulator-5554)",
  "page_size": 16384,
  "kernel_page_size": 16384,
  "script": "scripts/verify_emulator_e2e.py",
  "target_apk": "canary_install_floor_failing.apk",
  "revived_apk": "canary_install_floor_failing.revived.apk",
  "alignment": {
    "aligned_16kb": true,
    "entries_checked": 6,
    "cd_aligned_4k": true
  },
  "signing": {
    "has_signing_block": true,
    "cd_aligned_4k": true
  },
  "runtime_verification": {
    "install_floor_blocked_unpatched": true,
    "install_floor_passed_revived": true,
    "apache_http_check": "PASSED",
    "strict_mode_file_uri_check": "PASSED",
    "hidden_api_vmruntime_check": "PASSED",
    "apkrevive_init_provider": "PASSED",
    "app_process_active": "PASSED"
  },
  "status": "SUCCESS"
}
```
