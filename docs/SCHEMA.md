# ApkRevive Machine-Readable JSON Schema Specification

This document defines the authoritative JSON output schemas emitted by ApkRevive CLI commands, test harnesses, diagnostic engines, and evidence collection scripts.

All JSON outputs in ApkRevive version 0.5.0a1+ conform to Semantic Versioning and include a top-level `schema_version` attribute.

```json
{
  "schema_version": "1.0.0"
}
```

---

## 1. Schema Versioning Policy

- **Current Specification**: `1.0.0`
- **Backwards Compatibility**: Adding non-breaking, optional fields increments the minor version (`1.1.0`). Existing consumers can safely ignore unrecognized fields.
- **Breaking Changes**: Modifying or removing existing mandatory fields, changing types, or altering enum meanings increments the major version (`2.0.0`).

---

## 2. Triage Output Schema (`apkrevive triage --json`)

Emitted by `apkrevive triage <apk> --json` and `evaluate_triage()` in `apkrevive.core.triage`.

### Fields
| Field | Type | Description |
|---|---|---|
| `schema_version` | `string` | Schema version (e.g. `"1.0.0"`). |
| `verdict` | `string` | Triage decision: `"GREEN"`, `"YELLOW"`, `"RED"`, `"NEEDS_USER_INPUT"`. |
| `reason` | `string` | Primary triage signal identifier. |
| `install_method` | `string` | Recommended install pathway: `"DIRECT_INSTALL"`, `"BYPASS_LOW_TARGET_SDK_BLOCK"`. |
| `details` | `string` | Plain-text explanation of verdict rationales. |
| `warnings` | `list[string]` | Remediation codes and advisory warnings. |
| `required_transforms` | `list[string]` | List of transform IDs needed to achieve runtime compatibility. |
| `transform_risks` | `dict[string, string]` | Mapping of transform ID to risk tier (`"LOW"`, `"MEDIUM"`, `"HIGH"`). |
| `page_size_compat_verified` | `boolean` | `true` if 16KB execution is backed by non-simulated receipts. |
| `verdict_display` | `string \| null` | Formatted display verdict (e.g. `"YELLOW (UNVERIFIED)"`). |

### Example
```json
{
  "schema_version": "1.0.0",
  "verdict": "YELLOW",
  "reason": "MODIFICATION_REQUIRED",
  "install_method": "BYPASS_LOW_TARGET_SDK_BLOCK",
  "details": "APK targetSdk 22 is below device install floor 24",
  "warnings": [
    "WARN_SCOPED_STORAGE_OBB: Application requests external storage permissions on Android 11+ (API 30+)."
  ],
  "required_transforms": [
    "EXPAND_ASPECT_RATIO",
    "INJECT_USES_LIBRARY_APACHE_HTTP",
    "LOCK_60HZ_DISPLAY_MODE"
  ],
  "transform_risks": {
    "EXPAND_ASPECT_RATIO": "LOW",
    "INJECT_USES_LIBRARY_APACHE_HTTP": "LOW",
    "LOCK_60HZ_DISPLAY_MODE": "LOW"
  },
  "page_size_compat_verified": true,
  "verdict_display": null
}
```

---

## 3. Revive Patch Report Schema (`apkrevive revive --json`)

Emitted by `apkrevive revive <apk> --json` (and `--dry-run --json`) and `PatchReport.to_dict()` in `apkrevive.core.models`.

### Fields
| Field | Type | Description |
|---|---|---|
| `schema_version` | `string` | Schema version (e.g. `"1.0.0"`). |
| `timestamp` | `string` | ISO-8601 UTC timestamp of execution. |
| `apk_path` | `string` | Path to original input APK. |
| `package_name` | `string` | Extracted Android package name. |
| `target_sdk` | `integer` | Declared targetSdkVersion of the input APK. |
| `verdict` | `string` | Modernization outcome verdict (`"GREEN"`, `"YELLOW"`, `"RED"`). |
| `reason` | `string` | Reason identifier. |
| `install_method` | `string \| null` | Install method chosen. |
| `required_transforms` | `list[string]` | Planned/applied bytecode and manifest transforms. |
| `warnings` | `list[string]` | Advisory notices. |
| `details` | `string` | Operation audit narrative. |
| `output_apk` | `string \| null` | Path to output revived APK (`null` for dry runs). |
| `transform_risks` | `dict[string, string]` | Risk mapping per transform. |
| `page_size_compat_verified` | `boolean` | Receipt-backed status flag. |
| `verdict_display` | `string \| null` | Optional display suffix. |

---

## 4. Visual Binary Diff Schema (`apkrevive diff --json`)

Emitted by `apkrevive diff <orig> <revived> --json` and `compute_apk_diff()` in `apkrevive.cli.diff`.

### Fields
| Field | Type | Description |
|---|---|---|
| `schema_version` | `string` | Schema version (e.g. `"1.0.0"`). |
| `original_apk` | `string` | Path to baseline original APK. |
| `revived_apk` | `string` | Path to modernized comparison APK. |
| `manifest_diff` | `dict` | Attribute deltas across AndroidManifest.xml (target_sdk, min_sdk, has_code, resizeable_activity, pageSizeCompat, uses_libraries, providers, meta_data). |
| `dex_diff` | `dict` | DEX entry listing, multi-dex count, and shim provider presence. |
| `alignment_ladder` | `list[dict]` | Byte alignment verification ladder for ZIP offsets and ELF PT_LOAD segments. |

---

## 5. Doctor Diagnostic Report Schema (`apkrevive doctor --json`)

Emitted by `apkrevive doctor --json` and `run_doctor()` in `apkrevive.core.doctor`.

### Fields
| Field | Type | Description |
|---|---|---|
| `schema_version` | `string` | Schema version (e.g. `"1.0.0"`). |
| `status` | `string` | Overall host health status: `"PASS"`, `"WARN"`, `"FAIL"`. |
| `pass` | `list[string]` | List of passing diagnostic subsystems. |
| `warn` | `list[string]` | List of non-fatal warning subsystems. |
| `fail` | `list[string]` | List of failing required subsystems. |
| `checks` | `dict` | Subsystem detail dictionaries (`python`, `jdk`, `android_sdk`, `build_tools`, `adb`, `keystore_dir`, `shim_dex`). |

---

## 6. Install Floor Probe Schema (`apkrevive probe --json`)

Emitted by `apkrevive probe --json` and `probe_install_floor()` in `apkrevive.adb.probe`.

### Fields
| Field | Type | Description |
|---|---|---|
| `schema_version` | `string` | Schema version (e.g. `"1.0.0"`). |
| `floor` | `integer \| string` | Detected min_supported_target_sdk floor (e.g. `24`, `"NONE"`, `"UNKNOWN"`). |
| `status` | `string` | Detection confidence code (`"CONFIRMED_VIA_PROP"`, `"DETECTED_VIA_AOSP_ERROR"`, `"STANDARD_BASELINE"`, `"UNKNOWN_FUTURE_API"`). |
| `sdk` | `integer` | Connected device OS API level. |

---

## 7. OBB Expansion Delivery Schema (`apkrevive push-obb --json`)

Emitted by `apkrevive push-obb ... --json` and `validate_obb_delivery()` in `apkrevive.core.obb`.

### Fields
| Field | Type | Description |
|---|---|---|
| `schema_version` | `string` | Schema version (e.g. `"1.0.0"`). |
| `valid` | `boolean` | `true` if filename format, package name, and path traversal guards pass. |
| `reason` | `string \| null` | Rejection code if invalid. |
| `obb_type` | `string \| null` | Expansion type (`"main"` or `"patch"`). |
| `obb_version` | `integer \| null` | Expansion target version code. |
| `destination_path` | `string \| null` | Standard Android destination on device (`/Android/obb/<pkg>/...`). |
| `warning` | `string \| null` | Warning if expansion version is ahead of APK version. |

---

## 8. Verification Receipt Schema (`receipts/*.json`)

Created by `scripts/make_receipt.py` to record physical device or emulator execution facts.

### Fields
| Field | Type | Description |
|---|---|---|
| `schema_version` | `string` | Schema version (e.g. `"1.0.0"`). |
| `device_model` | `string` | Sanitize device model name (e.g. `"sdk_gphone16k_x86_64"`). |
| `api_level` | `integer` | Android OS API level (e.g. `35`, `37`). |
| `abi` | `string` | Primary CPU architecture (e.g. `"x86_64"`, `"arm64-v8a"`). |
| `page_size` | `integer` | Hardware memory page size in bytes (e.g. `16384` or `4096`). |
| `date` | `string` | Execution date in `YYYY-MM-DD` format. |
| `script` | `string` | Authoritative verification script path. |
| `simulated` | `boolean` | Must be strictly `false` for real evidence receipts. |

### Privacy & Sanitization Invariant
Receipts are stripped of personal identifiers (`serial`, `device_serial`, `username`, `hostname`, `IP`).

---

## 9. Compatibility Survey Report Schema (`results/survey/*.json`)

Created by `scripts/survey.py` across full multi-APK legacy evaluation runs.

### Fields
| Field | Type | Description |
|---|---|---|
| `schema_version` | `string` | Schema version (e.g. `"1.0.0"`). |
| `device_info` | `dict` | Target device profile properties. |
| `total_apks` | `integer` | Total legacy APK corpus size. |
| `direct_install_stats` | `dict` | Success/failure counts for standard `adb install`. |
| `bypass_install_stats` | `dict` | Success/failure counts for `--bypass-low-target-sdk-block`. |
| `revive_install_stats` | `dict` | Success/failure counts for revived package installations. |
| `liveness_stats` | `dict` | Counts for `"ALIVE"`, `"CRASH"`, `"DEAD"`, `"SKIPPED"`. |
| `failure_category_counts`| `dict` | Histogram of failure categories (`"ABI"`, `"GREYLIST"`, `"GLES1"`, `"DEAD_SDK"`, `"CRASH"`, `"INSTALL_FLOOR_BLOCKED"`, `"NONE"`, `"OTHER"`). |
| `per_apk_records` | `list[dict]` | Per-package detailed execution trial records. |
| `results` | `list[dict]` | Alias to `per_apk_records`. |
| `receipt_file` | `string` | Path to companion verification receipt. |

---

## 10. Canary Matrix Receipt Schema (`results/*.json`)

Created by `scripts/verify_canary_matrix.py` and validated by `scripts/generate_matrix.py`.

### Fields
| Field | Type | Description |
|---|---|---|
| `schema_version` | `string` | Schema version (e.g. `"1.0.0"`). |
| `device_model` | `string` | Device model or verification rig identifier. |
| `android_build` | `string` | System build identifier. |
| `kernel_page_size` | `integer` | Memory page size in bytes (`4096` or `16384`). |
| `refresh_rate` | `integer` | Display refresh rate in Hertz. |
| `emulator_or_hardware` | `string` | One of `"emulator"`, `"hardware"`, `"local_host"`. |
| `date` | `string` | Verification date in `YYYY-MM-DD` format. |
| `tool_commit` | `string` | Git commit SHA of the verification toolchain. |
| `canary_id` | `string` | Canonical canary identifier. |
| `expected` | `string` | Expected test outcome. |
| `observed` | `string` | Concrete execution telemetry observed. |
| `pass_fail` | `string` | `"PASS"` or `"FAIL"`. |
| `simulated` | `boolean` | `true` if simulated; `false` if verified against a real device or emulator. |
