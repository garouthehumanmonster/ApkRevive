# ApkRevive Operational Limits & Boundaries

This document defines the strict operational boundaries of ApkRevive. It details what ApkRevive **cannot** do, architectural edge cases where bytecode surgery is insufficient, and platform trade-offs inherent in running legacy Android applications on modern operating systems.

---

## 1. 32-Bit-Only Binaries on 64-Bit-Only Hardware

### The Constraint
Modern ARM processors (ARMv9 architecture, including Google Tensor G2+, Snapdragon 8 Gen 3, Dimensity 9300, and 64-bit-only devices like Pixel 7, Pixel 8, Pixel 9) completely remove hardware support for 32-bit execution (`AArch32` state at `EL0`).

### What ApkRevive Cannot Do
- ApkRevive **cannot** synthesize, decompile, or translate 64-bit native shared libraries (`.so`) from 32-bit machine code (`armeabi-v7a`, `x86`, `mips`).
- If an APK contains only 32-bit `.so` files in `lib/armeabi-v7a` or `lib/x86` and does not provide 64-bit equivalents (`lib/arm64-v8a` or `lib/x86_64`), modern 64-bit-only operating systems will reject installation with:
  ```
  INSTALL_FAILED_NO_MATCHING_ABIS: Failed to extract native libraries, res=-113
  ```
- Or, if forced into the filesystem, the dynamic linker (`/system/bin/linker64`) will abort with `java.lang.UnsatisfiedLinkError`.

### Remediation & Ceilings
- **Recompile from Source**: The application maintainer must recompile native C/C++ components using a modern Android NDK targeting `arm64-v8a`.
- **Hardware Selection**: Run the application on devices or emulators that implement hardware or software 32-bit support (e.g., standard 32-bit-capable Android emulators, or x86_64 emulators equipped with `libndk_translation` / Houdini).

### 16KB Kernel Page Alignment Exemption
32-bit ELF binaries (`ELFCLASS32`, e.g., `armeabi-v7a`, `x86`) are strictly exempt from 16KB kernel page alignment checks and are preserved byte-for-byte unmodified. Android kernels that support 32-bit execution manage 32-bit tasks via 4KB page compatibility mappings; 16KB ELF alignment constraints apply exclusively to 64-bit architectures (`ELFCLASS64`, `arm64-v8a`, `x86_64`).

---

## 2. Dead Google SDKs & Sunset Cloud Services

### The Constraint
Legacy applications often depend on deprecated or discontinued proprietary Google Play Services and system libraries that no longer exist on modern Android distributions or whose remote backend infrastructure has been permanently taken offline.

### What ApkRevive Cannot Do
ApkRevive can inject manifest declarations for legacy framework libraries present in the Android OS (such as `org.apache.http.legacy`), but it **cannot** restore defunct remote cloud servers or proprietary closed-source client SDKs:

1. **Google Maps API v1 (`com.google.android.maps`)**:
   - The original Google Maps v1 API relied on `MapView` and backend map tile servers that Google permanently decommissioned in March 2013.
   - Modern devices do not bundle `com.google.android.maps.jar`. Apps requiring it will fail triage with `UNRESOLVABLE_SYSTEM_LIBRARY` or throw `ClassNotFoundException` at runtime.
2. **Legacy Google Cloud Messaging (GCM)**:
   - GCM infrastructure was permanently decommissioned in April 2019 in favor of Firebase Cloud Messaging (FCM). Legacy GCM registration endpoints fail to resolve.
3. **Google Play In-App Billing (IAB v1, v2, v3)**:
   - Obsolete In-App Billing AIDL contracts have been sunset. Modern Google Play Store clients reject transaction requests from legacy billing interfaces, preventing in-app purchases.
4. **Apache Harmony Cryptographic Internals**:
   - Private internal classes (such as `org.apache.harmony.xnet.provider.jsse.*`) were removed in Android 10+. Apps that instantiate Harmony SSL sockets directly crash during network initialization.

### Remediation & Ceilings
- Replace obsolete cloud-dependent SDKs with modern equivalents (e.g. migrate Maps v1 to Maps SDK v2/v3, GCM to FCM).
- For pure offline functionality, use stubbing or mock libraries where available.

---

## 3. DRM, Anti-Tamper & Integrity Attestation

### The Constraint
Enterprise, banking, high-value gaming, and DRM-protected media applications implement cryptographic verification mechanisms to ensure binary integrity and trusted execution environments.

### What ApkRevive Cannot Do
Any modification to an APK—whether patching `AndroidManifest.xml`, injecting `ApkReviveInitProvider`, renumbering DEX files, or re-aligning ELF segments—breaks digital signatures and trips anti-tamper protections:

1. **Google Play Integrity API & SafetyNet Attestation**:
   - Play Integrity evaluates the cryptographic hash and signing certificate of the installed application against Google Play's canonical database.
   - Revived APKs fail integrity checks (`MEETS_BASIC_INTEGRITY`, `MEETS_DEVICE_INTEGRITY`, `MEETS_STRONG_INTEGRITY`). Applications enforcing Play Integrity will refuse to launch or lock access to remote APIs.
2. **Hardware-Backed DRM (Widevine Modular L1 / L3)**:
   - Secure media pipelines verify application identity and signature certificates inside TrustZone / Hardware Security Modules (HSM). Re-signed binaries cannot obtain valid cryptographic licenses for encrypted streams.
3. **Self-Signature Verification**:
   - Applications that verify their own signing certificate fingerprint at runtime (e.g. querying `PackageManager.getPackageInfo(GET_SIGNATURES)`) will detect that ApkRevive's signing key does not match the original developer certificate and terminate immediately.
4. **Commercial Packers & Obfuscators**:
   - Binaries protected by commercial packers (DexGuard, Arxan, SecNeo, Tencent Legu, Denuvo) detect byte modifications or debugging shims and crash intentionally to prevent analysis.

---

## 4. Re-Signing Consequences & Cryptographic Signature Breaks

### The Constraint
Android's security architecture treats the cryptographic signing certificate as the definitive identity of an application package. Re-signing an application is required after modifying its contents, which has significant operational side effects.

### What Breaks on Re-Signing
1. **Google Play In-Place Update Incompatibility & Data Wipe**:
   - Android's package manager strictly enforces signature consistency across app updates. A revived APK cannot update an existing app installed from Google Play or signed with original vendor keys (`INSTALL_FAILED_UPDATE_INCOMPATIBLE`).
   - Installing the revived APK requires an explicit uninstall of the existing application (`adb uninstall <package>`), which **permanently deletes all user data, application databases, and local storage** in `/data/data/<package_name>`.
2. **Signature-Level Permission Restrictions (`protectionLevel="signature"`) & Shared User IDs**:
   - Permissions declared with `android:protectionLevel="signature"` are granted by the system only to packages signed with the exact same cryptographic certificate.
   - Re-signing breaks custom signature permissions, causing IPC interfaces, content providers, and services protected by signature permissions to reject requests.
   - Applications that share Linux UIDs (`android:sharedUserId`) to access common databases and files must be signed with the identical cryptographic certificate; re-signing one app without re-signing all companion apps breaks shared process isolation.
3. **Android Keystore Cryptographic Keys**:
   - Keys stored in the Android Keystore (`AndroidKeyStore`) that are bound to the application's signature or authorization tokens are invalidated when the package signature changes.
4. **Encrypted SQLite Databases (SQLCipher / Custom Salts)**:
   - If an application derives database encryption keys or password salts from its signing certificate fingerprint, the existing database cannot be decrypted by the revived package.
5. **OAuth & Third-Party APIs**:
   - Google Sign-In, Firebase, Facebook SDK, and Twitter OAuth require developer console registration of the app's signing certificate SHA-1 fingerprint. Re-signed APKs receive authentication rejections (`DEVELOPER_ERROR` / 10).

---

## 5. Target SDK Bumps & Runtime Permissions (Android 6.0+)

### The Constraint
Modern Android releases (Android 14 API 34, Android 15 API 35, Android 16 API 36) enforce a minimum installation floor (`targetSdkVersion >= 24`). Direct installation of legacy apps targeting API < 24 fails with:
```
INSTALL_FAILED_DEPRECATED_SDK_VERSION: App package must target at least SDK version 24, but found 22
```

### The Architectural Conflict
ApkRevive supports bumping `targetSdkVersion` to the device floor via `--bump-target-sdk 24` or `--standalone-install`. However, bumping `targetSdkVersion` across the Android 6.0 (API 23) boundary fundamentally alters the OS permission model:

1. **Install-Time vs. Runtime Permissions**:
   - For `targetSdkVersion < 23`, Android grants all declared permissions at install time.
   - For `targetSdkVersion >= 23`, all permissions categorized as **dangerous** (`READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`, `CAMERA`, `ACCESS_FINE_LOCATION`, `RECORD_AUDIO`, `READ_CONTACTS`, `READ_PHONE_STATE`) require dynamic runtime requests via `ActivityCompat.requestPermissions()`.
2. **Silent Failure & SecurityExceptions**:
   - Legacy applications written for API < 23 do not contain code to invoke runtime permission dialogs.
   - When executed with a bumped targetSdk on modern Android, calling protected system APIs throws a `SecurityException` or returns empty/null results, causing immediate application crashes.

### Recommended Best Practice
- **Prefer Privileged Bypass**: Whenever ADB or Shizuku is available, prefer the privileged bypass:
  ```bash
  adb install -r --bypass-low-target-sdk-block legacy_app.apk
  ```
  Or using the ApkRevive Companion app. Privileged bypass maintains the original `targetSdkVersion`, keeping install-time permission semantics intact.
- **Grant Permissions Pre-emptively on Bump**: If targetSdk must be bumped for standalone distribution, always pre-grant all requested permissions during installation:
  ```bash
  adb install -g -r bumped_app.revived.apk
  ```
  Or execute `adb shell pm grant <package> <permission>` for each dangerous permission declared in the manifest.

---

## 6. Zip64 Archives Unsupported by In-Place Aligner

### The Constraint
Zip64 extensions (`PK\x06\x06` EOCD64 record, `PK\x06\x07` EOCD64 locator, `0xFFFF` entry counts, or `0xFFFFFFFF` 64-bit size/offset fields) allow ZIP containers exceeding 4GB or 65,535 entries. Standard Android APKs are limited by platform package manager specifications and do not use Zip64.

### What ApkRevive Refuses
The in-place ZIP aligner (`apkrevive.core.align`) explicitly fails closed upon encountering any Zip64 structure, raising `UnsupportedZip64Error`:
```python
raise UnsupportedZip64Error("Zip64 APKs are not supported by the in-place aligner; use build-tools zipalign")
```
ApkRevive will **never** silently corrupt Zip64 archives or attempt partial in-place rewrites of 64-bit offsets. Users handling Zip64 archives must use Android SDK `zipalign`.

---

## 7. Split APK Resource Table Merging Unsupported Without Explicit Opt-In

### The Constraint
Android App Bundles / Split APKs often contain distinct localized or screen-density resource tables (`resources.arsc`) in split configurations (e.g. `split_config.xxhdpi.apk`). Merging compiled binary resource tables requires de-indexing, deduplicating type specs, and rebuilding the `ResTable` chunk hierarchy, which cannot be done soundly without a full AAPT2 compilation pass.

### What ApkRevive Refuses
By default, `apkrevive.core.split_merger.merge_split_apks` fails closed if a secondary split APK contains a `resources.arsc` file, raising:
```python
raise UnsupportedSplitMerge("Secondary split contains resources.arsc which cannot be soundly merged without resource table recompilation")
```
To proceed when resource table loss is acceptable (e.g. relying solely on base APK resources), callers must pass `allow_resource_table_loss=True` (or CLI `--allow-resource-table-loss`). In this mode, secondary resource tables are dropped and `WARN_SPLIT_RESOURCE_TABLE_LOSS` is emitted, cataloging the dropped split qualifiers.

---

## 8. Non-Invasive ELF Handling: Relinking & PIE Refused with Byte Preservation

### The Constraint
Legacy 4KB-linked 64-bit shared libraries (`p_align == 0x1000`) or non-PIE executables cannot be realigned to 16KB boundaries (`0x4000`) purely through in-place binary header patching. Changing virtual segment alignments shifts segment relative virtual addresses, invalidating relative function calls, GOT/PLT offsets, string tables, dynamic symbols, and internal relocation entries.

### Refusal Policy & Byte Preservation
ApkRevive strictly follows the `elf16k.fix()` refusal policy:
1. **Never "patch headers and hope"**: Altering `p_align` without moving load segments causes memory mapping collisions (`s2_page_start < s1_page_end`) and dynamic linker `SIGSEGV` crashes.
2. **Byte Preservation**: If an ELF cannot be proven safe, ApkRevive preserves the original binary bytes unchanged and reports `Elf16kStatus.COMPAT_ONLY` or `Elf16kStatus.UNSAFE`.
3. **Android 15+ Page Size Compat**: On Android 16+ runtimes, ApkRevive leverages platform `android:pageSizeCompat="enabled"` rather than corrupting native libraries.

---

## 9. Unsupported AXML Chunks & Manifest Content Preservation

### The Constraint
Android binary XML (`AndroidManifest.xml`) comprises chunk streams structured per `ResXMLTree_node`. Certain specialized or non-standard chunk types (such as `RES_XML_CDATA_TYPE` `0x0104`) are unsupported by the surgical in-memory AST serializer.

### Refusal Policy & Escape Hatch
`AxmlSurgeon` fails closed with `UnsupportedAxmlChunk(ValueError)` whenever an unsupported chunk type is encountered, preventing silent corruption or dropping of manifest data.
- **Escape Hatch**: When manifest CDATA or text node loss is acceptable, callers can pass `--allow-axml-content-loss` (or catch `UnsupportedAxmlChunk` in custom tooling).

---

## 10. Aspect Ratio Rewriting Defaults

### The Constraint
Modern tall displays (18:9, 19.5:9, 20:9) pillarbox legacy applications that do not declare `android:resizeableActivity="true"`. By default, the `EXPAND_ASPECT_RATIO` transform injects or updates `<meta-data android:name="android.max_aspect" android:value="2.5" />`.

### Semantic Overwrite & Opt-Out
When `EXPAND_ASPECT_RATIO` is executed, any existing `max_aspect` value is overwritten to `2.5` to ensure consistent full-screen rendering across modern devices.
- **Escape Hatch**: Applications wishing to preserve an explicitly pinned legacy aspect ratio can exclude `EXPAND_ASPECT_RATIO` or pass `--no-aspect-ratio-expansion`.

---

## 11. 60Hz Display Mode Locking & Display Cutout Mode Architectural Limitation

### The Constraint
Legacy Android games and visual applications often rely on fixed 60Hz frame pacing or non-notched screen geometry. Modern displays frequently default to 90Hz/120Hz refresh rates and incorporate display cutouts (notches or camera punch-holes).

### What ApkRevive Cannot Do
`ApkReviveInitProvider` runs during startup in `ContentProvider.onCreate()` before any `Activity` is instantiated. Android's display mode switching (`preferredDisplayModeId`) and window cutout modes (`LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES`) require an active `Window` and `Activity` context, which do not exist in headless `ContentProvider` initialization without bytecode rewriting or `ActivityLifecycleCallbacks`.

As a result, headless initialization cannot programmatically configure window display modes or cutout layout behavior. These flags are not supported via static ContentProvider injection and have been removed from the patch CLI. Realizing display mode switching or cutout adjustments requires either an application-level `ActivityLifecycleCallbacks` implementation or per-activity bytecode manipulation.

