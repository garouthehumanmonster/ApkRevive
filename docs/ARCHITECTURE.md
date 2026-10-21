# ApkRevive Architecture & Runtime Remediation

ApkRevive is a ruthless, single-purpose CLI modernizer designed to make legacy Android APKs (API 3–28) install and run on modern Android runtimes (Android 14–16 / API 34–36).

Instead of merely reporting compatibility errors or generating telemetry reports, ApkRevive directly remediates root-cause runtime crashes.

---

## 1. Core Runtime Shims

### A. Dex Runtime Shim (`ApkReviveInitProvider`)
Legacy applications crash on Android 9+ (API 28+) through Android 15/16 due to strict runtime enforcements introduced across Android versions. `ApkReviveInitProvider` is injected as a high-priority `<provider>` (`initOrder=999999`) to execute during app initialization before `Application.onCreate()`:

1. **Hidden API / Reflection Unlock:**
   - **Problem:** Android 9+ blocks reflection into private system methods (`greylist`/`blacklist`), crashing legacy apps that access internal APIs.
   - **Remediation:** Executes the double-reflection bypass on `dalvik.system.VMRuntime` and invokes `setHiddenApiExemptions(new String[]{"L"})`, completely removing reflection restrictions for the application process.

2. **StrictMode & NetworkOnMainThread Disabler:**
   - **Problem:** Legacy applications perform synchronous network requests or file URI sharing on the main thread, causing immediate `NetworkOnMainThreadException` or `FileUriExposedException` crashes.
   - **Remediation:** Sets `StrictMode.setThreadPolicy(StrictMode.ThreadPolicy.LAX)` and `StrictMode.setVmPolicy(StrictMode.VmPolicy.LAX)`. Also invokes `StrictMode.disableDeathOnFileUriExposure()` via reflection.

3. **Storage Path Redirection & Exception Swallowing:**
   - **Problem:** Legacy applications hardcode `/sdcard/` paths or omit runtime permission requests (relying on pre-Marshmallow install-time permissions), triggering fatal `SecurityException` or `FileNotFoundException` crashes under Scoped Storage (API 29+).
   - **Remediation:** Installs a global thread `UncaughtExceptionHandler` that catches and suppresses unhandled exceptions originating from storage paths (`/sdcard`, `FileUriExposedException`, external storage `SecurityException`).

---

## 2. Bionic Linker Patcher (`elf_surgeon.py`)

- **Problem:** Android 7.0+ (Nougat) introduced strict Bionic linker namespace isolation. Legacy native libraries linked against private platform shared objects (such as `libcrypto.so`, `libssl.so`, or `libcutils.so`) fail at dynamic link time (`dlopen`) with fatal `CANNOT LINK EXECUTABLE` errors.
- **Remediation:**
  1. `patch_elf_dt_needed`: Scans the `.dynamic` section and `.dynstr` string table of ELF binaries (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`). Replaces private system library names with isolated legacy names (e.g., `libcrypto.so` -> `libcrypto_legacy.so`).
  2. `make_fallback_so`: Synthesizes minimal, 16KB-aligned ELF shared libraries providing fallback stubs for renamed dependencies, bundling them directly into the APK under `lib/<abi>/`.

---

## 3. In-Memory AXML Surgeon (`axml.py`)

Mutates compiled binary XML (`AndroidManifest.xml`) directly in-memory without invoking external tools (`apktool`, `aapt`):
- **Apache HTTP Legacy:** Injects `<uses-library android:name="org.apache.http.legacy" android:required="false" />` so legacy apps using Apache HTTP client do not crash on API 28+.
- **16KB Page Size Compatibility:** Injects `android:pageSizeCompat="enabled"` within `<application>` for Android 16 backward compatibility.
- **Widescreen & Display Controls:** Sets `android:resizeableActivity="true"`, removes restrictive `max_aspect` attributes, and unlocks modern aspect ratios.
- **Execution Flags:** Sets `android:hasCode="true"` when injecting initialization shims into resource-only APKs.

---

## 4. Container Alignment & Packaging (`align.py` & `signer.py`)

1. **16KB ZIP Boundary Alignment:**
   - Aligns uncompressed shared libraries (`.so`) and resources (`resources.arsc`) to 16,384-byte (16KB) boundaries using the standard Android zip extra field tag `0xD935`.
   - Validates ZIP container bounds, rejecting Zip Slip traversal and bomb anomalies without heavy external guards.
2. **V2/V3 APK Signing:**
   - Signs the aligned container using the user's keystore or a generated local development key via `apksigner` (or stdlib fallback).

---

## 5. CLI Interface

The CLI is strictly limited to two commands:

1. **`apkrevive inspect <input.apk>`:**
   - Scans APK and outputs a concise terminal summary of actual fatal blockers:
     - 32-bit only native libraries on 64-bit platforms
     - Private Bionic linker symbols (`libcrypto.so`, etc.)
     - `targetSdkVersion` below modern install floors
     - Missing Apache HTTP legacy library
   - Supports `--json` for automated workflows.

2. **`apkrevive patch <input.apk> -o <output.apk>`:**
   - Executes the complete binary remediation pipeline:
     - Injects `ApkReviveInitProvider` into DEX
     - Patches manifest AXML with required compatibility tags
     - Patches ELF DT_NEEDED tables and bundles fallback libraries
     - 16KB zipaligns container entries
     - Signs output APK with V2/V3 signature scheme
