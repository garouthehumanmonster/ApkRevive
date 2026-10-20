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
1. **Destructive Updates (Loss of App Data)**:
   - Android prevents upgrading an existing application if the installed version is signed with a different certificate (`INSTALL_FAILED_UPDATE_INCOMPATIBLE`).
   - Installing the revived APK requires an explicit uninstall of the existing application, which **permanently deletes all user data, application databases, and local storage** in `/data/data/<package_name>`.
2. **Shared User IDs (`android:sharedUserId`)**:
   - Applications that share Linux UIDs to access common databases and files must be signed with the identical cryptographic certificate. Re-signing one app without re-signing all companion apps breaks shared process isolation.
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
