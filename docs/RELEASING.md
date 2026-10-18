# Release Process & Distribution Guide

This document outlines the automated release pipeline, cryptographic signing architecture, and PyPI Trusted Publishing configuration for ApkRevive.

---

## 1. Automated Release Pipeline Overview

Releases are triggered by pushing annotated git tags matching `v*` (e.g. `v0.5.0a1` or `v0.5.0`). The pipeline in `.github/workflows/ci.yml` executes:

1. **Multi-Platform CI**: Unit tests, linting (`ruff`), type-checking (`mypy`), and Hypothesis fuzzing across Linux, macOS, and Windows on Python 3.9, 3.12, and 3.13.
2. **Android Companion CI**: Gradle verification, linting, unit tests, and dual APK compilation (debug and release).
3. **Multi-Tier Canary Matrix & SARIF Diagnostics**: Hermetic verification of all 8 canary vectors and generation of SARIF diagnostics.
4. **16KB Page-Size Emulator Verification**: Real boot and execution verification on an Android 15 (API 35) 16KB system image (`scripts/ci_16kb.sh`).
5. **Distribution & Release**:
   - Compiles Python source distribution (`sdist`) and wheels (`bdist_wheel`).
   - Downloads companion APK artifacts and SARIF reports.
   - Publishes to PyPI via OIDC Trusted Publishing (for stable releases only).
   - Generates GitHub Release with assets, marking pre-releases appropriately.

---

## 2. PyPI Trusted Publishing (OIDC) Setup

ApkRevive uses PyPI's OpenID Connect (OIDC) Trusted Publishing to publish releases without long-lived API tokens or passwords.

### Pending Publisher Configuration
Because `apkrevive` is not yet registered on PyPI, configure a **Pending Publisher** before the first stable release:

1. Log in to [pypi.org](https://pypi.org/).
2. Navigate to **Account settings** -> **Publishing** -> **Add a pending publisher**.
3. Fill in the publisher details:
   - **PyPI Project Name**: `apkrevive`
   - **Owner**: GitHub organization or user account owning the repository
   - **Repository name**: `apkrevive`
   - **Workflow name**: `ci.yml`
   - **Environment name**: `pypi`
4. Submit the pending publisher.
5. On the GitHub repository:
   - Navigate to **Settings** -> **Environments**.
   - Create an environment named `pypi`.
   - (Optional) Configure deployment branch protection rules (e.g., restrict to tags `v*`).

### Pre-Release vs. Stable Tags
- **PEP 440 Pre-Release Tags** (`^v[0-9]+\.[0-9]+\.[0-9]+(a|b|rc)[0-9]+$`, e.g. `v0.5.0a1`):
  - GitHub Release is automatically flagged with `prerelease: true`.
  - The PyPI publication step is explicitly **skipped** to prevent untracked alpha packages on PyPI.
- **Stable Tags** (`v0.5.0`, `v1.0.0`):
  - GitHub Release is marked as standard stable release.
  - PyPI publication executes via the `pypi` environment using trusted OIDC tokens.

---

## 3. Android Companion App Signing

Companion APKs (`apkrevive-android`) are compiled during CI in the `android-ci` job.

### GitHub Secrets for Production Signing
To sign release APKs with the official distribution key, configure the following repository secrets:
- `ANDROID_KEYSTORE_B64`: Base64-encoded Java Keystore (`.jks` or `.keystore`).
- `ANDROID_KEYSTORE_PASSWORD`: Keystore access password.
- `ANDROID_KEY_ALIAS`: Key alias within the keystore.
- `ANDROID_KEY_PASSWORD`: Private key password.

### Keystore Handling & Fallback
- Keystores are decoded dynamically in memory on the runner (`apkrevive-android/release.keystore`) and are **never committed** to source control.
- If `ANDROID_KEYSTORE_B64` is not configured:
  - The release build falls back to signing with the standard Android debug keystore.
  - The artifact is explicitly named `ApkRevive-Companion-<version>-debug-signed.apk`.
  - A CI warning is emitted (`::warning::Naming release APK with -debug-signed suffix because release keystore was absent`).

> [!WARNING]
> **Signing Key Migration**: Companion APKs for v0.5.0a1+ use a separate keystore from v0.4.0. Upgrading from v0.4.0 requires uninstalling the previous APK (`adb uninstall com.apkrevive`).
