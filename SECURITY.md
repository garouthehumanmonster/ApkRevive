# Security Policy

## Supported Versions

ApkRevive is currently in **Alpha** status. Security patches are applied to the active development branch (`main`).

| Version | Supported          |
| ------- | ------------------ |
| 0.5.x (Alpha) | :white_check_mark: |
| 0.4.x   | :white_check_mark: |
| < 0.4.0 | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in ApkRevive, please report it responsibly:

1. **Do not** file a public GitHub issue.
2. Email details to `security@apkrevive.local` (or file a private GitHub Security Advisory).
3. Include:
   - A description of the vulnerability and attack vector.
   - Proof-of-concept APK, command, or script.
   - Target Android version, architecture, and environment.

Reports will be acknowledged within 48 hours, followed by a proposed fix or remediation timeline.

## Security Posture & Invariants

- **Signing Keys:** Never reuse shared debug keystores in production environments. Always specify a private, protected keystore using `--ks`.
- **Untrusted Archives:** Treat all third-party APK files as potentially untrusted. ApkRevive performs boundary checks to prevent zip-slip and traversal attacks during extraction and realignment.
- **Legal Compliance:** Users are solely responsible for ensuring they have authorization and lawful rights to decompile, mutate, and re-sign target applications.

## Runtime Shim Security & Provenance

ApkRevive injects an optional lightweight lifecycle shim (`ApkReviveInitProvider`) when modern display compatibility flags (such as 60Hz display refresh locking or cutout short-edge mode) are enabled. To maintain uncompromising security and auditability:

- **Source Provenance:** The runtime shim source is maintained transparently at [`apkrevive/shim/ApkReviveInitProvider.java`](apkrevive/shim/ApkReviveInitProvider.java) and deterministically compiled via [`apkrevive/shim/build_shim.py`](apkrevive/shim/build_shim.py).
- **Zero Network:** The shim contains zero networking code, opens no sockets, and makes no HTTP/HTTPS calls.
- **Zero Data Collection / Telemetry:** The shim does not collect, read, store, or transmit device identifiers, user data, or telemetry.
- **Strictly Scoped Functionality:** Solely sets 60Hz display mode ID and short-edge display cutout layout mode on activity resume.
- **Provenance Verification:** Verified cryptographically by `apkrevive doctor` against pinned source (`d589872c5ea50fe537c07ecab3ed929261b03cd21aaecad588d080674c55fc28`) and binary DEX (`609b5dcbc8f657b046a73809afbd666cb6feb567497dc068733b57212286e590`) SHA256 hashes to guarantee complete build integrity and prevent tampering.

