# Security Policy

## Supported Versions

ApkRevive is currently in **Alpha** status. Security patches are applied to the active development branch (`main`).

| Version | Supported          |
| ------- | ------------------ |
| 3.3.x (Alpha) | :white_check_mark: |
| < 3.3.0 | :x:                |

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
