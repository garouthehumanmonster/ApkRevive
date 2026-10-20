# Contributing to ApkRevive

Thank you for your interest in contributing to ApkRevive!

---

## Development Setup

1. **Prerequisites:**
   - Python 3.9+ (Python 3.9 and 3.13 are verified in CI)
   - Android SDK Build-Tools (with `apksigner` and `zipalign`)
   - JDK 17+ (for canary compilation, bytecode shims, and Android Companion app build)
   - Git

2. **Installation:**
   ```bash
   git clone https://github.com/garouthehumanmonster/ApkRevive.git
   cd ApkRevive
   pip install -e ".[dev]"
   ```

---

## Running Verification

Before submitting pull requests, run all verification targets:

1. **Python Unit Tests (Python 3.9 & 3.13):**
   ```bash
   pytest -q
   ```

2. **Static Typing & Linting:**
   ```bash
   ruff check .
   mypy apkrevive
   ```

3. **Canary Build Suite:**
   ```bash
   python canaries/build_canaries.py
   ```

4. **Android Companion App:**
   ```bash
   cd apkrevive-android
   ./gradlew test
   ```

---

## Contribution Invariants

1. **No Behavior Change Without Tests:** Every bug fix, new triage signal, or AXML surgeon transform must include a corresponding unit test.
2. **Deterministic Outputs:** Binary transforms (AXML serialization, zip realignment, shim injection) must be strictly idempotent: `transform(transform(apk)) == transform(apk)`.
3. **No Unsafe Dependencies:** Avoid adding external Python runtime dependencies where standard library capabilities suffice.
4. **Receipts for Device Compatibility Claims:** Any change claiming device compatibility or modifying the compatibility matrix MUST include a non-simulated receipt generated via `scripts/make_receipt.py` in `receipts/`. Simulated runs carry `"simulated": true` and are never recorded as verified device evidence.
5. **Strict Zero-Commit Policy for Keystores:** Keystores, signing passwords, and private certificates must **never** be committed to source control. Ensure repository `.gitignore` exclusions remain respected.
6. **Schema Versioning Compliance:** All JSON outputs must conform to `docs/SCHEMA.md` and include `schema_version: "1.0.0"`.
7. **License Agreement:** All contributions are licensed under the Apache 2.0 License.

---

## Key Reference Documents
- [Operational Boundaries (`docs/LIMITS.md`)](docs/LIMITS.md)
- [JSON Schema Specification (`docs/SCHEMA.md`)](docs/SCHEMA.md)
- [Release Management & Attestations (`docs/RELEASING.md`)](docs/RELEASING.md)
- [Compatibility Survey Report (`docs/SURVEY.md`)](docs/SURVEY.md)
- [Engineering Roadmap (`docs/ROADMAP.md`)](docs/ROADMAP.md)
