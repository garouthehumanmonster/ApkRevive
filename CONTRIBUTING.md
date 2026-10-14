# Contributing to ApkRevive

Thank you for your interest in contributing to ApkRevive!

## Development Setup

1. **Prerequisites:**
   - Python 3.9+
   - Android SDK Build-Tools (with `apksigner` and `zipalign`)
   - JDK 17+ (for canary compilation and Companion app build)
   - Git

2. **Installation:**
   ```bash
   git clone https://github.com/garouthehumanmonster/ApkRevive.git
   cd ApkRevive
   pip install -e ".[dev]"
   ```

## Running Verification

Before submitting pull requests, run all verification targets:

1. **Python Unit Tests:**
   ```bash
   python -m unittest discover -s tests
   ```

2. **Canary Build Suite:**
   ```bash
   python canaries/build_canaries.py
   ```

3. **Android Companion App:**
   ```bash
   cd apkrevive-android
   ./gradlew test
   ```

## Contribution Invariants

1. **No Behavior Change Without Tests:** Every bug fix, new triage signal, or AXML surgeon transform must include a corresponding unit test.
2. **Deterministic Outputs:** Binary transforms (AXML serialization, zip realignment, shim injection) must be strictly idempotent: `transform(transform(apk)) == transform(apk)`.
3. **No Unsafe Dependencies:** Avoid adding external Python runtime dependencies where stdlib capabilities suffice.
4. **License Agreement:** All contributions are licensed under the Apache 2.0 License.
