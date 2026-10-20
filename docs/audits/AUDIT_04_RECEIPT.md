# AUDIT 04 — Verification Receipt & Reconciled Telemetry

**Verified Commit**: `6fd271032df49733fae9919f96b6ad3d3f9b2cb4` (HEAD before remediation commit)  
**Date**: 2026-10-20  

---

## 1. Automated Verification Suite Numbers

### Unit Test Suite
```text
360 passed, 12 deselected, 2 warnings, 89 subtests passed in 22.09s
```

### Integration Test Suite
```text
12 passed, 360 deselected, 39 subtests passed in 13.49s
```

### Branch & Statement Coverage
```text
TOTAL                                 3355    373   1592    267    85%
Enforced Threshold: 85%
Gate Status: PASS (85% >= 85%)
```

### Static Analysis & Type Checking
```text
ruff check . -> Exit 0 (All checks passed!)
mypy apkrevive --ignore-missing-imports -> Exit 0 (Success: no issues found in 27 source files; 0 errors)
```

### Android Companion CI Gate
```text
(cd apkrevive-android && ./gradlew test lintDebug --no-daemon -q) -> Exit 0
Wrote HTML report to app/build/reports/lint-results-debug.html
BUILD SUCCESSFUL
```

### Canary Suite Hash Count
```text
Canary files registered in canaries/canary_hashes.json: 28 (14 control/failing pairs)
```

### Verification Harness (`verify_apkrevive_fixes.py`)
```text
Status: Awaiting upload/placement of external harness verify_apkrevive_fixes.py
```
