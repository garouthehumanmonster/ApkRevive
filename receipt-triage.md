# Receipt Triage — Phase 10 Verification

| # | Check | Bucket | Evidence (file:line / command) | Intent |
|---|---|---|---|---|
| P10.1 | Integration tests run in CI | REAL | `.github/workflows/ci.yml:144` | Add dedicated `integration-suite` job running `pytest -m integration` |
| P10.2 | Justify `test_v040_hardening.py` modification | REAL | `tests/test_v040_hardening.py:422` | Document AOSP platform invariant and Defect 5.3 fail-closed citation |
| P10.3 | Pre-commit gate command output logging | REAL | Console gate output | Log `ruff`, `mypy`, `coverage pytest`, and `gradlew` results verbatim |
| P10.4 | Reconciled telemetry numbers | REAL | `docs/audits/AUDIT_04_RECEIPT.md` | Publish reproducible test counts, coverage, and canary numbers |
| P10.5 | Changelog & Limits breaking change entries | REAL | `CHANGELOG.md:10`, `docs/LIMITS.md:164` | Document unknown AXML chunk rejection & aspect ratio overwrites with escape hatches |
| P10.6 | Schema version bump for `Elf16kStatus.EXEMPT` | REAL | `apkrevive/core/models.py:10`, `docs/SCHEMA.md:17` | Bump `SCHEMA_VERSION` to `1.1.0` and document migration in schema docs |
| P10.7 | Deterministic `web/rules.json` generation | REAL | `scripts/gen_web_rules.py` | Generate `web/rules.json` programmatically and enforce diff check in CI |
