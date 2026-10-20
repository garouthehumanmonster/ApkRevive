---
name: Device Verification Receipt Submission
about: Submit a real-world hardware or emulator verification receipt to update the compatibility matrix
title: '[RECEIPT] '
labels: evidence, compatibility
assignees: ''
---

## Device Verification Evidence

ApkRevive strictly adheres to an unvarnished, receipt-driven evidence standard. We only record capabilities as `VERIFIED` when accompanied by a structured JSON receipt produced from an attached physical device or official Android emulator.

### How to Generate Your Receipt

1. Connect your Android device or boot your emulator with USB debugging enabled.
2. Run the receipt generation utility:
   ```bash
   python scripts/make_receipt.py --script scripts/survey.py --output my_device_receipt.json
   ```
3. Paste the contents of `my_device_receipt.json` below:

```json
{
  "schema_version": "1.0.0",
  "device_model": "...",
  "api_level": 35,
  "abi": "arm64-v8a",
  "page_size": 16384,
  "date": "2026-10-20",
  "script": "scripts/survey.py",
  "simulated": false
}
```

### Verification Checklist
- [ ] Output was produced with `"simulated": false` from real hardware or an official Android emulator.
- [ ] No serial numbers, personal hostnames, or usernames are present in the JSON.
- [ ] Target APKs tested are documented or part of the public survey manifest.
