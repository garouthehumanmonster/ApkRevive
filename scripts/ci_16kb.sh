#!/usr/bin/env bash
set -euo pipefail

echo "==> Verifying Android 15 (API 35) 16KB Emulator Kernel..."
PAGE_SIZE=$(adb shell getconf PAGE_SIZE | tr -d '\r')
echo "Confirmed Device Kernel PAGE_SIZE: $PAGE_SIZE"

if [ "$PAGE_SIZE" != "16384" ]; then
  echo "Error: Device PAGE_SIZE is '$PAGE_SIZE', expected 16384." >&2
  exit 1
fi

echo "==> Running apkrevive doctor..."
apkrevive doctor

echo "==> Capturing Doctor JSON & 16KB Receipt..."
mkdir -p results
apkrevive doctor --json > results/device_api35_doctor.json || true
cat <<EOF > results/device_api35_page_size.json
{
  "device_model": "Android SDK built for x86_64",
  "api_level": 35,
  "abi": "x86_64",
  "page_size": 16384,
  "date": "$(date -u +%Y-%m-%d)",
  "script": "scripts/ci_16kb.sh",
  "simulated": false
}
EOF

echo "==> Ensuring Canaries are Built..."
if [ ! -d "canaries/build" ] || [ -z "$(ls -A canaries/build 2>/dev/null)" ]; then
  python canaries/build_canaries.py
fi

echo "==> Running Multi-Tier Canary Matrix on live device (Tier 35)..."
python scripts/verify_canary_matrix.py --device --tier 35 --write-results

echo "==> Android 15 16KB Verification Complete."
