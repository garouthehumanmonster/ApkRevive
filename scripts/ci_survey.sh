#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "ApkRevive Android Compatibility Survey CI Runner"
echo "=========================================================="

echo "==> Verifying ADB connection..."
adb version
adb devices -l

echo "==> Creating required directories..."
mkdir -p results receipts build/survey_runs

echo "==> Downloading / Verifying Survey Corpus APKs..."
python scripts/download_corpus.py --manifest tests/corpus/survey.json

echo "==> Running Survey Matrix Execution (35 APKs)..."
python scripts/survey.py --manifest tests/corpus/survey.json --max-apks 35

echo "==> Survey Execution Complete."

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  echo "==> Writing Summary to GITHUB_STEP_SUMMARY..."
  python -c "
import glob, json, os, sys

result_files = glob.glob('results/survey/*.json') + glob.glob('results/survey_*.json')
if not result_files:
    sys.exit(0)

latest_file = max(result_files, key=os.path.getmtime)
with open(latest_file, 'r', encoding='utf-8') as f:
    data = json.load(f)

dev = data.get('device_info', {})
total = data.get('total_apks', 0)
d_stats = data.get('direct_install_stats', {})
b_stats = data.get('bypass_install_stats', {})
r_stats = data.get('revive_install_stats', {})
l_stats = data.get('liveness_stats', {})
cats = data.get('failure_category_counts', {})

d_succ = d_stats.get('success', 0)
b_succ = b_stats.get('success', 0)
r_succ = r_stats.get('install_success', 0)
alive = l_stats.get('alive', 0)
crash = l_stats.get('crash', 0)
dead = l_stats.get('dead', 0)

denom = max(1, total)

summary = f'''### ApkRevive Compatibility Survey Results

**Device:** {dev.get('model', 'Unknown')} (API {dev.get('sdk', '?')}, {dev.get('abi', '?')})
**Total APKs Processed:** {total}

| Stage | Success | Failed / Skipped | Success Rate |
| :--- | :--- | :--- | :--- |
| Direct Install (\`adb install -r\`) | {d_succ} | {d_stats.get('failed', 0)} | {d_succ * 100 // denom}% |
| Bypass Install (\`--bypass-low-target-sdk-block\`) | {b_succ} | {b_stats.get('failed', 0)} | {b_succ * 100 // denom}% |
| Revive + Install (\`-r -g\`) | {r_succ} | {r_stats.get('failed', 0)} | {r_succ * 100 // denom}% |
| Liveness (Monkey Launch + 8s Polling) | {alive} Alive | {crash} Crashed, {dead} Dead | {alive * 100 // denom}% |

#### Failure Category Breakdown
- **ABI:** {cats.get('ABI', 0)}
- **GREYLIST:** {cats.get('GREYLIST', 0)}
- **GLES1:** {cats.get('GLES1', 0)}
- **DEAD_SDK:** {cats.get('DEAD_SDK', 0)}
- **CRASH:** {cats.get('CRASH', 0)}
- **INSTALL_FLOOR_BLOCKED:** {cats.get('INSTALL_FLOOR_BLOCKED', 0)}
- **NONE (Clean / Alive):** {cats.get('NONE', 0)}
- **OTHER:** {cats.get('OTHER', 0)}
'''

summary_path = os.environ.get('GITHUB_STEP_SUMMARY')
if summary_path:
    with open(summary_path, 'a', encoding='utf-8') as sf:
        sf.write(summary)
"
fi
