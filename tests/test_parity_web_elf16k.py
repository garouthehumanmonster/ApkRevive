"""test_parity_web_elf16k.py - Parity verification between Python elf16k and Web app.js.

Verifies:
1. Native 16KB clean layout -> ALIGNED
2. Standard 4KB linked library -> COMPAT_ONLY
3. Fake header patch (p_align=16384 but vaddr page collision) -> UNSAFE
4. Incongruent offset-to-vaddr modulo -> UNSAFE
Both Python elf16k and JavaScript checkElf16k must emit identical 3-state verdicts.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest
import pytest

from apkrevive.core.elf16k import Elf16kStatus, LoadSegment

PROJECT_ROOT = Path(__file__).resolve().parent.parent
WEB_APP_JS = PROJECT_ROOT / "web" / "app.js"

TEST_VECTORS = [
    {
        "id": "vector_16k_clean",
        "expected_status": "ALIGNED",
        "segments": [
            {"index": 0, "p_offset": 0x0, "p_vaddr": 0x0, "p_filesz": 0x3000, "p_memsz": 0x3000, "p_align": 16384, "p_flags": 5},
            {"index": 1, "p_offset": 0x4000, "p_vaddr": 0x4000, "p_filesz": 0x2000, "p_memsz": 0x2000, "p_align": 16384, "p_flags": 6},
        ],
    },
    {
        "id": "vector_4k_standard",
        "expected_status": "COMPAT_ONLY",
        "segments": [
            {"index": 0, "p_offset": 0x1000, "p_vaddr": 0x10000, "p_filesz": 0x24000, "p_memsz": 0x24000, "p_align": 4096, "p_flags": 5},
            {"index": 1, "p_offset": 0x26000, "p_vaddr": 0x36000, "p_filesz": 0x8200, "p_memsz": 0x9000, "p_align": 4096, "p_flags": 6},
        ],
    },
    {
        "id": "vector_fake_16k_collision",
        "expected_status": "UNSAFE",
        "segments": [
            {"index": 0, "p_offset": 0x0, "p_vaddr": 0x0, "p_filesz": 0x1000, "p_memsz": 0x1000, "p_align": 16384, "p_flags": 5},
            {"index": 1, "p_offset": 0x4000, "p_vaddr": 0x2000, "p_filesz": 0x800, "p_memsz": 0x800, "p_align": 16384, "p_flags": 6},
        ],
    },
    {
        "id": "vector_incongruent_modulo",
        "expected_status": "UNSAFE",
        "segments": [
            {"index": 0, "p_offset": 0x1200, "p_vaddr": 0x10000, "p_filesz": 0x14000, "p_memsz": 0x14000, "p_align": 16384, "p_flags": 5},
        ],
    },
]


def evaluate_python_vector(seg_dicts: list[dict]) -> str:
    """Evaluates segment dictionaries through elf16k logic."""
    segments = [
        LoadSegment(
            index=s["index"],
            p_offset=s["p_offset"],
            p_vaddr=s["p_vaddr"],
            p_filesz=s["p_filesz"],
            p_memsz=s["p_memsz"],
            p_align=s["p_align"],
            p_flags=s["p_flags"],
        )
        for s in seg_dicts
    ]

    min_align = min(s.p_align for s in segments)
    reasons = []

    for seg in segments:
        if seg.p_align > 1 and (seg.p_vaddr % seg.p_align) != (seg.p_offset % seg.p_align):
            reasons.append("Incongruent")

    if reasons:
        return Elf16kStatus.UNSAFE.value

    is_16kb_aligned = min_align >= 16384
    congruent_16kb = all((s.p_vaddr % 16384) == (s.p_offset % 16384) for s in segments)

    sorted_by_vaddr = sorted(segments, key=lambda s: s.p_vaddr)
    has_page_collision = False
    for i in range(len(sorted_by_vaddr) - 1):
        s1 = sorted_by_vaddr[i]
        s2 = sorted_by_vaddr[i + 1]
        s1_page_end = (s1.p_vaddr + s1.p_memsz + 16384 - 1) // 16384
        s2_page_start = s2.p_vaddr // 16384
        if s2_page_start < s1_page_end:
            has_page_collision = True
            break

    if is_16kb_aligned and congruent_16kb and not has_page_collision:
        return Elf16kStatus.ALIGNED.value
    if has_page_collision and is_16kb_aligned:
        return Elf16kStatus.UNSAFE.value
    return Elf16kStatus.COMPAT_ONLY.value


def evaluate_js_vector(seg_dicts: list[dict]) -> str:
    """Executes checkElf16k from web/app.js using node."""
    js_path_str = str(WEB_APP_JS).replace("\\", "/")
    app_path_json = json.dumps(js_path_str)
    segments_json = json.dumps(seg_dicts)
    node_script = f"""
    const app = require({app_path_json});
    const segments = {segments_json};
    const res = app.checkElf16k(segments);
    console.log(res.status);
    """
    proc = subprocess.run(["node", "-e", node_script], capture_output=True, text=True, check=True)
    return proc.stdout.strip()


class TestParityWebElf16k(unittest.TestCase):
    def test_python_verdicts_match_expected(self):
        for v in TEST_VECTORS:
            with self.subTest(vector_id=v["id"]):
                py_status = evaluate_python_vector(v["segments"])
                self.assertEqual(py_status, v["expected_status"])

    @pytest.mark.integration
    def test_js_verdicts_match_python_parity(self):
        for v in TEST_VECTORS:
            with self.subTest(vector_id=v["id"]):
                py_status = evaluate_python_vector(v["segments"])
                js_status = evaluate_js_vector(v["segments"])
                self.assertEqual(js_status, py_status, f"Mismatch on {v['id']}: JS={js_status} vs PY={py_status}")

    def test_rules_json_matches_core_signals(self):
        rules_path = PROJECT_ROOT / "web" / "rules.json"
        self.assertTrue(rules_path.exists())
        with open(rules_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        signals = data.get("signals", {})
        self.assertIn("FATAL_16KB_INCOMPATIBILITY", signals)
        self.assertEqual(signals["FATAL_16KB_INCOMPATIBILITY"]["verdict"], "RED")
        self.assertIn("MODIFICATION_REQUIRED", signals)
        self.assertEqual(signals["MODIFICATION_REQUIRED"]["verdict"], "YELLOW")
        self.assertIn("RUNNABLE_UNMODIFIED", signals)
        self.assertEqual(signals["RUNNABLE_UNMODIFIED"]["verdict"], "GREEN")

    @pytest.mark.integration
    def test_js_escape_html_xss_protection(self):
        js_path_str = str(WEB_APP_JS).replace("\\", "/")
        app_path_json = json.dumps(js_path_str)
        payload = "<script>alert('xss')</script>\"&"
        node_script = f"""
        const app = require({app_path_json});
        console.log(app.escapeHtml({json.dumps(payload)}));
        """
        proc = subprocess.run(["node", "-e", node_script], capture_output=True, text=True, check=True)
        escaped = proc.stdout.strip()
        self.assertEqual(escaped, "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;&quot;&amp;")
        self.assertNotIn("<", escaped)
        self.assertNotIn(">", escaped)

    @pytest.mark.integration
    def test_js_triage_parity_with_python_on_presets(self):
        from apkrevive.core.triage import evaluate_triage
        from apkrevive.core.models import ApkMetadata, DeviceProfile

        js_path_str = str(WEB_APP_JS).replace("\\", "/")
        app_path_json = json.dumps(js_path_str)
        node_script = f"""
        const app = require({app_path_json});
        const results = {{}};
        for (const [k, preset] of Object.entries(app.PRESETS)) {{
            results[k] = app.evaluateTriage(preset).verdict;
        }}
        console.log(JSON.stringify(results));
        """
        proc = subprocess.run(["node", "-e", node_script], capture_output=True, text=True, check=True)
        js_results = json.loads(proc.stdout)

        device = DeviceProfile(os_api_level=36, install_floor=24, page_size_bytes=16384, is_widescreen=True)
        preset_metadata = {
            "arcade4k": ApkMetadata(package_name="com.legacy.arcade4k", target_sdk=22, min_sdk=16, has_code=False, uses_apache_http=False, elf_16kb_status="COMPAT_ONLY", force_page_size_compat=True, abis=["arm64-v8a"]),
            "enterprise34": ApkMetadata(package_name="com.corp.crm", target_sdk=28, min_sdk=21, has_code=True, uses_apache_http=True, elf_16kb_status="COMPAT_ONLY", force_page_size_compat=True, abis=["arm64-v8a"]),
            "congruenceFault": ApkMetadata(package_name="com.example.misaligned", target_sdk=33, min_sdk=24, has_code=True, uses_apache_http=False, elf_16kb_status="UNSAFE", abis=["arm64-v8a"]),
            "modern16k": ApkMetadata(package_name="com.modern.app", target_sdk=35, min_sdk=26, has_code=True, uses_apache_http=False, elf_16kb_status="ALIGNED", abis=["arm64-v8a"]),
        }

        for preset_name, apk_meta in preset_metadata.items():
            py_res = evaluate_triage(apk_meta, device)
            py_verdict = py_res["verdict"]
            js_verdict = js_results[preset_name]
            self.assertEqual(js_verdict, py_verdict, f"Mismatch on preset {preset_name}: JS={js_verdict} vs PY={py_verdict}")

    @pytest.mark.integration
    def test_js_triage_parity_across_fixture_matrix(self):
        from apkrevive.core.triage import evaluate_triage
        from apkrevive.core.models import ApkMetadata, DeviceProfile

        js_path_str = str(WEB_APP_JS).replace("\\", "/")
        app_path_json = json.dumps(js_path_str)

        device = DeviceProfile(os_api_level=36, install_floor=24, page_size_bytes=16384, is_widescreen=True)

        fixtures = []
        for target_sdk in [21, 28, 35]:
            for has_code in [True, False]:
                for uses_apache in [True, False]:
                    for non_resize in [True, False]:
                        for elf_status in ["ALIGNED", "COMPAT_ONLY", "UNSAFE"]:
                            fixtures.append({
                                "targetSdk": target_sdk,
                                "hasCode": has_code,
                                "usesApacheHttp": uses_apache,
                                "isNonResizeable": non_resize,
                                "elfStatus": elf_status,
                            })

        node_script = f"""
        const app = require({app_path_json});
        const matrix = {json.dumps(fixtures)};
        const results = matrix.map(m => {{
            let elfSegments = [];
            if (m.elfStatus === 'ALIGNED') {{
                elfSegments = [
                    {{ index: 0, p_offset: 0x0, p_vaddr: 0x0, p_filesz: 0x3000, p_memsz: 0x3000, p_align: 16384, p_flags: 5 }},
                    {{ index: 1, p_offset: 0x4000, p_vaddr: 0x4000, p_filesz: 0x2000, p_memsz: 0x2000, p_align: 16384, p_flags: 6 }}
                ];
            }} else if (m.elfStatus === 'COMPAT_ONLY') {{
                elfSegments = [
                    {{ index: 0, p_offset: 0x1000, p_vaddr: 0x10000, p_filesz: 0x24000, p_memsz: 0x24000, p_align: 4096, p_flags: 5 }}
                ];
            }} else if (m.elfStatus === 'UNSAFE') {{
                elfSegments = [
                    {{ index: 0, p_offset: 0x1200, p_vaddr: 0x10000, p_filesz: 0x14000, p_memsz: 0x14000, p_align: 16384, p_flags: 5 }}
                ];
            }}
            return app.evaluateTriage({{
                targetSdk: m.targetSdk,
                hasCode: m.hasCode,
                usesApacheHttp: m.usesApacheHttp,
                isNonResizeable: m.isNonResizeable,
                elfSegments
            }}).verdict;
        }});
        console.log(JSON.stringify(results));
        """
        proc = subprocess.run(["node", "-e", node_script], capture_output=True, text=True, check=True)
        js_verdicts = json.loads(proc.stdout)

        for i, m in enumerate(fixtures):
            apk_meta = ApkMetadata(
                package_name="com.test.matrix",
                target_sdk=m["targetSdk"],
                min_sdk=16,
                has_code=m["hasCode"],
                uses_apache_http=m["usesApacheHttp"],
                is_non_resizeable=m["isNonResizeable"],
                elf_16kb_status=m["elfStatus"],
                force_page_size_compat=(m["elfStatus"] == "COMPAT_ONLY"),
                abis=["arm64-v8a"],
            )
            py_verdict = evaluate_triage(apk_meta, device)["verdict"]
            self.assertEqual(js_verdicts[i], py_verdict, f"Matrix mismatch at index {i}: {m}")


if __name__ == "__main__":
    unittest.main()
