"""
scripts/gen_web_rules.py - Generate web/rules.json deterministically from core triage and behavior changes.
"""

from __future__ import annotations

import json
from pathlib import Path
from apkrevive.core.models import Verdict

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_PATH = REPO_ROOT / "web" / "rules.json"


def generate_web_rules() -> dict:
    signals = {
        "APACHE_HTTP_LEGACY": {
            "required_transforms": ["INJECT_USES_LIBRARY_APACHE_HTTP"],
            "verdict": Verdict.YELLOW.value,
        },
        "FATAL_16KB_INCOMPATIBILITY": {
            "required_transforms": ["RECOMPILE_ELF_NATIVE_16KB"],
            "verdict": Verdict.RED.value,
        },
        "HAS_CODE_FALSE": {
            "required_transforms": ["SET_HAS_CODE_TRUE"],
            "verdict": Verdict.YELLOW.value,
        },
        "INCOMPATIBLE_PAGE_SIZE": {
            "required_transforms": ["RECOMPILE_ELF_NATIVE_16KB"],
            "verdict": Verdict.RED.value,
        },
        "LOW_TARGET_SDK": {
            "required_transforms": ["BYPASS_LOW_TARGET_SDK_BLOCK"],
            "verdict": Verdict.GREEN.value,
        },
        "MODIFICATION_REQUIRED": {
            "required_transforms": ["INJECT_PAGE_SIZE_COMPAT"],
            "verdict": Verdict.YELLOW.value,
        },
        "RESTRICTIVE_ASPECT_RATIO": {
            "required_transforms": ["EXPAND_ASPECT_RATIO"],
            "verdict": Verdict.YELLOW.value,
        },
        "RUNNABLE_UNMODIFIED": {
            "required_transforms": [],
            "verdict": Verdict.GREEN.value,
        },
    }
    return {"signals": signals}


def main():
    rules = generate_web_rules()
    formatted = json.dumps(rules, indent=2, sort_keys=True) + "\n"
    RULES_PATH.write_text(formatted, encoding="utf-8")
    print(f"Generated {RULES_PATH.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
