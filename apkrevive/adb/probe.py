"""
probe.py - Target SDK install floor active prober matching exact AOSP error string.
"""

import re
from typing import Dict, Any
from apkrevive.adb.bridge import AdbBridge
from apkrevive.core.models import SCHEMA_VERSION


AOSP_ERROR_REGEX = re.compile(r"App package must target at least SDK version (\d+), but found (\d+)")


def probe_install_floor(bridge: AdbBridge, probe_apk_path: str = "") -> Dict[str, Any]:
    sdk_str = bridge.get_prop("ro.build.version.sdk")
    sdk = int(sdk_str) if sdk_str.isdigit() else 35

    if sdk >= 36:
        return {"schema_version": SCHEMA_VERSION, "floor": "UNKNOWN", "status": "UNKNOWN_FUTURE_API", "sdk": sdk}

    # Query OS-advertised min supported target sdk
    prop_floor = bridge.get_prop("ro.build.version.min_supported_target_sdk")
    if prop_floor.isdigit():
        return {"schema_version": SCHEMA_VERSION, "floor": int(prop_floor), "status": "CONFIRMED_VIA_PROP", "sdk": sdk}

    if probe_apk_path:
        success, out = bridge.install(probe_apk_path, bypass_low_target_sdk=False)
        if success:
            bridge.uninstall("com.apkrevive.probe")
            return {"schema_version": SCHEMA_VERSION, "floor": "NONE", "status": "SUCCESS_NO_FLOOR", "sdk": sdk}

        m = AOSP_ERROR_REGEX.search(out)
        if m:
            detected_floor = int(m.group(1))
            return {"schema_version": SCHEMA_VERSION, "floor": detected_floor, "status": "DETECTED_VIA_AOSP_ERROR", "sdk": sdk}

    # Baseline standard floor
    floor = 24 if sdk >= 35 else (23 if sdk >= 34 else 1)
    return {"schema_version": SCHEMA_VERSION, "floor": floor, "status": "STANDARD_BASELINE", "sdk": sdk}
