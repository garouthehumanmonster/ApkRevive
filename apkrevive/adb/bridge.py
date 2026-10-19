"""
bridge.py - Host ADB executor tracking install lifecycle and enforcing invariants.
"""

import os
import re
import shutil
import subprocess
from typing import Tuple, List, Optional


PACKAGE_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+$")


def find_adb(preferred_path: str = "adb") -> str:
    if preferred_path != "adb" and os.path.exists(preferred_path):
        return preferred_path
    which_adb = shutil.which("adb")
    if which_adb:
        return which_adb
    sdk_roots = [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk"),
        os.path.expanduser("~/Library/Android/sdk"),
        os.path.expanduser("~/Android/Sdk")
    ]
    for root in sdk_roots:
        if not root:
            continue
        for cand in ["adb.exe", "adb"]:
            p = os.path.join(root, "platform-tools", cand)
            if os.path.exists(p):
                return p
    return "adb"


class AdbBridge:
    def __init__(self, adb_path: str = "adb", serial: Optional[str] = None):
        self.adb_path = find_adb(adb_path)
        self.serial = serial

    def _cmd(self, args: List[str]) -> Tuple[int, str, str]:
        cmd = [self.adb_path]
        if self.serial:
            cmd.extend(["-s", self.serial])
        cmd.extend(args)
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return res.returncode, res.stdout, res.stderr

    def wait_for_device(self, timeout: int = 15) -> bool:
        code, _, _ = self._cmd(["wait-for-device"])
        return code == 0

    def get_serial(self) -> str:
        code, out, _ = self._cmd(["get-serialno"])
        return out.strip() if code == 0 else ""

    def get_prop(self, prop: str) -> str:
        code, out, err = self._cmd(["shell", "getprop", prop])
        if (code != 0 or not out.strip()) and "offline" in err:
            self._cmd(["wait-for-device"])
            code, out, err = self._cmd(["shell", "getprop", prop])
        return out.strip() if code == 0 else ""

    def get_page_size(self) -> int:
        code, out, err = self._cmd(["shell", "getconf", "PAGE_SIZE"])
        if (code != 0 or not out.strip()) and "offline" in err:
            self._cmd(["wait-for-device"])
            code, out, err = self._cmd(["shell", "getconf", "PAGE_SIZE"])
        if code == 0 and out.strip().isdigit():
            return int(out.strip())
        return 4096

    def get_sdk(self) -> int:
        val = self.get_prop("ro.build.version.sdk")
        return int(val) if val.isdigit() else 35

    def uninstall(self, package: str) -> bool:
        if not PACKAGE_NAME_REGEX.match(package):
            raise ValueError(f"Invalid Android package name: {package}")
        code, out, _ = self._cmd(["uninstall", package])
        return code == 0 and "Success" in out

    def install(
        self,
        apk_path: str,
        bypass_low_target_sdk: bool = False,
        grant_permissions: bool = False,
    ) -> Tuple[bool, str]:
        args = ["install"]
        if bypass_low_target_sdk:
            args.append("--bypass-low-target-sdk-block")
        if grant_permissions:
            args.append("-g")
        args.append(apk_path)
        code, out, err = self._cmd(args)
        success = (code == 0 and "Success" in out)
        return success, out + err

    def install_lifecycle(self, apk_path: str, package: str, target_sdk: int, floor: int) -> Tuple[bool, str]:
        if not PACKAGE_NAME_REGEX.match(package):
            raise ValueError(f"Invalid Android package name: {package}")
        self.uninstall(package)
        success, log = self.install(apk_path, bypass_low_target_sdk=False)
        if not success and "INSTALL_FAILED_DEPRECATED_SDK_VERSION" in log:
            self.uninstall(package)
            return self.install(apk_path, bypass_low_target_sdk=True)
        return success, log
