"""
signer.py - PKCS12 keystore manager and apksigner bridge.
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any


def get_apksigner_cmd() -> str:
    which_cmd = shutil.which("apksigner")
    if which_cmd:
        return which_cmd
    sdk_roots = [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk"),
        os.path.expanduser("~/Library/Android/sdk"),
        os.path.expanduser("~/Android/Sdk")
    ]
    for root in sdk_roots:
        if not root or not os.path.exists(root):
            continue
        build_tools_dir = os.path.join(root, "build-tools")
        if os.path.exists(build_tools_dir):
            versions = sorted(os.listdir(build_tools_dir), reverse=True)
            for ver in versions:
                for candidate in ["apksigner.bat", "apksigner"]:
                    cand_path = os.path.join(build_tools_dir, ver, candidate)
                    if os.path.exists(cand_path):
                        return cand_path
    return "apksigner"


def ensure_keystore(keystore_path: Optional[str] = None) -> str:
    path = Path(keystore_path) if keystore_path else Path.home() / ".apkrevive" / "debug.p12"
    path.parent.mkdir(parents=True, exist_ok=True)

    if not path.exists():
        keytool = shutil.which("keytool") or "keytool"
        cmd = [
            keytool, "-genkeypair", "-v",
            "-keystore", str(path),
            "-storetype", "PKCS12",
            "-storepass", "android",
            "-alias", "apkrevive",
            "-keypass", "android",
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "10000",
            "-dname", "CN=ApkRevive,O=ApkRevive,C=US"
        ]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception:
            pass
    return str(path)


def sign_apk(apk_path: str, keystore_path: Optional[str] = None) -> bool:
    apksigner = get_apksigner_cmd()
    ks = ensure_keystore(keystore_path)
    cmd = [
        apksigner, "sign",
        "--ks", ks,
        "--ks-pass", "pass:android",
        "--ks-key-alias", "apkrevive",
        "--key-pass", "pass:android",
        apk_path
    ]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return res.returncode == 0
    except Exception:
        return False


def verify_apk(apk_path: str) -> Dict[str, Any]:
    apksigner = get_apksigner_cmd()
    cmd = [apksigner, "verify", "-v", apk_path]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return {"verified": res.returncode == 0, "output": res.stdout + res.stderr}
    except Exception as e:
        return {"verified": False, "output": str(e)}
