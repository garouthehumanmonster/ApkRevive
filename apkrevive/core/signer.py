"""
signer.py - PKCS12 keystore manager and apksigner bridge.
"""

import getpass
import os
import secrets
import shutil
import struct
import subprocess
import sys
import warnings
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from apkrevive.core.toolchain import find_sdk_tool, find_jdk_tool


def get_apksigner_cmd() -> str:
    found = find_sdk_tool("apksigner")
    return found or "apksigner"


def get_default_user_keystore() -> Tuple[Path, str, str]:
    """
    Returns user-isolated keystore path, persistent password, and alias.
    Path format: ~/.apkrevive/user_<username>.p12
    Password format: saved in ~/.apkrevive/user_<username>.pwd with 0600 permissions.
    """
    username = getpass.getuser().lower().replace(" ", "_")
    base_dir = Path.home() / ".apkrevive"
    base_dir.mkdir(parents=True, exist_ok=True)

    ks_path = base_dir / f"user_{username}.p12"
    pwd_path = base_dir / f"user_{username}.pwd"
    alias = f"apkrevive_{username}"

    if pwd_path.is_file():
        password = pwd_path.read_text(encoding="utf-8").strip()
    else:
        password = secrets.token_hex(16)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(str(pwd_path), flags, 0o600)
        try:
            with open(fd, "w", encoding="utf-8") as f:
                f.write(password)
        finally:
            pass
        try:
            os.chmod(pwd_path, 0o600)
        except Exception as e:
            warnings.warn(f"Failed to set 0o600 permissions on password file {pwd_path}: {e}")

    return ks_path, password, alias


def ensure_keystore(
    keystore_path: Optional[str] = None,
    keystore_pass: Optional[str] = None,
    key_alias: Optional[str] = None
) -> Tuple[str, str, str]:
    """
    Ensures a valid keystore exists and returns (keystore_path, keystore_pass, key_alias).
    If keystore_path is provided, checks it exists (raises FileNotFoundError if missing).
    If keystore_path is None, generates per-user keystore via keytool if missing (raises RuntimeError on failure).
    """
    if keystore_pass is None:
        keystore_pass = os.environ.get("APKREVIVE_KEYSTORE_PASS")

    if keystore_path is None:
        env_ks = os.environ.get("APKREVIVE_KEYSTORE")
        if env_ks and Path(env_ks).is_file():
            keystore_path = env_ks

    if keystore_path:
        path = Path(keystore_path)
        if not path.is_file():
            raise FileNotFoundError(f"Keystore file not found: {keystore_path}")
        if not keystore_pass:
            warnings.warn(
                f"Custom keystore '{keystore_path}' specified without password; "
                "set via --ks-pass or APKREVIVE_KEYSTORE_PASS. Defaulting to 'android'."
            )
            keystore_pass = "android"
        alias = key_alias or "apkrevive"
        return str(path), keystore_pass, alias

    default_ks, default_pwd, default_alias = get_default_user_keystore()
    password = keystore_pass or default_pwd
    alias = key_alias or default_alias

    if not default_ks.is_file():
        keytool = find_jdk_tool("keytool")
        if not keytool:
            raise RuntimeError(
                "keytool binary not found in JDK or PATH. Keystore generation requires JDK keytool. "
                "Run 'apkrevive doctor' to diagnose toolchain prerequisites."
            )

        cmd = [
            keytool, "-genkeypair", "-v",
            "-keystore", str(default_ks),
            "-storetype", "PKCS12",
            "-storepass", password,
            "-alias", alias,
            "-keypass", password,
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "10000",
            "-dname", f"CN=ApkRevive ({alias}),O=ApkRevive,C=US"
        ]
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode != 0:
                raise RuntimeError(f"keytool failed to generate keystore: {res.stderr}")
        except FileNotFoundError as e:
            raise RuntimeError(
                "keytool binary not found in JDK or PATH. Keystore generation requires JDK keytool. "
                "Run 'apkrevive doctor' to diagnose toolchain prerequisites."
            ) from e

    return str(default_ks), password, alias


def sign_apk(
    apk_path: str,
    keystore_path: Optional[str] = None,
    keystore_pass: Optional[str] = None,
    key_alias: Optional[str] = None,
    key_pass: Optional[str] = None
) -> bool:
    """Signs target APK using apksigner and PKCS12 keystore."""
    apksigner = get_apksigner_cmd()
    try:
        ks, ks_pwd, alias = ensure_keystore(keystore_path, keystore_pass, key_alias)
    except RuntimeError:
        raise
    except Exception as e:
        sys.stderr.write(f"Keystore error: {e}\n")
        return False

    actual_key_pass = key_pass or ks_pwd
    cmd = [
        apksigner, "sign",
        "--ks", ks,
        "--ks-pass", "env:APKREVIVE_KS_PASS",
        "--ks-key-alias", alias,
        "--key-pass", "env:APKREVIVE_KEY_PASS",
        str(apk_path)
    ]
    env = os.environ.copy()
    env["APKREVIVE_KS_PASS"] = ks_pwd
    env["APKREVIVE_KEY_PASS"] = actual_key_pass
    try:
        res = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return res.returncode == 0
    except FileNotFoundError as e:
        raise RuntimeError(
            "Missing required signing tool(s): apksigner. "
            "APK signing requires JDK (keytool) and Android SDK build-tools (apksigner). "
            "Run 'apkrevive doctor' to diagnose your environment or use '--no-sign' to skip signing."
        ) from e
    except Exception as e:
        sys.stderr.write(f"apksigner execution error: {e}\n")
        return False


def verify_apk(apk_path: str, verbose: bool = False) -> Dict[str, Any]:
    """Verifies APK signatures using apksigner verify."""
    apksigner = get_apksigner_cmd()
    cmd = [apksigner, "verify"]
    if verbose:
        cmd.append("--verbose")
    cmd.append(str(apk_path))
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return {"verified": res.returncode == 0, "output": res.stdout + res.stderr}
    except Exception as e:
        return {"verified": False, "output": str(e)}


def verify_apk_certs(apk_path: str) -> Tuple[bool, str]:
    """
    Verifies APK certificates post-signing using apksigner if available,
    or falls back to internal signing block padding validation.
    """
    apksigner = get_apksigner_cmd()
    apksigner_available = (os.path.isabs(apksigner) and os.path.exists(apksigner)) or (shutil.which(apksigner) is not None)
    if apksigner_available:
        try:
            res = subprocess.run(
                [apksigner, "verify", "--print-certs", str(apk_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            return (res.returncode == 0, res.stdout + res.stderr)
        except Exception as e:
            return (False, f"apksigner execution error: {e}")

    result = verify_signing_block_padding(apk_path)
    msg = (
        "Internal signing block validation passed"
        if result["valid"]
        else "Invalid signing block or Central Directory alignment"
    )
    return (bool(result["valid"]), msg)


def verify_signing_block_padding(apk_path: str) -> Dict[str, Any]:
    """
    Verifies APK Signing Block presence, Android Verity Padding Block (0x42726577),
    and Central Directory 4KB alignment.
    """
    with open(apk_path, "rb") as f:
        in_buf = f.read()

    buf_len = len(in_buf)
    eocd_pos = in_buf.rfind(b"PK\x05\x06")
    if eocd_pos == -1 or eocd_pos + 22 > buf_len:
        return {
            "has_signing_block": False,
            "cd_offset": 0,
            "cd_aligned_4k": False,
            "has_verity_padding": False,
            "block_ids": [],
            "signing_block_size": 0,
            "valid": False,
        }

    cd_entries_total, cd_size, cd_offset = struct.unpack_from("<HII", in_buf, eocd_pos + 10)

    if cd_offset >= 32 and in_buf[cd_offset - 16 : cd_offset] == b"APK Sig Block 42":
        block_size = struct.unpack_from("<Q", in_buf, cd_offset - 24)[0]
        start_offset = cd_offset - block_size - 8
        if start_offset >= 0:
            block_size_start = struct.unpack_from("<Q", in_buf, start_offset)[0]
            if block_size_start == block_size:
                block_ids = []
                pos = cd_offset - block_size
                end_pos = cd_offset - 24
                while pos + 12 <= end_pos:
                    pair_size = struct.unpack_from("<Q", in_buf, pos)[0]
                    if pair_size < 4 or pos + 8 + pair_size > end_pos:
                        break
                    pair_id = struct.unpack_from("<I", in_buf, pos + 8)[0]
                    block_ids.append(pair_id)
                    pos += 8 + pair_size
                return {
                    "has_signing_block": True,
                    "cd_offset": cd_offset,
                    "cd_aligned_4k": (cd_offset % 4096 == 0),
                    "has_verity_padding": (0x42726577 in block_ids),
                    "block_ids": block_ids,
                    "signing_block_size": block_size,
                    "valid": (cd_offset % 4096 == 0),
                }

    return {
        "has_signing_block": False,
        "cd_offset": cd_offset,
        "cd_aligned_4k": (cd_offset % 4096 == 0),
        "has_verity_padding": False,
        "block_ids": [],
        "signing_block_size": 0,
        "valid": False,
    }

