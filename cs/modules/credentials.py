"""Gated OS-native credential data interface.

IMPORTANT AUTHORIZATION BOUNDARY
---------------------------------
This module does NOT dump passwords/hashes from process memory (no Mimikatz-
style LSASS scraping) -- that capability is out of scope and not shipped.

What it enumerates is only what the operating system itself exposes to the
*calling user* through documented, legitimate APIs:
  * Windows:  the Credential Manager (the logged-in user's own saved web/local
              credentials) via the built-in `cmdkey` utility, plus the current
              environment (env vars / Vault).
  * Linux:    the calling user's kernel session keyring (`keyctl`) and any
              plaintext session env, which the user themselves owns.

Use only on systems you are authorised to test as the operator's own account.
"""
import os
import platform
import shutil
import subprocess


def _is_windows():
    return os.name == "nt"


def _run(args, timeout=10):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.stdout + ("\n" + p.stderr if p.stderr else "")
    except Exception as e:
        return f"<err {e}>"


def _windows_credentials():
    cmdkey = shutil.which("cmdkey") or "cmdkey"
    lines = _run([cmdkey, "/list"]).splitlines()
    filtered = [
        l for l in lines
        if any(k in l for k in ("Target:", "User:", "Type:"))
    ]
    return "\n".join(filtered) or "(no saved credentials via cmdkey / none visible)"


def _linux_keyring():
    keyctl = shutil.which("keyctl")
    if not keyctl:
        return "(keyctl not installed; no keyring enumeration)"
    out = _run([keyctl, "session"])
    # filter to lines owned by this session
    kept = [l for l in out.splitlines() if l.strip()]
    return "\n".join(kept) or "(empty session keyring)"


def _environment():
    """Surface selected benign, documented env (target-process context)."""
    keys = [k for k in ("USER", "USERNAME", "LOGNAME", "HOME", "PWD", "TMP", "TEMP", "COMPUTERNAME", "HOSTNAME")
            if k in os.environ]
    return "\n".join(f"{k}={os.environ[k]}" for k in keys)


def enumerate_credentials(scope="all"):
    """Return a text report of credentials the OS exposes to this user, for the
    requested scope. Raises/gates on input."""
    if scope not in ("all", "windows", "linux", "env"):
        return (False, "scope must be one of: all, windows, linux, env")
    parts = []
    if scope in ("all", "env"):
        parts.append("[environment]\n" + _environment())
    is_win = _is_windows() or platform.system() == "Windows"
    if scope in ("all", "windows") and is_win:
        parts.append("[windows Credential Manager]\n" + _windows_credentials())
    elif scope in ("windows",):
        parts.append("[windows Credential Manager] not running on Windows, skipped")
    if scope in ("all", "linux") and not is_win:
        parts.append("[linux session keyring]\n" + _linux_keyring())
    elif scope == "linux" and is_win:
        parts.append("[linux keyring] not on Linux, skipped")
    return True, "\n\n".join(parts)
