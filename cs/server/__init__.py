"""TeamServer - orchestrator holding listeners, session store, and API for CLI."""
import json
import os
import time
import threading

from .store import SessionStore
from .listener import Listener
from .reverseshell import ReverseShellListener
from .. import commands as cmd


class TeamServer:
    def __init__(self, name="teamserver", data_dir=None):
        self.name = name
        if data_dir is None:
            data_dir = os.path.join(os.path.dirname(__file__), "..", "..", "data")
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.store = SessionStore(os.path.join(data_dir, "sessions.json"))
        self.listeners = {}
        self.rsh_listeners = {}   # name -> ReverseShellListener
        self.config = {
            "beacon_interval": 5,
            "jitter": 0.2,
        }
        self.mutex = threading.RLock()
        self._load_config()

    def _config_path(self):
        return os.path.join(self.data_dir, "config.json")

    def _load_config(self):
        if os.path.exists(self._config_path()):
            try:
                with open(self._config_path()) as f:
                    self.config.update(json.load(f))
            except Exception:
                pass

    def _save_config(self):
        with open(self._config_path(), "w") as f:
            json.dump(self.config, f, indent=2)

    # ---------- Listeners ----------
    def start_listener(self, name, host, port, tls=None, crypto_key=None, interval=None):
        with self.mutex:
            if name in self.listeners:
                return None, "listener already exists"
            if any(l.port == port for l in self.listeners.values()):
                return None, f"port {port} already in use by another listener"
            try:
                lis = Listener(name, host, port, self.store,
                               on_new_session_cb=self._on_new_session,
                               interval=interval or self.beacon_interval(),
                               command_names=self.command_names(),
                               tls=tls, crypto_key=crypto_key)
                lis.start()
                self.listeners[name] = lis
            except Exception as e:
                return None, f"failed to start listener: {e}"
        return lis, None

    def start_https_listener(self, name, host, port, cert=None, key=None,
                             crypto_key=None, interval=None):
        """Start a TLS-wrapped listener. Cert/key auto-generated if absent."""
        from ..crypto.certs import generate_self_signed_cert
        data_dir = self.data_dir
        cert = cert or os.path.join(data_dir, f"{name}.crt")
        key = key or os.path.join(data_dir, f"{name}.key")
        if not (os.path.exists(cert) and os.path.exists(key)):
            try:
                generate_self_signed_cert(cert, key)
            except Exception as e:
                return None, f"cert generation failed: {e}"
        tls = {"cert": cert, "key": key}
        return self.start_listener(name, host, port, tls=tls,
                                   crypto_key=crypto_key, interval=interval)

    def stop_listener(self, name):
        with self.mutex:
            lis = self.listeners.pop(name, None)
            if not lis:
                return False, "listener not found"
            try:
                lis.stop()
            except Exception:
                pass
        return True, None

    def _on_new_session(self, sess):
        # hook for CLI banner printing is wired in console
        pass

    def listener_status(self):
        out = []
        with self.mutex:
            for n, l in self.listeners.items():
                out.append({"name": n, "url": l.url, "running": l.running,
                            "port": l.port, "host": l.host})
        for n, l in self.rsh_listeners.items():
            out.append({"name": n, "url": l.url, "running": l.running,
                        "port": l.port, "host": l.host, "type": "reverse-shell"})
        return out

    # ---------- Reverse-shell (raw TCP) listeners ----------
    def start_reverse_shell(self, name, host, port, on_session=None):
        """Start a raw TCP reverse-shell listener."""
        with self.mutex:
            if name in self.rsh_listeners:
                return None, "reverse-shell listener already exists"
            if any(l.port == port for l in list(self.listeners.values()) +
                   list(self.rsh_listeners.values())):
                return None, f"port {port} already in use"
        try:
            lis = ReverseShellListener(name, host, port, on_session=on_session)
            lis.start()
            with self.mutex:
                self.rsh_listeners[name] = lis
        except Exception as e:
            return None, f"failed to start reverse-shell listener: {e}"
        return lis, None

    def stop_reverse_shell(self, name):
        with self.mutex:
            lis = self.rsh_listeners.pop(name, None)
        if not lis:
            return False, "reverse-shell listener not found"
        try:
            lis.stop()
        except Exception:
            pass
        return True, None

    # ---------- Command plumbing ----------
    def beacon_interval(self):
        return self.config.get("beacon_interval", 5)

    def set_beacon_interval(self, sec):
        self.config["beacon_interval"] = max(1, int(sec))
        self._save_config()
        return self.config["beacon_interval"]

    def command_names(self):
        return cmd.ALL_NAMES

    # ---------- Tasking ----------
    def task(self, sid, cmdline, echo=False):
        """Queue a task for a session. Returns queue info or error."""
        s = self.store.get(sid)
        if not s:
            return None, {"error": "session not found"}
        if not self.is_session_alive(s):
            return None, {"error": "session appears dead (beacon not seen recently). "
                                  "Try 'checkin' or wait for beacon to poll back."}
        name, args, err = cmd.validate_cmd(cmdline)
        if err:
            return None, {"error": err}
        tid = self.store.add_task(sid, cmdline)
        return tid, {"queued": tid, "cmd": cmdline, "target": sid}

    def is_session_alive(self, s, timeout=60):
        now = time.time()
        last = s.get("last_seen") or 0
        return (now - last) < max(timeout, self.beacon_interval() * 3)
