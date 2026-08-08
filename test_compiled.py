#!/usr/bin/env python3
"""Test the PyInstaller-compiled beacon binary against a live HTTPS+AES listener."""
import os, sys, time, subprocess, shutil, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs.server import TeamServer

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data_bin")
shutil.rmtree(DATA, ignore_errors=True)
KEY = "compile-test-key"
PORT = 19555

srv = TeamServer(data_dir=DATA)
lis, err = srv.start_https_listener("bin", "127.0.0.1", PORT, crypto_key=KEY)
assert not err, err
print("[+] listener:", lis.url, "| AES on")

bindir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist", "cscli-beacon")
if not os.path.exists(bindir):
    print("[!] no built binary, run PyInstaller first")
    sys.exit(1)

bid = hashlib.sha1(b"compiled-beacon").hexdigest()[:16]
proc = subprocess.Popen([bindir, f"https://127.0.0.1:{PORT}",
                         "--name", bid, "--key", KEY, "--no-verify"],
                        stdout=open(os.path.join(DATA,"b.log"),"w"),
                        stderr=subprocess.STDOUT)
dl = time.time() + 15
while time.time() < dl and not srv.store.all():
    time.sleep(0.4)
if not srv.store.all():
    print("[!] compiled beacon never checked in")
    print(open(os.path.join(DATA,"b.log")).read())
    proc.kill(); sys.exit(1)
sid = srv.store.all()[0]["id"]
print("[+] compiled beacon session:", sid, "(", srv.store.all()[0]['hostname'], ")")

srv.task(sid, "exec 1+1")
srv.task(sid, "sysinfo")
time.sleep(6)
final = srv.store.get(sid)
results = "".join(r["data"] for r in final["results"])
print("--- results ---")
print("\n".join("  " + l for r in final["results"] for l in r["data"].splitlines()[:5]))
proc.terminate()
srv.stop_listener("bin")
ok = "2" in results and ("aarch64" in results.lower() or "AArch64" in results)
print("\n[PASS]" if ok else "[FAIL]", "compiled beacon executable (64-bit) works")
sys.exit(0 if ok else 1)
