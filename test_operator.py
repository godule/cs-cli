#!/usr/bin/env python3
"""Simulate a full operator session through the interactive Console.
The Console is the single TeamServer; it starts its own listener, a real beacon
registers against it, and the operator uses/tasks the session from the CLI."""
import os, sys, time, subprocess, shutil, builtins, io, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data_op")
shutil.rmtree(DATA, ignore_errors=True)
os.environ["CSCLI_DATA_DIR"] = DATA

from cs.cli.console import Console
from cs.payload import write_payload

port = 19277

# The Console owns the TeamServer. Start a listener through it first (by
# invoking the listener command), so the beacon registers with the SAME store
# that the console tasks against.
console = Console(data_dir=DATA)
out = []
script = [
    f"listener main {port} 127.0.0.1",
    "listeners",
    "quit",
]
it = iter(script)
orig = builtins.input
def fake(prompt=""):
    try:
        return next(it)
    except StopIteration:
        raise EOFError
builtins.input = fake
try:
    console.run(None)
except SystemExit:
    pass
finally:
    builtins.input = orig

# confirm listener is up on the console's team server
ports = [l["port"] for l in console.srv.listener_status()]
assert port in ports, "listener not started on console's teamserver"
print("[+] console listener running on", port)

# Build + launch a real beacon point at that listener.
write_payload(f"http://127.0.0.1:{port}", os.path.join(DATA,"bp.py"), interval=1, jitter=0)
bid = hashlib.sha1(b"op-session").hexdigest()[:16]
proc = subprocess.Popen([sys.executable, "-u", os.path.join(DATA,"bp.py"), "--name", bid],
                        stdout=open(os.path.join(DATA,"beacon.log"),"w"), stderr=subprocess.STDOUT)

# Wait for the beacon session to appear in the console's store
dl = time.time()+8
sid = None
while time.time() < dl:
    if console.srv.store.all():
        sid = console.srv.store.all()[0]["id"]
        break
    time.sleep(0.2)
assert sid, "beacon never checked in to console"
print("[+] session:", sid)

# Drive the interactive `use <sid>` session and task it.
cmds = [
    f"use {sid}",
    "shell echo OPERATOR-OK",
    "pwd",
    "cat /etc/hostname",
    "exit",
    f"results {sid}",
    "quit",
]
it = iter(cmds)
builtins.input = fake
try:
    console.run(None)
except SystemExit:
    pass
finally:
    builtins.input = orig

# Wait for the beacon to poll, execute, and post results.
time.sleep(6)
final = console.srv.store.get(sid)
print("\n=== final tasks/status ===", [(t['cmd'][:20], t['status']) for t in final['tasks']])
print("=== final results ===")
allres = ""
for r in final["results"]:
    allres += r["data"] + "\n"
    print("---", r["data"][:160], "\n")
proc.terminate()
ok = "OPERATOR-OK" in allres
print("[PASS]" if ok else "[FAIL]", "operator tasking+results flow")
sys.exit(0 if ok else 1)
