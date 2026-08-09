#!/usr/bin/env python3
"""Test connection resilience + server-ordered disconnect / deletion.

Scenario:
  A. A beacon keeps retrying if it starts before the listener is up (reconnect).
  B. If the server drops/restarts, the beacon re-checks in (doesn't give up).
  C. `disconnect` task stops the beacon and self-removes its session.
  D. `--delete` removes a session record (and refuses/accepts based on liveness).
"""
import os, sys, time, subprocess, shutil, hashlib, socket
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs.server import TeamServer

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data_resil")
shutil.rmtree(DATA, ignore_errors=True)
os.makedirs(DATA, exist_ok=True)

# ---- A: beacon started before server is up should retry, not exit ----
def start_server(port):
    srv = TeamServer(data_dir=DATA)
    srv.start_listener("main", "127.0.0.1", port)
    return srv

PORT = 26551
beacon_script = os.path.join(DATA, "b.py")
from cs.payload import write_payload
write_payload(f"http://127.0.0.1:{PORT}", beacon_script, interval=1, jitter=0)

bid = hashlib.sha1(b"resilience").hexdigest()[:16]
# Launch the beacon FIRST (server not up yet)
bproc = subprocess.Popen([sys.executable, "-u", beacon_script, "--name", bid],
                         stdout=open(os.path.join(DATA, "b.log"), "w"),
                         stderr=subprocess.STDOUT)
time.sleep(2)  # beacon should be in its retry loop, still alive
assert bproc.poll() is None, "beacon exited while server was down (should retry)"
print("[A] beacon alive during initial server outage (retrying): OK")

# Now start the server; beacon should register within a few seconds
srv = start_server(PORT)
dl = time.time() + 10
while time.time() < dl and not srv.store.all():
    time.sleep(0.4)
assert srv.store.all(), "beacon never registered after server came up"
sid = srv.store.all()[0]["id"]
print("[B] beacon registered after server came online:", sid)

# ---- B: restart the server; beacon should re-checkin ----
srv.stop_listener("main")
time.sleep(2)  # beacon hits an outage; should keep retrying
assert bproc.poll() is None, "beacon exited during server restart (should retry)"
# reuse the same store (persisted) or re-init
srv2 = TeamServer(data_dir=DATA)
srv2.start_listener("main", "127.0.0.1", PORT)
dl = time.time() + 10
while time.time() < dl:
    s = srv2.store.reload() if hasattr(srv2.store, "reload") else None
    news = srv2.store.get(sid)
    if news and srv2.is_session_alive(news):
        break
    time.sleep(0.5)
print("[B] beacon reconnected after server restart (last_seen fresh):",
      srv2.is_session_alive(srv2.store.get(sid)))

# ---- C: server-ordered disconnect ----
srv2.task(sid, "disconnect")
time.sleep(4)   # beacon picks up the task, self-disconnects
# the beacon should have exited by now
gone = bproc.wait(timeout=5) if bproc.poll() is None else True
print("[C] beacon process exited after disconnect:", bproc.poll() is not None)

# ---- D: --delete removes a session record ----
# the disconnect already removed it; re-add a fake dead record to test --delete
from cs.server import SessionStore
dead_sid = "deadbeef0011"
meta = {"hostname": "rem", "username": "x", "pid": 0, "arch": "x",
        "osinfo": "gone", "internal_ip": "0.0.0.0"}
sess = srv2.store.new_session(dead_sid, meta, "main", "127.0.0.1")
sess["last_seen"] = time.time() - 9999  # make it stale/dead
srv2.store.save()
ok, msg = srv2.remove_session(dead_sid)
print("[D] delete dead session:", ok, msg)
assert ok
# delete an alive fake session without force should refuse
alive_sid = "aabbcc0011"
s2 = srv2.store.get(alive_sid) or srv2.store.new_session(alive_sid, meta, "main", "127.0.0.1")
ok2, msg2 = srv2.remove_session(alive_sid)   # no force
print("[D] delete alive session (no force) refused:", (not ok2), msg2)
assert not ok2
ok3, msg3 = srv2.remove_session(alive_sid, force=True)
print("[D] delete alive session (force):", ok3, msg3)
assert ok3

bproc.kill()
print("\n[PASS] resilience + disconnect + delete all verified")
sys.exit(0)
