#!/usr/bin/env python3
"""Test the non-interactive CLI driver (cs/cli/runner.py) end to end:
drive server+payload+list+task+wait+results purely as subprocess CLI calls."""
import os, sys, time, subprocess, shutil, json, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data_cli")
shutil.rmtree(DATA, ignore_errors=True)
os.environ["CSCLI_DATA_DIR"] = DATA

CLI = [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cscli")]
KEY = "cli-test-key"
# use a randomized high port to avoid stale-daemon collisions
import random
PORT = random.randint(22000, 26000)
# best-effort kill any stale cscli daemons from previous runs
subprocess.run(["pkill", "-f", "python.*cscli --server"], capture_output=True)
time.sleep(1)

def run(args, timeout=60):
    r = subprocess.run(CLI + args, capture_output=True, text=True, timeout=timeout,
                       env={**os.environ})
    return r.returncode, r.stdout, r.stderr

# 1. start HTTPS+AES server in background
rc, out, err = run(["--server", "--https", "--name", "main", "--host", "127.0.0.1",
                    "--port", str(PORT), "--key", KEY, "--background"])
print("[server]", out.strip()); assert rc == 0, err
srv_state = json.loads(out); assert srv_state["ok"]

# 2. generate payload (same key, no-verify for self-signed)
bp = os.path.join(DATA, "bp.py")
rc, out, err = run(["--payload", "--url", f"https://127.0.0.1:{PORT}",
                    "--out", bp, "--key", KEY, "--no-verify"])
print("[payload]", out.strip()); assert rc == 0, err
assert os.path.exists(bp)

# 3. run the beacon as a subprocess against that listener
bid = hashlib.sha1(b"cli-driver").hexdigest()[:16]
bproc = subprocess.Popen([sys.executable, "-u", bp, "--name", bid],
                         stdout=open(DATA+"/b.log","w"), stderr=subprocess.STDOUT)

# 4. poll --list until the beacon shows up
sid = None
for _ in range(20):
    rc, out, err = run(["--list"])
    data = json.loads(out)
    if data["sessions"]:
        sid = data["sessions"][0]["id"]
        break
    time.sleep(0.5)
assert sid, "beacon never listed (" + err + ")"
print("[list] session:", sid)

# 5. task with --wait (wait for result through the channel)
rc, out, err = run(["--task", sid, "exec 6*7", "--wait", "--timeout", "40"])
print("[task]", out.strip())
if rc != 0:
    print("=== beacon.log ===")
    try: print(open(os.path.join(DATA,"b.log")).read())
    except Exception: pass
    print("=== daemon.log ===")
    try: print(open(os.path.join(DATA,"daemon.log")).read())
    except Exception: pass
    print("=== sessions.json ===")
    try:
        for sid2, s in json.load(open(os.path.join(DATA,"sessions.json"))).items():
            print(sid2, [(t['cmd'],t['status']) for t in s.get('tasks',[])], [r['data'] for r in s.get('results',[])])
    except Exception as e: print("json reader", e)
    print("=== daemon alive? ===")
    import subprocess as sb
    r=sb.run(["ps","aux"],capture_output=True,text=True)
    print([l for l in r.stdout.splitlines() if "cscli --server" in l])
    sys.exit(1)
res = json.loads(out); assert res["ok"] and "42" in res["result"], res

# 6. results dump
rc, out, err = run(["--results", sid])
print("[results]", out.strip()[:200])
res = json.loads(out); assert res["count"] >= 1

bproc.terminate()
print("\n[PASS] non-interactive CLI driver works end-to-end")
sys.exit(0)
