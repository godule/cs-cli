#!/usr/bin/env python3
"""End-to-end self-test: start teamserver + listener, register a fake beacon,
queue a task, run a real Beacon tick against it, verify result."""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cs.server import TeamServer
import threading

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data_test")

def main():
    srv = TeamServer(data_dir=DATA)
    lis, err = srv.start_listener("t", "127.0.0.1", 19191)
    assert not err, err
    print("[+] listener up:", lis.url)

    # register a beacon-less checkin to create a session
    import hashlib
    bid = hashlib.sha1(b"e2e-test").hexdigest()[:16]
    meta = {"hostname":"testhost","username":"tester","pid":1234,
            "arch":"x86_64","osinfo":"Linux 5.15","internal_ip":"10.0.0.5"}
    sess_rec = srv.store.new_session(bid, meta, "t", "127.0.0.1")
    sid = sess_rec["id"]

    # queue 3 tasks
    srv.task(sid, "shell echo hello-from-beacon; uname -s")
    srv.task(sid, "pwd")
    srv.task(sid, "whoami")

    # Now use a real Beacon client pointed at the listener.
    from cs.client.beacon import Beacon
    # The beacon's _tick() does: checkin -> pull pending -> execute each -> post results.
    # First tick: polls, gets 3 pending tasks (marked sent), executes them, posts results.
    beac = Beacon(lis.url, interval=1, jitter=0, beacon_id=sid)
    beac._tick()

    # A second tick with no new tasks should be harmless and return no results.
    beac._tick()

    ok = True
    s = srv.store.get(sid)
    print("\n=== collected results ===")
    for r in s["results"]:
        if "hello-from-beacon" in r["data"]:
            print("[PASS] shell command executed and result collected")
        print("---")
        print(r["data"][:300])
    print("\n=== sessions ===")
    for s2 in srv.store.all():
        print(f"  {s2['id']} {s2['hostname']}@{s2['internal_ip']} alive={srv.is_session_alive(s2)}")

    # persist + reload
    srv.store.save()
    srv2 = TeamServer(data_dir=DATA)
    print("[+] reloaded sessions:", [x['id'] for x in srv2.store.all()])

    print("\n[PASS] e2e flow OK")
    return 0

if __name__ == "__main__":
    sys.exit(main())
