"""Session store - persistence for beacon sessions and task history."""
import json
import os
import time
import threading


class SessionStore:
    """Thread-safe persistence of sessions and their task/result history."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.RLock()
        self.sessions = {}
        self.load()

    def load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path) as f:
                data = json.load(f)
            for sid, s in data.items():
                s["last_seen"] = s.get("last_seen")
                self.sessions[sid] = s
        except Exception:
            self.sessions = {}

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with self.lock:
            with open(tmp, "w") as f:
                # drop transient fields before persisting
                data = {}
                for sid, s in self.sessions.items():
                    snap = {
                        "id": s["id"],
                        "hostname": s["hostname"],
                        "username": s["username"],
                        "pid": s["pid"],
                        "addr": s["addr"],
                        "arch": s["arch"],
                        "osinfo": s["osinfo"],
                        "internal_ip": s["internal_ip"],
                        "listener": s["listener"],
                        "first_seen": s["first_seen"],
                        "last_seen": s["last_seen"],
                        "tasks": s["tasks"],
                        "results": s["results"],
                    }
                    data[sid] = snap
                json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self.path)

    def new_session(self, sid, meta, listener, addr):
        now = time.time()
        s = {
            "id": sid,
            "hostname": meta.get("hostname", "unknown"),
            "username": meta.get("username", "unknown"),
            "pid": meta.get("pid", 0),
            "addr": addr,
            "arch": meta.get("arch", "unknown"),
            "osinfo": meta.get("osinfo", "unknown"),
            "internal_ip": meta.get("internal_ip", ""),
            "listener": listener,
            "first_seen": now,
            "last_seen": now,
            "tasks": [],   # {"id","cmd","ts","status"}
            "results": [], # {"id","data","ts"}
        }
        with self.lock:
            self.sessions[sid] = s
        self.save()
        return s

    def update_seen(self, sid):
        with self.lock:
            if sid in self.sessions:
                self.sessions[sid]["last_seen"] = time.time()

    def get(self, sid):
        with self.lock:
            return self.sessions.get(sid)

    def session_store_keys(self):
        with self.lock:
            return set(self.sessions.keys())

    def all(self):
        with self.lock:
            return list(self.sessions.values())

    def remove(self, sid):
        with self.lock:
            if sid in self.sessions:
                del self.sessions[sid]
        self.save()

    def add_task(self, sid, cmd):
        tid = f"{int(time.time()*1000)}"
        task = {"id": tid, "cmd": cmd, "ts": time.time(), "status": "queued"}
        with self.lock:
            if sid in self.sessions:
                self.sessions[sid]["tasks"].append(task)
        self.save()  # persist so multi-process drivers can queue tasks for the daemon
        return tid

    def set_task_status(self, sid, tid, status):
        with self.lock:
            s = self.sessions.get(sid)
            if s:
                for t in s["tasks"]:
                    if t["id"] == tid:
                        t["status"] = status

    def pending_tasks(self, sid):
        with self.lock:
            s = self.sessions.get(sid)
            if not s:
                return []
            pending = [t for t in s["tasks"] if t["status"] == "queued"]
            for t in pending:  # mark as dispatched
                t["status"] = "sent"
            return pending

    def add_result(self, sid, tid, data):
        with self.lock:
            s = self.sessions.get(sid)
            if s:
                s["results"].append({"id": tid, "data": data, "ts": time.time()})
        self.set_task_status(sid, tid, "completed")
        self.save()  # persist so other processes (CLI driver) can observe

    def reload(self):
        """Re-read state from disk (for multi-process CLI drivers)."""
        with self.lock:
            self.load()
