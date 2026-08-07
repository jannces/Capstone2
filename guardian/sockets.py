"""
guardian/sockets.py
Socket.IO events — pushes a stats heartbeat and serves initial state.
Individual events (device_update, new_threat, connection_event) are
emitted directly by the engines the moment they happen.
"""
import threading
import time

from flask import session
from . import socketio, state, devices, db

_heartbeat_started = False
_hb_lock = threading.Lock()


@socketio.on("connect")
def _on_connect():
    if not session.get("admin"):
        return False                      # sockets require a login session
    global _heartbeat_started
    with _hb_lock:
        if not _heartbeat_started:
            _heartbeat_started = True
            threading.Thread(target=_heartbeat, daemon=True).start()
    socketio.emit("devices_snapshot", devices.all_snapshots())


def _heartbeat():
    """Light stats push every 2 s so counters tick without polling."""
    while True:
        try:
            cnt = devices.counts()
            with state.lock:
                pkts = dict(state.stats)
                active = state.net["scan_active"]
            sev = {r["severity"]: r["n"] for r in db.query(
                "SELECT severity, COUNT(*) n FROM threats "
                "WHERE status NOT IN ('Resolved','False Positive') "
                "GROUP BY severity")}
            socketio.emit("heartbeat", {
                "devices": cnt, "packets": pkts, "scan_active": active,
                "severity": {s: sev.get(s, 0) for s in
                             ("Critical", "High", "Medium", "Low")},
                "server_time": db.now(),
            })
        except Exception:
            pass
        time.sleep(2)
