"""
guardian/devices.py
Connected Device Monitoring: registry, connect/disconnect/reconnect
events, hostname/vendor resolution, DB persistence, socket emits.
"""
import socket
import datetime
import threading

from . import state, db
from .vendors import oui_lookup
from .config import Config
from .netdiscovery import ip_in_subnet


def _emit(event: str, payload):
    try:
        state.socketio_ref().emit(event, payload)
    except Exception:
        pass


def _now_str() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def device_snapshot(mac: str, dev: dict) -> dict:
    """JSON-safe view of one device for the dashboard."""
    online_secs = dev.get("total_online_secs", 0)
    if dev.get("status") == "online" and dev.get("session_start_mono"):
        online_secs += int(state.mono() - dev["session_start_mono"])
    return {
        "mac": mac,
        "ip": dev.get("ip", ""),
        "hostname": dev.get("hostname", ""),
        "vendor": dev.get("vendor", ""),
        "status": dev.get("status", "online"),
        "first_seen": dev.get("first_seen", ""),
        "last_seen": dev.get("last_seen", ""),
        "session_start": dev.get("session_start", ""),
        "online_secs": online_secs,
        "is_gateway": dev.get("is_gateway", False),
        "is_self": dev.get("is_self", False),
    }


def all_snapshots() -> list:
    with state.lock:
        return [device_snapshot(m, d) for m, d in state.devices.items()]


def _log_event(event: str, mac: str, ip: str, hostname: str, vendor: str):
    db.execute(
        "INSERT INTO connection_log (ts, event, mac, ip, hostname, vendor) "
        "VALUES (?,?,?,?,?,?)",
        (_now_str(), event, mac, ip, hostname, vendor))
    _emit("connection_event", {
        "ts": _now_str(), "event": event, "mac": mac,
        "ip": ip, "hostname": hostname, "vendor": vendor,
    })


def _persist(mac: str, dev: dict):
    db.execute(
        """INSERT INTO devices
             (mac, ip, hostname, vendor, status, first_seen, last_seen,
              total_online_secs, session_start, is_gateway, is_self)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(mac) DO UPDATE SET
             ip=excluded.ip, hostname=excluded.hostname,
             vendor=excluded.vendor, status=excluded.status,
             last_seen=excluded.last_seen,
             total_online_secs=excluded.total_online_secs,
             session_start=excluded.session_start,
             is_gateway=excluded.is_gateway, is_self=excluded.is_self""",
        (mac, dev.get("ip", ""), dev.get("hostname", ""),
         dev.get("vendor", ""), dev.get("status", "online"),
         dev.get("first_seen", ""), dev.get("last_seen", ""),
         dev.get("total_online_secs", 0), dev.get("session_start", ""),
         int(dev.get("is_gateway", False)), int(dev.get("is_self", False))))


def load_from_db():
    """Restore device history (marked offline) on startup."""
    for row in db.query("SELECT * FROM devices"):
        with state.lock:
            state.devices[row["mac"]] = {
                "ip": row["ip"] or "",
                "hostname": row["hostname"] or "",
                "vendor": row["vendor"] or "",
                "status": "offline",
                "first_seen": row["first_seen"] or "",
                "last_seen": row["last_seen"] or "",
                "session_start": "",
                "session_start_mono": None,
                "total_online_secs": row["total_online_secs"] or 0,
                "last_packet": 0.0,
                "miss": 0,
                "is_gateway": bool(row["is_gateway"]),
                "is_self": bool(row["is_self"]),
            }


def register_sighting(ip: str, mac: str, hostname: str = "",
                      passive: bool = True):
    """
    Called every time a device is seen (packet, ARP scan, probe reply).
    Handles Connected / Reconnected transitions and last-seen bookkeeping.
    This is the hot path — keep it cheap.
    """
    if not mac or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return
    now_s = _now_str()
    now_m = state.mono()
    event = None

    with state.lock:
        gw_mac  = state.net["gateway_mac"]
        my_mac  = state.net["local_mac"]
        subnet  = state.net["subnet"]
        dev = state.devices.get(mac)

    # Traffic the router relays from the internet carries the router's MAC
    # but a PUBLIC source IP. Never let an out-of-subnet IP define a device
    # — it would overwrite the gateway's real IP and phantom "internet
    # devices" into the list. Strip it; an empty IP just refreshes liveness.
    if ip and subnet and not ip_in_subnet(ip, subnet):
        ip = ""
    # A sighting we can't place on the LAN (no in-subnet IP) may still keep
    # a KNOWN device alive, but must not CREATE a new phantom entry — those
    # get a real IP from the ARP sweep instead.
    if dev is None and not ip:
        return

    with state.lock:
        dev = state.devices.get(mac)

        if dev is None:                               # ── NEW DEVICE ──
            dev = {
                "ip": ip or "", "hostname": hostname,
                "vendor": oui_lookup(mac),
                "status": "online",
                "first_seen": now_s, "last_seen": now_s,
                "session_start": now_s, "session_start_mono": now_m,
                "total_online_secs": 0,
                "last_packet": now_m, "miss": 0,
                "is_gateway": mac == gw_mac,
                "is_self": mac == my_mac,
            }
            state.devices[mac] = dev
            event = "connected"
        else:
            if ip and dev.get("ip") != ip:
                dev["ip"] = ip                        # DHCP moved it
            if hostname and not dev.get("hostname"):
                dev["hostname"] = hostname
            dev["last_seen"]   = now_s
            dev["last_packet"] = now_m
            dev["miss"]        = 0
            if dev.get("status") == "offline":       # ── RECONNECTED ──
                dev["status"] = "online"
                dev["session_start"] = now_s
                dev["session_start_mono"] = now_m
                event = "reconnected"

        snap = device_snapshot(mac, dev)
        dev_copy = dict(dev)

    if event:
        _persist(mac, dev_copy)
        _log_event(event, mac, snap["ip"], snap["hostname"], snap["vendor"])
        _emit("device_update", snap)
        print(f"[+] Device {event.upper()}: {snap['ip']} ({mac}) "
              f"{snap['vendor']}")
        if not snap["hostname"]:
            threading.Thread(target=_resolve_hostname_bg,
                             args=(mac, snap["ip"]), daemon=True).start()


def set_hostname_by_mac(mac: str, hostname: str):
    """
    mDNS self-announced name (e.g. Johns-iPhone.local). On a LAN this is
    far better than reverse DNS — phones and IoT devices rarely have PTR
    records — so it overrides any earlier resolved name. Keyed by the
    announcing frame's source MAC: names must never be attached by IP,
    because a multi-homed host announces ALL of its addresses (VPN and
    VMware adapters included) and would mislabel whichever device
    happens to hold one of those IPs.
    """
    hostname = (hostname or "").rstrip(".")
    if hostname.lower().endswith(".local"):
        hostname = hostname[:-len(".local")]
    hostname = hostname.strip()[:64]
    # service-enumeration names (_airplay._tcp…) are not device names
    if not mac or not hostname or hostname.startswith("_") or "._" in hostname:
        return
    with state.lock:
        dev = state.devices.get(mac)
        if not dev or dev.get("hostname") == hostname:
            return
        dev["hostname"] = hostname
        snap = device_snapshot(mac, dev)
        dev_copy = dict(dev)
    _persist(mac, dev_copy)
    _emit("device_update", snap)


def mark_offline(mac: str):
    """Called by the liveness prober after confirmed missed probes."""
    now_s = _now_str()
    with state.lock:
        dev = state.devices.get(mac)
        if not dev or dev.get("status") == "offline":
            return
        # accumulate session duration
        if dev.get("session_start_mono"):
            dev["total_online_secs"] = (dev.get("total_online_secs", 0)
                + int(state.mono() - dev["session_start_mono"]))
        dev["status"] = "offline"
        dev["session_start"] = ""
        dev["session_start_mono"] = None
        dev["miss"] = 0
        snap = device_snapshot(mac, dev)
        dev_copy = dict(dev)

    _persist(mac, dev_copy)
    _log_event("disconnected", mac, snap["ip"], snap["hostname"],
               snap["vendor"])
    _emit("device_update", snap)
    print(f"[-] Device DISCONNECTED: {snap['ip']} ({mac}) {snap['vendor']}")


def _resolve_hostname_bg(mac: str, ip: str):
    """Reverse-DNS with hard timeout, off the hot path."""
    if not ip:
        return
    name = ""
    try:
        socket.setdefaulttimeout(Config.HOSTNAME_RESOLVE_TIMEOUT)
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        name = ""
    finally:
        socket.setdefaulttimeout(None)
    if name:
        with state.lock:
            dev = state.devices.get(mac)
            if dev:
                dev["hostname"] = name
                snap = device_snapshot(mac, dev)
                dev_copy = dict(dev)
            else:
                return
        _persist(mac, dev_copy)
        _emit("device_update", snap)


def counts() -> dict:
    with state.lock:
        devs = list(state.devices.values())
    online  = sum(1 for d in devs if d.get("status") == "online")
    return {"total": len(devs), "online": online,
            "offline": len(devs) - online}


def clear_devices(scope: str = "offline") -> int:
    """
    Remove devices from the registry and DB. scope:
      • "offline" — only devices currently offline (clears stale entries
        left over from a previous network without touching live ones).
      • "all"     — every device; the ones still on the network simply
        re-appear on their next packet / ARP sweep.
    Connection history (connection_log) is preserved either way.
    Returns the number of devices removed.
    """
    scope = "all" if scope == "all" else "offline"
    with state.lock:
        if scope == "all":
            macs = list(state.devices.keys())
        else:
            macs = [m for m, d in state.devices.items()
                    if d.get("status") != "online"]
        for m in macs:
            state.devices.pop(m, None)

    for m in macs:
        db.execute("DELETE FROM devices WHERE mac=?", (m,))
    _emit("devices_snapshot", all_snapshots())
    print(f"[*] Cleared {len(macs)} {scope} device(s) from the registry.")
    return len(macs)
