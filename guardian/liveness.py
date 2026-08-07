"""
guardian/liveness.py
FAST disconnect detection — the fix for the ~2 minute lag.

Old approach (v2): every 15 s, spawn PowerShell per device
(Remove-NetNeighbor → sleep 3 → Get-NetNeighbor) + 3-ping fallback,
require 2 misses  →  50–120 s to notice a disconnect.

New approach:
  1. PASSIVE (free, instant): every sniffed packet stamps
     dev["last_packet"]. A device with traffic in the last
     PASSIVE_ALIVE_SECS is alive — never probed.
  2. ACTIVE (cheap, in-process): quiet online devices get a *unicast*
     ARP request straight from Scapy every PROBE_INTERVAL_SECS (3 s),
     1 s timeout + 1 retry, all devices probed IN PARALLEL in a single
     srp() call — no subprocesses at all.
  3. OFFLINE_MISS_THRESHOLD (2) consecutive missed cycles → offline.

Detection latency ≈ 6–10 seconds. Phones answer unicast ARP even while
the screen is off, as long as they are still associated with the AP —
so the misses only start once the device has genuinely left.

Reconnect is detected instantly and passively: the first packet the
device sends (DHCP request, ARP, mDNS) flips it back online via
register_sighting().
"""
import time
import subprocess

from . import state, devices
from .config import Config
from .netdiscovery import ip_in_subnet


def _int_setting(key: str, default: int) -> int:
    from . import db
    try:
        return max(1, int(db.get_setting(key, str(default))))
    except Exception:
        return default


def _probe_batch_scapy(targets: list) -> set:
    """
    One parallel unicast-ARP round for many devices.
    targets: [(mac, ip)] → returns set of MACs that answered.
    """
    try:
        from scapy.all import srp, Ether, ARP
        pkts = [Ether(dst=mac) / ARP(pdst=ip, hwdst=mac)
                for mac, ip in targets]
        ans, _un = srp(pkts,
                       timeout=Config.PROBE_TIMEOUT_SECS,
                       retry=Config.PROBE_RETRY,
                       verbose=0,
                       iface=state.net.get("scapy_iface") or None)
        alive = set()
        for _sent, recv in ans:
            alive.add(recv.hwsrc.lower())
        return alive
    except Exception as e:
        print(f"[!] Scapy probe failed ({e}) — falling back to ping.")
        return _probe_batch_ping(targets)


def _probe_batch_ping(targets: list) -> set:
    """Fallback when Scapy is unavailable: fast parallel single pings."""
    from concurrent.futures import ThreadPoolExecutor

    def one(item):
        mac, ip = item
        try:
            r = subprocess.run(
                ["ping", "-n", "1", "-w", "700", ip],
                capture_output=True, timeout=3,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            ok = b"TTL=" in r.stdout or b"ttl=" in r.stdout
            return mac if ok else None
        except Exception:
            return None

    alive = set()
    if targets:
        with ThreadPoolExecutor(max_workers=min(32, len(targets))) as pool:
            for res in pool.map(one, targets):
                if res:
                    alive.add(res)
    return alive


def run_prober():
    """Background thread: fast disconnect + reconnect detection."""
    print(f"[*] Liveness prober: unicast-ARP every "
          f"{Config.PROBE_INTERVAL_SECS}s, "
          f"{Config.OFFLINE_MISS_THRESHOLD} misses → offline "
          f"(≈{Config.PROBE_INTERVAL_SECS * Config.OFFLINE_MISS_THRESHOLD}"
          f"–{Config.PROBE_INTERVAL_SECS * (Config.OFFLINE_MISS_THRESHOLD + 1)}s "
          f"detection).")
    last_offline_check = 0.0

    while True:
        with state.lock:
            active = state.net["scan_active"]
        if not active:
            time.sleep(1)
            continue

        interval  = _int_setting("probe_interval",
                                 Config.PROBE_INTERVAL_SECS)
        threshold = _int_setting("offline_miss_threshold",
                                 Config.OFFLINE_MISS_THRESHOLD)
        now = state.mono()

        with state.lock:
            subnet   = state.net["subnet"]
            local_ip = state.net["local_ip"]
            scapy_ok = state.net["scapy_ok"]
            online_quiet, offline = [], []
            for mac, dev in state.devices.items():
                ip = dev.get("ip", "")
                if not ip or ip == local_ip:
                    continue
                if subnet and not ip_in_subnet(ip, subnet):
                    continue
                if dev.get("status") == "offline":
                    offline.append((mac, ip))
                    continue
                # grace for brand-new devices
                if now - dev.get("last_packet", 0) < Config.PASSIVE_ALIVE_SECS:
                    dev["miss"] = 0          # passively alive — free
                    continue
                first = dev.get("session_start_mono") or 0
                if first and now - first < Config.NEW_DEVICE_GRACE_SECS:
                    continue
                online_quiet.append((mac, ip))

        # ── Probe quiet online devices (single parallel round) ──────────
        if online_quiet:
            probe = _probe_batch_scapy if scapy_ok else _probe_batch_ping
            alive = probe(online_quiet)
            to_offline = []
            with state.lock:
                for mac, _ip in online_quiet:
                    dev = state.devices.get(mac)
                    if not dev:
                        continue
                    if mac in alive:
                        dev["miss"] = 0
                        dev["last_packet"] = state.mono()
                        dev["last_seen"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        dev["miss"] = dev.get("miss", 0) + 1
                        if dev["miss"] >= threshold:
                            to_offline.append(mac)
            for mac in to_offline:
                devices.mark_offline(mac)

        # ── Re-check offline devices (reconnect fallback path) ───────────
        if offline and now - last_offline_check > Config.OFFLINE_RECHECK_SECS:
            last_offline_check = now
            probe = _probe_batch_scapy if scapy_ok else _probe_batch_ping
            back = probe(offline)
            for mac, ip in offline:
                if mac in back:
                    devices.register_sighting(ip, mac)

        time.sleep(interval)
