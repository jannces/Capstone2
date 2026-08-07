"""
guardian/monitor.py
Network Monitoring Engine — orchestrates all background threads:
  • initial + periodic ARP sweep (device discovery)
  • Scapy sniffer (passive capture)
  • liveness prober (fast disconnect detection)
  • gateway monitor (MITM watchdog)
"""
import time
import ipaddress
import threading
import subprocess

from . import state, devices, liveness, sniffer, detection, db
from .config import Config
from .netdiscovery import discover, mac_normalize, run_ps


def _arp_sweep_scapy():
    """One full-subnet ARP scan — discovers every device in ~2 s."""
    try:
        from scapy.all import srp, Ether, ARP
        with state.lock:
            subnet = state.net["subnet"]
            iface  = state.net.get("scapy_iface")
        if not subnet:
            return 0
        ans, _un = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            timeout=2, retry=1, verbose=0, iface=iface or None)
        n = 0
        for _s, r in ans:
            devices.register_sighting(r.psrc, r.hwsrc.lower())
            # learns unknown IPs into the truth table; on a mismatch with
            # the recorded owner it confirms + alerts (unicast-poisoning
            # and IP-takeover attacks that passive sniffing never sees)
            detection.inspect_sweep_reply(r.psrc, r.hwsrc.lower())
            n += 1
        return n
    except Exception as e:
        print(f"[!] ARP sweep failed: {e}")
        return 0


def _sweep_fallback_ping():
    """No-Scapy fallback: ping sweep then parse arp -a."""
    from concurrent.futures import ThreadPoolExecutor
    with state.lock:
        subnet, local_ip = state.net["subnet"], state.net["local_ip"]
    if not subnet:
        return
    try:
        hosts = [str(h) for h in ipaddress.ip_network(subnet).hosts()]
    except Exception:
        return
    if len(hosts) > 1024:
        return

    def ping(ip):
        try:
            subprocess.run(["ping", "-n", "1", "-w", "300", ip],
                           capture_output=True, timeout=2,
                           creationflags=getattr(subprocess,
                                                 "CREATE_NO_WINDOW", 0))
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=64) as pool:
        list(pool.map(ping, hosts))

    out = run_ps("Get-NetNeighbor -AddressFamily IPv4 -State Reachable,Stale "
                 "| ForEach-Object { \"$($_.IPAddress)|$($_.LinkLayerAddress)\" }")
    for line in (out or "").splitlines():
        if "|" in line:
            ip, mac = line.split("|", 1)
            mac = mac_normalize(mac)
            if mac and ip.strip() and not ip.startswith(("224.", "239.", "255.")):
                devices.register_sighting(ip.strip(), mac)


def run_sweeper():
    """Startup discovery + periodic re-scan to catch quiet devices."""
    time.sleep(2)
    while True:
        with state.lock:
            active   = state.net["scan_active"]
            scapy_ok = state.net["scapy_ok"]
        if active:
            n = _arp_sweep_scapy() if scapy_ok else 0
            if not scapy_ok:
                _sweep_fallback_ping()
            if n:
                print(f"[*] ARP sweep: {n} devices answered.")
        time.sleep(Config.ARP_SWEEP_INTERVAL_SECS)


def run_gateway_monitor():
    """Watchdog: if discovery lost the gateway MAC, keep retrying."""
    time.sleep(10)
    while True:
        with state.lock:
            gw_ip, gw_mac = state.net["gateway_ip"], state.net["gateway_mac"]
        if gw_ip and not gw_mac:
            discover()
        time.sleep(30)


def run_retention():
    """Periodic DB retention purge (tables must not grow unbounded)."""
    time.sleep(60)
    while True:
        try:
            db.purge_old()
        except Exception as e:
            print(f"[!] Retention purge failed: {e}")
        time.sleep(Config.RETENTION_SWEEP_SECS)


def start_all():
    """Start every background engine (daemon threads)."""
    discover()
    devices.load_from_db()
    detection.load_dhcp_trust()
    for target, name in (
        (sniffer.run_sniffer,     "sniffer"),
        (liveness.run_prober,     "liveness-prober"),
        (run_sweeper,             "arp-sweeper"),
        (run_gateway_monitor,     "gateway-monitor"),
        (run_retention,           "db-retention"),
    ):
        threading.Thread(target=target, name=name, daemon=True).start()
    print("[*] All monitoring engines started.")
