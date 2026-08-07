"""
guardian/state.py
Thread-safe in-memory runtime state.
SQLite is the source of truth for history; this holds the live view
so the hot paths (sniffer, prober) never touch disk.
"""
import time
import threading
from collections import defaultdict, deque

lock = threading.Lock()

net = {
    "interface":    "",
    "iface_desc":   "",
    "local_ip":     "",
    "local_mac":    "",
    "local_macs":   set(),      # every adapter on this machine (incl. virtual)
    "gateway_ip":   "",
    "gateway_mac":  "",
    "subnet":       "",
    "scan_active":  True,
    "scapy_ok":     False,
    "scapy_error":  "",
    "started_at":   time.time(),
}

# mac -> {"ip", "hostname", "vendor", "status", "first_seen", "last_seen",
#         "session_start", "last_packet": monotonic float, "miss": int}
devices = {}

stats = {
    "packets_analyzed": 0,
    "arp_packets": 0,
    "tcp_packets": 0,
    "dhcp_packets": 0,
    "mdns_packets": 0,
}

# ── Detection engine trackers ─────────────────────────────────────────────
# ip -> set of MACs recently claiming it (ARP poisoning)
arp_claims = defaultdict(dict)          # ip -> {mac: last_seen_monotonic}
# ground-truth ip->mac learned at discovery time
arp_truth  = {}
# port-scan sliding windows (in-subnet targets only):
#   syn_window     src_ip -> deque[(monotonic, dst_ip, dst_port)]
#                  pruned at the SLOW window; the fast tier reads the tail.
#   stealth_window src_ip -> deque[(monotonic, dst_ip, dst_port, kind)]
#   udp_window     src_ip -> deque[(monotonic, dst_ip, dst_port)]
syn_window     = defaultdict(deque)
stealth_window = defaultdict(deque)
udp_window     = defaultdict(deque)
# rogue-DHCP trust anchor (learned on first use or from settings)
dhcp_trust = {"ip": "", "mac": ""}
# threat dedup: (type, key) -> last emitted monotonic
threat_last = {}
# gateway mac-change confirmation counter
gateway_suspect = {"mac": "", "count": 0}


def mono() -> float:
    return time.monotonic()


def socketio_ref():
    """Late import to avoid circulars."""
    from . import socketio
    return socketio
