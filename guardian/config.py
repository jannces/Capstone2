"""
guardian/config.py
Central configuration for WiFi Admin Guardian.
All tunables live here — no magic numbers scattered through the code.
"""
import os
import secrets

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR    = os.path.join(BASE_DIR, "data")
REPORT_DIR  = os.path.join(BASE_DIR, "reports")
DB_PATH     = os.path.join(DATA_DIR, "guardian.db")
SECRET_FILE = os.path.join(DATA_DIR, ".secret_key")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)


def _load_secret_key() -> str:
    """Persistent secret key so sessions survive restarts."""
    try:
        if os.path.exists(SECRET_FILE):
            with open(SECRET_FILE, "r") as f:
                key = f.read().strip()
                if len(key) >= 32:
                    return key
        key = secrets.token_hex(32)
        with open(SECRET_FILE, "w") as f:
            f.write(key)
        return key
    except Exception:
        return secrets.token_hex(32)


class Config:
    # ── Flask ────────────────────────────────────────────────────────────
    SECRET_KEY   = _load_secret_key()
    # Reachable from the whole WiFi, like an IoT device: anyone on the
    # network can open http://<this-machine's-ip>:5000 and see the
    # read-only Network Status page (no login) — so every user can check
    # whether the network is safe. Admin functions stay behind the login.
    # Set GUARDIAN_HOST=127.0.0.1 to restrict everything to this machine.
    HOST         = os.environ.get("GUARDIAN_HOST", "0.0.0.0")
    PORT         = 5000
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME_MIN = 60          # auto-logout after inactivity

    # ── Auth ─────────────────────────────────────────────────────────────
    DEFAULT_ADMIN_USER = "admin"
    DEFAULT_ADMIN_PASS = "admin1234"              # user is warned to change it
    LOGIN_MAX_ATTEMPTS = 5                       # per window, per IP
    LOGIN_WINDOW_SECS  = 300
    LOGIN_LOCKOUT_SECS = 120

    # ── Liveness / disconnect detection (THE FAST PATH) ─────────────────
    # A device is "passively alive" if the sniffer saw ANY packet from it
    # within PASSIVE_ALIVE_SECS — those devices are never probed (zero cost).
    PASSIVE_ALIVE_SECS   = 6
    # Quiet online devices get a unicast ARP probe every PROBE_INTERVAL_SECS.
    PROBE_INTERVAL_SECS  = 3
    # Each probe sends ARP with this timeout and one retry inside scapy.
    PROBE_TIMEOUT_SECS   = 1.0
    PROBE_RETRY          = 1
    # Consecutive missed probe cycles before marking OFFLINE.
    # 2 misses ≈ 6–10 s total detection latency; raise to 3 on lossy Wi-Fi.
    OFFLINE_MISS_THRESHOLD = 2
    # Newly discovered devices get a short grace period before probing.
    NEW_DEVICE_GRACE_SECS  = 10
    # Offline devices are re-checked for reconnection at this interval
    # (reconnect is usually detected passively/instantly via the sniffer).
    OFFLINE_RECHECK_SECS   = 10

    # ── Discovery ────────────────────────────────────────────────────────
    ARP_SWEEP_INTERVAL_SECS = 60     # full-subnet ARP scan for new devices
    HOSTNAME_RESOLVE_TIMEOUT = 2

    # ── Threat detection thresholds (tuned to minimize FP/FN) ───────────
    # Port scan: distinct destination ports from one source within window.
    PORTSCAN_WINDOW_SECS   = 10
    PORTSCAN_PORT_THRESHOLD = 12     # distinct ports  → vertical scan
    PORTSCAN_HOST_THRESHOLD = 8      # distinct hosts  → horizontal scan
    # Only SYNs aimed at the local subnet count toward scan thresholds.
    # Outbound web browsing fans out SYNs to many public CDN hosts on
    # 443/80 within seconds — counting those flagged normal browsing as a
    # horizontal scan. A LAN attacker probing LAN hosts is what we defend.
    # Sources listed here are never flagged (in addition to self/gateway):
    PORTSCAN_ALLOWLIST_IPS = set()   # e.g. {"192.168.1.10"}
    # Low-and-slow tier: a scanner probing one port every few seconds
    # slides under the 10 s window, so keep a longer cumulative window
    # with its own thresholds.
    PORTSCAN_SLOW_WINDOW_SECS   = 600
    PORTSCAN_SLOW_PORT_THRESHOLD = 30    # distinct ports  / 10 min
    PORTSCAN_SLOW_HOST_THRESHOLD = 20    # distinct hosts  / 10 min
    # Stealth scans (FIN-only / NULL / Xmas TCP flags): no legitimate
    # traffic looks like this, so a handful of probes is enough to alert.
    PORTSCAN_STEALTH_WINDOW_SECS = 60
    PORTSCAN_STEALTH_THRESHOLD   = 3     # distinct targets / 60 s
    # UDP scans: distinct in-subnet UDP ports probed within the window.
    PORTSCAN_UDP_WINDOW_SECS   = 30
    PORTSCAN_UDP_THRESHOLD     = 15      # distinct (host,port) targets
    # UDP ports that chatty-but-legitimate LAN protocols use — never
    # counted as scan probes (DNS, DHCP, NTP, NetBIOS, SSDP, mDNS, LLMNR,
    # WS-Discovery, QUIC).
    UDP_IGNORE_PORTS = {53, 67, 68, 123, 137, 138, 139, 443,
                        1900, 3702, 5353, 5355}
    # ARP poisoning active confirmation: re-probe the contested IP and only
    # alert if conflicting replies are actually observed.
    ARP_CONFIRM_TIMEOUT    = 1.5
    ARP_CONFIRM_PROBES     = 2
    # Same threat (type + source) is not re-raised within this window.
    THREAT_DEDUP_SECS      = 120
    # Gateway MAC change requires this many consecutive confirmations
    # (protects against a single spoofed packet AND against DHCP renews).
    GATEWAY_CONFIRM_PROBES = 3

    # ── Rogue DHCP detection ─────────────────────────────────────────────
    # DHCP OFFER/ACK from a server that is neither the gateway, nor in
    # this list, nor the learned (trust-on-first-use) server → alert.
    DHCP_TRUSTED_SERVERS = set()     # e.g. {"192.168.1.1"}

    # ── Database retention (tables must not grow unbounded) ─────────────
    RETENTION_SWEEP_SECS     = 3600  # purge job interval
    RETENTION_CONNLOG_DAYS   = 7     # connection_log rows kept
    RETENTION_THREAT_DAYS    = 30    # threats rows kept
    RETENTION_ADMINLOG_DAYS  = 30    # admin_log rows kept

    # Virtual adapter OUIs that must never be flagged as spoofing
    # (VMware, VirtualBox, Hyper-V, Parallels, Docker, common randomized bits)
    VIRTUAL_OUI_WHITELIST = {
        "00:50:56", "00:0c:29", "00:05:69", "00:1c:14",   # VMware
        "08:00:27", "0a:00:27",                            # VirtualBox
        "00:15:5d",                                        # Hyper-V
        "00:1c:42",                                        # Parallels
        "02:42",                                           # Docker (prefix)
    }

    # ── Alerts ───────────────────────────────────────────────────────────
    ALARM_ENABLED_DEFAULT = True

    # ── Reports ──────────────────────────────────────────────────────────
    REPORT_DIR = REPORT_DIR
