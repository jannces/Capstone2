"""
guardian/detection.py
Threat Detection Engine — the manuscript attacks:
  1. Man-in-the-Middle (gateway MAC change / gateway impersonation,
                        rogue DHCP server)
  2. ARP Poisoning     (one IP claimed by multiple MACs)
  3. MAC Spoofing      (duplicate MAC / IP-MAC conflict / ARP header mismatch)
  4. Port Scanning     (SYN fan-out, stealth FIN/NULL/Xmas flags, UDP
                        probes, and a low-and-slow cumulative tier)

False-positive controls baked in:
  • Active confirmation: contested ARP claims are re-probed before alerting.
  • Gateway change needs N consecutive confirmations (DHCP renews are noisy).
  • Virtual adapter OUIs (VMware/VBox/Hyper-V/Docker) are whitelisted.
  • DHCP ACK reassignments update the truth table instead of alerting.
  • Randomized/private MACs don't trigger spoofing on IP churn alone.
  • SYN-only counting for port scans (established flows never counted).
  • Scan counting is scoped to the local subnet — outbound browsing SYNs
    to public CDN hosts (many hosts on 443 in seconds) never count.
  • Per-(type, source) dedup window so one attack = one threat record.
"""
import json
import uuid
import datetime
import threading
import ipaddress
from collections import deque

from . import state, db
from .config import Config
from .netdiscovery import is_virtual_mac

SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

MITIGATIONS = {
    "MITM": ("Verify the real gateway MAC on the router itself; "
             "disconnect the suspicious device from the access point; "
             "flush the ARP cache (arp -d *)."),
    "ARP Poisoning": ("Flush the ARP cache (arp -d *); block/disconnect the "
                      "suspicious device at the access point; notify all "
                      "network users to avoid sensitive logins."),
    "MAC Spoofing": ("Disconnect the unauthorized device from the access "
                     "point; enable MAC filtering or 802.1X if available; "
                     "notify the administrator."),
    "Port Scanning": ("Restrict/block the suspicious source IP at the "
                      "firewall or access point; review which services are "
                      "exposed on scanned hosts."),
    "Rogue DHCP": ("Disconnect the rogue DHCP server from the network "
                   "immediately; renew leases on affected clients "
                   "(ipconfig /release + /renew); enable DHCP snooping "
                   "on the switch/AP if available."),
}


def _emit(event, payload):
    try:
        state.socketio_ref().emit(event, payload)
    except Exception:
        pass


def _now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _dedup_ok(threat_type: str, key: str) -> bool:
    """True if this (type, key) hasn't fired inside the dedup window."""
    k = (threat_type, key)
    now = state.mono()
    with state.lock:
        last = state.threat_last.get(k, 0)
        if now - last < Config.THREAT_DEDUP_SECS:
            return False
        state.threat_last[k] = now
    return True


def raise_threat(threat_type: str, severity: str, src_ip: str, src_mac: str,
                 description: str, rule: str, evidence: dict,
                 dst_ip: str = "", detect_latency_ms: int = 0):
    """Persist + broadcast a threat. Assumes dedup was already checked."""
    tid = uuid.uuid4().hex[:12]
    row = {
        "id": tid, "ts": _now_str(), "threat_type": threat_type,
        "severity": severity, "src_ip": src_ip, "src_mac": src_mac,
        "dst_ip": dst_ip, "description": description,
        "detection_rule": rule, "evidence": json.dumps(evidence),
        "mitigation": MITIGATIONS.get(threat_type, ""),
        "status": "New", "detect_latency_ms": detect_latency_ms,
    }
    db.execute(
        """INSERT INTO threats
             (id, ts, threat_type, severity, src_ip, src_mac, dst_ip,
              description, detection_rule, evidence, mitigation, status,
              detect_latency_ms)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (row["id"], row["ts"], row["threat_type"], row["severity"],
         row["src_ip"], row["src_mac"], row["dst_ip"], row["description"],
         row["detection_rule"], row["evidence"], row["mitigation"],
         row["status"], row["detect_latency_ms"]))
    _emit("new_threat", row)
    print(f"[!] THREAT [{severity}] {threat_type}: {description}")


# ─────────────────────────────────────────────────────────────────────────
#  1 + 2 — ARP-based attacks (called from the sniffer on every ARP packet)
# ─────────────────────────────────────────────────────────────────────────
def _confirm_arp_conflict(ip: str) -> list:
    """
    Active confirmation: broadcast 'who-has ip' and collect every reply.
    Returns the list of distinct MACs that answered. Two or more distinct
    MACs answering for the same IP = confirmed poisoning, not packet noise.
    """
    try:
        from scapy.all import srp, Ether, ARP as SARP
        macs = set()
        for _ in range(Config.ARP_CONFIRM_PROBES):
            ans, _un = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / SARP(pdst=ip),
                timeout=Config.ARP_CONFIRM_TIMEOUT, verbose=0,
                iface=state.net.get("scapy_iface") or None, multi=True)
            for _s, r in ans:
                macs.add(r.hwsrc.lower())
        return sorted(macs)
    except Exception:
        return []


def _handle_gateway_claim(claim_mac: str, gw_ip: str, gw_mac: str):
    """A non-gateway MAC claimed the gateway IP → possible MITM.
    Needs GATEWAY_CONFIRM_PROBES consecutive sightings of the SAME
    rogue MAC before alerting (kills one-packet false positives)."""
    with state.lock:
        local_macs = state.net.get("local_macs") or set()
    if claim_mac in local_macs or is_virtual_mac(claim_mac):
        # The monitor's own virtual adapters (VMware VMnet, VirtualBox,
        # Hyper-V) run private NAT subnets that often reuse the real
        # router's IP (e.g. 192.168.1.1) — their ARP replies are not an
        # attack. Trade-off: an attacker deliberately spoofing a
        # virtual-adapter OUI evades this rule (documented limitation);
        # the ARP-poisoning and spoofing detectors apply the same rule.
        return
    with state.lock:
        gs = state.gateway_suspect
        if gs["mac"] == claim_mac:
            gs["count"] += 1
        else:
            gs["mac"], gs["count"] = claim_mac, 1
        confirmed = gs["count"] >= Config.GATEWAY_CONFIRM_PROBES

    if not confirmed:
        return
    if not _dedup_ok("MITM", claim_mac):
        return

    t0 = state.mono()
    replies = _confirm_arp_conflict(gw_ip)
    latency = int((state.mono() - t0) * 1000)

    # If only the legitimate gateway answers now, the rogue claim vanished
    # (transient) — count it but don't alarm unless it answered too.
    if replies and claim_mac not in replies and gw_mac in replies:
        with state.lock:
            state.gateway_suspect.update({"mac": "", "count": 0})
        return

    raise_threat(
        "MITM", "Critical", gw_ip, claim_mac,
        f"Gateway impersonation: {claim_mac} is claiming gateway "
        f"{gw_ip} (legitimate MAC {gw_mac}).",
        "gateway-mac-change: ARP replies for gateway IP from foreign MAC, "
        f"confirmed x{Config.GATEWAY_CONFIRM_PROBES} + active re-probe",
        {"gateway_ip": gw_ip, "legit_mac": gw_mac,
         "rogue_mac": claim_mac, "probe_replies": replies},
        detect_latency_ms=latency)
    with state.lock:
        state.gateway_suspect.update({"mac": "", "count": 0})


def inspect_arp(src_ip: str, src_mac: str, ether_src: str, op: int):
    """
    Called by the sniffer for every ARP packet.
    src_ip/src_mac come from the ARP payload, ether_src from the frame.
    """
    if not src_ip or src_ip == "0.0.0.0" or not src_mac:
        return
    now = state.mono()

    with state.lock:
        gw_ip, gw_mac = state.net["gateway_ip"], state.net["gateway_mac"]
        claims = state.arp_claims[src_ip]
        claims[src_mac] = now
        # prune stale claims (older than dedup window)
        for m in [m for m, t in claims.items()
                  if now - t > Config.THREAT_DEDUP_SECS]:
            del claims[m]
        distinct = sorted(claims.keys())
        truth = state.arp_truth.get(src_ip, "")

    # ── MAC spoofing signature: ARP payload MAC ≠ Ethernet source MAC ──
    # This is the classic spoof fingerprint and has near-zero FP rate.
    if (ether_src and ether_src != src_mac
            and ether_src != "ff:ff:ff:ff:ff:ff"
            and not is_virtual_mac(ether_src)
            and not is_virtual_mac(src_mac)):
        if _dedup_ok("MAC Spoofing", f"{ether_src}|{src_mac}"):
            raise_threat(
                "MAC Spoofing", "Medium", src_ip, ether_src,
                f"ARP header mismatch: frame from {ether_src} carries ARP "
                f"payload claiming MAC {src_mac} for {src_ip}.",
                "arp-header-mismatch: Ether.src != ARP.hwsrc",
                {"ether_src": ether_src, "arp_hwsrc": src_mac,
                 "claimed_ip": src_ip, "arp_op": op})

    # ── Gateway impersonation (MITM) ────────────────────────────────────
    if gw_ip and src_ip == gw_ip and gw_mac and src_mac != gw_mac:
        threading.Thread(target=_handle_gateway_claim,
                         args=(src_mac, gw_ip, gw_mac), daemon=True).start()
        return

    # ── ARP poisoning: same IP claimed by ≥2 MACs recently ─────────────
    if len(distinct) >= 2:
        # ignore pure virtual-adapter noise
        real = [m for m in distinct if not is_virtual_mac(m)]
        if len(real) >= 2 and _dedup_ok("ARP Poisoning", src_ip):
            threading.Thread(target=_confirm_and_raise_poison,
                             args=(src_ip, real, truth), daemon=True).start()


def _confirm_and_raise_poison(ip: str, passive_macs: list, truth: str):
    t0 = state.mono()
    replies = _confirm_arp_conflict(ip)
    latency = int((state.mono() - t0) * 1000)

    if len(replies) >= 2:
        confirmed = True
        evidence_macs = replies
    else:
        # active probe couldn't reproduce it — likely a DHCP handover.
        # Update truth table quietly instead of alerting (FP control),
        # unless the passive claim contradicted a *known* truth mapping.
        confirmed = bool(truth and truth not in (replies or passive_macs))
        evidence_macs = passive_macs
        if not confirmed:
            with state.lock:
                if replies:
                    state.arp_truth[ip] = replies[0]
                state.arp_claims[ip] = {m: state.mono() for m in (replies or [])}
            return

    rogue = next((m for m in evidence_macs if m != truth), evidence_macs[0])
    raise_threat(
        "ARP Poisoning", "Critical", ip, rogue,
        f"IP {ip} is being claimed by multiple MAC addresses: "
        f"{', '.join(evidence_macs)}.",
        "ip-multi-mac: passive multi-claim + active broadcast re-probe",
        {"contested_ip": ip, "claiming_macs": evidence_macs,
         "known_truth_mac": truth, "actively_confirmed": confirmed},
        detect_latency_ms=latency)


# ─────────────────────────────────────────────────────────────────────────
#  Sweep-time truth check — catches unicast-only poisoning / IP takeover
# ─────────────────────────────────────────────────────────────────────────
def inspect_sweep_reply(ip: str, mac: str):
    """
    Called by the discovery sweep for every ARP reply it collects.
    Passive sniffing never sees an attacker who poisons only the victim's
    cache with unicast replies — but the sweep already asks every IP
    'who are you?' every ARP_SWEEP_INTERVAL_SECS. Comparing each answer
    against the learned truth table turns those existing packets into a
    detector: a reply contradicting the recorded owner is either
    poisoning / IP takeover (old owner still answers too → alert) or a
    legitimate reassignment (old owner gone → truth updated quietly).
    """
    mac = (mac or "").lower()
    if not ip or not mac or is_virtual_mac(mac):
        return
    with state.lock:
        truth = state.arp_truth.get(ip, "")
        gw_ip, gw_mac = state.net["gateway_ip"], state.net["gateway_mac"]
    if not truth:
        with state.lock:
            state.arp_truth.setdefault(ip, mac)
        return
    if mac == truth or is_virtual_mac(truth):
        return
    if ip == gw_ip and gw_mac:
        # gateway truth mismatch → existing MITM confirmation path
        threading.Thread(target=_handle_gateway_claim,
                         args=(mac, gw_ip, gw_mac), daemon=True).start()
        return
    # dedup BEFORE probing so one contested IP can't cause a probe storm
    if not _dedup_ok("ARP Poisoning", f"sweep|{ip}"):
        return
    threading.Thread(target=_confirm_sweep_mismatch,
                     args=(ip, mac, truth), daemon=True).start()


def _confirm_sweep_mismatch(ip: str, new_mac: str, truth: str):
    t0 = state.mono()
    replies = _confirm_arp_conflict(ip)
    latency = int((state.mono() - t0) * 1000)

    if truth in replies and new_mac in replies:
        # both the recorded owner AND the newcomer claim the IP → poisoning
        raise_threat(
            "ARP Poisoning", "Critical", ip, new_mac,
            f"Sweep detected {ip} answering from {new_mac}, but the "
            f"recorded owner {truth} also still answers — the IP is "
            f"being claimed by two devices.",
            "sweep-truth-mismatch: discovery-sweep reply contradicts the "
            "learned IP→MAC truth table + active re-probe confirmation",
            {"contested_ip": ip, "recorded_mac": truth,
             "conflicting_mac": new_mac, "probe_replies": replies},
            detect_latency_ms=latency)
        return

    if replies and truth not in replies:
        # old owner is gone — legitimate DHCP reassignment, update quietly
        with state.lock:
            state.arp_truth[ip] = replies[0]
            state.arp_claims[ip] = {replies[0]: state.mono()}
        print(f"[*] ARP truth updated: {ip} → {replies[0]} (was {truth}).")
    # no replies, or only the recorded owner answered → transient, keep truth


# ─────────────────────────────────────────────────────────────────────────
#  3 — MAC spoofing via duplicate-IP conflict (from device registry side)
# ─────────────────────────────────────────────────────────────────────────
def inspect_ip_conflict(ip: str, new_mac: str):
    """Two *currently online* devices holding the same IP simultaneously."""
    # Null / broadcast MACs are ARP-probe artifacts, never real identities.
    if new_mac in ("", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return
    with state.lock:
        holders = [m for m, d in state.devices.items()
                   if d.get("ip") == ip and d.get("status") == "online"
                   and m != new_mac
                   and state.mono() - d.get("last_packet", 0) < 30]
    holders = [m for m in holders if not is_virtual_mac(m)]
    if holders and not is_virtual_mac(new_mac):
        if _dedup_ok("MAC Spoofing", f"ipconf|{ip}"):
            raise_threat(
                "MAC Spoofing", "Medium", ip, new_mac,
                f"IP/MAC conflict: {ip} is simultaneously held by "
                f"{new_mac} and {', '.join(holders)}.",
                "ip-conflict: two active devices share one IP within 30 s",
                {"ip": ip, "macs": [new_mac] + holders})


# ─────────────────────────────────────────────────────────────────────────
#  4 — Port scanning (called from the sniffer for every TCP/UDP packet)
# ─────────────────────────────────────────────────────────────────────────
_FIN, _SYN, _RST, _PSH, _ACK, _URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


def _scan_src_excluded(src_ip: str) -> bool:
    """Sources that must never be treated as scanners."""
    with state.lock:
        local_ip = state.net["local_ip"]
        gw_ip    = state.net["gateway_ip"]
    return (src_ip in (local_ip, gw_ip)
            or src_ip in Config.PORTSCAN_ALLOWLIST_IPS)


def _is_lan_source(src_ip: str) -> bool:
    """
    Only sources inside the local subnet can be LAN scanners. Traffic the
    router relays in from the internet fans out to many LAN hosts on random
    ephemeral ports — e.g. DNS replies from 8.8.8.8 answer every client on
    a different port, which is indistinguishable from a scan by counting
    alone. An off-subnet source is not the LAN attacker this system
    defends against, so it is never counted.
    """
    try:
        s = ipaddress.ip_address(src_ip)
    except ValueError:
        return False
    with state.lock:
        subnet = state.net["subnet"]
    if subnet:
        try:
            return s in ipaddress.ip_network(subnet)
        except ValueError:
            pass
    # subnet unknown (discovery failed) — fall back to "private address"
    return s.is_private


def _is_scan_target(dst_ip: str) -> bool:
    """
    Only destinations inside the local subnet count as scan targets.
    This is THE key false-positive control: one web-page load fans out
    SYNs to 8+ public CDN hosts on port 443 within seconds, which is
    indistinguishable from a horizontal scan by counting alone — but a
    LAN attacker probing LAN hosts is the threat this system defends,
    and those destinations are always in-subnet.
    """
    try:
        d = ipaddress.ip_address(dst_ip)
    except ValueError:
        return False
    if d.is_multicast or d.is_loopback or d.is_unspecified:
        return False
    with state.lock:
        subnet = state.net["subnet"]
    if subnet:
        try:
            net = ipaddress.ip_network(subnet)
            return d in net and d != net.broadcast_address
        except ValueError:
            pass
    # subnet unknown (discovery failed) — fall back to "private address"
    return d.is_private


def _raise_scan(src_ip, src_mac, dst_ip, severity, description, rule,
                evidence, dedup_key=None):
    if not _dedup_ok("Port Scanning", dedup_key or src_ip):
        return
    raise_threat("Port Scanning", severity, src_ip, src_mac,
                 description, rule, evidence, dst_ip=dst_ip)


def inspect_tcp(src_ip: str, src_mac: str, dst_ip: str, dst_port: int,
                flags: int):
    """
    Classify every TCP packet aimed at the local subnet:
      • pure SYN (SYN set, ACK clear)      → connect/SYN scan counting,
        in a fast window AND a low-and-slow cumulative window
      • FIN-only / NULL / Xmas flag combos → stealth scan counting
        (no legitimate stack emits these, so the threshold is tiny)
    Established flows (ACK set) are never counted.
    """
    f = flags & 0x3F
    if f == 0:
        stealth = "NULL"
    elif f == _FIN:
        stealth = "FIN"
    elif f == _FIN | _PSH | _URG:
        stealth = "Xmas"
    else:
        stealth = ""
    pure_syn = bool(f & _SYN) and not (f & _ACK) and not stealth

    if not (pure_syn or stealth):
        return
    if (not _is_lan_source(src_ip) or _scan_src_excluded(src_ip)
            or not _is_scan_target(dst_ip)):
        return

    if stealth:
        _track_stealth(src_ip, src_mac, dst_ip, dst_port, stealth)
    else:
        _track_syn(src_ip, src_mac, dst_ip, dst_port)


def _track_syn(src_ip, src_mac, dst_ip, dst_port):
    now = state.mono()
    fast_win = Config.PORTSCAN_WINDOW_SECS
    slow_win = Config.PORTSCAN_SLOW_WINDOW_SECS
    with state.lock:
        events = state.syn_window[src_ip]
        events.append((now, dst_ip, dst_port))
        # prune to the SLOW window (the fast tier reads the recent tail)
        while events and now - events[0][0] > slow_win:
            events.popleft()
        fast = [(d, p) for t, d, p in events if now - t <= fast_win]
        fast_ports = len({p for _d, p in fast})
        fast_hosts = len({d for d, _p in fast})
        slow_ports = len({p for _t, _d, p in events})
        slow_hosts = len({d for _t, d, _p in events})
        sample = [f"{d}:{p}" for _t, d, p in list(events)[-10:]]

    # ── fast tier (classic nmap default speed) ──────────────────────────
    if (fast_ports >= Config.PORTSCAN_PORT_THRESHOLD
            or fast_hosts >= Config.PORTSCAN_HOST_THRESHOLD):
        kind = ("vertical (many ports)"
                if fast_ports >= Config.PORTSCAN_PORT_THRESHOLD
                else "horizontal (many hosts)")
        _raise_scan(
            src_ip, src_mac, dst_ip, "Medium",
            f"{src_ip} sent SYNs to {fast_ports} distinct port(s) "
            f"across {fast_hosts} LAN host(s) within {fast_win} s — "
            f"{kind} scan pattern.",
            f"syn-fanout: ≥{Config.PORTSCAN_PORT_THRESHOLD} ports or "
            f"≥{Config.PORTSCAN_HOST_THRESHOLD} hosts / {fast_win} s, "
            f"SYN-only, in-subnet targets only",
            {"distinct_ports": fast_ports, "distinct_hosts": fast_hosts,
             "window_secs": fast_win, "sample": sample})
        with state.lock:
            state.syn_window[src_ip].clear()
        return

    # ── low-and-slow tier (one probe every few seconds evades the fast
    #    window but accumulates here) ─────────────────────────────────────
    if (slow_ports >= Config.PORTSCAN_SLOW_PORT_THRESHOLD
            or slow_hosts >= Config.PORTSCAN_SLOW_HOST_THRESHOLD):
        _raise_scan(
            src_ip, src_mac, dst_ip, "Medium",
            f"{src_ip} probed {slow_ports} distinct port(s) across "
            f"{slow_hosts} LAN host(s) over {slow_win // 60} min — "
            f"low-and-slow scan pattern (rate-limited to evade fast "
            f"detection).",
            f"syn-slow-fanout: ≥{Config.PORTSCAN_SLOW_PORT_THRESHOLD} ports "
            f"or ≥{Config.PORTSCAN_SLOW_HOST_THRESHOLD} hosts / "
            f"{slow_win} s, SYN-only, in-subnet targets only",
            {"distinct_ports": slow_ports, "distinct_hosts": slow_hosts,
             "window_secs": slow_win, "sample": sample},
            dedup_key=f"slow|{src_ip}")
        with state.lock:
            state.syn_window[src_ip].clear()


def _track_stealth(src_ip, src_mac, dst_ip, dst_port, kind):
    now = state.mono()
    win = Config.PORTSCAN_STEALTH_WINDOW_SECS
    with state.lock:
        events = state.stealth_window[src_ip]
        events.append((now, dst_ip, dst_port, kind))
        while events and now - events[0][0] > win:
            events.popleft()
        targets = {(d, p) for _t, d, p, _k in events}
        kinds = sorted({k for _t, _d, _p, k in events})
        sample = [f"{d}:{p} [{k}]" for _t, d, p, k in list(events)[-10:]]

    if len(targets) < Config.PORTSCAN_STEALTH_THRESHOLD:
        return
    _raise_scan(
        src_ip, src_mac, dst_ip, "High",
        f"{src_ip} sent {'/'.join(kinds)} stealth-scan probes to "
        f"{len(targets)} LAN target(s) within {win} s — no legitimate "
        f"traffic uses these TCP flag combinations.",
        f"stealth-flags: ≥{Config.PORTSCAN_STEALTH_THRESHOLD} FIN/NULL/Xmas "
        f"probes / {win} s, in-subnet targets only",
        {"distinct_targets": len(targets), "flag_kinds": kinds,
         "window_secs": win, "sample": sample},
        dedup_key=f"stealth|{src_ip}")
    with state.lock:
        state.stealth_window[src_ip].clear()


def inspect_udp_probe(src_ip: str, src_mac: str, dst_ip: str, dst_port: int,
                      src_port: int = 0):
    """
    UDP scan detection: many distinct in-subnet (host, port) UDP targets
    from one source. Well-known chatty LAN protocols (DNS/DHCP/NTP/SSDP/
    mDNS/LLMNR/NetBIOS/QUIC) are excluded up front — on BOTH ends: a
    packet *from* one of those ports is a service's reply to a client on
    a random ephemeral port (e.g. a LAN DNS server answering queries),
    not a probe.
    """
    if dst_port in Config.UDP_IGNORE_PORTS or src_port in Config.UDP_IGNORE_PORTS:
        return
    if (not _is_lan_source(src_ip) or _scan_src_excluded(src_ip)
            or not _is_scan_target(dst_ip)):
        return

    now = state.mono()
    win = Config.PORTSCAN_UDP_WINDOW_SECS
    with state.lock:
        events = state.udp_window[src_ip]
        events.append((now, dst_ip, dst_port))
        while events and now - events[0][0] > win:
            events.popleft()
        targets = {(d, p) for _t, d, p in events}
        hosts = {d for _t, d, _p in events}
        sample = [f"{d}:{p}" for _t, d, p in list(events)[-10:]]

    if len(targets) < Config.PORTSCAN_UDP_THRESHOLD:
        return
    _raise_scan(
        src_ip, src_mac, dst_ip, "Medium",
        f"{src_ip} sent UDP probes to {len(targets)} port/host "
        f"combinations across {len(hosts)} LAN host(s) within {win} s — "
        f"UDP scan pattern.",
        f"udp-fanout: ≥{Config.PORTSCAN_UDP_THRESHOLD} targets / {win} s, "
        f"in-subnet, common LAN service ports excluded",
        {"distinct_targets": len(targets), "distinct_hosts": len(hosts),
         "window_secs": win, "sample": sample},
        dedup_key=f"udp|{src_ip}")
    with state.lock:
        state.udp_window[src_ip].clear()


# ─────────────────────────────────────────────────────────────────────────
#  DHCP awareness — reduces ARP-poisoning false positives
# ─────────────────────────────────────────────────────────────────────────
def note_dhcp_ack(ip: str, mac: str):
    """A DHCP server officially bound ip→mac: update truth, clear claims."""
    if not ip or not mac:
        return
    with state.lock:
        state.arp_truth[ip] = mac
        state.arp_claims[ip] = {mac: state.mono()}


# ─────────────────────────────────────────────────────────────────────────
#  Rogue DHCP server (MITM vector: attacker hands out itself as gateway/DNS)
# ─────────────────────────────────────────────────────────────────────────
def load_dhcp_trust():
    """Restore the learned trusted DHCP server from settings at startup."""
    ip = db.get_setting("dhcp_server_ip", "")
    mac = db.get_setting("dhcp_server_mac", "")
    with state.lock:
        state.dhcp_trust.update({"ip": ip, "mac": mac})
    if ip:
        print(f"[*] Trusted DHCP server loaded: {ip} ({mac or 'mac unknown'})")


def _learn_dhcp_server(server_ip: str, server_mac: str):
    with state.lock:
        state.dhcp_trust.update({"ip": server_ip, "mac": server_mac})
    db.set_setting("dhcp_server_ip", server_ip)
    db.set_setting("dhcp_server_mac", server_mac)
    print(f"[*] Learned trusted DHCP server: {server_ip} ({server_mac})")


def inspect_dhcp_server(server_ip: str, server_mac: str, msg_type: int):
    """
    Called for every DHCP OFFER (2) / ACK (5) seen on the wire.
    Trust model: the configured DHCP_TRUSTED_SERVERS list, the default
    gateway, and the first server observed (trust-on-first-use, persisted
    in settings). Any other server answering leases = rogue DHCP — the
    classic public-Wi-Fi MITM (attacker hands out itself as gateway/DNS).
    Also alerts if the trusted server's IP suddenly answers from a
    different MAC (DHCP server impersonation).
    """
    if not server_ip or server_ip == "0.0.0.0":
        return
    server_mac = (server_mac or "").lower()
    with state.lock:
        gw_ip = state.net["gateway_ip"]
        trust = dict(state.dhcp_trust)

    trusted_ips = set(Config.DHCP_TRUSTED_SERVERS)
    if gw_ip:
        trusted_ips.add(gw_ip)
    if trust["ip"]:
        trusted_ips.add(trust["ip"])

    kind = "OFFER" if msg_type == 2 else "ACK"

    if server_ip in trusted_ips:
        if not trust["ip"]:
            _learn_dhcp_server(server_ip, server_mac)
        elif (server_ip == trust["ip"] and trust["mac"] and server_mac
                and server_mac != trust["mac"]
                and not is_virtual_mac(server_mac)):
            # trusted IP answering from a new MAC → impersonation
            if _dedup_ok("Rogue DHCP", f"impersonation|{server_mac}"):
                raise_threat(
                    "Rogue DHCP", "High", server_ip, server_mac,
                    f"DHCP {kind} for trusted server IP {server_ip} came "
                    f"from MAC {server_mac}, but the known server MAC is "
                    f"{trust['mac']} — possible DHCP server impersonation.",
                    "dhcp-server-mac-change: trusted server IP answering "
                    "from a different MAC",
                    {"server_ip": server_ip, "expected_mac": trust["mac"],
                     "observed_mac": server_mac, "dhcp_msg": kind})
        return

    if not trust["ip"]:
        # nothing learned yet and it's not the gateway — trust-on-first-use
        _learn_dhcp_server(server_ip, server_mac)
        return

    if _dedup_ok("Rogue DHCP", server_ip):
        raise_threat(
            "Rogue DHCP", "High", server_ip, server_mac,
            f"Unauthorized DHCP server: {server_ip} ({server_mac}) sent a "
            f"DHCP {kind}, but the trusted server is {trust['ip']}. A rogue "
            f"DHCP server can redirect all client traffic (MITM).",
            "rogue-dhcp: OFFER/ACK from a server that is not the gateway, "
            "not configured as trusted, and not the learned server",
            {"rogue_server_ip": server_ip, "rogue_server_mac": server_mac,
             "trusted_server_ip": trust["ip"], "dhcp_msg": kind})
