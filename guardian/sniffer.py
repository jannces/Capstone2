"""
guardian/sniffer.py
Packet Capture Module (Scapy + Npcap).
Continuous background sniffing of ARP / TCP / DHCP / mDNS.
Every packet feeds two consumers:
  • devices.register_sighting()  → presence (passive liveness, free)
  • detection.inspect_*()        → threat engine
"""
import time
import threading

from . import state, devices, detection

SCAPY_OK = False
SCAPY_ERR = ""
try:
    from scapy.all import sniff, Ether, ARP, IP, TCP, UDP, DNS
    try:
        from scapy.all import DHCP, BOOTP
    except ImportError:
        from scapy.layers.dhcp import DHCP, BOOTP
    SCAPY_OK = True
except Exception as e:                                   # pragma: no cover
    SCAPY_ERR = str(e)


def _harvest_mdns(pkt, ether_src):
    """
    Pull device names out of mDNS answers (Bonjour/Avahi). Devices
    announce their own name ("Johns-iPhone.local") in A records and
    reverse PTR records — far more complete than reverse DNS on a LAN.
    Only records about the SENDER's own IP are used, and the name is
    attached to the sender's MAC — a multi-homed host announces all of
    its addresses (VPN/VMware adapters too), and matching those by IP
    would mislabel other devices.
    """
    if not ether_src:
        return
    src_ip = pkt[IP].src if IP in pkt else ""
    rr = pkt[DNS].an
    while rr:                       # walk the chained answer records
        try:
            name = rr.rrname
            if isinstance(name, bytes):
                name = name.decode("utf-8", "ignore")
            rtype = int(rr.type)
            if rtype == 1:                            # A: hostname → IP
                host, ip = name, str(rr.rdata)
            elif rtype == 12 and name.endswith(".in-addr.arpa."):
                # reverse PTR: d.c.b.a.in-addr.arpa → hostname
                octets = name[:-len(".in-addr.arpa.")].split(".")
                ip = ".".join(reversed(octets))
                host = rr.rdata
                if isinstance(host, bytes):
                    host = host.decode("utf-8", "ignore")
            else:
                host, ip = "", ""
            if host and ip and ip == src_ip:
                devices.set_hostname_by_mac(ether_src, host)
        except Exception:
            pass
        rr = rr.payload


def _bump(key: str):
    with state.lock:
        state.stats["packets_analyzed"] += 1
        if key:
            state.stats[key] = state.stats.get(key, 0) + 1


def _handle(pkt):
    try:
        ether_src = pkt[Ether].src.lower() if Ether in pkt else ""

        # ── ARP ──────────────────────────────────────────────────────────
        if ARP in pkt:
            _bump("arp_packets")
            a = pkt[ARP]
            src_ip  = a.psrc or ""
            src_mac = (a.hwsrc or "").lower()
            # An all-zeros or broadcast sender MAC is not a real device — it
            # appears in ARP probes (RFC 5227 duplicate-address detection),
            # gratuitous ARP, and some DHCP frames. Never register it or feed
            # it to conflict detection, or it phantoms a device and triggers a
            # false "IP/MAC conflict".
            valid_mac = src_mac not in ("", "00:00:00:00:00:00",
                                        "ff:ff:ff:ff:ff:ff")
            if src_ip and src_ip != "0.0.0.0" and valid_mac:
                devices.register_sighting(src_ip, src_mac)
                detection.inspect_ip_conflict(src_ip, src_mac)
            if valid_mac:
                detection.inspect_arp(src_ip, src_mac, ether_src, int(a.op))
            return

        # ── DHCP ─────────────────────────────────────────────────────────
        if DHCP in pkt and BOOTP in pkt:
            _bump("dhcp_packets")
            b = pkt[BOOTP]
            msg_type, server_id = 0, ""
            for opt in (pkt[DHCP].options or []):
                if isinstance(opt, tuple) and opt[0] == "message-type":
                    msg_type = opt[1]
                elif isinstance(opt, tuple) and opt[0] == "server_id":
                    server_id = str(opt[1])
            client_mac = ""
            try:
                raw = bytes(b.chaddr)[:6]
                client_mac = ":".join(f"{x:02x}" for x in raw)
            except Exception:
                pass
            yiaddr = getattr(b, "yiaddr", "") or ""
            # OFFER/ACK come FROM the server → rogue-DHCP check.
            if msg_type in (2, 5):
                srv_ip = server_id or (pkt[IP].src if IP in pkt else "")
                detection.inspect_dhcp_server(srv_ip, ether_src, msg_type)
            if msg_type == 5 and yiaddr and yiaddr != "0.0.0.0":  # DHCP ACK
                detection.note_dhcp_ack(yiaddr, client_mac)
                devices.register_sighting(yiaddr, client_mac)
            elif client_mac and ether_src:
                # request/discover — the device is clearly alive
                devices.register_sighting("", client_mac)
            return

        # ── TCP ──────────────────────────────────────────────────────────
        if IP in pkt and TCP in pkt:
            _bump("tcp_packets")
            ip, tcp = pkt[IP], pkt[TCP]
            devices.register_sighting(ip.src, ether_src)
            detection.inspect_tcp(ip.src, ether_src, ip.dst,
                                  int(tcp.dport), int(tcp.flags))
            return

        # ── mDNS / other UDP ─────────────────────────────────────────────
        if IP in pkt and UDP in pkt:
            udp = pkt[UDP]
            if udp.dport == 5353 or udp.sport == 5353:
                _bump("mdns_packets")
                if DNS in pkt:
                    _harvest_mdns(pkt, ether_src)
            else:
                _bump("")
                detection.inspect_udp_probe(pkt[IP].src, ether_src,
                                            pkt[IP].dst, int(udp.dport),
                                            int(udp.sport))
            devices.register_sighting(pkt[IP].src, ether_src)
            return

        # anything else still proves the sender is alive
        if ether_src:
            _bump("")
            devices.register_sighting("", ether_src)

    except Exception:
        pass    # never let one bad packet kill the sniffer


def run_sniffer():
    """Background thread: continuous capture with auto-restart."""
    with state.lock:
        state.net["scapy_ok"] = SCAPY_OK
        state.net["scapy_error"] = SCAPY_ERR
    if not SCAPY_OK:
        print(f"[!] Scapy unavailable ({SCAPY_ERR}) — passive capture "
              f"disabled; liveness falls back to ping probing.")
        return

    from .netdiscovery import _scapy_iface_for
    with state.lock:
        local_ip = state.net["local_ip"]
        subnet   = state.net["subnet"]
    iface = _scapy_iface_for(local_ip)
    with state.lock:
        state.net["scapy_iface"] = iface

    # Tight BPF pre-filter — everything else is dropped in the kernel,
    # never reaching Python (keeps packet loss low on busy networks).
    # In-subnet UDP is included for UDP-scan detection; off-subnet UDP
    # (QUIC browsing etc.) stays filtered out.
    bpf = "arp or tcp or udp port 67 or udp port 68 or udp port 5353"
    if subnet:
        bpf += f" or (udp and dst net {subnet})"
    if not iface:
        print("[!] Could not match a capture interface to the local IP — "
              "sniffing on ALL interfaces (virtual adapters included).")
    print(f"[*] Sniffer starting on iface={iface or 'ALL'} "
          f"(ARP/TCP/DHCP/mDNS + in-subnet UDP).")

    while True:
        with state.lock:
            active = state.net["scan_active"]
        if not active:
            time.sleep(1)
            continue
        try:
            sniff(prn=_handle, store=False, iface=iface,
                  filter=bpf,
                  stop_filter=lambda p: not state.net["scan_active"],
                  timeout=30)
        except Exception as e:
            print(f"[!] Sniffer error: {e} — restarting in 3 s.")
            time.sleep(3)
