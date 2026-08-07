"""
guardian/netdiscovery.py
Network Discovery Module: local IP, gateway IP/MAC, interface,
subnet, adapter information (Windows).
"""
import re
import socket
import struct
import subprocess
import ipaddress

from . import state
from .vendors import oui_lookup


def run_ps(cmd: str, timeout: int = 10) -> str:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return r.stdout.strip()
    except Exception as e:
        return f"PS_ERROR: {e}"


def mac_normalize(mac: str) -> str:
    mac = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    if len(mac) != 12:
        return ""
    return ":".join(mac[i:i + 2] for i in range(0, 12, 2)).lower()


def _default_route():
    """Best-effort default gateway + interface via route print / PowerShell."""
    out = run_ps(
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 | "
        "Sort-Object RouteMetric | Select-Object -First 1 | "
        "ForEach-Object { \"$($_.NextHop)|$($_.InterfaceIndex)|$($_.InterfaceAlias)\" }"
    )
    if out and "|" in out and not out.startswith("PS_ERROR"):
        gw, idx, alias = (out.split("|") + ["", "", ""])[:3]
        return gw.strip(), idx.strip(), alias.strip()
    return "", "", ""


def _local_ip_toward(gateway_ip: str) -> str:
    """UDP-connect trick: what source IP would we use to reach the gateway?"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((gateway_ip or "8.8.8.8", 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def _prefix_for_ip(ip: str) -> int:
    out = run_ps(
        f"Get-NetIPAddress -IPAddress '{ip}' -AddressFamily IPv4 "
        f"-ErrorAction SilentlyContinue | "
        f"Select-Object -First 1 -ExpandProperty PrefixLength"
    )
    try:
        return int(out.strip())
    except Exception:
        return 24


def _mac_of_ip(ip: str) -> str:
    """Read the neighbor cache for an IP (populated by prior traffic)."""
    out = run_ps(
        f"Get-NetNeighbor -IPAddress '{ip}' -AddressFamily IPv4 "
        f"-ErrorAction SilentlyContinue | "
        f"Select-Object -First 1 -ExpandProperty LinkLayerAddress"
    )
    return mac_normalize(out)


def _local_mac(alias: str) -> str:
    out = run_ps(
        f"Get-NetAdapter -Name '{alias}' -ErrorAction SilentlyContinue | "
        f"Select-Object -First 1 -ExpandProperty MacAddress"
    )
    return mac_normalize(out)


def _all_local_macs() -> set:
    """
    MACs of EVERY adapter on this machine, including virtual ones
    (VMware VMnet, VirtualBox, Hyper-V). Needed so the detection engine
    can tell 'my own virtual adapter answering for 192.168.1.1 on its
    private virtual subnet' apart from a real gateway impersonator.
    """
    macs = set()
    out = run_ps("Get-NetAdapter -IncludeHidden -ErrorAction "
                 "SilentlyContinue | ForEach-Object { $_.MacAddress }")
    for line in (out or "").splitlines():
        m = mac_normalize(line)
        if m:
            macs.add(m)
    try:
        from scapy.interfaces import get_working_ifaces
        for i in get_working_ifaces():
            m = mac_normalize(getattr(i, "mac", "") or "")
            if m:
                macs.add(m)
    except Exception:
        pass
    return macs


def _scapy_iface_for(local_ip: str):
    """Find the scapy interface object whose IP matches the local IP."""
    try:
        from scapy.arch.windows import get_windows_if_list
        for i in get_windows_if_list():
            if local_ip in (i.get("ips") or []):
                return i.get("name") or i.get("description")
    except Exception:
        pass
    return None


def discover() -> dict:
    """Populate state.net with everything the dashboard sidebar needs."""
    gw_ip, _idx, alias = _default_route()
    local_ip = _local_ip_toward(gw_ip)

    # Ping the gateway once so its MAC lands in the neighbor cache
    if gw_ip:
        try:
            subprocess.run(["ping", "-n", "1", "-w", "500", gw_ip],
                           capture_output=True, timeout=3)
        except Exception:
            pass

    gw_mac    = _mac_of_ip(gw_ip) if gw_ip else ""
    local_mac = _local_mac(alias) if alias else ""
    prefix    = _prefix_for_ip(local_ip) if local_ip else 24

    subnet = ""
    if local_ip:
        try:
            subnet = str(ipaddress.ip_network(f"{local_ip}/{prefix}",
                                              strict=False))
        except Exception:
            subnet = ""

    local_macs = _all_local_macs()
    if local_mac:
        local_macs.add(local_mac)

    with state.lock:
        state.net.update({
            "interface":   alias,
            "iface_desc":  alias,
            "local_ip":    local_ip,
            "local_mac":   local_mac,
            "local_macs":  local_macs,
            "gateway_ip":  gw_ip,
            "gateway_mac": gw_mac,
            "subnet":      subnet,
        })
        if gw_ip and gw_mac:
            state.arp_truth[gw_ip] = gw_mac

    print(f"[*] Discovery: iface={alias}  local={local_ip} ({local_mac})  "
          f"gw={gw_ip} ({gw_mac})  subnet={subnet}")
    return dict(state.net)


def ip_in_subnet(ip: str, subnet: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet)
    except Exception:
        return False


def is_virtual_mac(mac: str) -> bool:
    from .config import Config
    m = (mac or "").lower()
    return any(m.startswith(p) for p in Config.VIRTUAL_OUI_WHITELIST)
