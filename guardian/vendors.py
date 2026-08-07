"""
guardian/vendors.py
Lightweight OUI → vendor lookup (offline, common prefixes) with
detection of locally-administered (randomized/private) MAC addresses.
"""

_OUI = {
    "00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware",
    "08:00:27": "VirtualBox", "00:15:5d": "Microsoft Hyper-V",
    "00:1c:42": "Parallels",
    "3c:22:fb": "Apple", "f0:18:98": "Apple", "a4:83:e7": "Apple",
    "dc:a9:04": "Apple", "88:66:5a": "Apple", "f8:ff:c2": "Apple",
    "28:6a:ba": "Apple", "ac:bc:32": "Apple", "b8:53:ac": "Apple",
    "94:65:2d": "OnePlus",
    "8c:f5:a3": "Samsung", "d0:87:e2": "Samsung", "5c:49:7d": "Samsung",
    "84:25:db": "Samsung", "f4:7b:09": "Samsung", "1c:af:4a": "Samsung",
    "a0:cc:2b": "Xiaomi", "64:cc:2e": "Xiaomi", "f8:a2:d6": "Xiaomi",
    "50:8f:4c": "Xiaomi", "98:fa:9b": "Xiaomi",
    "94:d9:b3": "Oppo", "1c:77:f6": "Oppo", "c8:f2:30": "Realme",
    "a4:50:46": "Vivo", "10:f6:0a": "Vivo",
    "b0:4e:26": "TP-Link", "50:c7:bf": "TP-Link", "60:32:b1": "TP-Link",
    "c0:25:e9": "TP-Link", "98:da:c4": "TP-Link", "d8:07:b6": "TP-Link",
    "e4:c3:2a": "Huawei", "48:46:fb": "Huawei", "00:e0:fc": "Huawei",
    "34:6b:d3": "Huawei", "70:8a:09": "Huawei",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi", "28:cd:c1": "Raspberry Pi",
    "24:0a:c4": "Espressif (ESP32)", "30:ae:a4": "Espressif (ESP32)",
    "a4:cf:12": "Espressif (ESP32)", "c8:2b:96": "Espressif (ESP32)",
    "3c:71:bf": "Espressif (ESP32)", "ec:fa:bc": "Espressif (ESP8266)",
    "00:1a:11": "Google", "f4:f5:d8": "Google", "54:60:09": "Google",
    "18:b4:30": "Nest", "64:16:66": "Nest",
    "3c:5a:b4": "Google", "a4:77:33": "Google",
    "00:1d:aa": "D-Link", "c4:a8:1d": "D-Link", "28:10:7b": "D-Link",
    "e8:48:b8": "Netgear", "a0:40:a0": "Netgear", "9c:3d:cf": "Netgear",
    "00:23:69": "Cisco-Linksys", "48:f8:b3": "Cisco-Linksys",
    "00:1e:8c": "ASUS", "1c:87:2c": "ASUS", "2c:fd:a1": "ASUS",
    "04:d9:f5": "ASUS", "70:4d:7b": "ASUS",
    "f8:32:e4": "ASUS", "d8:50:e6": "ASUS",
    "3c:97:0e": "Lenovo", "54:ee:75": "Lenovo", "e8:6a:64": "Lenovo",
    "8c:16:45": "Lenovo",
    "18:60:24": "HP", "40:b0:34": "HP", "70:5a:0f": "HP",
    "f4:39:09": "HP", "94:57:a5": "HP",
    "18:03:73": "Dell", "b8:ca:3a": "Dell", "f8:bc:12": "Dell",
    "d4:be:d9": "Dell", "84:7b:eb": "Dell",
    "fc:44:82": "Intel", "3c:e9:f7": "Intel", "a4:bf:01": "Intel",
    "00:1b:21": "Intel", "8c:c6:81": "Intel", "dc:41:a9": "Intel",
    "b4:6b:fc": "Intel", "e0:d4:e8": "Intel",
    "9c:b6:d0": "Rivet-Killer", "14:cc:20": "TP-Link",
    "00:03:7f": "Atheros", "00:0a:f5": "Airgo",
    "60:e3:2b": "Realtek", "00:e0:4c": "Realtek", "52:54:00": "QEMU/KVM",
}


def is_locally_administered(mac: str) -> bool:
    """Second-least-significant bit of first octet = locally administered
    (typical for iOS/Android randomized 'private' Wi-Fi addresses)."""
    try:
        first = int(mac.split(":")[0], 16)
        return bool(first & 0b10)
    except Exception:
        return False


def oui_lookup(mac: str) -> str:
    m = (mac or "").lower()
    if not m:
        return "Unknown"
    if m[:8] in _OUI:
        return _OUI[m[:8]]
    if m[:5] == "02:42":
        return "Docker"
    if is_locally_administered(m):
        return "Private/Randomized MAC"
    return "Unknown"
