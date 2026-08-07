#!/usr/bin/env python3
"""
WiFi Admin Guardian — entry point.
Run as Administrator on Windows 10/11 with Npcap installed:
    python run.py
Dashboard: http://127.0.0.1:5000   (default login: admin / admin123)
"""
import sys
import ctypes


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return True     # non-Windows / dev environment


def ensure_firewall_rule(port: int):
    """
    Windows Firewall blocks inbound connections to Python by default, so
    phones on the WiFi get an endless loading spinner while this PC works
    fine. The app already runs as Administrator — add (once) an inbound
    allow rule for its own port so the public status page is reachable
    from any device, IoT-style.
    """
    if sys.platform != "win32":
        return
    import subprocess
    rule = "WiFi Admin Guardian"
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        r = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule",
             f"name={rule}"],
            capture_output=True, timeout=10, creationflags=flags)
        if r.returncode == 0:
            return                       # rule already exists
        r = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule}", "dir=in", "action=allow",
             "protocol=TCP", f"localport={port}"],
            capture_output=True, timeout=10, creationflags=flags)
        if r.returncode == 0:
            print(f"[*] Windows Firewall: opened inbound TCP {port} "
                  f"so WiFi devices can reach the status page.")
        else:
            raise RuntimeError(r.stderr.decode(errors="ignore").strip()
                               or "netsh failed")
    except Exception as e:
        print(f"[!] Could not add a Windows Firewall rule ({e}).")
        print(f"    If phones only show a loading spinner, allow inbound "
              f"TCP {port} manually:")
        print(f"    netsh advfirewall firewall add rule "
              f"name=\"{rule}\" dir=in action=allow protocol=TCP "
              f"localport={port}")


def main():
    if sys.platform == "win32" and not is_admin():
        print("\n[!] WiFi Admin Guardian must be run as Administrator.")
        print("    Right-click PowerShell → 'Run as administrator'.\n")
        input("Press Enter to exit...")
        sys.exit(1)

    from guardian import create_app, socketio
    from guardian.config import Config
    from guardian import monitor

    app = create_app()
    monitor.start_all()

    print(f"\n[*] Admin dashboard: http://127.0.0.1:{Config.PORT}")
    print(f"[*] Default login: {Config.DEFAULT_ADMIN_USER} / "
          f"{Config.DEFAULT_ADMIN_PASS}  (change it in Settings!)")
    if Config.HOST not in ("127.0.0.1", "localhost", "::1"):
        ensure_firewall_rule(Config.PORT)
        from guardian import state
        lan_ip = state.net.get("local_ip") or "<this-pc-ip>"
        print(f"[*] Public status page (any device on the WiFi, no login): "
              f"http://{lan_ip}:{Config.PORT}\n")
    else:
        print()
    socketio.run(app, host=Config.HOST, port=Config.PORT,
                 debug=False, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()
