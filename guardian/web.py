"""
guardian/web.py
Dashboard + REST API: live data, search & filter, threat workflow,
settings, report export, performance metrics.
"""
import io
import time
import datetime

from flask import (Blueprint, render_template, jsonify, request,
                   session, send_file, redirect, url_for)

from . import state, db, devices, reports
from .auth import login_required, csrf_protect, get_csrf_token

web_bp = Blueprint("web", __name__)


# ─────────────────────────────────────────────────────────────────────────
#  Pages
# ─────────────────────────────────────────────────────────────────────────
@web_bp.route("/")
def dashboard():
    # IoT-style: visiting the monitor's IP without a login shows the
    # public read-only Network Status page; admins get the dashboard.
    if not session.get("admin"):
        return redirect(url_for("web.status"))
    with state.lock:
        net = dict(state.net)
    return render_template("dashboard.html",
                           net=net,
                           admin=session.get("admin", ""),
                           csrf=get_csrf_token(),
                           alarm=db.get_setting("alarm_enabled", "1"))


@web_bp.route("/status")
def status():
    """Public network-safety page — reachable by ANY device on the WiFi,
    no login, no internet needed (all assets served locally)."""
    return render_template("status.html")


@web_bp.route("/api/public/summary")
def api_public_summary():
    """
    Read-only safety summary for the public status page. Deliberately
    minimal: verdict, counts and threat types/times only — no device
    MACs/IPs, no logs, no settings, no admin data.
    """
    cnt = devices.counts()
    sev = {r["severity"]: r["n"] for r in
           db.query("SELECT severity, COUNT(*) n FROM threats "
                    "WHERE status IN ('New','Acknowledged') "
                    "GROUP BY severity")}
    active = {s: sev.get(s, 0) for s in ("Critical", "High", "Medium", "Low")}
    if active["Critical"] or active["High"]:
        verdict = "danger"
    elif active["Medium"] or active["Low"]:
        verdict = "caution"
    else:
        verdict = "safe"
    recent = db.query("SELECT ts, threat_type, severity FROM threats "
                      "WHERE status IN ('New','Acknowledged') "
                      "ORDER BY ts DESC LIMIT 10")
    with state.lock:
        monitoring = bool(state.net["scan_active"])
    return jsonify({"verdict": verdict, "devices": cnt,
                    "active_threats": active, "recent": recent,
                    "monitoring": monitoring, "server_time": db.now()})


# ─────────────────────────────────────────────────────────────────────────
#  Live data APIs
# ─────────────────────────────────────────────────────────────────────────
@web_bp.route("/api/summary")
@login_required
def api_summary():
    cnt = devices.counts()
    sev = {r["severity"]: r["n"] for r in
           db.query("SELECT severity, COUNT(*) n FROM threats "
                    "WHERE status NOT IN ('Resolved','False Positive') "
                    "GROUP BY severity")}
    typ = {r["threat_type"]: r["n"] for r in
           db.query("SELECT threat_type, COUNT(*) n FROM threats "
                    "GROUP BY threat_type")}
    with state.lock:
        stats = dict(state.stats)
        net = dict(state.net)
        uptime = int(time.time() - net["started_at"])
    return jsonify({
        "devices": cnt,
        "severity": {s: sev.get(s, 0)
                     for s in ("Critical", "High", "Medium", "Low")},
        "types": typ,
        "packets": stats,
        "network": {k: net.get(k, "") for k in
                    ("interface", "local_ip", "local_mac", "gateway_ip",
                     "gateway_mac", "subnet", "scan_active", "scapy_ok")},
        "uptime_secs": uptime,
        "server_time": db.now(),
    })


@web_bp.route("/api/devices")
@login_required
def api_devices():
    q      = (request.args.get("q") or "").lower().strip()
    status = (request.args.get("status") or "").lower().strip()
    data = devices.all_snapshots()
    if status in ("online", "offline"):
        data = [d for d in data if d["status"] == status]
    if q:
        data = [d for d in data if q in d["ip"].lower()
                or q in d["mac"].lower() or q in d["hostname"].lower()
                or q in d["vendor"].lower()]
    data.sort(key=lambda d: (d["status"] != "online", d["ip"]))
    return jsonify(data)


@web_bp.route("/api/devices/clear", methods=["POST"])
@login_required
@csrf_protect
def api_devices_clear():
    scope = (request.get_json(silent=True) or {}).get("scope", "offline")
    if scope not in ("offline", "all"):
        return jsonify({"error": "scope must be 'offline' or 'all'"}), 400
    removed = devices.clear_devices(scope)
    db.log_admin(session["admin"], "devices_clear",
                 f"{scope} ({removed} removed)")
    return jsonify({"ok": True, "removed": removed, "scope": scope})


@web_bp.route("/api/threats")
@login_required
def api_threats():
    """Search + filter: type, severity, status, date range, free text."""
    clauses, params = [], []
    if request.args.get("type"):
        clauses.append("threat_type = ?")
        params.append(request.args["type"])
    if request.args.get("severity"):
        clauses.append("severity = ?")
        params.append(request.args["severity"])
    if request.args.get("status"):
        clauses.append("status = ?")
        params.append(request.args["status"])
    if request.args.get("date_from"):
        clauses.append("ts >= ?")
        params.append(request.args["date_from"] + " 00:00:00")
    if request.args.get("date_to"):
        clauses.append("ts <= ?")
        params.append(request.args["date_to"] + " 23:59:59")
    if request.args.get("q"):
        q = f"%{request.args['q']}%"
        clauses.append("(src_ip LIKE ? OR src_mac LIKE ? OR dst_ip LIKE ? "
                       "OR description LIKE ?)")
        params += [q, q, q, q]
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = db.query(f"SELECT * FROM threats {where} "
                    f"ORDER BY ts DESC LIMIT 500", tuple(params))
    return jsonify(rows)


@web_bp.route("/api/threats/timeline")
@login_required
def api_threat_timeline():
    """Hourly threat counts for the last 24 h (Chart.js line)."""
    rows = db.query(
        "SELECT strftime('%Y-%m-%d %H:00', ts) hour, COUNT(*) n "
        "FROM threats WHERE ts >= datetime('now','localtime','-24 hours') "
        "GROUP BY hour ORDER BY hour")
    return jsonify(rows)


@web_bp.route("/api/threats/<tid>/status", methods=["POST"])
@login_required
@csrf_protect
def api_threat_status(tid):
    new = (request.get_json(silent=True) or {}).get("status", "")
    if new not in ("New", "Acknowledged", "Resolved", "False Positive"):
        return jsonify({"error": "invalid status"}), 400
    user = session["admin"]
    db.execute("UPDATE threats SET status=?, ack_by=?, ack_at=? WHERE id=?",
               (new, user, db.now(), tid))
    db.log_admin(user, "threat_ack", f"{tid} → {new}")
    try:
        state.socketio_ref().emit("threat_status",
                                  {"id": tid, "status": new})
    except Exception:
        pass
    return jsonify({"ok": True})


@web_bp.route("/api/logs/connection")
@login_required
def api_conn_log():
    q = (request.args.get("q") or "").strip()
    if q:
        like = f"%{q}%"
        rows = db.query("SELECT * FROM connection_log WHERE ip LIKE ? OR "
                        "mac LIKE ? OR hostname LIKE ? OR vendor LIKE ? "
                        "ORDER BY id DESC LIMIT 300",
                        (like, like, like, like))
    else:
        rows = db.query("SELECT * FROM connection_log "
                        "ORDER BY id DESC LIMIT 300")
    return jsonify(rows)


@web_bp.route("/api/logs/admin")
@login_required
def api_admin_log():
    return jsonify(db.query("SELECT * FROM admin_log "
                            "ORDER BY id DESC LIMIT 300"))


@web_bp.route("/api/metrics")
@login_required
def api_metrics():
    """Performance Evaluation: detection latency, FP rate, totals."""
    total = db.query_one("SELECT COUNT(*) n FROM threats")["n"]
    fp    = db.query_one("SELECT COUNT(*) n FROM threats "
                         "WHERE status='False Positive'")["n"]
    lat   = db.query_one("SELECT AVG(detect_latency_ms) a, "
                         "MAX(detect_latency_ms) m FROM threats "
                         "WHERE detect_latency_ms > 0")
    return jsonify({
        "total_threats": total,
        "false_positives": fp,
        "false_positive_rate": round(fp / total * 100, 2) if total else 0.0,
        "avg_detect_latency_ms": round(lat["a"] or 0, 1),
        "max_detect_latency_ms": lat["m"] or 0,
    })


# ─────────────────────────────────────────────────────────────────────────
#  Reports
# ─────────────────────────────────────────────────────────────────────────
@web_bp.route("/reports/export/<report_type>/<fmt>")
@login_required
def export_report(report_type, fmt):
    if fmt not in ("csv", "pdf"):
        return jsonify({"error": "format must be csv or pdf"}), 400
    try:
        fname, blob, mime = reports.generate(report_type, fmt,
                                             session["admin"])
    except RuntimeError as e:            # reportlab missing
        return jsonify({"error": str(e)}), 501
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return send_file(io.BytesIO(blob), mimetype=mime,
                     as_attachment=True, download_name=fname)


@web_bp.route("/api/reports/history")
@login_required
def api_report_history():
    return jsonify(db.query("SELECT * FROM reports "
                            "ORDER BY id DESC LIMIT 100"))


# ─────────────────────────────────────────────────────────────────────────
#  Settings
# ─────────────────────────────────────────────────────────────────────────
@web_bp.route("/api/settings", methods=["GET", "POST"])
@login_required
@csrf_protect
def api_settings():
    if request.method == "GET":
        keys = ("alarm_enabled", "probe_interval",
                "offline_miss_threshold", "monitoring_interface")
        return jsonify({k: db.get_setting(k) for k in keys})

    body = request.get_json(silent=True) or {}
    changed = []
    if "alarm_enabled" in body:
        db.set_setting("alarm_enabled",
                       "1" if body["alarm_enabled"] in (True, "1", 1) else "0")
        changed.append("alarm_enabled")
    for key, lo, hi in (("probe_interval", 1, 60),
                        ("offline_miss_threshold", 1, 10)):
        if key in body:
            try:
                v = max(lo, min(hi, int(body[key])))
                db.set_setting(key, str(v))
                changed.append(key)
            except (TypeError, ValueError):
                pass
    if "scan_active" in body:
        with state.lock:
            state.net["scan_active"] = bool(body["scan_active"])
        changed.append("scan_active")
    if changed:
        db.log_admin(session["admin"], "settings_change",
                     ", ".join(changed))
    return jsonify({"ok": True, "changed": changed})
