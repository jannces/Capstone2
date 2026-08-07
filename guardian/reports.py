"""
guardian/reports.py
Report Module: Threat / Connection / Device / Security reports,
exported as CSV (always available) or PDF (via reportlab if installed).
"""
import os
import csv
import io
import datetime

from . import db, devices
from .config import Config

try:
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import (SimpleDocTemplate, Table, TableStyle,
                                    Paragraph, Spacer)
    HAS_PDF = True
except ImportError:
    HAS_PDF = False


def _rows_for(report_type: str):
    """Return (title, headers, rows) for a report type."""
    if report_type == "threat":
        rows = db.query("SELECT ts, threat_type, severity, src_ip, src_mac, "
                        "dst_ip, description, status, mitigation "
                        "FROM threats ORDER BY ts DESC")
        headers = ["Timestamp", "Type", "Severity", "Source IP",
                   "Source MAC", "Dest IP", "Description", "Status",
                   "Mitigation"]
        data = [[r["ts"], r["threat_type"], r["severity"], r["src_ip"],
                 r["src_mac"], r["dst_ip"], r["description"], r["status"],
                 r["mitigation"]] for r in rows]
        return "Threat Report", headers, data

    if report_type == "connection":
        rows = db.query("SELECT ts, event, mac, ip, hostname, vendor "
                        "FROM connection_log ORDER BY ts DESC")
        headers = ["Timestamp", "Event", "MAC", "IP", "Hostname", "Vendor"]
        data = [[r["ts"], r["event"], r["mac"], r["ip"], r["hostname"],
                 r["vendor"]] for r in rows]
        return "Connection Report", headers, data

    if report_type == "device":
        headers = ["MAC", "IP", "Hostname", "Vendor", "Status",
                   "First Seen", "Last Seen", "Total Online (min)"]
        data = [[d["mac"], d["ip"], d["hostname"], d["vendor"], d["status"],
                 d["first_seen"], d["last_seen"],
                 round(d["online_secs"] / 60, 1)]
                for d in devices.all_snapshots()]
        return "Device Report", headers, data

    # security = summary counts + latest threats
    sev = db.query("SELECT severity, COUNT(*) n FROM threats "
                   "GROUP BY severity")
    typ = db.query("SELECT threat_type, COUNT(*) n FROM threats "
                   "GROUP BY threat_type")
    headers = ["Metric", "Value"]
    cnt = devices.counts()
    data = ([["Devices (total)", cnt["total"]],
             ["Devices online", cnt["online"]],
             ["Devices offline", cnt["offline"]]]
            + [[f"Threats — {r['severity']}", r["n"]] for r in sev]
            + [[f"Attack type — {r['threat_type']}", r["n"]] for r in typ])
    return "Security Summary Report", headers, data


def _filename(report_type: str, fmt: str) -> str:
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{report_type}_report_{ts}.{fmt}"


def generate_csv(report_type: str) -> tuple:
    title, headers, data = _rows_for(report_type)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([title, f"Generated {db.now()}"])
    w.writerow(headers)
    w.writerows(data)
    fname = _filename(report_type, "csv")
    path = os.path.join(Config.REPORT_DIR, fname)
    with open(path, "w", newline="", encoding="utf-8") as f:
        f.write(buf.getvalue())
    return fname, buf.getvalue().encode("utf-8"), "text/csv"


def generate_pdf(report_type: str) -> tuple:
    if not HAS_PDF:
        raise RuntimeError(
            "PDF export requires reportlab: pip install reportlab")
    title, headers, data = _rows_for(report_type)
    fname = _filename(report_type, "pdf")
    path = os.path.join(Config.REPORT_DIR, fname)

    doc = SimpleDocTemplate(path, pagesize=landscape(A4),
                            title=title, leftMargin=24, rightMargin=24)
    styles = getSampleStyleSheet()
    body = styles["BodyText"]
    body.fontSize = 7
    elems = [Paragraph(f"<b>WiFi Admin Guardian — {title}</b>",
                       styles["Title"]),
             Paragraph(f"Generated: {db.now()}", styles["Normal"]),
             Spacer(1, 10)]
    table_data = [headers] + [
        [Paragraph(str(c), body) for c in row] for row in data[:500]]
    t = Table(table_data, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16324f")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTSIZE",   (0, 0), (-1, -1), 7),
        ("GRID",       (0, 0), (-1, -1), 0.4, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#eef3f8")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elems.append(t)
    doc.build(elems)

    with open(path, "rb") as f:
        blob = f.read()
    return fname, blob, "application/pdf"


def generate(report_type: str, fmt: str, username: str) -> tuple:
    if report_type not in ("threat", "connection", "device", "security"):
        raise ValueError("unknown report type")
    if fmt == "pdf":
        fname, blob, mime = generate_pdf(report_type)
    else:
        fname, blob, mime = generate_csv(report_type)
    db.execute("INSERT INTO reports (ts, report_type, fmt, filename, "
               "created_by) VALUES (?,?,?,?,?)",
               (db.now(), report_type, fmt, fname, username))
    db.log_admin(username, "report_export", f"{report_type} ({fmt})")
    return fname, blob, mime
