"""
guardian/auth.py
Authentication: login/logout, password change, bcrypt hashing,
CSRF protection, brute-force rate limiting, session management.
"""
import time
import secrets
import functools
from collections import defaultdict, deque

from flask import (Blueprint, render_template, request, session,
                   redirect, url_for, flash, jsonify)

from .config import Config
from . import db

auth_bp = Blueprint("auth", __name__)

# ── Password hashing: bcrypt preferred, werkzeug fallback ────────────────
try:
    import bcrypt as _bcrypt
    _HAS_BCRYPT = True
except ImportError:
    _HAS_BCRYPT = False
    from werkzeug.security import generate_password_hash, check_password_hash


def hash_password(plain: str) -> str:
    if _HAS_BCRYPT:
        return "bcrypt$" + _bcrypt.hashpw(
            plain.encode(), _bcrypt.gensalt(rounds=12)).decode()
    return "werkzeug$" + generate_password_hash(plain)


def verify_password(plain: str, stored: str) -> bool:
    try:
        if stored.startswith("bcrypt$"):
            if not _HAS_BCRYPT:
                return False
            return _bcrypt.checkpw(plain.encode(),
                                   stored[len("bcrypt$"):].encode())
        if stored.startswith("werkzeug$"):
            return check_password_hash(stored[len("werkzeug$"):], plain)
        # legacy unprefixed bcrypt hash
        if _HAS_BCRYPT and stored.startswith("$2"):
            return _bcrypt.checkpw(plain.encode(), stored.encode())
    except Exception:
        pass
    return False


# ── Brute-force protection (per source IP) ───────────────────────────────
_fail_log = defaultdict(deque)      # ip -> deque of fail timestamps
_lockout  = {}                      # ip -> unlock time


def _client_ip() -> str:
    return request.remote_addr or "?"


def _is_locked(ip: str) -> float:
    """Returns remaining lockout seconds (0 = not locked)."""
    until = _lockout.get(ip, 0)
    return max(0.0, until - time.time())


def _register_failure(ip: str):
    q = _fail_log[ip]
    now = time.time()
    q.append(now)
    while q and now - q[0] > Config.LOGIN_WINDOW_SECS:
        q.popleft()
    if len(q) >= Config.LOGIN_MAX_ATTEMPTS:
        _lockout[ip] = now + Config.LOGIN_LOCKOUT_SECS
        q.clear()


def _register_success(ip: str):
    _fail_log.pop(ip, None)
    _lockout.pop(ip, None)


# ── CSRF ──────────────────────────────────────────────────────────────────
def get_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf() -> bool:
    sent = (request.form.get("csrf_token")
            or request.headers.get("X-CSRF-Token")
            or (request.get_json(silent=True) or {}).get("csrf_token", ""))
    good = session.get("csrf_token", "")
    return bool(good) and secrets.compare_digest(str(sent), good)


def csrf_protect(view):
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if request.method in ("POST", "PUT", "DELETE") and not validate_csrf():
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "CSRF validation failed"}), 403
            flash("Security token expired — please try again.", "danger")
            return redirect(request.referrer or url_for("web.dashboard"))
        return view(*a, **kw)
    return wrapped


# ── Session guard ─────────────────────────────────────────────────────────
def login_required(view):
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if not session.get("admin"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("auth.login", next=request.path))
        # idle-timeout
        last = session.get("last_active", 0)
        limit = Config.PERMANENT_SESSION_LIFETIME_MIN * 60
        if last and time.time() - last > limit:
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"error": "session expired"}), 401
            flash("Session expired — please log in again.", "warning")
            return redirect(url_for("auth.login"))
        session["last_active"] = time.time()
        return view(*a, **kw)
    return wrapped


# ── Routes ────────────────────────────────────────────────────────────────
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    ip = _client_ip()

    if request.method == "POST":
        remaining = _is_locked(ip)
        if remaining:
            flash(f"Too many failed attempts. Locked for {int(remaining)} s.",
                  "danger")
            return render_template("login.html", csrf=get_csrf_token())

        if not validate_csrf():
            flash("Security token expired — please try again.", "danger")
            return render_template("login.html", csrf=get_csrf_token())

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        row = db.query_one("SELECT * FROM admins WHERE username=?", (username,))

        if row and verify_password(password, row["password_hash"]):
            _register_success(ip)
            session.clear()
            session["admin"] = username
            session["last_active"] = time.time()
            get_csrf_token()
            db.execute("UPDATE admins SET last_login=? WHERE id=?",
                       (db.now(), row["id"]))
            db.log_admin(username, "login", "successful login", ip)
            return redirect(request.args.get("next") or url_for("web.dashboard"))

        _register_failure(ip)
        db.log_admin(username or "?", "login_failed", "invalid credentials", ip)
        flash("Invalid username or password.", "danger")

    return render_template("login.html", csrf=get_csrf_token())


@auth_bp.route("/logout", methods=["POST"])
@login_required
@csrf_protect
def logout():
    user = session.get("admin", "?")
    db.log_admin(user, "logout", "", _client_ip())
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/change-password", methods=["POST"])
@login_required
@csrf_protect
def change_password():
    user    = session["admin"]
    current = request.form.get("current_password") or ""
    new     = request.form.get("new_password") or ""
    confirm = request.form.get("confirm_password") or ""

    row = db.query_one("SELECT * FROM admins WHERE username=?", (user,))
    if not row or not verify_password(current, row["password_hash"]):
        flash("Current password is incorrect.", "danger")
    elif len(new) < 8:
        flash("New password must be at least 8 characters.", "warning")
    elif new != confirm:
        flash("New passwords do not match.", "warning")
    else:
        db.execute("UPDATE admins SET password_hash=? WHERE id=?",
                   (hash_password(new), row["id"]))
        db.log_admin(user, "password_change", "", _client_ip())
        flash("Password changed successfully.", "success")
    return redirect(url_for("web.dashboard") + "#settings")
