"""
guardian/__init__.py
Flask application factory + Socket.IO instance.
"""
from flask import Flask, redirect, url_for
from flask_socketio import SocketIO

socketio = SocketIO(cors_allowed_origins="*", async_mode="threading")


def create_app() -> Flask:
    from .config import Config
    from . import db
    from .auth import auth_bp
    from .web import web_bp

    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_db()

    app.register_blueprint(auth_bp)
    app.register_blueprint(web_bp)

    @app.errorhandler(404)
    def _nf(_e):
        return redirect(url_for("web.dashboard"))

    socketio.init_app(app)

    # Socket handlers (import registers them)
    from . import sockets  # noqa: F401

    return app
