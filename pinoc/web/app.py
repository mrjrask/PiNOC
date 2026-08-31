"""Flask application backed exclusively by the shared state cache."""
from __future__ import annotations

import logging
from typing import Any

from flask import Flask, abort, jsonify, render_template

from pinoc.state import PiNOCState


def create_app(state: PiNOCState, config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.update(config or {})

    @app.get("/")
    def dashboard():
        return render_template("dashboard.html")

    @app.get("/devices/<device_id>")
    def device_page(device_id: str):
        if state.device(device_id) is None:
            abort(404)
        return render_template("device.html", device_id=device_id)

    @app.get("/health")
    def health():
        summary = state.summary()
        return jsonify({"status": "ok", "devices": summary["devices"], "online": summary["online"],
                        "warnings": summary["warnings"], "critical": summary["critical"],
                        "database": summary["database"]})

    @app.get("/api/status")
    def api_status():
        return jsonify(state.summary())

    @app.get("/api/devices")
    def api_devices():
        return jsonify({"devices": state.devices()})

    @app.get("/api/devices/<device_id>")
    def api_device(device_id: str):
        device = state.device(device_id)
        return jsonify(device) if device else (jsonify({"error": "device not found"}), 404)

    @app.get("/api/devices/<device_id>/services")
    def api_services(device_id: str):
        device = state.device(device_id)
        return jsonify({"services": device.get("services", [])}) if device else (jsonify({"error": "device not found"}), 404)

    @app.get("/api/alerts")
    def api_alerts():
        return jsonify({"alerts": state.alerts()})

    return app


def serve(app: Flask, host: str, port: int) -> None:
    try:
        from waitress import serve as waitress_serve
        waitress_serve(app, host=host, port=port, threads=4)
    except ImportError:
        logging.getLogger("pinoc.web").warning("Waitress unavailable; using Flask development server")
        app.run(host=host, port=port, threaded=True, use_reloader=False)
