"""Flask application backed exclusively by the shared state cache."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from flask import Flask, abort, jsonify, render_template, request

from pinoc.state import PiNOCState


def create_app(state: PiNOCState, config: Optional[Dict[str, Any]] = None) -> Flask:
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
        status = "starting"
        if summary["last_collection"]:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(summary["last_collection"])).total_seconds()
            status = "ok" if age <= float(app.config.get("HEALTH_STALE_SECONDS", 120)) else "degraded"
        response_code = 200 if status == "ok" else 503
        return jsonify({"status": status, "devices": summary["devices"], "online": summary["online"],
                        "healthy": summary["healthy"], "warning": summary["warning"],
                        "warnings": summary["warnings"], "degraded": summary["degraded"],
                        "critical": summary["critical"], "offline": summary["offline"],
                        "collectors": "ok" if summary["last_collection"] else "starting"}), response_code

    @app.get("/api/status")
    def api_status():
        return jsonify(state.summary())

    @app.get("/api/devices")
    def api_devices():
        devices = state.devices()
        health, role, tag = request.args.get("health"), request.args.get("role"), request.args.get("tag")
        if health: devices = [d for d in devices if d.get("health") == health]
        if role: devices = [d for d in devices if role.lower() in d.get("roles", [])]
        if tag: devices = [d for d in devices if tag.lower() in d.get("tags", [])]
        return jsonify({"devices": devices})

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
