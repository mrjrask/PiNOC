"""Flask application backed exclusively by the shared state cache."""
from __future__ import annotations

import csv, io, logging, os, secrets, shutil, time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from flask import Flask, Response, abort, jsonify, render_template, request, session, redirect, url_for, g, send_file
from werkzeug.middleware.proxy_fix import ProxyFix

from pinoc.state import PiNOCState
from pinoc.integrations import sanitize
from pinoc.integrations.adsb import compare as compare_adsb
from pinoc.security import SecurityManager, install_security, redact, restore_redacted
from pinoc.actions import ActionDispatcher, ActionError
from pinoc.collectors.fleet import redact_log_line
from pinoc.development import DevelopmentGateway, DevError, PROTOCOL_VERSION
from pinoc.config_store import atomic_save, validate_config
from pinoc.playbooks import load_playbooks, match as match_playbook
from pinoc.history import storage_forecast

PROMETHEUS_HEALTH = {"healthy": 0, "maintenance": 0, "warning": 1, "degraded": 2, "critical": 3, "offline": 4}

PROMETHEUS_HELP = {
    "pinoc_fleet_devices_total": "Number of devices known to the fleet.",
    "pinoc_fleet_devices_online": "Number of fleet devices with current telemetry.",
    "pinoc_last_collection_timestamp_seconds": "Unix time of the last successful fleet collection.",
    "pinoc_uptime_seconds": "PiNOC process uptime in seconds.",
    "pinoc_device_up": "1 when the device is online, 0 otherwise.",
    "pinoc_device_health": "Device health: 0 healthy, 1 warning, 2 degraded, 3 critical, 4 offline (maintenance is reported as healthy).",
    "pinoc_device_cpu_utilization_percent": "Current CPU utilization in percent.",
    "pinoc_device_cpu_temperature_celsius": "Current CPU temperature in Celsius.",
    "pinoc_device_memory_percent": "Memory utilization in percent.",
    "pinoc_device_uptime_seconds": "Device uptime in seconds.",
    "pinoc_device_last_collection_timestamp_seconds": "Unix time of the device's last successful collection.",
    "pinoc_device_services_failed": "Number of monitored services not running on the device.",
    "pinoc_device_disk_used_percent": "Filesystem usage in percent per mount point.",
    "pinoc_device_media_errors": "1 when storage media is reporting kernel I/O errors.",
    "pinoc_alerts_total": "Open (unresolved) alerts by severity and state.",
    "pinoc_database_state": "History database state: 1 for the current state among ok, unavailable, disabled.",
}


def escape_label(value: Any) -> str:
    """Escape a label value for the Prometheus text exposition format."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render_prometheus(samples: List[tuple]) -> str:
    """Render (name, labels, value) tuples as Prometheus text format 0.0.4."""
    lines: List[str] = []
    typed: Set[str] = set()
    for name, labels, value in samples:
        if value is None or isinstance(value, bool):
            continue
        if name not in typed:
            typed.add(name)
            lines.append(f"# HELP {name} {PROMETHEUS_HELP.get(name, 'PiNOC metric.')}")
            lines.append(f"# TYPE {name} gauge")
        number = f"{value:g}" if isinstance(value, float) else str(value)
        labels = "{" + ",".join(f'{key}="{escape_label(item)}"' for key, item in labels.items()) + "}" if labels else ""
        lines.append(f"{name}{labels} {number}")
    return "\n".join(lines)


def collect_prometheus_samples(state: PiNOCState, history: Any, include_alerts: bool = True) -> List[tuple]:
    """Gauge samples for the /metrics endpoint from the shared state cache.

    ``include_alerts`` mirrors the ``alerts.read`` permission: a token that
    only reads the fleet must not export the alert series, matching the scope
    boundary enforced by ``/api/alerts`` and ``/api/overview``.
    """
    samples: List[tuple] = []
    summary = state.summary()
    samples.append(("pinoc_fleet_devices_total", {}, float(summary["devices"])))
    samples.append(("pinoc_fleet_devices_online", {}, float(summary["online"])))
    if summary.get("started_at"):
        samples.append(("pinoc_uptime_seconds", {}, max(0, int(time.time() - datetime.fromisoformat(summary["started_at"]).timestamp()))))
    if summary.get("last_collection"):
        samples.append(("pinoc_last_collection_timestamp_seconds", {}, int(datetime.fromisoformat(summary["last_collection"]).timestamp())))
    for device in state.devices():
        labels = {"device": device.get("id") or device.get("hostname") or "unknown"}
        samples.append(("pinoc_device_up", labels, 1.0 if device.get("online") else 0.0))
        samples.append(("pinoc_device_health", labels, float(PROMETHEUS_HEALTH.get(device.get("health"), 4))))
        cpu = device.get("cpu") or {}
        samples.append(("pinoc_device_cpu_utilization_percent", labels, cpu.get("utilization_percent")))
        samples.append(("pinoc_device_cpu_temperature_celsius", labels, cpu.get("temperature_c")))
        samples.append(("pinoc_device_memory_percent", labels, (device.get("memory") or {}).get("percent")))
        samples.append(("pinoc_device_uptime_seconds", labels, device.get("uptime_seconds")))
        if device.get("last_successful_collection"):
            samples.append(("pinoc_device_last_collection_timestamp_seconds", labels, int(datetime.fromisoformat(device["last_successful_collection"]).timestamp())))
        # The health evaluator and alert logic treat every state except
        # running/activating as failed (deactivating, unknown, ...).
        samples.append(("pinoc_device_services_failed", labels, float(
            sum(1 for service in device.get("services", []) if service.get("state") not in ("running", "activating")))))
        for disk in device.get("storage", []):
            mount = disk.get("mount_point") or disk.get("path")
            if mount and disk.get("percent") is not None:
                samples.append(("pinoc_device_disk_used_percent", {**labels, "mount": mount}, float(disk["percent"])))
        for medium in device.get("media", []):
            samples.append(("pinoc_device_media_errors", {**labels, "medium": medium.get("device") or "unknown"},
                            1.0 if medium.get("media_errors") else 0.0))
    if include_alerts:
        alert_counts: Dict[tuple, int] = {}
        for alert in state.alerts():
            key = (str(alert.get("severity") or "info"), str(alert.get("state") or "active"))
            alert_counts[key] = alert_counts.get(key, 0) + 1
        for (severity, alert_state), count in sorted(alert_counts.items()):
            samples.append(("pinoc_alerts_total", {"severity": severity, "state": alert_state}, float(count)))
    database_state = history.db.status()["status"] if history else "disabled"
    for candidate in ("ok", "unavailable", "disabled"):
        samples.append(("pinoc_database_state", {"state": candidate}, 1.0 if database_state == candidate else 0.0))
    return samples


def csv_safe(value: Any) -> Any:
    """Neutralize spreadsheet formula evaluation for a single exported cell.

    ``csv.writer`` quotes cells containing commas and quotes, but the viewing
    application still evaluates text that begins with ``=``, ``+``, ``-``, or
    ``@`` (CSV injection). A leading apostrophe forces the cell to be stored
    as text. Importers may also skip leading control characters (tab,
    carriage return, line feed) before applying that rule, so the marker is
    inspected past them and the apostrophe is still prefixed to the original
    value. Numeric values pass through untouched so exported metrics keep
    their natural representation.
    """
    if value is None:
        return ""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    text = str(value)
    if text.lstrip("\t\r\n")[:1] in {"=", "+", "-", "@"}:
        return "'" + text
    return text


def fleet_aggregates(devices: List[Dict[str, Any]], history: Any = None) -> Dict[str, Any]:
    """Fleet-wide rollup for the dashboard.

    Live values are averaged or summed across online devices from the state
    cache. When a history store is available, a 24-hour trend (fleet-averaged
    CPU, temperature, memory, network throughput, storage usage) and a fleet
    storage-growth forecast from the per-mount storage_forecast() are added.
    """
    online = [d for d in devices if d.get("online")]
    def average(values):
        values = [v for v in values if v is not None]
        return round(sum(values) / len(values), 1) if values else None
    temps = [d.get("cpu", {}).get("temperature_c") for d in online]
    storage_total = storage_used = 0
    storage_percents: List[float] = []
    mounts: List[tuple] = []
    for d in online:
        for x in d.get("storage", []):
            total = int(x.get("total") or 0)
            if total:
                storage_total += total
                storage_used += int(x.get("used") or 0)
                mounts.append((d.get("id"), x.get("mount_point") or x.get("path") or "", int(x.get("used") or 0)))
            if x.get("percent") is not None:
                storage_percents.append(x["percent"])
    uptimes = sorted(int(d["uptime_seconds"]) for d in online if d.get("uptime_seconds"))
    result: Dict[str, Any] = {
        "online_devices": len(online),
        "cpu_average_percent": average([d.get("cpu", {}).get("utilization_percent") for d in online]),
        "cpu_max_temperature_c": round(max(t for t in temps if t is not None), 1) if any(t is not None for t in temps) else None,
        "memory_average_percent": average([d.get("memory", {}).get("percent") for d in online]),
        "storage_total_bytes": storage_total or None,
        "storage_used_bytes": storage_used if storage_total else None,
        "storage_average_percent": average(storage_percents),
        "rx_rate_bps": sum(int(d.get("network", {}).get("rx_rate") or 0) for d in online) or None,
        "tx_rate_bps": sum(int(d.get("network", {}).get("tx_rate") or 0) for d in online) or None,
        "uptime_min_seconds": uptimes[0] if uptimes else None,
        "uptime_max_seconds": uptimes[-1] if uptimes else None,
        "storage_forecast": None,
        "sparkline": None,
    }
    if history is None or not history.db.available:
        return result
    now = datetime.now(timezone.utc)
    trend_start = (now - timedelta(hours=24)).isoformat()
    points: Dict[str, Dict[str, Any]] = {}
    for row in history.db.rows(
            "SELECT strftime('%Y-%m-%dT%H:00:00+00:00', timestamp) AS bucket, "
            "AVG(cpu_percent) AS avg_cpu, AVG(cpu_temp_c) AS avg_temp, AVG(memory_percent) AS avg_memory "
            "FROM device_metrics WHERE timestamp>=? GROUP BY bucket", (trend_start,)):
        points[row["bucket"]] = {"timestamp": row["bucket"], "avg_cpu": row["avg_cpu"],
                                  "avg_temp": row["avg_temp"], "avg_memory": row["avg_memory"]}
    for row in history.db.rows(
            "SELECT strftime('%Y-%m-%dT%H:00:00+00:00', timestamp) AS bucket, "
            "AVG(rx_rate_bps) AS rx_rate_bps, AVG(tx_rate_bps) AS tx_rate_bps "
            "FROM network_metrics WHERE timestamp>=? GROUP BY bucket", (trend_start,)):
        entry = points.setdefault(row["bucket"], {"timestamp": row["bucket"]})
        entry["rx_rate_bps"] = row["rx_rate_bps"]
        entry["tx_rate_bps"] = row["tx_rate_bps"]
    for row in history.db.rows(
            "SELECT bucket, SUM(used_bytes) AS used, SUM(total_bytes) AS total FROM ("
            "SELECT strftime('%Y-%m-%dT%H:00:00+00:00', timestamp) AS bucket, used_bytes, total_bytes, "
            "ROW_NUMBER() OVER (PARTITION BY device_id, mount_point, "
            "strftime('%Y-%m-%dT%H:00:00+00:00', timestamp) ORDER BY timestamp DESC) AS sample_rank "
            "FROM storage_metrics WHERE timestamp>=?) WHERE sample_rank=1 GROUP BY bucket", (trend_start,)):
        entry = points.setdefault(row["bucket"], {"timestamp": row["bucket"]})
        if row["total"]:
            entry["storage_percent"] = round(row["used"] * 100.0 / row["total"], 1)
    result["sparkline"] = [points[bucket] for bucket in sorted(points)][-24:]
    # Fleet storage growth: the shortest forecast across the highest-use mounts.
    days: List[float] = []
    statuses: List[str] = []
    for device_id, mount, used in sorted(mounts, key=lambda item: -item[2])[:12]:
        if not mount:
            continue
        rows = history.db.rows(
            "SELECT timestamp, used_bytes, total_bytes FROM storage_metrics WHERE device_id=? AND mount_point=? AND timestamp>=? ORDER BY timestamp",
            (device_id, mount, (now - timedelta(days=30)).isoformat()))
        forecast = storage_forecast(rows)
        statuses.append(forecast["status"])
        if forecast.get("estimated_days_remaining") is not None:
            days.append(forecast["estimated_days_remaining"])
    if days:
        status = "growing"
    elif "stable" in statuses:
        status = "stable"
    elif "decreasing" in statuses:
        status = "decreasing"
    else:
        status = statuses[0] if statuses else "insufficient"
    result["storage_forecast"] = {"status": status,
                                   "estimated_days_remaining": round(min(days), 1) if days else None}
    return result


def create_app(state: PiNOCState, config: Optional[Dict[str, Any]] = None, history: Any = None, coordinator: Any = None, notifications: Any = None, backups: Any = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.update(config or {})
    trusted_proxy_count=int(app.config.get("TRUSTED_PROXY_COUNT",0))
    if trusted_proxy_count:
        # Only trust forwarded client addresses when the operator explicitly
        # declares how many reverse proxies are in front of this application.
        app.wsgi_app=ProxyFix(app.wsgi_app,x_for=trusted_proxy_count)
    app.secret_key=app.config.get("SECRET_KEY") or os.getenv("PINOC_SECRET_KEY") or secrets.token_hex(32)
    app.config.update(SESSION_COOKIE_SECURE=bool(app.config.get("SESSION_COOKIE_SECURE",False)),SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE="Lax")
    auth_enabled=bool(app.config.get("AUTH_ENABLED",False))
    security_db=history.db if history else app.config.get("DATABASE")
    # Actions, maintenance, audit, and development jobs need the persistence
    # schema even when metric history and authentication are both disabled.
    if security_db and not security_db.available:security_db.initialize()
    security=SecurityManager(security_db,auth_enabled,app.config.get("RATE_LIMIT")) if security_db else None
    actions=ActionDispatcher(history.db,state,coordinator,int(app.config.get("ACTION_WORKERS",2))) if history else None
    development=DevelopmentGateway(history.db,app.config.get("DEV_ARTIFACT_ROOT","data/jobs"),app.config.get("DEV_CONFIG",{})) if history else None
    playbooks=load_playbooks(app.config.get("PINOC_CONFIG") or {},known_actions=actions.registry.keys() if actions else None)
    # Flask/Werkzeug enforces this while reading the stream, before the public
    # agent endpoints buffer a body for HMAC verification.  Allow enough room
    # for the configured artifact total after base64 and JSON encoding.
    artifact_total=int(app.config.get("DEV_CONFIG",{}).get("artifact_total_limit_bytes",25*1024*1024))
    app.config["MAX_CONTENT_LENGTH"]=int(app.config.get("DEV_AGENT_MAX_REQUEST_BYTES",artifact_total*4//3+1024*1024))
    app.config["TOKEN_SCOPE_PERMISSIONS"]={
        "api_session":"view","prometheus_metrics":"view",
        "api_status":"view","api_overview":"view","api_devices":"view","api_device":"view","api_integrations":"view","api_playbooks":"view",
        "api_notifications":"config.write","api_notifications_test":"config.write",
        "api_device_integrations":"view","api_device_integration":"view","api_adsb":"view","api_displays":"view",
        "api_deployments":"view","api_software":"view","api_network_inventory":"view","api_services":"view",
        "api_alerts":"alerts.read","api_alert":"alerts.read",
        "api_events":"history.read","device_events":"history.read","metrics":"history.read","forecast":"history.read","device_logs":"history.read",
        "action_list":"actions.execute","action_result":"actions.execute","api_audit":"config.write","database_status":"config.write",
    }
    if security:install_security(app,security)
    app.extensions["pinoc_security"]=security;app.extensions["pinoc_actions"]=actions
    app.extensions["pinoc_development"]=development;app.extensions["pinoc_playbooks"]=playbooks

    @app.route("/login",methods=["GET","POST"])
    def login():
        if not security or not security.enabled:return redirect(url_for("dashboard"))
        error=None
        if request.method=="POST":
            row,error,locked=security.authenticate(request.form.get("username",""),request.form.get("password",""),request.remote_addr or "unknown")
            if row:
                session.clear();session["username"]=row["username"];session["role"]=row["role"];session["csrf_token"]=secrets.token_urlsafe(32);session.permanent=True
                actions.audit(row["username"],row["role"],request.remote_addr,None,"auth.login",None,{},"allowed","succeeded") if actions else None
                return redirect(url_for("dashboard"))
            if locked:
                return jsonify({"error":error}),429
            actions.audit(request.form.get("username") or "unknown","viewer",request.remote_addr,None,"auth.login",None,{},"denied","failed",error="invalid credentials") if actions else None
        return render_template("login.html",error=error)

    @app.post("/logout")
    def logout():
        who=session.get("username","trusted-lan");role=session.get("role","viewer")
        actions.audit(who,role,request.remote_addr,None,"auth.logout",None,{},"allowed","succeeded") if actions else None
        session.clear();return redirect(url_for("login"))

    @app.get("/api/session")
    def api_session():return jsonify({"user":g.identity,"csrf_token":session.get("csrf_token")})

    @app.get("/api/settings")
    def api_settings():
        if not security.allowed(g.identity,"config.write"):return jsonify({"error":"permission denied"}),403
        return jsonify(redact(app.config.get("PINOC_CONFIG",{})))
    @app.put("/api/settings")
    def save_settings():
        if not security.allowed(g.identity,"config.write"):return jsonify({"error":"permission denied"}),403
        value=request.get_json(silent=True)
        try:
            value=restore_redacted(value,app.config.get("PINOC_CONFIG",{}))
            validate_config(value,app.config.get("APP_DIR","."));atomic_save(app.config.get("CONFIG_PATH","config.json"),value)
        except (ValueError,OSError) as exc:return jsonify({"error":str(redact(exc))}),400
        app.config["PINOC_CONFIG"]=value
        actions.audit(g.identity["username"],g.identity["role"],request.remote_addr,None,"config.update",None,{},"allowed","succeeded") if actions else None
        return jsonify({"ok":True,"restart_required":True})
    @app.get("/api/notifications")
    def api_notifications():
        if not security.allowed(g.identity,"config.write"):return jsonify({"error":"permission denied"}),403
        if notifications is None:return jsonify({"enabled":False,"channels":[]})
        return jsonify(redact(notifications.status()))
    @app.post("/api/notifications/test")
    def api_notifications_test():
        if not security.allowed(g.identity,"config.write"):return jsonify({"error":"permission denied"}),403
        if notifications is None:return jsonify({"ok":False,"error":"notifications are not running"}),409
        channel=(request.get_json(silent=True) or {}).get("channel")
        result=notifications.test_channel(str(channel)) if channel else None
        if result is None:return jsonify({"ok":False,"error":"unknown channel"}),404
        actions.audit(g.identity["username"],g.identity["role"],request.remote_addr,None,"notifications.test",channel,{},"allowed","succeeded" if result["ok"] else "failed",error=result["error"]) if actions else None
        return jsonify(result)
    @app.get("/api/backup")
    def backup_status():
        if not security.allowed(g.identity,"config.write"):return jsonify({"error":"administrator required"}),403
        if backups is None:return jsonify({"enabled":False,"destination":None,"interval_hours":None,"keep":None,"last_run":None,"last_bundle":None,"last_size_bytes":None,"last_error":None,"signing_key_configured":False})
        return jsonify(backups.status())
    @app.post("/api/backup/run")
    def backup_run():
        if not security.allowed(g.identity,"config.write"):return jsonify({"error":"administrator required"}),403
        if backups is None or not backups.enabled:return jsonify({"error":"scheduled backups are not configured"}),409
        status=backups.run_backup()
        actions.audit(g.identity["username"],g.identity["role"],request.remote_addr,None,"backup.run",None,{},"allowed","succeeded" if not status.get("last_error") else "failed",error=status.get("last_error")) if actions else None
        return jsonify(status)
    @app.get("/api/backup/export")
    def backup_export():
        if not security.allowed(g.identity,"config.write"):return jsonify({"error":"administrator required"}),403
        from pinoc.backup import BackupError, build_bundle
        import tempfile
        staging=Path(tempfile.mkdtemp(prefix="pinoc-export-"))
        try:
            db=history.db if history else app.config.get("DATABASE")
            if db is None or not getattr(db,"available",False):raise BackupError("database unavailable")
            key=(backups.signing_key() if backups is not None else None) or os.environ.get("PINOC_BACKUP_KEY") or None
            metadata=build_bundle(app.config.get("APP_DIR","."),staging/"pinoc-bundle.tar",db,config=app.config.get("PINOC_CONFIG"),signing_key=key)
        except BackupError as exc:
            shutil.rmtree(staging,ignore_errors=True)
            actions.audit(g.identity["username"],g.identity["role"],request.remote_addr,None,"backup.export",None,{},"allowed","failed",error=str(redact(exc))[:500]) if actions else None
            return jsonify({"error":str(redact(exc))}),500
        except Exception as exc:
            shutil.rmtree(staging,ignore_errors=True)
            actions.audit(g.identity["username"],g.identity["role"],request.remote_addr,None,"backup.export",None,{},"allowed","failed",error=str(redact(exc))[:500]) if actions else None
            return jsonify({"error":str(redact(exc))}),500
        actions.audit(g.identity["username"],g.identity["role"],request.remote_addr,None,"backup.export",None,{},"allowed","succeeded") if actions else None
        bundle_path=staging/"pinoc-bundle.tar"
        stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        response=send_file(bundle_path,as_attachment=True,download_name=f"pinoc-bundle-{stamp}.tar")
        response.headers["Content-Type"]="application/x-tar"
        def _cleanup():
            shutil.rmtree(staging,ignore_errors=True)
        response.call_on_close(_cleanup)
        return response
    @app.get("/api/users")
    def users():
        if not security.allowed(g.identity,"users.write"):return jsonify({"error":"permission denied"}),403
        return jsonify({"users":history.db.rows("SELECT username,role,enabled,created_at,last_login FROM users ORDER BY username")})
    @app.post("/api/users")
    def create_user():
        if not security.allowed(g.identity,"users.write"):return jsonify({"error":"permission denied"}),403
        body=request.get_json(silent=True) or {}
        try:security.create_user(str(body.get("username","")),str(body.get("password","")),str(body.get("role","viewer")))
        except (ValueError,Exception) as exc:
            if isinstance(exc,ValueError):return jsonify({"error":str(exc)}),400
            return jsonify({"error":"unable to create user"}),409
        actions.audit(g.identity["username"],g.identity["role"],request.remote_addr,None,"user.create",body.get("username"),{"role":body.get("role")},"allowed","succeeded");return jsonify({"ok":True}),201
    @app.post("/api/tokens")
    def create_token():
        if not security.allowed(g.identity,"users.write"):return jsonify({"error":"permission denied"}),403
        body=request.get_json(silent=True) or {}
        try:token=security.create_token(str(body.get("owner") or g.identity["username"]),body.get("scopes",[]),body.get("devices"),body.get("workspaces"),body.get("job_types"))
        except ValueError as exc:return jsonify({"error":str(exc)}),400
        return jsonify({"token":token,"display_once":True}),201
    @app.delete("/api/tokens/<token_id>")
    def revoke_token(token_id):
        if not security.allowed(g.identity,"users.write"):return jsonify({"error":"permission denied"}),403
        history.db.execute("UPDATE api_tokens SET enabled=0 WHERE token_id=?",(token_id,));return jsonify({"ok":True})

    @app.get("/")
    def dashboard():
        return render_template("dashboard.html")

    @app.get("/devices/<device_id>")
    def device_page(device_id: str):
        if state.device(device_id) is None:
            abort(404)
        return render_template("device.html", device_id=device_id)

    @app.get("/alerts")
    def alerts_page(): return render_template("alerts.html")

    @app.get("/events")
    def events_page(): return render_template("events.html")

    @app.get("/settings/status")
    def status_page(): return render_template("status.html")

    @app.get("/settings")
    def settings_page():
        if security and not security.allowed(g.identity,"config.write"):abort(403)
        return render_template("settings.html")

    @app.get("/audit")
    def audit_page(): return render_template("audit.html")

    @app.get("/agents")
    def agents_page(): return render_template("development.html",view="agents")
    @app.get("/workspaces")
    def workspaces_page(): return render_template("development.html",view="workspaces")
    @app.get("/jobs")
    def jobs_page(): return render_template("development.html",view="jobs")
    @app.get("/jobs/<job_id>")
    def job_page(job_id): return render_template("development.html",view="detail",job_id=job_id)
    @app.get("/jobs/approvals")
    def approvals_page(): return render_template("development.html",view="approvals")

    def dev_identity(scope=None):
        ident=g.get("identity")
        if not ident:return None
        if ident.get("token") and scope and scope not in ident.get("scopes",[]):return None
        if not ident.get("token") and ident.get("role") not in {"operator","administrator"}:return None
        return ident
    def dev_error(exc):return jsonify({"error":str(exc),"error_type":exc.error_type}),exc.status
    def authenticate_agent():
        raw=request.get_data(cache=True)
        return development.authenticate_agent(request.headers.get("X-PiNOC-Agent",""),request.headers.get("X-PiNOC-Timestamp",""),request.headers.get("X-PiNOC-Nonce",""),raw,request.headers.get("X-PiNOC-Signature",""))

    @app.post("/api/v1/agent/enroll")
    def agent_enroll():
        try:return jsonify(development.enroll(request.get_json(silent=True) or {})),201
        except DevError as exc:return dev_error(exc)
    @app.post("/api/v1/agent/heartbeat")
    def agent_heartbeat():
        try:
            agent=authenticate_agent();body=request.get_json(silent=True) or {}
            if body.get("protocol_version")!=PROTOCOL_VERSION:raise DevError("agent protocol incompatible","protocol_incompatible",409)
            development.heartbeat(agent["agent_id"],body)
            job=None if body.get("current_job_id") else development.claim(agent["device_id"])
            return jsonify({"job":job,"cancel":development.cancellations(agent["device_id"])})
        except DevError as exc:return dev_error(exc)
    @app.post("/api/v1/agent/jobs/<job_id>/result")
    def agent_result(job_id):
        try:return jsonify(development.result(authenticate_agent(),job_id,request.get_json(silent=True) or {}))
        except DevError as exc:return dev_error(exc)

    @app.get("/api/v1/dev/agents")
    def dev_agents():
        if not dev_identity("dev:read"):return jsonify({"error":"dev:read required"}),403
        return jsonify({"agents":development.agents()})
    @app.post("/api/v1/dev/agents/enrollment-codes")
    def enrollment_code():
        if not security.allowed(g.identity,"users.write"):return jsonify({"error":"administrator required"}),403
        body=request.get_json(silent=True) or {}
        try:code=development.enrollment_code(str(body.get("device_id","")),g.identity["username"],int(body.get("ttl_seconds",600)));return jsonify({"enrollment_code":code,"display_once":True}),201
        except DevError as exc:return dev_error(exc)
    @app.post("/api/v1/dev/agents/<agent_id>/rotate")
    def rotate_agent(agent_id):
        if not security.allowed(g.identity,"users.write"):return jsonify({"error":"administrator required"}),403
        try:return jsonify({"credential":development.rotate(agent_id),"display_once":True})
        except DevError as exc:return dev_error(exc)
    @app.delete("/api/v1/dev/agents/<agent_id>/credential")
    def revoke_agent(agent_id):
        if not security.allowed(g.identity,"users.write"):return jsonify({"error":"administrator required"}),403
        development.db.execute("UPDATE agents SET credential_revoked=1,status='credential_revoked' WHERE agent_id=?",(agent_id,));development.audit(g.identity,request.remote_addr,None,"agent.credential.revoke",agent_id,{},"allowed","succeeded");return jsonify({"ok":True})
    @app.get("/api/v1/dev/workspaces")
    def dev_workspaces():
        ident=dev_identity("dev:read")
        if not ident:return jsonify({"error":"dev:read required"}),403
        rows=development.workspaces();rows=[x for x in rows if (not ident.get("devices") or x["device_id"] in ident["devices"]) and (not ident.get("workspaces") or x["workspace_id"] in ident["workspaces"])]
        return jsonify({"workspaces":rows})
    @app.put("/api/v1/dev/workspaces/<workspace_id>")
    def save_workspace(workspace_id):
        if not security.allowed(g.identity,"config.write"):return jsonify({"error":"administrator required"}),403
        try:return jsonify(development.save_workspace({**(request.get_json(silent=True) or {}),"workspace_id":workspace_id}))
        except DevError as exc:return dev_error(exc)
    @app.get("/api/v1/dev/jobs")
    def dev_jobs():
        ident=dev_identity("dev:read")
        if not ident:return jsonify({"error":"dev:read required"}),403
        return jsonify({"jobs":development.jobs(ident,request.args.get("limit",100,type=int))})
    @app.get("/api/v1/dev/approvals")
    def dev_approvals():
        if not security.allowed(g.identity,"config.write"):return jsonify({"error":"administrator required"}),403
        return jsonify({"approvals":development.approvals()})
    @app.post("/api/v1/dev/approvals/<approval_id>/<decision>")
    def decide_approval(approval_id,decision):
        if not security.allowed(g.identity,"config.write"):return jsonify({"error":"administrator required"}),403
        if decision not in {"approve","reject"}:return jsonify({"error":"invalid decision"}),400
        try:return jsonify(development.decide(g.identity,approval_id,decision=="approve",(request.get_json(silent=True) or {}).get("reason","")))
        except DevError as exc:return dev_error(exc)
    @app.post("/api/v1/dev/jobs")
    def submit_dev_job():
        ident=dev_identity()
        if not ident:return jsonify({"error":"development authentication required"}),403
        try:return jsonify(development.submit(ident,request.get_json(silent=True) or {},request.remote_addr)),202
        except DevError as exc:return dev_error(exc)
    @app.post("/api/v1/dev/matrices")
    def submit_matrix():
        ident=dev_identity("dev:test")
        if not ident:return jsonify({"error":"dev:test required"}),403
        try:return jsonify(development.matrix(ident,request.get_json(silent=True) or {},request.remote_addr)),202
        except DevError as exc:return dev_error(exc)
    @app.get("/api/v1/dev/jobs/<job_id>")
    def dev_job(job_id):
        ident=dev_identity("dev:read");job=development.job(job_id)
        if not ident:return jsonify({"error":"dev:read required"}),403
        if not job:return jsonify({"error":"job not found"}),404
        try:development._restricted(ident,job["device_id"],job.get("workspace_id"),job["job_type"])
        except DevError as exc:return dev_error(exc)
        return jsonify({**job,"artifacts":development.artifacts(job_id)})
    @app.delete("/api/v1/dev/jobs/<job_id>")
    def cancel_dev_job(job_id):
        ident=dev_identity("dev:cancel")
        if not ident:return jsonify({"error":"dev:cancel required"}),403
        try:return jsonify(development.cancel(ident,job_id,request.remote_addr))
        except DevError as exc:return dev_error(exc)
    @app.get("/api/v1/dev/jobs/<job_id>/artifacts")
    def dev_artifacts(job_id):
        ident=dev_identity("dev:artifacts");job=development.job(job_id)
        if not ident:return jsonify({"error":"dev:artifacts required"}),403
        if not job:return jsonify({"error":"job not found"}),404
        try:development._restricted(ident,job["device_id"],job.get("workspace_id"),job["job_type"])
        except DevError as exc:return dev_error(exc)
        return jsonify({"artifacts":development.artifacts(job_id)})
    @app.get("/api/v1/dev/jobs/<job_id>/artifacts/<artifact_id>")
    def dev_artifact(job_id,artifact_id):
        ident=dev_identity("dev:artifacts");job=development.job(job_id)
        if not ident:return jsonify({"error":"dev:artifacts required"}),403
        if not job:return jsonify({"error":"job not found"}),404
        try:development._restricted(ident,job["device_id"],job.get("workspace_id"),job["job_type"])
        except DevError as exc:return dev_error(exc)
        row,path=development.artifact(job_id,artifact_id)
        return send_file(path,mimetype=row["content_type"],as_attachment=True,download_name=row["name"]) if row else (jsonify({"error":"artifact not found"}),404)

    @app.get("/integrations")
    @app.get("/adsb")
    @app.get("/displays")
    @app.get("/software")
    @app.get("/network-inventory")
    def integration_page(): return render_template("integrations.html", endpoint=request.path)

    @app.get("/health")
    def health():
        summary = state.summary()
        status = "starting"
        if summary["last_collection"]:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(summary["last_collection"])).total_seconds()
            status = "ok" if age <= float(app.config.get("HEALTH_STALE_SECONDS", 120)) else "degraded"
        database=history.db.status() if history else {"status":"disabled"}
        if status=="ok" and database["status"] not in ("ok","disabled"): status="degraded"
        response_code = 200 if status == "ok" else 503
        return jsonify({"status": status, "devices": summary["devices"], "online": summary["online"],
                        "healthy": summary["healthy"], "warning": summary["warning"],
                        "warnings": summary["warnings"], "degraded": summary["degraded"],
                        "critical": summary["critical"], "offline": summary["offline"],
                        "collectors": "ok" if summary["last_collection"] else "starting","database":database}), response_code

    @app.get("/metrics")
    def prometheus_metrics():
        if security is not None and not security.allowed(g.identity, "view"):
            return Response("permission denied", status=403, content_type="text/plain; charset=utf-8")
        include_alerts = security is None or security.allowed(g.identity, "alerts.read")
        body = render_prometheus(collect_prometheus_samples(state, history, include_alerts)) + "\n"
        return Response(body, content_type="text/plain; version=0.0.4; charset=utf-8")

    @app.get("/api/status")
    def api_status():
        return jsonify(state.summary())

    @app.get("/api/overview")
    def api_overview():
        """Return the dashboard's operational context in one cached request."""
        can_read_alerts = security is None or security.allowed(g.identity, "alerts.read")
        can_read_history = security is None or security.allowed(g.identity, "history.read")
        devices = state.devices()
        integration_counts: Dict[str, int] = {}
        for device in devices:
            for name in device.get("integrations", {}):
                integration_counts[name] = integration_counts.get(name, 0) + 1
        alerts = (
            [alert for alert in state.alerts() if alert.get("state") == "active"]
            if can_read_alerts else []
        )
        events = []
        if history and history.db.available:
            if can_read_alerts:
                alerts = history.db.rows(
                    "SELECT * FROM alerts WHERE resolved_at IS NULL AND state='active' ORDER BY "
                    "CASE severity WHEN 'critical' THEN 3 WHEN 'degraded' THEN 2 "
                    "WHEN 'warning' THEN 1 ELSE 0 END DESC, last_seen_at DESC LIMIT 5"
                )
            if can_read_history:
                events = history.db.rows(
                    "SELECT * FROM events ORDER BY timestamp DESC LIMIT 8"
                )
        return jsonify({
            "summary": state.summary(),
            "aggregates": fleet_aggregates(devices, history if can_read_history else None),
            "active_alerts": sanitize(alerts[:5]),
            "recent_events": sanitize(events),
            "integration_counts": integration_counts,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        })

    @app.get("/api/devices")
    def api_devices():
        devices = state.devices()
        for device in devices:
            device.pop("logs", None)
        health, role, tag = request.args.get("health"), request.args.get("role"), request.args.get("tag")
        if health: devices = [d for d in devices if d.get("health") == health]
        if role: devices = [d for d in devices if role.lower() in d.get("roles", [])]
        if tag: devices = [d for d in devices if tag.lower() in d.get("tags", [])]
        return jsonify({"devices": devices})

    @app.get("/api/devices/<device_id>")
    def api_device(device_id: str):
        device = state.device(device_id)
        if device:
            device.pop("logs", None)
        return jsonify(device) if device else (jsonify({"error": "device not found"}), 404)

    def _integration_rows(name=None):
        rows=[]
        for device in state.devices():
            for key,value in device.get("integrations",{}).items():
                if name is None or key==name: rows.append(sanitize({"device_id":device["id"],"friendly_name":device["friendly_name"],**value}))
        return rows

    @app.get("/api/integrations")
    def api_integrations(): return jsonify({"integrations":_integration_rows()})
    @app.get("/api/devices/<device_id>/integrations")
    def api_device_integrations(device_id):
        device=state.device(device_id)
        return jsonify({"integrations":sanitize(device.get("integrations",{}))}) if device else (jsonify({"error":"device not found"}),404)
    @app.get("/api/devices/<device_id>/integrations/<name>")
    def api_device_integration(device_id,name):
        device=state.device(device_id); value=(device or {}).get("integrations",{}).get(name)
        return jsonify(sanitize(value)) if value is not None else (jsonify({"error":"integration not found"}),404)
    @app.get("/api/adsb")
    def api_adsb(): return jsonify(compare_adsb(_integration_rows("adsb")))
    @app.get("/api/displays")
    def api_displays(): return jsonify({"displays":_integration_rows("desk_display")})
    @app.get("/api/deployments")
    def api_deployments(): return jsonify({"deployments":_integration_rows("git")})
    @app.get("/api/software")
    def api_software():
        return jsonify({"devices":[{"device_id":d["id"],"os":d.get("os"),"os_version":d.get("os_version"),"kernel":d.get("kernel"),"packages":sanitize(d.get("integrations",{}).get("packages")),"git":sanitize(d.get("integrations",{}).get("git"))} for d in state.devices()]})
    @app.get("/api/network-inventory")
    def api_network_inventory():
        rows=history.db.rows("SELECT * FROM network_inventory ORDER BY last_seen DESC") if history and history.db.available else []
        return jsonify({"devices":sanitize(rows)})

    @app.get("/api/devices/<device_id>/services")
    def api_services(device_id: str):
        device = state.device(device_id)
        return jsonify({"services": device.get("services", [])}) if device else (jsonify({"error": "device not found"}), 404)

    @app.get("/api/alerts")
    def api_alerts():
        if not history:return jsonify({"alerts":[{**row,"playbook":match_playbook(playbooks,row.get("alert_type"))} for row in state.alerts()]})
        page,limit=_page(); where,args=["1=1"],[]
        for field,column in (("device","device_id"),("severity","severity"),("state","state"),("type","alert_type")):
            if request.args.get(field):where.append(f"{column}=?");args.append(request.args[field])
        total=history.db.scalar("SELECT COUNT(*) FROM alerts WHERE "+" AND ".join(where),args) or 0
        rows=history.db.rows("SELECT * FROM alerts WHERE "+" AND ".join(where)+" ORDER BY CASE severity WHEN 'critical' THEN 3 WHEN 'degraded' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END DESC, opened_at DESC LIMIT ? OFFSET ?",args+[limit,(page-1)*limit])
        return jsonify({"alerts":[{**row,"playbook":match_playbook(playbooks,row.get("alert_type"))} for row in rows],"page":page,"limit":limit,"total":total})

    def _page():
        try:return max(1,int(request.args.get("page",1))),min(200,max(1,int(request.args.get("limit",50))))
        except ValueError:abort(400,"invalid pagination")

    @app.get("/api/alerts/<int:alert_id>")
    def api_alert(alert_id):
        rows=history.db.rows("SELECT * FROM alerts WHERE alert_id=?",(alert_id,)) if history else []
        if not rows:return jsonify({"error":"alert not found"}),404
        return jsonify({**rows[0],"playbook":match_playbook(playbooks,rows[0].get("alert_type"))})

    @app.get("/api/playbooks")
    def api_playbooks():
        if security and not security.allowed(g.identity,"view"):return jsonify({"error":"permission denied"}),403
        return jsonify({"playbooks":playbooks})
    @app.post("/api/alerts/<int:alert_id>/acknowledge")
    def acknowledge(alert_id):
        if security and not security.allowed(g.identity,"alerts.write"):return jsonify({"error":"permission denied"}),403
        history.acknowledge(alert_id,g.identity["username"] if security else "local");return jsonify({"ok":True})
    @app.post("/api/alerts/<int:alert_id>/mute")
    def mute(alert_id):
        if security and not security.allowed(g.identity,"alerts.write"):return jsonify({"error":"permission denied"}),403
        body=request.get_json(silent=True) or {}; until=body.get("muted_until")
        if not until:
            try: until=(datetime.now(timezone.utc)+__import__('datetime').timedelta(seconds=min(86400,max(60,int(body.get("seconds",3600)))))).isoformat()
            except ValueError:abort(400,"invalid mute duration")
        history.mute(alert_id,until);return jsonify({"ok":True,"muted_until":until})
    @app.post("/api/alerts/<int:alert_id>/unmute")
    def unmute(alert_id):
        if security and not security.allowed(g.identity,"alerts.write"):return jsonify({"error":"permission denied"}),403
        history.unmute(alert_id);return jsonify({"ok":True})

    def submit_action(device_id,action,target=None):
        if not actions:return jsonify({"error":"actions unavailable"}),503
        identity=g.identity
        try:definition=actions.definition(action)
        except ActionError as exc:return jsonify({"error":str(exc)}),400
        if not security.allowed(identity,definition.permission):
            actions.audit((identity or {}).get("username","anonymous"),(identity or {}).get("role","none"),request.remote_addr,device_id,action,target,request.get_json(silent=True),"denied",error="permission denied")
            return jsonify({"error":"permission denied"}),403
        try:job=actions.enqueue(action,device_id,target,identity["username"],identity["role"],request.remote_addr,request.get_json(silent=True));return jsonify(job),202
        except ActionError as exc:
            actions.audit(identity["username"],identity["role"],request.remote_addr,device_id,action,target,request.get_json(silent=True),"allowed","rejected",error=str(exc));return jsonify({"error":str(exc)}),409 if "conflicting" in str(exc) else 400

    @app.post("/api/devices/<device_id>/refresh")
    def refresh_action(device_id):return submit_action(device_id,"device.refresh")
    @app.post("/api/devices/<device_id>/reboot")
    def reboot_action(device_id):return submit_action(device_id,"device.reboot")
    @app.post("/api/devices/<device_id>/shutdown")
    def shutdown_action(device_id):return submit_action(device_id,"device.shutdown")
    @app.post("/api/devices/<device_id>/services/<path:service>/<operation>")
    def service_action(device_id,service,operation):
        if operation not in {"start","stop","restart"}:return jsonify({"error":"unsupported service operation"}),404
        return submit_action(device_id,"service."+operation,service)
    @app.post("/api/devices/<device_id>/actions/<integration_action>")
    def integration_action(device_id,integration_action):return submit_action(device_id,integration_action.replace("-","."))
    @app.get("/api/actions")
    def action_list():return jsonify({"actions":actions.list(min(200,max(1,request.args.get("limit",50,type=int))))}) if actions else (jsonify({"actions":[]}),503)
    @app.get("/api/actions/<job_id>")
    def action_result(job_id):
        job=actions.get(job_id) if actions else None;return jsonify(job) if job else (jsonify({"error":"action not found"}),404)
    @app.post("/api/devices/<device_id>/maintenance")
    def maintenance(device_id):
        if not security.allowed(g.identity,"maintenance.write"):return jsonify({"error":"permission denied"}),403
        body=request.get_json(silent=True) or {};seconds=body.get("seconds")
        if seconds not in (None,1800,3600,14400,86400):return jsonify({"error":"maintenance duration must be 1800, 3600, 14400, 86400, or null"}),400
        return jsonify(actions.set_maintenance(device_id,g.identity["username"],str(body.get("reason", ""))[:500],seconds))
    @app.delete("/api/devices/<device_id>/maintenance")
    def clear_maintenance(device_id):
        if not security.allowed(g.identity,"maintenance.write"):return jsonify({"error":"permission denied"}),403
        return jsonify(actions.clear_maintenance(device_id,g.identity["username"]) or {"ok":True})
    @app.delete("/api/devices/<device_id>/expected-offline")
    def clear_expected(device_id):
        if not security.allowed(g.identity,"device.power"):return jsonify({"error":"permission denied"}),403
        history.db.execute("UPDATE device_operational_state SET expected_offline=0,expected_offline_reason=NULL,expected_offline_until=NULL,updated_at=?,updated_by=? WHERE device_id=?",(datetime.now(timezone.utc).isoformat(),g.identity["username"],device_id));return jsonify({"ok":True})
    @app.get("/api/audit")
    def api_audit():
        if not history:return jsonify({"audit":[]})
        page,limit=_page();where,args=["1=1"],[]
        for field,column in (("user","user"),("device","device_id"),("action","action"),("result","execution_result")):
            if request.args.get(field):where.append(column+"=?");args.append(request.args[field])
        if request.args.get("date"):where.append("timestamp LIKE ?");args.append(request.args["date"]+"%")
        total=history.db.scalar("SELECT COUNT(*) FROM audit_records WHERE "+" AND ".join(where),args) or 0
        rows=history.db.rows("SELECT * FROM audit_records WHERE "+" AND ".join(where)+" ORDER BY timestamp DESC LIMIT ? OFFSET ?",args+[limit,(page-1)*limit]);return jsonify({"audit":redact(rows),"page":page,"limit":limit,"total":total})

    def event_response(device_id=None):
        if not history:return jsonify({"events":[],"page":1,"total":0})
        page,limit=_page();where,args=["1=1"],[]
        if device_id:where.append("device_id=?");args.append(device_id)
        for field,column in (("device","device_id"),("severity","severity"),("type","event_type")):
            if request.args.get(field):where.append(f"{column}=?");args.append(request.args[field])
        total=history.db.scalar("SELECT COUNT(*) FROM events WHERE "+" AND ".join(where),args) or 0
        rows=history.db.rows("SELECT * FROM events WHERE "+" AND ".join(where)+" ORDER BY timestamp DESC LIMIT ? OFFSET ?",args+[limit,(page-1)*limit]);return jsonify({"events":rows,"page":page,"limit":limit,"total":total})
    @app.get("/api/events")
    def api_events():return event_response()
    @app.get("/api/devices/<device_id>/events")
    def device_events(device_id):return event_response(device_id)

    RANGES={"1h":3600,"6h":21600,"24h":86400,"7d":604800,"30d":2592000}
    @app.get("/api/devices/<device_id>/metrics")
    def metrics(device_id):
        if not history or not history.db.available:return jsonify({"error":"history unavailable","series":[]}),503
        name=request.args.get("range","24h")
        if name not in RANGES: return jsonify({"error":"range must be 1h, 6h, 24h, 7d, or 30d"}),400
        now=datetime.now(timezone.utc); start=(now-__import__('datetime').timedelta(seconds=RANGES[name])).isoformat(); resolution="raw" if RANGES[name]<=7*86400 else "mixed"
        def newest(table,columns="*",since=start):
            return history.db.rows(f"SELECT * FROM (SELECT {columns} FROM {table} WHERE device_id=? AND timestamp>=? ORDER BY timestamp DESC LIMIT 5000) ORDER BY timestamp",(device_id,since))
        if resolution=="raw":core=newest("device_metrics")
        else:
            raw_start=(now-__import__('datetime').timedelta(days=int(history.config.get("raw_retention_days",7)))).isoformat()
            core=history.db.rows("SELECT bucket AS timestamp,avg_cpu AS cpu_percent,avg_temp AS cpu_temp_c,avg_memory AS memory_percent,max_cpu,max_temp,sample_count FROM metric_aggregates WHERE device_id=? AND resolution='hourly' AND bucket>=? AND bucket<? ORDER BY bucket",(device_id,start,raw_start))+newest("device_metrics","timestamp,cpu_percent,cpu_temp_c,memory_percent,cpu_percent AS max_cpu,cpu_temp_c AS max_temp,1 AS sample_count",raw_start)
            storage=history.db.rows("SELECT bucket AS timestamp,mount_point,latest_used AS used_bytes,total_bytes,CASE WHEN total_bytes>0 THEN latest_used*100.0/total_bytes END AS percent_used,sample_count FROM storage_aggregates WHERE device_id=? AND resolution='hourly' AND bucket>=? AND bucket<? ORDER BY bucket",(device_id,start,raw_start))+newest("storage_metrics","timestamp,mount_point,used_bytes,total_bytes,percent_used,1 AS sample_count",raw_start)
            network=history.db.rows("SELECT bucket AS timestamp,interface,avg_rx_rate AS rx_rate_bps,avg_tx_rate AS tx_rate_bps,avg_wifi_signal AS wifi_signal_dbm,avg_wifi_quality AS wifi_quality_percent,sample_count FROM network_aggregates WHERE device_id=? AND resolution='hourly' AND bucket>=? AND bucket<? ORDER BY bucket",(device_id,start,raw_start))+newest("network_metrics","timestamp,interface,rx_rate_bps,tx_rate_bps,wifi_signal_dbm,wifi_quality_percent,1 AS sample_count",raw_start)
        if resolution=="raw":storage=newest("storage_metrics");network=newest("network_metrics")
        def avg(k):v=[x[k] for x in core if x.get(k)!=None];return sum(v)/len(v) if v else None
        stats={"cpu_average":avg("cpu_percent"),"cpu_maximum":max((x["cpu_percent"] for x in core if x.get("cpu_percent")!=None),default=None),"temperature_average":avg("cpu_temp_c"),"temperature_maximum":max((x["cpu_temp_c"] for x in core if x.get("cpu_temp_c")!=None),default=None),"memory_average":avg("memory_percent")}
        return jsonify({"device_id":device_id,"range":name,"resolution":resolution,"units":{"rates":"bytes_per_second","storage":"bytes","temperature":"celsius","percent":"percent"},"core":core,"storage":storage,"network":network,"statistics":stats})
    @app.get("/api/devices/<device_id>/storage/forecast")
    def forecast(device_id):
        from pinoc.history import storage_forecast
        rows=history.db.rows("SELECT * FROM storage_metrics WHERE device_id=? AND timestamp>=? ORDER BY mount_point,timestamp",(device_id,(datetime.now(timezone.utc)-__import__('datetime').timedelta(days=14)).isoformat())) if history else []
        result=[]
        for mount in sorted({x["mount_point"] for x in rows}):result.append({"mount_point":mount,**storage_forecast([x for x in rows if x["mount_point"]==mount])})
        return jsonify({"forecasts":result})

    @app.get("/api/devices/<device_id>/logs")
    def device_logs(device_id):
        if not history or not history.db.available:return jsonify({"error":"history unavailable","unit":None,"samples":[]}),503
        try:samples=min(100,max(1,int(request.args.get("samples",20))))
        except ValueError:samples=20
        unit=(request.args.get("unit") or "").strip()[:128]
        if not unit:
            units=[]
            for row in history.db.rows("SELECT unit,MAX(timestamp) AS last_timestamp FROM service_logs WHERE device_id=? GROUP BY unit ORDER BY last_timestamp DESC,unit LIMIT 50",(device_id,)):
                latest=history.db.rows("SELECT lines FROM service_logs WHERE device_id=? AND unit=? ORDER BY timestamp DESC,id DESC LIMIT 1",(device_id,row["unit"]))
                line_count=len(latest[0]["lines"].splitlines()) if latest else 0
                units.append({"unit":row["unit"],"last_timestamp":row["last_timestamp"],"line_count":line_count})
            return jsonify({"device_id":device_id,"unit":None,"units":units})
        # Log lines were redacted when stored; redact again on the read path
        # so previously persisted samples stay safe if the rules ever tighten.
        rows=history.db.rows("SELECT timestamp,lines FROM service_logs WHERE device_id=? AND unit=? ORDER BY timestamp DESC,id DESC LIMIT ?",(device_id,unit,samples))
        out=[]
        for row in rows:
            # Redact the complete stored sample before splitting it so the
            # defense-in-depth read path also catches multiline PEM blocks
            # persisted by older versions.
            redacted=redact_log_line(row["lines"])
            lines=[line for line in redacted.splitlines() if line.strip()][:100]
            if lines:out.append({"timestamp":row["timestamp"],"lines":lines})
        return jsonify({"device_id":device_id,"unit":unit,"samples":out})
    # Historical tables behind /api/export and the permission each requires.
    # The alerts kind is exported under alerts.read (its list API permission)
    # rather than history.read so alert-only tokens work as expected.
    EXPORT_TABLES={
        "metrics":("device_metrics","timestamp","history.read"),
        "storage":("storage_metrics","timestamp","history.read"),
        "network":("network_metrics","timestamp","history.read"),
        "services":("service_status","timestamp","history.read"),
        "integrations":("integration_metrics","timestamp","history.read"),
        "alerts":("alerts","opened_at","alerts.read"),
        "events":("events","timestamp","history.read"),
    }
    @app.get("/api/export/<kind>")
    def api_export(kind):
        entry=EXPORT_TABLES.get(kind)
        if entry is None:return jsonify({"error":f"export kind must be one of {', '.join(EXPORT_TABLES)}"}),400
        table,time_column,permission=entry
        if security is not None and not security.allowed(g.identity,permission):return jsonify({"error":"permission denied"}),403
        if not history or not history.db.available:return jsonify({"error":"history unavailable"}),503
        name=request.args.get("range","24h")
        if name not in RANGES:return jsonify({"error":"range must be 1h, 6h, 24h, 7d, or 30d"}),400
        try:limit=min(50000,max(1,int(request.args.get("limit",10000))))
        except ValueError:abort(400,"invalid limit")
        device=request.args.get("device")
        where=[f"{time_column}>=?"]
        args=[(datetime.now(timezone.utc)-timedelta(seconds=RANGES[name])).isoformat()]
        if device:where.append("device_id=?");args.append(device)
        # Rows follow the matching list APIs: chronological for time-series
        # tables, newest-first for alerts and events.
        order=f"{time_column} DESC" if kind in ("alerts","events") else f"device_id, {time_column}"
        rows=sanitize(history.db.rows(f"SELECT * FROM {table} WHERE {' AND '.join(where)} ORDER BY {order} LIMIT ?",args+[limit]))
        fmt=(request.args.get("format") or "csv").lower()
        if fmt not in ("csv","json"):return jsonify({"error":"format must be csv or json"}),400
        if fmt=="json":
            return jsonify({"kind":kind,"range":name,"device":device or None,"generated_at":datetime.now(timezone.utc).isoformat(),"count":len(rows),"rows":rows})
        if rows:columns=list(rows[0].keys())
        else:columns=[x["name"] for x in history.db.rows(f"PRAGMA table_info({table})")]
        def generate():
            buffer=io.StringIO();csv.writer(buffer).writerow(columns);yield buffer.getvalue()
            for row in rows:
                buffer=io.StringIO();csv.writer(buffer).writerow([csv_safe(row.get(c)) for c in columns]);yield buffer.getvalue()
        return Response(generate(),mimetype="text/csv",headers={"Content-Disposition":f'attachment; filename="pinoc-{kind}-{name}.csv"'})

    @app.get("/api/database/status")
    def database_status():return jsonify(history.db.status() if history else {"status":"disabled"})

    return app


def serve(app: Flask, host: str, port: int) -> None:
    try:
        from waitress import serve as waitress_serve
        waitress_serve(app, host=host, port=port, threads=4)
    except ImportError:
        logging.getLogger("pinoc.web").warning("Waitress unavailable; using Flask development server")
        app.run(host=host, port=port, threaded=True, use_reloader=False)
