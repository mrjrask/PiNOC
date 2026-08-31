"""Flask application backed exclusively by the shared state cache."""
from __future__ import annotations

import logging, os, secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from flask import Flask, abort, jsonify, render_template, request, session, redirect, url_for, g

from pinoc.state import PiNOCState
from pinoc.integrations import sanitize
from pinoc.integrations.adsb import compare as compare_adsb
from pinoc.security import SecurityManager, install_security, require, redact
from pinoc.actions import ActionDispatcher, ActionError
from pinoc.config_store import atomic_save, validate_config


def create_app(state: PiNOCState, config: Optional[Dict[str, Any]] = None, history: Any = None, coordinator: Any = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.update(config or {})
    app.secret_key=app.config.get("SECRET_KEY") or os.getenv("PINOC_SECRET_KEY") or secrets.token_hex(32)
    app.config.update(SESSION_COOKIE_SECURE=bool(app.config.get("SESSION_COOKIE_SECURE",False)),SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE="Lax")
    auth_enabled=bool(app.config.get("AUTH_ENABLED",False))
    security=SecurityManager(history.db if history else app.config.get("DATABASE"),auth_enabled) if history or app.config.get("DATABASE") else None
    actions=ActionDispatcher(history.db,state,coordinator,int(app.config.get("ACTION_WORKERS",2))) if history else None
    if security:install_security(app,security)
    app.extensions["pinoc_security"]=security;app.extensions["pinoc_actions"]=actions

    @app.route("/login",methods=["GET","POST"])
    def login():
        if not security or not security.enabled:return redirect(url_for("dashboard"))
        error=None
        if request.method=="POST":
            row,error=security.authenticate(request.form.get("username",""),request.form.get("password",""),request.remote_addr or "unknown")
            if row:
                session.clear();session["username"]=row["username"];session["role"]=row["role"];session["csrf_token"]=secrets.token_urlsafe(32);session.permanent=True
                actions.audit(row["username"],row["role"],request.remote_addr,None,"auth.login",None,{},"allowed","succeeded") if actions else None
                return redirect(url_for("dashboard"))
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
            validate_config(value,app.config.get("APP_DIR","."));atomic_save(app.config.get("CONFIG_PATH","config.json"),value)
        except (ValueError,OSError) as exc:return jsonify({"error":str(redact(exc))}),400
        actions.audit(g.identity["username"],g.identity["role"],request.remote_addr,None,"config.update",None,{},"allowed","succeeded") if actions else None
        return jsonify({"ok":True,"restart_required":True})
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
        try:token=security.create_token(str(body.get("owner") or g.identity["username"]),body.get("scopes",[]))
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
        if not history:return jsonify({"alerts":state.alerts()})
        page,limit=_page(); where,args=["1=1"],[]
        for field,column in (("device","device_id"),("severity","severity"),("state","state"),("type","alert_type")):
            if request.args.get(field):where.append(f"{column}=?");args.append(request.args[field])
        total=history.db.scalar("SELECT COUNT(*) FROM alerts WHERE "+" AND ".join(where),args) or 0
        rows=history.db.rows("SELECT * FROM alerts WHERE "+" AND ".join(where)+" ORDER BY CASE severity WHEN 'critical' THEN 3 WHEN 'degraded' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END DESC, opened_at DESC LIMIT ? OFFSET ?",args+[limit,(page-1)*limit])
        return jsonify({"alerts":rows,"page":page,"limit":limit,"total":total})

    def _page():
        try:return max(1,int(request.args.get("page",1))),min(200,max(1,int(request.args.get("limit",50))))
        except ValueError:abort(400,"invalid pagination")

    @app.get("/api/alerts/<int:alert_id>")
    def api_alert(alert_id):
        rows=history.db.rows("SELECT * FROM alerts WHERE alert_id=?",(alert_id,)) if history else []
        return jsonify(rows[0]) if rows else (jsonify({"error":"alert not found"}),404)
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
