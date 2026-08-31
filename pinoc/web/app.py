"""Flask application backed exclusively by the shared state cache."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from flask import Flask, abort, jsonify, render_template, request

from pinoc.state import PiNOCState


def create_app(state: PiNOCState, config: Optional[Dict[str, Any]] = None, history: Any = None) -> Flask:
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

    @app.get("/alerts")
    def alerts_page(): return render_template("alerts.html")

    @app.get("/events")
    def events_page(): return render_template("events.html")

    @app.get("/settings/status")
    def status_page(): return render_template("status.html")

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
    def acknowledge(alert_id): history.acknowledge(alert_id,request.json.get("actor","local") if request.is_json else "local");return jsonify({"ok":True})
    @app.post("/api/alerts/<int:alert_id>/mute")
    def mute(alert_id):
        body=request.get_json(silent=True) or {}; until=body.get("muted_until")
        if not until:
            try: until=(datetime.now(timezone.utc)+__import__('datetime').timedelta(seconds=min(86400,max(60,int(body.get("seconds",3600)))))).isoformat()
            except ValueError:abort(400,"invalid mute duration")
        history.mute(alert_id,until);return jsonify({"ok":True,"muted_until":until})
    @app.post("/api/alerts/<int:alert_id>/unmute")
    def unmute(alert_id):history.unmute(alert_id);return jsonify({"ok":True})

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
        if resolution=="raw":core=history.db.rows("SELECT * FROM device_metrics WHERE device_id=? AND timestamp>=? ORDER BY timestamp LIMIT 5000",(device_id,start))
        else:
            raw_start=(now-__import__('datetime').timedelta(days=int(history.config.get("raw_retention_days",7)))).isoformat()
            core=history.db.rows("SELECT bucket AS timestamp,avg_cpu AS cpu_percent,avg_temp AS cpu_temp_c,avg_memory AS memory_percent,max_cpu,max_temp,sample_count FROM metric_aggregates WHERE device_id=? AND resolution='hourly' AND bucket>=? AND bucket<? UNION ALL SELECT timestamp,cpu_percent,cpu_temp_c,memory_percent,cpu_percent,cpu_temp_c,1 FROM device_metrics WHERE device_id=? AND timestamp>=? ORDER BY timestamp",(device_id,start,raw_start,device_id,raw_start))
            storage=history.db.rows("SELECT bucket AS timestamp,mount_point,latest_used AS used_bytes,total_bytes,CASE WHEN total_bytes>0 THEN latest_used*100.0/total_bytes END AS percent_used,sample_count FROM storage_aggregates WHERE device_id=? AND resolution='hourly' AND bucket>=? AND bucket<? UNION ALL SELECT timestamp,mount_point,used_bytes,total_bytes,percent_used,1 FROM storage_metrics WHERE device_id=? AND timestamp>=? ORDER BY timestamp",(device_id,start,raw_start,device_id,raw_start))
            network=history.db.rows("SELECT bucket AS timestamp,interface,avg_rx_rate AS rx_rate_bps,avg_tx_rate AS tx_rate_bps,avg_wifi_signal AS wifi_signal_dbm,avg_wifi_quality AS wifi_quality_percent,sample_count FROM network_aggregates WHERE device_id=? AND resolution='hourly' AND bucket>=? AND bucket<? UNION ALL SELECT timestamp,interface,rx_rate_bps,tx_rate_bps,wifi_signal_dbm,wifi_quality_percent,1 FROM network_metrics WHERE device_id=? AND timestamp>=? ORDER BY timestamp",(device_id,start,raw_start,device_id,raw_start))
        if resolution=="raw":storage=history.db.rows("SELECT * FROM storage_metrics WHERE device_id=? AND timestamp>=? ORDER BY timestamp LIMIT 5000",(device_id,start));network=history.db.rows("SELECT * FROM network_metrics WHERE device_id=? AND timestamp>=? ORDER BY timestamp LIMIT 5000",(device_id,start))
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
