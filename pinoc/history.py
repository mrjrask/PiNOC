"""Non-blocking history writer, transition detector, alerts and maintenance."""
from __future__ import annotations
import hashlib, json, logging, queue, threading, time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from .database import Database, utcnow

LOG=logging.getLogger("pinoc.history"); UTC=timezone.utc
SEVERITY_RANK={"info":0,"warning":1,"degraded":2,"critical":3}

class HistoryManager:
    def __init__(self,db:Database,config:Optional[Dict[str,Any]]=None,state:Any=None):
        self.db=db; self.config=config or {}; self.enabled=bool(self.config.get("enabled",True))
        self.queue:queue.Queue=queue.Queue(maxsize=int(self.config.get("queue_size",1000)))
        self.stop_event=threading.Event(); self.thread=threading.Thread(target=self._run,name="pinoc-history",daemon=True)
        self.previous={}; self.last_sample={}; self.cpu_since={}; self.dropped=0
        self.state=state
        self.intervals={"core":float(self.config.get("core_interval_seconds",60)),"network":float(self.config.get("network_interval_seconds",60)),"storage":float(self.config.get("storage_interval_seconds",300))}

    def start(self):
        if self.enabled and self.db.initialize(): self.thread.start(); self.event(None,"pinoc_started","info","PiNOC started")
    def submit(self,devices):
        if not self.enabled or not self.db.available:return
        try:self.queue.put_nowait(("snapshot",devices,utcnow()))
        except queue.Full:self.dropped+=1; LOG.warning("history queue full; dropped snapshot")
    def event(self,device_id,event_type,severity,message,metadata=None): self._enqueue("event",(device_id,event_type,severity,message,metadata or {},utcnow()))
    def _enqueue(self,kind,payload):
        try:self.queue.put_nowait((kind,payload))
        except queue.Full:self.dropped+=1
    def _run(self):
        next_maintenance=time.monotonic()+60
        while not self.stop_event.is_set() or not self.queue.empty():
            try:
                item=self.queue.get(timeout=.25)
                try:
                    if item[0]=="snapshot":self._snapshot(item[1],item[2])
                    elif item[0]=="event":self._write_event(*item[1])
                except Exception as exc:self.db.available=False;self.db.error=str(exc);LOG.exception("history write failed; live monitoring continues")
                finally:self.queue.task_done()
            except queue.Empty:pass
            if time.monotonic()>=next_maintenance:
                try:self.maintenance()
                except Exception as exc:LOG.warning("database maintenance failed: %s",exc)
                next_maintenance=time.monotonic()+float(self.config.get("maintenance_interval_seconds",3600))
    def stop(self,timeout=5):
        self.stop_event.set()
        if self.thread.is_alive():self.thread.join(timeout)

    def _snapshot(self,devices,stamp):
        for d in devices:self._device(d,stamp)
        self._refresh_cache()
    def _device(self,d,stamp):
        did=d["id"]; old=self.previous.get(did); ip=d.get("network",{}).get("ip") or d.get("ip") or ""
        persisted=self.db.scalar("SELECT 1 FROM devices WHERE device_id=?",(did,)) is not None
        self.db.execute("""INSERT INTO devices(device_id,hostname,friendly_name,first_seen,last_seen,first_ip,last_ip,model,roles_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET hostname=excluded.hostname,friendly_name=excluded.friendly_name,last_seen=excluded.last_seen,last_ip=CASE WHEN excluded.last_ip<>'' THEN excluded.last_ip ELSE devices.last_ip END,model=excluded.model,roles_json=excluded.roles_json,updated_at=excluded.updated_at""",(did,d.get("hostname"),d.get("friendly_name"),d.get("first_seen") or stamp,d.get("last_seen"),ip,ip,d.get("model"),json.dumps(d.get("roles",[])),stamp,stamp))
        if old is None:
            if not persisted:self._write_event(did,"device_first_seen","info","Device first discovered",{},stamp)
        else:
            if old.get("online") and not d.get("online"):self._write_event(did,"device_offline","critical","Device went offline",{},stamp)
            if not old.get("online") and d.get("online"):self._write_event(did,"device_online","info","Device returned online",{},stamp)
            oldip=old.get("network",{}).get("ip") or old.get("ip")
            if oldip and ip and oldip!=ip:self._write_event(did,"ip_changed","info",f"IP changed {oldip} → {ip}",{"old":oldip,"new":ip},stamp)
            if (old.get("boot_time") and d.get("boot_time") and old["boot_time"]!=d["boot_time"] and d.get("uptime_seconds",0)<old.get("uptime_seconds",0)):
                self._write_event(did,"device_rebooted","info","Device reboot detected",{"boot_time":d.get("boot_time")},stamp)
            self._service_transitions(did,old,d,stamp); self._hardware_events(did,old,d,stamp)
        self._sample(d,stamp); self._alerts(d,stamp); self.previous[did]=d

    def _due(self,did,kind,stamp):
        now=datetime.fromisoformat(stamp); key=(did,kind); last=self.last_sample.get(key)
        if last and (now-last).total_seconds()<self.intervals[kind]:return False
        self.last_sample[key]=now;return True
    def _sample(self,d,stamp):
        did=d["id"]
        if d.get("online") and self._due(did,"core",stamp):
            c,m,h=d.get("cpu",{}),d.get("memory",{}),d.get("hardware",{})
            self.db.execute("INSERT OR IGNORE INTO device_metrics(timestamp,device_id,cpu_percent,load_1m,load_5m,load_15m,cpu_freq_mhz,cpu_temp_c,soc_temp_c,memory_percent,memory_used_bytes,swap_percent,uptime_seconds) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(stamp,did,c.get("utilization_percent"),c.get("load_1m"),c.get("load_5m"),c.get("load_15m"),c.get("frequency_mhz"),c.get("temperature_c"),c.get("soc_temperature_c"),m.get("percent"),m.get("used"),m.get("swap_percent"),d.get("uptime_seconds")))
        if d.get("online") and self._due(did,"network",stamp):
            n=d.get("network",{}); interface=n.get("interface") or "unknown"
            self.db.execute("INSERT OR IGNORE INTO network_metrics(timestamp,device_id,interface,ip_address,rx_rate_bps,tx_rate_bps,rx_total_bytes,tx_total_bytes,wifi_signal_dbm,wifi_quality_percent) VALUES(?,?,?,?,?,?,?,?,?,?)",(stamp,did,interface,n.get("ip"),n.get("rx_rate"),n.get("tx_rate"),n.get("rx_bytes"),n.get("tx_bytes"),n.get("signal_dbm"),n.get("signal_quality_percent")))
        if d.get("online") and self._due(did,"storage",stamp):
            for x in d.get("storage",[]):self.db.execute("INSERT OR IGNORE INTO storage_metrics(timestamp,device_id,device,mount_point,filesystem,total_bytes,used_bytes,available_bytes,percent_used,read_only) VALUES(?,?,?,?,?,?,?,?,?,?)",(stamp,did,x.get("device"),x.get("mount_point") or x.get("path") or "unknown",x.get("filesystem"),x.get("total") or x.get("size"),x.get("used"),x.get("available"),x.get("percent"),int(bool(x.get("read_only")))))

    def _service_transitions(self,did,old,new,stamp):
        before={x.get("name"):x for x in old.get("services",[])}
        for s in new.get("services",[]):
            prior=before.get(s.get("name"));
            if prior and prior.get("state")==s.get("state"):continue
            self.db.execute("INSERT INTO service_status(timestamp,device_id,service_name,normalized_state,active_state,sub_state,main_pid,memory_bytes,restart_count) VALUES(?,?,?,?,?,?,?,?,?)",(stamp,did,s.get("name"),s.get("state"),s.get("active_state"),s.get("sub_state"),s.get("main_pid"),s.get("memory_bytes"),s.get("restart_count")))
            if prior:self._write_event(did,"service_changed","warning" if s.get("state")!="running" else "info",f"{s.get('name')} {prior.get('state')} → {s.get('state')}",{"service":s.get("name")},stamp)
    def _hardware_events(self,did,old,new,stamp):
        labels={"undervoltage_occurred":"Undervoltage occurred since boot","throttled_occurred":"Throttling occurred since boot","frequency_capped_occurred":"Frequency capping occurred since boot","soft_temp_limit_occurred":"Soft temperature limit occurred since boot"}
        for key,msg in labels.items():
            if new.get("hardware",{}).get(key) and not old.get("hardware",{}).get(key):self._write_event(did,key,"info",msg,{},stamp)
    def _alerts(self,d,stamp):
        did=d["id"]; active={}; c,m,h=d.get("cpu",{}),d.get("memory",{}),d.get("hardware",{}); t={"temperature_warning":70,"temperature_critical":80,"temperature_hysteresis":3,"cpu_warning":90,"cpu_duration_seconds":300,"memory_warning":85,"disk_warning":80,"disk_critical":95,"disk_hysteresis":2,**self.config.get("thresholds",{})}
        open_types={x["alert_type"] for x in self.db.rows("SELECT alert_type FROM alerts WHERE device_id=? AND resolved_at IS NULL",(did,))}
        if not d.get("online"):active["device_offline"]=("critical","Device is offline","")
        temp=c.get("temperature_c")
        if temp is not None:
            typ="critical_temperature" if temp>=(t["temperature_critical"]-t["temperature_hysteresis"] if "critical_temperature" in open_types else t["temperature_critical"]) else "high_temperature" if temp>=(t["temperature_warning"]-t["temperature_hysteresis"] if "high_temperature" in open_types else t["temperature_warning"]) else None
            if typ:active[typ]=("critical" if typ.startswith("critical") else "warning",f"CPU temperature is {temp:.1f}°C","cpu")
        cpu=c.get("utilization_percent")
        if cpu is not None and cpu>=t["cpu_warning"]:
            self.cpu_since.setdefault(did,datetime.fromisoformat(stamp))
            if (datetime.fromisoformat(stamp)-self.cpu_since[did]).total_seconds()>=t["cpu_duration_seconds"]:active["high_cpu"]=("warning",f"CPU utilization is {cpu:.1f}%","")
        else:self.cpu_since.pop(did,None)
        if (m.get("percent") or 0)>=t["memory_warning"]:active["high_memory"]=("warning",f"Memory utilization is {m['percent']:.1f}%","")
        for x in d.get("storage",[]):
            mount=x.get("mount_point") or x.get("path") or "unknown"; pct=x.get("percent") or 0
            critical_cut=t["disk_critical"]-t["disk_hysteresis"] if "critical_disk_usage" in open_types else t["disk_critical"]
            warning_cut=t["disk_warning"]-t["disk_hysteresis"] if "high_disk_usage" in open_types else t["disk_warning"]
            if pct>=critical_cut:active[f"critical_disk_usage:{mount}"]=("critical",f"{mount} is {pct:.1f}% full",mount)
            elif pct>=warning_cut:active[f"high_disk_usage:{mount}"]=("warning",f"{mount} is {pct:.1f}% full",mount)
            if x.get("read_only") and (not d.get("important_paths") or any(p.startswith(mount.rstrip('/')+'/') or p==mount for p in d.get("important_paths",[]))):active[f"filesystem_read_only:{mount}"]=("critical",f"{mount} is read-only",mount)
        for key in ("undervoltage_now","throttled_now","frequency_capped_now","soft_temp_limit_now"):
            if h.get(key):active[key]=("critical",key.replace("_now","").replace("_"," ").title()+" now","")
        for s in d.get("services",[]):
            if s.get("state") not in ("running","activating"):
                typ="critical_service_failed" if s.get("critical") else "service_failed";active[f"{typ}:{s.get('name')}"]=("critical" if s.get("critical") else "warning",f"{s.get('name')} is {s.get('state')}",s.get("name"))
        raid=d.get("applications",{}).get("raid",{}).get("status")
        if raid in ("DEGRADED","INACTIVE","MISSING"):active["raid_degraded"]=("critical",f"RAID is {raid.lower()}","raid")
        self._reconcile(did,active,stamp)
    def _reconcile(self,did,active,stamp):
        existing={x["fingerprint"]:x for x in self.db.rows("SELECT * FROM alerts WHERE device_id=? AND resolved_at IS NULL",(did,))}
        seen=set()
        for key,(sev,msg,resource) in active.items():
            typ=key.split(":",1)[0]; fp=f"{did}:{typ}:{resource}";seen.add(fp)
            if fp in existing:
                row=existing[fp]
                muted_until=row.get("muted_until")
                mute_expired=row.get("state")=="muted" and (not muted_until or datetime.fromisoformat(muted_until)<=datetime.fromisoformat(stamp))
                state="acknowledged" if row.get("acknowledged_at") else "active"
                if mute_expired:self.db.execute("UPDATE alerts SET last_seen_at=?,severity=?,message=?,muted_until=NULL,state=? WHERE alert_id=?",(stamp,sev,msg,state,row["alert_id"]))
                else:self.db.execute("UPDATE alerts SET last_seen_at=?,severity=?,message=? WHERE alert_id=?",(stamp,sev,msg,row["alert_id"]))
            else:self.db.execute("INSERT INTO alerts(device_id,alert_type,severity,message,fingerprint,opened_at,last_seen_at,state,metadata_json) VALUES(?,?,?,?,?,?,?,?,?)",(did,typ,sev,msg,fp,stamp,stamp,"active",json.dumps({"resource":resource})))
        for fp,row in existing.items():
            if fp not in seen:
                self.db.execute("UPDATE alerts SET resolved_at=?,state='resolved' WHERE alert_id=?",(stamp,row["alert_id"]));self._write_event(did,"alert_resolved","info",f"Recovered: {row['message']}",{"alert_id":row["alert_id"]},stamp)
    def _write_event(self,did,typ,sev,msg,metadata,stamp):self.db.execute("INSERT INTO events(timestamp,device_id,event_type,severity,message,metadata_json) VALUES(?,?,?,?,?,?)",(stamp,did,typ,sev,msg,json.dumps(metadata)))
    def _refresh_cache(self):
        if self.state:
            self.state.set_alerts(self.db.rows("SELECT * FROM alerts WHERE resolved_at IS NULL ORDER BY CASE severity WHEN 'critical' THEN 3 WHEN 'degraded' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END DESC"))

    def maintenance(self,now=None):
        now=now or datetime.now(UTC); raw=int(self.config.get("raw_retention_days",7)); hourly=int(self.config.get("hourly_retention_days",90)); daily=int(self.config.get("daily_retention_days",365))
        with self.db.connect() as con:
            con.execute("UPDATE alerts SET muted_until=NULL,state=CASE WHEN acknowledged_at IS NULL THEN 'active' ELSE 'acknowledged' END WHERE resolved_at IS NULL AND state='muted' AND muted_until<=?",(now.isoformat(),))
            for resolution,fmt,cutoff in (("hourly","%Y-%m-%dT%H:00:00+00:00",now-timedelta(days=raw)),("daily","%Y-%m-%dT00:00:00+00:00",now-timedelta(days=hourly))):
                source="device_metrics" if resolution=="hourly" else "metric_aggregates"; timecol="timestamp" if resolution=="hourly" else "bucket"; condition="timestamp<?" if resolution=="hourly" else "resolution='hourly' AND bucket<?"
                rows=con.execute(f"SELECT * FROM {source} WHERE {condition}",(cutoff.isoformat(),)).fetchall()
                groups={}
                for r in rows:
                    x=dict(r); dt=datetime.fromisoformat(x[timecol]); bucket=dt.strftime(fmt); groups.setdefault((bucket,x["device_id"]),[]).append(x)
                for (bucket,did),values in groups.items():
                    def vals(k):return [x[k] for x in values if x.get(k) is not None]
                    cpu=vals("cpu_percent" if resolution=="hourly" else "avg_cpu"); temp=vals("cpu_temp_c" if resolution=="hourly" else "avg_temp"); mem=vals("memory_percent" if resolution=="hourly" else "avg_memory")
                    con.execute("INSERT OR REPLACE INTO metric_aggregates VALUES(?,?,?,?,?,?,?,?,?,?)",(bucket,resolution,did,sum(cpu)/len(cpu) if cpu else None,max(cpu) if cpu else None,sum(temp)/len(temp) if temp else None,min(temp) if temp else None,max(temp) if temp else None,sum(mem)/len(mem) if mem else None,sum(x.get("sample_count",1) for x in values)))
            cutoff=(now-timedelta(days=raw)).isoformat()
            storage=con.execute("SELECT *,strftime('%Y-%m-%dT%H:00:00+00:00',timestamp) AS bucket FROM storage_metrics WHERE timestamp<?",(cutoff,)).fetchall()
            for row in storage:
                x=dict(row)
                con.execute("""INSERT INTO storage_aggregates(bucket,resolution,device_id,mount_point,min_used,max_used,latest_used,total_bytes,sample_count) VALUES(?,'hourly',?,?,?,?,?,?,1)
                    ON CONFLICT(bucket,resolution,device_id,mount_point) DO UPDATE SET min_used=min(min_used,excluded.min_used),max_used=max(max_used,excluded.max_used),latest_used=excluded.latest_used,total_bytes=excluded.total_bytes,sample_count=sample_count+1""",(x["bucket"],x["device_id"],x["mount_point"],x["used_bytes"],x["used_bytes"],x["used_bytes"],x["total_bytes"]))
            network=con.execute("SELECT strftime('%Y-%m-%dT%H:00:00+00:00',timestamp) AS bucket,device_id,interface,AVG(rx_rate_bps),AVG(tx_rate_bps),AVG(wifi_signal_dbm),AVG(wifi_quality_percent),COUNT(*) FROM network_metrics WHERE timestamp<? GROUP BY bucket,device_id,interface",(cutoff,)).fetchall()
            con.executemany("INSERT OR REPLACE INTO network_aggregates VALUES(?,'hourly',?,?,?,?,?,?,?)",network)
            con.execute("DELETE FROM device_metrics WHERE timestamp<?",((now-timedelta(days=raw)).isoformat(),));con.execute("DELETE FROM network_metrics WHERE timestamp<?",((now-timedelta(days=raw)).isoformat(),));con.execute("DELETE FROM storage_metrics WHERE timestamp<?",((now-timedelta(days=raw)).isoformat(),));con.execute("DELETE FROM metric_aggregates WHERE resolution='hourly' AND bucket<?",((now-timedelta(days=hourly)).isoformat(),));con.execute("DELETE FROM metric_aggregates WHERE resolution='daily' AND bucket<?",((now-timedelta(days=daily)).isoformat(),));con.execute("DELETE FROM storage_aggregates WHERE resolution='hourly' AND bucket<?",((now-timedelta(days=hourly)).isoformat(),));con.execute("DELETE FROM network_aggregates WHERE resolution='hourly' AND bucket<?",((now-timedelta(days=hourly)).isoformat(),))
        self.db.last_aggregation=self.db.last_retention_cleanup=utcnow()
        self._refresh_cache()

    def acknowledge(self,alert_id,actor="local"):
        stamp=utcnow();self.db.execute("UPDATE alerts SET acknowledged_at=?,acknowledged_by=?,state=CASE WHEN resolved_at IS NULL THEN 'acknowledged' ELSE state END WHERE alert_id=?",(stamp,actor,alert_id))
    def mute(self,alert_id,until):self.db.execute("UPDATE alerts SET muted_until=?,state=CASE WHEN resolved_at IS NULL THEN 'muted' ELSE state END WHERE alert_id=?",(until,alert_id))
    def unmute(self,alert_id):self.db.execute("UPDATE alerts SET muted_until=NULL,state=CASE WHEN resolved_at IS NULL THEN CASE WHEN acknowledged_at IS NULL THEN 'active' ELSE 'acknowledged' END ELSE state END WHERE alert_id=?",(alert_id,))

def storage_forecast(rows,minimum_samples=3,minimum_span_days=.5):
    if len(rows)<minimum_samples:return {"status":"insufficient","forecast_confidence":"insufficient"}
    points=sorted((datetime.fromisoformat(x["timestamp"]),int(x["used_bytes"]),int(x["total_bytes"])) for x in rows if x.get("used_bytes") is not None and x.get("total_bytes"))
    if len(points)<minimum_samples:return {"status":"insufficient","forecast_confidence":"insufficient"}
    span=(points[-1][0]-points[0][0]).total_seconds()/86400
    if span<minimum_span_days:return {"status":"insufficient","forecast_confidence":"insufficient"}
    growth=(points[-1][1]-points[0][1])/span; result={"daily_growth_bytes":growth,"trend_window_days":round(span,1),"forecast_confidence":"good" if len(points)>=7 and span>=7 else "moderate"}
    stable=max(1,points[-1][2]*.0001)
    if abs(growth)<stable:result.update(status="stable",estimated_days_remaining=None)
    elif growth<0:result.update(status="decreasing",estimated_days_remaining=None)
    else:result.update(status="growing",estimated_days_remaining=max(0,(points[-1][2]-points[-1][1])/growth))
    return result
