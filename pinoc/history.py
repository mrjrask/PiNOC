"""Non-blocking history writer, transition detector, alerts and maintenance."""
from __future__ import annotations
import json, logging, queue, threading, time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from .anomalies import BaselineTracker
from .correlation import CorrelationEngine, describe_context
from .database import Database, utcnow

LOG=logging.getLogger("pinoc.history"); UTC=timezone.utc
SEVERITY_RANK={"info":0,"warning":1,"degraded":2,"critical":3}

class HistoryManager:
    def __init__(self,db:Database,config:Optional[Dict[str,Any]]=None,state:Any=None,notifier:Any=None,anomalies:Optional[Dict[str,Any]]=None,correlation:Optional[Dict[str,Any]]=None,network_topology:Optional[Dict[str,Any]]=None,slos:Optional[Dict[str,Any]]=None):
        self.db=db; self.config=config or {}; self.enabled=bool(self.config.get("enabled",True)); self.notifier=notifier
        self.anomaly=BaselineTracker(db,anomalies)
        self.correlation=CorrelationEngine(db,correlation)
        # Raw network_topology config; re-parsed against the *current*
        # roster on every correlation pass (see _topology()) since segments
        # can be auto-derived from live device tags and the fleet changes
        # over the life of this process -- see pinoc.topology.
        self.topology_config=network_topology or {}
        self.queue:queue.Queue=queue.Queue(maxsize=int(self.config.get("queue_size",1000)))
        self.stop_event=threading.Event(); self.thread=threading.Thread(target=self._run,name="pinoc-history",daemon=True)
        self.previous={}; self.last_sample={}; self.cpu_since={}; self.dropped=0
        self.state=state
        self.intervals={"core":float(self.config.get("core_interval_seconds",60)),"network":float(self.config.get("network_interval_seconds",60)),"storage":float(self.config.get("storage_interval_seconds",300)),"integration":float(self.config.get("integration_interval_seconds",60))}
        self.log_ring_size=min(1000,max(1,int(self.config.get("log_ring_samples",50))))
        # SLOs and reliability scoring (enhancement #3, see pinoc.slo):
        # health_samples is sampled on its own interval/retention (a 30-day
        # SLO window needs far more history than device_metrics's 7-day raw
        # retention keeps), independent of the metrics intervals above.
        slo_config=slos or {}
        self.intervals["health"]=float(slo_config.get("interval_seconds",self.intervals["core"]))
        self.health_sample_retention_days=max(1,int(slo_config.get("sample_retention_days",35)))

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
        for d in devices:
            try:self._device(d,stamp)
            except Exception as exc:
                self.db.available=False;self.db.error=str(exc)
                LOG.exception("history snapshot failed for device %s; other devices this cycle are unaffected",d.get("id"))
        self._prune_stale_device_state({d.get("id") for d in devices if d.get("id")})
        self._refresh_cache()
    def _prune_stale_device_state(self,current_ids):
        # previous/last_sample/cpu_since are populated per device on every
        # poll but nothing ever removed an entry for a device_id that stops
        # appearing here (removed from config/devices.json, or renamed/
        # re-slugged) -- a long-running installation with device churn
        # would otherwise grow these unboundedly. FleetCollector.collect()
        # always returns one result per currently configured device (never
        # silently drops one, even on failure), so `devices` here is
        # reliably the full current roster, not a partial cycle.
        for did in [k for k in self.previous if k not in current_ids]:self.previous.pop(did,None)
        for key in [k for k in self.last_sample if k[0] not in current_ids]:self.last_sample.pop(key,None)
        for did in [k for k in self.cpu_since if k not in current_ids]:self.cpu_since.pop(did,None)
    def _device(self,d,stamp):
        did=d["id"]; old=self.previous.get(did); ip=d.get("network",{}).get("ip") or d.get("ip") or ""
        operational=self.db.rows("SELECT * FROM device_operational_state WHERE device_id=?",(did,))
        operational=operational[0] if operational else {}
        now=datetime.fromisoformat(stamp);maintenance_until=operational.get("maintenance_until");expected_until=operational.get("expected_offline_until")
        if maintenance_until and datetime.fromisoformat(maintenance_until)<=now:
            self.db.execute("UPDATE device_operational_state SET maintenance_until=NULL,maintenance_reason=NULL,expected_offline=0,expected_offline_reason=NULL,expected_offline_until=NULL,updated_at=?,updated_by='system' WHERE device_id=?",(stamp,did));operational={};maintenance_until=None
            self._write_event(did,"maintenance_ended","info","Maintenance window expired",{},stamp)
        if expected_until and datetime.fromisoformat(expected_until)<=now and not maintenance_until:
            self.db.execute("UPDATE device_operational_state SET expected_offline=0,expected_offline_reason=NULL,expected_offline_until=NULL,updated_at=?,updated_by='system' WHERE device_id=?",(stamp,did));operational["expected_offline"]=0
        # Collector/config maintenance remains authoritative even when no
        # operational-state row exists. Persisted maintenance augments it.
        configured_maintenance=bool(d.get("maintenance"))
        maintenance_active=operational.get("expected_offline_reason")=="maintenance"
        d["maintenance"]=bool(configured_maintenance or maintenance_active or maintenance_until or operational.get("maintenance_reason"));d["maintenance_until"]=maintenance_until;d["maintenance_reason"]=operational.get("maintenance_reason") or d.get("maintenance_reason") or ""
        d["expected_offline"]=bool(operational.get("expected_offline"));d["expected_offline_reason"]=operational.get("expected_offline_reason") or ""
        persisted=self.db.scalar("SELECT 1 FROM devices WHERE device_id=?",(did,)) is not None
        self.db.execute("""INSERT INTO devices(device_id,hostname,friendly_name,first_seen,last_seen,first_ip,last_ip,model,roles_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET hostname=excluded.hostname,friendly_name=excluded.friendly_name,last_seen=excluded.last_seen,last_ip=CASE WHEN excluded.last_ip<>'' THEN excluded.last_ip ELSE devices.last_ip END,model=excluded.model,roles_json=excluded.roles_json,updated_at=excluded.updated_at""",(did,d.get("hostname"),d.get("friendly_name"),d.get("first_seen") or stamp,d.get("last_seen"),ip,ip,d.get("model"),json.dumps(d.get("roles",[])),stamp,stamp))
        if old is None:
            if not persisted:self._write_event(did,"device_first_seen","info","Device first discovered",{},stamp)
        else:
            if old.get("online") and not d.get("online"):self._write_event(did,"device_offline","info" if d.get("expected_offline") else "critical","Device went offline as expected" if d.get("expected_offline") else "Device went offline",{},stamp)
            if not old.get("online") and d.get("online"):
                self._write_event(did,"device_online","info","Device returned online",{},stamp)
                if d.get("expected_offline_reason")=="reboot":self.db.execute("UPDATE device_operational_state SET expected_offline=0,expected_offline_reason=NULL,expected_offline_until=NULL,updated_at=?,updated_by='system' WHERE device_id=?",(stamp,did));self._write_event(did,"reboot_completed","info","Device returned after requested reboot",{},stamp)
            oldip=old.get("network",{}).get("ip") or old.get("ip")
            if oldip and ip and oldip!=ip:self._write_event(did,"ip_changed","info",f"IP changed {oldip} → {ip}",{"old":oldip,"new":ip},stamp)
            if (old.get("boot_time") and d.get("boot_time") and old["boot_time"]!=d["boot_time"] and d.get("uptime_seconds",0)<old.get("uptime_seconds",0)):
                self._write_event(did,"device_rebooted","info","Device reboot detected",{"boot_time":d.get("boot_time")},stamp)
            self._service_transitions(did,old,d,stamp); self._hardware_events(did,old,d,stamp)
        self._sample(d,stamp)
        opened,resolved=self._alerts(d,stamp)
        self.previous[did]=d
        self._correlate(opened,resolved,stamp)

    def _due(self,did,kind,stamp):
        now=datetime.fromisoformat(stamp); key=(did,kind); last=self.last_sample.get(key)
        if last and (now-last).total_seconds()<self.intervals[kind]:return False
        self.last_sample[key]=now;return True
    def _sample(self,d,stamp):
        did=d["id"]
        if self._due(did,"health",stamp):
            # Sampled regardless of online status -- an "offline" health
            # sample is exactly as informative for rolling attainment as a
            # "healthy" one. See pinoc.slo for what reads this back.
            self.db.execute("INSERT OR IGNORE INTO health_samples(timestamp,device_id,health,online) VALUES(?,?,?,?)",(stamp,did,d.get("health") or "offline",int(bool(d.get("online")))))
        if d.get("online") and self._due(did,"core",stamp):
            c,m=d.get("cpu",{}),d.get("memory",{})
            self.db.execute("INSERT OR IGNORE INTO device_metrics(timestamp,device_id,cpu_percent,load_1m,load_5m,load_15m,cpu_freq_mhz,cpu_temp_c,soc_temp_c,memory_percent,memory_used_bytes,swap_percent,uptime_seconds) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(stamp,did,c.get("utilization_percent"),c.get("load_1m"),c.get("load_5m"),c.get("load_15m"),c.get("frequency_mhz"),c.get("temperature_c"),c.get("soc_temperature_c"),m.get("percent"),m.get("used"),m.get("swap_percent"),d.get("uptime_seconds")))
        if d.get("online") and self._due(did,"network",stamp):
            n=d.get("network",{}); interface=n.get("interface") or "unknown"
            self.db.execute("INSERT OR IGNORE INTO network_metrics(timestamp,device_id,interface,ip_address,rx_rate_bps,tx_rate_bps,rx_total_bytes,tx_total_bytes,wifi_signal_dbm,wifi_quality_percent) VALUES(?,?,?,?,?,?,?,?,?,?)",(stamp,did,interface,n.get("ip"),n.get("rx_rate"),n.get("tx_rate"),n.get("rx_bytes"),n.get("tx_bytes"),n.get("signal_dbm"),n.get("signal_quality_percent")))
        if d.get("online") and self._due(did,"storage",stamp):
            for x in d.get("storage",[]):self.db.execute("INSERT OR IGNORE INTO storage_metrics(timestamp,device_id,device,mount_point,filesystem,total_bytes,used_bytes,available_bytes,percent_used,read_only) VALUES(?,?,?,?,?,?,?,?,?,?)",(stamp,did,x.get("device"),x.get("mount_point") or x.get("path") or "unknown",x.get("filesystem"),x.get("total") or x.get("size"),x.get("used"),x.get("available"),x.get("percent"),int(bool(x.get("read_only")))))
            for x in d.get("media",[]):self.db.execute("INSERT OR IGNORE INTO media_metrics(timestamp,device_id,block_device,read_bytes,written_bytes,io_errors,media_errors) VALUES(?,?,?,?,?,?,?)",(stamp,did,x.get("device"),x.get("read_bytes"),x.get("written_bytes"),x.get("io_errors"),None if x.get("media_errors") is None else int(bool(x.get("media_errors")))))
        if d.get("online"):
            for entry in d.get("logs",[]):
                unit=str(entry.get("unit") or "")[:128]
                lines="\n".join(str(x) for x in entry.get("lines") or [])[:65536]
                if unit and lines:
                    self.db.execute("INSERT INTO service_logs(timestamp,device_id,unit,lines) VALUES(?,?,?,?)",(stamp,did,unit,lines))
                    self.db.execute("DELETE FROM service_logs WHERE device_id=? AND unit=? AND id NOT IN (SELECT id FROM service_logs WHERE device_id=? AND unit=? ORDER BY id DESC LIMIT ?)",
                                    (did,unit,did,unit,self.log_ring_size))
        if d.get("online") and self._due(did,"integration",stamp):
            allow={"adsb":{"aircraft","aircraft_with_positions","messages_per_second","positions_per_second","maximum_range_nm","strong_signal_percent"},"samba":{"active_sessions","unique_users","open_files"},"pi_hotspot":{"client_count","response_latency_ms"},"magicmirror":{"response_latency_ms","restart_count"},"desk_display":{"response_latency_ms"},"wireguard":{"latest_handshake_seconds","rx_bytes","tx_bytes"},"probe":{"response_latency_ms","failed_checks","checks_total"}}
            for name,status in d.get("integrations",{}).items():
                data=status.get("data",{}) if isinstance(status,dict) else {}
                for metric in allow.get(name,set()):
                    value=data.get(metric)
                    if isinstance(value,(int,float)) and not isinstance(value,bool):
                        self.db.execute("INSERT OR IGNORE INTO integration_metrics(timestamp,device_id,integration,metric,value,unit) VALUES(?,?,?,?,?,?)",(stamp,did,name,metric,float(value),None))

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
        # Preserve conditions/history during maintenance without opening,
        # resolving, or notifying on transient maintenance observations.
        if d.get("maintenance"):return [],[]
        open_types={x["alert_type"] for x in self.db.rows("SELECT alert_type FROM alerts WHERE device_id=? AND resolved_at IS NULL",(did,))}
        if not d.get("online") and not d.get("expected_offline"):active["device_offline"]=("critical","Device is offline","")
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
        preserve=set()
        media_observability=d.get("collector_status",{}).get("media_errors",{}).get("status")
        if media_observability == "unavailable":
            preserve.update(x["fingerprint"] for x in self.db.rows(
                "SELECT fingerprint FROM alerts WHERE device_id=? AND alert_type='media_io_errors' AND resolved_at IS NULL",
                (did,)))
        for medium in d.get("media",[]):
            if medium.get("media_errors"):active[f"media_io_errors:{medium.get('device')}"]=("critical",f"Storage media {medium.get('device')} is reporting I/O errors ({medium.get('io_errors')} logged)",medium.get("device"))
            elif medium.get("io_error_status") == "unknown":preserve.add(f"{did}:media_io_errors:{medium.get('device')}")
        for name,status in d.get("integrations",{}).items():
            if not isinstance(status,dict) or not status.get("enabled",True):continue
            # Service failures remain owned by the generic service fingerprint.
            # Plugins only report distinct application/data-path conditions.
            for condition in status.get("conditions",[]):
                if condition.get("service"):continue
                key=str(condition.get("type") or f"{name}_unhealthy")
                active[f"{key}:{name}"]=(condition.get("severity","warning"),condition.get("message",f"{name} is unhealthy"),name)
        # Statistical anomalies reuse the same reconcile lifecycle: the metric
        # is the fingerprint resource, so a sustained deviation keeps one
        # alert alive and the hysteresis z-band decides resolution.
        if self.anomaly is not None and self.anomaly.enabled:
            prefix=f"{did}:anomaly:"
            open_metrics={row["fingerprint"][len(prefix):] for row in self.db.rows(
                "SELECT fingerprint FROM alerts WHERE device_id=? AND alert_type='anomaly' AND fingerprint LIKE ?",
                (did,f"{prefix}%")) if row["fingerprint"].startswith(prefix)}
            for a in self.anomaly.observe(d,stamp,open_metrics):
                active[f"anomaly:{a['metric']}"]=(a["severity"],a["message"],a["metric"])
        return self._reconcile(d,did,active,stamp,preserve)
    def _reconcile(self,d,did,active,stamp,preserve=None):
        preserve=preserve or set()
        existing={x["fingerprint"]:x for x in self.db.rows("SELECT * FROM alerts WHERE device_id=? AND resolved_at IS NULL",(did,))}
        seen=set(); opened=[]; resolved=[]
        for key,(sev,msg,resource) in active.items():
            typ=key.split(":",1)[0]; fp=f"{did}:{typ}:{resource}";seen.add(fp)
            if fp in existing:
                row=existing[fp]
                muted_until=row.get("muted_until")
                mute_expired=row.get("state")=="muted" and (not muted_until or datetime.fromisoformat(muted_until)<=datetime.fromisoformat(stamp))
                state="acknowledged" if row.get("acknowledged_at") else "active"
                if mute_expired:self.db.execute("UPDATE alerts SET last_seen_at=?,severity=?,message=?,muted_until=NULL,state=? WHERE alert_id=?",(stamp,sev,msg,state,row["alert_id"]))
                else:self.db.execute("UPDATE alerts SET last_seen_at=?,severity=?,message=? WHERE alert_id=?",(stamp,sev,msg,row["alert_id"]))
            else:
                alert_id=self.db.execute("INSERT INTO alerts(device_id,alert_type,severity,message,fingerprint,opened_at,last_seen_at,state,metadata_json) VALUES(?,?,?,?,?,?,?,?,?)",(did,typ,sev,msg,fp,stamp,stamp,"active",json.dumps({"resource":resource})))
                opened.append({"alert_id":alert_id,"device_id":did,"alert_type":typ,"severity":sev,"message":msg})
        for fp,row in existing.items():
            if fp not in seen and fp not in preserve:
                self.db.execute("UPDATE alerts SET resolved_at=?,state='resolved' WHERE alert_id=?",(stamp,row["alert_id"]));self._write_event(did,"alert_resolved","info",f"Recovered: {row['message']}",{"alert_id":row["alert_id"]},stamp)
                # row was fetched before this UPDATE, so its own resolved_at
                # is still stale (None) -- fold in the real resolution stamp
                # so downstream consumers (incident synthesis: see
                # pinoc.incidents.synthesize_alert) see the correct time
                # instead of falling back to wall-clock now().
                resolved.append({**row,"resolved_at":stamp,"state":"resolved"})
        return opened,resolved
    def _topology(self):
        """Build a fresh pinoc.topology.NetworkTopology from the current
        roster (self.previous), or None when the section is absent/off.
        Cheap: pairs/segments are always bounded (see pinoc.topology), and
        this only runs when there is alert activity to correlate."""
        if not self.topology_config or not self.topology_config.get("enabled",False):
            return None
        from .topology import NetworkTopology, parse_topology_config
        tags={did:tuple(d.get("tags") or ()) for did,d in self.previous.items()}
        try:
            parsed=parse_topology_config(self.topology_config,self.previous.keys(),tags)
        except Exception as exc:
            LOG.warning("invalid network_topology configuration: %s",exc)
            return None
        return NetworkTopology(self.db,parsed)
    def _correlate(self,opened,resolved,stamp):
        outcome=None
        if self.correlation.enabled and (opened or resolved):
            self.correlation.topology=self._topology()
            try:outcome=self.correlation.reconcile({a["alert_id"] for a in opened},resolved,self.previous,stamp)
            except Exception as exc:LOG.warning("alert correlation failed; falling back to per-alert notifications: %s",exc)
        absorbed_open=outcome.absorbed_open if outcome else set()
        absorbed_resolve=outcome.absorbed_resolve if outcome else set()
        for alert in opened:
            if alert["alert_id"] not in absorbed_open:
                self._notify(self.previous.get(alert["device_id"],{}),alert["device_id"],"open",alert)
        for row in resolved:
            if row["alert_id"] not in absorbed_resolve:
                self._notify(self.previous.get(row["device_id"],{}),row["device_id"],"resolve",row)
                self._synthesize_incident_alert(row)
        if outcome:
            for event in outcome.events:self._notify_cluster(event)
            for cluster in outcome.resolved_clusters:self._synthesize_incident_cluster(cluster)
    def _notify(self,d,did,transition,row):
        if self.notifier is None:return
        name=d.get("friendly_name") or d.get("hostname") or did
        try:self.notifier.enqueue(transition,row,name)
        except Exception as exc:LOG.warning("notification enqueue failed: %s",exc)
    def _notify_cluster(self,event):
        if self.notifier is None:return
        transition=event.get("type")
        if transition not in ("open","resolve"):return
        cluster=event["cluster"]
        members=self.db.rows("SELECT device_id FROM alerts WHERE cluster_id=?",(cluster["cluster_id"],))
        names=[]
        for member in members:
            info=self.previous.get(member["device_id"],{})
            names.append(info.get("friendly_name") or info.get("hostname") or member["device_id"])
        try:label=json.loads(cluster.get("context_json") or "{}").get("label")
        except (TypeError,ValueError):label=None
        context=describe_context(cluster["context_key"],cluster["context_value"],label)
        if transition=="open":
            shown=", ".join(names[:6])+(f" +{len(names)-6} more" if len(names)>6 else "")
            message=f"{len(names)} devices share {context}: {shown}"
        else:
            message=f"Cluster recovered ({len(names)} devices) — {context}"
        synthetic={"device_id":None,"alert_type":f"cluster_{cluster['trigger_class']}","severity":cluster["severity"],"message":message}
        try:self.notifier.enqueue(transition,synthetic,f"{cluster['trigger_class'].title()} cluster · {context}")
        except Exception as exc:LOG.warning("cluster notification enqueue failed: %s",exc);return
        flag="notified_open" if transition=="open" else "notified_resolved"
        self.db.execute(f"UPDATE alert_clusters SET {flag}=1 WHERE cluster_id=?",(cluster["cluster_id"],))
    def _synthesize_incident_alert(self,row):
        # Incident timelines and automatic post-mortems (see
        # pinoc.incidents): triggered inline off the same resolve path as
        # notifications, not a separate poll, so an incident exists as soon
        # as the resolving reconcile pass commits. A synthesis bug must
        # never take down history logging, hence the broad catch.
        try:
            from .incidents import synthesize_alert
            synthesize_alert(self.db,row)
        except Exception:LOG.warning("incident synthesis failed for alert %s",row.get("alert_id"),exc_info=True)
    def _synthesize_incident_cluster(self,cluster):
        try:
            from .incidents import synthesize_cluster
            synthesize_cluster(self.db,cluster)
        except Exception:LOG.warning("incident synthesis failed for cluster %s",cluster.get("cluster_id"),exc_info=True)
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
            con.execute("DELETE FROM device_metrics WHERE timestamp<?",((now-timedelta(days=raw)).isoformat(),));con.execute("DELETE FROM network_metrics WHERE timestamp<?",((now-timedelta(days=raw)).isoformat(),));con.execute("DELETE FROM storage_metrics WHERE timestamp<?",((now-timedelta(days=raw)).isoformat(),));con.execute("DELETE FROM integration_metrics WHERE timestamp<?",((now-timedelta(days=raw)).isoformat(),));con.execute("DELETE FROM media_metrics WHERE timestamp<?",((now-timedelta(days=raw)).isoformat(),));con.execute("DELETE FROM service_logs WHERE timestamp<?",(cutoff,));con.execute("DELETE FROM metric_aggregates WHERE resolution='hourly' AND bucket<?",((now-timedelta(days=hourly)).isoformat(),));con.execute("DELETE FROM metric_aggregates WHERE resolution='daily' AND bucket<?",((now-timedelta(days=daily)).isoformat(),));con.execute("DELETE FROM storage_aggregates WHERE resolution='hourly' AND bucket<?",((now-timedelta(days=hourly)).isoformat(),));con.execute("DELETE FROM network_aggregates WHERE resolution='hourly' AND bucket<?",((now-timedelta(days=hourly)).isoformat(),))
            # SLOs and reliability scoring (enhancement #3): health_samples
            # gets its own, longer retention (see pinoc.slo), not the raw
            # metrics window above -- an SLO window is commonly 30 days.
            con.execute("DELETE FROM health_samples WHERE timestamp<?",((now-timedelta(days=self.health_sample_retention_days)).isoformat(),))
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
