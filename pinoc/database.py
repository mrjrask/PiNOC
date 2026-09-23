"""SQLite history store with ordered, transactional migrations."""
from __future__ import annotations
import json, logging, sqlite3, threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Optional, Tuple

LOG = logging.getLogger("pinoc.database")
UTC = timezone.utc
SCHEMA_VERSION = 16

MIGRATIONS = (
"""CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
INSERT INTO schema_version SELECT 0 WHERE NOT EXISTS(SELECT 1 FROM schema_version);
CREATE TABLE devices(device_id TEXT PRIMARY KEY,hostname TEXT,friendly_name TEXT,first_seen TEXT,last_seen TEXT,first_ip TEXT,last_ip TEXT,model TEXT,roles_json TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE device_metrics(id INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,device_id TEXT NOT NULL,cpu_percent REAL,load_1m REAL,load_5m REAL,load_15m REAL,cpu_freq_mhz REAL,cpu_temp_c REAL,soc_temp_c REAL,memory_percent REAL,memory_used_bytes INTEGER,swap_percent REAL,uptime_seconds INTEGER,UNIQUE(device_id,timestamp));
CREATE TABLE storage_metrics(id INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,device_id TEXT NOT NULL,device TEXT,mount_point TEXT NOT NULL,filesystem TEXT,total_bytes INTEGER,used_bytes INTEGER,available_bytes INTEGER,percent_used REAL,read_only INTEGER,UNIQUE(device_id,mount_point,timestamp));
CREATE TABLE network_metrics(id INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,device_id TEXT NOT NULL,interface TEXT NOT NULL,ip_address TEXT,rx_rate_bps REAL,tx_rate_bps REAL,rx_total_bytes INTEGER,tx_total_bytes INTEGER,wifi_signal_dbm REAL,wifi_quality_percent REAL,UNIQUE(device_id,interface,timestamp));
CREATE TABLE service_status(id INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,device_id TEXT NOT NULL,service_name TEXT NOT NULL,normalized_state TEXT,active_state TEXT,sub_state TEXT,main_pid INTEGER,memory_bytes INTEGER,restart_count INTEGER);
CREATE TABLE alerts(alert_id INTEGER PRIMARY KEY,device_id TEXT NOT NULL,alert_type TEXT NOT NULL,severity TEXT NOT NULL,message TEXT NOT NULL,fingerprint TEXT NOT NULL,opened_at TEXT NOT NULL,last_seen_at TEXT NOT NULL,resolved_at TEXT,acknowledged_at TEXT,acknowledged_by TEXT,muted_until TEXT,state TEXT NOT NULL,metadata_json TEXT NOT NULL DEFAULT '{}');
CREATE UNIQUE INDEX alerts_one_open ON alerts(fingerprint) WHERE resolved_at IS NULL;
CREATE TABLE events(event_id INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,device_id TEXT,event_type TEXT NOT NULL,severity TEXT NOT NULL,message TEXT NOT NULL,metadata_json TEXT NOT NULL DEFAULT '{}');
CREATE TABLE metric_aggregates(bucket TEXT NOT NULL,resolution TEXT NOT NULL,device_id TEXT NOT NULL,avg_cpu REAL,max_cpu REAL,avg_temp REAL,min_temp REAL,max_temp REAL,avg_memory REAL,sample_count INTEGER NOT NULL,PRIMARY KEY(bucket,resolution,device_id));
CREATE TABLE storage_aggregates(bucket TEXT NOT NULL,resolution TEXT NOT NULL,device_id TEXT NOT NULL,mount_point TEXT NOT NULL,min_used INTEGER,max_used INTEGER,latest_used INTEGER,total_bytes INTEGER,sample_count INTEGER NOT NULL,PRIMARY KEY(bucket,resolution,device_id,mount_point));
CREATE TABLE maintenance_state(key TEXT PRIMARY KEY,value TEXT);
CREATE INDEX device_metrics_device_time ON device_metrics(device_id,timestamp); CREATE INDEX storage_device_mount_time ON storage_metrics(device_id,mount_point,timestamp); CREATE INDEX network_device_time ON network_metrics(device_id,timestamp); CREATE INDEX service_device_name_time ON service_status(device_id,service_name,timestamp); CREATE INDEX alerts_state ON alerts(state); CREATE INDEX alerts_device ON alerts(device_id); CREATE INDEX events_device_time ON events(device_id,timestamp); CREATE INDEX events_time ON events(timestamp);""",
"""CREATE INDEX IF NOT EXISTS alerts_type ON alerts(alert_type); CREATE INDEX IF NOT EXISTS events_type ON events(event_type);""",
"""CREATE TABLE network_aggregates(bucket TEXT NOT NULL,resolution TEXT NOT NULL,device_id TEXT NOT NULL,interface TEXT NOT NULL,avg_rx_rate REAL,avg_tx_rate REAL,avg_wifi_signal REAL,avg_wifi_quality REAL,sample_count INTEGER NOT NULL,PRIMARY KEY(bucket,resolution,device_id,interface));""",
"""CREATE TABLE integration_metrics(id INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,device_id TEXT NOT NULL,integration TEXT NOT NULL,metric TEXT NOT NULL,value REAL,unit TEXT,UNIQUE(timestamp,device_id,integration,metric));
CREATE INDEX integration_metrics_device_time ON integration_metrics(device_id,integration,timestamp);
CREATE TABLE network_inventory(identity TEXT PRIMARY KEY,ip TEXT,mac TEXT,hostname TEXT,vendor TEXT,first_seen TEXT,last_seen TEXT,managed_device_id TEXT,data_json TEXT NOT NULL DEFAULT '{}');""",
"""CREATE TABLE users(username TEXT PRIMARY KEY,password_hash TEXT NOT NULL,role TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,last_login TEXT);
CREATE TABLE api_tokens(token_id TEXT PRIMARY KEY,secret_hash TEXT NOT NULL,owner TEXT NOT NULL,scopes_json TEXT NOT NULL,created_at TEXT NOT NULL,last_used TEXT,enabled INTEGER NOT NULL DEFAULT 1,FOREIGN KEY(owner) REFERENCES users(username));
CREATE TABLE action_jobs(job_id TEXT PRIMARY KEY,device_id TEXT NOT NULL,action TEXT NOT NULL,target TEXT,parameters_json TEXT NOT NULL DEFAULT '{}',requested_by TEXT NOT NULL,requested_role TEXT NOT NULL,source_ip TEXT,requested_at TEXT NOT NULL,started_at TEXT,completed_at TEXT,status TEXT NOT NULL,exit_code INTEGER,summary TEXT,error TEXT,duration_ms INTEGER);
CREATE INDEX action_jobs_time ON action_jobs(requested_at); CREATE INDEX action_jobs_device_status ON action_jobs(device_id,status);
CREATE TABLE audit_records(audit_id INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,user TEXT NOT NULL,role TEXT NOT NULL,source_ip TEXT,device_id TEXT,action TEXT NOT NULL,target TEXT,parameters_json TEXT NOT NULL DEFAULT '{}',authorization_result TEXT NOT NULL,execution_result TEXT,exit_code INTEGER,duration_ms INTEGER,error TEXT);
CREATE INDEX audit_time ON audit_records(timestamp); CREATE INDEX audit_device ON audit_records(device_id); CREATE INDEX audit_action ON audit_records(action);
CREATE TABLE device_operational_state(device_id TEXT PRIMARY KEY,maintenance_until TEXT,maintenance_reason TEXT,expected_offline INTEGER NOT NULL DEFAULT 0,expected_offline_reason TEXT,expected_offline_until TEXT,updated_at TEXT NOT NULL,updated_by TEXT NOT NULL);""",
"""ALTER TABLE api_tokens ADD COLUMN device_restrictions_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE api_tokens ADD COLUMN workspace_restrictions_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE api_tokens ADD COLUMN job_type_restrictions_json TEXT NOT NULL DEFAULT '[]';
CREATE TABLE agent_enrollment_codes(code_id TEXT PRIMARY KEY,secret_hash TEXT NOT NULL,device_id TEXT NOT NULL,created_at TEXT NOT NULL,expires_at TEXT NOT NULL,used_at TEXT,created_by TEXT NOT NULL);
CREATE TABLE agents(agent_id TEXT PRIMARY KEY,device_id TEXT NOT NULL UNIQUE,credential_hash TEXT NOT NULL,hostname TEXT,model TEXT,architecture TEXT,agent_version TEXT NOT NULL,protocol_version INTEGER NOT NULL,status TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,credential_revoked INTEGER NOT NULL DEFAULT 0,capabilities_json TEXT NOT NULL DEFAULT '{}',hardware_json TEXT NOT NULL DEFAULT '{}',candidates_json TEXT NOT NULL DEFAULT '[]',created_at TEXT NOT NULL,last_seen TEXT,credential_rotated_at TEXT);
CREATE INDEX agents_status ON agents(status,last_seen);
CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY,device_id TEXT NOT NULL,path TEXT NOT NULL,repository TEXT,mode TEXT NOT NULL DEFAULT 'read_only',execution_user TEXT,allowed_job_types_json TEXT NOT NULL DEFAULT '[]',allowed_commands_json TEXT NOT NULL DEFAULT '[]',allowed_env_json TEXT NOT NULL DEFAULT '[]',test_profiles_json TEXT NOT NULL DEFAULT '{}',services_json TEXT NOT NULL DEFAULT '[]',artifact_patterns_json TEXT NOT NULL DEFAULT '[]',sensitive_patterns_json TEXT NOT NULL DEFAULT '[]',hardware_profile_json TEXT NOT NULL DEFAULT '{}',approved INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,UNIQUE(device_id,path));
CREATE INDEX workspaces_device ON workspaces(device_id,approved);
CREATE TABLE development_jobs(job_id TEXT PRIMARY KEY,parent_job_id TEXT,device_id TEXT NOT NULL,workspace_id TEXT,job_type TEXT NOT NULL,profile TEXT,argv_json TEXT NOT NULL DEFAULT '[]',environment_json TEXT NOT NULL DEFAULT '{}',permissions_json TEXT NOT NULL DEFAULT '[]',requested_by TEXT NOT NULL,api_token_id TEXT,source_ip TEXT,requested_at TEXT NOT NULL,approved_at TEXT,dispatched_at TEXT,started_at TEXT,completed_at TEXT,status TEXT NOT NULL,queue_reason TEXT,timeout_seconds INTEGER NOT NULL,exit_code INTEGER,error_type TEXT,summary TEXT,stdout TEXT NOT NULL DEFAULT '',stderr TEXT NOT NULL DEFAULT '',stdout_truncated INTEGER NOT NULL DEFAULT 0,stderr_truncated INTEGER NOT NULL DEFAULT 0,duration_ms INTEGER,request_json TEXT NOT NULL DEFAULT '{}',result_json TEXT NOT NULL DEFAULT '{}',cancel_requested INTEGER NOT NULL DEFAULT 0);
CREATE INDEX dev_jobs_time ON development_jobs(requested_at); CREATE INDEX dev_jobs_agent_status ON development_jobs(device_id,status); CREATE INDEX dev_jobs_workspace_status ON development_jobs(workspace_id,status);
CREATE TABLE job_artifacts(artifact_id TEXT PRIMARY KEY,job_id TEXT NOT NULL,name TEXT NOT NULL,storage_name TEXT NOT NULL,size_bytes INTEGER NOT NULL,sha256 TEXT NOT NULL,content_type TEXT NOT NULL,created_at TEXT NOT NULL,expires_at TEXT NOT NULL,FOREIGN KEY(job_id) REFERENCES development_jobs(job_id));
CREATE INDEX job_artifacts_job ON job_artifacts(job_id);
CREATE TABLE job_approvals(approval_id TEXT PRIMARY KEY,job_id TEXT NOT NULL,status TEXT NOT NULL,risk TEXT NOT NULL,requested_at TEXT NOT NULL,decided_at TEXT,decided_by TEXT,reason TEXT,FOREIGN KEY(job_id) REFERENCES development_jobs(job_id));
CREATE TABLE agent_request_nonces(agent_id TEXT NOT NULL,nonce TEXT NOT NULL,used_at TEXT NOT NULL,PRIMARY KEY(agent_id,nonce));""",
"""CREATE TABLE media_metrics(id INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,device_id TEXT NOT NULL,block_device TEXT NOT NULL,read_bytes INTEGER,written_bytes INTEGER,io_errors INTEGER,media_errors INTEGER,UNIQUE(device_id,block_device,timestamp));
CREATE INDEX media_device_time ON media_metrics(device_id,timestamp);""",
"""CREATE TABLE service_logs(id INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,device_id TEXT NOT NULL,unit TEXT NOT NULL,lines TEXT NOT NULL);
CREATE INDEX service_logs_device_unit_id ON service_logs(device_id,unit,id);
CREATE INDEX service_logs_time ON service_logs(timestamp);""",
"""CREATE TABLE action_schedules(schedule_id TEXT PRIMARY KEY,device_id TEXT NOT NULL,action TEXT NOT NULL,target TEXT,spec TEXT NOT NULL,timezone TEXT NOT NULL DEFAULT 'UTC',enabled INTEGER NOT NULL DEFAULT 1,paused INTEGER NOT NULL DEFAULT 0,requested_by TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,next_run TEXT,last_run TEXT,last_job_id TEXT,last_status TEXT,last_error TEXT,consecutive_failures INTEGER NOT NULL DEFAULT 0);
CREATE INDEX action_schedules_run ON action_schedules(enabled,paused,next_run);""",
"""CREATE TABLE metric_baselines(device_id TEXT NOT NULL,metric TEXT NOT NULL,hour INTEGER NOT NULL DEFAULT -1,ewma_mean REAL,ewma_var REAL,samples INTEGER NOT NULL DEFAULT 0,updated_at TEXT,PRIMARY KEY(device_id,metric,hour));
CREATE TABLE anomaly_previews(id INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,device_id TEXT NOT NULL,metric TEXT NOT NULL,value REAL,baseline_mean REAL,baseline_std REAL,z_score REAL,hour INTEGER NOT NULL DEFAULT -1);
CREATE INDEX anomaly_previews_time ON anomaly_previews(timestamp);
CREATE INDEX anomaly_previews_lookup ON anomaly_previews(device_id,metric);""",
"""ALTER TABLE alerts ADD COLUMN cluster_id INTEGER;
CREATE INDEX alerts_cluster ON alerts(cluster_id);
CREATE TABLE alert_clusters(cluster_id INTEGER PRIMARY KEY,trigger_class TEXT NOT NULL,context_key TEXT NOT NULL,context_value TEXT NOT NULL,context_json TEXT NOT NULL DEFAULT '{}',severity TEXT NOT NULL,opened_at TEXT NOT NULL,last_seen_at TEXT NOT NULL,resolved_at TEXT,notified_open INTEGER NOT NULL DEFAULT 0,notified_resolved INTEGER NOT NULL DEFAULT 0);
CREATE INDEX alert_clusters_open ON alert_clusters(resolved_at);
CREATE INDEX alert_clusters_lookup ON alert_clusters(trigger_class,context_key,context_value,resolved_at);""",
"""CREATE TABLE remediation_runs(fingerprint TEXT PRIMARY KEY,device_id TEXT NOT NULL,playbook_id TEXT NOT NULL,alert_type TEXT NOT NULL,action TEXT NOT NULL,target TEXT,policy TEXT NOT NULL,cooldown_seconds INTEGER NOT NULL,max_attempts INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,last_attempt_at TEXT,last_job_id TEXT,last_status TEXT,cooldown_until TEXT,approval_status TEXT,decided_by TEXT,decided_at TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE INDEX remediation_runs_device ON remediation_runs(device_id);
CREATE INDEX remediation_runs_approval ON remediation_runs(approval_status);""",
"""CREATE TABLE rollout_runs(run_id TEXT PRIMARY KEY,name TEXT NOT NULL DEFAULT '',scope TEXT NOT NULL,device_selector_json TEXT NOT NULL DEFAULT '{}',canary_count INTEGER NOT NULL DEFAULT 0,wave_size INTEGER,respect_maintenance INTEGER NOT NULL DEFAULT 1,status TEXT NOT NULL,current_wave INTEGER NOT NULL DEFAULT 0,wave_count INTEGER NOT NULL DEFAULT 0,halted_reason TEXT,requested_by TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,started_at TEXT,completed_at TEXT);
CREATE INDEX rollout_runs_status ON rollout_runs(status);
CREATE TABLE rollout_devices(id INTEGER PRIMARY KEY,run_id TEXT NOT NULL,device_id TEXT NOT NULL,wave INTEGER NOT NULL,status TEXT NOT NULL,before_kernel TEXT,after_kernel TEXT,before_updates_available INTEGER,after_updates_available INTEGER,reboot_required INTEGER NOT NULL DEFAULT 0,update_job_id TEXT,reboot_job_id TEXT,error TEXT,dispatched_at TEXT,reboot_at TEXT,completed_at TEXT,updated_at TEXT NOT NULL,UNIQUE(run_id,device_id));
CREATE INDEX rollout_devices_run_wave ON rollout_devices(run_id,wave);
CREATE INDEX rollout_devices_run_status ON rollout_devices(run_id,status);""",
"""CREATE TABLE network_matrix_samples(id INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,source_id TEXT NOT NULL,target_id TEXT NOT NULL,latency_ms REAL,loss_percent REAL,ok INTEGER NOT NULL,error TEXT,UNIQUE(source_id,target_id,timestamp));
CREATE INDEX network_matrix_pair_time ON network_matrix_samples(source_id,target_id,timestamp);""",
"""CREATE TABLE user_presets(preset_id TEXT PRIMARY KEY,owner TEXT NOT NULL,kind TEXT NOT NULL,name TEXT NOT NULL,payload_json TEXT NOT NULL DEFAULT '{}',created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE INDEX user_presets_owner_kind ON user_presets(owner,kind);""",
# Incident timelines and automatic post-mortems (see pinoc/incidents.py):
# a synthesized record per resolved alert cluster or standalone alert. The
# incident row itself is intentionally small -- it stores only the
# identifying references (which cluster/alert it came from, the devices and
# member alert_ids involved) plus the computed MTTA/MTTR; the full timeline
# is reconstructed at read time from the existing alerts/events/action_jobs/
# notification_log tables rather than duplicated here. notification_log is
# a new, minimal persisted record of each outbound notification send (see
# NotificationService._record in pinoc/notifications.py), needed so a
# resolved incident's timeline can show what was actually sent, including
# after a restart.
"""CREATE TABLE incidents(incident_id INTEGER PRIMARY KEY,kind TEXT NOT NULL,source_id INTEGER,trigger_class TEXT NOT NULL DEFAULT '',title TEXT NOT NULL,severity TEXT NOT NULL,opened_at TEXT NOT NULL,resolved_at TEXT NOT NULL,mtta_seconds REAL,mttr_seconds REAL,device_ids_json TEXT NOT NULL DEFAULT '[]',alert_ids_json TEXT NOT NULL DEFAULT '[]',created_at TEXT NOT NULL,UNIQUE(kind,source_id));
CREATE INDEX incidents_opened ON incidents(opened_at); CREATE INDEX incidents_resolved ON incidents(resolved_at); CREATE INDEX incidents_severity ON incidents(severity);
CREATE TABLE notification_log(id INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,transition TEXT NOT NULL,device_id TEXT,alert_type TEXT,severity TEXT,channel_id TEXT,channel_kind TEXT,ok INTEGER NOT NULL,error TEXT);
CREATE INDEX notification_log_device_time ON notification_log(device_id,timestamp); CREATE INDEX notification_log_time ON notification_log(timestamp);""",
)

def utcnow() -> str: return datetime.now(UTC).isoformat()

class Database:
    def __init__(self, path: str, busy_timeout_ms: int = 3000):
        self.path=Path(path).expanduser(); self.busy_timeout_ms=busy_timeout_ms
        self.available=False; self.error=""; self.last_write=None
        self.last_aggregation=None; self.last_retention_cleanup=None
        self._local = threading.local()

    def connect(self, readonly: bool=False) -> sqlite3.Connection:
        target=f"file:{self.path}?mode=ro" if readonly else str(self.path)
        con=sqlite3.connect(target,uri=readonly,timeout=self.busy_timeout_ms/1000)
        con.row_factory=sqlite3.Row; con.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
        if not readonly: con.execute("PRAGMA journal_mode=WAL"); con.execute("PRAGMA foreign_keys=ON")
        return con

    def _pooled(self, readonly: bool, attr: str) -> sqlite3.Connection:
        # execute()/rows()/initialize()/backup() run far more often than the
        # database file is ever replaced wholesale (a backup restore), so
        # cache one connection per thread per mode instead of paying a fresh
        # connect() + PRAGMA round-trip on every single call. Each thread
        # gets its own connection -- sqlite3 connections must not be shared
        # across threads -- and a cheap inode check (much cheaper than
        # reconnecting) detects the rare case where the file at this path
        # was replaced out from under an already-open connection, so a
        # restore is picked up exactly as it was when every call reconnected
        # fresh, without needing to wait for a service restart.
        try:
            current_ino: Optional[int] = self.path.stat().st_ino
        except OSError:
            current_ino = None
        cached: Optional[Tuple[sqlite3.Connection, Optional[int]]] = getattr(self._local, attr, None)
        if cached is not None and current_ino is not None and cached[1] == current_ino:
            return cached[0]
        if cached is not None:
            try: cached[0].close()
            except sqlite3.Error: pass
        con = self.connect(readonly)
        # The very first connection may create the file (it did not exist
        # to stat() above, hence current_ino is None there), so re-stat
        # afterward -- otherwise every later call would see a real inode
        # that never matches the None it cached and reconnect needlessly.
        try:
            current_ino = self.path.stat().st_ino
        except OSError:
            current_ino = None
        setattr(self._local, attr, (con, current_ino))
        return con

    @contextmanager
    def _open(self, readonly: bool=False) -> Iterator[sqlite3.Connection]:
        # sqlite3.Connection's own context-manager protocol only commits/
        # rolls back the transaction; it never closes the connection. That's
        # now what we want for the common case (the connection is pooled per
        # thread, not closed after every call) -- but a connection that
        # raised must not be handed back out again: drop it so the next call
        # reconnects fresh, matching the resilience a fresh-connection-per-
        # call design had against a transient error (a brief I/O hiccup, a
        # connection the OS or SQLite itself decided to tear down).
        attr = "_ro_con" if readonly else "_rw_con"
        con=self._pooled(readonly, attr)
        try:
            with con: yield con
        except Exception:
            try: con.close()
            except sqlite3.Error: pass
            if getattr(self._local, attr, None) is not None and getattr(self._local, attr)[0] is con:
                setattr(self._local, attr, None)
            raise

    def initialize(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True,exist_ok=True)
            with self._open() as con:
                con.execute("CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL)")
                row=con.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
                version=int(row[0]) if row else 0
                if not row: con.execute("INSERT INTO schema_version VALUES(0)")
                if version>SCHEMA_VERSION: raise RuntimeError(f"database schema {version} is newer than supported {SCHEMA_VERSION}")
                for number,sql in enumerate(MIGRATIONS,1):
                    if version<number:
                        con.executescript(f"BEGIN IMMEDIATE;\n{sql}\nUPDATE schema_version SET version={number};\nCOMMIT;")
                        version=number
            self.available=True; self.error=""; return True
        except Exception as exc:
            self.available=False; self.error=str(exc); LOG.exception("history database unavailable; live monitoring continues: %s",exc); return False

    def execute(self, sql: str, params: Iterable[Any]=()) -> int:
        with self._open() as con:
            cur=con.execute(sql,tuple(params)); self.last_write=utcnow(); self.available=True; return int(cur.lastrowid or 0)

    def rows(self, sql: str, params: Iterable[Any]=()) -> list[Dict[str,Any]]:
        if not self.available: return []
        try:
            with self._open(True) as con: return [dict(x) for x in con.execute(sql,tuple(params)).fetchall()]
        except Exception as exc: self.error=str(exc); return []

    def status(self) -> Dict[str,Any]:
        result={"status":"ok" if self.available else "unavailable","schema_version":SCHEMA_VERSION if self.available else None,"last_write":self.last_write,"error":self.error or None}
        try: result["size_bytes"]=self.path.stat().st_size
        except OSError: result["size_bytes"]=0
        if self.available:
            result.update({"oldest_raw_metric":self.scalar("SELECT MIN(timestamp) FROM device_metrics"),"newest_metric":self.scalar("SELECT MAX(timestamp) FROM device_metrics"),"active_alerts":self.scalar("SELECT COUNT(*) FROM alerts WHERE resolved_at IS NULL"),"event_count":self.scalar("SELECT COUNT(*) FROM events"),"last_aggregation_run":self.last_aggregation,"last_retention_cleanup":self.last_retention_cleanup})
        return result

    def scalar(self,sql:str,params:Iterable[Any]=()):
        rows=self.rows(sql,params); return next(iter(rows[0].values())) if rows else None

    def backup(self,destination:str) -> None:
        with self._open(True) as source:
            dest=sqlite3.connect(destination)
            try: source.backup(dest)
            finally: dest.close()

def main() -> int:
    import argparse, os
    p=argparse.ArgumentParser(); p.add_argument("command",choices=("backup","status","vacuum")); p.add_argument("target",nargs="?"); p.add_argument("--database",default=os.getenv("PINOC_DATABASE_PATH","data/pinoc.db")); a=p.parse_args(); db=Database(a.database)
    if not db.initialize(): return 1
    if a.command=="backup":
        if not a.target: p.error("backup requires target")
        db.backup(a.target)
    elif a.command=="vacuum": db.execute("VACUUM")
    else: print(json.dumps(db.status(),indent=2))
    return 0
if __name__=="__main__": raise SystemExit(main())
