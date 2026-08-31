"""SQLite history store with ordered, transactional migrations."""
from __future__ import annotations
import json, logging, shutil, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

LOG = logging.getLogger("pinoc.database")
UTC = timezone.utc
SCHEMA_VERSION = 3

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
)

def utcnow() -> str: return datetime.now(UTC).isoformat()

class Database:
    def __init__(self, path: str, busy_timeout_ms: int = 3000):
        self.path=Path(path).expanduser(); self.busy_timeout_ms=busy_timeout_ms
        self.available=False; self.error=""; self.last_write=None
        self.last_aggregation=None; self.last_retention_cleanup=None

    def connect(self, readonly: bool=False) -> sqlite3.Connection:
        target=f"file:{self.path}?mode=ro" if readonly else str(self.path)
        con=sqlite3.connect(target,uri=readonly,timeout=self.busy_timeout_ms/1000)
        con.row_factory=sqlite3.Row; con.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
        if not readonly: con.execute("PRAGMA journal_mode=WAL"); con.execute("PRAGMA foreign_keys=ON")
        return con

    def initialize(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True,exist_ok=True)
            with self.connect() as con:
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
        with self.connect() as con:
            cur=con.execute(sql,tuple(params)); self.last_write=utcnow(); self.available=True; return int(cur.lastrowid or 0)

    def rows(self, sql: str, params: Iterable[Any]=()) -> list[Dict[str,Any]]:
        if not self.available: return []
        try:
            with self.connect(True) as con: return [dict(x) for x in con.execute(sql,tuple(params)).fetchall()]
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
        with self.connect(True) as source, sqlite3.connect(destination) as dest: source.backup(dest)

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
