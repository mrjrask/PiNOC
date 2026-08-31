"""Explicit, allowlisted, asynchronous operational actions (never a shell)."""
from __future__ import annotations
import json, os, queue, re, subprocess, threading, time, uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from pinoc.database import utcnow
from pinoc.security import redact

UNIT=re.compile(r"[A-Za-z0-9_.@:-]{1,128}\.service$")
MAX_OUTPUT=8192

@dataclass(frozen=True)
class ActionDefinition:
    id:str;label:str;permission:str="actions.execute";confirmation:str="simple";timeout:int=30;conflict:str="device";handler:Callable|None=None

class ActionError(ValueError):pass

class ActionDispatcher:
    def __init__(self,db,state,coordinator=None,max_workers=2,runner=subprocess.run):
        self.db=db;self.state=state;self.coordinator=coordinator;self.runner=runner;self.queue=queue.Queue();self.stop_event=threading.Event();self.locks={};self.threads=[]
        self.registry={
          "device.refresh":ActionDefinition("device.refresh","Refresh now",timeout=10,conflict="refresh",handler=self._refresh),
          "device.reboot":ActionDefinition("device.reboot","Reboot device","device.power","strong",10,handler=self._power),
          "device.shutdown":ActionDefinition("device.shutdown","Shut down device","device.power","strong",10,handler=self._power),
          "service.start":ActionDefinition("service.start","Start service",handler=self._service),
          "service.stop":ActionDefinition("service.stop","Stop service","actions.execute","strong",30,handler=self._service),
          "service.restart":ActionDefinition("service.restart","Restart service",handler=self._service),
          "wireguard.restart":ActionDefinition("wireguard.restart","Restart WireGuard",handler=self._integration_service),
          "desk_display.restart":ActionDefinition("desk_display.restart","Restart desk display",handler=self._integration_service),
          "magicmirror.restart":ActionDefinition("magicmirror.restart","Restart MagicMirror","actions.execute","simple",60,handler=self._integration_service),
          "pi_hotspot.restart":ActionDefinition("pi_hotspot.restart","Restart hotspot",handler=self._integration_service),
          "package.check":ActionDefinition("package.check","Check package metadata",handler=self._package_check),
        }
        if db and db.available:
            db.execute("UPDATE action_jobs SET status='failed',completed_at=?,error='PiNOC restarted while action was running' WHERE status IN ('running','queued')",(utcnow(),))
        for n in range(max(1,min(4,int(max_workers)))):
            t=threading.Thread(target=self._worker,name=f"action-worker-{n}",daemon=True);t.start();self.threads.append(t)
    def definition(self,action):
        if action not in self.registry:raise ActionError("unsupported action")
        return self.registry[action]
    def validate(self,action,device_id,target=None):
        definition=self.definition(action);device=self.state.device(device_id)
        if not device:raise ActionError("device not found")
        if not device.get("online") and action not in {"device.refresh"}:raise ActionError("device is offline")
        if action.startswith("service."):
            if not target or not UNIT.fullmatch(target) or target not in device.get("manageable_services",[]):raise ActionError("service is not approved for management")
        if action.endswith(".restart") and not action.startswith("service."):
            service={"wireguard.restart":"wg-quick@wg0.service","desk_display.restart":"desk-display.service","magicmirror.restart":"magicmirror.service","pi_hotspot.restart":"pi-hotspot.service"}[action]
            cfg=(device.get("integrations") or {}).get(action.split(".")[0],{})
            if isinstance(cfg,dict):service=cfg.get("service",service)
            if service not in device.get("manageable_services",[]):raise ActionError("integration service is not approved for management")
        if action=="package.check" and action not in device.get("allowed_actions",[]):raise ActionError("package metadata checks are not approved for this device")
        running=self.db.scalar("SELECT COUNT(*) FROM action_jobs WHERE device_id=? AND status IN ('queued','running')",(device_id,)) if self.db else 0
        if running and definition.conflict!="refresh":raise ActionError("a conflicting device action is already pending")
        return definition,device
    def enqueue(self,action,device_id,target,actor,role,source_ip=None,parameters=None):
        definition,_=self.validate(action,device_id,target);job_id=str(uuid.uuid4());stamp=utcnow();params=json.dumps(redact(parameters or {}),sort_keys=True)
        self.db.execute("INSERT INTO action_jobs(job_id,device_id,action,target,parameters_json,requested_by,requested_role,source_ip,requested_at,status) VALUES(?,?,?,?,?,?,?,?,?,?)",(job_id,device_id,action,target,params,actor,role,source_ip,stamp,"queued"))
        self.audit(actor,role,source_ip,device_id,action,target,parameters,"allowed","queued")
        self.queue.put(job_id);return self.get(job_id)
    def audit(self,user,role,ip,device,action,target,params,auth,result=None,exit_code=None,duration=None,error=None):
        self.db.execute("INSERT INTO audit_records(timestamp,user,role,source_ip,device_id,action,target,parameters_json,authorization_result,execution_result,exit_code,duration_ms,error) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(utcnow(),user,role,ip,device,action,target,json.dumps(redact(params or {}),sort_keys=True),auth,result,exit_code,duration,redact(error) if error else None))
    def get(self,job_id):
        rows=self.db.rows("SELECT * FROM action_jobs WHERE job_id=?",(job_id,));return redact(rows[0]) if rows else None
    def list(self,limit=50):return [redact(x) for x in self.db.rows("SELECT * FROM action_jobs ORDER BY requested_at DESC LIMIT ?",(limit,))]
    def _worker(self):
        while not self.stop_event.is_set():
            try:job_id=self.queue.get(timeout=.2)
            except queue.Empty:continue
            row=self.get(job_id)
            if not row:continue
            lock=self.locks.setdefault(row["device_id"],threading.Lock())
            with lock:self._execute(row)
            self.queue.task_done()
    def _execute(self,row):
        started=utcnow();before=time.monotonic();self.db.execute("UPDATE action_jobs SET status='running',started_at=? WHERE job_id=?",(started,row["job_id"]))
        definition=self.registry[row["action"]]
        try:
            result=definition.handler(row,definition.timeout);code=int(result.get("exit_code",0));status="succeeded" if code==0 else "failed";summary=result.get("summary") or ("Action completed" if not code else "Remote system returned a non-zero exit code");error=result.get("error")
        except subprocess.TimeoutExpired:status="timed_out";code=None;summary="Action timed out";error=f"action exceeded {definition.timeout} second timeout"
        except Exception as exc:status="failed";code=None;summary="Action failed";error=str(redact(exc))[:500]
        duration=int((time.monotonic()-before)*1000);done=utcnow()
        self.db.execute("UPDATE action_jobs SET status=?,completed_at=?,exit_code=?,summary=?,error=?,duration_ms=? WHERE job_id=?",(status,done,code,summary,error,duration,row["job_id"]))
        self.audit(row["requested_by"],row["requested_role"],row.get("source_ip"),row["device_id"],row["action"],row.get("target"),{},"allowed",status,code,duration,error)
        if status=="succeeded" and self.coordinator:self.coordinator.refresh_device(row["device_id"]) if hasattr(self.coordinator,"refresh_device") else self.coordinator.refresh()
    def _command(self,device,args,timeout):
        if device.get("collection_method")=="local":cmd=args
        else:
            cmd=["ssh","-p",str(int(device.get("ssh_port",22))),"-o",f"ConnectTimeout={max(1,min(timeout,10))}","-o","BatchMode=yes",f"{device.get('ssh_user','pi')}@{device['address']}","--",*args]
        proc=self.runner(cmd,text=True,capture_output=True,timeout=timeout,check=False,env={**os.environ,"LC_ALL":"C"})
        output=((proc.stdout or "")+("\n" if proc.stdout and proc.stderr else "")+(proc.stderr or ""))[:MAX_OUTPUT]
        return {"exit_code":proc.returncode,"summary":"Command completed" if proc.returncode==0 else f"Remote system returned exit code {proc.returncode}","error":None if proc.returncode==0 else redact(output)}
    def _refresh(self,row,timeout):
        if not self.coordinator:raise ActionError("collector scheduling unavailable")
        self.coordinator.refresh_device(row["device_id"]) if hasattr(self.coordinator,"refresh_device") else self.coordinator.refresh();return {"exit_code":0,"summary":"Refresh scheduled"}
    def _service(self,row,timeout):return self._command(self.state.device(row["device_id"]),["sudo","-n","systemctl",row["action"].split(".")[1],row["target"]],timeout)
    def _integration_service(self,row,timeout):
        device=self.state.device(row["device_id"]); default={"wireguard.restart":"wg-quick@wg0.service","desk_display.restart":"desk-display.service","magicmirror.restart":"magicmirror.service","pi_hotspot.restart":"pi-hotspot.service"}[row["action"]]
        return self._command(device,["sudo","-n","systemctl","restart",default],timeout)
    def _package_check(self,row,timeout):return self._command(self.state.device(row["device_id"]),["/usr/bin/apt-get","--just-print","upgrade"],timeout)
    def set_maintenance(self,device_id,actor,reason="",seconds=None):
        if not self.state.device(device_id):raise ActionError("device not found")
        until=(datetime.now(timezone.utc)+timedelta(seconds=seconds)).isoformat() if seconds else None
        self.db.execute("INSERT INTO device_operational_state VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET maintenance_until=excluded.maintenance_until,maintenance_reason=excluded.maintenance_reason,expected_offline=excluded.expected_offline,expected_offline_reason=excluded.expected_offline_reason,expected_offline_until=excluded.expected_offline_until,updated_at=excluded.updated_at,updated_by=excluded.updated_by",(device_id,until,reason,1,"maintenance",until,utcnow(),actor));self.audit(actor,"operator",None,device_id,"maintenance.enter",None,{"reason":reason,"until":until},"allowed","succeeded");return self.operational_state(device_id)
    def clear_maintenance(self,device_id,actor):
        self.db.execute("UPDATE device_operational_state SET maintenance_until=NULL,maintenance_reason=NULL,expected_offline=0,expected_offline_reason=NULL,expected_offline_until=NULL,updated_at=?,updated_by=? WHERE device_id=?",(utcnow(),actor,device_id));self.audit(actor,"operator",None,device_id,"maintenance.clear",None,{},"allowed","succeeded")
        if self.coordinator:self.coordinator.refresh();return self.operational_state(device_id)
    def operational_state(self,device_id):
        rows=self.db.rows("SELECT * FROM device_operational_state WHERE device_id=?",(device_id,));row=rows[0] if rows else {}
        until=row.get("maintenance_until")
        if until and datetime.fromisoformat(until)<=datetime.now(timezone.utc):self.clear_maintenance(device_id,"system");return {}
        return row
    def _power(self,row,timeout):
        reason="reboot" if row["action"]=="device.reboot" else "shutdown";until=(datetime.now(timezone.utc)+timedelta(minutes=10)).isoformat() if reason=="reboot" else None
        self.db.execute("INSERT INTO device_operational_state VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET expected_offline=1,expected_offline_reason=excluded.expected_offline_reason,expected_offline_until=excluded.expected_offline_until,updated_at=excluded.updated_at,updated_by=excluded.updated_by",(row["device_id"],None,None,1,reason,until,utcnow(),row["requested_by"]))
        verb="reboot" if reason=="reboot" else "poweroff";return self._command(self.state.device(row["device_id"]),["sudo","-n","systemctl",verb],timeout)
    def stop(self):
        self.stop_event.set()
        for t in self.threads:t.join(timeout=1)
