"""Persistent, policy-driven PiNOC development gateway.

Agents poll outbound.  They authenticate each request with a per-agent HMAC
credential; development clients never receive that credential.
"""
from __future__ import annotations
import base64, fnmatch, hashlib, hmac, json, mimetypes, os, secrets, time, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from pinoc.database import utcnow
def hash_token(secret):return hashlib.sha256(secret.encode()).hexdigest()
def redact(value):
    """Best-effort managed-secret redaction; application secrets are unknowable."""
    if isinstance(value,dict):return {str(k):("[REDACTED]" if any(x in str(k).lower() for x in ("password","secret","token","credential","private_key")) else redact(v)) for k,v in value.items()}
    if isinstance(value,list):return [redact(x) for x in value]
    if isinstance(value,str):
        import re
        return re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~-]+",r"\1[REDACTED]",value)
    return value

PROTOCOL_VERSION=1
AGENT_VERSION="1.0.0"
STATUSES={"queued","dispatched","running","succeeded","failed","timed_out","cancelled","agent_lost","rejected"}
READ_TYPES={"capabilities","workspace_info","git_status","git_diff","file_read","log_read","service_status"}
TEST_TYPES={"test","python","pytest","npm_test","artifact_collect"}
ALL_TYPES=READ_TYPES|TEST_TYPES|{"command","git_fetch"}
SENSITIVE=[".env",".env.*","*.pem","*.key","id_rsa","id_ed25519","credentials*","secrets*"]
FORBIDDEN_EXEC={"sudo","su","doas","pkexec","bash","sh","dash","zsh","fish","env"}
FORBIDDEN_GIT={"reset","clean","checkout","pull","push","switch","restore"}

class DevError(ValueError):
    def __init__(self,message,error_type="invalid_request",status=400):super().__init__(message);self.error_type=error_type;self.status=status

def _loads(row,key,default):
    try:return json.loads(row.get(key) or json.dumps(default))
    except (TypeError,json.JSONDecodeError):return default

class DevelopmentGateway:
    def __init__(self,db,artifact_root="data/jobs",config=None):
        self.db=db;self.config=config or {};self.root=Path(artifact_root).resolve();self.root.mkdir(parents=True,exist_ok=True)
        self.default_timeout=max(1,int(self.config.get("default_timeout_seconds",300)));self.max_timeout=max(self.default_timeout,min(1800,int(self.config.get("max_timeout_seconds",1800))))
        self.output_limit=max(1024,int(self.config.get("output_limit_bytes",262144)));self.file_limit=max(1024,int(self.config.get("file_read_limit_bytes",1048576)))
        self.artifact_file_limit=max(1024,int(self.config.get("artifact_file_limit_bytes",10*1024*1024)));self.artifact_total_limit=max(self.artifact_file_limit,int(self.config.get("artifact_total_limit_bytes",25*1024*1024)));self.artifact_count=max(1,min(100,int(self.config.get("artifact_count",20))))
        if db.available:db.execute("UPDATE development_jobs SET status='agent_lost',completed_at=?,error_type='agent_lost',summary='PiNOC restarted before agent reconciliation' WHERE status IN ('dispatched','running')",(utcnow(),))
    def audit(self,identity,ip,device,action,target,params,auth,result=None,error=None):
        self.db.execute("INSERT INTO audit_records(timestamp,user,role,source_ip,device_id,action,target,parameters_json,authorization_result,execution_result,error) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(utcnow(),identity.get("username","agent"),identity.get("role","agent"),ip,device,action,target,json.dumps(redact(params or {}),sort_keys=True),auth,result,redact(error) if error else None))
    def enrollment_code(self,device,actor,ttl=600):
        if not device or ttl<60 or ttl>3600:raise DevError("invalid device or lifetime")
        code_id=secrets.token_urlsafe(9);secret=secrets.token_urlsafe(32);now=datetime.now(timezone.utc)
        self.db.execute("INSERT INTO agent_enrollment_codes VALUES(?,?,?,?,?,?,?)",(code_id,hash_token(secret),device,now.isoformat(),(now+timedelta(seconds=ttl)).isoformat(),None,actor));return code_id+"."+secret
    def enroll(self,body):
        raw=str(body.get("enrollment_code", ""));code_id,sep,secret=raw.partition(".");rows=self.db.rows("SELECT * FROM agent_enrollment_codes WHERE code_id=?",(code_id,)) if sep else [];row=rows[0] if rows else None
        now=datetime.now(timezone.utc)
        if not row or row["used_at"] or datetime.fromisoformat(row["expires_at"])<now or not hmac.compare_digest(row["secret_hash"],hash_token(secret)):raise DevError("enrollment code rejected","agent_credential_rejected",401)
        version=str(body.get("agent_version",""))[:32];protocol=int(body.get("protocol_version",0));hostname=str(body.get("hostname",""))[:255]
        if not version or protocol!=PROTOCOL_VERSION:raise DevError("agent protocol incompatible","protocol_incompatible",409)
        agent_id=str(uuid.uuid4());credential=secrets.token_urlsafe(48);stamp=utcnow()
        self.db.execute("INSERT INTO agents(agent_id,device_id,credential_hash,hostname,model,architecture,agent_version,protocol_version,status,capabilities_json,hardware_json,candidates_json,created_at,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(agent_id,row["device_id"],hash_token(credential),hostname,str(body.get("model",""))[:255],str(body.get("architecture",""))[:64],version,protocol,"connected",json.dumps(redact(body.get("capabilities",{}))),json.dumps(redact(body.get("hardware",{}))),json.dumps([]),stamp,stamp))
        self.db.execute("UPDATE agent_enrollment_codes SET used_at=? WHERE code_id=?",(stamp,code_id));return {"agent_id":agent_id,"device_id":row["device_id"],"credential":credential,"protocol_version":PROTOCOL_VERSION}
    def rotate(self,agent_id):
        if not self.agent(agent_id):raise DevError("agent not found","agent_not_found",404)
        secret=secrets.token_urlsafe(48);self.db.execute("UPDATE agents SET credential_hash=?,credential_revoked=0,enabled=1,credential_rotated_at=? WHERE agent_id=?",(hash_token(secret),utcnow(),agent_id));return secret
    def agent(self,agent_id):
        rows=self.db.rows("SELECT * FROM agents WHERE agent_id=?",(agent_id,));return self._agent(rows[0]) if rows else None
    def agents(self):return [self._agent(x) for x in self.db.rows("SELECT * FROM agents ORDER BY device_id")]
    def _agent(self,row):
        out={k:v for k,v in row.items() if k!="credential_hash"}
        for key in ("capabilities_json","hardware_json","candidates_json"):out[key[:-5]]=_loads(row,key,{} if key!="candidates_json" else []);out.pop(key,None)
        if row.get("last_seen"):
            age=(datetime.now(timezone.utc)-datetime.fromisoformat(row["last_seen"])).total_seconds()
            if age>int(self.config.get("offline_seconds",45)) and out["status"]=="connected":
                out["status"]="offline";self.db.execute("UPDATE development_jobs SET status='agent_lost',completed_at=?,error_type='agent_lost',summary='Agent disconnected during job' WHERE device_id=? AND status IN ('dispatched','running')",(utcnow(),row["device_id"]))
        out["compatible"]=int(row["protocol_version"])==PROTOCOL_VERSION;return out
    def authenticate_agent(self,agent_id,timestamp,nonce,body,signature):
        rows=self.db.rows("SELECT * FROM agents WHERE agent_id=?",(agent_id,));row=rows[0] if rows else None
        try:stamp=int(timestamp)
        except (ValueError,TypeError):stamp=0
        if not row or not row["enabled"] or row["credential_revoked"] or abs(time.time()-stamp)>60:raise DevError("agent credential rejected","agent_credential_rejected",401)
        if self.db.scalar("SELECT 1 FROM agent_request_nonces WHERE agent_id=? AND nonce=?",(agent_id,nonce)):raise DevError("replayed request","replay_rejected",409)
        digest=hashlib.sha256(body).hexdigest();message=f"{agent_id}\n{stamp}\n{nonce}\n{digest}".encode();expected=hmac.new(bytes.fromhex(row["credential_hash"]),message,hashlib.sha256).hexdigest()
        # Credentials are stored as SHA-256 material and used as the HMAC key.
        if not hmac.compare_digest(expected,str(signature)):raise DevError("agent credential rejected","agent_credential_rejected",401)
        self.db.execute("INSERT INTO agent_request_nonces VALUES(?,?,?)",(agent_id,nonce,utcnow()));self.db.execute("DELETE FROM agent_request_nonces WHERE used_at<?",((datetime.now(timezone.utc)-timedelta(minutes=5)).isoformat(),));return row
    @staticmethod
    def sign(agent_id,credential,timestamp,nonce,body):
        key=bytes.fromhex(hash_token(credential));digest=hashlib.sha256(body).hexdigest();return hmac.new(key,f"{agent_id}\n{timestamp}\n{nonce}\n{digest}".encode(),hashlib.sha256).hexdigest()
    def heartbeat(self,agent_id,body):
        self.db.execute("UPDATE agents SET status='connected',last_seen=?,hostname=?,model=?,architecture=?,agent_version=?,protocol_version=?,capabilities_json=?,hardware_json=?,candidates_json=? WHERE agent_id=?",(utcnow(),str(body.get("hostname",""))[:255],str(body.get("model",""))[:255],str(body.get("architecture",""))[:64],str(body.get("agent_version",""))[:32],int(body.get("protocol_version",0)),json.dumps(redact(body.get("capabilities",{}))),json.dumps(redact(body.get("hardware",{}))),json.dumps(redact(body.get("candidates",[]))[:100]),agent_id))
        self.cleanup()
    def save_workspace(self,data):
        wid=str(data.get("workspace_id", ""));device=str(data.get("device_id", ""));path=str(data.get("path", ""));mode=str(data.get("mode","read_only"))
        if not all((wid,device,path)) or mode not in {"read_only","development"} or not path.startswith("/") or not all(c.isalnum() or c in "_.-" for c in wid):raise DevError("invalid workspace")
        fields=(wid,device,path,str(data.get("repository", ""))[:512],mode,data.get("execution_user"),json.dumps(data.get("allowed_job_types",sorted(READ_TYPES|TEST_TYPES))),json.dumps(data.get("allowed_commands",[])),json.dumps(data.get("allowed_env",[])),json.dumps(data.get("test_profiles",{})),json.dumps(data.get("services",[])),json.dumps(data.get("artifact_patterns",[])),json.dumps(data.get("sensitive_patterns",SENSITIVE)),json.dumps(data.get("hardware_profile",{})),int(bool(data.get("approved",True))),utcnow(),utcnow())
        self.db.execute("INSERT INTO workspaces VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(workspace_id) DO UPDATE SET device_id=excluded.device_id,path=excluded.path,repository=excluded.repository,mode=excluded.mode,execution_user=excluded.execution_user,allowed_job_types_json=excluded.allowed_job_types_json,allowed_commands_json=excluded.allowed_commands_json,allowed_env_json=excluded.allowed_env_json,test_profiles_json=excluded.test_profiles_json,services_json=excluded.services_json,artifact_patterns_json=excluded.artifact_patterns_json,sensitive_patterns_json=excluded.sensitive_patterns_json,hardware_profile_json=excluded.hardware_profile_json,approved=excluded.approved,updated_at=excluded.updated_at",fields);return self.workspace(wid)
    def workspace(self,wid):
        rows=self.db.rows("SELECT * FROM workspaces WHERE workspace_id=?",(wid,));return self._workspace(rows[0]) if rows else None
    def workspaces(self,approved=True):return [self._workspace(x) for x in self.db.rows("SELECT * FROM workspaces"+(" WHERE approved=1" if approved else "")+" ORDER BY device_id,workspace_id")]
    def _workspace(self,row):
        out=dict(row)
        for key in ("allowed_job_types_json","allowed_commands_json","allowed_env_json","test_profiles_json","services_json","artifact_patterns_json","sensitive_patterns_json","hardware_profile_json"):out[key[:-5]]=_loads(row,key,{} if key in {"test_profiles_json","hardware_profile_json"} else []);out.pop(key,None)
        return out
    def _restricted(self,identity,device,wid,kind):
        for key,value in (("devices",device),("workspaces",wid),("job_types",kind)):
            if identity.get(key) and value not in identity[key]:raise DevError(f"token is not authorized for {key[:-1]}","authorization_denied",403)
    def submit(self,identity,body,ip=None,parent=None,validate_only=False):
        device=str(body.get("device_id",body.get("device", "")));wid=str(body.get("workspace_id",body.get("workspace", "")));kind=str(body.get("job_type", ""));self._restricted(identity,device,wid,kind)
        if kind not in ALL_TYPES:raise DevError("unsupported job type")
        required="dev:read" if kind in READ_TYPES else "dev:test" if kind in TEST_TYPES else "dev:command"
        if required not in identity.get("scopes",[]) and identity.get("token"):raise DevError("required development scope missing","authorization_denied",403)
        ws=self.workspace(wid) if wid else None
        if kind not in {"capabilities"} and (not ws or not ws["approved"] or ws["device_id"]!=device):raise DevError("approved workspace not found","workspace_not_found",404)
        if ws and kind not in ws["allowed_job_types"]:raise DevError("job type is not approved for workspace","authorization_denied",403)
        agent=next((x for x in self.agents() if x["device_id"]==device),None)
        if not agent or agent["status"]!="connected" or not agent["enabled"] or agent["credential_revoked"]:raise DevError("agent is offline","agent_offline",409)
        argv=body.get("argv",[]);profile=body.get("profile")
        approval_required=False
        if kind in TEST_TYPES:
            if not profile:raise DevError("an approved test profile is required","authorization_denied",403)
            definition=(ws or {}).get("test_profiles",{}).get(profile)
            if not definition:raise DevError("test profile is not approved")
            requires=definition.get("requires_capabilities",[]);caps=agent.get("capabilities",{})
            if any(not caps.get(x) for x in requires):raise DevError("required capability missing","capability_missing",409)
            # State-changing profiles are hardware-authorized and approved based
            # on their risk, even if an administrator omitted the advisory
            # ``hardware`` marker from the profile.
            if definition.get("hardware") or definition.get("state_changing"):
                if identity.get("token") and "dev:hardware" not in identity.get("scopes",[]):raise DevError("hardware scope missing","authorization_denied",403)
            approval_required=bool(definition.get("state_changing"))
            argv=definition.get("argv",[])
        if kind=="command":self._validate_command(ws,argv)
        if kind=="git_fetch":argv=["git","fetch","--prune"]
        env=body.get("environment",{});
        if not isinstance(env,dict) or any(k not in (ws or {}).get("allowed_env",[]) or not isinstance(v,str) or len(v)>4096 for k,v in env.items()):raise DevError("environment variable is not approved")
        timeout=int(body.get("timeout_seconds",self.default_timeout));timeout=max(1,min(timeout,self.max_timeout));job_id=str(uuid.uuid4());stamp=utcnow();permissions=[required]
        request_data={"relative_path":body.get("relative_path"),"staged":bool(body.get("staged")),"lines":min(1000,max(1,int(body.get("lines",200))))}
        if validate_only:return None
        self.db.execute("INSERT INTO development_jobs(job_id,parent_job_id,device_id,workspace_id,job_type,profile,argv_json,environment_json,permissions_json,requested_by,api_token_id,source_ip,requested_at,status,timeout_seconds,request_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(job_id,parent,device,wid or None,kind,profile,json.dumps(argv),json.dumps(redact(env)),json.dumps(permissions),identity["username"],identity.get("token_id"),ip,stamp,"queued",timeout,json.dumps(request_data)))
        if approval_required:
            self.db.execute("UPDATE development_jobs SET queue_reason='waiting_for_approval' WHERE job_id=?",(job_id,));self.db.execute("INSERT INTO job_approvals VALUES(?,?,?,?,?,?,?,?)",(str(uuid.uuid4()),job_id,"pending","hardware_state_change",stamp,None,None,None))
        self.audit(identity,ip,device,"dev.job.submit",job_id,{"workspace":wid,"job_type":kind,"profile":profile,"argv":argv,"permissions":permissions},"allowed","queued");return self.job(job_id)
    def _validate_command(self,ws,argv):
        if not ws or ws["mode"]!="development" or not isinstance(argv,list) or not argv or any(not isinstance(x,str) or len(x)>4096 or "\x00" in x for x in argv):raise DevError("command is not permitted","authorization_denied",403)
        # Only bare names may be resolved through the agent's controlled PATH.
        # Comparing basenames while retaining a supplied path would let a
        # workspace-local symlink impersonate an allowlisted executable.
        exe=argv[0]
        if Path(exe).name!=exe or "/" in exe or "\\" in exe:raise DevError("executable path is not permitted","authorization_denied",403)
        if exe in FORBIDDEN_EXEC or exe not in set(ws["allowed_commands"]):raise DevError("executable is not approved","authorization_denied",403)
        if exe=="git":
            # Global options may precede the operation (for example,
            # ``git -C . reset``), so argv[1] is not always the subcommand.
            value_options={"-C","-c","--config-env","--exec-path","--git-dir","--namespace","--super-prefix","--work-tree"}
            index=1
            while index<len(argv) and argv[index].startswith("-"):
                option=argv[index].split("=",1)[0]
                index+=1
                if option in value_options and "=" not in argv[index-1]:
                    if index>=len(argv):raise DevError("Git global option requires a value","authorization_denied",403)
                    index+=1
            if index<len(argv) and argv[index] in FORBIDDEN_GIT:raise DevError("destructive Git operation is forbidden","authorization_denied",403)
        if any(x in {"--exec","-exec"} for x in argv):raise DevError("command option is forbidden","authorization_denied",403)
    def matrix(self,identity,body,ip=None):
        devices=body.get("devices",[])
        if not isinstance(devices,list) or not devices or len(devices)>8:raise DevError("matrix requires 1-8 devices")
        # Validate the complete matrix before persisting any child.  A bad late
        # target must not leave earlier, undisclosed jobs eligible for claiming.
        for device in devices:self.submit(identity,{**body,"device_id":device},ip,validate_only=True)
        parent=str(uuid.uuid4());jobs=[]
        for device in devices:jobs.append(self.submit(identity,{**body,"device_id":device},ip,parent))
        return {"parent_job_id":parent,"jobs":jobs}
    def claim(self,device):
        rows=self.db.rows("SELECT * FROM development_jobs WHERE device_id=? AND status='queued' AND NOT EXISTS(SELECT 1 FROM job_approvals a WHERE a.job_id=development_jobs.job_id AND a.status='pending') ORDER BY requested_at LIMIT 1",(device,))
        if not rows:return None
        row=rows[0];self.db.execute("UPDATE development_jobs SET status='dispatched',dispatched_at=?,queue_reason=NULL WHERE job_id=? AND status='queued'",(utcnow(),row["job_id"]));return self._wire_job(self.job(row["job_id"]))
    def _wire_job(self,row):
        ws=self.workspace(row["workspace_id"]) if row.get("workspace_id") else None
        return {"job_id":row["job_id"],"job_type":row["job_type"],"profile":row.get("profile"),"workspace":ws,"argv":_loads(row,"argv_json",[]),"environment":_loads(row,"environment_json",{}),"request":_loads(row,"request_json",{}),"timeout_seconds":row["timeout_seconds"],"output_limit_bytes":self.output_limit,"file_limit_bytes":self.file_limit,"artifact_limits":{"count":self.artifact_count,"file_bytes":self.artifact_file_limit,"total_bytes":self.artifact_total_limit}}
    def result(self,agent,job_id,body):
        job=self.job(job_id)
        if not job or job["device_id"]!=agent["device_id"]:raise DevError("job not found","job_not_found",404)
        status=str(body.get("status"));
        if status not in {"running","succeeded","failed","timed_out","cancelled"}:raise DevError("invalid job status")
        if status=="running":self.db.execute("UPDATE development_jobs SET status='running',started_at=COALESCE(started_at,?) WHERE job_id=?",(utcnow(),job_id));return self.job(job_id)
        stdout=str(redact(body.get("stdout","")))[:self.output_limit];stderr=str(redact(body.get("stderr","")))[:self.output_limit];done=utcnow()
        self.db.execute("UPDATE development_jobs SET status=?,completed_at=?,started_at=COALESCE(started_at,?),exit_code=?,error_type=?,summary=?,stdout=?,stderr=?,stdout_truncated=?,stderr_truncated=?,duration_ms=?,result_json=? WHERE job_id=?",(status,done,done,body.get("exit_code"),body.get("error_type"),str(body.get("summary",""))[:1000],stdout,stderr,int(bool(body.get("stdout_truncated")) or len(str(body.get("stdout","")))>self.output_limit),int(bool(body.get("stderr_truncated")) or len(str(body.get("stderr","")))>self.output_limit),body.get("duration_ms"),json.dumps(redact(body.get("result",{}))),job_id))
        for item in body.get("artifacts",[])[:self.artifact_count]:self._store_artifact(job_id,item,status)
        self.audit({"username":"agent:"+agent["agent_id"],"role":"agent"},None,agent["device_id"],"dev.job.result",job_id,{},"allowed",status,body.get("error_type"));return self.job(job_id)
    def _store_artifact(self,job_id,item,status):
        try:data=base64.b64decode(item.get("data", ""),validate=True)
        except Exception:raise DevError("invalid artifact","artifact_invalid")
        current=self.db.scalar("SELECT COALESCE(SUM(size_bytes),0) FROM job_artifacts WHERE job_id=?",(job_id,)) or 0
        count=self.db.scalar("SELECT COUNT(*) FROM job_artifacts WHERE job_id=?",(job_id,)) or 0
        if len(data)>self.artifact_file_limit or current+len(data)>self.artifact_total_limit or count>=self.artifact_count:raise DevError("artifact limit exceeded","artifact_too_large",413)
        aid=str(uuid.uuid4());name=Path(str(item.get("name","artifact"))).name[:200] or "artifact";storage=aid+Path(name).suffix[:16];folder=(self.root/job_id).resolve()
        if self.root not in folder.parents:raise DevError("artifact path rejected","artifact_path_escape")
        folder.mkdir(mode=0o700,parents=True,exist_ok=True);path=folder/storage;path.write_bytes(data);os.chmod(path,0o600);days=30 if status!="succeeded" else 7
        self.db.execute("INSERT INTO job_artifacts VALUES(?,?,?,?,?,?,?,?,?)",(aid,job_id,name,storage,len(data),hashlib.sha256(data).hexdigest(),str(item.get("content_type") or mimetypes.guess_type(name)[0] or "application/octet-stream")[:100],utcnow(),(datetime.now(timezone.utc)+timedelta(days=days)).isoformat()))
    def artifacts(self,job_id):return self.db.rows("SELECT artifact_id,job_id,name,size_bytes,sha256,content_type,created_at,expires_at FROM job_artifacts WHERE job_id=? ORDER BY created_at",(job_id,))
    def artifact(self,job_id,aid):
        rows=self.db.rows("SELECT * FROM job_artifacts WHERE job_id=? AND artifact_id=?",(job_id,aid));row=rows[0] if rows else None
        if not row:return None,None
        path=(self.root/job_id/row["storage_name"]).resolve()
        if self.root not in path.parents or not path.is_file():return None,None
        return row,path
    def cancel(self,identity,job_id,ip=None):
        job=self.job(job_id)
        if not job:raise DevError("job not found","job_not_found",404)
        self._restricted(identity,job["device_id"],job.get("workspace_id"),job["job_type"])
        if identity.get("token") and "dev:cancel" not in identity.get("scopes",[]):raise DevError("cancel scope missing","authorization_denied",403)
        status="cancelled" if job["status"]=="queued" else job["status"];self.db.execute("UPDATE development_jobs SET cancel_requested=1,status=?,completed_at=CASE WHEN ?='cancelled' THEN ? ELSE completed_at END WHERE job_id=?",(status,status,utcnow(),job_id));self.audit(identity,ip,job["device_id"],"dev.job.cancel",job_id,{},"allowed",status);return self.job(job_id)
    def cancellations(self,device):return [x["job_id"] for x in self.db.rows("SELECT job_id FROM development_jobs WHERE device_id=? AND cancel_requested=1 AND status IN ('dispatched','running')",(device,))]
    def approvals(self):return self.db.rows("SELECT a.*,j.device_id,j.workspace_id,j.job_type,j.profile,j.requested_by FROM job_approvals a JOIN development_jobs j ON j.job_id=a.job_id ORDER BY a.requested_at DESC")
    def decide(self,identity,approval_id,approve,reason=""):
        rows=self.db.rows("SELECT a.*,j.device_id FROM job_approvals a JOIN development_jobs j ON j.job_id=a.job_id WHERE approval_id=? AND a.status='pending'",(approval_id,));row=rows[0] if rows else None
        if not row:raise DevError("pending approval not found","approval_not_found",404)
        status="approved" if approve else "rejected";stamp=utcnow();self.db.execute("UPDATE job_approvals SET status=?,decided_at=?,decided_by=?,reason=? WHERE approval_id=?",(status,stamp,identity["username"],str(reason)[:500],approval_id))
        if approve:self.db.execute("UPDATE development_jobs SET approved_at=?,queue_reason=NULL WHERE job_id=?",(stamp,row["job_id"]))
        else:self.db.execute("UPDATE development_jobs SET status='rejected',completed_at=?,error_type='approval_rejected',summary='Job rejected by administrator',queue_reason=NULL WHERE job_id=?",(stamp,row["job_id"]))
        self.audit(identity,None,row["device_id"],"dev.approval."+status,row["job_id"],{"approval_id":approval_id,"reason":reason},"allowed",status);return self.job(row["job_id"])
    def job(self,jid):
        rows=self.db.rows("SELECT * FROM development_jobs WHERE job_id=?",(jid,));return redact(rows[0]) if rows else None
    def jobs(self,identity=None,limit=100):
        rows=self.db.rows("SELECT * FROM development_jobs ORDER BY requested_at DESC LIMIT ?",(min(200,max(1,limit)),))
        if identity and identity.get("token"):rows=[x for x in rows if (not identity.get("devices") or x["device_id"] in identity["devices"]) and (not identity.get("workspaces") or x.get("workspace_id") in identity["workspaces"]) and (not identity.get("job_types") or x["job_type"] in identity["job_types"])]
        return [redact(x) for x in rows]
    def cleanup(self):
        now=utcnow();rows=self.db.rows("SELECT * FROM job_artifacts WHERE expires_at<? AND job_id NOT IN (SELECT job_id FROM development_jobs WHERE status IN ('queued','dispatched','running'))",(now,))
        for row in rows:
            path=(self.root/row["job_id"]/row["storage_name"]).resolve()
            if self.root in path.parents:path.unlink(missing_ok=True)
            self.db.execute("DELETE FROM job_artifacts WHERE artifact_id=?",(row["artifact_id"],))
        return len(rows)
