import base64,json,os,subprocess,threading,time
from pathlib import Path
import pytest
from pinoc.database import Database,SCHEMA_VERSION
from pinoc.development import DevelopmentGateway,DevError,PROTOCOL_VERSION
from pinoc.history import HistoryManager
from pinoc.security import SecurityManager
from pinoc.state import PiNOCState
from pinoc.web.app import create_app
from pinoc_agent import Executor

def setup(tmp_path):
 db=Database(str(tmp_path/"pinoc.db"));assert db.initialize();gw=DevelopmentGateway(db,str(tmp_path/"jobs"),{"output_limit_bytes":1024,"artifact_file_limit_bytes":1024,"artifact_total_limit_bytes":2048});return db,gw

def enroll(gw):
 code=gw.enrollment_code("pi","admin");answer=gw.enroll({"enrollment_code":code,"hostname":"mock","model":"Pi","architecture":"aarch64","agent_version":"1.0.0","protocol_version":PROTOCOL_VERSION,"capabilities":{"python":"3.12","git":"2"}});return answer

def workspace(gw,path,mode="development"):
 return gw.save_workspace({"workspace_id":"project","device_id":"pi","path":str(path),"mode":mode,"approved":True,"allowed_job_types":["file_read","git_status","git_diff","command","test","pytest","artifact_collect"],"allowed_commands":["python3","git"],"allowed_env":["HEADLESS"],"test_profiles":{"unit":{"argv":["python3","-c","print('ok')"],"timeout":10}},"artifact_patterns":["out/*.png"]})

def identity(**kw):return {"username":"codex","role":"administrator","token":True,"token_id":"t","scopes":["dev:read","dev:test","dev:command","dev:artifacts","dev:cancel"],"devices":[],"workspaces":[],"job_types":[],**kw}

def test_schema_enrollment_replay_rotation_and_revocation(tmp_path):
 db,gw=setup(tmp_path);assert SCHEMA_VERSION==6;a=enroll(gw);body=b'{}';stamp=str(int(time.time()));nonce="unique";sig=gw.sign(a["agent_id"],a["credential"],stamp,nonce,body)
 assert gw.authenticate_agent(a["agent_id"],stamp,nonce,body,sig)["device_id"]=="pi"
 with pytest.raises(DevError) as e:gw.authenticate_agent(a["agent_id"],stamp,nonce,body,sig)
 assert e.value.error_type=="replay_rejected"
 replacement=gw.rotate(a["agent_id"]);assert replacement!=a["credential"]
 db.execute("UPDATE agents SET credential_revoked=1 WHERE agent_id=?",(a["agent_id"],))
 with pytest.raises(DevError):gw.authenticate_agent(a["agent_id"],stamp,"new",body,gw.sign(a["agent_id"],replacement,stamp,"new",body))

def test_workspace_paths_sensitive_files_and_symlink_escape(tmp_path):
 root=tmp_path/"repo";root.mkdir();(root/"ok.txt").write_text("ok");(root/".env").write_text("SECRET=x");outside=tmp_path/"outside";outside.write_text("no");(root/"link").symlink_to(outside)
 assert Executor.safe_path(root,"ok.txt")==root/"ok.txt"
 for path in ("../outside","/etc/passwd","link",".env"):
  with pytest.raises(ValueError):Executor.safe_path(root,path)

def test_scope_device_workspace_command_and_environment_policy(tmp_path):
 _,gw=setup(tmp_path);enroll(gw);root=tmp_path/"repo";root.mkdir();workspace(gw,root)
 with pytest.raises(DevError):gw.submit(identity(devices=["other"]),{"device_id":"pi","workspace_id":"project","job_type":"git_status"})
 with pytest.raises(DevError):gw.submit(identity(workspaces=["other"]),{"device_id":"pi","workspace_id":"project","job_type":"git_status"})
 with pytest.raises(DevError):gw.submit(identity(scopes=["dev:read"]),{"device_id":"pi","workspace_id":"project","job_type":"command","argv":["python3","-V"]})
 for argv in (["sudo","id"],["sh","-c","id"],["git","reset","--hard"],["./git","status"],["/usr/bin/git","status"]):
  with pytest.raises(DevError):gw.submit(identity(),{"device_id":"pi","workspace_id":"project","job_type":"command","argv":argv})
 with pytest.raises(DevError):gw.submit(identity(),{"device_id":"pi","workspace_id":"project","job_type":"command","argv":["python3","-V"],"environment":{"PINOC_SECRET":"x"}})
 assert gw.submit(identity(),{"device_id":"pi","workspace_id":"project","job_type":"command","argv":["python3","-V"],"environment":{"HEADLESS":"1"}})["status"]=="queued"

def test_state_changing_profile_requires_hardware_scope_and_approval(tmp_path):
 db,gw=setup(tmp_path);enroll(gw);root=tmp_path/"repo";root.mkdir();workspace(gw,root)
 profiles={"flash":{"argv":["python3","-c","print('flash')"],"state_changing":True}}
 db.execute("UPDATE workspaces SET test_profiles_json=? WHERE workspace_id='project'",(json.dumps(profiles),))
 with pytest.raises(DevError) as error:gw.submit(identity(),{"device_id":"pi","workspace_id":"project","job_type":"test","profile":"flash"})
 assert error.value.error_type=="authorization_denied"
 job=gw.submit(identity(scopes=identity()["scopes"]+["dev:hardware"]),{"device_id":"pi","workspace_id":"project","job_type":"test","profile":"flash"})
 assert job["queue_reason"]=="waiting_for_approval" and db.scalar("SELECT COUNT(*) FROM job_approvals WHERE job_id=?",(job["job_id"],))==1

def test_test_jobs_require_an_approved_profile(tmp_path):
 _,gw=setup(tmp_path);enroll(gw);root=tmp_path/"repo";root.mkdir();workspace(gw,root)
 for kind in ("test","pytest"):
  with pytest.raises(DevError) as error:gw.submit(identity(),{"device_id":"pi","workspace_id":"project","job_type":kind,"argv":["bash","-c","id"]})
  assert error.value.error_type=="authorization_denied"

def test_offline_read_only_timeout_cancel_artifacts_and_matrix(tmp_path):
 db,gw=setup(tmp_path);a=enroll(gw);root=tmp_path/"repo";root.mkdir();workspace(gw,root,"read_only")
 with pytest.raises(DevError):gw.submit(identity(),{"device_id":"pi","workspace_id":"project","job_type":"command","argv":["python3","-V"]})
 db.execute("UPDATE workspaces SET mode='development' WHERE workspace_id='project'");job=gw.submit(identity(),{"device_id":"pi","workspace_id":"project","job_type":"test","profile":"unit","timeout_seconds":99999});assert job["timeout_seconds"]==1800
 claimed=gw.claim("pi");assert claimed["job_id"]==job["job_id"]
 gw.result(gw.agent(a["agent_id"]),job["job_id"],{"status":"succeeded","exit_code":0,"stdout":"token=abc","artifacts":[{"name":"screen.png","data":base64.b64encode(b"png").decode()}]});assert gw.artifacts(job["job_id"])[0]["name"]=="screen.png"
 row,path=gw.artifact(job["job_id"],gw.artifacts(job["job_id"])[0]["artifact_id"]);assert path.read_bytes()==b"png"
 queued=gw.submit(identity(),{"device_id":"pi","workspace_id":"project","job_type":"git_status"});assert gw.cancel(identity(),queued["job_id"])["status"]=="cancelled"
 matrix=gw.matrix(identity(),{"devices":["pi"],"workspace_id":"project","job_type":"test","profile":"unit"});assert len(matrix["jobs"])==1
 db.execute("UPDATE agents SET last_seen='2000-01-01T00:00:00+00:00'")
 with pytest.raises(DevError) as e:gw.submit(identity(),{"device_id":"pi","workspace_id":"project","job_type":"git_status"})
 assert e.value.error_type=="agent_offline"

def test_matrix_validates_every_target_before_creating_children(tmp_path):
 db,gw=setup(tmp_path);enroll(gw);root=tmp_path/"repo";root.mkdir();workspace(gw,root)
 with pytest.raises(DevError):gw.matrix(identity(),{"devices":["pi","offline"],"workspace_id":"project","job_type":"test","profile":"unit"})
 assert db.scalar("SELECT COUNT(*) FROM development_jobs")==0

def test_agent_request_body_is_capped_before_authentication(tmp_path):
 db=Database(str(tmp_path/"web.db"));assert db.initialize();history=HistoryManager(db,{})
 app=create_app(PiNOCState(),{"TESTING":True,"AUTH_ENABLED":False,"DEV_AGENT_MAX_REQUEST_BYTES":64},history)
 response=app.test_client().post("/api/v1/agent/heartbeat",data=b"x"*65,content_type="application/json")
 assert response.status_code==413
 app.extensions["pinoc_actions"].stop()

def test_executor_timeout_output_process_cleanup_and_git(tmp_path):
 root=tmp_path/"repo";root.mkdir();subprocess.run(["git","init",str(root)],check=True,capture_output=True);workspace={"path":str(root),"sensitive_patterns":[],"artifact_patterns":[],"services":[]};ex=Executor()
 base={"job_id":"j","job_type":"command","workspace":workspace,"argv":["python3","-c","import sys,time;sys.stdout.write('x'*2_000_000);sys.stderr.write('y'*2_000_000);sys.stdout.flush();sys.stderr.flush();time.sleep(3)"],"environment":{},"request":{},"timeout_seconds":1,"output_limit_bytes":100,"file_limit_bytes":100,"artifact_limits":{"count":1,"file_bytes":10,"total_bytes":10}}
 result=ex.execute(base);assert result["status"]=="timed_out" and result["stdout_truncated"] and result["stderr_truncated"] and len(result["stdout"])==len(result["stderr"])==100 and not ex.processes
 status=ex.execute({**base,"job_id":"g","job_type":"git_status","timeout_seconds":5});assert status["status"]=="succeeded"

def test_executor_can_cancel_a_running_job(tmp_path):
 root=tmp_path/"repo";root.mkdir();ex=Executor();job={"job_id":"cancel-me","job_type":"command","workspace":{"path":str(root),"artifact_patterns":[]},"argv":["python3","-c","import time; time.sleep(30)"],"environment":{},"request":{},"timeout_seconds":60,"output_limit_bytes":100,"file_limit_bytes":100,"artifact_limits":{"count":1,"file_bytes":10,"total_bytes":10}}
 result={};worker=threading.Thread(target=lambda:result.update(ex.execute(job)));worker.start()
 for _ in range(100):
  if job["job_id"] in ex.processes:break
  time.sleep(.01)
 ex.cancel(job["job_id"]);worker.join(5)
 assert not worker.is_alive() and result["status"]=="cancelled" and not ex.processes

def test_development_token_restrictions_are_persisted(tmp_path):
 db,_=setup(tmp_path);s=SecurityManager(db,True);s.create_user("admin","correct horse battery","administrator");raw=s.create_token("admin",["dev:test"],["pi"],["project"],["test"]);row=db.rows("SELECT * FROM api_tokens WHERE token_id=?",(raw.split('.')[0],))[0]
 assert json.loads(row["device_restrictions_json"])==["pi"] and "dev:test" in json.loads(row["scopes_json"])
