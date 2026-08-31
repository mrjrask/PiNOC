import subprocess,time
from pathlib import Path
from pinoc.actions import ActionDispatcher,ActionError
from pinoc.config_store import atomic_save
from pinoc.database import Database
from pinoc.history import HistoryManager
from pinoc.models import DeviceState
from pinoc.security import SecurityManager,redact
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

class Coordinator:
 def __init__(self):self.refreshed=[]
 def refresh_device(self,d):self.refreshed.append(d)
 def refresh(self):self.refreshed.append("all")

def fixture(tmp_path,role="operator",enabled=True):
 db=Database(str(tmp_path/"db.sqlite"));assert db.initialize();history=HistoryManager(db,{})
 sec=SecurityManager(db,True);sec.create_user("person","correct horse battery",role)
 state=PiNOCState();state.publish([DeviceState("pi","pi","Pi",online=True,address="host",collection_method="ssh",manageable_services=["demo.service"])])
 app=create_app(state,{"TESTING":True,"AUTH_ENABLED":enabled,"SECRET_KEY":"test-secret","DATABASE":db},history,Coordinator());return app,db

def login(client):
 client.get("/login")
 with client.session_transaction() as session:csrf=session["csrf_token"]
 return client.post("/login",data={"username":"person","password":"correct horse battery","csrf_token":csrf})

def token(client):return client.get("/api/session").json["csrf_token"]

def test_login_logout_csrf_and_authorization(tmp_path):
 app,db=fixture(tmp_path);c=app.test_client()
 assert c.get("/").status_code==302
 c.get("/login")
 with c.session_transaction() as session:csrf=session["csrf_token"]
 assert c.post("/login",data={"username":"person","password":"wrong","csrf_token":csrf}).status_code==200
 assert login(c).status_code==302
 assert c.post("/api/devices/pi/refresh").status_code==400
 assert c.post("/api/devices/pi/refresh",headers={"X-CSRF-Token":token(c)}).status_code==202
 assert c.post("/api/devices/pi/reboot",headers={"X-CSRF-Token":token(c)}).status_code==403
 assert c.post("/logout",headers={"X-CSRF-Token":token(c)}).status_code==302
 assert db.scalar("SELECT COUNT(*) FROM audit_records")>=3
 app.extensions["pinoc_actions"].stop()

def test_admin_action_allowlist_argument_safety_and_jobs(tmp_path):
 app,db=fixture(tmp_path,"administrator");state=app.extensions["pinoc_actions"].state
 calls=[]
 def runner(args,**kwargs):calls.append((args,kwargs));return subprocess.CompletedProcess(args,0,"ok","")
 dispatcher=ActionDispatcher(db,state,Coordinator(),runner=runner)
 try:
  try:dispatcher.validate("service.restart","pi","bad;touch.service")
  except ActionError:pass
  else:assert False
  job=dispatcher.enqueue("service.restart","pi","demo.service","admin","administrator")
  end=time.time()+2
  while time.time()<end and dispatcher.get(job["job_id"])["status"] in ("queued","running"):time.sleep(.01)
  assert dispatcher.get(job["job_id"])["status"]=="succeeded"
  assert calls[0][0][-3:]==["systemctl","restart","demo.service"]
  assert "shell" not in calls[0][1] or calls[0][1]["shell"] is False
 finally:dispatcher.stop();app.extensions["pinoc_actions"].stop()

def test_disabled_auth_still_requires_csrf(tmp_path):
 app,_=fixture(tmp_path,enabled=False);c=app.test_client();assert c.get("/").status_code==200
 assert c.post("/api/devices/pi/refresh").status_code==400
 assert c.post("/api/devices/pi/refresh",headers={"X-CSRF-Token":token(c)}).status_code==202
 app.extensions["pinoc_actions"].stop()

def test_maintenance_persistence_redaction_and_atomic_backup(tmp_path):
 app,db=fixture(tmp_path);dispatcher=app.extensions["pinoc_actions"]
 assert dispatcher.set_maintenance("pi","person","password=hidden",1800)["expected_offline"]==1
 assert Database(str(tmp_path/"db.sqlite")).initialize()
 assert redact({"token":"x","nested":{"private_key":"y"}})=={"token":"[REDACTED]","nested":{"private_key":"[REDACTED]"}}
 path=tmp_path/"config.json";atomic_save(path,{"devices":[],"polling":{"fleet_seconds":10}});atomic_save(path,{"devices":[],"polling":{"fleet_seconds":20}})
 assert path.with_name("config.json.bak.1").exists()
 dispatcher.stop()
