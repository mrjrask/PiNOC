import subprocess,time
from datetime import datetime,timezone
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
 # authorization_result is a benign allowed/denied classification on every
 # audit row, not a secret; a bare substring match on "authorization"
 # must not redact it, while a genuine Authorization-style key still is.
 assert redact({"authorization_result":"denied","Authorization":"Bearer x"})=={"authorization_result":"denied","Authorization":"[REDACTED]"}
 path=tmp_path/"config.json";atomic_save(path,{"devices":[],"polling":{"fleet_seconds":10}});atomic_save(path,{"devices":[],"polling":{"fleet_seconds":20}})
 assert path.with_name("config.json.bak.1").exists()
 dispatcher.stop()

def test_cookie_session_is_revoked_when_user_is_disabled(tmp_path):
 app,db=fixture(tmp_path);c=app.test_client();assert login(c).status_code==302
 db.execute("UPDATE users SET enabled=0 WHERE username='person'")
 assert c.get("/api/devices").status_code==401
 with c.session_transaction() as session:assert "username" not in session
 app.extensions["pinoc_actions"].stop()

def test_bearer_read_scopes_are_enforced_per_endpoint(tmp_path):
 app,db=fixture(tmp_path,"administrator");security=app.extensions["pinoc_security"]
 fleet=security.create_token("person",["read:fleet"])
 history=security.create_token("person",["read:history"])
 execute=security.create_token("person",["execute:safe_actions"])
 c=app.test_client()
 assert c.get("/api/devices",headers={"Authorization":"Bearer "+fleet}).status_code==200
 assert c.get("/api/devices/pi/metrics",headers={"Authorization":"Bearer "+fleet}).status_code==403
 assert c.get("/api/audit",headers={"Authorization":"Bearer "+fleet}).status_code==403
 assert c.get("/api/actions",headers={"Authorization":"Bearer "+fleet}).status_code==403
 assert c.get("/api/devices/pi/metrics",headers={"Authorization":"Bearer "+history}).status_code==200
 assert c.get("/api/actions",headers={"Authorization":"Bearer "+execute}).status_code==200
 app.extensions["pinoc_actions"].stop()

def test_viewer_browser_session_cannot_read_the_action_registry(tmp_path):
 # /api/actions and /api/actions/<id> map to the operator-only
 # "actions.execute" permission in TOKEN_SCOPE_PERMISSIONS, but that
 # mapping was only ever enforced for Bearer-token identities; a
 # logged-in viewer-role browser session must be denied too.
 app,db=fixture(tmp_path,"viewer");c=app.test_client();assert login(c).status_code==302
 assert c.get("/api/actions").status_code==403
 assert c.get("/api/actions/does-not-exist").status_code==403
 app.extensions["pinoc_actions"].stop()

def test_operator_browser_session_can_read_the_action_registry(tmp_path):
 app,db=fixture(tmp_path,"operator");c=app.test_client();assert login(c).status_code==302
 assert c.get("/api/actions").status_code==200
 assert c.get("/api/actions/does-not-exist").status_code==404
 app.extensions["pinoc_actions"].stop()

def test_only_administrator_browser_sessions_can_read_the_audit_log(tmp_path):
 # /api/audit maps to the administrator-only "config.write" permission in
 # TOKEN_SCOPE_PERMISSIONS, but -- like /api/actions above -- that mapping
 # was only ever enforced for Bearer-token identities.
 for role,expected in (("viewer",403),("operator",403),("administrator",200)):
  app,db=fixture(tmp_path/role,role);c=app.test_client();assert login(c).status_code==302
  assert c.get("/api/audit").status_code==expected
  app.extensions["pinoc_actions"].stop()

def test_only_administrator_browser_sessions_can_read_database_status(tmp_path):
    # /api/database/status and its /settings/status page both map to the
    # administrator-only "config.write" permission in
    # TOKEN_SCOPE_PERMISSIONS, but neither had an in-handler check --
    # /settings/status had none at all, unlike its sibling /settings page.
    for role,expected in (("viewer",403),("operator",403),("administrator",200)):
        app,db=fixture(tmp_path/role,role);c=app.test_client();assert login(c).status_code==302
        assert c.get("/api/database/status").status_code==expected
        assert c.get("/settings/status").status_code==expected
        app.extensions["pinoc_actions"].stop()

def test_overview_omits_alerts_and_events_without_their_scopes(tmp_path):
 app,db=fixture(tmp_path,"administrator");security=app.extensions["pinoc_security"]
 db.execute("INSERT INTO alerts(device_id,alert_type,severity,message,fingerprint,opened_at,last_seen_at,state) VALUES('pi','health','warning','alert','scope-alert','2026-09-14T00:00:00Z','2026-09-14T00:00:00Z','active')")
 db.execute("INSERT INTO events(timestamp,device_id,event_type,severity,message) VALUES('2026-09-14T00:00:00Z','pi','health','warning','event')")
 fleet=security.create_token("person",["read:fleet"])
 full=security.create_token("person",["read:fleet","read:alerts","read:history"])
 c=app.test_client()
 restricted=c.get("/api/overview",headers={"Authorization":"Bearer "+fleet})
 assert restricted.status_code==200
 assert restricted.json["active_alerts"]==[]
 assert restricted.json["recent_events"]==[]
 permitted=c.get("/api/overview",headers={"Authorization":"Bearer "+full}).json
 assert [row["message"] for row in permitted["active_alerts"]]==["alert"]
 assert [row["message"] for row in permitted["recent_events"]]==["event"]
 app.extensions["pinoc_actions"].stop()

def test_failed_shutdown_clears_expected_offline_state(tmp_path):
 app,db=fixture(tmp_path,"administrator");state=app.extensions["pinoc_actions"].state
 def failed(args,**kwargs):return subprocess.CompletedProcess(args,1,"","no")
 dispatcher=ActionDispatcher(db,state,runner=failed)
 row={"device_id":"pi","action":"device.shutdown","requested_by":"person"}
 try:
  assert dispatcher._power(row,10)["exit_code"]==1
  assert db.rows("SELECT expected_offline FROM device_operational_state WHERE device_id='pi'")[0]["expected_offline"]==0
  def raised(args,**kwargs):raise OSError("dispatch failed")
  dispatcher.runner=raised
  try:dispatcher._power(row,10)
  except OSError:pass
  else:assert False
  assert db.rows("SELECT expected_offline FROM device_operational_state WHERE device_id='pi'")[0]["expected_offline"]==0
 finally:dispatcher.stop();app.extensions["pinoc_actions"].stop()

def test_settings_save_restores_redacted_secrets(tmp_path):
 app,_=fixture(tmp_path,"administrator");path=tmp_path/"config.json"
 app.config.update(CONFIG_PATH=str(path),APP_DIR=str(tmp_path),PINOC_CONFIG={"devices":[],"network_inventory":{"shared_secret":"real-secret"}})
 c=app.test_client();assert login(c).status_code==302
 shown=c.get("/api/settings").json;assert shown["network_inventory"]["shared_secret"]=="[REDACTED]"
 shown["polling"]={"fleet_seconds":30}
 response=c.put("/api/settings",json=shown,headers={"X-CSRF-Token":token(c)})
 assert response.status_code==200
 assert __import__('json').loads(path.read_text())["network_inventory"]["shared_secret"]=="real-secret"
 app.extensions["pinoc_actions"].stop()

def test_indefinite_maintenance_without_reason_suppresses_alerts(tmp_path):
 app,db=fixture(tmp_path);history=HistoryManager(db,{"thresholds":{"cpu_duration_seconds":0}})
 dispatcher=app.extensions["pinoc_actions"];dispatcher.set_maintenance("pi","person","",None)
 device={"id":"pi","hostname":"pi","friendly_name":"Pi","online":True,"last_seen":datetime.now(timezone.utc).isoformat(),"cpu":{"utilization_percent":100,"temperature_c":90},"memory":{"percent":100},"storage":[],"services":[],"integrations":{}}
 history._snapshot([device],device["last_seen"])
 assert device["maintenance"] is True
 assert db.scalar("SELECT COUNT(*) FROM alerts WHERE resolved_at IS NULL")==0
 dispatcher.stop()

def test_auth_initializes_database_when_history_is_disabled(tmp_path):
 db=Database(str(tmp_path/"disabled-history.sqlite"));history=HistoryManager(db,{"enabled":False})
 bootstrap=Database(str(db.path));assert bootstrap.initialize();SecurityManager(bootstrap,True).create_user("person","correct horse battery","operator")
 state=PiNOCState();app=create_app(state,{"TESTING":True,"AUTH_ENABLED":True,"SECRET_KEY":"test"},history)
 assert db.available is True
 c=app.test_client();assert login(c).status_code==302
 app.extensions["pinoc_actions"].stop()

def test_actions_initialize_database_when_history_and_auth_are_disabled(tmp_path):
 db=Database(str(tmp_path/"actions.sqlite"));history=HistoryManager(db,{"enabled":False})
 state=PiNOCState();state.publish([DeviceState("pi","pi","Pi",online=True,address="host",collection_method="local")])
 app=create_app(state,{"TESTING":True,"AUTH_ENABLED":False,"SECRET_KEY":"test"},history,Coordinator())
 assert db.available is True
 c=app.test_client();csrf=c.get("/api/session").json["csrf_token"]
 response=c.post("/api/devices/pi/refresh",headers={"X-CSRF-Token":csrf})
 assert response.status_code==202
 assert db.scalar("SELECT COUNT(*) FROM action_jobs")==1
 app.extensions["pinoc_actions"].stop()

def test_configuration_maintenance_survives_history_reconciliation(tmp_path):
 db=Database(str(tmp_path/"maintenance.sqlite"));assert db.initialize()
 history=HistoryManager(db,{"thresholds":{"cpu_duration_seconds":0}})
 stamp=datetime.now(timezone.utc).isoformat()
 device={"id":"pi","hostname":"pi","friendly_name":"Pi","online":True,"last_seen":stamp,"maintenance":True,"maintenance_reason":"configured","cpu":{"utilization_percent":100,"temperature_c":90},"memory":{"percent":100},"storage":[],"services":[],"integrations":{}}
 history._snapshot([device],stamp)
 assert device["maintenance"] is True
 assert device["maintenance_reason"]=="configured"
 assert db.scalar("SELECT COUNT(*) FROM alerts WHERE resolved_at IS NULL")==0

def test_installer_loads_saved_authentication_default(tmp_path):
 env=tmp_path/"env";env.write_text("PINOC_AUTH_ENABLED=0\n")
 script=Path(__file__).parents[1]/"install.sh"
 command=f'''ENV_FILE={str(env)!r}; source <(sed -n '/^load_env_file()/,/^}}/p' {str(script)!r}); load_env_file; printf %s "$PINOC_AUTH_ENABLED"'''
 result=subprocess.run(["bash","-c",command],text=True,capture_output=True,check=True)
 assert result.stdout=="0"
