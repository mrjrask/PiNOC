from __future__ import annotations
import json

def parse_status(value,limit=100):
    if isinstance(value,str):
        try:value=json.loads(value)
        except json.JSONDecodeError:return {"available":False,"reason":"unsupported smbstatus output","sessions":[],"active_sessions":0,"unique_users":0,"connected_clients":0,"open_files":0,"shares":[]}
    value=value or {}; sessions=value.get("sessions",{}); sessions=list(sessions.values()) if isinstance(sessions,dict) else sessions
    files=value.get("open_files",{}); files=list(files.values()) if isinstance(files,dict) else files
    shares=value.get("tcons",value.get("shares",{})); shares=list(shares.values()) if isinstance(shares,dict) else shares
    users={str(x.get("username")) for x in sessions if x.get("username")}; clients={str(x.get("remote_machine") or x.get("hostname") or x.get("ip")) for x in sessions}
    return {"available":True,"active_sessions":len(sessions),"unique_users":len(users),"connected_clients":len(clients-{"None"}),"open_files":len(files),"share_names":sorted({str(x.get("service") or x.get("share")) for x in shares if x.get("service") or x.get("share")}),"sessions":sessions[:limit],"files":files[:limit]}
