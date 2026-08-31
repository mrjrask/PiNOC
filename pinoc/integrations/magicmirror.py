from __future__ import annotations
import json,re

def parse_pm2(value,process_name=None):
    rows=json.loads(value) if isinstance(value,str) else value; rows=rows or []
    row=next((x for x in rows if process_name and x.get('name')==process_name),None) or next((x for x in rows if 'magicmirror' in str(x.get('name','')).lower() or x.get('name')=='mm'),None)
    if not row:return {"available":False,"process_name":process_name}
    env=row.get('pm2_env',{}); mon=row.get('monit',{})
    return {"available":True,"process_name":row.get('name'),"process_state":env.get('status'),"restart_count":env.get('restart_time'),"unstable_restarts":env.get('unstable_restarts'),"uptime_since_ms":env.get('pm_uptime'),"memory_bytes":mon.get('memory')}
def parse_modules(text): return sorted(set(re.findall(r"module\s*:\s*['\"]([^'\"]+)",text)))
