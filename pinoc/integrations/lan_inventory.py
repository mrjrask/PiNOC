from __future__ import annotations
import json

def load_inventory(value):
    x=json.loads(value) if isinstance(value,str) else value; rows=x.get('devices',x) if isinstance(x,dict) else x
    return [{k:d.get(k) for k in ('ip','mac','hostname','vendor','manufacturer','first_seen','last_seen')} for d in (rows or []) if isinstance(d,dict)]
def enrich(inventory,managed):
    result=[]
    for row in inventory:
        matches=[d for d in managed if (row.get('mac') and str(d.get('mac','')).lower()==str(row['mac']).lower()) or (row.get('hostname') and row['hostname'] in (d.get('hostname'),d.get('id')))]
        result.append({**row,"managed":len(matches)==1,"managed_device_id":matches[0].get('id') if len(matches)==1 else None,"ambiguous":len(matches)>1})
    return result
