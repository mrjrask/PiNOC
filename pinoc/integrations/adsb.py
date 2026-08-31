"""dump1090-fa/SkyAware normalization."""
from __future__ import annotations
import json, math

def _load(v): return json.loads(v) if isinstance(v,str) else (v or {})
def parse_aircraft(value):
    x=_load(value); aircraft=x.get("aircraft",[]) if isinstance(x,dict) else []
    recent=[a for a in aircraft if float(a.get("seen",9999) or 9999)<=60]
    positions=[a for a in recent if (a.get("lat") is not None and a.get("lon") is not None)]
    return {"aircraft":len(recent),"aircraft_with_positions":len(positions),"aircraft_ids":sorted({str(a.get("hex")) for a in recent if a.get("hex")}),"recent_message_activity":bool(recent),"messages_total":x.get("messages"),"receiver_uptime_seconds":x.get("now")}
def parse_stats(value):
    x=_load(value); latest=(x.get("last1min") or x.get("last5min") or x.get("total") or {})
    local=latest.get("local",latest); messages=local.get("accepted") or latest.get("messages")
    seconds=(latest["end"]-latest["start"]) if latest.get("end") is not None and latest.get("start") is not None else None
    out={"messages_per_second":messages/seconds if messages is not None and seconds else latest.get("messages_per_second"),"positions_per_second":latest.get("positions_per_second"),"unique_aircraft_today":(x.get("total") or {}).get("unique_aircraft"),"strong_signal_percent":latest.get("strong_signals"),"signal_dbfs":latest.get("signal"),"noise_dbfs":latest.get("noise"),"peak_signal_dbfs":latest.get("peak_signal")}
    rng=latest.get("max_distance") or latest.get("max_range"); out["maximum_range_nm"]=rng/1852 if rng and rng>1000 else rng
    return {k:v for k,v in out.items() if v is not None}
def compare(receivers):
    ids=[set(x.get("data",{}).get("aircraft_ids",[])) for x in receivers]
    common=sorted(set.intersection(*ids)) if len(ids)>1 and all(ids) else []
    rows=[]
    for index,item in enumerate(receivers): rows.append({"device_id":item.get("device_id"),"aircraft":item.get("data",{}).get("aircraft"),"messages_per_second":item.get("data",{}).get("messages_per_second"),"positions_per_second":item.get("data",{}).get("positions_per_second"),"maximum_range_nm":item.get("data",{}).get("maximum_range_nm"),"health":item.get("health"),"unique_aircraft":sorted(ids[index]-set().union(*(ids[:index]+ids[index+1:]))) if len(ids)>1 else []})
    return {"receivers":rows,"aircraft_seen_by_all":common,"receiver_count":len(rows)}
