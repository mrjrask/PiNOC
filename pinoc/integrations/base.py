"""Read-only role integration contracts and safe helpers."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable
import re

HEALTHS={"healthy","warning","degraded","critical","unavailable","unsupported"}
SECRET=re.compile(r"(password|passwd|private[_-]?key|secret|token|credential|\.env)",re.I)
ROLE_MAP={"adsb_receiver":("adsb",),"desk_display":("desk_display","git"),"magicmirror":("magicmirror","ics_modifier","pi_hotspot","git"),"hotspot":("pi_hotspot",),"vpn_server":("wireguard",),"file_server":("samba","raid","disk_health"),"pinoc":("packages",)}
DEFAULT_INTERVALS={"adsb":15,"desk_display":15,"magicmirror":15,"ics_modifier":60,"pi_hotspot":30,"wireguard":15,"samba":30,"raid":30,"disk_health":300,"packages":21600,"git":300,"lan_inventory":600}

def now(): return datetime.now(timezone.utc).isoformat()

def sanitize(value: Any) -> Any:
    if isinstance(value,dict): return {k:sanitize(v) for k,v in value.items() if not SECRET.search(str(k))}
    if isinstance(value,list): return [sanitize(x) for x in value]
    if isinstance(value,tuple): return [sanitize(x) for x in value]
    return value

@dataclass
class IntegrationStatus:
    name:str; enabled:bool=True; available:bool=False; health:str="unavailable"
    last_success:str|None=None; last_attempt:str|None=None; poll_duration_ms:float|None=None
    data_source:str|None=None; error:str|None=None; data:Dict[str,Any]=field(default_factory=dict)
    critical:bool=False; available_actions:list=field(default_factory=list)
    def to_dict(self):
        value=asdict(self); value["health"]=value["health"] if value["health"] in HEALTHS else "unavailable"
        return sanitize(value)

def active_integrations(roles:Iterable[str], configured:Dict[str,Any]|None=None):
    result=[]
    for role in roles:
        for name in ROLE_MAP.get(role,()):
            if name not in result: result.append(name)
    for name,value in (configured or {}).items():
        enabled=value if isinstance(value,bool) else value.get("enabled",True)
        if enabled and name not in result: result.append(name)
        if not enabled and name in result: result.remove(name)
    return result

def service(services,name): return next((x for x in services if x.get("name")==name or x.get("name")==name+".service"),None)
