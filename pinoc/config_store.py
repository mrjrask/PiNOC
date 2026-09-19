"""Validated atomic JSON configuration persistence with bounded backups."""
import json, os, shutil, tempfile
from pathlib import Path
from pinoc.device_config import load_devices
from pinoc.playbooks import validate_playbooks

RATE_LIMIT_RULES={"login_window_seconds":(1,86400),"login_max_failed":(1,100),"lockout_seconds":(1,86400),"api_window_seconds":(1,86400),"api_max_unauthenticated":(1,10000)}

def validate_security(value):
    security=value.get("security",{})
    if not isinstance(security,dict):raise ValueError("security must be an object")
    rate_limit=security.get("rate_limit",{})
    if not isinstance(rate_limit,dict):raise ValueError("security.rate_limit must be an object")
    for name,setting in rate_limit.items():
        if name not in RATE_LIMIT_RULES:raise ValueError(f"unknown security.rate_limit setting: {name}")
        low,high=RATE_LIMIT_RULES[name]
        if isinstance(setting,bool) or not isinstance(setting,(int,float)) or not low<=setting<=high:raise ValueError(f"invalid security.rate_limit.{name}: must be a number between {low} and {high}")

def validate_config(value,base_dir=Path(".")):
    if not isinstance(value,dict):raise ValueError("configuration must be an object")
    polling=value.get("polling",{})
    if not isinstance(polling,dict):raise ValueError("polling must be an object")
    for name,seconds in polling.items():
        if not isinstance(seconds,(int,float)) or not 1<=seconds<=86400:raise ValueError(f"invalid polling interval: {name}")
    validate_security(value)
    validate_playbooks(value.get("playbooks"))
    _,errors=load_devices(value,Path(base_dir))
    if errors:raise ValueError("; ".join(errors))
    return value

def atomic_save(path,value,backups=3):
    path=Path(path);validate_config(value,path.parent.parent);path.parent.mkdir(parents=True,exist_ok=True)
    for n in range(max(1,backups),1,-1):
        older=path.with_name(path.name+f".bak.{n-1}");newer=path.with_name(path.name+f".bak.{n}")
        if older.exists():os.replace(older,newer)
    if path.exists():shutil.copy2(path,path.with_name(path.name+".bak.1"))
    fd,tmp=tempfile.mkstemp(prefix=path.name+".",suffix=".tmp",dir=path.parent)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as out:json.dump(value,out,indent=2);out.write("\n");out.flush();os.fsync(out.fileno())
        os.chmod(tmp,0o600);os.replace(tmp,path)
        directory=os.open(path.parent,os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    except BaseException:
        try:os.unlink(tmp)
        except FileNotFoundError:pass
        raise
