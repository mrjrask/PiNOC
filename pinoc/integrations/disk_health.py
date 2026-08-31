from __future__ import annotations
import json

def parse_nvme(value):
    x=json.loads(value) if isinstance(value,str) else value; warning=int(str(x.get("critical_warning",0)),0); temp=x.get("temperature"); temp=float(temp)-273.15 if temp and float(temp)>200 else temp
    return {"technology":"nvme","health":"critical" if warning else "healthy","critical_warning":warning,"temperature_c":temp,"available_spare_percent":x.get("avail_spare"),"percentage_used":x.get("percent_used"),"power_on_hours":x.get("power_on_hours"),"media_errors":x.get("media_errors"),"data_integrity_errors":x.get("num_err_log_entries")}
def parse_smart(value):
    x=json.loads(value) if isinstance(value,str) else value; passed=(x.get("smart_status") or {}).get("passed"); attrs={a.get("name"):a.get("raw",{}).get("value") for a in x.get("ata_smart_attributes",{}).get("table",[])}
    return {"technology":"smart","health":"healthy" if passed else "critical" if passed is False else "unsupported","overall_passed":passed,"temperature_c":(x.get("temperature") or {}).get("current"),"power_on_hours":(x.get("power_on_time") or {}).get("hours"),"reallocated_sectors":attrs.get("Reallocated_Sector_Ct"),"pending_sectors":attrs.get("Current_Pending_Sector"),"uncorrectable_sectors":attrs.get("Offline_Uncorrectable")}
