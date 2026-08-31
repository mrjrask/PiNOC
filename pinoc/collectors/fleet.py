"""Transport-neutral, bounded fleet metrics collection."""
from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from pinoc.device_config import DeviceConfig
from pinoc.health import evaluate
from pinoc.models import DeviceState

LOG = logging.getLogger("pinoc.collectors.fleet")
DISCOVERY = ("cockpit", "ssh", "desk-display", "piaware", "dump1090", "readsb", "magicmirror",
             "ics_modifier", "pi-hotspot", "temp-monitor", "smb", "smbd", "nmbd", "wg-quick")
SCRIPT = r'''set +e
echo __OS__; cat /etc/os-release 2>/dev/null; echo __UNAME__; uname -srm
echo __MODEL__; tr -d '\000' </proc/device-tree/model 2>/dev/null; echo
echo __UPTIME__; cat /proc/uptime; echo __LOAD__; cat /proc/loadavg
echo __CPU__; head -1 /proc/stat; echo __FREQ__; cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null
echo __TEMP__; for f in /sys/class/thermal/thermal_zone*/temp /sys/class/hwmon/hwmon*/temp1_input; do [ -r "$f" ] && echo "$f=$(cat "$f")"; done
echo __THROTTLED__; command -v vcgencmd >/dev/null && vcgencmd get_throttled
echo __MEM__; cat /proc/meminfo
echo __DF__; df -PT -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null
echo __MOUNTS__; cat /proc/mounts
echo __ROUTE__; ip -j route show default 2>/dev/null; echo __ADDR__; ip -j address show 2>/dev/null
echo __NET__; cat /proc/net/dev
echo __IW__; command -v iw >/dev/null && iw dev 2>/dev/null; command -v iw >/dev/null && iw dev $(iw dev 2>/dev/null | awk '$1=="Interface"{print $2;exit}') link 2>/dev/null
if [ "$1" = "__discover__" ]; then shift; discovered=$(systemctl list-unit-files --no-legend --no-pager 2>/dev/null | awk '{print $1}' | grep -E '^(cockpit|ssh|desk-display|piaware|dump1090|readsb|magicmirror|ics_modifier|pi-hotspot|temp-monitor|smb|smbd|nmbd|wg-quick)' | head -30); fi
echo __SERVICES__; systemctl show --no-pager --property=Id,LoadState,ActiveState,SubState,MainPID,ActiveEnterTimestampMonotonic,NRestarts,MemoryCurrent "$@" $discovered 2>/dev/null
echo __UNITS__; systemctl list-unit-files --no-legend --no-pager 2>/dev/null
'''


def sections(text: str) -> Dict[str, str]:
    result: Dict[str, List[str]] = {}; current = ""
    for line in text.splitlines():
        if line.startswith("__") and line.endswith("__"):
            current = line.strip("_"); result[current] = []
        elif current: result[current].append(line)
    return {key: "\n".join(value).strip() for key, value in result.items()}


def parse_cpu(data: Dict[str, str], previous: Optional[tuple[int, int]] = None) -> tuple[Dict[str, Any], tuple[int, int]]:
    fields = [int(x) for x in data.get("CPU", "").split()[1:] if x.isdigit()]
    idle, total = (sum(fields[3:5]), sum(fields)) if fields else (0, 0)
    utilization = None
    if previous and total > previous[1]: utilization = round(100 * (1 - (idle-previous[0])/(total-previous[1])), 1)
    loads = data.get("LOAD", "").split()
    temps = []
    for row in data.get("TEMP", "").splitlines():
        try:
            value = float(row.rsplit("=", 1)[1]); temps.append(value / 1000 if value > 1000 else value)
        except (ValueError, IndexError): pass
    try: freq = round(float(data.get("FREQ", "")) / 1000, 1)
    except ValueError: freq = None
    metric = {"utilization_percent": utilization, "load_1m": float(loads[0]) if loads else None,
              "load_5m": float(loads[1]) if len(loads)>1 else None, "load_15m": float(loads[2]) if len(loads)>2 else None,
              "frequency_mhz": freq, "temperature_c": max(temps) if temps else None,
              "soc_temperature_c": max(temps) if temps else None}
    return metric, (idle, total)


def parse_memory(text: str) -> Dict[str, Any]:
    values = {}
    for row in text.splitlines():
        if ":" in row:
            key, value = row.split(":", 1)
            try: values[key] = int(value.split()[0]) * 1024
            except (ValueError, IndexError): pass
    total, available = values.get("MemTotal", 0), values.get("MemAvailable", 0)
    swap_total, swap_free = values.get("SwapTotal", 0), values.get("SwapFree", 0)
    return {"total": total, "used": total-available, "available": available,
            "percent": round(100*(total-available)/total, 1) if total else None,
            "swap_total": swap_total, "swap_used": swap_total-swap_free,
            "swap_percent": round(100*(swap_total-swap_free)/swap_total, 1) if swap_total else 0.0}


def parse_storage(df: str, mounts: str) -> List[Dict[str, Any]]:
    mount_opts = {}
    for row in mounts.splitlines():
        bits=row.split();
        if len(bits)>=4: mount_opts[bits[1]]=bits[3].split(",")
    excluded=("/boot", "/snap")
    result=[]
    for row in df.splitlines()[1:]:
        bits=row.split()
        if len(bits)<7 or bits[6].startswith(excluded): continue
        try: size,used,avail=int(bits[2])*1024,int(bits[3])*1024,int(bits[4])*1024; pct=float(bits[5].rstrip("%"))
        except ValueError: continue
        result.append({"device":bits[0],"filesystem":bits[1],"mount_point":bits[6],"path":bits[6],
                       "size":size,"total":size,"used":used,"available":avail,"percent":pct,
                       "read_only":"ro" in mount_opts.get(bits[6],[])})
    return result


def parse_throttled(text: str) -> Dict[str, bool]:
    try: value=int(text.split("=",1)[-1], 0)
    except ValueError: return {}
    return {"undervoltage_now":bool(value&1),"frequency_capped_now":bool(value&2),"throttled_now":bool(value&4),
            "soft_temp_limit_now":bool(value&8),"undervoltage_occurred":bool(value&(1<<16)),
            "frequency_capped_occurred":bool(value&(1<<17)),"throttled_occurred":bool(value&(1<<18)),
            "soft_temp_limit_occurred":bool(value&(1<<19)),"raw":hex(value)}


def parse_services(text: str, critical: Iterable[str], system_uptime: float = 0) -> List[Dict[str, Any]]:
    def numeric_value(values: Dict[str, str], name: str) -> Optional[int]:
        try:
            return int(values.get(name, ""))
        except (TypeError, ValueError):
            return None

    result=[]; crit=set(critical)
    for block in text.split("\n\n"):
        values=dict(row.split("=",1) for row in block.splitlines() if "=" in row)
        if not values.get("Id"): continue
        active=values.get("ActiveState","unknown")
        state={"active":"running","inactive":"stopped","failed":"failed","activating":"activating","deactivating":"deactivating"}.get(active,"unknown")
        active_mono_raw=numeric_value(values,"ActiveEnterTimestampMonotonic")
        active_mono=active_mono_raw/1_000_000 if active_mono_raw else 0
        main_pid=numeric_value(values,"MainPID")
        result.append({"name":values["Id"],"state":state,"load_state":values.get("LoadState"),"active_state":active,
                       "sub_state":values.get("SubState"),"main_pid":main_pid or None,
                       "restart_count":numeric_value(values,"NRestarts"),"memory_bytes":numeric_value(values,"MemoryCurrent"),
                       "uptime_seconds":max(0,int(system_uptime-active_mono)) if active_mono else None,
                       "active_since_monotonic":active_mono or None,"critical":values["Id"] in crit})
    return result


class FleetCollector:
    def __init__(self, devices: List[DeviceConfig], max_workers: int = 4, timeout: float = 8,
                 password: str = "", runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run) -> None:
        self.devices=devices; self.max_workers=max(1,min(int(max_workers),16)); self.timeout=float(timeout)
        self.password=password; self.runner=runner; self.previous_cpu={}; self.previous_net={}; self.snapshots={}

    def _command(self, device: DeviceConfig) -> List[str]:
        args = (["__discover__"] if device.service_discovery else []) + list(device.monitored_services)
        if device.collection_method == "local": return ["sh", "-s", "--", *args]
        ssh=["ssh","-p",str(device.ssh_port),"-o",f"ConnectTimeout={max(1,int(self.timeout))}","-o","ServerAliveInterval=3"]
        if self.password: return ["sshpass","-e",*ssh,"-o","BatchMode=no",f"{device.ssh_user}@{device.address}","sh","-s","--",*args]
        return [*ssh,"-o","BatchMode=yes",f"{device.ssh_user}@{device.address}","sh","-s","--",*args]

    def collect_device(self, device: DeviceConfig) -> DeviceState:
        attempted=datetime.now(timezone.utc).isoformat(); old=self.snapshots.get(device.id)
        try:
            env={**os.environ,"LC_ALL":"C"};
            if self.password: env["SSHPASS"]=self.password
            proc=self.runner(self._command(device),input=SCRIPT,text=True,capture_output=True,timeout=self.timeout,env=env,check=False)
            if proc.returncode: raise RuntimeError((proc.stderr or f"command exited {proc.returncode}").strip()[:240])
            data=sections(proc.stdout); cpu,counter=parse_cpu(data,self.previous_cpu.get(device.id)); self.previous_cpu[device.id]=counter
            os_values={}
            for row in data.get("OS","").splitlines():
                if "=" in row: os_values[row.split("=",1)[0]]=row.split("=",1)[1].strip('"')
            uptime=float(data.get("UPTIME","0").split()[0]); uname=data.get("UNAME","").split()
            service_text=data.get("SERVICES",""); services=parse_services(service_text,device.critical_services,uptime)
            now=datetime.now(timezone.utc).isoformat()
            network=parse_network(data); stamp=time.monotonic(); prior=self.previous_net.get(device.id)
            if prior and network.get("rx_bytes") is not None:
                elapsed=max(.001,stamp-prior[0]); network["rx_rate"]=max(0,(network["rx_bytes"]-prior[1])/elapsed); network["tx_rate"]=max(0,(network["tx_bytes"]-prior[2])/elapsed)
            if network.get("rx_bytes") is not None: self.previous_net[device.id]=(stamp,network["rx_bytes"],network["tx_bytes"])
            raw={"id":device.id,"hostname":device.hostname,"friendly_name":device.friendly_name,"address":device.address,
                 "roles":list(device.roles),"tags":list(device.tags),"collection_method":device.collection_method,"notes":device.notes,
                 "cockpit_url":device.cockpit_url,"maintenance":device.maintenance,"online":True,"last_seen":now,"ip":network.get("ip", ""),
                 "last_successful_collection":now,"last_collection_attempt":attempted,"uptime_seconds":int(uptime),
                 "boot_time":datetime.fromtimestamp(time.time()-uptime,timezone.utc).isoformat(),
                 "model":data.get("MODEL", ""),"architecture":uname[-1] if uname else "","os":os_values.get("NAME",""),
                 "os_version":os_values.get("VERSION_ID",""),"kernel":uname[1] if len(uname)>1 else "","cpu":cpu,
                 "hardware":parse_throttled(data.get("THROTTLED","")),"memory":parse_memory(data.get("MEM","")),
                 "storage":parse_storage(data.get("DF",""),data.get("MOUNTS","")),"network":network,
                 "important_paths":list(device.important_paths),
                 "services":services,"critical_services":list(device.critical_services),
                 "collector_status":{"system":{"status":"ok"},"storage":{"status":"ok"},"network":{"status":"ok"},"services":{"status":"ok"}}}
            health,reasons,stale=evaluate(raw,device.thresholds); raw.update(health=health,health_reasons=reasons,stale=stale)
            result=DeviceState.from_dict(raw); self.snapshots[device.id]=result; return result
        except (subprocess.TimeoutExpired, OSError, RuntimeError) as exc:
            LOG.warning("[%s] collection failed: %s",device.id,exc)
            raw=old.to_dict() if old else {"id":device.id,"hostname":device.hostname,"friendly_name":device.friendly_name,
                "address":device.address,"roles":list(device.roles),"tags":list(device.tags),"collection_method":device.collection_method,
                "notes":device.notes,"cockpit_url":device.cockpit_url,"maintenance":device.maintenance}
            raw.update(last_collection_attempt=attempted,error=str(exc),collector_status={"transport":{"status":"error","error":str(exc)}})
            health,reasons,stale=evaluate(raw,device.thresholds)
            collected = raw.get("last_successful_collection") or raw.get("last_seen")
            raw.update(health=health,health_reasons=reasons,stale=stale,
                       online=bool(collected) and health != "offline")
            result=DeviceState.from_dict(raw); self.snapshots[device.id]=result; return result

    def collect(self) -> List[DeviceState]:
        with ThreadPoolExecutor(max_workers=self.max_workers,thread_name_prefix="fleet-device") as pool:
            futures={pool.submit(self.collect_device,d):d for d in self.devices}
            return [future.result() for future in as_completed(futures)]


def parse_network(data: Dict[str,str]) -> Dict[str,Any]:
    try: routes=json.loads(data.get("ROUTE") or "[]"); addresses=json.loads(data.get("ADDR") or "[]")
    except json.JSONDecodeError: routes,addresses=[],[]
    route=routes[0] if routes else {}; interface=route.get("dev",""); ip=""
    for item in addresses:
        if item.get("ifname")==interface:
            ip=next((x.get("local","") for x in item.get("addr_info",[]) if x.get("family")=="inet"),"")
    counters={}
    for row in data.get("NET","").splitlines()[2:]:
        if ":" in row:
            name,values=row.split(":",1); bits=values.split()
            if len(bits)>=9: counters[name.strip()]={"rx_bytes":int(bits[0]),"tx_bytes":int(bits[8])}
    wifi=interface.startswith(("wl","wlan")); iw=data.get("IW","")
    signal=ssid=channel=width=None
    for row in iw.splitlines():
        if row.strip().startswith("SSID:"): ssid=row.split(":",1)[1].strip()
        if "signal:" in row:
            try: signal=float(row.split("signal:",1)[1].split()[0])
            except ValueError: pass
        if row.strip().startswith("channel "):
            bits=row.strip().split();
            try: channel=int(bits[1])
            except (ValueError,IndexError): pass
            if "width:" in row: width=row.split("width:",1)[1].split(",",1)[0].strip()
    return {"interface":interface,"interface_type":"wifi" if wifi else ("ethernet" if interface.startswith(("eth","en")) else "other"),
            "ip":ip,"default_gateway":route.get("gateway"),**counters.get(interface,{}),"tx_rate":None,"rx_rate":None,
            "ssid":ssid,"signal_dbm":signal,"signal_quality_percent":max(0,min(100,2*(signal+100))) if signal is not None else None,
            "channel":channel,"channel_width":width}
