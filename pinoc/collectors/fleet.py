"""Transport-neutral, bounded fleet metrics collection."""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional

from pinoc.device_config import DeviceConfig
from pinoc.health import evaluate
from pinoc.models import DeviceState
from pinoc.integrations import IntegrationStatus, active_integrations
from pinoc.integrations.base import service as find_service

LOG = logging.getLogger("pinoc.collectors.fleet")
DISCOVERY = ("cockpit", "ssh", "desk-display", "piaware", "dump1090", "readsb", "magicmirror",
             "ics_modifier", "pi-hotspot", "temp-monitor", "smb", "smbd", "nmbd", "wg-quick")
SCRIPT = r'''set +e
# Optional bounded journal tail: "__jlogs__:<lines>:<unit1,unit2,...>" is passed
# only on the low-frequency cycles the PiNOC host selects.
jlogs_lines=""; jlogs_units=""
for arg in "$@"; do case "$arg" in __jlogs__:*) rest=${arg#__jlogs__:}; jlogs_lines=${rest%%:*}; jlogs_units=${rest#*:};; esac; done
echo __OS__; cat /etc/os-release 2>/dev/null; echo __UNAME__; uname -srm
echo __MODEL__; tr -d '\000' </proc/device-tree/model 2>/dev/null; echo
echo __UPTIME__; cat /proc/uptime; echo __LOAD__; cat /proc/loadavg
echo __CPU__; head -1 /proc/stat; echo __FREQ__; cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null
echo __TEMP__; for f in /sys/class/thermal/thermal_zone*/temp /sys/class/hwmon/hwmon*/temp1_input; do [ -r "$f" ] && echo "$f=$(cat "$f")"; done
echo __THROTTLED__; command -v vcgencmd >/dev/null && vcgencmd get_throttled
echo __MEM__; cat /proc/meminfo
echo __DF__; df -PT -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null
echo __DEVRESOLVE__
df -PT -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null | awk 'NR>1 && $1 ~ /^\/dev\//{print $1}' | sort -u | while IFS= read -r src; do printf '%s %s\n' "$src" "$(readlink -f "$src" 2>/dev/null || printf '%s' "$src")"; done
echo __MOUNTS__; cat /proc/mounts
echo __DISKSTATS__; cat /proc/diskstats 2>/dev/null
echo __IOERRORS__
kernel_log=$(dmesg 2>/dev/null); kernel_log_status=$?
if [ "$kernel_log_status" -ne 0 ]; then
    journal_stderr=$(mktemp "${TMPDIR:-/tmp}/pinoc-journal.XXXXXX" 2>/dev/null)
    if [ -n "$journal_stderr" ]; then
        kernel_log=$(journalctl -k --no-pager -n 500 2>"$journal_stderr"); kernel_log_status=$?
        # journalctl may return success while only reporting a privilege or
        # no-journal diagnostic.  Any diagnostic makes a clean result unsafe.
        [ -s "$journal_stderr" ] && kernel_log_status=1
        rm -f "$journal_stderr"
    else
        kernel_log_status=1
    fi
fi
if [ "$kernel_log_status" -eq 0 ]; then printf '%s\n' "$kernel_log" | grep -iE "i/o error|blk_update_request|EXT4-fs error|sdhci|mmcblk.*error|bad block" | tail -20; fi
echo __IOERRORSTATUS__; if [ "$kernel_log_status" -eq 0 ]; then echo available; else echo unavailable; fi
echo __ROUTE__; ip -j route show default 2>/dev/null; echo __ADDR__; ip -j address show 2>/dev/null
echo __NET__; cat /proc/net/dev
echo __IW__
if command -v iw >/dev/null; then
    iw dev 2>/dev/null
    ifc=$(iw dev 2>/dev/null | awk '$1=="Interface"{print $2;exit}')
    # "link" carries SSID/signal; channel/width only appear in "info"'s
    # "channel N (freq MHz), width: W MHz, ..." line -- link never prints it.
    [ -n "$ifc" ] && iw dev "$ifc" link 2>/dev/null
    [ -n "$ifc" ] && iw dev "$ifc" info 2>/dev/null
fi
if [ "$1" = "__discover__" ]; then shift; discovered=$(systemctl list-unit-files --no-legend --no-pager 2>/dev/null | awk '{print $1}' | grep -E '^(cockpit|ssh|desk-display|piaware|dump1090|readsb|magicmirror|ics_modifier|pi-hotspot|temp-monitor|smb|smbd|nmbd|wg-quick)' | head -30); fi
echo __SERVICES__; systemctl show --no-pager --property=Id,LoadState,ActiveState,SubState,MainPID,ActiveEnterTimestampMonotonic,NRestarts,MemoryCurrent "$@" $discovered 2>/dev/null
echo __UNITS__; systemctl list-unit-files --no-legend --no-pager 2>/dev/null
echo __JLOGS__
if [ -n "$jlogs_lines" ]; then
  for unit in $(printf '%s' "$jlogs_units" | tr ',' ' '); do
    echo "=== $unit"
    journalctl -u "$unit" --no-pager -q -n "$jlogs_lines" --output=short-precise 2>/dev/null | tail -n 200 | tail -c 65536
    echo
  done
fi
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


def _whole_disk(name: str) -> List[str]:
    """Whole-disk parent of a block device (sda1 -> sda, mmcblk0p2 -> mmcblk0)."""
    for pattern in (r"p\d+$", r"\d+$"):
        parent = re.sub(pattern, "", name)
        if parent and parent != name:
            return [parent]
    return []


def parse_devresolve(text: str) -> Dict[str, str]:
    """Map df filesystem sources to their resolved backing device paths.

    df reports mount sources verbatim, but some sources are aliases that
    /proc/diskstats does not use: /dev/root on Raspberry Pi OS points at the
    root partition, and /dev/mapper/* points at /dev/dm-N.  The collection
    script resolves each /dev/* source on the device, so media counters can
    be matched against the real block device name.
    """
    result: Dict[str, str] = {}
    for line in text.splitlines():
        bits = line.split()
        if len(bits) >= 2:
            result[bits[0]] = bits[-1]
    return result


def parse_media(diskstats: str, io_errors: str, storage: List[Dict[str, Any]],
                io_errors_available: bool = True,
                devresolve: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """Per-medium media wear/I-O-error status for block-backed filesystems.

    Best effort by design: non-root collectors (the normal case) may not read
    kernel logs, and unusual systems may lack matching /proc/diskstats rows;
    either way the capability degrades to an empty list instead of an error.
    Mount sources that df reports as aliases (/dev/root, /dev/mapper/*) are
    resolved to their backing block devices via ``devresolve`` before the
    diskstats lookup so aliased media still produce telemetry.
    """
    devresolve = devresolve or {}
    counters: Dict[str, Dict[str, int]] = {}
    for line in diskstats.splitlines():
        bits = line.split()
        if len(bits) < 10 or not bits[2]:
            continue
        try:
            counters[bits[2]] = {"read_sectors": int(bits[5]), "written_sectors": int(bits[9])}
        except ValueError:
            continue
    if not counters:
        return []
    mounts_by_device: Dict[str, List[str]] = {}
    for disk in storage:
        device = str(disk.get("device") or "")
        mount = disk.get("mount_point") or disk.get("path")
        if not device or not mount or device.startswith(("tmpfs", "devtmpfs", "overlay", "squashfs")):
            continue
        base = device.rsplit("/", 1)[-1]
        # df may report a mount-source alias that /proc/diskstats does not
        # name (e.g. /dev/root on Raspberry Pi OS, /dev/mapper/*).  Use the
        # resolved backing block device so its counters still match.
        resolved = devresolve.get(device)
        if resolved and resolved.startswith("/dev/"):
            base = resolved.rsplit("/", 1)[-1]
        # Also track the whole-disk parent (e.g. mmcblk0p2 -> mmcblk0) so wear
        # is reported once per physical medium.
        names = [base, *_whole_disk(base)]
        for name in names:
            targets = mounts_by_device.setdefault(name, [])
            if mount not in targets:
                targets.append(mount)
    error_lines = [line.strip() for line in io_errors.splitlines() if line.strip()][:20]
    # Consolidate partitions into their whole-disk medium (mmcblk0p2 ->
    # mmcblk0) so each physical medium is reported once.
    members: Dict[str, List[str]] = {}
    for name in mounts_by_device:
        medium = next((parent for parent in _whole_disk(name) if parent in counters), name)
        names = members.setdefault(medium, [])
        if name not in names:
            names.append(name)
    result: List[Dict[str, Any]] = []
    for medium, name_list in sorted(members.items()):
        row = counters.get(medium)
        if row is None:
            continue
        mounts: List[str] = []
        for name in name_list:
            for mount in mounts_by_device[name]:
                if mount not in mounts:
                    mounts.append(mount)
        # Kernel logs may reference the same medium under sibling names
        # (mmcblk0 vs mmc0); treat them as aliases.
        aliases = set(name_list)
        for name in name_list:
            if name.startswith("mmcblk"):
                aliases.add(name.replace("mmcblk", "mmc"))
            elif name.startswith("mmc"):
                aliases.add("mmcblk" + name[3:])
        errors = [line for line in error_lines if any(alias in line for alias in aliases)]
        result.append({
            "device": medium,
            "mount_points": mounts,
            "read_bytes": row["read_sectors"] * 512,
            "written_bytes": row["written_sectors"] * 512,
            "io_errors": len(errors) if io_errors_available else None,
            "media_errors": bool(errors) if io_errors_available else None,
            "io_error_status": "available" if io_errors_available else "unknown",
            "last_error": errors[-1][:200] if errors else None,
        })
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


_UNIT_RE = re.compile(r"[A-Za-z0-9@:_.\-]{1,128}")
_AUTHORIZATION_RE = re.compile(
    r"(?i)(?P<assignment>(?P<key_quote>['\"]?)[A-Za-z0-9_-]*authorization[A-Za-z0-9_-]*"
    r"(?P=key_quote)\s*[:=]\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\r\n]*)"
)
# An unquoted secret has no reliable delimiter: whitespace may be part of a
# passphrase.  Consume the remainder of the log line rather than risk retaining
# credential material after its first word.  Quoted values remain bounded by
# their matching quote so structured log fields following them are preserved.
_SECRET_RE = re.compile(
    r"(?i)(?P<assignment>(?P<key_quote>['\"]?)[A-Za-z0-9_-]*"
    r"(?:password|passwd|secret|token|api(?:[_\-]|[ \t]+)?key)[A-Za-z0-9_-]*"
    r"(?P=key_quote)\s*[:=]\s*)(?:Bearer\s+)?(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\r\n]*)"
    r"|\bBearer\s+\S+"
)
_KEY_BLOCK_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)

def redact_log_line(line: str) -> str:
    """Best-effort neutralization of obvious secret patterns in log text."""
    line = _KEY_BLOCK_RE.sub("[REDACTED-KEY]", line)
    def replacement(match: re.Match[str]) -> str:
        assignment = match.group("assignment")
        if assignment is None:
            return "[REDACTED]"
        value = match.group("value")
        quote = value[0] if value and value[0] in "'\"" else ""
        return assignment + quote + "[REDACTED]" + quote

    # Authorization schemes have different credential grammars (for example,
    # Basic, Digest, and AWS4-HMAC-SHA256), so redact an unquoted header value
    # through the end of the line rather than attempting to identify a token.
    line = _AUTHORIZATION_RE.sub(replacement, line)
    return _SECRET_RE.sub(replacement, line)

def parse_jlogs(text: str) -> List[Dict[str, Any]]:
    """Parse the __JLOGS__ section into per-unit tails with hard caps."""
    # Redact across the complete section before splitlines() so a conventional
    # multiline PEM block is matched from its BEGIN marker through its END
    # marker.  Per-line redaction alone cannot recognize such blocks.
    text = _KEY_BLOCK_RE.sub("[REDACTED-KEY]", text)
    entries: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    for line in text.splitlines():
        if line.startswith("=== "):
            if current is not None:
                entries.append(current)
            current = {"unit": line[4:].strip()[:128], "lines": []}
        elif current is not None and line.strip():
            current["lines"].append(redact_log_line(line)[:512])
            if len(current["lines"]) > 200:
                del current["lines"][: len(current["lines"]) - 200]
    if current is not None:
        entries.append(current)
    return [entry for entry in entries if entry["lines"]][:50]

class FleetCollector:
    def __init__(self, devices: List[DeviceConfig], max_workers: int = 4, timeout: float = 8,
                 password: str = "", runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
                 log_tail_seconds: float = 300.0, log_tail_lines: int = 50) -> None:
        self.devices=devices; self.max_workers=max(1,min(int(max_workers),16)); self.timeout=float(timeout)
        self.password=password; self.runner=runner; self.previous_cpu={}; self.previous_net={}; self.snapshots={}
        self.log_tail_seconds=max(30.0,float(log_tail_seconds)); self.log_tail_lines=min(200,max(1,int(log_tail_lines)))
        self._last_jlogs: Dict[str, float] = {}

    def _command(self, device: DeviceConfig, jlogs_due: bool = False) -> List[str]:
        args = (["__discover__"] if device.service_discovery else []) + list(device.monitored_services)
        if jlogs_due:
            units: List[str] = []
            for name in [str(x) for x in list(device.monitored_services) + list(device.critical_services)]:
                if _UNIT_RE.fullmatch(name) and name not in units:
                    units.append(name)
                if len(units) >= 10:
                    break
            if units:
                args.append(f"__jlogs__:{self.log_tail_lines}:{','.join(units)}")
        if device.collection_method == "local": return ["sh", "-s", "--", *args]
        ssh=["ssh","-p",str(device.ssh_port),"-o",f"ConnectTimeout={max(1,int(self.timeout))}","-o","ServerAliveInterval=3"]
        if self.password: return ["sshpass","-e",*ssh,"-o","BatchMode=no",f"{device.ssh_user}@{device.address}","sh","-s","--",*args]
        return [*ssh,"-o","BatchMode=yes",f"{device.ssh_user}@{device.address}","sh","-s","--",*args]

    def collect_device(self, device: DeviceConfig) -> DeviceState:
        attempted=datetime.now(timezone.utc).isoformat(); old=self.snapshots.get(device.id)
        jlogs_due=time.monotonic()-self._last_jlogs.get(device.id,0.0)>=self.log_tail_seconds
        try:
            env={**os.environ,"LC_ALL":"C"};
            if self.password: env["SSHPASS"]=self.password
            proc=self.runner(self._command(device,jlogs_due),input=SCRIPT,text=True,capture_output=True,timeout=self.timeout,env=env,check=False)
            if proc.returncode: raise RuntimeError((proc.stderr or f"command exited {proc.returncode}").strip()[:240])
            self._last_jlogs[device.id]=time.monotonic()
            data=sections(proc.stdout); cpu,counter=parse_cpu(data,self.previous_cpu.get(device.id)); self.previous_cpu[device.id]=counter
            os_values={}
            for row in data.get("OS","").splitlines():
                if "=" in row: os_values[row.split("=",1)[0]]=row.split("=",1)[1].strip('"')
            # data.get("UPTIME","0") only falls back when the key is absent
            # entirely; a present-but-empty UPTIME section (device command
            # failed silently, unreadable /proc/uptime, ...) still leaves
            # split() == [] and [0] raising IndexError, so guard it too.
            uptime_parts=data.get("UPTIME","0").split(); uptime=float(uptime_parts[0]) if uptime_parts else 0.0
            uname=data.get("UNAME","").split()
            service_text=data.get("SERVICES",""); services=parse_services(service_text,device.critical_services,uptime)
            now=datetime.now(timezone.utc).isoformat()
            network=parse_network(data); stamp=time.monotonic(); prior=self.previous_net.get(device.id)
            if prior and network.get("rx_bytes") is not None:
                elapsed=max(.001,stamp-prior[0]); network["rx_rate"]=max(0,(network["rx_bytes"]-prior[1])/elapsed); network["tx_rate"]=max(0,(network["tx_bytes"]-prior[2])/elapsed)
            if network.get("rx_bytes") is not None: self.previous_net[device.id]=(stamp,network["rx_bytes"],network["tx_bytes"])
            storage=parse_storage(data.get("DF",""),data.get("MOUNTS",""))
            io_errors_available=data.get("IOERRORSTATUS") == "available"
            media=parse_media(data.get("DISKSTATS",""),data.get("IOERRORS",""),storage,io_errors_available,
                              parse_devresolve(data.get("DEVRESOLVE","")))
            raw={"id":device.id,"hostname":device.hostname,"friendly_name":device.friendly_name,"address":device.address,
                 "roles":list(device.roles),"tags":list(device.tags),"collection_method":device.collection_method,"notes":device.notes,
                 "ssh_user":device.ssh_user,"ssh_port":device.ssh_port,"monitored_services":list(device.monitored_services),
                 "manageable_services":list(device.manageable_services),
                 "allowed_actions":list(device.allowed_actions),
                 "cockpit_url":device.cockpit_url,"maintenance":device.maintenance,"online":True,"last_seen":now,"ip":network.get("ip", ""),
                 "last_successful_collection":now,"last_collection_attempt":attempted,"uptime_seconds":int(uptime),
                 "boot_time":datetime.fromtimestamp(time.time()-uptime,timezone.utc).isoformat(),
                 "model":data.get("MODEL", ""),"architecture":uname[-1] if uname else "","os":os_values.get("NAME",""),
                 "os_version":os_values.get("VERSION_ID",""),"kernel":uname[1] if len(uname)>1 else "","cpu":cpu,
                 "hardware":parse_throttled(data.get("THROTTLED","")),"memory":parse_memory(data.get("MEM","")),
                 "storage":storage,"media":media,"network":network,
                 "important_paths":list(device.important_paths),
                 "services":services,"critical_services":list(device.critical_services),
                 "collector_status":{"system":{"status":"ok"},"storage":{"status":"ok"},
                                     "media_errors":{"status":"ok" if io_errors_available else "unavailable",
                                                     "error":None if io_errors_available else "kernel logs are not readable"},
                                     "network":{"status":"ok"},"services":{"status":"ok"}}}
            integrations={}
            for name in active_integrations(device.roles,device.integrations):
                cfg=device.integrations.get(name,{})
                cfg=cfg if isinstance(cfg,dict) else {}
                if name=="probe":
                    # Probes run from the PiNOC host on their own schedule;
                    # the fleet cycle only seeds the placeholder the probe
                    # collector then refreshes.
                    checks=cfg.get("checks",[])
                    integrations["probe"]=(IntegrationStatus(name="probe",available=bool(checks),
                        health="unavailable" if checks else "unsupported",
                        last_attempt=attempted,data_source="probe",
                        error=None if checks else "no probe checks configured",
                        data={"checks":[{"name":x.get("name"),"kind":x.get("kind")} for x in checks],
                              "checks_total":len(checks),"failed_checks":None,"response_latency_ms":None},
                        critical=bool(cfg.get("critical",False)))).to_dict()
                    continue
                candidates={"adsb":["piaware.service","dump1090-fa.service","readsb.service"],"desk_display":["desk-display.service"],"magicmirror":["magicmirror.service"],"ics_modifier":["ics_modifier.service"],"pi_hotspot":["pi-hotspot.service"],"wireguard":["wg-quick@wg0.service"],"samba":["smbd.service","smb.service"]}.get(name,[])
                found=[find_service(services,x) for x in candidates]; found=[x for x in found if x]
                available=bool(found) if candidates else False
                failed=any(x.get("state") not in ("running","activating") for x in found)
                integrations[name]=IntegrationStatus(name=name,available=available,
                    health="degraded" if failed else "healthy" if available else "unsupported",
                    last_success=now if available else None,last_attempt=attempted,
                    data_source="systemd" if candidates else None,
                    error=None if available else "optional data source not discovered",
                    data={"services":found},critical=bool(cfg.get("critical",False))).to_dict()
            raw["integrations"]=integrations
            raw["logs"]=parse_jlogs(data.get("JLOGS","")) if jlogs_due else (list(old.logs) if old else [])
            health,reasons,stale=evaluate(raw,device.thresholds); raw.update(health=health,health_reasons=reasons,stale=stale)
            result=DeviceState.from_dict(raw); self.snapshots[device.id]=result; return result
        except (subprocess.TimeoutExpired, OSError, RuntimeError) as exc:
            return self._failure_result(device,old,attempted,exc)

    def _failure_result(self, device: DeviceConfig, old: Optional[DeviceState], attempted: str, exc: BaseException) -> DeviceState:
        LOG.warning("[%s] collection failed: %s",device.id,exc)
        raw=old.to_dict() if old else {"id":device.id,"hostname":device.hostname,"friendly_name":device.friendly_name,
            "address":device.address,"roles":list(device.roles),"tags":list(device.tags),"collection_method":device.collection_method,
            "ssh_user":device.ssh_user,"ssh_port":device.ssh_port,"monitored_services":list(device.monitored_services),
            "critical_services":list(device.critical_services),"manageable_services":list(device.manageable_services),
            "allowed_actions":list(device.allowed_actions),
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
            results=[]
            for future in as_completed(futures):
                device=futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    # collect_device() already handles expected transport
                    # failures gracefully; reaching here means something
                    # unexpected went wrong in one device's collection. It
                    # must not silently drop that device from the fleet
                    # (state.publish(replace=True) deletes devices missing
                    # from this result) or abort every other device's
                    # result for the cycle.
                    results.append(self._failure_result(
                        device,self.snapshots.get(device.id),
                        datetime.now(timezone.utc).isoformat(),exc))
            return results


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
