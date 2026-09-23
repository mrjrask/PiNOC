"""Transport-neutral, bounded fleet metrics collection."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional

from pinoc.device_config import DeviceConfig, MAX_DRIFT_FILES
from pinoc.health import evaluate
from pinoc.models import DeviceState
from pinoc.integrations import IntegrationStatus, active_integrations
from pinoc.integrations.base import service as find_service
from pinoc.integrations.packages import parse_apt
from pinoc.integrations.raid import parse_mdstat

LOG = logging.getLogger("pinoc.collectors.fleet")
DISCOVERY = ("cockpit", "ssh", "desk-display", "piaware", "dump1090", "readsb", "magicmirror",
             "ics_modifier", "pi-hotspot", "temp-monitor", "smb", "smbd", "nmbd", "wg-quick")
SCRIPT = r'''set +e
# Optional bounded journal tail: "__jlogs__:<lines>:<unit1,unit2,...>" is passed
# only on the low-frequency cycles the PiNOC host selects. "__apt__" is
# passed only on the (much lower-frequency) cycle a package check is due --
# `apt-get --just-print upgrade` simulates a dependency resolution over the
# whole local apt cache and must not run on every fleet poll.
jlogs_lines=""; jlogs_units=""; apt_due=0; authcheck_due=0; drift_files=""; sshdcheck_due=0
for arg in "$@"; do case "$arg" in __jlogs__:*) rest=${arg#__jlogs__:}; jlogs_lines=${rest%%:*}; jlogs_units=${rest#*:};; __apt__) apt_due=1;; __authcheck__) authcheck_due=1;; __driftfiles__:*) drift_files=${arg#__driftfiles__:};; __sshdcheck__) sshdcheck_due=1;; esac; done
echo __OS__; cat /etc/os-release 2>/dev/null; echo __UNAME__; uname -srm
echo __MODEL__; tr -d '\000' </proc/device-tree/model 2>/dev/null; echo
echo __UPTIME__; cat /proc/uptime; echo __LOAD__; cat /proc/loadavg
echo __CPU__; head -1 /proc/stat; echo __FREQ__; cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null
echo __MDSTAT__; cat /proc/mdstat 2>/dev/null
echo __APT__; if [ "$apt_due" = "1" ]; then apt-get --just-print upgrade 2>/dev/null; fi
echo __REBOOTREQUIRED__; [ -f /var/run/reboot-required ] && echo 1 || echo 0
echo __APTREFRESH__; stat -c %Y /var/lib/apt/lists 2>/dev/null
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
echo __LISTENTCP__; ss -Htlnp 2>/dev/null | head -200
echo __LISTENUDP__; ss -Hulnp 2>/dev/null | head -200
echo __AUTHFAIL__
# Bounded, low-frequency (only on the same cadence as the journal tail
# above): count recent failed SSH login attempts. journalctl is preferred
# (systemd hosts); auth.log/secure is the fallback on hosts without a
# journal. Each source is capped at 500 lines, so this is a small, fixed-
# size scan, never an unbounded log walk.
if [ "$authcheck_due" = "1" ]; then
  { journalctl -u ssh -u sshd --no-pager -q -n 500 --since "-30 min" 2>/dev/null
    tail -n 500 /var/log/auth.log 2>/dev/null
    tail -n 500 /var/log/secure 2>/dev/null; } | grep -ciE "Failed password|Invalid user|authentication failure|Failed publickey"
fi
if [ "$1" = "__discover__" ]; then shift; discovered=$(systemctl list-unit-files --no-legend --no-pager 2>/dev/null | awk '{print $1}' | grep -E '^(cockpit|ssh|desk-display|piaware|dump1090|readsb|magicmirror|ics_modifier|pi-hotspot|temp-monitor|smb|smbd|nmbd|wg-quick)' | head -30); fi
echo __SERVICES__; systemctl show --no-pager --property=Id,LoadState,ActiveState,SubState,MainPID,ActiveEnterTimestampMonotonic,NRestarts,MemoryCurrent,UnitFileState "$@" $discovered 2>/dev/null
echo __UNITS__; systemctl list-unit-files --no-legend --no-pager 2>/dev/null
echo __DRIFTFILES__
if [ -n "$drift_files" ]; then
  for f in $(printf '%s' "$drift_files" | tr ',' ' '); do
    printf '=== %s\n' "$f"
    if [ -r "$f" ]; then
      sz=$(stat -c%s "$f" 2>/dev/null)
      if [ -n "$sz" ] && [ "$sz" -le 65536 ] 2>/dev/null; then
        printf 'SIZE:%s\n' "$sz"
        enc=$(base64 "$f" 2>/dev/null | tr -d '\n')
        printf '%s\n' "${enc:--}"
      else
        printf 'SIZE:%s\n' "${sz:-unknown}"
        printf -- '-\n'
      fi
    else
      printf 'MISSING\n'
      printf -- '-\n'
    fi
  done
fi
echo __SSHD__
if [ "$sshdcheck_due" = "1" ]; then sshd -T 2>/dev/null; fi
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


def _apt_refresh_iso(text: str) -> Optional[str]:
    """Convert __APTREFRESH__'s epoch seconds (the apt lists directory's
    mtime, updated whenever the local apt cache is refreshed) to ISO 8601."""
    try:
        return datetime.fromtimestamp(int(text.strip()), timezone.utc).isoformat()
    except (ValueError, OSError):
        return None


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


MAX_LISTENERS = 200
_LISTEN_PROCESS_RE = re.compile(r'users:\(\("([^"]+)"')


def parse_listeners(tcp_text: str, udp_text: str) -> List[Dict[str, Any]]:
    """Parse ``ss -Htlnp``/``ss -Hulnp`` output into a bounded listener
    inventory: one entry per local (proto, port), each carrying the owning
    process name when it was visible (unprivileged collection often cannot
    see it, which is fine -- the port/proto pair is what alerting keys on).
    """
    result: List[Dict[str, Any]] = []
    seen: set = set()
    for proto, text in (("tcp", tcp_text), ("udp", udp_text)):
        for line in text.splitlines():
            bits = line.split()
            if len(bits) < 4:
                continue
            local = bits[3]
            port_text = local.rsplit(":", 1)[-1]
            try:
                port = int(port_text)
            except ValueError:
                continue
            if not 1 <= port <= 65535:
                continue
            process_match = _LISTEN_PROCESS_RE.search(line)
            key = (proto, port)
            if key in seen:
                continue
            seen.add(key)
            result.append({"proto": proto, "port": port,
                           "process": process_match.group(1) if process_match else None})
            if len(result) >= MAX_LISTENERS:
                return result
    return result


_AUTH_FAIL_RE = re.compile(r"\A\s*(\d+)")


def parse_auth_failures(text: str) -> Optional[int]:
    """Parse the bounded ``__AUTHFAIL__`` section (a single ``grep -c``
    count) into an integer. ``None`` means the section was not collected
    this cycle (not due, or the command produced no parseable output)."""
    match = _AUTH_FAIL_RE.match(text or "")
    return int(match.group(1)) if match else None


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
                       "active_since_monotonic":active_mono or None,"critical":values["Id"] in crit,
                       # unit_file_state feeds configuration drift detection
                       # (enhancement #6): "enabled"/"static"/... vs.
                       # "disabled"/"masked" -- see compute_config_drift().
                       "unit_file_state":values.get("UnitFileState") or None})
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


# Configuration drift detection (enhancement #6): a device's actual state
# for whatever's named in its own ConfigDriftSpec (pinoc.device_config),
# diffed against that spec below to open a single readable config_drift
# alert through the normal integration-conditions path
# (HistoryManager._alerts()), never a parallel mechanism.
MAX_DRIFT_FILE_BYTES = 65536
# Unit states that count as "properly enabled" for drift purposes -- systemd
# reports more than a plain "enabled": a unit pulled in only via another
# unit's static dependency ("static"), one enabled for this boot only
# ("enabled-runtime"), or an alias/indirect target are all legitimately
# non-disabled, non-masked states an administrator would not call drift.
_UNIT_ENABLED_STATES = frozenset({"enabled", "enabled-runtime", "static", "alias", "indirect"})


def parse_drift_files(text: str) -> Dict[str, Dict[str, Any]]:
    """Parse the bounded __DRIFTFILES__ section (fixed 3-line records: a
    ``=== path`` header, a ``SIZE:n``/``MISSING`` line, and a base64 content
    line or ``-``) into per-path actual state. ``sha256``/``content`` stay
    ``None`` when the file is missing, unreadable, or larger than
    MAX_DRIFT_FILE_BYTES (too large to safely fetch/verify in a bounded
    poll) -- the hash is always computed locally from the fetched bytes,
    never trusted from the remote side.
    """
    lines = text.splitlines()
    result: Dict[str, Dict[str, Any]] = {}
    i = 0
    while i < len(lines):
        header = lines[i]
        if not header.startswith("=== "):
            i += 1
            continue
        path = header[4:].strip()
        entry: Dict[str, Any] = {"exists": False, "size": None, "sha256": None, "content": None}
        meta = lines[i + 1] if i + 1 < len(lines) else ""
        content_line = lines[i + 2] if i + 2 < len(lines) else "-"
        i += 3
        if meta == "MISSING":
            result[path] = entry
            continue
        entry["exists"] = True
        if meta.startswith("SIZE:"):
            raw_size = meta[len("SIZE:"):].strip()
            if raw_size.isdigit():
                entry["size"] = int(raw_size)
        content_line = content_line.strip()
        if content_line and content_line != "-" and entry["size"] is not None and entry["size"] <= MAX_DRIFT_FILE_BYTES:
            try:
                content = base64.b64decode(content_line, validate=False)
            except (ValueError, binascii.Error):
                content = None
            if content is not None:
                entry["content"] = content
                entry["sha256"] = hashlib.sha256(content).hexdigest()
        result[path] = entry
    return result


def parse_sshd_options(text: str) -> Dict[str, str]:
    """Parse ``sshd -T``'s normalized ``key value`` lines (already
    lowercase, one option per line, defaults resolved) into a dict."""
    result: Dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            result[parts[0].lower()] = parts[1].strip()
    return result


def compute_config_drift(spec: Any, unit_states: Dict[str, Dict[str, Any]],
                         drift_files: Dict[str, Dict[str, Any]], sshd_options: Dict[str, str],
                         files_due: bool, sshd_due: bool,
                         previous: Optional[List[Dict[str, Any]]] = None) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Diff a device's ConfigDriftSpec against its collected actual state.

    Returns ``(drift_items, snapshots)``:

    - ``drift_items``: ``{"type","name","expected","actual"}`` per drifted
      unit/file/sshd option (empty when nothing has drifted).
    - ``snapshots``: ``{"path","sha256","content"}`` for files that
      currently match their expected hash -- fed back into
      pinoc.backup's known-good file store so "config_drift.restore_file"
      has something to restore once the file actually drifts.

    Units are checked every call (systemctl show is cheap and always runs
    for expected_units -- see FleetCollector._command()); files/sshd
    options only run on the low-frequency ``files_due``/``sshd_due``
    cadence and otherwise carry forward `previous`'s items for that
    category, the same not-due fallback `packages`/`security` already use
    elsewhere in this module, so a config_drift alert doesn't flap
    open/resolved every poll the expensive check isn't due.
    """
    drift: List[Dict[str, Any]] = []
    snapshots: List[Dict[str, Any]] = []
    for unit in spec.expected_units:
        state = unit_states.get(unit)
        if state is None:
            drift.append({"type": "unit", "name": unit, "expected": "enabled", "actual": "unit not found"})
            continue
        unit_file_state = state.get("unit_file_state")
        if not unit_file_state:
            continue  # not reported this cycle -- avoid a false positive
        if unit_file_state not in _UNIT_ENABLED_STATES:
            drift.append({"type": "unit", "name": unit, "expected": "enabled", "actual": unit_file_state})
    if files_due:
        for path, expected_hash in spec.expected_files.items():
            actual = drift_files.get(path)
            if actual is None:
                continue
            if not actual["exists"]:
                drift.append({"type": "file", "name": path, "expected": expected_hash[:12], "actual": "missing"})
            elif actual["sha256"] is None:
                drift.append({"type": "file", "name": path, "expected": expected_hash[:12],
                             "actual": "unreadable or too large to verify"})
            elif actual["sha256"] != expected_hash:
                drift.append({"type": "file", "name": path, "expected": expected_hash[:12],
                             "actual": actual["sha256"][:12]})
            elif actual.get("content") is not None:
                snapshots.append({"path": path, "sha256": actual["sha256"], "content": actual["content"]})
    else:
        drift.extend(item for item in (previous or []) if item["type"] == "file")
    if sshd_due:
        for option, expected_value in spec.expected_sshd_options.items():
            actual_value = sshd_options.get(option.lower())
            if actual_value is None:
                continue
            if actual_value != expected_value:
                drift.append({"type": "sshd_option", "name": option, "expected": expected_value, "actual": actual_value})
    else:
        drift.extend(item for item in (previous or []) if item["type"] == "sshd_option")
    return drift, snapshots


_DRIFT_LABELS = {"unit": "unit", "file": "file", "sshd_option": "sshd option"}


def format_drift_diff(drift_items: Iterable[Dict[str, Any]]) -> str:
    """One readable ``expected vs. found`` line per drifted item -- the
    text carried in the config_drift alert's message/metadata."""
    lines = []
    for item in drift_items:
        label = _DRIFT_LABELS.get(item["type"], item["type"])
        lines.append(f"{label} {item['name']}: expected {item['expected']!r}, found {item['actual']!r}")
    return "\n".join(lines)


def _config_drift_expected_dict(device: DeviceConfig) -> Dict[str, Any]:
    """JSON-safe form of a device's ConfigDriftSpec, carried through
    DeviceState.config_drift_expected so pinoc.actions.ActionDispatcher can
    bound "config_drift.*" repair actions to exactly this device's own
    configured units/files -- never an arbitrary one. Empty when the device
    has no expected-state spec configured."""
    spec = device.config_drift
    if spec.is_empty():
        return {}
    return {"expected_units": list(spec.expected_units),
            "expected_files": dict(spec.expected_files),
            "expected_sshd_options": dict(spec.expected_sshd_options)}


class FleetCollector:
    def __init__(self, devices: List[DeviceConfig], max_workers: int = 4, timeout: float = 8,
                 password: str = "", runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
                 log_tail_seconds: float = 300.0, log_tail_lines: int = 50,
                 passwords: Optional[Dict[str, str]] = None,
                 packages_check_seconds: float = 21600.0,
                 auth_fail_warning: float = 5, auth_fail_critical: float = 20,
                 auth_fail_hysteresis: float = 2,
                 listener_change_duration_seconds: float = 60.0,
                 drift_check_seconds: float = 300.0) -> None:
        self.devices=devices; self.max_workers=max(1,min(int(max_workers),16)); self.timeout=float(timeout)
        self.password=password; self.runner=runner
        # Per-device password override (device_id -> password): compromising
        # one device's SSH access no longer exposes every other password-
        # auth device's credential too. `password` remains as the
        # fleet-wide fallback for devices without their own entry, so
        # existing single-password deployments keep working unchanged.
        self.passwords=dict(passwords or {})
        # previous_cpu/previous_net/snapshots/_last_jlogs are shared across
        # every collect_device() call, which collect() dispatches to a
        # ThreadPoolExecutor -- one worker thread per device. Safe today
        # only because each device.id is ever read/written by the single
        # worker thread processing that device (no two threads ever touch
        # the same key), and every access here is a single dict item
        # get/assignment, which is atomic under CPython's GIL. This is an
        # invariant of *how these dicts are used*, not of the dicts
        # themselves: a future change that reads-then-writes a key across
        # more than one step (e.g. an in-place update instead of a
        # wholesale replace) would need its own explicit synchronization.
        self.previous_cpu={}; self.previous_net={}; self.snapshots={}
        self.log_tail_seconds=max(30.0,float(log_tail_seconds)); self.log_tail_lines=min(200,max(1,int(log_tail_lines)))
        self._last_jlogs: Dict[str, float] = {}
        # apt-get --just-print upgrade simulates a dependency resolution over
        # the whole local apt cache -- far too expensive to run on every
        # fleet poll (default every ~10s). Bounded like jlogs above, but on
        # its own, much lower-frequency cadence (default 6h, matching the
        # long-documented-but-previously-unused DEFAULT_INTERVALS["packages"]).
        self.packages_check_seconds=max(60.0,float(packages_check_seconds))
        self._last_apt_check: Dict[str, float] = {}
        # Configuration drift detection (enhancement #6): file-hash/sshd
        # checks are their own low-frequency, bounded cadence -- unit
        # enabled/masked state rides along with every poll instead (see
        # _command() above), the same jlogs-style due-gating idiom as
        # apt/packages above.
        self.drift_check_seconds=max(30.0,float(drift_check_seconds))
        self._last_drift_check: Dict[str, float] = {}
        # Security-surface monitoring (auth failures, listening ports): each
        # threshold/hysteresis pair follows the exact same open-until-you-
        # drop-back-down shape history.HistoryManager._alerts() already uses
        # for temperature/disk usage, just evaluated here since these
        # signals are computed in this collector rather than persisted
        # thresholds. auth_fail_active/listener_since are per-device
        # cross-poll state, the same idiom as previous_cpu/cpu_since above.
        self.auth_fail_warning=max(1.0,float(auth_fail_warning))
        self.auth_fail_critical=max(self.auth_fail_warning,float(auth_fail_critical))
        self.auth_fail_hysteresis=max(0.0,float(auth_fail_hysteresis))
        self.listener_change_duration_seconds=max(0.0,float(listener_change_duration_seconds))
        self._auth_fail_active: Dict[str, bool] = {}
        self._last_auth_failures: Dict[str, Optional[int]] = {}
        self._listener_since: Dict[str, Dict[str, float]] = {}

    def _password_for(self, device: DeviceConfig) -> str:
        return self.passwords.get(device.id) or self.password

    def _command(self, device: DeviceConfig, jlogs_due: bool = False, apt_due: bool = False,
                 drift_due: bool = False) -> List[str]:
        # config_drift.expected_units ride along with monitored_services in
        # the same single `systemctl show` call (see __SERVICES__ below,
        # which now also asks for UnitFileState) -- cheap enough to check on
        # every poll, unlike the file-hash/sshd checks below, which only run
        # on the low-frequency drift_due cadence.
        base_units = list(dict.fromkeys(list(device.monitored_services) + list(device.config_drift.expected_units)))
        args = (["__discover__"] if device.service_discovery else []) + base_units
        if jlogs_due:
            units: List[str] = []
            for name in [str(x) for x in list(device.monitored_services) + list(device.critical_services)]:
                if _UNIT_RE.fullmatch(name) and name not in units:
                    units.append(name)
                if len(units) >= 10:
                    break
            if units:
                args.append(f"__jlogs__:{self.log_tail_lines}:{','.join(units)}")
            # Independent of whether any journal units were found above (a
            # device with no monitored_services would otherwise never get an
            # auth-failure check at all) -- gated on the same jlogs_due
            # cadence so it stays a bounded, low-frequency scan.
            args.append("__authcheck__")
        if apt_due:
            args.append("__apt__")
        if drift_due:
            files = list(device.config_drift.expected_files)[:MAX_DRIFT_FILES]
            if files:
                args.append(f"__driftfiles__:{','.join(files)}")
            if device.config_drift.expected_sshd_options:
                args.append("__sshdcheck__")
        if device.collection_method == "local": return ["sh", "-s", "--", *args]
        ssh=["ssh","-p",str(device.ssh_port),"-o",f"ConnectTimeout={max(1,int(self.timeout))}","-o","ServerAliveInterval=3"]
        if self._password_for(device): return ["sshpass","-e",*ssh,"-o","BatchMode=no",f"{device.ssh_user}@{device.address}","sh","-s","--",*args]
        return [*ssh,"-o","BatchMode=yes",f"{device.ssh_user}@{device.address}","sh","-s","--",*args]

    def collect_device(self, device: DeviceConfig) -> DeviceState:
        attempted=datetime.now(timezone.utc).isoformat(); old=self.snapshots.get(device.id)
        # time.monotonic()'s reference point is platform-defined (often time
        # since boot, not process start) and can legitimately be smaller
        # than log_tail_seconds/packages_check_seconds on a freshly booted
        # host or container -- "subtract a 0.0 default" would then make
        # jlogs/apt spuriously NOT due on a device's very first collection.
        # Missing-from-the-dict must be its own explicit "always due" case.
        last_jlogs=self._last_jlogs.get(device.id)
        jlogs_due=last_jlogs is None or time.monotonic()-last_jlogs>=self.log_tail_seconds
        last_apt=self._last_apt_check.get(device.id)
        apt_due=last_apt is None or time.monotonic()-last_apt>=self.packages_check_seconds
        last_drift=self._last_drift_check.get(device.id)
        drift_due=(not device.config_drift.is_empty()
                  and (last_drift is None or time.monotonic()-last_drift>=self.drift_check_seconds))
        try:
            env={**os.environ,"LC_ALL":"C"}
            device_password=self._password_for(device)
            if device_password: env["SSHPASS"]=device_password
            proc=self.runner(self._command(device,jlogs_due,apt_due,drift_due),input=SCRIPT,text=True,capture_output=True,timeout=self.timeout,env=env,check=False)
            if proc.returncode: raise RuntimeError((proc.stderr or f"command exited {proc.returncode}").strip()[:240])
            self._last_jlogs[device.id]=time.monotonic()
            # Only reset the apt cadence clock when a check actually ran
            # this cycle -- unlike jlogs above, resetting it unconditionally
            # on every poll would mean apt_due, computed from "time since
            # last reset", could never reach packages_check_seconds again
            # after the very first collection.
            if apt_due: self._last_apt_check[device.id]=time.monotonic()
            if drift_due: self._last_drift_check[device.id]=time.monotonic()
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
                 "config_drift_expected":_config_drift_expected_dict(device),
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
                if name=="raid":
                    arrays=parse_mdstat(data.get("MDSTAT",""))
                    degraded=any(a["degraded"] for a in arrays)
                    integrations["raid"]=IntegrationStatus(name="raid",available=bool(arrays),
                        health="critical" if degraded else "healthy" if arrays else "unsupported",
                        last_success=now if arrays else None,last_attempt=attempted,
                        data_source="mdstat" if arrays else None,
                        error=None if arrays else "no RAID arrays reported by /proc/mdstat",
                        data={"arrays":arrays},critical=bool(cfg.get("critical",False))).to_dict()
                    continue
                if name=="packages":
                    old_packages=(old.integrations or {}).get("packages") if old else None
                    if apt_due:
                        parsed=parse_apt(data.get("APT",""),
                            reboot_required=data.get("REBOOTREQUIRED","").strip()=="1",
                            metadata_refresh=_apt_refresh_iso(data.get("APTREFRESH","")))
                        integrations["packages"]=IntegrationStatus(name="packages",available=True,
                            health="warning" if parsed["security_updates"] else "healthy",
                            last_success=now,last_attempt=attempted,data_source="apt-get",
                            data=parsed,critical=bool(cfg.get("critical",False))).to_dict()
                    elif old_packages:
                        # Not due this cycle -- surface the last real check
                        # rather than flip to "unavailable" every poll that
                        # doesn't happen to land on the (multi-hour) cadence.
                        integrations["packages"]={**old_packages,"last_attempt":attempted}
                    else:
                        integrations["packages"]=IntegrationStatus(name="packages",available=False,
                            health="unavailable",last_attempt=attempted,
                            error="awaiting first package check",
                            critical=bool(cfg.get("critical",False))).to_dict()
                    continue
                candidates={"adsb":["piaware.service","dump1090-fa.service","readsb.service"],"desk_display":["desk-display.service"],"magicmirror":["magicmirror.service"],"ics_modifier":["ics_modifier.service"],"pi_hotspot":["pi-hotspot.service"],"wireguard":["wg-quick@wg0.service"],"samba":["smbd.service","smb.service"]}.get(name,[])
                configured_service=cfg.get("service")
                if isinstance(configured_service,str):candidates=[configured_service]
                found=[find_service(services,x) for x in candidates]; found=[x for x in found if x]
                available=bool(found) if candidates else False
                failed=any(x.get("state") not in ("running","activating") for x in found)
                integrations[name]=IntegrationStatus(name=name,available=available,
                    health="degraded" if failed else "healthy" if available else "unsupported",
                    last_success=now if available else None,last_attempt=attempted,
                    data_source="systemd" if candidates else None,
                    error=None if available else "optional data source not discovered",
                    data={"services":found},critical=bool(cfg.get("critical",False))).to_dict()
                # Runtime state replaces DeviceConfig.integrations, so carry
                # the configured action target forward for the dispatcher.
                if configured_service is not None:integrations[name]["service"]=configured_service
            # Security-surface monitoring runs for every device unconditionally
            # (it is a baseline signal, not an opt-in role integration like the
            # ones above), reusing the same IntegrationStatus/"conditions"
            # contract so it surfaces on the device page and feeds the alert
            # engine exactly like every other integration already does.
            integrations["security"]=self._security_status(device,data,attempted,now,jlogs_due)
            config_drift_status=self._config_drift_status(device,data,services,attempted,now,drift_due,old)
            if config_drift_status is not None:integrations["config_drift"]=config_drift_status
            raw["integrations"]=integrations
            raw["logs"]=parse_jlogs(data.get("JLOGS","")) if jlogs_due else (list(old.logs) if old else [])
            health,reasons,stale=evaluate(raw,device.thresholds); raw.update(health=health,health_reasons=reasons,stale=stale)
            result=DeviceState.from_dict(raw); self.snapshots[device.id]=result; return result
        except (subprocess.TimeoutExpired, OSError, RuntimeError) as exc:
            return self._failure_result(device,old,attempted,exc)

    def _security_status(self, device: DeviceConfig, data: Dict[str, str], attempted: str, now: str,
                         jlogs_due: bool) -> Dict[str, Any]:
        """Auth-failure count + listening-port inventory for one device.

        Both signals are bounded (parse_auth_failures reads one bounded
        `grep -c` count; parse_listeners caps at MAX_LISTENERS) and each
        alert condition is gated so a single noisy poll can't spam an open:
        auth_fail uses the same open-band/close-band hysteresis
        history.HistoryManager._alerts() already uses for temperature/disk
        usage; listener_change requires the change to persist across polls
        (listener_change_duration_seconds) before it opens, the same
        duration-gate shape that file already uses for high_cpu.
        """
        did = device.id
        auth_failures = parse_auth_failures(data.get("AUTHFAIL", "")) if jlogs_due else None
        if auth_failures is None:
            # Not due this cycle -- surface the last real count rather than
            # flip to "unknown" on every poll that doesn't land on the
            # (multi-minute) log-tail cadence, mirroring the "packages"
            # integration's same not-due fallback above.
            auth_failures = self._last_auth_failures.get(did)
        else:
            self._last_auth_failures[did] = auth_failures
        listeners = parse_listeners(data.get("LISTENTCP", ""), data.get("LISTENUDP", ""))
        expected = set(device.expected_listeners)
        observed = {f"{entry['proto']}:{entry['port']}" for entry in listeners}
        unexpected = sorted(observed - expected) if expected else []
        missing = sorted(expected - observed) if expected else []
        changed = set(unexpected) | set(missing)
        since = self._listener_since.setdefault(did, {})
        for key in list(since):
            if key not in changed:
                del since[key]
        now_mono = time.monotonic()
        confirmed = []
        for key in changed:
            first_seen = since.setdefault(key, now_mono)
            if now_mono - first_seen >= self.listener_change_duration_seconds:
                confirmed.append(key)
        conditions: List[Dict[str, Any]] = []
        active_before = self._auth_fail_active.get(did, False)
        if auth_failures is not None:
            cutoff = (self.auth_fail_warning - self.auth_fail_hysteresis) if active_before else self.auth_fail_warning
            is_active = auth_failures >= max(1.0, cutoff)
            self._auth_fail_active[did] = is_active
            if is_active:
                severity = "critical" if auth_failures >= self.auth_fail_critical else "warning"
                conditions.append({"type": "auth_fail", "severity": severity,
                                   "message": f"{auth_failures} failed SSH login attempt(s) in the last ~30 minutes"})
        else:
            self._auth_fail_active[did] = active_before
        if confirmed:
            details = [f"unexpected listener {key}" if key in unexpected else f"expected listener missing: {key}"
                      for key in sorted(confirmed)]
            conditions.append({"type": "listener_change", "severity": "warning",
                               "message": "; ".join(details)[:400]})
        status = IntegrationStatus(
            name="security", enabled=True, available=True,
            health="critical" if any(c["severity"] == "critical" for c in conditions)
            else "warning" if conditions else "healthy",
            last_success=now, last_attempt=attempted, data_source="ssh",
            data={"auth_failures": auth_failures, "listeners": listeners,
                 "expected_listeners": sorted(expected), "unexpected_listeners": unexpected,
                 "missing_listeners": missing},
            critical=False)
        value = status.to_dict()
        value["conditions"] = conditions
        return value

    def _config_drift_status(self, device: DeviceConfig, data: Dict[str, str], services: List[Dict[str, Any]],
                             attempted: str, now: str, drift_due: bool,
                             old: Optional[DeviceState]) -> Optional[Dict[str, Any]]:
        """Configuration drift detection (enhancement #6) for one device:
        diff its ConfigDriftSpec against the actual state this same poll
        already gathered (unit enabled/masked state) or a bounded
        low-frequency check gathered this cycle (file hashes, sshd
        options). Returns None when the device has no expected-state spec
        configured at all -- no integration entry, no alert, matching how
        `expected_listeners` is treated elsewhere in this module.
        """
        spec = device.config_drift
        if spec.is_empty():
            return None
        unit_states = {s["name"]: s for s in services}
        drift_files = parse_drift_files(data.get("DRIFTFILES", "")) if drift_due and spec.expected_files else {}
        sshd_options = parse_sshd_options(data.get("SSHD", "")) if drift_due and spec.expected_sshd_options else {}
        old_status = (old.integrations or {}).get("config_drift") if old else None
        previous = ((old_status or {}).get("data") or {}).get("drift") if isinstance(old_status, dict) else None
        drift_items, snapshots = compute_config_drift(
            spec, unit_states, drift_files, sshd_options,
            files_due=drift_due and bool(spec.expected_files),
            sshd_due=drift_due and bool(spec.expected_sshd_options),
            previous=previous)
        diff_text = format_drift_diff(drift_items)
        status = IntegrationStatus(
            name="config_drift", enabled=True, available=True,
            health="warning" if drift_items else "healthy",
            last_success=now, last_attempt=attempted, data_source="ssh",
            data={"drift": drift_items, "diff": diff_text,
                 "good_snapshots": [
                     {"path": s["path"], "sha256": s["sha256"],
                      "content_b64": base64.b64encode(s["content"]).decode("ascii")}
                     for s in snapshots]},
            critical=False)
        value = status.to_dict()
        value["conditions"] = [{"type": "config_drift", "severity": "warning",
                               "message": diff_text[:1000]}] if drift_items else []
        return value

    def _failure_result(self, device: DeviceConfig, old: Optional[DeviceState], attempted: str, exc: BaseException) -> DeviceState:
        LOG.warning("[%s] collection failed: %s",device.id,exc)
        raw=old.to_dict() if old else {"id":device.id,"hostname":device.hostname,"friendly_name":device.friendly_name,
            "address":device.address,"roles":list(device.roles),"tags":list(device.tags),"collection_method":device.collection_method,
            "ssh_user":device.ssh_user,"ssh_port":device.ssh_port,"monitored_services":list(device.monitored_services),
            "critical_services":list(device.critical_services),"manageable_services":list(device.manageable_services),
            "allowed_actions":list(device.allowed_actions),
            "config_drift_expected":_config_drift_expected_dict(device),
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
