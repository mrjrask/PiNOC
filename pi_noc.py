#!/usr/bin/env python3
"""Desk NOC display for Adafruit or Pimoroni Raspberry Pi displays.

Controls:
  Joystick left/right/up/down: change page
  Joystick press: refresh immediately
  Button B: toggle automatic page rotation
  Hold Button A for 1.5 seconds: restart WireGuard

The VPN warning always overrides the normal pages when WireGuard has no recent
handshake.
"""

from __future__ import annotations

import base64
import binascii
import importlib
import json
import os
import re
import signal
import socket
import shlex
import hmac
import hashlib
import subprocess
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import board
from digitalio import DigitalInOut, Direction, Pull
from PIL import Image, ImageDraw, ImageFont


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

APP_DIR = Path(__file__).resolve().parent
CONFIG_FILE = APP_DIR / "config.json"
ENV_FILE = APP_DIR / ".env"

DEFAULT_CONFIG: Dict[str, Any] = {
    "vpn_interface": "wg0",
    "vpn_service": "wg-quick@wg0.service",
    "vpn_stale_seconds": 150,
    "refresh_seconds": 10,
    "auto_rotate_seconds": 8,
    "remote_host": "cm5",
    "remote_user": "pi",
    "remote_ssh_port": 22,
    "remote_paths": [
        {"name": "JONAH", "path": "/srv/jonah"},
        {"name": "TIME MACHINE", "path": "/mnt/timemachine"},
    ],
    "raid_device": "md0",
    "display_address": "0x3c",
    "remote_temp_monitor": {
        "enabled": True,
        "port": 9876,
        "max_device_age": 30,
        "shared_secret": "",
    },
}

DISPLAY_ADA_BONNET = "ADA_BONNET"
DISPLAY_PIM_DHM = "PIM_DHM"
DISPLAY_TYPES = (DISPLAY_ADA_BONNET, DISPLAY_PIM_DHM)

WIDTH = 128
HEIGHT = 64
PAGE_NAMES = ["SUMMARY", "VPN", "STORAGE", "SERVER", "SMB", "TEMPS", "LOCAL"]

FONT_PATHS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
]
BOLD_FONT_PATHS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class VPNStatus:
    service_active: bool = False
    interface_present: bool = False
    handshake_epoch: int = 0
    handshake_age: Optional[int] = None
    rx_bytes: int = 0
    tx_bytes: int = 0
    endpoint: str = ""
    tunnel_addresses: str = ""
    full_tunnel_v4: bool = False
    full_tunnel_v6: bool = False
    error: str = ""

    @property
    def connected(self) -> bool:
        return (
            self.service_active
            and self.interface_present
            and self.handshake_age is not None
            and self.handshake_age <= CONFIG["vpn_stale_seconds"]
        )


@dataclass
class DiskStatus:
    name: str
    path: str
    total: int = 0
    used: int = 0
    available: int = 0
    percent: int = 0
    error: str = ""


@dataclass
class RemoteStatus:
    online: bool = False
    error: str = ""
    temperature_c: Optional[float] = None
    load_1m: Optional[float] = None
    uptime_seconds: int = 0
    raid_status: str = "UNKNOWN"
    raid_detail: str = ""
    smb_sessions: Optional[int] = None
    smb_users: List[str] = field(default_factory=list)
    smb_error: str = ""
    disks: List[DiskStatus] = field(default_factory=list)


@dataclass
class TempDevice:
    device_id: str
    hostname: str
    celsius: float
    fahrenheit: float
    last_seen: float
    ip: str = ""


@dataclass
class LocalStatus:
    hostname: str = ""
    temperature_c: Optional[float] = None
    load_1m: Optional[float] = None
    uptime_seconds: int = 0
    memory_used: int = 0
    memory_total: int = 0
    wlan_ip: str = ""


@dataclass
class Snapshot:
    collected_at: float
    vpn: VPNStatus
    remote: RemoteStatus
    local: LocalStatus
    temp_devices: List[TempDevice] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Configuration and command helpers
# ---------------------------------------------------------------------------

def load_config() -> Dict[str, Any]:
    if not CONFIG_FILE.exists():
        CONFIG_FILE.write_text(json.dumps(DEFAULT_CONFIG, indent=2) + "\n")
        return dict(DEFAULT_CONFIG)

    try:
        user_config = json.loads(CONFIG_FILE.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to read {CONFIG_FILE}: {exc}") from exc

    config = dict(DEFAULT_CONFIG)
    config.update(user_config)
    return config


CONFIG = load_config()


def run_command(
    command: Sequence[str],
    *,
    timeout: float = 5.0,
    input_text: Optional[str] = None,
    env_extra: Optional[Dict[str, str]] = None,
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "LC_ALL": "C"}

    if env_extra:
        env.update(env_extra)

    try:
        return subprocess.run(
            list(command),
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            env=env,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return subprocess.CompletedProcess(
            args=list(command),
            returncode=124,
            stdout="",
            stderr=str(exc),
        )


def read_text(path: str) -> str:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return ""


def read_env_value(key: str) -> str:
    try:
        lines = ENV_FILE.read_text().splitlines()
    except OSError:
        return ""

    prefix = f"{key}="

    for line in lines:
        line = line.rstrip("\r")

        if line.startswith(prefix):
            return line[len(prefix):]

    return ""


def load_display_type() -> str:
    display_type = read_env_value("DISPLAY") or DISPLAY_ADA_BONNET

    if display_type not in DISPLAY_TYPES:
        raise RuntimeError(
            f"DISPLAY must be one of {', '.join(DISPLAY_TYPES)}; "
            f"got {display_type!r}"
        )

    return display_type


DISPLAY_TYPE = load_display_type()


# ---------------------------------------------------------------------------
# Status collection
# ---------------------------------------------------------------------------

def collect_vpn_status() -> VPNStatus:
    interface = str(CONFIG["vpn_interface"])
    service = str(CONFIG["vpn_service"])
    status = VPNStatus()

    service_result = run_command(
        ["/usr/bin/systemctl", "is-active", service],
        timeout=2,
    )
    status.service_active = (
        service_result.returncode == 0
        and service_result.stdout.strip() == "active"
    )

    link_result = run_command(
        ["/usr/sbin/ip", "link", "show", "dev", interface],
        timeout=2,
    )
    if link_result.returncode != 0:
        link_result = run_command(
            ["/usr/bin/ip", "link", "show", "dev", interface],
            timeout=2,
        )
    status.interface_present = link_result.returncode == 0

    if status.interface_present:
        address_result = run_command(
            [
                "/usr/sbin/ip",
                "-brief",
                "address",
                "show",
                "dev",
                interface,
            ],
            timeout=2,
        )
        if address_result.returncode != 0:
            address_result = run_command(
                [
                    "/usr/bin/ip",
                    "-brief",
                    "address",
                    "show",
                    "dev",
                    interface,
                ],
                timeout=2,
            )

        if address_result.returncode == 0:
            fields = address_result.stdout.split()
            status.tunnel_addresses = (
                " ".join(fields[2:]) if len(fields) >= 3 else ""
            )

    wg_commands = [
        [
            "/usr/bin/sudo",
            "-n",
            "/usr/bin/wg",
            "show",
            interface,
            "dump",
        ],
        [
            "/usr/bin/wg",
            "show",
            interface,
            "dump",
        ],
    ]

    wg_result: Optional[subprocess.CompletedProcess[str]] = None

    for command in wg_commands:
        candidate = run_command(command, timeout=3)
        if candidate.returncode == 0:
            wg_result = candidate
            break

    if wg_result is None:
        status.error = "WireGuard status unavailable"
        return status

    now = int(time.time())
    peer_lines = wg_result.stdout.strip().splitlines()[1:]
    latest = 0
    allowed_ips: List[str] = []

    for line in peer_lines:
        fields = line.split("\t")

        if len(fields) < 8:
            continue

        if not status.endpoint:
            status.endpoint = fields[2]

        allowed_ips.extend(
            part.strip()
            for part in fields[3].split(",")
        )

        try:
            peer_handshake = int(fields[4])
            status.rx_bytes += int(fields[5])
            status.tx_bytes += int(fields[6])
            latest = max(latest, peer_handshake)
        except ValueError:
            continue

    status.handshake_epoch = latest
    status.handshake_age = (
        max(0, now - latest)
        if latest > 0
        else None
    )
    status.full_tunnel_v4 = "0.0.0.0/0" in allowed_ips
    status.full_tunnel_v6 = "::/0" in allowed_ips

    return status


def build_remote_script() -> str:
    disk_commands: List[str] = []

    for index, item in enumerate(CONFIG["remote_paths"]):
        name = shlex.quote(str(item["name"]))
        path = shlex.quote(str(item["path"]))

        disk_commands.append(
            f"disk_status D{index} {name} {path}"
        )

    return """#!/bin/sh
set -u

printf 'REMOTE_OK=1\\n'
printf 'TEMP_MILLI=%s\\n' "$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || printf '')"
printf 'LOAD_1M=%s\\n' "$(awk '{print $1}' /proc/loadavg 2>/dev/null || printf '')"
printf 'UPTIME_SECONDS=%s\\n' "$(awk '{printf "%.0f", $1}' /proc/uptime 2>/dev/null || printf '0')"

disk_status() {
    key="$1"
    label="$2"
    path="$3"

    if values=$(df -P -B1 "$path" 2>/dev/null | awk 'NR==2 {gsub(/%/,"",$5); print $2"|"$3"|"$4"|"$5}'); then
        if [ -n "$values" ]; then
            printf 'DISK_%s=%s|%s|%s\\n' "$key" "$label" "$path" "$values"
        else
            printf 'DISK_%s=%s|%s|ERROR\\n' "$key" "$label" "$path"
        fi
    else
        printf 'DISK_%s=%s|%s|ERROR\\n' "$key" "$label" "$path"
    fi
}

""" + "\n".join(disk_commands) + """

if [ -r /proc/mdstat ]; then
    printf 'MDSTAT_B64=%s\\n' "$(base64 -w0 /proc/mdstat 2>/dev/null || base64 /proc/mdstat 2>/dev/null | tr -d '\\n')"
else
    printf 'MDSTAT_B64=\\n'
fi

SMB_BIN=$(command -v smbstatus 2>/dev/null || true)

if [ -n "$SMB_BIN" ]; then
    SMB_RAW=$(sudo -n "$SMB_BIN" -b 2>/dev/null || "$SMB_BIN" -b 2>/dev/null || true)
    SMB_COUNT=$(printf '%s\\n' "$SMB_RAW" | awk '$1 ~ /^[0-9]+$/ {count++} END {print count+0}')
    SMB_USERS=$(printf '%s\\n' "$SMB_RAW" | awk '$1 ~ /^[0-9]+$/ {print $2}' | sort -u | paste -sd, -)

    printf 'SMB_SESSIONS=%s\\n' "$SMB_COUNT"
    printf 'SMB_USERS=%s\\n' "$SMB_USERS"
else
    printf 'SMB_ERROR=smbstatus not installed\\n'
fi
"""


def parse_raid(
    mdstat: str,
    raid_device: str,
) -> Tuple[str, str]:
    lines = mdstat.splitlines()
    block: List[str] = []
    collecting = False

    for line in lines:
        if re.match(
            rf"^{re.escape(raid_device)}\s*:",
            line,
        ):
            collecting = True
            block.append(line)
            continue

        if collecting:
            if (
                re.match(r"^md\d+\s*:", line)
                or not line.strip()
            ):
                break

            block.append(line)

    if not block:
        return (
            "MISSING",
            f"/dev/{raid_device} not in mdstat",
        )

    text = " ".join(
        part.strip()
        for part in block
    )

    if " inactive " in f" {text.lower()} ":
        return "INACTIVE", "Array is inactive"

    operation_match = re.search(
        r"(recovery|resync|reshape|check)\s*=\s*([0-9.]+%)",
        text,
        re.IGNORECASE,
    )

    if operation_match:
        operation = operation_match.group(1).upper()
        percent = operation_match.group(2)
        return operation, percent

    health_matches = re.findall(
        r"\[([U_]+)\]",
        text,
    )

    if health_matches:
        health = health_matches[-1]

        if "_" in health:
            return "DEGRADED", health

        return "CLEAN", health

    return "ACTIVE", "No member-health marker"


def collect_remote_status(
    vpn_connected: bool,
) -> RemoteStatus:
    result_status = RemoteStatus(
        disks=[
            DiskStatus(
                name=str(item["name"]),
                path=str(item["path"]),
            )
            for item in CONFIG["remote_paths"]
        ]
    )

    if not vpn_connected:
        result_status.error = "VPN offline"
        return result_status

    host = str(CONFIG["remote_host"])
    user = str(CONFIG["remote_user"])
    port = str(CONFIG["remote_ssh_port"])
    target = f"{user}@{host}"

    ssh_options = [
        "-T",
        "-p",
        port,
        "-o",
        "ConnectTimeout=4",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "ServerAliveInterval=3",
        "-o",
        "ServerAliveCountMax=1",
        "-o",
        "StrictHostKeyChecking=accept-new",
    ]
    env_extra: Optional[Dict[str, str]] = None
    cm5_password = read_env_value("CM5_SSH_PASS")

    if cm5_password:
        ssh_command = [
            "/usr/bin/sshpass",
            "-e",
            "/usr/bin/ssh",
            *ssh_options,
            target,
            "sh -s",
        ]
        env_extra = {"SSHPASS": cm5_password}
    else:
        ssh_command = [
            "/usr/bin/ssh",
            *ssh_options,
            "-o",
            "BatchMode=yes",
            target,
            "sh -s",
        ]

    result = run_command(
        ssh_command,
        timeout=8,
        input_text=build_remote_script(),
        env_extra=env_extra,
    )

    if result.returncode != 0:
        result_status.error = (
            result.stderr.strip()
            or "SSH connection failed"
        )[:100]

        return result_status

    values: Dict[str, str] = {}

    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()

    result_status.online = (
        values.get("REMOTE_OK") == "1"
    )

    try:
        milli = int(values.get("TEMP_MILLI", ""))
        result_status.temperature_c = milli / 1000.0
    except ValueError:
        pass

    try:
        result_status.load_1m = float(
            values.get("LOAD_1M", "")
        )
    except ValueError:
        pass

    try:
        result_status.uptime_seconds = int(
            values.get("UPTIME_SECONDS", "0")
        )
    except ValueError:
        pass

    mdstat_b64 = values.get("MDSTAT_B64", "")

    if mdstat_b64:
        try:
            mdstat = base64.b64decode(
                mdstat_b64
            ).decode(
                "utf-8",
                errors="replace",
            )

            (
                result_status.raid_status,
                result_status.raid_detail,
            ) = parse_raid(
                mdstat,
                str(CONFIG["raid_device"]),
            )
        except (ValueError, binascii.Error):
            result_status.raid_status = "UNKNOWN"
            result_status.raid_detail = (
                "Unable to decode mdstat"
            )

    parsed_disks: List[DiskStatus] = []

    for index, item in enumerate(
        CONFIG["remote_paths"]
    ):
        disk = DiskStatus(
            name=str(item["name"]),
            path=str(item["path"]),
        )

        raw = values.get(
            f"DISK_D{index}",
            "",
        )
        parts = raw.split("|")

        if (
            len(parts) == 6
            and parts[2] != "ERROR"
        ):
            disk.name = parts[0]
            disk.path = parts[1]

            try:
                disk.total = int(parts[2])
                disk.used = int(parts[3])
                disk.available = int(parts[4])
                disk.percent = int(parts[5])
            except ValueError:
                disk.error = "Invalid disk data"
        else:
            disk.error = "Path unavailable"

        parsed_disks.append(disk)

    result_status.disks = parsed_disks

    if "SMB_SESSIONS" in values:
        try:
            result_status.smb_sessions = int(
                values["SMB_SESSIONS"]
            )
        except ValueError:
            result_status.smb_error = (
                "Invalid session count"
            )

        result_status.smb_users = [
            user_name
            for user_name in values.get(
                "SMB_USERS",
                "",
            ).split(",")
            if user_name
        ]
    else:
        result_status.smb_error = values.get(
            "SMB_ERROR",
            "smbstatus unavailable",
        )

    return result_status


def parse_temp_monitor_packet(
    packet: bytes,
    ip_address: str,
) -> Optional[TempDevice]:
    try:
        raw_message = packet.decode("utf-8")
        data = json.loads(raw_message)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None

    if not isinstance(data, dict):
        return None

    if (
        data.get("type") != "temperature"
        or not data.get("hostname")
        or not isinstance(data.get("temperature"), dict)
    ):
        return None

    secret = str(
        CONFIG.get("remote_temp_monitor", {}).get(
            "shared_secret",
            "",
        )
    )

    if secret:
        signature = str(data.get("hmac", ""))
        unsigned = dict(data)
        unsigned.pop("hmac", None)
        expected = hmac.new(
            secret.encode("utf-8"),
            json.dumps(
                unsigned,
                separators=(",", ":"),
            ).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(signature, expected):
            return None

    try:
        celsius = float(data["temperature"]["celsius"])
        fahrenheit = float(data["temperature"].get(
            "fahrenheit",
            celsius * 9 / 5 + 32,
        ))
    except (TypeError, ValueError, KeyError):
        return None

    if celsius < -50 or celsius > 150:
        return None

    hostname = str(data["hostname"])
    device_id = str(
        data.get("device_id")
        or f"{ip_address}:{hostname}"
    )

    return TempDevice(
        device_id=device_id,
        hostname=hostname,
        celsius=celsius,
        fahrenheit=fahrenheit,
        last_seen=time.time(),
        ip=ip_address,
    )


def collect_local_status() -> LocalStatus:
    status = LocalStatus(
        hostname=socket.gethostname()
    )

    temp_text = read_text(
        "/sys/class/thermal/thermal_zone0/temp"
    )

    try:
        status.temperature_c = (
            int(temp_text) / 1000.0
        )
    except ValueError:
        pass

    load_text = read_text("/proc/loadavg")

    try:
        status.load_1m = float(
            load_text.split()[0]
        )
    except (ValueError, IndexError):
        pass

    uptime_text = read_text("/proc/uptime")

    try:
        status.uptime_seconds = int(
            float(uptime_text.split()[0])
        )
    except (ValueError, IndexError):
        pass

    meminfo: Dict[str, int] = {}

    for line in read_text(
        "/proc/meminfo"
    ).splitlines():
        if ":" not in line:
            continue

        key, value = line.split(":", 1)

        try:
            meminfo[key] = (
                int(value.strip().split()[0])
                * 1024
            )
        except (ValueError, IndexError):
            continue

    status.memory_total = meminfo.get(
        "MemTotal",
        0,
    )
    status.memory_used = max(
        0,
        status.memory_total
        - meminfo.get(
            "MemAvailable",
            status.memory_total,
        ),
    )

    for ip_binary in (
        "/usr/sbin/ip",
        "/usr/bin/ip",
    ):
        ip_result = run_command(
            [
                ip_binary,
                "-4",
                "-brief",
                "address",
                "show",
                "dev",
                "wlan0",
            ],
            timeout=2,
        )

        if ip_result.returncode == 0:
            fields = ip_result.stdout.split()

            if len(fields) >= 3:
                status.wlan_ip = (
                    fields[2].split("/")[0]
                )

            break

    return status


def collect_snapshot() -> Snapshot:
    vpn = collect_vpn_status()
    local = collect_local_status()
    remote = collect_remote_status(
        vpn.connected
    )

    return Snapshot(
        collected_at=time.time(),
        vpn=vpn,
        remote=remote,
        local=local,
        temp_devices=[],
    )


# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------

def load_font(
    paths: Sequence[str],
    size: int,
) -> ImageFont.ImageFont:
    for path in paths:
        if Path(path).exists():
            return ImageFont.truetype(
                path,
                size,
            )

    return ImageFont.load_default()


FONT_SMALL = load_font(FONT_PATHS, 9)
FONT_NORMAL = load_font(FONT_PATHS, 10)
FONT_BOLD = load_font(BOLD_FONT_PATHS, 10)
FONT_ALERT = load_font(BOLD_FONT_PATHS, 13)


def text_width(
    draw: ImageDraw.ImageDraw,
    text: str,
    font: ImageFont.ImageFont,
) -> int:
    bbox = draw.textbbox(
        (0, 0),
        text,
        font=font,
    )

    return bbox[2] - bbox[0]


def fit_text(
    draw: ImageDraw.ImageDraw,
    text: str,
    max_width: int,
    font: ImageFont.ImageFont = FONT_NORMAL,
) -> str:
    if text_width(draw, text, font) <= max_width:
        return text

    shortened = text

    while (
        shortened
        and text_width(
            draw,
            shortened + "…",
            font,
        ) > max_width
    ):
        shortened = shortened[:-1]

    return shortened + "…" if shortened else ""


def draw_header(
    draw: ImageDraw.ImageDraw,
    title: str,
    page_index: int,
    status_ok: Optional[bool] = None,
) -> None:
    draw.text(
        (1, 0),
        title,
        font=FONT_BOLD,
        fill=255,
    )

    page_text = (
        f"{page_index + 1}/{len(PAGE_NAMES)}"
    )
    page_x = (
        WIDTH
        - text_width(
            draw,
            page_text,
            FONT_SMALL,
        )
        - 1
    )

    draw.text(
        (page_x, 1),
        page_text,
        font=FONT_SMALL,
        fill=255,
    )

    if status_ok is not None:
        circle_x = page_x - 8

        draw.ellipse(
            (
                circle_x,
                3,
                circle_x + 4,
                7,
            ),
            outline=255,
            fill=255 if status_ok else 0,
        )

    draw.line(
        (0, 12, WIDTH - 1, 12),
        fill=255,
    )


def draw_two_column_line(
    draw: ImageDraw.ImageDraw,
    y: int,
    left: str,
    right: str = "",
    *,
    font: ImageFont.ImageFont = FONT_NORMAL,
) -> None:
    right_width = (
        text_width(draw, right, font)
        if right
        else 0
    )

    left_width = (
        WIDTH
        - right_width
        - (5 if right else 2)
    )

    draw.text(
        (1, y),
        fit_text(
            draw,
            left,
            left_width,
            font,
        ),
        font=font,
        fill=255,
    )

    if right:
        draw.text(
            (
                WIDTH
                - right_width
                - 1,
                y,
            ),
            right,
            font=font,
            fill=255,
        )


def format_bytes(value: int) -> str:
    units = ["B", "K", "M", "G", "T", "P"]
    number = float(max(0, value))

    for unit in units:
        if (
            number < 1024.0
            or unit == units[-1]
        ):
            if unit in ("B", "K", "M"):
                return f"{number:.0f}{unit}"

            return f"{number:.1f}{unit}"

        number /= 1024.0

    return f"{number:.1f}P"


def format_duration(
    seconds: Optional[int],
    compact: bool = True,
) -> str:
    if seconds is None:
        return "NEVER"

    seconds = max(0, int(seconds))
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(
        remainder,
        3600,
    )
    minutes, secs = divmod(
        remainder,
        60,
    )

    if days:
        return f"{days}d {hours}h"

    if hours:
        return f"{hours}h {minutes}m"

    if minutes:
        if compact:
            return f"{minutes}m"

        return f"{minutes}m {secs}s"

    return f"{secs}s"


def draw_summary(
    draw: ImageDraw.ImageDraw,
    snapshot: Snapshot,
    page: int,
) -> None:
    draw_header(
        draw,
        "DESK NOC",
        page,
        snapshot.vpn.connected,
    )

    vpn_text = (
        "OK"
        if snapshot.vpn.connected
        else "DOWN"
    )

    draw_two_column_line(
        draw,
        15,
        "VPN",
        (
            f"{vpn_text} "
            f"{format_duration(snapshot.vpn.handshake_age)}"
        ),
    )

    remote_text = (
        "ONLINE"
        if snapshot.remote.online
        else "OFFLINE"
    )

    temp_text = (
        f" {snapshot.remote.temperature_c:.0f}C"
        if snapshot.remote.temperature_c
        is not None
        else ""
    )

    draw_two_column_line(
        draw,
        27,
        "CM5",
        remote_text + temp_text,
    )

    raid = (
        snapshot.remote.raid_status
        if snapshot.remote.online
        else "UNKNOWN"
    )

    draw_two_column_line(
        draw,
        39,
        "RAID",
        raid,
    )

    if snapshot.remote.smb_sessions is None:
        smb_right = "N/A"
    else:
        smb_right = str(
            snapshot.remote.smb_sessions
        )

    draw_two_column_line(
        draw,
        51,
        "SMB sessions",
        smb_right,
    )


def draw_vpn(
    draw: ImageDraw.ImageDraw,
    snapshot: Snapshot,
    page: int,
) -> None:
    vpn = snapshot.vpn

    draw_header(
        draw,
        "WIREGUARD",
        page,
        vpn.connected,
    )

    draw_two_column_line(
        draw,
        15,
        "Service",
        (
            "ACTIVE"
            if vpn.service_active
            else "DOWN"
        ),
    )

    draw_two_column_line(
        draw,
        27,
        "Handshake",
        format_duration(
            vpn.handshake_age,
            compact=False,
        ),
    )

    draw_two_column_line(
        draw,
        39,
        "RX / TX",
        (
            f"{format_bytes(vpn.rx_bytes)} / "
            f"{format_bytes(vpn.tx_bytes)}"
        ),
    )

    if (
        vpn.full_tunnel_v4
        and vpn.full_tunnel_v6
    ):
        tunnel = "IPv4+IPv6"
    elif vpn.full_tunnel_v4:
        tunnel = "IPv4"
    else:
        tunnel = "NO"

    draw_two_column_line(
        draw,
        51,
        "Full tunnel",
        tunnel,
    )


def draw_storage(
    draw: ImageDraw.ImageDraw,
    snapshot: Snapshot,
    page: int,
) -> None:
    draw_header(
        draw,
        "STORAGE",
        page,
        snapshot.remote.online,
    )

    y_values = [15, 27, 39, 51]
    line_index = 0

    for disk in snapshot.remote.disks[:2]:
        if disk.error:
            draw_two_column_line(
                draw,
                y_values[line_index],
                disk.name,
                "ERROR",
            )
            line_index += 1

            draw_two_column_line(
                draw,
                y_values[line_index],
                disk.path,
                "",
            )
            line_index += 1
            continue

        draw_two_column_line(
            draw,
            y_values[line_index],
            disk.name,
            f"{disk.percent}% used",
        )
        line_index += 1

        draw_two_column_line(
            draw,
            y_values[line_index],
            f"Free {format_bytes(disk.available)}",
            f"Total {format_bytes(disk.total)}",
            font=FONT_SMALL,
        )
        line_index += 1

    while line_index < len(y_values):
        draw_two_column_line(
            draw,
            y_values[line_index],
            "No disk data",
            "",
        )
        line_index += 1


def draw_server(
    draw: ImageDraw.ImageDraw,
    snapshot: Snapshot,
    page: int,
) -> None:
    remote = snapshot.remote

    draw_header(
        draw,
        "CM5 SERVER",
        page,
        remote.online,
    )

    draw_two_column_line(
        draw,
        15,
        "Status",
        (
            "ONLINE"
            if remote.online
            else "OFFLINE"
        ),
    )

    temp = (
        f"{remote.temperature_c:.1f}C"
        if remote.temperature_c is not None
        else "N/A"
    )

    draw_two_column_line(
        draw,
        27,
        "Temperature",
        temp,
    )

    load = (
        f"{remote.load_1m:.2f}"
        if remote.load_1m is not None
        else "N/A"
    )

    draw_two_column_line(
        draw,
        39,
        "Load 1m",
        load,
    )

    draw_two_column_line(
        draw,
        51,
        "Uptime",
        format_duration(
            remote.uptime_seconds
        ),
    )


def draw_smb(
    draw: ImageDraw.ImageDraw,
    snapshot: Snapshot,
    page: int,
) -> None:
    remote = snapshot.remote

    draw_header(
        draw,
        "SAMBA",
        page,
        (
            remote.online
            and remote.smb_sessions is not None
        ),
    )

    sessions = (
        "N/A"
        if remote.smb_sessions is None
        else str(remote.smb_sessions)
    )

    draw_two_column_line(
        draw,
        15,
        "Sessions",
        sessions,
    )

    users = (
        ", ".join(remote.smb_users)
        if remote.smb_users
        else "None"
    )

    draw_two_column_line(
        draw,
        27,
        "Users",
        users,
    )

    draw_two_column_line(
        draw,
        39,
        "Share host",
        str(CONFIG["remote_host"]),
    )

    detail = (
        remote.smb_error
        if remote.smb_error
        else "Live smbstatus"
    )

    draw_two_column_line(
        draw,
        51,
        detail,
        "",
        font=FONT_SMALL,
    )


def draw_remote_temps(
    draw: ImageDraw.ImageDraw,
    snapshot: Snapshot,
    page: int,
) -> None:
    devices = sorted(
        snapshot.temp_devices,
        key=lambda device: device.celsius,
        reverse=True,
    )

    draw_header(
        draw,
        "REMOTE TEMPS",
        page,
        bool(devices),
    )

    if not devices:
        draw_two_column_line(
            draw,
            15,
            "No monitors found",
            "",
        )
        draw_two_column_line(
            draw,
            27,
            "Listening UDP",
            str(CONFIG["remote_temp_monitor"].get("port", 9876)),
        )
        return

    y_values = [15, 27, 39, 51]

    for y, device in zip(y_values, devices[:4]):
        age = format_duration(
            int(time.time() - device.last_seen)
        )
        draw_two_column_line(
            draw,
            y,
            device.hostname,
            f"{device.celsius:.1f}C {age}",
        )


def draw_local(
    draw: ImageDraw.ImageDraw,
    snapshot: Snapshot,
    page: int,
) -> None:
    local = snapshot.local

    draw_header(
        draw,
        "DESK PI",
        page,
        True,
    )

    draw_two_column_line(
        draw,
        15,
        local.hostname,
        local.wlan_ip or "No Wi-Fi IP",
    )

    temp = (
        f"{local.temperature_c:.1f}C"
        if local.temperature_c is not None
        else "N/A"
    )

    load = (
        f"{local.load_1m:.2f}"
        if local.load_1m is not None
        else "N/A"
    )

    draw_two_column_line(
        draw,
        27,
        "Temp / Load",
        f"{temp} / {load}",
    )

    if local.memory_total:
        mem_percent = int(
            100
            * local.memory_used
            / local.memory_total
        )
    else:
        mem_percent = 0

    draw_two_column_line(
        draw,
        39,
        "Memory",
        (
            f"{mem_percent}% "
            f"{format_bytes(local.memory_used)}"
        ),
    )

    draw_two_column_line(
        draw,
        51,
        "Uptime",
        format_duration(
            local.uptime_seconds
        ),
    )


PAGE_DRAWERS = [
    draw_summary,
    draw_vpn,
    draw_storage,
    draw_server,
    draw_smb,
    draw_remote_temps,
    draw_local,
]


def draw_vpn_warning(
    draw: ImageDraw.ImageDraw,
    snapshot: Snapshot,
    flash_on: bool,
    restart_message: str,
) -> None:
    fill = 255 if flash_on else 0
    text_fill = 0 if flash_on else 255

    draw.rectangle(
        (0, 0, WIDTH - 1, HEIGHT - 1),
        outline=255,
        fill=fill,
    )

    draw.rectangle(
        (2, 2, WIDTH - 3, HEIGHT - 3),
        outline=text_fill,
        fill=fill,
    )

    title = "VPN DISCONNECTED"
    title_x = max(
        1,
        (
            WIDTH
            - text_width(
                draw,
                title,
                FONT_ALERT,
            )
        )
        // 2,
    )

    draw.text(
        (title_x, 6),
        title,
        font=FONT_ALERT,
        fill=text_fill,
    )

    if restart_message:
        detail = restart_message
    elif not snapshot.vpn.service_active:
        detail = "WireGuard service down"
    elif snapshot.vpn.handshake_age is None:
        detail = "No VPN handshake"
    else:
        detail = (
            "Handshake age "
            + format_duration(
                snapshot.vpn.handshake_age,
                False,
            )
        )

    detail_x = max(
        1,
        (
            WIDTH
            - text_width(
                draw,
                detail,
                FONT_SMALL,
            )
        )
        // 2,
    )

    draw.text(
        (detail_x, 30),
        detail,
        font=FONT_SMALL,
        fill=text_fill,
    )

    action = "Hold A: reconnect"
    action_x = max(
        1,
        (
            WIDTH
            - text_width(
                draw,
                action,
                FONT_SMALL,
            )
        )
        // 2,
    )

    draw.text(
        (action_x, 47),
        action,
        font=FONT_SMALL,
        fill=text_fill,
    )


# ---------------------------------------------------------------------------
# Display and input handling
# ---------------------------------------------------------------------------

class DisplayDevice:
    def image(self, image: Image.Image) -> None:
        raise NotImplementedError

    def fill(self, value: int) -> None:
        raise NotImplementedError

    def show(self) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass


class AdafruitOLEDDisplay(DisplayDevice):
    def __init__(self) -> None:
        busio_module = importlib.import_module("busio")
        ssd1306_module = importlib.import_module("adafruit_ssd1306")
        i2c = busio_module.I2C(
            board.SCL,
            board.SDA,
        )
        address = int(
            str(CONFIG["display_address"]),
            0,
        )
        self.display = ssd1306_module.SSD1306_I2C(
            WIDTH,
            HEIGHT,
            i2c,
            addr=address,
        )

    def image(self, image: Image.Image) -> None:
        self.display.image(image.rotate(180))

    def fill(self, value: int) -> None:
        self.display.fill(value)

    def show(self) -> None:
        self.display.show()


class PimoroniDisplayHATMiniDisplay(DisplayDevice):
    LCD_WIDTH = 320
    LCD_HEIGHT = 240

    def __init__(self) -> None:
        displayhatmini_module = importlib.import_module("displayhatmini")
        self.buffer = Image.new(
            "RGB",
            (self.LCD_WIDTH, self.LCD_HEIGHT),
        )
        self.display = displayhatmini_module.DisplayHATMini(self.buffer)
        self.display.set_backlight(1.0)
        self.display.set_led(0.0, 0.0, 0.0)

    def image(self, image: Image.Image) -> None:
        scaled = image.rotate(180).convert("RGB").resize(
            (self.LCD_WIDTH, 160),
            Image.Resampling.NEAREST,
        )
        self.buffer.paste(
            Image.new("RGB", self.buffer.size),
            (0, 0),
        )
        self.buffer.paste(scaled, (0, 40))

    def fill(self, value: int) -> None:
        fill = 255 if value else 0
        self.buffer.paste(
            Image.new("RGB", self.buffer.size, (fill, fill, fill)),
            (0, 0),
        )

    def show(self) -> None:
        self.display.display()

    def close(self) -> None:
        self.display.set_led(0.0, 0.0, 0.0)


def create_display() -> DisplayDevice:
    if DISPLAY_TYPE == DISPLAY_PIM_DHM:
        return PimoroniDisplayHATMiniDisplay()

    return AdafruitOLEDDisplay()


class Buttons:
    ADAFRUIT_PIN_MAP = {
        "A": board.D5,
        "B": board.D6,
        "LEFT": board.D27,
        "RIGHT": board.D23,
        "UP": board.D17,
        "DOWN": board.D22,
        "CENTER": board.D4,
    }
    PIMORONI_PIN_MAP = {
        "A": board.D5,
        "B": board.D6,
        "CENTER": board.D16,
        "RIGHT": board.D24,
    }

    def __init__(self) -> None:
        self.devices: Dict[
            str,
            DigitalInOut,
        ] = {}
        self.previous: Dict[str, bool] = {}
        self.press_started: Dict[
            str,
            float,
        ] = {}
        self.hold_fired: Dict[
            str,
            bool,
        ] = {}

        pin_map = (
            self.PIMORONI_PIN_MAP
            if DISPLAY_TYPE == DISPLAY_PIM_DHM
            else self.ADAFRUIT_PIN_MAP
        )

        for name, pin in pin_map.items():
            device = DigitalInOut(pin)
            device.direction = Direction.INPUT
            device.pull = Pull.UP

            self.devices[name] = device
            self.previous[name] = False
            self.press_started[name] = 0.0
            self.hold_fired[name] = False

    def poll(
        self,
    ) -> Tuple[List[str], List[str]]:
        now = time.monotonic()
        pressed_events: List[str] = []
        hold_events: List[str] = []

        for name, device in self.devices.items():
            pressed = not device.value
            was_pressed = self.previous[name]

            if pressed and not was_pressed:
                self.press_started[name] = now
                self.hold_fired[name] = False
                pressed_events.append(name)

            if (
                pressed
                and name == "A"
                and not self.hold_fired[name]
            ):
                if (
                    now
                    - self.press_started[name]
                    >= 1.5
                ):
                    self.hold_fired[name] = True
                    hold_events.append(name)

            self.previous[name] = pressed

        return pressed_events, hold_events

    def close(self) -> None:
        for device in self.devices.values():
            device.deinit()


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

class DeskNOC:
    def __init__(self) -> None:
        self.stop_event = threading.Event()

        self.executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="status",
        )

        self.refresh_future: Optional[
            Future[Snapshot]
        ] = None

        self.snapshot = Snapshot(
            collected_at=0,
            vpn=VPNStatus(error="Starting"),
            remote=RemoteStatus(
                error="Starting"
            ),
            local=collect_local_status(),
            temp_devices=[],
        )

        self.page = 0
        self.auto_rotate = True
        self.last_page_change = (
            time.monotonic()
        )
        self.last_refresh_started = 0.0
        self.restart_message = ""
        self.restart_message_until = 0.0

        self.display = create_display()

        self.image = Image.new(
            "1",
            (WIDTH, HEIGHT),
        )
        self.draw = ImageDraw.Draw(
            self.image
        )
        self.buttons = Buttons()

        self.display.fill(0)
        self.display.show()

        self.temp_socket: Optional[socket.socket] = None
        self.temp_devices: Dict[str, TempDevice] = {}
        self.setup_temp_monitor_socket()

        self.start_refresh(force=True)

    def setup_temp_monitor_socket(self) -> None:
        temp_config = CONFIG.get("remote_temp_monitor", {})

        if not temp_config.get("enabled", True):
            return

        try:
            port = int(temp_config.get("port", 9876))
            self.temp_socket = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM,
            )
            self.temp_socket.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_REUSEADDR,
                1,
            )
            self.temp_socket.bind(("", port))
            self.temp_socket.setblocking(False)
        except OSError as exc:
            self.temp_socket = None
            self.restart_message = f"Temp UDP failed: {exc}"[:40]
            self.restart_message_until = time.monotonic() + 5

    def poll_temp_monitor(self) -> None:
        if self.temp_socket is None:
            return

        while True:
            try:
                packet, address = self.temp_socket.recvfrom(4096)
            except BlockingIOError:
                break
            except OSError:
                return

            device = parse_temp_monitor_packet(
                packet,
                address[0],
            )

            if device is not None:
                self.temp_devices[device.device_id] = device

        max_age = float(
            CONFIG.get("remote_temp_monitor", {}).get(
                "max_device_age",
                30,
            )
        )
        now = time.time()
        self.temp_devices = {
            device_id: device
            for device_id, device in self.temp_devices.items()
            if now - device.last_seen <= max_age
        }
        self.snapshot.temp_devices = list(
            self.temp_devices.values()
        )

    def start_refresh(
        self,
        force: bool = False,
    ) -> None:
        if (
            self.refresh_future is not None
            and not self.refresh_future.done()
        ):
            return

        now = time.monotonic()

        if (
            not force
            and (
                now
                - self.last_refresh_started
                < float(CONFIG["refresh_seconds"])
            )
        ):
            return

        self.last_refresh_started = now
        self.refresh_future = (
            self.executor.submit(
                collect_snapshot
            )
        )

    def accept_refresh(self) -> None:
        if (
            self.refresh_future is None
            or not self.refresh_future.done()
        ):
            return

        try:
            self.snapshot = (
                self.refresh_future.result()
            )
        except Exception as exc:
            self.snapshot.remote.error = (
                str(exc)[:100]
            )
        finally:
            self.refresh_future = None

    def change_page(
        self,
        delta: int,
    ) -> None:
        self.page = (
            self.page + delta
        ) % len(PAGE_NAMES)

        self.last_page_change = (
            time.monotonic()
        )

    def restart_vpn(self) -> None:
        service = str(
            CONFIG["vpn_service"]
        )

        self.restart_message = (
            "Restarting WireGuard"
        )
        self.restart_message_until = (
            time.monotonic() + 8
        )

        command = [
            "/usr/bin/sudo",
            "-n",
            "/usr/bin/systemctl",
            "restart",
            service,
        ]

        result = run_command(
            command,
            timeout=15,
        )

        if result.returncode == 0:
            self.restart_message = (
                "Restart requested"
            )
        else:
            self.restart_message = (
                "Restart permission failed"
            )

        self.restart_message_until = (
            time.monotonic() + 5
        )
        self.last_refresh_started = 0
        self.start_refresh(force=True)

    def handle_buttons(self) -> None:
        pressed, held = self.buttons.poll()

        for name in pressed:
            if name in ("LEFT", "UP"):
                self.change_page(-1)

            elif name in ("RIGHT", "DOWN"):
                self.change_page(1)

            elif name == "CENTER":
                self.last_refresh_started = 0
                self.start_refresh(force=True)

            elif name == "B":
                self.auto_rotate = (
                    not self.auto_rotate
                )

                if self.auto_rotate:
                    self.restart_message = (
                        "Auto rotate ON"
                    )
                else:
                    self.restart_message = (
                        "Auto rotate OFF"
                    )

                self.restart_message_until = (
                    time.monotonic() + 2
                )

        if "A" in held:
            self.restart_vpn()

    def render(self) -> None:
        self.draw.rectangle(
            (0, 0, WIDTH - 1, HEIGHT - 1),
            outline=0,
            fill=0,
        )

        now = time.monotonic()

        if now > self.restart_message_until:
            self.restart_message = ""

        if not self.snapshot.vpn.connected:
            flash_on = (
                int(now * 2) % 2 == 0
            )

            draw_vpn_warning(
                self.draw,
                self.snapshot,
                flash_on,
                self.restart_message,
            )
        else:
            PAGE_DRAWERS[self.page](
                self.draw,
                self.snapshot,
                self.page,
            )

            if self.restart_message:
                box_width = min(
                    WIDTH - 4,
                    text_width(
                        self.draw,
                        self.restart_message,
                        FONT_SMALL,
                    )
                    + 6,
                )

                x0 = (
                    WIDTH - box_width
                ) // 2

                self.draw.rectangle(
                    (
                        x0,
                        45,
                        x0 + box_width,
                        61,
                    ),
                    outline=255,
                    fill=0,
                )

                message = fit_text(
                    self.draw,
                    self.restart_message,
                    box_width - 4,
                    FONT_SMALL,
                )

                self.draw.text(
                    (x0 + 2, 49),
                    message,
                    font=FONT_SMALL,
                    fill=255,
                )

        self.display.image(self.image)
        self.display.show()

    def run(self) -> None:
        try:
            while not self.stop_event.is_set():
                loop_started = (
                    time.monotonic()
                )

                self.accept_refresh()
                self.poll_temp_monitor()
                self.start_refresh()
                self.handle_buttons()

                if (
                    self.auto_rotate
                    and self.snapshot.vpn.connected
                    and (
                        loop_started
                        - self.last_page_change
                        >= float(
                            CONFIG[
                                "auto_rotate_seconds"
                            ]
                        )
                    )
                ):
                    self.change_page(1)

                self.render()

                elapsed = (
                    time.monotonic()
                    - loop_started
                )

                time.sleep(
                    max(
                        0.03,
                        0.10 - elapsed,
                    )
                )
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        self.stop_event.set()

        self.executor.shutdown(
            wait=False,
            cancel_futures=True,
        )

        try:
            self.display.fill(0)
            self.display.show()
        except Exception:
            pass

        if self.temp_socket is not None:
            self.temp_socket.close()

        self.buttons.close()
        self.display.close()


def main() -> None:
    app = DeskNOC()

    def request_stop(
        _signum: int,
        _frame: Any,
    ) -> None:
        app.stop_event.set()

    signal.signal(
        signal.SIGTERM,
        request_stop,
    )
    signal.signal(
        signal.SIGINT,
        request_stop,
    )

    app.run()


if __name__ == "__main__":
    main()
