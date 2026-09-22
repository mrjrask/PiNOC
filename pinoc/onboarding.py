"""Onboarding wizard: passive network discovery + bounded SSH fingerprinting.

Two bounded passes propose candidate Raspberry Pis for the operator to
review and confirm before anything is written to the device store:

* **Passive discovery** (:func:`read_arp_table`, :func:`mdns_browse`,
  :func:`merge_candidates`) never sends a single packet PiNOC didn't already
  cause some other way -- it reads the kernel's own ARP table
  (``/proc/net/arp``, populated by ordinary LAN traffic) and asks the local
  ``avahi-browse`` daemon (if installed) what it has already heard over
  mDNS. There is no active scanning of address ranges here.
* **SSH fingerprinting** (:func:`fingerprint_host`) is a bounded, read-only
  SSH session -- reusing the same ``ssh``/``sshpass`` subprocess-with-a-
  stdin-script shape as :mod:`pinoc.collectors.fleet` (including its
  ``DISCOVERY`` unit-name list, so "what services does this box run" stays
  defined in exactly one place) -- run only against candidates the operator
  selected, never swept across a whole subnet.

:class:`OnboardingService` ties both passes together with hard bounds
(candidate count, fingerprint host count, per-host timeout, worker count)
and every I/O boundary (ARP file read, mDNS browse, SSH runner) is
injectable so tests never touch a real network, matching the ``runner=``
convention :mod:`pinoc.collectors.fleet` already tests against.

Suggested config derivation (:func:`suggest_config`) turns a fingerprint's
detected systemd units into the same role/tag/monitored-service shape
``config/devices.json`` expects (see :mod:`pinoc.device_config`), so a
confirmed candidate needs at most a light edit, not a blank form.
"""
from __future__ import annotations

import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from pinoc.collectors.fleet import DISCOVERY, sections
from pinoc.device_config import _slug

DEFAULT_ARP_PATH = "/proc/net/arp"
MDNS_COMMAND = ["avahi-browse", "-artp"]

# Bounded SSH fingerprint script: hostname, OS release, kernel/arch, model,
# and the same short, known-unit allowlist FleetCollector's own discovery
# grep already uses (see pinoc.collectors.fleet.DISCOVERY) -- never a raw
# dump of every unit file on the box.
FP_SCRIPT = (
    "set +e\n"
    "echo __HOSTNAME__; hostname\n"
    "echo __OS__; cat /etc/os-release 2>/dev/null\n"
    "echo __UNAME__; uname -srm\n"
    "echo __MODEL__; tr -d '\\000' </proc/device-tree/model 2>/dev/null; echo\n"
    "echo __UNITS__; systemctl list-unit-files --no-legend --no-pager 2>/dev/null | "
    "awk '{print $1}' | grep -E '^(" + "|".join(DISCOVERY) + ")'\n"
    "echo __LISTEN__; ss -ltn 2>/dev/null | awk 'NR>1{print $4}'\n"
)

# unit-name substring -> suggested role/tags/critical for suggest_config().
# Keys are matched as substrings of a detected unit's lowercased name, so
# "dump1090-fa.service" matches "dump1090" and "wg-quick@wg0.service"
# matches "wg-quick".
SERVICE_ROLE_RULES: Dict[str, Dict[str, Any]] = {
    "piaware": {"role": "adsb_receiver", "tags": ["adsb"], "critical": True},
    "dump1090": {"role": "adsb_receiver", "tags": ["adsb"], "critical": True},
    "readsb": {"role": "adsb_receiver", "tags": ["adsb"], "critical": True},
    "desk-display": {"role": "desk_display", "tags": ["display"], "critical": False},
    "magicmirror": {"role": "magicmirror", "tags": ["display"], "critical": False},
    "pi-hotspot": {"role": "hotspot", "tags": ["network"], "critical": False},
    "smb": {"role": "file_server", "tags": ["storage"], "critical": False},
    "smbd": {"role": "file_server", "tags": ["storage"], "critical": False},
    "nmbd": {"role": "file_server", "tags": ["storage"], "critical": False},
    "wg-quick": {"role": "vpn_server", "tags": ["vpn"], "critical": False},
    "ics_modifier": {"role": "general", "tags": ["automation"], "critical": False},
}


# -- Passive discovery: ARP -------------------------------------------------

def parse_arp_text(text: str) -> List[Dict[str, Any]]:
    """Parse ``/proc/net/arp``-formatted text into candidate rows.

    Incomplete entries (no resolved hardware address -- flags ``0x0`` or an
    all-zero MAC) are dropped; they carry no usable identity yet.
    """
    rows: List[Dict[str, Any]] = []
    for line in text.splitlines()[1:]:  # skip the header row
        parts = line.split()
        if len(parts) < 6:
            continue
        ip, _hwtype, flags, mac, _mask, device = parts[:6]
        if flags == "0x0" or mac.lower() == "00:00:00:00:00:00":
            continue
        rows.append({"ip": ip, "mac": mac.lower(), "iface": device, "hostname": None, "source": "arp"})
    return rows


def read_arp_table(path: str = DEFAULT_ARP_PATH) -> List[Dict[str, Any]]:
    """Read and parse the local kernel ARP table. Never raises; a missing or
    unreadable table (containers, non-Linux, permissions) is just no rows."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return parse_arp_text(text)


# -- Passive discovery: mDNS -------------------------------------------------

def parse_mdns_text(text: str) -> List[Dict[str, Any]]:
    """Parse ``avahi-browse -artp`` output into one row per resolved address.

    ``-p`` gives semicolon-delimited, parseable lines; a resolved entry
    starts with ``=`` and carries ``iface;proto;name;type;domain;host;
    address;port;txt``. Anything shorter (an unresolved browse-only line) is
    skipped.
    """
    rows: Dict[str, Dict[str, Any]] = {}
    for line in text.splitlines():
        if not line.startswith("="):
            continue
        fields = line.split(";")
        if len(fields) < 8:
            continue
        service_type, hostname, address = fields[4], fields[6].strip(), fields[7].strip()
        if not address:
            continue
        entry = rows.setdefault(
            address, {"ip": address, "hostname": None, "services": [], "source": "mdns"})
        if hostname and not entry["hostname"]:
            entry["hostname"] = hostname
        if service_type and service_type not in entry["services"]:
            entry["services"].append(service_type)
    return list(rows.values())


def mdns_browse(timeout_seconds: float = 3.0,
                runner: Optional[Callable[..., Any]] = None) -> List[Dict[str, Any]]:
    """Bounded mDNS browse via the local ``avahi-browse`` daemon, if present.

    ``-t`` makes avahi-browse dump its current cache and terminate on its
    own; ``timeout_seconds`` is a backstop against a hung/missing daemon,
    not the primary bound. Missing ``avahi-browse`` (not installed) or any
    other failure degrades to an empty result rather than raising --
    passive mDNS discovery is a nice-to-have, never a hard requirement.
    """
    runner = runner or subprocess.run
    try:
        proc = runner(MDNS_COMMAND, capture_output=True, text=True,
                      timeout=timeout_seconds, check=False)
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout if isinstance(exc.stdout, str) else ""
        return parse_mdns_text(output or "")
    except OSError:
        return []
    return parse_mdns_text(proc.stdout or "")


def merge_candidates(arp_rows: List[Dict[str, Any]],
                     mdns_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge ARP and mDNS rows into one candidate per IP, sorted by IP for a
    stable, deterministic order (both for the UI and for tests)."""
    merged: Dict[str, Dict[str, Any]] = {}
    for row in arp_rows:
        ip = row.get("ip")
        if not ip:
            continue
        merged[ip] = {"ip": ip, "mac": row.get("mac"), "hostname": row.get("hostname"),
                      "mdns_services": [], "sources": ["arp"]}
    for row in mdns_rows:
        ip = row.get("ip")
        if not ip:
            continue
        entry = merged.setdefault(
            ip, {"ip": ip, "mac": None, "hostname": None, "mdns_services": [], "sources": []})
        if row.get("hostname") and not entry.get("hostname"):
            entry["hostname"] = row["hostname"]
        for service in row.get("services", []):
            if service not in entry["mdns_services"]:
                entry["mdns_services"].append(service)
        if "mdns" not in entry["sources"]:
            entry["sources"].append("mdns")
    return sorted(merged.values(), key=lambda entry: entry["ip"])


# -- Bounded SSH fingerprinting ----------------------------------------------

def _ssh_command(ip: str, ssh_user: str, ssh_port: int, timeout: float) -> List[str]:
    return ["ssh", "-p", str(ssh_port), "-o", f"ConnectTimeout={max(1, int(timeout))}",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
            f"{ssh_user}@{ip}", "sh", "-s", "--"]


def fingerprint_host(ip: str, *, ssh_user: str = "pi", ssh_port: int = 22,
                     timeout: float = 6.0, password: Optional[str] = None,
                     runner: Optional[Callable[..., Any]] = None) -> Dict[str, Any]:
    """Run the bounded fingerprint script over SSH against one candidate IP.

    Returns ``{"ok": False, "error": ...}`` on any failure (unreachable,
    auth failure, timeout) rather than raising, so a batch fingerprint pass
    over several candidates never aborts on the first bad one.
    """
    runner = runner or subprocess.run
    cmd = _ssh_command(ip, ssh_user, ssh_port, timeout)
    env = {**os.environ, "LC_ALL": "C"}
    if password:
        cmd = ["sshpass", "-e", *cmd]
        env["SSHPASS"] = password
    try:
        proc = runner(cmd, input=FP_SCRIPT, text=True, capture_output=True,
                      timeout=timeout, env=env, check=False)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "ssh timed out"}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    if proc.returncode:
        return {"ok": False, "error": (proc.stderr or f"ssh exited {proc.returncode}").strip()[:240]}
    data = sections(proc.stdout)
    os_values: Dict[str, str] = {}
    for row in data.get("OS", "").splitlines():
        if "=" in row:
            key, value = row.split("=", 1)
            os_values[key] = value.strip('"')
    uname = data.get("UNAME", "").split()
    units = [u for u in data.get("UNITS", "").splitlines() if u.strip()]
    listening = [p for p in data.get("LISTEN", "").splitlines() if p.strip()]
    return {"ok": True, "hostname": data.get("HOSTNAME", "").strip(),
            "os": os_values.get("NAME", ""), "os_version": os_values.get("VERSION_ID", ""),
            "kernel": uname[1] if len(uname) > 1 else "", "architecture": uname[-1] if uname else "",
            "model": (data.get("MODEL") or "").strip(), "units": units, "listening_ports": listening}


# -- Suggested config derivation ---------------------------------------------

def suggest_config(ip: str, fingerprint: Dict[str, Any], *,
                   ssh_user: str = "pi", ssh_port: int = 22) -> Dict[str, Any]:
    """Derive a suggested ``config/devices.json`` entry from a successful
    fingerprint, using the same role-from-detected-service heuristic as
    :data:`SERVICE_ROLE_RULES`. Falls back to role ``general`` when nothing
    matched -- every device still needs *a* role to pass
    :func:`pinoc.device_config.parse_device`.
    """
    hostname = (fingerprint.get("hostname") or "").strip() or ip.replace(".", "-")
    roles: List[str] = []
    tags: List[str] = []
    monitored: List[str] = []
    critical: List[str] = []
    cockpit_enabled = False
    for unit in fingerprint.get("units") or []:
        lowered = unit.lower()
        if lowered.startswith("cockpit"):
            cockpit_enabled = True
            if unit not in monitored:
                monitored.append(unit)
            continue
        if lowered.startswith("ssh"):
            continue  # every SSH-managed candidate has this; not role-indicative
        for pattern, rule in SERVICE_ROLE_RULES.items():
            if pattern not in lowered:
                continue
            if rule["role"] not in roles:
                roles.append(rule["role"])
            for tag in rule["tags"]:
                if tag not in tags:
                    tags.append(tag)
            if unit not in monitored:
                monitored.append(unit)
            if rule["critical"] and unit not in critical:
                critical.append(unit)
    if not roles:
        roles = ["general"]
    notes = (f"Discovered via the onboarding wizard "
            f"({fingerprint.get('os') or 'unknown OS'} {fingerprint.get('os_version') or ''} "
            f"on {fingerprint.get('architecture') or 'unknown arch'}).").replace("  ", " ")
    return {"id": _slug(hostname), "hostname": hostname, "friendly_name": hostname or ip,
            "address": ip, "collection_method": "ssh", "ssh_user": ssh_user, "ssh_port": ssh_port,
            "roles": roles, "tags": tags, "monitored_services": monitored,
            "critical_services": critical, "cockpit_enabled": cockpit_enabled, "notes": notes}


# -- Orchestration ------------------------------------------------------------

class OnboardingService:
    """Bounds and wires the two discovery passes for the web wizard.

    Every I/O boundary is injectable (``arp_reader``, ``mdns_runner``,
    ``ssh_runner``) so tests exercise the real merge/parse/heuristic logic
    against fake data without ever touching a real network -- the same
    pattern :class:`pinoc.collectors.fleet.FleetCollector` uses for its own
    ``runner``.
    """

    def __init__(self, *, arp_path: str = DEFAULT_ARP_PATH,
                arp_reader: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
                mdns_runner: Optional[Callable[..., Any]] = None,
                ssh_runner: Optional[Callable[..., Any]] = None,
                mdns_timeout: float = 3.0, ssh_timeout: float = 6.0,
                max_candidates: int = 50, max_fingerprint_hosts: int = 20,
                fingerprint_workers: int = 4) -> None:
        self.arp_path = arp_path
        self.arp_reader = arp_reader or read_arp_table
        self.mdns_runner = mdns_runner
        self.ssh_runner = ssh_runner
        self.mdns_timeout = max(0.5, float(mdns_timeout))
        self.ssh_timeout = max(1.0, float(ssh_timeout))
        self.max_candidates = max(1, int(max_candidates))
        self.max_fingerprint_hosts = max(1, int(max_fingerprint_hosts))
        self.fingerprint_workers = max(1, int(fingerprint_workers))

    def scan(self) -> List[Dict[str, Any]]:
        """Bounded passive-discovery pass: ARP table + mDNS browse, merged
        and capped at ``max_candidates``. Never raises."""
        try:
            arp_rows = self.arp_reader(self.arp_path)
        except Exception:
            arp_rows = []
        try:
            mdns_rows = mdns_browse(self.mdns_timeout, runner=self.mdns_runner)
        except Exception:
            mdns_rows = []
        return merge_candidates(arp_rows, mdns_rows)[: self.max_candidates]

    def fingerprint(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Bounded SSH fingerprint pass over operator-selected candidates
        (never more than ``max_fingerprint_hosts``, never a subnet sweep).
        Each host's own hostname/OS/services/suggested config comes back
        even when another host in the same batch fails."""
        hosts = list(hosts)[: self.max_fingerprint_hosts]
        results: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=min(self.fingerprint_workers, max(1, len(hosts)) or 1)) as pool:
            futures = {pool.submit(self._fingerprint_one, host): host for host in hosts}
            for future in as_completed(futures):
                results.append(future.result())
        return sorted(results, key=lambda entry: entry.get("ip") or "")

    def _fingerprint_one(self, host: Dict[str, Any]) -> Dict[str, Any]:
        ip = str(host.get("ip") or "")
        ssh_user = str(host.get("ssh_user") or "pi")
        try:
            ssh_port = int(host.get("ssh_port") or 22)
        except (TypeError, ValueError):
            ssh_port = 22
        fp = fingerprint_host(ip, ssh_user=ssh_user, ssh_port=ssh_port, timeout=self.ssh_timeout,
                              password=host.get("password"), runner=self.ssh_runner)
        entry: Dict[str, Any] = {"ip": ip, "mac": host.get("mac"), "arp_hostname": host.get("hostname"),
                                 "ok": bool(fp.get("ok")), "fingerprint": fp, "suggested": None}
        if entry["ok"]:
            entry["suggested"] = suggest_config(ip, fp, ssh_user=ssh_user, ssh_port=ssh_port)
        return entry
