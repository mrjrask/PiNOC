"""Normalized, JSON-safe PiNOC state models."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DeviceState:
    id: str
    hostname: str
    friendly_name: str
    roles: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    ip: str = ""
    local_hostname: str = ""
    mac: Optional[str] = None
    model: str = ""
    architecture: str = ""
    os: str = ""
    os_version: str = ""
    kernel: str = ""
    uptime_seconds: int = 0
    boot_time: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    online: bool = False
    health: str = "offline"
    cpu: Dict[str, Any] = field(default_factory=dict)
    hardware: Dict[str, Any] = field(default_factory=dict)
    memory: Dict[str, Any] = field(default_factory=dict)
    storage: List[Dict[str, Any]] = field(default_factory=list)
    network: Dict[str, Any] = field(default_factory=dict)
    services: List[Dict[str, Any]] = field(default_factory=list)
    applications: Dict[str, Any] = field(default_factory=dict)
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""
    address: str = ""
    collection_method: str = ""
    notes: str = ""
    cockpit_url: Optional[str] = None
    maintenance: bool = False
    last_successful_collection: Optional[str] = None
    last_collection_attempt: Optional[str] = None
    stale: bool = False
    collector_status: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    health_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "DeviceState":
        allowed = cls.__dataclass_fields__
        return cls(**{key: item for key, item in value.items() if key in allowed})
