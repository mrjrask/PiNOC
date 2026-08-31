from __future__ import annotations

def normalize_http(payload,status=None,latency_ms=None):
    data=dict(payload or {}) if isinstance(payload,dict) else {}; data.update(http_reachable=status is not None,http_status=status,response_latency_ms=latency_ms); return data
