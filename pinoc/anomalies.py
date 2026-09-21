"""Statistical anomaly detection over the per-device metric stream.

Alerting in PiNOC is built from static thresholds, which structurally cannot
see the gradual or unusual-but-below-threshold class of problems: slow memory
growth, a crypto miner idling at 60% CPU, or a nightly traffic spike three
times the norm.

This module keeps a lightweight statistical baseline per device and per
metric — an EWMA mean and variance (with optional hour-of-day buckets for
seasonality) — and flags samples that deviate from it by a configurable
z-score.  Detection runs inside the history writer (one sample at a time, in
the order samples arrive) and reuses the durable alert engine's
fingerprinting, hysteresis, and open/resolve lifecycle verbatim: an anomaly
is a distinct ``anomaly`` alert type whose fingerprint encodes the metric, so
a sustained deviation keeps one alert alive and recovery resolves it.

Two modes:

* ``alerting`` — deviations open real ``anomaly`` alerts (and notifications);
* preview (default) — deviations are recorded in a bounded
  ``anomaly_previews`` ring that the web console shows, without opening
  alerts, so operators can watch what *would* have fired before trusting the
  feature.

The whole feature is off unless the top-level ``anomaly_detection`` config
section sets ``enabled: true``; individual metrics can be disabled and each
carries its own z-score sensitivity.
"""
from __future__ import annotations

import math
from datetime import datetime
from typing import Any, Dict, Iterable, Optional

from .database import Database, utcnow

# Floor so a constant signal (zero variance) does not divide by zero; the
# floor scales with the signal so a constant 0 cpu_percent and a constant
# 45 000 000 B/s link are treated with equal relative sensitivity.
MIN_STD_FRACTION = 0.01

METRICS = {
    "cpu_percent": {"label": "CPU utilization", "unit": "%", "decimal": 1},
    "load_1m": {"label": "1-minute load", "unit": "", "decimal": 2},
    "cpu_temp_c": {"label": "CPU temperature", "unit": "°C", "decimal": 1},
    "memory_percent": {"label": "Memory utilization", "unit": "%", "decimal": 1},
    "rx_rate_bps": {"label": "Network receive rate", "unit": "B/s", "decimal": 0},
    "tx_rate_bps": {"label": "Network transmit rate", "unit": "B/s", "decimal": 0},
}


def _extract(d: Dict[str, Any]) -> "list[tuple[str, Optional[float]]]":
    cpu = d.get("cpu") or {}
    memory = d.get("memory") or {}
    network = d.get("network") or {}
    return [
        ("cpu_percent", cpu.get("utilization_percent")),
        ("load_1m", cpu.get("load_1m")),
        ("cpu_temp_c", cpu.get("temperature_c")),
        ("memory_percent", memory.get("percent")),
        ("rx_rate_bps", network.get("rx_rate")),
        ("tx_rate_bps", network.get("tx_rate")),
    ]


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    return number


class BaselineTracker:
    """Per-device/per-metric EWMA baselines with z-score deviation checks."""

    def __init__(self, db: Database, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        self.db = db
        self.enabled = bool(cfg.get("enabled", False))
        # ``enabled`` gates everything; ``alerting`` selects real alerts over
        # preview-only recording.
        self.alerting = bool(cfg.get("alerting", False))
        self.severity = str(cfg.get("severity") or "warning")
        self.z_open = float(cfg.get("z_open") or 3.5)
        self.z_hysteresis = float(cfg.get("z_hysteresis") or 2.5)
        self.min_samples = max(10, int(cfg.get("min_samples") or 50))
        self.alpha = min(1.0, max(1e-6, float(cfg.get("ewma_alpha") or 0.03)))
        self.outlier_limit = float(cfg.get("outlier_limit") or 8.0)
        self.preview_keep = max(1, int(cfg.get("preview_keep") or 200))
        self.hourly = bool(cfg.get("hourly_seasonality", True))
        self.max_baseline_age_seconds = max(3600, int(cfg.get("max_baseline_age_seconds") or 24 * 3600))
        per_metric = cfg.get("metrics") or {}
        self.metric_config: Dict[str, Dict[str, Any]] = {}
        for key, meta in METRICS.items():
            override = per_metric.get(key) or {}
            self.metric_config[key] = {
                **meta,
                "enabled": bool(override.get("enabled", True)),
                "z_open": float(override["z_open"]) if override.get("z_open") is not None else self.z_open,
                "z_hysteresis": float(override["z_hysteresis"]) if override.get("z_hysteresis") is not None else self.z_hysteresis,
            }

    # -- public ------------------------------------------------------------
    def observe(self, d: Dict[str, Any], stamp: str,
                open_metrics: Iterable[str] = ()) -> "list[Dict[str, Any]]":
        """Consume one device sample.

        Updates the device's baselines and returns one dict per metric that
        currently deviates far enough to *hold* an open anomaly alert (or to
        open a new one).  In preview mode the same deviations are recorded in
        ``anomaly_previews`` instead of being returned.
        """
        if not self.enabled or not d.get("online") or d.get("maintenance"):
            return []
        did = d.get("id")
        if not did:
            return []
        hour = datetime.fromisoformat(stamp).hour
        open_metrics = set(open_metrics)
        candidates = []
        for metric, raw in _extract(d):
            spec = self.metric_config.get(metric)
            if spec is None or not spec["enabled"]:
                continue
            value = _number(raw)
            if value is None:
                continue
            candidates.append((metric, value))
        if not candidates:
            return []
        # One query for every tracked metric on this device instead of one
        # per metric -- observe() runs once per device per poll, and with 6
        # tracked metrics that was 6 round-trips just to read the baselines.
        metrics = [metric for metric, _ in candidates]
        placeholders = ",".join("?" * len(metrics))
        baselines_by_metric: Dict[str, Dict[int, Dict[str, Any]]] = {}
        for row in self.db.rows(
                f"SELECT * FROM metric_baselines WHERE device_id=? AND metric IN ({placeholders}) AND hour IN (-1,?)",
                (did, *metrics, hour)):
            baselines_by_metric.setdefault(row["metric"], {})[row["hour"]] = row
        results = []
        for metric, value in candidates:
            baselines = baselines_by_metric.get(metric, {})
            ref, z, stale = self._reference(baselines, hour, value, stamp)
            anomaly = self._evaluate(metric, value, hour, stamp, baselines, open_metrics,
                                     ref=ref, z=z, stale=stale)
            if anomaly is not None:
                if self.alerting:
                    results.append(anomaly)
                else:
                    self._record_preview(did, metric, value, hour, stamp, anomaly)
            # The *global* baseline is the always-live reference, so a sample
            # extreme against it updates recency but not mean/variance (a
            # one-off spike must not drag it).  Hour buckets absorb every
            # sample: their variance self-normalizes, which lets a genuinely
            # different hour-of-day regime bootstrap and self-heal.
            self._update(did, metric, value, hour, stamp, baselines, stale=stale)
        return results

    def previews(self, limit: int = 100) -> "list[Dict[str, Any]]":
        """Most recent previewed deviations, newest first."""
        return self.db.rows(
            "SELECT * FROM anomaly_previews ORDER BY timestamp DESC, id DESC LIMIT ?",
            (max(1, min(int(limit), 1000)),))

    # -- internals ---------------------------------------------------------
    def _reference(self, baselines: Dict[int, Dict[str, Any]], hour: int, value: float,
                   stamp: str) -> "tuple[Optional[Dict[str, Any]], Optional[float], bool]":
        """Pick the baseline to judge against and compute its z-score.

        Prefers the hour-of-day bucket once it has enough samples; falls back
        to the global baseline.  The z-score here drives the *evaluation*
        decision; the global row's own z (computed in :meth:`_update`) drives
        outlier rejection.
        """
        hour_row = baselines.get(hour) if self.hourly else None
        ref = hour_row if (hour_row is not None and hour_row["ewma_mean"] is not None
                           and hour_row["samples"] >= self.min_samples) else None
        if ref is None:
            global_row = baselines.get(-1)
            ref = global_row if (global_row is not None and global_row["ewma_mean"] is not None) else None
        if ref is None or ref["ewma_mean"] is None:
            return None, None, False
        mean = ref["ewma_mean"]
        std = math.sqrt(max(ref["ewma_var"] or 0.0, 0.0))
        floor = max(abs(mean) * MIN_STD_FRACTION, 1e-9)
        z = (value - mean) / max(std, floor)
        return ref, z, self._stale(ref, stamp)

    def _evaluate(self, metric: str, value: float, hour: int, stamp: str,
                  baselines: Dict[int, Dict[str, Any]], open_metrics: set,
                  ref: Optional[Dict[str, Any]], z: Optional[float],
                  stale: bool) -> Optional[Dict[str, Any]]:
        if ref is None or z is None or stale:
            return None  # still learning, or re-learning after a long gap
        if ref["samples"] < self.min_samples:
            return None
        spec = self.metric_config[metric]
        threshold = spec["z_hysteresis"] if metric in open_metrics else spec["z_open"]
        if abs(z) < threshold:
            return None
        mean = ref["ewma_mean"]
        std = math.sqrt(max(ref["ewma_var"] or 0.0, 0.0))
        meta = METRICS[metric]
        decimal = meta["decimal"]
        unit = meta["unit"]
        above = z > 0
        message = (f"{meta['label']} at {value:.{decimal}f}{unit} is {abs(z):.1f}σ "
                   f"{'above' if above else 'below'} the usual {hour:02d}:00 baseline "
                   f"(mean {mean:.{decimal}f}{unit})")
        return {"metric": metric, "value": value, "mean": mean,
                "std": max(std, max(abs(mean) * MIN_STD_FRACTION, 1e-9)),
                "z": z, "hour": hour if self.hourly else -1, "message": message,
                "severity": self.severity, "label": meta["label"]}

    def _stale(self, row: Dict[str, Any], stamp: str) -> bool:
        updated = row.get("updated_at")
        if not updated:
            return False
        try:
            age = (datetime.fromisoformat(stamp) - datetime.fromisoformat(updated)).total_seconds()
        except ValueError:
            return False
        return age > self.max_baseline_age_seconds

    def _update(self, did: str, metric: str, value: float, hour: int, stamp: str,
                baselines: Dict[int, Dict[str, Any]], stale: bool) -> None:
        alpha = self.alpha
        targets = {-1} | ({hour} if self.hourly else set())
        for target in targets:
            row = baselines.get(target)
            count = int(row["samples"] or 0) if row is not None else 0
            rejected = False
            if target == -1 and row is not None and row["ewma_mean"] is not None and not stale:
                mean = row["ewma_mean"]
                std = math.sqrt(max(row["ewma_var"] or 0.0, 0.0))
                z_global = (value - mean) / max(std, max(abs(mean) * MIN_STD_FRACTION, 1e-9))
                rejected = abs(z_global) >= self.outlier_limit
            if rejected:
                self.db.execute(
                    "UPDATE metric_baselines SET updated_at=? WHERE device_id=? AND metric=? AND hour=?",
                    (stamp, did, metric, target))
                continue
            if row is None or row["ewma_mean"] is None:
                mean, var = value, 0.0
            else:
                mean = row["ewma_mean"]
                var = row["ewma_var"] or 0.0
                diff = value - mean
                var = (1 - alpha) * var + alpha * diff * diff
                mean = mean + alpha * diff
            if row is None:
                self.db.execute(
                    "INSERT INTO metric_baselines(device_id,metric,hour,ewma_mean,ewma_var,samples,updated_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (did, metric, target, mean, var, 1, stamp))
            else:
                self.db.execute(
                    "UPDATE metric_baselines SET ewma_mean=?,ewma_var=?,samples=?,updated_at=? "
                    "WHERE device_id=? AND metric=? AND hour=?",
                    (mean, var, count + 1, stamp, did, metric, target))

    def _record_preview(self, did: str, metric: str, value: float, hour: int,
                        stamp: str, anomaly: Dict[str, Any]) -> None:
        self.db.execute(
            "INSERT INTO anomaly_previews(timestamp,device_id,metric,value,baseline_mean,baseline_std,z_score,hour) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (stamp, did, metric, value, anomaly["mean"], anomaly["std"], anomaly["z"],
             anomaly["hour"]))
        self.db.execute(
            "DELETE FROM anomaly_previews WHERE device_id=? AND metric=? AND id NOT IN "
            "(SELECT id FROM anomaly_previews WHERE device_id=? AND metric=? ORDER BY id DESC LIMIT ?)",
            (did, metric, did, metric, self.preview_keep))
