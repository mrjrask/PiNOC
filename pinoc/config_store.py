"""Validated atomic JSON configuration persistence with bounded backups."""
import json, os, re, shutil, tempfile
from pathlib import Path
from pinoc.device_config import load_devices
from pinoc.playbooks import validate_playbooks

RATE_LIMIT_RULES={"login_window_seconds":(1,86400),"login_max_failed":(1,100),"login_max_failed_per_source":(1,10000),"lockout_seconds":(1,86400),"api_window_seconds":(1,86400),"api_max_unauthenticated":(1,10000)}

def validate_security(value):
    security=value.get("security",{})
    if not isinstance(security,dict):raise ValueError("security must be an object")
    rate_limit=security.get("rate_limit",{})
    if not isinstance(rate_limit,dict):raise ValueError("security.rate_limit must be an object")
    for name,setting in rate_limit.items():
        if name not in RATE_LIMIT_RULES:raise ValueError(f"unknown security.rate_limit setting: {name}")
        low,high=RATE_LIMIT_RULES[name]
        if isinstance(setting,bool) or not isinstance(setting,(int,float)) or not low<=setting<=high:raise ValueError(f"invalid security.rate_limit.{name}: must be a number between {low} and {high}")

def validate_authentication(value):
    authentication=value.get("authentication",{})
    if not isinstance(authentication,dict):raise ValueError("authentication must be an object")
    trusted_proxy_count=authentication.get("trusted_proxy_count",0)
    if isinstance(trusted_proxy_count,bool) or not isinstance(trusted_proxy_count,int) or not 0<=trusted_proxy_count<=10:
        raise ValueError("invalid authentication.trusted_proxy_count: must be an integer between 0 and 10")

def validate_notifications(value):
    section=value.get("notifications") or {}
    if not isinstance(section,dict):raise ValueError("notifications must be an object")
    if not isinstance(section.get("enabled",False),bool):raise ValueError("notifications.enabled must be a boolean")
    queue_size=section.get("queue_size")
    if queue_size is not None and (isinstance(queue_size,bool) or not isinstance(queue_size,int) or not 1<=queue_size<=10000):
        raise ValueError("notifications.queue_size must be an integer between 1 and 10000")
    for key in ("open_severities","resolve_severities"):
        severities=section.get(key) or []
        if not isinstance(severities,list) or any(not isinstance(s,str) or s not in ("info","warning","degraded","critical") for s in severities):
            raise ValueError(f"notifications.{key} must be a list of info, warning, degraded, or critical")
    ids=set()
    for i,channel in enumerate(section.get("channels") or []):
        if not isinstance(channel,dict):raise ValueError(f"notifications.channels[{i}] must be an object")
        cid=channel.get("id")
        if not isinstance(cid,str) or not cid or cid in ids:raise ValueError(f"notifications.channels[{i}].id must be a unique non-empty string")
        ids.add(cid)
        kind=channel.get("kind")
        if kind not in ("ntfy","smtp","webhook"):raise ValueError(f"notifications.channels[{i}].kind must be ntfy, smtp, or webhook")
        if "enabled" in channel and not isinstance(channel.get("enabled"),bool):raise ValueError(f"notifications.channels[{i}].enabled must be a boolean")
        url=str(channel.get("url") or "")
        if kind in ("ntfy","webhook") and not url.startswith(("http://","https://")):
            raise ValueError(f"notifications.channels[{i}].url must be an http(s) URL")
        if kind=="ntfy" and not str(channel.get("topic") or "").strip():
            raise ValueError(f"notifications.channels[{i}].topic is required for ntfy channels")
        if kind=="smtp":
            if not str(channel.get("host") or "").strip():raise ValueError(f"notifications.channels[{i}].host is required for smtp channels")
            port=channel.get("port")
            if port is not None and (isinstance(port,bool) or not isinstance(port,int) or not 1<=port<=65535):
                raise ValueError(f"notifications.channels[{i}].port must be between 1 and 65535")
            to=channel.get("to") or []
            if not isinstance(to,list) or not to or any(not isinstance(x,str) or not x.strip() for x in to):
                raise ValueError(f"notifications.channels[{i}].to must be a non-empty list of addresses")

def validate_backups(value):
    section=value.get("backups")
    if section is None:return
    if not isinstance(section,dict):raise ValueError("backups must be an object")
    if "enabled" in section and not isinstance(section.get("enabled"),bool):raise ValueError("backups.enabled must be a boolean")
    interval=section.get("interval_hours",24)
    if isinstance(interval,bool) or not isinstance(interval,(int,float)) or not 1<=interval<=8760:
        raise ValueError("backups.interval_hours must be a number between 1 and 8760")
    keep=section.get("keep",7)
    if isinstance(keep,bool) or not isinstance(keep,int) or not 1<=keep<=99:
        raise ValueError("backups.keep must be an integer between 1 and 99")
    key_env=section.get("signing_key_env","PINOC_BACKUP_KEY")
    if not isinstance(key_env,str) or not re.fullmatch(r"[A-Z0-9_]{1,64}",key_env):
        raise ValueError("backups.signing_key_env must be an environment variable name")
    if section.get("enabled") and not section.get("destination"):
        raise ValueError("backups.destination is required when backups.enabled is true")
    destination=section.get("destination")
    if destination is None:return
    if not isinstance(destination,dict):raise ValueError("backups.destination must be an object")
    kind=destination.get("type")
    if kind not in ("path","ssh"):raise ValueError("backups.destination.type must be path or ssh")
    path=str(destination.get("path") or "")
    if not path.startswith("/") or "\x00" in path or len(path)>4096:
        raise ValueError("backups.destination.path must be an absolute path")
    if kind=="ssh":
        host=str(destination.get("host") or "")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,255}",host):raise ValueError("backups.destination.host must be a hostname")
        user=str(destination.get("user") or "pi")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,255}",user):
            raise ValueError("backups.destination.user must be a simple username")
        port=destination.get("port",22)
        if isinstance(port,bool) or not isinstance(port,int) or not 1<=port<=65535:
            raise ValueError("backups.destination.port must be between 1 and 65535")

def validate_anomaly_detection(value):
    section=value.get("anomaly_detection")
    if section is None:return
    if not isinstance(section,dict):raise ValueError("anomaly_detection must be an object")
    from pinoc.anomalies import METRICS
    for name in ("enabled","alerting","hourly_seasonality"):
        if name in section and not isinstance(section.get(name),bool):raise ValueError(f"anomaly_detection.{name} must be a boolean")
    for name,low,high in (("z_open",1,100),("z_hysteresis",0,100),("outlier_limit",1,100)):
        setting=section.get(name)
        if setting is not None and (isinstance(setting,bool) or not isinstance(setting,(int,float)) or not low<=setting<=high):
            raise ValueError(f"anomaly_detection.{name} must be a number between {low} and {high}")
    alpha=section.get("ewma_alpha")
    if alpha is not None and (isinstance(alpha,bool) or not isinstance(alpha,(int,float)) or not 0<alpha<1):
        raise ValueError("anomaly_detection.ewma_alpha must be a number between 0 and 1 (exclusive)")
    minimum=section.get("min_samples")
    if minimum is not None and (isinstance(minimum,bool) or not isinstance(minimum,int) or not 10<=minimum<=100000):
        raise ValueError("anomaly_detection.min_samples must be an integer between 10 and 100000")
    keep=section.get("preview_keep")
    if keep is not None and (isinstance(keep,bool) or not isinstance(keep,int) or not 1<=keep<=10000):
        raise ValueError("anomaly_detection.preview_keep must be an integer between 1 and 10000")
    age=section.get("max_baseline_age_seconds")
    if age is not None and (isinstance(age,bool) or not isinstance(age,(int,float)) or not 3600<=age<=86400*30):
        raise ValueError("anomaly_detection.max_baseline_age_seconds must be between 3600 and 2592000")
    severity=section.get("severity")
    if severity is not None and severity not in ("info","warning","degraded","critical"):
        raise ValueError("anomaly_detection.severity must be info, warning, degraded, or critical")
    metrics=section.get("metrics")
    if metrics is None:return
    if not isinstance(metrics,dict):raise ValueError("anomaly_detection.metrics must be an object")
    for name,entry in metrics.items():
        if name not in METRICS:raise ValueError(f"unknown anomaly_detection.metrics entry: {name}")
        if not isinstance(entry,dict):raise ValueError(f"anomaly_detection.metrics.{name} must be an object")
        if "enabled" in entry and not isinstance(entry.get("enabled"),bool):raise ValueError(f"anomaly_detection.metrics.{name}.enabled must be a boolean")
        for zname in ("z_open","z_hysteresis"):
            setting=entry.get(zname)
            if setting is not None and (isinstance(setting,bool) or not isinstance(setting,(int,float)) or not 0<=setting<=100):
                raise ValueError(f"anomaly_detection.metrics.{name}.{zname} must be a number between 0 and 100")

def validate_alert_correlation(value):
    section=value.get("alert_correlation")
    if section is None:return
    if not isinstance(section,dict):raise ValueError("alert_correlation must be an object")
    if "enabled" in section and not isinstance(section.get("enabled"),bool):raise ValueError("alert_correlation.enabled must be a boolean")
    window=section.get("window_seconds")
    if window is not None and (isinstance(window,bool) or not isinstance(window,(int,float)) or not 30<=window<=3600):
        raise ValueError("alert_correlation.window_seconds must be a number between 30 and 3600")
    minimum=section.get("min_members")
    if minimum is not None and (isinstance(minimum,bool) or not isinstance(minimum,int) or not 2<=minimum<=100):
        raise ValueError("alert_correlation.min_members must be an integer between 2 and 100")

def validate_config(value,base_dir=Path(".")):
    if not isinstance(value,dict):raise ValueError("configuration must be an object")
    polling=value.get("polling",{})
    if not isinstance(polling,dict):raise ValueError("polling must be an object")
    for name,seconds in polling.items():
        if not isinstance(seconds,(int,float)) or not 1<=seconds<=86400:raise ValueError(f"invalid polling interval: {name}")
    validate_authentication(value)
    validate_security(value)
    validate_backups(value)
    validate_playbooks(value.get("playbooks"))
    validate_notifications(value)
    validate_anomaly_detection(value)
    validate_alert_correlation(value)
    _,errors=load_devices(value,Path(base_dir))
    if errors:raise ValueError("; ".join(errors))
    return value

def _atomic_write(path,value,backups=3):
    """Bounded-backup, fsync'd, rename-into-place JSON write shared by
    :func:`atomic_save` (config.json) and :func:`save_devices`
    (config/devices.json) -- the mechanics are identical, only what gets
    validated first differs."""
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
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

def atomic_save(path,value,backups=3):
    # base_dir must be the directory *containing* config.json (where
    # config/devices.json also lives), matching validate_config.py's own
    # `root = Path.cwd()` -- not its parent, which would look one level too
    # high and silently fall back to load_devices()'s empty in-config
    # "devices" default instead of validating the real devices file.
    path=Path(path);validate_config(value,path.parent);_atomic_write(path,value,backups)

def save_devices(config,base_dir,payload,backups=3):
    """Validate and atomically write the device store (``config/devices.json``
    by default, per ``config['devices_file']``) through the same
    :class:`~pinoc.device_config.DeviceConfig` parsing/validation
    :func:`~pinoc.device_config.load_devices` itself uses -- the onboarding
    wizard's confirm step (and anything else that wants to add/update
    devices from code) calls this instead of hand-writing the JSON file, so
    it can never persist an entry the rest of PiNOC would reject.

    Validation happens entirely before anything touches disk: a bad payload
    raises :class:`ValueError` and leaves the existing devices file (and its
    backups) untouched.
    """
    from pinoc.device_config import validate_device_list
    if not isinstance(payload,dict) or not isinstance(payload.get("devices"),list):
        raise ValueError("devices payload must be an object with a devices list")
    _,errors=validate_device_list(payload["devices"],config.get("health_thresholds",{}))
    if errors:raise ValueError("; ".join(errors))
    devices_path=Path(base_dir)/str(config.get("devices_file","config/devices.json"))
    _atomic_write(devices_path,payload,backups)
    return devices_path
