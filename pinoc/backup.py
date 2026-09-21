"""One-file backup/restore bundles for a whole PiNOC instance.

A bundle is a single signed tar archive containing:

    config.json         the live configuration file (values included)
    config/devices.json the fleet file, when present
    env-manifest.txt    .env key names only — values never enter a bundle
    pinoc.db            an online SQLite backup (the service never stops)
    bundle.json         metadata: creation time, host, schema, member digests
    bundle.sig          HMAC-SHA256 when a signing key is configured, otherwise
                        a plain SHA-256 digest of the canonical member digests

CLI (run on the PiNOC host)::

    python3 -m pinoc.backup export [-o FILE]
    python3 -m pinoc.backup restore BUNDLE [--yes] [--allow-missing-secrets]

Export requires the live config, so the restore path re-validates the bundle
before touching anything: signature (no bypass), schema version, and the
required .env secrets.  Restore is audited against the pre-restore database
and replaces files atomically while the service runs; a service restart is
then required for the restored state to take effect.

Scheduled remote backups read the ``backups`` config section::

    "backups": {
        "enabled": true,
        "interval_hours": 24,
        "keep": 7,
        "signing_key_env": "PINOC_BACKUP_KEY",
        "destination": {"type": "path", "path": "/mnt/nas/pinoc"}
                       or {"type": "ssh", "host": "...", "user": "pi",
                           "port": 22, "path": "/var/backups/pinoc"}
    }

Remote delivery uses fixed-argv ``scp``/``ssh`` (never a shell) and rotates
bundles beyond ``keep``.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from pinoc.database import Database, SCHEMA_VERSION

LOG = logging.getLogger("pinoc.backup")

BUNDLE_PREFIX = "pinoc-bundle-"
PAYLOAD_MEMBERS = ("config.json", "config/devices.json", "env-manifest.txt",
                   "pinoc.db", "bundle.json")
# Everything except the fleet file is mandatory in a valid bundle.
REQUIRED_MEMBERS = tuple(m for m in PAYLOAD_MEMBERS if m != "config/devices.json")
_SAFE_REMOTE_NAME = re.compile(r"[A-Za-z0-9._-]{1,255}")
MAX_BUNDLE_BYTES = 2 * 1024 * 1024 * 1024
MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_DATABASE_BYTES = 1 * 1024 * 1024 * 1024


class BackupError(RuntimeError):
    pass


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def env_manifest(env_path: Path) -> List[str]:
    """Key names from a KEY=value .env file — never their values."""
    keys: List[str] = []
    try:
        lines = Path(env_path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for line in lines:
        line = line.rstrip("\r").lstrip()
        if line.startswith("export "):
            line = line[len("export "):]
        if not line or line.startswith("#") or "=" not in line:
            continue
        name = line.split("=", 1)[0].strip()
        if name and name not in keys:
            keys.append(name)
    return keys


def _sized(data: bytes, name: str, limit: int) -> bytes:
    if len(data) > limit:
        raise BackupError(f"{name} is {len(data)} bytes; exceeds the {limit}-byte backup limit")
    return data


def build_bundle(instance_dir: Path, destination: Path, db: Database,
                 config: Optional[Dict[str, Any]] = None,
                 signing_key: Optional[str] = None) -> Dict[str, Any]:
    """Create a signed bundle. Returns bundle metadata; raises BackupError."""
    instance_dir = Path(instance_dir)
    destination = Path(destination)
    config_path = instance_dir / "config.json"
    if not config_path.exists():
        raise BackupError(f"{config_path} not found")
    try:
        raw_config = _sized(config_path.read_bytes(), "config.json", MAX_CONFIG_BYTES)
    except OSError as exc:
        raise BackupError(f"cannot read {config_path}: {exc}")
    if config is None:
        try:
            config = json.loads(raw_config)
        except ValueError as exc:
            raise BackupError(f"config.json is not valid JSON: {exc}")
    if not isinstance(config, dict):
        raise BackupError("config.json must contain an object")

    members: Dict[str, bytes] = {"config.json": raw_config}
    devices_path = instance_dir / str(config.get("devices_file", "config/devices.json"))
    if devices_path.exists():
        members["config/devices.json"] = _sized(
            devices_path.read_bytes(), str(devices_path), MAX_CONFIG_BYTES)
    keys = env_manifest(instance_dir / ".env")
    members["env-manifest.txt"] = ("\n".join(keys) + ("\n" if keys else "")).encode("utf-8")

    # Online backup API: the database never needs stopping.
    if not db.available and not db.initialize():
        raise BackupError(f"database unavailable: {db.error}")
    # tempfile.mktemp() only generates a name -- it never creates the file,
    # leaving a window where another local process could create or symlink
    # that path first. mkstemp() creates the file atomically (O_EXCL) under
    # a securely random name.
    fd, database_name = tempfile.mkstemp(suffix=".db", prefix="pinoc-bundle-")
    os.close(fd)
    database_path = Path(database_name)
    try:
        db.backup(database_path)
        members["pinoc.db"] = _sized(database_path.read_bytes(), "pinoc.db", MAX_DATABASE_BYTES)
    finally:
        try:
            database_path.unlink()
        except OSError:
            pass

    metadata: Dict[str, Any] = {
        "format": "pinoc-bundle",
        "format_version": 1,
        "created_at": utcnow(),
        "hostname": socket.gethostname(),
        "schema_version": SCHEMA_VERSION,
        "environment_keys": keys,
        "config_sha256": _sha256(raw_config),
        "members": {name: len(data) for name, data in members.items()},
        "member_sha256": {name: _sha256(data) for name, data in members.items()},
        "signature_algorithm": "HMAC-SHA256" if signing_key else "SHA-256",
    }
    metadata_bytes = (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode("utf-8")
    members["bundle.json"] = metadata_bytes
    payload = [members[name] for name in PAYLOAD_MEMBERS]
    digest = hashlib.sha256(b"".join(hashlib.sha256(chunk).digest() for chunk in payload))
    if signing_key:
        signature = hmac.new(signing_key.encode("utf-8"), digest.digest(), hashlib.sha256).hexdigest()
    else:
        signature = digest.hexdigest()
    members["bundle.sig"] = signature.encode("utf-8")

    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(destination, "w") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = int(time.time())
            info.type = tarfile.REGTYPE
            tar.addfile(info, io.BytesIO(data))
    if destination.stat().st_size > MAX_BUNDLE_BYTES:
        destination.unlink()
        raise BackupError("bundle exceeds the maximum size")
    metadata.update({"path": str(destination), "size_bytes": destination.stat().st_size, "signature": signature})
    return metadata


_MEMBER_SIZE_LIMITS = {"pinoc.db": MAX_DATABASE_BYTES}


def read_bundle(path: Path) -> Tuple[Dict[str, Any], Dict[str, bytes]]:
    """Return (bundle.json metadata, {member name: bytes})."""
    members: Dict[str, bytes] = {}
    with tarfile.open(path, "r") as tar:
        for member in tar.getmembers():
            if not member.isreg() or member.name not in PAYLOAD_MEMBERS + ("bundle.sig",):
                continue
            # build_bundle() enforces MAX_CONFIG_BYTES/MAX_DATABASE_BYTES on
            # write, but nothing enforced the same limits here before any
            # trust decision (signature/digest) is made -- a corrupted or
            # maliciously oversized member would be fully buffered into
            # memory regardless. Check the tar header's declared size (cheap
            # -- getmembers() already parsed it) before reading it.
            limit = _MEMBER_SIZE_LIMITS.get(member.name, MAX_CONFIG_BYTES)
            if member.size > limit:
                raise BackupError(f"{member.name} is {member.size} bytes; exceeds the {limit}-byte backup limit")
            handle = tar.extractfile(member)
            if handle:
                members[member.name] = handle.read()
    if "bundle.json" not in members:
        raise BackupError("bundle is missing bundle.json")
    return json.loads(members["bundle.json"]), members


def verify_bundle(path: Path, signing_key: Optional[str] = None) -> Tuple[bool, Dict[str, Any], List[str]]:
    """Verify digests, signature, and schema version. No bypass is supported."""
    issues: List[str] = []
    try:
        metadata, members = read_bundle(path)
    except (OSError, ValueError, tarfile.TarError, BackupError) as exc:
        return False, {}, [f"cannot read bundle: {exc}"]
    for name in REQUIRED_MEMBERS:
        if name not in members:
            issues.append(f"missing member {name}")
    if issues:
        return False, metadata, issues
    recorded = metadata.get("member_sha256") or {}
    # bundle.json cannot record its own digest; the signature covers it.
    for name in PAYLOAD_MEMBERS:
        if name == "bundle.json":
            continue
        if name in members and _sha256(members[name]) != recorded.get(name):
            issues.append(f"digest mismatch for {name}")
    signature = (members.get("bundle.sig") or b"").decode("utf-8").strip()
    payload = [members[name] for name in PAYLOAD_MEMBERS]
    digest = hashlib.sha256(b"".join(hashlib.sha256(chunk).digest() for chunk in payload))
    if signing_key:
        expected = hmac.new(signing_key.encode("utf-8"), digest.digest(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            issues.append("signature verification failed (HMAC-SHA256)")
    else:
        if metadata.get("signature_algorithm") == "HMAC-SHA256":
            issues.append("bundle was signed; a signing key is required to verify it")
        elif signature != digest.hexdigest():
            issues.append("digest verification failed")
    try:
        schema = int(metadata.get("schema_version") or 0)
    except (TypeError, ValueError):
        schema = 0
        issues.append("bundle has an invalid schema version")
    if schema > SCHEMA_VERSION:
        issues.append(f"bundle is from a newer PiNOC (schema {schema} > {SCHEMA_VERSION})")
    return (not issues), metadata, issues


def required_env_keys(config: Dict[str, Any], source_keys: List[str],
                      target_keys: List[str]) -> List[str]:
    """Secrets the source instance needed that are missing from the target .env.

    The bundle's env manifest is key names only, so the source's requirements
    are reconstructed from it: every source key in REQUIRED_ENV_KEYS that the
    restored config actually uses must also exist in the target .env.
    """
    target = set(target_keys)
    required = set()
    if config.get("authentication", {}).get("enabled"):
        required.add("PINOC_SECRET_KEY")
    if config.get("remote_host"):
        required.add("CM5_SSH_PASS")
    return [key for key in source_keys if key in required and key not in target]


def _write_atomic(path: Path, data: bytes, mode: int = 0o600) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def restore_bundle(path: Path, instance_dir: Path, database_path: Path,
                   confirm: Optional[str] = None, allow_missing_secrets: bool = False,
                   signing_key: Optional[str] = None,
                   audit: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Validate and apply a bundle. Raises BackupError unless everything passes."""
    ok, metadata, issues = verify_bundle(path, signing_key)
    if not ok:
        raise BackupError("; ".join(issues))
    members = read_bundle(path)[1]
    config = json.loads(members["config.json"])
    source_keys = [line for line in members["env-manifest.txt"].decode("utf-8").splitlines() if line]
    missing = required_env_keys(config, source_keys, env_manifest(instance_dir / ".env"))
    if missing and not allow_missing_secrets:
        raise BackupError(
            f"required secret(s) missing from .env: {', '.join(missing)} "
            "(add them to .env or pass --allow-missing-secrets)")
    if confirm is None:
        if not sys.stdin.isatty():
            raise BackupError("explicit confirmation required (pass --yes)")
        confirm = input(
            f"Type RESTORE to replace the configuration and database in {instance_dir}: ")
    if confirm != "RESTORE":
        raise BackupError("confirmation required")

    if audit is None:
        audit = _default_audit(database_path)
    detail = f"backup.restore bundle={path} schema={metadata.get('schema_version')}"
    # Audit the pre-restore database so the event survives in the file the
    # service had open...
    try:
        audit(detail)
    except Exception:
        LOG.exception("could not audit the pre-restore database; continuing")

    restored = []
    _write_atomic(instance_dir / "config.json", members["config.json"])
    restored.append("config.json")
    if "config/devices.json" in members:
        devices_path = instance_dir / str(config.get("devices_file", "config/devices.json"))
        _write_atomic(devices_path, members["config/devices.json"])
        restored.append(devices_path.name)
    current = Path(database_path)
    if current.exists():
        _write_atomic(current, members["pinoc.db"])
    else:
        current.parent.mkdir(parents=True, exist_ok=True)
        _write_atomic(current, members["pinoc.db"])
    # Drop stale WAL sidecars from the pre-restore database: a replaced main
    # file combined with the old -wal would replay pre-restore frames into
    # the restored database. The restored bundle's database is self-contained.
    for suffix in ("-wal", "-shm"):
        sidecar = current.with_name(current.name + suffix)
        if sidecar.exists():
            try:
                sidecar.unlink()
            except OSError:
                LOG.warning("could not remove stale %s; restart the service", sidecar)
    restored.append("pinoc.db")
    # ...and again against the restored database, which becomes the active
    # one after the service restarts.
    try:
        audit(detail)
    except Exception:
        LOG.exception("could not audit the restored database; continuing")
    return {
        "restored": restored,
        "missing_secrets": missing,
        "schema_version": metadata.get("schema_version"),
        "created_at": metadata.get("created_at"),
        "source_hostname": metadata.get("hostname"),
        "note": "restart the PiNOC service for the restored state to take effect",
    }


def _default_audit(database_path: Path) -> Callable[[str], None]:
    def audit(detail: str) -> None:
        db = Database(str(database_path))
        if not db.available:
            db.initialize()
        if not db.available:
            raise BackupError("database unavailable; cannot audit")
        db.execute(
            "INSERT INTO audit_records(timestamp,user,role,source_ip,device_id,action,target,"
            "parameters_json,authorization_result,execution_result,exit_code,duration_ms,error)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,NULL,NULL,?)",
            (utcnow(), "local-cli", "administrator", None, None, "backup.restore",
             None, "{}", "allowed", "succeeded", detail[:500]))
    return audit


class BackupService:
    """Scheduled bundle export to a local (SMB/NFS) path or a remote ssh host."""

    def __init__(self, config: Optional[Dict[str, Any]] = None, app_dir: Path = Path("."),
                 database_path: str = "data/pinoc.db", notifier: Any = None,
                 runner: Callable = subprocess.run) -> None:
        self.config = dict(config or {})
        self.app_dir = Path(app_dir)
        self.database_path = str(database_path)
        self.notifier = notifier
        self.runner = runner
        self.destination = dict(self.config.get("destination") or {})
        kind = self.destination.get("type")
        self.destination_valid = (
            kind == "path" and str(self.destination.get("path") or "").startswith("/")
            or kind == "ssh" and bool(self.destination.get("host"))
            and str(self.destination.get("path") or "").startswith("/"))
        self.enabled = bool(self.config.get("enabled")) and self.destination_valid
        interval = self.config.get("interval_hours", 24)
        self.interval = max(1.0, min(float(interval) if isinstance(interval, (int, float)) else 24.0, 8760.0))
        self.keep = max(1, min(int(self.config.get("keep", 7)), 99))
        self.key_env = str(self.config.get("signing_key_env", "PINOC_BACKUP_KEY"))
        self.lock = threading.Lock()
        self.last_run: Optional[str] = None
        self.last_bundle: Optional[str] = None
        self.last_error: Optional[str] = None
        self.last_size: Optional[int] = None
        self.next_run = time.monotonic() + 60
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="pinoc-backups", daemon=True)

    def start(self) -> None:
        if self.enabled:
            self.thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self.stop_event.set()
        if self.thread.is_alive():
            self.thread.join(timeout)

    def signing_key(self) -> Optional[str]:
        return os.environ.get(self.key_env) or None

    def run_backup(self) -> Dict[str, Any]:
        """Build one bundle, deliver it, rotate old copies. Returns status."""
        name = BUNDLE_PREFIX + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".tar"
        staging = Path(tempfile.mkdtemp(prefix="pinoc-backup-"))
        try:
            db = Database(self.database_path)
            if not db.available and not db.initialize():
                raise BackupError(f"database unavailable: {db.error}")
            metadata = build_bundle(self.app_dir, staging / name, db, signing_key=self.signing_key())
            self._deliver(staging / name, name)
            self._rotate(name)
            with self.lock:
                self.last_run = utcnow()
                self.last_bundle = name
                self.last_size = metadata["size_bytes"]
                self.last_error = None
            return self.status()
        except Exception as exc:
            LOG.exception("scheduled backup failed")
            with self.lock:
                self.last_error = str(exc)[:500]
            self._notify_failure(str(exc))
            return self.status()
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    def _deliver(self, staging: Path, name: str) -> None:
        if self.destination.get("type") == "ssh":
            user = str(self.destination.get("user") or "pi")
            host = str(self.destination["host"])
            port = int(self.destination.get("port", 22))
            remote = f"{user}@{host}:{self.destination['path']}"
            self.runner(["scp", "-P", str(port), "-o", "BatchMode=yes", str(staging), remote],
                        check=True, capture_output=True, text=True, timeout=600)
            # _rotate(), called immediately after by run_backup(), does its
            # own "ls -1t" listing and actually uses it for rotation --
            # listing here too just paid for a wasted SSH round-trip whose
            # result was never even read.
            return
        target = Path(self.destination["path"]) / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(staging, target)

    def _rotate(self, current_name: Optional[str] = None) -> None:
        # Keep the newest `keep` bundles, always including the one just
        # delivered so keep=1 cannot delete it.
        if self.destination.get("type") == "ssh":
            user = str(self.destination.get("user") or "pi")
            host = str(self.destination["host"])
            port = int(self.destination.get("port", 22))
            # Fixed-argv listing, then one fixed-argv rm per excess bundle;
            # remote file names are only accepted if they look like ours.
            result = self.runner(["ssh", "-p", str(port), "-o", "BatchMode=yes", f"{user}@{host}",
                                  "ls", "-1t", str(self.destination["path"]), f"{BUNDLE_PREFIX}*.tar"],
                                 check=False, capture_output=True, text=True, timeout=60)
            listed = [line.strip() for line in (result.stdout or "").splitlines()
                      if line.strip() and _SAFE_REMOTE_NAME.fullmatch(line.strip())]
            newest_first = [current_name] if current_name else []
            newest_first += [name for name in listed if name != current_name]
            for name in newest_first[self.keep:]:
                rm = self.runner(["ssh", "-p", str(port), "-o", "BatchMode=yes", f"{user}@{host}",
                                  "rm", "-f", "--", f"{self.destination['path']}/{name}"],
                                 check=False, capture_output=True, text=True, timeout=60)
                if rm.returncode:
                    LOG.warning("remote rotation could not remove %s", name)
            return
        folder = Path(self.destination["path"])
        if not folder.is_dir():
            return
        bundles = [p for p in folder.glob(BUNDLE_PREFIX + "*.tar")
                   if current_name is None or p.name != current_name]
        current = sorted(bundles, key=lambda p: p.stat().st_mtime, reverse=True)
        current = ([Path(folder / current_name)] if current_name else []) + current
        for old in current[self.keep:]:
            try:
                old.unlink()
            except OSError:
                LOG.warning("could not rotate out %s", old)

    def _notify_failure(self, error: str) -> None:
        if self.notifier is None or not self.notifier.enabled:
            return
        try:
            self.notifier.enqueue("open", {
                "severity": "critical", "alert_type": "backup_failed",
                "message": f"PiNOC backup failed: {error[:200]}", "device_id": None,
            })
        except Exception:
            LOG.exception("backup failure notification failed")

    def status(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "enabled": self.enabled,
                "destination": {"type": self.destination.get("type"),
                                "path": self.destination.get("path"),
                                "host": self.destination.get("host")},
                "interval_hours": self.interval,
                "keep": self.keep,
                "last_run": self.last_run,
                "last_bundle": self.last_bundle,
                "last_size_bytes": self.last_size,
                "last_error": self.last_error,
                "signing_key_configured": bool(os.environ.get(self.key_env)),
            }

    def _run(self) -> None:
        while not self.stop_event.is_set():
            if time.monotonic() >= self.next_run:
                self.run_backup()
                self.next_run = time.monotonic() + self.interval * 3600
            self.stop_event.wait(30)


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="pinoc.backup",
                                     description="One-file backup/restore bundles for PiNOC")
    parser.add_argument("--instance-dir", default=os.getenv("PINOC_APP_DIR") or os.path.dirname(os.path.abspath(__file__)) + "/..")
    parser.add_argument("--database", default=os.getenv("PINOC_DATABASE_PATH", "data/pinoc.db"))
    parser.add_argument("--key", default=None, help="signing key (default: $PINOC_BACKUP_KEY)")
    sub = parser.add_subparsers(dest="command", required=True)
    export = sub.add_parser("export", help="write a signed bundle")
    export.add_argument("-o", "--output", default=None,
                        help="bundle path (default: data/backups/pinoc-bundle-<utc>.tar)")
    restore = sub.add_parser("restore", help="validate and apply a bundle")
    restore.add_argument("bundle")
    restore.add_argument("--yes", action="store_true", help="confirm non-interactively")
    restore.add_argument("--allow-missing-secrets", action="store_true")
    args = parser.parse_args()

    instance_dir = Path(args.instance_dir).resolve()
    key = args.key or os.environ.get("PINOC_BACKUP_KEY") or None
    if args.command == "export":
        output = Path(args.output) if args.output else instance_dir / "data" / "backups" / (
            BUNDLE_PREFIX + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".tar")
        db = Database(args.database)
        if not db.available and not db.initialize():
            print(f"error: database unavailable: {db.error}", file=sys.stderr)
            return 1
        metadata = build_bundle(instance_dir, output, db, signing_key=key)
        print(json.dumps({k: metadata[k] for k in
                          ("path", "size_bytes", "members", "signature_algorithm", "signature")},
                         indent=2))
        return 0
    try:
        result = restore_bundle(Path(args.bundle), instance_dir, Path(args.database),
                                confirm="RESTORE" if args.yes else None,
                                allow_missing_secrets=args.allow_missing_secrets,
                                signing_key=key)
    except BackupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
