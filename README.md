# PiNOC 2.0

PiNOC is a Raspberry Pi network-operations console for monitoring and safely
managing a fleet of Pis. A single background backend collects local, SSH, and
legacy telemetry into a thread-safe cache used by the responsive web console.
SQLite adds durable metrics, alerts,
events, actions, audit records, and the optional outbound-agent development
workflow.

PiNOC is designed for a trusted private network. It does not make SSH or remote
HTTP calls while serving a web request, and a failed collector cannot stop the
other collection domains.

## What PiNOC provides

- **Fleet monitoring:** stable device identities; local and bounded concurrent
  SSH collection; CPU, temperature, memory, storage, storage-media wear and
  I/O-error status, networking, systemd services, Raspberry Pi power/throttling
  state, roles, tags, and Cockpit links.
- **Operational history:** SQLite/WAL storage, configurable sampling and
  retention, graphs, storage forecasts, transition events, persistent alert
  lifecycles (active, acknowledged, muted, and resolved), outbound alert
  notifications (ntfy, e-mail, webhooks), CSV/JSON export, Prometheus
  scraping, and configurable alert runbooks (playbooks).
- **Application integrations:** ADS-B, desk displays, MagicMirror, ICS Modifier,
  pi-hotspot, WireGuard, Samba, RAID, SMART/NVMe health, packages, Git, optional
  passive LAN inventory, and user-defined HTTP/TCP probes for arbitrary services.
- **Safe administration:** optional users and API tokens, role/scoped
  authorization, CSRF protection, allowlisted service and power actions,
  maintenance windows, configuration backups, and an audit log.
- **Remote development gateway:** optional outbound-only agents, one-use
  enrollment, restricted workspaces, approved test profiles, bounded output and
  artifacts, explicit state-changing approvals, cancellation, and matrix jobs.
- **Web operations console:** a responsive, accessible Flask/Waitress interface
  with fleet health summaries, fleet-wide aggregates (average CPU, memory, and
  temperature; storage totals with growth forecast; combined network throughput;
  uptime range) plus a 24-hour trend chart, search and filters, device
  drill-downs, history, integrations, alerts, events, safe actions, and
  development workflows.

## Architecture

```text
 local commands     bounded SSH     legacy HTTP/sensors     outbound agents
       \                 |                 /                       |
        +---------- collection scheduler/cache -------------------+
                              |
                  normalized PiNOC state
                              |
                    history queue
                              |
                         SQLite/WAL
                              |
               Flask/Waitress web + cached APIs
```

Collectors use explicit timeouts and independent schedules. HTTP handlers read
cached state or persistent records; safe actions and development jobs are
queued rather than executed in request threads. Failed attempts preserve the
last successful snapshot and separately record attempt time, collector status,
and a sanitized error.

## Requirements

- Raspberry Pi OS or another Debian-family system with systemd
- Python 3 and a virtual environment (the installer installs system and Python
  dependencies from `requirements.txt`)
- SSH key access from the PiNOC service user to remotely collected devices
- Optional I²C environmental sensor hardware
- Optional WireGuard tools, Cockpit, and remote application services

The supplied installer must run as root through `sudo` and assumes the checkout
belongs to `${SUDO_USER}` (or `pi` when `SUDO_USER` is unavailable).

## Quick start

```sh
git clone <repository-url> PiNOC
cd PiNOC
cp .env.example .env
chmod 600 .env
cp config/devices.example.json config/devices.json
python3 -m pinoc.validate_config
sudo ./install.sh
```

The installer configures authentication and the web port, installs dependencies,
enables I²C for optional environmental sensors, creates the virtual
environment; provisions CM5 SSH key access; installs the WireGuard sudoers rule;
and enables/restarts `pi-noc.service`.

If authentication was enabled, create the first administrator before exposing
the listener:

```sh
sudo -u pi .venv/bin/python -m pinoc.admin create-user \
  --role administrator admin
```

Replace `pi` with the installation user. Open
`http://<pinoc-host>:8088/` (or the configured port). PiNOC serves plain HTTP by
default; use a TLS reverse proxy before exposing it beyond a trusted LAN. When
using a reverse proxy, set `authentication.trusted_proxy_count` to the exact
number of proxies in front of PiNOC and prevent clients from reaching PiNOC
directly. Leave it at `0` for direct connections; forwarded client-address
headers are then ignored.

### Upgrade

Preserve `.env`, `config.json`, `config/devices.json`, and `data/pinoc.db`, pull
or copy the new checkout, and rerun:

```sh
python3 -m pinoc.validate_config
sudo ./install.sh
```

Database migrations are ordered and automatic. Do not delete a database after a
migration or corruption error; first preserve the database and its `-wal` and
`-shm` companions and investigate a copy.

## Configuration

PiNOC reads `config.json` from the repository root. Frontend and secret values
in `.env` override the corresponding runtime settings.

### Environment values

```dotenv
CM5_SSH_PASS=                # temporary/runtime password fallback; keys preferred
PINOC_WEB_HOST=0.0.0.0
PINOC_WEB_PORT=8088
PINOC_DATABASE_PATH=         # empty uses data/pinoc.db
PINOC_AUTH_ENABLED=0
PINOC_SECRET_KEY=            # long random value; changing it ends browser sessions
PINOC_SECURE_COOKIE=0        # set to 1 only behind HTTPS
```

Protect `.env` with mode `0600`. Do not put passwords in device JSON. The
installer uses `CM5_SSH_PASS` only as a compatibility/provisioning fallback;
normal SSH collection uses keys and `BatchMode=yes`.

A device that needs password auth of its own, instead of sharing
`CM5_SSH_PASS` with the rest of the fleet, can get its own credential: set
`SSH_PASS_<DEVICE_ID>` in `.env` (the device's `id`, uppercased, with any
run of non-alphanumeric characters collapsed to a single underscore --
e.g. `cm5-file-server` becomes `SSH_PASS_CM5_FILE_SERVER`). A device with
its own entry uses only that password; every other device keeps falling
back to `CM5_SSH_PASS` if set. This keeps one compromised device's SSH
credential from exposing every other password-auth device's too.

### Main configuration groups

| Setting | Default | Purpose |
| --- | ---: | --- |
| `web_host`, `web_port` | `0.0.0.0`, `8088` | Web listener values. PiNOC always starts its web console. |
| `authentication.enabled` | `false` | Authentication fallback; `PINOC_AUTH_ENABLED` takes precedence. |
| `security.rate_limit.*` | see `config.json` | Login lockout (window, max failed attempts, lockout) and the unauthenticated `/api/*` 429 window. |
| `polling.*` | 10–60 s | Independent fleet, local, network, remote, service, storage, sensor, and temperature schedules. |
| `polling.log_tail_seconds` / `log_tail_lines` | `300` / `50` | Journal-tail capture cadence and per-unit line count (1–200). |
| `history.log_ring_samples` | `50` | Service-log samples kept per device/unit ring buffer. |
| `fleet_max_workers` | `4` | Maximum concurrent fleet collection workers. |
| `ssh_command_timeout` | `8` s | Per-device SSH command timeout. |
| `health_thresholds` | see `config.json` | Live CPU, memory, temperature, disk, stale, and offline thresholds. |
| `history.*` | enabled | Database path, sample intervals, retention, maintenance, and alert thresholds. |
| `notifications.*` | disabled | Severity filters and ntfy/SMTP/webhook channels for alert open/resolve transitions. |
| `integration_polling.*` | integration-specific | Integration collection intervals. |
| `development_gateway.*` | bounded defaults | Job timeouts, output, file-read, artifact, and offline limits. |
| `remote_*`, `raid_device` | legacy CM5 defaults | Backward-compatible file-server collection. |
| `remote_temp_monitor` | enabled | Temperature endpoint, timeout, freshness, optional shared secret, and SSH settings for system metrics from discovered devices. |
| `inside_sensor` | auto | BME280, BME680/BME688, or SHT4x detection. |
| `vpn_*` | WireGuard defaults | Interface/service, handshake freshness, and Wi-Fi networks where VPN is optional. |
| `lan_inventory` | disabled | Passive inventory source; PiNOC does not actively scan the LAN. |

When `remote_temp_monitor.collect_system_metrics` is enabled, PiNOC uses each
authenticated temperature record's `ip` field to collect CPU, memory, storage,
services, and uptime over SSH. Set `shared_secret` on PiNOC and the temperature
monitor so the snapshot HMAC can be verified; unsigned or incorrectly signed
records remain visible as temperature data but are never scheduled for SSH.
The defaults use `pi` on port 22. Configure passwordless SSH
for the PiNOC service account, or provide the existing `CM5_SSH_PASS` environment
secret when every discovered device shares that password. Devices already
declared in `config/devices.json` retain their explicit SSH settings and are
merged with matching temperature records by address or hostname.

Run the validator after every manual configuration change. It applies the same
full rules the web settings editor uses, checking every group the service
parses at startup — polling intervals, `authentication` (including
`trusted_proxy_count`), `security.rate_limit`, playbooks, notifications, and
fleet devices —
so an invalid value cannot pass the preflight check and still fail startup:

```sh
python3 -m pinoc.validate_config
```

The web settings editor redacts managed secrets, writes atomically, retains
numbered backups, and reports when a restart is required.

## Fleet devices

Copy `config/devices.example.json` to `config/devices.json`. Its top-level
`devices` array uses ordinary JSON (comments are not supported). Important
fields include:

| Field | Meaning |
| --- | --- |
| `id` | Persistent API/URL identity. Use a stable slug, never an IP address. |
| `hostname`, `friendly_name`, `address` | System name, display label, and SSH/network destination. |
| `collection_method` | `local` or `ssh`; normally only one entry is local. |
| `ssh_user`, `ssh_port` | Remote SSH account and port. |
| `roles`, `tags`, `notes` | Classification, filtering, and operator context. |
| `monitored_services`, `critical_services` | Observed systemd units; critical units are automatically monitored. |
| `manageable_services` | Explicit allowlist for safe service actions. |
| `allowed_actions` | Per-device allowlist for optional actions (package checks, apt updates, disk rescues); none are enabled by default. |
| `important_paths` | Paths whose read-only mounts are critical. |
| `expected_listeners` | Optional `"tcp:22"`/`"udp:53"`-style baseline for listener-change alerting (see [Security-surface monitoring](#security-surface-monitoring)); omit/empty to collect the inventory without alerting on it. |
| `config_drift` | Optional expected-state baseline (units, file hashes, sshd options) for [Configuration drift detection](#configuration-drift-detection-and-repair); omit/empty to skip drift checks entirely. |
| `thresholds` | Per-device live health threshold overrides. |
| `integrations` | Per-integration enablement and options. |
| `repositories` | Named, configured Git working trees for read-only status. |
| `cockpit_*` | Direct Cockpit link settings; PiNOC never proxies Cockpit. |

When `id` is omitted, PiNOC derives a lowercase slug from `hostname`; an
explicit ID is recommended. Unknown role strings and tags remain available for
labels and filters. Critical services are folded into monitored services.

If `config/devices.json` is absent, the legacy `remote_host`, `remote_user`,
`remote_ssh_port`, `remote_paths`, `raid_device`, and `remote_device_id` settings
still create the CM5 file-server view. With a devices file, a non-duplicated
legacy CM5 may also be added so upgrades can be gradual.

Provision and verify an SSH key as the systemd service user:

```sh
sudo -u pi ssh-copy-id -p 22 pi@device.local
sudo -u pi ssh -o BatchMode=yes -p 22 pi@device.local true
```

### Onboarding wizard (device discovery)

Administrators can add devices from the web console instead of hand-editing
`config/devices.json`, at **Onboarding** in the navigation
(`/onboarding`, gated like Settings):

1. **Scan** reads the local kernel ARP table (`/proc/net/arp`) and anything
   the host's `avahi-browse` daemon has already heard over mDNS. This is
   passive only -- nothing is actively probed or swept across an address
   range -- and proposes candidate hosts (IP, MAC, hostname, advertised
   mDNS services).
2. **Fingerprint selected** runs a bounded, read-only SSH session (default
   20 hosts per batch, a few seconds per host) against the candidates you
   check, reusing the same `ssh`/`sshpass` machinery
   `pinoc/collectors/fleet.py` already uses for fleet polling. It detects
   hostname, OS/kernel/architecture, and a short allowlist of known service
   units, and suggests a role, tags, and monitored/critical services from
   what it finds (an ADS-B receiver's `piaware.service`, a file server's
   `smbd.service`, and so on).
3. **Review and confirm** shows the suggested `config/devices.json` entry
   for each successfully fingerprinted host as editable JSON. Adding a
   device (individually, or all shown at once) writes through the same
   validated device-parsing path `load_devices()` itself uses
   (`pinoc.config_store.save_devices`); an invalid entry is rejected with
   nothing written, so the existing device store is never corrupted.
   Confirming an `id` that already exists updates that device in place
   rather than duplicating it. Restart PiNOC afterwards to start collecting
   from newly added devices.

`avahi-browse` (part of `avahi-utils`) is optional -- when it isn't
installed, discovery falls back to the ARP table alone.

## Health, alerts, events, and history

Live health is computed once in the backend. Default warnings begin above 70%
CPU, 80% memory, 70 °C, or 80% disk. Critical conditions include temperatures
above 80 °C, disks above 95%, current undervoltage/throttling, important
read-only storage, degraded RAID, storage media reporting kernel I/O errors, and
failed critical services. One warning is
`warning`; multiple warnings or telemetry older than 30 seconds is `degraded`;
telemetry older than 120 seconds is `offline`. Maintenance suppresses normal
health evaluation but does not make never-successful telemetry healthy.

The durable alert engine additionally supports hysteresis and sustained
conditions under `history.thresholds`. A stable fingerprint updates an existing
unresolved occurrence rather than opening one per poll. Recovery resolves the
occurrence and records an event. A later recurrence opens a new occurrence.

### Alert playbooks (runbooks)

The optional top-level `playbooks` list attaches operator runbooks to alert
types. Each entry needs an `id`, an `alert_type` (exact match, or a type
prefix such as `critical_`), a `title`, and a markdown `markdown` body (up to
20,000 characters); `actions` (up to 10, restricted to the safe-action
registry) and `links` (up to 10, http(s) or relative URLs) are optional, and
at most 50 playbooks are loaded. A `Runbook` button appears on matching alert
rows in the web console, rendering the markdown, links, and one-click safe
actions (service actions target the resource recorded on the alert; actions
the registry marks `strong` — reboot, shutdown, service stop — require
typing the target to confirm before they are queued). Invalid
entries fail `validate_config`; the runtime loader drops them so a bad entry
cannot break the console. `GET /api/playbooks` returns the loaded list.

#### Automatic remediation (self-healing)

A playbook may add an optional `remediation` block so a known-safe fix runs
without waiting for someone to click the runbook button:

```json
"remediation": {
  "action": "service.restart",
  "policy": "auto",
  "cooldown_seconds": 900,
  "max_attempts": 3,
  "respect_maintenance": true
}
```

- `action` (required) is one action from the same safe-action registry as
  `actions` above; an optional `target` pins a static target (a log path, a
  journal-vacuum spec, ...) — service actions with no explicit `target`
  reuse the resource already recorded on the matching alert (e.g. the failed
  unit name), so one playbook covers every service it protects.
- `policy` is `"auto"` (run automatically) or `"approve"` (queue a
  pending decision instead of running). `"auto"` is only accepted for
  actions ActionDispatcher itself would run without a "strong" confirmation
  (service start/restart, a refresh, an integration restart, a package
  check, `apt.clean`/`apt.autoremove`); a reboot, a shutdown, a service
  stop, or a destructive disk rescue (`logs.truncate`, `journal.vacuum`,
  `cache.drop`) must use `"approve"`.
- `cooldown_seconds` (60–604800, default 900) and `max_attempts` (1–20,
  default 3) bound how often and how many times remediation retries the
  *same* alert (tracked per alert fingerprint, i.e. per device + alert type
  + resource); both reset once the alert resolves.
- `respect_maintenance` (default `true`) defers remediation — without
  spending an attempt — while the device is in a maintenance window.

Every run, automatic or approved, is enqueued through the same action queue,
job table, and audit trail as a manual click (`requested_by` is
`"remediation"` for automatic runs, or the approving operator for an
approved one) — there is no separate execution path. A device that recovers
resolves its alert exactly as it already did without remediation configured
(see the durable alert engine above); remediation only notices that and
resets its own attempt/cooldown bookkeeping for the next occurrence. A
pending `"approve"` decision shows on the alert's runbook panel with
Approve/Deny buttons; `GET /api/remediations` (optionally `?state=pending`
or `?device=<id>`) and `GET /api/devices/<id>/remediations` list live
remediation status, and `POST /api/remediations/<fingerprint>/approve` or
`/deny` decide a pending one.

SQLite defaults:

- Core and network samples every 60 seconds; storage and media-wear counters
every 300 seconds.
- Journal tails for each device's monitored/critical services (up to 10 units)
every 300 seconds (`polling.log_tail_seconds`), at most 50 lines per unit
(`polling.log_tail_lines`, 1–200).
- Raw data retained 7 days, hourly aggregates 90 days, and daily aggregates 365
  days.
- WAL mode and a busy timeout; database failures degrade history without
  stopping live monitoring.
- Storage forecasts require at least three sufficiently separated samples and
  distinguish insufficient, stable, decreasing, and growing series.

Back up the live database with SQLite's online backup API:

```sh
python3 -m pinoc.database backup /safe/path/pinoc-backup.db \
  --database data/pinoc.db
```

### Backup/restore bundles (one file = one instance)

`pinoc backup` packages a whole PiNOC instance into a single signed tar:
`config.json`, `config/devices.json` (when present), `env-manifest.txt` (the
`.env` **key names only — values never enter a bundle**), an online SQLite
backup, and a `bundle.json`/`bundle.sig` metadata pair. The signature is
HMAC-SHA256 when a signing key is set (environment `PINOC_BACKUP_KEY` by
default, overridable via `backups.signing_key_env`), otherwise a plain
SHA-256 digest; verification has no bypass.

```sh
# Export one bundle (also available as “Download backup” on the Settings page)
python3 -m pinoc.backup export -o /safe/path/pinoc-bundle.tar

# Restore: validates signature, schema version, and required .env secrets,
# audits the restore against the pre-restore database, then replaces
# config.json / config/devices.json / pinoc.db atomically while the service
# runs and audits the restored database as well. Type RESTORE (or --yes) to
# confirm; restart the service afterwards.
python3 -m pinoc.backup restore /safe/path/pinoc-bundle.tar --yes
```

Restore refuses a bundle that fails its signature, is from a newer PiNOC
schema, or references required secrets (for example `PINOC_SECRET_KEY` when
authentication is enabled) that are absent from the local `.env`; the missing
keys are listed and `--allow-missing-secrets` is the only way to proceed.

Scheduled remote backups read the `backups` section (default: disabled):

```json
"backups": {
  "enabled": true,
  "interval_hours": 24,
  "keep": 7,
  "signing_key_env": "PINOC_BACKUP_KEY",
  "destination": {"type": "path", "path": "/mnt/nas/pinoc"}
}
```

`destination.type` is `path` (any local, SMB, or NFS mount) or `ssh`
(`host`, `user`, `port`, `path`) for outbound copies; delivery uses fixed-argv
`scp`/`ssh`, rotates to `keep` bundles, and a failed run raises a `critical`
notification when notifications are configured. The Settings page shows the
schedule, last run, and size, with Download and Run-now controls (both
administrator-only and audited).

### Service logs (bounded journal tails)

Each device's monitored and critical services receive a bounded `journalctl`
tail. The collector requests journal output only on the low-frequency
`polling.log_tail_seconds` cycle (default 300 s) and never more than
`polling.log_tail_lines` lines per unit (1–200; default 50). The device-side
capture is further limited to the newest 200 lines and 64 KiB per unit, and
PiNOC caps each stored line at 512 characters. Apparent secrets — key material,
`password`/`token`/`api key`/`authorization` values, and `Bearer`
credentials — are redacted when the tail is stored and again when it is read
back. Between journal cycles the device keeps its most recent tail, so the Logs
panel always shows the latest capture.

Samples persist in the history database as a per-unit ring of
`history.log_ring_samples` (default 50) plus the normal raw retention. The
device page renders a **Service logs** panel with unit selection, refresh,
copy, and plain-text download, backed by `GET /api/devices/<id>/logs` (a
per-unit summary without `unit`, or the newest `samples` — 1 to 100, default
20 — line tails for one unit). The route requires `history.read` (token scope
`read:history`).

Use `python3 -m pinoc.database status --database PATH` for status. Run
`python3 -m pinoc.database vacuum --database PATH` only during a planned
maintenance window; routine retention does not vacuum.

### Alert notifications

The optional `notifications` section delivers a message when an alert opens
or resolves. `open_severities` and `resolve_severities` (subsets of
`info`, `warning`, `degraded`, `critical`; empty lists notify for every
severity) filter transitions, and `channels` lists up to one entry per
destination. Delivery is queued on a background worker — alert reconciliation
and the web console never block on a remote endpoint — with per-channel
sent/failed counters surfaced in the settings UI.

```json
{
  "notifications": {
    "enabled": true,
    "open_severities": ["warning", "critical"],
    "resolve_severities": ["critical"],
    "channels": [
      {"id": "ntfy", "kind": "ntfy", "url": "https://ntfy.example.com", "topic": "pinoc"},
      {"id": "mail", "kind": "smtp", "host": "mail.example.com", "port": 587,
       "username": "pinoc", "password": "…", "from": "pinoc@example.com",
       "to": ["ops@example.com"], "starttls": true},
      {"id": "webhook", "kind": "webhook", "url": "https://hooks.example.com/pinoc"}
    ]
  }
}
```

- `ntfy` posts the message body with an `X-Title` header to `{url}/{topic}`
  (critical alerts use the high ntfy priority; optional `tags` list maps to
  `X-Tags`).
- `smtp` uses Python's `smtplib`; `starttls` and `username`/`password`
  (SMTP AUTH) are optional.
- `webhook` POSTs a JSON object: `source`, `transition`, `device_id`,
  `device_name`, `alert_type`, `severity`, `subject`, and `body`.

The web settings page (`/settings`) shows live channel status with one-click
test messages and an editor for this section; `GET /api/notifications`
returns the redacted status and `POST /api/notifications/test` with a
`{"channel": "<id>"}` body sends a test synchronously — both require the
`config.write` permission (administrator). Channel credentials live in
`config.json`, which the service writes with 0600 mode; the settings API
redacts secret-valued keys and restores them on save. Configuration changes
apply after a restart. While a device is in maintenance, alert transitions
are neither opened, resolved, nor notified.

### Alert correlation & common-cause grouping

A single shared cause — a Wi-Fi access point dropping, a switch reboot, a
power blip — can open near-identical alerts on many devices at once. The
history writer clusters open alerts that share a trigger class (e.g.
"connectivity", "temperature", "power") and the same Wi-Fi SSID,
gateway/WAN interface, or `/24` IP subnet, within a rolling time window.

This is a grouping layer only: it is conservative by design and never
merges, suppresses, or changes the lifecycle of an individual alert — every
alert keeps its own row, and its own acknowledge/mute/resolve state. A
cluster is a label (`alerts.cluster_id`) attached to alerts that appear to
share a cause, exposed at `GET /api/alert-clusters` (`?state=all` includes
resolved clusters) and shown on `/alerts` as a collapsible card listing the
member devices and the specific shared context that grouped them (e.g.
`Wi-Fi SSID "HomeWiFi"` or `gateway 192.168.1.1`). Notifications (see above)
fire once per cluster transition instead of once per member: the first
alert in a burst still notifies individually (nothing to correlate with
yet), and subsequent members that join the cluster within the window are
folded into that one notification instead of paging separately.

Enabled by default with conservative settings; override via the optional
`alert_correlation` section:

```json
{
  "alert_correlation": {
    "enabled": true,
    "window_seconds": 300,
    "min_members": 2
  }
}
```

- `window_seconds` (30–3600, default 300) — how close in time alerts must
  be to correlate, and how long a cluster keeps accepting new members after
  its last update.
- `min_members` (2–100, default 2) — minimum distinct devices required
  before alerts are presented as a cluster; below that they remain
  ordinary, individually notified alerts.

### Incident timelines and automatic post-mortems

After a multi-alert incident resolves, the story is otherwise scattered
across the alerts, events, audit, and notification history. PiNOC turns a
resolved correlated alert cluster — or any standalone alert that resolves
on its own — into a single **incident** record: a reconstructed
chronological timeline of every alert open/acknowledge/resolve transition,
related device events, action jobs, and notification sends, plus computed
MTTA (time to first acknowledgment), MTTR (time to resolution), and the
devices involved.

Incidents are synthesized automatically the moment a cluster or alert
resolves (hooked into the same history-writer reconcile pass that already
detects the resolution — no separate polling loop) and appear on the
**Incidents** page (`/incidents`), filterable by device, severity, and
resolved-date range. Each incident's detail page (`/incidents/<id>`) shows
the full timeline and can be exported as Markdown or JSON, or opened as a
standalone printable HTML page (`/api/incidents/<id>/print` — use the
browser's own Print/Save-as-PDF). A resolved alert on `/alerts` links
straight to its incident once one has been synthesized.

The incident record itself only stores identifying references (which
cluster/alert it came from, the devices and alert IDs involved, and the
computed MTTA/MTTR) — the timeline is reconstructed at read time from the
existing `alerts`, `events`, `action_jobs`, and `notification_log` tables,
never duplicated. `notification_log` is a small persisted record of every
outbound notification send (see "Alert notifications" above), added so a
resolved incident's timeline still shows what was actually sent after a
restart.

APIs: `GET /api/incidents` (filters: `device`, `severity`, `since`,
`until`, plus the usual `page`/`limit`), `GET /api/incidents/<id>`, and
`GET /api/incidents/<id>/export.md` / `export.json` / `print`.

### Network topology (device-to-device ping matrix)

Per-device network metrics can look normal on every device individually even
when a faulty router, a degraded Wi-Fi SSID, or a sick switch segment is the
real cause — link-level evidence needs a device-to-device view. Optional and
off by default; enable it with a `network_topology` section:

```json
{
  "network_topology": {
    "enabled": true,
    "gateway": "192.168.1.1",
    "segments": [
      {"name": "upstairs", "gateway": "192.168.1.1", "devices": ["pinoc", "piawaren"]},
      {"name": "downstairs", "devices": ["cm5-file-server"]}
    ],
    "pairs": [["pinoc", "piawaren"], ["pinoc", "cm5-file-server"]],
    "max_pairs": 40,
    "interval_seconds": 60,
    "ping_count": 3,
    "ping_timeout_seconds": 2,
    "thresholds": {
      "latency_warning_ms": 80,
      "latency_critical_ms": 250,
      "loss_warning_percent": 5,
      "persistence_samples": 3
    }
  }
}
```

- `segments` (optional) — the logical topology: a gateway plus named groups
  of device ids. Omit it to auto-derive segments from devices that share a
  `tags` value (two or more devices per shared tag; anything left over falls
  into one catch-all `"lan"` segment) — this reuses the existing per-device
  `tags` from `config/devices.json` rather than a separate inventory.
- `pairs` (optional) — the exact device-id pairs to sample. Omit it to
  auto-derive a bounded, `max_pairs`-capped chain of consecutive devices
  within each segment (never every device paired with every other one).
  Either way the pair set is always capped at `max_pairs` (default 40, max
  500), so a large fleet never turns into an O(n²) ping mesh.
- Sampling runs **from the source device** over SSH (`ping -c ... <target>`,
  like the fleet collector already reaches every device), except when the
  source is the local PiNOC host, which pings directly — so a sample
  measures genuine device-to-device reachability, on the `interval_seconds`
  schedule, into the same history database as every other metric
  (`network_matrix_samples`).
- A pair only counts as **degraded** once its last `persistence_samples`
  consecutive samples (default 3) all breach `latency_warning_ms` /
  `loss_warning_percent` — a single lost ping or slow reply is normal
  jitter, not a bad link. A segment is degraded when any of its owned pairs
  is; `latency_critical_ms` or a failed ping marks it critical.
- The `/topology` page renders the resulting gateway + segment view and the
  raw pair matrix (latency, loss, status), backed by `GET
  /api/network-topology`.
- A device whose segment is currently degraded feeds that into
  [alert correlation](#alert-correlation--common-cause-grouping) as one more
  shared-cause hint (alongside Wi-Fi SSID, gateway, and IP subnet) — so
  alerts on otherwise unrelated devices that share a bad segment can still
  cluster into one explainable card instead of looking unrelated.

## Integrations

Roles activate sensible integration defaults:

- `adsb_receiver` → ADS-B
- `desk_display` → desk display and Git
- `magicmirror` → MagicMirror, ICS Modifier, pi-hotspot, and Git
- `hotspot` → pi-hotspot
- `vpn_server` → WireGuard
- `file_server` → Samba, RAID, and disk health

A device's `integrations` object can enable, disable, or configure individual
integrations. Package and Git views are configuration-driven; arbitrary
repositories are not discovered for execution. Integration results are
normalized in the cache with status, source, attempt/success timestamps,
duration, sanitized data/errors, and only explicitly available safe actions.
Application health avoids duplicating conditions already owned by generic
service monitoring.

#### Probes (user-defined checks)

Any device can declare read-only health checks that run **from the PiNOC host**
on their own intervals:

```json
"integrations": {
  "probe": {
    "enabled": true,
    "checks": [
      {"name": "api", "kind": "http_get",
       "url": "http://192.168.1.50:8080/health",
       "timeout_seconds": 5, "interval_seconds": 60,
       "expected_status": 200, "pattern": "\\\"status\\\":\\\"ok\\\""},
      {"name": "database", "kind": "tcp",
       "host": "192.168.1.50", "port": 5432, "critical": true}
    ]
  }
}
```

Check kinds are `http_get`, `http_head`, `tcp`, and `tls_cert`. `expected_status`
accepts a single code or a list, `pattern` is an optional response-body regular
expression, and `critical` escalates a failing check from a warning alert to a
critical one. Probes are passive and read-only, run on the collection scheduler
(never from a web request), honor per-check intervals, and are capped at 20
checks per device. Failing `http_get`/`http_head`/`tcp` checks open a single
`probe_failed` alert per device (naming every offending check) with the normal
acknowledge/mute/resolve lifecycle, and latency plus failure counts are sampled
into `integration_metrics`. `tls_cert` checks (below) open their own
`cert_expiry` alert instead, so an approaching certificate expiry reads as its
own explainable condition rather than a generic probe failure.

`integration_polling.probe_seconds` (default 30) is the base scheduler tick;
individual checks still honor their own `interval_seconds`.

### Security-surface monitoring

Every device's fleet poll gathers a bounded, read-only "security" signal set
alongside its normal metrics: a recent failed-SSH-login count and the current
listening TCP/UDP port inventory (`ss -tlnp`/`ss -ulnp`). Both are bounded and
rate-limited, and both surface in the API/UI like any other integration
(`integrations.security`) and open alerts through the same lifecycle as every
other alert type:

- **`auth_fail`** — opens when recent failed SSH login attempts (read from
  `journalctl`/`auth.log`, bounded to the last ~30 minutes / 500 lines, on the
  same low-frequency cadence as the existing journal tail) reach
  `security_monitoring.auth_fail_warning` (default 5), escalates to critical
  at `auth_fail_critical` (default 20), and needs to drop back below
  `auth_fail_warning - auth_fail_hysteresis` (default hysteresis 2) before it
  closes — the same open/close-band hysteresis the temperature and disk-usage
  alerts already use.
- **`listener_change`** — compares the live listener inventory against a
  device's optional `expected_listeners` list (see below); an unexpected port
  or a missing expected one must persist for
  `security_monitoring.listener_change_duration_seconds` (default 60s) before
  it opens, so a single flapping service doesn't spam an alert. A device with
  no `expected_listeners` configured is never alerted on (its inventory is
  still collected and visible, just not compared against anything).
- **`cert_expiry`** — see the `tls_cert` probe kind above: a 30/7/1-day
  info/warning/critical severity ladder as a configured certificate's expiry
  approaches.

```json
{
  "expected_listeners": ["tcp:22", "tcp:9090", "udp:53"]
}
```

is a per-device field (sibling of `important_paths`), and
`security_monitoring` is a top-level `config.json` section:

```json
"security_monitoring": {
  "auth_fail_warning": 5,
  "auth_fail_critical": 20,
  "auth_fail_hysteresis": 2,
  "listener_change_duration_seconds": 60
}
```

### Configuration drift detection and repair

PiNOC watches liveness (a service is up, a host answers) but, without this,
never notices a *correctness* regression: an sshd option flipped back to an
insecure default, a critical unit silently disabled or masked, or a tuned
config file reverted to its distro default. A device's optional
`config_drift` field declares the expected-state baseline PiNOC should hold
it to:

```json
"config_drift": {
  "expected_units": ["ssh.service"],
  "expected_files": {
    "/etc/ssh/sshd_config": "44c91857f34b1ec68e246ebcbad66c4b9380b41c3490c719bdfd6696ba7b40b5"
  },
  "expected_sshd_options": {
    "PermitRootLogin": "no",
    "PasswordAuthentication": "no"
  }
}
```

is a per-device field (sibling of `expected_listeners`): `expected_units`
(bounded to 20) must be enabled and not masked/disabled; `expected_files`
(bounded to 10) maps an absolute path to its expected `sha256sum` output;
`expected_sshd_options` (bounded to 25) maps an sshd config key to its
expected effective value. All three are optional and independent; a device
with none configured never runs a drift check at all.

Collection extends the same fleet poll used for everything else:
unit-enabled state rides along in the existing `systemctl show` call on
every poll (cheap), while file hashes and the effective sshd configuration
(`sshd -T`) run on their own low-frequency, bounded cadence
(`drift_check_seconds`, default 300s) — the same "expensive check, its own
cadence" pattern `packages`/the journal tail already use. A file's content
is only ever fetched up to 64 KiB and its hash is always recomputed locally
from the fetched bytes, never trusted from the remote side.

Any mismatch opens a single **`config_drift`** alert per device through the
normal alert lifecycle (open → acknowledge/mute → resolve), distinct from a
liveness/service-failure alert, carrying a readable expected-vs-found diff
as its message, one line per drifted item:

```text
unit ssh.service: expected 'enabled', found 'disabled'
file /etc/ssh/sshd_config: expected '44c91857f34b', found '9f2c7a10e881'
sshd option permitrootlogin: expected 'no', found 'yes'
```

It resolves automatically once everything matches again, exactly like any
other alert type.

Repair is only ever available through two allowlisted actions (per-device
`allowed_actions`, same opt-in pattern as [disk rescue
actions](#disk-rescue-actions)), each bounded to exactly what that device's
own `config_drift` spec names — never an arbitrary unit or path:

| Action | Effect | Target |
| --- | --- | --- |
| `config_drift.reenable_unit` | `systemctl unmask` (best-effort) then `systemctl enable` | A unit listed in this device's `expected_units` |
| `config_drift.restore_file` | Restores a file from its last known-good capture | A path listed in this device's `expected_files` |

Whenever a drift-checked file's live content matches its configured
expected hash, PiNOC opportunistically captures that content (still capped
at 64 KiB) as a "known-good" snapshot in a small local store
(`config_snapshots`, keyed by device + path) — see `pinoc/backup.py`. This
is what `config_drift.restore_file` restores from: it refuses to run until
a snapshot whose hash matches the currently configured `expected_files`
value exists, so it can never write back stale or unverified content.
**Scope cut:** only text files are restored (content is written back over
SSH as UTF-8); a file is never captured, and restore is refused, until it
has been observed once in its known-good state — there is no seeding from
elsewhere (e.g. the signed system backup bundle above, which only covers
PiNOC's own config/database, not arbitrary device files).

## Scheduled actions (cron-style)

Administrators can queue any action from the safe-action registry to run on a
schedule: weekly service restarts, daily package checks, log truncation, and
so on. Schedules live in the history database (`action_schedules`) and are
managed in the **Scheduled actions** panel on the Settings page. A background
thread ticks every 30 seconds, reconciles the outcomes of previously queued
jobs, and dispatches any schedule whose next run has passed through the same
action queue as manually requested actions — with the same registry checks,
target approval, and audit trail. Scheduler dispatches are recorded as
`scheduler`/administrator; a manual Run-now is recorded under the requesting
operator.

Firing specs accept three forms:

- standard five-field cron — `minute hour day-of-month month day-of-week`,
  supporting `*`, `*/n`, ranges, and comma lists (e.g. `0 3 * * *` for 03:00
daily);
- aliases — `@hourly`, `@daily`/`@midnight`, `@weekly`, `@monthly`, `@yearly`;
- a one-shot — `once:<ISO-8601 timestamp>`, which fires a single time and is
then consumed.

Each schedule carries its own IANA timezone (default `UTC`); the spec is
evaluated in that zone. Creation and updates validate the action against the
registry, the device's approval for its target, the spec's syntax, and that
the spec fires within two years.

Failure handling: a dispatch failure (for example an offline device or a
target that is no longer approved) retries after 5 minutes; a job that ends in
a non-success state is re-evaluated at the next scheduled slot — destructive
actions are never retried in a tight loop. Three consecutive failures
automatically pause the schedule, record a critical `schedule_failed` event,
and enqueue a notification; the counter resets on the first success. A paused
schedule never dispatches on its own until an administrator resumes it, but it
can always be run manually.

All routes require the `config.write` permission (administrator) and are
audited:

```text
GET    /api/schedules                   list schedules and scheduler status
POST   /api/schedules                   create {device_id, action, spec, target?, timezone?}
PUT    /api/schedules/<id>              pause/resume, or change spec/target
                                         (resuming or changing the spec resets the failure counter)
POST   /api/schedules/<id>/run          queue one run immediately without
                                         touching the next scheduled slot
DELETE /api/schedules/<id>              delete (already-queued jobs are left intact)
```

## Staged fleet updates (rolling apt upgrades)

Administrators can roll apt updates across a set of devices in waves instead
of upgrading and rebooting them one at a time, or all at once with no way to
stop a bad rollout mid-flight. A run is started from the **Staged fleet
updates** panel on the Settings page (or the API below) with:

- **scope** — `security` (delegates to `unattended-upgrade`'s own
  security-origin allowlist) or `all` (`apt-get upgrade`);
- **device selection** — by role and/or tag (matching how other fleet-wide
  features select devices); a device must also list `apt.upgrade` in its own
  `allowed_actions` (see [Disk rescue actions](#disk-rescue-actions) for the
  same per-device opt-in pattern);
- **wave plan** — an explicit canary count (the first N selected devices, by
  id) updates first; everything else follows in one wave, or, with a wave
  size set, in successive fixed-size waves.

A background thread (`pinoc/rollout.py`, `RolloutService`) ticks every 20
seconds and walks the plan: each device's `apt.upgrade` is queued through the
same action dispatcher, queue, and audit trail as a manual or scheduled
action, and only while that device reports being inside its own configured
maintenance window (the same per-device maintenance state used elsewhere).
When an update leaves a reboot pending (`/var/run/reboot-required`, the
practical Debian/Ubuntu proxy for "a new kernel needs a reboot to take
effect"), the device is rebooted and re-verified once it comes back online.
A wave only advances once every device in it reports healthy (not
`critical`); if any device's update, reboot, or post-update health check
fails, the rollout halts immediately — later waves never run — and a
critical notification is enqueued over the existing notification path, the
same as a repeatedly failing schedule.

Each run's per-device results (wave, status, before/after kernel and
pending-update count, timestamps, any error) and its rollout summary are
kept in the history database (`rollout_runs`/`rollout_devices`) and shown in
the panel; an administrator can cancel a running rollout, which halts it the
same way a failed health gate would (devices already mid-update finish, but
no further wave starts).

All routes require the `config.write` permission (administrator) and are
audited:

```text
GET    /api/rollouts                    list rollout runs
POST   /api/rollouts                    start a run {scope, roles?, tags?, device_ids?,
                                         canary_device_ids?, canary_count?, wave_size?,
                                         respect_maintenance?}
GET    /api/rollouts/<run_id>           run detail: the run, its per-device rows, and a summary
POST   /api/rollouts/<run_id>/cancel    halt a running rollout
```

## Anomaly detection (statistical baselines)

Static thresholds structurally miss the gradual or below-threshold class of
problems: a slow memory leak that climbs to 84%, a crypto miner idling at 60%
CPU, or a nightly traffic spike three times the norm. The optional
`anomaly_detection` section runs a statistical analyzer in the history writer:
it keeps an EWMA mean/variance baseline per device and metric (plus
hour-of-day buckets for seasonality) and flags samples that deviate from it by
a configurable z-score.

```json
"anomaly_detection": {
  "enabled": false,          /* master switch; off by default */
  "alerting": false,         /* false = preview-only, true = real anomaly alerts */
  "z_open": 3.5,             /* open when |z| is at least this */
  "z_hysteresis": 2.5,       /* keep open while |z| is at least this */
  "min_samples": 50,         /* baseline must see this many samples first */
  "ewma_alpha": 0.03,        /* learning rate (0..1) */
  "outlier_limit": 8.0,      /* |z| beyond this does not update the baseline */
  "hourly_seasonality": true,
  "max_baseline_age_seconds": 86400,
  "severity": "warning",
  "preview_keep": 200,
  "metrics": {
    "memory_percent": {"enabled": true, "z_open": 3.5, "z_hysteresis": 2.5},
    "rx_rate_bps": {"enabled": false}
  }
}
```

Tracked metrics are CPU utilization, 1-minute load, CPU temperature, memory
utilization, and network receive/transmit rates; each can be switched off or
given its own z-scores in `metrics`. Detected deviations reuse the durable
alert engine verbatim: a distinct `anomaly` alert type fingerprinted per
device and metric, with hysteresis (a value that drifts back under
`z_hysteresis` resolves the alert), the normal acknowledge/mute/resolve
lifecycle, events, and notifications. Anomalies respect maintenance windows.

Outlier rejection protects the always-live global baseline: a sample whose
|z| against it reaches `outlier_limit` updates recency but not the global
mean or variance, so a single spike cannot distort the primary reference.
Hour-of-day buckets absorb every sample — their variance self-normalizes, so
a genuinely different hour-of-day regime bootstraps and self-heals. Baselines
not refreshed within `max_baseline_age_seconds` (a long device gap) re-learn
before judging again. Start with `"enabled": true, "alerting": false`
(preview): deviations are recorded in a bounded ring shown on the Settings
page's Anomaly detection panel (`GET /api/anomalies`) with each baseline's
sample maturity. Once the noise level looks acceptable, set `"alerting": true`
(restart required) to open real alerts.

## Console self-monitoring

PiNOC also watches itself. A background service (`pinoc/self_monitoring.py`,
config section `self_monitoring`) ticks on an interval and computes six
signals: per-domain **collector success rate** and **cache staleness** (both
read straight from the collector scheduler's own per-task run bookkeeping —
consecutive failures, last successful run — since a domain's last successful
collector run is exactly when its results were published into the shared
state cache), **history database size and retention** (is `maintenance()`'s
retention cleanup still running on schedule, and how close is the database
file to a configured size ceiling), **scheduler tick lag** (how far behind
its due time a collector task actually started, plus a heartbeat check that
catches a fully stalled scheduler thread), **agent reachability** (last-seen
staleness per row of the `agents` table), and **queued-action depth**
(pending/running `action_jobs`, by count and by oldest-queued age).

A crossed threshold opens an alert through the *same* `alerts` table and
open/resolve lifecycle every device alert uses — same acknowledge/mute path,
same alerts page, same notification channels — tagged onto a synthetic
`pinoc-console` device id with alert types prefixed `console_self_` (e.g.
`console_self_collector_failing`, `console_self_cache_stale`,
`console_self_database_size`, `console_self_database_retention_lag`,
`console_self_scheduler_lag`, `console_self_agent_offline`,
`console_self_action_queue_backlog`) so they read at a glance as being about
the console itself, not a monitored device. Recovery resolves them the same
way a device alert recovers.

```json
"self_monitoring": {
  "interval_seconds": 30,
  "consecutive_failure_threshold": 3,
  "cache_stale_multiplier": 3.0,
  "database_size_ceiling_bytes": 2147483648,
  "database_retention_stale_seconds": 7200,
  "scheduler_heartbeat_stale_seconds": 30,
  "scheduler_lag_seconds": 30,
  "agent_offline_seconds": 600,
  "queue_backlog_depth": 20,
  "queue_backlog_age_seconds": 900
}
```

All signals are rendered together on `/console-status`
(`GET /api/console-status`, gated the same as `/settings/status`). That
existing page stays scoped to the history database specifically;
`/console-status` is the console's overall health.

## SLOs and reliability scoring

Device health (`pinoc/health.py`) is an instant snapshot — healthy, warning,
degraded, critical, or offline — plus alerts, with no view of whether a
device, role, or tag is actually meeting an availability target *over
time*. `pinoc/slo.py` adds that: define one or more SLOs in the top-level
`slos` config section, each a target percentage over a rolling window for a
scope (one device, every device with a given role, or every device with a
given tag), and PiNOC computes rolling attainment and error-budget burn rate
from a new `health_samples` history table (a lightweight point-in-time
health sample HistoryManager writes on every poll — nothing else in PiNOC
persists health at arbitrary past timestamps, so a 30-day rolling window
needed its own table, kept independently of `device_metrics`'s much shorter
7-day raw retention).

Burn-rate alerting uses the standard SRE two-window approach: a short "fast"
window and a longer "slow" window are both expressed as a multiple of the
steady, sustainable burn rate (1.0x means "exactly using up the whole error
budget by the end of the SLO window"); an alert opens only when *both*
windows are burning too fast at once, which catches a real outage quickly
without paging on one brief blip. This is a simplified, single-pair version
of Google's multi-window multi-burn-rate alerting (which typically pairs a
page-now tier with a slower ticket-now tier) — an MVP simplification.

```json
"slos": {
  "enabled": true,
  "interval_seconds": 60,
  "sample_retention_days": 35,
  "definitions": [
    {
      "id": "core-uptime",
      "name": "Core fleet uptime",
      "scope": {"type": "role", "value": "pinoc"},
      "target_percent": 99.5,
      "window_days": 30,
      "severity": "critical",
      "burn_rate": {
        "fast_window_minutes": 60, "fast_threshold": 14.4,
        "slow_window_minutes": 360, "slow_threshold": 6
      }
    },
    {
      "id": "display-tag-uptime",
      "name": "Display devices uptime",
      "scope": {"type": "tag", "value": "display"},
      "target_percent": 99,
      "window_days": 7
    }
  ]
}
```

`scope.type` is `device` (an exact device id), `role`, or `tag` (matching
`config/devices.json` entries — see `config/devices.example.json`); `role`/
`tag` scopes are pooled across every matching device (summed good/bad time,
not averaged per device), so "critical services >= 99% over 30 days" reads
as fleet-wide availability across that whole scope. `burn_rate` is optional
and defaults to the classic 30-day-window constants shown above (2%
consumed in 1h, or 5% in 6h). A crossed threshold opens an alert through the
*same* `alerts` table and open/resolve lifecycle every device alert uses —
tagged onto a synthetic `pinoc-slo` device id, alert type `slo_burn` — so it
shows up on the alerts page and through every configured notification
channel exactly like a device alert does.

Reliability scores and error-budget bars are available two ways: a
`slo_summary` dashboard card (`pinoc/dashboards.py`'s card library — add it
to any `/dashboards` layout or the `/glance` view) showing one SLO's rolling
attainment and remaining error budget, and a dedicated `/slos` page
(`GET /api/slos`, `GET /api/slos/<id>`) listing every configured SLO's
attainment, target/window, error-budget bar, and fast/slow burn rate in one
table — useful when there are more SLOs than fit comfortably as cards.

## Scheduled fleet health reports

Export (`/api/export/<kind>`) and backup bundles are both on-demand, so
operators only learn about slow trends — filling disks, accumulating
warnings, drifting patch levels — when they remember to open the console.
`pinoc/reports.py` adds a recurring state-of-the-fleet document: define one
or more reports in the top-level `reports` config section, each with a
firing schedule, a scope, a set of content sections, an output format, and
an audience notification channel. Firing reuses `pinoc/schedules.py`'s
cron/alias/one-shot spec parsing directly (no second scheduler), and
delivery reuses the *exact* ntfy/SMTP/webhook channel implementations
`pinoc/notifications.py` already has (via a new
`NotificationService.send_direct` method) — no second delivery mechanism.

```json
"reports": {
  "enabled": true,
  "interval_seconds": 60,
  "edition_retention": 90,
  "definitions": [
    {
      "id": "weekly-fleet",
      "name": "Weekly fleet health",
      "spec": "@weekly",
      "timezone": "UTC",
      "scope": {"type": "fleet"},
      "channel_id": "ops",
      "sections": ["uptime", "alerts", "capacity", "storage_media", "patch_status"],
      "format": "html",
      "window_days": 7
    }
  ]
}
```

`scope.type` is `fleet` (every device), `role`, or `tag` (same matching as
SLO scopes above); `channel_id` must reference an id in
`notifications.channels[]` — reports piggyback on whatever ntfy/SMTP/webhook
channels are already configured, rather than adding a second set of
delivery credentials. Each firing renders the chosen `sections` from data
every other feature already computes — uptime/attainment from the same
`health_samples` table `pinoc/slo.py` reads, the open-alert summary from the
`alerts` table, per-mount capacity forecasts from
`pinoc.history.storage_forecast` (the same function `/api/devices/<id>/storage/forecast`
uses), storage-media health from the live device snapshot (the same signal
that opens `media_io_errors` alerts), and patch status from live package
metadata plus the most recent `pinoc/rollout.py` run touching each device —
into an HTML or CSV edition, archived in a new `report_editions` table.
Delivery through the configured channel is a short plain-text summary (open
alert count, mounts filling up, devices with pending updates, ...) rather
than the full document, since ntfy/SMTP/webhook are plain-text channels; the
full edition is viewed or downloaded from the `/reports` page
(`GET /api/reports`, `POST /api/reports/<id>/run`, `GET /api/reports/editions`,
`GET /api/reports/editions/<id>/download`). PDF rendering is deliberately
out of scope for this MVP — an HTML edition opens standalone and downloads
via the browser's own Print/Save-as-PDF, the same way `pinoc/incidents.py`'s
printable view avoids a PDF dependency.

## Web console and APIs

Primary pages are `/`, `/devices/<id>`, `/integrations`, `/adsb`, `/displays`,
`/software`, `/network-inventory`, `/alerts`, `/events`, `/audit`, `/settings`,
`/settings/status`, `/console-status`, `/agents`, `/workspaces`, `/jobs`,
`/jobs/approvals`, `/dashboards`, `/glance`, `/slos`, and `/reports`.

### Customizable dashboards, saved views, and Glance

`/dashboards` is a personal dashboard composer: add cards from a fixed
library (device health, a specific device metric, fleet summary counts,
active-alert counts, a fleet-wide aggregate, the fleet storage-growth
forecast, or a short active-alerts list), reorder them, and save the layout
as a named preset. Each saved dashboard gets a stable id and a shareable URL
(`/dashboards/<id>`), viewable by its owner. `/glance` renders one preset —
or, with no `?preset=<id>`, a sensible default (fleet summary, active-alert
count, and the worst-health devices) — as a fixed-viewport, chrome-free page
with large tiles and a 30-second auto-refresh, for a TV or desk display
alongside the `desk_display` integration. The fleet page's own filter bar
gets the same treatment: save the current search/health/role/sort
combination as a named view and reapply it with one click.

Presets are per-user data stored in the `user_presets` table (see `GET/POST
/api/dashboards`, `GET/PUT/DELETE /api/dashboards/<id>`, `GET
/api/dashboards/<id>/data`, `POST /api/dashboards/preview` for the
composer's live preview, `GET/POST /api/fleet-filters`, and `GET/PUT/DELETE
/api/fleet-filters/<id>`); a saved dashboard is only readable by the user who
saved it. `GET /api/card-library` lists the available card types and the
config fields each one accepts.

Frequently used read APIs:

```text
GET /health
GET /api/status
GET /api/devices
GET /api/devices/<id>
GET /api/devices/<id>/services
GET /api/devices/<id>/integrations[/<name>]
GET /api/integrations
GET /api/adsb
GET /api/displays
GET /api/deployments
GET /api/software
GET /api/network-inventory
GET /api/devices/<id>/metrics?range=24h
GET /api/devices/<id>/logs[?unit=&samples=20]
GET /api/devices/<id>/integrations/probe
GET /api/devices/<id>/storage/forecast
GET /api/alerts[?state=active]
GET /api/alert-clusters[?state=all]
GET /api/events
GET /api/export/<kind>?device=&range=24h&format=csv&limit=10000
GET /api/database/status
GET /api/console-status
```

Fleet queries accept `health`, `role`, and `tag` filters. Event and alert APIs
support bounded pagination and relevant device/type/severity/state filters.
Allowed metric ranges are `1h`, `6h`, `24h`, `7d`, and `30d`.

The dashboard's `GET /api/overview` also returns an `aggregates` object:
fleet-wide rollups (online count, average CPU/memory/temperature, storage
totals and average usage, summed network rates, uptime range) computed from
the live state cache, plus — when the caller holds `history.read` — a 24-hour
sparkline and a storage-growth forecast (the shortest time-to-full across the
most-used mounts).

The export API returns a whole history table as a CSV download (the default)
or a JSON object with the same range and device filters. Kinds are `metrics`,
`storage`, `network`, `services`, `integrations`, `alerts`, and `events` (the
corresponding SQLite tables, newest rows first for alerts and events).
`limit` defaults to 10000 rows and is capped at 50000; metric kinds require
`history.read` and the alerts kind requires `alerts.read` (token scopes
`read:history` / `read:alerts`). CSV cells whose text begins with a formula
character (`=`, `+`, `-`, or `@`) — including when hidden behind leading
tab, carriage-return, or line-feed characters — are prefixed with an
apostrophe so a spreadsheet viewer stores them as text instead of
evaluating them (CSV injection); numeric cells and JSON output are exported
as-is.

A Prometheus endpoint is served at `GET /metrics` (text format 0.0.4) with
fleet totals, per-device health/up/CPU/memory/disk/uptime, failed-service and
media-error gauges, open alert counts by severity and state, and history
database state. When authentication is enabled, create a read-only token and
scrape with its Bearer credential. The `pinoc_alerts_total` series is only
exported to identities with the alerts-read permission (browser sessions or
tokens carrying `read:alerts`), so a fleet-only token does not leak alert
data; the fleet and device gauges remain available to `read:fleet`. The
`pinoc_device_services_failed` gauge counts every monitored service whose
state is not `running`/`activating`, matching the health evaluator:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: pinoc
    metrics_path: /metrics
    static_configs:
      - targets: ["pinoc.example:8401"]
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/pinoc-token
```

Management endpoints include alert acknowledgement/mute, cached refresh,
allowlisted service operations, administrator-only reboot/shutdown, integration
actions, maintenance/expected-offline state, settings, users, tokens, action
jobs, and audit records. Consult `pinoc/web/app.py` for the authoritative route
list and request shapes.

## Authentication and safe management

When authentication is disabled, every client that can reach PiNOC receives the
synthetic `trusted-lan` administrator identity. Mutating browser requests still
require the session CSRF token. **Do not bind an unauthenticated instance to an
untrusted network.**

Roles are:

- **viewer:** fleet, history, and alert reads
- **operator:** viewer access plus alert lifecycle, maintenance, refresh, and
  approved safe actions
- **administrator:** operator access plus power, settings, users, tokens,
  approvals, and development administration

Local account/token commands:

```sh
python3 -m pinoc.admin create-user --role administrator USER
python3 -m pinoc.admin reset-password USER
python3 -m pinoc.admin disable-user USER
python3 -m pinoc.admin list-users
python3 -m pinoc.admin create-token USER --scope read:fleet
python3 -m pinoc.admin revoke-token TOKEN_ID
```

Passwords are hashed; tokens and agent credentials are displayed once and only
hashes are stored. API token scopes include fleet/history/alert reads, alert
writes, safe actions, configuration administration, and the `dev:*` scopes.
Optional device, workspace, and job-type restrictions further narrow
development tokens. Browser sessions use HTTP-only, SameSite cookies; enable
`PINOC_SECURE_COOKIE=1` only when HTTPS is actually in use.

Failed logins are rate limited per source address and username: after
`security.rate_limit.login_max_failed` failures for one address and username, or
`login_max_failed_per_source` failures from one address across all usernames,
within `login_window_seconds`, the matching account key or source is locked for
`lockout_seconds` and the login endpoint answers `429` instead of rendering the
form. The lockout transition writes a single `auth.lockout` audit record. A
successful login clears its per-account failure window and lockout; source-wide
failures remain in their sliding window so rotating usernames cannot bypass the
CPU safeguard. When authentication is enabled, unauthenticated
`/api/*` requests are limited to `api_max_unauthenticated` per
`api_window_seconds` per address and then receive `429` with a `Retry-After`
header before the usual `401`; token and session requests are not counted
against this limit. Behind a reverse proxy these address-based controls require
an accurately configured `authentication.trusted_proxy_count`; only enable it
when direct access to PiNOC is blocked, since trusting forwarded headers from
untrusted clients permits address spoofing.

Actions accept structured identifiers only, use fixed argv arrays without a
shell, and enforce configured service/integration allowlists. Device power is
administrator-only and expected-offline state is cleared if dispatch fails.
Audit records capture actor, role/token, source, target, authorization,
outcome, duration, and redacted errors.

### Disk rescue actions

Five recovery actions close the loop on the most common physical pressure
(filesystem nearly full, log or cache bloat). Each executes on the device
through the same fixed-argv, no-shell executor, requires operator or higher
(token scope `execute:safe_actions`), and — unlike the built-in service and
power actions — must be explicitly allowlisted per device via
`allowed_actions` in `config/devices.json`; none are enabled by default.

| Action | Effect | Optional target | Confirmation |
| --- | --- | --- | --- |
| `apt.clean` | Removes cached package files (`apt-get clean`) | — | Confirm |
| `apt.autoremove` | Simulates `apt-get autoremove` and reports the count; no changes | — | Confirm |
| `logs.truncate` | Truncates one log file; without a target, the largest `*.log` under `/var/log` | A path under `/var/log` or a declared `important_paths` entry | Strong |
| `journal.vacuum` | `journalctl --vacuum-size=…` / `--vacuum-time=…` (default `time:7d`) | e.g. `size:100M`, `time:7d` | Strong |
| `cache.drop` | Writes 3 to `/proc/sys/vm/drop_caches` | — | Strong |

Completed jobs record a bounded summary in `action_jobs` and the audit log —
for example space freed from before/after `df` reads, the number of packages
a simulation would remove, or the journal size before and after. Rescue
buttons appear on a device's Safe actions panel (and in alert runbooks) only
when the device allowlists the action, and strong actions require a typed
confirmation before they are queued.

## Optional outbound agent and development gateway

The `pinoc-agent` has no inbound listener and runs unprivileged. It polls PiNOC
over HTTPS, signs requests with its per-agent HMAC credential, and executes only
the policy envelope of an approved workspace. SSH-only monitored devices remain
fully supported.

### Install and enroll

1. Enable PiNOC authentication and put PiNOC behind HTTPS.
2. Create a one-use enrollment code (10 minutes in this example):

   ```sh
   curl -H 'Authorization: Bearer ADMIN_TOKEN' \
     -H 'Content-Type: application/json' \
     -d '{"device_id":"square","ttl_seconds":600}' \
     https://pinoc.example/api/v1/dev/agents/enrollment-codes
   ```

3. On the target Pi:

   ```sh
   sudo ./install_agent.sh https://pinoc.example ONE_TIME_CODE /home/pi /opt
   ```

4. Confirm the identity and capabilities at `/agents`, then explicitly approve
   workspaces and test profiles. Candidate repositories are informational and
   are never automatically approved.

The installer creates a locked `pinoc-agent` account, `/opt/pinoc-agent`, a
mode-0750 `/etc/pinoc-agent`, a mode-0600 credential configuration, and a
hardened systemd service. `allow_insecure_http` exists only for isolated local
testing and exposes credentials and job traffic in plaintext.

Remove the agent with `sudo ./uninstall_agent.sh --confirm`; workspaces are
preserved. Agent credentials can be rotated or revoked independently.

### Execution policy

Approved workspaces specify an absolute root, target device, mode, execution
user, allowed job types/commands/environment, named test profiles, service
allowlists, artifacts, sensitive patterns, and hardware requirements.
Client-supplied paths must be relative. The agent resolves paths canonically,
rejects traversal, absolute paths, symlink escapes, non-regular reads, and
secret-like files. File reads are UTF-8 and size bounded.

Generic commands require development mode, `dev:command`, and an allowlisted
bare executable. Shells, privilege tools, environment wrappers, executable
paths, Git configuration aliases, destructive Git operations, and exec-style
options are rejected. Named tests use administrator-approved argv/environment/
timeout definitions. State-changing hardware tests also require `dev:hardware`
and explicit approval. Output, file reads, artifacts, counts, runtime, processes,
file descriptors, memory, and file size are bounded. Cancellation terminates the
process group. PiNOC provides no unrestricted shell, filesystem-write endpoint,
SSH-key export, automatic pull/reset/rollback, or root agent.

## Operations and troubleshooting

```sh
sudo systemctl status pi-noc.service --no-pager --full
sudo journalctl -u pi-noc.service -b -n 100 --no-pager
sudo systemctl show pi-noc.service -p NRestarts -p ExecMainCode -p ExecMainStatus
sudo ss -ltnp '( sport = :8088 )'
curl -v --connect-timeout 5 http://127.0.0.1:8088/health
```

- **Web unavailable:** verify the configured host/port, the systemd
  environment file, journal, listener, and loopback request before debugging
  VLAN/client-isolation/firewall paths. Use `http://` unless a TLS proxy exists.
- **Device offline:** validate configuration and test key SSH as the service
  user. Check DNS/mDNS, host keys, firewall, WireGuard requirements, and
  `logs/pinoc.log`.
- **Empty optional telemetry:** missing `vcgencmd`, thermal sysfs, `iw`,
  `smbstatus`, SMART/NVMe utilities, or application data is represented as an
  unavailable capability rather than crashing collection.
- **No environmental readings:** check the remote endpoint timeout/freshness or
  inspect I²C with `i2cdetect -y 1` and verify sensor type/address settings.
- **Database degraded:** check `/api/database/status`, permissions, disk space,
  and logs. Live monitoring continues without history.

## Uninstall

```sh
sudo ./uninstall.sh
```

The uninstaller stops/disables PiNOC and removes the installed unit, managed
WireGuard sudoers rule, and virtual environment. It intentionally preserves the
checkout, `.env`, configuration, logs, database, history, alerts, events, audit,
and job data. Back up and remove preserved data manually only when intended.

## Repository layout

| Path | Purpose |
| --- | --- |
| `pi_noc.py` | Web-only process, legacy collectors, and shared scheduler. |
| `pinoc_agent.py` | Unprivileged outbound development agent. |
| `pinoc/collectors/` | Fleet collection, parsing, scheduling, and failure isolation. |
| `pinoc/integrations/` | Role/application normalizers. |
| `pinoc/web/` | Flask app, Jinja templates, CSS, and browser JavaScript. |
| `pinoc/database.py`, `pinoc/history.py` | Migrations, persistence, history, events, alerts, and forecasts. |
| `pinoc/security.py`, `pinoc/actions.py` | Authentication, authorization, CSRF, audit, and safe actions. |
| `pinoc/dashboards.py` | Card library, card-data resolution, and preset persistence for `/dashboards` and `/glance`. |
| `pinoc/development.py` | Enrollment, agent authentication, workspace/job policy, and artifacts. |
| `pinoc/self_monitoring.py` | Console self-monitoring: collector health, cache staleness, database, scheduler lag, agent reachability, action-queue depth, and `console_self_*` alerts. |
| `pinoc/incidents.py` | Incident timelines and automatic post-mortems: synthesizes an incident record on cluster/alert resolution and reconstructs its timeline plus MTTA/MTTR for `/incidents`. |
| `pinoc/slo.py` | SLOs and reliability scoring: rolling attainment, error-budget burn rate, and `slo_burn` alerts, from the `health_samples` history table. |
| `config.json`, `config/devices.example.json`, `.env.example` | Runtime and fleet configuration examples. |
| `install.sh`, `uninstall.sh` | Main service lifecycle. |
| `install_agent.sh`, `uninstall_agent.sh` | Optional agent lifecycle. |
| `tests/` | Unit, integration, security, installer, and milestone regression tests. |

## Development and verification

```sh
python3 -m pytest -q
python3 -m unittest discover -s tests -v
python3 -m compileall -q pi_noc.py pinoc pinoc_agent.py tests
bash -n install.sh uninstall.sh install_agent.sh uninstall_agent.sh pinoc-device-setup.sh
python3 -m json.tool config.json >/dev/null
python3 -m json.tool config/devices.example.json >/dev/null
```

The test suite covers the shared cache, scheduler isolation, local/SSH parsing,
health, history, migrations, alerts, integrations, safe actions, authentication,
CSRF, agent enrollment and replay protection, workspace restrictions, execution
limits, artifacts, cancellation, installer dependencies, web-only runtime imports, and web console behavior.
