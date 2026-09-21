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
| `allowed_actions` | Per-device allowlist for optional actions (package checks, disk rescues); none are enabled by default. |
| `important_paths` | Paths whose read-only mounts are critical. |
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

Check kinds are `http_get`, `http_head`, and `tcp`. `expected_status` accepts a
single code or a list, `pattern` is an optional response-body regular expression,
and `critical` escalates a failing check from a warning alert to a critical one.
Probes are passive and read-only, run on the collection scheduler (never from a
web request), honor per-check intervals, and are capped at 20 checks per device.
Failing checks open a single `probe_failed` alert per device (naming every
offending check) with the normal acknowledge/mute/resolve lifecycle, and
latency plus failure counts are sampled into `integration_metrics`.

`integration_polling.probe_seconds` (default 30) is the base scheduler tick;
individual checks still honor their own `interval_seconds`.

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

## Web console and APIs

Primary pages are `/`, `/devices/<id>`, `/integrations`, `/adsb`, `/displays`,
`/software`, `/network-inventory`, `/alerts`, `/events`, `/audit`, `/settings`,
`/settings/status`, `/agents`, `/workspaces`, `/jobs`, and `/jobs/approvals`.

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
GET /api/events
GET /api/export/<kind>?device=&range=24h&format=csv&limit=10000
GET /api/database/status
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
| `pinoc/development.py` | Enrollment, agent authentication, workspace/job policy, and artifacts. |
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
