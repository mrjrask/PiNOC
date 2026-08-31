# PiNOC 2.0

PiNOC is a centralized Raspberry Pi network operations console with one shared,
cached monitoring backend and two frontends: a responsive web console and the
existing Adafruit 128x64 OLED Bonnet or Pimoroni Display HAT Mini. Milestone 2
adds true multi-device local/SSH fleet monitoring while preserving the established
WireGuard, CM5/file-server, RAID, SMB, storage, local Pi, remote-temperature,
and StemmaQT sensor pages.

## Architecture

```text
                          bounded background work
┌──────────────────────────────────────────────────────────┐
│ Collectors: bounded local/SSH fleet, WireGuard, legacy   │
│ CM5/RAID/SMB, temperatures, and environmental sensor     │
└───────────────────────────┬──────────────────────────────┘
                            ▼
                 ┌──────────────────────┐
                 │ thread-safe PiNOC    │
                 │ current-state cache  │
                 └──────────┬───────────┘
                         ┌──┴───────────────┐
                         ▼                  ▼
              Flask/Waitress web     Physical display
              (cache reads only)     (cache reads only)
```

HTTP requests never run SSH, subprocesses, probes, or remote HTTP calls. The
background coordinator catches collection-cycle failures, retains the service,
and publishes normalized devices with persistent configured IDs rather than
using IP addresses as identity. Current state is in memory; database history is
a Milestone 3 feature.

## Features and URLs

* Responsive fleet dashboard: `http://<pinoc-host>:8088/`
* Device details: `/devices/<device_id>`
* Health probe: `GET /health`
* Cached REST API: `GET /api/status`, `/api/devices`,
  `/api/devices/<id>`, `/api/devices/<id>/services`, and `/api/alerts`
* Fleet summary counts for online/healthy/warning/degraded/critical/offline,
  failed services, and updates (fields are already stable for later collectors).
* Existing physical pages and controls remain: Summary, WireGuard, RAID,
  Storage, CM5 Server, Samba, Remote Temps, Desk Pi, Sensors, and Network.
* Explicit command timeouts, SSH connection limits, and remote HTTP timeouts.
* Rotating runtime/collector logging in `logs/pinoc.log` (three 1 MB backups).

## Repository layout

| Path | Purpose |
| --- | --- |
| `pi_noc.py` | Compatibility entry point, existing collection/display implementation, and unified process orchestration. |
| `pinoc/models.py` | Normalized, JSON-safe device model. |
| `pinoc/state.py` | Locked current-state cache and fleet summaries. |
| `pinoc/collectors/base.py` | Collector interface and failure-isolated background coordinator. |
| `pinoc/legacy.py` | Adapter from existing snapshots to normalized fleet devices. |
| `pinoc/web/` | Flask app, cached API, Jinja pages, responsive CSS, and lightweight JavaScript. |
| `config.json` / `.env` | Backward-compatible monitoring and frontend configuration. |
| `install.sh` / `uninstall.sh` | Raspberry Pi install and safe component removal. |
| `pi-noc.service` | Unified collector, web, and optional display systemd unit. |

## Configuration

Existing `config.json` keys remain supported. Important defaults are:

| Key | Default | Meaning |
| --- | --- | --- |
| `polling.local_seconds` | `10` | Local health collection interval. |
| `polling.network_seconds` | `10` | WireGuard/network collection interval. |
| `polling.remote_health_seconds` | `10` | CM5 health collection interval. |
| `polling.service_seconds` | `15` | Remote SMB/service collection interval. |
| `polling.storage_seconds` | `60` | Remote disk and RAID collection interval. |
| `polling.sensor_seconds` | `10` | Local environmental sensor interval. |
| `web_enabled` | `true` | Config fallback for the integrated web console. |
| `web_host` / `web_port` | `0.0.0.0` / `8088` | Web listener. |
| `remote_device_id` | `cm5-file-server` | Optional stable remote identity. |
| `remote_host`, `remote_user`, `remote_ssh_port` | existing values | CM5 SSH target. |
| `remote_paths` | configured paths | Remote filesystems to collect. |
| `raid_device` | `md0` | Array parsed from remote `/proc/mdstat`. |
| `vpn_interface`, `vpn_service`, `vpn_stale_seconds` | `wg0`, `wg-quick@wg0.service`, `150` | WireGuard monitoring. |
| `vpn_optional_wifi_networks` | `wiffy`, `wiffyToo` | LANs on which the VPN is not required. |
| `remote_temp_monitor` | enabled | Endpoint, interval/age metadata, and explicit HTTP timeout. |
| `inside_sensor` | enabled/auto | BME280, BME680/BME688, or SHT4x probing. |

Environment values take precedence for frontends:

```dotenv
DISPLAY=ADA_BONNET                 # or PIM_DHM
PINOC_DISPLAY_ENABLED=1            # 0 supports a headless web deployment
PINOC_WEB_ENABLED=1
PINOC_WEB_HOST=0.0.0.0
PINOC_WEB_PORT=8088
CM5_SSH_PASS=                      # optional provisioning fallback; keys preferred
```

The installer still provisions an Ed25519 key. If `CM5_SSH_PASS` is absent at
runtime, SSH uses key-only `BatchMode=yes`; the password behavior remains as a
backward-compatible fallback. Keep `.env` mode-restricted.

Normalized devices include identity, roles/tags, CPU, hardware health, memory,
storage, network, services, applications, Cockpit links, collector-domain
status, collection timestamps, and centralized health reasons.

## Adding devices

Copy `config/devices.example.json` to `config/devices.json` and edit its standard
JSON `devices` array. JSON comments are not supported; put explanations in the
device `notes` field or documentation. Validate before restarting:

```bash
cp config/devices.example.json config/devices.json
python3 -m pinoc.validate_config
sudo systemctl restart pi-noc
```

Each device should have an explicit, persistent `id`; it is the API and URL
identity and must not be an IP address. When omitted, PiNOC derives a lowercase
slug from `hostname` (for example `ADS-B North` becomes `ads-b-north`), so DHCP
address changes do not alter identity. `friendly_name` is the prominent label,
with hostname beneath it. `roles` can contain `file_server`, `vpn_server`,
`adsb_receiver`, `desk_display`, `magicmirror`, `pinoc`, `hotspot`, or `general`.
Unknown role strings and arbitrary tags are retained for labeling and filters.

Both `local` and `ssh` collection methods produce the same cached schema. There
should normally be one `local` entry. SSH supports DNS names, mDNS names, or IPs,
custom `ssh_user` and `ssh_port`, an 8-second default command timeout, and a
bounded four-worker pool. PiNOC prefers SSH keys and uses `BatchMode=yes`.
`CM5_SSH_PASS` remains a deprecated provisioning/runtime fallback via `sshpass`;
never place a password in device JSON. Provision keys with `ssh-copy-id -p 22
pi@host` and test the connection as the service user.

Example device:

```json
{
  "id": "piawaren",
  "hostname": "piawaren",
  "friendly_name": "ADS-B North",
  "address": "piawaren.local",
  "collection_method": "ssh",
  "ssh_user": "pi",
  "ssh_port": 22,
  "roles": ["adsb_receiver"],
  "tags": ["adsb", "upstairs"],
  "cockpit_enabled": true,
  "cockpit_scheme": "https",
  "cockpit_port": 9090,
  "monitored_services": ["piaware.service", "dump1090-fa.service", "cockpit.socket"],
  "critical_services": ["piaware.service", "dump1090-fa.service"],
  "notes": "North receiver"
}
```

Critical services are automatically included in monitored services. Service
rows expose systemd load/active/sub states, normalized state, PID, restart count,
and memory where systemd provides them. `service_discovery` reserves opt-in
PiNOC-relevant discovery behavior; manually listed services remain authoritative.
Cockpit is never proxied: **Open Cockpit** links directly to
`<scheme>://<cockpit_host-or-address>:<port>`.

## Health, freshness, and collection errors

Health is evaluated in one backend layer, never templates. Defaults are warning
above 70% CPU, 80% RAM, 70°C, or 80% disk; critical above 80°C or 95% disk, for
current undervoltage/throttling, read-only important storage, degraded legacy
RAID, or failed critical services. One warning is `warning`; multiple warnings
or telemetry older than 30 seconds is `degraded`; telemetry older than 120
seconds is `offline`. `maintenance` suppresses normal evaluation. Per-device
numeric `thresholds` are accepted as the forward-compatible override mechanism.
Failed attempts do not erase the last successful snapshot: `last_seen`,
`last_successful_collection`, `last_collection_attempt`, a safe error message,
and `collector_status` remain distinct. Missing `vcgencmd` or `iw` is treated as
an unavailable optional capability, not device failure.

## Fleet console and physical Fleet page

The dashboard automatically shows every cached device, eight summary cards,
numeric fleet highlights, case-insensitive search across names/IP/roles/tags/
services, and generated health/role filters. The API also accepts `health`,
`role`, and `tag` query parameters. Device pages contain overview, hardware,
CPU/temperature, memory, filtered filesystems, network, services, collector
status, roles/tags, notes, and an optional Cockpit action. The physical **Fleet**
page uses the same cache, shows online/total, friendly names, temperatures and
health symbols, and uses the existing scrolling controls on both display types.

## Legacy CM5 compatibility

If `config/devices.json` is absent, existing `remote_host`, `remote_user`,
`remote_ssh_port`, `remote_paths`, `raid_device`, `remote_device_id`, and
`CM5_SSH_PASS` settings are translated into a fleet device. If new-style devices
exist, a non-duplicated legacy CM5 is still added. The dedicated CM5 Server,
Storage, Samba, RAID, and WireGuard collectors/pages remain intact, so migration
can be gradual. Set the same explicit ID as `remote_device_id` to let the richer
new collector representation take precedence in generalized fleet views.

## Troubleshooting fleet devices

* Run `python3 -m pinoc.validate_config`; errors identify the device and field.
* For unreachable devices, test `ssh -o BatchMode=yes -p PORT USER@ADDRESS true`,
  then check DNS/mDNS, host keys, firewall, keys, and `logs/pinoc.log`.
* A slow host times out independently and cannot serialize the rest of the fleet.
* Empty temperature/Wi-Fi fields commonly mean `vcgencmd`/thermal sysfs/`iw` is
  unavailable; this is supported. Use DEBUG logging when diagnosing collectors.
* The web and API intentionally serve cached snapshots only; they never SSH.

## Installation and upgrade

1. Clone/copy the repository and review `config.json`.
2. Run `cp .env.example .env`, set `CM5_SSH_PASS` only if needed to provision an SSH key, and protect it
   with `chmod 600 .env`.
3. Run `sudo ./install.sh`. It prompts for physical-display enablement/type,
   web enablement, and web port while retaining the existing dependency, I2C,
   SPI, group, SSH-key, WireGuard sudoers, virtualenv, and systemd workflow.
   The unified environment always installs the lightweight Flask/Waitress web
   dependencies; the enable switch controls whether the listener runs.
4. Start with `sudo systemctl start pi-noc.service`, then visit port 8088.

**Migration from PiNOC 1.x:** pull/copy the new files, keep the existing `.env`
and `config.json`, add the optional frontend environment variables shown above,
and rerun `sudo ./install.sh` so Flask/Waitress are installed and the unified
service receives its environment file. No data migration is required in
Milestone 1. Existing display type, controls, CM5 password, SSH keys, paths,
sensors, and WireGuard configuration remain valid.

## Physical display controls

Adafruit left/right changes pages, up/down scrolls, center refreshes, Button B
toggles rotation, and holding Button A restarts configured WireGuard. Pimoroni
A/B moves pages, double-click A/B scrolls, X refreshes, Y toggles rotation, and
holding/triple-clicking A requests the same narrow WireGuard restart. Refresh
now signals the shared background coordinator; it does not create a second
collection path.

## Security, database, alerts, and administration

Milestone 1 provides read-only HTTP routes. Authentication, CSRF-protected safe
management actions, allowlisted services, and audit logging arrive in Milestone
5. Do not expose the listener to an untrusted network meanwhile. The existing
sudoers file permits only status/restart operations for the configured
WireGuard unit; the web API exposes no shell or action endpoint.

SQLite metrics/history, persistent alerts/events, retention, graphs, and
storage forecasting are Milestone 3. `/api/alerts` is a real cached read API but
is empty until alert production is implemented; current RAID state and errors
are fully exposed under the CM5 device applications today.

## Uninstallation

Run `sudo ./uninstall.sh`. It stops/disables the unit and removes the installed
unit, managed WireGuard sudoers rule, and virtualenv. It intentionally preserves
the checkout, `.env`, `config.json`, logs, and any future database/history.
Delete those only after making your own backup.

## Troubleshooting

* **Web unavailable:** inspect `PINOC_WEB_ENABLED`, host/port, `ss -ltnp`, and
  `journalctl -u pi-noc`; verify the selected port is not already used.
* **Display blank:** check `PINOC_DISPLAY_ENABLED`, `DISPLAY`, I2C/SPI, service
  group membership, cabling, and `display_address`.
* **CM5 offline:** test key SSH as the service user; check the fallback password,
  remote address/port, trusted Wi-Fi list, and WireGuard state.
* **SMB unavailable:** install/permit `smbstatus` remotely. **RAID unknown:**
  verify `raid_device` and remote `/proc/mdstat` readability.
* **No temperatures/sensor:** validate endpoint JSON/freshness/timeout or use
  `i2cdetect -y 1` and review sensor type/address configuration.
* **Collector error:** check `logs/pinoc.log`; an individual failure is isolated
  and the next background interval retries it.

## Development

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q pi_noc.py pinoc tests
bash -n install.sh
bash -n uninstall.sh
python3 -m json.tool config.json >/dev/null
```

## Milestone 2 baseline

Milestone 2 provided read-only current-state monitoring. The following section documents the durable Milestone 3 additions while later transport, application, and management work remains deferred.

## Milestone 3: durable history and operational awareness

PiNOC now attaches a bounded, serialized history queue after publication to the
live state cache. Collectors, current-state API routes, and both displays remain
independent of SQLite. If initialization, migration, locking, or a later write
fails, PiNOC logs the failure and continues in live/no-history mode; `/health`
and `/settings/status` expose the degraded database state.

### SQLite, migrations, and sampling

The default database is `data/pinoc.db`; set `PINOC_DATABASE_PATH` to an absolute
file path when another durable volume is preferred. The standard-library SQLite
driver uses WAL and a busy timeout. Ordered transactions recorded by
`schema_version` create `devices`, `device_metrics`, `storage_metrics`,
`network_metrics`, transition-only `service_status`, `alerts`, `events`, and
hourly/daily aggregate tables. Configuration is authoritative; persisted device
rows are observations tied to stable device IDs, not a second configuration.
Mount point is the stable storage-series key and systemd unit name is the stable
service key.

Live polls are not database sampling intervals. Defaults store core and network
samples every 60 seconds and storage every 300 seconds. Raw samples remain seven
days, idempotent hourly buckets remain 90 days, and daily buckets remain 365
days. Maintenance aggregates before deleting raw rows and never routinely runs
`VACUUM`. Run `python3 -m pinoc.database vacuum --database PATH` during a planned
maintenance window if compaction is required. Timestamps and numeric units are
UTC ISO-8601, Celsius, integer bytes, bytes/second, and percentages. Missing
samples remain gaps and are never interpolated.

### Graphs, APIs, and forecasts

Device pages asynchronously load CPU, temperature, memory, network, Wi-Fi, and
storage history with `1h`, `6h`, `24h`, `7d`, and `30d` controls, browser-local
timestamps, range summary statistics, empty-data handling, and bounded point
counts. Thirty-day requests automatically select hourly aggregates. Available
read APIs are:

* `GET /api/devices/<id>/metrics?range=24h`
* `GET /api/devices/<id>/storage/forecast`
* `GET /api/events` and `GET /api/devices/<id>/events`
* `GET /api/alerts` and `GET /api/alerts/<alert_id>`
* `POST /api/alerts/<id>/acknowledge`, `/mute`, and `/unmute`
* `GET /api/database/status`

Alerts/events accept bounded pagination (`page`, `limit`, default 50, maximum
200) and device/type/severity/state filters as applicable. History metric ranges
are deliberately allowlisted; the JSON response documents units and is suitable
for external export.

Storage forecasting uses the observed change between sufficiently separated
samples over up to 14 days. Fewer than three samples or less than half a day is
`insufficient`; near-zero growth is `stable`; negative growth is `decreasing`;
positive growth reports an approximate days-remaining value and a qualitative
confidence based only on sample count/span. It does not invent exact full dates.

### Alerts and health

The centralized alert engine evaluates connectivity, sustained CPU, temperature,
memory, disk capacity/read-only state, active Pi power/throttling bits, monitored
services, and RAID degradation. A stable `device:type:resource` fingerprint
updates one unresolved occurrence instead of inserting every poll. Recovery
marks that occurrence resolved and adds a recovery event; a later recurrence
creates a new occurrence, preserving history.

States are `active`, `acknowledged`, `muted`, and `resolved`. Acknowledgement
records time/actor without resolving the condition. Mute suppresses presentation
noise temporarily without collection loss. Automatically evaluated problems are
resolved only when telemetry clears them. Active severity (`info`, `warning`,
`degraded`, `critical`) is folded into cached health so health cannot be less
severe than its active alerts. Thresholds are configured under
`history.thresholds`; current defaults and per-device live health overrides
remain backward compatible. Temperature/disk configuration includes hysteresis
fields and CPU uses a configurable sustained duration. Maintenance-mode devices
remain a future scheduling hook rather than a new settings editor.

The `/alerts` page provides lifecycle filters and acknowledgement/mute actions.
The dashboard emphasizes active alerts, device payloads include active alert
indicators, and the physical `ALERTS` page uses the same persistent alert cache,
ordered critical, degraded, then warning. Display navigation dismisses a view
without acknowledging its durable alert.

### Events

Events are append-only notable transitions, not routine polls. PiNOC records
startup, first discovery, offline/returned-online, non-empty IP changes, uptime/
boot-time reboot evidence, monitored service changes and recoveries, alert
recoveries, and newly observed vcgencmd historical undervoltage, throttling,
frequency-cap, and soft-temperature-limit bits. `/events` provides the fleet
feed and every device page includes its recent timeline. Initial observations
seed prior state and do not fabricate IP changes or reboots.

### Backup, upgrade, and recovery

Use SQLite's online backup API while PiNOC is running:

```bash
python3 -m pinoc.database backup /safe/path/pinoc-backup.db --database data/pinoc.db
```

Upgrading from Milestone 2 preserves `config.json`, `.env`, live behavior, and
stable device identities. The installer creates the data parent with restricted
ownership and never removes an existing database. The uninstaller continues to
preserve checkout configuration, logs, alerts, events, and history by default.
The database initializes automatically and history begins at the first new
sample; Milestone 2 had no historical rows to migrate.

Never delete a database in response to a migration/corruption error. Stop PiNOC,
back up the file and its `-wal`/`-shm` companions, run SQLite integrity/recovery
tools on a copy, then move the damaged files aside only after preserving them.
Restarting creates a new history database while live monitoring remains usable.

## Milestone 3 non-goals / Milestone 4+

Intentionally deferred are role-specific ADS-B/application analytics,
desk-display/MagicMirror/ICS/hotspot management, package and Git dashboards,
remote service/reboot/shutdown actions, the configuration editor and user
management, a remote agent, Prometheus/Grafana, and active LAN scanning. No fake
UI or control endpoints for these later features are included.
