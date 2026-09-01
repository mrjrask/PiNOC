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
4. The installer enables and starts `pi-noc.service`. Visit the selected web
   port when the web console is enabled; reboot if newly enabled I2C or hardware
   group membership is not active yet.

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
* **Service crash-loops with `ImportError: libopenjp2.so.7`** from Pillow: the
  OpenJPEG runtime library is missing. Install it, then
  `sudo systemctl restart pi-noc`. On Raspberry Pi OS/Debian (bookworm or later)
  the package is `libopenjp2-7`; on older releases it is `libopenjp2-2.3`, and on
  Ubuntu `libopenjp2-7-1` or `libopenjp2-7-2`. Re-running `sudo ./install.sh`
  detects and installs it automatically. Verify with
  `/home/pi/PiNOC/.venv/bin/python -c "import PIL.Image"` and
  `ldconfig -p | grep openjp2`.
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

## Milestone 4: role-specific application intelligence

### Integration architecture

`pinoc.integrations` contains read-only, transport-neutral normalizers. Role activation is centralized in `base.py`; collectors attach normalized `IntegrationStatus` objects to `DeviceState.integrations`, so the cache—not Flask or Jinja—is the source for web, API, history, health, and display consumers. Results distinguish unavailable devices, unavailable/unsupported integrations, degraded applications, and healthy applications. Every status includes attempt/success timestamps, source, duration/error fields, a sanitized data object, and an intentionally empty `available_actions` list reserved for the bounded Milestone 5 action interface. This inventory also provides the capability/application context needed by a future Milestone 6 agent without implementing an agent or remote jobs.

Roles activate integrations as follows: `adsb_receiver` → ADS-B; `desk_display` → desk_display/Git; `magicmirror` → MagicMirror, ICS Modifier, pi-hotspot, and Git; `hotspot` → pi-hotspot; `vpn_server` → WireGuard; `file_server` → Samba, RAID, and disk health. Per-device `integrations` values can enable, disable, or configure an integration. A service condition is owned by generic service monitoring; an integration emits only a distinct data-path/application condition, preventing duplicate alerts.

```json
{
  "id": "receiver-north",
  "hostname": "piawaren",
  "collection_method": "ssh",
  "roles": ["adsb_receiver"],
  "monitored_services": ["piaware.service", "dump1090-fa.service"],
  "critical_services": ["piaware.service", "dump1090-fa.service"],
  "integrations": {
    "adsb": {"enabled": true, "critical": true, "interval_seconds": 15,
      "no_messages_seconds": 300},
    "packages": false
  },
  "repositories": [{"name": "receiver-config", "path": "/home/pi/receiver-config"}]
}
```

### ADS-B and displays

ADS-B parsers consume local dump1090-fa/SkyAware `aircraft.json` and `stats.json` shapes, including recent aircraft, positions, rates, range, IDs, and supported signal fields. `/adsb` and `/api/adsb` compare any number of receivers and calculate common/unique identifiers only when identifiers exist. `desk_display` accepts heterogeneous local status payloads and normalizes profile, screen, refresh, HTTP, and Git context. `/displays` exposes the cached fleet view; version groups describe differences without calling a majority “correct.” Sustained no-message/staleness conditions are intended to be configured rather than inferred from a momentary zero.

### MagicMirror, ICS Modifier, and pi-hotspot

MagicMirror supports PM2 JSON, configurable process names, restart/memory/uptime fields, lightweight HTTP results, and module inventory. ICS Modifier and pi-hotspot normalize their `/health` or `/status` responses, latency, refresh/failure details, hotspot state, uplink, and non-aggressively supplied client lists. Missing optional fields remain absent. Companion integrations remain separate and are linked by shared device context rather than copied.

### WireGuard, Samba, RAID, and disk health

WireGuard parses `wg show all dump`, shortens public keys in normal presentation, maps configured peer names, records allowed IPs/endpoint/handshake/RX/TX/keepalive, and distinguishes optional from required peers. Private keys and secret-named fields are stripped before API serialization. Existing Direct LAN VPN suppression remains unchanged.

Samba consumes `smbstatus --json`, summarizes sessions/users/clients/open files/shares, caps detail lists, and treats zero sessions as healthy. RAID parses `/proc/mdstat` array membership, level, failed/spare counts and bounded rebuild progress. SMART JSON and NVMe smart-log JSON normalize overall health, temperature, life, spare, media errors, and documented sector counters. Missing `wg`, `smbstatus`, `smartctl`, or `nvme` is “unsupported,” not a collector crash.

### Package updates and Git deployments

APT parsing uses existing metadata (`apt-get --simulate upgrade` output) and never installs packages or implicitly runs `apt update`; the default package interval is six hours. Available/security update and reboot-required values are informational. Git monitoring is restricted to configured repository paths and is read-only by default: branch, commit, dirty state, remote, ahead/behind, and commit date. Remote fetch is opt-in, long-interval, timed, and its failure does not mark the application down. `/software`, `/api/software`, and `/api/deployments` expose objective OS/kernel/application drift without declaring a version correct.

### LAN Inventory

The LAN-Inventory adapter imports JSON without coupling to its database. It conservatively matches MAC first and unambiguous hostname/device ID next; ambiguous observations remain unmanaged. `/network-inventory` separates managed enrichment from other observed devices. New observations are informational events, never critical managed hosts.

### Integration history, alerts, and diagnostics

Schema migration 4 adds generalized numeric `integration_metrics` and `network_inventory` tables to the existing SQLite database. Selected operational metrics (ADS-B counts/rates/range, Samba counts, WireGuard summaries, hotspot clients, and HTTP latency) use existing retention infrastructure. Alert reconciliation and event storage remain central. Integration diagnostics expose last attempt/success, duration, source, and a safe last error; stack traces and credentials are excluded.

### Optional dependencies and troubleshooting integrations

Optional commands run on the monitored host (locally or over SSH), not necessarily on the PiNOC console: `git`, `wg`, `smbstatus`, `smartctl`, `nvme`, and `iw`. `install.sh` intentionally does not install all of them. HTTP and subprocess work must use configured timeouts and background collectors; routes only read cache. If an integration says `unsupported`, install the relevant tool on that device or disable the integration. If it says `unavailable`, inspect its data source, configured port/path/process name, last attempt, and last error. Configuration errors identify device/integration fields without invalidating otherwise valid devices.

Milestone 4 intentionally provides no shell, service/reboot controls, apt upgrades, Git deployment, display screen controls, hotspot disconnection, WireGuard/Samba/RAID mutation, SMART repair, settings editor, agent protocol, or Codex/ChatGPT gateway. Those controls remain deferred to Milestone 5; agent execution remains deferred to Milestone 6.

## Milestone 5: secure management

### Authentication, sessions, users, and roles

Authentication is optional and explicit. Set `PINOC_AUTH_ENABLED=1`, create a random `PINOC_SECRET_KEY`, then bootstrap the first administrator locally with `python -m pinoc.admin create-user --role administrator NAME`. There are no default credentials. Passwords use Werkzeug's maintained salted password hashing; only hashes are stored. Sessions expire (one hour by default), rotate their CSRF token at login, and use HttpOnly/SameSite=Lax cookies. Set `PINOC_SECURE_COOKIE=1` only behind HTTPS. **Plain trusted-LAN HTTP is not encrypted:** anyone able to observe that network can read traffic, and with authentication disabled every reachable client is treated as a trusted-LAN administrator.

Roles are enforced by the server, not just hidden controls: viewers read fleet/history/alerts; operators may acknowledge/mute alerts, schedule refresh, maintain devices, and execute configured safe actions; administrators additionally control power, settings, users, and tokens. Login failures use one generic error and a five-attempt/five-minute per-IP temporary throttle. `/login` signs in and the CSRF-protected `POST /logout` signs out. Authentication events are audited.

Users can be listed/created via the administrator API or the local CLI. `reset-password`, `disable-user`, and `list-users` avoid manual SQLite edits. Administrators can issue optional tokens with only named scopes (`read:fleet`, `read:history`, `read:alerts`, `write:alerts`, `execute:safe_actions`, `admin:config`). A token is stored as SHA-256, shown once as `ID.SECRET`, passed as `Authorization: Bearer ID.SECRET`, can be revoked by ID, and updates `last_used`. Never put tokens in URLs.

### CSRF and web/API security

Every cookie-authenticated POST/PUT/PATCH/DELETE supplies the session token in `X-CSRF-Token` (available from `/api/session`); missing and invalid tokens are rejected. Bearer tokens are not cookie credentials and are instead protected by their unguessable secret and explicit scopes. Responses set CSP, frame denial, `nosniff`, and same-origin referrer policy. Static assets and `/health` remain public; protected API requests receive 401, insufficient roles/scopes receive 403. Errors and serialized configuration pass through centralized password/token/key/credential redaction.

Example session request (placeholder values only):

```sh
curl -c cookies.txt http://pinoc.local:8088/login
# Submit the login form, then obtain csrf_token:
curl -b cookies.txt http://pinoc.local:8088/api/session
curl -b cookies.txt -H 'X-CSRF-Token: EXAMPLE' -X POST \
  http://pinoc.local:8088/api/devices/square/refresh
```

Example token request: `curl -H 'Authorization: Bearer TOKEN_ID.TOKEN_SECRET' http://pinoc.local:8088/api/devices`.

### Manageable services and safe actions

`monitored_services`, `critical_services`, and `manageable_services` are intentionally separate. Monitoring or criticality never grants control. A systemd unit must match the strict unit syntax and be listed in `manageable_services` before start/stop/restart is accepted. Registered actions are fixed definitions with permission, confirmation, timeout, conflict class, validation, and an internal handler: device refresh/reboot/shutdown; allowlisted service start/stop/restart; configured WireGuard, desk_display, MagicMirror, and pi-hotspot restarts; and a non-mutating package check. Package upgrade/install, Git mutation, and arbitrary commands are absent.

Routes include `POST /api/devices/ID/refresh|reboot|shutdown`, `POST /api/devices/ID/services/UNIT/start|stop|restart`, `POST`/`DELETE /api/devices/ID/maintenance`, `DELETE /api/devices/ID/expected-offline`, and `GET /api/actions[/JOB_ID]`. Requests return HTTP 202 with a durable job ID; poll the result endpoint until `succeeded`, `failed`, or `timed_out`. Output is bounded and sanitized. Commands use subprocess argument arrays with `shell=False`, exact verbs/units, `sudo -n`, explicit timeout and exit-code handling. Actions are serialized per device by a bounded worker pool independent of monitoring. Jobs abandoned by PiNOC restart become failed and are not replayed.

### Reboot, shutdown, maintenance, and expected offline

Reboot and shutdown require administrators and stronger UI confirmation. The audit request is written before dispatch. Reboot creates a ten-minute expected-offline grace and clears it when telemetry returns; shutdown remains expected offline until manually cleared. Expected outages are recorded as informational rather than network failures. Maintenance supports 30 minutes, 1, 4, 24 hours, or manual clearing plus a reason. Collection, metrics, and events continue, while reconciliation preserves existing alert conditions without generating takeover noise. Expiry is persistent across PiNOC restart, clears automatically on the next history cycle, records an event, and reevaluates the fresh state.

### Audit, settings, and recovery

`/audit` and `/api/audit` provide paginated/filterable records by user, device, action, result, and date. Attempts include identity/role/IP, sanitized parameters, authorization, execution status, exit code, duration, and safe error text. Action/audit data is retained independently of metric cleanup. Schema migration 5 adds users, hashed API tokens, action jobs, audit records, and persistent device operational state without recreating earlier history.

`/settings` describes administrator configuration areas; `GET/PUT /api/settings` returns redacted configuration, validates the complete candidate, creates three rotating backups, fsyncs a mode-0600 temporary file, and atomically renames it. Current runtime changes report `restart_required`; no partial reload is claimed. On recovery, use the CLI to reset an administrator password or revoke a token. The uninstaller continues preserving config, database, audit records, users, and credentials unless explicit removal is chosen.

### SSH enrollment and least privilege

Key-based SSH in BatchMode is preferred; password fallback remains collection-only compatibility. Install the PiNOC public key with `pinoc-device-setup.sh`. Enroll a host key deliberately (for example, compare `ssh-keyscan` output with a console-displayed fingerprint before adding it to the PiNOC account's `known_hosts`). Normal OpenSSH checking then fails closed on a changed key; never replace a changed key without investigating.

The helper generates only exact per-unit `systemctl start/stop/restart` entries and optionally exact `systemctl reboot/poweroff`; it validates the fragment with `visudo`. It never emits `NOPASSWD: ALL`. A compromised managed Pi can still attack data returned to collectors and its own SSH key relationship, so isolate management networks and remove stale keys. Private keys remain filesystem paths/permissions and are never exposed by the web API.

### Threat model and remaining risk

Mitigations address LAN attackers (enable HTTPS/authentication), stolen tokens (minimal scopes, hashes, revocation, last-use), compromised accounts (roles and complete audit), compromised managed Pis (per-device keys/segmentation), SSH host-key changes (fail closed), CSRF (session-bound token), command injection (fixed registry, unit allowlist, argument arrays), privilege escalation (exact sudoers), and secret leakage (central redaction and no private-key APIs). Remaining risks include an administrator's intentional power/config authority, traffic disclosure over HTTP, denial of service by a reachable peer, and the privileges necessarily granted for each selected service. Back up `config.json`, `data/pinoc.db`, SSH material, and the secret key with service-account-only permissions.

## Milestone 6: Agent and remote development gateway

### Architecture and protocol

Milestone 6 adds an **optional** outbound-polling `pinoc-agent` beside the existing SSH monitoring and safe-management paths. Non-agent Pis remain fully supported. A trusted client authenticates to PiNOC, PiNOC validates a structured development job and persists it, and the target agent claims it on its next HTTPS heartbeat. The unprivileged agent executes only the resulting policy envelope in an approved workspace and reports a durable result. It has no inbound listener and PiNOC exposes no `/shell`, root command, SSH-key export, arbitrary service, apt-upgrade, destructive rollback, or unrestricted filesystem endpoint.

The protocol version is `1`; agent software is independently versioned (`1.0.0`). Agent methods are limited to enrollment, signed heartbeat/job claim, result upload, cancellation reconciliation, and artifact upload. Each authenticated request covers agent ID, Unix timestamp, a random nonce, and the exact request-body digest with HMAC-SHA256. PiNOC accepts a 60-second clock window and persists recently used nonces. Credentials are unique per agent and stored by PiNOC only as SHA-256 key material. TLS is still required: HMAC authenticates messages but does not hide job source, output, or credentials during enrollment. There are no special network ports beyond the PiNOC HTTPS endpoint and agents require only outbound access to it.

### Install, enroll, rotate, and remove an agent

1. Enable authentication and HTTPS on PiNOC. As an administrator, create a one-use, ten-minute enrollment code:

   ```sh
   curl -H 'Authorization: Bearer ADMIN_TOKEN' -H 'Content-Type: application/json' \
     -d '{"device_id":"square","ttl_seconds":600}' \
     https://pinoc.example/api/v1/dev/agents/enrollment-codes
   ```
2. On the intended Pi, verify the PiNOC TLS certificate and run `sudo ./install_agent.sh https://pinoc.example ONE_TIME_CODE /home/pi /opt`. The script creates the locked `pinoc-agent` system account, `/opt/pinoc-agent`, mode-0750 `/etc/pinoc-agent`, a mode-0600 configuration/credential file, and `pinoc-agent.service`. It does not install an SSH credential or reusable fleet enrollment secret. Add only deliberately required groups or workspace permissions; the supplied service has `NoNewPrivileges`, a strict system view, private temporary storage, and no root user.
3. Confirm identity, version, protocol, last-seen time, capabilities, and candidates at `/agents`. Repository candidates are informational and never become executable automatically.
4. Rotate with `POST /api/v1/dev/agents/AGENT_ID/rotate`, then replace only that agent's credential in `/etc/pinoc-agent/config.json`. Revoke immediately with `DELETE /api/v1/dev/agents/AGENT_ID/credential`. A revoked credential cannot heartbeat, claim, or report another result. Rotation does not require reimaging.
5. Remove with `sudo ./uninstall_agent.sh --confirm`. It removes only agent runtime, service, credential, and system account; project workspaces are preserved. There is no automatic self-update. Upgrade the installed files through the administrator's normal package/deployment process and use `/agents` to find version/protocol mismatches.

For an isolated local test only, `allow_insecure_http` can be set in agent configuration. This sends sensitive development traffic in plaintext and is **not secure**, even on a home LAN.

### Capabilities and hardware profile

Heartbeats normalize tool versions for Python, Git, Node, npm, Docker, ffmpeg, and `vcgencmd`; booleans for systemd, GPIO, I2C, SPI, camera, display, framebuffer, X11, and Wayland; and hardware fields for model, RAM, architecture, kernel, named I2C/SPI/camera/framebuffer nodes, DRM connector names, and display-session mode. The code enumerates only these relevant patterns, not unrestricted `/dev`. Profiles may declare `requires_capabilities`; missing capabilities produce `capability_missing` rather than attempting the job. A hardware profile describes what a workspace is approved to test. State-changing hardware profiles should be granted only to tokens with `dev:hardware`; presence of GPIO/I2C/SPI alone grants no arbitrary writes. Capture results must truthfully describe headless render, framebuffer capture, initialization-only, or unavailable physical capture; a generated PNG is not proof that a physical panel looked correct.

### Approved workspaces and execution policy

Administrators approve/update workspaces with `PUT /api/v1/dev/workspaces/WORKSPACE_ID`. Important fields are `device_id`, absolute `path`, `repository`, `mode`, `execution_user`, `allowed_job_types`, `allowed_commands`, `allowed_env`, `test_profiles`, `services`, `artifact_patterns`, `sensitive_patterns`, and `hardware_profile`. `read_only` is the safe default; `development` is required for generic command jobs. Candidate discovery never implies approval. Project-to-device mapping is represented by distinct approved workspace records and matrices explicitly name their target devices.

Paths supplied by clients must be relative. The agent resolves the approved root and target canonically, rejects traversal and absolute paths, verifies containment, rejects symlink escapes/root replacement and non-regular reads, and denies `.env`, keys, credentials, and secret-like patterns by default. File reads are UTF-8 text and size bounded. Milestone 6 intentionally does not expose a general write endpoint. Administrators can later add atomic complete-file or validated patch operations without weakening this boundary.

Named tests use argv arrays, for example:

```json
{
  "test_profiles": {
    "unit": {
      "description": "Project unit suite",
      "argv": ["venv/bin/python", "-m", "pytest"],
      "timeout": 300,
      "environment": {"DESK_DISPLAY_FORCE_HEADLESS": "1"},
      "requires_capabilities": ["python"],
      "artifact_patterns": ["test-output/*.png"]
    }
  }
}
```

Generic `command` jobs require a development-mode workspace, `dev:command`, an argv array, and an executable in `allowed_commands`. Shells, `sudo`, `su`, `doas`, `pkexec`, environment wrappers, exec-style options, and destructive Git verbs are rejected. `git_status` and bounded `git_diff` are read-only; `git_fetch` is a distinct permissioned job and does not change working files. PiNOC never runs reset, clean, pull, push, or automatic rollback and never discards a dirty tree. `service_status` and `log_read` accept only configured unit names, bounded lines, and no arbitrary journal browsing. Existing Milestone 5 actions remain the sole path for approved service restart.

### Jobs, limits, cancellation, and artifacts

Development jobs are separate from operational `action_jobs`. Statuses are `queued`, `dispatched`, `running`, `succeeded`, `failed`, `timed_out`, `cancelled`, `agent_lost`, and `rejected`; normalized errors include authorization, offline agent, missing workspace/capability, timeout, command failure, artifact limit, and replay rejection. PiNOC rejects an offline target clearly instead of losing work. A server restart marks uncertain dispatched/running work `agent_lost` and never blindly reruns it. `/jobs` shows history/queue state and `/jobs/JOB_ID` shows identity, policy representation, timing, exit code, bounded output, result, artifacts, and audit linkage. Polling is the intentionally simple streaming mechanism.

Every job has a 300-second default and 1,800-second ceiling. The agent creates a new process session, closes stdin, supplies a small explicit environment, enforces wall timeout, and terminates the entire process group on timeout/cancel. Where supported it also limits CPU time, address space (1 GiB), open files (128), output file size (20 MiB), and processes (64). Stdout/stderr are independently capped and truncation is explicit. Conservative per-agent polling executes one claimed job at a time; workspace-changing concurrency remains serialized by the agent. Future isolation can replace the runner with transient systemd units, namespaces, bubblewrap, or containers.

Artifacts are discovered only through administrator-configured workspace glob patterns and canonical containment. The agent limits count, individual bytes, and total bytes; PiNOC generates IDs/storage names, stores mode-0600 files under `data/jobs/JOB_ID`, hashes them, and never accepts a destination path. Defaults are 20 files, 10 MiB each, and 25 MiB total. Successful artifacts expire after seven days and failed-job artifacts after thirty; cleanup removes bytes but not durable job/audit metadata and skips active jobs. Use the authenticated list/download routes, not filesystem paths.

### Client authentication and stable API

Codex, ChatGPT, and other tools use `Authorization: Bearer ID.SECRET` with a dedicated PiNOC API token—not cookies, SSH keys, enrollment codes, or agent credentials. Development scopes are `dev:read`, `dev:test`, `dev:command`, `dev:artifacts`, `dev:cancel`, `dev:write`, and `dev:hardware`. Tokens can additionally restrict device IDs, workspace IDs, and job types. A test-only token does not gain generic commands. A client's claimed product name grants nothing.

Core versioned routes are:

```text
GET    /api/v1/dev/agents
GET    /api/v1/dev/workspaces
GET    /api/v1/dev/jobs
POST   /api/v1/dev/jobs
GET    /api/v1/dev/jobs/{id}
DELETE /api/v1/dev/jobs/{id}
GET    /api/v1/dev/jobs/{id}/artifacts
GET    /api/v1/dev/jobs/{id}/artifacts/{artifact_id}
POST   /api/v1/dev/matrices
```

Create a tightly restricted client token (returned once):

```sh
curl -b admin.cookies -H 'X-CSRF-Token: EXAMPLE' -H 'Content-Type: application/json' \
  -d '{"owner":"codex","scopes":["dev:read","dev:test","dev:artifacts","dev:cancel"],"devices":["square"],"workspaces":["desk-display"],"job_types":["workspace_info","git_status","git_diff","test"]}' \
  https://pinoc.example/api/tokens
```

Run and poll an approved test:

```sh
curl -H 'Authorization: Bearer TOKEN_ID.TOKEN_SECRET' -H 'Content-Type: application/json' \
  -d '{"device_id":"square","workspace_id":"desk-display","job_type":"test","profile":"unit","timeout_seconds":300}' \
  https://pinoc.example/api/v1/dev/jobs
curl -H 'Authorization: Bearer TOKEN_ID.TOKEN_SECRET' https://pinoc.example/api/v1/dev/jobs/JOB_ID
```

A Codex workflow lists agents/workspaces, checks capabilities and dirty Git state, reads approved status/logs, submits syntax/unit/headless/hardware profiles, polls durable state, then downloads declared artifacts. A ChatGPT integration follows the identical structured flow. Natural-language intent must be mapped by the client to an approved device/workspace/profile; PiNOC does not turn prose into a shell command. A matrix request uses one profile/workspace across up to eight explicit devices, returns a parent ID plus independently persisted child jobs, and keeps each device's artifacts separate.

### Database and audit

Migration 6 extends token restriction metadata and adds normalized enrollment codes, agents, workspaces, development jobs, artifacts, approvals, and replay nonces without deleting prior tables/history. Enrollment, revocation, submission, cancellation, and completion use the Milestone 5 audit log with actor/client token ID, source, device, workspace/job representation, permissions, authorization, outcome, and redacted errors. Job records preserve timestamps, duration, status, exit code, approved argv, sanitized environment, truncation, result summary, and artifact references. Credential plaintext is never stored by PiNOC.

### Security and threat model

This gateway is substantially narrower than unrestricted SSH: stolen development tokens are bounded by scopes and optional device/workspace/job restrictions; malicious clients encounter structured schemas, allowlists, canonical paths, size/time limits, and audits; traversal and symlink escapes fail closed; commands bypass no shell because strings are never evaluated by one; agent replay is rejected; secret-like output is best-effort redacted; agent/PiNOC credentials and unrelated process environment are not inherited; and no development operation implicitly invokes sudo.

**Important limitation:** an approved `pytest`, npm script, Python program, or dependency hook executes project code. That code can perform anything available to the configured Linux execution user, including network access and files/hardware that account can access. Filename rules and output redaction cannot detect every application secret. Use a dedicated low-privilege account, minimal groups/filesystem permissions, HTTPS, short-lived restricted client tokens, network segmentation, and stronger sandboxing for untrusted repositories.

Remaining threats include a compromised PiNOC server dispatching policy-valid work, a compromised agent falsifying results or using its account access, malicious repositories consuming resources within available limits, stolen on-device credentials until revocation, administrator misconfiguration of broad commands/artifact globs/groups, and state-changing hardware tests damaging attached equipment. The agent is not a perfect sandbox and does not claim one. No automatic update or destructive recovery is provided.

### Troubleshooting and manual Pi validation

If an agent is offline, verify systemd status, outbound DNS/TCP/TLS, server URL/certificate, clock synchronization (the signature window is 60 seconds), credential revocation, and protocol version. If a workspace fails, verify its approval, exact canonical path, account traversal permissions, mode, job/executable/environment allowlists, capability prerequisites, and sensitive patterns. If a job times out, inspect its bounded stderr and choose an administrator-approved timeout no greater than the configured maximum. For display tests, inspect the reported validation mode before interpreting a screenshot.

Before deploying broadly, enroll a disposable Pi, approve a temporary repository, exercise status/diff/read/test/timeout/cancel/artifact flows, revoke its credential, confirm reconnect after rotation, and verify processes are absent after cancellation. Never test with production secrets in project output. The automated mock-agent suite covers enrollment/replay/revocation, restrictions, traversal/symlink/sensitive denial, command/sudo policy, environment filtering, timeout/process cleanup/output truncation, Git status, artifact limits/retrieval, matrices, offline agents, cancellation, and schema preservation without requiring Raspberry Pi hardware.
