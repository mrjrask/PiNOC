# PiNOC 2.0

PiNOC is a Raspberry Pi network-operations console for monitoring and safely
managing a fleet of Pis. A single background backend collects local, SSH, and
legacy telemetry into a thread-safe cache used by both the responsive web
console and an optional physical display. SQLite adds durable metrics, alerts,
events, actions, audit records, and the optional outbound-agent development
workflow.

PiNOC is designed for a trusted private network. It does not make SSH or remote
HTTP calls while serving a web request, and a failed collector cannot stop the
other collection domains.

## What PiNOC provides

- **Fleet monitoring:** stable device identities; local and bounded concurrent
  SSH collection; CPU, temperature, memory, storage, networking, systemd
  services, Raspberry Pi power/throttling state, roles, tags, and Cockpit links.
- **Operational history:** SQLite/WAL storage, configurable sampling and
  retention, graphs, storage forecasts, transition events, and persistent alert
  lifecycles (active, acknowledged, muted, and resolved).
- **Application integrations:** ADS-B, desk displays, MagicMirror, ICS Modifier,
  pi-hotspot, WireGuard, Samba, RAID, SMART/NVMe health, packages, Git, and
  optional passive LAN inventory.
- **Safe administration:** optional users and API tokens, role/scoped
  authorization, CSRF protection, allowlisted service and power actions,
  maintenance windows, configuration backups, and an audit log.
- **Remote development gateway:** optional outbound-only agents, one-use
  enrollment, restricted workspaces, approved test profiles, bounded output and
  artifacts, explicit state-changing approvals, cancellation, and matrix jobs.
- **Two frontends:** a responsive Flask/Waitress console and either an Adafruit
  128×64 OLED Bonnet or Pimoroni Display HAT Mini. Headless web-only operation
  is supported.

## Architecture

```text
 local commands     bounded SSH     legacy HTTP/sensors     outbound agents
       \                 |                 /                       |
        +---------- collection scheduler/cache -------------------+
                              |
                  normalized PiNOC state
                    /                    \
             history queue            display renderer
                  |                         |
             SQLite/WAL              physical display
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
- Optional I²C/SPI display and sensor hardware
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

The installer interactively selects the physical display, authentication, web
listener, and port; installs dependencies; enables I²C/SPI; creates the virtual
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
default; use a TLS reverse proxy before exposing it beyond a trusted LAN.

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
DISPLAY=ADA_BONNET           # ADA_BONNET or PIM_DHM
PINOC_DISPLAY_ENABLED=1      # 0 for a headless deployment
PINOC_WEB_ENABLED=1
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
| `web_enabled`, `web_host`, `web_port` | `true`, `0.0.0.0`, `8088` | Web listener fallback values. |
| `authentication.enabled` | `false` | Authentication fallback; `PINOC_AUTH_ENABLED` takes precedence. |
| `polling.*` | 10–60 s | Independent fleet, local, network, remote, service, storage, sensor, and temperature schedules. |
| `fleet_max_workers` | `4` | Maximum concurrent fleet collection workers. |
| `ssh_command_timeout` | `8` s | Per-device SSH command timeout. |
| `health_thresholds` | see `config.json` | Live CPU, memory, temperature, disk, stale, and offline thresholds. |
| `history.*` | enabled | Database path, sample intervals, retention, maintenance, and alert thresholds. |
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

Run the validator after every manual configuration change:

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
read-only storage, degraded RAID, and failed critical services. One warning is
`warning`; multiple warnings or telemetry older than 30 seconds is `degraded`;
telemetry older than 120 seconds is `offline`. Maintenance suppresses normal
health evaluation but does not make never-successful telemetry healthy.

The durable alert engine additionally supports hysteresis and sustained
conditions under `history.thresholds`. A stable fingerprint updates an existing
unresolved occurrence rather than opening one per poll. Recovery resolves the
occurrence and records an event. A later recurrence opens a new occurrence.

SQLite defaults:

- Core and network samples every 60 seconds; storage every 300 seconds.
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

Use `python3 -m pinoc.database status --database PATH` for status. Run
`python3 -m pinoc.database vacuum --database PATH` only during a planned
maintenance window; routine retention does not vacuum.

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
GET /api/devices/<id>/storage/forecast
GET /api/alerts[?state=active]
GET /api/events
GET /api/database/status
```

Fleet queries accept `health`, `role`, and `tag` filters. Event and alert APIs
support bounded pagination and relevant device/type/severity/state filters.
Allowed metric ranges are `1h`, `6h`, `24h`, `7d`, and `30d`.

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

Actions accept structured identifiers only, use fixed argv arrays without a
shell, and enforce configured service/integration allowlists. Device power is
administrator-only and expected-offline state is cleared if dispatch fails.
Audit records capture actor, role/token, source, target, authorization,
outcome, duration, and redacted errors.

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

## Physical display

The physical pages use the shared cache: Summary, Fleet, Alerts, WireGuard,
RAID, Storage, Server, SMB, remote temperatures, Local, Sensors, and Network.

- **Adafruit Bonnet:** left/right changes page, up/down scrolls, center refreshes,
  Button B toggles rotation, and holding Button A requests the configured
  WireGuard restart.
- **Pimoroni Display HAT Mini:** A/B changes page, double-click A/B scrolls, X
  refreshes, Y toggles rotation, and holding/triple-clicking A requests the same
  WireGuard action.

Refresh signals the shared scheduler; it does not start a second collector path.

## Operations and troubleshooting

```sh
sudo systemctl status pi-noc.service --no-pager --full
sudo journalctl -u pi-noc.service -b -n 100 --no-pager
sudo systemctl show pi-noc.service -p NRestarts -p ExecMainCode -p ExecMainStatus
sudo ss -ltnp '( sport = :8088 )'
curl -v --connect-timeout 5 http://127.0.0.1:8088/health
```

- **Web unavailable:** verify `PINOC_WEB_ENABLED`, host/port, the systemd
  environment file, journal, listener, and loopback request before debugging
  VLAN/client-isolation/firewall paths. Use `http://` unless a TLS proxy exists.
- **Display blank:** verify `PINOC_DISPLAY_ENABLED`, `DISPLAY`, I²C/SPI, service
  group membership, cabling, and `display_address`. For web-only recovery, set
  `PINOC_DISPLAY_ENABLED=0` and restart.
- **Pillow import failure:** rerun `sudo ./install.sh`; it installs and verifies
  FreeType and the distro-appropriate OpenJPEG runtime.
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
| `pi_noc.py` | Unified process, legacy collectors, shared scheduler, and display frontend. |
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
limits, artifacts, cancellation, installer dependencies, headless import, and
physical-button behavior.
