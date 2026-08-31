# PiNOC 2.0

PiNOC is a centralized Raspberry Pi network operations console with one shared,
cached monitoring backend and two frontends: a responsive web console and the
existing Adafruit 128x64 OLED Bonnet or Pimoroni Display HAT Mini. Milestone 1
preserves the established WireGuard, CM5/file-server, RAID, SMB, storage, local
Pi, remote-temperature, and StemmaQT sensor monitoring and makes that same data
available on the web.

## Architecture

```text
                          bounded background work
┌──────────────────────────────────────────────────────────┐
│ Collectors: local, WireGuard, SSH/CM5, RAID, SMB, disks, │
│ remote temperatures, and local environmental sensor      │
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
storage, network, services, applications, and alerts. Milestone 1 emits the
local console (`pinoc`, `desk_display` roles), configured CM5 (`file_server`),
and remote temperature sources. Arbitrary device definitions, richer health
thresholds, and Cockpit URLs are deliberately scheduled for Milestone 2.

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

## Milestone 2 remaining work

Milestone 2 will add arbitrary multi-Pi definitions and local/SSH collection
modes, full CPU/memory/storage/network/service data, roles/tags/friendly names,
central configurable warning/critical/offline classification, Cockpit links,
and richer fleet filtering/search. The collector interface and normalized
model intentionally leave room for a later `agent` mode without coupling this
release to another repository.
