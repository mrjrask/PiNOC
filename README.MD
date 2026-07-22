# Desk Pi NOC

Desk Pi NOC is a small Raspberry Pi network operations console for an Adafruit
128x64 OLED Bonnet. It monitors a WireGuard tunnel, a remote CM5 file server,
RAID health, SMB sessions, disk usage, local Pi health, and optional remote
temperature broadcasters.

## Features

- Full-screen flashing warning when the WireGuard tunnel has no recent
  handshake.
- One-button WireGuard restart via a passwordless sudo rule created by the
  installer.
- Remote CM5 checks over SSH, using `CM5_SSH_PASS` from `.env` when present:
  - CPU temperature, load average, and uptime.
  - `/proc/mdstat` RAID state for the configured array.
  - Disk usage for configured paths.
  - Samba session count and unique users from `smbstatus` when available.
- Local Desk Pi checks for temperature, load, uptime, memory use, and Wi-Fi IP.
- Optional UDP listener for
  [MMM-RemoteTempMonitor](https://github.com/mrjrask/MMM-RemoteTempMonitor)
  JSON temperature packets.
- Joystick navigation and automatic page rotation.

## Repository layout

| File | Purpose |
| --- | --- |
| `pi_noc.py` | Main Python application. |
| `config.json` | Runtime configuration for VPN, SSH, display, storage, and temperature monitoring. |
| `.env.example` | Template for `.env`, which stores `CM5_SSH_PASS` for install-time and runtime CM5 SSH authentication. |
| `requirements.txt` | Python package dependencies installed into the virtual environment. |
| `install.sh` | Raspberry Pi installer for system packages, I2C, virtualenv, SSH keys, sudoers, and systemd. |
| `pi-noc.service` | systemd unit template rewritten by `install.sh` for the install path and user. |

## Hardware and system requirements

- Raspberry Pi OS or another Debian-based Raspberry Pi environment.
- Adafruit 128x64 OLED Bonnet connected over I2C.
- WireGuard tools and a configured WireGuard systemd service, defaulting to
  `wg-quick@wg0.service`.
- SSH access from the display Pi to the remote CM5/server.
- Optional: Samba `smbstatus` and Linux MD RAID `/proc/mdstat` on the remote
  server.

## Configuration

Edit `config.json` before installation or service start.

| Key | Default | Description |
| --- | --- | --- |
| `vpn_interface` | `wg0` | WireGuard interface to inspect with `wg show`. |
| `vpn_service` | `wg-quick@wg0.service` | systemd service restarted when Button A is held. |
| `vpn_stale_seconds` | `150` | Maximum acceptable WireGuard handshake age. |
| `refresh_seconds` | `10` | Minimum interval between background status refreshes. |
| `auto_rotate_seconds` | `8` | Page rotation interval while VPN is healthy. |
| `remote_host` | `cm5` | Remote server hostname or IP. |
| `remote_user` | `pi` | SSH user for remote checks. |
| `remote_ssh_port` | `22` | SSH port for remote checks. |
| `remote_paths` | two sample paths | Named remote paths shown on the storage page. |
| `raid_device` | `md0` | MD RAID device name to find in `/proc/mdstat`. |
| `display_address` | `0x3c` | I2C address for the OLED display. |
| `remote_temp_monitor.enabled` | `true` | Enables the UDP temperature packet listener. |
| `remote_temp_monitor.port` | `9876` | UDP port for temperature packets. |
| `remote_temp_monitor.max_device_age` | `30` | Hide temperature devices older than this many seconds. |
| `remote_temp_monitor.shared_secret` | empty | Optional HMAC shared secret for authenticated temperature packets. |

## Installation

1. Copy or clone this repository onto the display Pi.
2. Review and edit `config.json`.
3. Create the installer environment file:

   ```bash
   cp .env.example .env
   nano .env
   ```

4. Set `CM5_SSH_PASS` in `.env` to the remote CM5 SSH password. The
   installer uses it for `ssh-copy-id`, and the running service reads the same
   file whenever it authenticates to the CM5. Update `.env` if the remote
   password changes; no reinstall is required.
5. Run the installer:

   ```bash
   sudo ./install.sh
   ```

6. Reboot if I2C or group membership changed, then start or inspect the service:

   ```bash
   sudo systemctl start pi-noc.service
   sudo systemctl status pi-noc.service
   ```

The installer writes `/etc/sudoers.d/pi-noc-wireguard` so the service user can
run WireGuard status checks and restart only the configured WireGuard service
without a password.

## Runtime CM5 password behavior

At runtime, `pi_noc.py` reads `CM5_SSH_PASS` directly from `.env` in the
project root before each remote CM5 status refresh. If the value is present,
remote checks use `sshpass -e ssh`; if it is absent, remote checks fall back to
key-only SSH with `BatchMode=yes`. Keep `.env` readable only by the account that
runs the service.

## Controls

| Control | Action |
| --- | --- |
| Joystick left/up | Previous page. |
| Joystick right/down | Next page. |
| Joystick center | Refresh status immediately. |
| Button B | Toggle automatic page rotation. |
| Hold Button A for 1.5 seconds | Restart the configured WireGuard service. |

## Display pages

1. **Summary**: VPN, CM5, RAID, and SMB session overview.
2. **WireGuard**: service state, latest handshake age, traffic counters, and
   full-tunnel status.
3. **Storage**: usage for the first two configured remote paths.
4. **CM5 Server**: remote status, temperature, load, and uptime.
5. **Samba**: active SMB session count and users.
6. **Remote Temps**: hottest recent MMM-RemoteTempMonitor devices.
7. **Desk Pi**: local hostname/IP, temperature/load, memory, and uptime.

## Remote temperature monitor packets

When enabled, PiNOC listens for UDP JSON packets compatible with
MMM-RemoteTempMonitor. If `remote_temp_monitor.shared_secret` is set, packets
must include a valid `hmac` field calculated over the JSON payload without the
`hmac` key using compact JSON separators.

Devices are keyed by `device_id` when present, otherwise by source IP and
hostname. Devices older than `remote_temp_monitor.max_device_age` are removed
from the page.

## Troubleshooting

- **Display stays blank**: confirm I2C is enabled, the service user is in the
  `i2c` and `gpio` groups, and the OLED address matches `display_address`.
- **VPN warning never clears**: run `wg show wg0 dump` and verify a recent peer
  handshake. Also verify `vpn_interface`, `vpn_service`, and the generated
  sudoers file.
- **Remote pages show offline**: verify the `.env` `CM5_SSH_PASS` value and
  SSH connectivity with `ssh -p <port> <user>@<host> true` from the service
  user, or confirm key-based SSH is still valid if `.env` omits the password.
- **SMB shows unavailable**: install Samba tools on the remote server and allow
  the remote user to run `smbstatus` if root privileges are required.
- **No remote temperatures**: check UDP reachability, port configuration, packet
  age, and the shared secret on both broadcaster and PiNOC.

## Development checks

Run these before committing changes:

```bash
python3 -m py_compile pi_noc.py
bash -n install.sh
python3 -m json.tool config.json >/dev/null
```
