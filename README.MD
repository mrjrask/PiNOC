Desk Pi NOC
===========

Files:
- pi_noc.py: main application
- config.json: WireGuard, SSH host, paths, and refresh settings
- requirements.txt: Python dependencies for the virtual environment
- pi-noc.service: systemd unit template for the autostart service
- install.sh: Raspberry Pi installer that installs system dependencies, enables
  I2C, builds the virtual environment, configures SSH keys for the CM5, grants
  passwordless WireGuard status/restart controls, and enables pi-noc.service

Install:
1. Copy or clone this project onto the display Pi.
2. Review config.json and adjust the CM5 host/user, WireGuard service/interface,
   display address, remote paths, and MMM-RemoteTempMonitor UDP settings if needed.
3. Copy .env.example to .env and set CM5_SSH_PASS to the CM5 SSH password.
4. Run the installer:

   sudo ./install.sh

The installer prompts for the CM5 SSH host, user, and port only. It requires
CM5_SSH_PASS in .env and uses that password once with ssh-copy-id so the
pi-noc service can use key-based SSH non-interactively after installation.

The installer also writes /etc/sudoers.d/pi-noc-wireguard so the service user
can run the WireGuard status command and restart the configured WireGuard
systemd service without a password.

Controls:
- Joystick left/right/up/down: change page
- Joystick center: refresh now
- Button B: toggle automatic page rotation
- Hold Button A for 1.5 seconds: restart WireGuard

The application displays a flashing full-screen warning whenever wg0 has no
handshake newer than 150 seconds.

MMM-RemoteTempMonitor:
- PiNOC listens for the same UDP JSON packets emitted by
  https://github.com/mrjrask/MMM-RemoteTempMonitor and shows the hottest recent
  devices on the REMOTE TEMPS page.
- Configure `remote_temp_monitor.port` if your broadcasters do not use the
  default UDP port 9876.
- Set `remote_temp_monitor.shared_secret` to the same value as
  `TEMP_MONITOR_SHARED_SECRET` on the broadcasters when packet authentication is
  enabled.
- Devices older than `remote_temp_monitor.max_device_age` seconds are hidden.
