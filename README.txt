Desk Pi NOC
===========

Files:
- pi_noc.py: main application
- config.json: WireGuard, SSH host, paths, and refresh settings
- requirements.txt: Python dependencies for the virtual environment
- pi-noc.service: systemd unit for /home/pi/pi-noc

Controls:
- Joystick left/right/up/down: change page
- Joystick center: refresh now
- Button B: toggle automatic page rotation
- Hold Button A for 1.5 seconds: restart WireGuard

The application displays a flashing full-screen warning whenever wg0 has no
handshake newer than 150 seconds.
