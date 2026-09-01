#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo" >&2; exit 1; }
[[ ${1:-} == --confirm ]] || { echo "Usage: sudo ./uninstall_agent.sh --confirm" >&2; exit 2; }
systemctl disable --now pinoc-agent.service 2>/dev/null || true
rm -f /etc/systemd/system/pinoc-agent.service; systemctl daemon-reload
rm -rf /opt/pinoc-agent /etc/pinoc-agent /var/lib/pinoc-agent
userdel pinoc-agent 2>/dev/null || true
echo "Agent removed; project workspaces were preserved."
