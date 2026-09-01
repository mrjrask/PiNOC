#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo" >&2; exit 1; }
SERVER=${1:?Usage: sudo ./install_agent.sh https://pinoc.example enrollment-code [discovery-root ...]}
CODE=${2:?Enrollment code required}; shift 2
id pinoc-agent &>/dev/null || useradd --system --home /var/lib/pinoc-agent --create-home --shell /usr/sbin/nologin pinoc-agent
install -d -o root -g pinoc-agent -m 0750 /etc/pinoc-agent /opt/pinoc-agent /var/lib/pinoc-agent
python3 -m venv /opt/pinoc-agent/venv
/opt/pinoc-agent/venv/bin/pip install --disable-pip-version-check --no-deps -e "$(cd "$(dirname "$0")" && pwd)" 2>/dev/null || true
install -m 0755 "$(dirname "$0")/pinoc_agent.py" /opt/pinoc-agent/pinoc_agent.py
install -d /opt/pinoc-agent/pinoc; install -m 0644 "$(dirname "$0")/pinoc/development.py" "$(dirname "$0")/pinoc/database.py" "$(dirname "$0")/pinoc/security.py" /opt/pinoc-agent/pinoc/
printf '{"server":%s,"discovery_roots":%s}\n' "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$SERVER")" "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1:]))' "$@")" > /etc/pinoc-agent/config.json
chmod 0600 /etc/pinoc-agent/config.json; chown root:pinoc-agent /etc/pinoc-agent/config.json
/opt/pinoc-agent/venv/bin/python /opt/pinoc-agent/pinoc_agent.py --config /etc/pinoc-agent/config.json --enroll --code "$CODE"
install -m 0644 "$(dirname "$0")/pinoc-agent.service" /etc/systemd/system/pinoc-agent.service
systemctl daemon-reload; systemctl enable --now pinoc-agent.service
echo "PiNOC agent installed; no SSH credentials were configured."
