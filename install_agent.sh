#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo" >&2; exit 1; }
SERVER=${1:?Usage: sudo ./install_agent.sh https://pinoc.example enrollment-code [discovery-root ...]}
CODE=${2:?Enrollment code required}; shift 2
if ! command -v bwrap >/dev/null 2>&1; then
  command -v apt-get >/dev/null 2>&1 || { echo "bubblewrap is required, but apt-get is unavailable" >&2; exit 1; }
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends bubblewrap
fi
id pinoc-agent &>/dev/null || useradd --system --home /var/lib/pinoc-agent --create-home --shell /usr/sbin/nologin pinoc-agent

# Device nodes keep their host ownership and mode when they are bind-mounted
# into Bubblewrap's private /dev.  Give the unprivileged agent the conventional
# supplementary groups that are present on this host so an explicitly approved
# node remains usable in the sandbox.  Missing groups are normal (for example,
# non-Pi hosts often have no gpio or spi group), so only add existing ones.
hardware_groups=()
for group in gpio i2c spi video render; do
  getent group "$group" >/dev/null && hardware_groups+=("$group")
done
if ((${#hardware_groups[@]})); then
  usermod -aG "$(IFS=,; echo "${hardware_groups[*]}")" pinoc-agent
fi

install -d -o root -g pinoc-agent -m 0750 /etc/pinoc-agent /opt/pinoc-agent /var/lib/pinoc-agent
python3 -m venv /opt/pinoc-agent/venv
/opt/pinoc-agent/venv/bin/pip install --disable-pip-version-check --no-deps -e "$(cd "$(dirname "$0")" && pwd)" 2>/dev/null || true
install -m 0755 "$(dirname "$0")/pinoc_agent.py" /opt/pinoc-agent/pinoc_agent.py
install -d /opt/pinoc-agent/pinoc; install -m 0644 "$(dirname "$0")/pinoc/development.py" "$(dirname "$0")/pinoc/database.py" "$(dirname "$0")/pinoc/security.py" /opt/pinoc-agent/pinoc/
printf '{"server":%s,"discovery_roots":%s}\n' "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$SERVER")" "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1:]))' "$@")" > /etc/pinoc-agent/config.json
chmod 0600 /etc/pinoc-agent/config.json; chown pinoc-agent:pinoc-agent /etc/pinoc-agent/config.json
/opt/pinoc-agent/venv/bin/python /opt/pinoc-agent/pinoc_agent.py --config /etc/pinoc-agent/config.json --enroll --code "$CODE"
install -m 0644 "$(dirname "$0")/pinoc-agent.service" /etc/systemd/system/pinoc-agent.service
systemctl daemon-reload; systemctl enable --now pinoc-agent.service
echo "PiNOC agent installed; no SSH credentials were configured."
