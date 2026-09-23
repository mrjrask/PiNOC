#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo" >&2; exit 1; }
[[ ${1:-} == --confirm ]] || {
  echo "Usage: sudo ./uninstall_agent.sh --confirm [--server URL --token ADMIN_TOKEN]" >&2
  echo "  --server/--token (or PINOC_SERVER/PINOC_ADMIN_TOKEN) let this script also" >&2
  echo "  revoke the agent's credential server-side; without them you must revoke it" >&2
  echo "  yourself (PiNOC Agents page, or the API), or a recovered/extracted copy of" >&2
  echo "  /etc/pinoc-agent/config.json remains valid to impersonate this agent." >&2
  exit 2
}
shift
SERVER="${PINOC_SERVER:-}"
TOKEN="${PINOC_ADMIN_TOKEN:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER=${2:-}; shift 2;;
    --token) TOKEN=${2:-}; shift 2;;
    *) echo "Unknown argument: $1" >&2; exit 2;;
  esac
done

AGENT_ID=""
if [[ -r /etc/pinoc-agent/config.json ]]; then
  AGENT_ID=$(python3 -c "import json,sys
try:
    print(json.load(open('/etc/pinoc-agent/config.json')).get('agent_id') or '')
except Exception:
    pass" 2>/dev/null || true)
fi

REVOKED=0
if [[ -n "$SERVER" && -n "$TOKEN" && -n "$AGENT_ID" ]]; then
  if curl -fsS -X DELETE -H "Authorization: Bearer $TOKEN" \
      "${SERVER%/}/api/v1/dev/agents/$AGENT_ID/credential" >/dev/null; then
    REVOKED=1
  else
    echo "WARNING: could not revoke agent $AGENT_ID's credential server-side (request failed)." >&2
  fi
fi

systemctl disable --now pinoc-agent.service 2>/dev/null || true
rm -f /etc/systemd/system/pinoc-agent.service; systemctl daemon-reload
rm -rf /opt/pinoc-agent /etc/pinoc-agent
if [[ -d /var/lib/pinoc-agent && ! -L /var/lib/pinoc-agent ]]; then
  if [[ -n "$(find /var/lib/pinoc-agent -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "Preserving /var/lib/pinoc-agent because it contains user data." >&2
  else
    rmdir /var/lib/pinoc-agent
  fi
fi
userdel pinoc-agent 2>/dev/null || true

if [[ "$REVOKED" -eq 1 ]]; then
  echo "Agent removed; project workspaces were preserved. Credential $AGENT_ID revoked server-side."
elif [[ -n "$AGENT_ID" ]]; then
  echo "Agent removed; project workspaces were preserved."
  echo "IMPORTANT: agent $AGENT_ID's credential was NOT revoked server-side -- it" >&2
  echo "  remains valid until you revoke it (PiNOC Agents page, or" >&2
  echo "  DELETE /api/v1/dev/agents/$AGENT_ID/credential as an administrator)." >&2
else
  echo "Agent removed; project workspaces were preserved."
  echo "IMPORTANT: could not determine this agent's id, so its credential was NOT" >&2
  echo "  revoked server-side. Find and revoke it via the PiNOC Agents page before" >&2
  echo "  repurposing, reselling, or discarding this device." >&2
fi
