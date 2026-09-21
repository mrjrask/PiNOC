#!/usr/bin/env bash
set -Eeuo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${REPO_DIR}/.venv"
REQUIREMENTS_FILE="${REPO_DIR}/requirements.txt"
REQUIREMENTS_STAMP="${VENV_DIR}/.pinoc-requirements.sha256"
PYTHON="${VENV_DIR}/bin/python"

if [[ ! -x "$PYTHON" ]]; then
  echo "ERROR: PiNOC virtual environment is missing at ${VENV_DIR}. Run: sudo ${REPO_DIR}/install.sh" >&2
  exit 1
fi

if [[ ! -f "$REQUIREMENTS_FILE" ]]; then
  echo "ERROR: Missing ${REQUIREMENTS_FILE}" >&2
  exit 1
fi

requirements_hash="$(sha256sum "$REQUIREMENTS_FILE" | awk '{print $1}')"
installed_hash="$(cat "$REQUIREMENTS_STAMP" 2>/dev/null || true)"
needs_sync=0

# A changed requirements file means a git update may have introduced a new
# runtime dependency. Also verify the core web/development imports that must be
# available before pi_noc.py starts, so a stale or manually altered venv heals
# itself even if the stamp happens to match.
if [[ "$requirements_hash" != "$installed_hash" ]]; then
  needs_sync=1
elif ! "$PYTHON" -c 'import flask, waitress; from cryptography.fernet import Fernet' >/dev/null 2>&1; then
  needs_sync=1
fi

if ((needs_sync)); then
  echo "PiNOC Python dependencies are missing or changed; synchronizing virtual environment..."
  "$PYTHON" -m pip install -r "$REQUIREMENTS_FILE"
  printf '%s\n' "$requirements_hash" > "$REQUIREMENTS_STAMP"
fi

exec "$PYTHON" "${REPO_DIR}/pi_noc.py"
