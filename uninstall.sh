#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="pi-noc"
SERVICE_NAME="pi-noc.service"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${REPO_DIR}/.venv"
SERVICE_DEST="/etc/systemd/system/${SERVICE_NAME}"
SUDOERS_DEST="/etc/sudoers.d/pi-noc-wireguard"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARN:\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
need_root() { [[ ${EUID} -eq 0 ]] || fail "Run this uninstaller with sudo: sudo ./uninstall.sh"; }

stop_service() {
  log "Stopping and disabling ${SERVICE_NAME}"
  if systemctl list-unit-files "${SERVICE_NAME}" >/dev/null 2>&1 || [[ -f "$SERVICE_DEST" ]]; then
    systemctl stop "$SERVICE_NAME" || warn "Could not stop ${SERVICE_NAME}; it may already be inactive"
    systemctl disable "$SERVICE_NAME" || warn "Could not disable ${SERVICE_NAME}; it may not be enabled"
  else
    warn "${SERVICE_NAME} is not installed"
  fi
}

remove_service() {
  log "Removing systemd service"
  if [[ -f "$SERVICE_DEST" ]]; then
    rm -f "$SERVICE_DEST"
  else
    warn "Service file ${SERVICE_DEST} does not exist"
  fi
  systemctl daemon-reload
  systemctl reset-failed "$SERVICE_NAME" >/dev/null 2>&1 || true
}

remove_sudoers() {
  log "Removing ${APP_NAME} sudoers rule"
  if [[ -f "$SUDOERS_DEST" ]]; then
    rm -f "$SUDOERS_DEST"
  else
    warn "Sudoers file ${SUDOERS_DEST} does not exist"
  fi
}

remove_venv() {
  log "Removing Python virtual environment"
  if [[ -d "$VENV_DIR" ]]; then
    rm -rf "$VENV_DIR"
  else
    warn "Virtual environment ${VENV_DIR} does not exist"
  fi
}

main() {
  need_root
  stop_service
  remove_service
  remove_sudoers
  remove_venv
  log "Uninstall complete"
}

main "$@"
