#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="pi-noc"
SERVICE_NAME="pi-noc.service"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${REPO_DIR}/config.json"
VENV_DIR="${REPO_DIR}/.venv"
SERVICE_SOURCE="${REPO_DIR}/${SERVICE_NAME}"
SERVICE_DEST="/etc/systemd/system/${SERVICE_NAME}"
SUDOERS_DEST="/etc/sudoers.d/pi-noc-wireguard"
ENV_FILE="${REPO_DIR}/.env"
APT_PACKAGES=(
  python3
  python3-venv
  python3-pip
  python3-dev
  build-essential
  git
  i2c-tools
  python3-smbus
  fonts-dejavu-core
  wireguard-tools
  iproute2
  openssh-client
  sshpass
  rsync
)
APT_PACKAGE_ALTERNATIVES=(
  "libgpiod3 libgpiod2"
)

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARN:\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
need_root() { [[ ${EUID} -eq 0 ]] || fail "Run this installer with sudo: sudo ./install.sh"; }
run_as_user() { sudo -H -u "${INSTALL_USER}" "$@"; }

json_value() {
  local key="$1"
  python3 - "$CONFIG_FILE" "$key" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)
print(data.get(sys.argv[2], ""))
PY
}

prompt_default() {
  local var_name="$1" prompt="$2" default="$3" value
  read -r -p "${prompt} [${default}]: " value
  printf -v "$var_name" '%s' "${value:-$default}"
}

load_env_file() {
  [[ -f "$ENV_FILE" ]] || fail "Missing ${ENV_FILE}; copy .env.example to .env and set CM5_SSH_PASS"
  local line
  CM5_SSH_PASS=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ "$line" == CM5_SSH_PASS=* ]] || continue
    CM5_SSH_PASS="${line#CM5_SSH_PASS=}"
  done < "$ENV_FILE"
  [[ -n "$CM5_SSH_PASS" ]] || fail "Set CM5_SSH_PASS in ${ENV_FILE} before running the installer"
}

resolve_apt_alternative() {
  local candidate
  for candidate in "$@"; do
    if apt-cache show "$candidate" >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

install_system_dependencies() {
  log "Installing/verifying system dependencies"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update

  local packages=("${APT_PACKAGES[@]}") alternative resolved
  local -a candidates
  for alternative in "${APT_PACKAGE_ALTERNATIVES[@]}"; do
    read -r -a candidates <<< "$alternative"
    if resolved="$(resolve_apt_alternative "${candidates[@]}")"; then
      packages+=("$resolved")
    else
      fail "None of these alternative packages are available from apt: ${alternative}"
    fi
  done

  apt-get install -y --no-install-recommends "${packages[@]}"
}

enable_i2c() {
  log "Enabling I2C"
  if command -v raspi-config >/dev/null 2>&1; then
    raspi-config nonint do_i2c 0 || warn "raspi-config could not enable I2C"
  else
    warn "raspi-config not found; adding dtparam=i2c_arm=on manually"
  fi

  local boot_config="/boot/firmware/config.txt"
  [[ -f /boot/config.txt && ! -f "$boot_config" ]] && boot_config="/boot/config.txt"
  if [[ -f "$boot_config" ]] && ! grep -Eq '^dtparam=i2c_arm=on' "$boot_config"; then
    printf '\ndtparam=i2c_arm=on\n' >> "$boot_config"
  fi

  modprobe i2c-dev || warn "Could not load i2c-dev immediately; reboot may be required"
}

enable_spi() {
  log "Enabling SPI"
  if command -v raspi-config >/dev/null 2>&1; then
    raspi-config nonint do_spi 0 || warn "raspi-config could not enable SPI"
  else
    warn "raspi-config not found; adding dtparam=spi=on manually"
  fi

  local boot_config="/boot/firmware/config.txt"
  [[ -f /boot/config.txt && ! -f "$boot_config" ]] && boot_config="/boot/config.txt"
  if [[ -f "$boot_config" ]] && ! grep -Eq '^dtparam=spi=on' "$boot_config"; then
    printf '\ndtparam=spi=on\n' >> "$boot_config"
  fi
}

existing_hardware_groups() {
  local group
  for group in i2c gpio spi; do
    if getent group "$group" >/dev/null; then
      printf '%s\n' "$group"
    else
      warn "Group ${group} does not exist on this OS" >&2
    fi
  done
}

setup_user_groups() {
  log "Adding ${INSTALL_USER} to hardware access groups"
  local groups=() group
  mapfile -t groups < <(existing_hardware_groups)
  for group in "${groups[@]}"; do
    usermod -aG "$group" "$INSTALL_USER"
  done
}

setup_venv() {
  log "Creating/updating Python virtual environment"
  run_as_user python3 -m venv "$VENV_DIR"
  run_as_user "$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel
  run_as_user "$VENV_DIR/bin/python" -m pip install -r "${REPO_DIR}/requirements.txt"
}

install_service() {
  log "Installing systemd service"
  local tmp_service vpn_service groups=() supplementary_groups
  vpn_service="$(json_value vpn_service)"
  vpn_service="${vpn_service:-wg-quick@wg0.service}"
  tmp_service="$(mktemp)"
  mapfile -t groups < <(existing_hardware_groups)
  supplementary_groups="${groups[*]}"

  sed \
    -e "s#^User=.*#User=${INSTALL_USER}#" \
    -e "s#^Group=.*#Group=${INSTALL_USER}#" \
    -e "s#^WorkingDirectory=.*#WorkingDirectory=${REPO_DIR}#" \
    -e "s#^ExecStart=.*#ExecStart=${VENV_DIR}/bin/python ${REPO_DIR}/pi_noc.py#" \
    -e "s#^After=.*#After=network-online.target ${vpn_service}#" \
    "$SERVICE_SOURCE" > "$tmp_service"

  if ((${#groups[@]})); then
    sed -i "s#^SupplementaryGroups=.*#SupplementaryGroups=${supplementary_groups}#" "$tmp_service"
  else
    sed -i '/^SupplementaryGroups=/d' "$tmp_service"
  fi

  install -m 0644 "$tmp_service" "$SERVICE_DEST"
  rm -f "$tmp_service"
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
}

configure_wireguard_controls() {
  log "Configuring passwordless WireGuard status/restart controls"
  local vpn_service vpn_interface wg_bin systemctl_bin
  vpn_service="$(json_value vpn_service)"
  vpn_interface="$(json_value vpn_interface)"
  wg_bin="$(command -v wg || printf '/usr/bin/wg')"
  systemctl_bin="$(command -v systemctl || printf '/usr/bin/systemctl')"
  cat > "$SUDOERS_DEST" <<EOF_SUDOERS
# Managed by ${APP_NAME}/install.sh
${INSTALL_USER} ALL=(root) NOPASSWD: ${wg_bin} show ${vpn_interface} dump, ${systemctl_bin} restart ${vpn_service}, ${systemctl_bin} is-active ${vpn_service}
EOF_SUDOERS
  chmod 0440 "$SUDOERS_DEST"
  visudo -cf "$SUDOERS_DEST" >/dev/null
}

configure_ssh_to_cm5() {
  log "Configuring passwordless SSH to the CM5"
  local default_host default_user default_port ssh_host ssh_user ssh_port key_file target
  default_host="$(json_value remote_host)"
  default_user="$(json_value remote_user)"
  default_port="$(json_value remote_ssh_port)"
  prompt_default ssh_host "CM5 SSH host" "${default_host:-cm5}"
  prompt_default ssh_user "CM5 SSH user" "${default_user:-pi}"
  prompt_default ssh_port "CM5 SSH port" "${default_port:-22}"
  key_file="$(eval echo "~${INSTALL_USER}/.ssh/id_ed25519")"
  if [[ ! -f "$key_file" ]]; then
    run_as_user ssh-keygen -t ed25519 -N '' -f "$key_file" -C "${APP_NAME}@$(hostname)"
  fi

  target="${ssh_user}@${ssh_host}"
  SSHPASS="$CM5_SSH_PASS" sudo --preserve-env=SSHPASS -H -u "${INSTALL_USER}" \
    sshpass -e ssh-copy-id \
      -p "$ssh_port" \
      -o StrictHostKeyChecking=accept-new \
      "$target"

  run_as_user ssh \
    -p "$ssh_port" \
    -o BatchMode=yes \
    -o ConnectTimeout=5 \
    -o StrictHostKeyChecking=accept-new \
    "$target" true
}

main() {
  need_root
  INSTALL_USER="${SUDO_USER:-pi}"
  id "$INSTALL_USER" >/dev/null 2>&1 || fail "Install user ${INSTALL_USER} does not exist"
  [[ -f "$CONFIG_FILE" ]] || fail "Missing ${CONFIG_FILE}"
  [[ -f "$SERVICE_SOURCE" ]] || fail "Missing ${SERVICE_SOURCE}"
  load_env_file

  install_system_dependencies
  enable_i2c
  enable_spi
  setup_user_groups
  setup_venv
  configure_wireguard_controls
  configure_ssh_to_cm5
  install_service

  log "Installation complete"
  log "Reboot if I2C or new group membership was not already active, then start with: sudo systemctl start ${SERVICE_NAME}"
}

main "$@"
