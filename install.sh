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
DATA_DIR="${REPO_DIR}/data"
APT_PACKAGES=(
  python3
  python3-venv
  python3-pip
  python3-dev
  build-essential
  git
  i2c-tools
  python3-smbus
  libgpiod3
  fonts-dejavu-core
  wireguard-tools
  iproute2
  openssh-client
  sshpass
  rsync
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
  [[ -f "$ENV_FILE" ]] || fail "Missing ${ENV_FILE}; copy .env.example to .env"
  local line
  CM5_SSH_PASS=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    case "$line" in
      CM5_SSH_PASS=*) CM5_SSH_PASS="${line#CM5_SSH_PASS=}" ;;
      DISPLAY=*) DISPLAY="${line#DISPLAY=}" ;;
      PINOC_DISPLAY_ENABLED=*) PINOC_DISPLAY_ENABLED="${line#PINOC_DISPLAY_ENABLED=}" ;;
      PINOC_WEB_ENABLED=*) PINOC_WEB_ENABLED="${line#PINOC_WEB_ENABLED=}" ;;
      PINOC_WEB_HOST=*) PINOC_WEB_HOST="${line#PINOC_WEB_HOST=}" ;;
      PINOC_WEB_PORT=*) PINOC_WEB_PORT="${line#PINOC_WEB_PORT=}" ;;
      PINOC_AUTH_ENABLED=*) PINOC_AUTH_ENABLED="${line#PINOC_AUTH_ENABLED=}" ;;
      PINOC_DATABASE_PATH=*) PINOC_DATABASE_PATH="${line#PINOC_DATABASE_PATH=}" ;;
    esac
  done < "$ENV_FILE"
}

configure_frontends() {
  local display_enabled display_type web_enabled web_host web_port
  prompt_default display_enabled "Enable physical display (1/0)" "${PINOC_DISPLAY_ENABLED:-1}"
  prompt_default auth_enabled "Enable PiNOC web authentication (1/0)" "${PINOC_AUTH_ENABLED:-1}"
  prompt_default display_type "Display type (ADA_BONNET/PIM_DHM)" "${DISPLAY:-ADA_BONNET}"
  [[ "$display_type" == "ADA_BONNET" || "$display_type" == "PIM_DHM" ]] || fail "Unsupported display type: ${display_type}"
  prompt_default web_enabled "Enable web console (1/0)" "${PINOC_WEB_ENABLED:-1}"
  web_host="${PINOC_WEB_HOST:-0.0.0.0}"
  prompt_default web_port "Web console port" "${PINOC_WEB_PORT:-8088}"
  [[ "$web_port" =~ ^[0-9]+$ ]] && ((web_port >= 1 && web_port <= 65535)) || fail "Invalid web port: ${web_port}"
  python3 - "$ENV_FILE" "$display_enabled" "$display_type" "$web_enabled" "$web_host" "$web_port" "$auth_enabled" <<'PY'
import sys
path, display_enabled, display_type, web_enabled, web_host, web_port, auth_enabled = sys.argv[1:]
values = {"PINOC_DISPLAY_ENABLED": display_enabled, "DISPLAY": display_type,
          "PINOC_WEB_ENABLED": web_enabled, "PINOC_WEB_HOST": web_host, "PINOC_WEB_PORT": web_port,
          "PINOC_AUTH_ENABLED": auth_enabled}
lines = open(path, encoding="utf-8").read().splitlines()
seen = set()
for index, line in enumerate(lines):
    key = line.split("=", 1)[0]
    if key in values:
        lines[index] = f"{key}={values[key]}"
        seen.add(key)
lines.extend(f"{key}={value}" for key, value in values.items() if key not in seen)
open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
PY
}

install_system_dependencies() {
  log "Installing/verifying system dependencies"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update

  apt-get install -y --no-install-recommends "${APT_PACKAGES[@]}"
}

# Pillow is built with JPEG2000 (OpenJPEG) support, and a missing libopenjp2
# runtime library makes `import PIL.Image` fail, which crash-loops pi-noc.service
# when the display is enabled. The apt package name differs across releases
# (libopenjp2-7 on Debian bookworm/trixie, libopenjp2-2.3 on bullseye,
# libopenjp2-7-1/-2 on Ubuntu), so try candidates until the library resolves.
install_openjpeg() {
  local package
  if ldconfig -p 2>/dev/null | grep -q 'libopenjp2\.so'; then
    return 0
  fi
  for package in libopenjp2-7 libopenjp2-7-1 libopenjp2-7-2 libopenjp2-2.3; do
    if apt-get install -y --no-install-recommends -- "$package" 2>/dev/null; then
      if ldconfig -p 2>/dev/null | grep -q 'libopenjp2\.so'; then
        return 0
      fi
      warn "${package} installed but libopenjp2 is still unresolvable"
    else
      log "OpenJPEG package ${package} is not available on this release"
    fi
  done
  fail "Pillow requires the OpenJPEG runtime library (libopenjp2.so); install the libopenjp2 package for your distro"
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

# pi_noc.py imports PIL.Image at startup when the display is enabled; fail the
# install early with an actionable message instead of letting the service crash-loop.
verify_python_environment() {
  if [[ "${PINOC_DISPLAY_ENABLED:-1}" == "0" ]]; then
    log "Display disabled; skipping Pillow verification"
    return 0
  fi
  if run_as_user "$VENV_DIR/bin/python" -c "import PIL.Image" >/dev/null 2>&1; then
    log "Pillow is importable in the venv"
    return 0
  fi
  fail "Pillow cannot be imported into ${VENV_DIR}; a missing system library (most often the OpenJPEG libopenjp2 library) is the usual cause; install it, then re-run sudo ./install.sh"
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
    -e "s#^EnvironmentFile=.*#EnvironmentFile=-${ENV_FILE}#" \
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
  prompt_default ssh_host "CM5 SSH host" "${default_host:-192.168.1.200}"
  prompt_default ssh_user "CM5 SSH user" "${default_user:-pi}"
  prompt_default ssh_port "CM5 SSH port" "${default_port:-22}"
  key_file="$(eval echo "~${INSTALL_USER}/.ssh/id_ed25519")"
  if [[ ! -f "$key_file" ]]; then
    run_as_user ssh-keygen -t ed25519 -N '' -f "$key_file" -C "${APP_NAME}@$(hostname)"
  fi

  target="${ssh_user}@${ssh_host}"
  if run_as_user ssh \
    -p "$ssh_port" \
    -o BatchMode=yes \
    -o ConnectTimeout=5 \
    -o StrictHostKeyChecking=accept-new \
    "$target" true; then
    log "Existing SSH key authentication works for ${target}"
    return
  fi
  [[ -n "$CM5_SSH_PASS" ]] || fail "SSH key authentication failed; set CM5_SSH_PASS temporarily to provision the key"
  SSHPASS="$CM5_SSH_PASS" sudo --preserve-env=SSHPASS -H -u "${INSTALL_USER}" \
    sshpass -e ssh-copy-id -p "$ssh_port" -o StrictHostKeyChecking=accept-new "$target"
  run_as_user ssh -p "$ssh_port" -o BatchMode=yes -o ConnectTimeout=5 \
    -o StrictHostKeyChecking=accept-new "$target" true
}

main() {
  (cd "$REPO_DIR" && python3 -m pinoc.validate_config) || fail "PiNOC configuration validation failed"
  need_root
  INSTALL_USER="${SUDO_USER:-pi}"
  id "$INSTALL_USER" >/dev/null 2>&1 || fail "Install user ${INSTALL_USER} does not exist"
  [[ -f "$CONFIG_FILE" ]] || fail "Missing ${CONFIG_FILE}"
  [[ -f "$SERVICE_SOURCE" ]] || fail "Missing ${SERVICE_SOURCE}"
  load_env_file
  configure_frontends

  install_system_dependencies
  install_openjpeg
  enable_i2c
  enable_spi
  setup_user_groups
  setup_venv
  verify_python_environment
  log "Creating persistent history directory (existing databases are preserved)"
  install -d -m 0750 -o "$INSTALL_USER" -g "$INSTALL_USER" "$(dirname "${PINOC_DATABASE_PATH:-$DATA_DIR/pinoc.db}")"
  configure_wireguard_controls
  configure_ssh_to_cm5
  install_service

  log "Installation complete"
  log "Web console: http://$(hostname -I 2>/dev/null | awk '{print $1}'):${web_port}/ (when enabled)"
  log "Reboot if I2C or new group membership was not already active, then start with: sudo systemctl start ${SERVICE_NAME}"
  if [[ ${auth_enabled:-1} == 1 ]]; then
    log "Create the initial administrator before exposing the web port: sudo -u ${INSTALL_USER} ${VENV_DIR}/bin/python -m pinoc.admin create-user --role administrator USERNAME"
  else
    log "WARNING: authentication is disabled; every client able to reach PiNOC has trusted-LAN administrator access. HTTP is not encrypted."
  fi
}

main "$@"
