#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

PRIMARY_IFACE="${SGX_SURICATA_IFACE:-}"
if [[ -z "${PRIMARY_IFACE}" ]]; then
  PRIMARY_IFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
fi
if [[ -z "${PRIMARY_IFACE}" ]]; then
  PRIMARY_IFACE="eth0"
fi

HOME_NET_CIDR="${SGX_SURICATA_HOME_NET:-}"
if [[ -z "${HOME_NET_CIDR}" ]]; then
  HOME_NET_CIDR="$(ip -o -f inet addr show "${PRIMARY_IFACE}" 2>/dev/null | awk '{print $4; exit}')"
fi
if [[ -z "${HOME_NET_CIDR}" ]]; then
  HOME_NET_CIDR="[192.168.100.0/24,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
fi

warn() {
  echo "WARN: $*" >&2
}

install_nmap() {
  echo "-> Installing nmap (Sprint 6 NMP-series)..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y nmap || return 1
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y nmap || return 1
  elif command -v opkg >/dev/null 2>&1; then
    opkg update && opkg install nmap || return 1
  else
    warn "No supported package manager (apt/dnf/opkg). Skipping nmap install."
    return 0
  fi
}

configure_nmap() {
  if command -v nmap >/dev/null 2>&1; then
    if command -v setcap >/dev/null 2>&1; then
      setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)" || \
        warn "setcap failed - NMAP will fall back to TCP-connect mode."
    fi
    echo "-> nmap ready at $(command -v nmap)"
  else
    warn "nmap not on PATH after install attempt. Discovery scheduler will report BinaryMissing."
  fi
}

suricata_candidate_available() {
  local candidate
  candidate="$(apt-cache policy suricata 2>/dev/null | awk '/Candidate:/ {print $2; exit}')"
  [[ -n "${candidate}" && "${candidate}" != "(none)" ]]
}

ensure_suricata_repo() {
  if ! command -v apt-get >/dev/null 2>&1 || suricata_candidate_available; then
    return 0
  fi

  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
  fi

  if [[ "${ID:-}" == "ubuntu" ]]; then
    echo "-> Adding OISF Suricata PPA for Ubuntu ${VERSION_ID:-unknown}..."
    apt-get install -y software-properties-common ca-certificates gnupg
    if ! grep -Rqs "oisf/suricata-stable" /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
      add-apt-repository -y ppa:oisf/suricata-stable
    fi
    apt-get update
  fi
}

install_suricata() {
  echo "-> Installing suricata (Sprint 8 SUR-series)..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    ensure_suricata_repo
    apt-get install -y suricata jq || return 1
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y suricata jq || return 1
  else
    warn "Suricata auto-install is only configured for apt/dnf environments. Skipping package install."
    return 0
  fi
}

configure_suricata() {
  if ! command -v suricata >/dev/null 2>&1; then
    warn "suricata not found on PATH after install attempt. Threat service will stay disabled until installed."
    return 0
  fi

  mkdir -p /etc/sgx-guardian/threat
  mkdir -p /var/lib/sgx-guardian/threat
  mkdir -p /etc/suricata/rules
  mkdir -p /var/lib/suricata/rules
  mkdir -p /var/log/suricata

  install -m 0644 config/threat/config.yaml /etc/sgx-guardian/threat/config.yaml
  install -m 0644 packaging/guardian-custom.rules /etc/suricata/rules/guardian-custom.rules
  sed \
    -e "s|__INTERFACE__|${PRIMARY_IFACE}|g" \
    -e "s|__HOME_NET__|${HOME_NET_CIDR}|g" \
    packaging/suricata.yaml.template > /etc/suricata/suricata.yaml

  if command -v suricata-update >/dev/null 2>&1; then
    suricata-update --no-test || warn "suricata-update failed - daemon will retry later."
  fi

  if [[ -e /var/lib/suricata/rules/suricata.rules ]]; then
    ln -sf /var/lib/suricata/rules/suricata.rules /etc/suricata/rules/suricata.rules
  fi

  suricata -T -c /etc/suricata/suricata.yaml

  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable suricata
    systemctl restart suricata
  else
    warn "systemctl not available. Start suricata manually after install."
  fi
}

if ! install_nmap; then
    echo "⚠ nmap install failed. Continuing without hard-fail."
fi
configure_nmap
install_suricata
configure_suricata
