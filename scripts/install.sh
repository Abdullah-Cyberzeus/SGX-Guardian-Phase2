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

suricata_candidate_available() {
  local candidate
  candidate="$(apt-cache policy suricata 2>/dev/null | awk '/Candidate:/ {print $2; exit}')"
  [[ -n "${candidate}" && "${candidate}" != "(none)" ]]
}

ensure_suricata_repo() {
  if suricata_candidate_available; then
    return 0
  fi

  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
  fi

  if [[ "${ID:-}" == "ubuntu" ]]; then
    echo "-> No Suricata apt candidate found on Ubuntu ${VERSION_ID:-unknown}; adding OISF Suricata PPA..."
    apt-get install -y software-properties-common ca-certificates gnupg
    if ! grep -Rqs "oisf/suricata-stable" /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
      add-apt-repository -y ppa:oisf/suricata-stable
    fi
    apt-get update
  fi

  if ! suricata_candidate_available; then
    echo "ERROR: Suricata package still has no installation candidate after repository setup." >&2
    echo "       Verify apt sources or install Suricata manually, then rerun this script." >&2
    exit 1
  fi
}

echo "-> Installing suricata (Sprint 8 SUR-series)..."
apt-get update
ensure_suricata_repo
apt-get install -y suricata jq

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

suricata-update --no-test || echo "WARNING: suricata-update failed - will retry from daemon"
ln -sf /var/lib/suricata/rules/suricata.rules /etc/suricata/rules/suricata.rules
suricata -T -c /etc/suricata/suricata.yaml

systemctl enable suricata
systemctl restart suricata
