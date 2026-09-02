# SGX Guardian Cloud Broker — VPS Deployment Guide

## Overview

The VPS runs two services:
1. **`sgx-broker`** — HTTP/WS enrollment relay (port 8080/tcp)
2. **`nebula`** — Mesh lighthouse + relay (port 4242/udp)

## Step 1: Issue VPS Certificate (on Node A)

```bash
cd /var/lib/sgx-guardian/nebula

nebula-cert sign \
  -name "vps-lighthouse" \
  -ip "192.168.100.10/24" \
  -groups "lighthouse,relay" \
  -ca-crt ca/ca.crt \
  -ca-key ca/ca.key

# Copy to VPS
scp ca/ca.crt vps-lighthouse.crt vps-lighthouse.key user@<VPS_IP>:/etc/nebula/
```

## Step 2: Install Nebula on VPS

```bash
# Download latest release
curl -L -o nebula.tar.gz https://github.com/slackhq/nebula/releases/download/v1.9.5/nebula-linux-amd64.tar.gz
tar xzf nebula.tar.gz
sudo mv nebula nebula-cert /usr/local/bin/

# Copy the reference config
sudo mkdir -p /etc/nebula
sudo cp nebula-vps.yaml /etc/nebula/config.yaml

# Test config
nebula -config /etc/nebula/config.yaml -test
```

## Step 3: Upload Broker Binary

```bash
# Build on your dev machine:
cargo build -p sgx-broker --release

# Upload:
scp target/release/sgx-broker user@<VPS_IP>:/usr/local/bin/
```

## Step 4: Install Systemd Services

```bash
# Nebula service (if not already present)
sudo tee /etc/systemd/system/nebula.service <<'EOF'
[Unit]
Description=Nebula Overlay Network
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/nebula -config /etc/nebula/config.yaml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Broker service
sudo cp sgx-broker.service /etc/systemd/system/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now nebula
sudo systemctl enable --now sgx-broker
```

## Step 5: Open Firewall Ports

```bash
sudo ufw allow 8080/tcp   # Broker HTTP/WS
sudo ufw allow 4242/udp   # Nebula mesh
sudo ufw enable
```

## Step 6: Verify

```bash
# Check broker health
curl http://localhost:8080/health

# Check nebula interface
ip addr show nebula0

# Check services
sudo systemctl status nebula sgx-broker
```

## Node Configuration

### Node A (Home CA)
Set these environment variables before starting the SGX Guardian service:
```bash
export SGX_BROKER_URL=http://<VPS_IP>:8080
export SGX_BROKER_TOKEN=your-secret-token     # optional
export SGX_VPS_PUBLIC_IP=<VPS_IP>
export SGX_VPS_OVERLAY_IP=192.168.100.10
```

### Node C (Remote Board)
```bash
export SGX_BROKER_URL=http://<VPS_IP>:8080
```
