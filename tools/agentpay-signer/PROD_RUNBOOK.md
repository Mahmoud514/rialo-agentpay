# Rialo AgentPay Hardened Signer — Production Runbook

## Overview

This document provides the complete installation, configuration, and operational procedures for running the Hardened Signer as a persistent systemd service.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  systemd                                                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ agentpay-signer.service                                 │   │
│  │  • Runs as user: agentpay-signer                        │   │
│  │  • Binds: 127.0.0.1:9000 only                          │   │
│  │  • Restart: on-failure, max 5/30sec                    │   │
│  │  • Binary pin verification before start                │   │
│  │  • Environment from: /etc/agentpay-signer/env          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                          │                                      │
│  ┌───────────────────────┴────────────────────────────────┐   │
│  │         /var/lib/agentpay-signer (0700)                 │   │
│  │  • {agent_id}.wallet.json  — public wallet records     │   │
│  │  • {agent_id}.key.json     — private key containers    │   │
│  │  • signer_identity.key.json — channel auth key         │   │
│  └────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Linux VPS with systemd (Ubuntu 22.04+, Debian 12+, RHEL 9+)
- Root access for initial setup
- Existing AgentPay deployment and `.env` configuration

## Installation

### 1. Create Dedicated User

```bash
# Create system user with no shell
sudo useradd --system \
    --no-create-home \
    --shell /usr/sbin/nologin \
    --home-dir /var/lib/agentpay-signer \
    agentpay-signer
```

### 2. Create Directories

```bash
# Store directory (signer data)
sudo mkdir -p /var/lib/agentpay-signer
sudo chown agentpay-signer:agentpay-signer /var/lib/agentpay-signer
sudo chmod 0700 /var/lib/agentpay-signer

# Config directory
sudo mkdir -p /etc/agentpay-signer
sudo chmod 0750 /etc/agentpay-signer

# Binary directory
sudo mkdir -p /opt/agentpay-signer/bin
```

### 3. Build and Install Binary

```bash
cd ~/rialo-agentpay/tools/agentpay-signer
cargo build --release

# Install binary
sudo cp target/release/agentpay-signer /opt/agentpay-signer/bin/
sudo chown root:root /opt/agentpay-signer/bin/agentpay-signer
sudo chmod 0755 /opt/agentpay-signer/bin/agentpay-signer
```

### 4. Generate Initial Pin and Channel Key

```bash
# Start once to generate channel key and get handshake
sudo -u agentpay-signer /opt/agentpay-signer/bin/agentpay-signer &
SIGNER_PID=$!
sleep 2

# Get handshake (contains channel pubkey and binary digest)
curl -s http://127.0.0.1:9000/handshake | tee /tmp/handshake.json

# Extract values
CHANNEL_PUBKEY=$(jq -r '.channel_pubkey' /tmp/handshake.json)
BINARY_DIGEST=$(jq -r '.binary_digest' /tmp/handshake.json)

echo "Channel Pubkey: $CHANNEL_PUBKEY"
echo "Binary Digest: $BINARY_DIGEST"

# Stop the temporary signer
kill $SIGNER_PID 2>/dev/null

# Create binary pin file
echo "$BINARY_DIGEST  /opt/agentpay-signer/bin/agentpay-signer" | \
    sudo tee /etc/agentpay-signer/binary.pin
```

### 5. Create Policy File

```bash
# Example policy - adjust for your needs
sudo tee /etc/agentpay-signer/policy.json << 'EOF'
{
  "schema_version": 1,
  "recipients": [
    "7siRGNwSzvpCqdsZw5tjsz4XZ1SrpMXqKsr4zEjBVr1a"
  ],
  "max_per_tx_kelvin": 100000000,
  "max_tx_per_day": 100
}
EOF
sudo chmod 0640 /etc/agentpay-signer/policy.json
```

### 6. Generate Admin Secret

```bash
# Generate secure admin secret (e.g., 64 hex chars)
ADMIN_SECRET=$(openssl rand -hex 32)
echo "Generated admin secret (save this): $ADMIN_SECRET"
```

### 7. Configure Environment

```bash
# Copy template and edit
sudo tee /etc/agentpay-signer/env << EOF
# Required configuration
AGENTPAY_SIGNER_ENDPOINT=127.0.0.1:9000
AGENTPAY_SIGNER_STORE=/var/lib/agentpay-signer
AGENTPAY_SIGNER_SIGNING_ENABLED=1
AGENTPAY_SIGNER_POLICY=/etc/agentpay-signer/policy.json
AGENTPAY_SIGNER_ADMIN_SECRET=$ADMIN_SECRET
AGENTPAY_SIGNER_CHANNEL_PUBKEY=$CHANNEL_PUBKEY
AGENTPAY_SIGNER_BINARY_PIN=$BINARY_DIGEST
# Optional: provision agents at startup
# AGENTPAY_SIGNER_PROVISION_AGENTS=agent_id:auth_pubkey,...
EOF

# Secure permissions
sudo chmod 0600 /etc/agentpay-signer/env
sudo chown root:root /etc/agentpay-signer/env
```

### 8. Install Systemd Service

```bash
sudo cp ~/rialo-agentpay/tools/agentpay-signer/agentpay-signer.service \
        /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable agentpay-signer.service
```

### 9. Start and Verify

```bash
# Start service
sudo systemctl start agentpay-signer

# Check status
sudo systemctl status agentpay-signer

# Verify health endpoint
curl -s http://127.0.0.1:9000/health | jq .

# Verify handshake
SIGNER_CHANNEL=$(curl -s http://127.0.0.1:9000/handshake | jq -r '.channel_pubkey')
if [ "$SIGNER_CHANNEL" = "$CHANNEL_PUBKEY" ]; then
    echo "✓ Channel pubkey matches"
else
    echo "✗ Channel mismatch!"
fi
```

## Operations

### Start/Stop/Restart

```bash
sudo systemctl start agentpay-signer
sudo systemctl stop agentpay-signer
sudo systemctl restart agentpay-signer
```

### View Logs

```bash
# Real-time logs
sudo journalctl -u agentpay-signer -f

# Recent logs
sudo journalctl -u agentpay-signer --since "1 hour ago"

# Full logs since boot
sudo journalctl -u agentpay-signer --boot
```

### Status Checks

```bash
# systemd service status
sudo systemctl status agentpay-signer

# Health endpoint
curl -s http://127.0.0.1:9000/health

# Handshake with signature verification
curl -s http://127.0.0.1:9000/handshake
```

### List Registered Agents

```bash
ls -la /var/lib/agentpay-signer/*.wallet.json
```

## Binary Update Procedure

### Controlled Upgrade Steps

1. **Backup current state:**
```bash
sudo systemctl stop agentpay-signer
sudo cp -a /var/lib/agentpay-signer /var/lib/agentpay-signer.bak.$(date +%Y%m%d)
```

2. **Build new binary:**
```bash
cd ~/rialo-agentpay/tools/agentpay-signer
cargo build --release
```

3. **Get new pin:**
```bash
NEW_DIGEST=$(sha256sum target/release/agentpay-signer | cut -d' ' -f1)
echo "New binary digest: $NEW_DIGEST"
```

4. **Verify in staging (if available):**
```bash
# Test binary launches
./target/release/agentpay-signer --help
# Or run with temporary store
```

5. **Install new binary:**
```bash
sudo cp target/release/agentpay-signer /opt/agentpay-signer/bin/agentpay-signer-new
sudo chown root:root /opt/agentpay-signer/bin/agentpay-signer-new
sudo chmod 0755 /opt/agentpay-signer/bin/agentpay-signer-new
```

6. **Get new handshake (new channel key):**
```bash
sudo -u agentpay-signer /opt/agentpay-signer/bin/agentpay-signer-new &
PID=$!
sleep 2
NEW_CHANNEL=$(curl -s http://127.0.0.1:9000/handshake | jq -r '.channel_pubkey')
kill $PID 2>/dev/null
```

7. **Update configuration:**
```bash
# Update pin in env file
sudo sed -i "s/AGENTPAY_SIGNER_BINARY_PIN=.*/AGENTPAY_SIGNER_BINARY_PIN=$NEW_DIGEST/" \
    /etc/agentpay-signer/env

# Update channel pubkey (if signing capability uses it)
sudo sed -i "s/AGENTPAY_SIGNER_CHANNEL_PUBKEY=.*/AGENTPAY_SIGNER_CHANNEL_PUBKEY=$NEW_CHANNEL/" \
    /etc/agentpay-signer/env

# Update binary pin file
echo "$NEW_DIGEST  /opt/agentpay-signer/bin/agentpay-signer" | \
    sudo tee /etc/agentpay-signer/binary.pin
```

8. **Swap binaries:**
```bash
sudo mv /opt/agentpay-signer/bin/agentpay-signer \
        /opt/agentpay-signer/bin/agentpay-signer.old
sudo mv /opt/agentpay-signer/bin/agentpay-signer-new \
        /opt/agentpay-signer/bin/agentpay-signer
```

9. **Start service:**
```bash
sudo systemctl start agentpay-signer
sudo systemctl status agentpay-signer
```

10. **Verify:**
```bash
# Health check
curl -s http://127.0.0.1:9000/health | jq .

# Agents still recoverable from store
curl -s http://127.0.0.1:9000/wallet/YOUR_AGENT_ID
```

## Troubleshooting

### Service Won't Start

```bash
# Check for errors
sudo systemctl status agentpay-signer
sudo journalctl -u agentpay-signer -n 50

# Verify binary pin
cat /etc/agentpay-signer/binary.pin
sha256sum /opt/agentpay-signer/bin/agentpay-signer

# Check config file permissions
ls -la /etc/agentpay-signer/
sudo -u agentpay-signer cat /etc/agentpay-signer/env
```

### Binary Pin Mismatch

If the signer exits with "binary pin verification failed":

```bash
# Get actual digest
ACTUAL=$(sha256sum /opt/agentpay-signer/bin/agentpay-signer | cut -d' ' -f1)
echo "Actual: $ACTUAL"

# Get expected digest
EXPECTED=$(grep -v '^#' /etc/agentpay-signer/env | grep BINARY_PIN | cut -d= -f2)
echo "Expected: $EXPECTED"
```

### Agent Shows Unknown After Restart

The signer now automatically recovers persisted wallet files. If an agent
still shows as unknown:

```bash
# Check wallet files exist
ls -la /var/lib/agentpay-signer/AGENT_ID.wallet.json
ls -la /var/lib/agentpay-signer/AGENT_ID.key.json

# Verify file integrity (check they match)
cat /var/lib/agentpay-signer/AGENT_ID.wallet.json
```

## Security Considerations

### What This Protects Against

| Threat | Protection |
|--------|------------|
| Process isolation | ✓ Dedicated user, no_new_privs, cleared caps |
| File isolation | ✓ 0700 store, no access from app user |
| Binary substitution | ✓ Startup pin verification |
| Loopback impersonation | ✓ Channel auth, signed responses |
| Root compromise | ✗ NOT protected — requires hardware/TEE |
| Network exposure | ✗ 127.0.0.1 only — never expose 9000 to network |

### Key Files and Permissions

```
/etc/agentpay-signer/env              0600 root:root
/etc/agentpay-signer/binary.pin       0644 root:root
/etc/agentpay-signer/policy.json      0640 root:root
/opt/agentpay-signer/bin/...          0755 root:root
/var/lib/agentpay-signer/             0700 agentpay-signer:agentpay-signer
```

## AgentPay Configuration

Add to your AgentPay `.env`:

```
AGENTPAY_ISOLATED_SIGNER_LANE=1
AGENTPAY_ISOLATED_SIGNER_URL=http://127.0.0.1:9000
AGENTPAY_SIGNER_CHANNEL_PUBKEY=<from handshake above>
AGENTPAY_SIGNER_BINARY_PIN=<from handshake above>
```

## Registration Procedure

After creating an Agent in AgentPay:

```bash
# Get agent ID and auth_pubkey from AgentPay
curl -X POST http://127.0.0.1:9000/admin/register \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "YOUR_AGENT_UUID",
    "auth_pubkey": "AUTH_PUBKEY_FROM_AGENTPAY",
    "admin_secret": "YOUR_ADMIN_SECRET"
  }'
```

The registration is idempotent—re-registering with the same values succeeds.

## Recovery After Host Reboot

The service is configured to start automatically on boot and restart on
failure. Agents registered via `/admin/register` are automatically
recovered from persisted wallet files on startup.
