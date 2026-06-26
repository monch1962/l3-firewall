#!/bin/sh
# l3-firewall container entrypoint
# Configures nftables to QUEUE traffic, then starts the firewall binary.

set -e

echo "[l3-firewall] Setting up nftables rules..."

# Create a forwarding firewall table
nft add table inet l3_firewall 2>/dev/null || true

# Delete existing chain to allow re-entry
nft delete chain inet l3_firewall forward 2>/dev/null || true

# Add forward chain that queues all forwarded traffic to queue 0
nft add chain inet l3_firewall forward { type filter hook forward priority 0 \; }
nft add rule inet l3_firewall forward queue num 0

# Add input chain to protect the host itself
nft add chain inet l3_firewall input { type filter hook input priority 0 \; }
nft add rule inet l3_firewall input queue num 1

echo "[l3-firewall] nftables rules configured. Starting firewall..."

exec /app/l3-firewall "$@"
