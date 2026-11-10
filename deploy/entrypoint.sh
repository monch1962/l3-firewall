#!/bin/sh
# l3-firewall container entrypoint
# Configures nftables to QUEUE traffic, then starts the firewall binary.

set -e

echo "[l3-firewall] Setting up nftables rules..."

# Create a forwarding firewall table
nft add table inet l3_firewall 2>/dev/null || true

# Delete existing chain to allow re-entry
nft delete chain inet l3_firewall forward 2>/dev/null || true

# Add forward chain that queues all forwarded traffic to queue 0.
# Queue 0 is the queue the engine registers (cmd/server --queue default 0);
# eng.Run() binds exactly that one queue.
nft add chain inet l3_firewall forward { type filter hook forward priority 0 \; }
nft add rule inet l3_firewall forward queue num 0

# R83 — host INPUT traffic is deliberately NOT queued.
#
# Pre-R83 this script installed `input hook -> queue num 1`, but the binary
# serves ONLY the forward queue: --queue-input is parsed and never wired into
# Engine.Run (see the startup warning in cmd/server). Netfilter DROPS every
# packet queued to a queue with no userspace listener (there is no `bypass`
# on the rule), so the shipped container black-holed 100% of host input — the
# admin API published by the README's own `docker run -p 8082:8082`,
# /metrics, SSH and every container healthcheck (an orchestrator then
# restart-loops the firewall). Measured in a netns: an input-queue rule made a
# UDP datagram to a local socket vanish, while the same datagram was delivered
# with no ruleset.
#
# A queue rule is only safe once something serves that queue, so it is added
# back together with the --queue-input wiring (cmd/server's
# attack_round83_test.go enforces the pairing: every queue this script queues
# must be a queue the engine actually registers).
echo "[l3-firewall] input traffic is NOT queued (engine serves the forward queue only; --queue-input unwired)"

echo "[l3-firewall] nftables rules configured. Starting firewall..."

exec /app/l3-firewall "$@"
