#!/usr/bin/env bash
# Bootstraps SPIRE, registers the agents, and starts the demo.
set -euo pipefail
cd "$(dirname "$0")"

SERVER="docker compose exec -T spire-server /opt/spire/bin/spire-server"
NODE_ID="spiffe://example.org/node"

echo "==> Starting SPIRE server"
docker compose up -d spire-server
until $SERVER healthcheck >/dev/null 2>&1; do sleep 1; done

echo "==> Exporting trust bundle for agent bootstrap"
$SERVER bundle show > spire/agent/bootstrap.crt

echo "==> Generating join token for the SPIRE agent (node: $NODE_ID)"
JOIN_TOKEN=$($SERVER token generate -spiffeID "$NODE_ID" | awk '/Token:/{print $2}')
export JOIN_TOKEN

echo "==> Registering workloads (selector: unix uid)"
register() { # spiffe-id uid
  $SERVER entry create -parentID "$NODE_ID" -spiffeID "$1" -selector "unix:uid:$2" >/dev/null
  echo "    $1  <=  unix:uid:$2"
}
register spiffe://example.org/agent-a     1001
register spiffe://example.org/agent-b     1002
register spiffe://example.org/agent-rogue 1003
register spiffe://example.org/token-service 1004

echo "==> Starting SPIRE agent"
docker compose up -d spire-agent

echo "==> Building and starting agents"
docker compose up -d --build opa token-service agent-b agent-a agent-rogue

echo
echo "Done. Follow the conversation with:"
echo "  docker compose logs -f agent-a agent-b agent-rogue token-service"
