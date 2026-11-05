#!/usr/bin/env bash
# Smoke test for the container deployment: build the image, start the gateway
# from deploy/compose.yaml with a stand-in upstream, list tools and make one
# call from the clients network, then stop it and verify the audit log it left
# in the host folder. Runs as its own compose project on its own networks, so
# a real deployment on the same host is untouched. Everything is removed after.
set -euo pipefail

cd "$(dirname "$0")"
WORK=$(mktemp -d)
export COMPOSE_PROJECT_NAME=mcp-gateway-smoke
export MCP_GATEWAY_CLIENTS_NETWORK=mcp-gateway-smoke-clients
export MCP_GATEWAY_UPSTREAMS_NETWORK=mcp-gateway-smoke-upstreams
export MCP_GATEWAY_CONFIG_FILE="$WORK/gateway.yaml"
export MCP_GATEWAY_AUDIT_DIR="$WORK/audit"
export SMOKE_KEY=unset
COMPOSE=(docker compose -f compose.yaml -f smoke/compose.smoke.yaml)

cleanup() {
    local status=$?
    if [ "$status" -ne 0 ]; then
        "${COMPOSE[@]}" logs --no-color mcp-gateway echo-mcp || true
    fi
    "${COMPOSE[@]}" --profile smoke down --volumes --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

"${COMPOSE[@]}" build mcp-gateway

# A throwaway key for this run, from the image's own hash-key.
KEYS=$(docker run --rm mcp-gateway:local mcp-gateway hash-key)
SMOKE_KEY=$(sed -n 's/^key (.*): //p' <<<"$KEYS")
KEY_SHA256=$(sed -n 's/^key_sha256 (.*): //p' <<<"$KEYS")

cat >"$MCP_GATEWAY_CONFIG_FILE" <<EOF
upstreams:
  echo: {transport: http, url: "http://echo-mcp:8000/mcp"}
callers:
  smoke: {key_sha256: "$KEY_SHA256", policy: smoke}
policies:
  smoke:
    routes:
      echo:
        tools: {show_meta: {}}
allowed_hosts: ["mcp-gateway:*"]
detector:
  rules: true
audit:
  path: /var/log/mcp-gateway/audit.jsonl
EOF
chmod 0644 "$MCP_GATEWAY_CONFIG_FILE"
# The container runs as uid 10001; on a server, chown the folder to it instead.
mkdir -m 0777 "$MCP_GATEWAY_AUDIT_DIR"

"${COMPOSE[@]}" up -d --wait mcp-gateway
"${COMPOSE[@]}" run --rm client
# The cgroup's peak since start, the figure the memory cap in compose.yaml is set from.
PEAK_BYTES=$("${COMPOSE[@]}" exec -T mcp-gateway cat /sys/fs/cgroup/memory.peak)
echo "gateway memory peak: $((PEAK_BYTES / 1024 / 1024)) MiB"

# A clean stop writes the log's stop line; then the chain must verify.
"${COMPOSE[@]}" stop mcp-gateway
docker run --rm -v "$MCP_GATEWAY_AUDIT_DIR:/audit:ro" mcp-gateway:local mcp-gateway verify-log /audit/audit.jsonl
grep -q '"kind":"stop"' "$MCP_GATEWAY_AUDIT_DIR/audit.jsonl" || { echo "no stop line: the gateway didn't shut down cleanly"; exit 1; }
echo "smoke test passed"
