#!/bin/bash
set -e

cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"

kill_port() {
  local port=$1
  local pids
  pids=$(lsof -ti:"$port" 2>/dev/null || true)
  if [ -n "$pids" ]; then
    echo "Killing processes on port $port: $pids"
    kill $pids 2>/dev/null || true
    sleep 1
    pids=$(lsof -ti:"$port" 2>/dev/null || true)
    if [ -n "$pids" ]; then
      echo "Force killing: $pids"
      kill -9 $pids 2>/dev/null || true
    fi
  fi
}

if [ "${MASKURA_PORT+x}" = x ] && [ "${S4_PORT+x}" = x ] && [ "$MASKURA_PORT" != "$S4_PORT" ]; then
  echo "ERROR: conflicting environment aliases: MASKURA_PORT and S4_PORT" >&2
  exit 1
fi
if [ "${MASKURA_PORT+x}" = x ]; then
  GATEWAY_PORT="$MASKURA_PORT"
elif [ "${S4_PORT+x}" = x ]; then
  GATEWAY_PORT="$S4_PORT"
else
  GATEWAY_PORT=9000
fi

echo "=== Maskura dev harness ==="
echo "Port: $GATEWAY_PORT"

echo ""
echo "[1/3] Building Wasm filter components..."
just build-filters

echo ""
echo "[2/3] Building gateway..."
cargo build -p s4-gateway

echo ""
echo "[3/3] Starting services..."
kill_port "$GATEWAY_PORT"

nohup env LISTEN_ADDR="0.0.0.0:$GATEWAY_PORT" AUTH_DISABLED="${AUTH_DISABLED:-true}" ./target/debug/s4-gateway > /tmp/s4-gateway.log 2>&1 &
GATEWAY_PID=$!

sleep 2

if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
  echo "ERROR: Gateway failed to start. Check /tmp/s4-gateway.log"
  cat /tmp/s4-gateway.log
  exit 1
fi

echo ""
echo "=== All services started ==="
echo "Dashboard: http://localhost:$GATEWAY_PORT"
echo "Health:    http://localhost:$GATEWAY_PORT/health"
echo "PID:       $GATEWAY_PID"
echo "Logs:      /tmp/s4-gateway.log"
echo ""
echo "Stop:      kill $GATEWAY_PID"
