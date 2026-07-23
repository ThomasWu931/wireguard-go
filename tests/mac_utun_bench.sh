#!/usr/bin/env bash
# Benchmark real utun datapath on macOS with two wireguard-go processes + iperf3.
#
# Topology (loopback UDP endpoints):
#
#   iperf3 -c 10.66.66.2  →  utunA (10.66.66.1)  ⇄  UDP 127.0.0.1  ⇄  utunB (10.66.66.2)  →  iperf3 -s
#
# Usage (from repo root):
#   ./tests/mac_utun_bench.sh
#   WG_BIN=./wireguard-go TIME=30 PARALLEL=4 ./tests/mac_utun_bench.sh
#   ./tests/mac_utun_bench.sh --udp
#
# Requires: sudo, wireguard-tools (wg), iperf3, Go (to build if WG_BIN missing).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TIME="${TIME:-10}"
PARALLEL="${PARALLEL:-4}"
UDP=0
MTU="${MTU:-1420}"
# Optional overrides; default is listen-port 0 (kernel-chosen ephemeral).
PORT_A="${PORT_A:-0}"
PORT_B="${PORT_B:-0}"
# Use a less common /30 so we don't collide with other local tunnels.
IP_A="${IP_A:-10.77.77.1}"
IP_B="${IP_B:-10.77.77.2}"

for arg in "$@"; do
  case "$arg" in
    --udp) UDP=1 ;;
    -h|--help)
      sed -n '2,16p' "$0"
      exit 0
      ;;
    *)
      echo "unknown arg: $arg" >&2
      exit 1
      ;;
  esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: this script is for macOS (real utun)" >&2
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "==> re-running under sudo (utun requires root)"
  exec sudo --preserve-env=WG_BIN,TIME,PARALLEL,MTU,PORT_A,PORT_B,IP_A,IP_B,KEEP,LOG_LEVEL,PATH,HOME "$0" "$@"
fi

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: missing '$1'. Try: brew install $2" >&2
    exit 1
  }
}
need wg wireguard-tools
need iperf3 iperf3

WG_BIN="${WG_BIN:-$ROOT/wireguard-go}"
if [[ ! -x "$WG_BIN" ]]; then
  echo "==> building wireguard-go"
  (cd "$ROOT" && go build -o "$WG_BIN" .)
fi

TMP="$(mktemp -d /tmp/wg-mac-bench.XXXXXX)"
NAME_A="$TMP/name_a"
NAME_B="$TMP/name_b"
LOG_A="$TMP/a.log"
LOG_B="$TMP/b.log"
KEY_A="$TMP/a.key"
KEY_B="$TMP/b.key"
PUB_A="$TMP/a.pub"
PUB_B="$TMP/b.pub"
PID_A=""
PID_B=""
IF_A=""
IF_B=""
IPERF_PID=""

cleanup() {
  set +e
  [[ -n "$IPERF_PID" ]] && kill "$IPERF_PID" 2>/dev/null
  [[ -n "$PID_A" ]] && kill "$PID_A" 2>/dev/null
  [[ -n "$PID_B" ]] && kill "$PID_B" 2>/dev/null
  wait "$PID_A" "$PID_B" "$IPERF_PID" 2>/dev/null
  # Removing the UAPI socket asks wireguard-go to exit if still alive.
  [[ -n "$IF_A" ]] && rm -f "/var/run/wireguard/${IF_A}.sock"
  [[ -n "$IF_B" ]] && rm -f "/var/run/wireguard/${IF_B}.sock"
  if [[ "${KEEP:-0}" == "1" ]]; then
    echo "kept workdir: $TMP"
  else
    rm -rf "$TMP"
  fi
}
trap cleanup EXIT

echo "==> generating keys"
wg genkey | tee "$KEY_A" | wg pubkey >"$PUB_A"
wg genkey | tee "$KEY_B" | wg pubkey >"$PUB_B"

echo "==> starting wireguard-go peers"
WG_TUN_NAME_FILE="$NAME_A" LOG_LEVEL="${LOG_LEVEL:-error}" \
  "$WG_BIN" -f utun >"$LOG_A" 2>&1 &
PID_A=$!
WG_TUN_NAME_FILE="$NAME_B" LOG_LEVEL="${LOG_LEVEL:-error}" \
  "$WG_BIN" -f utun >"$LOG_B" 2>&1 &
PID_B=$!

# Wait for interface names to appear.
for _ in $(seq 1 50); do
  [[ -s "$NAME_A" && -s "$NAME_B" ]] && break
  if ! kill -0 "$PID_A" 2>/dev/null || ! kill -0 "$PID_B" 2>/dev/null; then
    echo "error: wireguard-go exited early" >&2
    echo "---- peer A log ----"; cat "$LOG_A" || true
    echo "---- peer B log ----"; cat "$LOG_B" || true
    exit 1
  fi
  sleep 0.1
done
IF_A="$(tr -d '[:space:]' <"$NAME_A")"
IF_B="$(tr -d '[:space:]' <"$NAME_B")"
if [[ -z "$IF_A" || -z "$IF_B" ]]; then
  echo "error: failed to learn utun names (is WG_TUN_NAME_FILE supported?)" >&2
  cat "$LOG_A" "$LOG_B" || true
  exit 1
fi
echo "    peer A: $IF_A"
echo "    peer B: $IF_B"

echo "==> configuring WireGuard + addresses"
# Bind first (port 0 => ephemeral), then learn real ports and set endpoints.
# Fixed 51820/51821 often hit "Address already in use" from leftover daemons.
if ! wg set "$IF_A" \
  listen-port "$PORT_A" \
  private-key "$KEY_A" \
  peer "$(cat "$PUB_B")" \
  allowed-ips "${IP_B}/32"; then
  echo "error: wg set $IF_A failed (port in use?). Try: sudo pkill wireguard-go" >&2
  exit 1
fi
if ! wg set "$IF_B" \
  listen-port "$PORT_B" \
  private-key "$KEY_B" \
  peer "$(cat "$PUB_A")" \
  allowed-ips "${IP_A}/32"; then
  echo "error: wg set $IF_B failed (port in use?). Try: sudo pkill wireguard-go" >&2
  exit 1
fi

PORT_A="$(wg show "$IF_A" listen-port)"
PORT_B="$(wg show "$IF_B" listen-port)"
echo "    UDP ports: A=$PORT_A B=$PORT_B"

wg set "$IF_A" peer "$(cat "$PUB_B")" endpoint "127.0.0.1:${PORT_B}"
wg set "$IF_B" peer "$(cat "$PUB_A")" endpoint "127.0.0.1:${PORT_A}"

ifconfig "$IF_A" inet "$IP_A" "$IP_B" mtu "$MTU" up
ifconfig "$IF_B" inet "$IP_B" "$IP_A" mtu "$MTU" up

echo "==> waiting for handshake"
ok=0
for _ in $(seq 1 50); do
  if ping -c 1 -W 1000 "$IP_B" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.1
done
if [[ "$ok" -ne 1 ]]; then
  echo "error: ping ${IP_B} failed" >&2
  wg show
  echo "---- peer A log ----"; cat "$LOG_A" || true
  echo "---- peer B log ----"; cat "$LOG_B" || true
  exit 1
fi
wg show

echo "==> starting iperf3 server on ${IP_B}"
iperf3 -s -1 -B "$IP_B" >"$TMP/iperf-server.log" 2>&1 &
IPERF_PID=$!
for _ in $(seq 1 50); do
  if kill -0 "$IPERF_PID" 2>/dev/null; then
    # server is up once it binds; give it a beat
    sleep 0.2
    break
  fi
  sleep 0.1
done

echo "==> running iperf3 client → ${IP_B} (time=${TIME}s parallel=${PARALLEL} udp=${UDP})"
set +e
if [[ "$UDP" -eq 1 ]]; then
  iperf3 -c "$IP_B" -B "$IP_A" -u -b 0 -t "$TIME" -P "$PARALLEL" | tee "$TMP/iperf-client.log"
else
  iperf3 -c "$IP_B" -B "$IP_A" -t "$TIME" -P "$PARALLEL" | tee "$TMP/iperf-client.log"
fi
rc=$?
set -e

echo
echo "Done (iperf exit=${rc})."
echo "  interfaces: $IF_A <-> $IF_B"
echo "  set KEEP=1 to preserve logs under $TMP"
exit "$rc"
