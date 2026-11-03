#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${PORT:-9000}"
BACKEND_PORT="${BACKEND_PORT:-19000}"
UPSTREAM_HOST="${UPSTREAM_HOST:-127.0.0.1}"
HOST_IP="${HOST_IP:-$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)}"
CERT_DIR="${CERT_DIR:-$ROOT/certs}"
LOG="$ROOT/demo.log"
BACKEND_LOG="$ROOT/backend.log"
NS="msh-cli"
VETH_HOST="msh-vh"
VETH_CLI="msh-vc"
NET_HOST_IP="10.201.0.1"
NET_CLIENT_IP="10.201.0.2"

if [ "$(id -u)" -ne 0 ]; then
	echo "run this demo as root: eBPF loading requires CAP_BPF/CAP_NET_ADMIN"
	exit 1
fi
if [ -z "$HOST_IP" ]; then
	echo "cannot detect a global IPv4 address; set HOST_IP=..."
	exit 1
fi

make -C "$ROOT"
EXTRA_SAN="IP:$NET_HOST_IP" HOST_IP="$HOST_IP" \
	"$ROOT/scripts/gen_certs.sh" "$CERT_DIR"

PIDS=()
cleanup() {
	local pid
	for pid in "${PIDS[@]:-}"; do
		kill "$pid" 2>/dev/null || true
	done
	wait 2>/dev/null || true
	ip netns del "$NS" 2>/dev/null || true
	ip link del "$VETH_HOST" 2>/dev/null || true
	rm -f /tmp/mtls-shield-large.out /tmp/mtls-shield-echo.out
}
trap cleanup EXIT

setup_netns() {
	ip netns del "$NS" 2>/dev/null || true
	ip link del "$VETH_HOST" 2>/dev/null || true

	ip netns add "$NS" || return 1
	ip link add "$VETH_HOST" type veth peer name "$VETH_CLI" || return 1
	ip link set "$VETH_CLI" netns "$NS" || return 1
	ip addr add "$NET_HOST_IP/24" dev "$VETH_HOST" || return 1
	ip link set "$VETH_HOST" up || return 1
	ip netns exec "$NS" ip addr add "$NET_CLIENT_IP/24" dev "$VETH_CLI" || return 1
	ip netns exec "$NS" ip link set "$VETH_CLI" up || return 1
	ip netns exec "$NS" ip link set lo up || return 1
	ip netns exec "$NS" ip route add default via "$NET_HOST_IP" || return 1
	return 0
}

start_shield() {
	"$ROOT/mtls_shield" \
		--listen "0.0.0.0:$PORT" \
		--protect-port "$PORT" \
		--upstream "$UPSTREAM_HOST:$BACKEND_PORT" \
		--ca "$CERT_DIR/ca.crt" \
		--cert "$CERT_DIR/server.crt" \
		--key "$CERT_DIR/server.key" >"$LOG" 2>&1 &
	SHIELD_PID=$!
	PIDS+=("$SHIELD_PID")

	for _ in $(seq 1 100); do
		if grep -q "ready:" "$LOG" 2>/dev/null; then
			return 0
		fi
		if ! kill -0 "$SHIELD_PID" 2>/dev/null; then
			cat "$LOG"
			return 1
		fi
		sleep 0.1
	done

	cat "$LOG"
	return 1
}

mtls_curl() {
	local host="$1"
	curl -fsS --max-time 5 \
		--cacert "$CERT_DIR/ca.crt" \
		--cert "$CERT_DIR/client.crt" \
		--key "$CERT_DIR/client.key" \
		"https://$host:$PORT/"
}

PASS=0
FAIL=0
ok() { echo "PASS $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL $1"; FAIL=$((FAIL + 1)); }

echo "== phase 1: mTLS on the original port, eBPF moves backend bind =="
start_shield

python3 "$ROOT/scripts/demo_backend.py" \
	--host 127.0.0.1 --port "$PORT" >"$BACKEND_LOG" 2>&1 &
PIDS+=("$!")

BACKEND_READY=0
for _ in $(seq 1 50); do
	if curl -fsS --max-time 1 \
		"http://127.0.0.1:$BACKEND_PORT/" >/dev/null 2>&1; then
		BACKEND_READY=1
		break
	fi
	sleep 0.1
done
if [ "$BACKEND_READY" -ne 1 ]; then
	cat "$BACKEND_LOG"
	echo "backend did not come up on 127.0.0.1:$BACKEND_PORT"
	exit 1
fi

if ss -ltn | grep -q "127.0.0.1:$BACKEND_PORT"; then
	ok "eBPF rewrote backend bind tcp/$PORT -> tcp/$BACKEND_PORT"
else
	bad "eBPF rewrote backend bind tcp/$PORT -> tcp/$BACKEND_PORT"
fi

if ss -ltn | grep -q "127.0.0.1:$PORT"; then
	bad "backend is no longer bound to the original port"
else
	ok "backend is no longer bound to the original port"
fi

if mtls_curl "$HOST_IP" >/dev/null; then
	ok "mTLS via original port $HOST_IP:$PORT"
else
	bad "mTLS via original port $HOST_IP:$PORT"
fi

if mtls_curl 127.0.0.1 >/dev/null; then
	ok "mTLS via original port 127.0.0.1:$PORT"
else
	bad "mTLS via original port 127.0.0.1:$PORT"
fi

if curl -fsS --max-time 5 --cacert "$CERT_DIR/ca.crt" \
	"https://$HOST_IP:$PORT/" >/dev/null 2>&1; then
	bad "connection without client certificate was rejected"
else
	ok "connection without client certificate was rejected"
fi

if curl -fsS --max-time 5 --cacert "$CERT_DIR/ca.crt" \
	--cert "$CERT_DIR/rogue-client.crt" \
	--key "$CERT_DIR/rogue-client.key" \
	"https://$HOST_IP:$PORT/" >/dev/null 2>&1; then
	bad "client certificate from untrusted CA was rejected"
else
	ok "client certificate from untrusted CA was rejected"
fi

if curl -fsS --max-time 5 "http://$HOST_IP:$PORT/" >/dev/null 2>&1; then
	bad "plain HTTP on the original port was rejected"
else
	ok "plain HTTP on the original port was rejected"
fi

if curl -fsS --max-time 5 \
	"http://127.0.0.1:$BACKEND_PORT/" >/dev/null; then
	ok "internal backend still speaks plain TCP on 127.0.0.1:$BACKEND_PORT"
else
	bad "internal backend still speaks plain TCP on 127.0.0.1:$BACKEND_PORT"
fi

LARGE_OUT="/tmp/mtls-shield-large.out"
ECHO_OUT="/tmp/mtls-shield-echo.out"

if curl -fsS --max-time 5 \
	--cacert "$CERT_DIR/ca.crt" \
	--cert "$CERT_DIR/client.crt" \
	--key "$CERT_DIR/client.key" \
	"https://$HOST_IP:$PORT/large" -o "$LARGE_OUT"; then
	SIZE=$(wc -c <"$LARGE_OUT")
	if [ "$SIZE" -eq 1048576 ]; then
		ok "1 MiB backend response relayed to mTLS client"
	else
		bad "1 MiB backend response relayed (got $SIZE bytes)"
	fi
else
	bad "1 MiB backend response relayed"
fi

if head -c 262144 /dev/zero | curl -fsS --max-time 5 \
	--cacert "$CERT_DIR/ca.crt" \
	--cert "$CERT_DIR/client.crt" \
	--key "$CERT_DIR/client.key" \
	--data-binary @- "https://$HOST_IP:$PORT/echo" -o "$ECHO_OUT"; then
	SIZE=$(wc -c <"$ECHO_OUT")
	if [ "$SIZE" -eq 262144 ]; then
		ok "256 KiB request relayed to plain backend"
	else
		bad "256 KiB request relayed (got $SIZE bytes)"
	fi
else
	bad "256 KiB request relayed"
fi

echo
echo "== phase 2: remote client, still connecting to the original port =="
if setup_netns; then
	if ip netns exec "$NS" curl -fsS --max-time 5 \
		--cacert "$CERT_DIR/ca.crt" \
		--cert "$CERT_DIR/client.crt" \
		--key "$CERT_DIR/client.key" \
		"https://$NET_HOST_IP:$PORT/" >/dev/null; then
		ok "mTLS from $NET_CLIENT_IP to $NET_HOST_IP:$PORT"
	else
		bad "mTLS from $NET_CLIENT_IP to $NET_HOST_IP:$PORT"
	fi

	if ip netns exec "$NS" curl -fsS --max-time 5 \
		--cacert "$CERT_DIR/ca.crt" \
		"https://$NET_HOST_IP:$PORT/" >/dev/null 2>&1; then
		bad "remote connection without client certificate was rejected"
	else
		ok "remote connection without client certificate was rejected"
	fi
else
	echo "SKIP network namespace test (cannot create netns/veth)"
fi

kill -USR1 "$SHIELD_PID" 2>/dev/null || true
sleep 0.8
grep "bpf stats" "$LOG" | tail -n 1 || true
grep "upstream pool" "$LOG" | tail -n 1 || true

echo
echo "passed=$PASS failed=$FAIL"
echo "logs: $LOG $BACKEND_LOG"
if [ "$FAIL" -ne 0 ]; then
	exit 1
fi
