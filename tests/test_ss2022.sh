#!/bin/bash
# Integration test: ShadowTLS V3 + ss-2022-aes-128-gcm
#
# Chain: curl --socks5 -> sslocal(:21080) -> shadowtls-client(:21443)
#        -> shadowtls-server(:21444) -> ssserver(:21388)
#
# Uses a local openssl TLS server as handshake target to avoid DNS/routing
# issues (corporate proxies, VPN interceptors, etc.).
#
# Tests: connectivity and data correctness through the full proxy chain.

set -euo pipefail

SHADOW_TLS="$(dirname "$0")/../target/release/shadow-tls"
SS_PASSWORD="MDEyMzQ1Njc4OWFiY2RlZg=="  # base64("0123456789abcdef"), 16 bytes for aes-128
STLS_PASSWORD="shadow-test"

# Initialize PID variables to avoid unbound variable errors in trap
PID_TLS_SERVER=""
PID_SSSERVER=""
PID_STLS_SERVER=""
PID_STLS_CLIENT=""
PID_SSLOCAL=""

cleanup() {
    echo "[*] Cleaning up..."
    for pid in ${PID_TLS_SERVER:-} ${PID_SSSERVER:-} ${PID_STLS_SERVER:-} ${PID_STLS_CLIENT:-} ${PID_SSLOCAL:-}; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    rm -f /tmp/stls_test.key /tmp/stls_test.crt /tmp/stls_test1.body /tmp/stls_test2.body
}
trap cleanup EXIT

# wait_for_port HOST PORT TIMEOUT_SECS
# Uses ss(8) to check listening state without connecting (avoids sending
# garbage bytes that confuse SOCKS5/shadowtls).
wait_for_port() {
    local host=$1 port=$2 timeout=${3:-10}
    for ((i=0; i<timeout*10; i++)); do
        if ss -tlnH "sport = :$port" 2>/dev/null | grep -q "$port"; then return 0; fi
        sleep 0.1
    done
    echo "FAIL: port $host:$port not ready after ${timeout}s"
    exit 1
}

echo "[0/5] Starting local TLS handshake server on :21999..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -days 1 -nodes -keyout /tmp/stls_test.key -out /tmp/stls_test.crt \
    -subj '/CN=test.local' 2>/dev/null
openssl s_server -accept 21999 -cert /tmp/stls_test.crt -key /tmp/stls_test.key \
    -www -quiet &>/dev/null &
PID_TLS_SERVER=$!
wait_for_port 127.0.0.1 21999

echo "[1/5] Starting ssserver on :21388..."
ssserver -s "127.0.0.1:21388" -m "2022-blake3-aes-128-gcm" -k "$SS_PASSWORD" &
PID_SSSERVER=$!
wait_for_port 127.0.0.1 21388 10

echo "[2/5] Starting shadowtls server on :21444..."
"$SHADOW_TLS" --v3 --strict server \
    --listen "127.0.0.1:21444" \
    --server "127.0.0.1:21388" \
    --tls "127.0.0.1:21999" \
    --password "$STLS_PASSWORD" &
PID_STLS_SERVER=$!
wait_for_port 127.0.0.1 21444 10

echo "[3/5] Starting shadowtls client on :21443..."
"$SHADOW_TLS" --v3 --strict client \
    --listen "127.0.0.1:21443" \
    --server "127.0.0.1:21444" \
    --sni "test.local" \
    --password "$STLS_PASSWORD" &
PID_STLS_CLIENT=$!
wait_for_port 127.0.0.1 21443 10

echo "[4/5] Starting sslocal on :21080..."
sslocal -b "127.0.0.1:21080" -s "127.0.0.1:21443" -m "2022-blake3-aes-128-gcm" -k "$SS_PASSWORD" &
PID_SSLOCAL=$!
wait_for_port 127.0.0.1 21080 10

echo ""
echo "=== Testing connectivity ==="

# Test 1: HTTP request through the chain — verify status code and body marker
echo -n "[Test 1] HTTP through socks5 proxy... "
HTTP_CODE=$(curl -s -o /tmp/stls_test1.body -w "%{http_code}" --max-time 15 --socks5-hostname 127.0.0.1:21080 http://captive.apple.com/ 2>&1) || true
if [ "$HTTP_CODE" = "200" ] && grep -q "Success" /tmp/stls_test1.body; then
    echo "PASS (HTTP $HTTP_CODE)"
else
    echo "FAIL (HTTP $HTTP_CODE)"
    cat /tmp/stls_test1.body 2>/dev/null || true
    exit 1
fi

# Test 2: HTTPS request — verify status code and minimum body size
echo -n "[Test 2] HTTPS through socks5 proxy... "
HTTP_CODE=$(curl -s -o /tmp/stls_test2.body -w "%{http_code}" --max-time 15 --socks5-hostname 127.0.0.1:21080 https://captive.apple.com/ 2>&1) || true
BODY_LEN=$(wc -c < /tmp/stls_test2.body 2>/dev/null || echo 0)
if [ "$HTTP_CODE" = "200" ] && [ "$BODY_LEN" -gt 10 ]; then
    echo "PASS (HTTP $HTTP_CODE, ${BODY_LEN} bytes)"
else
    echo "FAIL (HTTP $HTTP_CODE, ${BODY_LEN} bytes)"
    exit 1
fi

echo ""
echo "=== All tests passed ==="
