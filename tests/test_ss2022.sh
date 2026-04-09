#!/bin/bash
# Integration test: ShadowTLS V3 + ss-2022-aes-128-gcm
#
# Chain: curl --socks5 -> sslocal(:21080) -> shadowtls-client(:21443)
#        -> shadowtls-server(:21444) -> ssserver(:21388)
#
# Tests: connectivity and data correctness through the full proxy chain.

set -euo pipefail

SHADOW_TLS="$(dirname "$0")/../target/release/shadow-tls"
SS_PASSWORD="MDEyMzQ1Njc4OWFiY2RlZg=="  # base64("0123456789abcdef"), 16 bytes for aes-128
STLS_PASSWORD="shadow-test"
HANDSHAKE_SERVER="www.google.com"

cleanup() {
    echo "[*] Cleaning up..."
    kill $PID_SSSERVER $PID_STLS_SERVER $PID_STLS_CLIENT $PID_SSLOCAL 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

echo "[1/4] Starting ssserver on :21388..."
ssserver -s "127.0.0.1:21388" -m "2022-blake3-aes-128-gcm" -k "$SS_PASSWORD" 2>/dev/null &
PID_SSSERVER=$!
sleep 0.5

echo "[2/4] Starting shadowtls server on :21444..."
"$SHADOW_TLS" --v3 --strict server \
    --listen "127.0.0.1:21444" \
    --server "127.0.0.1:21388" \
    --tls "$HANDSHAKE_SERVER" \
    --password "$STLS_PASSWORD" 2>/dev/null &
PID_STLS_SERVER=$!
sleep 0.5

echo "[3/4] Starting shadowtls client on :21443..."
"$SHADOW_TLS" --v3 --strict client \
    --listen "127.0.0.1:21443" \
    --server "127.0.0.1:21444" \
    --sni "$HANDSHAKE_SERVER" \
    --password "$STLS_PASSWORD" 2>/dev/null &
PID_STLS_CLIENT=$!
sleep 0.5

echo "[4/4] Starting sslocal on :21080..."
sslocal -b "127.0.0.1:21080" -s "127.0.0.1:21443" -m "2022-blake3-aes-128-gcm" -k "$SS_PASSWORD" 2>/dev/null &
PID_SSLOCAL=$!
sleep 1

echo ""
echo "=== Testing connectivity ==="

# Test 1: HTTP request through the chain
echo -n "[Test 1] HTTP through socks5 proxy... "
RESP=$(curl -s --max-time 10 --socks5 127.0.0.1:21080 http://captive.apple.com/ 2>&1) || true
if echo "$RESP" | grep -q "Success"; then
    echo "PASS"
else
    echo "FAIL"
    echo "Response: $RESP"
    exit 1
fi

# Test 2: HTTPS request
echo -n "[Test 2] HTTPS through socks5 proxy... "
RESP=$(curl -s --max-time 10 --socks5-hostname 127.0.0.1:21080 https://www.google.com/ 2>&1) || true
if [ ${#RESP} -gt 100 ]; then
    echo "PASS (${#RESP} bytes)"
else
    echo "FAIL (response too short: ${#RESP} bytes)"
    exit 1
fi

echo ""
echo "=== All tests passed ==="
