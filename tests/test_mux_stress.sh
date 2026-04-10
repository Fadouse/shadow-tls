#!/bin/bash
# Stress test: ShadowTLS V3 + mux + ss-2022, high-concurrency
#
# Uses a local openssl TLS server as handshake target to avoid DNS/routing issues.
# Chain: curl --socks5 -> sslocal -> shadowtls-client -> shadowtls-server -> ssserver

set -euo pipefail

SHADOW_TLS="$(dirname "$0")/../target/release/shadow-tls"
SS_PASSWORD="MDEyMzQ1Njc4OWFiY2RlZg=="
STLS_PASSWORD="shadow-stress-test"
THREADS=1

declare -a PIDS=()

cleanup() {
    echo "[*] Cleaning up..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    rm -f /tmp/tls_test.key /tmp/tls_test.crt
}
trap cleanup EXIT

wait_for_port() {
    local port=$1 timeout=${2:-10}
    for ((i=0; i<timeout*10; i++)); do
        if ss -tlnH "sport = :$port" 2>/dev/null | grep -q "$port"; then return 0; fi
        sleep 0.1
    done
    echo "FAIL: port $port not ready after ${timeout}s"; exit 1
}

run_parallel_curls() {
    local proxy_port=$1 count=$2 label=$3
    local tmpdir=$(mktemp -d)
    # Run curls in a subshell so `wait` only waits for curl children
    (
        for i in $(seq 1 "$count"); do
            curl -s -o /dev/null -w "%{http_code}\n" --max-time 30 \
                --socks5-hostname "127.0.0.1:$proxy_port" \
                http://captive.apple.com/ > "$tmpdir/$i.txt" 2>/dev/null &
        done
        wait
    )
    local pass=0 fail=0
    for i in $(seq 1 "$count"); do
        code=$(cat "$tmpdir/$i.txt" 2>/dev/null || echo "000")
        if [ "$code" = "200" ]; then pass=$((pass+1)); else fail=$((fail+1)); fi
    done
    rm -rf "$tmpdir"
    echo "$pass/$count passed ($fail failed)"
    if [ "$fail" -gt "$((count/5))" ]; then
        echo "FAIL: $label"; exit 1
    fi
}

echo "============================================"
echo "  ShadowTLS Stress Test"
echo "============================================"

# --- Local TLS handshake server ---
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -days 1 -nodes -keyout /tmp/tls_test.key -out /tmp/tls_test.crt \
    -subj '/CN=test.local' 2>/dev/null
openssl s_server -accept 22999 -cert /tmp/tls_test.crt -key /tmp/tls_test.key \
    -www -quiet &>/dev/null &
PIDS+=($!)
wait_for_port 22999

# --- ssserver ---
ssserver -s "127.0.0.1:22388" -m "2022-blake3-aes-128-gcm" -k "$SS_PASSWORD" &>/dev/null &
PIDS+=($!)
wait_for_port 22388

# ==============================
# PHASE 1: Non-mux
# ==============================
echo ""
echo "=== Phase 1: Non-mux ==="

RUST_LOG=warn "$SHADOW_TLS" --threads $THREADS --v3 --strict server \
    --listen "127.0.0.1:22444" --server "127.0.0.1:22388" \
    --tls "127.0.0.1:22999" --password "$STLS_PASSWORD" &>/dev/null &
PIDS+=($!)
wait_for_port 22444

RUST_LOG=warn "$SHADOW_TLS" --threads $THREADS --v3 --strict client \
    --listen "127.0.0.1:22443" --server "127.0.0.1:22444" \
    --sni "test.local" --password "$STLS_PASSWORD" &>/dev/null &
PIDS+=($!)
wait_for_port 22443

sslocal -b "127.0.0.1:22080" -s "127.0.0.1:22443" \
    -m "2022-blake3-aes-128-gcm" -k "$SS_PASSWORD" &>/dev/null &
PIDS+=($!)
wait_for_port 22080

echo -n "[Test 1] HTTP connectivity... "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
    --socks5-hostname 127.0.0.1:22080 http://captive.apple.com/ 2>/dev/null) || HTTP_CODE="err"
if [ "$HTTP_CODE" = "200" ]; then echo "PASS"; else echo "FAIL ($HTTP_CODE)"; exit 1; fi

echo -n "[Test 2] 20 parallel... "
run_parallel_curls 22080 20 "non-mux 20 parallel"

echo -n "[Test 3] 40 parallel... "
run_parallel_curls 22080 40 "non-mux 40 parallel"

# Stop non-mux stls + sslocal (indices 2,3,4)
kill "${PIDS[2]}" "${PIDS[3]}" "${PIDS[4]}" 2>/dev/null || true
sleep 1

# ==============================
# PHASE 2: Mux
# ==============================
echo ""
echo "=== Phase 2: Mux ==="

RUST_LOG=warn "$SHADOW_TLS" --threads $THREADS --v3 --strict --mux server \
    --listen "127.0.0.1:22446" --server "127.0.0.1:22388" \
    --tls "127.0.0.1:22999" --password "$STLS_PASSWORD" &>/dev/null &
PIDS+=($!)
wait_for_port 22446

RUST_LOG=warn "$SHADOW_TLS" --threads $THREADS --v3 --strict --mux client \
    --listen "127.0.0.1:22445" --server "127.0.0.1:22446" \
    --sni "test.local" --password "$STLS_PASSWORD" &>/dev/null &
PIDS+=($!)
wait_for_port 22445

sslocal -b "127.0.0.1:22082" -s "127.0.0.1:22445" \
    -m "2022-blake3-aes-128-gcm" -k "$SS_PASSWORD" &>/dev/null &
PIDS+=($!)
wait_for_port 22082

echo -n "[Test 4] Mux connectivity... "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
    --socks5-hostname 127.0.0.1:22082 http://captive.apple.com/ 2>/dev/null) || HTTP_CODE="err"
if [ "$HTTP_CODE" = "200" ]; then echo "PASS"; else echo "FAIL ($HTTP_CODE)"; exit 1; fi

echo -n "[Test 5] Mux 20 parallel... "
run_parallel_curls 22082 20 "mux 20 parallel"

echo -n "[Test 6] Mux 40 parallel... "
run_parallel_curls 22082 40 "mux 40 parallel"

echo -n "[Test 7] Mux sustained (3x20)... "
TP=0; TF=0
for wave in 1 2 3; do
    tmpdir=$(mktemp -d)
    (
        for i in $(seq 1 20); do
            curl -s -o /dev/null -w "%{http_code}\n" --max-time 30 \
                --socks5-hostname 127.0.0.1:22082 http://captive.apple.com/ > "$tmpdir/$i.txt" 2>/dev/null &
        done
        wait
    )
    for i in $(seq 1 20); do
        code=$(cat "$tmpdir/$i.txt" 2>/dev/null || echo "000")
        if [ "$code" = "200" ]; then TP=$((TP+1)); else TF=$((TF+1)); fi
    done
    rm -rf "$tmpdir"
done
echo "$TP/60 passed ($TF failed)"
if [ "$TF" -gt 10 ]; then echo "FAIL: sustained mux"; exit 1; fi

echo ""
echo "=== All stress tests passed! ==="
