#!/usr/bin/env bash
# Integration test: HTTP gateway + dummy MCP server
# Starts both processes, runs curl-based scenarios, then cleans up.

set -euo pipefail

GATEWAY="./target/debug/gateway"
DUMMY="./target/debug/dummy-server"
CONFIG="gateway.yml"
GATEWAY_PORT=4000
DUMMY_PORT=3000
PASS=0
FAIL=0
DUMMY_PID=""
GATEWAY_PID=""

# ── Helpers ───────────────────────────────────────────────────────────────────

cleanup() {
    [ -n "$GATEWAY_PID" ] && kill "$GATEWAY_PID" 2>/dev/null || true
    [ -n "$DUMMY_PID"   ] && kill "$DUMMY_PID"   2>/dev/null || true
}
trap cleanup EXIT

wait_for_port() {
    local port=$1 retries=30
    while ! (echo > /dev/tcp/localhost/"$port") 2>/dev/null; do
        retries=$((retries - 1))
        [ $retries -eq 0 ] && { echo "  ABORT  port $port never opened"; exit 1; }
        sleep 0.2
    done
}

mcp_post() {
    local session="$1"
    local body="$2"
    if [ -n "$session" ]; then
        curl -s -D /tmp/mcp-headers.txt \
            -H "Content-Type: application/json" \
            -H "Mcp-Session-Id: $session" \
            -d "$body" \
            "http://localhost:${GATEWAY_PORT}/mcp"
    else
        curl -s -D /tmp/mcp-headers.txt \
            -H "Content-Type: application/json" \
            -d "$body" \
            "http://localhost:${GATEWAY_PORT}/mcp"
    fi
}

mcp_post_status() {
    local session="$1"
    local body="$2"
    if [ -n "$session" ]; then
        curl -s -o /dev/null -w "%{http_code}" \
            -H "Content-Type: application/json" \
            -H "Mcp-Session-Id: $session" \
            -d "$body" \
            "http://localhost:${GATEWAY_PORT}/mcp"
    else
        curl -s -o /dev/null -w "%{http_code}" \
            -H "Content-Type: application/json" \
            -d "$body" \
            "http://localhost:${GATEWAY_PORT}/mcp"
    fi
}

check() {
    local label="$1" output="$2" expect="$3"
    if echo "$output" | grep -q "$expect"; then
        echo "  PASS  $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  $label"
        echo "        expected: $expect"
        echo "        got:      $(echo "$output" | tr '\n' ' ' | cut -c1-120)"
        FAIL=$((FAIL + 1))
    fi
}

check_absent() {
    local label="$1" output="$2" pattern="$3"
    if echo "$output" | grep -q "$pattern"; then
        echo "  FAIL  $label (pattern found: $pattern)"
        FAIL=$((FAIL + 1))
    else
        echo "  PASS  $label"
        PASS=$((PASS + 1))
    fi
}

check_status() {
    local label="$1" got="$2" expect="$3"
    if [ "$got" = "$expect" ]; then
        echo "  PASS  $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  $label (expected HTTP $expect, got $got)"
        FAIL=$((FAIL + 1))
    fi
}

# ── Start servers ─────────────────────────────────────────────────────────────

"$DUMMY" > /dev/null 2>&1 &
DUMMY_PID=$!
wait_for_port $DUMMY_PORT

"$GATEWAY" "$CONFIG" > /dev/null 2>&1 &
GATEWAY_PID=$!
wait_for_port $GATEWAY_PORT

# ── Tests ─────────────────────────────────────────────────────────────────────

echo ""
echo "━━━ 1. initialize as cursor → get session ━━━"
OUT=$(mcp_post "" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cursor","version":"1.0.0"}}}')
SESSION=$(grep -i "mcp-session-id:" /tmp/mcp-headers.txt | awk '{print $2}' | tr -d '\r\n')
check "initialize returns serverInfo" "$OUT" "serverInfo"
check "session ID assigned"           "$SESSION" "."

echo ""
echo "━━━ 2. notifications/initialized ━━━"
STATUS=$(mcp_post_status "$SESSION" '{"jsonrpc":"2.0","method":"notifications/initialized"}')
check_status "notifications/initialized returns 202" "$STATUS" "202"

echo ""
echo "━━━ 3. tools/list — cursor sees only echo ━━━"
OUT=$(mcp_post "$SESSION" '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
check        "tools/list contains echo"              "$OUT" '"echo"'
check_absent "tools/list does not expose other tools" "$OUT" '"delete_database"'

echo ""
echo "━━━ 4. echo tool call — allowed ━━━"
OUT=$(mcp_post "$SESSION" '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}')
check "echo returns result" "$OUT" "echo: hello"

echo ""
echo "━━━ 5. unknown tool — blocked ━━━"
OUT=$(mcp_post "$SESSION" '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_database","arguments":{}}}')
check "unknown tool blocked" "$OUT" "blocked"

echo ""
echo "━━━ 6. sensitive payload — blocked ━━━"
OUT=$(mcp_post "$SESSION" '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"echo","arguments":{"text":"my secret=abc"}}}')
check "sensitive payload blocked" "$OUT" "blocked"

echo ""
echo "━━━ 7. expired/invalid session → 404 ━━━"
STATUS=$(mcp_post_status "invalid-session-id" '{"jsonrpc":"2.0","id":6,"method":"tools/list"}')
check_status "invalid session returns 404" "$STATUS" "404"

echo ""
echo "━━━ 8. unknown agent — blocked ━━━"
OUT=$(mcp_post "" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"malicious-agent","version":"1.0.0"}}}')
EVIL_SESSION=$(grep -i "mcp-session-id:" /tmp/mcp-headers.txt | awk '{print $2}' | tr -d '\r\n')
OUT=$(mcp_post "$EVIL_SESSION" '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}')
check "unknown agent blocked" "$OUT" "unknown"

echo ""
echo "━━━ 9. /metrics endpoint ━━━"
METRICS=$(curl -s "http://localhost:${GATEWAY_PORT}/metrics")
check "metrics endpoint responds"              "$METRICS" "mcp_gateway_requests_total"
check "metrics tracks allowed requests"        "$METRICS" 'outcome="allowed"'
check "metrics tracks blocked requests"        "$METRICS" 'outcome="blocked"'

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Result: $PASS passed | $FAIL failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
[ $FAIL -eq 0 ] && exit 0 || exit 1
