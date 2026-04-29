#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  test_detector.sh — end-to-end test suite for the HNG anomaly detection stack
#
#  Run on your VPS AFTER docker compose up -d --build
#  Usage:  chmod +x test_detector.sh && ./test_detector.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail
SERVER="http://localhost"
DASHBOARD="http://localhost:8080"
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

pass(){ echo -e "${GREEN}✓ PASS${NC} — $1"; }
fail(){ echo -e "${RED}✗ FAIL${NC} — $1"; }
info(){ echo -e "${YELLOW}▶${NC} $1"; }

echo "======================================================"
echo "  HNG Anomaly Detection Engine — Test Suite"
echo "======================================================"


# ── 1. Docker services are all running ───────────────────────────────────────
info "TEST 1: All Docker services running"
for svc in nginx nextcloud detector db; do
    STATE=$(docker compose ps --format json 2>/dev/null | python3 -c \
        "import sys,json; [print(s['State']) for s in [json.loads(l) for l in sys.stdin] if s.get('Service')=='$svc']" 2>/dev/null | head -1)
    if [[ "$STATE" == "running" ]]; then
        pass "Service '$svc' is running"
    else
        fail "Service '$svc' state='$STATE' (expected 'running')"
    fi
done


# ── 2. Nginx responds on port 80 ─────────────────────────────────────────────
info "TEST 2: Nginx responds on port 80"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$SERVER" --max-time 5 || echo "000")
if [[ "$CODE" =~ ^[23] ]]; then
    pass "Nginx returned HTTP $CODE"
else
    fail "Nginx returned HTTP $CODE (expected 2xx/3xx)"
fi


# ── 3. JSON log is being written ─────────────────────────────────────────────
info "TEST 3: Nginx writes JSON access log"
curl -s "$SERVER/" > /dev/null   # generate at least one log line
sleep 1
LOGFILE="/var/log/nginx/hng-access.log"
LINE=$(docker compose exec nginx tail -1 "$LOGFILE" 2>/dev/null || echo "")
if echo "$LINE" | python3 -c "import sys,json; json.loads(sys.stdin.read())" 2>/dev/null; then
    pass "Log line is valid JSON"
    # Check required fields
    for field in source_ip timestamp method path status response_size; do
        if echo "$LINE" | grep -q "\"$field\""; then
            pass "  Field '$field' present"
        else
            fail "  Field '$field' MISSING from log"
        fi
    done
else
    fail "Log line is NOT valid JSON: $LINE"
fi


# ── 4. Named volume HNG-nginx-logs exists ─────────────────────────────────────
info "TEST 4: Named volume HNG-nginx-logs exists"
if docker volume ls --format '{{.Name}}' | grep -q "HNG-nginx-logs"; then
    pass "Volume 'HNG-nginx-logs' found"
else
    fail "Volume 'HNG-nginx-logs' NOT found"
fi


# ── 5. Dashboard is reachable ────────────────────────────────────────────────
info "TEST 5: Dashboard accessible at port 8080"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$DASHBOARD" --max-time 5 || echo "000")
if [[ "$CODE" == "200" ]]; then
    pass "Dashboard returned HTTP 200"
else
    fail "Dashboard returned HTTP $CODE"
fi


# ── 6. /api/metrics returns valid JSON ───────────────────────────────────────
info "TEST 6: /api/metrics returns valid JSON with required keys"
METRICS=$(curl -s "$DASHBOARD/api/metrics" --max-time 5 || echo "{}")
for key in global_rps baseline_mean baseline_std banned top_ips cpu_pct mem_pct uptime; do
    if echo "$METRICS" | python3 -c "import sys,json; d=json.load(sys.stdin); assert '$key' in d" 2>/dev/null; then
        pass "  Key '$key' present in /api/metrics"
    else
        fail "  Key '$key' MISSING from /api/metrics"
    fi
done


# ── 7. Simulate DDoS and check detection ─────────────────────────────────────
info "TEST 7: Simulate DDoS attack and verify detection"
echo ""
echo "  Sending 3000 rapid requests (this takes ~15 seconds)…"

# First let the baseline settle a bit with normal traffic
for i in $(seq 1 20); do curl -s "$SERVER/" > /dev/null; sleep 0.5; done

echo "  Baseline primed. Now sending attack traffic…"

# Attack from THIS machine's IP — rapid-fire
if command -v ab &>/dev/null; then
    ab -n 3000 -c 100 -q "$SERVER/" &
    AB_PID=$!
elif command -v wrk &>/dev/null; then
    wrk -t4 -c100 -d15s "$SERVER/" &
    AB_PID=$!
else
    # Fallback: plain curl loop
    for i in $(seq 1 500); do curl -s "$SERVER/" > /dev/null & done
    AB_PID=$!
    echo "  (using curl fallback — install 'ab' for better simulation)"
fi

# Poll detector logs for a ban event
echo "  Polling for ban event (up to 30 seconds)…"
DETECTED=false
for i in $(seq 1 30); do
    sleep 1
    if docker compose logs detector --since=30s 2>/dev/null | grep -q "BLOCKING"; then
        DETECTED=true
        break
    fi
    echo -n "."
done
echo ""

wait $AB_PID 2>/dev/null || true

if $DETECTED; then
    pass "Detector BLOCKED an IP during simulated attack"
else
    fail "No block detected within 30 s — check detector logs"
    echo "      Run: docker compose logs detector"
fi


# ── 8. iptables has a DROP rule ───────────────────────────────────────────────
info "TEST 8: iptables has at least one DROP rule"
RULES=$(sudo iptables -L INPUT -n 2>/dev/null | grep -c "DROP" || echo "0")
if [[ "$RULES" -gt 0 ]]; then
    pass "$RULES DROP rule(s) found in iptables INPUT chain"
    sudo iptables -L INPUT -n --line-numbers | grep DROP | head -5
else
    fail "No DROP rules in iptables (attack may not have triggered yet)"
fi


# ── 9. Audit log is being written ────────────────────────────────────────────
info "TEST 9: Audit log contains entries"
AUDIT=$(docker compose exec detector cat /var/log/detector/audit.log 2>/dev/null || echo "")
if [[ -n "$AUDIT" ]]; then
    pass "Audit log has entries:"
    echo "$AUDIT" | tail -5 | sed 's/^/    /'
else
    fail "Audit log is empty or not found"
fi


# ── 10. Banned IPs appear in dashboard ───────────────────────────────────────
info "TEST 10: Banned IPs reflected in dashboard API"
BANNED=$(curl -s "$DASHBOARD/api/metrics" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(len(d.get('banned',[])))")
if [[ "$BANNED" -gt 0 ]]; then
    pass "Dashboard shows $BANNED banned IP(s)"
else
    fail "Dashboard shows 0 banned IPs (detection may not have fired)"
fi


# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "======================================================"
echo "  Test run complete."
echo "  • View dashboard:  $DASHBOARD"
echo "  • Live logs:       docker compose logs -f detector"
echo "  • iptables rules:  sudo iptables -L INPUT -n"
echo "  • Audit log:       docker compose exec detector tail -f /var/log/detector/audit.log"
echo "======================================================"
