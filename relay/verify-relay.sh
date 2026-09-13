#!/bin/bash
# Verify the Phaethon relay contract: health, auth, allowlist, egress.
R="${1:?relay URL required}"
T="${2:?relay token required}"

echo "=== health (no auth) ==="
timeout 25 curl -sS --max-time 20 -w '\n[code=%{http_code} ip=%{remote_ip}]\n' "$R/health" 2>&1 | head -20

echo
echo "=== no token -> must be 401 ==="
timeout 25 curl -sS -o /tmp/r1.txt --max-time 20 -w 'code=%{http_code}\n' "$R/relay/example.test/" 2>&1 | head -2
head -c 160 /tmp/r1.txt | tr -d '\n'; echo

echo
echo "=== wrong token -> must be 401 ==="
timeout 25 curl -sS -o /tmp/r2.txt --max-time 20 -H 'X-Phaethon-Token: wrong' -w 'code=%{http_code}\n' "$R/relay/example.test/" 2>&1 | head -2
head -c 160 /tmp/r2.txt | tr -d '\n'; echo

echo
echo "=== non-allowlisted host -> must be 403 ==="
timeout 25 curl -sS -o /tmp/r3.txt --max-time 20 -H "X-Phaethon-Token: $T" -w 'code=%{http_code}\n' "$R/relay/example.com/" 2>&1 | head -2
head -c 220 /tmp/r3.txt | tr -d '\n'; echo

echo
echo "=== allowlisted egress: example through the relay ==="
timeout 30 curl -sS -o /tmp/r4.txt --max-time 25 -H "X-Phaethon-Token: $T" \
  -D /tmp/r4.head -w 'code=%{http_code} bytes=%{size_download} t=%{time_total}\n' "$R/relay/example.test/" 2>&1 | head -2
grep -iE '^(HTTP/|x-phaethon-|content-type|server|location)' /tmp/r4.head | head -8 | sed 's/^/  /'
echo "  body head: $(head -c 120 /tmp/r4.txt | tr -d '\n')"

echo
echo "=== allowlisted egress: api.example.test (expect 3xx/2xx JSON) ==="
timeout 30 curl -sS -o /tmp/r5.txt --max-time 25 -H "X-Phaethon-Token: $T" \
  -w 'code=%{http_code} bytes=%{size_download}\n' "$R/relay/api.example.test/" 2>&1 | head -2
echo "  body head: $(head -c 120 /tmp/r5.txt | tr -d '\n')"

echo
echo "=== control: direct path from this machine, same host ==="
timeout 20 curl -sS -o /dev/null --max-time 15 -w 'direct example.test code=%{http_code} verify=%{ssl_verify_result}\n' https://example.test 2>&1 | head -2
