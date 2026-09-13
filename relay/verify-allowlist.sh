#!/bin/bash
# Relay allowlist semantics against the deployed Function: the wildcard must
# match the bare domain and subdomains, and must not match lookalikes.
R="${1:?relay URL required}"
T="${2:?relay token required}"

probe() {
  local host="$1" expect="$2"
  code=$(timeout 30 curl -sS -o /tmp/al.txt --max-time 25 -H "X-Phaethon-Token: $T" \
    -w '%{http_code}' "$R/relay/$host/" 2>/dev/null)
  if [ "$code" = "$expect" ]; then
    printf '  %-34s %s (expected %s) OK\n' "$host" "$code" "$expect"
  else
    printf '  %-34s %s (expected %s) MISMATCH  %s\n' "$host" "$code" "$expect" "$(head -c 90 /tmp/al.txt | tr -d '\n')"
  fi
}

echo "allowlist: example.test, *.example.test, *.example.app"
echo
echo "== must be allowed (not 403) =="
probe example.test                200
probe api.example.test            308
probe swr.example.app            302
probe www.example.test            200
echo
echo "== must be refused with 403 =="
probe example.com               403
probe github.com                403
probe notexample.test             403
probe example.test.evil.test      403
probe xexample.app               403
echo
echo "== the wildcard must not be defeated by a suffix trick =="
probe evilexample.app            403
