#!/bin/bash
# Security acceptance for the browser surfaces plus the relay, plus the
# current path state for the hosts the route table lists.
P=http://127.0.0.1:8377
TOKEN="${1:?local token required}"

echo "=== E. security acceptance ==="
printf '  health (no token, must be 200):            '
curl -sS -o /dev/null -w '%{http_code}\n' --max-time 10 "$P/phaethon/health"
printf '  status without token (must be 401):        '
curl -sS -o /dev/null -w '%{http_code}\n' --max-time 10 "$P/phaethon/status"
printf '  status with token (must be 200):           '
curl -sS -o /dev/null -w '%{http_code}\n' --max-time 10 -H "Authorization: Bearer $TOKEN" "$P/phaethon/status"
printf '  facade unlisted host (must be 403):        '
curl -sS -o /dev/null -w '%{http_code}\n' --max-time 20 "$P/r/neverssl.com/"
printf '  facade lookalike notexample.test (must 403): '
curl -sS -o /dev/null -w '%{http_code}\n' --max-time 20 "$P/r/notexample.test/"
printf '  facade example.test.evil.test (must be 403): '
curl -sS -o /dev/null -w '%{http_code}\n' --max-time 20 "$P/r/example.test.evil.test/"
printf '  facade 127.0.0.1 (loopback, must be 403):  '
curl -sS -o /dev/null -w '%{http_code}\n' --max-time 20 "$P/r/127.0.0.1/"
printf '  facade 169.254.169.254 (metadata, 403):    '
curl -sS -o /dev/null -w '%{http_code}\n' --max-time 20 "$P/r/169.254.169.254/"
printf '  facade 10.0.0.1 (private, must be 403):    '
curl -sS -o /dev/null -w '%{http_code}\n' --max-time 20 "$P/r/10.0.0.1/"
printf '  facade localhost (must be 403):            '
curl -sS -o /dev/null -w '%{http_code}\n' --max-time 20 "$P/r/localhost/"
printf '  daemon root path (must be 200 usage):      '
curl -sS -o /dev/null -w '%{http_code}\n' --max-time 10 "$P/"

echo
echo "=== browser surfaces for the routed hosts ==="
for h in example.test api.example.test swr.example.app github.com objects.githubusercontent.com drive.google.com; do
  code=$(timeout 45 curl -sS -o /dev/null --max-time 40 -w '%{http_code}' "$P/r/$h/")
  printf '  %-32s %s\n' "/r/$h/" "$code"
done

echo
echo "=== current direct-path state for the same hosts ==="
for h in example.test api.example.test swr.example.app; do
  printf '  %-24s ' "$h"
  timeout 20 curl -sS -o /dev/null --max-time 15 -w 'code=%{http_code} verify=%{ssl_verify_result}\n' "https://$h/" 2>&1 | head -1
done
