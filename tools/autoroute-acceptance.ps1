#!/usr/bin/env pwsh
# Live acceptance for automatic routing. Reads the token from the daemon's own
# config so no secret is passed on a command line.

$ErrorActionPreference = 'Stop'
$cfg = Get-Content "$env:ProgramData\Phaethon\phaethon.json" -Raw | ConvertFrom-Json
$tok = $cfg.local_token
$base = 'http://127.0.0.1:8377'

function Get-Status {
    (curl.exe -sS --max-time 10 -H "Authorization: Bearer $tok" "$base/phaethon/status" 2>$null | ConvertFrom-Json)
}

function Show-Leases($status) {
    if (-not $status.auto_route.leases) { Write-Host '              (no leases)'; return }
    foreach ($l in $status.auto_route.leases) {
        Write-Host ("              {0,-32} {1,-6} {2,-16} {3,-24} expires {4,4}s stale={5}" -f `
            $l.scope, $l.route, $l.state, $l.reason, [int]($l.expires_in_ms / 1000), $l.stale)
    }
}

Write-Host '=== A. FACADE RENDERS (auto-routed host, no static rule) ==='
$html = Join-Path $env:TEMP 'autoroute-facade.html'
$code = curl.exe -sS -o $html --max-time 50 -w '%{http_code}' "$base/r/example.test/"
$bytes = (Get-Item $html).Length
$body = Get-Content $html -Raw
Write-Host ("  http={0} bytes={1} title={2}" -f $code, $bytes, ($body -match 'Agentic Infrastructure'))
Write-Host ("  rewritten refs: {0}" -f ([regex]::Matches($body, [regex]::Escape('/r/example.test/')).Count))

Write-Host ''
Write-Host '=== B. LEASE BEHAVIOUR: one diagnosis, then cache ==='
$before = Get-Status
Write-Host ("  before:      lookups={0} static={1} lease={2} fairy={3}" -f `
    $before.auto_route.counters.lookups, $before.auto_route.counters.static_hits,
    $before.auto_route.counters.lease_hits, $before.auto_route.counters.oracle_calls)

$t0 = Get-Date
$c1 = curl.exe -sS -o NUL --max-time 50 -w '%{http_code}' "$base/r/example.test/ai-sdk"
$d1 = ((Get-Date) - $t0).TotalMilliseconds
$s1 = Get-Status
Write-Host ("  request 1:   http={0} in {1:N0}ms  -> fairy={2} lease_hits={3}" -f `
    $c1, $d1, $s1.auto_route.counters.oracle_calls, $s1.auto_route.counters.lease_hits)

$t0 = Get-Date
foreach ($i in 2..9) {
    curl.exe -sS -o NUL --max-time 50 "$base/r/example.test/ai-gateway" | Out-Null
}
$d2 = ((Get-Date) - $t0).TotalMilliseconds
$s2 = Get-Status
Write-Host ("  8 more:      in {0:N0}ms total -> fairy={1} lease_hits={2}" -f `
    $d2, $s2.auto_route.counters.oracle_calls, $s2.auto_route.counters.lease_hits)
Write-Host ("  VERDICT: fairy calls {0} -> {1} -> {2} across 9 requests" -f `
    $before.auto_route.counters.oracle_calls, $s1.auto_route.counters.oracle_calls, $s2.auto_route.counters.oracle_calls)
Show-Leases $s2

Write-Host ''
Write-Host '=== C. STALE-WHILE-REVALIDATE (short TTLs, waiting for expiry) ==='
$s3 = Get-Status
$ttl = [int]($s3.auto_route.leases | Where-Object { $_.scope -eq 'example.test' } | Select-Object -First 1).expires_in_ms / 1000
Write-Host ("  relay lease expires in {0}s; waiting..." -f [int]$ttl)
Start-Sleep -Seconds ([int]$ttl + 4)
$s4 = Get-Status
Write-Host ("  after expiry (before use): revalidations={0} fairy={1}" -f `
    $s4.auto_route.counters.revalidations, $s4.auto_route.counters.oracle_calls)
Show-Leases $s4

$t0 = Get-Date
$c2 = curl.exe -sS -o NUL --max-time 50 -w '%{http_code}' "$base/r/example.test/"
$d3 = ((Get-Date) - $t0).TotalMilliseconds
Write-Host ("  first use after expiry: http={0} in {1:N0}ms (served immediately, not blocked on diagnosis)" -f $c2, $d3)
Start-Sleep -Seconds 6
$s5 = Get-Status
Write-Host ("  then: revalidations={0} fairy={1} relay_verified={2}" -f `
    $s5.auto_route.counters.revalidations, $s5.auto_route.counters.oracle_calls, $s5.auto_route.counters.relay_verified)
Show-Leases $s5

Write-Host ''
Write-Host '=== D. STATIC RULES BEAT LEARNING (never diagnosed) ==='
$s6 = Get-Status
Write-Host ("  counters now: lookups={0} static={1} fairy={2}" -f `
    $s6.auto_route.counters.lookups, $s6.auto_route.counters.static_hits, $s6.auto_route.counters.oracle_calls)
foreach ($h in 'github.com', 'objects.githubusercontent.com') {
    $c = curl.exe -sS -o NUL --max-time 40 -w '%{http_code}' "$base/r/$h/"
    Write-Host ("  /r/{0,-32} {1}" -f "$h/", $c)
}
$s7 = Get-Status
Write-Host ("  after:       lookups={0} static={1} fairy={2}  (static grew, fairy flat)" -f `
    $s7.auto_route.counters.lookups, $s7.auto_route.counters.static_hits, $s7.auto_route.counters.oracle_calls)
