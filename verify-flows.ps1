# Phaethon V0 milestone verification: the three flows that matter.
#
#   1. example.test                -> relay        -> works (direct is intercepted)
#   2. objects.githubusercontent -> direct + multi-IP failover -> works
#   3. github.com                -> direct       -> git works through the proxy
#
#   .\verify-flows.ps1
param(
    [string]$Proxy = '127.0.0.1:8377',
    [string]$Config = "$env:ProgramData\Phaethon\phaethon.json"
)

$ErrorActionPreference = 'Continue'
$cfg = Get-Content $Config -Raw | ConvertFrom-Json
$token = $cfg.local_token

function Note($t) { Write-Host $t }

Note "=== control: direct path is still broken for example ==="
foreach ($u in 'https://example.test', 'https://api.example.test') {
    $r = & curl.exe -sS -o NUL --max-time 15 -w 'code=%{http_code} verify=%{ssl_verify_result}' $u 2>&1 | Select-Object -First 1
    Note ("  direct {0,-24} {1}" -f $u, $r)
}

Note ""
Note "=== FLOW 1: example.test through the relay ==="
$r = & curl.exe -sS -o "$env:TEMP\phaethon-example.html" --max-time 40 `
    -D "$env:TEMP\phaethon-example.head" -w 'code=%{http_code} bytes=%{size_download} t=%{time_total}' `
    "http://$Proxy/r/example.test/" 2>&1 | Select-Object -First 1
Note "  facade  http://$Proxy/r/example.test/  -> $r"
Get-Content "$env:TEMP\phaethon-example.head" -ErrorAction SilentlyContinue |
    Where-Object { $_ -match '^(HTTP/|X-Phaethon|Content-Type|Server)' } |
    ForEach-Object { "    $($_.Trim())" }
$body = Get-Content "$env:TEMP\phaethon-example.html" -Raw -ErrorAction SilentlyContinue
if ($body -match '<title>([^<]+)</title>') { Note "    title: $($matches[1])" }

Note ""
Note "  api.example.test through the relay:"
$r = & curl.exe -sS -o NUL --max-time 40 -w 'code=%{http_code}' "http://$Proxy/r/api.example.test/" 2>&1 | Select-Object -First 1
Note "    $r"

Note ""
Note "  example.app through the relay:"
$r = & curl.exe -sS -o NUL --max-time 40 -w 'code=%{http_code}' "http://$Proxy/r/swr.example.app/" 2>&1 | Select-Object -First 1
Note "    $r"

Note ""
Note "=== FLOW 2: objects.githubusercontent.com direct with multi-IP failover ==="
Note "  raw direct with the stalling address pinned (control):"
$r = & curl.exe -sS -o NUL --max-time 12 --resolve 'objects.githubusercontent.com:443:185.199.109.133' `
    -w 'code=%{http_code} t=%{time_total}' https://objects.githubusercontent.com/ 2>&1 | Select-Object -First 1
Note "    pinned .109 -> $r"

Note "  30 sequential requests through Phaethon:"
$ok = 0; $fail = 0; $times = @()
for ($i = 1; $i -le 30; $i++) {
    $out = & curl.exe -sS -o NUL --max-time 25 -w '%{http_code} %{time_total}' `
        "http://$Proxy/r/objects.githubusercontent.com/" 2>&1 | Select-Object -First 1
    $parts = "$out".Split(' ')
    if ($parts[0] -match '^\d+$' -and $parts[0] -ne '000') { $ok++; $times += [double]$parts[1] } else { $fail++ }
}
Note "    reached origin: $ok/30  failed: $fail"
if ($times.Count -gt 0) {
    Note ("    latency avg {0:N0}ms max {1:N0}ms" -f (($times | Measure-Object -Average).Average * 1000), (($times | Measure-Object -Maximum).Maximum * 1000))
}

Note ""
Note "=== FLOW 3: github.com direct, git over the local proxy (CONNECT) ==="
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$gitOut = & git -c "http.proxy=http://$Proxy" ls-remote https://github.com/arahe-dev/fairy.git 2>&1
$code = $LASTEXITCODE
$sw.Stop()
Note "  git ls-remote exit=$code wall=$([int]$sw.Elapsed.TotalMilliseconds)ms refs=$(($gitOut | Measure-Object).Count)"
$gitOut | Select-Object -First 3 | ForEach-Object { "    $_" }

Note ""
Note "=== daemon counters after the flows ==="
$status = & curl.exe -sS --max-time 10 -H "Authorization: Bearer $token" "http://$Proxy/phaethon/status" 2>&1 | ConvertFrom-Json
Note "  requests=$($status.counts.requests) direct=$($status.counts.direct_requests) relay=$($status.counts.relayed_requests)"
$status.counts.by_route.PSObject.Properties | ForEach-Object { "    route $($_.Name) = $($_.Value)" }
$status.counts.by_host.PSObject.Properties | ForEach-Object { "    host  $($_.Name) = $($_.Value)" }
$status.counts.failures.PSObject.Properties | ForEach-Object { "    fail  $($_.Name) = $($_.Value)" }
$status.address_health.PSObject.Properties | ForEach-Object { "    addr  $($_.Name) = $($_.Value)" }
