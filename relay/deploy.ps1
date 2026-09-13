# Deploy the Phaethon relay to Cloudflare Pages.
#
#   .\deploy.ps1 [-Project phaethon-relay] [-Token <relay-shared-secret>]
#
# Requires wrangler auth (npx wrangler login) or CLOUDFLARE_API_TOKEN.
# The shared secret is generated if not supplied; it must match
# relay.token in the Phaethon daemon's configuration.
param(
    [string]$Project = 'phaethon-relay',
    [string]$Token = '',
    [switch]$NoSecret
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not $Token) {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $Token = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
    Write-Host "generated relay token: $Token"
}
$Token | Set-Content -Path "$PSScriptRoot\.relay-token" -NoNewline -Encoding ASCII

Write-Host "=== ensuring Pages project $Project ==="
npx --yes wrangler@latest pages project create $Project --production-branch main 2>&1 |
    Select-String -Pattern 'Successfully created|already exists|error' | ForEach-Object { $_.Line.Trim() }

if (-not $NoSecret) {
    Write-Host "=== setting PHAETHON_TOKEN secret ==="
    $Token | npx --yes wrangler@latest pages secret put PHAETHON_TOKEN --project-name $Project 2>&1 |
        Select-Object -Last 4
}

Write-Host "=== deploying ==="
npx --yes wrangler@latest pages deploy public --project-name $Project 2>&1 | Select-Object -Last 5

$url = "https://$Project.pages.dev"
Write-Host ""
Write-Host "relay URL:   $url"
Write-Host "relay token: $Token"
Write-Host ""
Write-Host "Configure the daemon with:"
Write-Host "  phaethon config init --relay-url $url --relay-token $Token"
Write-Host ""
Write-Host "Verify:"
Write-Host "  curl `"$url/health`""
Write-Host "  curl -H `"X-Phaethon-Token: $Token`" `"$url/relay/example.test/`" -o NUL -w `"%{http_code}`""
