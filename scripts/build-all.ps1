<#
.SYNOPSIS
  Builds one self-contained executable per supported platform.

.DESCRIPTION
  The product claim is "one self-contained executable per platform", not "one
  binary everywhere": Go still needs a build per OS and architecture.

  The commit is stamped into every binary so a running daemon can be told apart
  from the binary on disk, which is how `phaethon doctor` detects a stale
  daemon after an upgrade.

.PARAMETER Out
  Output directory. Defaults to dist.
#>
[CmdletBinding()]
param(
    [string]$Out = "dist",
    [string]$CloudflareClientID = "",
    [switch]$Checksums
)

$ErrorActionPreference = 'Stop'
$commit = (git rev-parse --short HEAD 2>$null)
if (-not $commit) { $commit = "dev" }

# A PKCE public client has no secret, so baking the identifier in is normal and
# is what lets a user run `phaethon setup` with no arguments. Without it the
# binary still works, but the user must supply --cloudflare-client-id.
if (-not $CloudflareClientID) { $CloudflareClientID = $env:PHAETHON_CLOUDFLARE_CLIENT_ID }
$ldflags = "-s -w -X main.buildCommit=$commit"
if ($CloudflareClientID) {
    $ldflags += " -X main.cloudflareClientID=$CloudflareClientID"
    Write-Host "  embedding Cloudflare client $CloudflareClientID"
} else {
    Write-Warning "No Cloudflare client id supplied; this build will require --cloudflare-client-id"
}
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Out = (Resolve-Path -LiteralPath $Out).Path

$targets = @(
    @{ OS = 'windows'; Arch = 'amd64'; Ext = '.exe' },
    @{ OS = 'windows'; Arch = 'arm64'; Ext = '.exe' },
    @{ OS = 'linux';   Arch = 'amd64'; Ext = '' },
    @{ OS = 'linux';   Arch = 'arm64'; Ext = '' },
    @{ OS = 'darwin';  Arch = 'amd64'; Ext = '' },
    @{ OS = 'darwin';  Arch = 'arm64'; Ext = '' }
)

$saved = @{ GOOS = $env:GOOS; GOARCH = $env:GOARCH; CGO_ENABLED = $env:CGO_ENABLED }
try {
    foreach ($t in $targets) {
        $env:GOOS = $t.OS; $env:GOARCH = $t.Arch; $env:CGO_ENABLED = '0'
        $name = "phaethon-$($t.OS)-$($t.Arch)$($t.Ext)"
        Write-Host "  building $name"
        go build -trimpath -ldflags $ldflags -o (Join-Path $Out $name) ./cmd/phaethon
        if ($LASTEXITCODE -ne 0) { throw "build failed for $($t.OS)/$($t.Arch)" }
    }
}
finally {
    $env:GOOS = $saved.GOOS; $env:GOARCH = $saved.GOARCH; $env:CGO_ENABLED = $saved.CGO_ENABLED
}

if ($Checksums) {
    $lines = Get-ChildItem $Out -File |
        Where-Object { $_.Name -like 'phaethon-*' } |
        ForEach-Object { "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name }
    $lines | Set-Content (Join-Path $Out 'SHA256SUMS.txt') -Encoding ascii
    Write-Host "  wrote SHA256SUMS.txt"
}
Write-Host "  commit $commit"
