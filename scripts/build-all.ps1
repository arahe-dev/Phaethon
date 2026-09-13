<#
.SYNOPSIS
  Builds one self-contained executable per supported platform, packaged for
  release.

.DESCRIPTION
  The product claim is "one self-contained executable per platform", not "one
  binary that runs everywhere": Go still needs a build per OS and architecture.

  Builds are packaged into archives rather than published as loose binaries,
  because the installer fetches an archive. Releasing raw binaries while
  install.sh downloads phaethon-linux-amd64.tar.gz is a 404 for every user, and
  nothing in the build would have said so. The naming contract is produced here
  and asserted by TestReleaseAssetNamingMatchesInstaller:

      phaethon-<os>-<arch>.tar.gz    linux, darwin
      phaethon-<os>-<arch>.zip       windows

  The commit is stamped into every binary so a running daemon can be told apart
  from the binary on disk, which is how `phaethon doctor` detects a stale daemon
  after an upgrade.

.PARAMETER Out
  Output directory. Defaults to dist.

.PARAMETER CloudflareClientID
  Cloudflare OAuth client to bake into official builds, so setup is turnkey.
  Omitted for source builds, which then ask for one.

.PARAMETER Checksums
  Write SHA256SUMS.txt covering the packages. The raw binaries are intermediate
  and are never checksummed or published: nobody downloads them.
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
# is what lets a user run `phaethon setup` with no arguments.
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

# The archive extension is part of the contract the installer depends on.
$targets = @(
    @{ OS = 'windows'; Arch = 'amd64'; Ext = '.exe'; Pkg = 'zip' },
    @{ OS = 'windows'; Arch = 'arm64'; Ext = '.exe'; Pkg = 'zip' },
    @{ OS = 'linux';   Arch = 'amd64'; Ext = '';     Pkg = 'tar.gz' },
    @{ OS = 'linux';   Arch = 'arm64'; Ext = '';     Pkg = 'tar.gz' },
    @{ OS = 'darwin';  Arch = 'amd64'; Ext = '';     Pkg = 'tar.gz' },
    @{ OS = 'darwin';  Arch = 'arm64'; Ext = '';     Pkg = 'tar.gz' }
)

# Staging keeps the raw binaries out of the release directory, so the checksum
# step cannot accidentally cover an intermediate.
$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("phaethon-build-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $stage | Out-Null

$saved = @{ GOOS = $env:GOOS; GOARCH = $env:GOARCH; CGO_ENABLED = $env:CGO_ENABLED }
$packages = @()
try {
    foreach ($t in $targets) {
        $env:GOOS = $t.OS; $env:GOARCH = $t.Arch; $env:CGO_ENABLED = '0'
        $exeName = "phaethon$($t.Ext)"
        $path = Join-Path $stage $exeName
        Write-Host "  building $($t.OS)/$($t.Arch)"
        go build -trimpath -ldflags $ldflags -o $path ./cmd/phaethon
        if ($LASTEXITCODE -ne 0) { throw "build failed for $($t.OS)/$($t.Arch)" }

        $base = "phaethon-$($t.OS)-$($t.Arch)"
        if ($t.Pkg -eq 'zip') {
            $archive = Join-Path $Out "$base.zip"
            # The Windows archive carries the installer too, so a Windows user
            # gets the same choice a Linux user does.
            $extra = @($path)
            $installer = Join-Path $PSScriptRoot '..\installer\install.ps1'
            if (Test-Path -LiteralPath $installer) { $extra += (Resolve-Path -LiteralPath $installer).Path }
            Compress-Archive -Path $extra -DestinationPath $archive -Force
        } else {
            $archive = Join-Path $Out "$base.tar.gz"
            # Tar runs from the staging directory so the archive holds
            # `phaethon` at its root rather than a path from this machine.
            Push-Location $stage
            try { tar -czf $archive $exeName } finally { Pop-Location }
        }
        if (-not (Test-Path -LiteralPath $archive)) { throw "packaging produced no archive for $base" }
        $packages += $archive
    }
}
finally {
    $env:GOOS = $saved.GOOS; $env:GOARCH = $saved.GOARCH; $env:CGO_ENABLED = $saved.CGO_ENABLED
    Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
}

if ($Checksums) {
    $lines = $packages | Sort-Object | ForEach-Object {
        "{0}  {1}" -f (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLower(), (Split-Path $_ -Leaf)
    }
    $lines | Set-Content (Join-Path $Out 'SHA256SUMS.txt') -Encoding ascii
    Write-Host "  wrote SHA256SUMS.txt covering $($packages.Count) package(s)"
}

Write-Host "  commit $commit"
Get-ChildItem $Out -File | Sort-Object Name | ForEach-Object {
    Write-Host ("    {0}  {1:N1} MB" -f $_.Name, ($_.Length / 1MB))
}
