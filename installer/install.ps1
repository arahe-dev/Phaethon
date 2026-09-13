<#
.SYNOPSIS
  Installs Phaethon for the current user.

.DESCRIPTION
  This installer deliberately stops short of the two actions that change what
  the machine trusts: it never installs a certificate authority and never
  enables the system proxy. Those happen in `phaethon setup`, where they are
  explained and consented to individually.

  What it does: lay down a versioned binary, put it on PATH, create the state
  directory with owner-only access, and register the uninstaller.

  Installing is idempotent: running it again replaces the binary and leaves
  configuration, the certificate authority and learned routes untouched, so an
  upgrade does not disturb a working installation.

.PARAMETER Version
  Version label for the installed build, e.g. v0.1.0-beta.1.

.PARAMETER Binary
  Path to the phaethon.exe to install. Defaults to the one beside this script.

.PARAMETER InstallDir
  Where to install. Defaults to %LOCALAPPDATA%\Programs\Phaethon.

.PARAMETER Quiet
  Suppress progress output.
#>
[CmdletBinding()]
param(
    [string]$Version = "dev",
    [string]$Binary,
    [string]$InstallDir,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

function Say([string]$Message) { if (-not $Quiet) { Write-Host $Message } }

function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
}

# --- resolve inputs ---------------------------------------------------------
if (-not $Binary) {
    $candidates = @(
        (Join-Path $PSScriptRoot 'phaethon.exe'),
        (Join-Path $PSScriptRoot '..\dist\phaethon.exe'),
        (Join-Path $PSScriptRoot '..\phaethon.exe')
    )
    $Binary = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if (-not $Binary -or -not (Test-Path -LiteralPath $Binary)) {
    throw "Cannot find phaethon.exe. Pass -Binary <path>."
}
if (-not $InstallDir) {
    $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\Phaethon'
}

$dataDir  = Join-Path $env:ProgramData 'Phaethon'
$exeName  = 'phaethon.exe'
$tag      = $Version.TrimStart('v')

Say "Installing Phaethon $Version"
Say "  from  $Binary"
Say "  to    $InstallDir"

# --- stop a running daemon before replacing its file ------------------------
# Windows will not let a running executable be overwritten, and an
# installation that half-replaced the binary would be worse than one that
# refused.
$running = Get-Process -Name phaethon -ErrorAction SilentlyContinue
if ($running) {
    Say "  stopping the running daemon first"
    try { & $running[0].Path down --quiet | Out-Null } catch { }
    Start-Sleep -Milliseconds 800
    $still = Get-Process -Name phaethon -ErrorAction SilentlyContinue
    if ($still) {
        & schtasks /end /tn Phaethon 2>$null | Out-Null
        $still | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    }
}

# --- lay down the binary ----------------------------------------------------
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$target = Join-Path $InstallDir $exeName

# Versioned copies are kept so a rollback is a copy rather than a re-download.
$versioned = Join-Path $InstallDir ("phaethon-{0}.exe" -f $tag)

Copy-Item -LiteralPath $Binary -Destination $target -Force
if ($tag -ne 'dev') { Copy-Item -LiteralPath $Binary -Destination $versioned -Force }

$hash = Get-Sha256 $target
Say "  installed $target"
Say "  sha256    $hash"

# --- state directory with owner-only access ---------------------------------
# The configuration holds a local token and the relay secret, and the CA
# directory holds a private key. Neither may be readable by other accounts.
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
try {
    & icacls $dataDir /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" | Out-Null
    Say "  secured   $dataDir (owner-only)"
} catch {
    Write-Warning "Could not restrict access to $dataDir; other users on this machine may be able to read its contents."
}

# --- PATH -------------------------------------------------------------------
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$entries = @()
if ($userPath) { $entries = $userPath -split ';' | Where-Object { $_ -ne '' } }
if ($entries -notcontains $InstallDir) {
    $newPath = (@($entries) + $InstallDir) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Say "  added to PATH (open a new terminal to use it)"
} else {
    Say "  already on PATH"
}

# --- uninstall registration -------------------------------------------------
$uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Phaethon'
New-Item -Path $uninstallKey -Force | Out-Null
$uninstallCmd = '"{0}" uninstall' -f $target
Set-ItemProperty -Path $uninstallKey -Name 'DisplayName'     -Value 'Phaethon'
Set-ItemProperty -Path $uninstallKey -Name 'DisplayVersion'  -Value $tag
Set-ItemProperty -Path $uninstallKey -Name 'Publisher'       -Value 'Phaethon'
Set-ItemProperty -Path $uninstallKey -Name 'InstallLocation' -Value $InstallDir
Set-ItemProperty -Path $uninstallKey -Name 'UninstallString' -Value $uninstallCmd
Set-ItemProperty -Path $uninstallKey -Name 'NoModify'        -Value 1 -Type DWord
Set-ItemProperty -Path $uninstallKey -Name 'NoRepair'        -Value 1 -Type DWord
Say "  registered in Settings > Apps"

# --- what this installer deliberately did NOT do ----------------------------
# --- offer to finish the job ------------------------------------------------
# Setup is what installs the certificate and enables the proxy, and both of
# those ask for consent, so they cannot happen silently during an install.
# Offering to run it here is the difference between a product and a set of
# instructions.
Say ""
Say "Phaethon is installed but not yet active."
Say ""
Say "Setup finishes it: it authorizes Cloudflare, asks before trusting the"
Say "Phaethon certificate authority, enables the proxy, and verifies the result."
Say ""
if ($Quiet -or -not $Host.UI.RawUI -or $env:PHAETHON_SKIP_SETUP_PROMPT -eq '1') {
    Say "Run it when you are ready:"
    Say "    phaethon setup"
    Say ""
    return
}
$answer = Read-Host "Set up Phaethon now? [Y/n]"
if ($answer -eq '' -or $answer -match '^(y|yes)$') {
    Say ""
    # Setup asks its own questions, so it runs in this window rather than
    # detached: a consent prompt with no visible terminal is worse than none.
    & $target setup
    $code = $LASTEXITCODE
    Say ""
    if ($code -eq 0) { Say "Phaethon is ready." } else { Say "Setup did not complete. Run 'phaethon setup' to resume." }
} else {
    Say ""
    Say "Skipped. Run this whenever you are ready:"
    Say "    phaethon setup"
}
Say ""
