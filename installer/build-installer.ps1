<#
.SYNOPSIS
  Builds PhaethonSetup-x64.exe: a single self-extracting installer.

.DESCRIPTION
  A tester should receive one file, not a repository. This wraps the compiled
  binary and install.ps1 into a self-extracting executable using IExpress,
  which ships with Windows, so building the installer needs no extra tooling
  and no network access.

  The resulting EXE extracts to a temporary directory, runs the installer, and
  removes the temporary copy.

.PARAMETER Version
  Version label baked into the installer, e.g. v0.1.0-beta.1.

.PARAMETER Binary
  Path to the phaethon.exe to package.

.PARAMETER Out
  Output directory for PhaethonSetup-x64.exe.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$Binary,
    [string]$Out = "dist"
)

$ErrorActionPreference = 'Stop'
$tag = $Version.TrimStart('v')

if (-not (Test-Path -LiteralPath $Binary)) { throw "binary not found: $Binary" }
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Out = (Resolve-Path -LiteralPath $Out).Path

$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("phaethon-installer-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $stage | Out-Null

try {
    # --- stage the payload --------------------------------------------------
    Copy-Item -LiteralPath $Binary -Destination (Join-Path $stage 'phaethon.exe')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'install.ps1') -Destination (Join-Path $stage 'install.ps1')

    # A launcher, because IExpress runs a command rather than a PowerShell script.
    # -NoProfile keeps a tester's profile from affecting the install, and
    # -ExecutionPolicy Bypass is scoped to this process only.
    $launch = @"
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" -Version "$tag" -Binary "%~dp0phaethon.exe"
if errorlevel 1 (
  echo.
  echo Installation failed. See the messages above.
  pause
  exit /b 1
)
echo.
echo Installation complete.
pause
"@
    Set-Content -LiteralPath (Join-Path $stage 'launch.cmd') -Value $launch -Encoding ascii

    # --- build the self-extracting package ---------------------------------
    $sed = Join-Path $stage 'phaethon.sed'
    $outExe = Join-Path $Out 'PhaethonSetup-x64.exe'
    $cab = Join-Path $stage 'payload.cab'

    # Files are listed explicitly so nothing unintended is packaged.
    $sedBody = @"
[Version]
Class=IEXPRESS
SEDVersion=3
[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=0
HideExtractAnimation=1
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=
DisplayLicense=
FinishMessage=
TargetName=$outExe
FriendlyName=Phaethon Setup $Version
AppLaunched=launch.cmd
PostInstallCmd=<None>
AdminQuietInstCmd=
UserQuietInstCmd=
SourceFiles=SourceFiles
[Strings]
FILE0="phaethon.exe"
FILE1="install.ps1"
FILE2="launch.cmd"
[SourceFiles]
SourceFiles0=$stage\
[SourceFiles0]
%FILE0%=
%FILE1%=
%FILE2%=
"@
    Set-Content -LiteralPath $sed -Value $sedBody -Encoding ascii

    Write-Host "Building $outExe"
    $iexpress = Join-Path $env:SystemRoot 'System32\iexpress.exe'
    if (-not (Test-Path -LiteralPath $iexpress)) {
        throw "IExpress is unavailable; ship dist\phaethon.exe plus installer\install.ps1 instead"
    }
    & $iexpress /N /Q $sed | Out-Null
    if (-not (Test-Path -LiteralPath $outExe)) {
        throw "IExpress did not produce $outExe"
    }

    $size = [math]::Round((Get-Item -LiteralPath $outExe).Length / 1MB, 1)
    Write-Host "  PhaethonSetup-x64.exe  $size MB"

    # The plain binary and script are shipped too, so a tester who prefers a
    # scripted install is not forced through the self-extractor. They may
    # already be in place when building straight into dist.
    $plainTarget = Join-Path $Out 'phaethon.exe'
    if ((Resolve-Path -LiteralPath $Binary).Path -ne (Join-Path $Out 'phaethon.exe')) {
        Copy-Item -LiteralPath $Binary -Destination $plainTarget -Force
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'install.ps1') -Destination (Join-Path $Out 'install.ps1') -Force
    Write-Host "  phaethon.exe + install.ps1 (for scripted installs)"
}
finally {
    Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
}
