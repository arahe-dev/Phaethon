# Add Phaethon's build directory to the *user* PATH, so `phaethon` works from
# any new terminal.
#
# Deliberate choices:
#   - The raw registry value is read with DoNotExpandEnvironmentNames and
#     rewritten with its original value kind preserved, so entries like
#     %USERPROFILE%... survive untouched.
#   - setx is NOT used: it truncates PATH at 1024 characters.
#   - Only the user PATH changes (no elevation, no machine-wide effect).
#   - The value is backed up before it is written.
#   - The directory is appended, so it cannot shadow an existing tool.

$ErrorActionPreference = 'Stop'

$dir = 'C:\phaethon\Phaethon'
$exe = Join-Path $dir 'phaethon.exe'

if (-not (Test-Path $exe)) { throw "expected binary at $exe" }

$key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
if ($null -eq $key) { throw 'cannot open HKCU\Environment for writing' }

$raw = $key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
$kind = $key.GetValueKind('Path')
Write-Host "current user PATH: $($raw.Length) chars, kind $kind"

# Back up first.
$backupDir = Join-Path $env:ProgramData 'Phaethon'
if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir | Out-Null }
$backup = Join-Path $backupDir ("user-path-backup-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
Set-Content -LiteralPath $backup -Value $raw -Encoding UTF8
Write-Host "backup written: $backup"

# Already present? Compare case-insensitively and ignore a trailing separator.
$entries = $raw -split ';'
$normalized = $entries | ForEach-Object { $_.Trim().TrimEnd('\') }
if ($normalized -contains $dir.TrimEnd('\')) {
    Write-Host "already on the user PATH: $dir (nothing to do)"
} else {
    $new = $raw.TrimEnd(';') + ';' + $dir
    # Write back with the same kind, so REG_EXPAND_SZ semantics are preserved.
    $key.SetValue('Path', $new, $kind)
    Write-Host "added: $dir  (user PATH now $($new.Length) chars)"
}
$key.Close()

# Ask running shells and Explorer to re-read the environment, so newly opened
# terminals pick this up without a sign-out.
$sig = @'
using System;
using System.Runtime.InteropServices;
public static class Env {
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam,
        string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
    public static void Broadcast() {
        UIntPtr result;
        SendMessageTimeout(new IntPtr(0xffff), 0x1A, UIntPtr.Zero, "Environment", 2, 5000, out result);
    }
}
'@
try {
    Add-Type -TypeDefinition $sig -ErrorAction Stop
    [Env]::Broadcast()
    Write-Host 'broadcast WM_SETTINGCHANGE (new terminals pick the change up)'
} catch {
    Write-Host "note: could not broadcast WM_SETTINGCHANGE ($($_.Exception.Message));"
    Write-Host "      new terminals will still see it, but apps already running may need a restart."
}
