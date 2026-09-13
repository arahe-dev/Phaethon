<#
.SYNOPSIS
  Tags a release. One command, because tagging by hand is how a tag ends up on a
  commit nobody verified.

.DESCRIPTION
  The tag is the source of truth for the version. There is deliberately no
  version file to bump: a second place recording the version is a second place
  to get it wrong, and the binary already reports its commit so a running daemon
  can be told apart from the binary on disk.

  This wrapper does the things a person forgets under time pressure: it refuses
  a dirty tree, it runs the same gates CI runs, it checks that CI actually
  passed for the commit being tagged, and it warns when the build will ship
  without a Cloudflare client so setup is not turnkey.

  It pushes only the tag. The release workflow owns everything after that:
  gating, building, packaging, checksums and publishing.

.EXAMPLE
  ./scripts/release.ps1 v0.1.0-beta.1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][string]$Version,
    [string]$Message = "",
    [switch]$SkipCI,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

function Step($n, $text) { Write-Host "`n[$n] $text" }
function Fail($text) { Write-Error $text; exit 1 }

if ($Version -notmatch '^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$') {
    Fail "version must look like v0.1.0 or v0.1.0-beta.1 (got '$Version')"
}

# --- 1. clean main, up to date ---------------------------------------------
Step 1 "working tree and branch"
$branch = git rev-parse --abbrev-ref HEAD
if ($branch -ne 'main') { Fail "releases are cut from main, but this is '$branch'" }
$dirty = git status --porcelain
if ($dirty) { Fail "the working tree is not clean:`n$dirty" }
Write-Host "  clean, on main"

git fetch --quiet origin main
$local = git rev-parse HEAD
$remote = git rev-parse origin/main
if ($local -ne $remote) { Fail "local main is not origin/main; push or pull first" }
Write-Host "  up to date with origin/main ($($local.Substring(0,7)))"

if (git tag --list $Version) { Fail "tag $Version already exists" }

# --- 2. the gates CI runs ---------------------------------------------------
Step 2 "gofmt, vet, test, race"
$unformatted = gofmt -l .
if ($unformatted) { Fail "these files are not gofmt-clean:`n$unformatted" }
Write-Host "  gofmt clean"

go vet ./...; if ($LASTEXITCODE -ne 0) { Fail "go vet failed" }
Write-Host "  vet clean"

# Uncached, because a cached pass is not a pass: this session shipped a broken
# test that a cached result had been reporting as green.
go test -count=1 ./... -timeout 10m; if ($LASTEXITCODE -ne 0) { Fail "tests failed" }
Write-Host "  tests pass (uncached)"

go test -race -count=1 ./... -timeout 15m; if ($LASTEXITCODE -ne 0) { Fail "race tests failed" }
Write-Host "  race clean"

# --- 3. the packaging contract ---------------------------------------------
Step 3 "release contract"
go test ./internal/release/ -count=1 -timeout 2m
if ($LASTEXITCODE -ne 0) { Fail "the release contract test failed; the installer and the build disagree" }
Write-Host "  installer and build agree on asset names"

# --- 4. was this commit verified? ------------------------------------------
Step 4 "CI status for $($local.Substring(0,7))"
if ($SkipCI) {
    Write-Warning "  skipped (-SkipCI): this tag may land on a commit CI never passed"
} else {
    # gh is required, because "I think CI was green" is not a check.
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        Fail "gh is required to confirm CI, or pass -SkipCI to tag anyway"
    }
    $runs = gh run list --limit 20 --json headSha,status,conclusion,workflowName,url | ConvertFrom-Json
    $mine = @($runs | Where-Object { $_.headSha -eq $local })
    if (-not $mine) {
        Fail "no CI run found for $($local.Substring(0,7)); push and wait for it, or pass -SkipCI"
    }
    $pending = @($mine | Where-Object { $_.status -ne 'completed' })
    if ($pending) {
        Fail "$($pending.Count) CI run(s) still in progress for this commit; wait for them"
    }
    $failed = @($mine | Where-Object { $_.conclusion -ne 'success' -and $_.conclusion -ne 'skipped' })
    if ($failed) {
        $detail = ($failed | ForEach-Object { "    $($_.workflowName): $($_.conclusion)  $($_.url)" }) -join "`n"
        Fail "CI did not pass for this commit:`n$detail"
    }
    Write-Host "  $($mine.Count) run(s) green"
}

# --- 5. will the release be turnkey? ---------------------------------------
Step 5 "Cloudflare client for official builds"
$clientID = if ($env:PHAETHON_CLOUDFLARE_CLIENT_ID) { $env:PHAETHON_CLOUDFLARE_CLIENT_ID } else { "" }
if ($clientID) {
    Write-Host "  set locally ($($clientID.Substring(0, [Math]::Min(8, $clientID.Length)))...)"
} else {
    Write-Warning "  PHAETHON_CLOUDFLARE_CLIENT_ID is not set here."
    Write-Warning "  The workflow reads a repository *variable* of that name, not this shell."
    Write-Warning "  Without it the release ships with no client and every user must supply one,"
    Write-Warning "  which is correct for source builds and wrong for an official build."
}
Write-Host "  verify with: gh variable list"

# --- 6. tag ----------------------------------------------------------------
Step 6 "tagging $Version"
$notes = if ($Message) { $Message } else { "Phaethon $Version" }
if ($DryRun) {
    Write-Host "  -DryRun: would create an annotated tag '$Version' at $($local.Substring(0,7)) and push it"
    exit 0
}
git tag -a $Version -m $notes
if ($LASTEXITCODE -ne 0) { Fail "could not create the tag" }
Write-Host "  created annotated tag $Version"

# Only the tag, never the branch: the workflow triggers on tags, and pushing a
# branch here would be an unrelated action taken on the user's behalf.
git push origin $Version
if ($LASTEXITCODE -ne 0) {
    Write-Warning "the tag exists locally but the push failed; retry with: git push origin $Version"
    exit 1
}

Write-Host ""
Write-Host "Pushed $Version. The release workflow now gates, builds, packages and publishes."
Write-Host "Watch it with:  gh run watch"
Write-Host "If it fails, the tag can be removed before anyone downloads it:"
Write-Host "  git push --delete origin $Version; git tag -d $Version"
