<#
.SYNOPSIS
  Run every ADAdmin suite and report one verdict.

.DESCRIPTION
  Plain scripts, not Pester: the toolkit has to be verifiable on a target PC where nothing is
  installed, and requiring a module the box may not have would defeat the point. Each suite
  prints PASS/FAIL per check and exits non-zero on any failure.

  ⛔ EVERY SUITE HERE IS OFFLINE, AND THAT IS DELIBERATE. This has to work on a target PC with no
  directory in reach; a suite needing a domain controller would turn "the toolkit is broken" and
  "you are not on the network" into the same red line. The handful of claims that genuinely
  cannot be made without a live directory -- chiefly that a real DirectorySearcher returns
  SizeLimit+1 rows when more exist -- live in `tests\live\Invoke-AdmLiveTests.ps1`, which is run
  by hand against a real forest and is NOT in the list below.

  ⚠ RUN THIS UNDER WINDOWS POWERSHELL 5.1, not only PowerShell 7. Two real bugs found on
  2026-08-26 -- `Split-Path -LiteralPath -Parent` (invalid parameter-set combination) and member
  enumeration over an empty property collection -- are accepted by 7 and fail on 5.1. Testing
  only on 7 tests a laxer world than the one this ships into.
#>
[CmdletBinding()]
param(
    # 'both' needs pwsh on PATH; it is skipped with a notice if absent.
    [ValidateSet('current', 'both')][string]$On = 'current'
)

$ErrorActionPreference = 'Continue'
# ENUMERATED, not hand-listed. A written-out list means a new suite is silently not run, and a
# check that never runs is worth less than no check -- it reads as coverage. GuiAccessibility was
# added 2026-08-28 and was the first suite the old list missed. tests\live\ is a separate tree and
# stays out by construction: it needs a directory, so it must never make "not on the network" look
# like "broken". Order is alphabetical rather than curated -- no suite may depend on another.
$suites = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.Tests.ps1' |
            Sort-Object Name | ForEach-Object { $_.Name -replace '\.Tests\.ps1$', '' })

# A control that cannot legitimately be empty: an enumeration can succeed at finding nothing and
# then report that everything passed.
if ($suites.Count -lt 10) {
    Write-Host "suite discovery found only $($suites.Count) suites in $PSScriptRoot -- that is the discovery breaking, not the tests passing." -ForegroundColor Red
    exit 2
}
$failed = @()

function Invoke-Suite {
    param([string]$Name, [string]$Exe, [string]$Label)
    $path = Join-Path $PSScriptRoot "$Name.Tests.ps1"
    Write-Host ""
    Write-Host "--- $Name  [$Label] " -NoNewline -ForegroundColor Cyan
    Write-Host ('-' * [Math]::Max(1, 50 - $Name.Length - $Label.Length)) -ForegroundColor DarkGray
    & $Exe -NoProfile -ExecutionPolicy Bypass -File $path
    if ($LASTEXITCODE -ne 0) { $script:failed += "$Name [$Label]" }
}

$ps51 = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
foreach ($s in $suites) { Invoke-Suite -Name $s -Exe $ps51 -Label '5.1' }

if ($On -eq 'both') {
    $pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue)
    if ($pwsh) { foreach ($s in $suites) { Invoke-Suite -Name $s -Exe $pwsh.Source -Label '7' } }
    else { Write-Host "`npwsh not found -- skipped the PowerShell 7 pass." -ForegroundColor Yellow }
}

Write-Host ""
if ($failed.Count) {
    Write-Host "FAILED: $($failed -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host "all suites passed" -ForegroundColor Green
exit 0
