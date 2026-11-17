<#
.SYNOPSIS
  Interactive ADAdmin session -- unlock once, then work.

.DESCRIPTION
  Deliberately NOT a bespoke mini-REPL. It imports the module, unlocks the store, and hands you
  a real PowerShell prompt: tab completion, pipelines, Get-Help and every cmdlet you already
  know, with the store open for the life of the session. A hand-written command loop would take
  all of that away in exchange for a slightly shorter prompt.
#>
[CmdletBinding()]
param([string]$ModuleRoot)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Resolved here, not as a param default: $PSScriptRoot is empty during param binding under
# Windows PowerShell 5.1 with -File. See gui\Start-AdmGui.ps1 for the failure it produces.
if (-not $ModuleRoot) { $ModuleRoot = Split-Path -Parent $PSScriptRoot }

Import-Module (Join-Path $ModuleRoot 'ADAdmin\ADAdmin.psd1') -Force

$info = Get-AdmStoreInfo
if (-not $info.Exists) {
    Write-Host "No store at $($info.Path)." -ForegroundColor Yellow
    Write-Host "Create one with:  adm store init -Name <your-name>" -ForegroundColor Yellow
    return
}

if (-not $info.Unlocked) {
    $p = if ($env:ADADMIN_PASSPHRASE) { ConvertTo-SecureString $env:ADADMIN_PASSPHRASE -AsPlainText -Force }
         else { Read-Host -Prompt 'Store passphrase' -AsSecureString }
    $r = Unlock-AdmStore -Passphrase $p
    Write-Host "Unlocked as $($r.UnlockedAs) -- $($r.Domains) domain(s), auto-lock $($r.AutoLockMinutes)m." -ForegroundColor Green
}

$i = Get-AdmStoreInfo
Write-Host ''
Write-Host '  ADAdmin session' -ForegroundColor Cyan
Write-Host "  store    $($i.Path)"
Write-Host "  admin    $($i.UnlockedAs)"
Write-Host "  provider $($i.Provider)$(if ($i.Provider -eq 'mock') { '   <- fixture data, not a real directory' })" -ForegroundColor $(if ($i.Provider -eq 'mock') { 'Yellow' } else { 'Gray' })
Write-Host "  domains  $($i.Domains)"
Write-Host ''
Write-Host '  Resolve-AdmDomain -Target <host>      which domain owns this target'
Write-Host '  Get-AdmUser -Target <t> -Identity <s> find users'
Write-Host '  Get-AdmDomain                         list registered domains'
Write-Host '  Lock-AdmStore                         forget the key'
Write-Host '  exit                                  leave the session'
Write-Host ''

try {
    $host.EnterNestedPrompt()
} catch {
    # EnterNestedPrompt needs a real console host. Say so rather than looking broken.
    Write-Host 'This host does not support a nested prompt. The module is imported and the store is unlocked in this session -- carry on here.' -ForegroundColor Yellow
} finally {
    Lock-AdmStore | Out-Null
    Write-Host 'Store locked.' -ForegroundColor DarkGray
}
