# Public/ScriptImport.ps1 -- bring existing scripts in, and run them with the toolkit's plumbing.
#
# An import produces THREE files and never touches the original:
#   <Name>.body.ps1  the converted script, its own param block intact
#   <Name>.ps1       a generated wrapper: -Target, the guard, the log, -WhatIf
#   <Name>.json      what it came from, its hash at import time, and every finding
#
# ⛔ WHY A WRAPPER AND NOT A REWRITE. Splicing a house param block into someone's script means
# merging two param blocks, and PowerShell allows exactly one, at the top. Every tool that tries
# this eventually mangles a working script. Keeping the body whole means the import is reviewable
# as a diff against its source, and reversible by deleting three files.

function Get-AdmScriptRoot {
    [OutputType([string])]
    param()
    if ($env:ADADMIN_SCRIPT_DIR) { return $env:ADADMIN_SCRIPT_DIR }
    # Beside the store, so a USB stick carries its imported scripts with its credentials, and a
    # read-only module tree still works.
    try {
        $store = if ($script:AdmSession) { $script:AdmSession.Path } else { Get-AdmDefaultStorePath }
        return (Join-Path ([System.IO.Path]::GetDirectoryName($store)) 'adadmin-scripts')
    } catch { }
    Join-Path $env:LOCALAPPDATA 'ADAdmin\scripts'
}

function Get-AdmFileHash256 {
    param([Parameter(Mandatory)][string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try { ([BitConverter]::ToString($sha.ComputeHash($fs)) -replace '-', '').ToLowerInvariant() }
        finally { $fs.Dispose() }
    } finally { $sha.Dispose() }
}

function Test-AdmScript {
    <#
    .SYNOPSIS
      Check a script against the house rules. Reads it; changes nothing.
    .DESCRIPTION
      Findings use the same shape as `adm scan`: what is wrong, what it will break, what to do.
      AutoFix marks the ones the importer can apply mechanically and safely.
    .EXAMPLE
      Test-AdmScript -Path .\Unlock-StaleUsers.ps1
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][string]$Path)
    process {
        Invoke-AdmGuarded -Operation "check script '$([System.IO.Path]::GetFileName($Path))'" -Target $Path -Action {
            Get-AdmScriptFinding -Path $Path
        }
    }
}

function Import-AdmScript {
    <#
    .SYNOPSIS
      Convert a script to the house style and install it into the toolkit.
    .DESCRIPTION
      Applies only the mechanical fixes; everything else is reported for a human. The original
      file is never modified.

      The installed script gains, without any edit to its own logic:
        -Target      the domain is resolved for it, and $AdmTarget/$AdmDomain are set
        the guard    a failure is diagnosed, written to the 7-day log, and raised in plain English
        -WhatIf      at the outer level
        an audit     start and finish are recorded

    .EXAMPLE
      Import-AdmScript -Path .\Unlock-StaleUsers.ps1
    .EXAMPLE
      Import-AdmScript -Path .\x.ps1 -Name stale-users -Force
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Name,
        [switch]$Force,
        # Report and install nothing. Same as Test-AdmScript, kept here so one command covers
        # "show me what would happen" without switching cmdlets.
        [switch]$AnalyzeOnly
    )

    if (-not (Test-Path -LiteralPath $Path)) { throw "No script at '$Path'." }
    $src = (Resolve-Path -LiteralPath $Path).Path
    if (-not $Name) { $Name = [System.IO.Path]::GetFileNameWithoutExtension($src) }
    if ($Name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
        throw "'$Name' is not a usable script name. Use letters, digits, dot, dash or underscore."
    }

    $findings = @(Get-AdmScriptFinding -Path $src)
    $blocking = @($findings | Where-Object { $_.Id -eq 'ADM-IMP-000' })
    if ($blocking.Count) {
        # It does not parse. Refuse rather than install something that cannot run.
        return [pscustomobject]@{
            Name = $Name; Source = $src; Installed = $false
            Findings = $findings; Applied = @()
            Detail = 'The script does not parse, so nothing was installed.'
        }
    }

    $text = [System.IO.File]::ReadAllText($src)
    $conv = ConvertTo-AdmHouseText -Text $text -Findings $findings

    if ($AnalyzeOnly) {
        return [pscustomobject]@{
            Name = $Name; Source = $src; Installed = $false
            Findings = $findings; Applied = @($conv.Applied)
            Detail = 'Analysis only -- nothing was written.'
        }
    }

    $root = Get-AdmScriptRoot
    $bodyPath = Join-Path $root "$Name.body.ps1"
    $wrapPath = Join-Path $root "$Name.ps1"
    $metaPath = Join-Path $root "$Name.json"

    if ((Test-Path -LiteralPath $wrapPath) -and -not $Force) {
        throw "A script named '$Name' is already imported. Use -Force to replace it."
    }
    if (-not $PSCmdlet.ShouldProcess($wrapPath, "Install imported script '$Name'")) { return }

    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $hash = Get-AdmFileHash256 -Path $src
    $errCount = @($findings | Where-Object { $_.Severity -eq 'error' }).Count
    $warnCount = @($findings | Where-Object { $_.Severity -eq 'warn' }).Count

    $bodyHeader = @(
        "# ==== IMPORTED BY ADAdmin -- DO NOT EDIT THIS COPY ===="
        "# Source : $src"
        "# When   : $stamp"
        "# Hash   : $hash   (of the source at import time)"
        "# Fixes  : $(@($conv.Applied).Count) applied automatically"
        "# Left   : $errCount error(s), $warnCount warning(s) for a human -- see: adm script check -Name $Name"
        "#"
        "# Edit the SOURCE and import again. Editing this file makes the two diverge silently,"
        "# and the hash above is what tells anyone they have."
        "# ======================================================"
        ""
    ) -join "`r`n"
    Write-AdmFileAtomic -Path $bodyPath -Content ($bodyHeader + $conv.Text)

    Write-AdmFileAtomic -Path $wrapPath -Content (New-AdmScriptWrapper -Name $Name -Source $src -Stamp $stamp)

    $meta = [pscustomobject]@{
        name = $Name; source = $src; imported = $stamp; sourceHash = $hash
        applied = @($conv.Applied); findings = @($findings | Select-Object Id, Name, Severity, Line, Detail, Problem, Impact, Fix, AutoFix)
        errors = $errCount; warnings = $warnCount
    }
    Write-AdmFileAtomic -Path $metaPath -Content ($meta | ConvertTo-Json -Depth 8)

    [void](Write-AdmLogEntry -Severity info -Event 'import' -Operation 'import script' -Target $src `
            -Message "Imported '$Name': $(@($conv.Applied).Count) fixes applied, $errCount error(s) and $warnCount warning(s) left for review")

    [pscustomobject]@{
        Name = $Name; Source = $src; Installed = $true
        Path = $wrapPath; BodyPath = $bodyPath; MetaPath = $metaPath
        Findings = $findings; Applied = @($conv.Applied)
        Detail = "Installed. Run it with: adm script run -Name $Name -Target <domain>"
    }
}

function New-AdmScriptWrapper {
    param([string]$Name, [string]$Source, [string]$Stamp)
    # A here-string with SINGLE quotes: the wrapper is full of $variables that must survive into
    # the generated file rather than being expanded now.
    $t = @'
<#
.SYNOPSIS
  ADAdmin wrapper for the imported script "@NAME@".
.DESCRIPTION
  GENERATED on @STAMP@ from @SOURCE@ -- do not edit; import again instead.

  The imported logic lives in @NAME@.body.ps1 and is unchanged apart from the mechanical fixes
  recorded in @NAME@.json. This wrapper is what gives it the toolkit's plumbing.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # Which domain this run is aimed at. Resolved through the credential store, so the script
    # never picks a credential itself.
    [string]$Target,
    [string]$Tier,
    [Parameter(ValueFromRemainingArguments = $true)]$ScriptArgs
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$AdmScriptName = '@NAME@'
$AdmBody = Join-Path $PSScriptRoot '@NAME@.body.ps1'
if (-not (Test-Path -LiteralPath $AdmBody)) { throw "The imported body '@NAME@.body.ps1' is missing next to this wrapper." }

# Anything the body needs is set here, so the imported logic can use $AdmDomain / $AdmCredential
# instead of hard-coding a domain -- which is finding ADM-IMP-007.
$AdmDomain = $null; $AdmCredential = $null; $AdmTarget = $Target
if ($Target) {
    $ctx = Get-AdmTargetContextPublic -Target $Target -Tier $Tier
    $AdmDomain = $ctx.Domain
    $AdmCredential = $ctx.Credential
}

Write-AdmLog -Severity info -Message "Running imported script '$AdmScriptName'" -Operation $AdmScriptName -Target $Target | Out-Null

if (-not $PSCmdlet.ShouldProcess($(if ($Target) { $Target } else { 'this machine' }), "Run imported script '$AdmScriptName'")) { return }

# The guard is the point of the wrapper: whatever the body throws is diagnosed in plain English,
# written to the 7-day log, and re-raised with the explanation attached.
Invoke-AdmGuardedPublic -Operation "imported script '$AdmScriptName'" -Target $Target -Action {
    & $AdmBody @ScriptArgs
}

Write-AdmLog -Severity info -Message "Finished imported script '$AdmScriptName'" -Operation $AdmScriptName -Target $Target | Out-Null
'@
    $t.Replace('@NAME@', $Name).Replace('@SOURCE@', $Source).Replace('@STAMP@', $Stamp)
}

function Get-AdmScript {
    <#
    .SYNOPSIS
      List imported scripts, and say whether their source has changed since import.
    #>
    [CmdletBinding()]
    param([string]$Name)
    $root = Get-AdmScriptRoot
    if (-not (Test-Path -LiteralPath $root)) { return }
    foreach ($m in (Get-ChildItem -LiteralPath $root -Filter '*.json' -EA SilentlyContinue | Sort-Object Name)) {
        $meta = $null
        try { $meta = [System.IO.File]::ReadAllText($m.FullName) | ConvertFrom-Json } catch { continue }
        if ($Name -and $meta.name -ne $Name) { continue }
        # Drift is worth surfacing: an imported copy silently older than its source is the same
        # class of problem as a stale mirror.
        $drift = 'unknown'
        if ($meta.source -and (Test-Path -LiteralPath $meta.source)) {
            $drift = if ((Get-AdmFileHash256 -Path $meta.source) -eq $meta.sourceHash) { 'current' } else { 'SOURCE CHANGED' }
        } elseif ($meta.source) { $drift = 'source missing' }
        [pscustomobject]@{
            Name = $meta.name; Source = $meta.source; Imported = $meta.imported
            Errors = $meta.errors; Warnings = $meta.warnings
            AutoFixed = @($meta.applied).Count; SourceState = $drift
            Path = Join-Path $root "$($meta.name).ps1"
        }
    }
}

function Invoke-AdmScript {
    <#
    .SYNOPSIS
      Run an imported script through the toolkit's plumbing.
    .EXAMPLE
      Invoke-AdmScript -Name stale-users -Target corp.example.com
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Target,
        [string]$Tier,
        [object[]]$ScriptArgs = @()
    )
    $root = Get-AdmScriptRoot
    $path = Join-Path $root "$Name.ps1"
    if (-not (Test-Path -LiteralPath $path)) {
        throw "No imported script named '$Name'. Installed: $((@(Get-AdmScript | ForEach-Object { $_.Name })) -join ', ')"
    }
    if (-not $PSCmdlet.ShouldProcess($Name, 'Run imported script')) { return }
    & $path -Target $Target -Tier $Tier @ScriptArgs
}

function Remove-AdmScript {
    <#
    .SYNOPSIS
      Uninstall an imported script. The original source file is untouched.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([Parameter(Mandatory)][string]$Name)
    $root = Get-AdmScriptRoot
    $files = @("$Name.ps1", "$Name.body.ps1", "$Name.json" | ForEach-Object { Join-Path $root $_ } |
               Where-Object { Test-Path -LiteralPath $_ })
    if (-not $files.Count) { throw "No imported script named '$Name'." }
    if (-not $PSCmdlet.ShouldProcess($Name, 'Remove imported script (the original source is not touched)')) { return }
    foreach ($f in $files) { Remove-Item -LiteralPath $f -Force }
    [pscustomobject]@{ Removed = $Name; Files = $files.Count }
}

# The wrapper runs in its own scope and needs these two, so they are exported under public names.
function Get-AdmTargetContextPublic {
    <#
    .SYNOPSIS
      Resolve a target to its domain and credential, for scripts written against this module.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Target, [string]$Tier)
    Get-AdmTargetContext -Target $Target -Tier $Tier
}

function Invoke-AdmGuardedPublic {
    <#
    .SYNOPSIS
      Run a scriptblock with the toolkit's diagnosis, logging and plain-English failure handling.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][scriptblock]$Action, [Parameter(Mandatory)][string]$Operation, [string]$Target)
    Invoke-AdmGuarded -Action $Action -Operation $Operation -Target $Target
}
