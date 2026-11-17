# Public/Scan.ps1 -- scan a system, then fix what was found, one confirmation at a time.

function Invoke-AdmScan {
    <#
    .SYNOPSIS
      Check this machine, the credential store, and every registered domain. Changes nothing.
    .DESCRIPTION
      Safe to run at any time: no check writes anything. Each finding says what is wrong, what
      it will break, and -- where a fix exists -- exactly what that fix would do.

      A check that could not run reports 'unknown', never 'pass'. "I could not look" and "there
      is no problem" are different answers.
    .EXAMPLE
      Invoke-AdmScan
    .EXAMPLE
      Invoke-AdmScan -Domain corp -Problems
    #>
    [CmdletBinding()]
    param(
        [string]$Domain,
        [ValidateSet('all', 'machine', 'store', 'domain')][string]$Scope = 'all',
        [switch]$Problems   # only findings that need attention
    )

    $findings = New-Object System.Collections.ArrayList
    $baseCtx = [pscustomobject]@{ ModuleRoot = $script:AdmModuleRoot; Domain = $null }

    function Add-Finding {
        param($Check, $Result, $Ctx, [string]$TargetLabel)
        $remedy = $Check.Remedy
        [void]$findings.Add([pscustomobject]@{
            Id             = "ADM-$($Check.Id)"
            Name           = $Check.Name
            Scope          = $Check.Scope
            Target         = $TargetLabel
            Status         = $Result.Status
            Detail         = $Result.Detail
            Data           = $Result.Data
            Problem        = if ($Result.Status -in @('fail', 'warn')) { $Check.Problem } else { $null }
            Impact         = if ($Result.Status -in @('fail', 'warn')) { $Check.Impact } else { $null }
            CanFix         = [bool]($remedy -and $Result.Status -in @('fail', 'warn'))
            FixDescription = if ($remedy) { $remedy.Description } else { $null }
            Changes        = if ($remedy) { $remedy.Changes } else { $null }
            NeedsAdmin     = if ($remedy) { [bool]$remedy.NeedsAdmin } else { $false }
            Apply          = if ($remedy) { $remedy.Apply } else { $null }
            Context        = $Ctx
        })
    }

    # Each check is isolated: one that throws becomes an 'unknown' finding rather than ending
    # the scan. A scan that stops at the first broken check is worse than no scan, because the
    # findings it did not reach look like findings that passed.
    function Run-Check {
        param($Check, $Ctx, [string]$Label)
        try {
            $r = & $Check.Run $Ctx
            if (-not $r) { $r = New-AdmCheckResult -Status unknown -Detail 'the check returned nothing' }
        } catch {
            $r = New-AdmCheckResult -Status unknown -Detail "the check itself failed: $($_.Exception.Message)"
        }
        Add-Finding -Check $Check -Result $r -Ctx $Ctx -TargetLabel $Label
    }

    if ($Scope -in @('all', 'machine')) {
        foreach ($c in $script:AdmMachineChecks) { Run-Check -Check $c -Ctx $baseCtx -Label $env:COMPUTERNAME }
    }
    if ($Scope -in @('all', 'store')) {
        foreach ($c in $script:AdmStoreChecks) { Run-Check -Check $c -Ctx $baseCtx -Label 'credential store' }
    }
    if ($Scope -in @('all', 'domain')) {
        $domains = @()
        try { $domains = @(Get-AdmSession).Data.domains } catch {
            [void]$findings.Add([pscustomobject]@{
                Id = 'ADM-STORE-000'; Name = 'Domains could not be listed'; Scope = 'store'
                Target = 'credential store'; Status = 'unknown'
                Detail = 'the store is locked, so per-domain checks were skipped'
                Data = $null
                Problem = 'The credential store is locked, so the domains inside it could not be checked.'
                Impact = 'The machine and store checks above still ran. Unlock the store and scan again for the rest.'
                CanFix = $false; FixDescription = $null; Changes = $null; NeedsAdmin = $false
                Apply = $null; Context = $baseCtx
            })
        }
        if ($Domain) { $domains = @($domains | Where-Object { $_.Name -eq $Domain }) }
        foreach ($d in $domains) {
            $ctx = [pscustomobject]@{ ModuleRoot = $script:AdmModuleRoot; Domain = $d }
            foreach ($c in $script:AdmDomainChecks) { Run-Check -Check $c -Ctx $ctx -Label $d.Name }
        }
    }

    $out = @($findings)
    if ($Problems) { $out = @($out | Where-Object { $_.Status -in @('fail', 'warn', 'unknown') }) }

    $counts = @{
        pass = @($findings | Where-Object { $_.Status -eq 'pass' }).Count
        warn = @($findings | Where-Object { $_.Status -eq 'warn' }).Count
        fail = @($findings | Where-Object { $_.Status -eq 'fail' }).Count
        unknown = @($findings | Where-Object { $_.Status -eq 'unknown' }).Count
    }
    [void](Write-AdmLogEntry -Severity $(if ($counts.fail) { 'warn' } else { 'info' }) -Event 'scan' `
            -Operation 'system scan' -Target $env:COMPUTERNAME `
            -Message "Scan: $($counts.pass) pass, $($counts.warn) warn, $($counts.fail) fail, $($counts.unknown) unknown")

    $out
}

function Invoke-AdmRepair {
    <#
    .SYNOPSIS
      Apply the fix for a finding, after showing exactly what it will do.
    .DESCRIPTION
      Pipe findings from Invoke-AdmScan. Each fixable finding is presented as: the problem, what
      it breaks, and what the fix will change -- then it asks. Nothing is applied without a yes.

      -WhatIf shows every fix that would run and applies none of them.
      -Yes accepts all of them, for a caller that has already read the scan.

      Fixes marked as changing the MACHINE additionally require -AllowMachineChanges. Editing
      this toolkit's own settings and editing the computer's settings are different acts, and
      one blanket confirmation should not cover both.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Finding,
        [switch]$Yes,
        [switch]$AllowMachineChanges
    )
    begin { $results = New-Object System.Collections.ArrayList }
    process {
        foreach ($f in @($Finding)) {
            if (-not $f.CanFix) { continue }

            if ($f.Changes -eq 'machine' -and -not $AllowMachineChanges) {
                [void]$results.Add([pscustomobject]@{
                    Id = $f.Id; Name = $f.Name; Target = $f.Target; Outcome = 'skipped'
                    Detail = 'This fix changes settings on this computer. Re-run with -AllowMachineChanges to permit it.'
                })
                continue
            }
            if ($f.NeedsAdmin -and -not (Test-AdmIsElevated)) {
                [void]$results.Add([pscustomobject]@{
                    Id = $f.Id; Name = $f.Name; Target = $f.Target; Outcome = 'skipped'
                    Detail = 'This fix needs administrator rights. Run the toolkit elevated and try again.'
                })
                continue
            }

            # The confirmation text IS the specification of the change. Anyone reading it should
            # be able to decide without knowing what a cmdlet is.
            $prompt = @(
                "PROBLEM : $($f.Problem)"
                "IMPACT  : $($f.Impact)"
                "THE FIX : $($f.FixDescription)"
                "CHANGES : $(switch ($f.Changes) {
                    'machine' { 'settings on THIS COMPUTER' }
                    'store'   { 'this toolkit''s own settings only' }
                    'files'   { 'files inside the toolkit folder' }
                    default   { $f.Changes } })"
            ) -join "`n          "

            $go = $Yes -or $PSCmdlet.ShouldProcess("$($f.Target) -- $($f.Name)", $prompt)
            if (-not $go) {
                [void]$results.Add([pscustomobject]@{
                    Id = $f.Id; Name = $f.Name; Target = $f.Target; Outcome = 'declined'; Detail = 'not applied'
                })
                continue
            }
            # -WhatIf: ShouldProcess already returned false above, so reaching here means it runs.
            try {
                $detail = & $f.Apply $f.Context $f
                [void](Write-AdmLogEntry -Severity info -Event 'repair' -Operation "fix $($f.Id)" `
                        -Target $f.Target -Message "$($f.Name): $detail")
                [void]$results.Add([pscustomobject]@{
                    Id = $f.Id; Name = $f.Name; Target = $f.Target; Outcome = 'fixed'; Detail = $detail
                })
            } catch {
                $d = Resolve-AdmDiagnosis -ErrorObject $_ -Operation "fix $($f.Id)" -Target $f.Target
                [void](Write-AdmLogEntry -Severity error -Event 'repair' -Operation "fix $($f.Id)" `
                        -Target $f.Target -Message $_.Exception.Message -Diagnosis $d)
                [void]$results.Add([pscustomobject]@{
                    Id = $f.Id; Name = $f.Name; Target = $f.Target; Outcome = 'failed'; Detail = $d.Title
                })
            }
        }
    }
    end { $results }
}

function Test-AdmIsElevated {
    [OutputType([bool])]
    param()
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        (New-Object System.Security.Principal.WindowsPrincipal($id)).IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { $false }
}
