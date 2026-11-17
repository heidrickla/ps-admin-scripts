<#
.SYNOPSIS
  Run one of the toolkit's scripts against EVERY registered domain, and merge the results.

.DESCRIPTION
  Everything else here takes a single -Target. With many forests and no
  trusts between them, "check the domain" is a question that has to be asked once per forest
  and the answers stitched together by hand. This does that: one run, one table, one CSV, with a
  Domain column on every row.

  ⭐ IT ALSO FINDS THINGS NO SINGLE-DOMAIN RUN CAN. -CrossDomain does not merely concatenate
  per-domain reports; it collects the raw values from every domain and groups them GLOBALLY.
  Duplicate SPNs are the case that matters: a domain controller enforces SPN uniqueness within
  its OWN domain and cannot see any other, so a single-domain scan is structurally incapable of
  finding a collision that spans two of them -- and that is where the real ones are. The same
  applies to SID history, which exists precisely because objects moved between domains.

  ⛔ ONE FOREST FAILING MUST NOT STOP THE SWEEP. A domain that is unreachable, has no credential,
  or whose script throws is recorded as FAILED and the sweep continues. The summary at the end
  says exactly which domains produced the results, so a partial sweep can never be mistaken for
  a complete one -- and the exit code distinguishes the two.

  ⚠ A domain that failed is UNKNOWN, not clean. If you are sweeping for a problem and three
  forests would not answer, the correct reading is "found none in sixteen of twenty".

.EXAMPLE
  .\Invoke-AdmSweep.ps1 -Script Get-AdPrivilegedAccess
.EXAMPLE
  .\Invoke-AdmSweep.ps1 -Script Find-StaleComputers -Arguments @{ StaleDays = 180 } -ExportCsv .\stale-all.csv
.EXAMPLE
  .\Invoke-AdmSweep.ps1 -CrossDomain -ExportCsv .\collisions.csv
.EXAMPLE
  .\Invoke-AdmSweep.ps1 -Script Get-AdForestStatus -Domain corp,plant

.NOTES
  EXIT CODES
    0   every domain answered, nothing found
    10  every domain answered, and something was found
    20  at least one domain FAILED -- the result is partial, treat the rest as unknown
    30  every domain answered, nothing found, but at least one was read only IN PART -- so
        "nothing found" could not be established and this is NOT a clean estate

  ⛔ 30 EXISTS BECAUSE A COLLISION IS FOUND BY COMPARING TWO HOLDERS. If one domain's read is cut
  at the size limit, every pair with a leg in that domain is never compared, so the collision does
  not appear -- and this sweep's whole answer is the ABSENCE of collisions. ⭐ Cross-domain makes
  that worse rather than better: one cut domain out of twenty silently removes pairs whose OTHER
  leg was read perfectly. Exiting 0 there would assert a clean estate on the strength of a partial
  read of one member of it.
#>
[CmdletBinding(DefaultParameterSetName = 'Script')]
param(
    # A script name in scripts\ (with or without .ps1), or a path to one.
    [Parameter(Mandatory, ParameterSetName = 'Script')][string]$Script,
    # Extra parameters for that script, e.g. @{ StaleDays = 180 }. -Target is supplied per domain.
    [Parameter(ParameterSetName = 'Script')][hashtable]$Arguments = @{},

    [Parameter(Mandatory, ParameterSetName = 'CrossDomain')][switch]$CrossDomain,

    # Limit the sweep to these registered domain names. Default: all of them.
    [string[]]$Domain,
    [string]$ExportCsv,
    [int]$Limit = 5000,
    [string]$Tier
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# NOT -Force: a forced import makes a fresh module instance and re-locks the caller's store.
if (-not (Get-Module ADAdmin)) {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'ADAdmin\ADAdmin.psd1')
}

$scriptDir = $PSScriptRoot

$domains = @(Get-AdmDomain)
if ($Domain) { $domains = @($domains | Where-Object { $Domain -contains $_.Name }) }
if (-not $domains.Count) {
    throw 'No registered domains to sweep. Add one with: adm domain add -Name <n> -Dns <fqdn>'
}

$status = New-Object System.Collections.ArrayList
$rows   = New-Object System.Collections.ArrayList

function Add-Status {
    param([string]$DomainName, [string]$Outcome, [int]$Count = 0, [string]$Detail = '')
    [void]$status.Add([pscustomobject]@{ Domain = $DomainName; Outcome = $Outcome; Rows = $Count; Detail = $Detail })
}

# ------------------------------------------------------------------------------------------------
# Mode 1: run a script per domain
# ------------------------------------------------------------------------------------------------

if ($PSCmdlet.ParameterSetName -eq 'Script') {

    $path = if (Test-Path -LiteralPath $Script) { (Resolve-Path -LiteralPath $Script).Path }
            else {
                $n = if ($Script.EndsWith('.ps1')) { $Script } else { "$Script.ps1" }
                Join-Path $scriptDir $n
            }
    if (-not (Test-Path -LiteralPath $path)) {
        throw ("No script '$Script'. Available: " +
               ((Get-ChildItem -LiteralPath $scriptDir -Filter '*.ps1' | ForEach-Object { $_.BaseName }) -join ', '))
    }
    Write-Verbose "Sweeping $($domains.Count) domain(s) with $([System.IO.Path]::GetFileName($path))"

    foreach ($d in $domains) {

        $target = if ($d.DnsDomain) { $d.DnsDomain } else { $d.Name }
        Write-Verbose "-- $($d.Name) ($target)"

        try {
            $splat = @{ Target = $target }
            foreach ($k in $Arguments.Keys) { $splat[$k] = $Arguments[$k] }
            if ($Tier -and -not $splat.ContainsKey('Tier')) { $splat['Tier'] = $Tier }

            # ⛔ RESET FIRST. $LASTEXITCODE is sticky: a script that returns without calling `exit`
            # leaves the PREVIOUS script's code in place, so without this a healthy domain
            # inherits the last failure and vice versa.
            $global:LASTEXITCODE = 0

            # `&` on a .ps1 runs it in its own scope, so the child's `exit 10` ends the CHILD and
            # returns here. (Dot-sourcing it instead would take this sweep down with it on the
            # first domain that found something.) Errors are caught, not allowed to abort.
            $result = & $path @splat
            $childCode = $LASTEXITCODE

            # ⛔ CATCHING THE EXCEPTION IS NOT ENOUGH, and assuming it was is how this script
            # first reported two dead forests as clean. The house scripts DIAGNOSE their own
            # failures rather than throwing -- Get-AdPrivilegedAccess catches an unreachable DC,
            # records it as unchecked and exits 30 -- so nothing reaches this catch block and the
            # domain looked like a healthy one that simply found nothing. The exit code is the
            # only signal that survives: 0 = clean, 10 = found something, anything else = did not
            # complete. Measured against a registered domain pointed at an address with no DC.
            # ⚠ AND 30 IS ITS OWN BUCKET, not a hard failure. Every house script uses 30 for "ran,
            # but at least one thing could NOT be checked" -- a truncated read, an unreachable DC,
            # a section skipped. That is a DIFFERENT state from "did not complete", and it prompts
            # a different action: raise the limit or fix coverage, rather than fix connectivity.
            # Folding them together would make "twenty forests reported nothing" and "sixteen
            # reported nothing and three could not look" produce the same summary line, which is
            # the conflation this file exists to prevent -- one level up from where it started.
            # ⛔ AND IT DOES NOT `continue`. A domain that exited 30 RAN and printed findings; the
            # 30 is about coverage, not about the output. Skipping to the next domain here would
            # throw those findings away while the status line said "it reported what it saw" --
            # a label contradicting its own behaviour, and the more expensive half of the error,
            # since what it DID find is real. (The previous code folded 30 into FAILED and
            # dropped the rows, so this is the fix for both halves at once.)
            $partialDomain = ($childCode -eq 30)
            if ($partialDomain) {
                Write-Warning ("$($d.Name): script exited 30. It ran and reported what it saw, but part of this " +
                               'domain was NOT examined -- do not read a quiet result here as a clean one.')
            }
            if (-not $partialDomain -and $childCode -ne 0 -and $childCode -ne 10) {
                Add-Status $d.Name 'FAILED' 0 "the script exited $childCode -- it did not complete against this domain"
                Write-Warning "$($d.Name): script exited $childCode; this domain is UNKNOWN, not clean."
                continue
            }

            $n = 0
            foreach ($r in @($result)) {
                if ($null -eq $r) { continue }
                # Tag the origin. Some scripts already emit a Domain column; do not fight them,
                # and do not silently overwrite what they said.
                if ($r -is [psobject] -and -not $r.PSObject.Properties['Domain']) {
                    $r | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $d.Name -Force
                }
                [void]$rows.Add($r); $n++
            }
            if ($partialDomain) {
                Add-Status $d.Name 'PARTIAL' $n `
                    ("the script exited 30 -- it ran and returned $n row(s), but could not check " +
                     'everything against this domain, so a quiet result here is not a clean one')
            } else {
                Add-Status $d.Name 'ok' $n
            }
        }
        catch {
            # ⛔ Continue. Twenty forests means something is always down, and a sweep that stops
            # at the first failure never finishes once.
            Add-Status $d.Name 'FAILED' 0 $_.Exception.Message
            Write-Warning "$($d.Name): $($_.Exception.Message)"
        }
    }
}

# ------------------------------------------------------------------------------------------------
# Mode 2: cross-domain collisions -- the thing a per-domain run cannot see
# ------------------------------------------------------------------------------------------------

if ($PSCmdlet.ParameterSetName -eq 'CrossDomain') {

    $spnHolders = @{}   # spn (lowercased) -> list of "domain\account"
    $sidHolders = @{}   # sid string       -> list of "domain\account (kind)"

    foreach ($d in $domains) {
        $target = if ($d.DnsDomain) { $d.DnsDomain } else { $d.Name }
        Write-Verbose "-- collecting from $($d.Name) ($target)"
        try {
            $n = 0
            # ⛔ ONE RESET FOR BOTH READS, because either being cut has the same consequence and
            # the flag is sticky. A collision is found by COMPARING TWO HOLDERS, so a truncated
            # read in ONE domain means every pair with a leg in it is never compared -- and the
            # sweep reports no collision, which is the opposite of the truth on the check whose
            # whole purpose is to find one.
            #
            # ⭐ CROSS-DOMAIN MAKES THIS WORSE, NOT BETTER. A single-domain miss loses one
            # finding. Here, one cut domain out of twenty silently removes every pair that had
            # a leg in it -- including pairs whose other leg was read perfectly.
            Reset-AdmSearchTruncated

            foreach ($o in @(Get-AdmSearchResult -Target $target -Tier $Tier -Limit $Limit `
                        -Filter '(servicePrincipalName=*)' `
                        -Properties @('samaccountname', 'serviceprincipalname', 'distinguishedname'))) {
                $sam = [string](Get-AdmRawProp $o 'samaccountname')
                foreach ($spn in @(Get-AdmRawProp $o 'serviceprincipalname')) {
                    if (-not $spn) { continue }
                    # Case-insensitive: the KDC treats SPNs that way, so comparing case-sensitively
                    # misses exactly the collisions hardest to spot by eye.
                    $k = ([string]$spn).ToLowerInvariant()
                    if (-not $spnHolders.ContainsKey($k)) { $spnHolders[$k] = @() }
                    $spnHolders[$k] += "$($d.Name)\$sam"
                    $n++
                }
            }

            foreach ($o in @(Get-AdmSearchResult -Target $target -Tier $Tier -Limit $Limit `
                        -Filter '(sIDHistory=*)' `
                        -Properties @('samaccountname', 'sidhistory', 'objectsid'))) {
                $sam = [string](Get-AdmRawProp $o 'samaccountname')
                foreach ($h in @(Get-AdmRawProp $o 'sidhistory')) {
                    $s = ConvertTo-AdmSidString -Raw $h
                    if (-not $s) { continue }
                    if (-not $sidHolders.ContainsKey($s)) { $sidHolders[$s] = @() }
                    $sidHolders[$s] += "$($d.Name)\$sam"
                    $n++
                }
            }

            # ⚠ 'ok' IS A CLAIM ABOUT COVERAGE, not just about not throwing. A domain whose read
            # was cut contributed a PREFIX of its holders, so it is not ok -- and calling it ok
            # is what makes the missing collisions invisible.
            if (Get-AdmSearchTruncated) {
                Add-Status $d.Name 'PARTIAL' $n `
                    ("the read stopped at the size limit of $Limit, so this domain contributed only part of its " +
                     "holders -- any collision with a leg here may be missing from the results below")
                Write-Warning ("$($d.Name): PARTIAL -- read cut at $Limit. Collisions involving this domain " +
                               "may be absent from the results, and absence is what this sweep reports as clean.")
            } else {
                Add-Status $d.Name 'ok' $n
            }
        }
        catch {
            Add-Status $d.Name 'FAILED' 0 $_.Exception.Message
            Write-Warning "$($d.Name): $($_.Exception.Message)"
        }
    }

    foreach ($k in $spnHolders.Keys) {
        $holders = @($spnHolders[$k] | Select-Object -Unique)
        if ($holders.Count -lt 2) { continue }
        # Same domain twice is what Find-AdDuplicates already reports; this mode exists for the
        # case that one cannot see, so the two are labelled differently rather than merged.
        $doms = @($holders | ForEach-Object { ($_ -split '\\')[0] } | Select-Object -Unique)
        [void]$rows.Add([pscustomobject]@{
            Kind    = if ($doms.Count -gt 1) { 'SPN across domains' } else { 'SPN within one domain' }
            Value   = $k
            Domains = $doms -join ', '
            Holders = $holders -join ', '
            Why     = if ($doms.Count -gt 1) {
                          'A domain controller enforces SPN uniqueness only within its own domain, so neither of these domains could have refused this. Kerberos authentication to the service will fail intermittently or land on the wrong account depending on which domain a client resolves first.'
                      } else {
                          'Two accounts in the same domain hold this SPN. AD normally refuses this at write time, so it usually means it arrived by replication or a restore.'
                      }
        })
    }

    foreach ($k in $sidHolders.Keys) {
        $holders = @($sidHolders[$k] | Select-Object -Unique)
        if ($holders.Count -lt 2) { continue }
        $doms = @($holders | ForEach-Object { ($_ -split '\\')[0] } | Select-Object -Unique)
        [void]$rows.Add([pscustomobject]@{
            Kind    = 'SID history shared'
            Value   = $k
            Domains = $doms -join ', '
            Holders = $holders -join ', '
            Why     = 'More than one account carries the same historical SID. Both inherit whatever that SID was granted, so access intended for one person applies to all of them -- and nothing in either account''s permissions shows why.'
        })
    }
}

# ------------------------------------------------------------------------------------------------
# Output
# ------------------------------------------------------------------------------------------------

if ($ExportCsv) {
    $rows | Export-Csv -LiteralPath $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Verbose "Wrote $($rows.Count) row(s) to $ExportCsv"
}

$rows

$failed  = @($status | Where-Object { $_.Outcome -eq 'FAILED' })
$partial = @($status | Where-Object { $_.Outcome -eq 'PARTIAL' })
# ⚠ 'ok' ONLY. A PARTIAL domain answered but did not answer FULLY, so counting it in "swept N of
# M" would restore exactly the false completeness the PARTIAL status exists to prevent.
$ok      = @($status | Where-Object { $_.Outcome -eq 'ok' })

Write-Verbose "Swept $($ok.Count) of $($domains.Count) domain(s); $($rows.Count) row(s)."
$status | Format-Table Domain, Outcome, Rows, Detail -AutoSize | Out-String -Width 200 | Write-Verbose

if ($failed.Count) {
    Write-Warning ("PARTIAL SWEEP. $($failed.Count) of $($domains.Count) domain(s) did not answer: " +
                   "$(($failed | ForEach-Object { $_.Domain }) -join ', '). Those domains are UNKNOWN, " +
                   'not clean -- whatever you are looking for may be in one of them.')
    exit 20
}
if ($rows.Count) { exit 10 }
# ⛔ A PARTIAL DOMAIN MUST NOT EXIT 0. Zero here means "every domain answered, nothing found" --
# a positive claim of a clean estate. A domain whose read was cut contributed a prefix of its
# holders, so every collision with a leg in it went uncompared and is absent rather than absent-
# because-it-does-not-exist. ⚠ Findings still win: 10 means act on this, and 30 would cast doubt
# on collisions that were genuinely found. Same precedence as Find-AdDuplicates.
if ($partial.Count) {
    Write-Warning ("INCOMPLETE SWEEP. $($partial.Count) of $($domains.Count) domain(s) were read only in part: " +
                   "$(($partial | ForEach-Object { $_.Domain }) -join ', '). A collision is found by comparing " +
                   'two holders, so any pair with a leg in those domains was never compared. Nothing found is ' +
                   'NOT the same as nothing there. Re-run with a higher -Limit before recording this estate as clean.')
    exit 30
}
exit 0
