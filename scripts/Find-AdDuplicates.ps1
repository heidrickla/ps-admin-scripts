<#
.SYNOPSIS
  Find duplicate SPNs and duplicate SID history in a domain, and optionally repair the SPNs.

.DESCRIPTION
  Two classes of duplicate that break authentication, both read over plain LDAP -- no RSAT, no
  setspn.exe, and it works from outside the forest.

  DUPLICATE SPNs are the serious one and the one worth fixing. When two accounts claim the same
  service principal name, Kerberos refuses to issue a ticket for it at all -- so the service
  fails with "the target principal name is incorrect", or works intermittently depending on which
  DC answered, and nothing in the application logs points at the directory.

  ⚠ HOW THEY ACTUALLY ARISE, measured 2026-08-27. A modern domain controller ENFORCES SPN
  uniqueness at write time: an attempt to add an SPN that another object in the SAME DOMAIN
  already holds is rejected outright with "A constraint violation occurred". So within one
  healthy domain you largely cannot create this by hand -- which is why a scan of a healthy
  domain finding nothing is the expected result, not evidence the scan is broken.

  The duplicates that do exist come from the paths the constraint does not cover:
    * ACROSS DOMAINS in one forest. The uniqueness check is per-domain, so the same SPN on
      accounts in two different domains is never refused -- and Kerberos still breaks. This is
      the common real-world case, and finding it means running this against EACH domain and
      comparing, because one run only sees one domain.
    * Replication collisions, where two DCs accept the same SPN before they converge.
    * Objects predating the constraint, or restored from backup / reanimated from a tombstone.
    * Domains where the uniqueness check has been deliberately relaxed.

  DUPLICATE SID HISTORY is a migration artefact. sIDHistory lets a migrated account keep access
  granted to its old SID; if two accounts carry the same historical SID, or one account's
  sIDHistory contains another LIVE account's SID, both get access intended for one.

  ⚠ WHAT THIS DOES NOT CHECK, AND WHY. objectSid cannot genuinely duplicate WITHIN a domain --
  the RID master hands out each RID once, so a scan for duplicate objectSid inside one domain
  finds nothing by construction and would be theatre. The duplicate-SID problem people usually
  mean is a LOCAL MACHINE SID shared by machines cloned without sysprep, and that is not visible
  from the directory at all: every one of those machines still has its own unique computer
  object. Detecting it means asking each machine for its own SID, which is a different tool.

  Reporting changes nothing. -RepairSpn removes a duplicate SPN from ONE account, asking about
  each, and it will not guess which account is the right one.

.EXAMPLE
  .\Find-AdDuplicates.ps1 -Target corp.example.com
.EXAMPLE
  .\Find-AdDuplicates.ps1 -Target corp.example.com -ExportCsv .\duplicates.csv
.EXAMPLE
  .\Find-AdDuplicates.ps1 -Target corp.example.com -RepairSpn -RemoveFrom OLD-SERVER$ -WhatIf

.NOTES
  EXIT CODES
    0   no duplicates found
    10  duplicates found (report mode) -- for scripting a "did it find anything" gate
    20  a repair failed
    30  a read was truncated, so "no duplicates" could not be established -- NOT clean

  ⛔ 30 EXISTS BECAUSE A DUPLICATE IS FOUND BY COMPARING TWO OBJECTS. If one of a pair sits past
  the size limit the pair is never compared, so the finding never appears -- and this script's
  whole answer is the ABSENCE of findings. A truncated run does not report fewer duplicates, it
  reports NONE, and exiting 0 would tell every caller reading that code that the domain is clean.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Target,
    [switch]$SkipSpn,
    [switch]$SkipSidHistory,

    # Repair mode. Removes the duplicated SPN from the named account only -- never from both, and
    # never chosen automatically.
    [switch]$RepairSpn,
    [string]$RemoveFrom,

    [string]$ExportCsv,
    [int]$Limit = 20000,
    [string]$Tier
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# NOT -Force: a forced import makes a fresh module instance and re-locks the caller's store.
if (-not (Get-Module ADAdmin)) {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'ADAdmin\ADAdmin.psd1')
}

# ⚠ WAS `if ($Raw -is [byte[]])`, WHICH IS FALSE FOR EVERY REAL SEARCH RESULT. A directory hands
# binary attributes back as Object[] of Byte, so that test never fired and this fell through to
# [string]$Raw -- printing "1 4 0 0 0 0 0 5 21 ..." where a SID belonged. Grouping still found
# genuine duplicates (identical bytes give identical soup), so it failed silently and the lab run
# that reported 0 duplicates could not reveal it. The module owns this conversion now.
function ConvertTo-SidString {
    param($Raw)
    ConvertTo-AdmSidString -Raw $Raw
}

$findings = @()
# ⚠ A CAVEAT RECORDED RATHER THAN CODED. `servicePrincipalName` is read plainly below, not through
# Get-AdmRangedProp -- so an account with more than ~1500 SPNs would read as having NONE and its
# duplicates would vanish. The asymmetry mildly favours covering it, since absence is exactly what
# this script reports as clean. It is left alone on purpose: 1500 SPNs on one account is not a
# thing that happens, and a guard that can never fire is precisely what was found sitting in
# Get-AdPrivilegedAccess doing active harm by looking like protection. If you ever meet an account
# that large, this comment is the thing to come back to.
#
# Sticky across all three reads: any one of them being cut is enough to make "no duplicates"
# unprovable, and which one it was does not change the answer.
$readTruncated = $false
Reset-AdmSearchTruncated

# --- duplicate SPNs -------------------------------------------------------------------------------

if (-not $SkipSpn) {
    $objs = @(Get-AdmSearchResult -Target $Target -Tier $Tier -Limit $Limit `
                -Filter '(servicePrincipalName=*)' `
                -Properties @('samaccountname', 'distinguishedname', 'serviceprincipalname', 'objectcategory'))

    # SPN -> the accounts claiming it. Case-INSENSITIVE, because Kerberos treats SPNs that way and
    # a case-only difference is still a duplicate to the KDC -- comparing case-sensitively would
    # miss exactly the duplicates that are hardest to spot by eye.
    $bySpn = @{}
    foreach ($o in $objs) {
        $sam = [string](Get-AdmRawProp $o 'samaccountname')
        $dn  = [string](Get-AdmRawProp $o 'distinguishedname')
        foreach ($spn in @(Get-AdmRawProp $o 'serviceprincipalname' @())) {
            if (-not $spn) { continue }
            $k = ([string]$spn).ToLowerInvariant()
            if (-not $bySpn.ContainsKey($k)) { $bySpn[$k] = @() }
            $bySpn[$k] += [pscustomobject]@{ Spn = [string]$spn; Sam = $sam; Dn = $dn }
        }
    }

    foreach ($k in $bySpn.Keys) {
        $holders = @($bySpn[$k])
        if ($holders.Count -lt 2) { continue }
        $findings += [pscustomobject]@{
            Kind    = 'DuplicateSPN'
            Value   = $holders[0].Spn
            Holders = ($holders | ForEach-Object { $_.Sam }) -join ' | '
            Count   = $holders.Count
            Detail  = ($holders | ForEach-Object { $_.Dn }) -join ' | '
            Impact  = 'Kerberos will not issue a ticket for this SPN while it is claimed twice, so the service fails to authenticate.'
            Repairable = $true
        }
    }
}

# --- duplicate SID history -------------------------------------------------------------------------

if (-not $SkipSidHistory) {
    $withHistory = @(Get-AdmSearchResult -Target $Target -Tier $Tier -Limit $Limit `
                        -Filter '(sIDHistory=*)' `
                        -Properties @('samaccountname', 'distinguishedname', 'sidhistory', 'objectsid'))

    $byHistSid = @{}
    foreach ($o in $withHistory) {
        $sam = [string](Get-AdmRawProp $o 'samaccountname')
        foreach ($h in @(Get-AdmRawProp $o 'sidhistory' @())) {
            $s = ConvertTo-SidString $h
            if (-not $s) { continue }
            if (-not $byHistSid.ContainsKey($s)) { $byHistSid[$s] = @() }
            $byHistSid[$s] += $sam
        }
    }

    foreach ($s in $byHistSid.Keys) {
        $accts = @($byHistSid[$s] | Select-Object -Unique)
        if ($accts.Count -lt 2) { continue }
        $findings += [pscustomobject]@{
            Kind    = 'DuplicateSIDHistory'
            Value   = $s
            Holders = $accts -join ' | '
            Count   = $accts.Count
            Detail  = 'the same historical SID appears on more than one account'
            Impact  = 'Every one of these accounts inherits the access originally granted to that single old account.'
            Repairable = $false
        }
    }

    # An account carrying a LIVE account's SID in its history. Rarer, and worse: the holder gets
    # everything the live account has, invisibly, because nothing shows it in a group membership.
    if ($byHistSid.Keys.Count) {
        $live = @{}
        foreach ($o in @(Get-AdmSearchResult -Target $Target -Tier $Tier -Limit $Limit `
                            -Filter '(|(objectCategory=person)(objectCategory=computer)(objectCategory=group))' `
                            -Properties @('samaccountname', 'objectsid'))) {
            $s = ConvertTo-SidString (Get-AdmRawProp $o 'objectsid')
            if ($s) { $live[$s] = [string](Get-AdmRawProp $o 'samaccountname') }
        }
        foreach ($s in $byHistSid.Keys) {
            if (-not $live.ContainsKey($s)) { continue }
            $findings += [pscustomobject]@{
                Kind    = 'SIDHistoryCollidesWithLiveAccount'
                Value   = $s
                Holders = (@($byHistSid[$s] | Select-Object -Unique) -join ' | ') + "  -> live account: $($live[$s])"
                Count   = @($byHistSid[$s] | Select-Object -Unique).Count + 1
                Detail  = "this SID is the CURRENT objectSid of '$($live[$s])' and also sits in another account's sIDHistory"
                Impact  = "Those accounts silently hold everything '$($live[$s])' can access, and no group membership shows it."
                Repairable = $false
            }
        }
    }
}

# --- output ------------------------------------------------------------------------------------------

$readTruncated = [bool](Get-AdmSearchTruncated)

if ($ExportCsv) { $findings | Export-Csv -LiteralPath $ExportCsv -NoTypeInformation -Encoding UTF8 }

if (-not $RepairSpn) {
    $findings
    if ($readTruncated) {
        Write-Warning ("INCOMPLETE: at least one read stopped at the size limit of $Limit. A duplicate " +
                       "is found by comparing two objects, so if either sits past that limit the pair " +
                       "was never compared and the finding is simply absent -- which is indistinguishable " +
                       "from there being none. Whatever is listed above is real; the SILENCE is not. " +
                       "Re-run with a higher -Limit before recording this domain as clean.")
    }
    if (@($findings | Where-Object { $_.Kind -ne 'DuplicateSPN' }).Count) {
        Write-Warning ('SID-history findings are reported only. Removing a value from sIDHistory ' +
                       'revokes whatever access it was carrying, which may be exactly what someone ' +
                       'still relies on -- that is a migration decision, not a repair a script should make.')
    }
    # ⚠ FINDINGS BEAT TRUNCATION IN THE EXIT CODE. 10 already means "act on this"; a caller that
    # gets 30 instead would be told the run was inconclusive and might treat the real duplicates
    # above as unconfirmed. Truncation only decides the code when the alternative would have been
    # a CLEAN 0, which is the only claim it can falsify.
    if (@($findings).Count) { exit 10 }
    if ($readTruncated) { exit 30 }
    exit 0
}

# --- repair (SPNs only) -------------------------------------------------------------------------------

$dupSpns = @($findings | Where-Object { $_.Kind -eq 'DuplicateSPN' })
if (-not $dupSpns.Count) { Write-Verbose 'No duplicate SPNs to repair.'; exit 0 }

if (-not $RemoveFrom) {
    Write-Error ('-RepairSpn needs -RemoveFrom naming the account to take the SPN OFF. This script ' +
                 'will not choose: the SPN belongs on whichever account actually runs the service, ' +
                 'and getting that backwards breaks the working half instead of fixing the broken one. ' +
                 'Run without -RepairSpn first and look at the holders.')
    exit 10
}

$failed = 0
$results = foreach ($d in $dupSpns) {
    $holders = $d.Holders -split ' \| '
    if ($holders -notcontains $RemoveFrom) {
        [pscustomobject]@{ Spn = $d.Value; Account = $RemoveFrom; Outcome = 'skipped'
                           Detail = "'$RemoveFrom' does not hold this SPN (holders: $($d.Holders))" }
        continue
    }
    if ($PSCmdlet.ShouldProcess("$RemoveFrom @ $Target",
            "Remove SPN '$($d.Value)' -- it is also held by $(($holders | Where-Object { $_ -ne $RemoveFrom }) -join ', ')")) {
        try {
            Remove-AdmSpn -Target $Target -Identity $RemoveFrom -Spn $d.Value -Tier $Tier -Confirm:$false | Out-Null
            [pscustomobject]@{ Spn = $d.Value; Account = $RemoveFrom; Outcome = 'removed'; Detail = '' }
        } catch {
            $script:failed++
            [pscustomobject]@{ Spn = $d.Value; Account = $RemoveFrom; Outcome = 'failed'; Detail = $_.Exception.Message }
        }
    } else {
        [pscustomobject]@{ Spn = $d.Value; Account = $RemoveFrom; Outcome = 'declined'; Detail = '' }
    }
}

$results
if ($failed) { exit 20 }
exit 0
