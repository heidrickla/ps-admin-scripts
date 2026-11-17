<#
.SYNOPSIS
  Why an account keeps locking out, and which machine is doing it. Reads every DC, not just one.

.DESCRIPTION
  The highest-volume question in any Active Directory estate, and the one most often answered
  wrongly, because the evidence is NOT REPLICATED and the obvious query reads one domain
  controller and reports its answer as the domain's.

  ⛔ badPwdCount AND badPasswordTime ARE PER-DC. Every domain controller keeps its own count of
  failed passwords for an account, and neither attribute replicates. Read one DC and you learn
  what that DC saw -- which, if the machine spraying stale credentials authenticates against a
  different one, is zero. The account is locked, the count reads 0, and the report says there is
  nothing wrong. This is the same trap as lastLogon, documented in docs/active-directory-traps.md,
  and it is why this script queries EVERY domain controller and takes the newest answer.

  lockoutTime is different: it IS replicated, urgently, so the fact of a lockout is visible
  anywhere. What is not visible anywhere is WHERE it came from -- and that is the whole question.

  WHAT IT DOES

  Policy       lockoutThreshold, lockoutDuration and lockoutObservationWindow off the domain head,
               so the numbers are read rather than assumed. ⚠ A threshold of 0 means lockout is
               DISABLED domain-wide and no account can ever lock; that is reported, because
               "no locked accounts" then means something completely different.
               Fine-grained password policies are detected and reported where they exist, since
               they silently override every number above for the accounts they apply to.

  Per-DC read  Every domain controller is asked for badPwdCount, badPasswordTime and lockoutTime
               for the account. The DC holding the NEWEST badPasswordTime is named, because that
               is the only DC whose Security log is worth opening.
               ⛔ A domain controller that does not answer makes the result UNKNOWN, not clean --
               the newest attempt may be the one on the DC that was unreachable. Exit code 30.

  Event 4740   Read from the PDC emulator, which is where every lockout is recorded regardless of
               which DC processed the failures. Event 4740 names the CALLING COMPUTER, which is
               the actual answer to "from what?".
               ⚠ This usually fails from outside the domain, and it fails for a reason that has
               nothing to do with the account: Get-WinEvent reaches a remote log over RPC/DCOM,
               which is routinely blocked, and reading Security needs rights this toolkit does not
               assume. When it cannot be read the script says so in those words. It never reports
               "no source found" for a log it could not open.

  -Unlock      Clears the lockout through Unlock-AdmUser. Honours -WhatIf.
               ⚠ Unlocking without finding the source is a treadmill: the stale credential is
               still on the machine and the account locks again within the observation window.

.EXAMPLE
  .\Get-AdLockoutSource.ps1 -Target corp.example.com
.EXAMPLE
  .\Get-AdLockoutSource.ps1 -Target corp.example.com -Identity jsmith
.EXAMPLE
  .\Get-AdLockoutSource.ps1 -Target corp.example.com -Identity jsmith -Unlock -WhatIf

.NOTES
  EXIT CODES
    0   ran, nothing found  (no locked accounts, no failed-password activity)
    10  ran, and found something
    20  a change failed  (an -Unlock did not take)
    30  ran, but at least one domain controller or check could NOT be reached

  VERIFIED LIVE against a lab domain controller (corp.example.com, Windows Server 2025) on 2026-08-28:
    - The per-DC read works: a domain record cloned and pinned to a single DC address, then
      Invoke-AdmAdsiSearch against it, returns that DC's own badPwdCount and badPasswordTime.
    - Domain controllers are found by (&(objectCategory=computer)(userAccountControl:...:=8192)),
      which returned DC01$ with its dNSHostName.
      ⛔ (objectClass=nTDSDSA) RETURNS NOTHING from the domain naming context -- those objects
      live in the CONFIGURATION NC. Measured: 0 hits against DC=corp,DC=example,DC=com, 1 hit against
      CN=Configuration,DC=corp,DC=example,DC=com. It is used here only as the fallback, with that base.
    - The PDC is found from the domain head's fSMORoleOwner, by trimming the leading
      "CN=NTDS Settings," and reading dNSHostName off the server object. Verified end to end.
    - lockoutTime is ABSENT (not zero, not empty) on an account that has never been locked, so
      every read goes through Get-AdmRawProp.
    - Get-WinEvent against the DC failed with "The RPC server is unavailable"
      (System.Diagnostics.Eventing.Reader.EventLogException). That is the expected result from
      outside the domain and it is what the degradation path below was written against.
  NOT VERIFIED: ⚠ NO LOCKOUT WAS EVER OBSERVED. The lab forest has lockoutThreshold 0, so a
  lockout cannot be induced there, and lockoutTime is system-managed -- a DC refuses a direct
  write of a non-zero value, so one cannot be faked either. Everything downstream of "an account
  is actually locked" -- the newest-wins selection across DCs, the severity scoring, and the 4740
  field mapping -- is exercised offline in tests/Delegation.Tests.ps1 and has NOT been seen
  against a real lockout. The 4740 field names in particular are from the event schema, not from
  an event this script has read.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Target,
    # One account. Omitted, every account that is currently locked is examined.
    [string]$Identity,
    [switch]$Unlock,
    [string]$ExportCsv,
    # How far back to look in the PDC's Security log.
    [int]$EventLookbackHours = 48,
    # Skip the event-log read entirely, when it is known to be blocked and the noise is unwanted.
    [switch]$SkipEventLog,
    [int]$Limit = 5000,
    [string]$Tier
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# NOT -Force: a forced import makes a fresh module instance and re-locks the caller's store.
if (-not (Get-Module ADAdmin)) {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'ADAdmin\ADAdmin.psd1')
}

$findings      = New-Object System.Collections.ArrayList
$couldNotCheck = New-Object System.Collections.ArrayList
$changeFailed  = $false
$now = (Get-Date).ToUniversalTime()

# ⛔ EVERY ROW CARRIES EVERY COLUMN, even when the value is null. Export-Csv takes its header from
# the FIRST object it is given and silently drops any property the later ones add -- so when the
# first row was a policy finding with only the seven standard fields, the CSV came out with seven
# columns and the per-DC evidence, which is the entire point of this script, was not in the file.
# It looked like a successful export. Measured 2026-08-28.
$AccountColumns = @('SamAccountName', 'LockedOut', 'LockoutTimeUtc', 'BadPwdCountMax',
                    'BadPasswordTimeUtc', 'NewestOnDc', 'DcsAnswered', 'DcsUnreachable',
                    'PerDc', 'CallingComputer')

function Add-Finding {
    param(
        [ValidateSet('critical', 'high', 'warn', 'info')][string]$Severity,
        [string]$Category, [string]$Principal, [string]$Detail, [string]$Why, [string]$Action,
        $Path = $null, $Extra = $null
    )
    $row = [ordered]@{
        Severity = $Severity; Category = $Category; Principal = $Principal
        Detail = $Detail; Why = $Why; Action = $Action; Via = $Path
    }
    # The account columns come after the seven every script in this repo emits, so the report
    # tables line up with the others and a CSV of several scripts can be concatenated.
    foreach ($k in $AccountColumns) {
        $row[$k] = if ($Extra -and $Extra.Contains($k)) { $Extra[$k] } else { $null }
    }
    [void]$findings.Add([pscustomobject]$row)
}

function Note-Unchecked {
    param([string]$What, [string]$Reason)
    [void]$couldNotCheck.Add([pscustomobject]@{ Check = $What; Reason = $Reason })
    Write-Warning "Could not check $What -- $Reason"
}

# Windows FILETIME as a SEARCH returns it (Int64). 0 and Int64::MaxValue are both sentinels
# meaning "no value", and neither is a date.
function ConvertFrom-AdLockoutFileTime {
    param($Value)
    $n = 0L
    if (-not [int64]::TryParse([string]$Value, [ref]$n)) { return $null }
    if ($n -le 0 -or $n -eq [int64]::MaxValue) { return $null }
    try { [datetime]::FromFileTimeUtc($n) } catch { $null }
}

# A duration on the domain object is a NEGATIVE count of 100-ns intervals. Measured on a lab domain controller:
# lockoutDuration -6000000000 = 10 minutes. Zero means "until an administrator unlocks it", which
# is a real setting and not a missing value.
function ConvertFrom-AdLockoutDuration {
    param($Value)
    $n = 0L
    if (-not [int64]::TryParse([string]$Value, [ref]$n)) { return $null }
    try { [timespan]::FromTicks([math]::Abs($n)) } catch { $null }
}

# --- the target --------------------------------------------------------------------------------

$ctx = $null
try { $ctx = Get-AdmTargetContextPublic -Target $Target -Tier $Tier } catch {
    Write-Error "Could not resolve '$Target' to a registered domain and credential: $($_.Exception.Message)"
    exit 30
}
$domainDn = ConvertTo-AdmDistinguishedName -DnsDomain $ctx.Domain.DnsDomain
$configDn = "CN=Configuration,$domainDn"

# ⛔ EVERY READ GOES THROUGH HERE, WHICH IS WHY THE TRUNCATION CHECK DOES TOO. Exit 0 on this
# script means "ran, nothing found" -- and a locked account past the size limit is never read, so
# it can never be found. A truncated run therefore reports the reassuring answer rather than a
# short one. It becomes unchecked coverage, which already drives exit 30 ("ran, but at least one
# check could NOT be reached"), because that is exactly what happened.
#
# ⚠ Buffered rather than streamed: the flag can only be read once the enumeration has finished.
function Search-AdLockoutDir {
    param([string]$Filter, [string[]]$Properties, [string]$SearchBase, [int]$Max = 0)
    $lim = $(if ($Max) { $Max } else { $Limit })
    $p = @{ Target = $Target; Filter = $Filter; Properties = $Properties; Tier = $Tier; Limit = $lim }
    if ($SearchBase) { $p['SearchBase'] = $SearchBase }
    Reset-AdmSearchTruncated
    $rows = @(Get-AdmSearchResult @p)
    if (Get-AdmSearchTruncated) {
        $short = if ($Filter.Length -gt 70) { $Filter.Substring(0, 70) + '...' } else { $Filter }
        Note-Unchecked "everything matching $short" `
            ("the read stopped at $lim objects, so accounts past that limit were never read -- " +
             "a locked one among them would not appear here")
    }
    $rows
}

# --- 1. the lockout policy ----------------------------------------------------------------------

$threshold = $null
$policyKnown = $false
try {
    $head = @(Search-AdLockoutDir -Filter '(objectClass=domainDNS)' `
                -Properties @('lockoutthreshold', 'lockoutduration', 'lockoutobservationwindow', 'fsmoroleowner', 'distinguishedname') -Max 5)[0]
    if (-not $head) {
        Note-Unchecked 'the domain lockout policy' 'the domain object did not come back'
    } else {
        # ⚠ Read with a SEARCH, never through DirectoryEntry.Properties. Every duration on the
        # domain object comes back as a COM object that way, and [int64] on it throws -- or worse,
        # silently yields a blank, which makes every threshold comparison below match nothing.
        $rawT = Get-AdmRawProp $head 'lockoutthreshold'
        $dur  = ConvertFrom-AdLockoutDuration (Get-AdmRawProp $head 'lockoutduration')
        $win  = ConvertFrom-AdLockoutDuration (Get-AdmRawProp $head 'lockoutobservationwindow')
        $t = 0
        if ($null -ne $rawT -and [int]::TryParse([string]$rawT, [ref]$t)) { $threshold = $t; $policyKnown = $true }

        if (-not $policyKnown) {
            Note-Unchecked 'the domain lockout threshold' 'lockoutThreshold was not readable, so nothing below can say whether an account is close to locking'
        } elseif ($threshold -eq 0) {
            # Measured on a lab domain controller: this is that lab's actual setting, and it changes what an empty
            # report means.
            Add-Finding -Severity 'warn' -Category 'Policy' -Principal '(domain)' -Path $domainDn `
                -Detail 'lockoutThreshold is 0 -- account lockout is DISABLED for the whole domain' `
                -Why 'No account in this domain can ever lock out, however many wrong passwords are tried. That makes a clean report here meaningless -- there are no locked accounts because there cannot be -- and it means the domain has no brake at all on online password guessing.' `
                -Action 'Decide deliberately. A threshold of 0 is a defensible choice only when something else is stopping password spraying (smart lockout, an identity provider in front, conditional access). If nothing is, set a threshold with a short duration -- 10 attempts over 15 minutes is a common balance between guessing and self-inflicted denial of service.'
        } else {
            Add-Finding -Severity 'info' -Category 'Policy' -Principal '(domain)' -Path $domainDn `
                -Detail ("lockoutThreshold $threshold; duration $(if ($dur -and $dur.TotalSeconds -gt 0) { "$([math]::Round($dur.TotalMinutes,1)) minute(s)" } else { 'until an administrator unlocks' }); observation window $(if ($win) { "$([math]::Round($win.TotalMinutes,1)) minute(s)" } else { 'unknown' })") `
                -Why 'The numbers every count below is measured against, read from the domain rather than assumed.' `
                -Action 'None.'
        }
    }
} catch {
    Note-Unchecked 'the domain lockout policy' $_.Exception.Message
}

# Fine-grained password policies override all of the above, per-user, invisibly.
try {
    $psos = @(Search-AdLockoutDir -Filter '(objectClass=msDS-PasswordSettings)' -Properties @('cn', 'msds-lockoutthreshold') -SearchBase $domainDn -Max 200)
    if ($psos.Count) {
        Add-Finding -Severity 'info' -Category 'Policy' -Principal '(domain)' -Path $domainDn `
            -Detail "$($psos.Count) fine-grained password policy object(s) exist: $((@($psos | ForEach-Object { [string](Get-AdmRawProp $_ 'cn') })) -join ', ')" `
            -Why 'A fine-grained password policy replaces the domain lockout settings for the users and groups it is applied to, and nothing on the account itself shows which one is in force. The domain-level numbers reported above may not be the numbers governing the account you are looking at.' `
            -Action 'If the account under investigation is in scope of one of these, read its msDS-LockoutThreshold and msDS-LockoutObservationWindow instead of the domain values.'
    }
} catch {
    # Not fatal: a domain below 2008 functional level has no PSO class at all.
    Write-Verbose "Fine-grained password policies could not be enumerated: $($_.Exception.Message)"
}

# --- 2. the domain controllers ------------------------------------------------------------------

# What the per-DC read needs is an ADDRESS it can reach. Two independent routes to the list, and
# the profile's own configured addresses as the thing that makes them reachable.
$dcs = New-Object System.Collections.ArrayList

try {
    # Route 1, and the one that works from the DOMAIN naming context. uac 0x2000 = SERVER_TRUST,
    # which is what makes a computer object a domain controller.
    foreach ($c in @(Search-AdLockoutDir -Filter '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' `
                        -Properties @('dnshostname', 'samaccountname', 'distinguishedname') -Max 200)) {
        $sam = [string](Get-AdmRawProp $c 'samaccountname')
        $dns = [string](Get-AdmRawProp $c 'dnshostname')
        [void]$dcs.Add([pscustomobject]@{ Name = $sam.TrimEnd('$'); Dns = $dns; Source = 'computer object' })
    }
} catch { Note-Unchecked 'the list of domain controllers (via computer objects)' $_.Exception.Message }

if (-not $dcs.Count) {
    # Route 2, the fallback -- and it MUST be given the Configuration NC as its base. Measured:
    # (objectClass=nTDSDSA) matches nothing at all from the domain NC, so a script that uses this
    # filter without a search base finds no domain controllers and then reads none of them.
    try {
        foreach ($s in @(Search-AdLockoutDir -Filter '(objectClass=server)' -Properties @('dnshostname', 'cn') -SearchBase $configDn -Max 200)) {
            $dns = [string](Get-AdmRawProp $s 'dnshostname')
            $cn  = [string](Get-AdmRawProp $s 'cn')
            if ($cn) { [void]$dcs.Add([pscustomobject]@{ Name = $cn; Dns = $dns; Source = 'configuration NC' }) }
        }
    } catch { Note-Unchecked 'the list of domain controllers (via the configuration NC)' $_.Exception.Message }
}

if (-not $dcs.Count) {
    Note-Unchecked 'the list of domain controllers' 'no domain controller could be enumerated, so the per-DC read below cannot run and every bad-password count is UNKNOWN'
}

# ⭐ THE ADDRESS PROBLEM, and it is not an edge case for a portable toolkit. A domain controller
# advertises itself by dNSHostName -- dc01.corp.example.com -- and from a machine outside the
# forest that name does not resolve, because the only DNS that knows it is the forest's own. So
# each DC is tried by its advertised name first and then by every address in the domain profile,
# which is where the reachable addresses actually live. If neither works the DC is UNKNOWN.
$profileAddresses = @(@($ctx.Domain.DomainControllers) | Where-Object { $_ })

function Get-AdLockoutDcCandidate {
    param($Dc)
    $out = New-Object System.Collections.ArrayList
    if ($Dc.Dns) { [void]$out.Add($Dc.Dns) }
    foreach ($a in $profileAddresses) {
        # A profile entry naming this DC is the best fallback; the rest are tried after.
        if ($Dc.Name -and "$a" -match "(?i)^$([regex]::Escape($Dc.Name))(\.|$)") { [void]$out.Add($a) }
    }
    foreach ($a in $profileAddresses) { if ($out -notcontains $a) { [void]$out.Add($a) } }
    $out
}

# Read one account's per-DC attributes from ONE domain controller, by cloning the domain record
# with its DomainControllers list pinned to that single address. Get-AdmSearchResult always uses
# the FIRST entry in the profile's list, so pinning is the only way to choose.
function Get-AdLockoutFromDc {
    param([string]$Address, [string]$Filter)
    $pinned = [pscustomobject]@{
        Name              = $ctx.Domain.Name
        DnsDomain         = $ctx.Domain.DnsDomain
        NetbiosName       = $ctx.Domain.NetbiosName
        DomainControllers = @($Address)
        Port              = $ctx.Domain.Port
        UseSsl            = $ctx.Domain.UseSsl
    }
    Invoke-AdmAdsiSearch -Domain $pinned -Credential $ctx.Credential -Filter $Filter `
        -Properties @('samaccountname', 'distinguishedname', 'badpwdcount', 'badpasswordtime',
                      'lockouttime', 'lastlogon', 'pwdlastset', 'useraccountcontrol') `
        -SearchBase $domainDn -SizeLimit 5
}

# --- 3. the PDC emulator -------------------------------------------------------------------------

# Every lockout is recorded on the PDC whichever DC processed the failures, so it is the one log
# worth opening -- and the one account-lockout event, 4740, is written there.
$pdcName = $null
$pdcDns  = $null
try {
    $head2 = @(Search-AdLockoutDir -Filter '(objectClass=domainDNS)' -Properties @('fsmoroleowner') -Max 5)[0]
    $fsmo = [string](Get-AdmRawProp $head2 'fsmoroleowner')
    if ($fsmo) {
        # "CN=NTDS Settings,CN=DC01,CN=Servers,..." -- the server object is the parent, and it is
        # the thing carrying dNSHostName. Verified end to end on a lab domain controller.
        $parts = $fsmo -split ','
        if ($parts.Count -gt 2) {
            $serverDn = ($parts[1..($parts.Count - 1)]) -join ','
            $pdcName = ($parts[1] -replace '^CN=', '')
            try {
                $srv = @(Search-AdLockoutDir -Filter '(objectClass=server)' -Properties @('dnshostname', 'cn') -SearchBase $serverDn -Max 3)[0]
                if ($srv) { $pdcDns = [string](Get-AdmRawProp $srv 'dnshostname') }
            } catch { Write-Verbose "PDC server object lookup failed: $($_.Exception.Message)" }
        }
    }
} catch { Write-Verbose "fSMORoleOwner could not be read: $($_.Exception.Message)" }
if (-not $pdcName) {
    Note-Unchecked 'which domain controller is the PDC emulator' 'fSMORoleOwner on the domain head was not readable, so the Security log cannot be pointed at the right DC'
}

# --- 4. which accounts -----------------------------------------------------------------------------

$accounts = New-Object System.Collections.ArrayList
$identityMissing = $false
try {
    if ($Identity) {
        $v = $Identity -replace '\\', '\5c' -replace '\(', '\28' -replace '\)', '\29' -replace '\*', '\2a'
        foreach ($u in @(Search-AdLockoutDir -Filter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$v))" `
                            -Properties @('samaccountname', 'distinguishedname') -Max 5)) {
            [void]$accounts.Add([string](Get-AdmRawProp $u 'samaccountname'))
        }
        # ⚠ NOT Write-Error here. With $ErrorActionPreference = 'Stop' that throws, and the throw
        # would be swallowed by this function's own catch below and reported as "could not check
        # which accounts are locked" -- which is the wrong answer twice over: the directory
        # answered perfectly well, and what it said is that there is no such account.
        if (-not $accounts.Count) { $identityMissing = $true }
    } else {
        # lockoutTime IS replicated urgently, so any DC can answer "who is locked right now".
        # ⚠ (lockoutTime>=1) rather than (lockoutTime=*): an account that has been UNLOCKED keeps
        # the attribute with a value of 0, so the presence test matches every account that has
        # ever been locked, which is a completely different question.
        foreach ($u in @(Search-AdLockoutDir -Filter '(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))' `
                            -Properties @('samaccountname', 'distinguishedname'))) {
            [void]$accounts.Add([string](Get-AdmRawProp $u 'samaccountname'))
        }
        Write-Verbose "$($accounts.Count) account(s) currently locked."
    }
} catch {
    Note-Unchecked 'which accounts are locked' $_.Exception.Message
}

if ($identityMissing) {
    Write-Warning "No user account has sAMAccountName '$Identity' in $($ctx.Domain.DnsDomain). Nothing was examined."
    exit 30
}

# --- 5. the per-DC read ------------------------------------------------------------------------

# sam -> the DC that saw the newest bad password, so section 6 knows where to look.
$newestDcFor = @{}

foreach ($sam in $accounts) {
    $esc = $sam -replace '\\', '\5c' -replace '\(', '\28' -replace '\)', '\29' -replace '\*', '\2a'
    $filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$esc))"

    $perDc = New-Object System.Collections.ArrayList
    $unreachable = New-Object System.Collections.ArrayList

    foreach ($dc in $dcs) {
        $got = $false
        $lastErr = $null
        foreach ($addr in (Get-AdLockoutDcCandidate -Dc $dc)) {
            try {
                $row = @(Get-AdLockoutFromDc -Address $addr -Filter $filter)[0]
                if (-not $row) { $lastErr = 'the account was not returned by this DC'; continue }
                $bpc = 0
                [void][int]::TryParse([string](Get-AdmRawProp $row 'badpwdcount' 0), [ref]$bpc)
                [void]$perDc.Add([pscustomobject]@{
                    Dc              = $dc.Name
                    Address         = $addr
                    BadPwdCount     = $bpc
                    BadPasswordTime = ConvertFrom-AdLockoutFileTime (Get-AdmRawProp $row 'badpasswordtime')
                    LockoutTime     = ConvertFrom-AdLockoutFileTime (Get-AdmRawProp $row 'lockouttime')
                    LastLogon       = ConvertFrom-AdLockoutFileTime (Get-AdmRawProp $row 'lastlogon')
                })
                $got = $true
                break
            } catch {
                $lastErr = $_.Exception.Message
            }
        }
        if (-not $got) {
            [void]$unreachable.Add($dc.Name)
            # ⛔ NOT a warning to be scrolled past. The whole method is "ask every DC and take the
            # newest"; a DC that did not answer may be holding the newest attempt, so the answer
            # below is at best a lower bound.
            Note-Unchecked "the bad-password counters for '$sam' on $($dc.Name)" `
                "no address for that DC could be reached ($lastErr). Its badPwdCount and badPasswordTime are UNKNOWN, so the source named below may not be the real one"
        }
    }

    if (-not $perDc.Count) {
        Note-Unchecked "the bad-password history of '$sam'" 'not one domain controller answered, so nothing about this account could be determined'
        continue
    }

    # ⭐ NEWEST WINS, and only among the DCs that actually answered. Sorting on a $null
    # BadPasswordTime is the trap here: a DC that has never seen a failure for this account sorts
    # as if it had, so it is filtered out BEFORE the sort rather than compared inside it.
    $withTime = @($perDc | Where-Object { $null -ne $_.BadPasswordTime })
    $newest = $null
    if ($withTime.Count) { $newest = @($withTime | Sort-Object BadPasswordTime -Descending)[0] }

    $maxCount = 0
    foreach ($p in $perDc) { if ($p.BadPwdCount -gt $maxCount) { $maxCount = $p.BadPwdCount } }

    $lockRow = $null
    foreach ($p in $perDc) { if ($null -ne $p.LockoutTime) { $lockRow = $p; break } }
    $isLocked = ($null -ne $lockRow)

    if ($newest) { $newestDcFor[$sam] = $newest }

    $breakdown = (@($perDc | ForEach-Object {
        "$($_.Dc)=$($_.BadPwdCount)@$(if ($_.BadPasswordTime) { $_.BadPasswordTime.ToString('u') } else { 'never' })"
    }) -join '; ')

    $extra = [ordered]@{
        SamAccountName     = $sam
        LockedOut          = $isLocked
        LockoutTimeUtc     = $(if ($lockRow) { $lockRow.LockoutTime } else { $null })
        BadPwdCountMax     = $maxCount
        BadPasswordTimeUtc = $(if ($newest) { $newest.BadPasswordTime } else { $null })
        NewestOnDc         = $(if ($newest) { $newest.Dc } else { $null })
        DcsAnswered        = $perDc.Count
        DcsUnreachable     = $unreachable.Count
        PerDc              = $breakdown
        CallingComputer    = $null
    }

    $ageMin = if ($newest) { [math]::Round(($now - $newest.BadPasswordTime).TotalMinutes, 1) } else { $null }
    $sev = if ($isLocked) { 'high' }
           elseif ($policyKnown -and $threshold -gt 0 -and $maxCount -ge $threshold) { 'high' }
           elseif ($maxCount -gt 0) { 'warn' }
           else { 'info' }

    if ($isLocked) {
        Add-Finding -Severity $sev -Category 'Lockout' -Principal $sam -Extra $extra `
            -Path $(if ($newest) { "newest failure seen on $($newest.Dc)" } else { 'no DC recorded a failed password' }) `
            -Detail ("LOCKED OUT since $(if ($lockRow.LockoutTime) { $lockRow.LockoutTime.ToString('u') } else { 'unknown' }); highest badPwdCount across $($perDc.Count) DC(s) is $maxCount" +
                     $(if ($newest) { "; newest failed password $($newest.BadPasswordTime.ToString('u')) ($ageMin minute(s) ago) on $($newest.Dc)" } else { '; no DC has a badPasswordTime for it' }) +
                     "  [$breakdown]") `
            -Why ('The account is locked. badPwdCount and badPasswordTime are held separately by every domain controller and are not replicated, so the counts above are per-DC and the highest one is the closest thing to a domain-wide answer. ' +
                  $(if ($newest) { "$($newest.Dc) recorded the most recent failure, which makes its Security log -- and the PDC's event 4740 -- the place the calling machine is named." } else { 'No domain controller holds a badPasswordTime for this account, which usually means the failures happened outside the observation window and the counters have since been reset.' })) `
            -Action ('Find the source before unlocking, or it locks again: the usual causes are a saved credential in Credential Manager, a mapped drive, a scheduled task or service running as the account, a phone or tablet with the old password, or an RDP session left signed in. ' +
                     'Event 4740 on the PDC names the calling computer; 4771 and 4625 on ' + $(if ($newest) { $newest.Dc } else { 'the DC with the newest failure' }) + ' name the process. Then unlock with -Unlock.')
    } elseif ($maxCount -gt 0) {
        Add-Finding -Severity $sev -Category 'BadPassword' -Principal $sam -Extra $extra `
            -Path $(if ($newest) { "newest failure seen on $($newest.Dc)" } else { $null }) `
            -Detail ("not locked, but $maxCount failed password attempt(s) are counted" +
                     $(if ($policyKnown -and $threshold -gt 0) { " against a threshold of $threshold" }) +
                     $(if ($newest) { "; newest $($newest.BadPasswordTime.ToString('u')) ($ageMin minute(s) ago) on $($newest.Dc)" }) +
                     "  [$breakdown]") `
            -Why 'Failed attempts are accumulating. Because each domain controller counts separately and none of them replicates the count, the true number of attempts against the domain is the SUM of these, while lockout is triggered by the individual DC counts -- so an account can be under sustained attack and still be several attempts from locking on any single DC.' `
            -Action 'If the account is not expected to be failing, treat it as either a stale saved credential or password guessing, and use the DC named above to tell which: a stale credential retries from one machine on a timer, guessing comes from many sources or against many accounts.'
    } else {
        Add-Finding -Severity 'info' -Category 'BadPassword' -Principal $sam -Extra $extra `
            -Path $null `
            -Detail "no failed password attempts counted on any of the $($perDc.Count) domain controller(s) read" `
            -Why 'Recorded so that "nothing found" is distinguishable from "not looked at". Every DC that answered reports a badPwdCount of zero.' `
            -Action 'None.'
    }
}

# --- 6. event 4740 on the PDC ---------------------------------------------------------------------

# ⛔ Deliberately NOT Get-AdmWindowsEvent. That cmdlet reads the LOCAL machine's System and
# Application logs, and it excludes Security on purpose. What is needed here is the Security log
# of a REMOTE domain controller, which is a different operation with a different failure mode.
function Get-AdLockoutEvent {
    param([string]$Computer, [int]$Hours, $Credential)
    $p = @{
        FilterHashtable = @{ LogName = 'Security'; Id = 4740; StartTime = (Get-Date).AddHours(-1 * $Hours) }
        MaxEvents       = 200
        ErrorAction     = 'Stop'
    }
    # -ComputerName plus -Credential against the local machine is rejected by Get-WinEvent, so a
    # run ON a domain controller has to omit both.
    # [regex]::Escape on the machine name: it is environment data going into a pattern, and an
    # unescaped one would be a regex, not a name.
    $isLocal = $Computer -and ($Computer -match ('(?i)^' + [regex]::Escape("$env:COMPUTERNAME") + '(\.|$)'))
    if ($Computer -and -not $isLocal) {
        $p['ComputerName'] = $Computer
        if ($Credential) { $p['Credential'] = $Credential }
    }
    Get-WinEvent @p
}

# Pull the EventData fields out BY NAME. The positional layout of 4740 is stable but reading it
# positionally makes the code silently wrong if it ever is not, and the XML carries the names.
function ConvertFrom-AdLockoutEventXml {
    param($Event)
    $out = @{}
    try {
        [xml]$x = $Event.ToXml()
        foreach ($d in @($x.Event.EventData.Data)) {
            $n = [string]$d.Name
            if ($n) { $out[$n] = [string]$d.'#text' }
        }
    } catch { }
    $out
}

if (-not $SkipEventLog) {
    $eventHost = if ($pdcDns) { $pdcDns } else { $pdcName }
    if (-not $eventHost) {
        Note-Unchecked 'event 4740 (account locked out)' 'the PDC emulator could not be identified, so there was no host to read the Security log from'
    } elseif (-not $accounts.Count) {
        Write-Verbose 'No accounts to look up in the event log.'
    } else {
        $events = $null
        $eventError = $null
        try {
            $events = @(Get-AdLockoutEvent -Computer $eventHost -Hours $EventLookbackHours -Credential $ctx.Credential)
        } catch {
            # A genuinely EMPTY log is a terminating error too, and the ONLY locale-invariant way
            # to tell it from a real failure is the FullyQualifiedErrorId. Matching the English
            # message misreports every empty read on a non-English machine as an unknown error.
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $events = @() }
            else { $eventError = $_ }
        }

        if ($eventError) {
            # ⛔ SAY WHAT WAS TESTED, NOT WHAT IT MEANS. This failure bounds the TRANSPORT to the
            # event log. It says nothing about the account, and reporting "no source found" here
            # would be a claim about evidence that was never read.
            $hint = if ($eventError.Exception.Message -match '(?i)RPC server is unavailable') {
                        'Get-WinEvent reads a remote log over RPC/DCOM (135 plus a dynamic port range), not over LDAP or WinRM, and that is routinely blocked to a domain controller from anywhere but a management network. This is the expected result from outside the domain -- measured against a lab domain controller, 2026-08-28.'
                    } elseif ($eventError.Exception.Message -match '(?i)access is denied') {
                        'Reading the Security log needs membership of Event Log Readers on that domain controller, or administrative rights on it. A directory read credential does not carry either.'
                    } else {
                        'The Security log could not be opened; the message above is the reason the event log service gave.'
                    }
            Note-Unchecked "event 4740 on $eventHost (which names the CALLING COMPUTER)" `
                "$($eventError.Exception.Message) -- $hint The calling machine is therefore UNKNOWN, not absent. Read it on the domain controller itself (Get-WinEvent -LogName Security -FilterXPath ""*[System[EventID=4740]]""), or from a machine that can reach it over RPC with Event Log Reader rights."
        } elseif ($null -ne $events) {
            $matched = 0
            foreach ($e in $events) {
                $d = ConvertFrom-AdLockoutEventXml -Event $e
                $who = if ($d.ContainsKey('TargetUserName')) { $d['TargetUserName'] } else { $null }
                if (-not $who) { continue }
                if ($accounts -notcontains $who) { continue }
                $matched++
                # For 4740 the CALLING COMPUTER is carried in TargetDomainName -- which is a
                # genuinely confusing field name, and the reason this is read by name and the raw
                # first line of the message is reported alongside it. ⚠ NOT verified against a
                # real 4740: no lockout could be induced on the lab (lockoutThreshold 0).
                $caller = if ($d.ContainsKey('TargetDomainName')) { $d['TargetDomainName'] } else { $null }
                $first = if ($e.Message) { (($e.Message -split "`r?`n")[0]).Trim() } else { '(no message text)' }

                Add-Finding -Severity 'high' -Category 'LockoutSource' -Principal $who `
                    -Path "$eventHost, event 4740 at $($e.TimeCreated.ToUniversalTime().ToString('u'))" `
                    -Extra ([ordered]@{ SamAccountName = $who; CallingComputer = $caller }) `
                    -Detail "locked out from '$(if ($caller) { $caller } else { '(the event carried no caller)' })' -- $first" `
                    -Why 'Event 4740 is written on the PDC emulator every time an account locks, whichever domain controller processed the failures, and it names the machine the attempts came from. That machine is where the stale credential lives.' `
                    -Action "Go to that machine. Check Credential Manager, mapped drives, scheduled tasks and services running as this account, and any signed-in session. Until the saved password there is corrected, unlocking the account only restarts the clock."
            }
            if (-not $matched) {
                Add-Finding -Severity 'info' -Category 'LockoutSource' -Principal '(none)' -Path $eventHost `
                    -Detail "the Security log on $eventHost was read successfully and holds no event 4740 for these account(s) in the last $EventLookbackHours hour(s)" `
                    -Why 'This is a real negative, not a failed read: the log was opened and searched. A locked account with no 4740 in the window usually locked longer ago than the lookback.' `
                    -Action "Widen the window with -EventLookbackHours if the lockout is older than $EventLookbackHours hours."
            }
        }
    }
}

# --- 7. unlock ------------------------------------------------------------------------------------

if ($Unlock) {
    $toUnlock = @($findings | Where-Object { $_.Category -eq 'Lockout' })
    if (-not $toUnlock.Count) {
        Write-Verbose 'Nothing is locked; -Unlock had nothing to do.'
    }
    foreach ($f in $toUnlock) {
        $sam = $f.Principal
        try {
            # ShouldProcess lives in Unlock-AdmUser, so -WhatIf and -Confirm flow through from
            # this script's own CmdletBinding without being re-implemented here.
            $r = Unlock-AdmUser -Target $Target -Identity $sam -Tier write
            if ($WhatIfPreference) {
                Write-Verbose "WhatIf: would unlock '$sam'."
            } elseif ($r) {
                Add-Finding -Severity 'info' -Category 'Change' -Principal $sam `
                    -Extra ([ordered]@{ SamAccountName = $sam }) `
                    -Detail 'unlocked' `
                    -Why 'The lockout was cleared at the request of -Unlock.' `
                    -Action 'Confirm the source above has been dealt with, or it will lock again within the observation window.'
            }
        } catch {
            $changeFailed = $true
            Add-Finding -Severity 'critical' -Category 'Change' -Principal $sam `
                -Extra ([ordered]@{ SamAccountName = $sam }) `
                -Detail "unlock FAILED: $($_.Exception.Message)" `
                -Why 'The account is still locked. An unlock is a write to lockoutTime and needs a write-tier credential with the right to reset it on that object.' `
                -Action 'Check that the domain profile has a write credential (Set-AdmDomainCredential -Tier write) and that it has "Unlock account" or Reset Password delegated on the account''s OU.'
        }
    }
}

# --- output ------------------------------------------------------------------------------------

$order = @{ critical = 0; high = 1; warn = 2; info = 3 }
$sorted = @($findings | Sort-Object @{ Expression = { $order[$_.Severity] } }, Category, Principal)

if ($ExportCsv) {
    $sorted | Export-Csv -LiteralPath $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Verbose "Wrote $($sorted.Count) row(s) to $ExportCsv"
}

$sorted

$actionable = @($sorted | Where-Object { $_.Severity -ne 'info' })

# An explicit loop variable: a nested Where-Object inside a ForEach-Object rebinds $_, so
# `$_.Severity -eq $_` compares each row against itself and yields plausible nonsense.
$summary = foreach ($sev in @('critical', 'high', 'warn', 'info')) {
    $n = @($sorted | Where-Object { $_.Severity -eq $sev }).Count
    if ($n) { "$sev $n" }
}
Write-Verbose ("$($sorted.Count) row(s): " + ((@($summary) -join ', ')))

if ($dcs.Count -eq 1) {
    Write-Warning ('Only ONE domain controller was found, so the per-DC comparison that is the ' +
                   'point of this script had nothing to compare. On a domain with more than one ' +
                   'DC, a single-DC read is how the wrong answer gets produced.')
}

# ⛔ The house contract: 20 first -- a failed change is more urgent than an incomplete read --
# then 30, because a check that could not run must never be reported as a pass.
if ($changeFailed) {
    Write-Warning 'At least one unlock FAILED; those accounts are still locked.'
    exit 20
}
if ($couldNotCheck.Count) {
    Write-Warning "$($couldNotCheck.Count) check(s) could not run; those answers are UNKNOWN, not clean."
    $couldNotCheck | Format-Table -AutoSize | Out-String | Write-Verbose
    exit 30
}
if ($actionable.Count) { exit 10 }
exit 0
