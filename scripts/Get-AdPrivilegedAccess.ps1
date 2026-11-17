<#
.SYNOPSIS
  Who could take over this domain, and by which route. Read-only.

.DESCRIPTION
  Everything else in this toolkit answers "is it working?". This answers "who holds the keys?" --
  over plain LDAP through ADAdmin, so it works from outside the forest with no RSAT. It changes
  NOTHING: there is no fix mode, on purpose. Every finding here is a decision about who should
  have access, and that is not a decision a script gets to make.

  Across forests with no trusts between them this is the report nobody has, because privilege
  sprawl is invisible per-forest and there is no single place to look.

  WHAT IT LOOKS FOR

  Membership   Who is in the Tier 0 groups, resolved THROUGH NESTING and reported with the path
               that got them there. Nesting is the point: "Helpdesk -> Tier0-Ops -> Domain Admins"
               is how someone ends up a domain admin without anyone deciding they should be.
               Groups are found by well-known RID, not by name, so this works on a
               non-English domain where the group is called Domanen-Admins.

  Primary group ⭐ A user whose primaryGroupID is 512 IS a domain admin and does NOT appear in the
               group's member list. Nothing that reads membership the obvious way will see them.
               It is a real privilege-hiding technique and a real misconfiguration; both are found
               here.

  Delegation   Unconstrained delegation (userAccountControl 0x80000) lets a host impersonate any
               user who authenticates to it -- including a domain admin -- straight to any service.
               On a non-DC it is a domain-takeover primitive. Constrained delegation is reported
               too, and protocol transition (0x1000000) separately, because that one does not need
               the user to turn up at all. Resource-based delegation is reported where readable.

  Roastable    A USER account with a servicePrincipalName can have a service ticket requested by
               anyone in the domain and cracked offline at leisure -- no privilege needed to ask.
               Accounts with pre-authentication disabled (0x400000) are worse: the crackable
               material can be requested without any credential whatsoever. Both are scored by
               password age, since that is what decides whether cracking is worth anyone's time.

  Hygiene      On privileged principals only: passwords that never expire, PASSWD_NOTREQD
               (0x20 -- an account permitted to have NO password), accounts long idle, and
               accounts DISABLED but still sitting in a Tier 0 group.

  adminCount   Accounts stamped adminCount=1 that are no longer in any protected group. They are
               ex-privileged: AdminSDHolder gave them a locked-down ACL that does not get cleaned
               up, and their presence is a record of privilege somebody removed from the group and
               forgot about.

  krbtgt       The age of the krbtgt password, because that number is the lifetime of any golden
               ticket already minted against this domain.

  ⚠ WHAT IT DOES NOT DO. It does not read ACLs on the domain head, so rights delegated directly
  (DCSync via Replicating Directory Changes, or write access to an OU) are NOT covered -- those
  are a real takeover path and need a different tool. It does not read GPO permissions. It does
  not evaluate password quality. A clean report here is not a clean bill of health.

  ⚠ It reads a lot of the directory. Run it with a READ credential.

.EXAMPLE
  .\Get-AdPrivilegedAccess.ps1 -Target corp.example.com
.EXAMPLE
  .\Get-AdPrivilegedAccess.ps1 -Target corp.example.com -ExportCsv .\tier0.csv
.EXAMPLE
  .\Get-AdPrivilegedAccess.ps1 -Target corp.example.com -Section Delegation,Roastable

.NOTES
  EXIT CODES
    0   ran, nothing found worth reporting
    10  ran, and found something
    30  ran, but at least one section could not be checked
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Target,
    [ValidateSet('Membership', 'Delegation', 'Roastable', 'Hygiene', 'AdminCount', 'Krbtgt')]
    [string[]]$Section,
    [string]$ExportCsv,
    # Days without a logon before a PRIVILEGED account is called idle. Deliberately shorter than
    # the 90 used for ordinary users: an admin account nobody uses is an admin account nobody
    # would notice being used.
    [int]$IdleDays = 60,
    # A password older than this on a roastable account makes it worth cracking.
    [int]$RoastablePasswordAgeDays = 365,
    [int]$Limit = 5000,
    [string]$Tier
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# NOT -Force: a forced import makes a fresh module instance and re-locks the caller's store.
if (-not (Get-Module ADAdmin)) {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'ADAdmin\ADAdmin.psd1')
}

$Sections = if ($Section) { $Section } else { @('Membership', 'Delegation', 'Roastable', 'Hygiene', 'AdminCount', 'Krbtgt') }
function Use-Section { param([string]$Name) $Sections -contains $Name }

$findings = New-Object System.Collections.ArrayList
$couldNotCheck = New-Object System.Collections.ArrayList
$now = (Get-Date).ToUniversalTime()

function Add-Finding {
    param(
        [ValidateSet('critical', 'high', 'warn', 'info')][string]$Severity,
        [string]$Category, [string]$Principal, [string]$Detail, [string]$Why, [string]$Action,
        $Path = $null
    )
    [void]$findings.Add([pscustomobject]@{
        Severity = $Severity; Category = $Category; Principal = $Principal
        Detail = $Detail; Why = $Why; Action = $Action; Via = $Path
    })
}

function Note-Unchecked {
    param([string]$What, [string]$Reason)
    [void]$couldNotCheck.Add([pscustomobject]@{ Check = $What; Reason = $Reason })
    Write-Warning "Could not check $What -- $Reason"
}

# --- userAccountControl bits ------------------------------------------------------------------
# Named rather than inlined, because a bare 0x80000 in a filter is unreviewable.
$UAC_DISABLED          = 0x2
$UAC_PASSWD_NOTREQD    = 0x20
$UAC_DONT_EXPIRE_PASSWD= 0x10000
$UAC_TRUSTED_FOR_DELEG = 0x80000      # unconstrained delegation
$UAC_DONT_REQ_PREAUTH  = 0x400000     # AS-REP roastable
$UAC_TRUSTED_TO_AUTH   = 0x1000000    # constrained delegation WITH protocol transition
$UAC_SERVER_TRUST      = 0x2000       # domain controller

function Test-Uac { param($Value, [int]$Bit) $n = 0; [void][int]::TryParse([string]$Value, [ref]$n); [bool]($n -band $Bit) }

function Get-Age {
    param($FileTime)
    $n = 0L
    if (-not [int64]::TryParse([string]$FileTime, [ref]$n)) { return $null }
    if ($n -le 0 -or $n -eq [int64]::MaxValue) { return $null }
    try { [math]::Round(($now - [datetime]::FromFileTimeUtc($n)).TotalDays, 1) } catch { $null }
}

# ⛔ EVERY READ IN THIS AUDIT GOES THROUGH HERE, WHICH IS WHY THE TRUNCATION CHECK LIVES HERE.
# This script's answer is largely the ABSENCE of findings: no unconstrained delegation, no
# roastable accounts, no adminCount orphans. An object past the size limit is never examined and
# so can never be reported -- a truncated audit does not look short, it looks CLEAN. Recorded as
# unchecked coverage, which already drives the exit-30 path, rather than silently narrowing the
# scope of a security report.
#
# ⚠ The results are BUFFERED rather than streamed, because the flag can only be read once the
# enumeration has finished. That is the price of noticing.
function Search-Dir {
    param([string]$Filter, [string[]]$Properties, [string]$SearchBase, [int]$Max = 0)
    $lim = $(if ($Max) { $Max } else { $Limit })
    $p = @{ Target = $Target; Filter = $Filter; Properties = $Properties; Tier = $Tier; Limit = $lim }
    if ($SearchBase) { $p['SearchBase'] = $SearchBase }
    Reset-AdmSearchTruncated
    $rows = @(Get-AdmSearchResult @p)
    if (Get-AdmSearchTruncated) {
        $short = if ($Filter.Length -gt 70) { $Filter.Substring(0, 70) + '...' } else { $Filter }
        Note-Unchecked "everything matching $short" `
            ("the read stopped at $lim objects, so any past that limit were never examined -- " +
             "this report cannot claim they are clean")
    }
    $rows
}

# --- the domain SID, which every well-known group is keyed off ---------------------------------

$domainSid = $null
try {
    # The domain head object carries the domain SID. Everything Tier 0 is <domainSid>-<RID>.
    $dom = @(Search-Dir -Filter '(objectClass=domainDNS)' -Properties @('objectsid', 'distinguishedname', 'name') -Max 5)[0]
    # ConvertTo-AdmSidString, NOT a local `-is [byte[]]` test -- see the comment on that function.
    # A search returns Object[] of Byte, so the naive check silently produced "1 4 0 0 0 ..." and
    # every "<domainSid>-512" filter built from it matched nothing.
    if ($dom) { $domainSid = ConvertTo-AdmSidString -Raw (Get-AdmRawProp $dom 'objectsid') }
} catch {
    Note-Unchecked 'the domain SID' $_.Exception.Message
}
if (-not $domainSid) {
    Note-Unchecked 'the domain SID' 'the domain object did not return a readable objectSid -- every domain-relative group (Domain Admins, Enterprise Admins, Schema Admins) is therefore UNCHECKED'
}

# Well-known privileged groups. ⭐ BY RID, NOT BY NAME -- these groups are LOCALISED, so a filter
# on 'Domain Admins' silently finds nothing on a German or French domain and reports a clean
# result for the most privileged group in the forest. Domain-relative RIDs need the domain SID;
# the BUILTIN ones are the same constant in every domain on earth.
# Mandatory = exists in EVERY domain, so not finding it means the lookup failed, not that the
# group is absent. Domain Admins reported as empty because a filter silently matched nothing is
# the worst possible output this script could produce, so those two are checked explicitly.
# The rest are legitimately absent in many domains: Enterprise Admins and Schema Admins live only
# in the forest root, Key Admins only from Server 2016, Cert Publishers only where AD CS exists.
$Tier0 = @(
    @{ Rid = 512;  Label = 'Domain Admins';                  Weight = 'critical'; Mandatory = $true }
    @{ Rid = 519;  Label = 'Enterprise Admins';              Weight = 'critical' }
    @{ Rid = 518;  Label = 'Schema Admins';                  Weight = 'critical' }
    @{ Rid = 520;  Label = 'Group Policy Creator Owners';    Weight = 'high' }
    @{ Rid = 517;  Label = 'Cert Publishers';                Weight = 'high' }
    @{ Rid = 526;  Label = 'Key Admins';                     Weight = 'high' }
    @{ Rid = 527;  Label = 'Enterprise Key Admins';          Weight = 'high' }
    @{ Sid = 'S-1-5-32-544'; Label = 'Administrators (BUILTIN)';     Weight = 'critical'; Mandatory = $true }
    @{ Sid = 'S-1-5-32-548'; Label = 'Account Operators (BUILTIN)';  Weight = 'high' }
    @{ Sid = 'S-1-5-32-549'; Label = 'Server Operators (BUILTIN)';   Weight = 'high' }
    @{ Sid = 'S-1-5-32-551'; Label = 'Backup Operators (BUILTIN)';   Weight = 'high' }
    @{ Sid = 'S-1-5-32-550'; Label = 'Print Operators (BUILTIN)';    Weight = 'warn' }
    @{ Sid = 'S-1-5-32-552'; Label = 'Replicator (BUILTIN)';         Weight = 'warn' }
)

$PrincipalProps = @('samaccountname', 'distinguishedname', 'objectclass', 'useraccountcontrol',
                    'admincount', 'serviceprincipalname', 'pwdlastset', 'lastlogontimestamp',
                    'primarygroupid', 'msds-allowedtodelegateto', 'member', 'displayname',
                    'objectsid', 'whencreated')

function Get-ByDn {
    param([string]$Dn)
    # An LDAP filter value must be escaped, and a DN is full of characters that need it.
    $esc = $Dn -replace '\\', '\5c' -replace '\(', '\28' -replace '\)', '\29' -replace '\*', '\2a'
    @(Search-Dir -Filter "(distinguishedName=$esc)" -Properties $PrincipalProps -Max 2)[0]
}

# --- 1. Tier 0 membership, through nesting -----------------------------------------------------

# Every principal that ended up privileged, keyed by DN, so the later sections can score
# "is this account privileged?" without asking the directory again.
$privileged = @{}

if (Use-Section 'Membership') {

    # ⭐ PRE-PASS: resolve every Tier 0 group FIRST, so the walk can tell the difference between
    # nesting that hides privilege and nesting that IS the product's own design.
    #
    # Active Directory ships with Domain Admins and Enterprise Admins nested inside
    # BUILTIN\Administrators. That is true in every domain that has ever existed, so reporting
    # "Administrators -> Domain Admins -> Administrator" as a critical finding is noise -- and
    # noise is how the real finding gets scrolled past. The rule is not a hardcoded exception for
    # those two groups: a path whose intermediate links are ALL themselves Tier 0 groups reveals
    # nothing new, because that member is already reported directly under the inner group. A path
    # through a group that is NOT Tier 0 -- "Domain Admins <- Tier0-Ops <- Helpdesk" -- is the
    # thing nobody decided on, and that is what gets the severity.
    $tier0Dns = @{}
    $resolved = New-Object System.Collections.ArrayList

    foreach ($g in $Tier0) {
        $mandatory = $g.ContainsKey('Mandatory') -and $g.Mandatory
        $sid = if ($g.ContainsKey('Sid')) { $g.Sid } elseif ($domainSid) { "$domainSid-$($g.Rid)" } else { $null }
        if (-not $sid) {
            if ($mandatory) { Note-Unchecked "the group $($g.Label)" 'no usable domain SID, so its RID could not be built' }
            continue
        }
        $grp = $null
        try { $grp = @(Search-Dir -Filter "(objectSid=$sid)" -Properties $PrincipalProps -Max 2)[0] } catch {
            Note-Unchecked "the group $($g.Label)" $_.Exception.Message; continue
        }
        if (-not $grp) {
            if ($mandatory) {
                Note-Unchecked "the group $($g.Label)" "no object matched objectSid=$sid, but this group exists in every domain -- the lookup failed"
            }
            continue
        }
        $tier0Dns[[string](Get-AdmRawProp $grp 'distinguishedname')] = $g.Label
        [void]$resolved.Add([pscustomobject]@{ Spec = $g; Object = $grp })
    }

    foreach ($r in $resolved) {

        $g = $r.Spec

        $group = $r.Object

        $groupDn   = [string](Get-AdmRawProp $group 'distinguishedname')
        $groupName = [string](Get-AdmRawProp $group 'samaccountname')
        if (-not $groupName) { $groupName = [string](Get-AdmRawProp $group 'name') }

        # Recursive expansion, carrying the path. Cycle-safe: AD permits A->B->A and a naive
        # walk hangs on it forever.
        $seen = @{}
        function Expand-Group {
            # $Intermediate carries the DNs of the nested groups walked through to get here --
            # NOT the root group, and not the member. It is what decides whether a path is
            # ordinary AD structure or a route somebody built.
            param($GroupObject, [string[]]$Path, [int]$Depth, [string[]]$Intermediate = @())

            $dn = [string](Get-AdmRawProp $GroupObject 'distinguishedname')
            if ($seen.ContainsKey($dn)) { return }        # already walked -- cycle, or diamond
            $seen[$dn] = $true
            if ($Depth -gt 20) {                          # belt as well as braces
                Note-Unchecked "nesting under $($Path[0])" 'nested more than 20 deep; stopped'
                return
            }

            # ⛔ THE CHECK THAT USED TO BE HERE COULD NEVER FIRE, and it was guarding the most
            # important read in this script. It tested `$members.Count -ge 1500` -- but past 1500
            # AD does not return a SHORT list, it RENAMES the attribute to `member;range=0-1499`,
            # so a plain read finds no `member` property and hands back ZERO. The count is 0, the
            # check never fires, and a privileged group with 3000 members is audited as EMPTY.
            # Get-AdmRangedProp reads the ranged name, so the walk gets the first 1500 AND knows.
            $mem = Get-AdmRangedProp $GroupObject 'member'
            $members = @($mem.Values)
            if ($mem.Truncated) {
                Note-Unchecked "the full membership of $($Path[-1])" `
                    ("AD renamed the attribute past 1500 values; the first $($members.Count) were walked and " +
                     "the rest were NOT. Members beyond that are unexamined and cannot appear in this report.")
            }

            foreach ($mdn in $members) {
                if (-not $mdn) { continue }
                $m = $null
                try { $m = Get-ByDn -Dn ([string]$mdn) } catch { }
                if (-not $m) {
                    # A member DN that does not resolve is usually a ForeignSecurityPrincipal from
                    # another domain, or an orphaned SID left by a deleted account.
                    $kind = if ([string]$mdn -match 'CN=ForeignSecurityPrincipals') { 'a principal from another domain' } else { 'an unresolvable member (likely a deleted account)' }
                    Add-Finding -Severity warn -Category 'Membership' -Principal ([string]$mdn) `
                        -Detail "$kind in $groupName" -Path (($Path + '?') -join ' -> ') `
                        -Why 'A member of a Tier 0 group that cannot be resolved in this domain. If it is a foreign principal it holds privilege here that is granted somewhere you are not looking; if it is orphaned it is noise that hides real members.' `
                        -Action 'Resolve the SID against the domain it came from, or remove it if the account is gone.'
                    continue
                }

                $classes = @(Get-AdmRawProp $m 'objectclass')
                $isGroup = $classes -contains 'group'
                $mName   = [string](Get-AdmRawProp $m 'samaccountname')
                $mDn     = [string](Get-AdmRawProp $m 'distinguishedname')

                if ($isGroup) {
                    Expand-Group -GroupObject $m -Path ($Path + $mName) -Depth ($Depth + 1) `
                                 -Intermediate ($Intermediate + $mDn)
                } else {
                    if (-not $privileged.ContainsKey($mDn)) {
                        $privileged[$mDn] = [pscustomobject]@{ Object = $m; Groups = @() }
                    }
                    $privileged[$mDn].Groups += $groupName

                    $via = ($Path + $mName) -join ' -> '

                    # Only nesting through a group that is NOT itself Tier 0 hides anything. The
                    # default "Administrators -> Domain Admins -> someone" reveals nothing that
                    # the Domain Admins walk does not already report directly, so it stays info.
                    $throughOrdinary = @($Intermediate | Where-Object { -not $tier0Dns.ContainsKey($_) })
                    $hidden = $throughOrdinary.Count -gt 0

                    $sev = if ($hidden) { $g.Weight } else { 'info' }
                    $detail = if ($hidden) {
                        "reaches $groupName through $($throughOrdinary.Count) non-privileged group(s)"
                    } elseif ($Intermediate.Count) {
                        "member of $groupName via $($Path[1]), which is itself a Tier 0 group (this is AD's default structure)"
                    } else {
                        "direct member of $groupName"
                    }
                    $why = if ($hidden) {
                        "Nested membership grants the full rights of $groupName without anyone being added to it. Adding a person to the innermost group is a routine act -- typically delegated to a helpdesk -- that quietly makes them a $groupName, and nothing in the group's own Members tab shows it."
                    } elseif ($Intermediate.Count) {
                        "Expected: Active Directory nests this group inside $groupName by default. Listed for completeness; the membership itself is reported against the inner group."
                    } else {
                        "Holds $groupName directly."
                    }
                    Add-Finding -Severity $sev -Category 'Membership' -Principal $mName -Detail $detail -Path $via `
                        -Why $why `
                        -Action $(if ($hidden) { "Confirm the whole chain is intended -- specifically that '$($throughOrdinary.Count)' ordinary group(s) are meant to confer $groupName. If not, break it at the link that should not carry Tier 0, not at the person." } else { 'Confirm this account still needs it.' })
                }
            }
        }

        Expand-Group -GroupObject $group -Path @($groupName) -Depth 0

        # ⭐ primaryGroupID. A user whose PRIMARY group is this one is a full member and is NOT in
        # the member attribute -- the walk above cannot see them by construction. It is how an
        # attacker hides a domain admin, and also how a badly-scripted account creation makes one
        # by accident.
        if ($g.ContainsKey('Rid')) {
            try {
                $primary = @(Search-Dir -Filter "(&(objectCategory=person)(objectClass=user)(primaryGroupID=$($g.Rid)))" -Properties $PrincipalProps)
                foreach ($p in $primary) {
                    $pName = [string](Get-AdmRawProp $p 'samaccountname')
                    $pDn   = [string](Get-AdmRawProp $p 'distinguishedname')
                    if (-not $privileged.ContainsKey($pDn)) {
                        $privileged[$pDn] = [pscustomobject]@{ Object = $p; Groups = @() }
                    }
                    $privileged[$pDn].Groups += $groupName
                    Add-Finding -Severity 'critical' -Category 'Membership' -Principal $pName `
                        -Detail "has $groupName as its PRIMARY group (primaryGroupID $($g.Rid))" -Path "$groupName (primary group)" `
                        -Why 'A primary group membership carries the same rights as any other, but the account does NOT appear in the group''s member list. Nothing that reads membership the normal way -- including Active Directory Users and Computers'' Members tab -- will show this account. It is a known privilege-hiding technique, and it is also what a careless bulk account creation produces.' `
                        -Action 'Unless this is deliberate, set the primary group back to Domain Users (RID 513) and add the account to the privileged group properly, so it is visible.'
                }
            } catch {
                Note-Unchecked "primary-group membership of $($g.Label)" $_.Exception.Message
            }
        }
    }
}

# If Membership did not run, later sections still need to know who is privileged. adminCount=1 is
# the cheap approximation -- imperfect (it lags, and it over-reports) but far better than nothing.
if (-not (Use-Section 'Membership')) {
    try {
        foreach ($p in @(Search-Dir -Filter '(&(objectCategory=person)(adminCount=1))' -Properties $PrincipalProps)) {
            $privileged[[string](Get-AdmRawProp $p 'distinguishedname')] = [pscustomobject]@{ Object = $p; Groups = @('(adminCount=1)') }
        }
    } catch { Note-Unchecked 'which accounts are privileged' $_.Exception.Message }
}

function Test-Privileged { param([string]$Dn) $privileged.ContainsKey($Dn) }

# --- 2. Delegation -----------------------------------------------------------------------------

if (Use-Section 'Delegation') {
    try {
        # Unconstrained. The filter is a bitwise AND on userAccountControl -- LDAP_MATCHING_RULE_BIT_AND.
        $unc = @(Search-Dir -Filter "(userAccountControl:1.2.840.113556.1.4.803:=$UAC_TRUSTED_FOR_DELEG)" -Properties $PrincipalProps)
        foreach ($o in $unc) {
            $name = [string](Get-AdmRawProp $o 'samaccountname')
            # ⛔ A DOMAIN CONTROLLER HAS THIS BY DESIGN and is not a finding. Reporting every DC
            # here would bury the one host that matters under noise.
            if (Test-Uac (Get-AdmRawProp $o 'useraccountcontrol' 0) $UAC_SERVER_TRUST) { continue }
            Add-Finding -Severity 'critical' -Category 'Delegation' -Principal $name `
                -Detail 'trusted for UNCONSTRAINED delegation' `
                -Why 'Any user who authenticates to this host has their forwardable ticket-granting ticket cached on it, and this host can then impersonate them to ANY service. If a domain admin ever touches it -- or can be made to, which is a one-line coercion -- whoever controls this host controls the domain. Only domain controllers should have it.' `
                -Action 'Turn it off and use constrained delegation naming the specific services, or resource-based delegation set on the target. If the application genuinely requires unconstrained, put its accounts in Protected Users and mark the sensitive accounts "account is sensitive and cannot be delegated".'
        }
        if (-not $unc.Count) { Write-Verbose 'No unconstrained delegation outside domain controllers.' }

        # Protocol transition -- constrained, but does not need the user to appear at all.
        foreach ($o in @(Search-Dir -Filter "(userAccountControl:1.2.840.113556.1.4.803:=$UAC_TRUSTED_TO_AUTH)" -Properties $PrincipalProps)) {
            $name = [string](Get-AdmRawProp $o 'samaccountname')
            $to = @(Get-AdmRawProp $o 'msds-allowedtodelegateto')
            Add-Finding -Severity 'high' -Category 'Delegation' -Principal $name `
                -Detail "constrained delegation WITH protocol transition, to: $($to -join ', ')" `
                -Why 'Protocol transition ("use any authentication protocol") lets this account request a ticket on behalf of any user WITHOUT that user ever authenticating to it. Compromise of this account is compromise of every service listed -- against any user it chooses, including an administrator.' `
                -Action 'Switch to "Kerberos only" if the application can manage it, narrow the service list, and make sure no listed service is on a domain controller.'
        }

        # Plain constrained. Reported at a lower level: it is the RIGHT answer most of the time,
        # and it is here so the list is complete rather than because it is wrong.
        foreach ($o in @(Search-Dir -Filter '(&(msDS-AllowedToDelegateTo=*)(!(userAccountControl:1.2.840.113556.1.4.803:=16777216)))' -Properties $PrincipalProps)) {
            $name = [string](Get-AdmRawProp $o 'samaccountname')
            $to = @(Get-AdmRawProp $o 'msds-allowedtodelegateto')
            $sev = if (@($to | Where-Object { $_ -match '(?i)^(ldap|cifs|host)/' }).Count) { 'high' } else { 'info' }
            Add-Finding -Severity $sev -Category 'Delegation' -Principal $name `
                -Detail "constrained delegation (Kerberos only) to: $($to -join ', ')" `
                -Why $(if ($sev -eq 'high') { 'Constrained delegation is normally fine, but this one is allowed to delegate to LDAP, CIFS or HOST -- on a domain controller those are equivalent to full control of the directory or its filesystem.' } else { 'Constrained delegation, scoped to named services. Listed so the inventory is complete.' }) `
                -Action $(if ($sev -eq 'high') { 'Check whether any listed target is a domain controller. If so, this account is Tier 0 and must be treated as such.' } else { 'No action; confirm the service list is still accurate.' })
        }
    } catch {
        Note-Unchecked 'delegation' $_.Exception.Message
    }

    # Resource-based constrained delegation, where readable. The attribute is a security
    # descriptor; it is reported as PRESENT rather than decoded, because a half-decoded ACL
    # printed as fact is worse than an honest pointer.
    try {
        foreach ($o in @(Search-Dir -Filter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' -Properties @('samaccountname', 'distinguishedname'))) {
            Add-Finding -Severity 'warn' -Category 'Delegation' -Principal ([string](Get-AdmRawProp $o 'samaccountname')) `
                -Detail 'has resource-based constrained delegation configured (msDS-AllowedToActOnBehalfOfOtherIdentity is set)' `
                -Why 'Something has been granted the right to impersonate users TO this host. Unlike the other kinds, this is set on the TARGET, so it does not appear in any list of what an account may delegate -- and any account that can write this attribute on a computer object can grant itself that right.' `
                -Action 'Read the value on the object (Get-ADComputer -Properties PrincipalsAllowedToDelegateToAccount, from a machine with RSAT) and confirm the principal listed is meant to have it. Then check who can WRITE that attribute.'
        }
    } catch {
        Note-Unchecked 'resource-based delegation' $_.Exception.Message
    }
}

# --- 3. Roastable accounts ---------------------------------------------------------------------

if (Use-Section 'Roastable') {
    try {
        # Kerberoastable: a USER (not a computer) with an SPN. krbtgt has one by design.
        $spnUsers = @(Search-Dir -Filter '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' -Properties $PrincipalProps)
        foreach ($o in $spnUsers) {
            $name = [string](Get-AdmRawProp $o 'samaccountname')
            if ($name -eq 'krbtgt') { continue }   # has an SPN by design; covered by its own section
            $dn   = [string](Get-AdmRawProp $o 'distinguishedname')
            $age  = Get-Age (Get-AdmRawProp $o 'pwdlastset')
            $spns = @(Get-AdmRawProp $o 'serviceprincipalname')
            $isPriv = Test-Privileged $dn

            # Severity is about EXPLOITABILITY, not about the SPN existing. A privileged account is
            # critical whatever its password age; an unprivileged one with a recent password is
            # worth knowing about but is not an emergency.
            $sev = if ($isPriv) { 'critical' }
                   elseif ($null -ne $age -and $age -ge $RoastablePasswordAgeDays) { 'high' }
                   else { 'warn' }

            Add-Finding -Severity $sev -Category 'Roastable' -Principal $name `
                -Detail "Kerberoastable: user account with $($spns.Count) SPN(s), password $(if ($null -ne $age) { "$age day(s) old" } else { 'age unknown' })$(if ($isPriv) { ' -- AND IS PRIVILEGED' })" `
                -Path $(if ($isPriv) { ($privileged[$dn].Groups | Select-Object -Unique) -join ', ' } else { $null }) `
                -Why $('Any authenticated user in the domain can request a service ticket for this account and crack it offline at their own pace -- no privilege and no noise. The password''s strength is the only thing protecting it.' +
                       $(if ($isPriv) { ' This account is PRIVILEGED, so cracking it is a direct route to Tier 0.' } else { '' })) `
                -Action $(if ($isPriv) { 'Remove the privilege, or remove the SPN. A privileged account with an SPN should not exist. If the service genuinely needs both, make it a group Managed Service Account (gMSA), where the password is 240 characters and rotates automatically.' } else { 'Move it to a gMSA. Failing that, give it a genuinely long random password (25+ characters) and rotate it.' })
        }

        # AS-REP roastable: pre-authentication disabled.
        foreach ($o in @(Search-Dir -Filter "(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=$UAC_DONT_REQ_PREAUTH))" -Properties $PrincipalProps)) {
            $name = [string](Get-AdmRawProp $o 'samaccountname')
            $dn   = [string](Get-AdmRawProp $o 'distinguishedname')
            $age  = Get-Age (Get-AdmRawProp $o 'pwdlastset')
            $isPriv = Test-Privileged $dn
            Add-Finding -Severity $(if ($isPriv) { 'critical' } else { 'high' }) -Category 'Roastable' -Principal $name `
                -Detail "AS-REP roastable: Kerberos pre-authentication is DISABLED, password $(if ($null -ne $age) { "$age day(s) old" } else { 'age unknown' })$(if ($isPriv) { ' -- AND IS PRIVILEGED' })" `
                -Why 'With pre-authentication off, ANYONE -- with no credential at all, from anywhere that can reach a domain controller -- can ask for material encrypted with this account''s password and crack it offline. It is strictly worse than Kerberoasting, which at least requires a domain account first.' `
                -Action 'Clear "Do not require Kerberos preauthentication" on the account. It is almost always set for a long-dead interoperability reason. If something genuinely depends on it, that thing needs replacing.'
        }
    } catch {
        Note-Unchecked 'roastable accounts' $_.Exception.Message
    }
}

# --- 4. Hygiene on privileged principals -------------------------------------------------------

if (Use-Section 'Hygiene') {
    foreach ($dn in $privileged.Keys) {
        $o = $privileged[$dn].Object
        $name = [string](Get-AdmRawProp $o 'samaccountname')
        $groups = ($privileged[$dn].Groups | Select-Object -Unique) -join ', '
        $uac = Get-AdmRawProp $o 'useraccountcontrol' 0

        if (Test-Uac $uac $UAC_DISABLED) {
            Add-Finding -Severity 'warn' -Category 'Hygiene' -Principal $name -Path $groups `
                -Detail 'is DISABLED but still holds Tier 0 membership' `
                -Why 'A disabled account is not safe, it is dormant. Re-enabling it is a single click and restores full privilege with no further approval -- and it will not stand out, because it was always meant to be there.' `
                -Action 'Remove it from the privileged group. Disabling and de-privileging are different acts; do both.'
        }

        if (Test-Uac $uac $UAC_PASSWD_NOTREQD) {
            Add-Finding -Severity 'critical' -Category 'Hygiene' -Principal $name -Path $groups `
                -Detail 'PASSWD_NOTREQD is set -- this privileged account is permitted to have NO password' `
                -Why 'The flag exempts the account from the domain''s minimum password length, including a length of zero. The account may well have a password today; nothing stops it being set to empty tomorrow, and the domain will accept it.' `
                -Action 'Clear the flag, then set a new password to confirm the policy now applies.'
        }

        if (Test-Uac $uac $UAC_DONT_EXPIRE_PASSWD) {
            Add-Finding -Severity 'high' -Category 'Hygiene' -Principal $name -Path $groups `
                -Detail "password never expires (age $(Get-Age (Get-AdmRawProp $o 'pwdlastset')) day(s))" `
                -Why 'A Tier 0 password that never changes is a Tier 0 password that stays valid for every copy of it ever taken -- from an old backup, a departed admin''s notes, or a credential dump nobody noticed.' `
                -Action 'Either bring it under the expiry policy, or if it is a service account, replace it with a gMSA so rotation is automatic.'
        }

        $idle = Get-Age (Get-AdmRawProp $o 'lastlogontimestamp')
        if ($null -ne $idle -and $idle -ge $IdleDays) {
            Add-Finding -Severity 'high' -Category 'Hygiene' -Principal $name -Path $groups `
                -Detail "privileged and idle for $idle day(s)" `
                -Why 'Nobody is watching this account, and nobody would notice it being used. Unused privilege is the cheapest privilege to steal.' `
                -Action 'If it is still needed, say who owns it. If it is not, remove the membership -- do not merely disable it.'
        }
    }
}

# --- 5. adminCount orphans ---------------------------------------------------------------------

if (Use-Section 'AdminCount') {
    try {
        foreach ($o in @(Search-Dir -Filter '(&(objectCategory=person)(adminCount=1))' -Properties $PrincipalProps)) {
            $dn = [string](Get-AdmRawProp $o 'distinguishedname')
            if (Test-Privileged $dn) { continue }   # currently privileged: expected, not a finding
            $name = [string](Get-AdmRawProp $o 'samaccountname')
            Add-Finding -Severity 'warn' -Category 'AdminCount' -Principal $name `
                -Detail 'adminCount=1 but is in no Tier 0 group now' `
                -Why 'This account WAS privileged. AdminSDHolder stamped it and gave it a protected, non-inheriting ACL, and neither the flag nor the ACL is cleaned up when the membership is removed -- so it keeps an access control list that no longer matches its OU, and normal delegation on that OU does not apply to it. It is also a record of privilege that somebody granted and later withdrew.' `
                -Action 'Confirm the removal was intended. If so, clear adminCount and re-enable inheritance on the object so its permissions match everything around it.'
        }
    } catch {
        Note-Unchecked 'adminCount orphans' $_.Exception.Message
    }
}

# --- 6. krbtgt ---------------------------------------------------------------------------------

if (Use-Section 'Krbtgt') {
    try {
        $k = @(Search-Dir -Filter '(&(objectCategory=person)(sAMAccountName=krbtgt))' -Properties $PrincipalProps -Max 2)[0]
        if (-not $k) {
            Note-Unchecked 'the krbtgt password age' 'the krbtgt account was not returned'
        } else {
            $age = Get-Age (Get-AdmRawProp $k 'pwdlastset')
            if ($null -eq $age) {
                Note-Unchecked 'the krbtgt password age' 'pwdLastSet was not readable'
            } else {
                $sev = if ($age -ge 730) { 'critical' } elseif ($age -ge 365) { 'high' } elseif ($age -ge 180) { 'warn' } else { 'info' }
                Add-Finding -Severity $sev -Category 'Krbtgt' -Principal 'krbtgt' `
                    -Detail "the krbtgt password is $age day(s) old" `
                    -Why 'krbtgt signs every Kerberos ticket in the domain. A golden ticket forged with a stolen krbtgt hash stays valid until that password changes -- so this number is the maximum lifetime of any forgery already committed, and of any yet to be noticed.' `
                    -Action $(if ($sev -eq 'info') { 'Nothing to do; keep it on that schedule.' } else { 'Reset it TWICE, with a full replication cycle plus the maximum ticket lifetime (10 hours by default) between the two resets. Two resets are required because the account keeps its previous password and one reset alone leaves forgeries working. Resetting both in quick succession without waiting WILL break authentication domain-wide -- use Microsoft''s krbtgt reset script rather than doing it by hand.' })
            }
        }
    } catch {
        Note-Unchecked 'the krbtgt password age' $_.Exception.Message
    }
}

# --- output ------------------------------------------------------------------------------------

$order = @{ critical = 0; high = 1; warn = 2; info = 3 }
$sorted = @($findings | Sort-Object @{ Expression = { $order[$_.Severity] } }, Category, Principal)

if ($ExportCsv) {
    $sorted | Export-Csv -LiteralPath $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Verbose "Wrote $($sorted.Count) finding(s) to $ExportCsv"
}

$sorted

$actionable = @($sorted | Where-Object { $_.Severity -ne 'info' })

# Counted with an explicit loop variable. A nested Where-Object inside a ForEach-Object rebinds
# $_ to the INNER pipeline, so `$_.Severity -eq $_` compares a finding against itself and every
# count comes out wrong -- silently, since it still produces a plausible-looking line.
$summary = foreach ($sev in @('critical', 'high', 'warn', 'info')) {
    $n = @($sorted | Where-Object { $_.Severity -eq $sev }).Count
    if ($n) { "$sev $n" }
}
Write-Verbose ("$($sorted.Count) finding(s): " + ((@($summary) -join ', ')))

Write-Warning ('This is a read of group membership, account flags and delegation only. It does NOT read ' +
               'ACLs on the domain head, so rights delegated directly -- DCSync, or write access to an OU -- ' +
               'are not covered and are a real takeover path. A clean report here is not a clean bill of health.')

if ($couldNotCheck.Count) {
    Write-Warning "$($couldNotCheck.Count) check(s) could not run; those areas are UNKNOWN, not clean."
    $couldNotCheck | Format-Table -AutoSize | Out-String | Write-Verbose
    exit 30
}
if ($actionable.Count) { exit 10 }
exit 0
