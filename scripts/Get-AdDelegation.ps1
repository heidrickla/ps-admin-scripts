<#
.SYNOPSIS
  Who has been GRANTED control of this domain in its ACLs, including DCSync. Read-only.

.DESCRIPTION
  Get-AdPrivilegedAccess answers "who is in the groups?". This answers the other half: "who was
  given the rights directly?" -- and says so by reading nTSecurityDescriptor, which that script
  explicitly does not do. Rights delegated in an ACL grant everything a group membership grants
  and appear in no membership list, no Members tab, and no report built on `member`. It is where
  real domain takeover lives.

  It changes NOTHING, and there is no fix mode, for the same reason as the privilege audit: every
  finding here is a decision about who should have access, and that is not a decision a script
  gets to make. Removing an ACE you do not understand breaks Exchange, Entra Connect, a backup
  agent, or replication -- quietly, and later.

  WHAT IT LOOKS FOR

  DCSync       A principal holding BOTH DS-Replication-Get-Changes and
               DS-Replication-Get-Changes-All on the DOMAIN HEAD can ask a domain controller to
               hand over every password hash in the domain, over a normal replication call, from
               anywhere. It is not an exploit; it is the API working as designed.
               ⭐ BOTH rights are required, and that single rule does most of the work: measured
               on a clean Server 2025 domain, `Domain Controllers` holds only -All and
               `Enterprise Domain Controllers` holds only -Get, so neither is DCSync-capable and
               neither needs an exception. See .NOTES.

  Containers   GenericAll, WriteDacl, WriteOwner, write-all-properties, and WriteProperty on
               `member`, on the domain head, on every OU, and on the containers that hold accounts.
               WriteDacl is the quiet one: it is not control, it is the right to GRANT yourself
               control, and it leaves the object looking untouched until it is used.

  Privileged   Non-inherited ACEs on Tier 0 groups and accounts. ⚠ On an AdminSDHolder-protected
               object EVERY ACE is non-inherited by design -- measured, 23 of 23 on Domain Admins
               -- so "non-inherited" alone is noise. What is reported is a non-inherited grant of
               a DANGEROUS right to a principal the domain did not ship with.

  Owner        The owner of an object can rewrite its DACL whatever the DACL says, so an owner
               that is not a built-in is equivalent to full control and is invisible to any
               review that reads permissions only.

  AdminSDHolder Whatever is granted on CN=AdminSDHolder,CN=System is stamped by SDProp onto every
               protected account in the domain, roughly hourly. It is a persistence mechanism
               that survives cleaning up the accounts themselves.

  ShadowCred   Write access to msDS-KeyCredentialLink lets the holder add a certificate to an
               account and then authenticate AS it, with no password and no password change.
               ⚠ It can be granted three different ways -- the attribute GUID, the
               Private-Information PROPERTY SET that contains it, or write-all-properties -- and
               all three are checked. The default grant of it to SELF is not a finding.

  ⚠ WHAT IT DOES NOT DO. It does not read GPO permissions, SYSVOL filesystem ACLs, the
  Configuration or Schema naming contexts, or the ACLs of individual user and computer objects
  outside Tier 0. It does not read the SACL (auditing). A clean report here is not a clean bill
  of health, and it does not replace Get-AdPrivilegedAccess -- run both.

  ⚠ An object whose DACL cannot be READ is reported as UNCHECKED, never as clean. A missing
  nTSecurityDescriptor looks exactly like an object with no dangerous ACEs, and that is the one
  way this script could lie.

.EXAMPLE
  .\Get-AdDelegation.ps1 -Target corp.example.com
.EXAMPLE
  .\Get-AdDelegation.ps1 -Target corp.example.com -ExportCsv .\delegation.csv
.EXAMPLE
  .\Get-AdDelegation.ps1 -Target corp.example.com -Section DCSync,AdminSDHolder

.NOTES
  EXIT CODES
    0   ran, nothing found worth reporting
    10  ran, and found something
    20  a change failed  (unreachable here -- this script never writes)
    30  ran, but at least one object or section could NOT be checked

  VERIFIED LIVE against a lab domain controller (corp.example.com, Windows Server 2025) on 2026-08-28:
    - nTSecurityDescriptor reads back as Object[] of Byte, 2468 bytes on the domain head with
      SecurityMasks Owner+Group+Dacl, and ActiveDirectorySecurity parses it.
    - The DCSync rule was run against the real domain-head DACL. With correct mask arithmetic it
      names exactly SYSTEM, BUILTIN\Administrators, Domain Admins and Enterprise Admins -- all of
      which reach it through an "all extended rights" ACE.
      ⛔ With the NAIVE mask test (`-band GenericAll -ne 0`) the same DACL produced SIXTEEN
      "DCSync-capable" principals including Everyone, Authenticated Users and CREATOR OWNER. That
      test is wrong because GenericAll is a COMPOSITE mask (0xF01FF) and plain ReadProperty
      (0x10) shares bits with it. See Test-Right below; it is pinned in Delegation.Tests.ps1.
    - Enterprise Domain Controllers (S-1-5-9) holds -Get but NOT -All; Domain Controllers
      (RID 516) holds -All but NOT -Get. Neither is DCSync-capable under the both-rights rule.
    - Every ACE on Domain Admins, Enterprise Admins, Schema Admins and BUILTIN\Administrators is
      non-inherited (23 of 23) -- AdminSDHolder disables inheritance.
    - GUIDs read from this forest's schema, not from memory:
        DS-Replication-Get-Changes      1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
        DS-Replication-Get-Changes-All  1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
        member                          bf9679c0-0de6-11d0-a285-00aa003049e2
        msDS-KeyCredentialLink          5b47d60f-6090-40b2-9f37-2a4de88f3063
        Private-Information (prop set)  91e647de-d96f-4b70-9557-d63ff4f3ccd8
  NOT VERIFIED: no domain was available with a genuinely dangerous delegation on it, so the
  positive findings are exercised by Delegation.Tests.ps1 offline, not against a directory.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Target,
    [ValidateSet('DCSync', 'Containers', 'Privileged', 'Owner', 'AdminSDHolder', 'ShadowCred')]
    [string[]]$Section,
    [string]$ExportCsv,
    # Containers scanned as well as every OU. Deliberately NOT the whole of CN=System: measured on
    # a bare domain, "(|(objectCategory=organizationalUnit)(objectClass=container))" returns 122
    # objects, almost all of them GPO and service containers nobody delegates. Scanning them turns
    # the report into a directory listing.
    [string[]]$ExtraContainer = @('CN=Users', 'CN=Computers', 'CN=Managed Service Accounts'),
    [int]$Limit = 5000,
    [string]$Tier
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# NOT -Force: a forced import makes a fresh module instance and re-locks the caller's store.
if (-not (Get-Module ADAdmin)) {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'ADAdmin\ADAdmin.psd1')
}
Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop

$Sections = if ($Section) { $Section } else { @('DCSync', 'Containers', 'Privileged', 'Owner', 'AdminSDHolder', 'ShadowCred') }
function Use-Section { param([string]$Name) $Sections -contains $Name }

$findings      = New-Object System.Collections.ArrayList
$couldNotCheck = New-Object System.Collections.ArrayList

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

# Set by Get-AdDelegationObject when a search stopped at its size limit. Sticky: the caller clears
# it before a read it intends to check, exactly as the module's Get-AdmSearchTruncated works.
$script:DelegationReadTruncated = $false

# --- the GUIDs ---------------------------------------------------------------------------------
# Every one of these was READ OUT OF THE SCHEMA of a live forest rather than copied from memory
# (see .NOTES). They are constants across every Active Directory deployment, which is why they can
# be baked in at all; the verification is what makes that safe rather than hopeful.
$GUID_REPL_GET     = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'   # DS-Replication-Get-Changes
$GUID_REPL_ALL     = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'   # DS-Replication-Get-Changes-All
$GUID_MEMBER       = [guid]'bf9679c0-0de6-11d0-a285-00aa003049e2'   # the `member` attribute
$GUID_KEYCRED      = [guid]'5b47d60f-6090-40b2-9f37-2a4de88f3063'   # msDS-KeyCredentialLink
$GUID_PRIVATE_INFO = [guid]'91e647de-d96f-4b70-9557-d63ff4f3ccd8'   # Private-Information property set
$GUID_NONE         = [guid]::Empty                                  # "applies to everything"

# --- rights ------------------------------------------------------------------------------------
$R = [System.DirectoryServices.ActiveDirectoryRights]
$RIGHT_GENERIC_ALL    = [int]$R::GenericAll        # 0xF01FF -- a COMPOSITE, not a single bit
$RIGHT_WRITE_DACL     = [int]$R::WriteDacl         # 0x40000
$RIGHT_WRITE_OWNER    = [int]$R::WriteOwner        # 0x80000
$RIGHT_WRITE_PROPERTY = [int]$R::WriteProperty     # 0x20
$RIGHT_EXTENDED       = [int]$R::ExtendedRight     # 0x100
$RIGHT_SELF           = [int]$R::Self              # 0x8

# ⛔ THE MASK TEST. `($mask -band $want) -ne 0` is WRONG for any composite right and it fails
# CATASTROPHICALLY QUIETLY: GenericAll is 0xF01FF, so a harmless ReadProperty (0x10) ACE satisfies
# it. Measured on a lab domain controller -- the naive form reported Everyone, Authenticated Users and CREATOR OWNER
# as able to DCSync the domain, from a DACL where none of them can. A report that cries wolf about
# Everyone is a report nobody reads twice.
function Test-AdDelegationRight {
    param([int]$Mask, [int]$Want)
    ($Mask -band $Want) -eq $Want
}

# --- resolving the target ----------------------------------------------------------------------

$ctx = $null
try { $ctx = Get-AdmTargetContextPublic -Target $Target -Tier $Tier } catch {
    Write-Error "Could not resolve '$Target' to a registered domain and credential: $($_.Exception.Message)"
    exit 30
}
$domainDn = ConvertTo-AdmDistinguishedName -DnsDomain $ctx.Domain.DnsDomain

# ⭐ THE MODULE'S OWN SEARCH CANNOT BE USED FOR THIS.
#
# Invoke-AdmAdsiSearch does not set DirectorySearcher.SecurityMasks, so the LDAP_SERVER_SD_FLAGS
# control is never sent and the server returns whichever parts of the descriptor it feels the
# caller may have -- including the SACL, which needs SeSecurityPrivilege. Measured on a lab domain controller as
# Domain Admin: 2668 bytes without the control, 2468 with Owner+Group+Dacl. The extra 200 bytes
# are audit entries this script has no use for and a read-tier account has no right to.
#
# Asking for exactly Owner+Group+Dacl is the difference between a query that works with an
# ordinary read credential and one that depends on being an administrator. So the searcher is
# built here rather than in the module -- the module is not modified by this script.
#
# ⚠ THIS IS NOT Set-AdmDaclMask, AND IT MUST NOT BE. That helper pins
# DirectoryEntry.Options.SecurityMasks to Dacl ONLY, which is right for the protected-from-deletion
# check it was written for and wrong here for two reasons: it governs the ENTRY path
# (entry.ObjectSecurity), not the SEARCHER path used below, and dropping Owner would make the
# ownership section report "no owner" on every object it looks at. The SACL -- the part that
# actually needs SeSecurityPrivilege, and the reason that helper exists -- is excluded here too.
function Get-AdDelegationObject {
    param(
        [string]$Filter,
        [string[]]$Properties,
        [string]$SearchBase,
        [int]$SizeLimit = 200,
        [switch]$WithDescriptor,
        # Base scope: read THIS object, not the subtree under it. Named for what it does -- a
        # switch called -OneLevel that sets SearchScope::Base is a comment that lies.
        [switch]$BaseOnly
    )
    $root = New-AdmDirectoryEntry -Domain $ctx.Domain -Credential $ctx.Credential -DistinguishedName $SearchBase
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
        try {
            $searcher.Filter = $Filter
            # ⛔ ONE ROW MORE THAN WE RETURN, so the extra row IS the truncation signal. This
            # matters more in an AUDIT than anywhere else: a truncated sweep does not report a
            # short list, it reports NOTHING WRONG. "No dangerous delegation found" computed from
            # 5000 of 9000 OUs is a clean bill of health for a domain that was never fully read.
            $searcher.SizeLimit = Get-AdmOverfetchLimit $SizeLimit
            $searcher.PageSize = 500
            $searcher.SearchScope = if ($BaseOnly) { [System.DirectoryServices.SearchScope]::Base }
                                    else { [System.DirectoryServices.SearchScope]::Subtree }
            if ($WithDescriptor) {
                $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Owner -bor `
                                          [System.DirectoryServices.SecurityMasks]::Group -bor `
                                          [System.DirectoryServices.SecurityMasks]::Dacl
            }
            foreach ($p in $Properties) { [void]$searcher.PropertiesToLoad.Add($p) }
            $results = $searcher.FindAll()
            try {
                $n = 0
                foreach ($r in $results) {
                    $n++
                    if ($SizeLimit -gt 0 -and $n -gt $SizeLimit) { $script:DelegationReadTruncated = $true; break }
                    # Same normalisation the module does, so Get-AdmRawProp works on the result and
                    # an unset attribute is ABSENT rather than $null -- which under StrictMode 2.0
                    # is the difference between a missing value and a thrown exception.
                    $o = [ordered]@{}
                    foreach ($name in $r.Properties.PropertyNames) {
                        $vals = @($r.Properties[$name])
                        $o[$name] = if ($vals.Count -eq 1) { $vals[0] } else { $vals }
                    }
                    [pscustomobject]$o
                }
            } finally { $results.Dispose() }
        } finally { $searcher.Dispose() }
    } finally { Close-AdmDirectoryEntry $root }
}

# --- the domain SID ----------------------------------------------------------------------------

$domainSid = $null
try {
    $head = @(Get-AdDelegationObject -Filter '(objectClass=domainDNS)' -Properties @('objectsid', 'distinguishedname') -SearchBase $domainDn -SizeLimit 5)[0]
    # ConvertTo-AdmSidString, never a local `-is [byte[]]` test: a search hands binary attributes
    # back as Object[] of Byte, so the naive check is false every time and the fallback yields
    # the bytes space-joined. That silently emptied Domain Admins once already.
    if ($head) { $domainSid = ConvertTo-AdmSidString -Raw (Get-AdmRawProp $head 'objectsid') }
} catch { Note-Unchecked 'the domain SID' $_.Exception.Message }
if (-not $domainSid) {
    Note-Unchecked 'the domain SID' 'the domain object returned no readable objectSid, so no domain-relative principal (Domain Admins, Domain Users, the RID rule) can be classified -- every "is this a built-in?" answer below is therefore a guess and is reported as unknown'
}

# --- classifying a principal -------------------------------------------------------------------

# Well-known SIDs that are the directory's own machinery. Names are carried because these do NOT
# exist as directory objects -- (objectSid=S-1-1-0) returns nothing on a real DC, measured.
$WellKnown = @{
    'S-1-1-0'    = 'Everyone'
    'S-1-3-0'    = 'CREATOR OWNER'
    'S-1-5-4'    = 'INTERACTIVE'
    'S-1-5-7'    = 'ANONYMOUS LOGON'
    'S-1-5-9'    = 'Enterprise Domain Controllers'
    'S-1-5-10'   = 'SELF'
    'S-1-5-11'   = 'Authenticated Users'
    'S-1-5-18'   = 'SYSTEM'
    'S-1-5-19'   = 'LOCAL SERVICE'
    'S-1-5-20'   = 'NETWORK SERVICE'
    'S-1-5-32-544' = 'BUILTIN\Administrators'
    'S-1-5-32-548' = 'BUILTIN\Account Operators'
    'S-1-5-32-549' = 'BUILTIN\Server Operators'
    'S-1-5-32-551' = 'BUILTIN\Backup Operators'
    'S-1-5-32-554' = 'BUILTIN\Pre-Windows 2000 Compatible Access'
}

# ⛔ "BUILT-IN" MEANS "ACTIVE DIRECTORY SHIPPED IT", NOT "IT IS SAFE".
# Everyone, Authenticated Users, Domain Users and Domain Computers are all built-in and all
# catastrophic to hand a takeover right to. They are ALWAYS reported, and reported harder, which
# is why this list exists separately from Test-AdDelegationBuiltIn rather than as an entry in it.
function Test-AdDelegationBroadPrincipal {
    param([string]$Sid)
    if (@('S-1-1-0', 'S-1-5-7', 'S-1-5-11', 'S-1-5-4', 'S-1-5-32-545', 'S-1-5-32-546', 'S-1-5-32-554') -contains $Sid) { return $true }
    if ($domainSid) {
        # 513 Domain Users, 514 Domain Guests, 515 Domain Computers, 501 Guest.
        foreach ($rid in @(513, 514, 515, 501)) { if ($Sid -eq "$domainSid-$rid") { return $true } }
    }
    $false
}

# ⭐ THE RID RULE. Every principal Active Directory creates for itself gets a RID below 1000; the
# RID pool for anything a human or a product creates starts at 1000. So "domain SID + RID < 1000"
# is an exact test for "the domain came with this", with no name matching and no localisation
# problem -- the same reason the privilege audit keys groups by RID.
function Test-AdDelegationBuiltIn {
    param([string]$Sid)
    if (-not $Sid) { return $false }
    if ($Sid -like 'S-1-5-32-*') { return $true }          # BUILTIN\*
    if ($WellKnown.ContainsKey($Sid)) { return $true }
    if ($Sid -like 'S-1-5-80-*') { return $true }          # NT SERVICE\* virtual accounts
    if ($domainSid -and $Sid -like "$domainSid-*") {
        $rid = 0
        $tail = $Sid.Substring($domainSid.Length + 1)
        if ([int]::TryParse($tail, [ref]$rid)) { return ($rid -lt 1000) }
    }
    $false
}

$sidNames = @{}
function Resolve-AdDelegationSid {
    param([string]$Sid)
    if (-not $Sid) { return '(no SID)' }
    if ($sidNames.ContainsKey($Sid)) { return $sidNames[$Sid] }
    $name = $null
    try {
        # ⚠ objectSid, and DELIBERATELY no objectClass constraint. A name-based lookup would need
        # one -- (name=DC01) in the domain NC also matches the AD-integrated DNS node of the same
        # name -- but objectSid is unique by construction, and narrowing to user/group/computer
        # here would drop the ForeignSecurityPrincipal objects, which are exactly the holders this
        # script most needs to name.
        $o = @(Get-AdDelegationObject -Filter "(objectSid=$Sid)" -Properties @('samaccountname', 'name', 'distinguishedname') -SearchBase $domainDn -SizeLimit 2)[0]
        if ($o) {
            # ⚠ Get-AdmRawProp, not `$o.samaccountname`. A ForeignSecurityPrincipal has NO
            # samAccountName -- measured: (objectSid=S-1-5-11) returns the FSP under
            # CN=ForeignSecurityPrincipals with only a name -- and StrictMode makes reading a
            # missing property a terminating error that takes the whole scan with it.
            $name = [string](Get-AdmRawProp $o 'samaccountname')
            if (-not $name) { $name = [string](Get-AdmRawProp $o 'name') }
        }
    } catch { }
    if (-not $name -and $WellKnown.ContainsKey($Sid)) { $name = $WellKnown[$Sid] }
    if (-not $name -and $Sid -like 'S-1-5-32-*') {
        # ⚠ .NET translation ONLY for the well-known ranges. Calling Translate() on an arbitrary
        # S-1-5-21 SID from an untrusted forest goes out on the network and blocks; the well-known
        # ranges are answered locally with no traffic at all.
        try { $name = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { }
    }
    if (-not $name) {
        # ⛔ NOT dropped. A SID that resolves nowhere is either a principal from another domain
        # holding rights here, or the tombstone of a deleted account -- and the first of those is
        # a finding in its own right. Silently omitting it would report the object as clean.
        $name = if ($domainSid -and $Sid -like "$domainSid-*") { "$Sid (ORPHANED -- deleted account in this domain)" }
                else { "$Sid (FOREIGN or unresolvable)" }
    }
    $sidNames[$Sid] = $name
    $name
}

# --- reading one object's DACL -----------------------------------------------------------------

# ⚠ CACHED, and the failures are cached too. The domain head and each Tier 0 object are wanted by
# four different sections, and without this each one re-binds, re-reads and -- when the object is
# unreadable -- records the SAME object as unchecked four times, inflating the count that decides
# exit 30 into something an operator cannot reconcile with the list.
$daclCache = @{}

# Returns $null when the descriptor could not be read, which the callers must treat as UNKNOWN.
# -Optional marks an object that may legitimately not exist (a redirected or renamed container);
# absence is then a verbose note, while an object that exists and cannot be READ is always
# unchecked.
function Get-AdDelegationDacl {
    param([string]$Dn, [string]$Label, [switch]$Optional)
    if ($daclCache.ContainsKey($Dn)) { return $daclCache[$Dn] }
    $daclCache[$Dn] = $null      # cache the failure up front; every early return below keeps it

    $obj = $null
    try {
        $obj = @(Get-AdDelegationObject -Filter '(objectClass=*)' -Properties @('distinguishedname', 'ntsecuritydescriptor') -SearchBase $Dn -SizeLimit 2 -WithDescriptor -BaseOnly)[0]
    } catch {
        # Measured on a lab domain controller: a search base that does not exist comes back as
        # "No object with that name exists in this domain. ... There is no such object on the
        # server." That is a different fact from "the DACL could not be read", and conflating them
        # makes a domain whose Users container was redirected look like a domain we failed to audit.
        if ($Optional -and $_.Exception.Message -match '(?i)no such object|No object with that name') {
            Write-Verbose "$Label does not exist in this domain; skipped."
            return $null
        }
        Note-Unchecked "the ACL of $Label" $_.Exception.Message
        return $null
    }
    if (-not $obj) {
        if ($Optional) { Write-Verbose "$Label does not exist in this domain; skipped."; return $null }
        Note-Unchecked "the ACL of $Label" 'the object did not come back from the directory'
        return $null
    }
    $raw = Get-AdmRawProp $obj 'ntsecuritydescriptor'
    if (-not $raw) {
        # ⛔ THE ONE WAY THIS SCRIPT COULD LIE. An unreadable DACL is ABSENT, not empty, and an
        # absent DACL is indistinguishable from an object with nothing dangerous on it. Whoever
        # ran this needs to know the answer for this object is "we do not know".
        Note-Unchecked "the ACL of $Label" 'nTSecurityDescriptor was not returned -- the credential has no READ_CONTROL on the object, so its permissions are UNKNOWN, not clean'
        return $null
    }
    try {
        $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity
        # [byte[]]@($raw): the @() then hard cast is what turns Object[]-of-Byte into a real
        # byte[]. Passing $raw straight in throws on the method signature.
        $sec.SetSecurityDescriptorBinaryForm([byte[]]@($raw))
    } catch {
        Note-Unchecked "the ACL of $Label" "the security descriptor did not parse: $($_.Exception.Message)"
        return $null
    }
    $owner = $null
    try { $owner = $sec.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { }
    $rules = @()
    try { $rules = @($sec.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) } catch {
        Note-Unchecked "the ACEs of $Label" $_.Exception.Message
        return $null
    }
    $daclCache[$Dn] = [pscustomobject]@{ Dn = $Dn; Label = $Label; Owner = $owner; Rules = $rules }
    $daclCache[$Dn]
}

# Which dangerous rights does one ACE carry? Named, so the finding text can say what was granted
# rather than printing a hex mask at an operator.
#
# ⚠ Deliberately a sequence of tests, NOT a mask -> name lookup table. An `[ordered]@{ 0x20 = ... }`
# indexed by an integer does a POSITIONAL lookup rather than a key lookup, so a high bit like
# WriteDacl (0x40000) runs off the end and returns $null with no error at all. A right that is
# silently never decoded is a finding that is silently never reported.
function Get-AdDelegationAceKind {
    param($Ace)
    $mask = [int]$Ace.ActiveDirectoryRights
    $objType = $Ace.ObjectType
    $out = @()
    if (Test-AdDelegationRight $mask $RIGHT_GENERIC_ALL)  { $out += 'GenericAll (full control)' }
    if (Test-AdDelegationRight $mask $RIGHT_WRITE_DACL)   { $out += 'WriteDacl (can grant itself anything)' }
    if (Test-AdDelegationRight $mask $RIGHT_WRITE_OWNER)  { $out += 'WriteOwner (can take ownership)' }
    if ((Test-AdDelegationRight $mask $RIGHT_WRITE_PROPERTY) -and $objType -eq $GUID_NONE) { $out += 'WriteProperty on ALL attributes' }
    if ((Test-AdDelegationRight $mask $RIGHT_WRITE_PROPERTY) -and $objType -eq $GUID_MEMBER) { $out += 'WriteProperty on `member` (can add anyone to this group)' }
    # Self on `member` is "add or remove SELF as a member" -- a validated write, much narrower
    # than WriteProperty, but on a Tier 0 group it is still "make myself a domain admin".
    if ((Test-AdDelegationRight $mask $RIGHT_SELF) -and $objType -eq $GUID_MEMBER) { $out += 'Self on `member` (can add ITSELF to this group)' }
    $out
}

# Should this ACE be reported at all? Deny ACEs are not a delegation of power, inherited ACEs are
# reported against the container they came from, and SELF is the object acting on itself.
function Test-AdDelegationReportableAce {
    param($Ace)
    if ("$($Ace.AccessControlType)" -ne 'Allow') { return $false }
    if ("$($Ace.IdentityReference)" -eq 'S-1-5-10') { return $false }   # SELF -- by design
    $true
}

# --- 1. DCSync on the domain head --------------------------------------------------------------

if (Use-Section 'DCSync') {
    $acl = Get-AdDelegationDacl -Dn $domainDn -Label "the domain head ($domainDn)"
    if ($acl) {
        # Collected per principal FIRST, because the two rights are usually two separate ACEs and
        # neither one alone means anything. This is the whole rule.
        $repl = @{}
        foreach ($ace in $acl.Rules) {
            if ("$($ace.AccessControlType)" -ne 'Allow') { continue }
            $sid = "$($ace.IdentityReference)"
            $mask = [int]$ace.ActiveDirectoryRights
            if (-not $repl.ContainsKey($sid)) { $repl[$sid] = [pscustomobject]@{ Get = $false; All = $false; Route = @() } }

            if (Test-AdDelegationRight $mask $RIGHT_GENERIC_ALL) {
                $repl[$sid].Get = $true; $repl[$sid].All = $true; $repl[$sid].Route += 'GenericAll on the domain'
            }
            if (Test-AdDelegationRight $mask $RIGHT_EXTENDED) {
                if ($ace.ObjectType -eq $GUID_NONE) {
                    # An ExtendedRight ACE with no ObjectType is EVERY extended right, which
                    # includes both replication rights. Measured: this is how all four default
                    # holders on a clean domain actually get DCSync.
                    $repl[$sid].Get = $true; $repl[$sid].All = $true; $repl[$sid].Route += 'all extended rights on the domain'
                }
                if ($ace.ObjectType -eq $GUID_REPL_GET) { $repl[$sid].Get = $true; $repl[$sid].Route += 'DS-Replication-Get-Changes' }
                if ($ace.ObjectType -eq $GUID_REPL_ALL) { $repl[$sid].All = $true; $repl[$sid].Route += 'DS-Replication-Get-Changes-All' }
            }
        }

        $capable = 0
        foreach ($sid in $repl.Keys) {
            $r = $repl[$sid]
            # ⭐ BOTH, OR IT IS NOT DCSYNC. Measured on a clean domain: Domain Controllers holds
            # -All alone and Enterprise Domain Controllers holds -Get alone. Reporting either as a
            # DCSync holder would be wrong on every domain in existence.
            if (-not ($r.Get -and $r.All)) { continue }
            $capable++
            $name = Resolve-AdDelegationSid $sid
            $route = (@($r.Route | Select-Object -Unique) -join ' + ')
            $broad = Test-AdDelegationBroadPrincipal $sid
            $builtIn = Test-AdDelegationBuiltIn $sid

            if ($broad) {
                Add-Finding -Severity 'critical' -Category 'DCSync' -Principal $name -Path $route `
                    -Detail "holds BOTH replication rights on the domain head -- and is a group that effectively contains everybody" `
                    -Why 'This principal can run a replication request against a domain controller and be handed the password hash of every account in the domain, including krbtgt and every domain admin. Because the principal is a broad group, that means any authenticated account -- or on Everyone, any account at all -- can do it. This is domain compromise, present tense, not a risk of one.' `
                    -Action 'Treat the domain as compromised until proven otherwise: reset krbtgt twice (with a replication cycle between), then remove this ACE. Find out what added it -- an ACE granting replication to a broad group is not something a product installer does by accident.'
            } elseif (-not $builtIn) {
                Add-Finding -Severity 'critical' -Category 'DCSync' -Principal $name -Path $route `
                    -Detail 'holds BOTH DS-Replication-Get-Changes and DS-Replication-Get-Changes-All on the domain head' `
                    -Why 'Together those two rights are DCSync: the holder can ask any domain controller to replicate secrets to it and receive the password hash of every account in the domain -- krbtgt included, which is a golden ticket. No group membership is involved, so this appears in no membership audit and on no Members tab. It is the single most valuable permission in Active Directory.' `
                    -Action "Confirm this is a deliberate grant to a known product (Entra Connect, a password-sync agent, a migration tool). If it is, the account holding it is TIER 0 and must be managed as a domain admin is: no shared password, no logon to workstations, monitored. If it is not recognised, remove it and reset krbtgt twice."
            } else {
                # Named, not silently dropped: showing the expected holders is how the operator can
                # tell "the check ran and found the normal four" from "the check found nothing".
                Add-Finding -Severity 'info' -Category 'DCSync' -Principal $name -Path $route `
                    -Detail 'holds both replication rights (a built-in principal -- expected)' `
                    -Why 'SYSTEM, BUILTIN\Administrators, Domain Admins and Enterprise Admins reach the replication rights through an "all extended rights" ACE that Active Directory places on the domain head when the domain is created. Listed so this section is visibly complete rather than silently empty.' `
                    -Action 'None. Confirm the list contains nothing else.'
            }
        }
        if (-not $capable) {
            Note-Unchecked 'DCSync' 'the domain head DACL parsed but NOT ONE principal holds both replication rights -- not even SYSTEM or Domain Admins, which every domain grants. That is not a clean result, it means the ACEs were not read correctly'
        }
    }
}

# --- 2. dangerous rights on the domain head, the OUs and the account containers -----------------

# Built while section 2 runs and reused by sections 3, 4 and 6.
$tier0Dns = @{}
if ($domainSid) {
    foreach ($spec in @(
        @{ Sid = "$domainSid-512"; Label = 'Domain Admins' }
        @{ Sid = "$domainSid-519"; Label = 'Enterprise Admins' }
        @{ Sid = "$domainSid-518"; Label = 'Schema Admins' }
        @{ Sid = "$domainSid-520"; Label = 'Group Policy Creator Owners' }
        @{ Sid = "$domainSid-526"; Label = 'Key Admins' }
        @{ Sid = "$domainSid-527"; Label = 'Enterprise Key Admins' }
        @{ Sid = "$domainSid-502"; Label = 'krbtgt' }
        @{ Sid = "$domainSid-500"; Label = 'the built-in Administrator account' }
        @{ Sid = 'S-1-5-32-544';   Label = 'BUILTIN\Administrators' }
        @{ Sid = 'S-1-5-32-548';   Label = 'BUILTIN\Account Operators' }
        @{ Sid = 'S-1-5-32-551';   Label = 'BUILTIN\Backup Operators' }
    )) {
        try {
            $o = @(Get-AdDelegationObject -Filter "(objectSid=$($spec.Sid))" -Properties @('distinguishedname', 'samaccountname') -SearchBase $domainDn -SizeLimit 2)[0]
            if ($o) { $tier0Dns[[string](Get-AdmRawProp $o 'distinguishedname')] = $spec.Label }
        } catch {
            Note-Unchecked "the location of $($spec.Label)" $_.Exception.Message
        }
    }
    if (-not $tier0Dns.Count) {
        Note-Unchecked 'which objects are Tier 0' 'not one well-known privileged group resolved, so nothing below can be scored as privileged'
    }
}

function Test-AdDelegationTier0Container {
    param([string]$Dn)
    # The Domain Controllers OU is Tier 0 by content: write access there is write access to the
    # computer accounts of the domain controllers themselves.
    if ($Dn -match '(?i)^OU=Domain Controllers,') { return $true }
    # ⚠ EndsWith, not -like. A DN is user-supplied text and an OU named "Team [A]" turns a -like
    # pattern into a character class that matches nothing -- silently downgrading a Tier 0
    # container to an ordinary one.
    foreach ($t in $tier0Dns.Keys) {
        if ([string]$t -and ([string]$t).EndsWith(",$Dn", [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    $false
}

if (Use-Section 'Containers') {
    $targets = New-Object System.Collections.ArrayList
    [void]$targets.Add([pscustomobject]@{ Dn = $domainDn; Label = "the domain head ($domainDn)"; Tier0 = $true })

    try {
        $script:DelegationReadTruncated = $false
        foreach ($ou in @(Get-AdDelegationObject -Filter '(objectCategory=organizationalUnit)' -Properties @('distinguishedname') -SearchBase $domainDn -SizeLimit $Limit)) {
            $dn = [string](Get-AdmRawProp $ou 'distinguishedname')
            if ($dn) { [void]$targets.Add([pscustomobject]@{ Dn = $dn; Label = "the OU $dn"; Tier0 = (Test-AdDelegationTier0Container $dn) }) }
        }
        # ⛔ THE ONE PLACE THIS AUDIT CAN LIE BY OMISSION. Every OU past the limit is simply never
        # examined, and an OU that is never examined contributes no findings -- so a truncated
        # sweep does not look short, it looks CLEAN. Recorded as unchecked coverage, which is what
        # the report already has a section for, rather than left to the reader to infer.
        if ($script:DelegationReadTruncated) {
            Note-Unchecked "every organizational unit (the list stopped at $Limit)" `
                ("OUs past that limit were never examined, so this report cannot claim they are clean. " +
                 "Re-run with a higher -Limit, or per-OU with -ExtraContainer.")
        }
    } catch { Note-Unchecked 'the list of organizational units' $_.Exception.Message }

    foreach ($c in $ExtraContainer) {
        $dn = "$c,$domainDn"
        # Optional: CN=Users and CN=Computers can be REDIRECTED (redircmp / redirusr) and
        # CN=Managed Service Accounts predates none of them. A domain that does not have one is
        # not a domain we failed to audit.
        [void]$targets.Add([pscustomobject]@{ Dn = $dn; Label = "the container $dn"; Tier0 = (Test-AdDelegationTier0Container $dn); Optional = $true })
    }

    foreach ($t in $targets) {
        $acl = Get-AdDelegationDacl -Dn $t.Dn -Label $t.Label -Optional:([bool](Get-AdmRawProp $t 'Optional' $false))
        # A container that could not be read has already been recorded as unchecked by Get-AdDelegationDacl.
        if (-not $acl) { continue }

        foreach ($ace in $acl.Rules) {
            if (-not (Test-AdDelegationReportableAce $ace)) { continue }
            $rights = @(Get-AdDelegationAceKind $ace)
            if (-not $rights.Count) { continue }

            $sid = "$($ace.IdentityReference)"
            $broad = Test-AdDelegationBroadPrincipal $sid
            # ⚠ Built-in AND not broad is the only case that is quiet. Everything else is reported.
            if ((Test-AdDelegationBuiltIn $sid) -and -not $broad) { continue }

            $name = Resolve-AdDelegationSid $sid
            $isHead = ($t.Dn -eq $domainDn)
            $sev = if ($broad) { 'critical' }
                   elseif ($isHead -or $t.Tier0) { 'critical' }
                   else { 'high' }
            $inh = if ($ace.IsInherited) { 'inherited' } else { 'granted directly on this object' }

            Add-Finding -Severity $sev -Category 'Delegation' -Principal $name -Path $t.Dn `
                -Detail "$($rights -join '; ') on $($t.Label) ($inh)" `
                -Why $(
                    $base = 'Control of a container is control of everything under it: the holder can reset the passwords of the accounts inside, create new ones, or add itself to the groups. WriteDacl is worse than it looks -- it is not the power itself, it is the power to GRANT itself the power, so an attacker holding it leaves the object apparently untouched until the moment they use it.'
                    if ($isHead) { $base + ' On the DOMAIN HEAD this is the whole domain, and WriteDacl there is one step from adding a DCSync ACE.' }
                    elseif ($t.Tier0) { $base + ' This container holds Tier 0 objects, so it is a domain-takeover path.' }
                    elseif ($broad) { $base + ' The principal is a group that effectively contains everybody, so every account in the domain holds this.' }
                    else { $base }
                ) `
                -Action "Find out who granted it and why -- delegation is usually deliberate and usually undocumented. If it is a helpdesk delegation, narrow it: grant the specific right on the specific attribute (reset password, or WriteProperty on the attributes actually needed) instead of $($rights[0]). If it is unrecognised, remove it, then look for what else that principal holds."
        }
    }
}

# --- 3. non-inherited ACEs on privileged objects -----------------------------------------------

if (Use-Section 'Privileged') {
    foreach ($dn in $tier0Dns.Keys) {
        $label = $tier0Dns[$dn]
        $acl = Get-AdDelegationDacl -Dn $dn -Label "$label ($dn)"
        if (-not $acl) { continue }

        foreach ($ace in $acl.Rules) {
            if (-not (Test-AdDelegationReportableAce $ace)) { continue }
            # ⛔ "NON-INHERITED" IS NOT A FINDING ON ITS OWN. Measured on a lab domain controller: all 23 ACEs on
            # Domain Admins, Enterprise Admins, Schema Admins and BUILTIN\Administrators are
            # non-inherited, because AdminSDHolder disables inheritance on every protected object.
            # Reporting non-inheritance by itself would emit two hundred lines of noise on a
            # perfectly healthy domain, and the one real finding would be somewhere in the middle.
            if ($ace.IsInherited) { continue }
            $rights = @(Get-AdDelegationAceKind $ace)
            if (-not $rights.Count) { continue }

            $sid = "$($ace.IdentityReference)"
            $broad = Test-AdDelegationBroadPrincipal $sid
            if ((Test-AdDelegationBuiltIn $sid) -and -not $broad) { continue }

            Add-Finding -Severity 'critical' -Category 'Privileged ACL' -Principal (Resolve-AdDelegationSid $sid) -Path $dn `
                -Detail "$($rights -join '; ') granted EXPLICITLY on $label" `
                -Why "An explicit grant on a Tier 0 object is the quietest privilege escalation there is. It confers everything membership of $label confers -- the holder can add themselves to it whenever they choose -- while the group's own member list, and every report built on it, stays exactly as it was. Nobody reviewing membership will find this." `
                -Action "Confirm the grant. If it is not deliberate and documented, remove the ACE and treat whatever holds it as compromised. Note that removing it is not enough on its own: check whether the principal has already used it, by comparing $label's membership against your records."
        }
    }
}

# --- 4. ownership -------------------------------------------------------------------------------

if (Use-Section 'Owner') {
    $ownerTargets = New-Object System.Collections.ArrayList
    [void]$ownerTargets.Add([pscustomobject]@{ Dn = $domainDn; Label = "the domain head ($domainDn)" })
    foreach ($dn in $tier0Dns.Keys) { [void]$ownerTargets.Add([pscustomobject]@{ Dn = $dn; Label = $tier0Dns[$dn] }) }

    foreach ($t in $ownerTargets) {
        $acl = Get-AdDelegationDacl -Dn $t.Dn -Label $t.Label
        if (-not $acl) { continue }
        if (-not $acl.Owner) {
            Note-Unchecked "the owner of $($t.Label)" 'the descriptor parsed but carried no owner'
            continue
        }
        $sid = [string]$acl.Owner
        $broad = Test-AdDelegationBroadPrincipal $sid
        if ((Test-AdDelegationBuiltIn $sid) -and -not $broad) { continue }

        Add-Finding -Severity 'critical' -Category 'Owner' -Principal (Resolve-AdDelegationSid $sid) -Path $t.Dn `
            -Detail "OWNS $($t.Label)" `
            -Why 'The owner of an object holds WRITE_DAC implicitly and permanently: whatever the permissions say, the owner can rewrite them and then do anything. It is full control that does not appear in the permissions list, so a review that reads the DACL and stops will not see it. Ownership is usually acquired by whoever created the object, which makes it a quiet leftover from a migration or a script as often as it is an attack.' `
            -Action 'Set the owner back to Domain Admins (or Administrators). Then find out how it changed -- an object whose owner drifted has usually been recreated or restored by something that ran with more rights than anyone remembers granting it.'
    }
}

# --- 5. AdminSDHolder ---------------------------------------------------------------------------

if (Use-Section 'AdminSDHolder') {
    $asdhDn = "CN=AdminSDHolder,CN=System,$domainDn"
    $acl = Get-AdDelegationDacl -Dn $asdhDn -Label 'AdminSDHolder'
    if ($acl) {
        $reported = 0
        foreach ($ace in $acl.Rules) {
            if (-not (Test-AdDelegationReportableAce $ace)) { continue }
            $rights = @(Get-AdDelegationAceKind $ace)
            if (-not $rights.Count) { continue }
            $sid = "$($ace.IdentityReference)"
            $broad = Test-AdDelegationBroadPrincipal $sid
            if ((Test-AdDelegationBuiltIn $sid) -and -not $broad) { continue }
            $reported++

            Add-Finding -Severity 'critical' -Category 'AdminSDHolder' -Principal (Resolve-AdDelegationSid $sid) -Path $asdhDn `
                -Detail "$($rights -join '; ') on AdminSDHolder" `
                -Why 'AdminSDHolder is the template Active Directory stamps onto every protected account -- every domain admin, every enterprise admin, krbtgt, the built-in Administrator -- roughly every 60 minutes, by the SDProp task. Anything granted here is therefore granted on all of them, automatically, and re-granted after anyone cleans it off the accounts themselves. It is the standard way to make domain-admin access survive a cleanup, and it is invisible unless someone reads this exact object.' `
                -Action 'Remove the ACE, then remove the same grant from every protected account -- SDProp propagates additions, it does not undo them. Force a run (or wait an hour) and re-check. Treat the presence of an unexplained ACE here as a compromise indicator, not as configuration drift.'
        }
        if (-not $reported) {
            Add-Finding -Severity 'info' -Category 'AdminSDHolder' -Principal '(none)' -Path $asdhDn `
                -Detail "AdminSDHolder carries $($acl.Rules.Count) ACE(s), none of them a dangerous right held by a non-built-in principal" `
                -Why 'Recorded so a clean result here is distinguishable from a section that did not run. A clean domain has around 23 ACEs on this object, all of them built-in.' `
                -Action 'None.'
        }
        if ($acl.Owner -and -not (Test-AdDelegationBuiltIn ([string]$acl.Owner))) {
            Add-Finding -Severity 'critical' -Category 'AdminSDHolder' -Principal (Resolve-AdDelegationSid ([string]$acl.Owner)) -Path $asdhDn `
                -Detail 'OWNS AdminSDHolder' `
                -Why 'The owner can rewrite this object''s permissions at will, which means it can grant itself -- or anyone -- rights that SDProp will then stamp onto every protected account in the domain.' `
                -Action 'Set the owner back to Domain Admins and audit what has been stamped onto the protected accounts since it changed.'
        }
    }
}

# --- 6. shadow credentials: write access to msDS-KeyCredentialLink ------------------------------

if (Use-Section 'ShadowCred') {
    # ⚠ THREE ROUTES TO THE SAME POWER, and a check that looks for only the attribute GUID misses
    # two of them. Measured on a lab domain controller: the DEFAULT ACE granting this is on the Private-Information
    # PROPERTY SET (91e647de-...), not on the attribute -- so a scanner that matches the attribute
    # GUID alone finds nothing on any domain, healthy or not, and reports a clean result.
    $scDn = New-Object System.Collections.ArrayList
    [void]$scDn.Add([pscustomobject]@{ Dn = $domainDn; Label = "the domain head ($domainDn)"; Tier0 = $true })
    foreach ($dn in $tier0Dns.Keys) { [void]$scDn.Add([pscustomobject]@{ Dn = $dn; Label = $tier0Dns[$dn]; Tier0 = $true }) }

    foreach ($t in $scDn) {
        $acl = Get-AdDelegationDacl -Dn $t.Dn -Label $t.Label
        if (-not $acl) { continue }
        foreach ($ace in $acl.Rules) {
            if (-not (Test-AdDelegationReportableAce $ace)) { continue }
            $mask = [int]$ace.ActiveDirectoryRights
            if (-not (Test-AdDelegationRight $mask $RIGHT_WRITE_PROPERTY)) { continue }

            $route = if ($ace.ObjectType -eq $GUID_KEYCRED) { 'the msDS-KeyCredentialLink attribute directly' }
                     elseif ($ace.ObjectType -eq $GUID_PRIVATE_INFO) { 'the Private-Information property set, which CONTAINS msDS-KeyCredentialLink' }
                     elseif ($ace.ObjectType -eq $GUID_NONE) { 'write-all-properties, which includes msDS-KeyCredentialLink' }
                     else { $null }
            if (-not $route) { continue }

            $sid = "$($ace.IdentityReference)"
            $broad = Test-AdDelegationBroadPrincipal $sid
            if ((Test-AdDelegationBuiltIn $sid) -and -not $broad) { continue }

            Add-Finding -Severity $(if ($t.Tier0) { 'critical' } else { 'high' }) -Category 'ShadowCredentials' `
                -Principal (Resolve-AdDelegationSid $sid) -Path "$($t.Dn) -- via $route" `
                -Detail "can write msDS-KeyCredentialLink on $($t.Label), via $route" `
                -Why 'Writing that attribute adds a certificate to the account, and the holder can then obtain a Kerberos ticket AS that account using the certificate -- no password, no password reset, nothing the account owner would notice. Against a Tier 0 object it is a direct impersonation of a domain admin. It works wherever the domain has a certificate authority or Key Trust configured, which is most domains from Server 2016 onward.' `
                -Action 'Remove the write grant. Then read the current value of msDS-KeyCredentialLink on the affected accounts -- if it already contains a key nobody can account for, the impersonation has already been set up and clearing the write right does not undo it.'
        }
    }
}

# --- output -------------------------------------------------------------------------------------

$order = @{ critical = 0; high = 1; warn = 2; info = 3 }
$sorted = @($findings | Sort-Object @{ Expression = { $order[$_.Severity] } }, Category, Principal)

if ($ExportCsv) {
    $sorted | Export-Csv -LiteralPath $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Verbose "Wrote $($sorted.Count) finding(s) to $ExportCsv"
}

$sorted

$actionable = @($sorted | Where-Object { $_.Severity -ne 'info' })

# An explicit loop variable, not a nested Where-Object inside a ForEach-Object: the inner pipeline
# rebinds $_, so `$_.Severity -eq $_` compares each finding against itself and produces
# plausible-looking numbers without ever erroring.
$summary = foreach ($sev in @('critical', 'high', 'warn', 'info')) {
    $n = @($sorted | Where-Object { $_.Severity -eq $sev }).Count
    if ($n) { "$sev $n" }
}
Write-Verbose ("$($sorted.Count) finding(s): " + ((@($summary) -join ', ')))

Write-Warning ('This reads ACLs on the domain head, the OUs, the account containers, the Tier 0 ' +
               'objects and AdminSDHolder. It does NOT read GPO permissions, SYSVOL, the ' +
               'Configuration or Schema naming contexts, or the ACLs of ordinary user and ' +
               'computer objects -- and it does not read group MEMBERSHIP at all. Run ' +
               'Get-AdPrivilegedAccess as well; neither script is complete without the other.')

if ($couldNotCheck.Count) {
    Write-Warning "$($couldNotCheck.Count) check(s) could not run; those objects are UNKNOWN, not clean."
    $couldNotCheck | Format-Table -AutoSize | Out-String | Write-Verbose
    exit 30
}
if ($actionable.Count) { exit 10 }
exit 0
