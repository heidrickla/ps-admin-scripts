# Public/Recovery.ps1 -- the two secrets a help desk actually needs out of the directory:
# the local administrator password (LAPS) and a BitLocker recovery key.
#
# ⛔ THE VALUES ARE SECRETS AND ARE NEVER WRITTEN TO THE LOG. The FACT of the retrieval is logged
# -- who asked, for which machine, when -- because that record is the entire audit trail for a
# password disclosure and it is worth more than the convenience of omitting it. The value itself
# appears only in the returned object.
#
# ⭐ THE HARD PART IS NOT READING THE ATTRIBUTE, IT IS SAYING WHY IT IS MISSING.
# Active Directory omits an attribute you are not allowed to read in EXACTLY the same way it omits
# one that was never set: the attribute simply is not in the result. So the naive implementation
# reports "no LAPS password for this machine" to someone who merely lacks the extended right, and
# they go and re-deploy LAPS to a machine that already had it.
#
# Both generations of LAPS give us a way out. The expiration-time attribute is an ORDINARY
# attribute readable by anyone who can read the computer object, while the password itself is
# guarded by a separate extended right. So:
#
#     expiry present + password present  -> here it is
#     expiry present + password ABSENT   -> a password IS stored; you cannot read it   <-- the one
#     expiry absent  + password absent   -> LAPS is not managing this machine
#
# That middle case is the whole point of this file.

# --- naming contexts ------------------------------------------------------------------------

# Read a naming-context path from the rootDSE. Authenticated, because a hardened DC refuses
# anonymous rootDSE reads and the failure looks like the DC being down.
function Get-AdmNamingContext {
    <#
    .SYNOPSIS
      Read a naming-context DN (default, configuration or schema) from the rootDSE.
    .DESCRIPTION
      Authenticated, because a hardened DC refuses anonymous rootDSE reads and the failure then
      looks like the domain controller being down.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]$Context,
        [ValidateSet('defaultNamingContext', 'configurationNamingContext', 'schemaNamingContext')]
        [string]$Name = 'defaultNamingContext'
    )
    $root = New-AdmDirectoryEntry -Domain $Context.Domain -Credential $Context.Credential -DistinguishedName 'RootDSE'
    try {
        $root.RefreshCache()
        $p = $root.Properties[$Name]
        if ($null -eq $p -or $null -eq $p.Value) { return $null }
        [string]$p.Value
    } finally { Close-AdmDirectoryEntry $root }
}

# Is an attribute present in the forest schema at all? This separates "LAPS was never deployed
# here" from "deployed, but not to this machine" -- two answers that produce identical LDAP
# results on the computer object and demand completely different actions.
function Test-AdmSchemaAttribute {
    <#
    .SYNOPSIS
      Does an attribute exist in the forest schema? Separates "never deployed" from "not set here".
    .DESCRIPTION
      A computer with no LAPS password and a forest where LAPS was never deployed produce
      identical LDAP results on the computer object, and demand completely different actions.
      This is what tells them apart.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$LdapDisplayName
    )
    $schemaNc = Get-AdmNamingContext -Context $Context -Name 'schemaNamingContext'
    if (-not $schemaNc) { return $false }
    $v = ConvertTo-AdmLdapFilterValue -Value $LdapDisplayName
    $hits = @(Invoke-AdmAdsiSearch -Domain $Context.Domain -Credential $Context.Credential `
                -Filter "(&(objectClass=attributeSchema)(lDAPDisplayName=$v))" `
                -Properties @('ldapdisplayname') -SearchBase $schemaNc -SizeLimit 1)
    [bool]$hits.Count
}

# --- LAPS ---------------------------------------------------------------------------------------

# Windows LAPS stores a JSON document, not a bare password:
#   {"n":"Administrator","t":"1d9bd9ac1d0c0d5","p":"<password>"}
# n = account name, t = a HEX FILETIME (not decimal, and not an ISO date), p = the password.
function ConvertFrom-AdmLapsJson {
    [CmdletBinding()]
    param($Value)
    # The attribute can arrive as a string or as raw bytes depending on the directory and the
    # runtime; normalise before parsing rather than assuming one.
    $text = if ($Value -is [string]) { $Value }
            elseif ($null -ne $Value) { [System.Text.Encoding]::UTF8.GetString([byte[]]@($Value)) }
            else { $null }
    if (-not $text) { return $null }
    try {
        $o = $text | ConvertFrom-Json
        $when = $null
        $t = [string](Get-AdmRawProp $o 't')
        if ($t) {
            # Hex, base 16. Parsing it as decimal yields a date centuries out and no error.
            try { $when = [datetime]::FromFileTimeUtc([Convert]::ToInt64($t, 16)) } catch { }
        }
        [pscustomobject]@{
            Account  = Get-AdmRawProp $o 'n'
            Password = Get-AdmRawProp $o 'p'
            SetAt    = $when
        }
    } catch { $null }
}

function Get-AdmLapsPassword {
    <#
    .SYNOPSIS
    Retrieve the LAPS-managed local administrator password for a machine. Read-only.
    .DESCRIPTION
      Handles BOTH generations without the caller having to know which is deployed: legacy
      Microsoft LAPS (ms-Mcs-AdmPwd) and Windows LAPS (msLAPS-Password, and the encrypted
      msLAPS-EncryptedPassword).

      ⛔ IT DISTINGUISHES "NOT SET" FROM "YOU CANNOT READ IT". The directory hides an unreadable
      attribute exactly as it hides an unset one, so this reads the expiration-time attribute --
      an ordinary attribute, not guarded by the extended right -- and uses its presence to tell
      the two apart. Status is one of:

        Available      the password is in the returned object
        NoPermission   a password IS stored; this credential lacks the extended right to read it
        Encrypted      Windows LAPS stored it encrypted; LDAP alone cannot decrypt it
        NotManaged     LAPS is deployed in the forest but not managing this machine
        NotDeployed    the LAPS schema attributes do not exist in this forest at all

      ⚠ The password is NOT written to the log. The fact that it was retrieved IS, deliberately:
      that record is the audit trail for a credential disclosure.
    .EXAMPLE
      Get-AdmLapsPassword -Target corp.example.com -Identity WS1
    .EXAMPLE
      (Get-AdmLapsPassword -Target corp.example.com -Identity WS1).Password
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Identity,
        [string]$Tier,
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "read LAPS password for '$Identity'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup

        if ((Get-AdmProviderName) -eq 'mock') {
            $c = @(Invoke-AdmMockSearch -Domain $ctx.Domain -ObjectClass 'computers' -Identity $Identity)
            if (-not $c.Count) { throw "No computer matching '$Identity' in $($ctx.Domain.DnsDomain)." }
            return [pscustomobject]@{
                Domain = $ctx.Domain.Name; Computer = Get-AdmRawProp $c[0] 'name'
                DistinguishedName = Get-AdmRawProp $c[0] 'distinguishedName'
                Status = 'NotDeployed'; Source = $null; Account = $null; Password = $null
                SetAt = $null; ExpiresAt = $null
                Explanation = 'The fixture does not model LAPS. Point at a real domain to read one.'
                IsMock = $true
            }
        }

        $v = ConvertTo-AdmLdapFilterValue -Value $Identity
        $bare = $v.TrimEnd('$')
        # ⚠ Lowercase attribute names. A DirectorySearcher lowercases the property names it
        # returns, so a lookup keyed on the schema's mixed case finds nothing.
        $props = @('name', 'dnshostname', 'distinguishedname',
                   'ms-mcs-admpwd', 'ms-mcs-admpwdexpirationtime',
                   'mslaps-password', 'mslaps-passwordexpirationtime', 'mslaps-encryptedpassword')
        $rows = @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential `
                    -Filter "(&(objectCategory=computer)(|(sAMAccountName=$bare`$)(cn=$bare)(dNSHostName=$v)))" `
                    -Properties $props -SizeLimit 2)
        if ($rows.Count -eq 0) { throw "No computer matching '$Identity' in $($ctx.Domain.DnsDomain)." }
        if ($rows.Count -gt 1) { throw "'$Identity' matched more than one computer in $($ctx.Domain.DnsDomain); refusing to guess." }
        $row = $rows[0]

        $legacyPwd    = Get-AdmRawProp $row 'ms-mcs-admpwd'
        $legacyExp    = Get-AdmRawProp $row 'ms-mcs-admpwdexpirationtime'
        $winPwd       = Get-AdmRawProp $row 'mslaps-password'
        $winExp       = Get-AdmRawProp $row 'mslaps-passwordexpirationtime'
        $winEncrypted = Get-AdmRawProp $row 'mslaps-encryptedpassword'

        $status = 'NotManaged'; $source = $null; $account = $null; $password = $null
        $setAt = $null; $expires = $null; $explain = $null

        if ($winPwd) {
            $parsed = ConvertFrom-AdmLapsJson -Value $winPwd
            $status = 'Available'; $source = 'Windows LAPS (msLAPS-Password)'
            if ($parsed) { $account = $parsed.Account; $password = $parsed.Password; $setAt = $parsed.SetAt }
            else {
                # Not JSON. Report the raw value rather than dropping it -- a non-standard writer
                # is still a password, and silently returning nothing would be the worse failure.
                $password = [string]$winPwd
                $explain = 'The attribute did not contain the expected JSON document; returned raw.'
            }
            $expires = ConvertFrom-AdmFileTime $winExp
        }
        elseif ($legacyPwd) {
            $status = 'Available'; $source = 'Legacy LAPS (ms-Mcs-AdmPwd)'
            $password = [string]$legacyPwd
            $account = 'Administrator'   # legacy LAPS manages the built-in account only
            $expires = ConvertFrom-AdmFileTime $legacyExp
        }
        elseif ($winEncrypted) {
            $status = 'Encrypted'; $source = 'Windows LAPS (msLAPS-EncryptedPassword)'
            $expires = ConvertFrom-AdmFileTime $winExp
            $explain = 'Windows LAPS encrypted this password to a specific group or user. Decryption is not an LDAP operation -- it needs the LAPS client API on a machine whose caller is authorised, so this toolkit can confirm it exists but cannot reveal it.'
        }
        elseif ($winExp -or $legacyExp) {
            # ⭐ THE CASE THAT MATTERS. The expiry is readable and the password is not, so a
            # password is definitely stored and this credential simply cannot see it.
            $status = 'NoPermission'
            $source = if ($winExp) { 'Windows LAPS' } else { 'Legacy LAPS' }
            $expires = ConvertFrom-AdmFileTime $(if ($winExp) { $winExp } else { $legacyExp })
            $explain = "A LAPS password IS stored for this machine -- its expiry time is readable -- but the password attribute was not returned, which means this credential lacks the extended right to read it. Ask for 'All extended rights' or the specific LAPS password-read right on the OU containing this computer. Re-deploying LAPS would not fix this and would rotate a working password."
        }
        else {
            # Nothing at all. Before saying "not managed", check whether the schema even has the
            # attributes -- otherwise this reports a per-machine problem for a forest-wide absence.
            $hasWin    = Test-AdmSchemaAttribute -Context $ctx -LdapDisplayName 'msLAPS-Password'
            $hasLegacy = Test-AdmSchemaAttribute -Context $ctx -LdapDisplayName 'ms-Mcs-AdmPwd'
            if (-not $hasWin -and -not $hasLegacy) {
                $status = 'NotDeployed'
                $explain = 'Neither LAPS schema attribute exists in this forest, so LAPS has never been deployed here. This is a forest-wide state, not something about this machine.'
            } else {
                $status = 'NotManaged'
                $source = $(if ($hasWin) { 'Windows LAPS' } else { 'Legacy LAPS' })
                $explain = 'LAPS is deployed in this forest, but this computer has no stored password and no expiry time -- the policy is most likely not applied to the OU this machine sits in, or the machine has not yet checked in since it was.'
            }
        }

        # ⛔ The message records the RETRIEVAL, never the value.
        [void](Write-AdmLogEntry -Severity info -Event 'read' -Operation 'read LAPS password' `
                -Target $Target -Domain $ctx.Domain.Name `
                -Message "LAPS password requested for '$Identity' in $($ctx.Domain.DnsDomain); result: $status")

        [pscustomobject]@{
            Domain            = $ctx.Domain.Name
            Computer          = Get-AdmRawProp $row 'name'
            DnsHostName       = Get-AdmRawProp $row 'dnshostname'
            DistinguishedName = Get-AdmRawProp $row 'distinguishedname'
            Status            = $status
            Source            = $source
            Account           = $account
            Password          = $password
            SetAt             = $setAt
            ExpiresAt         = $expires
            Explanation       = $explain
        }
    }
}

# --- BitLocker ------------------------------------------------------------------------------------

function Get-AdmBitLockerRecoveryKey {
    <#
    .SYNOPSIS
    BitLocker recovery keys escrowed in the directory for a machine. Read-only.
    .DESCRIPTION
      Recovery keys are not attributes on the computer object -- they are child objects of class
      msFVE-RecoveryInformation beneath it, one per volume per escrow. A machine that has been
      re-encrypted, or that has more than one protected volume, has SEVERAL, and handing back only
      the first is how someone ends up typing a key that belongs to a disk they are not unlocking.
      All of them are returned, newest first.

      ⚠ THE RECOVERY KEY ID IS THE THING TO MATCH ON. BitLocker's recovery screen shows a key
      identifier; find the row whose KeyId starts with those characters rather than assuming the
      newest key is the right one.

      ⛔ AN EMPTY RESULT IS AMBIGUOUS AND SAYS SO. No child objects means either nothing was ever
      escrowed or this credential cannot read them -- the directory hides both identically. The
      Explanation on an empty result spells that out instead of implying the keys do not exist.

      ⚠ Keys are NOT written to the log; the fact of the retrieval is.
    .EXAMPLE
      Get-AdmBitLockerRecoveryKey -Target corp.example.com -Identity WS1
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Identity,
        # Match the identifier BitLocker shows on the recovery screen. A prefix is enough.
        [string]$KeyId,
        [string]$Tier,
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "read BitLocker recovery keys for '$Identity'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup

        if ((Get-AdmProviderName) -eq 'mock') {
            $c = @(Invoke-AdmMockSearch -Domain $ctx.Domain -ObjectClass 'computers' -Identity $Identity)
            if (-not $c.Count) { throw "No computer matching '$Identity' in $($ctx.Domain.DnsDomain)." }
            return @()
        }

        $v = ConvertTo-AdmLdapFilterValue -Value $Identity
        $bare = $v.TrimEnd('$')
        $comp = @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential `
                    -Filter "(&(objectCategory=computer)(|(sAMAccountName=$bare`$)(cn=$bare)(dNSHostName=$v)))" `
                    -Properties @('name', 'distinguishedname') -SizeLimit 2)
        if ($comp.Count -eq 0) { throw "No computer matching '$Identity' in $($ctx.Domain.DnsDomain)." }
        if ($comp.Count -gt 1) { throw "'$Identity' matched more than one computer in $($ctx.Domain.DnsDomain); refusing to guess." }
        $compDn   = [string](Get-AdmRawProp $comp[0] 'distinguishedname')
        $compName = [string](Get-AdmRawProp $comp[0] 'name')

        # Scoped to the computer object's own subtree.
        # ⛔ 200 WAS TOO LOW FOR THE WORST CASE, and the worst case here is nastier than a short
        # list. A directory search returns no particular ORDER, so truncating a machine with more
        # recovery objects than the limit does not drop the OLDEST -- it drops an arbitrary set,
        # which can include the CURRENT key. The caller then gets a page of recovery passwords,
        # none of which unlock the volume, and no reason to suspect the list was incomplete.
        $keyLimit = 20000
        Reset-AdmSearchTruncated
        $rows = @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential `
                    -Filter '(objectClass=msFVE-RecoveryInformation)' -SearchBase $compDn -SizeLimit $keyLimit `
                    -Properties @('name', 'distinguishedname', 'whencreated',
                                  'msfve-recoverypassword', 'msfve-recoveryguid', 'msfve-volumeguid'))
        $keysTruncated = [bool](Get-AdmSearchTruncated)

        [void](Write-AdmLogEntry -Severity info -Event 'read' -Operation 'read BitLocker recovery key' `
                -Target $Target -Domain $ctx.Domain.Name `
                -Message "BitLocker recovery keys requested for '$compName' in $($ctx.Domain.DnsDomain); $($rows.Count) found")

        if ($rows.Count -eq 0) {
            return [pscustomobject]@{
                Domain = $ctx.Domain.Name; Computer = $compName; DistinguishedName = $compDn
                KeyId = $null; RecoveryPassword = $null; VolumeGuid = $null; WhenCreated = $null
                Status = 'NoneFound'
                Explanation = 'No recovery information objects exist beneath this computer. That means either no key was ever escrowed to the directory, or this credential cannot read them -- Active Directory hides an unreadable child object exactly as it hides one that is not there, so these two cannot be told apart from here. If you expect keys, have someone with rights on the computer object check before concluding the machine was never backed up.'
            }
        }

        $out = foreach ($r in $rows) {
            # The RDN is "<ISO timestamp>{<key guid>}"; the GUID attribute is the authoritative
            # source and is a raw byte array, so convert rather than parsing the name.
            $guidRaw = Get-AdmRawProp $r 'msfve-recoveryguid'
            $keyId = $null
            if ($guidRaw) { try { $keyId = (New-Object System.Guid(, [byte[]]@($guidRaw))).ToString() } catch { } }
            if (-not $keyId) {
                $nm = [string](Get-AdmRawProp $r 'name')
                if ($nm -match '\{([0-9a-fA-F-]{36})\}') { $keyId = $Matches[1] }
            }
            $volRaw = Get-AdmRawProp $r 'msfve-volumeguid'
            $volGuid = $null
            if ($volRaw) { try { $volGuid = (New-Object System.Guid(, [byte[]]@($volRaw))).ToString() } catch { } }

            [pscustomobject]@{
                Domain            = $ctx.Domain.Name
                Computer          = $compName
                DistinguishedName = Get-AdmRawProp $r 'distinguishedname'
                KeyId             = $keyId
                RecoveryPassword  = Get-AdmRawProp $r 'msfve-recoverypassword'
                VolumeGuid        = $volGuid
                WhenCreated       = Get-AdmRawProp $r 'whencreated'
                Status            = 'Available'
                Explanation       = if ($keysTruncated) {
                    "INCOMPLETE: more than $keyLimit recovery objects exist beneath this computer and the read stopped there. A search returns no particular order, so the CURRENT key may not be among these. If none of them unlock the volume, that is why."
                } else { $null }
            }
        }

        $result = @($out | Sort-Object -Property WhenCreated -Descending)
        if ($KeyId) {
            $needle = $KeyId.Trim('{', '}').ToLowerInvariant()
            $result = @($result | Where-Object { $_.KeyId -and $_.KeyId.ToLowerInvariant().StartsWith($needle) })
            if (-not $result.Count) {
                return [pscustomobject]@{
                    Domain = $ctx.Domain.Name; Computer = $compName; DistinguishedName = $compDn
                    KeyId = $KeyId; RecoveryPassword = $null; VolumeGuid = $null; WhenCreated = $null
                    Status = 'NoMatchingKeyId'
                    Explanation = "This machine has $($rows.Count) escrowed key(s), but none whose identifier starts with '$KeyId'. Check the characters shown on the BitLocker recovery screen -- and check you are looking at the right machine, because a key identifier belongs to a volume, not to a computer name."
                }
            }
        }
        $result
    }
}
