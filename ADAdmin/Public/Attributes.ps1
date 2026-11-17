# Public/Attributes.ps1 -- editing an existing object.
#
# The module could CREATE a user and could not change one, which meant every "they got married",
# "they moved team", "their manager changed" ended outside the toolkit. This closes that.
#
# Two levels, deliberately:
#   Set-AdmUser             -- named parameters for the fields people actually edit
#   Set-AdmObjectAttribute  -- the escape hatch, any attribute on any object, for the long tail
#
# ⛔ A WRITE HERE IS ATOMIC. Everything goes into one CommitChanges, so if one attribute is
# rejected NOTHING is applied. That is the behaviour you want -- a half-applied identity change
# is worse than a failed one -- but it means the error names one problem while several may exist,
# so the failure message lists every attribute the call was trying to set.

# Friendly name -> LDAP attribute. Written as a list of pairs rather than a hashtable keyed by
# anything numeric; see the group-type note about positional lookups.
$script:AdmUserAttributeMap = [ordered]@{
    DisplayName       = 'displayName'
    GivenName         = 'givenName'
    Surname           = 'sn'
    Initials          = 'initials'
    Description       = 'description'
    EmailAddress      = 'mail'
    Title             = 'title'
    Department        = 'department'
    Company           = 'company'
    Office            = 'physicalDeliveryOfficeName'
    OfficePhone       = 'telephoneNumber'
    MobilePhone       = 'mobile'
    Fax               = 'facsimileTelephoneNumber'
    StreetAddress     = 'streetAddress'
    City              = 'l'
    State             = 'st'
    PostalCode        = 'postalCode'
    EmployeeID        = 'employeeID'
    EmployeeNumber    = 'employeeNumber'
    HomeDirectory     = 'homeDirectory'
    HomeDrive         = 'homeDrive'
    ScriptPath        = 'scriptPath'
    ProfilePath       = 'profilePath'
    WebPage           = 'wWWHomePage'
    Notes             = 'info'
    UserPrincipalName = 'userPrincipalName'
}

# Clear an attribute. ⛔ NOT `.Value = $null` and NOT `.Value = ''` -- the first is ignored on some
# paths and the second writes an EMPTY STRING, which for a directory is a value, not an absence:
# the attribute stays present, `Get-AdmRawProp` finds it, and every "is this set?" test that was
# written against a real directory's habit of omitting unset attributes now answers wrongly.
function Clear-AdmEntryAttribute {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Entry, [Parameter(Mandatory)][string]$Name)
    try { $Entry.Properties[$Name].Clear() }
    catch {
        # ADS_PROPERTY_CLEAR = 1. The documented COM operation, for the paths where the .NET
        # collection wrapper will not do it.
        $Entry.PutEx(1, $Name, $null)
    }
}

# Set or clear, choosing correctly. An empty string from the caller means "clear this", because
# that is what someone typing -Title '' into a shell means, and writing a literal empty string
# instead is the silent-wrong-answer described above.
function Set-AdmEntryAttribute {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Entry, [Parameter(Mandatory)][string]$Name, $Value)
    if ($null -eq $Value -or ($Value -is [string] -and $Value -eq '')) {
        Clear-AdmEntryAttribute -Entry $Entry -Name $Name
    } else {
        $Entry.Properties[$Name].Value = $Value
    }
}

function Set-AdmUser {
    <#
    .SYNOPSIS
    Change attributes on an existing user. Writes -- honours -WhatIf.
    .DESCRIPTION
      Only the parameters you actually pass are touched. Passing an empty string CLEARS an
      attribute; not passing it at all leaves it alone. That distinction is why this works from
      $PSBoundParameters rather than checking for null -- otherwise "leave it alone" and "clear
      it" are the same call, and one of them is wrong.

      ⚠ -Manager TAKES A PERSON, NOT A DN. The directory stores a distinguished name, so a
      sAMAccountName or display name is resolved first and the resolution refuses if it is
      ambiguous. Writing a non-DN into `manager` is accepted by some tooling and then shows as
      blank in every console that reads it.

      ⚠ -Country IS A TWO-LETTER ISO CODE ('GB', 'US'), because that is what the `c` attribute
      is. The human-readable name lives in a different attribute (`co`) and setting one without
      the other is why address blocks come out half-populated; -CountryName sets that one.

      ⚠ CHANGING -UserPrincipalName DOES NOT CHANGE THE LOGON NAME everywhere. sAMAccountName is
      separate and is what DOMAIN\user authentication uses; this cmdlet does not touch it, and a
      duplicate UPN elsewhere in the forest makes the directory reject the whole write.
    .EXAMPLE
      Set-AdmUser -Target corp.example.com -Identity jsmith -Title 'Senior Engineer' -Department Platform
    .EXAMPLE
      Set-AdmUser -Target corp.example.com -Identity jsmith -Manager aokafor -Office ''    # '' clears
    .EXAMPLE
      Set-AdmUser -Target corp.example.com -Identity jsmith -AccountExpires (Get-Date).AddDays(30)
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Identity,

        [string]$DisplayName, [string]$GivenName, [string]$Surname, [string]$Initials,
        [string]$Description, [string]$EmailAddress, [string]$Title, [string]$Department,
        [string]$Company, [string]$Office, [string]$OfficePhone, [string]$MobilePhone,
        [string]$Fax, [string]$StreetAddress, [string]$City, [string]$State, [string]$PostalCode,
        [string]$EmployeeID, [string]$EmployeeNumber, [string]$HomeDirectory, [string]$HomeDrive,
        [string]$ScriptPath, [string]$ProfilePath, [string]$WebPage, [string]$Notes,
        [string]$UserPrincipalName,

        # Resolved to a DN before it is written.
        [string]$Manager,
        # ISO 3166 alpha-2. Validated rather than trusted: 'United Kingdom' in `c` is a silent
        # mess that only shows up in whatever consumes the address.
        [string]$Country,
        [string]$CountryName,

        # Date, or -NeverExpires. These are mutually exclusive and the directory stores them in
        # the same attribute.
        [datetime]$AccountExpires,
        [switch]$NeverExpires,

        [bool]$PasswordNeverExpires,
        [bool]$SmartcardLogonRequired,

        # Attributes with no named parameter. Values follow the same rule: '' or $null clears.
        [hashtable]$Attribute,
        # Explicit clears, for callers that would rather say so than pass an empty string.
        [string[]]$Clear,

        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    # ⛔ CAPTURED HERE, OUTSIDE THE GUARDED BLOCK, AND THIS IS NOT A STYLE CHOICE.
    # Inside the -Action scriptblock, $PSBoundParameters does NOT resolve to this function's
    # bound parameters -- it resolves to Invoke-AdmGuarded's, which holds Action, Operation and
    # Target. So every ContainsKey('Title') test came back FALSE and the cmdlet reported
    # "no attribute parameters were passed" for a call that passed several. It fails the same way
    # for every attribute, so it looks like the parameters are being ignored rather than like a
    # scoping problem. Found by the CLI suite on its first run, 2026-08-28 -- no unit test could
    # have caught it, because the fault is in how the two functions nest.
    $bound = $PSBoundParameters
    Invoke-AdmGuarded -Operation "update user '$Identity'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup

        if ($bound.ContainsKey('AccountExpires') -and $NeverExpires) {
            throw "-AccountExpires and -NeverExpires both set the same attribute; pass one."
        }
        if ($bound.ContainsKey('Country') -and $Country -and $Country -notmatch '^[A-Za-z]{2}$') {
            throw "-Country is the two-letter ISO code that the 'c' attribute holds (for example 'GB'), not a country name. Use -CountryName for the readable form."
        }

        # Build the change set from what was ACTUALLY passed.
        $changes = [ordered]@{}
        foreach ($friendly in $script:AdmUserAttributeMap.Keys) {
            if ($bound.ContainsKey($friendly)) {
                $changes[$script:AdmUserAttributeMap[$friendly]] = $bound[$friendly]
            }
        }
        if ($bound.ContainsKey('Country'))     { $changes['c']  = $Country.ToUpperInvariant() }
        if ($bound.ContainsKey('CountryName')) { $changes['co'] = $CountryName }
        if ($Attribute) { foreach ($k in $Attribute.Keys) { $changes[[string]$k] = $Attribute[$k] } }
        if ($Clear)     { foreach ($c in $Clear) { $changes[$c] = '' } }

        $uacChanges = @{}
        if ($bound.ContainsKey('PasswordNeverExpires'))   { $uacChanges['0x10000'] = $PasswordNeverExpires }
        if ($bound.ContainsKey('SmartcardLogonRequired')) { $uacChanges['0x40000'] = $SmartcardLogonRequired }

        $wantsExpiry = $bound.ContainsKey('AccountExpires') -or $NeverExpires
        if (-not $changes.Count -and -not $uacChanges.Count -and -not $wantsExpiry -and -not $bound.ContainsKey('Manager')) {
            throw "Nothing to change -- no attribute parameters were passed."
        }

        # ⚠ THE @() WRAPS THE WHOLE PIPELINE, not just the literal. `@(a,b,c) | Where-Object {...}`
        # returns a SCALAR when exactly one value survives the filter, and .Count on a scalar
        # throws under Set-StrictMode 2.0 -- so the array subexpression has to enclose the filter
        # too or this breaks precisely in the single-attribute case, which is the common one.
        $summary = @(@($changes.Keys) + @($(if ($bound.ContainsKey('Manager')) { 'manager' })) +
                     @($(if ($wantsExpiry) { 'accountExpires' })) +
                     @($(if ($uacChanges.Count) { 'userAccountControl' })) | Where-Object { $_ })
        if (-not $PSCmdlet.ShouldProcess("$Identity @ $($ctx.Domain.DnsDomain)", "Set $($summary -join ', ')")) { return }

        if ((Get-AdmProviderName) -eq 'mock') {
            $set = @{}
            foreach ($k in $changes.Keys) { $set[$k] = $changes[$k] }
            $o = Invoke-AdmMockModify -Domain $ctx.Domain -ObjectClass 'users' -Identity $Identity -Set $set
            return [pscustomobject]@{ Domain = $ctx.Domain.Name; SamAccountName = (Get-AdmRawProp $o 'samAccountName')
                                      Changed = @($summary); Action = 'set-user' }
        }

        # Manager is resolved BEFORE the bind, so an unresolvable manager fails without having
        # touched the account at all.
        if ($bound.ContainsKey('Manager')) {
            if ([string]::IsNullOrEmpty($Manager)) { $changes['manager'] = '' }
            else { $changes['manager'] = Resolve-AdmObjectDn -Context $ctx -Identity $Manager -Class 'user' }
        }

        $v = ConvertTo-AdmLdapFilterValue -Value $Identity
        $entry = Get-AdmSingleEntry -Context $ctx -Identity $Identity `
            -Filter "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=$v)(userPrincipalName=$v)(cn=$v)))"
        try {
            foreach ($name in $changes.Keys) {
                Set-AdmEntryAttribute -Entry $entry -Name $name -Value $changes[$name]
            }

            if ($uacChanges.Count) {
                $uac = 0
                [void][int]::TryParse([string]$entry.Properties['userAccountControl'].Value, [ref]$uac)
                foreach ($bitText in $uacChanges.Keys) {
                    $bit = [Convert]::ToInt32($bitText, 16)
                    if ($uacChanges[$bitText]) { $uac = $uac -bor $bit } else { $uac = $uac -band (-bnot $bit) }
                }
                $entry.Properties['userAccountControl'].Value = $uac
            }

            if ($wantsExpiry) { Set-AdmEntryAccountExpiry -Entry $entry -Never:$NeverExpires -When $AccountExpires }

            try { $entry.CommitChanges() }
            catch {
                # The directory names ONE problem. Say which write we were attempting, or the
                # operator is left matching "invalid attribute syntax" against a call they cannot see.
                throw (New-Object System.Exception(
                    ("Could not update '$Identity'. The write was rejected while setting: " +
                     "$($summary -join ', '). Nothing was applied -- the change is atomic. " +
                     "The directory said: $($_.Exception.Message)"), $_.Exception))
            }

            [void](Write-AdmLogEntry -Severity info -Event 'change' -Operation 'update user' `
                    -Target $Target -Domain $ctx.Domain.Name `
                    -Message "Updated '$Identity' in $($ctx.Domain.DnsDomain): $($summary -join ', ')")

            [pscustomobject]@{
                Domain = $ctx.Domain.Name; SamAccountName = $Identity
                DistinguishedName = [string]$entry.Properties['distinguishedName'].Value
                Changed = @($summary); Action = 'set-user'
            }
        } finally { Close-AdmDirectoryEntry $entry }
    }
}

# accountExpires is a LargeInteger and it has TWO "never" values, which is the trap: 0 and
# 0x7FFFFFFFFFFFFFFF both mean no expiry, and code that tests only one of them reports an account
# as expiring in the year 30828. Writing goes through the same care.
#
# ✔ VERIFIED against a lab domain controller (corp.example.com), 2026-08-28: a date is written and reads back as the same
# date, and -NeverExpires clears it. The Int64 write succeeded, so the InvokeSet fallback below
# has not itself been exercised -- it remains the documented-API path for a directory that
# refuses the attribute write.
function Set-AdmEntryAccountExpiry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Entry,
        [switch]$Never,
        # ⚠ UNTYPED ON PURPOSE. Declared [datetime] this cannot accept $null, and the caller
        # passes -When $AccountExpires unconditionally -- so -NeverExpires, whose whole point is
        # that no date was given, died with "Cannot convert null to type System.DateTime" on a
        # parameter the operator never mentioned. Measured on a lab domain controller, 2026-08-28.
        $When
    )
    if ($Never) {
        # 0 is the value the Microsoft consoles write for "never", and unlike Int64::MaxValue it
        # survives a round trip through every tool that reads it.
        $Entry.Properties['accountExpires'].Value = 0
        return
    }
    if ($null -eq $When) { throw 'Set-AdmEntryAccountExpiry needs either -Never or a -When date.' }
    $dt = [datetime]$When
    # ⚠ FileTimeUtc, not FileTime. The attribute is UTC; using the local-time conversion shifts
    # every expiry by the host's offset, which is invisible in a lab on UTC and wrong everywhere else.
    $ticks = $dt.ToUniversalTime().ToFileTimeUtc()
    try {
        $Entry.Properties['accountExpires'].Value = $ticks
    } catch {
        # Some ADSI paths will not marshal an Int64 into a LargeInteger and want the IADsUser
        # property instead, which takes a DateTime directly.
        $Entry.InvokeSet('AccountExpirationDate', $dt)
    }
}

function Set-AdmObjectAttribute {
    <#
    .SYNOPSIS
    Set or clear arbitrary attributes on any object. Writes -- honours -WhatIf.
    .DESCRIPTION
      The long tail: anything the typed cmdlets do not cover, on a user, group, computer, OU or
      contact. Values follow the same rule as Set-AdmUser -- '' or $null clears the attribute
      rather than writing an empty one.

      ⚠ NO VALIDATION BEYOND WHAT THE DIRECTORY DOES. This is the escape hatch, so it will
      happily attempt whatever you pass and report what the directory said. For anything with a
      named parameter elsewhere, prefer the named one: it carries the checks.
    .EXAMPLE
      Set-AdmObjectAttribute -Target corp.example.com -Identity 'OU=Staff,DC=corp,DC=example,DC=com' -Attribute @{ description = 'Employees' }
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][hashtable]$Attribute,
        [ValidateSet('any', 'user', 'group', 'computer', 'ou')][string]$Class = 'any',
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "set attributes on '$Identity'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        $names = @($Attribute.Keys | ForEach-Object { [string]$_ })
        if (-not $names.Count) { throw "No attributes given." }
        if (-not $PSCmdlet.ShouldProcess("$Identity @ $($ctx.Domain.DnsDomain)", "Set $($names -join ', ')")) { return }

        if ((Get-AdmProviderName) -eq 'mock') {
            return [pscustomobject]@{ Domain = $ctx.Domain.Name; Identity = $Identity
                                      Changed = $names; Action = 'set-attribute' }
        }

        $dn = Resolve-AdmObjectDn -Context $ctx -Identity $Identity -Class $Class
        $entry = Get-AdmEntryByDn -Context $ctx -DistinguishedName $dn
        try {
            foreach ($n in $names) { Set-AdmEntryAttribute -Entry $entry -Name $n -Value $Attribute[$n] }
            try { $entry.CommitChanges() }
            catch {
                throw (New-Object System.Exception(
                    ("Could not update '$dn'. The write was rejected while setting: $($names -join ', '). " +
                     "Nothing was applied. The directory said: $($_.Exception.Message)"), $_.Exception))
            }
            [void](Write-AdmLogEntry -Severity info -Event 'change' -Operation 'set attributes' `
                    -Target $Target -Domain $ctx.Domain.Name `
                    -Message "Set $($names -join ', ') on '$dn' in $($ctx.Domain.DnsDomain)")
            [pscustomobject]@{ Domain = $ctx.Domain.Name; Identity = $Identity; DistinguishedName = $dn
                               Changed = $names; Action = 'set-attribute' }
        } finally { Close-AdmDirectoryEntry $entry }
    }
}
