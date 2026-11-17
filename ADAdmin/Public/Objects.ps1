# Public/Objects.ps1 -- the directory operations.
#
# Every cmdlet takes -Target (a hostname, FQDN, UPN or NetBIOS name), resolves it to a domain,
# and uses that domain's stored credential. The caller never picks a credential by hand, which
# is the whole point: choosing the wrong one across untrusted forests is the failure mode.
#
# Output shape is NORMALISED across providers. The GUI and the CLI must not be able to tell
# whether they are talking to a real DC or the fixture, or the mock stops being a useful test.
#
# EVERY operation runs inside Invoke-AdmGuarded, so a failure is diagnosed in plain English,
# written to the 7-day log, and re-thrown loudly with the explanation attached. Writes also log
# on SUCCESS -- an administrative change with no record is the thing you regret later.

$script:AdmUserProperties = @(
    'samaccountname', 'displayname', 'userprincipalname', 'distinguishedname',
    'useraccountcontrol', 'lockouttime', 'mail', 'whencreated', 'lastlogontimestamp',
    'pwdlastset', 'accountexpires', 'memberof'
)

# userAccountControl bit 0x10000 = DONT_EXPIRE_PASSWD.
function Test-AdmUacPasswordNeverExpires { param([int]$Uac) [bool]($Uac -band 0x10000) }

# Windows FILETIME (100-ns ticks since 1601) as it comes back from a SEARCH, where LargeIntegers
# arrive as Int64. Two sentinels mean "no value" and neither is a date:
#   0                    never set / must change at next logon
#   9223372036854775807  never expires
function ConvertFrom-AdmFileTime {
    param($Value)
    $n = 0L
    if (-not [int64]::TryParse([string]$Value, [ref]$n)) { return $null }
    if ($n -le 0 -or $n -eq [int64]::MaxValue) { return $null }
    try { [datetime]::FromFileTimeUtc($n) } catch { $null }
}

# userAccountControl bit 2 = ACCOUNTDISABLE.
function Test-AdmUacDisabled { param([int]$Uac) [bool]($Uac -band 0x2) }

# ⚠ A REAL DIRECTORY ONLY RETURNS ATTRIBUTES THAT ARE SET. An account that has never been locked
# has NO lockoutTime property at all -- not an empty one -- so `$Raw.lockouttime` throws under
# Set-StrictMode 2.0 and takes the whole search down. The mock fixture cannot show this, because
# fixtures are written with every field present; it appeared on the first real bind to a lab domain controller
# (2026-08-27). Treat every attribute as optional, always.
function Get-AdmRawProp {
    <#
    .SYNOPSIS
      Read one attribute off a directory or JSON object. Use this, never $obj.attr.
    .DESCRIPTION
      A real directory returns ONLY the attributes that are set, and a JSON log entry carries only
      the keys that were written. Under Set-StrictMode 2.0 reading an absent property THROWS, so
      direct access works right up until it meets an object that happens to lack the field -- which
      in a WPF handler closes the window. This returns the default instead.
    #>
    param($Raw, [string]$Name, $Default = $null)
    if ($null -eq $Raw) { return $Default }
    try { if ($Raw.PSObject.Properties[$Name]) { return $Raw.$Name } } catch { }
    $Default
}

# ⛔ A MULTI-VALUED ATTRIBUTE PAST ~1500 VALUES DOES NOT COME BACK SHORT. IT COMES BACK UNDER A
# DIFFERENT NAME, so asking for it by its own name returns NOTHING and the object reads as EMPTY.
# AD renames `member` to `member;range=0-1499` once the group is large, and Get-AdmRawProp $_
# 'member' then finds no such property and hands back the default. A 3000-member group therefore
# reported ZERO members, with no error and -- worse, once the truncation flag existed --
# `truncated: false` actively asserting the empty list was complete.
#
# ⚠ THE SEARCH-TRUNCATION FLAG CANNOT SEE THIS. It watches SizeLimit on the SEARCH; this is a
# per-attribute limit inside a single row, and the search returned exactly the one row it was
# asked for. Two different limits, and only one of them was being watched.
#
# ⭐ NO EXTRA QUERY. The first window is already in the result, just under the ranged name -- so
# this costs a property-name scan on the uncommon path and nothing at all on the common one.
# `Get-AdmRangedAttribute` walks every window when the whole set is genuinely needed; this is for
# the grid reads where the first window plus an honest "there are more" is the right answer.
function Get-AdmRangedProp {
    <#
    .SYNOPSIS
      Read a multi-valued attribute that AD may have renamed to <name>;range=0-1499.
    .DESCRIPTION
      Returns a hashtable: Values (the first window, or all of them if there is only one) and
      Truncated ($true when the directory renamed the attribute, meaning more values exist than
      came back). Reading such an attribute by its plain name returns NOTHING, not a short list,
      so a large group reads as empty unless this is used.

      When Truncated is $true the module's search-truncation flag is raised as well, so a caller
      that already asks Get-AdmSearchTruncated -- the CLI's -Json envelope, for one -- reports it
      without needing to know which of the two kinds of limit was hit.
    .EXAMPLE
      $m = Get-AdmRangedProp $row 'member'
      if ($m.Truncated) { "$($m.Values.Count) is a FLOOR" }
    #>
    param($Raw, [string]$Name)
    $out = @{ Values = @(); Truncated = $false }
    if ($null -eq $Raw) { return $out }
    try {
        if ($Raw.PSObject.Properties[$Name]) {
            $out.Values = @($Raw.$Name)
            return $out
        }
        # `member;range=0-1499` on a large group; `member;range=1500-*` would be a later window,
        # which this never asks for -- but match it too rather than return empty if one appears.
        $ranged = @($Raw.PSObject.Properties.Name | Where-Object { $_ -like "$Name;range=*" })
        if ($ranged.Count) {
            $out.Values = @($Raw.$($ranged[0]))
            $out.Truncated = $true
            $script:AdmLastSearchTruncated = $true
        }
    } catch { }
    $out
}

# ⛔ THE ONLY CORRECT WAY TO READ A SID OUT OF THIS MODULE'S SEARCH RESULTS.
#
# A DirectorySearcher property collection hands binary attributes back as a COLLECTION, and
# Invoke-AdmAdsiSearch normalises that to System.Object[] whose elements happen to be System.Byte.
# It is NOT a byte[], so the obvious `if ($Raw -is [byte[]])` is FALSE on every real result, and
# the usual fallback -- [string]$Raw -- yields the bytes space-joined:
#
#     1 4 0 0 0 0 0 5 21 0 0 0 15 64 75 122 152 58 61 164 44 28 223 120
#
# which is not a SID, is not an error, and is not obviously wrong at a glance. Two callers had
# written that check independently and both were silently broken (measured on a lab domain controller, 2026-08-27):
# Find-AdDuplicates printed byte soup for sIDHistory, and the privileged-access audit built
# "<bytes>-512" as a filter, matched nothing, and reported Domain Admins as empty.
#
# ⚠ A UNIT TEST THAT PASSES A REAL [byte[]] CANNOT CATCH THIS. It has to pass Object[] of Byte,
# which is what the directory actually returns.
function ConvertTo-AdmSidString {
    <#
    .SYNOPSIS
      Turn a directory SID value into S-1-5-... . The only correct way to read one here.
    .DESCRIPTION
      A search returns binary attributes as Object[] of Byte, NOT as byte[], so the obvious
      `-is [byte[]]` test is false on every real result and the usual fallback prints the bytes
      space-joined. Two call sites were silently broken that way.
    #>
    [CmdletBinding()]
    param($Raw)
    if ($null -eq $Raw) { return $null }
    # Already a string SID (some providers, and the fixture, hand one straight over).
    if ($Raw -is [string]) { return $(if ($Raw -match '^S-\d-') { $Raw } else { $null }) }
    try {
        # @() then a hard cast: this is what turns Object[]-of-Byte into a real byte[]. It is also
        # a no-op for something that genuinely is a byte[] already.
        $bytes = [byte[]]@($Raw)
        if ($bytes.Length -lt 8) { return $null }
        (New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)).Value
    } catch { $null }
}

function ConvertTo-AdmUserObject {
    param([Parameter(Mandatory)]$Raw, [Parameter(Mandatory)][string]$DomainName)
    $uac = 0; [void][int]::TryParse([string](Get-AdmRawProp $Raw 'useraccountcontrol' 0), [ref]$uac)
    $lockout = 0L; [void][int64]::TryParse([string](Get-AdmRawProp $Raw 'lockouttime' 0), [ref]$lockout)
    [pscustomobject]@{
        Domain            = $DomainName
        SamAccountName    = Get-AdmRawProp $Raw 'samaccountname'
        DisplayName       = Get-AdmRawProp $Raw 'displayname'
        UserPrincipalName = Get-AdmRawProp $Raw 'userprincipalname'
        DistinguishedName = Get-AdmRawProp $Raw 'distinguishedname'
        Mail              = Get-AdmRawProp $Raw 'mail'
        Enabled           = -not (Test-AdmUacDisabled -Uac $uac)
        LockedOut         = ($lockout -gt 0)
        WhenCreated       = Get-AdmRawProp $Raw 'whencreated'
        PasswordLastSet   = ConvertFrom-AdmFileTime (Get-AdmRawProp $Raw 'pwdlastset')
        PasswordNeverExpires = Test-AdmUacPasswordNeverExpires -Uac $uac
        MustChangePassword   = ([string](Get-AdmRawProp $Raw 'pwdlastset' '1') -eq '0')
        # ⚠ REPLICATED LAZILY. lastLogonTimestamp is deliberately not replicated on every logon --
        # by default it only advances when the new logon is more than ~9-14 days newer than the
        # stored value. So this can be up to about 14 days OLDER than the truth, and an account
        # that signed in last week may look idle. Fine for a 90-day sweep, dangerous for a 20-day
        # one. The accurate attribute, lastLogon, is per-DC and not replicated at all.
        LastLogonTimestamp = ConvertFrom-AdmFileTime (Get-AdmRawProp $Raw 'lastlogontimestamp')
        AccountExpires     = ConvertFrom-AdmFileTime (Get-AdmRawProp $Raw 'accountexpires')
        # Ranged: past ~1500 groups the attribute is renamed and a plain read returns NOTHING,
        # so an account in many groups would report as being in none.
        MemberOf           = @((Get-AdmRangedProp $Raw 'memberof').Values)
        ObjectClass       = 'user'
    }
}

function Get-AdmUser {
    <#
    .SYNOPSIS
      Find users in whichever domain the target belongs to.
    .EXAMPLE
      Get-AdmUser -Target corp.example.com -Identity jsmith
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Identity,
        [string]$Tier,
        [int]$Limit = 200,
        # Scope a listing to one container, which is what makes an OU browser possible.
        [string]$SearchBase,
        [ValidateSet('Subtree', 'OneLevel')][string]$Scope = 'Subtree',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation 'find users' -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        switch (Get-AdmProviderName) {
            'mock' {
                Invoke-AdmMockSearch -Domain $ctx.Domain -ObjectClass 'users' -Identity $Identity -SizeLimit $Limit |
                    ForEach-Object { ConvertTo-AdmUserObject -Raw $_ -DomainName $ctx.Domain.Name }
            }
            default {
                $filter = if ($Identity) {
                    $v = ConvertTo-AdmLdapFilterValue -Value $Identity
                    "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=*$v*)(displayName=*$v*)(userPrincipalName=*$v*)))"
                } else { '(&(objectCategory=person)(objectClass=user))' }
                Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential -Filter $filter `
                    -Properties $script:AdmUserProperties -SearchBase $SearchBase -Scope $Scope -SizeLimit $Limit |
                    ForEach-Object { ConvertTo-AdmUserObject -Raw $_ -DomainName $ctx.Domain.Name }
            }
        }
    }
}

function Get-AdmGroup {
    <#
    .SYNOPSIS
      Find groups in whichever domain the target belongs to.
    .DESCRIPTION
      ⚠ The Members list here is NOT reliable above ~1500. AD pages the `member` attribute and
      returns nothing at all past the boundary, so a very large group appears EMPTY. That is
      tolerated in this list view because counting properly costs a search per row. Use
      Get-AdmGroupMember to enumerate, or Get-AdmObjectDetail for an accurate count.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Identity,
        [string]$Tier,
        [int]$Limit = 200,
        # Scope a listing to one container, which is what makes an OU browser possible.
        [string]$SearchBase,
        [ValidateSet('Subtree', 'OneLevel')][string]$Scope = 'Subtree',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation 'find groups' -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        switch (Get-AdmProviderName) {
            'mock' {
                Invoke-AdmMockSearch -Domain $ctx.Domain -ObjectClass 'groups' -Identity $Identity -SizeLimit $Limit |
                    ForEach-Object {
                        [pscustomobject]@{
                            Domain = $ctx.Domain.Name; SamAccountName = $_.samAccountName; Name = $_.name
                            DistinguishedName = $_.distinguishedName; Members = @($_.members); ObjectClass = 'group'
                        }
                    }
            }
            default {
                $filter = if ($Identity) {
                    $v = ConvertTo-AdmLdapFilterValue -Value $Identity
                    "(&(objectCategory=group)(|(sAMAccountName=*$v*)(name=*$v*)))"
                } else { '(objectCategory=group)' }
                Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential -Filter $filter `
                    -Properties @('samaccountname', 'name', 'distinguishedname', 'member') `
                    -SearchBase $SearchBase -Scope $Scope -SizeLimit $Limit |
                    ForEach-Object {
                        # Same rule as users: an empty group has no `member` attribute at all.
                        #
                        # ⚠ AND THIS LIST IS NOT RELIABLE ABOVE 1500. AD pages `member`, returning
                        # it as `member;range=0-1499`, so a request for `member` on a larger group
                        # comes back EMPTY rather than truncated -- a 4000-member group looks like
                        # an empty one here. That is tolerated in this LIST view because counting
                        # properly costs one extra search per row and this returns up to 5000 rows.
                        # Anything that needs a true count uses Get-AdmObjectDetail (which counts
                        # by search) or Get-AdmGroupMember (which enumerates by search).
                        # ⛔ VIA Get-AdmRangedProp, NOT Get-AdmRawProp. Past ~1500 members AD
                        # renames the attribute, so a plain read of `member` returns NOTHING and
                        # a 3000-member group reports ZERO. MembersTruncated says which it is.
                        $mem = Get-AdmRangedProp $_ 'member'
                        [pscustomobject]@{
                            Domain = $ctx.Domain.Name
                            SamAccountName = Get-AdmRawProp $_ 'samaccountname'
                            Name = Get-AdmRawProp $_ 'name'
                            DistinguishedName = Get-AdmRawProp $_ 'distinguishedname'
                            Members = @($mem.Values)
                            MembersTruncated = $mem.Truncated
                            ObjectClass = 'group'
                        }
                    }
            }
        }
    }
}

function Get-AdmComputer {
    <#
    .SYNOPSIS
      Find computers in whichever domain the target belongs to.
    .DESCRIPTION
      IsDomainController is derived from userAccountControl 0x2000 and is what keeps a staleness
      sweep away from a DC. PasswordLastSet is the more reliable staleness signal for a machine:
      a live member rotates its own account password every 30 days and that replicates normally,
      whereas lastLogonTimestamp is deliberately lazy.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Identity,
        [string]$Tier,
        [int]$Limit = 200,
        # Scope a listing to one container, which is what makes an OU browser possible.
        [string]$SearchBase,
        [ValidateSet('Subtree', 'OneLevel')][string]$Scope = 'Subtree',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation 'find computers' -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        switch (Get-AdmProviderName) {
            'mock' {
                Invoke-AdmMockSearch -Domain $ctx.Domain -ObjectClass 'computers' -Identity $Identity -SizeLimit $Limit |
                    ForEach-Object {
                        # Same shape as the adsi branch below, INCLUDING the fields a fixture has
                        # no natural value for -- a consumer under Set-StrictMode throws on a
                        # missing property, so a narrower mock object would fail only on the
                        # mock path, which is exactly backwards.
                        [pscustomobject]@{
                            Domain = $ctx.Domain.Name; Name = $_.name; DnsHostName = $_.dnsHostName
                            OperatingSystem = $_.operatingSystem
                            OperatingSystemVersion = (Get-AdmRawProp $_ 'operatingSystemVersion')
                            DistinguishedName = $_.distinguishedName
                            Enabled = $(if ($null -ne $_.enabled) { [bool]$_.enabled } else { $true })
                            IsDomainController = [bool](Get-AdmRawProp $_ 'isDomainController' $false)
                            LastLogonTimestamp = ConvertFrom-AdmFileTime (Get-AdmRawProp $_ 'lastLogonTimestamp')
                            PasswordLastSet = ConvertFrom-AdmFileTime (Get-AdmRawProp $_ 'pwdLastSet')
                            WhenCreated = (Get-AdmRawProp $_ 'whenCreated')
                            ObjectClass = 'computer'
                        }
                    }
            }
            default {
                $filter = if ($Identity) {
                    $v = ConvertTo-AdmLdapFilterValue -Value $Identity
                    "(&(objectCategory=computer)(|(name=*$v*)(dNSHostName=*$v*)))"
                } else { '(objectCategory=computer)' }
                Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential -Filter $filter `
                    -Properties @('name', 'dnshostname', 'operatingsystem', 'operatingsystemversion',
                                  'distinguishedname', 'useraccountcontrol', 'lastlogontimestamp',
                                  'pwdlastset', 'whencreated') `
                    -SearchBase $SearchBase -Scope $Scope -SizeLimit $Limit |
                    ForEach-Object {
                        # A computer object that has never registered a DNS name has no
                        # dNSHostName; a freshly-created one may have no operatingSystem.
                        $uac = 0; [void][int]::TryParse([string](Get-AdmRawProp $_ 'useraccountcontrol' 0), [ref]$uac)
                        [pscustomobject]@{
                            Domain = $ctx.Domain.Name
                            Name = Get-AdmRawProp $_ 'name'
                            DnsHostName = Get-AdmRawProp $_ 'dnshostname'
                            OperatingSystem = Get-AdmRawProp $_ 'operatingsystem'
                            OperatingSystemVersion = Get-AdmRawProp $_ 'operatingsystemversion'
                            DistinguishedName = Get-AdmRawProp $_ 'distinguishedname'
                            Enabled = -not (Test-AdmUacDisabled -Uac $uac)
                            # ⛔ SERVER_TRUST_ACCOUNT (0x2000) marks a DOMAIN CONTROLLER. Disabling
                            # one of these is not a cleanup, it is an outage -- every staleness
                            # sweep must exclude them, and a DC legitimately looks idle by these
                            # measures because nobody "logs on" to it the way a workstation does.
                            IsDomainController = [bool]($uac -band 0x2000)
                            LastLogonTimestamp = ConvertFrom-AdmFileTime (Get-AdmRawProp $_ 'lastlogontimestamp')
                            # ⭐ THE BETTER STALENESS SIGNAL FOR A COMPUTER. A live domain member
                            # rotates its own machine-account password every 30 days by default,
                            # and that write replicates normally -- unlike lastLogonTimestamp,
                            # which is deliberately lazy and can be ~14 days behind. A machine
                            # whose password has not changed in 60+ days is almost certainly gone.
                            PasswordLastSet = ConvertFrom-AdmFileTime (Get-AdmRawProp $_ 'pwdlastset')
                            WhenCreated = Get-AdmRawProp $_ 'whencreated'
                            ObjectClass = 'computer'
                        }
                    }
            }
        }
    }
}

function Unlock-AdmUser {
    <#
    .SYNOPSIS
      Clear a locked-out account. Writes -- honours -WhatIf.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Identity,
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "unlock account '$Identity'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        if (-not $PSCmdlet.ShouldProcess("$Identity @ $($ctx.Domain.DnsDomain)", 'Unlock account')) { return }

        $result = if ((Get-AdmProviderName) -eq 'mock') {
            $o = Invoke-AdmMockModify -Domain $ctx.Domain -ObjectClass 'users' -Identity $Identity -Set @{ lockoutTime = 0 }
            [pscustomobject]@{ Domain = $ctx.Domain.Name; SamAccountName = $o.samAccountName; LockedOut = $false; Action = 'unlock' }
        } else {
            $v = ConvertTo-AdmLdapFilterValue -Value $Identity
            $entry = Get-AdmSingleEntry -Context $ctx -Filter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$v))" -Identity $Identity
            try {
                $entry.Properties['lockoutTime'].Value = 0
                $entry.CommitChanges()
                [pscustomobject]@{ Domain = $ctx.Domain.Name; SamAccountName = $Identity; LockedOut = $false; Action = 'unlock' }
            } finally { Close-AdmDirectoryEntry $entry }
        }
        [void](Write-AdmLogEntry -Severity info -Event 'change' -Operation 'unlock account' `
                -Target $Target -Domain $ctx.Domain.Name -Message "Unlocked '$Identity' in $($ctx.Domain.DnsDomain)")
        $result
    }
}

function Set-AdmUserEnabled {
    <#
    .SYNOPSIS
      Enable or disable an account. Writes -- honours -WhatIf.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][bool]$Enabled,
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    $verb = if ($Enabled) { 'enable' } else { 'disable' }
    Invoke-AdmGuarded -Operation "$verb account '$Identity'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        if (-not $PSCmdlet.ShouldProcess("$Identity @ $($ctx.Domain.DnsDomain)", "$verb account")) { return }

        $result = if ((Get-AdmProviderName) -eq 'mock') {
            $cur = @(Invoke-AdmMockSearch -Domain $ctx.Domain -ObjectClass 'users' -Identity $Identity)[0]
            $uac = [int]$cur.useraccountcontrol
            $new = if ($Enabled) { $uac -band (-bnot 0x2) } else { $uac -bor 0x2 }
            $o = Invoke-AdmMockModify -Domain $ctx.Domain -ObjectClass 'users' -Identity $Identity -Set @{ useraccountcontrol = $new }
            [pscustomobject]@{ Domain = $ctx.Domain.Name; SamAccountName = $o.samAccountName; Enabled = $Enabled; Action = $verb }
        } else {
            $v = ConvertTo-AdmLdapFilterValue -Value $Identity
            $entry = Get-AdmSingleEntry -Context $ctx -Filter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$v))" -Identity $Identity
            try {
                $uac = [int]$entry.Properties['userAccountControl'].Value
                $entry.Properties['userAccountControl'].Value = if ($Enabled) { $uac -band (-bnot 0x2) } else { $uac -bor 0x2 }
                $entry.CommitChanges()
                [pscustomobject]@{ Domain = $ctx.Domain.Name; SamAccountName = $Identity; Enabled = $Enabled; Action = $verb }
            } finally { Close-AdmDirectoryEntry $entry }
        }
        [void](Write-AdmLogEntry -Severity info -Event 'change' -Operation "$verb account" `
                -Target $Target -Domain $ctx.Domain.Name -Message "Set '$Identity' enabled=$Enabled in $($ctx.Domain.DnsDomain)")
        $result
    }
}

function Set-AdmComputerEnabled {
    <#
    .SYNOPSIS
      Enable or disable a COMPUTER account. Writes -- honours -WhatIf.
    .DESCRIPTION
      Separate from Set-AdmUserEnabled because that one filters on (objectCategory=person), which
      a computer object is not -- pointing it at a machine returns "No object matching".

      ⛔ IT REFUSES TO DISABLE A DOMAIN CONTROLLER, and the refusal lives HERE rather than in the
      calling script on purpose: this is the one mistake in a computer-cleanup sweep that is an
      outage rather than an inconvenience, and a check in one caller does not protect the next
      caller. A DC also looks idle by every measure a staleness sweep uses -- nobody interactively
      logs on to it -- so it is exactly the object such a sweep is most likely to select.
      There is deliberately no override switch.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Identity,   # machine name, with or without the trailing $
        [Parameter(Mandatory)][bool]$Enabled,
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    $verb = if ($Enabled) { 'enable' } else { 'disable' }
    # A computer's sAMAccountName always ends in '$'; the name people type never does.
    $sam = if ($Identity.EndsWith('$')) { $Identity } else { "$Identity`$" }
    Invoke-AdmGuarded -Operation "$verb computer '$Identity'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        if (-not $PSCmdlet.ShouldProcess("$Identity @ $($ctx.Domain.DnsDomain)", "$verb computer account")) { return }

        $result = if ((Get-AdmProviderName) -eq 'mock') {
            $cur = @(Invoke-AdmMockSearch -Domain $ctx.Domain -ObjectClass 'computers' -Identity $Identity)[0]
            if (-not $cur) { throw "No computer matching '$Identity' in $($ctx.Domain.DnsDomain)." }
            if (-not $Enabled -and (Get-AdmRawProp $cur 'isDomainController' $false)) {
                throw "'$Identity' is a DOMAIN CONTROLLER. Disabling a DC's computer account takes the domain controller offline; refusing."
            }
            $o = Invoke-AdmMockModify -Domain $ctx.Domain -ObjectClass 'computers' -Identity $Identity -Set @{ enabled = $Enabled }
            [pscustomobject]@{ Domain = $ctx.Domain.Name; Name = $o.name; Enabled = $Enabled; Action = $verb }
        } else {
            $v = ConvertTo-AdmLdapFilterValue -Value $sam
            $entry = Get-AdmSingleEntry -Context $ctx -Filter "(&(objectCategory=computer)(sAMAccountName=$v))" -Identity $Identity
            try {
                $uac = [int]$entry.Properties['userAccountControl'].Value
                # 0x2000 SERVER_TRUST_ACCOUNT. Checked against the directory's own value, not
                # against whatever the caller believed when it built its list.
                if (-not $Enabled -and ($uac -band 0x2000)) {
                    throw "'$Identity' is a DOMAIN CONTROLLER (userAccountControl 0x2000). Disabling a DC's computer account takes that domain controller offline; refusing."
                }
                $entry.Properties['userAccountControl'].Value = if ($Enabled) { $uac -band (-bnot 0x2) } else { $uac -bor 0x2 }
                $entry.CommitChanges()
                [pscustomobject]@{ Domain = $ctx.Domain.Name; Name = $Identity; Enabled = $Enabled; Action = $verb }
            } finally { Close-AdmDirectoryEntry $entry }
        }
        [void](Write-AdmLogEntry -Severity info -Event 'change' -Operation "$verb computer" `
                -Target $Target -Domain $ctx.Domain.Name -Message "Set computer '$Identity' enabled=$Enabled in $($ctx.Domain.DnsDomain)")
        $result
    }
}

function Reset-AdmUserPassword {
    <#
    .SYNOPSIS
      Set a new password. Writes -- honours -WhatIf.
    .DESCRIPTION
      The new password is taken as a SecureString and converted only at the moment of the call.
      It is never echoed, logged, or included in the returned object.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][System.Security.SecureString]$NewPassword,
        [switch]$MustChangeAtNextLogon,
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "reset password for '$Identity'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        if (-not $PSCmdlet.ShouldProcess("$Identity @ $($ctx.Domain.DnsDomain)", 'Reset password')) { return }

        # ⚠ No warning here about port 389 any more, and that is a CORRECTION. This used to warn
        # that AD refuses password changes over plain LDAP -- which is the wrong explanation and
        # was measured wrong: the connection on 389 is SEALED (encrypted), and writing unicodePwd
        # over it works against a real DC. What actually failed before was ADSI's SetPassword
        # falling back to RPC. See Set-AdmEntryPassword.

        $result = if ((Get-AdmProviderName) -eq 'mock') {
            $set = @{ pwdLastSet = $(if ($MustChangeAtNextLogon) { 0 } else { [DateTime]::UtcNow.ToFileTimeUtc() }) }
            $o = Invoke-AdmMockModify -Domain $ctx.Domain -ObjectClass 'users' -Identity $Identity -Set $set
            [pscustomobject]@{ Domain = $ctx.Domain.Name; SamAccountName = $o.samAccountName
                               MustChangeAtNextLogon = [bool]$MustChangeAtNextLogon; Action = 'reset-password' }
        } else {
            $v = ConvertTo-AdmLdapFilterValue -Value $Identity
            $entry = Get-AdmSingleEntry -Context $ctx -Filter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$v))" -Identity $Identity
            try {
                $plain = ConvertFrom-AdmSecureString -Secure $NewPassword
                try { $null = Set-AdmEntryPassword -Entry $entry -Plain $plain } finally { $plain = $null }
                if ($MustChangeAtNextLogon) {
                    # Must be a SEPARATE commit, after the password one. Setting pwdLastSet in the
                    # same modify as unicodePwd is rejected.
                    $entry.Properties['pwdLastSet'].Value = 0
                    $entry.CommitChanges()
                }
                [pscustomobject]@{ Domain = $ctx.Domain.Name; SamAccountName = $Identity
                                   MustChangeAtNextLogon = [bool]$MustChangeAtNextLogon; Action = 'reset-password' }
            } finally { Close-AdmDirectoryEntry $entry }
        }
        # The password itself is never in the message -- only the fact of the change.
        [void](Write-AdmLogEntry -Severity info -Event 'change' -Operation 'reset password' `
                -Target $Target -Domain $ctx.Domain.Name -Message "Password reset for '$Identity' in $($ctx.Domain.DnsDomain)")
        $result
    }
}

# Bind to exactly one object or refuse. A write that matched two accounts and silently took the
# first is the kind of mistake that is only discovered by its consequences.
function Get-AdmSingleEntry {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Filter, [Parameter(Mandatory)][string]$Identity)
    $root = New-AdmDirectoryEntry -Domain $Context.Domain -Credential $Context.Credential
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
        try {
            $searcher.Filter = $Filter
            $searcher.SizeLimit = 2
            $found = @($searcher.FindAll())
            if ($found.Count -eq 0) { throw "No object matching '$Identity' in $($Context.Domain.DnsDomain)." }
            if ($found.Count -gt 1) { throw "'$Identity' matched more than one object in $($Context.Domain.DnsDomain); refusing to guess." }
            $found[0].GetDirectoryEntry()
        } finally { $searcher.Dispose() }
    } finally { Close-AdmDirectoryEntry $root }
}

function Test-AdmDomain {
    <#
    .SYNOPSIS
      Prove the stored credential actually binds, and say plainly why it did not.
    .DESCRIPTION
      Reports unknown rather than healthy on failure. -Deep also probes the LDAP ports from this
      machine, which separates "cannot reach the DC" from "reached it and it said no" -- two
      problems with completely different fixes that produce similar-looking errors.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Tier,
        [switch]$UseDnsLookup,
        [switch]$Deep
    )
    $started = Get-Date
    try {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
    } catch {
        $d = Resolve-AdmDiagnosis -ErrorObject $_ -Operation 'test domain' -Target $Target
        [void](Write-AdmLogEntry -Severity $d.Severity -Event 'failure' -Message $_.Exception.Message `
                -Operation 'test domain' -Target $Target -Diagnosis $d)
        return [pscustomobject]@{ Target = $Target; Domain = $null; Reachable = $false
                                  Status = 'unresolved'; Detail = $d.Title; Diagnosis = $d
                                  Provider = (Get-AdmProviderName) }
    }

    if ((Get-AdmProviderName) -eq 'mock') {
        return [pscustomobject]@{ Target = $Target; Domain = $ctx.Domain.Name; Reachable = $true
                                  Status = 'mock'; Detail = 'fixture provider -- proves nothing about a real DC'
                                  Diagnosis = $null; Provider = 'mock'; ElapsedMs = 0 }
    }

    $ports = $null
    if ($Deep) { $ports = Test-AdmDomainPort -Domain $ctx.Domain }

    try {
        $root = New-AdmDirectoryEntry -Domain $ctx.Domain -Credential $ctx.Credential
        try {
            # RefreshCache() forces the bind AND raises the real directory error.
            # ⚠ Do NOT force it by reading a property instead: on a failed bind `.Properties` is
            # a NULL collection, so `$root.Properties['x']` throws "Cannot index into a null
            # array" -- a PowerShell error that replaces the directory's own and makes every
            # connection failure land as UNRECOGNISED. Measured against a lab domain controller over LDAPS, 2026-08-27.
            $root.RefreshCache()
            $dn = $root.Properties['distinguishedName'].Value
            [pscustomobject]@{
                Target = $Target; Domain = $ctx.Domain.Name; Reachable = $true; Status = 'bound'
                Detail = "$dn"; Diagnosis = $null; Provider = 'adsi'; Ports = $ports
                ElapsedMs = [int]((Get-Date) - $started).TotalMilliseconds
            }
        } finally { Close-AdmDirectoryEntry $root }
    } catch {
        # Probe the ONE port we just tried, on the failure path only. It costs a second and it is
        # what separates "the DC is unreachable" from "the DC answered and the TLS handshake
        # failed" -- identical error codes, completely different fixes.
        $thisPort = if ($ctx.Domain.Port) { $ctx.Domain.Port } elseif ($ctx.Domain.UseSsl) { 636 } else { 389 }
        $portOpen = $false
        if ($ports) {
            $portOpen = [bool](@($ports | Where-Object { $_.Port -eq $thisPort -and $_.Open })).Count
        } else {
            try {
                $probe = @(Test-AdmDomainPort -Domain $ctx.Domain | Where-Object { $_.Port -eq $thisPort })
                $portOpen = [bool]($probe -and $probe[0].Open)
            } catch { }
        }
        $d = Resolve-AdmDiagnosis -ErrorObject $_ -Operation 'bind to domain controller' -Target $Target `
                -Hint @{ UseSsl = [bool]$ctx.Domain.UseSsl; PortOpen = $portOpen; Port = $thisPort }
        [void](Write-AdmLogEntry -Severity $d.Severity -Event 'failure' -Message $_.Exception.Message `
                -Operation 'bind to domain controller' -Target $Target -Domain $ctx.Domain.Name -Diagnosis $d)
        [pscustomobject]@{
            Target = $Target; Domain = $ctx.Domain.Name; Reachable = $false; Status = 'bind-failed'
            Detail = $d.Title; Diagnosis = $d; Provider = 'adsi'; Ports = $ports
            ElapsedMs = [int]((Get-Date) - $started).TotalMilliseconds
        }
    }
}

# Cheap TCP reachability for the ports this toolkit uses. Not a substitute for a bind, but it
# answers the one question a bind failure cannot: was anything listening at all.
function Test-AdmDomainPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Domain,
        [int]$TimeoutMs = 1500,
        # Probe ONE port instead of all three. A scan asks about the configured port far more
        # often than about all of them, and three sequential 1.5s timeouts against an
        # unreachable host is most of a scan's wall-clock.
        [int]$Port
    )
    $server = Get-AdmLdapServer -Domain $Domain
    $checks = @(
        @{ Port = 389;  Name = 'LDAP' }
        @{ Port = 636;  Name = 'LDAPS' }
        @{ Port = 3268; Name = 'GlobalCatalog' }
    )
    if ($Port) {
        $named = @($checks | Where-Object { $_.Port -eq $Port })
        $checks = if ($named) { $named } else { @(@{ Port = $Port; Name = "port$Port" }) }
    }
    foreach ($c in $checks) {
        $open = $false; $err = $null
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $client.BeginConnect($server, $c.Port, $null, $null)
            $open = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $client.Connected
        } catch { $err = $_.Exception.Message } finally { $client.Close() }
        [pscustomobject]@{ Server = $server; Name = $c.Name; Port = $c.Port; Open = $open; Error = $err }
    }
}

function Get-AdmSearchResult {
    <#
    .SYNOPSIS
      Run a raw LDAP filter against whichever domain the target resolves to.
    .DESCRIPTION
      The escape hatch for scripts that need an attribute or a filter the typed cmdlets do not
      cover. It still resolves the domain and picks the credential through the store, so a script
      using it cannot accidentally aim at the wrong forest.

      Results are raw: attribute names are lowercase LDAP names and unset attributes are ABSENT,
      so read them with Get-AdmRawProp rather than direct property access.
    .EXAMPLE
      Get-AdmSearchResult -Target corp.example.com -Filter '(servicePrincipalName=*)' -Properties samaccountname,serviceprincipalname
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Filter,
        [string[]]$Properties = @(),
        [string]$SearchBase,
        # OneLevel lists what is directly IN a container, which is what a browser needs.
        [ValidateSet('Subtree', 'OneLevel', 'Base')][string]$Scope = 'Subtree',
        [int]$Limit = 1000,
        [string]$Tier,
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation 'directory search' -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        if ((Get-AdmProviderName) -eq 'mock') {
            # The fixture has no general query engine, and inventing one would let a script pass
            # here and fail against a real directory. Say so instead.
            throw 'Get-AdmSearchResult needs a real directory; the mock provider has no query engine.'
        }
        Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential -Filter $Filter `
            -Properties $Properties -SearchBase $SearchBase -Scope $Scope -SizeLimit $Limit
    }
}

function Set-AdmProvider {
    <#
    .SYNOPSIS
      Choose the directory backend: 'adsi' for real domains, 'mock' for the fixture.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('adsi', 'mock')][string]$Name)
    Set-AdmProviderName -Name $Name
    Clear-AdmMockData
    [pscustomobject]@{ Provider = Get-AdmProviderName }
}
