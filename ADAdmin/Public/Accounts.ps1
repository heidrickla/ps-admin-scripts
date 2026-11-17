# Public/Accounts.ps1 -- creating accounts, group membership, and the domain password policy.
#
# Everything here goes through the same guard, log and -WhatIf as the rest of the module, and
# writes over the LDAP connection the credential store resolved. No RSAT.

function Get-AdmPasswordPolicy {
    <#
    .SYNOPSIS
      The domain's password and lockout policy, as numbers you can compute with.
    .DESCRIPTION
      Read from the domain naming context. MaxPasswordAgeDays is what "expiring soon" is measured
      against.

      ⚠ THIS IS THE DEFAULT DOMAIN POLICY ONLY. Fine-grained password policies (PSOs) can override
      it for specific users or groups, and nothing here reads those -- so an account governed by a
      PSO may expire on a different schedule than this implies. Treat an expiry date computed from
      this as indicative, not authoritative, wherever PSOs are in use.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Tier,
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation 'read the domain password policy' -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup

        if ((Get-AdmProviderName) -eq 'mock') {
            return [pscustomobject]@{
                Domain = $ctx.Domain.Name; MaxPasswordAgeDays = 90; MinPasswordAgeDays = 1
                MinPasswordLength = 14; PasswordHistoryLength = 24
                LockoutThreshold = 5; LockoutDurationMinutes = 30; Source = 'mock'
            }
        }

        # ⚠ READ VIA A SEARCH, not DirectoryEntry.Properties. maxPwdAge, minPwdAge and
        # lockoutDuration are LargeInteger attributes: a search returns them as Int64, a
        # DirectoryEntry returns a COM object whose ToString is "System.__ComObject". Reading
        # them the other way silently produced a BLANK maximum password age against a real DC --
        # and a blank max age means "expiring soon" quietly matches nothing at all.
        # This repo already documented that trap; it still caught us here.
        $row = @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential `
                    -Filter '(objectClass=domainDNS)' -SizeLimit 1 `
                    -Properties @('maxpwdage', 'minpwdage', 'minpwdlength', 'pwdhistorylength',
                                  'lockoutthreshold', 'lockoutduration'))[0]

        # Negative 100-nanosecond intervals. Int64.MinValue means "never expires".
        $toDays = {
            param($v)
            $n = 0L
            if (-not [int64]::TryParse([string]$v, [ref]$n)) { return $null }
            if ($n -eq [int64]::MinValue -or $n -eq 0) { return $null }
            [math]::Round([math]::Abs($n) / 864000000000.0, 2)
        }
        $toMinutes = {
            param($v)
            $d = & $toDays $v
            if ($null -eq $d) { $null } else { [math]::Round($d * 1440, 1) }
        }

        [pscustomobject]@{
            Domain                 = $ctx.Domain.Name
            MaxPasswordAgeDays     = & $toDays (Get-AdmRawProp $row 'maxpwdage')
            MinPasswordAgeDays     = & $toDays (Get-AdmRawProp $row 'minpwdage')
            MinPasswordLength      = [int](Get-AdmRawProp $row 'minpwdlength' 0)
            PasswordHistoryLength  = [int](Get-AdmRawProp $row 'pwdhistorylength' 0)
            LockoutThreshold       = [int](Get-AdmRawProp $row 'lockoutthreshold' 0)
            LockoutDurationMinutes = & $toMinutes (Get-AdmRawProp $row 'lockoutduration')
            Source                 = 'default domain policy (fine-grained policies not read)'
        }
    }
}

function New-AdmUser {
    <#
    .SYNOPSIS
      Create a user account. Writes -- honours -WhatIf.
    .DESCRIPTION
      Creates the object, sets the password over the encrypted LDAP channel, then enables it.
      The order matters: Active Directory refuses to enable an account that has no password
      meeting policy, so enabling before setting one fails with "unwilling to perform".
    .EXAMPLE
      New-AdmUser -Target corp.example.com -SamAccountName jbloggs -DisplayName 'Jo Bloggs' -Password $p
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$SamAccountName,
        [string]$DisplayName,
        [string]$UserPrincipalName,
        [Parameter(Mandatory)][System.Security.SecureString]$Password,
        # Where to put it. Defaults to the domain's Users container, which is what most estates
        # expect for a hand-created account.
        [string]$Path,
        [bool]$Enabled = $true,
        [switch]$MustChangeAtNextLogon,
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "create user '$SamAccountName'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        if (-not $PSCmdlet.ShouldProcess("$SamAccountName @ $($ctx.Domain.DnsDomain)", 'Create user account')) { return }

        if ((Get-AdmProviderName) -eq 'mock') {
            return [pscustomobject]@{ Domain = $ctx.Domain.Name; SamAccountName = $SamAccountName
                                      Enabled = $Enabled; Action = 'create-user'; Path = $Path }
        }

        $base = if ($Path) { $Path } else { "CN=Users,$(ConvertTo-AdmDistinguishedName -DnsDomain $ctx.Domain.DnsDomain)" }
        $container = New-AdmDirectoryEntry -Domain $ctx.Domain -Credential $ctx.Credential -DistinguishedName $base
        $entry = $null
        try {
            $entry = $container.Children.Add("CN=$SamAccountName", 'user')
            $entry.Properties['sAMAccountName'].Value = $SamAccountName
            if ($DisplayName) { $entry.Properties['displayName'].Value = $DisplayName }
            $upn = if ($UserPrincipalName) { $UserPrincipalName } else { "$SamAccountName@$($ctx.Domain.DnsDomain)" }
            $entry.Properties['userPrincipalName'].Value = $upn
            $entry.CommitChanges()

            $plain = ConvertFrom-AdmSecureString -Secure $Password
            try { $null = Set-AdmEntryPassword -Entry $entry -Plain $plain } finally { $plain = $null }

            if ($Enabled) {
                $entry.Properties['userAccountControl'].Value = 512   # NORMAL_ACCOUNT
                $entry.CommitChanges()
            }
            if ($MustChangeAtNextLogon) {
                $entry.Properties['pwdLastSet'].Value = 0
                $entry.CommitChanges()
            }

            [void](Write-AdmLogEntry -Severity info -Event 'change' -Operation 'create user' `
                    -Target $Target -Domain $ctx.Domain.Name `
                    -Message "Created '$SamAccountName' in $($ctx.Domain.DnsDomain) under $base (enabled=$Enabled)")

            [pscustomobject]@{
                Domain = $ctx.Domain.Name; SamAccountName = $SamAccountName
                UserPrincipalName = $upn; DistinguishedName = [string]$entry.Properties['distinguishedName'].Value
                Enabled = $Enabled; Action = 'create-user'
            }
        } finally {
            Close-AdmDirectoryEntry $entry
            Close-AdmDirectoryEntry $container
        }
    }
}

# A computer's sAMAccountName ends in '$', and people never type the '$'. Accept either form
# rather than making the caller remember, and match on objectCategory=computer so a user-shaped
# filter cannot silently find nothing.
function Remove-AdmSpn {
    <#
    .SYNOPSIS
      Remove one service principal name from an account. Writes -- honours -WhatIf.
    .DESCRIPTION
      For clearing a DUPLICATE SPN. An SPN must be unique in the forest: while two accounts claim
      the same one, Kerberos issues a ticket for neither, so the service fails to authenticate.

      ⚠ Removing it from the WRONG account breaks the half that was working. The SPN belongs on
      whichever account actually runs the service; this cmdlet does not and cannot know which
      that is, so it removes exactly what it is told and nothing more.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][string]$Spn,
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "remove SPN '$Spn' from '$Identity'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        if (-not $PSCmdlet.ShouldProcess("$Identity @ $($ctx.Domain.DnsDomain)", "Remove SPN '$Spn'")) { return }

        if ((Get-AdmProviderName) -eq 'mock') {
            return [pscustomobject]@{ Domain = $ctx.Domain.Name; Identity = $Identity; Spn = $Spn
                                      Action = 'remove-spn'; Result = 'removed' }
        }

        $v = ConvertTo-AdmLdapFilterValue -Value $Identity
        $bare = $v.TrimEnd('$')
        # Either an account type can hold an SPN, so do not assume a computer.
        $entry = Get-AdmSingleEntry -Context $ctx -Identity $Identity `
            -Filter "(|(sAMAccountName=$v)(sAMAccountName=$bare`$)(sAMAccountName=$bare))"
        try {
            $current = @($entry.Properties['servicePrincipalName'])
            # Case-insensitive: the KDC treats SPNs that way, so a case-only mismatch is still the
            # same SPN and must still be removable.
            $match = @($current | Where-Object { $_ -and ([string]$_).ToLowerInvariant() -eq $Spn.ToLowerInvariant() })
            if (-not $match.Count) {
                return [pscustomobject]@{ Domain = $ctx.Domain.Name; Identity = $Identity; Spn = $Spn
                                          Action = 'remove-spn'; Result = 'not-present' }
            }
            foreach ($m in $match) { $entry.Properties['servicePrincipalName'].Remove($m) }
            $entry.CommitChanges()

            [void](Write-AdmLogEntry -Severity info -Event 'change' -Operation 'remove SPN' `
                    -Target $Target -Domain $ctx.Domain.Name `
                    -Message "Removed SPN '$Spn' from '$Identity' in $($ctx.Domain.DnsDomain)")

            [pscustomobject]@{ Domain = $ctx.Domain.Name; Identity = $Identity; Spn = $Spn
                               Action = 'remove-spn'; Result = 'removed' }
        } finally { Close-AdmDirectoryEntry $entry }
    }
}

function Get-AdmMemberFilter {
    param([string]$MemberType, [string]$Escaped)
    if ($MemberType -eq 'Computer') {
        $bare = $Escaped.TrimEnd('$')
        "(&(objectCategory=computer)(|(sAMAccountName=$bare`$)(sAMAccountName=$bare)(cn=$bare)))"
    } else {
        "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$Escaped))"
    }
}

function Remove-AdmGroupMember {
    <#
    .SYNOPSIS
      Remove an account or computer from a group. Writes -- honours -WhatIf.
    .DESCRIPTION
      Removing someone who is not a member is reported as 'not-a-member' rather than failing, so
      a membership script is safe to re-run.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Group,
        [Parameter(Mandatory)][string]$Identity,
        [ValidateSet('User', 'Computer')][string]$MemberType = 'User',
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "remove '$Identity' from group '$Group'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        if (-not $PSCmdlet.ShouldProcess("$Identity from $Group @ $($ctx.Domain.DnsDomain)", 'Remove group member')) { return }

        if ((Get-AdmProviderName) -eq 'mock') {
            return [pscustomobject]@{ Domain = $ctx.Domain.Name; Group = $Group; Member = $Identity
                                      Action = 'remove-group-member'; Result = 'removed' }
        }

        $gv = ConvertTo-AdmLdapFilterValue -Value $Group
        $uv = ConvertTo-AdmLdapFilterValue -Value $Identity
        $groupEntry = Get-AdmSingleEntry -Context $ctx -Identity $Group `
            -Filter "(&(objectCategory=group)(|(sAMAccountName=$gv)(cn=$gv)))"
        try {
            $memberEntry = Get-AdmSingleEntry -Context $ctx -Identity $Identity `
                -Filter (Get-AdmMemberFilter -MemberType $MemberType -Escaped $uv)
            $dn = $null
            try { $dn = [string]$memberEntry.Properties['distinguishedName'].Value }
            finally { Close-AdmDirectoryEntry $memberEntry }

            if (@($groupEntry.Properties['member']) -notcontains $dn) {
                return [pscustomobject]@{ Domain = $ctx.Domain.Name; Group = $Group; Member = $Identity
                                          Action = 'remove-group-member'; Result = 'not-a-member' }
            }
            $groupEntry.Properties['member'].Remove($dn)
            $groupEntry.CommitChanges()

            [void](Write-AdmLogEntry -Severity info -Event 'change' -Operation 'remove group member' `
                    -Target $Target -Domain $ctx.Domain.Name `
                    -Message "Removed '$Identity' from group '$Group' in $($ctx.Domain.DnsDomain)")

            [pscustomobject]@{ Domain = $ctx.Domain.Name; Group = $Group; Member = $Identity
                               MemberDn = $dn; Action = 'remove-group-member'; Result = 'removed' }
        } finally { Close-AdmDirectoryEntry $groupEntry }
    }
}

function Add-AdmGroupMember {
    <#
    .SYNOPSIS
      Add an account to a group. Writes -- honours -WhatIf.
    .DESCRIPTION
      Membership is a link on the GROUP, not on the member, so this edits the group's `member`
      attribute. Adding someone who is already in the group is reported as 'already-member'
      rather than failing -- re-running a membership script must be safe.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Group,
        [Parameter(Mandatory)][string]$Identity,
        # A computer's own account name ends in '$' and its objectCategory is computer, not
        # person -- so a user-shaped filter silently finds nothing for a machine.
        [ValidateSet('User', 'Computer')][string]$MemberType = 'User',
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "add '$Identity' to group '$Group'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        if (-not $PSCmdlet.ShouldProcess("$Identity -> $Group @ $($ctx.Domain.DnsDomain)", 'Add group member')) { return }

        if ((Get-AdmProviderName) -eq 'mock') {
            return [pscustomobject]@{ Domain = $ctx.Domain.Name; Group = $Group; Member = $Identity
                                      Action = 'add-group-member'; Result = 'added' }
        }

        $gv = ConvertTo-AdmLdapFilterValue -Value $Group
        $uv = ConvertTo-AdmLdapFilterValue -Value $Identity

        $groupEntry = Get-AdmSingleEntry -Context $ctx -Identity $Group `
            -Filter "(&(objectCategory=group)(|(sAMAccountName=$gv)(cn=$gv)))"
        try {
            $memberFilter = Get-AdmMemberFilter -MemberType $MemberType -Escaped $uv
            $userEntry = Get-AdmSingleEntry -Context $ctx -Identity $Identity -Filter $memberFilter
            $userDn = $null
            try { $userDn = [string]$userEntry.Properties['distinguishedName'].Value }
            finally { Close-AdmDirectoryEntry $userEntry }

            $existing = @($groupEntry.Properties['member'])
            if ($existing -contains $userDn) {
                return [pscustomobject]@{ Domain = $ctx.Domain.Name; Group = $Group; Member = $Identity
                                          Action = 'add-group-member'; Result = 'already-member' }
            }

            [void]$groupEntry.Properties['member'].Add($userDn)
            $groupEntry.CommitChanges()

            [void](Write-AdmLogEntry -Severity info -Event 'change' -Operation 'add group member' `
                    -Target $Target -Domain $ctx.Domain.Name `
                    -Message "Added '$Identity' to group '$Group' in $($ctx.Domain.DnsDomain)")

            [pscustomobject]@{ Domain = $ctx.Domain.Name; Group = $Group; Member = $Identity
                               MemberDn = $userDn; Action = 'add-group-member'; Result = 'added' }
        } finally { Close-AdmDirectoryEntry $groupEntry }
    }
}
