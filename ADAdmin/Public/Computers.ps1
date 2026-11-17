# Public/Computers.ps1 -- creating and editing computer accounts.
#
# Set-ComputerDomainMembership can JOIN a machine; nothing here could create the account first.
# That gap matters for two ordinary reasons:
#
#   1. A DELEGATED JOIN. Someone who is not a domain admin can join a machine if its account
#      already exists and they have rights on it. Without pre-staging, joining needs an account
#      that can create computer objects in the domain.
#   2. THE MACHINE LANDS IN THE RIGHT OU FROM THE FIRST BOOT. An unstaged join drops the account
#      into CN=Computers, which is a CONTAINER, not an organizational unit -- and Group Policy
#      cannot be linked to a container. So the machine applies none of the OU-linked policy anyone
#      expected, is moved later, and picks it up only after a reboot. Pre-staging into the right
#      OU is the whole point.

function New-AdmComputer {
    <#
    .SYNOPSIS
      Pre-stage a computer account so a machine can be joined into the right OU. Writes -- honours -WhatIf.
    .DESCRIPTION
      Creates the account in the state a join expects: sAMAccountName ending in '$' and
      userAccountControl 4096 (WORKSTATION_TRUST_ACCOUNT), which is ENABLED.

      ⛔ IT IS NOT CREATED DISABLED, and that is deliberate. A disabled computer account cannot be
      joined to -- the join fails with an access error that says nothing about the account being
      disabled -- so "create it safely disabled and enable it later" is a trap, not caution.

      ⚠ THE NAME LIMIT IS 15 CHARACTERS, not 20 and not 64. A computer's sAMAccountName is the
      NetBIOS name plus '$', and NetBIOS names cap at 15. The directory rejects a longer one with
      a message about attribute syntax that does not mention the limit, so it is checked here.

      ⚠ -Path MATTERS MORE THAN IT LOOKS. It defaults to CN=Computers, which is where an unstaged
      join would have put the machine anyway -- and that is a container, so no Group Policy can be
      linked to it. If you are pre-staging in order to control which policy applies, pass the OU.
    .EXAMPLE
      New-AdmComputer -Target corp.example.com -Name WS42 -Path 'OU=Workstations,DC=corp,DC=example,DC=com'
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Name,
        [string]$Path,
        [string]$Description,
        [string]$Location,
        # The DNS name the machine will register. Usually left alone -- the machine sets it on
        # join -- but useful when a monitoring system reads it before the machine is built.
        [string]$DnsHostName,
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "create computer '$Name'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup

        $bare = $Name.TrimEnd('$')
        if ($bare.Length -gt 15) {
            throw "'$bare' is $($bare.Length) characters. A computer's sAMAccountName is its NetBIOS name plus '`$', and NetBIOS names are limited to 15 characters; the directory would reject this with a message about attribute syntax that does not mention the limit."
        }
        if ($bare -match '[\\/:*?"<>|\.]') {
            throw "'$bare' contains a character that is not valid in a NetBIOS computer name (\ / : * ? "" < > | or a full stop)."
        }
        $sam = "$bare`$"

        $base = if ($Path) { $Path } else { "CN=Computers,$(ConvertTo-AdmDistinguishedName -DnsDomain $ctx.Domain.DnsDomain)" }
        $dn = "CN=$(ConvertTo-AdmRdnEscaped -Value $bare),$base"
        if (-not $PSCmdlet.ShouldProcess($dn, 'Pre-stage computer account')) { return }

        if ((Get-AdmProviderName) -eq 'mock') {
            return [pscustomobject]@{ Domain = $ctx.Domain.Name; Name = $bare; SamAccountName = $sam
                                      DistinguishedName = $dn; Enabled = $true
                                      DnsHostName = $DnsHostName; Action = 'create-computer' }
        }

        $container = New-AdmDirectoryEntry -Domain $ctx.Domain -Credential $ctx.Credential -DistinguishedName $base
        $entry = $null
        try {
            $entry = $container.Children.Add("CN=$bare", 'computer')
            $entry.Properties['sAMAccountName'].Value = $sam
            # 4096 = WORKSTATION_TRUST_ACCOUNT. Set at creation rather than after, because an
            # account committed without it is a malformed computer object that a join rejects.
            $entry.Properties['userAccountControl'].Value = 4096
            if ($Description) { $entry.Properties['description'].Value = $Description }
            if ($Location)    { $entry.Properties['location'].Value = $Location }
            if ($DnsHostName) { $entry.Properties['dNSHostName'].Value = $DnsHostName }
            $entry.CommitChanges()

            [void](Write-AdmLogEntry -Severity info -Event 'change' -Operation 'create computer' `
                    -Target $Target -Domain $ctx.Domain.Name `
                    -Message "Pre-staged computer '$dn' in $($ctx.Domain.DnsDomain)")

            [pscustomobject]@{
                Domain = $ctx.Domain.Name; Name = $bare; SamAccountName = $sam
                DistinguishedName = [string]$entry.Properties['distinguishedName'].Value
                Enabled = $true; DnsHostName = $DnsHostName; Action = 'create-computer'
            }
        } finally {
            Close-AdmDirectoryEntry $entry
            Close-AdmDirectoryEntry $container
        }
    }
}

function Set-AdmComputer {
    <#
    .SYNOPSIS
      Change the descriptive attributes on a computer account. Writes -- honours -WhatIf.
    .DESCRIPTION
      The fields an administrator owns: description, location, managedBy and displayName.

      ⛔ IT DELIBERATELY WILL NOT TOUCH dNSHostName OR servicePrincipalName ON AN EXISTING
      ACCOUNT. The machine maintains both itself, and the SPNs are derived from the DNS name --
      editing either by hand desynchronises them from what the machine will register at its next
      startup, and the symptom is Kerberos failing for that host with an error about the ticket
      rather than about the name. Use Remove-AdmSpn for a genuinely duplicate SPN.

      -ManagedBy takes a user or group and is resolved to a distinguished name, the same as
      Set-AdmUser -Manager.
    .EXAMPLE
      Set-AdmComputer -Target corp.example.com -Identity WS42 -Description 'Lab bench 3' -Location 'Building A'
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Identity,
        [string]$Description,
        [string]$Location,
        [string]$DisplayName,
        [string]$ManagedBy,
        [hashtable]$Attribute,
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    # Captured OUTSIDE the guarded block: inside it, $PSBoundParameters is Invoke-AdmGuarded's.
    $bound = $PSBoundParameters
    Invoke-AdmGuarded -Operation "update computer '$Identity'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup

        $changes = [ordered]@{}
        if ($bound.ContainsKey('Description')) { $changes['description'] = $Description }
        if ($bound.ContainsKey('Location'))    { $changes['location'] = $Location }
        if ($bound.ContainsKey('DisplayName')) { $changes['displayName'] = $DisplayName }
        if ($Attribute) { foreach ($k in $Attribute.Keys) { $changes[[string]$k] = $Attribute[$k] } }

        foreach ($blocked in @('dnshostname', 'serviceprincipalname')) {
            if (@($changes.Keys | ForEach-Object { $_.ToLowerInvariant() }) -contains $blocked) {
                throw "Refusing to set '$blocked' on a computer account: the machine maintains it and the SPNs derive from it, so editing it by hand desynchronises them from what the machine registers at next startup."
            }
        }
        if (-not $changes.Count -and -not $bound.ContainsKey('ManagedBy')) {
            throw 'Nothing to change -- no attribute parameters were passed.'
        }

        $summary = @(@($changes.Keys) + @($(if ($bound.ContainsKey('ManagedBy')) { 'managedBy' })) | Where-Object { $_ })
        if (-not $PSCmdlet.ShouldProcess("$Identity @ $($ctx.Domain.DnsDomain)", "Set $($summary -join ', ')")) { return }

        if ((Get-AdmProviderName) -eq 'mock') {
            return [pscustomobject]@{ Domain = $ctx.Domain.Name; Name = $Identity
                                      Changed = @($summary); Action = 'set-computer' }
        }

        if ($bound.ContainsKey('ManagedBy')) {
            $changes['managedBy'] = if ([string]::IsNullOrEmpty($ManagedBy)) { '' }
                                    else { Resolve-AdmObjectDn -Context $ctx -Identity $ManagedBy }
        }

        $v = ConvertTo-AdmLdapFilterValue -Value $Identity
        $bare = $v.TrimEnd('$')
        $entry = Get-AdmSingleEntry -Context $ctx -Identity $Identity `
            -Filter "(&(objectCategory=computer)(|(sAMAccountName=$bare`$)(cn=$bare)(dNSHostName=$v)))"
        try {
            foreach ($n in $changes.Keys) { Set-AdmEntryAttribute -Entry $entry -Name $n -Value $changes[$n] }
            try { $entry.CommitChanges() }
            catch {
                throw (New-Object System.Exception(
                    ("Could not update '$Identity'. The write was rejected while setting: " +
                     "$($summary -join ', '). Nothing was applied -- the change is atomic. " +
                     "The directory said: $($_.Exception.Message)"), $_.Exception))
            }
            [void](Write-AdmLogEntry -Severity info -Event 'change' -Operation 'update computer' `
                    -Target $Target -Domain $ctx.Domain.Name `
                    -Message "Updated computer '$Identity' in $($ctx.Domain.DnsDomain): $($summary -join ', ')")
            [pscustomobject]@{
                Domain = $ctx.Domain.Name; Name = $Identity
                DistinguishedName = [string]$entry.Properties['distinguishedName'].Value
                Changed = @($summary); Action = 'set-computer'
            }
        } finally { Close-AdmDirectoryEntry $entry }
    }
}
