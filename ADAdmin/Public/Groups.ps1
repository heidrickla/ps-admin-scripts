# Public/Groups.ps1 -- group lifecycle, and enumerating what is actually IN a group.
#
# Membership has two directions and they are not the same query. Detail.ps1 answers the reverse
# one -- "which groups does this principal end up in" -- with LDAP_MATCHING_RULE_IN_CHAIN against
# `member`. This file answers the FORWARD one: "who is in this group", including through nesting.
#
# ⭐ WHY THIS IS NOT JUST READING THE `member` ATTRIBUTE. Three separate things go wrong that way,
# and all three are silent:
#
#   1. RANGE RETRIEVAL. A directory returns at most ~1500 values of a multi-valued attribute per
#      read. Past that it hands back `member;range=0-1499` and the caller that asked for `member`
#      gets NOTHING -- not a truncated list, no attribute at all. So a 3000-member group reads as
#      empty, and a 1600-member group reads as 1500 with no indication the rest exist.
#   2. PRIMARY GROUP MEMBERS ARE NOT IN `member`. An account whose primaryGroupID points at this
#      group is a member of it and appears nowhere in the attribute. This is why "Domain Users"
#      looks empty and why a privileged group can hide a member behind primaryGroupID=512.
#   3. NESTING. `member` is one level deep.
#
# Searching for the members instead of reading the attribute fixes 1 and 3 outright, and 2 is
# handled by a second query keyed on the group's RID.

# --- group type encoding ---------------------------------------------------------------------

# groupType is a bitfield, and it is signed. 0x80000000 is the SECURITY_ENABLED bit, which makes
# every security group's value negative when read as Int32 -- a global security group is
# -2147483646, not 2147483650. Getting that wrong creates a distribution group that looks right
# in a listing and grants nothing, which is discovered when someone cannot reach a share.
function ConvertTo-AdmGroupType {
    [OutputType([int])]
    [CmdletBinding()]
    param(
        [ValidateSet('Global', 'DomainLocal', 'Universal')][string]$Scope = 'Global',
        [ValidateSet('Security', 'Distribution')][string]$Category = 'Security'
    )
    $v = switch ($Scope) {
        'Global'      { 0x00000002 }
        'DomainLocal' { 0x00000004 }
        'Universal'   { 0x00000008 }
    }
    if ($Category -eq 'Security') {
        # -2147483648 is 0x80000000 as a signed Int32. Written as the literal rather than the hex
        # so nobody "corrects" it into an overflow.
        $v = $v -bor -2147483648
    }
    [int]$v
}

# --- range-aware attribute read ------------------------------------------------------------------

# Read every value of a multi-valued attribute, walking the range windows the directory imposes.
#
# The protocol: ask for `member`, and if the directory decides there are too many it returns the
# property under the name `member;range=0-1499` instead. Ask again for `member;range=1500-*` and
# so on until the returned name ends in `-*`, which marks the final window.
#
# ⚠ THE PROPERTY NAME COMES BACK LOWERCASED and with the range suffix attached, so a lookup by
# the plain attribute name finds nothing. Match on the prefix, not on equality.
function Get-AdmRangedAttribute {
    <#
    .SYNOPSIS
      Read every value of a multi-valued attribute, walking the directory's range windows.
    .DESCRIPTION
      ⛔ A PLAIN READ RETURNS NOTHING PAST ~1500 VALUES -- not a truncated list. The directory
      renames the property to `member;range=0-1499`, so a caller asking for `member` gets no
      attribute at all and a 3000-member group reads as EMPTY. A "truncated if count >= 1500"
      check can never fire, because above the boundary the count is zero.

      Takes the raw Domain and Credential rather than a context object:
        Get-AdmRangedAttribute -Domain $ctx.Domain -Credential $ctx.Credential -DistinguishedName $dn -Attribute member

      Always returns an array, so .Count is safe on a single result.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]$Domain,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory)][string]$DistinguishedName,
        [Parameter(Mandatory)][string]$Attribute,
        [int]$Window = 1500
    )
    $values = New-Object System.Collections.ArrayList
    $root = New-AdmDirectoryEntry -Domain $Domain -Credential $Credential -DistinguishedName $DistinguishedName
    try {
        $low = 0
        $done = $false
        while (-not $done) {
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
            try {
                $searcher.Filter = '(objectClass=*)'
                # Base scope: we are reading ONE object's attribute, not searching beneath it.
                $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
                $range = "$Attribute;range=$low-*"
                [void]$searcher.PropertiesToLoad.Add($range)
                $res = $searcher.FindOne()
                if ($null -eq $res) { break }

                $matched = $null
                foreach ($name in $res.Properties.PropertyNames) {
                    if ([string]$name -like "$($Attribute.ToLowerInvariant());range=*") { $matched = [string]$name; break }
                    if ([string]$name -eq $Attribute.ToLowerInvariant()) { $matched = [string]$name; break }
                }
                if (-not $matched) { break }

                $chunk = @($res.Properties[$matched])
                foreach ($v in $chunk) { [void]$values.Add([string]$v) }

                # A window ending in '-*' is the last one. Anything else means continue from the
                # value after this window's upper bound.
                if ($matched -notmatch 'range=\d+-(\d+)$') { $done = $true }
                else { $low = [int]$Matches[1] + 1 }
                if ($chunk.Count -eq 0) { $done = $true }
            } finally { $searcher.Dispose() }
        }
    } finally { Close-AdmDirectoryEntry $root }
    # ⛔ EMIT THE COLLECTION, do not `,`-wrap it. The unary comma is the idiom for stopping
    # PowerShell unrolling a returned array -- but every caller here writes `@(Get-Adm...)`, and
    # against a `,`-wrapped return that yields ONE element which is itself an array: an empty
    # result counts as 1, and a real result fails `-contains` because the element is an array
    # rather than a string. This repo's notes record the same trap hit four times; the guidance
    # there is exactly this, just emit it.
    $values.ToArray()
}

# NOTE: reading a multi-valued attribute that the directory may have renamed to
# `<name>;range=0-1499` is `Get-AdmRangedProp` in Objects.ps1. I wrote a second one here and
# deleted it: two implementations of the same read is the load-order coin toss this module has
# been careful to avoid all along, and theirs is the better of the two because it also raises the
# module's search-truncation flag -- so the CLI's -Json envelope reports the cut without needing
# to know which kind of limit was hit.

# --- membership ------------------------------------------------------------------------------------

function Get-AdmGroupMember {
    <#
    .SYNOPSIS
    Who is in a group -- directly, or through nesting. Read-only.
    .DESCRIPTION
      Finds members by SEARCHING for them rather than by reading the group's `member` attribute,
      which is what makes it correct on a large group: the attribute read silently returns nothing
      past ~1500 values, and the search has no such limit.

      -Recursive walks nested groups SERVER-SIDE with LDAP_MATCHING_RULE_IN_CHAIN, so a cycle in
      the nesting cannot hang the client and the whole chain costs one query.

      ⭐ PRIMARY GROUP MEMBERS ARE INCLUDED, and they are the ones people miss. An account whose
      primaryGroupID is this group's RID is a member and appears in no `member` list anywhere.
      That is exactly how a privileged group hides a member, and it is why "Domain Users" appears
      to have none at all.

      ⚠ MEMBERS FROM ANOTHER DOMAIN are reported from the group's own attribute and marked
      Foreign, because a search bounded by this domain cannot resolve them. Their DN is given; no
      attempt is made to bind to the other domain, since in this estate there is usually no trust
      to bind over.
    .EXAMPLE
      Get-AdmGroupMember -Target corp.example.com -Identity 'Domain Admins' -Recursive
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Identity,
        [switch]$Recursive,
        # Groups nested inside this one are members too. Off by default so a membership list is a
        # list of principals, which is what people mean when they ask who is in a group.
        [switch]$IncludeGroups,
        [string]$Tier,
        [int]$Limit = 100000,
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "list members of '$Identity'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup

        if ((Get-AdmProviderName) -eq 'mock') {
            $g = @(Invoke-AdmMockSearch -Domain $ctx.Domain -ObjectClass 'groups' -Identity $Identity)
            if (-not $g.Count) { throw "No group matching '$Identity' in $($ctx.Domain.DnsDomain)." }
            $dns = @(Get-AdmRawProp $g[0] 'members' @())
            $out = foreach ($dn in $dns) {
                [pscustomobject]@{
                    Domain = $ctx.Domain.Name; GroupName = Get-AdmRawProp $g[0] 'name'
                    Name = ($dn -replace '^CN=([^,]+).*$', '$1'); SamAccountName = $null
                    DistinguishedName = $dn; ObjectClass = 'user'
                    Enabled = $true; Via = 'direct'; Foreign = $false
                }
            }
            return $out
        }

        $groupDn = Resolve-AdmObjectDn -Context $ctx -Identity $Identity -Class 'group'
        $esc = ConvertTo-AdmFilterDn -DistinguishedName $groupDn

        # The class filter. objectCategory=person catches users AND contacts; adding computers
        # matters because a computer account in a group is easy to forget and perfectly legal.
        $classFilter = if ($IncludeGroups) { '(|(objectCategory=person)(objectCategory=computer)(objectCategory=group))' }
                       else { '(|(objectCategory=person)(objectCategory=computer))' }

        $rule = if ($Recursive) { 'memberOf:1.2.840.113556.1.4.1941:' } else { 'memberOf' }
        $filter = "(&$classFilter($rule=$esc))"

        $props = @('samaccountname', 'name', 'displayname', 'distinguishedname', 'objectclass',
                   'useraccountcontrol', 'objectsid', 'primarygroupid')
        $rows = @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential `
                    -Filter $filter -Properties $props -SizeLimit $Limit)

        $seen = @{}
        $out = New-Object System.Collections.ArrayList
        $groupName = ($groupDn -replace '^CN=([^,]+).*$', '$1')

        foreach ($r in $rows) {
            $dn = [string](Get-AdmRawProp $r 'distinguishedname')
            if (-not $dn -or $seen.ContainsKey($dn)) { continue }
            $seen[$dn] = $true
            $uac = 0; [void][int]::TryParse([string](Get-AdmRawProp $r 'useraccountcontrol' 0), [ref]$uac)
            $classes = @(Get-AdmRawProp $r 'objectclass' @())
            $cls = if ($classes -contains 'group') { 'group' }
                   elseif ($classes -contains 'computer') { 'computer' }
                   else { 'user' }
            [void]$out.Add([pscustomobject]@{
                Domain = $ctx.Domain.Name; GroupName = $groupName
                Name = Get-AdmRawProp $r 'name'
                SamAccountName = Get-AdmRawProp $r 'samaccountname'
                DisplayName = Get-AdmRawProp $r 'displayname'
                DistinguishedName = $dn
                ObjectClass = $cls
                # A group object has no ACCOUNTDISABLE bit; reporting it as "enabled" would be a
                # claim about something that does not exist.
                Enabled = $(if ($cls -eq 'group') { $null } else { -not (Test-AdmUacDisabled -Uac $uac) })
                Via = $(if ($Recursive) { 'direct-or-nested' } else { 'direct' })
                Foreign = $false
            })
        }

        # --- primary group members -------------------------------------------------------------
        # The group's RID is the last sub-authority of its SID. An account carrying that value in
        # primaryGroupID is a member and is in no `member` list.
        $gRows = @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential `
                    -Filter "(distinguishedName=$esc)" -Properties @('objectsid') -SizeLimit 1)
        $gSid = ConvertTo-AdmSidString (Get-AdmRawProp $gRows[0] 'objectsid')
        if ($gSid -and $gSid -match '-(\d+)$') {
            $rid = $Matches[1]
            $primary = @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential `
                        -Filter "(primaryGroupID=$rid)" -Properties $props -SizeLimit $Limit)
            foreach ($r in $primary) {
                $dn = [string](Get-AdmRawProp $r 'distinguishedname')
                if (-not $dn -or $seen.ContainsKey($dn)) { continue }
                $seen[$dn] = $true
                $uac = 0; [void][int]::TryParse([string](Get-AdmRawProp $r 'useraccountcontrol' 0), [ref]$uac)
                $classes = @(Get-AdmRawProp $r 'objectclass' @())
                $cls = if ($classes -contains 'computer') { 'computer' } else { 'user' }
                [void]$out.Add([pscustomobject]@{
                    Domain = $ctx.Domain.Name; GroupName = $groupName
                    Name = Get-AdmRawProp $r 'name'
                    SamAccountName = Get-AdmRawProp $r 'samaccountname'
                    DisplayName = Get-AdmRawProp $r 'displayname'
                    DistinguishedName = $dn
                    ObjectClass = $cls
                    Enabled = -not (Test-AdmUacDisabled -Uac $uac)
                    # Named distinctly so it is obvious in the output WHY this row is here -- it
                    # is the row people did not expect and would otherwise assume was a bug.
                    Via = 'primary-group'
                    Foreign = $false
                })
            }
        }

        # --- foreign / unresolvable members ------------------------------------------------------
        # Whatever is in `member` but was not found by the search is either in another domain or
        # a foreign security principal. Read range-aware, or a large group loses them all.
        $declared = @(Get-AdmRangedAttribute -Domain $ctx.Domain -Credential $ctx.Credential `
                        -DistinguishedName $groupDn -Attribute 'member')
        foreach ($dn in $declared) {
            if (-not $dn -or $seen.ContainsKey($dn)) { continue }
            $seen[$dn] = $true
            [void]$out.Add([pscustomobject]@{
                Domain = $ctx.Domain.Name; GroupName = $groupName
                Name = ($dn -replace '^CN=([^,]+).*$', '$1')
                SamAccountName = $null; DisplayName = $null
                DistinguishedName = $dn
                ObjectClass = $(if ($dn -match 'CN=ForeignSecurityPrincipals') { 'foreignSecurityPrincipal' } else { 'unknown' })
                Enabled = $null
                Via = 'direct'
                Foreign = $true
            })
        }

        $out.ToArray()
    }
}

# --- group lifecycle ---------------------------------------------------------------------------

function New-AdmGroup {
    <#
    .SYNOPSIS
    Create a group. Writes -- honours -WhatIf.
    .DESCRIPTION
      Scope and category are set at creation because CHANGING THEM LATER IS RESTRICTED: the
      directory refuses a global-to-domain-local conversion outright, and refuses any conversion
      while the group is a member of another group whose scope would then be illegal. Choosing
      correctly here avoids deleting and recreating, which loses the SID and every ACL that
      referenced it.

      Scope, in one line each:
        Global      -- members from THIS domain only; usable in any domain in the forest. The default.
        DomainLocal -- members from anywhere; usable only in THIS domain. For granting resource access.
        Universal   -- members from anywhere, usable anywhere; replicated to the global catalog.
    .EXAMPLE
      New-AdmGroup -Target corp.example.com -Name 'FileShare-Finance' -Scope DomainLocal
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Name,
        [string]$SamAccountName,
        [string]$Path,
        [string]$Description,
        [ValidateSet('Global', 'DomainLocal', 'Universal')][string]$Scope = 'Global',
        [ValidateSet('Security', 'Distribution')][string]$Category = 'Security',
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "create group '$Name'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        $base = if ($Path) { $Path } else { "CN=Users,$(ConvertTo-AdmDistinguishedName -DnsDomain $ctx.Domain.DnsDomain)" }
        $sam = if ($SamAccountName) { $SamAccountName } else { $Name }
        $dn = "CN=$Name,$base"
        if (-not $PSCmdlet.ShouldProcess($dn, "Create $Scope $Category group")) { return }

        $gt = ConvertTo-AdmGroupType -Scope $Scope -Category $Category

        if ((Get-AdmProviderName) -eq 'mock') {
            return [pscustomobject]@{ Domain = $ctx.Domain.Name; Name = $Name; SamAccountName = $sam
                                      DistinguishedName = $dn; Scope = $Scope; Category = $Category
                                      GroupType = $gt; Action = 'create-group' }
        }

        $container = New-AdmDirectoryEntry -Domain $ctx.Domain -Credential $ctx.Credential -DistinguishedName $base
        $entry = $null
        try {
            $entry = $container.Children.Add("CN=$Name", 'group')
            $entry.Properties['sAMAccountName'].Value = $sam
            $entry.Properties['groupType'].Value = $gt
            if ($Description) { $entry.Properties['description'].Value = $Description }
            $entry.CommitChanges()

            [void](Write-AdmLogEntry -Severity info -Event 'change' -Operation 'create group' `
                    -Target $Target -Domain $ctx.Domain.Name `
                    -Message "Created $Scope $Category group '$dn' in $($ctx.Domain.DnsDomain)")

            [pscustomobject]@{ Domain = $ctx.Domain.Name; Name = $Name; SamAccountName = $sam
                               DistinguishedName = [string]$entry.Properties['distinguishedName'].Value
                               Scope = $Scope; Category = $Category; GroupType = $gt; Action = 'create-group' }
        } finally {
            Close-AdmDirectoryEntry $entry
            Close-AdmDirectoryEntry $container
        }
    }
}

function Remove-AdmGroup {
    <#
    .SYNOPSIS
    Delete a group. Writes -- honours -WhatIf.
    .DESCRIPTION
      ⛔ REFUSES A BUILT-IN OR WELL-KNOWN GROUP, with no override. Any group whose RID is below
      1000 is created by the directory itself -- Domain Admins (512), Domain Users (513), the
      BUILTIN groups, and the rest. Deleting one is not recoverable by recreating it: the new
      group gets a NEW SID, so every ACL, GPO reference and local-group nesting that named the old
      one silently stops matching anything. The damage surfaces days later as scattered access
      failures with no common cause.

      A group with members is refused unless -Force, because the membership is the thing being
      destroyed and it is not stored anywhere else. The member count is reported in the refusal.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Identity,
        [switch]$Force,
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "delete group '$Identity'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup

        if ((Get-AdmProviderName) -eq 'mock') {
            if (-not $PSCmdlet.ShouldProcess($Identity, 'Delete group')) { return }
            return [pscustomobject]@{ Domain = $ctx.Domain.Name; DistinguishedName = $Identity
                                      MemberCount = 0; Action = 'delete-group' }
        }

        $dn = Resolve-AdmObjectDn -Context $ctx -Identity $Identity -Class 'group'
        $esc = ConvertTo-AdmFilterDn -DistinguishedName $dn
        $row = @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential `
                    -Filter "(distinguishedName=$esc)" -Properties @('objectsid', 'samaccountname') -SizeLimit 1)[0]
        $sid = ConvertTo-AdmSidString (Get-AdmRawProp $row 'objectsid')
        if ($sid -and $sid -match '-(\d+)$') {
            $rid = [int]$Matches[1]
            if ($rid -lt 1000) {
                throw "'$dn' is a built-in group (RID $rid). Deleting it is not reversible by recreating it -- the replacement would get a different SID and every ACL naming the old one would stop matching. Refusing."
            }
        }

        $members = @(Get-AdmRangedAttribute -Domain $ctx.Domain -Credential $ctx.Credential `
                        -DistinguishedName $dn -Attribute 'member')
        if ($members.Count -gt 0 -and -not $Force) {
            throw "'$dn' still has $($members.Count) member(s), and the membership is not recorded anywhere else once the group is gone. Re-run with -Force if that is intended."
        }
        if (-not $PSCmdlet.ShouldProcess("$dn @ $($ctx.Domain.DnsDomain)", "Delete group with $($members.Count) member(s)")) { return }

        $entry = Get-AdmEntryByDn -Context $ctx -DistinguishedName $dn
        try {
            if (Test-AdmObjectProtected -Context $ctx -DistinguishedName $dn -Entry $entry) {
                throw "'$dn' is protected from accidental deletion. Clear it first: Set-AdmObjectProtection -Identity '$dn' -Protected `$false"
            }
            $entry.DeleteTree()
            [void](Write-AdmLogEntry -Severity warn -Event 'change' -Operation 'delete group' `
                    -Target $Target -Domain $ctx.Domain.Name `
                    -Message "Deleted group '$dn' from $($ctx.Domain.DnsDomain) with $($members.Count) member(s)")
            [pscustomobject]@{ Domain = $ctx.Domain.Name; DistinguishedName = $dn
                               MemberCount = $members.Count; Action = 'delete-group' }
        } finally { Close-AdmDirectoryEntry $entry }
    }
}
