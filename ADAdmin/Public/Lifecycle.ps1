# Public/Lifecycle.ps1 -- creating, editing, moving, renaming and deleting directory objects.
#
# The everyday work. Everything here follows the same contract as the rest of the module: one
# -Target resolves the domain and its credential, the work runs inside Invoke-AdmGuarded so a
# failure comes out diagnosed and logged, writes honour -WhatIf, and a successful write is
# logged too -- an administrative change with no record is the one you regret later.
#
# The mock provider is kept at parity deliberately. A cmdlet that only works against a real DC
# cannot be exercised by the suites, and this repo's tests run on a workstation that usually
# cannot reach a domain at all.

# --- shared helpers ---------------------------------------------------------------------------

# The RDN prefix is NOT always CN=. An organizationalUnit uses OU=, and a domain or container
# uses DC= / CN=. Renaming with the wrong prefix fails with a message about a naming violation
# that says nothing about which prefix was expected, so derive it from the object's own DN
# rather than assuming.
function Get-AdmRdnPrefix {
    <#
    .SYNOPSIS
      The RDN prefix of a DN (CN, OU, DC). An OU does not rename as CN=.
    #>
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$DistinguishedName)
    if ($DistinguishedName -match '^\s*([A-Za-z]+)\s*=') { return $Matches[1].ToUpperInvariant() }
    'CN'
}

# Everything left of the first unescaped comma. Splitting a DN on ',' is wrong in general --
# a CN may legitimately contain an escaped comma, as in "CN=Smith\, Jo" -- so step over '\,'.
function Get-AdmParentDn {
    <#
    .SYNOPSIS
      The parent container of a DN, stepping over escaped commas.
    .DESCRIPTION
      ⛔ DO NOT `-split ','` A DN. "CN=Smith\, Jo,OU=Staff,DC=c" is an ordinary Active Directory
      common name, and splitting on the comma yields " Jo,OU=Staff,DC=c" -- so a move or a delete
      built on it targets something that does not exist, or worse, does.
    #>
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$DistinguishedName)
    $i = 0
    while ($i -lt $DistinguishedName.Length) {
        if ($DistinguishedName[$i] -eq '\') { $i += 2; continue }
        if ($DistinguishedName[$i] -eq ',') { return $DistinguishedName.Substring($i + 1).TrimStart() }
        $i++
    }
    ''
}

function ConvertTo-AdmRdnEscaped {
    <#
    .SYNOPSIS
      Escape a value for use as an RDN in a distinguished name (RFC 4514).
    .DESCRIPTION
      The WRITE-side counterpart to Get-AdmParentDn's read-side handling. "Smith, Jo" is an
      ordinary common name, and building `CN=Smith, Jo,OU=Staff,DC=c` unescaped produces a DN with
      an extra component -- so the object lands somewhere else entirely, or the operation fails in
      a way that looks like the PARENT is wrong rather than the name.

      ⚠ The backslash is escaped FIRST, deliberately. Escape it later and the backslashes added
      for the other characters get escaped again, doubling them.
    #>
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    $out = $Value.Replace('\', '\\')
    foreach ($ch in @(',', '+', '"', '<', '>', ';', '=')) { $out = $out.Replace($ch, '\' + $ch) }
    $out
}

# A DN going INTO an LDAP filter still needs RFC 4515 escaping -- a DN containing '(' or '\'
# rewrites the filter otherwise. This is the same escape as any other filter value; it is given
# a name only because forgetting it on a DN looks harmless and is not.
function ConvertTo-AdmFilterDn {
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$DistinguishedName)
    ConvertTo-AdmLdapFilterValue -Value $DistinguishedName
}

# Bind straight to a DN, with a clearer failure than ADSI's own. A DN that does not exist binds
# LAZILY and only fails when something touches it, which puts the error at a confusing place --
# so force the bind here with RefreshCache() and report it against the DN the caller passed.
function Get-AdmEntryByDn {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$DistinguishedName
    )
    $entry = New-AdmDirectoryEntry -Domain $Context.Domain -Credential $Context.Credential -DistinguishedName $DistinguishedName
    try {
        # ⚠ THE BIND HAS NOT HAPPENED YET. New-AdmDirectoryEntry returns an unbound object, and
        # `.Properties` on a failed bind is NULL rather than throwing -- which is where
        # "Cannot index into a null array" comes from. RefreshCache() forces the connection now,
        # so the error lands here with the DN in hand.
        $entry.RefreshCache()
        $entry
    } catch {
        Close-AdmDirectoryEntry $entry
        throw "Could not bind to '$DistinguishedName' in $($Context.Domain.DnsDomain): $($_.Exception.Message)"
    }
}

# Resolve whatever the caller typed -- a DN, a sAMAccountName, a UPN, a machine name -- to a
# single DN. Refuses on more than one match rather than taking the first: a move or a delete
# that silently picked one of two candidates is discovered by its consequences.
function Resolve-AdmObjectDn {
    <#
    .SYNOPSIS
      Resolve a name, UPN, machine name or DN to exactly one distinguished name, or refuse.
    .DESCRIPTION
      Refuses on more than one match rather than taking the first: a move or a delete that
      silently picked one of two candidates is discovered by its consequences.

      ⚠ The class constraint is not decoration. A name-only search of the domain naming context
      also matches AD-INTEGRATED DNS NODES -- on a stock domain `(name=DC01)` returns the computer
      AND its dnsNode under CN=MicrosoftDNS,CN=System -- so an unconstrained resolver refuses
      every DC-named host as ambiguous.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Identity,
        [ValidateSet('any', 'user', 'group', 'computer', 'ou')][string]$Class = 'any'
    )
    # Already a DN. Trust it -- but only after it binds, which Get-AdmEntryByDn proves.
    if ($Identity -match '^\s*(CN|OU|DC)\s*=') { return $Identity.Trim() }

    $v = ConvertTo-AdmLdapFilterValue -Value $Identity
    $bare = $v.TrimEnd('$')
    $filter = switch ($Class) {
        'user'     { "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=$v)(userPrincipalName=$v)(cn=$v)))" }
        'group'    { "(&(objectCategory=group)(|(sAMAccountName=$v)(cn=$v)))" }
        'computer' { "(&(objectCategory=computer)(|(sAMAccountName=$bare`$)(cn=$bare)(dNSHostName=$v)))" }
        'ou'       { "(&(objectCategory=organizationalUnit)(ou=$v))" }
        # ⛔ THE CLASS CONSTRAINT IS NOT OPTIONAL. A name-only search of the domain naming context
        # also matches AD-INTEGRATED DNS NODES: on a stock domain `(name=DC01)` returns two
        # objects -- the computer, and the dnsNode for it under CN=MicrosoftDNS,CN=System. Without
        # this, Resolve-AdmObjectDn reports "matched more than one object" for a perfectly ordinary
        # machine name and every move, rename and delete on a DC-named host refuses. Measured on
        # a lab domain controller, 2026-08-28.
        default    { "(&(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=organizationalUnit))(|(sAMAccountName=$v)(sAMAccountName=$bare`$)(userPrincipalName=$v)(cn=$v)(ou=$v)(dNSHostName=$v)))" }
    }
    $hits = @(Invoke-AdmAdsiSearch -Domain $Context.Domain -Credential $Context.Credential `
                -Filter $filter -Properties @('distinguishedname') -SizeLimit 2)
    if ($hits.Count -eq 0) { throw "No $(if ($Class -eq 'any') { 'object' } else { $Class }) matching '$Identity' in $($Context.Domain.DnsDomain)." }
    if ($hits.Count -gt 1) { throw "'$Identity' matched more than one object in $($Context.Domain.DnsDomain); refusing to guess. Pass the full distinguished name instead." }
    [string](Get-AdmRawProp $hits[0] 'distinguishedname')
}

# --- organizational units ----------------------------------------------------------------------

function Get-AdmOrganizationalUnit {
    <#
    .SYNOPSIS
    List organizational units, optionally under one subtree.
    .DESCRIPTION
      The container view an administrator actually navigates. -SearchBase scopes it to a subtree;
      without one it starts at the domain root.

      -IncludeProtection reads each OU's ACL to report whether it is protected from accidental
      deletion. That is a SEPARATE BIND PER OU, so it is opt-in rather than always-on -- on a
      directory with a few hundred OUs the difference is one search versus a few hundred.
    .EXAMPLE
      Get-AdmOrganizationalUnit -Target corp.example.com
    .EXAMPLE
      Get-AdmOrganizationalUnit -Target corp.example.com -SearchBase 'OU=Staff,DC=corp,DC=example,DC=com' -IncludeProtection
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Identity,
        [string]$SearchBase,
        [switch]$IncludeProtection,
        # ⭐ CN=Users AND CN=Computers ARE NOT OUs. They are objectClass `container`, so an OU-only
        # listing is correct and still shows an empty tree on a stock domain, because that is
        # exactly where the default accounts live. Measured on a lab domain controller: an OU
        # query returned 1 OU and the browser showed no users at all. Anything building a picker
        # wants this switch; a report about OU structure does not.
        [switch]$IncludeContainers,
        [string]$Tier,
        # ⚠ Not 500. A real estate has far more OUs than that, and a DirectorySearcher stops at
        # its limit silently -- so a low default quietly hands back a partial tree that looks
        # complete. The lab has one OU and could never have shown this.
        [int]$Limit = 20000,
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation 'list organizational units' -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup

        if ((Get-AdmProviderName) -eq 'mock') {
            # Same DN-vs-name distinction as the adsi branch below, or the fixture path disagrees
            # with the real one about what -Identity means.
            $isDn = $Identity -and ($Identity -match '^\s*(CN|OU|DC)\s*=')
            $rows = if ($isDn) {
                @(Invoke-AdmMockSearch -Domain $ctx.Domain -ObjectClass 'ous' -SizeLimit $Limit |
                    Where-Object { [string](Get-AdmRawProp $_ 'distinguishedName') -eq $Identity.Trim() })
            } else {
                @(Invoke-AdmMockSearch -Domain $ctx.Domain -ObjectClass 'ous' -Identity $Identity -SizeLimit $Limit)
            }
            $out = foreach ($r in $rows) {
                $dn = [string](Get-AdmRawProp $r 'distinguishedName')
                if ($SearchBase -and -not $dn.ToLowerInvariant().EndsWith($SearchBase.ToLowerInvariant())) { continue }
                [pscustomobject]@{
                    Domain            = $ctx.Domain.Name
                    Name              = Get-AdmRawProp $r 'name'
                    DistinguishedName = $dn
                    ParentDn          = Get-AdmParentDn -DistinguishedName $dn
                    Description       = Get-AdmRawProp $r 'description'
                    ManagedBy         = Get-AdmRawProp $r 'managedBy'
                    WhenCreated       = Get-AdmRawProp $r 'whenCreated'
                    # ⚠ SAME SHAPE AS THE ADSI BRANCH, including the fields a fixture has no
                    # natural value for. A narrower mock object throws under Set-StrictMode on the
                    # MOCK path only, which is exactly the wrong way round -- the fixture is what
                    # the tests and the GUI demo run against.
                    GpoLinkCount      = 0
                    Protected         = $(if ($IncludeProtection) { [bool](Get-AdmRawProp $r 'protected' $false) } else { $null })
                    ObjectClass       = 'organizationalUnit'
                    CanLinkGpo        = $true
                }
            }
            return $out
        }

        # builtinDomain is CN=Builtin, which is neither an OU nor a plain container and would be
        # missed by both halves otherwise.
        $classClause = if ($IncludeContainers) {
            '(|(objectCategory=organizationalUnit)(objectClass=container)(objectClass=builtinDomain))'
        } else { '(objectCategory=organizationalUnit)' }

        $filter = if ($Identity) {
            $v = ConvertTo-AdmLdapFilterValue -Value $Identity
            # ⛔ A DISTINGUISHED NAME IS NOT A NAME. Matched as `(ou=*OU=ZZ-Prot,DC=corp,DC=example,DC=com*)`
            # it can never hit anything -- `ou` holds "ZZ-Prot" -- so the cmdlet returned ZERO ROWS
            # for the one key every other cmdlet in this module accepts. And zero rows is not an
            # error: the caller reads it as "no such OU", or worse leaves Protected as $null, which
            # then shows an already-protected OU as unprotected and sends a delete in without
            # -RemoveProtection, to fail with "Access is denied" about a permissions problem that
            # does not exist. Three wrong behaviours from one silent empty result.
            # Found driving the GUI against a lab domain controller, 2026-08-28.
            if ($Identity -match '^\s*(CN|OU|DC)\s*=') { "(&$classClause(distinguishedName=$v))" }
            else { "(&$classClause(|(ou=*$v*)(name=*$v*)(cn=*$v*)))" }
        } else { $classClause }

        $rows = @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential -Filter $filter `
                    -SearchBase $SearchBase -SizeLimit $Limit `
                    -Properties @('name', 'ou', 'cn', 'objectclass', 'distinguishedname', 'description',
                                  'managedby', 'whencreated', 'whenchanged', 'gplink'))
        foreach ($r in $rows) {
            $dn = [string](Get-AdmRawProp $r 'distinguishedname')
            $protected = $null
            if ($IncludeProtection) { $protected = Test-AdmObjectProtected -Context $ctx -DistinguishedName $dn }
            # Report the REAL class. A caller that asked for containers has to be able to tell an
            # OU from CN=Users, because most of what you can do to one you cannot do to the other:
            # a container cannot be renamed, moved, or have Group Policy linked to it.
            $classes = @(Get-AdmRawProp $r 'objectclass' @())
            $cls = if ($classes -contains 'organizationalUnit') { 'organizationalUnit' }
                   elseif ($classes -contains 'builtinDomain') { 'builtinDomain' }
                   elseif ($classes -contains 'container') { 'container' }
                   else { 'organizationalUnit' }
            [pscustomobject]@{
                Domain            = $ctx.Domain.Name
                Name              = Get-AdmRawProp $r 'name' (Get-AdmRawProp $r 'ou')
                DistinguishedName = $dn
                ParentDn          = Get-AdmParentDn -DistinguishedName $dn
                Description       = Get-AdmRawProp $r 'description'
                ManagedBy         = Get-AdmRawProp $r 'managedby'
                WhenCreated       = Get-AdmRawProp $r 'whencreated'
                # A linked GPO is the single most common reason an OU cannot simply be deleted
                # without consequence, so surface the fact that links exist even here.
                GpoLinkCount      = @(ConvertFrom-AdmGpLink (Get-AdmRawProp $r 'gplink')).Count
                Protected         = $protected
                ObjectClass       = $cls
                # Group Policy cannot be linked to a container, only to an OU, a site or the
                # domain head -- which is the usual reason someone is surprised that a policy is
                # not applying to the accounts sitting in CN=Users.
                CanLinkGpo        = ($cls -eq 'organizationalUnit')
            }
        }
    }
}

function New-AdmOrganizationalUnit {
    <#
    .SYNOPSIS
    Create an organizational unit. Writes -- honours -WhatIf.
    .DESCRIPTION
      ⭐ PROTECTED FROM ACCIDENTAL DELETION BY DEFAULT, which is what the Microsoft tooling does
      and what every estate assumes has happened. An unprotected OU can be deleted with its whole
      subtree by one mis-click, and the objects underneath do not come back without a restore.
      Pass -ProtectFromAccidentalDeletion:$false to opt out deliberately.
    .EXAMPLE
      New-AdmOrganizationalUnit -Target corp.example.com -Name 'Contractors' -Path 'DC=corp,DC=example,DC=com'
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Name,
        # Where it goes. Defaults to the domain root, which is where a top-level OU belongs.
        [string]$Path,
        [string]$Description,
        [bool]$ProtectFromAccidentalDeletion = $true,
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "create OU '$Name'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        $base = if ($Path) { $Path } else { ConvertTo-AdmDistinguishedName -DnsDomain $ctx.Domain.DnsDomain }
        $dn = "OU=$Name,$base"
        if (-not $PSCmdlet.ShouldProcess($dn, 'Create organizational unit')) { return }

        if ((Get-AdmProviderName) -eq 'mock') {
            return [pscustomobject]@{ Domain = $ctx.Domain.Name; Name = $Name; DistinguishedName = $dn
                                      ParentDn = $base; Description = $Description
                                      Protected = $ProtectFromAccidentalDeletion; Action = 'create-ou' }
        }

        $container = New-AdmDirectoryEntry -Domain $ctx.Domain -Credential $ctx.Credential -DistinguishedName $base
        $entry = $null
        try {
            $entry = $container.Children.Add("OU=$Name", 'organizationalUnit')
            if ($Description) { $entry.Properties['description'].Value = $Description }
            $entry.CommitChanges()
            if ($ProtectFromAccidentalDeletion) { Set-AdmEntryProtection -Entry $entry -Protected $true }

            [void](Write-AdmLogEntry -Severity info -Event 'change' -Operation 'create OU' `
                    -Target $Target -Domain $ctx.Domain.Name `
                    -Message "Created '$dn' in $($ctx.Domain.DnsDomain) (protected=$ProtectFromAccidentalDeletion)")

            [pscustomobject]@{ Domain = $ctx.Domain.Name; Name = $Name; DistinguishedName = $dn
                               ParentDn = $base; Description = $Description
                               Protected = $ProtectFromAccidentalDeletion; Action = 'create-ou' }
        } finally {
            Close-AdmDirectoryEntry $entry
            Close-AdmDirectoryEntry $container
        }
    }
}

function Remove-AdmOrganizationalUnit {
    <#
    .SYNOPSIS
    Delete an organizational unit. Writes -- honours -WhatIf.
    .DESCRIPTION
      ⛔ REFUSES A NON-EMPTY OU UNLESS -Recurse IS GIVEN. Deleting an OU in AD deletes everything
      beneath it, and the directory offers no confirmation of its own -- the whole subtree simply
      goes. So the count of children is taken first and reported in the refusal.

      A protected OU is detected and reported as protected rather than surfaced as the bare
      "Access is denied" the directory returns, which sends people to check their permissions for
      a problem that is nothing to do with permissions.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Identity,
        [switch]$Recurse,
        # Clear the protection ACE first. Without this a protected OU is refused, on purpose:
        # protection exists to make exactly this operation require a second thought.
        [switch]$RemoveProtection,
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "delete OU '$Identity'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup

        if ((Get-AdmProviderName) -eq 'mock') {
            if (-not $PSCmdlet.ShouldProcess($Identity, 'Delete organizational unit')) { return }
            return [pscustomobject]@{ Domain = $ctx.Domain.Name; DistinguishedName = $Identity
                                      ChildCount = 0; Action = 'delete-ou' }
        }

        $dn = Resolve-AdmObjectDn -Context $ctx -Identity $Identity -Class 'ou'
        $entry = Get-AdmEntryByDn -Context $ctx -DistinguishedName $dn
        try {
            # Count first. The refusal has to say HOW MUCH would go, or "not empty" is not a
            # number anyone can weigh a decision against.
            $children = 0
            foreach ($c in $entry.Children) { $children++; Close-AdmDirectoryEntry $c }
            if ($children -gt 0 -and -not $Recurse) {
                throw "'$dn' is not empty -- it contains $children object(s), and deleting an OU deletes its entire subtree. Re-run with -Recurse if that is what you mean."
            }

            $wasProtected = Test-AdmObjectProtected -Context $ctx -DistinguishedName $dn -Entry $entry
            if ($wasProtected -and -not $RemoveProtection) {
                throw "'$dn' is protected from accidental deletion. That protection is a Deny ACE on the object, not a permissions problem with your account -- re-run with -RemoveProtection to clear it and delete."
            }

            $what = if ($children -gt 0) { "Delete organizational unit AND $children object(s) beneath it" } else { 'Delete organizational unit' }
            if (-not $PSCmdlet.ShouldProcess("$dn @ $($ctx.Domain.DnsDomain)", $what)) { return }

            if ($wasProtected) { Set-AdmEntryProtection -Entry $entry -Protected $false }
            $entry.DeleteTree()

            [void](Write-AdmLogEntry -Severity warn -Event 'change' -Operation 'delete OU' `
                    -Target $Target -Domain $ctx.Domain.Name `
                    -Message "Deleted '$dn' from $($ctx.Domain.DnsDomain) with $children child object(s)")

            [pscustomobject]@{ Domain = $ctx.Domain.Name; DistinguishedName = $dn
                               ChildCount = $children; WasProtected = $wasProtected; Action = 'delete-ou' }
        } finally { Close-AdmDirectoryEntry $entry }
    }
}

# --- protection from accidental deletion ---------------------------------------------------------

# "Protect from accidental deletion" is not a flag -- it is a pair of DENY aces for Everyone on
# the object itself: Delete and DeleteTree. That is why a protected object fails deletion with
# "Access is denied" even for a Domain Admin, and why the message is so misleading.
$script:AdmEveryoneSid = 'S-1-1-0'

function Get-AdmEveryoneIdentity {
    New-Object System.Security.Principal.SecurityIdentifier($script:AdmEveryoneSid)
}

function Set-AdmDaclMask {
    <#
    .SYNOPSIS
      Ask a DirectoryEntry for Owner + Group + DACL, excluding the SACL. Returns whether it applied.
    .DESCRIPTION
      ⚠ TWO CORRECTIONS, both found during delegation work and both measured.

      1. `$Entry.Options` IS NULL on an entry from New-AdmDirectoryEntry -- before and after
         RefreshCache(). The first version of this function assigned through it inside a bare
         try/catch, so it reported success while doing nothing at all. It now returns a boolean
         and callers can stop believing it.

      2. Pinning the mask to Dacl ALONE drops the Owner, so an ownership check reports "no owner"
         on every object. Owner + Group + Dacl is the correct set: it still excludes the SACL,
         which is the part that actually needs SeSecurityPrivilege and whose absence throws an
         error blaming the object rather than the mask.

      This is not fatal when it cannot apply: a DirectoryEntry's DEFAULT security mask is already
      Owner + Group + Dacl, so ObjectSecurity reads correctly either way. The value of the call is
      making the intent explicit and pinning it where the platform lets us -- which is why a
      $false return is worth having rather than a silent shrug.

      On the SEARCH path use DirectorySearcher.SecurityMasks instead, which does take the value.
    #>
    [OutputType([bool])]
    param($Entry)
    $masks = [System.DirectoryServices.SecurityMasks]::Owner -bor `
             [System.DirectoryServices.SecurityMasks]::Group -bor `
             [System.DirectoryServices.SecurityMasks]::Dacl
    try {
        if ($null -eq $Entry.Options) { return $false }
        $Entry.Options.SecurityMasks = $masks
        $true
    } catch { $false }
}

function Test-AdmObjectProtected {
    <#
    .SYNOPSIS
      Is this object protected from accidental deletion? Raises rather than guessing.
    .DESCRIPTION
      Protection is a pair of Deny ACEs for Everyone on Delete and Delete Subtree, which is why a
      protected object fails deletion with "Access is denied" -- a message about the wrong thing.

      ⚠ ON `-band` AND COMPOSITE RIGHTS. GenericAll is a COMPOSITE mask (0xF01FF), so testing
      `$rights -band [GenericAll]` is satisfied by a plain ReadProperty (0x10) and over-matches
      wildly. That is not a risk for the two rights tested here, and it was measured rather than
      assumed (2026-08-28): Delete is 0x10000 and DeleteTree is 0x40, both single bits, and
      `ReadProperty -band Delete` and `ReadProperty -band DeleteTree` are both 0. A Deny
      GenericAll DOES match Delete (0xF01FF -band 0x10000 = 0x10000), which is correct here --
      such an ACE genuinely does block deletion.
    #>
    [OutputType([bool])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$DistinguishedName,
        # Reuse a bind the caller already has, rather than making a second one.
        $Entry
    )
    $own = $false
    $e = $Entry
    if (-not $e) { $e = Get-AdmEntryByDn -Context $Context -DistinguishedName $DistinguishedName; $own = $true }
    try {
        # ⛔ VOIDED. Set-AdmDaclMask RETURNS a bool, and an unvoided call emits it into this
        # function's output -- so the caller gets @($false, $true) instead of $true. A two-element
        # array is TRUTHY whatever is in it, which made every object look protected: every move
        # and every unforced delete refused, citing protection that was not there. Measured on
        # a lab domain controller, 2026-08-28, and introduced by making this helper return a value in the first place.
        [void](Set-AdmDaclMask -Entry $e)
        $sec = $e.ObjectSecurity
        if ($null -eq $sec) { return $false }
        $everyone = Get-AdmEveryoneIdentity
        foreach ($rule in $sec.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Deny) { continue }
            if ([string]$rule.IdentityReference -ne [string]$everyone) { continue }
            # Either bit is enough to make a delete fail, so either one counts as protected.
            if ($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::Delete)     { return $true }
            if ($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree) { return $true }
        }
        $false
    } catch {
        # ⛔ AN ACL WE COULD NOT READ IS NOT AN ABSENCE OF PROTECTION. Returning $false here would
        # make a caller step straight into a delete it should have been warned about, so the
        # failure is raised rather than flattened into a reassuring answer.
        throw "Could not read the access control list on '$DistinguishedName': $($_.Exception.Message)"
    } finally { if ($own) { Close-AdmDirectoryEntry $e } }
}

function Set-AdmEntryProtection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Entry,
        [Parameter(Mandatory)][bool]$Protected
    )
    # Voided for the same reason as in Test-AdmObjectProtected: this function is called without
    # assignment, so anything it emits ends up in its CALLER's return value.
    [void](Set-AdmDaclMask -Entry $Entry)
    $sec = $Entry.ObjectSecurity
    $everyone = Get-AdmEveryoneIdentity
    $rights = [System.DirectoryServices.ActiveDirectoryRights]::Delete -bor `
              [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $everyone, $rights, [System.Security.AccessControl.AccessControlType]::Deny)

    if ($Protected) { $sec.AddAccessRule($rule) }
    else {
        # RemoveAccessRule matches on the rights too, so a partially-set protection (Delete but
        # not DeleteTree, which older tooling produced) would survive the removal and the delete
        # would still fail. Take out every Deny-to-Everyone that carries either bit instead.
        foreach ($existing in @($sec.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) {
            if ($existing.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Deny) { continue }
            if ([string]$existing.IdentityReference -ne [string]$everyone) { continue }
            if (($existing.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::Delete) -or
                ($existing.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree)) {
                [void]$sec.RemoveAccessRuleSpecific($existing)
            }
        }
    }
    $Entry.ObjectSecurity = $sec
    $Entry.CommitChanges()
}

function Set-AdmObjectProtection {
    <#
    .SYNOPSIS
    Protect an object from accidental deletion, or clear that protection. Writes -- honours -WhatIf.
    .DESCRIPTION
      Works on any object, not just an OU -- a service account or a critical group is worth the
      same guard. The protection is a Deny ACE for Everyone on Delete and Delete Subtree.

      ⚠ IT DENIES EVERYONE, INCLUDING YOU. That is the point, and it is also why a protected
      object reports "Access is denied" on deletion rather than anything about protection.
    .EXAMPLE
      Set-AdmObjectProtection -Target corp.example.com -Identity 'OU=Staff,DC=corp,DC=example,DC=com' -Protected $true
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][bool]$Protected,
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    $verb = if ($Protected) { 'protect' } else { 'unprotect' }
    Invoke-AdmGuarded -Operation "$verb '$Identity'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup

        if ((Get-AdmProviderName) -eq 'mock') {
            if (-not $PSCmdlet.ShouldProcess($Identity, "$verb object")) { return }
            return [pscustomobject]@{ Domain = $ctx.Domain.Name; DistinguishedName = $Identity
                                      Protected = $Protected; Action = "$verb-object" }
        }

        $dn = Resolve-AdmObjectDn -Context $ctx -Identity $Identity
        if (-not $PSCmdlet.ShouldProcess("$dn @ $($ctx.Domain.DnsDomain)", "$verb from accidental deletion")) { return }
        $entry = Get-AdmEntryByDn -Context $ctx -DistinguishedName $dn
        try {
            Set-AdmEntryProtection -Entry $entry -Protected $Protected
            [void](Write-AdmLogEntry -Severity info -Event 'change' -Operation "$verb object" `
                    -Target $Target -Domain $ctx.Domain.Name `
                    -Message "Set accidental-deletion protection=$Protected on '$dn' in $($ctx.Domain.DnsDomain)")
            [pscustomobject]@{ Domain = $ctx.Domain.Name; DistinguishedName = $dn
                               Protected = $Protected; Action = "$verb-object" }
        } finally { Close-AdmDirectoryEntry $entry }
    }
}

# --- move / rename / delete ----------------------------------------------------------------------

function Move-AdmObject {
    <#
    .SYNOPSIS
    Move an object to another container. Writes -- honours -WhatIf.
    .DESCRIPTION
      ⚠ A MOVE CHANGES WHICH GROUP POLICY APPLIES. The object's DN changes, so every GPO linked
      to the old parent stops applying and every GPO linked to the new one starts. For a computer
      that is a reboot away from a different configuration; for a user, a logon away. The
      returned object reports both DNs so the change is visible in the log afterwards.

      ⛔ MOVING BETWEEN DOMAINS IS NOT THIS OPERATION. A cross-domain move needs the directory's
      own inter-domain move support and re-issues the object's SID; it is refused here rather
      than half-attempted.
    .EXAMPLE
      Move-AdmObject -Target corp.example.com -Identity jsmith -DestinationPath 'OU=Leavers,DC=corp,DC=example,DC=com'
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][string]$DestinationPath,
        [ValidateSet('any', 'user', 'group', 'computer', 'ou')][string]$Class = 'any',
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "move '$Identity'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup

        if ((Get-AdmProviderName) -eq 'mock') {
            if (-not $PSCmdlet.ShouldProcess($Identity, "Move to $DestinationPath")) { return }
            return [pscustomobject]@{ Domain = $ctx.Domain.Name; Identity = $Identity
                                      FromDn = $Identity; ToDn = $DestinationPath; Action = 'move-object' }
        }

        $dn = Resolve-AdmObjectDn -Context $ctx -Identity $Identity -Class $Class
        $domainDn = ConvertTo-AdmDistinguishedName -DnsDomain $ctx.Domain.DnsDomain
        if (-not $DestinationPath.ToLowerInvariant().EndsWith($domainDn.ToLowerInvariant())) {
            throw "'$DestinationPath' is not inside $($ctx.Domain.DnsDomain) ($domainDn). Moving an object between domains re-issues its SID and is a different operation; refusing."
        }
        if (-not $PSCmdlet.ShouldProcess("$dn @ $($ctx.Domain.DnsDomain)", "Move to $DestinationPath")) { return }

        $entry = Get-AdmEntryByDn -Context $ctx -DistinguishedName $dn
        $dest = $null
        try {
            # A protected object cannot be moved either -- the Deny covers Delete, and a move is
            # implemented as a delete-and-add of the naming attribute. Say so plainly.
            if (Test-AdmObjectProtected -Context $ctx -DistinguishedName $dn -Entry $entry) {
                throw "'$dn' is protected from accidental deletion, which also blocks a move. Clear it first: Set-AdmObjectProtection -Identity '$dn' -Protected `$false"
            }
            $dest = Get-AdmEntryByDn -Context $ctx -DistinguishedName $DestinationPath
            $entry.MoveTo($dest)
            $newDn = [string]$entry.Properties['distinguishedName'].Value

            [void](Write-AdmLogEntry -Severity info -Event 'change' -Operation 'move object' `
                    -Target $Target -Domain $ctx.Domain.Name `
                    -Message "Moved '$dn' to '$newDn' in $($ctx.Domain.DnsDomain) -- linked Group Policy changes with the parent")

            [pscustomobject]@{ Domain = $ctx.Domain.Name; Identity = $Identity
                               FromDn = $dn; ToDn = $newDn; Action = 'move-object' }
        } finally {
            Close-AdmDirectoryEntry $dest
            Close-AdmDirectoryEntry $entry
        }
    }
}

function Rename-AdmObject {
    <#
    .SYNOPSIS
    Change an object's name (its RDN). Writes -- honours -WhatIf.
    .DESCRIPTION
      ⚠ THIS RENAMES THE OBJECT, NOT THE ACCOUNT. Renaming a user changes its CN and therefore
      its distinguished name; it does NOT change sAMAccountName, userPrincipalName or
      displayName, and someone who renames "CN=Jo Smith" to "CN=Jo Brown" and expects the logon
      name to follow will find it unchanged. Use Set-AdmUser for those, and expect to do both.

      The RDN prefix is taken from the object's existing DN, so an OU renames as OU= and a user
      as CN= without the caller having to know which.
    .EXAMPLE
      Rename-AdmObject -Target corp.example.com -Identity 'CN=Jo Smith,OU=Staff,DC=corp,DC=example,DC=com' -NewName 'Jo Brown'
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][string]$NewName,
        [ValidateSet('any', 'user', 'group', 'computer', 'ou')][string]$Class = 'any',
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "rename '$Identity'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup

        if ((Get-AdmProviderName) -eq 'mock') {
            if (-not $PSCmdlet.ShouldProcess($Identity, "Rename to '$NewName'")) { return }
            return [pscustomobject]@{ Domain = $ctx.Domain.Name; FromDn = $Identity
                                      ToDn = $NewName; Action = 'rename-object' }
        }

        $dn = Resolve-AdmObjectDn -Context $ctx -Identity $Identity -Class $Class
        $prefix = Get-AdmRdnPrefix -DistinguishedName $dn
        if (-not $PSCmdlet.ShouldProcess("$dn @ $($ctx.Domain.DnsDomain)", "Rename to '$prefix=$NewName'")) { return }

        $entry = Get-AdmEntryByDn -Context $ctx -DistinguishedName $dn
        try {
            $entry.Rename("$prefix=$NewName")
            $newDn = [string]$entry.Properties['distinguishedName'].Value
            [void](Write-AdmLogEntry -Severity info -Event 'change' -Operation 'rename object' `
                    -Target $Target -Domain $ctx.Domain.Name `
                    -Message "Renamed '$dn' to '$newDn' in $($ctx.Domain.DnsDomain) -- sAMAccountName and UPN are unchanged")
            [pscustomobject]@{ Domain = $ctx.Domain.Name; FromDn = $dn; ToDn = $newDn; Action = 'rename-object' }
        } finally { Close-AdmDirectoryEntry $entry }
    }
}

function Remove-AdmObject {
    <#
    .SYNOPSIS
    Delete a directory object. Writes -- honours -WhatIf.
    .DESCRIPTION
      ⛔ REFUSES A DOMAIN CONTROLLER'S COMPUTER ACCOUNT, on the same grounds and with the same
      absence of an override as Set-AdmComputerEnabled: deleting one is not a cleanup, it is an
      outage, and a sweep is more likely to select a DC than anything else because a DC looks
      idle by every measure such a sweep uses.

      ⛔ REFUSES AN OU unless it is empty, and points at Remove-AdmOrganizationalUnit, which knows
      how to count what would go with it.

      A deleted object is recoverable ONLY if the AD Recycle Bin is enabled in the forest --
      otherwise what remains is a stripped tombstone that cannot be usefully restored.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Identity,
        [ValidateSet('any', 'user', 'group', 'computer', 'ou')][string]$Class = 'any',
        [switch]$RemoveProtection,
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "delete '$Identity'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup

        if ((Get-AdmProviderName) -eq 'mock') {
            if (-not $PSCmdlet.ShouldProcess($Identity, 'Delete object')) { return }
            return [pscustomobject]@{ Domain = $ctx.Domain.Name; DistinguishedName = $Identity; Action = 'delete-object' }
        }

        $dn = Resolve-AdmObjectDn -Context $ctx -Identity $Identity -Class $Class
        $entry = Get-AdmEntryByDn -Context $ctx -DistinguishedName $dn
        try {
            $classes = @($entry.Properties['objectClass'] | ForEach-Object { [string]$_ })
            if ($classes -contains 'organizationalUnit') {
                $kids = 0
                foreach ($c in $entry.Children) { $kids++; Close-AdmDirectoryEntry $c }
                if ($kids -gt 0) {
                    throw "'$dn' is an organizational unit containing $kids object(s). Use Remove-AdmOrganizationalUnit -Recurse if you mean to delete the whole subtree."
                }
            }
            if ($classes -contains 'computer') {
                $uac = 0
                [void][int]::TryParse([string]$entry.Properties['userAccountControl'].Value, [ref]$uac)
                # 0x2000 SERVER_TRUST_ACCOUNT. Same rule as Set-AdmComputerEnabled, and it lives
                # here rather than in a caller so every caller inherits it.
                if ($uac -band 0x2000) {
                    throw "'$dn' is a DOMAIN CONTROLLER (userAccountControl 0x2000). Deleting a DC's computer account removes that domain controller from the domain; refusing."
                }
            }

            $wasProtected = Test-AdmObjectProtected -Context $ctx -DistinguishedName $dn -Entry $entry
            if ($wasProtected -and -not $RemoveProtection) {
                throw "'$dn' is protected from accidental deletion. Re-run with -RemoveProtection if the deletion is intended."
            }
            if (-not $PSCmdlet.ShouldProcess("$dn @ $($ctx.Domain.DnsDomain)", 'Delete object')) { return }

            if ($wasProtected) { Set-AdmEntryProtection -Entry $entry -Protected $false }
            $entry.DeleteTree()

            [void](Write-AdmLogEntry -Severity warn -Event 'change' -Operation 'delete object' `
                    -Target $Target -Domain $ctx.Domain.Name `
                    -Message "Deleted '$dn' from $($ctx.Domain.DnsDomain)")

            [pscustomobject]@{ Domain = $ctx.Domain.Name; DistinguishedName = $dn
                               WasProtected = $wasProtected; Action = 'delete-object' }
        } finally { Close-AdmDirectoryEntry $entry }
    }
}

# --- gPLink, shared with the OU listing and the GPO report ----------------------------------------

# gPLink is a single string of bracketed pairs, newest LAST in precedence terms:
#   [LDAP://cn={GUID},cn=policies,cn=system,DC=x;0][LDAP://...;2]
# The trailing number is a flag: 1 = link disabled, 2 = enforced, 3 = both.
function ConvertFrom-AdmGpLink {
    <#
    .SYNOPSIS
      Parse a gPLink string into linked GPOs, with Enabled and Enforced per link.
    .DESCRIPTION
      gPLink is one string of bracketed pairs: [LDAP://<gpo dn>;<flags>]. The trailing number is
      1 = link disabled, 2 = enforced, 3 = both. A DISABLED link still counts as a link, so the
      two are reported separately rather than collapsed -- a GPO whose only link is disabled
      applies nothing while looking linked.
    #>
    [CmdletBinding()]
    param($Value)
    $s = [string]$Value
    if (-not $s) { return @() }
    $out = New-Object System.Collections.ArrayList
    foreach ($m in [regex]::Matches($s, '\[LDAP://([^;\]]+);(\d+)\]')) {
        $flag = 0; [void][int]::TryParse($m.Groups[2].Value, [ref]$flag)
        [void]$out.Add([pscustomobject]@{
            GpoDn    = $m.Groups[1].Value
            Enabled  = -not ($flag -band 1)
            Enforced = [bool]($flag -band 2)
        })
    }
    $out.ToArray()
}
