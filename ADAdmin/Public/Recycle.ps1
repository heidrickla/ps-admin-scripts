# Public/Recycle.ps1 -- finding and restoring deleted objects.
#
# ⛔ THE SINGLE MOST IMPORTANT THING IN THIS FILE: whether the AD Recycle Bin is ENABLED changes
# what "restore" even means, and the difference is not cosmetic.
#
#   Recycle Bin ENABLED   -- a deleted object keeps its attributes and its group memberships for
#                            the deleted-object lifetime. Restoring gives back the object you had.
#   Recycle Bin DISABLED  -- deletion STRIPS the object down to a tombstone: a handful of
#                            attributes survive and group memberships DO NOT. Restoring gives back
#                            a shell with the right name and SID and almost nothing else, and the
#                            person who ran it reasonably believes the problem is fixed.
#
# So every function here reports the forest's Recycle Bin state alongside the result, and the
# restore REFUSES to run against a tombstone unless the caller says explicitly that a stripped
# object is what they want. That refusal is the point of the file.
#
# ✔ VERIFICATION STATUS, 2026-08-28, measured on a lab forest:
#   Test-AdmRecycleBinEnabled  -- verified; the bin is DISABLED on that forest
#   Get-AdmDeletedObject       -- verified against 65 real tombstones, names recovered correctly
#                                 from mangled RDNs, classes correct including an OU
#   Restore-AdmObject          -- verified on the TOMBSTONE path end to end: refused without
#                                 -AcceptTombstone, restored with it, came back in its ORIGINAL
#                                 OU and DISABLED, and left the bin
#   ⚠ THE FULL-RESTORE BRANCH (Recycle Bin ON) IS STILL UNVERIFIED. It cannot be tested on this
#     forest at all, because the bin is off there.
#
# ⛔ DO NOT ENABLE THE RECYCLE BIN ON THE LAB TO TEST IT. Enabling is forest-wide and
# IRREVERSIBLE -- it would permanently change the forest the tests run against, and that is the
# forest owner's call, not a test fixture decision.

# The Recycle Bin optional feature's well-known GUID. Enabling it adds this feature's DN to
# msDS-EnabledFeature on the Partitions container, and it is IRREVERSIBLE once done.
$script:AdmRecycleBinFeatureGuid = '766ddcd8-acd0-445e-f3b9-a7f9b6744f2a'

function Test-AdmRecycleBinEnabled {
    <#
    .SYNOPSIS
    Is the AD Recycle Bin enabled in this forest? Read-only.
    .DESCRIPTION
      Determines what a restore would actually give back. Enabling the Recycle Bin is a one-way
      forest-wide change, so this is a property of the forest and not of any object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Tier,
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation 'check the AD Recycle Bin' -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        if ((Get-AdmProviderName) -eq 'mock') {
            return [pscustomobject]@{ Domain = $ctx.Domain.Name; Enabled = $false
                                      Detail = 'not modelled by the fixture'; IsMock = $true }
        }
        $configNc = Get-AdmNamingContext -Context $ctx -Name 'configurationNamingContext'
        if (-not $configNc) { throw "Could not read configurationNamingContext from the rootDSE of $($ctx.Domain.DnsDomain)." }

        $rows = @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential `
                    -Filter '(objectClass=crossRefContainer)' -SearchBase "CN=Partitions,$configNc" `
                    -Properties @('msds-enabledfeature') -SizeLimit 1)
        $features = @(Get-AdmRawProp $rows[0] 'msds-enabledfeature' @())
        $on = [bool](@($features | Where-Object { [string]$_ -match $script:AdmRecycleBinFeatureGuid }).Count)
        [pscustomobject]@{
            Domain  = $ctx.Domain.Name
            Enabled = $on
            Detail  = $(if ($on) {
                          'Deleted objects keep their attributes and group memberships for the deleted-object lifetime, so a restore returns a usable object.'
                        } else {
                          'Deletion strips objects to tombstones: most attributes and ALL group memberships are lost at deletion time and cannot be recovered by restoring. Enabling the Recycle Bin is forest-wide and irreversible, and does not help with anything already deleted.'
                        })
        }
    }
}

# Deleted objects are only visible with the "Show Deleted Objects" LDAP control. DirectorySearcher
# exposes it as .Tombstone -- without it the container appears empty, which reads as "nothing was
# deleted" rather than "you did not ask to see them". Invoke-AdmAdsiSearch deliberately does not
# set it, so this file does its own search.
#
# ⛔ THE SEARCH BASE IS THE DOMAIN ROOT, NOT "CN=Deleted Objects". This looks like the wrong base
# and is the only one that works: .Tombstone is a property of the SEARCHER, and by the time it is
# set the base DirectoryEntry has already been bound WITHOUT the Show Deleted Objects control.
# CN=Deleted Objects is a hidden container that cannot be bound without that control, so FindAll
# fails on the BASE rather than on the query -- and it fails with "There is no such object on the
# server", which blames the object and sends you looking for a container that is demonstrably
# there. Measured on a lab domain controller, 2026-08-28, by isolating three cases: binding to
# the container threw, searching from the root with the control returned 57 objects including
# everything inside it, and a root search for (cn=Deleted Objects) found the container itself.
function Invoke-AdmDeletedSearch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Filter,
        [string[]]$Properties = @(),
        [int]$SizeLimit = 200
    )
    # No -DistinguishedName: New-AdmDirectoryEntry then binds the domain naming context, which is
    # an ordinary container and binds without any control.
    $root = New-AdmDirectoryEntry -Domain $Context.Domain -Credential $Context.Credential
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
        try {
            $searcher.Filter = $Filter
            # One past the limit, so the extra row IS the truncation signal -- see the note on
            # Invoke-AdmAdsiSearch. It matters more here than anywhere: "the object is not in the
            # Recycle Bin" is how somebody concludes it is unrecoverable.
            $searcher.SizeLimit = Get-AdmOverfetchLimit $SizeLimit
            $searcher.PageSize = 500
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $searcher.Tombstone = $true
            foreach ($p in $Properties) { [void]$searcher.PropertiesToLoad.Add($p) }
            $results = $searcher.FindAll()
            try {
                $n = 0
                foreach ($r in $results) {
                    $n++
                    if ($SizeLimit -gt 0 -and $n -gt $SizeLimit) {
                        $script:AdmLastSearchTruncated = $true
                        Write-Warning ("More than $SizeLimit deleted objects match. Only that many were read, " +
                                       'so an object missing from this list is not proof it is gone.')
                        break
                    }
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

# ⛔ A DELETED OBJECT CANNOT BE WRITTEN THROUGH System.DirectoryServices AT ALL, and this is the
# single most surprising thing in this file. Everything else in the module uses DirectoryEntry;
# the restore cannot. Measured on a lab domain controller, 2026-08-28, by isolating three cases against a real
# tombstone:
#
#   A. searcher.Tombstone = $true, FindOne(), then GetDirectoryEntry()
#      -> the entry comes back with NULL properties. Reading `name` throws "Cannot index into a
#         null array" -- this module's own signature for a bind that silently failed. The
#         SearchResult carries the control; the DirectoryEntry made from it does NOT.
#   B. PutEx on that entry
#      -> "There is no such object on the server", from PutEx rather than from the bind, which
#         blames the object and hides that the bind never happened.
#   C. System.DirectoryServices.Protocols, ModifyRequest carrying ShowDeletedControl
#      -> ResultCode: Success. The object was genuinely restored.
#
# So the restore is the one operation here that drops to the lower-level LDAP API. It is not a
# stylistic choice and it must not be "simplified" back to a DirectoryEntry later.
function New-AdmLdapConnection {
    <#
    .SYNOPSIS
      An S.DS.Protocols LdapConnection to a domain, for the operations DirectoryEntry cannot do.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
    $server = Get-AdmLdapServer -Domain $Context.Domain
    $port = if ($Context.Domain.Port) { $Context.Domain.Port } else { if ($Context.Domain.UseSsl) { 636 } else { 389 } }

    # NetworkCredential wants the domain separately. Accept DOMAIN\user and user@domain, which are
    # both forms the store holds.
    $u = $Context.Credential.UserName
    $dom = ''
    if ($u -match '^(?<d>[^\\]+)\\(?<u>.+)$') { $dom = $Matches['d']; $u = $Matches['u'] }
    elseif ($u -match '^(?<u>[^@]+)@(?<d>.+)$') { $dom = $Matches['d']; $u = $Matches['u'] }

    $plain = ConvertFrom-AdmSecureString -Secure $Context.Credential.Password
    try {
        $id = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($server, $port)
        $nc = New-Object System.Net.NetworkCredential($u, $plain, $dom)
        $conn = New-Object System.DirectoryServices.Protocols.LdapConnection(
                    $id, $nc, [System.DirectoryServices.Protocols.AuthType]::Negotiate)
        if ($Context.Domain.UseSsl) { $conn.SessionOptions.SecureSocketLayer = $true }
        else {
            # Same protection as the DirectoryEntry path: sealing and signing, so a plain-389
            # connection is still encrypted.
            $conn.SessionOptions.Sealing = $true
            $conn.SessionOptions.Signing = $true
        }
        $conn.Bind()
        $conn
    } finally { $plain = $null }
}

function Get-AdmDeletedObject {
    <#
    .SYNOPSIS
    Objects that have been deleted and can still be restored. Read-only.
    .DESCRIPTION
      Reads CN=Deleted Objects with the Show Deleted Objects control. Without that control the
      container looks empty, which reads as "nothing was deleted" rather than "you did not ask".

      ⚠ WHAT COMES BACK DEPENDS ON THE RECYCLE BIN. With it enabled these are full objects. With
      it disabled they are tombstones -- name and SID and little else, with group memberships
      already gone. RecycleBinEnabled is reported on every row so the difference is never implicit.

      LastKnownParent is where the object lived, and is what Restore-AdmObject puts it back into
      when no destination is given. It is empty if the parent was itself deleted, and in that case
      the parent has to be restored first or a destination supplied.
    .OUTPUTS
      One object per deleted item, with EXACTLY these fields. The list is here because binding a
      grid to a name the object does not have yields a BLANK COLUMN rather than an error --
      Select-Object invents the property and fills it with nothing -- so a wrong name looks like
      an empty directory rather than like a typo.

        Domain             the registered domain name
        Name               the ORIGINAL name, un-mangled (see below)
        SamAccountName     may be absent on a tombstone
        ObjectClass        user | group | computer | organizationalUnit | other
        DistinguishedName  the object's CURRENT dn, inside CN=Deleted Objects
        LastKnownParent    where it lived; empty if its parent was deleted too
        ParentAvailable    bool -- false means restore needs an explicit -DestinationPath
        Sid                string SID, or null
        DeletedOn          when it was deleted   <-- NOT 'Deleted'
        WhenCreated        original creation time
        RecycleBinEnabled  forest-wide, and it decides what a restore actually returns
        Restorable         'fully', or a sentence saying the memberships are already gone

      ⚠ Name on a TOMBSTONE is derived, not read. With the Recycle Bin on, msDS-LastKnownRDN
      holds the original. With it off that attribute does not exist, so the name is recovered by
      cutting the mangled RDN "<original>\0ADEL:<guid>" at its marker -- where \0A is a literal
      newline, not the two characters backslash and zero.
    .EXAMPLE
      Get-AdmDeletedObject -Target corp.example.com
    .EXAMPLE
      Get-AdmDeletedObject -Target corp.example.com -Identity jsmith -Class user
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Identity,
        [ValidateSet('any', 'user', 'group', 'computer', 'ou')][string]$Class = 'any',
        [int]$Limit = 200,
        [string]$Tier,
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation 'list deleted objects' -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        if ((Get-AdmProviderName) -eq 'mock') { return @() }

        $rb = Test-AdmRecycleBinEnabled -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        $domainNc = ConvertTo-AdmDistinguishedName -DnsDomain $ctx.Domain.DnsDomain
        # The container's own DN, used to drop it from the results -- it matches (isDeleted=TRUE)
        # itself and would otherwise appear as a deleted object you could try to restore.
        $containerDn = "CN=Deleted Objects,$domainNc"

        $classClause = switch ($Class) {
            'user'     { '(objectClass=user)' }
            'group'    { '(objectClass=group)' }
            'computer' { '(objectClass=computer)' }
            'ou'       { '(objectClass=organizationalUnit)' }
            default    { '' }
        }
        $nameClause = ''
        if ($Identity) {
            $v = ConvertTo-AdmLdapFilterValue -Value $Identity
            # msDS-LastKnownRDN only exists with the Recycle Bin on; match `name` too, which on a
            # deleted object carries the mangled "<rdn>\0ADEL:<guid>" form.
            $nameClause = "(|(msDS-LastKnownRDN=*$v*)(name=*$v*)(sAMAccountName=*$v*))"
        }
        $filter = "(&(isDeleted=TRUE)$classClause$nameClause)"

        $rows = @(Invoke-AdmDeletedSearch -Context $ctx -Filter $filter -SizeLimit $Limit `
                    -Properties @('name', 'msds-lastknownrdn', 'distinguishedname', 'lastknownparent',
                                  'objectclass', 'objectsid', 'whenchanged', 'whencreated', 'samaccountname'))

        foreach ($r in $rows) {
            # ⛔ NOT filtered with (lastKnownParent=*), which would be the obvious way to exclude
            # the container: an object whose PARENT was also deleted has no lastKnownParent, and
            # those are precisely the ones that need an explicit -DestinationPath to restore. Drop
            # the container by name instead, so orphaned tombstones survive the filter.
            if ([string](Get-AdmRawProp $r 'distinguishedname') -eq $containerDn) { continue }
            $classes = @(Get-AdmRawProp $r 'objectclass' @())
            $cls = if ($classes -contains 'computer') { 'computer' }
                   elseif ($classes -contains 'group') { 'group' }
                   elseif ($classes -contains 'organizationalUnit') { 'organizationalUnit' }
                   elseif ($classes -contains 'user') { 'user' }
                   else { 'other' }
            # The RDN of a deleted object is mangled to "<original>\0ADEL:<guid>"; strip it back
            # for display rather than showing the operator the mangled form.
            $rawName = [string](Get-AdmRawProp $r 'name')
            $original = [string](Get-AdmRawProp $r 'msds-lastknownrdn')
            if (-not $original -and $rawName) {
                # The mangled RDN is "<original>\0ADEL:<guid>", where \0A is a LITERAL NEWLINE
                # (0x0A) -- not the two characters '\' and '0'. Written as an escape rather than
                # as a real line break in the source, because a source newline becomes CRLF the
                # moment this file is stored with Windows line endings and then never matches.
                $marker = "`nDEL:"
                $idx = $rawName.IndexOf($marker)
                $original = if ($idx -ge 0) { $rawName.Substring(0, $idx) } else { $rawName }
            }
            $parent = [string](Get-AdmRawProp $r 'lastknownparent')

            [pscustomobject]@{
                Domain            = $ctx.Domain.Name
                Name              = $original
                SamAccountName    = Get-AdmRawProp $r 'samaccountname'
                ObjectClass       = $cls
                DistinguishedName = Get-AdmRawProp $r 'distinguishedname'
                LastKnownParent   = $parent
                # A parent that was itself deleted cannot be restored into.
                ParentAvailable   = [bool]$parent
                Sid               = ConvertTo-AdmSidString (Get-AdmRawProp $r 'objectsid')
                DeletedOn         = Get-AdmRawProp $r 'whenchanged'
                WhenCreated       = Get-AdmRawProp $r 'whencreated'
                RecycleBinEnabled = $rb.Enabled
                Restorable        = $(if ($rb.Enabled) { 'fully' } else { 'tombstone only -- group memberships and most attributes are already gone' })
            }
        }
    }
}

function Restore-AdmObject {
    <#
    .SYNOPSIS
    Restore a deleted object. Writes -- honours -WhatIf.
    .DESCRIPTION
      Clears isDeleted and moves the object back to its last known parent, or to -DestinationPath.

      ⛔ IT REFUSES WHEN THE RECYCLE BIN IS DISABLED unless -AcceptTombstone is given. Restoring a
      tombstone returns an object with the correct name and SID and almost nothing else -- every
      group membership was destroyed at deletion time and is not coming back. That restored
      account cannot do the job it could yesterday, and it LOOKS restored, which is why the
      refusal is explicit rather than a warning someone scrolls past.

      ⚠ RESTORING DOES NOT RE-ENABLE. A restored user account comes back DISABLED and must be
      enabled separately with Set-AdmUserEnabled, deliberately: an account reappearing already
      able to log on is not something a restore should decide on its own.

      ⚠ Its password is not restored in a usable state either. Expect to reset it.
    .EXAMPLE
      Restore-AdmObject -Target corp.example.com -Identity jsmith
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Identity,
        # Where to put it back. Defaults to lastKnownParent.
        [string]$DestinationPath,
        [ValidateSet('any', 'user', 'group', 'computer', 'ou')][string]$Class = 'any',
        # Required to restore when the Recycle Bin is off and the object is a stripped tombstone.
        [switch]$AcceptTombstone,
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "restore '$Identity'" -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup

        if ((Get-AdmProviderName) -eq 'mock') {
            if (-not $PSCmdlet.ShouldProcess($Identity, 'Restore deleted object')) { return }
            return [pscustomobject]@{ Domain = $ctx.Domain.Name; Name = $Identity
                                      RestoredTo = $DestinationPath; Action = 'restore-object' }
        }

        $candidates = @(Get-AdmDeletedObject -Target $Target -Identity $Identity -Class $Class -Tier $Tier -UseDnsLookup:$UseDnsLookup)
        if ($candidates.Count -eq 0) { throw "No deleted object matching '$Identity' in $($ctx.Domain.DnsDomain). Note that deleted objects are only visible with the Show Deleted Objects control, and only until the deleted-object lifetime expires." }
        if ($candidates.Count -gt 1) {
            $list = ($candidates | ForEach-Object { "$($_.Name) (deleted $($_.DeletedOn))" }) -join '; '
            throw "'$Identity' matched $($candidates.Count) deleted objects and restoring the wrong one is not something to guess at: $list. Pass the full distinguished name."
        }
        $obj = $candidates[0]

        if (-not $obj.RecycleBinEnabled -and -not $AcceptTombstone) {
            throw "The AD Recycle Bin is NOT enabled in this forest, so '$($obj.Name)' is a tombstone rather than a recoverable object: its group memberships and most of its attributes were destroyed when it was deleted and cannot be brought back by restoring it. The restore would produce an object with the right name and SID that cannot do what it did before -- while looking restored. Re-run with -AcceptTombstone if that is genuinely what you want."
        }

        $dest = if ($DestinationPath) { $DestinationPath } else { $obj.LastKnownParent }
        if (-not $dest) {
            throw "'$($obj.Name)' has no lastKnownParent -- its parent container was deleted too. Restore the parent first, or pass -DestinationPath to say where it should go."
        }

        # ⛔ NOT ALWAYS "CN=". An organizationalUnit's RDN prefix is OU=, and building CN=<name>
        # for one is rejected with a naming-violation error that says nothing about which prefix
        # was expected -- the same trap Rename-AdmObject handles by reading the prefix off the
        # existing DN. Here the object's live DN is gone, so the class is what decides.
        $prefix = if ($obj.ObjectClass -eq 'organizationalUnit') { 'OU' } else { 'CN' }
        $newDn = "$prefix=$(ConvertTo-AdmRdnEscaped -Value $obj.Name),$dest"
        if (-not $PSCmdlet.ShouldProcess("$($obj.Name) @ $($ctx.Domain.DnsDomain)", "Restore to $dest")) { return }

        # The restore itself: clear isDeleted and set the new DN in ONE commit. They cannot be
        # separated -- the directory rejects clearing isDeleted without also giving the object a
        # live distinguished name to occupy.
        # ⛔ S.DS.Protocols, NOT DirectoryEntry -- see New-AdmLdapConnection for the measurement.
        # The two modifications must go in ONE request: the directory rejects clearing isDeleted
        # without simultaneously giving the object a live distinguished name to occupy.
        $conn = New-AdmLdapConnection -Context $ctx
        try {
            $req = New-Object System.DirectoryServices.Protocols.ModifyRequest
            $req.DistinguishedName = $obj.DistinguishedName
            [void]$req.Controls.Add((New-Object System.DirectoryServices.Protocols.ShowDeletedControl))

            $mDel = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
            $mDel.Name = 'isDeleted'
            $mDel.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete

            $mDn = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
            $mDn.Name = 'distinguishedName'
            $mDn.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
            [void]$mDn.Add($newDn)

            [void]$req.Modifications.Add($mDel)
            [void]$req.Modifications.Add($mDn)

            $resp = $conn.SendRequest($req)
            if ($resp.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                throw "The directory refused the restore: $($resp.ResultCode) $($resp.ErrorMessage)"
            }

            [void](Write-AdmLogEntry -Severity warn -Event 'change' -Operation 'restore object' `
                    -Target $Target -Domain $ctx.Domain.Name `
                    -Message "Restored '$($obj.Name)' to '$newDn' in $($ctx.Domain.DnsDomain) (recycle bin enabled=$($obj.RecycleBinEnabled))")

            [pscustomobject]@{
                Domain = $ctx.Domain.Name
                Name = $obj.Name
                ObjectClass = $obj.ObjectClass
                RestoredTo = $newDn
                RecycleBinEnabled = $obj.RecycleBinEnabled
                # Said plainly in the RESULT, not only in the help, because this is the moment
                # someone believes the job is done.
                NextSteps = @(
                    'The account is restored DISABLED -- enable it with Set-AdmUserEnabled when you are ready.',
                    'Reset the password; the old one is not restored in a usable state.',
                    $(if (-not $obj.RecycleBinEnabled) { 'Group memberships were NOT restored -- they were destroyed at deletion. Re-add them by hand.' } else { 'Group memberships were preserved by the Recycle Bin; check them anyway.' })
                )
                Action = 'restore-object'
            }
        } finally { if ($conn) { try { $conn.Dispose() } catch { } } }
    }
}
