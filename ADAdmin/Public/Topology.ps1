# Public/Topology.ps1 -- the shape of the forest rather than the objects in it: trusts, sites and
# subnets, and Group Policy inventory.
#
# All three read from the CONFIGURATION partition or from CN=System, not from the part of the
# directory the other cmdlets touch, and all three are read-only. No RSAT, no GPMC: everything
# here is a plain LDAP read over the connection the credential store already resolved.

# --- trusts ---------------------------------------------------------------------------------

# trustDirection and trustType are small enumerations; trustAttributes is a bitfield. They are
# kept as ordered pairs rather than a hashtable keyed by number, because indexing a hashtable
# with an integer key does a POSITIONAL lookup in PowerShell and silently returns the wrong entry
# -- or $null for a value past the end.
function ConvertFrom-AdmTrustDirection {
    <#
    .SYNOPSIS
      Name a trustDirection value: Inbound means THEY trust US, Outbound means we trust them.
    .DESCRIPTION
      The two directions are routinely read backwards. Inbound (1) means the partner trusts this
      domain, so their users can reach our resources; Outbound (2) means we trust them. An
      unrecognised value is reported WITH its number rather than guessed at.
    #>
    [OutputType([string])]
    param($Value)
    $n = ConvertTo-AdmSignedFlag $Value
    switch ($n) {
        0 { 'Disabled' }
        1 { 'Inbound' }          # they trust us; their users can use our resources
        2 { 'Outbound' }         # we trust them; our users can use their resources
        3 { 'Bidirectional' }
        default { "Unknown ($n)" }
    }
}

function ConvertFrom-AdmTrustType {
    <#
    .SYNOPSIS
      Name a trustType value (Active Directory, Windows NT downlevel, MIT Kerberos realm, DCE).
    #>
    [OutputType([string])]
    param($Value)
    $n = ConvertTo-AdmSignedFlag $Value
    switch ($n) {
        1 { 'Windows NT (downlevel)' }
        2 { 'Active Directory' }
        3 { 'MIT Kerberos realm' }
        4 { 'DCE' }
        default { "Unknown ($n)" }
    }
}

function ConvertTo-AdmSignedFlag {
    <#
    .SYNOPSIS
      Parse a directory bitfield to a SIGNED Int32, wrapping a value that carries 0x80000000.
    .DESCRIPTION
      Delegates the parsing to ConvertTo-AdmInt64 and adds only the signed-32 narrowing. There is
      deliberately ONE parser in the module; this exists for the wrap, not to parse.
      ⛔ NEVER `[int]::TryParse([string]$Value, ...)`. That round trip is the bug, and it is worth
      stating precisely because the imprecise version leads to a fix that only covers one case.

      MEASURED, 5.1 and 7, 2026-08-28. Pass a hex literal in COMMAND-ARGUMENT position:

          function A { param($Value) "$($Value.GetType().Name) [string]=$([string]$Value)" }
          A -Value 0x200     ->     Int32  [string]=0x200

      The argument is a genuine Int32 whose value is 512 -- `$Value -eq 512` is true. But
      PowerShell keeps the ORIGINAL LITERAL TEXT and hands it back on string conversion, so
      `[string]$Value` is "0x200" and `[int]::TryParse("0x200")` returns FALSE, leaving 0. The
      decoder then reports NO FLAGS SET, with no error, for a value that was perfectly valid.

      Note this is specific to argument binding: `$v = 0x200; [string]$v` gives "512" and parses
      fine, which is why the bug hides from a quick test at the console.

      A direct cast handles every form -- Int32, the decimal string a directory returns, AND a
      hex string -- because PowerShell's own converter understands all three. Verified:
      `[int64]0x200`, `[int64]'512'` and `[int64]'0x200'` all give 512.

      The first version here was a hex-aware string parser, which fixed the case in hand and left
      the general trap in place.
    #>
    [OutputType([int])]
    param($Value)
    # Parsing is ConvertTo-AdmInt64's job (Detail.ps1) -- one parser for the module, and it is
    # the one that carries the cast-don't-stringify rule described above.
    $n64 = ConvertTo-AdmInt64 -Value $Value
    # What this adds, and the only reason it exists separately: NARROWING TO A SIGNED 32-BIT VIEW.
    # groupType sets 0x80000000 on every security group, so read as an unsigned number it exceeds
    # Int32 and a plain [int] cast overflows -- while the directory means it as a NEGATIVE Int32
    # (a global security group is -2147483646, which is why ConvertTo-AdmGroupType writes it that
    # way). Wrap rather than throw.
    $u = $n64 -band 0xFFFFFFFFL
    if ($u -ge 2147483648L) { $u = $u - 4294967296L }
    [int]$u
}

function ConvertFrom-AdmTrustAttributes {
    <#
    .SYNOPSIS
      Decode trustAttributes into named flags. QuarantinedDomain means SID filtering is ON.
    .DESCRIPTION
      Returns a plain array of names, so an empty result really is empty and -contains works.
      QuarantinedDomain is the SID-filtering flag: on an EXTERNAL trust its absence is the notable
      case, while a forest trust expresses the same protection differently -- so the flag is
      reported, not judged.
    #>
    [CmdletBinding()]
    param($Value)
    $n = ConvertTo-AdmSignedFlag $Value
    $flags = New-Object System.Collections.ArrayList
    # ⛔ TWO PARALLEL ARRAYS, not an array of pairs. `@( @(1,'A') )` containing EXACTLY ONE inner
    # array is FLATTENED by PowerShell into `@(1,'A')` -- so `$pair` becomes an Int32 and
    # `$pair[0]` throws "Unable to index into an object of type System.Int32". A pair table that
    # is correct with ten entries breaks the day someone trims it to one, which is the worst
    # possible time for it to break. Parallel arrays cannot do that.
    $bits  = @(0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x200, 0x800)
    $names = @('NonTransitive', 'UplevelOnly', 'QuarantinedDomain', 'ForestTransitive',
               'CrossOrganization', 'WithinForest', 'TreatAsExternal', 'UsesRC4Encryption',
               'CrossOrganizationNoTgtDelegation', 'PimTrust')
    for ($i = 0; $i -lt $bits.Count; $i++) {
        if ($n -band $bits[$i]) { [void]$flags.Add($names[$i]) }
    }
    # Emitted, not `,`-wrapped -- see the note in Get-AdmRangedAttribute. Callers wrap in @(),
    # and a comma-return makes an empty flag set count as one and breaks -contains.
    $flags.ToArray()
}

function Get-AdmTrust {
    <#
    .SYNOPSIS
    Trust relationships this domain has with any other. Read-only.
    .DESCRIPTION
      Reads the trustedDomain objects under CN=System. Each one is one side of a relationship, so
      a two-way trust between two domains appears once here and once in the other domain.

      ⭐ WORTH RUNNING EVEN WHEN YOU BELIEVE THERE ARE NO TRUSTS. This toolkit exists because the
      estate is a set of forests with no trusts between them, and every safety argument it makes
      rests on that. A trust nobody remembered creating changes which credential can reach what,
      and it is a single LDAP read to find out rather than an assumption to carry.

      ⚠ SID FILTERING IS REPORTED, NOT JUDGED. QuarantinedDomain in the flags means SID filtering
      is ON for an external trust -- which is the safe setting, so its ABSENCE on an external
      trust is the notable case. On a forest trust the same protection is expressed differently,
      so the flag alone is not a verdict and this does not pretend otherwise.
    .EXAMPLE
      Get-AdmTrust -Target corp.example.com
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Tier,
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation 'list trusts' -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup

        if ((Get-AdmProviderName) -eq 'mock') {
            # The fixture models untrusted forests, which is the estate's real shape. An empty
            # list here is the correct answer, not a gap -- but say so, because "no trusts" and
            # "not modelled" look identical otherwise.
            return @()
        }

        $rows = @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential `
                    -Filter '(objectClass=trustedDomain)' -SizeLimit 5000 `
                    -Properties @('trustpartner', 'flatname', 'trustdirection', 'trusttype',
                                  'trustattributes', 'whencreated', 'whenchanged', 'distinguishedname'))
        foreach ($r in $rows) {
            $attrs = @(ConvertFrom-AdmTrustAttributes (Get-AdmRawProp $r 'trustattributes'))
            [pscustomobject]@{
                Domain            = $ctx.Domain.Name
                Partner           = Get-AdmRawProp $r 'trustpartner'
                NetbiosName       = Get-AdmRawProp $r 'flatname'
                Direction         = ConvertFrom-AdmTrustDirection (Get-AdmRawProp $r 'trustdirection')
                TrustType         = ConvertFrom-AdmTrustType (Get-AdmRawProp $r 'trusttype')
                Attributes        = $attrs
                Transitive        = -not ($attrs -contains 'NonTransitive')
                ForestTrust       = ($attrs -contains 'ForestTransitive')
                WithinForest      = ($attrs -contains 'WithinForest')
                SidFilteringOn    = ($attrs -contains 'QuarantinedDomain')
                WhenCreated       = Get-AdmRawProp $r 'whencreated'
                WhenChanged       = Get-AdmRawProp $r 'whenchanged'
                DistinguishedName = Get-AdmRawProp $r 'distinguishedname'
            }
        }
    }
}

# --- sites and subnets --------------------------------------------------------------------------

function Get-AdmSite {
    <#
    .SYNOPSIS
    Sites, their subnets, and which domain controllers serve them. Read-only.
    .DESCRIPTION
      Replication topology and, more usefully day to day, the reason a client authenticates
      against a domain controller on the wrong continent.

      ⭐ A SITE WITH NO SUBNETS IS THE COMMON FAULT. A client is assigned to a site by matching
      its IP against the subnet objects. An address that matches no subnet gets NO site, and the
      client then picks a domain controller essentially at random -- which shows up as slow logons
      and odd replication complaints, and is invisible unless you look here. Sites with no subnet
      are flagged in the returned object rather than left for the reader to notice.

      ⚠ THIS CMDLET REPORTS ITS OWN TRUNCATION IN ITS ROWS, not through the global
      Get-AdmSearchTruncated flag. It makes three searches -- sites, subnets, servers -- and needs
      to know which of them was cut, so it resets the flag between them. That means an outer
      `Reset-AdmSearchTruncated; Get-AdmSite; Get-AdmSearchTruncated` sequence sees only the LAST
      search. Use SubnetsTruncated and ServersTruncated instead; they are per-read and exact.

      ⛔ NoSubnets and NoServers are $null -- UNKNOWN -- when their read was truncated. If we could
      not see every subnet we cannot say a site has none, and "none" is the finding people act on.

      Every row already carries Subnets, SubnetCount and NoSubnets, so there is no switch to ask
      for them. There used to be an -IncludeSubnets switch and it was a design error: it did not
      ADD subnets to the sites, it replaced the sites with subnets -- so on a forest with no
      subnets it returned nothing at all, which reads as "no sites" for a forest that always has
      at least Default-First-Site-Name. Use Get-AdmSubnet for the subnet-centric view; it is a
      different question and it can show subnets that belong to no site, which this cannot.
    .EXAMPLE
      Get-AdmSite -Target corp.example.com
    .EXAMPLE
      Get-AdmSite -Target corp.example.com | Where-Object { $_.NoSubnets }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Tier,
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation 'list sites' -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        if ((Get-AdmProviderName) -eq 'mock') { return @() }

        $configNc = Get-AdmNamingContext -Context $ctx -Name 'configurationNamingContext'
        if (-not $configNc) { throw "Could not read configurationNamingContext from the rootDSE of $($ctx.Domain.DnsDomain)." }
        $sitesDn = "CN=Sites,$configNc"

        $siteRows = @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential `
                        -Filter '(objectClass=site)' -SearchBase $sitesDn -SizeLimit 20000 `
                        -Properties @('name', 'distinguishedname', 'description', 'whencreated'))

        # ⛔ A SILENTLY TRUNCATED SUBNET LIST IS WORSE THAN NO SUBNET LIST HERE, because every
        # number this cmdlet reports is derived from it: a short read makes SubnetCount wrong and
        # NoSubnets FALSELY TRUE, which is the single finding the cmdlet exists to surface. A
        # DirectorySearcher stops at SizeLimit without saying so, so the limit is set high and the
        # hit is DETECTED rather than trusted. Production estates really do have many subnets --
        # the lab has none, so this could never have shown up there (measured 2026-08-28).
        # ⛔ THE FLAG, NOT `.Count -ge $limit`. The searches over-fetch by one so the extra row IS
        # the signal, which means a count that merely EQUALS the limit is a COMPLETE result -- and
        # the count comparison cannot tell that apart from a truncated one, so it refuses on
        # perfectly good data. Reset immediately before the read whose truncation is being
        # measured: the flag is sticky, so without the reset it would still carry the answer from
        # the sites search above.
        Reset-AdmSearchTruncated
        $subnetRows = @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential `
                        -Filter '(objectClass=subnet)' -SearchBase "CN=Subnets,$sitesDn" -SizeLimit 50000 `
                        -Properties @('cn', 'name', 'siteobject', 'location', 'description'))
        $subnetsTruncated = Get-AdmSearchTruncated

        # Servers live at CN=Servers,<site DN>; the object carrying dNSHostName is the server, and
        # a DC additionally has an nTDSDSA child. Counting servers per site is enough to answer
        # "is anything actually serving this site".
        Reset-AdmSearchTruncated
        $serverRows = @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential `
                        -Filter '(objectClass=server)' -SearchBase $sitesDn -SizeLimit 20000 `
                        -Properties @('cn', 'dnshostname', 'distinguishedname'))

        # Index the subnets and servers by their site DN once, rather than filtering the whole
        # list inside the per-site loop.
        $subnetsBySite = @{}
        foreach ($s in $subnetRows) {
            $siteDn = [string](Get-AdmRawProp $s 'siteobject')
            if (-not $siteDn) { continue }
            $k = $siteDn.ToLowerInvariant()
            if (-not $subnetsBySite.ContainsKey($k)) { $subnetsBySite[$k] = New-Object System.Collections.ArrayList }
            [void]$subnetsBySite[$k].Add([string](Get-AdmRawProp $s 'cn' (Get-AdmRawProp $s 'name')))
        }
        $serversTruncated = Get-AdmSearchTruncated
        $serversBySite = @{}
        foreach ($sv in $serverRows) {
            $dn = [string](Get-AdmRawProp $sv 'distinguishedname')
            # "CN=DC01,CN=Servers,CN=<site>,CN=Sites,..." -- the site is the third RDN up.
            if ($dn -match '^CN=[^,]+,CN=Servers,(CN=[^,]+,CN=Sites,.+)$') {
                $k = $Matches[1].ToLowerInvariant()
                if (-not $serversBySite.ContainsKey($k)) { $serversBySite[$k] = New-Object System.Collections.ArrayList }
                [void]$serversBySite[$k].Add([string](Get-AdmRawProp $sv 'cn'))
            }
        }

        foreach ($site in $siteRows) {
            $dn = [string](Get-AdmRawProp $site 'distinguishedname')
            $k = $dn.ToLowerInvariant()
            $subnets = @(if ($subnetsBySite.ContainsKey($k)) { $subnetsBySite[$k].ToArray() } else { @() })
            $servers = @(if ($serversBySite.ContainsKey($k)) { $serversBySite[$k].ToArray() } else { @() })
            [pscustomobject]@{
                Domain            = $ctx.Domain.Name
                Name              = Get-AdmRawProp $site 'name'
                DistinguishedName = $dn
                Description       = Get-AdmRawProp $site 'description'
                Subnets           = $subnets
                SubnetCount       = $subnets.Count
                Servers           = $servers
                ServerCount       = $servers.Count
                # ⭐ The two states worth seeing at a glance -- but ⛔ NoSubnets is $null, meaning
                # UNKNOWN, when the subnet read was truncated. If we could not see every subnet we
                # cannot say this site has none, and "unknown" is a distinct answer from "none"
                # exactly as it is in the scan.
                NoSubnets         = $(if ($subnetsTruncated) { $null } else { $subnets.Count -eq 0 })
                SubnetsTruncated  = $subnetsTruncated
                NoServers         = $(if ($serversTruncated) { $null } else { $servers.Count -eq 0 })
                ServersTruncated  = $serversTruncated
                WhenCreated       = Get-AdmRawProp $site 'whencreated'
                ObjectClass       = 'site'
            }
        }
    }
}

function Get-AdmSubnet {
    <#
    .SYNOPSIS
      Subnets and the site each maps to, including any that map to nothing. Read-only.
    .DESCRIPTION
      The subnet-centric view, and a different question from Get-AdmSite rather than a detail of
      it -- which is why it is a separate cmdlet.

      ⭐ IT CAN SHOW WHAT A SITE LISTING CANNOT. A subnet whose siteObject is empty belongs to no
      site, so it appears under no site anywhere and is invisible to any view that walks sites and
      lists their subnets. Clients in that range are assigned to no site and then pick a domain
      controller essentially at random. Orphaned is that case, named.

      ⚠ AN EMPTY RESULT HERE IS A REAL ANSWER. Plenty of forests define no subnets at all -- which
      is itself the finding, because it means site assignment is not working for anybody. Compare
      with Get-AdmSite, where an empty result is never right: every forest has at least
      Default-First-Site-Name, so zero sites means the read failed.

      ⛔ IT REFUSES TO RETURN A SHORT LIST QUIETLY. A DirectorySearcher stops at its size limit
      without saying so, and a truncated subnet list looks exactly like a complete one -- so a
      real estate, which has many subnets, would silently lose the tail and any "which subnet is
      missing a site" answer computed from it would be wrong. If the limit is reached this throws
      and tells you to raise -Limit, because a wrong answer here is worse than no answer.
    .EXAMPLE
      Get-AdmSubnet -Target corp.example.com
    .EXAMPLE
      Get-AdmSubnet -Target corp.example.com | Where-Object { $_.Orphaned }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Tier,
        # High by default: production forests really do have thousands, and the lab has none, so
        # the low default this started with could never have been shown to be wrong there.
        [int]$Limit = 50000,
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation 'list subnets' -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        if ((Get-AdmProviderName) -eq 'mock') { return @() }

        $configNc = Get-AdmNamingContext -Context $ctx -Name 'configurationNamingContext'
        if (-not $configNc) { throw "Could not read configurationNamingContext from the rootDSE of $($ctx.Domain.DnsDomain)." }

        $rows = @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential `
                    -Filter '(objectClass=subnet)' -SearchBase "CN=Subnets,CN=Sites,$configNc" -SizeLimit $Limit `
                    -Properties @('cn', 'name', 'siteobject', 'location', 'description', 'whencreated'))
        if (Get-AdmSearchTruncated) {
            throw "The subnet list was truncated at the size limit of $Limit, so any conclusion drawn from it -- including which subnets belong to no site -- would be wrong. Re-run with a higher -Limit."
        }
        foreach ($s in $rows) {
            $siteDn = [string](Get-AdmRawProp $s 'siteobject')
            [pscustomobject]@{
                Domain      = $ctx.Domain.Name
                Subnet      = Get-AdmRawProp $s 'cn' (Get-AdmRawProp $s 'name')
                Site        = $(if ($siteDn) { ($siteDn -replace '^CN=([^,]+).*$', '$1') } else { $null })
                SiteDn      = $siteDn
                Location    = Get-AdmRawProp $s 'location'
                Description = Get-AdmRawProp $s 'description'
                # Belongs to no site: clients in this range are assigned nowhere.
                Orphaned    = [string]::IsNullOrEmpty($siteDn)
                WhenCreated = Get-AdmRawProp $s 'whencreated'
                ObjectClass = 'subnet'
            }
        }
    }
}

# --- group policy -----------------------------------------------------------------------------

# groupPolicyContainer flags: which half of the GPO is switched off.
function ConvertFrom-AdmGpoStatus {
    <#
    .SYNOPSIS
      Name a groupPolicyContainer flags value -- which half of the GPO is switched off.
    #>
    [OutputType([string])]
    param($Value)
    $n = ConvertTo-AdmSignedFlag $Value
    switch ($n) {
        0 { 'AllSettingsEnabled' }
        1 { 'UserSettingsDisabled' }
        2 { 'ComputerSettingsDisabled' }
        3 { 'AllSettingsDisabled' }
        default { "Unknown ($n)" }
    }
}

function Get-AdmGpo {
    <#
    .SYNOPSIS
    Group Policy objects, where they are linked, and which are linked nowhere. Read-only.
    .DESCRIPTION
      Reads the groupPolicyContainer objects under CN=Policies,CN=System and then walks every
      container that can carry a gPLink -- the domain root, every OU, and every site -- to build
      the reverse map. No GPMC and no RSAT.

      ⭐ UNLINKED GPOs ARE THE POINT. A GPO linked nowhere applies to nobody, and estates
      accumulate them: superseded policies kept "just in case", half-finished ones, copies made
      before a change. They are indistinguishable from live policy in any list that does not do
      this join, which is why people are afraid to delete any of them.

      ⚠ A LINK CAN BE DISABLED, AND THAT STILL COUNTS AS A LINK. Enabled and Enforced are
      reported per link rather than collapsed, because a GPO whose only link is disabled is
      applying nothing while looking linked.

      ⛔ THIS DOES NOT COMPUTE RESULTANT POLICY. Which settings actually win for a given user on a
      given machine depends on link order, enforcement, block-inheritance, security filtering, WMI
      filters and loopback -- that is what gpresult on the target machine answers. This reports
      the links, honestly, and does not imply more.
    .EXAMPLE
      Get-AdmGpo -Target corp.example.com
    .EXAMPLE
      Get-AdmGpo -Target corp.example.com | Where-Object { $_.LinkCount -eq 0 }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Identity,
        [string]$Tier,
        # ⛔ A PARAMETER SO THE REFUSAL CAN BE TESTED. This was hardcoded, which made the most
        # important safety behaviour in this cmdlet unexercisable: no estate reachable from here
        # has 50000 gPLink-bearing containers, so the throw below had never run and could not be
        # made to run. A guard nobody can fire is a guard nobody knows works -- the same shape as
        # the `0 -ge 1500` check that sat in the privileged audit looking like protection.
        #
        # ⚠ Lower it deliberately to exercise the refusal, and derive the value from a live count
        # rather than typing one: a fixed small number only truncates depending on what the domain
        # happens to hold that minute, which is exactly how the delegation harness fooled itself.
        [int]$LinkLimit = 50000,
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation 'list group policy objects' -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup
        if ((Get-AdmProviderName) -eq 'mock') { return @() }

        $domainNc = ConvertTo-AdmDistinguishedName -DnsDomain $ctx.Domain.DnsDomain
        $configNc = Get-AdmNamingContext -Context $ctx -Name 'configurationNamingContext'

        $filter = if ($Identity) {
            $v = ConvertTo-AdmLdapFilterValue -Value $Identity
            "(&(objectClass=groupPolicyContainer)(|(displayName=*$v*)(cn=*$v*)))"
        } else { '(objectClass=groupPolicyContainer)' }

        $gpoRows = @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential `
                        -Filter $filter -SearchBase "CN=Policies,CN=System,$domainNc" -SizeLimit 20000 `
                        -Properties @('cn', 'displayname', 'distinguishedname', 'versionnumber',
                                      'flags', 'gpcfilesyspath', 'whencreated', 'whenchanged'))

        # --- build the reverse link map --------------------------------------------------------
        # Everything in the domain partition that carries a gPLink: the domain head and the OUs.
        #
        # ⛔ TRUNCATION HERE PRODUCES THE MOST DANGEROUS WRONG ANSWER IN THIS FILE. Every link this
        # read misses turns a LIVE policy into one reported as Unlinked -- and Unlinked is exactly
        # the filter someone uses to decide what is safe to delete. A short read would hand you a
        # list of in-force GPOs labelled as dead configuration. So the limit is high and reaching
        # it is a refusal, not a silent shrug.
        # ⭐ STICKY IS EXACTLY WHAT IS WANTED HERE. One reset before the first link search, one
        # check after the last, and EITHER of them being truncated is caught without tracking the
        # two separately -- which is the whole reason the flag does not clear on entry.
        $linkLimit = $LinkLimit
        Reset-AdmSearchTruncated
        $linkSources = @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential `
                            -Filter '(gPLink=*)' -SizeLimit $linkLimit `
                            -Properties @('distinguishedname', 'gplink', 'objectclass', 'gpoptions'))
        # Sites live in the configuration partition and are linked the same way. A site-linked GPO
        # invisible to a domain-only scan is exactly the kind of policy nobody can account for.
        if ($configNc) {
            $linkSources += @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential `
                                -Filter '(gPLink=*)' -SearchBase "CN=Sites,$configNc" -SizeLimit $linkLimit `
                                -Properties @('distinguishedname', 'gplink', 'objectclass', 'gpoptions'))
        }
        if (Get-AdmSearchTruncated) {
            throw "The Group Policy link scan was truncated at the size limit of $linkLimit. Every link it missed would make a LIVE policy report as Unlinked, which is the filter used to decide what is safe to delete -- so this refuses rather than answer wrongly."
        }

        $linksByGpo = @{}
        foreach ($src in $linkSources) {
            $srcDn = [string](Get-AdmRawProp $src 'distinguishedname')
            $classes = @(Get-AdmRawProp $src 'objectclass' @())
            $srcKind = if ($classes -contains 'organizationalUnit') { 'OU' }
                       elseif ($classes -contains 'site') { 'Site' }
                       elseif ($classes -contains 'domainDNS') { 'Domain' }
                       else { 'Other' }
            # gPOptions 1 on the container = block inheritance, which changes what actually
            # applies beneath it and is worth carrying on the link.
            $blocks = ([string](Get-AdmRawProp $src 'gpoptions' '0') -eq '1')
            $order = 0
            foreach ($link in @(ConvertFrom-AdmGpLink (Get-AdmRawProp $src 'gplink'))) {
                $order++
                $k = $link.GpoDn.ToLowerInvariant()
                if (-not $linksByGpo.ContainsKey($k)) { $linksByGpo[$k] = New-Object System.Collections.ArrayList }
                [void]$linksByGpo[$k].Add([pscustomobject]@{
                    Container         = $srcDn
                    ContainerKind     = $srcKind
                    Enabled           = $link.Enabled
                    Enforced          = $link.Enforced
                    Order             = $order
                    BlocksInheritance = $blocks
                })
            }
        }

        foreach ($g in $gpoRows) {
            $dn = [string](Get-AdmRawProp $g 'distinguishedname')
            $k = $dn.ToLowerInvariant()
            $links = @(if ($linksByGpo.ContainsKey($k)) { $linksByGpo[$k].ToArray() } else { @() })
            $activeLinks = @($links | Where-Object { $_.Enabled })
            [pscustomobject]@{
                Domain            = $ctx.Domain.Name
                DisplayName       = Get-AdmRawProp $g 'displayname'
                Id                = Get-AdmRawProp $g 'cn'
                DistinguishedName = $dn
                Status            = ConvertFrom-AdmGpoStatus (Get-AdmRawProp $g 'flags')
                VersionNumber     = Get-AdmRawProp $g 'versionnumber'
                SysvolPath        = Get-AdmRawProp $g 'gpcfilesyspath'
                Links             = $links
                LinkCount         = $links.Count
                EnabledLinkCount  = $activeLinks.Count
                # ⭐ The two cleanup cases, named so they can be filtered on directly.
                Unlinked          = ($links.Count -eq 0)
                LinkedButInactive = (($links.Count -gt 0) -and ($activeLinks.Count -eq 0))
                WhenCreated       = Get-AdmRawProp $g 'whencreated'
                WhenChanged       = Get-AdmRawProp $g 'whenchanged'
                ObjectClass       = 'groupPolicyContainer'
            }
        }
    }
}
