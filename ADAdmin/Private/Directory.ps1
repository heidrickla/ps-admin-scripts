# Directory.ps1 -- the seam between the toolkit and an actual directory.
#
# TWO PROVIDERS behind one interface:
#   adsi  -- System.DirectoryServices against a real DC. The production path.
#   mock  -- a JSON fixture. Not a toy: it is how the CLI, the GUI and the tests are exercised
#            on a workstation that cannot reach production, which is most days.
#
# ⚠ THE ADSI PATH IS UNVERIFIED AGAINST A LIVE FOREST as of 2026-08-26 -- the dev environment
# has no reachable production domain. The shapes below are written from the documented APIs;
# treat the first real run as the verification, and fix here rather than working around it
# at the call site.

# Declared up front: Set-StrictMode 2.0 treats a reference to a never-assigned variable as an
# error, so every module-scope slot has to exist before anything reads it.
$script:AdmProviderOverride = $null
$script:AdmMockData         = $null
$script:AdmRsatPresent      = $null

function Get-AdmProviderName {
    [OutputType([string])]
    param()
    if ($script:AdmProviderOverride) { return $script:AdmProviderOverride }
    if ($env:ADADMIN_PROVIDER) { return $env:ADADMIN_PROVIDER.ToLowerInvariant() }
    'adsi'
}

function Set-AdmProviderName {
    param([ValidateSet('adsi', 'mock')][string]$Name)
    $script:AdmProviderOverride = $Name
}

function ConvertTo-AdmDistinguishedName {
    <#
    .SYNOPSIS
      Turn a DNS domain name into its distinguished name (corp.example.com -> DC=corp,DC=example,DC=com).
    #>
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$DnsDomain)
    (($DnsDomain.TrimEnd('.') -split '\.') | ForEach-Object { "DC=$_" }) -join ','
}

# Escape a value going into an LDAP filter (RFC 4515). Skipping this is an injection bug:
# a display name containing ')(' rewrites the filter.
function ConvertTo-AdmLdapFilterValue {
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        switch ($ch) {
            '\' { [void]$sb.Append('\5c') }
            '*' { [void]$sb.Append('\2a') }
            '(' { [void]$sb.Append('\28') }
            ')' { [void]$sb.Append('\29') }
            "`0" { [void]$sb.Append('\00') }
            '/' { [void]$sb.Append('\2f') }
            default { [void]$sb.Append($ch) }
        }
    }
    $sb.ToString()
}

function Get-AdmLdapServer {
    param([Parameter(Mandatory)]$Domain)
    $dc = @($Domain.DomainControllers) | Where-Object { $_ } | Select-Object -First 1
    if ($dc) { $dc } else { $Domain.DnsDomain }
}

# --- adsi provider --------------------------------------------------------------------------

function New-AdmDirectoryEntry {
    <#
    .SYNOPSIS
      Bind to a domain over LDAP with a stored credential. Close it with Close-AdmDirectoryEntry.
    .DESCRIPTION
      Authenticates with Negotiate, which is what makes an explicit credential work across forests
      with no trust, and adds sealing and signing when not already inside TLS.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Domain,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$Credential,
        [string]$DistinguishedName
    )
    Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
    $server = Get-AdmLdapServer -Domain $Domain
    $base = if ($DistinguishedName) { $DistinguishedName } else { ConvertTo-AdmDistinguishedName -DnsDomain $Domain.DnsDomain }
    $port = if ($Domain.Port) { $Domain.Port } else { if ($Domain.UseSsl) { 636 } else { 389 } }
    $path = "LDAP://${server}:${port}/$base"

    # Secure = Negotiate, which is what makes an explicit credential work across forests with
    # no trust. Sealing+Signing protect the channel when we are not already inside TLS.
    $auth = [System.DirectoryServices.AuthenticationTypes]::Secure
    if ($Domain.UseSsl) {
        $auth = $auth -bor [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer
    } else {
        $auth = $auth -bor [System.DirectoryServices.AuthenticationTypes]::Sealing `
                      -bor [System.DirectoryServices.AuthenticationTypes]::Signing
    }

    $plain = ConvertFrom-AdmSecureString -Secure $Credential.Password
    try {
        New-Object System.DirectoryServices.DirectoryEntry($path, $Credential.UserName, $plain, $auth)
    } finally { $plain = $null }
}

# Disposing a DirectoryEntry whose bind FAILED throws again -- ADSI binds lazily, so even
# touching `.Dispose` re-triggers the connection and raises "The server is not operational".
# In a finally block that exception REPLACES the real one, and the operator is shown a message
# about Dispose instead of about the domain controller. Measured against a lab domain controller, 2026-08-27.
function Close-AdmDirectoryEntry {
    <#
    .SYNOPSIS
      Dispose a DirectoryEntry safely, swallowing the second failure.
    .DESCRIPTION
      Dispose() on an entry whose bind FAILED throws again, and that second exception replaces the
      real one -- so the caller is told about disposal instead of about the bind. Always close
      through this.
    #>
    param($Entry)
    if ($null -eq $Entry) { return }
    try { $Entry.Dispose() } catch { }
}

# Set a password over the LDAP connection we already have.
#
# ⛔ NOT `Invoke('SetPassword')`. ADSI's SetPassword tries LDAP-over-TLS, then falls back to
# RPC on 135/445 -- and on a plain (even sealed) LDAP connection it takes the RPC path. From the
# kind of machine this toolkit runs on, RPC to a domain controller is routinely blocked, so it
# fails with "The RPC server is unavailable (0x800706BA)" -- an error that says nothing about
# passwords and sends people to check the DC. Measured against a lab domain controller, 2026-08-27.
#
# `unicodePwd` is a plain LDAP attribute write and needs no RPC at all. It requires an ENCRYPTED
# channel, which every connection this module makes already has: SSL on 636, or Sealing on 389.
# The value is the password wrapped in double quotes, UTF-16LE encoded.
function Set-AdmEntryPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Entry,
        [Parameter(Mandatory)][string]$Plain
    )
    $bytes = [System.Text.Encoding]::Unicode.GetBytes('"' + $Plain + '"')
    try {
        try {
            $Entry.Properties['unicodePwd'].Value = $bytes
            $Entry.CommitChanges()
            return 'unicodePwd'
        } catch {
            $primary = $_
            # Last resort for a directory that refuses the attribute write. If this also fails,
            # report the FIRST error: it is the one about the path we actually intend to use.
            try {
                [void]$Entry.Invoke('SetPassword', $Plain)
                $Entry.CommitChanges()
                return 'SetPassword'
            } catch {
                $second = $_
                throw (New-Object System.Exception(
                    ("Could not set the password. Writing unicodePwd over LDAP failed with: " +
                     "$($primary.Exception.Message) -- and the SetPassword fallback failed with: " +
                     "$($second.Exception.Message)"), $primary.Exception))
            }
        }
    } finally { Clear-AdmBytes -Bytes $bytes }
}

# ⛔ A SEARCH THAT HITS ITS SIZE LIMIT RETURNS ROWS AND NO COMPLAINT. DirectorySearcher stops at
# SizeLimit silently: you get exactly N objects and nothing anywhere says there were N+900 more.
# Every wrong answer this toolkit has produced from a real estate has that shape -- "this site has
# no subnets", "this GPO is linked nowhere", "this OU contains 40 objects, delete it". None of
# them are display bugs. They are conclusions DERIVED from a partial read, and they are worse than
# an error because they look like answers.
#
# So the searchers ask the directory for ONE MORE ROW THAN THEY WILL RETURN. If that extra row
# arrives, the limit was reached rather than merely met, and $script:AdmLastSearchTruncated says
# so. `$rows.Count -ge $limit` -- which is what call sites were doing by hand -- CANNOT tell
# "exactly $limit objects exist" from "truncated", and only fires at call sites somebody
# remembered to write it at.
#
# ⛔ THE FLAG IS STICKY AND ONLY THE CALLER CLEARS IT. Reset, call, ask:
#
#     Reset-AdmSearchTruncated
#     $rows = @(Get-AdmGroupMember -Target x -Identity y)
#     if (Get-AdmSearchTruncated) { <$rows.Count is a FLOOR> }
#
# It has to work this way because a public cmdlet runs SEVERAL searches -- Get-AdmGroupMember
# resolves the group, then reads members, then reads primary-group members. Had the searchers
# cleared the flag on entry, a truncated member read followed by a one-row SID lookup would
# report NOT truncated, which is the exact failure this exists to prevent. Sticky errs towards
# warning when it need not; that is the correct direction for this.
$script:AdmLastSearchTruncated = $false

function Reset-AdmSearchTruncated {
    <#
    .SYNOPSIS
      Clear the truncation flag before a read you intend to check.
    #>
    [CmdletBinding()]
    param()
    $script:AdmLastSearchTruncated = $false
}

function Get-AdmSearchTruncated {
    <#
    .SYNOPSIS
      Did any directory search since the last reset stop at its size limit?
    .DESCRIPTION
      $true means rows were dropped, so any count, "none found" or "not linked anywhere" derived
      from that read is a FLOOR rather than the answer. Call Reset-AdmSearchTruncated first --
      the flag is sticky and spans every search in between. A size limit of 0 means the server's
      own limit applies and truncation cannot be detected, so this stays $false.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    [bool]$script:AdmLastSearchTruncated
}

function Invoke-AdmAdsiSearch {
    <#
    .SYNOPSIS
      Run an LDAP search against a domain and return raw attribute bags.
    .DESCRIPTION
      Results are RAW: attribute names are lowercase LDAP names, unset attributes are ABSENT, and
      binary values arrive as Object[] of Byte. Read them with Get-AdmRawProp and convert SIDs
      with ConvertTo-AdmSidString.

      At most SizeLimit rows are returned. If the directory held more, Get-AdmSearchTruncated
      returns $true afterwards.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Domain,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory)][string]$Filter,
        [string[]]$Properties = @(),
        [string]$SearchBase,
        # OneLevel is what a BROWSER wants: the objects directly in this container, not everything
        # beneath it. Subtree stays the default so every existing caller is unaffected.
        [ValidateSet('Subtree', 'OneLevel', 'Base')][string]$Scope = 'Subtree',
        [int]$SizeLimit = 200
    )
    $root = New-AdmDirectoryEntry -Domain $Domain -Credential $Credential -DistinguishedName $SearchBase
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
        try {
            $searcher.Filter = $Filter
            $searcher.SizeLimit = Get-AdmOverfetchLimit $SizeLimit
            $searcher.PageSize = 500
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::$Scope
            foreach ($p in $Properties) { [void]$searcher.PropertiesToLoad.Add($p) }
            $results = $searcher.FindAll()
            try {
                $n = 0
                foreach ($r in $results) {
                    $n++
                    if ($SizeLimit -gt 0 -and $n -gt $SizeLimit) {
                        $script:AdmLastSearchTruncated = $true
                        Write-Warning ("The directory holds more than $SizeLimit objects matching this search. " +
                                       'Only that many were read, so any count or "none found" from this is a floor, not the total.')
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

# One row past what the caller will be given, so arrival of that row IS the truncation signal.
# 0 means "server's own limit" to DirectorySearcher and cannot be over-fetched; MaxValue would
# overflow to negative, which DirectorySearcher rejects outright.
function Get-AdmOverfetchLimit {
    param([int]$SizeLimit)
    if ($SizeLimit -le 0 -or $SizeLimit -eq [int]::MaxValue) { return $SizeLimit }
    $SizeLimit + 1
}

# --- mock provider --------------------------------------------------------------------------

function Get-AdmMockData {
    if ($script:AdmMockData) { return $script:AdmMockData }
    $path = if ($env:ADADMIN_MOCK_DATA) { $env:ADADMIN_MOCK_DATA }
            else { Join-Path $script:AdmModuleRoot 'Fixtures\mock-directory.json' }
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Mock provider selected but no fixture at '$path'. Set ADADMIN_MOCK_DATA."
    }
    $script:AdmMockData = [System.IO.File]::ReadAllText($path, (Get-AdmUtf8Encoding)) | ConvertFrom-Json
    $script:AdmMockData
}

function Clear-AdmMockData { $script:AdmMockData = $null }

function Invoke-AdmMockSearch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Domain,
        [Parameter(Mandatory)][string]$ObjectClass,
        [string]$Identity,
        [int]$SizeLimit = 200
    )
    $data = Get-AdmMockData
    $bucket = @($data.domains) | Where-Object { $_.dnsDomain -eq $Domain.DnsDomain } | Select-Object -First 1
    if (-not $bucket) { return @() }
    $items = @($bucket.$ObjectClass)
    if ($Identity) {
        $needle = $Identity.Trim('*').ToLowerInvariant()
        # ⚠ VIA Get-AdmRawProp, NOT `$_.samAccountName`. Computer entries in the fixture have no
        # samAccountName at all, and under Set-StrictMode 2.0 reading a missing property throws --
        # so `Get-AdmComputer -Identity <name>` failed on the mock path with "The property
        # 'samAccountName' cannot be found on this object". Same lesson as a real directory
        # omitting unset attributes: treat every property as optional, fixtures included.
        $items = @($items | Where-Object {
            $sam = [string](Get-AdmRawProp $_ 'samAccountName')
            $nm  = [string](Get-AdmRawProp $_ 'name')
            $upn = [string](Get-AdmRawProp $_ 'userPrincipalName')
            ($sam -and $sam.ToLowerInvariant().Contains($needle)) -or
            ($nm  -and $nm.ToLowerInvariant().Contains($needle))  -or
            ($upn -and $upn.ToLowerInvariant().Contains($needle))
        })
    }
    # The mock reports truncation the same way the directory does, so a test can prove the
    # "this is a floor, not the total" path without a domain controller.
    # Only ever set, never cleared -- the flag is sticky and the caller owns the reset.
    if ($SizeLimit -gt 0 -and @($items).Count -gt $SizeLimit) { $script:AdmLastSearchTruncated = $true }
    if ($SizeLimit -gt 0) { $items | Select-Object -First $SizeLimit } else { $items }
}

# Mock writes mutate the in-memory fixture only. They are visible for the rest of the session
# and never touch the fixture file -- a demo must not be able to look like a change that
# persisted, because that is indistinguishable from having really worked.
function Invoke-AdmMockModify {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Domain,
        [Parameter(Mandatory)][string]$ObjectClass,
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][hashtable]$Set
    )
    $found = @(Invoke-AdmMockSearch -Domain $Domain -ObjectClass $ObjectClass -Identity $Identity)
    if (-not $found) { throw "Mock: no $ObjectClass matching '$Identity' in $($Domain.DnsDomain)." }
    $obj = $found[0]
    foreach ($k in $Set.Keys) {
        if ($obj.PSObject.Properties[$k]) { $obj.$k = $Set[$k] }
        else { $obj | Add-Member -NotePropertyName $k -NotePropertyValue $Set[$k] -Force }
    }
    $obj
}

# --- RSAT (opportunistic) ---------------------------------------------------------------------

function Test-AdmRsat {
    [OutputType([bool])]
    param()
    if ($null -ne $script:AdmRsatPresent) { return $script:AdmRsatPresent }
    $script:AdmRsatPresent = [bool](Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue)
    $script:AdmRsatPresent
}
