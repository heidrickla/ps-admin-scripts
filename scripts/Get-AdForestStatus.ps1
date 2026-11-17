<#
.SYNOPSIS
  Who holds which FSMO role, what the functional levels are, and whether replication is healthy.

.DESCRIPTION
  Reads everything it can over PLAIN LDAP through ADAdmin, so it works from a machine that is not
  joined to the target forest and has no RSAT installed -- which is the whole point of this
  toolkit. FSMO ownership and functional levels are ordinary directory attributes; nothing about
  reading them needs Microsoft's AD module.

  Replication is the one part LDAP cannot fully answer, and this script is explicit about that
  rather than quietly reporting less than it looked at:

    ALWAYS   every domain controller is contacted directly and asked for its own rootDSE. A DC
             that does not answer is the most common cause of a replication backlog, and this
             finds it from anywhere.
    IF PRESENT  repadmin.exe is parsed for real per-partner failure counts. When repadmin is not
             available the replication rows say 'unknown', never 'ok'.

  Everything here is a READ. Nothing is changed.

.PARAMETER Target
  A hostname, FQDN, UPN or NetBIOS name. ADAdmin resolves it to the right forest and uses that
  forest's stored credential.

.PARAMETER Tier
  Credential tier. Defaults to the domain's default (normally 'read'), because nothing here writes.

.EXAMPLE
  .\Get-AdForestStatus.ps1 -Target corp.example.com

.EXAMPLE
  .\Get-AdForestStatus.ps1 -Target corp.example.com | Where-Object State -ne 'ok'

.OUTPUTS
  One object per fact: Category, Item, Value, State, Detail.
  Category is FSMO / FunctionalLevel / DomainController / Replication.
  State is ok / info / warn / fail / unknown -- and 'unknown' is used wherever this script could
  not look, which is never the same thing as 'fine'.

.NOTES
  EXIT CODES
    0   nothing wrong found
    20  at least one fail (a DC that would not answer, or a failing replication link)
    30  nothing failed, but something could not be checked
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Target,
    [string]$Tier
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# ⚠ NOT `-Force`. A forced import creates a FRESH module instance, and the unlocked store lives in
# module scope -- so force-importing here silently re-locks the caller's session and this script
# then fails with "The credential store is locked" about a store the caller had just unlocked.
# Import only if it is not already loaded.
if (-not (Get-Module ADAdmin)) {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'ADAdmin\ADAdmin.psd1')
}

# Functional levels are msDS-Behavior-Version numbers. Only the values Microsoft has actually
# defined are named; anything else is reported as unknown WITH its number rather than guessed at,
# because a wrong level here would be read as a real constraint on an upgrade decision.
$LevelNames = @{
    0 = 'Windows 2000'
    1 = 'Windows Server 2003 interim'
    2 = 'Windows Server 2003'
    3 = 'Windows Server 2008'
    4 = 'Windows Server 2008 R2'
    5 = 'Windows Server 2012'
    6 = 'Windows Server 2012 R2'
    7 = 'Windows Server 2016'
    10 = 'Windows Server 2025'
}
# Server 2019 and 2022 introduced NO new functional level -- they run at 7. A report that invents
# "Windows Server 2019" for level 7 would be confidently wrong.

function Get-LevelName {
    param($Value)
    $n = -1
    if ($null -ne $Value -and [int]::TryParse([string]$Value, [ref]$n) -and $LevelNames.ContainsKey($n)) {
        "$($LevelNames[$n])  (level $n)"
    } elseif ($n -ge 0) {
        "unknown functional level $n"
    } else {
        'not reported'
    }
}

function Get-EntryProp {
    param($Entry, [string]$Name)
    try {
        $p = $Entry.Properties[$Name]
        if ($null -eq $p) { return $null }
        $v = $p.Value
        if ($null -eq $v) { return $null }
        [string]$v
    } catch { $null }
}

# "CN=NTDS Settings,CN=DC01,CN=Servers,CN=Site,..." -> "DC01". The role owner is always the NTDS
# Settings object, so the server is the second RDN.
function ConvertFrom-FsmoOwnerDn {
    param([string]$Dn)
    if (-not $Dn) { return $null }
    $parts = $Dn -split '(?<!\\),'
    if ($parts.Count -ge 2 -and $parts[1] -match '^CN=(.+)$') { return $Matches[1] }
    $Dn
}

$rows = @()
function Add-Row {
    param([string]$Category, [string]$Item, $Value, [string]$State = 'info', [string]$Detail = '')
    $script:rows += [pscustomobject]@{
        Category = $Category; Item = $Item; Value = $Value; State = $State; Detail = $Detail
    }
}

# --- connect ---------------------------------------------------------------------------------

$ctx = Get-AdmTargetContextPublic -Target $Target -Tier $Tier
$domain = $ctx.Domain

$root = New-AdmDirectoryEntry -Domain $domain -Credential $ctx.Credential -DistinguishedName 'RootDSE'
try {
    # Force the bind here so a connection failure is diagnosed as one, rather than surfacing later
    # as a missing attribute that looks like a directory problem.
    $root.RefreshCache()

    $defaultNC = Get-EntryProp $root 'defaultNamingContext'
    $configNC  = Get-EntryProp $root 'configurationNamingContext'
    $schemaNC  = Get-EntryProp $root 'schemaNamingContext'

    Add-Row 'FunctionalLevel' 'Forest'            (Get-LevelName (Get-EntryProp $root 'forestFunctionality'))
    Add-Row 'FunctionalLevel' 'Domain'            (Get-LevelName (Get-EntryProp $root 'domainFunctionality'))
    # Remember WHICH DC answered. It is provably reachable -- we are reading from it -- so it must
    # never be reported as unreachable later just because its name does not resolve here.
    $connectedDc = Get-EntryProp $root 'dnsHostName'

    Add-Row 'FunctionalLevel' 'This DC'           (Get-LevelName (Get-EntryProp $root 'domainControllerFunctionality')) 'info' `
        "as reported by $connectedDc"
} finally { Close-AdmDirectoryEntry $root }

# --- FSMO ------------------------------------------------------------------------------------
# All five owners are the fSMORoleOwner attribute on a well-known object. No RSAT, no WMI.

$fsmo = [ordered]@{
    'Schema Master'         = $schemaNC
    'Domain Naming Master'  = "CN=Partitions,$configNC"
    'PDC Emulator'          = $defaultNC
    'RID Master'            = "CN=RID Manager`$,CN=System,$defaultNC"
    'Infrastructure Master' = "CN=Infrastructure,$defaultNC"
}

foreach ($role in $fsmo.Keys) {
    $dn = $fsmo[$role]
    $e = $null
    try {
        $e = New-AdmDirectoryEntry -Domain $domain -Credential $ctx.Credential -DistinguishedName $dn
        $e.RefreshCache()
        $owner = ConvertFrom-FsmoOwnerDn (Get-EntryProp $e 'fSMORoleOwner')
        if ($owner) { Add-Row 'FSMO' $role $owner 'ok' $dn }
        else { Add-Row 'FSMO' $role $null 'unknown' "no fSMORoleOwner on $dn" }
    } catch {
        Add-Row 'FSMO' $role $null 'unknown' "could not read $dn -- $($_.Exception.Message)"
    } finally { Close-AdmDirectoryEntry $e }
}

# --- domain controllers ------------------------------------------------------------------------
# Every DC has an nTDSDSA object under CN=Sites in the configuration partition. Its PARENT is the
# server object carrying dNSHostName, so one search over the server objects gets the inventory.

$dcs = @()
try {
    $servers = @(Invoke-AdmAdsiSearch -Domain $domain -Credential $ctx.Credential `
                    -Filter '(objectClass=nTDSDSA)' -SearchBase "CN=Sites,$configNC" `
                    -Properties @('distinguishedname', 'msds-behavior-version') -SizeLimit 200)
    foreach ($s in $servers) {
        $ntdsDn = [string](Get-AdmRawProp $s 'distinguishedname')
        if (-not $ntdsDn) { continue }
        $serverDn = ($ntdsDn -split '(?<!\\),', 2)[1]     # strip "CN=NTDS Settings,"
        $se = $null
        try {
            $se = New-AdmDirectoryEntry -Domain $domain -Credential $ctx.Credential -DistinguishedName $serverDn
            $se.RefreshCache()
            $dcs += [pscustomobject]@{
                Name = Get-EntryProp $se 'cn'
                Dns  = Get-EntryProp $se 'dNSHostName'
                Site = if ($serverDn -match 'CN=Servers,CN=([^,]+),CN=Sites') { $Matches[1] } else { '' }
            }
        } catch {
            Add-Row 'DomainController' $serverDn $null 'unknown' "could not read the server object -- $($_.Exception.Message)"
        } finally { Close-AdmDirectoryEntry $se }
    }
} catch {
    Add-Row 'DomainController' '(inventory)' $null 'unknown' "could not enumerate domain controllers -- $($_.Exception.Message)"
}

# Ask each DC for its OWN rootDSE. A DC that does not answer is the single most common reason a
# replication partner falls behind, and this catches it without repadmin and from off-domain.
foreach ($dc in $dcs) {

    # The DC we are already connected to is answering by definition. Probing it again by a name
    # this machine may not resolve would report the DC we are reading from as unreachable.
    if ($connectedDc -and $dc.Dns -and $dc.Dns -eq $connectedDc) {
        Add-Row 'DomainController' $dc.Name $dc.Dns 'ok' "site $($dc.Site); answering -- this report was read from it"
        continue
    }

    $host_ = if ($dc.Dns) { $dc.Dns } else { $dc.Name }

    # ⛔ "its name does not resolve from here" is NOT "the DC is down". Outside the forest, the
    # forest's own DNS is usually the only thing that knows these names, so calling that a failure
    # would report a healthy estate as broken every time this runs from a non-joined machine.
    $resolves = $false
    try { $null = [System.Net.Dns]::GetHostAddresses($host_); $resolves = $true }
    catch {
        # Deliberate: failing to resolve IS the answer here, and $resolves carries it. There is
        # nothing to log -- the row written below says exactly what happened and why it is not
        # a fault.
    }
    if (-not $resolves) {
        Add-Row 'DomainController' $dc.Name $dc.Dns 'unknown' `
            ("site $($dc.Site); '$host_' does not resolve from this machine, so it could not be " +
             "probed. That is normal off-domain -- it says nothing about the DC's health. Pin it " +
             "in the domain profile's Hosts list, or run this from inside the forest, to include it.")
        continue
    }

    $probe = $domain.PSObject.Copy()
    $probe.DomainControllers = @($host_)
    $e = $null
    try {
        $e = New-AdmDirectoryEntry -Domain $probe -Credential $ctx.Credential -DistinguishedName 'RootDSE'
        $e.RefreshCache()
        $usn = Get-EntryProp $e 'highestCommittedUSN'
        Add-Row 'DomainController' $dc.Name $dc.Dns 'ok' "site $($dc.Site); answering, highestCommittedUSN $usn"
    } catch {
        Add-Row 'DomainController' $dc.Name $dc.Dns 'fail' "site $($dc.Site); DID NOT ANSWER -- $($_.Exception.Message)"
    } finally { Close-AdmDirectoryEntry $e }
}

# --- replication --------------------------------------------------------------------------------

$repadmin = Get-Command repadmin.exe -ErrorAction SilentlyContinue

if (-not $repadmin) {
    Add-Row 'Replication' '(all partners)' $null 'unknown' `
        ('repadmin.exe is not on this machine, so per-partner replication failures could not be read. ' +
         'The domain controller rows above still show which DCs are answering at all. Run this on a ' +
         'domain controller or an RSAT-equipped admin host for full replication detail.')
}
else {
    try {
        # /csv is the machine-readable form and is stable across Windows versions.
        # Give it the DC we are already talking to as the home server: without one, repadmin tries
        # to work out "our domain" from THIS machine, which fails immediately when this machine is
        # not joined to the target forest.
        $csv = if ($connectedDc) {
            & $repadmin.Source /showrepl "/homeserver:$connectedDc" '*' /csv 2>&1
        } else {
            & $repadmin.Source /showrepl '*' /csv 2>&1
        }
        $parsed = @($csv | Where-Object { $_ -match ',' } | ConvertFrom-Csv -ErrorAction SilentlyContinue)
        if (-not $parsed.Count) {
            # Say why, not just that. repadmin authenticates as the CALLER's Windows identity and
            # has no way to take the credential out of the store -- so from a machine outside the
            # forest it cannot work at all, however it is invoked. Sending someone to try
            # /homeserver (which repadmin's own error suggests) wastes their time here.
            Add-Row 'Replication' '(all partners)' $null 'unknown' `
                ('repadmin produced nothing parseable. It authenticates as the Windows identity ' +
                 'running it and cannot use this toolkit''s stored credential, so from a machine ' +
                 'outside the target forest it cannot report replication at all. Run this on a ' +
                 'domain controller, or from a machine signed in to that forest. The domain ' +
                 'controller rows above are still a real reachability check and do not depend on it.')
        }
        foreach ($r in $parsed) {
            $fails = 0
            [void][int]::TryParse([string](Get-AdmRawProp $r 'Number of Failures'), [ref]$fails)
            $src = Get-AdmRawProp $r 'Source DSA'
            $dst = Get-AdmRawProp $r 'Destination DSA'
            $nc  = Get-AdmRawProp $r 'Naming Context'
            $last = Get-AdmRawProp $r 'Last Failure Time'
            $state = if ($fails -gt 0) { 'fail' } else { 'ok' }
            $detail = if ($fails -gt 0) { "$fails failure(s), last at $last" } else { "partition $nc" }
            Add-Row 'Replication' "$src -> $dst" $nc $state $detail
        }
    } catch {
        Add-Row 'Replication' '(all partners)' $null 'unknown' "repadmin could not be run -- $($_.Exception.Message)"
    }
}

# --- output and verdict --------------------------------------------------------------------------

$rows

$failed  = @($rows | Where-Object { $_.State -eq 'fail' })
$unknown = @($rows | Where-Object { $_.State -eq 'unknown' })

if ($failed.Count) {
    Write-Warning ("$($failed.Count) problem(s): " + (($failed | ForEach-Object { "$($_.Category)/$($_.Item)" }) -join ', '))
    exit 20
}
if ($unknown.Count) {
    Write-Warning ("$($unknown.Count) thing(s) could not be checked -- that is not the same as healthy: " +
                   (($unknown | ForEach-Object { "$($_.Category)/$($_.Item)" }) -join ', '))
    exit 30
}
exit 0
