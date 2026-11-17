# Public/Domains.ps1 -- the domain registry and the target->domain resolver.

function Register-AdmDomain {
    <#
    .SYNOPSIS
      Add or update a domain profile in the store.
    .EXAMPLE
      Register-AdmDomain -Name corp -DnsDomain corp.example.com -NetbiosName CORP `
                         -DomainControllers dc01.corp.example.com
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$DnsDomain,
        [string]$NetbiosName,
        [string[]]$Aliases = @(),
        [string[]]$Hosts = @(),
        [string[]]$DomainControllers = @(),
        [int]$Port = 0,
        [bool]$UseSsl = $true,
        [switch]$Force
    )
    $s = Get-AdmSession
    $existing = @($s.Data.domains) | Where-Object { $_.Name -eq $Name }
    if ($existing -and -not $Force) {
        throw "A domain named '$Name' is already registered. Use -Force to overwrite it (its stored credentials are kept)."
    }
    if (-not $PSCmdlet.ShouldProcess($Name, 'Register domain')) { return }

    $rec = New-AdmDomainRecord -Name $Name -DnsDomain $DnsDomain -NetbiosName $NetbiosName `
        -Aliases $Aliases -Hosts $Hosts -DomainControllers $DomainControllers -Port $Port -UseSsl $UseSsl
    if ($existing) {
        # Overwriting the profile must not silently discard credentials -- that would look like
        # an edit and behave like a deletion.
        $rec.Credentials = $existing.Credentials
        $rec.DefaultCredential = $existing.DefaultCredential
        $s.Data.domains = @(@($s.Data.domains) | Where-Object { $_.Name -ne $Name }) + $rec
    } else {
        $s.Data.domains = @($s.Data.domains) + $rec
    }
    Save-AdmSession
    $rec
}

function Unregister-AdmDomain {
    <#
    .SYNOPSIS
      Remove a domain profile AND every credential stored for it. Nothing in the domain changes.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string]$Name)
    $s = Get-AdmSession
    $remaining = @($s.Data.domains | Where-Object { $_.Name -ne $Name })
    if ($remaining.Count -eq @($s.Data.domains).Count) { throw "No domain named '$Name'." }
    if (-not $PSCmdlet.ShouldProcess($Name, 'Remove domain and its stored credentials')) { return }
    $s.Data.domains = $remaining
    Save-AdmSession
    [pscustomobject]@{ Removed = $Name }
}

function Get-AdmDomain {
    <#
    .SYNOPSIS
      List registered domains. Credentials are reported by tier NAME only, never value.
    #>
    [CmdletBinding()]
    param([string]$Name)
    $s = Get-AdmSession
    $items = @($s.Data.domains)
    if ($Name) { $items = @($items | Where-Object { $_.Name -eq $Name }) }
    foreach ($d in $items) {
        [pscustomobject]@{
            Name              = $d.Name
            DnsDomain         = $d.DnsDomain
            NetbiosName       = $d.NetbiosName
            Aliases           = @($d.Aliases)
            Hosts             = @($d.Hosts)
            DomainControllers = @($d.DomainControllers)
            Port              = $d.Port
            UseSsl            = $d.UseSsl
            # ForEach-Object, not `.Properties.Name`: member enumeration over an EMPTY property
            # collection throws under Set-StrictMode 2.0, so a domain with no credentials yet --
            # i.e. every domain the moment it is registered -- would fail to list.
            CredentialTiers   = @($d.Credentials.PSObject.Properties | ForEach-Object { $_.Name })
            DefaultCredential = $d.DefaultCredential
        }
    }
}

function Export-AdmDomainProfile {
    <#
    .SYNOPSIS
      Write the registered domain profiles to a file, so they can be carried to another copy.
    .DESCRIPTION
      The domain registry is the part of the store that took real work to build -- twenty
      forests, their controllers, their aliases and the hostname suffixes that route to each. It
      is configuration, not secrets, and this moves it: to a new version of the toolkit, to a
      second admin's stick, or into a rebuild.

      ⛔ CREDENTIALS ARE NOT EXPORTED, AND THIS IS NOT AN OVERSIGHT. Each one is sealed with a data
      key that is itself wrapped per admin passphrase; a file that carried them would either be
      useless on the far side or would be the credentials in the clear. The whole store file is
      already a single portable file if you want to move everything -- copy that instead, and
      keep the passphrase. What this produces is safe to email, commit or hand over.
    .EXAMPLE
      Export-AdmDomainProfile -Path .\domains.json
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    # Built from Get-AdmDomain rather than the raw session, so the export cannot disagree with
    # what the UI shows -- and because that helper already reports credentials by TIER NAME only,
    # never by value, which is exactly what belongs in a portable file.
    $domains = @(Get-AdmDomain | ForEach-Object {
        [ordered]@{
            Name              = $_.Name
            DnsDomain         = $_.DnsDomain
            NetbiosName       = $_.NetbiosName
            Aliases           = @($_.Aliases)
            Hosts             = @($_.Hosts)
            DomainControllers = @($_.DomainControllers)
            Port              = $_.Port
            UseSsl            = $_.UseSsl
            # Names only, so the far side can see WHICH tiers to set up. No values.
            CredentialTiers   = @($_.CredentialTiers)
        }
    })

    $payload = [ordered]@{
        kind        = 'adadmin-domain-profiles'
        version     = 1
        exported    = (Get-Date).ToString('o')
        exportedBy  = "$env:USERDOMAIN\$env:USERNAME"
        note        = 'Domain profiles only. No credentials are present in this file.'
        domains     = $domains
    }
    Write-AdmFileAtomic -Path $Path -Content (($payload | ConvertTo-Json -Depth 8))
    [pscustomobject]@{ Path = $Path; Domains = $domains.Count; Credentials = 'not included' }
}

function Import-AdmDomainProfile {
    <#
    .SYNOPSIS
      Read domain profiles back in. Existing domains are left alone unless -Force.
    .DESCRIPTION
      Merges rather than replaces: a name already registered here is SKIPPED, so importing a
      colleague's file cannot quietly repoint one of your forests at their domain controller.
      -Force overwrites those, and even then the stored credentials of an existing domain are
      kept -- Register-AdmDomain is explicit about not discarding them.

      ⚠ EVERY IMPORTED DOMAIN ARRIVES WITH NO CREDENTIAL, because none were exported. Until one is
      set it will resolve and then fail to bind, which is the honest state rather than a
      half-working profile.
    .EXAMPLE
      Import-AdmDomainProfile -Path .\domains.json
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Force
    )
    if (-not (Test-Path -LiteralPath $Path)) { throw "No such file: $Path" }
    $raw = $null
    try { $raw = [System.IO.File]::ReadAllText($Path) | ConvertFrom-Json }
    catch { throw "That file is not readable as JSON: $($_.Exception.Message)" }

    $kind = Get-AdmRawProp $raw 'kind'
    if ($kind -ne 'adadmin-domain-profiles') {
        throw "That is not a domain profile export (kind='$kind'). Refusing to guess at its shape."
    }

    $existing = @{}
    foreach ($d in @(Get-AdmDomain)) { $existing[$d.Name] = $true }

    $added = @(); $skipped = @(); $replaced = @()
    foreach ($d in @(Get-AdmRawProp $raw 'domains' @())) {
        $name = [string](Get-AdmRawProp $d 'Name')
        $dns  = [string](Get-AdmRawProp $d 'DnsDomain')
        if (-not $name -or -not $dns) { continue }

        if ($existing.ContainsKey($name) -and -not $Force) { $skipped += $name; continue }
        if (-not $PSCmdlet.ShouldProcess($name, 'Import domain profile')) { continue }

        $useSsl = Get-AdmRawProp $d 'UseSsl' $true
        $port = 0; [void][int]::TryParse([string](Get-AdmRawProp $d 'Port' 0), [ref]$port)

        Register-AdmDomain -Name $name -DnsDomain $dns `
            -NetbiosName ([string](Get-AdmRawProp $d 'NetbiosName')) `
            -Aliases @(Get-AdmRawProp $d 'Aliases' @()) `
            -Hosts @(Get-AdmRawProp $d 'Hosts' @()) `
            -DomainControllers @(Get-AdmRawProp $d 'DomainControllers' @()) `
            -Port $port -UseSsl ([bool]$useSsl) -Force -Confirm:$false | Out-Null

        if ($existing.ContainsKey($name)) { $replaced += $name } else { $added += $name }
    }

    [pscustomobject]@{
        Added = $added; Replaced = $replaced; Skipped = $skipped
        Note = $(if ($skipped.Count) { "$($skipped.Count) already registered and left alone -- use -Force to overwrite" }
                 else { 'imported domains have no credential yet' })
    }
}

function Set-AdmDomainCredential {
    <#
    .SYNOPSIS
      Store a credential for a domain under a named tier.
    .DESCRIPTION
      Tiers exist so a read credential cannot perform a write. Convention: 'read' for queries,
      'write' for changes. Nothing enforces the split inside AD -- that is the directory's job,
      via the rights you grant each account. This only keeps them separate on your side.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$Credential,
        [string]$Tier = 'read',
        [switch]$SetDefault
    )
    $s = Get-AdmSession
    $d = Get-AdmDomainRecord -Name $Domain
    if (-not $PSCmdlet.ShouldProcess("$Domain/$Tier", 'Store credential')) { return }

    $plain = ConvertFrom-AdmSecureString -Secure $Credential.Password
    try {
        $d.Credentials | Add-Member -NotePropertyName $Tier -NotePropertyValue ([pscustomobject]@{
            UserName = $Credential.UserName
            Password = $plain
        }) -Force
    } finally { $plain = $null }
    if ($SetDefault) { $d.DefaultCredential = $Tier }
    Save-AdmSession
    [pscustomobject]@{
        Domain = $Domain; Tier = $Tier; UserName = $Credential.UserName
        DefaultCredential = $d.DefaultCredential
    }
}

function Remove-AdmDomainCredential {
    <#
    .SYNOPSIS
      Forget one stored credential tier for a domain. The account itself is untouched.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$Tier
    )
    $d = Get-AdmDomainRecord -Name $Domain
    if (-not $d.Credentials.PSObject.Properties[$Tier]) { throw "Domain '$Domain' has no '$Tier' credential." }
    if (-not $PSCmdlet.ShouldProcess("$Domain/$Tier", 'Remove stored credential')) { return }
    $d.Credentials.PSObject.Properties.Remove($Tier)
    Save-AdmSession
    [pscustomobject]@{ Domain = $Domain; RemovedTier = $Tier }
}

function Resolve-AdmDomain {
    <#
    .SYNOPSIS
      Work out which registered domain a hostname, FQDN, UPN or NetBIOS name belongs to.
    .DESCRIPTION
      The core of the toolkit. Precedence, most specific first: an explicit Hosts entry, a named
      domain controller, an exact DNS domain or alias, the longest matching DNS suffix, then the
      NetBIOS name. A tie is an ERROR, never a guess.
    .EXAMPLE
      Resolve-AdmDomain -Target ws1.child.corp.example.com
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][string]$Target,
        [switch]$UseDnsLookup
    )
    process {
        $s = Get-AdmSession
        $r = Resolve-AdmDomainProfile -Target $Target -Domains @($s.Data.domains) -UseDnsLookup:$UseDnsLookup
        [pscustomobject]@{
            Target            = $r.Original
            Normalized        = $r.Target
            Domain            = $r.Domain.Name
            DnsDomain         = $r.Domain.DnsDomain
            NetbiosName       = $r.Domain.NetbiosName
            MatchedOn         = $r.MatchedOn
            ViaDnsLookup      = $r.ViaDns
            DefaultCredential = $r.Domain.DefaultCredential
        }
    }
}

# Internal helper the object cmdlets share: target -> (domain record, credential).
function Get-AdmTargetContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Tier,
        [switch]$UseDnsLookup
    )
    $s = Get-AdmSession
    $r = Resolve-AdmDomainProfile -Target $Target -Domains @($s.Data.domains) -UseDnsLookup:$UseDnsLookup
    [pscustomobject]@{
        Domain     = $r.Domain
        Credential = Get-AdmDomainCredential -Domain $r.Domain -Tier $Tier
        MatchedOn  = $r.MatchedOn
    }
}
