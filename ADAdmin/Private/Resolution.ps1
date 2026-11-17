# Resolution.ps1 -- work out WHICH domain a target belongs to.
#
# This is the load-bearing piece of the whole toolkit: the forests share no trusts, so binding
# with the wrong domain's credential is not a soft failure. It either fails outright or, worse,
# succeeds against a domain you did not mean to touch.
#
# TWO RULES, both learned from failures that looked like successes:
#   1. MOST SPECIFIC WINS -- an explicit host mapping beats a DNS suffix, which beats NetBIOS.
#   2. AMBIGUITY IS AN ERROR, NEVER A PICK. If two profiles match equally well, throw and name
#      them. Silently choosing the first is how a confident, well-formed, wrong answer happens.

function ConvertTo-AdmNormalizedTarget {
    <#
      Reduce whatever the caller typed to the parts we can match on. Accepts:
        dc01.corp.example.com      ldaps://dc01.corp.example.com:636
        corp.example.com           CORP\alice
        CORP                       alice@corp.example.com
        dc01                       192.0.2.41
    #>
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Target)

    $t = $Target.Trim()
    if (-not $t) { throw 'Target is empty.' }

    $netbios = $null

    # ldap://host:port/dn -- keep only the authority
    if ($t -match '^(?i)ldaps?://') {
        $t = $t -replace '^(?i)ldaps?://', ''
        $t = ($t -split '/')[0]
    }
    # DOMAIN\user -- the left side is a NetBIOS name and is the strongest hint present
    if ($t.Contains('\')) {
        $parts = $t -split '\\', 2
        $netbios = $parts[0]
        $t = $parts[0]
    }
    # user@domain.tld -- the right side is a DNS domain
    elseif ($t.Contains('@')) {
        $t = ($t -split '@', 2)[1]
    }
    # host:636
    if ($t -match '^(.*):(\d+)$') { $t = $Matches[1] }

    $t = $t.TrimEnd('.').Trim()
    if (-not $t) { throw "Target '$Target' has no host or domain part." }

    $isIp = [bool]($t -as [System.Net.IPAddress])

    [pscustomobject]@{
        Original    = $Target
        Value       = $t.ToLowerInvariant()
        Netbios     = $netbios
        IsIpAddress = $isIp
        IsDotted    = ($t.Contains('.') -and -not $isIp)
    }
}

# "is $Candidate the domain $Suffix, or a host inside it"
function Test-AdmDnsSuffix {
    [OutputType([bool])]
    param([string]$Candidate, [string]$Suffix)
    if (-not $Candidate -or -not $Suffix) { return $false }
    $c = $Candidate.ToLowerInvariant().TrimEnd('.')
    $s = $Suffix.ToLowerInvariant().TrimEnd('.')
    return ($c -eq $s) -or $c.EndsWith('.' + $s)
}

function Get-AdmDomainMatch {
    <#
      Score every profile against the target and return the winners. Emitted as objects rather
      than a single profile so the caller can distinguish "no match" from "ambiguous", which are
      different operator problems with different fixes.

      Rank (lower is more specific):
        0  explicit Hosts entry            -- the operator said so directly
        1  named domain controller
        2  exact DnsDomain / alias
        3  DNS suffix (longest suffix wins within this rank)
        4  NetBIOS name
    #>
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]$Normalized,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Domains
    )

    $hits = @()
    foreach ($d in $Domains) {
        $rank = $null; $on = $null; $len = 0

        $hosts = @($d.Hosts) | Where-Object { $_ }
        $dcs   = @($d.DomainControllers) | Where-Object { $_ }
        $names = @($d.DnsDomain) + @($d.Aliases) | Where-Object { $_ }

        if ($hosts | Where-Object { $_.ToLowerInvariant().TrimEnd('.') -eq $Normalized.Value }) {
            $rank = 0; $on = 'Hosts'
        }
        elseif ($dcs | Where-Object { $_.ToLowerInvariant().TrimEnd('.') -eq $Normalized.Value }) {
            $rank = 1; $on = 'DomainController'
        }
        elseif ($names | Where-Object { $_.ToLowerInvariant().TrimEnd('.') -eq $Normalized.Value }) {
            $rank = 2; $on = 'DnsDomain'
        }
        else {
            # Longest suffix wins: a host in child.corp.example.com must not be attributed to
            # corp.example.com when a profile for the child exists.
            $best = $names |
                Where-Object { Test-AdmDnsSuffix -Candidate $Normalized.Value -Suffix $_ } |
                Sort-Object { $_.Length } -Descending |
                Select-Object -First 1
            if ($best) { $rank = 3; $on = 'DnsSuffix'; $len = $best.Length }
            elseif ($d.NetbiosName -and
                    $d.NetbiosName.ToLowerInvariant() -eq $Normalized.Value) {
                $rank = 4; $on = 'NetbiosName'
            }
        }

        if ($null -ne $rank) {
            $hits += [pscustomobject]@{
                Domain = $d; Rank = $rank; MatchedOn = $on; SuffixLength = $len
            }
        }
    }

    $top = @()
    if ($hits) {
        $bestRank = ($hits | Measure-Object -Property Rank -Minimum).Minimum
        $top = @($hits | Where-Object { $_.Rank -eq $bestRank })
        if ($bestRank -eq 3) {
            $bestLen = ($top | Measure-Object -Property SuffixLength -Maximum).Maximum
            $top = @($top | Where-Object { $_.SuffixLength -eq $bestLen })
        }
    }

    # ONE exit, via -NoEnumerate. Returning a collection from a PowerShell function is a trap
    # with three wrong answers: `return @()` unrolls to nothing (caller gets $null, and $null.Count
    # throws under strict mode), and `return ,@()` emits a one-element array CONTAINING the empty
    # array -- so the caller sees Count 1 and a first element with no properties, which is how the
    # "no match" path started reporting a missing .Domain instead of a clean refusal.
    # -NoEnumerate emits the array itself, empty or not, and says so at the point of emission.
    Write-Output -NoEnumerate $top
}

function Resolve-AdmDomainProfile {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Domains,
        # Off by default and deliberately so. Asking the LOCAL resolver what a bare hostname
        # means, while standing in one forest and aiming at another, is a guess wearing an
        # answer's clothes. Opt in per call when the operator knows the resolver is the right one.
        [switch]$UseDnsLookup
    )

    $norm = ConvertTo-AdmNormalizedTarget -Target $Target
    $top = Get-AdmDomainMatch -Normalized $norm -Domains $Domains

    if ($top.Count -eq 1) {
        return [pscustomobject]@{
            Domain     = $top[0].Domain
            MatchedOn  = $top[0].MatchedOn
            Target     = $norm.Value
            Original   = $Target
            ViaDns     = $false
        }
    }

    if ($top.Count -gt 1) {
        $names = ($top | ForEach-Object { $_.Domain.Name }) -join ', '
        throw ("Target '$Target' matches more than one domain equally well ($names). " +
               "Disambiguate with -Domain <name>, or add the host to exactly one profile's Hosts list.")
    }

    # No match. A bare, non-dotted name may still be resolvable to an FQDN -- but only if the
    # caller has said the local resolver is trustworthy for this question.
    if ($UseDnsLookup -and -not $norm.IsDotted -and -not $norm.IsIpAddress) {
        $fqdn = $null
        try {
            $entry = [System.Net.Dns]::GetHostEntry($norm.Value)
            if ($entry -and $entry.HostName -and $entry.HostName.Contains('.')) { $fqdn = $entry.HostName }
        } catch {
            Write-Verbose "DNS lookup for '$($norm.Value)' failed: $($_.Exception.Message)"
        }
        if ($fqdn) {
            $norm2 = ConvertTo-AdmNormalizedTarget -Target $fqdn
            $top2 = Get-AdmDomainMatch -Normalized $norm2 -Domains $Domains
            if ($top2.Count -eq 1) {
                return [pscustomobject]@{
                    Domain    = $top2[0].Domain
                    MatchedOn = $top2[0].MatchedOn
                    Target    = $norm2.Value
                    Original  = $Target
                    ViaDns    = $true
                }
            }
            if ($top2.Count -gt 1) {
                $names = ($top2 | ForEach-Object { $_.Domain.Name }) -join ', '
                throw "Target '$Target' resolved to '$fqdn', which matches more than one domain ($names)."
            }
        }
    }

    $known = if ($Domains) { (@($Domains) | ForEach-Object { $_.Name }) -join ', ' } else { '(none registered)' }
    $hint = if (-not $norm.IsDotted -and -not $norm.IsIpAddress) {
        " A bare hostname cannot be attributed on its own: add it to a profile's Hosts list, pass the FQDN, or re-run with -UseDnsLookup."
    } elseif ($norm.IsIpAddress) {
        " An IP address cannot be attributed on its own: add it to a profile's Hosts or DomainControllers list."
    } else { '' }
    throw "No registered domain matches '$Target'. Registered: $known.$hint"
}
