# Public/Policies.ps1 -- fine-grained password policies, as objects.
#
# Get-AdmPasswordPolicy reads the DEFAULT DOMAIN POLICY and says plainly that it does not read
# these. Detail.ps1 answers "which PSO applies to this one account" via msDS-ResultantPSO. What
# neither does is enumerate the policies themselves -- which is what you need to answer "why does
# this group of people have a different expiry to everyone else", and to find the PSO somebody
# created for a project three years ago and left applying to a group that still has members.

# PSO durations are stored the same way the domain policy's are: NEGATIVE 100-nanosecond
# intervals, as LargeInteger attributes.
#
# ⛔ READ THEM WITH A SEARCH, never DirectoryEntry.Properties. A search returns Int64; a
# DirectoryEntry returns a COM object whose ToString is "System.__ComObject", and the resulting
# blank is silent -- this repo has already been bitten by exactly that on maxPwdAge, where a blank
# maximum age made "expiring soon" quietly match nothing at all.
function ConvertFrom-AdmPsoDuration {
    [CmdletBinding()]
    param($Value, [ValidateSet('Days', 'Minutes')][string]$As = 'Days')
    $n = 0L
    if (-not [int64]::TryParse([string]$Value, [ref]$n)) { return $null }
    # Int64::MinValue is the "never" sentinel; 0 means unset.
    if ($n -eq [int64]::MinValue -or $n -eq 0) { return $null }
    $days = [math]::Abs($n) / 864000000000.0
    if ($As -eq 'Minutes') { return [math]::Round($days * 1440, 1) }
    [math]::Round($days, 2)
}

function Get-AdmPasswordSettingsPolicy {
    <#
    .SYNOPSIS
      Fine-grained password policies (PSOs), who they apply to, and in what order. Read-only.
    .DESCRIPTION
      Reads the msDS-PasswordSettings objects from CN=Password Settings Container,CN=System. These
      override the default domain policy for the users and groups they name, and nothing in the
      default policy hints that they exist.

      ⭐ PRECEDENCE IS NOT SENIORITY -- A LOWER NUMBER WINS. msDS-PasswordSettingsPrecedence 1
      beats 10. Read the other way round, which is the natural reading, you conclude the wrong
      policy applies and go and change the one that was never in effect.

      ⭐ AND PRECEDENCE IS NOT THE FIRST TEST. A PSO linked DIRECTLY to a user beats every PSO
      linked to a group the user is in, whatever the precedence numbers say. Only among
      group-linked PSOs does precedence decide, and a tie there is broken by the smallest
      objectGUID -- which is effectively arbitrary and is worth eliminating rather than relying on.
      This reports the numbers and the links; for the answer for one account, ask the directory
      itself via the resultant PSO rather than recomputing the rules here.

      ⚠ AppliesTo IS OFTEN THE INTERESTING FIELD. A PSO applying to nothing is dead configuration;
      one applying to a group whose membership has drifted is a policy nobody knows is in force.
      Both are reported rather than left to be noticed.
    .OUTPUTS
      One object per PSO, with exactly these fields:
        Domain, Name, DistinguishedName, Precedence, MinPasswordLength, MaxPasswordAgeDays,
        MinPasswordAgeDays, PasswordHistoryLength, ComplexityEnabled, ReversibleEncryptionEnabled,
        LockoutThreshold, LockoutDurationMinutes, LockoutObservationWindowMinutes,
        AppliesTo (array of DNs), AppliesToCount, Unlinked (bool, or $null for UNKNOWN when the
        attribute read was truncated), AppliesToTruncated, WhenCreated, WhenChanged
    .EXAMPLE
      Get-AdmPasswordSettingsPolicy -Target corp.example.com
    .EXAMPLE
      Get-AdmPasswordSettingsPolicy -Target corp.example.com | Where-Object { $_.Unlinked }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Identity,
        [string]$Tier,
        [int]$Limit = 5000,
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation 'list fine-grained password policies' -Target $Target -Action {
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup

        if ((Get-AdmProviderName) -eq 'mock') {
            # The fixture does not model PSOs. An empty list is the honest answer and matches the
            # shape of a domain that has none, which is most of them.
            return @()
        }

        $domainNc = ConvertTo-AdmDistinguishedName -DnsDomain $ctx.Domain.DnsDomain
        $base = "CN=Password Settings Container,CN=System,$domainNc"

        $filter = if ($Identity) {
            $v = ConvertTo-AdmLdapFilterValue -Value $Identity
            "(&(objectClass=msDS-PasswordSettings)(|(cn=*$v*)(name=*$v*)))"
        } else { '(objectClass=msDS-PasswordSettings)' }

        $rows = @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential `
                    -Filter $filter -SearchBase $base -SizeLimit $Limit `
                    -Properties @('cn', 'name', 'distinguishedname', 'whencreated', 'whenchanged',
                                  'msds-passwordsettingsprecedence', 'msds-minimumpasswordlength',
                                  'msds-maximumpasswordage', 'msds-minimumpasswordage',
                                  'msds-passwordhistorylength', 'msds-passwordcomplexityenabled',
                                  'msds-passwordreversibleencryptionenabled',
                                  'msds-lockoutthreshold', 'msds-lockoutduration',
                                  'msds-lockoutobservationwindow', 'msds-psoappliesto'))

        foreach ($r in $rows) {
            # msDS-PSOAppliesTo is multi-valued and absent entirely when the PSO applies to
            # nothing -- which is the case worth surfacing, so it must not throw on the way there.
            #
            # ⛔ READ THROUGH Get-AdmRangedProp, NOT Get-AdmRawProp. Past ~1500 values the
            # directory renames the property to `msDS-PSOAppliesTo;range=0-1499`, so a plain read
            # returns $null and this would report Unlinked = TRUE -- "this policy applies to
            # nobody", which is the conclusion someone deletes on. The search-level truncation
            # flag cannot see it, because the SEARCH was complete; only the attribute was cut.
            # A PSO realistically never has 1500 direct links, but the shape is identical to the
            # one that does bite on `member`, and relying on "realistically" is how the other
            # instances got written.
            $appliesRead = Get-AdmRangedProp $r 'msds-psoappliesto'
            $applies = @($appliesRead.Values)
            [pscustomobject]@{
                Domain            = $ctx.Domain.Name
                Name              = Get-AdmRawProp $r 'cn' (Get-AdmRawProp $r 'name')
                DistinguishedName = Get-AdmRawProp $r 'distinguishedname'
                # Lower wins. Named plainly rather than as 'Priority', which reads the other way.
                Precedence        = [int](Get-AdmRawProp $r 'msds-passwordsettingsprecedence' 0)
                MinPasswordLength = [int](Get-AdmRawProp $r 'msds-minimumpasswordlength' 0)
                MaxPasswordAgeDays = ConvertFrom-AdmPsoDuration (Get-AdmRawProp $r 'msds-maximumpasswordage')
                MinPasswordAgeDays = ConvertFrom-AdmPsoDuration (Get-AdmRawProp $r 'msds-minimumpasswordage')
                PasswordHistoryLength = [int](Get-AdmRawProp $r 'msds-passwordhistorylength' 0)
                ComplexityEnabled = [bool](Get-AdmRawProp $r 'msds-passwordcomplexityenabled' $false)
                # ⚠ Reversible encryption means the password is recoverable in plaintext. It is
                # almost never wanted and is reported for exactly that reason.
                ReversibleEncryptionEnabled = [bool](Get-AdmRawProp $r 'msds-passwordreversibleencryptionenabled' $false)
                LockoutThreshold  = [int](Get-AdmRawProp $r 'msds-lockoutthreshold' 0)
                LockoutDurationMinutes = ConvertFrom-AdmPsoDuration (Get-AdmRawProp $r 'msds-lockoutduration') -As Minutes
                LockoutObservationWindowMinutes = ConvertFrom-AdmPsoDuration (Get-AdmRawProp $r 'msds-lockoutobservationwindow') -As Minutes
                AppliesTo         = $applies
                AppliesToCount    = $applies.Count
                # ⛔ $null -- UNKNOWN -- rather than a confident $true when the attribute read was
                # cut. "Applies to nobody" is what somebody deletes a policy on, and a partial read
                # must not be able to assert it. Same three-state shape as NoSubnets.
                Unlinked          = $(if ($appliesRead.Truncated) { $null } else { $applies.Count -eq 0 })
                AppliesToTruncated = $appliesRead.Truncated
                WhenCreated       = Get-AdmRawProp $r 'whencreated'
                WhenChanged       = Get-AdmRawProp $r 'whenchanged'
                ObjectClass       = 'msDS-PasswordSettings'
            }
        }
    }
}
