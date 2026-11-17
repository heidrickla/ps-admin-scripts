<#
.SYNOPSIS
  Find and act on domain user accounts: locked, expiring, stale, plus create / group / reset.

.DESCRIPTION
  One tool for the account questions that come up weekly, over plain LDAP through ADAdmin -- so it
  works from a machine outside the forest with no RSAT. Reporting is the default and changes
  nothing; every mode that writes asks first.

  ⚠⚠ READ THIS BEFORE USING -DisableStale.
  "Last logon" here is lastLogonTimestamp, which Active Directory replicates LAZILY -- by default
  it only advances when a logon is more than about 9-14 days newer than the stored value. So the
  figure can be up to roughly 14 days OLDER than the truth, and an account that signed in last
  week can look idle. That is harmless for a 90-day sweep and dangerous for a 20-day one, so
  -StaleDays below 30 is refused unless you pass -IAcceptTheReplicationLag. The genuinely accurate
  attribute, lastLogon, is per-domain-controller and never replicated, so reading it properly
  means querying every DC and taking the newest -- which this script does not do.

  ⚠ Built-in accounts (krbtgt, Guest, Administrator, DefaultAccount) are EXCLUDED from stale
  results by default. They never log in interactively, so a naive sweep flags them every time --
  and disabling krbtgt breaks Kerberos for the whole domain. -IncludeBuiltIn overrides that.

  ⚠ Password expiry is computed from the DEFAULT DOMAIN POLICY. Fine-grained password policies
  (PSOs) can give specific users a different schedule, and this does not read them.

.EXAMPLE
  .\Manage-AdUserAccounts.ps1 -Target corp.example.com -Locked
.EXAMPLE
  .\Manage-AdUserAccounts.ps1 -Target corp.example.com -PasswordExpiringDays 14 -ExportCsv .\expiring.csv
.EXAMPLE
  .\Manage-AdUserAccounts.ps1 -Target corp.example.com -StaleDays 90 -ExportCsv .\pending-lockout.csv
.EXAMPLE
  .\Manage-AdUserAccounts.ps1 -Target corp.example.com -DisableStale -StaleDays 90 -Only jbloggs,asmith -WhatIf
.EXAMPLE
  .\Manage-AdUserAccounts.ps1 -Target corp.example.com -CreateUser -Identity jbloggs -DisplayName 'Jo Bloggs' -Group Helpdesk

.NOTES
  EXIT CODES
    0   ran, nothing needing attention (or the change succeeded)
    10  ran, and found accounts matching the filter -- for scripting a "did it find anything" gate
    20  a change failed
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Report')]
param(
    [Parameter(Mandatory)][string]$Target,

    # --- report -------------------------------------------------------------------------------
    [Parameter(ParameterSetName = 'Report')][switch]$Locked,
    [Parameter(ParameterSetName = 'Report')][int]$PasswordExpiringDays,
    [Parameter(ParameterSetName = 'Report')][int]$StaleDays,
    [Parameter(ParameterSetName = 'Report')][switch]$NeverLoggedOn,

    # --- disable stale ------------------------------------------------------------------------
    [Parameter(Mandatory, ParameterSetName = 'DisableStale')][switch]$DisableStale,
    [Parameter(ParameterSetName = 'DisableStale')][int]$StaleDaysForDisable = 90,
    # Only these accounts, so a sweep can be applied in reviewed batches rather than all at once.
    [Parameter(ParameterSetName = 'DisableStale')][string[]]$Only,

    # --- reset --------------------------------------------------------------------------------
    [Parameter(Mandatory, ParameterSetName = 'Reset')][switch]$ResetPassword,
    [Parameter(Mandatory, ParameterSetName = 'Reset')]
    [Parameter(Mandatory, ParameterSetName = 'Create')]
    [Parameter(Mandatory, ParameterSetName = 'AddGroup')]
    [Parameter(ParameterSetName = 'Report')][string]$Identity,
    [Parameter(ParameterSetName = 'Reset')]
    [Parameter(ParameterSetName = 'Create')][System.Security.SecureString]$NewPassword,
    [Parameter(ParameterSetName = 'Reset')]
    [Parameter(ParameterSetName = 'Create')][switch]$MustChangeAtNextLogon,

    # --- create -------------------------------------------------------------------------------
    [Parameter(Mandatory, ParameterSetName = 'Create')][switch]$CreateUser,
    [Parameter(ParameterSetName = 'Create')][string]$DisplayName,
    [Parameter(ParameterSetName = 'Create')][string]$Path,

    # --- group --------------------------------------------------------------------------------
    [Parameter(Mandatory, ParameterSetName = 'AddGroup')][switch]$AddToGroup,
    [Parameter(ParameterSetName = 'Create')]
    [Parameter(Mandatory, ParameterSetName = 'AddGroup')][string]$Group,

    # --- common -------------------------------------------------------------------------------
    [string]$ExportCsv,
    [switch]$IncludeBuiltIn,
    [switch]$IAcceptTheReplicationLag,
    [int]$Limit = 5000,
    [string]$Tier
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# NOT -Force: a forced import makes a fresh module instance and re-locks the caller's store.
if (-not (Get-Module ADAdmin)) {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'ADAdmin\ADAdmin.psd1')
}

# Accounts that never log in interactively and must not be swept up by a staleness filter.
# krbtgt in particular: disabling it breaks Kerberos for the entire domain.
$BuiltIn = @('krbtgt', 'Guest', 'Administrator', 'DefaultAccount', 'WDAGUtilityAccount')

function Test-BuiltIn { param([string]$Sam) $BuiltIn -contains $Sam }

# --- writes ---------------------------------------------------------------------------------

if ($PSCmdlet.ParameterSetName -eq 'Reset') {
    $pw = $NewPassword
    if (-not $pw) { $pw = Read-Host -Prompt "New password for '$Identity'" -AsSecureString }
    $r = Reset-AdmUserPassword -Target $Target -Identity $Identity -NewPassword $pw `
            -MustChangeAtNextLogon:$MustChangeAtNextLogon -Tier $Tier -WhatIf:$WhatIfPreference -Confirm:$false
    $r
    exit 0
}

if ($PSCmdlet.ParameterSetName -eq 'Create') {
    $pw = $NewPassword
    if (-not $pw) { $pw = Read-Host -Prompt "Password for the new account '$Identity'" -AsSecureString }
    $created = New-AdmUser -Target $Target -SamAccountName $Identity -DisplayName $DisplayName `
                    -Password $pw -Path $Path -MustChangeAtNextLogon:$MustChangeAtNextLogon `
                    -Tier $Tier -WhatIf:$WhatIfPreference -Confirm:$false
    $created
    if ($Group -and -not $WhatIfPreference) {
        Add-AdmGroupMember -Target $Target -Group $Group -Identity $Identity -Tier $Tier -Confirm:$false
    }
    exit 0
}

if ($PSCmdlet.ParameterSetName -eq 'AddGroup') {
    Add-AdmGroupMember -Target $Target -Group $Group -Identity $Identity -Tier $Tier `
        -WhatIf:$WhatIfPreference -Confirm:$false
    exit 0
}

# --- gather -----------------------------------------------------------------------------------

$policy = $null
try { $policy = Get-AdmPasswordPolicy -Target $Target -Tier $Tier } catch {
    Write-Warning "Could not read the domain password policy, so password expiry cannot be computed: $($_.Exception.Message)"
}
$maxAge = if ($policy) { $policy.MaxPasswordAgeDays } else { $null }

$users = @(Get-AdmUser -Target $Target -Identity $Identity -Tier $Tier -Limit $Limit)
$now = (Get-Date).ToUniversalTime()

$rows = foreach ($u in $users) {

    $daysIdle = $null
    if ($u.LastLogonTimestamp) { $daysIdle = [math]::Round(($now - $u.LastLogonTimestamp).TotalDays, 1) }

    $expires = $null; $daysToExpiry = $null
    if ($u.PasswordNeverExpires) { $expires = 'never' }
    elseif ($u.MustChangePassword) { $expires = 'must change at next logon'; $daysToExpiry = 0 }
    elseif ($maxAge -and $u.PasswordLastSet) {
        $d = $u.PasswordLastSet.AddDays($maxAge)
        $expires = $d.ToString('yyyy-MM-dd')
        $daysToExpiry = [math]::Round(($d - $now).TotalDays, 1)
    }

    [pscustomobject]@{
        SamAccountName    = $u.SamAccountName
        DisplayName       = $u.DisplayName
        Mail              = $u.Mail
        Enabled           = $u.Enabled
        LockedOut         = $u.LockedOut
        PasswordLastSet   = if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString('yyyy-MM-dd') } else { $null }
        PasswordExpires   = $expires
        DaysToExpiry      = $daysToExpiry
        LastLogon         = if ($u.LastLogonTimestamp) { $u.LastLogonTimestamp.ToString('yyyy-MM-dd') } else { $null }
        DaysIdle          = $daysIdle
        NeverLoggedOn     = ($null -eq $u.LastLogonTimestamp)
        WhenCreated       = $u.WhenCreated
        IsBuiltIn         = Test-BuiltIn $u.SamAccountName
        DistinguishedName = $u.DistinguishedName
    }
}

# --- filter -------------------------------------------------------------------------------------

$staleThreshold = if ($PSCmdlet.ParameterSetName -eq 'DisableStale') { $StaleDaysForDisable } else { $StaleDays }

if ($staleThreshold -and $staleThreshold -lt 30 -and -not $IAcceptTheReplicationLag) {
    throw ("-StaleDays $staleThreshold is below 30. lastLogonTimestamp can be up to about 14 days " +
           "behind reality, so a threshold this low will report accounts that signed in recently " +
           "as idle -- and with -DisableStale that means disabling active users. Use 30 or more, " +
           "or pass -IAcceptTheReplicationLag if you have a reason.")
}

$selected = @($rows)

if ($Locked)        { $selected = @($selected | Where-Object { $_.LockedOut }) }
if ($NeverLoggedOn) { $selected = @($selected | Where-Object { $_.NeverLoggedOn }) }
if ($PasswordExpiringDays) {
    $selected = @($selected | Where-Object {
        $null -ne $_.DaysToExpiry -and $_.DaysToExpiry -le $PasswordExpiringDays
    })
}
if ($staleThreshold) {
    $selected = @($selected | Where-Object {
        # An account that has NEVER logged on is not "idle since" anything -- judge it on age
        # instead, or a brand-new account created this morning is swept up on day one.
        $idle = if ($null -ne $_.DaysIdle) { $_.DaysIdle }
                elseif ($_.WhenCreated) { try { ($now - [datetime]$_.WhenCreated).TotalDays } catch { $null } }
                else { $null }
        $null -ne $idle -and $idle -ge $staleThreshold
    })
}
if (-not $IncludeBuiltIn) { $selected = @($selected | Where-Object { -not $_.IsBuiltIn }) }

# --- export --------------------------------------------------------------------------------------
# Deliberately BEFORE any disable, so the list you notify people from is the list you acted on.

if ($ExportCsv) {
    $selected | Export-Csv -LiteralPath $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Verbose "Wrote $($selected.Count) row(s) to $ExportCsv"
}

# --- disable -------------------------------------------------------------------------------------

if ($PSCmdlet.ParameterSetName -eq 'DisableStale') {

    $targets = @($selected | Where-Object { $_.Enabled })
    if ($Only) { $targets = @($targets | Where-Object { $Only -contains $_.SamAccountName }) }

    if (-not $targets.Count) {
        Write-Verbose 'No enabled, stale, non-built-in accounts matched.'
        $selected
        exit 0
    }

    $results = foreach ($t in $targets) {
        # One confirmation per account, naming the evidence. A single "disable 47 accounts?" prompt
        # is not a decision anybody can actually make.
        $prompt = "Disable '$($t.SamAccountName)' ($($t.DisplayName))? Last logon $(if ($t.LastLogon) { $t.LastLogon } else { 'never' }), idle $($t.DaysIdle) day(s)"
        if ($PSCmdlet.ShouldProcess("$($t.SamAccountName) @ $Target", $prompt)) {
            try {
                Set-AdmUserEnabled -Target $Target -Identity $t.SamAccountName -Enabled $false `
                    -Tier $Tier -Confirm:$false | Out-Null
                [pscustomobject]@{ SamAccountName = $t.SamAccountName; Outcome = 'disabled'; Detail = "idle $($t.DaysIdle) day(s)" }
            } catch {
                [pscustomobject]@{ SamAccountName = $t.SamAccountName; Outcome = 'failed'; Detail = $_.Exception.Message }
            }
        } else {
            [pscustomobject]@{ SamAccountName = $t.SamAccountName; Outcome = 'skipped'; Detail = 'not confirmed' }
        }
    }

    $results
    if (@($results | Where-Object { $_.Outcome -eq 'failed' }).Count) { exit 20 }
    exit 0
}

# --- report ----------------------------------------------------------------------------------------

$selected

if ($staleThreshold -or $PasswordExpiringDays) {
    Write-Verbose ("Password expiry is computed from the default domain policy" +
                   $(if ($maxAge) { " (maximum password age $maxAge days)" } else { ' (not available)' }) +
                   '. Fine-grained password policies are not read.')
}
if ($staleThreshold) {
    Write-Warning ("Idle time comes from lastLogonTimestamp, which can be up to ~14 days behind " +
                   "reality. Treat these as candidates to review, not as proof of inactivity.")
}

if (@($selected).Count) { exit 10 }
exit 0
