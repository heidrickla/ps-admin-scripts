<#
.SYNOPSIS
  Find computer objects for machines that no longer exist, and optionally disable them.

.DESCRIPTION
  Computer accounts accumulate forever. A machine is rebuilt, a VM is deleted, a laptop is
  retired -- and the object stays in the directory, holding a name, an SPN and a password, and
  padding out every report anyone runs afterwards. This finds them over plain LDAP through
  ADAdmin, so it works from outside the forest with no RSAT.

  ⭐ IT JUDGES STALENESS BY THE MACHINE PASSWORD, NOT BY LAST LOGON, and that is the point.
  A domain member rotates its own computer-account password every 30 days by default and the
  write replicates normally. lastLogonTimestamp is deliberately LAZY -- Active Directory only
  advances it when a logon is roughly 9-14 days newer than the stored value -- so it can be two
  weeks behind the truth. For a computer, pwdLastSet is both fresher and harder to fake: a
  machine that has not changed its password in 60 days is almost certainly gone, whatever its
  last-logon field says. Both are reported; -By selects which one filters.

  ⛔ DOMAIN CONTROLLERS ARE EXCLUDED, ALWAYS, AND CANNOT BE DISABLED FROM HERE.
  Nobody interactively logs on to a DC, so a DC looks idle by exactly the measures this script
  uses -- it is the object a naive sweep is most likely to select, and disabling its computer
  account takes the domain controller offline. The refusal is enforced in the module
  (Set-AdmComputerEnabled), not just in this script, so it holds for any caller.

  ⚠ THREE WAYS A LIVE MACHINE CAN LOOK DEAD. Check these before acting on a long list:
    - Password rotation turned OFF by policy (DisablePasswordChange, or a very long
      MaximumPasswordAge) freezes pwdLastSet, so healthy machines age out. Use -By LastLogon
      instead where that policy is in force.
    - Machines that are genuinely off for months -- seasonal kit, spare laptops, DR standbys --
      are indistinguishable from deleted ones by any directory attribute.
    - Cluster name objects and other virtual computer objects do not behave like real members.

  ⚠ IT DISABLES, IT NEVER DELETES. Disabling is reversible in seconds and immediately tells you
  who was still using the machine; deletion destroys the object's SID and its group memberships,
  and rejoining under the same name produces a different object. Delete later, by hand, from the
  exported list, once nobody has complained.

.EXAMPLE
  .\Find-StaleComputers.ps1 -Target corp.example.com -StaleDays 90
.EXAMPLE
  .\Find-StaleComputers.ps1 -Target corp.example.com -StaleDays 180 -ExportCsv .\stale.csv
.EXAMPLE
  .\Find-StaleComputers.ps1 -Target corp.example.com -DisableStale -StaleDays 180 -Only OLDPC1,OLDPC2 -WhatIf

.NOTES
  EXIT CODES
    0   ran, nothing matched (or the change succeeded)
    10  ran, and found computers matching the filter
    20  a change failed
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Report')]
param(
    [Parameter(Mandatory)][string]$Target,

    # --- report -------------------------------------------------------------------------------
    [Parameter(ParameterSetName = 'Report')][int]$StaleDays = 90,
    # Report only, no filtering: computers already disabled, i.e. the backlog of previous sweeps.
    [Parameter(ParameterSetName = 'Report')][switch]$AlreadyDisabled,

    # --- disable ------------------------------------------------------------------------------
    [Parameter(Mandatory, ParameterSetName = 'Disable')][switch]$DisableStale,
    [Parameter(ParameterSetName = 'Disable')][int]$StaleDaysForDisable = 180,
    # Only these machines, so a sweep is applied in reviewed batches rather than all at once.
    [Parameter(ParameterSetName = 'Disable')][string[]]$Only,

    # --- common -------------------------------------------------------------------------------
    # PasswordLastSet is the default because it is the more reliable signal for a computer; see
    # the description. LastLogon is there for estates that have frozen password rotation.
    [ValidateSet('PasswordLastSet', 'LastLogon', 'Either')][string]$By = 'PasswordLastSet',
    [string]$ExportCsv,
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

$threshold = if ($PSCmdlet.ParameterSetName -eq 'Disable') { $StaleDaysForDisable } else { $StaleDays }

# The same floor as the user sweep, for the same reason -- and it applies to -By LastLogon
# especially, since that is the attribute with the ~14 day lag.
if ($threshold -lt 30 -and -not $IAcceptTheReplicationLag) {
    throw ("A staleness window of $threshold days is below 30. lastLogonTimestamp can be ~14 days " +
           "behind reality, and a machine that was simply switched off for a fortnight has not " +
           "gone anywhere. Use 30 or more -- 90 to report and 180 to disable are sane defaults -- " +
           "or pass -IAcceptTheReplicationLag if you have a reason.")
}

# --- gather -----------------------------------------------------------------------------------

# ⛔ A TRUNCATED READ HERE DOES NOT PRODUCE A SHORT LIST, IT PRODUCES A CLEAN-LOOKING ONE. Every
# computer past the limit is never judged, so it can never be reported stale -- and the summary's
# "out of N computer object(s)" quotes a denominator that is simply wrong. On a -Disable run it is
# worse than a wrong number: "the stale machines have been dealt with" is false, and nothing in
# the output would say so.
Reset-AdmSearchTruncated
$computers = @(Get-AdmComputer -Target $Target -Tier $Tier -Limit $Limit)
$readTruncated = [bool](Get-AdmSearchTruncated)
if ($readTruncated) {
    Write-Warning ("INCOMPLETE: the read of computer objects stopped at $Limit, so this domain has " +
                   "more than were examined. Everything below is a FLOOR -- machines past the limit " +
                   "were never judged and cannot appear here however stale they are. Re-run with a " +
                   "higher -Limit before treating this as the set.")
}
$now = (Get-Date).ToUniversalTime()

function Get-AgeDays {
    param($When)
    if (-not $When) { return $null }
    try { [math]::Round(($now - [datetime]$When).TotalDays, 1) } catch { $null }
}

$rows = foreach ($c in $computers) {

    $pwAge  = Get-AgeDays $c.PasswordLastSet
    $logAge = Get-AgeDays $c.LastLogonTimestamp

    # A machine that has never done either is judged on its own age instead, or a computer object
    # pre-staged this morning is reported as stale on day one.
    $createdAge = Get-AgeDays $c.WhenCreated

    [pscustomobject]@{
        Name               = $c.Name
        DnsHostName        = $c.DnsHostName
        OperatingSystem    = $c.OperatingSystem
        OSVersion          = $c.OperatingSystemVersion
        Enabled            = $c.Enabled
        IsDomainController = $c.IsDomainController
        PasswordLastSet    = if ($c.PasswordLastSet) { $c.PasswordLastSet.ToString('yyyy-MM-dd') } else { $null }
        PasswordAgeDays    = $pwAge
        LastLogon          = if ($c.LastLogonTimestamp) { $c.LastLogonTimestamp.ToString('yyyy-MM-dd') } else { $null }
        LastLogonAgeDays   = $logAge
        NeverContacted     = ($null -eq $c.PasswordLastSet -and $null -eq $c.LastLogonTimestamp)
        AgeDays            = $createdAge
        WhenCreated        = $c.WhenCreated
        DistinguishedName  = $c.DistinguishedName
    }
}

# --- filter -------------------------------------------------------------------------------------

# ⛔ First and unconditional. Everything downstream -- the report, the export, the disable -- is
# built from a list a domain controller cannot be in.
$selected = @($rows | Where-Object { -not $_.IsDomainController })
$dcCount = @($rows).Count - $selected.Count

if ($AlreadyDisabled) {
    $selected = @($selected | Where-Object { -not $_.Enabled })
} else {
    $selected = @($selected | Where-Object {
        # ⚠ `switch` REBINDS $_ TO ITS OWN INPUT. Inside `switch ($By) { ... }` below, $_ is the
        # string 'PasswordLastSet', NOT the pipeline row -- so $_.PasswordAgeDays fails with
        # "The property 'PasswordAgeDays' cannot be found on this object". Capture the row first.
        $row = $_
        # Both null means the object has never been used at all -- fall back to how long it has
        # existed, which is the only evidence there is.
        if ($row.NeverContacted) {
            $null -ne $row.AgeDays -and $row.AgeDays -ge $threshold
        } else {
            switch ($By) {
                'PasswordLastSet' { $null -ne $row.PasswordAgeDays  -and $row.PasswordAgeDays  -ge $threshold }
                'LastLogon'       { $null -ne $row.LastLogonAgeDays -and $row.LastLogonAgeDays -ge $threshold }
                # Both signals must agree. The conservative reading: one fresh timestamp is
                # enough to believe the machine is alive.
                'Either' {
                    $p = if ($null -ne $row.PasswordAgeDays)  { $row.PasswordAgeDays }  else { [double]::MaxValue }
                    $l = if ($null -ne $row.LastLogonAgeDays) { $row.LastLogonAgeDays } else { [double]::MaxValue }
                    [math]::Min($p, $l) -ge $threshold
                }
            }
        }
    })
}

# --- export --------------------------------------------------------------------------------------
# Before any disable, so the list you keep is the list that was acted on.

if ($ExportCsv) {
    $selected | Export-Csv -LiteralPath $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Verbose "Wrote $(@($selected).Count) row(s) to $ExportCsv"
}

# --- disable -------------------------------------------------------------------------------------

if ($PSCmdlet.ParameterSetName -eq 'Disable') {

    $targets = @($selected | Where-Object { $_.Enabled })
    if ($Only) { $targets = @($targets | Where-Object { $Only -contains $_.Name }) }

    if (-not $targets.Count) {
        Write-Verbose 'No enabled, stale, non-domain-controller computers matched.'
        $selected
        exit 0
    }

    $results = foreach ($t in $targets) {
        # One confirmation per machine, naming the evidence that selected it. A single
        # "disable 300 computers?" prompt is not a decision anybody can actually make.
        $why = if ($t.NeverContacted) { "never contacted the domain, object is $($t.AgeDays) day(s) old" }
               else { "password $($t.PasswordAgeDays) day(s) old, last logon $(if ($t.LastLogon) { "$($t.LastLogon) ($($t.LastLogonAgeDays)d)" } else { 'never' })" }
        $prompt = "Disable computer '$($t.Name)' ($(if ($t.OperatingSystem) { $t.OperatingSystem } else { 'unknown OS' }))? $why"

        if ($PSCmdlet.ShouldProcess("$($t.Name) @ $Target", $prompt)) {
            try {
                Set-AdmComputerEnabled -Target $Target -Identity $t.Name -Enabled $false `
                    -Tier $Tier -Confirm:$false | Out-Null
                [pscustomobject]@{ Name = $t.Name; Outcome = 'disabled'; Detail = $why }
            } catch {
                [pscustomobject]@{ Name = $t.Name; Outcome = 'failed'; Detail = $_.Exception.Message }
            }
        } else {
            [pscustomobject]@{ Name = $t.Name; Outcome = 'skipped'; Detail = 'not confirmed' }
        }
    }

    $results
    Write-Warning ("Disabled, not deleted. Leave them disabled for a full business cycle before " +
                   "deleting anything -- a disabled machine that someone still needed will make " +
                   "itself known, and re-enabling is instant.")
    if ($readTruncated) {
        # Said again HERE, because the one at the top of a long run has scrolled away by now and
        # this is the point at which somebody concludes the job is done.
        Write-Warning ("AND THIS WAS NOT ALL OF THEM. The read stopped at $Limit computer objects, " +
                       "so stale machines past that limit were never examined and are still enabled. " +
                       "Do not record this domain as cleaned up.")
    }
    if (@($results | Where-Object { $_.Outcome -eq 'failed' }).Count) { exit 20 }
    exit 0
}

# --- report ----------------------------------------------------------------------------------------

$selected

if ($dcCount) {
    Write-Verbose "$dcCount domain controller(s) excluded. They are never reported as stale and cannot be disabled from here."
}
if (-not $AlreadyDisabled) {
    Write-Verbose "Selected on $By, threshold $threshold day(s), out of $(if ($readTruncated) { "AT LEAST $(@($rows).Count)" } else { @($rows).Count }) computer object(s)."
    if ($By -eq 'PasswordLastSet') {
        Write-Warning ("Judged on the machine account password age. If password rotation is " +
                       "disabled by policy in this domain, live machines will appear here -- " +
                       "re-run with -By LastLogon to check.")
    } else {
        Write-Warning ("Judged on lastLogonTimestamp, which replicates lazily and can be ~14 days " +
                       "behind. Treat these as candidates to review, not proof the machine is gone.")
    }
}

if (@($selected).Count) { exit 10 }
exit 0
