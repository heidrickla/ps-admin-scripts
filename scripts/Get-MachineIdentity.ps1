<#
.SYNOPSIS
  Collect each machine's cloning fingerprint, and find machines that share one.

.DESCRIPTION
  Machines imaged without a proper sysprep /generalize carry identifiers that were meant to be
  unique. This collects them per machine and compares across the set.

  ⛔ READ THIS BEFORE ACTING ON A DUPLICATE MACHINE SID. A shared machine SID is NOT the
  domain-breaking problem it is usually assumed to be. Domain membership, authentication and
  group policy all key off the COMPUTER ACCOUNT's SID, which the domain issues and which is
  unique for every machine no matter how it was imaged. Microsoft retired NewSID in 2009 for
  exactly this reason -- its author concluded the duplicate-machine-SID danger was a myth.

  What a duplicate machine SID DOES affect, and these are worth checking before you rebuild
  anything:
    * LOCAL accounts and local ACLs. Two machines with the same machine SID have local accounts
      with identical SIDs, so a disk moved between them, or an ACL referencing a local account,
      resolves to the wrong principal.
    * Software that keys licensing or identity off the machine SID.
    * Removable media and offline access where a local SID is the only identity available.

  ⚠ AND THE ONE PEOPLE USUALLY MEAN. When cloned machines "disappear from WSUS", or take each
  other's place in an inventory, the culprit is almost never the SID -- it is a duplicate
  SusClientId, or a duplicate MachineGuid. Those are collected here too, and SusClientId is the
  one duplicate on this list that has a safe, scripted repair.

  REPAIR
    SusClientId  -- repairable. -RepairWsusId resets it: stop the update service, clear the id
                    and the SoftwareDistribution cache, restart, re-register. The machine then
                    reports as itself at the next check-in.
    MachineGuid  -- reported only. It is referenced by installed software and changing it out
                    from under that software causes worse problems than it solves.
    Machine SID  -- reported only, and deliberately. The only supported fix is sysprep
                    /generalize or a rebuild. There is no supported tool to change it in place;
                    NewSID was withdrawn and should not be resurrected.

.EXAMPLE
  .\Get-MachineIdentity.ps1
.EXAMPLE
  .\Get-MachineIdentity.ps1 -ComputerName host1,host2 -Target corp.example.com -AppendTo .\fleet.csv
.EXAMPLE
  .\Get-MachineIdentity.ps1 -Compare .\fleet.csv
.EXAMPLE
  .\Get-MachineIdentity.ps1 -RepairWsusId -WhatIf

.NOTES
  EXIT CODES
    0   collected, or compared with no duplicates
    10  duplicates found
    20  a collection or repair failed
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Collect')]
param(
    # Remote machines to collect from. Needs PowerShell remoting to each.
    [Parameter(ParameterSetName = 'Collect')][string[]]$ComputerName,
    # Resolve the credential for those machines out of the store, rather than typing one.
    [Parameter(ParameterSetName = 'Collect')][string]$Target,
    [Parameter(ParameterSetName = 'Collect')][string]$Tier,
    # Take the machine list from the directory instead of naming them.
    [Parameter(ParameterSetName = 'Collect')][switch]$FromDirectory,
    [Parameter(ParameterSetName = 'Collect')][string]$AppendTo,

    [Parameter(Mandatory, ParameterSetName = 'Compare')][string]$Compare,

    [Parameter(Mandatory, ParameterSetName = 'Repair')][switch]$RepairWsusId,

    # How long to wait for one machine before giving up on it. The default is deliberately short:
    # this sweeps a fleet, and the cost of a long timeout is paid once per DEAD machine, which on
    # a real domain is most of them.
    [int]$TimeoutSeconds = 15,
    # Ceiling on how many computers -FromDirectory will contact, so pointing this at a large
    # domain cannot silently turn into an all-day job. 250 sits comfortably above the ~150 a
    # domain runs here, so a normal sweep is never truncated.
    [int]$MaxMachines = 250,
    # How many machines are contacted at once. This is what keeps a fleet sweep to about a minute
    # instead of about forty: the timeout is paid once per BATCH of dead machines, not once each.
    [int]$ThrottleLimit = 32
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# NOT -Force: a forced import makes a fresh module instance and re-locks the caller's store.
if ($Target -and -not (Get-Module ADAdmin)) {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'ADAdmin\ADAdmin.psd1')
}

# What runs on each machine. Kept as one self-contained block so it can be shipped to a remote
# session unchanged -- and so the local path and the remote path collect exactly the same thing.
$Collector = {
    function Get-Reg {
        param([string]$Path, [string]$Name)
        try {
            $i = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            $p = $i.PSObject.Properties[$Name]
            if ($p) { [string]$p.Value } else { $null }
        } catch {
            # Deliberate: a registry value that is not present IS the answer here -- a machine with
            # no SusClientId has never talked to WSUS. Returning null is the finding.
            $null
        }
    }

    # The machine SID is the DOMAIN PORTION of any local account's SID. Take the built-in
    # Administrator (RID 500), which exists on every Windows installation even when disabled,
    # and strip the RID. Reading it this way needs no privilege.
    $machineSid = $null
    try {
        $admin = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE 'S-1-5-21-%-500'" -ErrorAction Stop |
                    Select-Object -First 1
        if ($admin -and $admin.SID -match '^(S-1-5-21-\d+-\d+-\d+)-500$') { $machineSid = $Matches[1] }
    } catch {
        # Deliberate: fall through to the Get-LocalUser path below, which is tried precisely
        # because this one is unavailable on some builds.
    }
    if (-not $machineSid) {
        try {
            $u = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match '-500$' } | Select-Object -First 1
            if ($u -and $u.SID.Value -match '^(S-1-5-21-\d+-\d+-\d+)-500$') { $machineSid = $Matches[1] }
        } catch {
            # Both routes failed. MachineSid stays null and is REPORTED as unknown -- never
            # silently treated as "no duplicate".
        }
    }

    $os = $null; $cs = $null
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop }
    catch { <# reported as null OS rather than failing the whole collection #> }
    try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop }
    catch { <# same: membership reads as null #> }

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        MachineSid   = $machineSid
        MachineGuid  = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Cryptography' 'MachineGuid'
        SusClientId  = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\WindowsUpdate' 'SusClientId'
        Membership   = $(if ($cs) { if ($cs.PartOfDomain) { $cs.Domain } else { "workgroup:$($cs.Workgroup)" } } else { $null })
        OsCaption    = $(if ($os) { $os.Caption } else { $null })
        InstallDate  = $(if ($os -and $os.InstallDate) { $os.InstallDate.ToString('yyyy-MM-dd HH:mm') } else { $null })
        CollectedAt  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Source       = 'local'
        Error        = $null
    }
}

# --- compare ---------------------------------------------------------------------------------------

if ($PSCmdlet.ParameterSetName -eq 'Compare') {
    if (-not (Test-Path -LiteralPath $Compare)) { throw "No collected data at '$Compare'." }
    $rows = @(Import-Csv -LiteralPath $Compare)

    $findings = @()
    foreach ($field in @('MachineSid', 'MachineGuid', 'SusClientId')) {
        $groups = $rows | Where-Object { $_.$field } | Group-Object -Property $field | Where-Object { $_.Count -gt 1 }
        foreach ($g in $groups) {
            $machines = @($g.Group | ForEach-Object { $_.ComputerName } | Select-Object -Unique)
            if ($machines.Count -lt 2) { continue }   # the same machine collected twice is not a duplicate
            $findings += [pscustomobject]@{
                Field    = $field
                Value    = $g.Name
                Machines = $machines -join ', '
                Count    = $machines.Count
                Impact   = switch ($field) {
                    'MachineSid'  { 'Local accounts on these machines share SIDs. Domain logon and GPO are NOT affected -- the computer account SID is separate and unique. Affects local ACLs, moved disks, and software keyed to the machine SID.' }
                    'MachineGuid' { 'Software that identifies the machine by MachineGuid cannot tell these apart.' }
                    'SusClientId' { 'These machines take each other''s place in WSUS -- one appears and the others vanish, and patch reporting is wrong for all of them.' }
                }
                Repair   = switch ($field) {
                    'MachineSid'  { 'Not repairable in place. sysprep /generalize or rebuild. Do NOT look for a tool to rewrite it -- NewSID was withdrawn by its author.' }
                    'MachineGuid' { 'Reported only: installed software references it, and changing it causes worse problems than it solves.' }
                    'SusClientId' { 'Run this script with -RepairWsusId ON EACH affected machine except the one you want to keep.' }
                }
            }
        }
    }

    $findings
    if (-not $findings.Count) { Write-Verbose "No duplicates across $($rows.Count) machine(s)."; exit 0 }
    Write-Warning ("$($findings.Count) duplicate identifier(s) across $($rows.Count) machine(s). " +
                   'Read the Impact column before acting -- a shared machine SID is far less serious than it looks, ' +
                   'and a shared SusClientId is far more.')
    exit 10
}

# --- repair the WSUS id ------------------------------------------------------------------------------

if ($PSCmdlet.ParameterSetName -eq 'Repair') {
    $id = $null
    try { $id = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\WindowsUpdate' -Name SusClientId -EA Stop).SusClientId }
    catch {
        # Deliberate: not set is a normal state, and the reset below still runs -- it re-registers
        # the client either way. The old id is only reported for the record.
    }
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME,
            "Reset the WSUS client id (currently $(if ($id) { $id } else { 'not set' })): stop wuauserv, clear the id and the SoftwareDistribution cache, restart, re-register")) {
        exit 0
    }
    try {
        Stop-Service wuauserv -Force -ErrorAction Stop
        foreach ($n in @('SusClientId', 'SusClientIdValidation')) {
            Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\WindowsUpdate' -Name $n -ErrorAction SilentlyContinue
        }
        $sd = Join-Path $env:SystemRoot 'SoftwareDistribution'
        if (Test-Path $sd) { Rename-Item $sd "SoftwareDistribution.old-$(Get-Date -Format yyyyMMddHHmmss)" -ErrorAction SilentlyContinue }
        Start-Service wuauserv -ErrorAction Stop
        # The client mints a new id on its next authorisation, not immediately.
        & wuauclt.exe /resetauthorization /detectnow 2>&1 | Out-Null
        [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME; OldSusClientId = $id
            Action = 'reset-wsus-id'
            Detail = 'The new id is minted at the next check-in, so it will read as empty for a few minutes. Re-collect afterwards to confirm.'
        }
    } catch {
        Write-Error "Could not reset the WSUS client id: $($_.Exception.Message)"
        exit 20
    }
    exit 0
}

# --- collect -----------------------------------------------------------------------------------------

# Filter, do not just wrap. `@($null)` is an array of ONE element that happens to be null, so a
# bare @($ComputerName) reports Count 1 when nothing was passed -- and the local collection then
# takes the REMOTE path with a null computer name.
$targets = @($ComputerName | Where-Object { $_ })

if ($FromDirectory) {
    if (-not $Target) { throw '-FromDirectory needs -Target so the directory can be queried.' }
    $targets = @(Get-AdmComputer -Target $Target -Tier $Tier -Limit $MaxMachines |
                    ForEach-Object { if ($_.DnsHostName) { $_.DnsHostName } else { $_.Name } })

    # ⚠ SAY THE SIZE OF THE JOB BEFORE STARTING IT. This contacts every machine in turn over
    # WinRM, and the ones that ANSWER are not the problem -- each one that is switched off,
    # decommissioned or firewalled costs the full connection timeout before it fails. On a real
    # domain that is the majority, and the run takes hours rather than the seconds a lab
    # suggests. Reported as a warning, not verbose, because it changes what you do next.
    $batches = [math]::Ceiling($targets.Count / [math]::Max(1, $ThrottleLimit))
    $est = [timespan]::FromSeconds($batches * $TimeoutSeconds)
    Write-Warning ("$($targets.Count) computer(s) from the directory, contacted $ThrottleLimit at a " +
                   "time over WinRM with a $TimeoutSeconds second timeout. Worst case is about " +
                   "$([math]::Round($est.TotalMinutes, 1)) minute(s) if none of them answer. Narrow it " +
                   "with -ComputerName, or raise the ceiling with -MaxMachines.")
    if ($targets.Count -ge $MaxMachines) {
        Write-Warning ("Stopped at the -MaxMachines ceiling of $MaxMachines, so this sweep is " +
                       "PARTIAL -- there are more computers in the directory than were collected.")
    }
}

$results = @()

if (-not $targets.Count) {
    $results += & $Collector
}
else {
    $cred = $null
    if ($Target) {
        try { $cred = (Get-AdmTargetContextPublic -Target $Target -Tier $Tier).Credential }
        catch { Write-Warning "Could not take a credential from the store: $($_.Exception.Message)" }
    }

    # ⛔ A BOUNDED CONNECTION ATTEMPT. Invoke-Command has no timeout parameter of its own; the
    # wait is governed by the WSMan session option, so it has to be set here. Without it an
    # unreachable machine blocks on the operating system's default, which is far longer than
    # anyone waiting on a fleet sweep would choose.
    $so = New-PSSessionOption -OpenTimeout ($TimeoutSeconds * 1000) -CancelTimeout 5000 `
                              -OperationTimeout ($TimeoutSeconds * 1000)

    # ⭐ ONE CALL WITH THE WHOLE LIST, NOT A LOOP. Invoke-Command fans out across -ThrottleLimit
    # machines at once; a foreach contacts them strictly one at a time. The difference is the
    # difference between working and not: at roughly 150 computers per domain, and a timeout paid
    # once per machine that is switched off, sequential is ~40 minutes of nothing while parallel
    # is about one. This is what locked the GUI up when pointed at a real domain.
    $splat = @{
        ComputerName  = $targets
        ScriptBlock   = $Collector
        SessionOption = $so
        ThrottleLimit = $ThrottleLimit
        ErrorAction   = 'SilentlyContinue'
        ErrorVariable = 'remoteErrors'
    }
    if ($cred) { $splat.Credential = $cred }

    $remoteErrors = @()
    $answered = @(Invoke-Command @splat)

    foreach ($r in $answered) {
        $results += [pscustomobject]@{
            ComputerName = $r.ComputerName; MachineSid = $r.MachineSid; MachineGuid = $r.MachineGuid
            SusClientId = $r.SusClientId; Membership = $r.Membership; OsCaption = $r.OsCaption
            InstallDate = $r.InstallDate; CollectedAt = $r.CollectedAt
            Source = $r.PSComputerName; Error = $null
        }
    }

    # ⛔ EVERY MACHINE THAT DID NOT ANSWER IS STILL RECORDED, as UNKNOWN. Dropping them would make
    # a partial sweep look like a complete one -- and with a fan-out the ones that fail come back
    # on the error stream rather than as exceptions, so they have to be matched back to their
    # machine by name deliberately.
    $ok = @{}
    foreach ($r in $answered) { $ok[[string]$r.PSComputerName] = $true }

    $errByHost = @{}
    foreach ($e in @($remoteErrors)) {
        $h = $null
        if ($e.OriginInfo -and $e.OriginInfo.PSComputerName) { $h = [string]$e.OriginInfo.PSComputerName }
        elseif ($e.TargetObject) { $h = [string]$e.TargetObject }
        if ($h) { $errByHost[$h] = $e.Exception.Message }
    }

    foreach ($c in $targets) {
        if ($ok.ContainsKey($c)) { continue }
        $why = if ($errByHost.ContainsKey($c)) { $errByHost[$c] } else { 'did not answer within the timeout' }
        $results += [pscustomobject]@{
            ComputerName = $c; MachineSid = $null; MachineGuid = $null; SusClientId = $null
            Membership = $null; OsCaption = $null; InstallDate = $null
            CollectedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); Source = $c
            Error = $why
        }
    }

    $reached = @($results | Where-Object { -not $_.Error }).Count
    Write-Verbose "$reached of $($targets.Count) machine(s) answered."
}

if ($AppendTo) {
    $existing = @()
    if (Test-Path -LiteralPath $AppendTo) { $existing = @(Import-Csv -LiteralPath $AppendTo) }
    # Replace any earlier row for the same machine, so re-running does not create false duplicates
    # of a machine with itself.
    $names = @($results | ForEach-Object { $_.ComputerName })
    $keep = @($existing | Where-Object { $names -notcontains $_.ComputerName })
    ($keep + $results) | Export-Csv -LiteralPath $AppendTo -NoTypeInformation -Encoding UTF8
    Write-Verbose "$AppendTo now holds $((@($keep) + @($results)).Count) machine(s)."
}

$results

$failed = @($results | Where-Object { $_.Error })
if ($failed.Count) {
    Write-Warning ("$($failed.Count) machine(s) could not be collected from and are recorded as unknown: " +
                   (($failed | ForEach-Object { $_.ComputerName }) -join ', '))
    exit 20
}
exit 0
