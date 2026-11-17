<#
.SYNOPSIS
  Join or leave a domain, rename the machine, manage its AD group membership, and set up time.

.DESCRIPTION
  ⚠ THIS ONE RUNS ON THE MACHINE IT CHANGES. Every other script here talks to a directory over
  LDAP from wherever you are; this one joins, renames and reconfigures the computer it is
  executed on. Group membership is the exception -- that is an LDAP write against the domain, and
  goes through the credential store like everything else.

  ⛔ THE MOST IMPORTANT THING THIS SCRIPT DOES IS REFUSE TO LOCK YOU OUT.
  When a machine leaves a domain, every domain account stops being able to sign in to it. If the
  local Administrator is disabled or its password is unknown -- the normal state on a
  domain-joined machine -- the machine becomes unreachable the moment it reboots, and the fix is
  a recovery disc. So -Action Leave REQUIRES -LocalAdminPassword, sets it, verifies the account
  is enabled, and proves the credential works BEFORE it unjoins anything.

  ⚠ TIME: A DOMAIN MEMBER SHOULD NOT USE A MANUAL PEER LIST. Domain members take time from the
  domain hierarchy, which ultimately comes from the PDC emulator. Pointing every member at an
  external server is a common and damaging misconfiguration -- it competes with the domain
  hierarchy and causes exactly the Kerberos skew failures it looks like it should prevent. So:

    workgroup machine        -> manual peer list (the -NtpServer values)
    domain member           -> /syncfromflags:domhier, and the peer list is IGNORED
    the PDC emulator itself -> manual peer list, because it IS the domain's time root

  The script works out which case applies and says so. -ForceManualPeers overrides it if you have
  a reason.

.PARAMETER Target
  The domain, for the LDAP-side work (group membership, PDC lookup). Resolved through ADAdmin's
  credential store, so the join credential does not have to be typed.

.PARAMETER NtpServer
  Time sources for the manual-peer cases. There is no default. When none are given, the machine is
  left on the domain hierarchy time source (/syncfromflags:domhier) and no manual peers are set.

.EXAMPLE
  .\Set-ComputerDomainMembership.ps1 -Action Report -Target corp.example.com
.EXAMPLE
  .\Set-ComputerDomainMembership.ps1 -Action Join -Target corp.example.com -NewName WS-042 -Restart
.EXAMPLE
  .\Set-ComputerDomainMembership.ps1 -Action Leave -LocalAdminPassword $p -Restart

.NOTES
  ⚠ VERIFICATION STATUS, stated plainly: -Action Report and -Action ConfigureNtp were exercised.
  Join, Leave and Rename CANNOT be tested from the development environment -- doing so would
  unjoin a working machine -- so those paths are written from the documented APIs and are
  UNVERIFIED. Run them on a disposable machine first.

  EXIT CODES
    0   done, or nothing to do
    3   done, but a REBOOT IS REQUIRED to finish
    10  refused for a safety reason (the message says which)
    20  a step failed
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Report', 'Join', 'Leave', 'Rename', 'ConfigureNtp', 'AddToGroup', 'RemoveFromGroup')]
    [string]$Action = 'Report',

    [string]$Target,
    [string]$NewName,
    [string]$OUPath,
    [string]$Group,
    [string]$ComputerName = $env:COMPUTERNAME,

    # Required to LEAVE a domain. Without a working local administrator, unjoining strands the
    # machine at the next reboot.
    [System.Security.SecureString]$LocalAdminPassword,
    [string]$LocalAdminName = 'Administrator',

    [string[]]$NtpServer = @(),
    [switch]$UseDomainControllers,
    [switch]$ForceManualPeers,

    [switch]$Restart,
    [string]$Tier
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# NOT -Force: a forced import makes a fresh module instance and re-locks the caller's store.
if ($Target -and -not (Get-Module ADAdmin)) {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'ADAdmin\ADAdmin.psd1')
}

function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object System.Security.Principal.WindowsPrincipal($id)).IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-MembershipState {
    $cs = Get-CimInstance Win32_ComputerSystem
    [pscustomobject]@{
        ComputerName = $cs.Name
        PartOfDomain = [bool]$cs.PartOfDomain
        Domain       = $cs.Domain
        Workgroup    = $cs.Workgroup
    }
}

# Which time role this machine is in. The answer decides whether a manual peer list is correct
# or actively harmful.
function Get-TimeRole {
    param($State)
    if (-not $State.PartOfDomain) { return 'workgroup' }
    if (-not $Target) { return 'domain-member (PDC role not checked -- no -Target given)' }
    try {
        $ctx = Get-AdmTargetContextPublic -Target $Target -Tier $Tier
        $e = New-AdmDirectoryEntry -Domain $ctx.Domain -Credential $ctx.Credential `
                -DistinguishedName (ConvertTo-AdmDistinguishedName -DnsDomain $ctx.Domain.DnsDomain)
        try {
            $e.RefreshCache()
            $owner = [string]$e.Properties['fSMORoleOwner'].Value
            # "CN=NTDS Settings,CN=DC01,..." -- the second RDN is the server.
            $pdc = if ($owner -match '^CN=NTDS Settings,CN=([^,]+),') { $Matches[1] } else { $null }
            if ($pdc -and $pdc -eq $State.ComputerName) { 'pdc-emulator' } else { "domain-member (PDC is $pdc)" }
        } finally { Close-AdmDirectoryEntry $e }
    } catch {
        "domain-member (could not identify the PDC emulator -- $($_.Exception.Message))"
    }
}

function Get-CurrentNtpConfig {
    $out = [pscustomobject]@{ Source = $null; PeerList = $null; SyncFromFlags = $null }
    try { $out.Source = (& w32tm /query /source 2>&1 | Out-String).Trim() }
    catch {
        # Deliberate: w32tm missing or the service stopped IS the answer. The caller sees a null
        # Source and reports it -- as it did on this workstation, where w32time is not running.
    }
    try {
        $cfg = & w32tm /query /configuration 2>&1 | Out-String
        if ($cfg -match '(?im)^\s*NtpServer:\s*(.+?)\s*$')     { $out.PeerList = $Matches[1].Trim() }
        if ($cfg -match '(?im)^\s*Type:\s*(.+?)\s*$')          { $out.SyncFromFlags = $Matches[1].Trim() }
    }
    catch {
        # Same: an unreadable configuration leaves the fields null, which the report shows.
    }
    $out
}

$state = Get-MembershipState
$rebootRequired = $false

# --- report -------------------------------------------------------------------------------------

if ($Action -eq 'Report') {
    $ntp = Get-CurrentNtpConfig
    $role = Get-TimeRole -State $state
    $la = $null
    try { $la = Get-LocalUser -Name $LocalAdminName -ErrorAction Stop }
    catch {
        # Deliberate: the account not existing is a REPORTED FINDING, not an error. It is exactly
        # what makes SafeToLeaveDomain false, which is the whole point of this row.
    }

    [pscustomobject]@{
        ComputerName        = $state.ComputerName
        PartOfDomain        = $state.PartOfDomain
        Domain              = $(if ($state.PartOfDomain) { $state.Domain } else { $state.Workgroup })
        TimeRole            = $role
        RecommendedTimeMode = $(if ($role -eq 'workgroup' -or $role -eq 'pdc-emulator') { 'manual peer list' } else { 'domain hierarchy (domhier)' })
        NtpSource           = $ntp.Source
        NtpPeerList         = $ntp.PeerList
        NtpType             = $ntp.SyncFromFlags
        LocalAdminName      = $LocalAdminName
        LocalAdminExists    = [bool]$la
        LocalAdminEnabled   = $(if ($la) { $la.Enabled } else { $null })
        # The point of surfacing this: if it is false, LEAVING THE DOMAIN WILL STRAND THIS MACHINE.
        SafeToLeaveDomain   = [bool]($la -and $la.Enabled)
        Elevated            = Test-IsElevated
    }
    exit 0
}

if (-not (Test-IsElevated)) {
    Write-Error "This action changes the computer and needs administrator rights. Re-run elevated."
    exit 10
}

# --- group membership (an LDAP write, not a local change) ------------------------------------------

if ($Action -in @('AddToGroup', 'RemoveFromGroup')) {
    if (-not $Target -or -not $Group) { Write-Error 'AddToGroup/RemoveFromGroup need -Target and -Group.'; exit 10 }
    $r = if ($Action -eq 'AddToGroup') {
        Add-AdmGroupMember -Target $Target -Group $Group -Identity $ComputerName -MemberType Computer `
            -Tier $Tier -WhatIf:$WhatIfPreference -Confirm:$false
    } else {
        Remove-AdmGroupMember -Target $Target -Group $Group -Identity $ComputerName -MemberType Computer `
            -Tier $Tier -WhatIf:$WhatIfPreference -Confirm:$false
    }
    $r
    exit 0
}

# --- time -----------------------------------------------------------------------------------------

if ($Action -eq 'ConfigureNtp') {
    $role = Get-TimeRole -State $state
    $useManual = $ForceManualPeers -or $role -eq 'workgroup' -or $role -eq 'pdc-emulator'

    $peers = @($NtpServer | Where-Object { $_ })
    if ($UseDomainControllers) {
        if (-not $Target) { Write-Error '-UseDomainControllers needs -Target so the DCs can be looked up.'; exit 10 }
        try {
            $ctx = Get-AdmTargetContextPublic -Target $Target -Tier $Tier
            $peers = @($ctx.Domain.DomainControllers) | Where-Object { $_ }
            if (-not $peers.Count) { $peers = @($ctx.Domain.DnsDomain) }
        } catch { Write-Error "Could not look up the domain controllers: $($_.Exception.Message)"; exit 20 }
    }

    if ($useManual -and -not $peers.Count) {
        Write-Warning ('No -NtpServer (or -UseDomainControllers) was given, so no manual peers are set. ' +
                       'Leaving this machine on the domain hierarchy time source.')
        $useManual = $false
    } elseif (-not $useManual) {
        Write-Warning ("This machine is a $role, so it should take time from the DOMAIN HIERARCHY, " +
                       "not from a manual peer list. Configuring it as domhier and IGNORING " +
                       "$($peers -join ', '). Pass -ForceManualPeers if you really want manual peers " +
                       "here -- but on a domain member that competes with the domain time source and " +
                       "causes the skew it looks like it prevents.")
    }

    $args_ = if ($useManual) {
        @('/config', "/manualpeerlist:`"$($peers -join ' ')`"", '/syncfromflags:manual', '/reliable:no', '/update')
    } else {
        @('/config', '/syncfromflags:domhier', '/update')
    }

    $what = if ($useManual) { "manual peers: $($peers -join ', ')" } else { 'domain hierarchy' }
    if ($PSCmdlet.ShouldProcess($state.ComputerName, "Configure Windows Time to use $what")) {
        $out = & w32tm @args_ 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { Write-Error "w32tm failed: $($out.Trim())"; exit 20 }
        # Restart the service so the change takes effect, then prove it by re-reading.
        Restart-Service w32time -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        [void](& w32tm /resync 2>&1)
        $after = Get-CurrentNtpConfig
        [pscustomobject]@{
            ComputerName = $state.ComputerName; TimeRole = $role; Mode = $what
            NtpTypeNow = $after.SyncFromFlags; NtpPeerListNow = $after.PeerList; SourceNow = $after.Source
        }
    }
    exit 0
}

# --- rename ----------------------------------------------------------------------------------------

if ($Action -eq 'Rename') {
    if (-not $NewName) { Write-Error 'Rename needs -NewName.'; exit 10 }
    if ($PSCmdlet.ShouldProcess("$($state.ComputerName) -> $NewName", 'Rename this computer')) {
        # A domain-joined rename needs domain rights, because the computer object is renamed too.
        if ($state.PartOfDomain -and $Target) {
            $ctx = Get-AdmTargetContextPublic -Target $Target -Tier $(if ($Tier) { $Tier } else { 'write' })
            Rename-Computer -NewName $NewName -DomainCredential $ctx.Credential -Force -ErrorAction Stop
        } else {
            Rename-Computer -NewName $NewName -Force -ErrorAction Stop
        }
        $rebootRequired = $true
        [pscustomobject]@{ ComputerName = $state.ComputerName; NewName = $NewName; Action = 'rename'; RebootRequired = $true }
    }
}

# --- leave ------------------------------------------------------------------------------------------

if ($Action -eq 'Leave') {
    if (-not $state.PartOfDomain) { Write-Warning "This machine is not domain-joined (workgroup $($state.Workgroup))."; exit 0 }
    if (-not $LocalAdminPassword) {
        Write-Error ('Refusing to leave the domain without -LocalAdminPassword. Once this machine ' +
                     'leaves, no domain account can sign in to it -- if the local administrator is ' +
                     'disabled or its password is unknown, the machine is unreachable after the next ' +
                     'reboot and needs a recovery disc.')
        exit 10
    }

    # Set it, enable it, and PROVE it works -- before unjoining anything. Verifying by effect,
    # because "the command succeeded" is not evidence that you can actually sign in.
    if ($PSCmdlet.ShouldProcess($state.ComputerName, "Set and verify the local '$LocalAdminName' password, then leave $($state.Domain)")) {
        try {
            $la = Get-LocalUser -Name $LocalAdminName -ErrorAction Stop
            Set-LocalUser -Name $LocalAdminName -Password $LocalAdminPassword -ErrorAction Stop
            if (-not $la.Enabled) { Enable-LocalUser -Name $LocalAdminName -ErrorAction Stop }
        } catch {
            Write-Error "Could not prepare the local '$LocalAdminName' account, so the domain was NOT left: $($_.Exception.Message)"
            exit 10
        }

        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
                [System.DirectoryServices.AccountManagement.ContextType]::Machine)
        try {
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringUni(
                        [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($LocalAdminPassword))
            $ok = $pc.ValidateCredentials($LocalAdminName, $plain)
            $plain = $null
        } finally { $pc.Dispose() }

        if (-not $ok) {
            Write-Error ("The local '$LocalAdminName' password was set but did NOT validate, so the " +
                         'domain was NOT left. Fix the local account first -- leaving now would strand this machine.')
            exit 10
        }

        Remove-Computer -UnjoinDomainCredential $(
            if ($Target) { (Get-AdmTargetContextPublic -Target $Target -Tier $(if ($Tier) { $Tier } else { 'write' })).Credential }
            else { Get-Credential -Message 'Domain credential to remove the computer account' }
        ) -Force -PassThru -ErrorAction Stop | Out-Null
        $rebootRequired = $true
        [pscustomobject]@{ ComputerName = $state.ComputerName; LeftDomain = $state.Domain
                           LocalAdminVerified = $true; Action = 'leave'; RebootRequired = $true }
    }
}

# --- join --------------------------------------------------------------------------------------------

if ($Action -eq 'Join') {
    if (-not $Target) { Write-Error 'Join needs -Target (the domain to join).'; exit 10 }
    $ctx = Get-AdmTargetContextPublic -Target $Target -Tier $(if ($Tier) { $Tier } else { 'write' })
    $domainDns = $ctx.Domain.DnsDomain

    $desc = "Join $domainDns" + $(if ($NewName) { " as $NewName" } else { '' }) + $(if ($OUPath) { " into $OUPath" } else { '' })
    if ($PSCmdlet.ShouldProcess($state.ComputerName, $desc)) {
        $splat = @{ DomainName = $domainDns; Credential = $ctx.Credential; Force = $true; ErrorAction = 'Stop' }
        if ($NewName) { $splat.NewName = $NewName }
        if ($OUPath)  { $splat.OUPath  = $OUPath }
        Add-Computer @splat
        $rebootRequired = $true
        [pscustomobject]@{ ComputerName = $state.ComputerName; JoinedDomain = $domainDns
                           NewName = $NewName; OUPath = $OUPath; Action = 'join'; RebootRequired = $true }
    }
}

# --- verdict -------------------------------------------------------------------------------------------

if ($rebootRequired) {
    if ($Restart) {
        if ($PSCmdlet.ShouldProcess($state.ComputerName, 'Restart now to complete the change')) {
            Restart-Computer -Force
        }
    } else {
        Write-Warning 'A REBOOT IS REQUIRED before this change takes effect. Re-run with -Restart, or reboot manually.'
    }
    exit 3
}
exit 0
