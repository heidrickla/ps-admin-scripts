#requires -RunAsAdministrator

# Veeam Agent local cleanup.
#
# CHANGES 2026-08-27 (three fixes; everything else is unchanged):
#   1. EXIT CODE NOW MEANS SOMETHING. It used to return 0 unless Veeam B&R was present, so
#      "everything removed" and "every uninstall failed" were indistinguishable to anything
#      calling it. Outcomes are tracked and the exit code reports them -- see the table below.
#   2. MSI 1641 is handled. It is ERROR_SUCCESS_REBOOT_INITIATED, i.e. a SUCCESS, and it was
#      falling into `default` and printing "Unexpected MSI exit code" for an uninstall that worked.
#   3. De-duplication is by PSChildName (the MSI product code), not DisplayName. Two different
#      components sharing a display name silently lost one, which would then reappear in the
#      post-cleanup check as "remaining" with no explanation.
#
# EXIT CODES
#   0   clean -- no targeted components remain
#   3   removed, but a REBOOT IS REQUIRED to finish
#   10  aborted: Veeam Backup & Replication is installed on this machine
#   20  one or more components failed to uninstall
#   21  uninstalls reported success, but targeted components are still registered

[CmdletBinding()]
param(
    # Which machines to clean. Omit for this one. Everything below acts on the local box -- the
    # uninstalls, the registry sweep, the transcript in C:\ProgramData -- so without this there
    # was no way to point it at anything but the machine you are sitting at.
    [string[]]$ComputerName,
    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Continue'

# --- run somewhere else, if asked ------------------------------------------------------------
#
# ⭐ THE SCRIPT SENDS ITSELF: its own text is rebuilt as a scriptblock on the far side, so the
# cleanup logic below is written once and is identical local or remote. -ComputerName is not
# forwarded, or the remote copy would try to hop again.
#
# ⚠ THE `#requires -RunAsAdministrator` AT THE TOP IS NOT ENFORCED ON THE FAR SIDE -- it applies
# to script FILES, not to a recreated scriptblock. In practice a WinRM session for an
# administrator is already elevated, but that is the session's doing, not this line's.
if ($ComputerName) {
    $body = [System.IO.File]::ReadAllText($PSCommandPath)
    $remote = {
        param($Body)
        $sb = [scriptblock]::Create($Body)
        $out = & $sb *>&1 | Out-String
        [pscustomobject]@{ Machine = $env:COMPUTERNAME; Output = $out; Code = $LASTEXITCODE }
    }
    $splat = @{ ComputerName = $ComputerName; ScriptBlock = $remote; ArgumentList = @($body)
                ErrorAction = 'SilentlyContinue'; ErrorVariable = 'remoteErr' }
    if ($Credential) { $splat['Credential'] = $Credential }

    $remoteErr = @()
    $answers = @(Invoke-Command @splat)
    $worst = 0
    foreach ($a in $answers) {
        "===== $($a.Machine) ====="
        $a.Output.TrimEnd()
        $c = 0; [void][int]::TryParse([string]$a.Code, [ref]$c)
        if ($c -gt $worst) { $worst = $c }
    }
    foreach ($e in @($remoteErr)) {
        Write-Warning "unreachable: $($e.Exception.Message)"
        if ($worst -lt 20) { $worst = 20 }
    }
    exit $worst
}

$LogDir = 'C:\ProgramData\VeeamAgentCleanup'
$LogFile = Join-Path $LogDir "Cleanup-$(Get-Date -Format yyyyMMdd-HHmmss).log"

New-Item -Path $LogDir -ItemType Directory -Force | Out-Null

Start-Transcript -Path $LogFile -Force

# Outcome tracking. Populated as each component is processed and read at the very bottom.
$Failures = @()
$RebootRequired = $false

Write-Host ""
Write-Host "=============================================="
Write-Host " VEEAM AGENT LOCAL CLEANUP"
Write-Host "=============================================="
Write-Host "Computer : $env:COMPUTERNAME"
Write-Host "Log      : $LogFile"
Write-Host ""

# -------------------------------------------------------------
# Find installed software from uninstall registry
# -------------------------------------------------------------

$UninstallPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

# The agent-side components this script is allowed to remove. Defined once so the post-cleanup
# check can ask the SAME question it asked before -- previously the final check looked for any
# '*Veeam*', which also matches components this script never targets.
$TargetPattern = '^Veeam Agent for Microsoft Windows|^Veeam Installer Service|^Veeam.*Transport|^Veeam CBT|^Veeam OpenSSL'

$Installed = foreach ($Path in $UninstallPaths) {
    Get-ItemProperty $Path -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName }
}

$Veeam = $Installed |
    Where-Object {
        $_.DisplayName -like '*Veeam*'
    } |
    Sort-Object PSChildName -Unique

Write-Host "Detected Veeam products:"
Write-Host ""

if (-not $Veeam) {
    Write-Warning "No Veeam products were found in Windows uninstall registry."
}
else {
    $Veeam |
        Select-Object DisplayName, DisplayVersion, PSChildName |
        Format-Table -AutoSize
}

# -------------------------------------------------------------
# SAFETY CHECK
# -------------------------------------------------------------

$VBR = $Veeam |
    Where-Object {
        $_.DisplayName -match 'Backup.*Replication'
    }

if ($VBR) {
    Write-Host ""
    Write-Error "Veeam Backup & Replication appears to be installed on this server."
    Write-Error "ABORTING."
    Stop-Transcript
    exit 10
}

# -------------------------------------------------------------
# Remove VBR ownership if configurator exists
# -------------------------------------------------------------

$ConfiguratorPaths = @(
    "$env:ProgramFiles\Veeam\Endpoint Backup\Veeam.Agent.Configurator.exe",
    "${env:ProgramFiles(x86)}\Veeam\Endpoint Backup\Veeam.Agent.Configurator.exe"
)

$Configurator = $ConfiguratorPaths |
    Where-Object { Test-Path $_ } |
    Select-Object -First 1

if ($Configurator) {

    Write-Host ""
    Write-Host "Found Agent Configurator:"
    Write-Host $Configurator

    Write-Host ""
    Write-Host "Removing VBR ownership..."

    try {
        & $Configurator -removeOwner /i /force

        Write-Host "Configurator exit code: $LASTEXITCODE"
    }
    catch {
        Write-Warning "Could not remove ownership:"
        Write-Warning $_.Exception.Message
    }

}
else {
    Write-Warning "Veeam.Agent.Configurator.exe was not found."
}

# -------------------------------------------------------------
# Stop Veeam services
# -------------------------------------------------------------

Write-Host ""
Write-Host "Stopping Veeam services..."
Write-Host ""

$VeeamServices = Get-Service |
    Where-Object {
        $_.Name -like '*Veeam*' -or
        $_.DisplayName -like '*Veeam*'
    }

foreach ($Service in $VeeamServices) {

    Write-Host "$($Service.Name) - $($Service.Status)"

    if ($Service.Status -ne 'Stopped') {

        try {
            Stop-Service -Name $Service.Name -Force -ErrorAction Stop
            Write-Host "  Stopped."
        }
        catch {
            Write-Warning "  Could not stop: $($_.Exception.Message)"
        }
    }
}

# -------------------------------------------------------------
# Refresh installed Veeam inventory
# -------------------------------------------------------------

$Installed = foreach ($Path in $UninstallPaths) {
    Get-ItemProperty $Path -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName }
}

# -------------------------------------------------------------
# Only target Agent-side Veeam components
# -------------------------------------------------------------

$Targets = $Installed |
    Where-Object {
        $_.DisplayName -match $TargetPattern
    } |
    Sort-Object PSChildName -Unique

Write-Host ""
Write-Host "Components selected for uninstall:"
Write-Host ""

if (-not $Targets) {

    Write-Warning "No matching Agent components found."

}
else {

    $Targets |
        Select-Object DisplayName, DisplayVersion, PSChildName |
        Format-Table -AutoSize
}

# -------------------------------------------------------------
# Uninstall
# -------------------------------------------------------------

foreach ($Product in $Targets) {

    Write-Host ""
    Write-Host "----------------------------------------------"
    Write-Host "Uninstalling: $($Product.DisplayName)"
    Write-Host "Version     : $($Product.DisplayVersion)"
    Write-Host "----------------------------------------------"

    $ProductCode = $null

    # MSI product GUID normally exists as registry key name
    if ($Product.PSChildName -match '^\{[A-Fa-f0-9-]{36}\}$') {

        $ProductCode = $Product.PSChildName

    }
    elseif ($Product.UninstallString -match '\{[A-Fa-f0-9-]{36}\}') {

        $ProductCode = $Matches[0]
    }

    if ($ProductCode) {

        Write-Host "MSI Product Code: $ProductCode"

        $Arguments = @(
            '/x'
            $ProductCode
            '/qn'
            '/norestart'
            'REBOOT=ReallySuppress'
        )

        Write-Host "Running msiexec..."

        $Process = Start-Process `
            -FilePath 'msiexec.exe' `
            -ArgumentList $Arguments `
            -Wait `
            -PassThru

        Write-Host "Exit code: $($Process.ExitCode)"

        switch ($Process.ExitCode) {

            0 {
                Write-Host "SUCCESS: Removed."
            }

            1605 {
                Write-Host "SUCCESS: Product was already removed."
            }

            1618 {
                Write-Warning "Another MSI installation is currently running."
                $Failures += "$($Product.DisplayName) (1618: another installation in progress -- retry)"
            }

            1619 {
                Write-Warning "Windows Installer could not locate installation package."
                $Failures += "$($Product.DisplayName) (1619: installation package not found)"
            }

            1603 {
                Write-Warning "MSI returned fatal error 1603."
                $Failures += "$($Product.DisplayName) (1603: fatal error during uninstall)"
            }

            3010 {
                Write-Host "SUCCESS: Removed. REBOOT REQUIRED."
                $RebootRequired = $true
            }

            1641 {
                # ERROR_SUCCESS_REBOOT_INITIATED -- a SUCCESS code. Windows Installer has begun
                # a restart. Without this case it fell into `default` and was reported as an
                # unexpected failure for an uninstall that had actually worked.
                Write-Host "SUCCESS: Removed. REBOOT HAS BEEN INITIATED BY WINDOWS INSTALLER."
                $RebootRequired = $true
            }

            default {
                Write-Warning "Unexpected MSI exit code: $($Process.ExitCode)"
                $Failures += "$($Product.DisplayName) (unexpected MSI exit code $($Process.ExitCode))"
            }
        }

    }
    else {

        Write-Warning "Could not determine MSI Product Code."
        Write-Host "Registered uninstall command:"
        Write-Host $Product.UninstallString
        $Failures += "$($Product.DisplayName) (no MSI product code could be determined)"
    }
}

# -------------------------------------------------------------
# Final inventory
# -------------------------------------------------------------

Write-Host ""
Write-Host "=============================================="
Write-Host " POST-CLEANUP CHECK"
Write-Host "=============================================="
Write-Host ""

$Remaining = foreach ($Path in $UninstallPaths) {

    Get-ItemProperty $Path -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DisplayName -like '*Veeam*'
        }
}

$Remaining = $Remaining | Sort-Object PSChildName -Unique

# Only components this script actually TARGETED count against success. Other Veeam products may
# be legitimately installed and are none of this script's business.
$RemainingTargets = $Remaining |
    Where-Object { $_.DisplayName -match $TargetPattern }

if ($Remaining) {

    Write-Host "Remaining Veeam products:"
    Write-Host ""

    $Remaining |
        Select-Object DisplayName, DisplayVersion |
        Sort-Object DisplayName |
        Format-Table -AutoSize

}
else {

    Write-Host "No Veeam products remain registered."
}

Write-Host ""
Write-Host "Remaining Veeam services:"
Write-Host ""

Get-Service |
    Where-Object {
        $_.Name -like '*Veeam*' -or
        $_.DisplayName -like '*Veeam*'
    } |
    Format-Table Name, DisplayName, Status -AutoSize

# -------------------------------------------------------------
# Verdict
# -------------------------------------------------------------
# Say what happened in one place, and make the exit code agree with it. A caller that only sees
# the exit code and a caller that reads the log must reach the same conclusion.

Write-Host ""
Write-Host "=============================================="
Write-Host " RESULT"
Write-Host "=============================================="
Write-Host ""

$ExitCode = 0

if ($Failures.Count) {

    $ExitCode = 20

    Write-Host "FAILED: $($Failures.Count) component(s) did not uninstall cleanly."
    Write-Host ""

    foreach ($f in $Failures) {
        Write-Host "  - $f"
    }
}
elseif ($RemainingTargets) {

    $ExitCode = 21

    Write-Host "FAILED: every uninstall reported success, but these targeted components are still registered:"
    Write-Host ""

    $RemainingTargets |
        Select-Object DisplayName, DisplayVersion, PSChildName |
        Format-Table -AutoSize
}
elseif ($RebootRequired) {

    $ExitCode = 3

    Write-Host "SUCCESS, PENDING REBOOT: all targeted components were removed."
}
else {

    Write-Host "SUCCESS: no targeted Veeam components remain."
}

Write-Host ""
Write-Host "Cleanup finished with exit code $ExitCode."
Write-Host "Log file: $LogFile"
Write-Host ""
Write-Host "REBOOT THE SERVER before attempting VBR redeployment."
Write-Host ""

Stop-Transcript

exit $ExitCode
