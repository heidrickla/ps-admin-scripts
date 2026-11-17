# NOTE: deliberately NO `#requires -RunAsAdministrator`. That is file-level and would block
# -Report, which only reads and needs no privilege at all -- making the safe, diagnostic mode the
# hardest one to run. Elevation is checked at the point of WRITING instead, and refused clearly.
<#
.SYNOPSIS
  Apply (or just report) a baseline UAC profile on this machine.

.DESCRIPTION
  The golden profile is a fixed baseline: UAC on, with administrators elevated without a prompt.
  See docs/development-notes.md for the values.

  Under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:

    EnableLUA                  1   UAC subsystem ON -- deliberately NOT "disabled"
    ConsentPromptBehaviorAdmin 0   admins elevate SILENTLY, no prompt ("Never notify")
    ConsentPromptBehaviorUser  0   standard-user elevation is auto-denied
    PromptOnSecureDesktop      0   no secure-desktop dim

  Windows ships 5 / 3 / 1 for the last three, so a stock machine differs from golden on all of them.

  ⚠ WHAT THIS POSTURE MEANS, stated once and plainly: UAC stays ON, but an administrator elevates
  with no consent dialog, so `Start-Process -Verb RunAs` succeeds silently and unattended. That is
  the point -- it is what gives scripts and scheduled jobs a standing elevation path -- and it is
  also a real reduction in interactive protection on a shared or user-facing machine. Apply it to
  runners, not to someone's daily workstation, unless that is the deliberate intent.

  ⚠ EnableLUA IS NOT LIVE UNTIL A REBOOT. The other three take effect immediately. A machine that
  had UAC fully off (EnableLUA=0) is still effectively off until it restarts, so this script exits
  3 to say so rather than claiming success.

  ⚠ LocalAccountTokenFilterPolicy and FilterAdministratorToken are deliberately LEFT UNSET in
  golden. This script reports them if present and never removes them: an
  Administrators-group member can already get a FULL token over Windows OpenSSH regardless of UAC,
  and deleting those values could take away someone's remote admin path.
  That is a decision for a person, not for a script.

.PARAMETER Report
  Read and report only. Makes no change whatever, and is safe to run anywhere at any time.

.EXAMPLE
  .\Set-UacGoldenPolicy.ps1 -Report

.EXAMPLE
  .\Set-UacGoldenPolicy.ps1 -WhatIf

.OUTPUTS
  One object per value: Name, Desired, Current, State, Action. State is compliant / drift /
  missing / extra.

.NOTES
  EXIT CODES
    0   already compliant, or applied and live
    3   applied, but a REBOOT IS REQUIRED before EnableLUA takes effect
    20  one or more values could not be written, or did not read back as written
    30  reporting only: the machine is NOT compliant (with -Report)
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Report,
    # Which machines to act on. Omit for this one. This script writes under HKLM, so without it
    # there was no way to point it at anything but the box you are sitting at.
    [string[]]$ComputerName,
    # For reaching a machine in a forest this workstation has no rights in.
    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'
# Safe here because every property access below is guarded -- a registry value that does not exist
# is a normal state for this script and is read through PSObject.Properties rather than directly.
Set-StrictMode -Version 2.0

# --- run somewhere else, if asked ------------------------------------------------------------
#
# ⭐ THE SCRIPT SENDS ITSELF. Rather than restructuring the whole body into a scriptblock, the
# file's own text is rebuilt as a scriptblock on the far side and called with the SAME parameters
# by splatting -- so the logic below is written once and behaves identically local or remote.
# -ComputerName is deliberately left out of what is forwarded, or the remote copy would try to
# hop again.
#
# ⚠ `#requires` IS NOT ENFORCED ON A RECREATED SCRIPTBLOCK -- it only applies to script FILES. The
# elevation check further down is what actually guards the write, and it runs on the far side
# where it belongs.
if ($ComputerName) {
    $forward = @{}
    if ($Report) { $forward['Report'] = $true }
    if ($WhatIfPreference) { $forward['WhatIf'] = $true }

    $body = [System.IO.File]::ReadAllText($PSCommandPath)
    $remote = {
        param($Body, $P)
        $sb = [scriptblock]::Create($Body)
        # *>&1 so warnings and errors come back with the output instead of being lost at the far
        # end -- on this script the warnings ARE the finding.
        $out = & $sb @P *>&1 | Out-String
        [pscustomobject]@{ Machine = $env:COMPUTERNAME; Output = $out; Code = $LASTEXITCODE }
    }

    $splat = @{ ComputerName = $ComputerName; ScriptBlock = $remote
                ArgumentList = @($body, $forward); ErrorAction = 'SilentlyContinue'
                ErrorVariable = 'remoteErr' }
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
    # A machine that could not be reached is reported, never silently dropped -- otherwise a
    # partial sweep reads as a clean one.
    foreach ($e in @($remoteErr)) {
        Write-Warning "unreachable: $($e.Exception.Message)"
        if ($worst -lt 20) { $worst = 20 }
    }
    exit $worst
}

$PolicyKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

# The golden profile, as data. Kept in one place so the report and the apply cannot disagree.
$Golden = [ordered]@{
    EnableLUA                  = 1
    ConsentPromptBehaviorAdmin = 0
    ConsentPromptBehaviorUser  = 0
    PromptOnSecureDesktop      = 0
}

# Present in golden by their ABSENCE. Reported, never removed -- see the note above.
$MustBeUnset = @('LocalAccountTokenFilterPolicy', 'FilterAdministratorToken')

# Only EnableLUA needs a restart; the rest are live the moment they are written.
$NeedsReboot = @('EnableLUA')

function Get-UacValue {
    param([string]$Name)
    # -ErrorAction SilentlyContinue on the PROPERTY: a missing value is a normal state here, not
    # a failure, and it must be distinguishable from a value that is present and set to 0.
    $item = Get-ItemProperty -Path $PolicyKey -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    $prop = $item.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    [int]$prop.Value
}

function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object System.Security.Principal.WindowsPrincipal($id)).IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Refuse BEFORE touching anything, not partway through. A half-applied UAC profile is a worse
# state than the one we started in.
if (-not $Report -and -not (Test-IsElevated)) {
    Write-Error ('Applying the golden UAC profile needs administrator rights, and this session ' +
                 'does not have them. Re-run elevated, or use -Report to see what would change.')
    exit 20
}

$results = @()
$failures = @()
$rebootRequired = $false

foreach ($name in $Golden.Keys) {

    $desired = [int]$Golden[$name]
    $current = Get-UacValue -Name $name

    $state = if ($null -eq $current) { 'missing' }
             elseif ($current -eq $desired) { 'compliant' }
             else { 'drift' }

    $action = 'none'

    if ($state -ne 'compliant' -and -not $Report) {

        $what = "$name : $(if ($null -eq $current) { '(not set)' } else { $current }) -> $desired"

        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Set UAC policy $what")) {

            try {
                New-ItemProperty -Path $PolicyKey -Name $name -PropertyType DWord `
                    -Value $desired -Force -ErrorAction Stop | Out-Null

                # Read it back. A write that reported success and did not land is exactly the
                # failure this script exists to make impossible to miss.
                $after = Get-UacValue -Name $name

                if ($after -eq $desired) {
                    $action = 'set'
                    $current = $after
                    $state = 'compliant'
                    if ($NeedsReboot -contains $name) { $rebootRequired = $true }
                }
                else {
                    $action = 'set-but-did-not-stick'
                    $failures += "$name read back as '$after' after being set to '$desired'"
                }
            }
            catch {
                $action = 'failed'
                $failures += "$name could not be written: $($_.Exception.Message)"
            }
        }
        else {
            $action = 'skipped'
        }
    }

    $results += [pscustomobject]@{
        Name        = $name
        Desired     = $desired
        Current     = $current
        State       = $state
        Action      = $action
        # Both of these describe THIS run. Saying "not live until reboot" about a value nobody
        # touched is just wrong, and it is the kind of wrong that makes someone reboot for nothing.
        LiveNow     = -not ($NeedsReboot -contains $name -and $action -eq 'set')
        Note        = if ($NeedsReboot -contains $name -and $action -eq 'set') {
                          'CHANGED -- not live until this machine reboots'
                      } elseif ($NeedsReboot -contains $name) {
                          'changes to this value require a reboot'
                      } else { '' }
    }
}

# The two that golden defines by absence.
foreach ($name in $MustBeUnset) {

    $current = Get-UacValue -Name $name

    $results += [pscustomobject]@{
        Name    = $name
        Desired = '(unset)'
        Current = $current
        State   = if ($null -eq $current) { 'compliant' } else { 'extra' }
        Action  = if ($null -eq $current) { 'none' } else { 'reported only -- removing this may remove someone''s remote admin path' }
        LiveNow = $true
        Note    = 'golden leaves this unset; this script never removes it'
    }
}

$results

# --- verdict -------------------------------------------------------------------------------------
# The exit code and the objects above must agree. A caller reading only one of them should reach
# the same conclusion as a caller reading the other.

$notCompliant = @($results | Where-Object { $_.State -ne 'compliant' })

if ($failures.Count) {
    foreach ($f in $failures) { Write-Error $f }
    exit 20
}

if ($Report) {
    if ($notCompliant.Count) {
        # Name them. An exit code of 30 with no explanation is the kind of result people learn to
        # ignore -- especially the 'extra' rows, which this script deliberately never fixes, so
        # that code cannot be cleared without a human deciding to act.
        Write-Warning ("Not compliant with the golden UAC profile -- " +
                       (($notCompliant | ForEach-Object { "$($_.Name) [$($_.State)]" }) -join ', '))
        if (@($notCompliant | Where-Object { $_.State -eq 'extra' }).Count) {
            Write-Warning ('An "extra" row is a value golden leaves unset. This script reports it and ' +
                           'never removes it, so this exit code stays until someone decides. LocalAccountTokenFilterPolicy=1 ' +
                           'can be what makes an admin SSH login land ' +
                           'at High integrity -- removing it may take away a remote admin path.')
        }
        exit 30
    }
    Write-Verbose 'Compliant with the golden UAC profile.'
    exit 0
}

if ($rebootRequired) {
    Write-Warning 'EnableLUA was changed. It does NOT take effect until this machine reboots -- until then UAC is still in its previous state.'
    exit 3
}

exit 0
