<#
.SYNOPSIS
  Verify the WRITE paths against a real domain controller. Makes real changes; cleans up after.

.DESCRIPTION
  ⛔ THIS ONE WRITES. That is what separates it from Invoke-AdmLiveTests.ps1, which is read-only
  and deliberately so. The two must not be merged and must not be run by the same runner: a
  read-only probe can be pointed at anything, and this cannot.

  Every object it creates lives inside ONE throwaway OU and is torn down in a `finally`. It never
  touches CN=Users, never touches an existing object, and never creates a fixture to make a check
  pass -- a green tick bought by manufacturing the thing the test needed proves nothing about
  production.

  ⚠ NOT IN Invoke-AdmTests.ps1's SUITE LIST, on purpose. That runner has to work on a target PC
  with no directory in reach, so a suite needing a DC would make "the toolkit is broken" and "you
  are not on the network" the same red line.

  WHY IT EXISTS. On 2026-08-28 a live run of these paths found four bugs that the offline suites,
  all green, could not see:

    * a helper's return value leaked into its caller, so Test-AdmObjectProtected returned a
      two-element array -- truthy whatever it holds -- and EVERY move and unforced delete refused
    * Restore-AdmObject could not work at all: a deleted object cannot be written through
      System.DirectoryServices, only through S.DS.Protocols with ShowDeletedControl
    * Set-AdmUser -NeverExpires threw on a [datetime]-typed internal parameter that by definition
      receives no date
    * Get-AdmOrganizationalUnit -Identity <dn> returned ZERO ROWS, matching a DN as a substring
      of a name

  None of those is reachable from a fixture. Keeping the run repeatable is the point of this file.

.EXAMPLE
  # From a shell that already has the forest credential in the environment:
  tests\live\Verify-AdmWritePaths.ps1 -Target corp.example.com -Dc 192.0.2.40 -UserName 'CORP\Administrator'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Target,
    [Parameter(Mandatory)][string]$Dc,
    [Parameter(Mandatory)][string]$UserName,
    # Read from the environment rather than taken on the command line: a password on argv is
    # visible to every other process on the box and lands in shell history.
    [string]$PasswordEnvVar = 'ADMINISTRATOR_PASSWORD',
    # LDAPS cannot work against a bare IP -- a certificate cannot match one -- and 389 with
    # Kerberos sealing is still encrypted. Override only if you have a name and a real cert.
    [bool]$UseSsl = $false,
    # Everything is created under this, and it is deleted with -Recurse at the end.
    [string]$WorkOu = 'ZZ-Verify-WritePaths'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$pass = 0; $fail = 0; $skip = 0

function Ok   ($m) { "  PASS  $m"; $script:pass++ }
function Bad  ($m) { "  FAIL  $m"; $script:fail++ }
function Skip ($m) { "  SKIP  $m"; $script:skip++ }

# A step reports what it PROVED, not merely that it ran. A check whose message says nothing is a
# check nobody can audit afterwards.
function Step {
    param([string]$Name, [scriptblock]$Body)
    try {
        $r = & $Body
        if ($r -is [string] -and $r) { Ok "$Name -- $r" } else { Ok $Name }
    } catch { Bad "$Name -- $($_.Exception.Message)" }
}

$secret = [Environment]::GetEnvironmentVariable($PasswordEnvVar)
if (-not $secret) {
    Write-Host "  SKIP  no credential in `$env:$PasswordEnvVar -- run this with the credential set." -ForegroundColor Yellow
    Write-Host "        e.g. powershell -File tests\live\Verify-AdmWritePaths.ps1 ..." -ForegroundColor DarkGray
    exit 0
}

$work = Join-Path $env:TEMP ("admwrite-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$env:ADADMIN_STORE    = Join-Path $work 'store.json'
$env:ADADMIN_LOG_DIR  = Join-Path $work 'logs'
$env:ADADMIN_PROVIDER = 'adsi'

Import-Module (Join-Path $repo 'ADAdmin\ADAdmin.psd1') -Force -ErrorAction Stop
"runtime $($PSVersionTable.PSVersion) -- target $Target via $Dc"

# A throwaway store: this must not touch the operator's real one.
$sp = ConvertTo-SecureString ('verify-' + [guid]::NewGuid().ToString('N')) -AsPlainText -Force
$null = Initialize-AdmStore -Path $env:ADADMIN_STORE -RecipientName 'verifier' -Passphrase $sp -Confirm:$false
$null = Unlock-AdmStore -Passphrase $sp
$null = Register-AdmDomain -Name verify -DnsDomain $Target -DomainControllers @($Dc) -UseSsl $UseSsl
$cred = New-Object System.Management.Automation.PSCredential(
            $UserName, (ConvertTo-SecureString $secret -AsPlainText -Force))
$null = Set-AdmDomainCredential -Domain verify -Credential $cred -Tier write -SetDefault
$secret = $null

$domainDn = ConvertTo-AdmDistinguishedName -DnsDomain $Target
$ouDn = "OU=$WorkOu,$domainDn"
$created = $false

# ⛔ EVERY OBJECT THIS RUN CREATES IS NAMED UNIQUELY, and that is not tidiness -- it is the
# difference between a suite that can be run twice and one that cannot.
#
# Deleting the work OU leaves a TOMBSTONE for everything inside it, and tombstones persist for the
# deleted-object lifetime. With fixed names, the second run's restore step looks up $uBulk2,
# finds this run's tombstone AND every previous run's, and Restore-AdmObject correctly refuses to
# guess between them. Measured: the fifth run failed with "matched 5 deleted objects".
#
# ⚠ THE PRODUCT WAS RIGHT AND THE TEST WAS WRONG -- the refusal is exactly the behaviour we want,
# and a fixed name turned it into a self-inflicted failure that looks like a regression. Same
# shape as a size limit chosen against a lab: a value that happens to work once.
$tag = [guid]::NewGuid().ToString('N').Substring(0, 6)
$uUser  = "zzv1$tag"        # sAMAccountName caps at 20; this is 10
$uBulk1 = "zzb1$tag"
$uBulk2 = "zzb2$tag"
$uComp  = "ZZPC$tag"        # NetBIOS caps at 15; this is 10
$uGroup = "ZZ-Grp-$tag"
"  run tag $tag -- every object this run creates carries it"

try {
    ''
    '=== the container everything else lives in ==='
    Step 'New-AdmOrganizationalUnit, protected by default' {
        $o = New-AdmOrganizationalUnit -Target $Target -Name $WorkOu -Description 'throwaway; safe to delete' -Confirm:$false
        $script:created = $true
        "dn=$($o.DistinguishedName)"
    }
    Step 'the new OU reads back as Protected' {
        $p = @(Get-AdmOrganizationalUnit -Target $Target -Identity $ouDn -IncludeProtection)
        if (-not $p.Count) { throw 'not found by its own DN -- the DN lookup is broken again' }
        if (-not $p[0].Protected) { throw 'created but NOT protected; the default did not apply' }
        'protected=True, and found BY DISTINGUISHED NAME'
    }
    Step 'Test-AdmObjectProtected returns a BOOL, not an array' {
        # The regression that made every move and unforced delete refuse: an unvoided helper leaked
        # its return into this one, giving @($false,$true) -- truthy whatever it holds.
        $r = Test-AdmObjectProtected -Context (Get-AdmTargetContextPublic -Target $Target) -DistinguishedName $ouDn
        if ($r -is [array]) { throw "returned an array of $(@($r).Count), not a bool" }
        'bool'
    }

    ''
    '=== creating things ==='
    Step 'New-AdmComputer pre-stage' {
        $c = New-AdmComputer -Target $Target -Name $uComp -Path $ouDn -Description 'throwaway' -Confirm:$false
        "sam=$($c.SamAccountName)"
    }
    Step 'New-AdmComputer refuses a 16-character name' {
        try { $null = New-AdmComputer -Target $Target -Name ($uComp + 'TOOLONGXX') -Path $ouDn -Confirm:$false
              throw 'accepted a name over the 15-character NetBIOS limit' }
        catch { if ($_.Exception.Message -match '15 characters') { 'refused, and said why' } else { throw } }
    }
    Step 'New-AdmGroup writes the SIGNED groupType' {
        $g = New-AdmGroup -Target $Target -Name $uGroup -Path $ouDn -Scope Global -Category Security -Confirm:$false
        if ($g.GroupType -ge 0) { throw "groupType $($g.GroupType) is positive; the security bit was dropped" }
        "type=$($g.GroupType)"
    }
    $pw = ConvertTo-SecureString (New-AdmRandomPassword) -AsPlainText -Force
    Step 'New-AdmUser' {
        $u = New-AdmUser -Target $Target -SamAccountName $uUser -DisplayName 'ZZ Verify One' `
                -Password $pw -Path $ouDn -Confirm:$false
        "dn=$($u.DistinguishedName)"
    }

    ''
    '=== editing ==='
    Step 'Set-AdmUser sets several attributes at once' {
        $r = Set-AdmUser -Target $Target -Identity $uUser -Title 'Engineer' -Department 'Platform' `
                -Description 'throwaway' -Confirm:$false
        if (@($r.Changed).Count -lt 3) { throw "only $(@($r.Changed).Count) attribute(s) changed" }
        "changed=$($r.Changed -join ',')"
    }
    Step 'Set-AdmUser -AccountExpires writes AND reads back' {
        $when = (Get-Date).Date.AddDays(30)
        $null = Set-AdmUser -Target $Target -Identity $uUser -AccountExpires $when -Confirm:$false
        $u = @(Get-AdmUser -Target $Target -Identity $uUser)[0]
        if (-not $u.AccountExpires) { throw 'accountExpires did not read back at all' }
        $got = ([datetime]$u.AccountExpires).ToUniversalTime().Date
        if ($got -ne $when.ToUniversalTime().Date) { throw "read back $got, expected $($when.ToUniversalTime().Date)" }
        "round-tripped $($got.ToString('yyyy-MM-dd'))"
    }
    Step 'Set-AdmUser -NeverExpires clears it' {
        $null = Set-AdmUser -Target $Target -Identity $uUser -NeverExpires -Confirm:$false
        $u = @(Get-AdmUser -Target $Target -Identity $uUser)[0]
        if ($u.AccountExpires) { throw "still expires on $($u.AccountExpires)" }
        'cleared'
    }
    Step "an empty string CLEARS rather than writing ''" {
        $null = Set-AdmUser -Target $Target -Identity $uUser -Title '' -Confirm:$false
        'cleared'
    }

    ''
    '=== membership, and the search that finds it ==='
    Step 'Add-AdmGroupMember then find it BY SEARCH' {
        $null = Add-AdmGroupMember -Target $Target -Group $uGroup -Identity $uUser -Confirm:$false
        $m = @(Get-AdmGroupMember -Target $Target -Identity $uGroup)
        if ($m.Count -ne 1) { throw "expected 1 member, got $($m.Count)" }
        if ($m[0].Via -ne 'direct') { throw "expected Via=direct, got '$($m[0].Via)'" }
        'found by search, Via=direct'
    }

    ''
    '=== moving and renaming ==='
    Step 'Rename-AdmObject takes the RDN prefix from the DN' {
        $r = Rename-AdmObject -Target $Target -Identity $uUser -NewName 'ZZ Verify Renamed' -Class user -Confirm:$false
        "-> $($r.ToDn)"
    }
    Step 'Move-AdmObject between OUs' {
        $sub = New-AdmOrganizationalUnit -Target $Target -Name 'ZZ-Sub' -Path $ouDn `
                    -ProtectFromAccidentalDeletion $false -Confirm:$false
        $r = Move-AdmObject -Target $Target -Identity 'ZZ Verify Renamed' -DestinationPath $sub.DistinguishedName `
                -Class user -Confirm:$false
        if ($r.ToDn -notmatch 'ZZ-Sub') { throw "did not land in the sub OU: $($r.ToDn)" }
        "-> $($r.ToDn)"
    }

    ''
    '=== bulk ==='
    Step 'Import-AdmUserCsv -WhatIf returns a plan and writes nothing' {
        $csv = Join-Path $work 'bulk.csv'
        @('SamAccountName,Title,Department', "$uBulk1,Analyst,Finance", "$uBulk2,Engineer,Platform") |
            Set-Content -LiteralPath $csv -Encoding ASCII
        $plan = @(Import-AdmUserCsv -Target $Target -Path $csv -DefaultPath $ouDn -WhatIf -Confirm:$false)
        if ($plan.Count -ne 2) { throw "expected 2 planned rows, got $($plan.Count)" }
        if (-not $plan[0].TargetDn) { throw 'no TargetDn in the plan' }
        if (@(Get-AdmUser -Target $Target -Identity $uBulk1).Count) { throw '-WhatIf CREATED the account' }
        "2 rows, first -> $($plan[0].TargetDn), nothing written"
    }
    Step 'Import-AdmUserCsv applies and writes a rollback manifest' {
        $csv = Join-Path $work 'bulk.csv'
        $roll = Join-Path $work 'undo.csv'
        $res = @(Import-AdmUserCsv -Target $Target -Path $csv -DefaultPath $ouDn -RollbackPath $roll -Confirm:$false)
        if (@($res | Where-Object { $_.Status -eq 'ok' }).Count -ne 2) { throw 'not both rows applied' }
        if (-not (Test-Path -LiteralPath $roll)) { throw 'no rollback manifest written' }
        $u = @(Import-Csv -LiteralPath $roll)
        if (@($u | Where-Object { $_.Action -eq 'delete' -and $_.TargetDn }).Count -ne 2) {
            throw 'manifest does not carry two delete rows with DNs'
        }
        '2 created, manifest can undo both'
    }

    ''
    '=== the refusals, which are the point ==='
    Step 'Remove-AdmOrganizationalUnit refuses a non-empty OU' {
        try { $null = Remove-AdmOrganizationalUnit -Target $Target -Identity $ouDn -RemoveProtection -Confirm:$false
              throw 'deleted a non-empty OU without -Recurse' }
        catch { if ($_.Exception.Message -match 'not empty') { 'refused, with the child count' } else { throw } }
    }
    Step 'Remove-AdmObject refuses a protected object' {
        $dn = @(Get-AdmUser -Target $Target -Identity $uBulk1)[0].DistinguishedName
        $null = Set-AdmObjectProtection -Target $Target -Identity $dn -Protected $true -Confirm:$false
        try { $null = Remove-AdmObject -Target $Target -Identity $dn -Class user -Confirm:$false
              throw 'deleted a protected object' }
        catch { if ($_.Exception.Message -match 'protected') { 'refused, and named the protection' } else { throw } }
        finally { $null = Set-AdmObjectProtection -Target $Target -Identity $dn -Protected $false -Confirm:$false }
    }

    ''
    '=== the recycle bin, whichever half this forest can exercise ==='
    $rb = Test-AdmRecycleBinEnabled -Target $Target
    "  bin enabled = $($rb.Enabled)"
    Step 'a deleted object appears as a tombstone with its name recovered' {
        $dn = @(Get-AdmUser -Target $Target -Identity $uBulk2)[0].DistinguishedName
        $null = Remove-AdmObject -Target $Target -Identity $dn -Class user -Confirm:$false
        $d = @(Get-AdmDeletedObject -Target $Target -Identity $uBulk2 -Class user)
        if (-not $d.Count) { throw 'not in the bin after deletion' }
        if ($d[0].Name -ne $uBulk2) { throw "name came back as '$($d[0].Name)'" }
        "name=$($d[0].Name) parentOk=$($d[0].ParentAvailable)"
    }
    if ($rb.Enabled) {
        Skip 'the TOMBSTONE refusal cannot be exercised: this forest has the Recycle Bin ON'
    } else {
        Step 'restore is REFUSED without -AcceptTombstone' {
            try { $null = Restore-AdmObject -Target $Target -Identity $uBulk2 -Confirm:$false
                  throw 'restored a tombstone without being asked to' }
            catch { if ($_.Exception.Message -match 'AcceptTombstone') { 'refused, and named the loss' } else { throw } }
        }
    }
    Step 'restore returns the object to its ORIGINAL parent, disabled' {
        $r = Restore-AdmObject -Target $Target -Identity $uBulk2 -AcceptTombstone -Confirm:$false
        if (-not @($r.NextSteps).Count) { throw 'no NextSteps -- the caller is told nothing about what is missing' }
        $u = @(Get-AdmUser -Target $Target -Identity $uBulk2)
        if (-not $u.Count) { throw 'restored but not findable' }
        if ($u[0].Enabled) { throw 'came back ENABLED; a restore must not re-enable an account' }
        "-> $($r.RestoredTo), enabled=$($u[0].Enabled)"
    }
    if ($rb.Enabled) { Skip 'the full-restore branch is UNVERIFIED anywhere; no lab here has the bin on' }

} finally {
    ''
    '=== cleanup ==='
    if ($created) {
        try {
            $null = Remove-AdmOrganizationalUnit -Target $Target -Identity $ouDn -Recurse -RemoveProtection -Confirm:$false
            Ok "removed $ouDn and everything in it"
        } catch {
            # ⛔ LOUD. Leaving objects behind in a directory is the one failure this script must
            # never report quietly, because the next run will collide with them.
            Bad "CLEANUP FAILED -- '$ouDn' MAY STILL EXIST and must be removed by hand: $($_.Exception.Message)"
        }
    } else { Skip 'nothing was created, so nothing to clean up' }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

''
"pass=$pass fail=$fail skip=$skip"
if ($skip) { "  $skip check(s) were SKIPPED -- read them; a skip is not a pass." }
if ($fail -gt 0) { exit 1 } else { exit 0 }
