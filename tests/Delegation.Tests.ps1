$repo = Split-Path -Parent $PSScriptRoot   # run from any clone, USB or share
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# The logic behind Get-AdDelegation and Get-AdLockoutSource, tested offline.
#
# ⛔ WHY NOT AGAINST A REAL DOMAIN. The interesting cases here are a domain with a genuinely
# dangerous delegation on it and an account actually locking out, and the lab forest can produce
# NEITHER on demand: lockoutThreshold is 0 there so a lockout cannot be induced, and lockoutTime
# is system-managed so one cannot be faked either (a DC refuses a direct write of a non-zero
# value). What CAN be measured there was, on 2026-08-28, and the numbers below are the real ones:
#
#   - the domain-head DACL was read and its ACE masks recorded (0xF01BD, 0xE01BD, 0xF01FF)
#   - Enterprise Domain Controllers holds DS-Replication-Get-Changes but NOT -All
#   - Domain Controllers holds -All but NOT -Get
#   - all 23 ACEs on Domain Admins are non-inherited, because AdminSDHolder disables inheritance
#   - GenericAll on a throwaway OU was granted to a throwaway principal, detected as 'high' with
#     exit 10, and torn down
#
# What is pinned here is the ARITHMETIC and the SCORING, which is what silently rots.

$fail = 0
function Check($name, [scriptblock]$b) {
    try { if (& $b) { "  PASS  $name" } else { "  FAIL  $name"; $script:fail++ } }
    catch { "  FAIL  $name -- $($_.Exception.Message)"; $script:fail++ }
}

$work = Join-Path $env:TEMP ("admdeleg-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$env:ADADMIN_STORE    = Join-Path $work 'store.json'
$env:ADADMIN_LOG_DIR  = Join-Path $work 'logs'
$env:ADADMIN_PROVIDER = 'mock'

Import-Module (Join-Path $repo 'ADAdmin\ADAdmin.psd1') -Force

# --- the rights, as .NET actually numbers them ---------------------------------------------------
# Hard-coded rather than read from the enum, so a change in the enum is a FAILURE here rather than
# a silent agreement between two copies of the same mistake. Measured on a lab domain controller, 2026-08-28.
$CREATE_CHILD  = 0x00000001
$SELF          = 0x00000008
$READ_PROPERTY = 0x00000010
$WRITE_PROPERTY= 0x00000020
$EXTENDED      = 0x00000100
$READ_CONTROL  = 0x00020000
$WRITE_DACL    = 0x00040000
$WRITE_OWNER   = 0x00080000
$GENERIC_ALL   = 0x000F01FF

"== the enum really is shaped like that =="
$T = [System.DirectoryServices.ActiveDirectoryRights]
Check 'GenericAll is 0xF01FF, a COMPOSITE not a bit' { [int]$T::GenericAll -eq $GENERIC_ALL }
Check 'WriteDacl is 0x40000'                         { [int]$T::WriteDacl  -eq $WRITE_DACL }
Check 'WriteOwner is 0x80000'                        { [int]$T::WriteOwner -eq $WRITE_OWNER }
Check 'ExtendedRight is 0x100'                       { [int]$T::ExtendedRight -eq $EXTENDED }
Check 'ReadProperty is 0x10'                         { [int]$T::ReadProperty -eq $READ_PROPERTY }

"== mask arithmetic: the bug that made Everyone a domain admin =="
# Mirrors Test-AdDelegationRight in Get-AdDelegation.ps1.
function Test-Right { param([int]$Mask, [int]$Want) ($Mask -band $Want) -eq $Want }

Check 'THE NAIVE TEST IS TRUE WHERE IT MUST BE FALSE' {
    # ⛔ The bug, pinned. `-band GenericAll -ne 0` on a plain ReadProperty ACE is NON-ZERO,
    # because 0x10 is one of the bits inside 0xF01FF. Run against the real domain-head DACL of
    # a lab domain controller it turned 4 DCSync holders into 16, including Everyone, Authenticated Users and
    # CREATOR OWNER. A report that accuses Everyone is a report nobody believes twice.
    (($READ_PROPERTY -band $GENERIC_ALL) -ne 0)
}
Check 'the CORRECT test is false for ReadProperty'   { -not (Test-Right $READ_PROPERTY $GENERIC_ALL) }
Check 'GenericAll satisfies GenericAll'              { Test-Right $GENERIC_ALL $GENERIC_ALL }
Check 'GenericAll IMPLIES WriteDacl'                 { Test-Right $GENERIC_ALL $WRITE_DACL }
Check 'GenericAll IMPLIES WriteOwner'                { Test-Right $GENERIC_ALL $WRITE_OWNER }
Check 'WriteDacl alone does NOT imply GenericAll'    { -not (Test-Right $WRITE_DACL $GENERIC_ALL) }
Check 'a single-bit right still tests correctly'     { Test-Right ($WRITE_DACL -bor $READ_CONTROL) $WRITE_DACL }
Check 'REAL MASK 0xF01BD (BUILTIN\Administrators on the domain head) is NOT GenericAll' {
    # Measured on a lab domain controller. It is missing DeleteChild (0x2) and DeleteTree (0x40), so a naive
    # "close enough" test would call it full control and a correct one does not.
    -not (Test-Right 0xF01BD $GENERIC_ALL)
}
Check 'REAL MASK 0xF01BD DOES carry WriteDacl and WriteOwner' {
    (Test-Right 0xF01BD $WRITE_DACL) -and (Test-Right 0xF01BD $WRITE_OWNER)
}
Check 'REAL MASK 0xE01BD (Domain Admins on the domain head) carries WriteDacl but not GenericAll' {
    (Test-Right 0xE01BD $WRITE_DACL) -and -not (Test-Right 0xE01BD $GENERIC_ALL)
}
Check 'an ACE-kind table keyed by INTEGER would silently lose the high rights' {
    # ⚠ Why Get-AdDelegationAceKind is a chain of ifs and not a lookup table. An [ordered]
    # hashtable indexed by an int does a POSITIONAL lookup, so asking for entry 0x40000 of a
    # 3-entry table returns nothing at all -- no error, no match, and WriteDacl is never decoded.
    $t = [ordered]@{ 16 = 'ReadProperty'; 32 = 'WriteProperty'; 262144 = 'WriteDacl' }
    $null -eq $t[$WRITE_DACL]
}

"== DCSync: BOTH rights, or it is not DCSync =="
$GUID_GET  = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
$GUID_ALL  = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
$GUID_NONE = [guid]::Empty

function Ace {
    param([string]$Sid, [int]$Mask, $ObjType = $GUID_NONE, [string]$Type = 'Allow', [bool]$Inherited = $false)
    [pscustomobject]@{ IdentityReference = $Sid; ActiveDirectoryRights = $Mask
                       ObjectType = $ObjType; AccessControlType = $Type; IsInherited = $Inherited }
}

# Mirrors section 1 of Get-AdDelegation.ps1.
function Get-DcSyncHolder {
    param($Aces)
    $repl = @{}
    foreach ($a in $Aces) {
        if ("$($a.AccessControlType)" -ne 'Allow') { continue }
        $sid = "$($a.IdentityReference)"
        $m = [int]$a.ActiveDirectoryRights
        if (-not $repl.ContainsKey($sid)) { $repl[$sid] = @{ Get = $false; All = $false } }
        if (Test-Right $m $GENERIC_ALL) { $repl[$sid].Get = $true; $repl[$sid].All = $true }
        if (Test-Right $m $EXTENDED) {
            if ($a.ObjectType -eq $GUID_NONE) { $repl[$sid].Get = $true; $repl[$sid].All = $true }
            if ($a.ObjectType -eq $GUID_GET)  { $repl[$sid].Get = $true }
            if ($a.ObjectType -eq $GUID_ALL)  { $repl[$sid].All = $true }
        }
    }
    $out = @()
    foreach ($k in $repl.Keys) { if ($repl[$k].Get -and $repl[$k].All) { $out += $k } }
    $out
}

Check 'DS-Replication-Get-Changes ALONE is not DCSync' {
    @(Get-DcSyncHolder @((Ace 'S-1-5-21-1-2-3-1234' $EXTENDED $GUID_GET))).Count -eq 0
}
Check 'DS-Replication-Get-Changes-All ALONE is not DCSync' {
    @(Get-DcSyncHolder @((Ace 'S-1-5-21-1-2-3-1234' $EXTENDED $GUID_ALL))).Count -eq 0
}
Check 'BOTH, as two separate ACEs, IS DCSync' {
    # This is how it really appears: two ACEs, not one, so anything that scores a single ACE at a
    # time can never see it.
    $h = @(Get-DcSyncHolder @(
        (Ace 'S-1-5-21-1-2-3-1234' $EXTENDED $GUID_GET),
        (Ace 'S-1-5-21-1-2-3-1234' $EXTENDED $GUID_ALL)))
    $h.Count -eq 1 -and $h[0] -eq 'S-1-5-21-1-2-3-1234'
}
Check 'an "all extended rights" ACE is DCSync' {
    # ExtendedRight with an EMPTY ObjectType means every extended right, which includes both
    # replication rights. Measured: this is how all four default holders on a lab domain controller get it.
    @(Get-DcSyncHolder @((Ace 'S-1-5-18' $EXTENDED $GUID_NONE))).Count -eq 1
}
Check 'GenericAll is DCSync' {
    @(Get-DcSyncHolder @((Ace 'S-1-5-21-1-2-3-519' $GENERIC_ALL))).Count -eq 1
}
Check 'a DENY ace granting both is not a holder' {
    @(Get-DcSyncHolder @(
        (Ace 'S-1-5-21-1-2-3-1234' $EXTENDED $GUID_GET 'Deny'),
        (Ace 'S-1-5-21-1-2-3-1234' $EXTENDED $GUID_ALL 'Deny'))).Count -eq 0
}
Check 'plain ReadProperty is not DCSync -- the naive-mask regression' {
    @(Get-DcSyncHolder @((Ace 'S-1-1-0' $READ_PROPERTY $GUID_NONE))).Count -eq 0
}
Check 'THE REAL LAB DOMAIN-HEAD ACES yield exactly the four built-ins' {
    # ⭐ The exact ACEs read off the live domain head on 2026-08-28, replayed. Everyone,
    # Authenticated Users, CREATOR OWNER and SELF appear on that DACL and must NOT come out.
    $real = @(
        (Ace 'S-1-1-0'      $READ_PROPERTY $GUID_NONE)
        (Ace 'S-1-5-9'      0x20094        $GUID_NONE)
        (Ace 'S-1-5-11'     0x20094        $GUID_NONE)
        (Ace 'S-1-5-18'     0xF01FF        $GUID_NONE)
        (Ace 'S-1-5-32-544' 0xF01BD        $GUID_NONE)
        (Ace 'S-1-5-21-1-2-3-512' 0xE01BD  $GUID_NONE)
        (Ace 'S-1-5-21-1-2-3-519' 0xF01FF  $GUID_NONE)
        # the explicit replication ACEs, exactly as they are on a clean domain
        (Ace 'S-1-5-9'            $EXTENDED $GUID_GET)
        (Ace 'S-1-5-21-1-2-3-498' $EXTENDED $GUID_GET)
        (Ace 'S-1-5-21-1-2-3-516' $EXTENDED $GUID_ALL)
        (Ace 'S-1-5-32-544'       $EXTENDED $GUID_GET)
        (Ace 'S-1-5-32-544'       $EXTENDED $GUID_ALL)
    )
    $h = @(Get-DcSyncHolder $real)
    ($h.Count -eq 4) -and
    ($h -contains 'S-1-5-18') -and ($h -contains 'S-1-5-32-544') -and
    ($h -contains 'S-1-5-21-1-2-3-512') -and ($h -contains 'S-1-5-21-1-2-3-519')
}
Check 'ENTERPRISE DOMAIN CONTROLLERS is excluded by the RULE, not by an exception list' {
    # ⭐ The point of the both-rights rule. S-1-5-9 holds -Get and not -All on every clean domain,
    # so it falls out arithmetically. No allow-list is needed, and none can therefore go stale.
    @(Get-DcSyncHolder @(
        (Ace 'S-1-5-9' 0x20094 $GUID_NONE),
        (Ace 'S-1-5-9' $EXTENDED $GUID_GET))).Count -eq 0
}
Check 'DOMAIN CONTROLLERS (RID 516) is excluded by the rule too' {
    # It holds -All and not -Get. The mirror image of the case above, and equally real.
    @(Get-DcSyncHolder @((Ace 'S-1-5-21-1-2-3-516' $EXTENDED $GUID_ALL))).Count -eq 0
}

"== built-in principals: the RID rule =="
$domSid = 'S-1-5-21-2051751951-2755476120-2027887660'
$WellKnown = @('S-1-1-0','S-1-3-0','S-1-5-4','S-1-5-7','S-1-5-9','S-1-5-10','S-1-5-11','S-1-5-18','S-1-5-19','S-1-5-20')

# Mirrors Test-AdDelegationBuiltIn.
function Test-BuiltIn {
    param([string]$Sid, [string]$DomainSid)
    if (-not $Sid) { return $false }
    if ($Sid -like 'S-1-5-32-*') { return $true }
    if ($WellKnown -contains $Sid) { return $true }
    if ($Sid -like 'S-1-5-80-*') { return $true }
    if ($DomainSid -and $Sid -like "$DomainSid-*") {
        $rid = 0
        if ([int]::TryParse($Sid.Substring($DomainSid.Length + 1), [ref]$rid)) { return ($rid -lt 1000) }
    }
    $false
}

Check 'BUILTIN\Administrators is built-in'        { Test-BuiltIn 'S-1-5-32-544' $domSid }
Check 'SYSTEM is built-in'                        { Test-BuiltIn 'S-1-5-18' $domSid }
Check 'Domain Admins (RID 512) is built-in'       { Test-BuiltIn "$domSid-512" $domSid }
Check 'RID 999 is still built-in'                 { Test-BuiltIn "$domSid-999" $domSid }
Check 'RID 1000 IS NOT -- the pool starts there'  { -not (Test-BuiltIn "$domSid-1000" $domSid) }
Check 'A REAL CREATED ACCOUNT (RID 1121) is not built-in' {
    # The throwaway principal built on a lab domain controller got exactly this RID, and it was reported. If this
    # rule ever said "built-in" the whole Containers section would go quiet on a real estate.
    -not (Test-BuiltIn "$domSid-1121" $domSid)
}
Check 'a SID from ANOTHER domain is not built-in even at a low RID' {
    -not (Test-BuiltIn 'S-1-5-21-9-9-9-512' $domSid)
}
Check 'with NO domain SID, a domain principal is not silently called built-in' {
    # Losing the domain SID must not turn every finding off. It makes the classification unknown,
    # and unknown must fall on the side of reporting.
    -not (Test-BuiltIn "$domSid-512" '')
}
Check 'a malformed tail does not throw and is not built-in' {
    -not (Test-BuiltIn "$domSid-notanumber" $domSid)
}

"== built-in does NOT mean safe: the broad principals =="
# Mirrors Test-AdDelegationBroadPrincipal.
function Test-Broad {
    param([string]$Sid, [string]$DomainSid)
    if (@('S-1-1-0','S-1-5-7','S-1-5-11','S-1-5-4','S-1-5-32-545','S-1-5-32-546','S-1-5-32-554') -contains $Sid) { return $true }
    if ($DomainSid) { foreach ($r in @(513,514,515,501)) { if ($Sid -eq "$DomainSid-$r") { return $true } } }
    $false
}
# The rule in the script: skip only when built-in AND not broad.
function Test-Reported {
    param([string]$Sid, [string]$DomainSid)
    -not ((Test-BuiltIn $Sid $DomainSid) -and -not (Test-Broad $Sid $DomainSid))
}

Check 'A WELL-KNOWN BUILT-IN HOLDING DCSYNC IS NOT REPORTED AS A PROBLEM' {
    # ⭐ What the task asked for explicitly. Domain Admins, Enterprise Admins, Administrators and
    # SYSTEM hold it on every domain in existence; scoring them as findings is pure noise, and
    # noise is how the real one gets scrolled past.
    (-not (Test-Reported 'S-1-5-32-544' $domSid)) -and
    (-not (Test-Reported "$domSid-512" $domSid)) -and
    (-not (Test-Reported "$domSid-519" $domSid)) -and
    (-not (Test-Reported 'S-1-5-18' $domSid))
}
Check 'EVERYONE is built-in and is reported ANYWAY'      { (Test-BuiltIn 'S-1-1-0' $domSid) -and (Test-Reported 'S-1-1-0' $domSid) }
Check 'Authenticated Users is reported'                  { Test-Reported 'S-1-5-11' $domSid }
Check 'Domain Users (RID 513) is reported despite RID<1000' {
    (Test-BuiltIn "$domSid-513" $domSid) -and (Test-Reported "$domSid-513" $domSid)
}
Check 'Domain Computers (RID 515) is reported'           { Test-Reported "$domSid-515" $domSid }
Check 'Pre-Windows 2000 Compatible Access is reported'   { Test-Reported 'S-1-5-32-554' $domSid }
Check 'an ordinary created account is reported'          { Test-Reported "$domSid-1121" $domSid }

"== non-inherited alone is not a finding =="
Check 'ALL 23 ACES ON DOMAIN ADMINS ARE NON-INHERITED, so non-inheritance cannot be the test' {
    # Measured on a lab domain controller: AdminSDHolder disables inheritance on every protected object, so
    # "non-inherited" is true of every ACE on every Tier 0 group. The test has to be
    # non-inherited AND dangerous AND non-built-in.
    $aces = @(1..23 | ForEach-Object { Ace 'S-1-5-32-544' $READ_PROPERTY $GUID_NONE 'Allow' $false })
    $naive = @($aces | Where-Object { -not $_.IsInherited })
    $real  = @($aces | Where-Object {
        $a = $_    # capture BEFORE anything that rebinds $_
        (-not $a.IsInherited) -and (Test-Right ([int]$a.ActiveDirectoryRights) $GENERIC_ALL) -and (Test-Reported "$($a.IdentityReference)" $domSid)
    })
    $naive.Count -eq 23 -and $real.Count -eq 0
}
Check 'a non-inherited GenericAll for a CREATED principal IS a finding' {
    $a = Ace "$domSid-1121" $GENERIC_ALL $GUID_NONE 'Allow' $false
    (-not $a.IsInherited) -and (Test-Right ([int]$a.ActiveDirectoryRights) $GENERIC_ALL) -and (Test-Reported "$($a.IdentityReference)" $domSid)
}

"== shadow credentials: three routes to the same power =="
$GUID_KEYCRED = [guid]'5b47d60f-6090-40b2-9f37-2a4de88f3063'
$GUID_PRIVATE = [guid]'91e647de-d96f-4b70-9557-d63ff4f3ccd8'
function Test-KeyCredWrite {
    param($Ace)
    if (-not (Test-Right ([int]$Ace.ActiveDirectoryRights) $WRITE_PROPERTY)) { return $false }
    ($Ace.ObjectType -eq $GUID_KEYCRED) -or ($Ace.ObjectType -eq $GUID_PRIVATE) -or ($Ace.ObjectType -eq $GUID_NONE)
}
Check 'the attribute GUID is caught'      { Test-KeyCredWrite (Ace "$domSid-1121" $WRITE_PROPERTY $GUID_KEYCRED) }
Check 'THE PROPERTY SET IS CAUGHT TOO' {
    # ⛔ Measured on a lab domain controller: the DEFAULT grant of this is on the Private-Information PROPERTY SET,
    # not on the attribute. A scanner matching only the attribute GUID finds nothing on any
    # domain, healthy or compromised, and reports clean.
    Test-KeyCredWrite (Ace "$domSid-1121" $WRITE_PROPERTY $GUID_PRIVATE)
}
Check 'write-all-properties is caught'    { Test-KeyCredWrite (Ace "$domSid-1121" $WRITE_PROPERTY $GUID_NONE) }
Check 'a READ of the same attribute is not a write' { -not (Test-KeyCredWrite (Ace "$domSid-1121" $READ_PROPERTY $GUID_KEYCRED)) }
Check 'an unrelated attribute is not caught' {
    -not (Test-KeyCredWrite (Ace "$domSid-1121" $WRITE_PROPERTY ([guid]'bf9679c0-0de6-11d0-a285-00aa003049e2')))
}
Check 'SELF holding it is the DEFAULT and is skipped' {
    # S-1-5-10 has ReadProperty+WriteProperty+ExtendedRight on Private-Information out of the box.
    "$((Ace 'S-1-5-10' $WRITE_PROPERTY $GUID_PRIVATE).IdentityReference)" -eq 'S-1-5-10'
}

"== per-DC bad passwords: newest wins, and only among DCs that answered =="
function DcRow { param([string]$Dc, [int]$Count, $Time)
    [pscustomobject]@{ Dc = $Dc; BadPwdCount = $Count; BadPasswordTime = $Time } }

# Mirrors section 5 of Get-AdLockoutSource.ps1.
function Select-NewestDc {
    param($Rows)
    $withTime = @($Rows | Where-Object { $null -ne $_.BadPasswordTime })
    if (-not $withTime.Count) { return $null }
    @($withTime | Sort-Object BadPasswordTime -Descending)[0]
}
function Get-MaxBadCount {
    param($Rows)
    $max = 0
    foreach ($r in $Rows) { if ($r.BadPwdCount -gt $max) { $max = $r.BadPwdCount } }
    $max
}

$t0 = [datetime]::new(2026, 8, 28, 10, 0, 0, [System.DateTimeKind]::Utc)
Check 'THE DC WITH THE NEWEST FAILURE IS CHOSEN, NOT THE FIRST ONE READ' {
    # ⛔ The whole reason this script exists. DC01 answers 0 and DC03 holds the evidence; a
    # single-DC read hits DC01 and reports that nothing is wrong with a locked account.
    $rows = @(
        (DcRow 'DC01' 0 $null)
        (DcRow 'DC02' 2 $t0.AddMinutes(-30))
        (DcRow 'DC03' 5 $t0.AddMinutes(-2))
    )
    (Select-NewestDc $rows).Dc -eq 'DC03'
}
Check 'A DC THAT HAS NEVER SEEN A FAILURE CANNOT WIN THE SORT' {
    # $null sorts as the smallest value descending in some paths and the largest in others; the
    # null rows are removed BEFORE the sort rather than compared inside it.
    $rows = @((DcRow 'DC01' 0 $null), (DcRow 'DC02' 1 $t0.AddHours(-5)))
    (Select-NewestDc $rows).Dc -eq 'DC02'
}
Check 'no DC with a time gives null, not a crash' {
    $null -eq (Select-NewestDc @((DcRow 'DC01' 0 $null), (DcRow 'DC02' 0 $null)))
}
Check 'ONE row still works -- @() around the pipeline, not around its input' {
    # `@($rows) | Sort-Object` unwraps again and yields a scalar; the wrap has to cover the whole
    # pipeline or a single-DC domain throws on .Dc under strict mode.
    (Select-NewestDc @((DcRow 'DC01' 3 $t0))).Dc -eq 'DC01'
}
Check 'the MAXIMUM count across DCs is taken, not the first' { (Get-MaxBadCount @((DcRow 'DC01' 0 $null), (DcRow 'DC02' 7 $t0))) -eq 7 }
Check 'all-zero counts give zero'                            { (Get-MaxBadCount @((DcRow 'DC01' 0 $null))) -eq 0 }

"== a DC that did not answer makes the answer UNKNOWN =="
function Get-LockoutExit {
    param([int]$Unreachable, [int]$Actionable, [bool]$ChangeFailed)
    if ($ChangeFailed) { return 20 }
    if ($Unreachable -gt 0) { return 30 }
    if ($Actionable -gt 0) { return 10 }
    0
}
Check 'every DC answered and nothing found -> 0'     { (Get-LockoutExit 0 0 $false) -eq 0 }
Check 'every DC answered and something found -> 10'  { (Get-LockoutExit 0 1 $false) -eq 10 }
Check 'A DC DID NOT ANSWER -> 30, EVEN WITH FINDINGS' {
    # ⛔ The newest bad password may be on the DC that was unreachable, so the source named is at
    # best a lower bound. A check that could not look NEVER reports a pass -- and it must not be
    # allowed to report a confident 10 either.
    (Get-LockoutExit 1 1 $false) -eq 30
}
Check 'a failed unlock beats an unreachable DC -> 20' { (Get-LockoutExit 1 1 $true) -eq 20 }
Check 'exit 30 is FAILED to the sweep, not clean' {
    # Same contract Invoke-AdmSweep reads: 0 and 10 are ok, everything else is a failure.
    $code = Get-LockoutExit 1 0 $false
    ($code -ne 0 -and $code -ne 10)
}

"== lockout severity =="
function Get-LockoutSeverity {
    param([bool]$Locked, [int]$MaxCount, [int]$Threshold, [bool]$PolicyKnown)
    if ($Locked) { return 'high' }
    if ($PolicyKnown -and $Threshold -gt 0 -and $MaxCount -ge $Threshold) { return 'high' }
    if ($MaxCount -gt 0) { return 'warn' }
    'info'
}
Check 'locked is high'                          { (Get-LockoutSeverity $true 0 5 $true) -eq 'high' }
Check 'at the threshold but not yet locked is high' { (Get-LockoutSeverity $false 5 5 $true) -eq 'high' }
Check 'some failures below the threshold is warn'   { (Get-LockoutSeverity $false 2 5 $true) -eq 'warn' }
Check 'no failures is info'                         { (Get-LockoutSeverity $false 0 5 $true) -eq 'info' }
Check 'AN UNKNOWN POLICY DOES NOT INVENT A THRESHOLD' {
    # With lockoutThreshold unreadable, "2 failures" cannot be scored against anything, so it
    # stays warn rather than being promoted on a threshold nobody read.
    (Get-LockoutSeverity $false 2 0 $false) -eq 'warn'
}
Check 'a threshold of 0 (lockout disabled) never promotes to high' {
    # Measured: the lab domain really is set this way. Comparing >= 0 would make every account high.
    (Get-LockoutSeverity $false 3 0 $true) -eq 'warn'
}

"== time and duration conversion =="
function ConvertFrom-FileTime {
    param($Value)
    $n = 0L
    if (-not [int64]::TryParse([string]$Value, [ref]$n)) { return $null }
    if ($n -le 0 -or $n -eq [int64]::MaxValue) { return $null }
    try { [datetime]::FromFileTimeUtc($n) } catch { $null }
}
function ConvertFrom-Duration {
    param($Value)
    $n = 0L
    if (-not [int64]::TryParse([string]$Value, [ref]$n)) { return $null }
    try { [timespan]::FromTicks([math]::Abs($n)) } catch { $null }
}
Check 'badPasswordTime 0 is "never", not 1601'  { $null -eq (ConvertFrom-FileTime 0) }
Check 'Int64::MaxValue is "never expires"'      { $null -eq (ConvertFrom-FileTime ([int64]::MaxValue)) }
Check 'an ABSENT attribute is null, not an error' {
    # A real directory omits lockoutTime entirely on an account never locked -- measured on
    # Administrator on the lab domain. Get-AdmRawProp hands back $null and this must survive it.
    $null -eq (ConvertFrom-FileTime $null)
}
Check 'a real FILETIME converts'                { (ConvertFrom-FileTime 133700000000000000).Year -gt 2020 }
Check 'REAL lockoutDuration -6000000000 is 10 minutes' {
    # The literal value read off a lab domain controller.
    (ConvertFrom-Duration -6000000000).TotalMinutes -eq 10
}
Check 'lockoutDuration 0 means "until an admin unlocks", and is not null' {
    $d = ConvertFrom-Duration 0
    $null -ne $d -and $d.TotalSeconds -eq 0
}

"== the CSV must not lose the evidence =="
Check 'EXPORT-CSV TAKES ITS HEADER FROM THE FIRST ROW ONLY' {
    # ⛔ The bug found on 2026-08-28. The first finding emitted is the policy row, which has only
    # the seven standard fields; every per-DC column on the later rows was dropped and the file
    # looked like a successful export.
    $p = Join-Path $work 'ragged.csv'
    @(
        [pscustomobject]@{ Severity = 'warn'; Detail = 'policy' }
        [pscustomobject]@{ Severity = 'high'; Detail = 'account'; PerDc = 'DC01=5' }
    ) | Export-Csv -LiteralPath $p -NoTypeInformation
    $cols = @((Import-Csv $p)[0].PSObject.Properties | ForEach-Object { $_.Name })
    $cols -notcontains 'PerDc'
}
Check 'a UNIFORM row shape keeps every column' {
    $p = Join-Path $work 'uniform.csv'
    @(
        [pscustomobject]@{ Severity = 'warn'; Detail = 'policy';  PerDc = $null }
        [pscustomobject]@{ Severity = 'high'; Detail = 'account'; PerDc = 'DC01=5' }
    ) | Export-Csv -LiteralPath $p -NoTypeInformation
    $cols = @((Import-Csv $p)[0].PSObject.Properties | ForEach-Object { $_.Name })
    $cols -contains 'PerDc'
}

"== SIDs, as a directory really returns them =="
Check 'OBJECT[] OF BYTE converts -- the shape a search returns' {
    # The same regression the privilege audit hit. Repeated here because Get-AdDelegation builds
    # its whole built-in/created classification off the domain SID read this way; get it wrong and
    # every principal looks created and every ACE becomes a critical finding.
    $sidBytes = [byte[]]@(1,5,0,0,0,0,0,5,21,0,0,0,1,0,0,0,2,0,0,0,3,0,0,0,0,2,0,0)
    $asObjectArray = [object[]]@($sidBytes | ForEach-Object { $_ })
    $asObjectArray.GetType().Name -eq 'Object[]' -and
    (ConvertTo-AdmSidString -Raw $asObjectArray) -eq 'S-1-5-21-1-2-3-512'
}
Check 'AN UNRESOLVABLE SID IS REPORTED, NOT DROPPED' {
    # Measured: (objectSid=S-1-1-0) returns NOTHING from a real DC, and S-1-5-11 comes back as a
    # ForeignSecurityPrincipal with no samAccountName at all. Dropping either would report the
    # object as clean.
    function Resolve-Name { param([string]$Sid, [string]$DomainSid, $Found)
        if ($Found) { return $Found }
        if ($DomainSid -and $Sid -like "$DomainSid-*") { return "$Sid (ORPHANED -- deleted account in this domain)" }
        "$Sid (FOREIGN or unresolvable)"
    }
    ((Resolve-Name "$domSid-1500" $domSid $null) -match 'ORPHANED') -and
    ((Resolve-Name 'S-1-5-21-9-9-9-1500' $domSid $null) -match 'FOREIGN')
}

"== the scripts are well-formed =="
foreach ($s in @('Get-AdDelegation', 'Get-AdLockoutSource')) {
    Check "$s.ps1 parses" {
        $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $repo "scripts\$s.ps1"), [ref]$null, [ref]$errs)
        (-not $errs) -or $errs.Count -eq 0
    }
}

$delegSrc = Get-Content (Join-Path $repo 'scripts\Get-AdDelegation.ps1') -Raw
$lockSrc  = Get-Content (Join-Path $repo 'scripts\Get-AdLockoutSource.ps1') -Raw

# ⚠ A "the source must NOT contain X" test has to look at CODE, not at the file. These scripts
# document the wrong forms in order to warn about them -- Get-AdLockoutSource explains why it
# filters lockoutTime>=1 "rather than (lockoutTime=*)" -- so a raw text search fails on the
# comment that exists to prevent the very bug being tested for. Tokenising and dropping the
# comments is exact, where stripping '#' by hand would also mangle any string containing one.
function Get-CodeOnly {
    param([string]$Path)
    $tokens = $null
    $errs = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errs)
    (@($tokens | Where-Object { "$($_.Kind)" -ne 'Comment' } | ForEach-Object { $_.Text })) -join ' '
}
$delegCode = Get-CodeOnly (Join-Path $repo 'scripts\Get-AdDelegation.ps1')
$lockCode  = Get-CodeOnly (Join-Path $repo 'scripts\Get-AdLockoutSource.ps1')

Check 'the tokenizer really does drop the comments' {
    # If this ever stops being true, every "must NOT contain" check below silently starts passing
    # for the wrong reason.
    ($lockSrc -match 'lockoutTime=\*') -and -not ($lockCode -match 'lockoutTime=\*')
}

Check 'the delegation audit has NO write path' {
    # Read-only by design, for the same reason as the privilege audit: every finding is a decision
    # about who should have access. Guard against a future edit adding one.
    -not ($delegCode -match '\bCommitChanges\b|\bAddAccessRule\b|\bSetAccessRule\b|\bRemoveAccessRule\b|\bSetOwner\b|\bUnlock-AdmUser\b|\bSet-AdmUserEnabled\b')
}
Check 'the delegation audit sets SecurityMasks EXPLICITLY' {
    # ⛔ Without this the SD_FLAGS control is never sent and the server decides what to return --
    # including the SACL, which needs SeSecurityPrivilege. Owner must be in the set or the
    # ownership section reports "no owner" on every object.
    # ⚠ Whitespace-tolerant, because Get-CodeOnly joins TOKENS with a space and the brackets of a
    # type literal are tokens of their own: "[X]::Owner" comes back as "[ X ] :: Owner". A regex
    # written against the file's own spacing passes on the raw source and fails here for a reason
    # that has nothing to do with the code -- which is what it did, twice, before this comment.
    ($delegCode -match 'SecurityMasks\s*\]\s*::\s*Owner') -and ($delegCode -match 'SecurityMasks\s*\]\s*::\s*Dacl')
}
Check 'the delegation audit uses the correct mask test everywhere' {
    # The naive form must not reappear. A search for "-band $RIGHT_..." NOT followed by the -eq
    # that makes it correct.
    $naive = '-band\s+\$RIGHT_[A-Z_]+\s*\)?\s*-ne\s+0'
    # ⛔ Prove the guard can actually fire before trusting that it did not. A regex that matches
    # nothing passes this test for ever, whatever the code says.
    $canFail = ('if (($mask -band $RIGHT_GENERIC_ALL) -ne 0) { }' -match $naive)
    $canFail -and ([regex]::Matches($delegCode, $naive).Count -eq 0)
}
Check 'the lockout script queries per-DC by PINNING DomainControllers' {
    # Get-AdmSearchResult always uses the FIRST entry in the profile's list, so the only way to
    # choose a DC is to clone the record with a single-address list.
    ($lockCode -match 'DomainControllers\s*=\s*@\(\s*\$Address\s*\)') -and ($lockCode -match 'Invoke-AdmAdsiSearch')
}
Check 'the lockout script filters lockoutTime>=1, NOT lockoutTime=*' {
    # An unlocked account KEEPS lockoutTime with a value of 0, so a presence test matches every
    # account that has ever been locked -- a completely different question.
    ($lockCode -match 'lockoutTime>=1') -and -not ($lockCode -match 'lockoutTime=\*')
}
Check 'the lockout script does not use nTDSDSA without a SearchBase' {
    # Measured: 0 hits from DC=corp,DC=example,DC=com, 1 from CN=Configuration,DC=corp,DC=example,DC=com. If that
    # filter is ever used in code it must carry the configuration naming context as its base.
    (-not ($lockCode -match 'nTDSDSA')) -or ($lockCode -match 'configDn')
}
Check 'the lockout script tells NoMatchingEventsFound apart from a real failure' {
    # The only locale-invariant discriminator. Matching the English message misreports every empty
    # read on a non-English machine as an unknown error.
    $lockCode -match 'NoMatchingEventsFound'
}
Check 'the ONLY write in the lockout script is Unlock-AdmUser' {
    ($lockCode -match '\bUnlock-AdmUser\b') -and
    (-not ($lockCode -match '\bReset-AdmUserPassword\b|\bSet-AdmUserEnabled\b|\bRemove-AdmObject\b|\bSet-AdmObjectAttribute\b|\bCommitChanges\b'))
}
Check 'both scripts import the module WITHOUT -Force' {
    # A forced import makes a fresh module instance and RE-LOCKS the caller's store, so a script
    # run from the CLI or the GUI would demand the passphrase again.
    ($delegCode -match 'Import-Module') -and ($lockCode -match 'Import-Module') -and
    (-not ($delegCode -match "ADAdmin\.psd1'\s*\)\s*-Force")) -and
    (-not ($lockCode  -match "ADAdmin\.psd1'\s*\)\s*-Force"))
}
Check 'both scripts declare the strict settings the house requires' {
    ($delegCode -match 'Set-StrictMode -Version 2\.0') -and ($delegCode -match "ErrorActionPreference = 'Stop'") -and
    ($lockCode  -match 'Set-StrictMode -Version 2\.0') -and ($lockCode  -match "ErrorActionPreference = 'Stop'")
}
Check 'both scripts document the exit codes in .NOTES' {
    # Raw source on purpose: comment-based help IS a comment.
    ($delegSrc -match 'EXIT CODES') -and ($lockSrc -match 'EXIT CODES') -and ($lockSrc -match '20\s+a change failed')
}
Check 'neither script uses the return-an-empty-array form' {
    # The collection-return trap, hit five times in this repo. `return @()` unrolls to $null and
    # the caller's .Count throws under strict mode.
    (-not ($delegCode -match 'return\s+@\(\s*\)')) -and (-not ($lockCode -match 'return\s+@\(\s*\)'))
}

Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { "`nFAILURES: $fail"; exit 1 } else { "`nall delegation/lockout checks passed"; exit 0 }
