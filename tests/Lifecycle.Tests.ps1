# Lifecycle.Tests.ps1 -- the pure, deterministic parts of the object-lifecycle, group, topology
# and recovery cmdlets: the decoders and DN handling that a wrong answer from is silent.
#
# Everything here runs with NO directory and NO credential store, which is the point -- these are
# the bits that can be got wrong in a way no live run would obviously reveal, because they return
# a plausible value rather than an error.

$repo = Split-Path -Parent $PSScriptRoot
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0   # match the module, or the harness tests a laxer world than production

# Dot-sourced rather than imported, because the helpers under test are deliberately not exported.
. (Join-Path $repo 'ADAdmin\Private\Directory.ps1')
. (Join-Path $repo 'ADAdmin\Public\Objects.ps1')
# Detail.ps1 owns ConvertTo-AdmInt64, which ConvertTo-AdmSignedFlag delegates parsing to. There
# is one numeric parser in the module by agreement, so this suite depends on it.
. (Join-Path $repo 'ADAdmin\Public\Detail.ps1')
. (Join-Path $repo 'ADAdmin\Public\Lifecycle.ps1')
. (Join-Path $repo 'ADAdmin\Public\Groups.ps1')
. (Join-Path $repo 'ADAdmin\Public\Topology.ps1')
. (Join-Path $repo 'ADAdmin\Public\Recovery.ps1')
. (Join-Path $repo 'ADAdmin\Private\Util.ps1')
. (Join-Path $repo 'ADAdmin\Public\Bulk.ps1')

$fail = 0
function Check($label, $actual, $expected) {
    if ([string]$actual -eq [string]$expected) { "  PASS  {0,-52} -> {1}" -f $label, $actual }
    else { "  FAIL  {0,-52} -> {1}; wanted {2}" -f $label, $actual, $expected; $script:fail++ }
}
function CheckTrue($label, $condition) {
    if ($condition) { "  PASS  {0}" -f $label }
    else { "  FAIL  {0}" -f $label; $script:fail++ }
}

"== RDN prefix: an OU does not rename as CN= =="
Check 'CN object'      (Get-AdmRdnPrefix -DistinguishedName 'CN=Jo,OU=Staff,DC=c,DC=com') 'CN'
Check 'OU object'      (Get-AdmRdnPrefix -DistinguishedName 'OU=Staff,DC=c,DC=com')       'OU'
Check 'domain head'    (Get-AdmRdnPrefix -DistinguishedName 'DC=c,DC=com')                'DC'
Check 'lowercase in'   (Get-AdmRdnPrefix -DistinguishedName 'ou=Staff,DC=c')              'OU'
Check 'malformed -> CN' (Get-AdmRdnPrefix -DistinguishedName 'not-a-dn')                  'CN'

"== parent DN: splitting on ',' is wrong when a CN contains an escaped comma =="
Check 'simple'   (Get-AdmParentDn -DistinguishedName 'CN=Jo,OU=Staff,DC=c,DC=com') 'OU=Staff,DC=c,DC=com'
Check 'nested'   (Get-AdmParentDn -DistinguishedName 'OU=A,OU=B,DC=c')             'OU=B,DC=c'
# ⭐ THE ONE THAT MATTERS. "Smith, Jo" is an ordinary AD common name and its comma is escaped;
# a naive -split ',' returns " Jo,OU=Staff,DC=c" and every move/delete built on it targets junk.
Check 'escaped comma' (Get-AdmParentDn -DistinguishedName 'CN=Smith\, Jo,OU=Staff,DC=c') 'OU=Staff,DC=c'
Check 'no parent'     (Get-AdmParentDn -DistinguishedName 'DC=com')                       ''

"== RDN escaping: the write-side counterpart, and it must round-trip =="
Check 'comma escaped'     (ConvertTo-AdmRdnEscaped -Value 'Smith, Jo')   'Smith\, Jo'
Check 'backslash escaped' (ConvertTo-AdmRdnEscaped -Value 'a\b')         'a\\b'
Check 'plus escaped'      (ConvertTo-AdmRdnEscaped -Value 'a+b')         'a\+b'
Check 'equals escaped'    (ConvertTo-AdmRdnEscaped -Value 'a=b')         'a\=b'
Check 'nothing to do'     (ConvertTo-AdmRdnEscaped -Value 'Plain Name')  'Plain Name'
Check 'empty stays empty' (ConvertTo-AdmRdnEscaped -Value '')            ''
# ⛔ THE BACKSLASH MUST BE ESCAPED FIRST. Do it last and the backslashes added for the other
# characters get escaped again, so "Smith, Jo" becomes "Smith\\, Jo" and the DN is wrong in a way
# that still looks plausible.
Check 'no double-escaping' (ConvertTo-AdmRdnEscaped -Value 'a\,b')       'a\\\,b'
# The pair has to compose: build a DN with an escaped RDN, and reading the parent back must
# return the container we put it in rather than a fragment of the name.
$built = "CN=$(ConvertTo-AdmRdnEscaped -Value 'Smith, Jo'),OU=Staff,DC=c,DC=com"
Check 'escape -> parse round trip' (Get-AdmParentDn -DistinguishedName $built) 'OU=Staff,DC=c,DC=com'

"== groupType: security groups are NEGATIVE as Int32 =="
Check 'global security'      (ConvertTo-AdmGroupType -Scope Global      -Category Security)     -2147483646
Check 'domainlocal security' (ConvertTo-AdmGroupType -Scope DomainLocal -Category Security)     -2147483644
Check 'universal security'   (ConvertTo-AdmGroupType -Scope Universal   -Category Security)     -2147483640
Check 'global distribution'  (ConvertTo-AdmGroupType -Scope Global      -Category Distribution)  2
Check 'dlocal distribution'  (ConvertTo-AdmGroupType -Scope DomainLocal -Category Distribution)  4
Check 'universal distrib'    (ConvertTo-AdmGroupType -Scope Universal   -Category Distribution)  8
# A security group read as a positive number is the sign the 0x80000000 bit was dropped.
CheckTrue 'security bit makes it negative' ((ConvertTo-AdmGroupType -Scope Global -Category Security) -lt 0)

"== ConvertTo-AdmSignedFlag: parses via ConvertTo-AdmInt64, adds the signed-32 wrap =="
Check 'decimal'          (ConvertTo-AdmSignedFlag 512)      512
Check 'decimal string'   (ConvertTo-AdmSignedFlag '512')    512
# ⚠ The hex STRING has to work, because a hex LITERAL in argument position stringifies to its
# own source text ("0x200") and a [string]-then-TryParse round trip silently yields 0.
Check 'hex string'       (ConvertTo-AdmSignedFlag '0x200')  512
Check 'hex literal'      (ConvertTo-AdmSignedFlag 0x200)    512
Check 'null is zero'     (ConvertTo-AdmSignedFlag $null)    0
Check 'garbage is zero'  (ConvertTo-AdmSignedFlag 'nope')   0
# ⭐ THE REASON THIS FUNCTION EXISTS. groupType sets 0x80000000 on every security group. Read as
# unsigned that is 2147483650, which overflows Int32; the directory means -2147483646.
Check 'groupType wraps to negative'  (ConvertTo-AdmSignedFlag 2147483650) -2147483646
Check 'agrees with the encoder'      (ConvertTo-AdmSignedFlag 2147483650) (ConvertTo-AdmGroupType -Scope Global -Category Security)
Check 'below the boundary unchanged' (ConvertTo-AdmSignedFlag 2147483647) 2147483647

"== gPLink parsing: flags decide whether a link does anything at all =="
Check 'empty string'  @(ConvertFrom-AdmGpLink '').Count   0
Check 'null'          @(ConvertFrom-AdmGpLink $null).Count 0
$one = @(ConvertFrom-AdmGpLink '[LDAP://cn={31B2F340-016D-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=c,DC=com;0]')
Check 'one link count' $one.Count 1
CheckTrue 'flag 0 -> enabled, not enforced'  ($one[0].Enabled -and -not $one[0].Enforced)
$disabled = @(ConvertFrom-AdmGpLink '[LDAP://cn={A},cn=policies,cn=system,DC=c;1]')
CheckTrue 'flag 1 -> link DISABLED'          (-not $disabled[0].Enabled)
$enforced = @(ConvertFrom-AdmGpLink '[LDAP://cn={A},cn=policies,cn=system,DC=c;2]')
CheckTrue 'flag 2 -> enforced and enabled'   ($enforced[0].Enforced -and $enforced[0].Enabled)
$both = @(ConvertFrom-AdmGpLink '[LDAP://cn={A},cn=policies,cn=system,DC=c;3]')
CheckTrue 'flag 3 -> enforced but disabled'  ($both[0].Enforced -and -not $both[0].Enabled)
$two = @(ConvertFrom-AdmGpLink '[LDAP://cn={A},cn=policies,DC=c;0][LDAP://cn={B},cn=policies,DC=c;2]')
Check 'two links'        $two.Count 2
Check 'order preserved'  $two[1].GpoDn 'cn={B},cn=policies,DC=c'

"== trust decoding =="
Check 'direction 0' (ConvertFrom-AdmTrustDirection 0) 'Disabled'
Check 'direction 1' (ConvertFrom-AdmTrustDirection 1) 'Inbound'
Check 'direction 2' (ConvertFrom-AdmTrustDirection 2) 'Outbound'
Check 'direction 3' (ConvertFrom-AdmTrustDirection 3) 'Bidirectional'
CheckTrue 'unknown direction is reported, not guessed' ((ConvertFrom-AdmTrustDirection 9) -like 'Unknown*')
Check 'type 2 is AD'    (ConvertFrom-AdmTrustType 2) 'Active Directory'
Check 'type 3 is MIT'   (ConvertFrom-AdmTrustType 3) 'MIT Kerberos realm'
$attrs = @(ConvertFrom-AdmTrustAttributes 0x4)
CheckTrue 'quarantine bit -> SID filtering flag' ($attrs -contains 'QuarantinedDomain')
$forest = @(ConvertFrom-AdmTrustAttributes 0x8)
CheckTrue 'forest transitive bit'               ($forest -contains 'ForestTransitive')
$combo = @(ConvertFrom-AdmTrustAttributes (0x1 -bor 0x8))
CheckTrue 'combined bits both decode'           (($combo -contains 'NonTransitive') -and ($combo -contains 'ForestTransitive'))
Check 'no bits -> empty'  @(ConvertFrom-AdmTrustAttributes 0).Count 0
# ⚠ A BARE 0x4 IN ARGUMENT POSITION ARRIVES AS THE STRING "0x4", and [int]::TryParse rejects it,
# which used to decode as NO FLAGS with no error at all. Both forms must give the same answer.
CheckTrue 'hex string "0x4" decodes'   (@(ConvertFrom-AdmTrustAttributes '0x4') -contains 'QuarantinedDomain')
CheckTrue 'hex and decimal agree'      ((@(ConvertFrom-AdmTrustAttributes '0x8') -join ',') -eq (@(ConvertFrom-AdmTrustAttributes 8) -join ','))
Check     'unparseable -> no flags'    @(ConvertFrom-AdmTrustAttributes 'rubbish').Count 0

"== GPO status =="
Check 'flags 0' (ConvertFrom-AdmGpoStatus 0) 'AllSettingsEnabled'
Check 'flags 1' (ConvertFrom-AdmGpoStatus 1) 'UserSettingsDisabled'
Check 'flags 2' (ConvertFrom-AdmGpoStatus 2) 'ComputerSettingsDisabled'
Check 'flags 3' (ConvertFrom-AdmGpoStatus 3) 'AllSettingsDisabled'

"== Windows LAPS JSON: the timestamp is HEX, not decimal =="
$when = [datetime]::SpecifyKind([datetime]'2024-01-01T00:00:00', 'Utc')
$hex  = [Convert]::ToString($when.ToFileTimeUtc(), 16)
$json = '{"n":"Administrator","t":"' + $hex + '","p":"Sec' + 'ret123!"}'
$laps = ConvertFrom-AdmLapsJson -Value $json
CheckTrue 'parsed a value'        ($null -ne $laps)
Check     'account'               $laps.Account  'Administrator'
Check     'password'              $laps.Password 'Secret123!'
# Parsing that hex as decimal yields a date centuries away, with no error to notice.
Check     'hex FILETIME decoded'  $laps.SetAt.ToString('yyyy-MM-dd') '2024-01-01'

# The directory hands binary-ish attributes back as Object[] of Byte, never as byte[] -- the same
# trap ConvertTo-AdmSidString exists for. A test passing a real byte[] would not catch it.
$bytesAsObjectArray = @([System.Text.Encoding]::UTF8.GetBytes($json))
CheckTrue 'fixture shape is Object[] not byte[]' (-not ($bytesAsObjectArray -is [byte[]]))
$fromBytes = ConvertFrom-AdmLapsJson -Value $bytesAsObjectArray
CheckTrue 'decodes from Object[] of Byte'        ($null -ne $fromBytes -and $fromBytes.Password -eq 'Secret123!')

CheckTrue 'garbage returns null, does not throw' ($null -eq (ConvertFrom-AdmLapsJson -Value 'not json'))
CheckTrue 'empty returns null'                   ($null -eq (ConvertFrom-AdmLapsJson -Value ''))

"== generated passwords: complexity is not optional, and neither is uniqueness =="
$pw = New-AdmRandomPassword
Check 'default length' $pw.Length 20
Check 'honours -Length' (New-AdmRandomPassword -Length 32).Length 32
# AD's default complexity policy wants three of four character classes; this guarantees all four.
# A generator that produced only lowercase would be accepted by New-AdmUser and then rejected by
# the directory with "unwilling to perform", which says nothing about passwords.
$many = @(1..40 | ForEach-Object { New-AdmRandomPassword })
CheckTrue 'every password has an uppercase' (@($many | Where-Object { $_ -cmatch '[A-Z]' }).Count -eq 40)
CheckTrue 'every password has a lowercase'  (@($many | Where-Object { $_ -cmatch '[a-z]' }).Count -eq 40)
CheckTrue 'every password has a digit'      (@($many | Where-Object { $_ -match '\d' }).Count -eq 40)
CheckTrue 'every password has a symbol'     (@($many | Where-Object { $_ -match '[!#%^*_+=?-]' }).Count -eq 40)
CheckTrue 'all 40 are distinct'             ((@($many | Sort-Object -Unique)).Count -eq 40)
# ⭐ THE SHUFFLE MATTERS. Without it the first four characters are always upper, lower, digit,
# symbol in that order -- which is a pattern an attacker can rely on and a human would not notice.
CheckTrue 'first character is not always uppercase' (@($many | Where-Object { $_[0] -cmatch '[A-Z]' }).Count -lt 40)
# Ambiguous glyphs are excluded on purpose: these get read aloud and typed by hand.
CheckTrue 'no ambiguous characters (0 O 1 l I)' (-not (@($many | Where-Object { $_ -cmatch '[0O1lI]' }).Count))

"== comment-based help actually reaches Get-Help =="
# `.SYNOPSIS <text>` on ONE line is silently ignored -- PowerShell needs the keyword to stand
# alone -- and a malformed first directive discards the whole block, .DESCRIPTION included. The
# symptom is a Synopsis that is really the generated syntax line, which reads fine until you
# notice it is not what anyone wrote.
# ⛔ ENUMERATED, NOT NAMED. This check listed five files by hand and was written when there were
# five. Four more of mine landed afterwards -- Bulk, Computers, Policies, Recycle -- and none of
# them was covered, so the regression could have come back in any of them with the guard sitting
# green beside it.
#
# That is the same failure twice over in one day: the no-plain-read check protected a hand-listed
# set, and the mojibake check scanned exactly one GUI file while the defect shipped from adm.ps1.
# ⭐ THE LESSON IS NOT "WIDEN THIS LIST" -- it is that a check which names its inputs will be
# outlived by the code it guards. Enumerate the directory and the file added next month is covered
# the day it lands.
$helpFiles = @(Get-ChildItem -LiteralPath (Join-Path $repo 'ADAdmin') -Recurse -Filter '*.ps1')
if ($helpFiles.Count -lt 10) {
    # A control that cannot legitimately be small: if the enumeration ever returns almost nothing,
    # this check would "pass" by scanning nothing at all, which is the silent-empty-result shape.
    "  FAIL  the help scan found only $($helpFiles.Count) file(s) -- the enumeration is broken"
    $script:fail++
}
$badHelp = 0
foreach ($f in $helpFiles) {
    $bad = @(Select-String -LiteralPath $f.FullName -Pattern '^\s*\.SYNOPSIS\s+\S' -AllMatches)
    if ($bad.Count) {
        "  FAIL  {0,-52} has {1} same-line .SYNOPSIS" -f $f.Name, $bad.Count
        $script:fail++; $badHelp++
    }
}
if (-not $badHelp) { "  PASS  {0,-52} help directives stand alone in all {1}" -f 'every file in ADAdmin', $helpFiles.Count }

"== a multi-valued attribute cut by RANGE is not an empty attribute =="
# ⛔ The search-level truncation flag cannot see this: the SEARCH completed, only the ATTRIBUTE
# was cut. The directory renames the property to `member;range=0-1499`, so a plain read returns
# $null and the caller concludes the list is EMPTY while everything reports success.
$plainRow = [pscustomobject]@{ 'member' = @('CN=a,DC=x', 'CN=b,DC=x') }
$plainRead = Get-AdmRangedProp $plainRow 'member'
Check 'plain attribute: value count'   @($plainRead.Values).Count 2
Check 'plain attribute: not truncated' $plainRead.Truncated $false

# The mangled name is what a real directory returns above the window.
$cutRow = [pscustomobject]@{ 'member;range=0-1499' = @('CN=a,DC=x', 'CN=b,DC=x') }
$cutRead = Get-AdmRangedProp $cutRow 'member'
Check     'ranged attribute: values still returned' @($cutRead.Values).Count 2
CheckTrue 'ranged attribute: reported TRUNCATED'    ($cutRead.Truncated -eq $true)
# ⚠ The whole point: the PLAIN read sees nothing at all on that row, so a caller using it
# concludes the list is empty while every other signal says the read succeeded.
CheckTrue 'the plain read sees NOTHING on that row' ($null -eq (Get-AdmRawProp $cutRow 'member'))

Check     'absent attribute is empty' @((Get-AdmRangedProp ([pscustomobject]@{ x = 1 }) 'member').Values).Count 0
CheckTrue 'absent attribute is not truncated' ((Get-AdmRangedProp ([pscustomobject]@{ x = 1 }) 'member').Truncated -eq $false)
CheckTrue 'null row does not throw' ((Get-AdmRangedProp $null 'member').Truncated -eq $false)

# ⛔ AND THE HASHTABLE RETURN IS SAFE, which is not obvious and is worth pinning. A key named
# `Values` on a hashtable sits alongside Hashtable's own `.Values` property, and if the .NET member
# won, `.Values` would return BOTH stored values -- the array AND the bool -- so `.Count` would be
# 2 no matter how many members there were. Measured: PowerShell resolves the KEY. Asserted here so
# a future refactor to a different container cannot silently change what `.Values` means.
$probe = Get-AdmRangedProp ([pscustomobject]@{ 'member' = @('only-one') }) 'member'
Check 'the Values key is not shadowed by Hashtable.Values' @($probe.Values).Count 1

"== helpers that RETURN a value are never called bare =="
# ⛔ THE REGRESSION THIS GUARDS. Set-AdmDaclMask was changed to return a bool; its call sites were
# left bare, so the bool leaked into the CALLER's output. Test-AdmObjectProtected then returned
# @($false,$true) -- and a two-element array is truthy whatever it holds -- so every object read
# as protected, every move and every unforced delete refused, and New-AdmOrganizationalUnit's
# return object lost its properties behind the stray value.
#
# ⚠ NO UNIT TEST CAUGHT IT AND THE WHOLE SUITE WAS GREEN. It took a live run against a DC. A
# static check is the cheap way to stop it recurring, so this asserts the call SHAPE rather than
# the behaviour: any call to one of these must be voided or assigned.
# ⛔ ENUMERATED, NOT NAMED -- same correction as the help scan above. This listed one function by
# hand, so the next action-verb helper that gains a return value would leak into its caller with
# the guard sitting green beside it. Instead: find every function that DECLARES an OutputType and
# whose verb implies an action rather than a query, and require its call sites to be voided or
# assigned.
#
# ⭐ Get-/Test-/ConvertTo- and friends are excluded because returning IS their job and callers
# naturally assign them. The danger is specifically a Set-/Add-/Remove- that quietly returns
# something, because its name promises it will not -- which is exactly how Set-AdmDaclMask's bool
# ended up inside Test-AdmObjectProtected's return, making every object look protected.
#
# ⚠ Unprotect-AdmBytes is caught by this enumeration too and passes on its own merits: its return
# is the decrypted value and every caller assigns it. No exemption needed, which is the sign the
# rule is the right one rather than a list with a hole cut for the inconvenient case.
$leaky = @()
foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $repo 'ADAdmin') -Recurse -Filter '*.ps1')) {
    $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errs)
    foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
        # ⛔ AN ALLOW-LIST OF VERBS THAT PROMISE NO RETURN, not a deny-list of ones that do.
        # The first version of this excluded Get-/Test-/ConvertTo- and friends, which let
        # Unprotect-AdmBytes through -- and it is CORRECT for that to return: decrypting IS
        # producing a value, and its caller comma-wraps it as its own return. The check fired on
        # right code, which is the always-complaining detector we have twice agreed is worthless.
        #
        # ⭐ The rule that actually holds: a Set-/Add-/Remove- style verb NAMES ITSELF as an
        # action, so a caller reasonably writes it bare -- and anything it returns lands silently
        # in that caller's output. Unprotect-, Get-, Test- carry no such promise.
        if ($fn.Name -notmatch '^(Set|Add|Remove|Clear|Close|Write|Enable|Disable|Register|Unregister|Move|Rename|Restore|Lock|Unlock|Initialize|Save)-') { continue }
        $hasOut = $false
        if ($fn.Body.ParamBlock -and $fn.Body.ParamBlock.Attributes) {
            foreach ($a in $fn.Body.ParamBlock.Attributes) {
                if ($a.TypeName.Name -eq 'OutputType') { $hasOut = $true }
            }
        }
        if ($hasOut) { $leaky += $fn.Name }
    }
}
$leaky = @($leaky | Sort-Object -Unique)
if (-not $leaky.Count) {
    # A control that cannot legitimately be empty: the module has at least one such function, so
    # zero means the enumeration broke and this check is scanning nothing.
    "  FAIL  found NO action-verb functions declaring an OutputType -- the enumeration is broken"
    $script:fail++
}
foreach ($name in $leaky) {
    $bad = New-Object System.Collections.ArrayList
    foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $repo 'ADAdmin') -Recurse -Filter '*.ps1')) {
        $n = 0
        foreach ($line in (Get-Content -LiteralPath $f.FullName)) {
            $n++
            if ($line -match '^\s*#') { continue }
            if ($line -notmatch [regex]::Escape($name)) { continue }
            if ($line -match "function\s+$([regex]::Escape($name))") { continue }
            # Acceptable: [void](...), $x = ..., $null = ...
            if ($line -match '\[void\]|=\s*.*' + [regex]::Escape($name)) { continue }
            [void]$bad.Add("$($f.Name):$n")
        }
    }
    if ($bad.Count) {
        "  FAIL  {0} is called bare at {1} -- its return value leaks into the caller" -f $name, ($bad -join ', ')
        $script:fail++
    } else { "  PASS  {0,-52} every call is voided or assigned" -f $name }
}

"== no duplicate function names across the module =="
# Every Public and Private file dot-sources into ONE scope, so two files defining the same name
# do not error -- the one that sorts later silently wins. With more than one person in the module
# that is a real hazard, and it is cheap to assert against.
$defs = @{}
foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $repo 'ADAdmin') -Recurse -Filter '*.ps1')) {
    $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errs)
    foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
        if (-not $defs.ContainsKey($fn.Name)) { $defs[$fn.Name] = New-Object System.Collections.ArrayList }
        [void]$defs[$fn.Name].Add($f.Name)
    }
}
$dupes = @($defs.Keys | Where-Object { $defs[$_].Count -gt 1 })
if ($dupes.Count) {
    foreach ($d in $dupes) { "  FAIL  duplicate function '{0}' in {1}" -f $d, ($defs[$d] -join ', '); $script:fail++ }
} else { "  PASS  {0} function names, all unique" -f $defs.Count }

"== every name the manifest exports has a function behind it =="
# Export-ModuleMember tolerates a name with no implementation in silence; the failure surfaces
# later as "command not found" for something the manifest promised.
$manifest = Import-PowerShellDataFile (Join-Path $repo 'ADAdmin\ADAdmin.psd1')
$missing = @($manifest.FunctionsToExport | Where-Object { -not $defs.ContainsKey($_) })
if ($missing.Count) {
    foreach ($m in $missing) { "  FAIL  manifest exports '{0}' but nothing defines it" -f $m; $script:fail++ }
} else { "  PASS  all {0} exported names are defined" -f @($manifest.FunctionsToExport).Count }

"== every doc is reachable, and every doc link resolves =="
# ⛔ THE SAME RULE AS THE CMDLET REACHABILITY CHECK BELOW, APPLIED TO PROSE. A document that is
# tracked, shipped in the release zip, and linked from nowhere is not documentation -- it is a
# file. `docs\gui-conventions.md` sat unlinked while carrying seventeen interface rules, including
# four written the same day; other docs were the same.
#
# ⚠ CHECKED IN BOTH DIRECTIONS, because they fail differently: an unlinked doc is invisible and
# silent, while a broken link is visible and embarrassing. Neither is caught by the other.
$docFiles = @(Get-ChildItem -LiteralPath (Join-Path $repo 'docs') -Filter '*.md' -File)
if ($docFiles.Count -lt 5) {
    # A control that cannot legitimately be empty -- see the note on the help scan.
    "  FAIL  the docs scan found only $($docFiles.Count) file(s) -- the enumeration is broken"
    $script:fail++
}
$readmeText = Get-Content -LiteralPath (Join-Path $repo 'README.md') -Raw
$linked = @([regex]::Matches($readmeText, 'docs/([a-z0-9-]+\.md)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)

$unlinked = @($docFiles | Where-Object { $linked -notcontains $_.Name })
if ($unlinked.Count) {
    foreach ($d in $unlinked) { "  FAIL  docs\{0} exists and ships, but the README links to it from nowhere" -f $d.Name; $script:fail++ }
} else { "  PASS  {0,-52} all {1} docs are linked from the README" -f 'docs reachable', $docFiles.Count }

$broken = @($linked | Where-Object { -not (Test-Path -LiteralPath (Join-Path $repo "docs\$_")) })
if ($broken.Count) {
    foreach ($b in $broken) { "  FAIL  the README links docs\{0}, which does not exist" -f $b; $script:fail++ }
} else { "  PASS  {0,-52} all {1} README doc links resolve" -f 'doc links resolve', $linked.Count }

"== every exported feature is reachable from somewhere a user can get to =="
# ⛔ EXPORTING A CMDLET IS NOT SHIPPING A FEATURE. The manifest check above catches a NAME with no
# function; this catches the inverse -- a function nobody can call. Both are invisible: the module
# loads, the tests pass, and the capability simply does not exist for any user.
#
# New-AdmComputer and Set-AdmComputer shipped exported and wired to NOTHING, found by a
# coherence pass rather than by any test. Hence this.
#
# The allow-list is the library API: building blocks for scripts and for the GUI, deliberately not
# user-facing verbs. Adding to it should be a decision, which is the point of having to edit it.
$libraryOnly = @(
    'ConvertFrom-AdmGpLink', 'ConvertFrom-AdmGpoStatus', 'ConvertFrom-AdmGroupType',
    'ConvertFrom-AdmPsoDuration', 'ConvertFrom-AdmTrustAttributes', 'ConvertFrom-AdmTrustDirection',
    'ConvertFrom-AdmTrustType', 'ConvertFrom-AdmUac', 'ConvertTo-AdmRdnEscaped',
    'ConvertTo-AdmSignedFlag', 'Get-AdmNamingContext', 'Get-AdmParentDn', 'Get-AdmRangedAttribute',
    'Get-AdmRdnPrefix', 'Invoke-AdmGuardedPublic', 'New-AdmLdapConnection', 'Resolve-AdmObjectDn',
    'Test-AdmObjectProtected', 'Test-AdmSchemaAttribute'
)
$surfaceText = New-Object System.Collections.ArrayList
[void]$surfaceText.Add((Get-Content -LiteralPath (Join-Path $repo 'adm.ps1') -Raw))
foreach ($d in @('gui', 'scripts')) {
    $dir = Join-Path $repo $d
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.ps*' -File)) {
        [void]$surfaceText.Add((Get-Content -LiteralPath $f.FullName -Raw))
    }
}
$surface = $surfaceText.ToArray() -join "`n"
$orphans = @($manifest.FunctionsToExport |
              Where-Object { $libraryOnly -notcontains $_ } |
              Where-Object { $surface -notmatch [regex]::Escape($_) })
if ($orphans.Count) {
    foreach ($o in $orphans) {
        "  FAIL  '{0}' is exported but reachable from no CLI verb, GUI control or script" -f $o
        $script:fail++
    }
} else {
    "  PASS  {0,-52} all {1} feature exports are reachable" -f 'reachability', @($manifest.FunctionsToExport | Where-Object { $libraryOnly -notcontains $_ }).Count
}

if ($fail -gt 0) { "`nFAILURES: $fail"; exit 1 } else { "`nall lifecycle checks passed"; exit 0 }
