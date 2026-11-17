# A size limit chosen against a lab is a silent wrong answer waiting for production.
#
# ⛔ WHAT THIS SUITE DEFENDS. DirectorySearcher stops at SizeLimit and says NOTHING: you get
# exactly N rows and no indication that N+900 more existed. Displaying 200 of 3000 rows is a
# nuisance. Deriving "this site has no subnets", "this GPO is linked nowhere" or "this OU
# contains 40 objects, delete it" from 200 of 3000 is a WRONG ANSWER SOMEBODY ACTS ON, and it is
# indistinguishable from a right one.
#
# So the searchers over-fetch by one row and set a sticky flag, and this suite proves the three
# properties every caller depends on: it fires when rows were dropped, it does NOT fire when the
# result merely equals the limit, and it SURVIVES a second, smaller search inside the same cmdlet.
$repo = Split-Path -Parent $PSScriptRoot   # run from any clone, USB or share
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$fail = 0
function Check($name, [scriptblock]$b) {
    try { if (& $b) { "  PASS  $name" } else { "  FAIL  $name"; $script:fail++ } }
    catch { "  FAIL  $name -- $($_.Exception.Message)"; $script:fail++ }
}

$work = Join-Path $env:TEMP ("admtrunc-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$env:ADADMIN_STORE    = Join-Path $work 'store.json'
$env:ADADMIN_LOG_DIR  = Join-Path $work 'logs'
$env:ADADMIN_PROVIDER = 'mock'

Import-Module (Join-Path $repo 'ADAdmin\ADAdmin.psd1') -Force

$pp = ConvertTo-SecureString 'trunc-suite-pass' -AsPlainText -Force
Initialize-AdmStore -RecipientName t -Passphrase $pp -Iterations 100000 -Force -Confirm:$false | Out-Null
Unlock-AdmStore -Passphrase $pp | Out-Null
Register-AdmDomain -Name corp -DnsDomain 'corp.example.com' -NetbiosName CORP -Confirm:$false | Out-Null
$c = New-Object System.Management.Automation.PSCredential('CORP\svc', (ConvertTo-SecureString 'x' -AsPlainText -Force))
Set-AdmDomainCredential -Domain corp -Credential $c -Tier read -SetDefault -Confirm:$false | Out-Null

# corp.example.com holds four users in the fixture. Everything below is expressed against that
# count rather than a typed number, so growing the fixture cannot silently void these checks.
$total = @(Get-AdmUser -Target corp.example.com -Limit 1000).Count
"fixture holds $total users in corp.example.com"

"== the flag itself =="
Check 'exported by the module' {
    $e = (Get-Module ADAdmin).ExportedFunctions.Keys
    ($e -contains 'Get-AdmSearchTruncated') -and ($e -contains 'Reset-AdmSearchTruncated')
}
Check 'reset clears it' { Reset-AdmSearchTruncated; -not (Get-AdmSearchTruncated) }

"== fires only when rows were actually dropped =="
Check 'a limit BELOW the count reports truncation' {
    Reset-AdmSearchTruncated
    $rows = @(Get-AdmUser -Target corp.example.com -Limit ($total - 1))
    $rows.Count -eq ($total - 1) -and (Get-AdmSearchTruncated)
}
Check 'a limit EQUAL to the count does NOT report truncation' {
    # ⛔ THE CHECK THAT JUSTIFIES OVER-FETCHING. Every call site used to test `$rows.Count -ge
    # $limit`, which cannot tell "exactly $limit objects exist" from "stopped at $limit" and so
    # cries truncation on a complete answer. Asking the directory for one row more than we return
    # is what makes the two distinguishable.
    Reset-AdmSearchTruncated
    $rows = @(Get-AdmUser -Target corp.example.com -Limit $total)
    $rows.Count -eq $total -and -not (Get-AdmSearchTruncated)
}
Check 'a limit ABOVE the count does not report truncation' {
    Reset-AdmSearchTruncated
    @(Get-AdmUser -Target corp.example.com -Limit ($total + 50)).Count -eq $total -and
        -not (Get-AdmSearchTruncated)
}

"== sticky across a cmdlet that searches more than once =="
Check 'a later untruncated read does NOT clear an earlier truncation' {
    # ⛔ THE FAILURE MODE THAT MADE THE FLAG STICKY. Get-AdmGroupMember resolves the group, reads
    # members, then reads primary-group members. Had each search cleared the flag on entry, a
    # truncated member read followed by a one-row SID lookup would report NOT truncated -- the
    # precise wrong answer this exists to prevent.
    Reset-AdmSearchTruncated
    Get-AdmUser -Target corp.example.com -Limit 1 | Out-Null      # truncates
    Get-AdmUser -Target corp.example.com -Limit 1000 | Out-Null   # does not
    Get-AdmSearchTruncated
}
Check 'and the next reset does clear it' { Reset-AdmSearchTruncated; -not (Get-AdmSearchTruncated) }

"== the over-fetch arithmetic =="
Check 'one past a normal limit' { (& (Get-Module ADAdmin) { Get-AdmOverfetchLimit 200 }) -eq 201 }
Check 'zero stays zero -- 0 means the SERVER decides, and cannot be over-fetched' {
    (& (Get-Module ADAdmin) { Get-AdmOverfetchLimit 0 }) -eq 0
}
Check 'MaxValue does not overflow to a negative SizeLimit' {
    # [int]::MaxValue + 1 wraps to [int]::MinValue, and DirectorySearcher rejects a negative
    # SizeLimit outright -- so the search would throw instead of returning rows.
    (& (Get-Module ADAdmin) { Get-AdmOverfetchLimit ([int]::MaxValue) }) -eq [int]::MaxValue
}

"== both searchers carry the same guard =="
Check 'the tombstone searcher over-fetches too' {
    # It matters more there than anywhere: "the object is not in the Recycle Bin" is how somebody
    # concludes it is unrecoverable.
    $src = Get-Content (Join-Path $repo 'ADAdmin\Public\Recycle.ps1') -Raw
    $src -match 'SizeLimit\s*=\s*Get-AdmOverfetchLimit' -and $src -match 'AdmLastSearchTruncated\s*=\s*\$true'
}
Check 'the ADSI searcher over-fetches too' {
    $src = Get-Content (Join-Path $repo 'ADAdmin\Private\Directory.ps1') -Raw
    $src -match 'SizeLimit\s*=\s*Get-AdmOverfetchLimit' -and $src -match 'AdmLastSearchTruncated\s*=\s*\$true'
}
Check 'no searcher clears the flag on entry' {
    # A clear-on-entry anywhere would quietly un-stick it and reintroduce the bug above.
    $src = (Get-Content (Join-Path $repo 'ADAdmin\Private\Directory.ps1') -Raw) +
           (Get-Content (Join-Path $repo 'ADAdmin\Public\Recycle.ps1') -Raw)
    @([regex]::Matches($src, 'AdmLastSearchTruncated\s*=\s*\$false')).Count -eq 2   # declaration + Reset-
}

"== callers that DERIVE a conclusion ask the flag, not the row count =="
Check 'the OU delete confirmation asks the flag' {
    # Truncation here understates how much a delete destroys -- the worst direction to be wrong.
    $src = Get-Content (Join-Path $repo 'gui\Start-AdmGui.ps1') -Raw
    $src -match 'AT LEAST \$\(\$found\.Count - 1\)' -and $src -match 'Reset-AdmSearchTruncated'
}
Check 'every function that reads the flag also resets it' {
    # ⛔ A Get WITHOUT A RESET READS A STALE FLAG. Sticky is what makes the mechanism correct
    # through multi-search cmdlets, and it is exactly what makes a missing reset silent: the
    # panel inherits whatever the last unrelated read left behind and cries truncation on a
    # complete answer, or -- worse, if something cleared it -- stays quiet on a cut one. Checked
    # over the AST rather than by counting lines, so a reset in a DIFFERENT function cannot
    # satisfy it.
    $bad = @()
    foreach ($f in @('gui\Start-AdmGui.ps1', 'ADAdmin\Public\Detail.ps1', 'ADAdmin\Public\Topology.ps1')) {
        $tok = $null; $perr = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repo $f), [ref]$tok, [ref]$perr)
        $fns = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
        foreach ($fn in $fns) {
            $src = $fn.Extent.Text
            if ($src -match 'Get-AdmSearchTruncated' -and $src -notmatch 'Reset-AdmSearchTruncated') {
                $bad += "$f :: $($fn.Name)"
            }
        }
    }
    if ($bad.Count) { $bad | ForEach-Object { "     $_" } }
    $bad.Count -eq 0
}
Check 'no caller still tests -ge its own limit' {
    $src = @(Get-Content (Join-Path $repo 'gui\Start-AdmGui.ps1')) +
           @(Get-Content (Join-Path $repo 'ADAdmin\Public\Detail.ps1'))
    $bad = @($src | Where-Object { $_ -match '\.Count -ge \$\w*[Ll]imit' })
    if ($bad.Count) { $bad | ForEach-Object { "     $($_.Trim())" } }
    $bad.Count -eq 0
}

"== the audit scripts, where the finding IS the absence =="
# ⛔ THESE FOUR ANSWER LARGELY BY REPORTING NOTHING: no dangerous delegation, no duplicate SPN, no
# stale machine, no unconstrained delegation. An object past the size limit is never examined and
# so can never be reported -- which means a truncated audit does not look SHORT, it looks CLEAN.
# That is the one output shape where truncation is indistinguishable from a good result, so each
# of them has to say so rather than leave the reader to infer it from a row count.
$audits = @(
    @{ File = 'scripts\Get-AdPrivilegedAccess.ps1'; Reset = 'Reset-AdmSearchTruncated'; Read = 'Get-AdmSearchTruncated' }
    @{ File = 'scripts\Find-AdDuplicates.ps1';      Reset = 'Reset-AdmSearchTruncated'; Read = 'Get-AdmSearchTruncated' }
    @{ File = 'scripts\Find-StaleComputers.ps1';    Reset = 'Reset-AdmSearchTruncated'; Read = 'Get-AdmSearchTruncated' }
    @{ File = 'scripts\Get-AdLockoutSource.ps1';    Reset = 'Reset-AdmSearchTruncated'; Read = 'Get-AdmSearchTruncated' }
    @{ File = 'scripts\Invoke-AdmSweep.ps1';        Reset = 'Reset-AdmSearchTruncated'; Read = 'Get-AdmSearchTruncated' }
    # Its own searcher, so its own flag -- it does not go through the module's search path.
    @{ File = 'scripts\Get-AdDelegation.ps1';       Reset = 'DelegationReadTruncated = \$false'; Read = 'DelegationReadTruncated' }
)
foreach ($a in $audits) {
    $name = Split-Path $a.File -Leaf
    Check "$name notices a truncated read" {
        $src = Get-Content (Join-Path $repo $a.File) -Raw
        ($src -match $a.Reset) -and ($src -match $a.Read)
    }
}
Check 'Find-AdDuplicates exits 30 rather than 0 when it could not see everything' {
    # ⛔ EXIT 0 IS A CLAIM, NOT A DEFAULT. Invoke-AdmSweep reads these codes and treats anything
    # other than 0 or 10 as "did not complete", so a truncated run has to leave the 0 alone or a
    # sweep records the domain as clean on the strength of a partial read.
    $src = Get-Content (Join-Path $repo 'scripts\Find-AdDuplicates.ps1') -Raw
    ($src -match 'exit 30') -and ($src -match '(?m)^\s+30\s+a read was truncated')
}
Check 'the sweep keeps "could not look" apart from "did not complete"' {
    # ⚠ Every house script uses exit 30 for "ran, but could not check everything". Folding that
    # into FAILED would make "twenty forests reported nothing" and "sixteen reported nothing
    # and three could not look" produce the same summary line -- and they prompt different
    # actions: raise the limit versus fix connectivity.
    $src = Get-Content (Join-Path $repo 'scripts\Invoke-AdmSweep.ps1') -Raw
    $src -match '\$childCode -eq 30' -and $src -match "Add-Status \`$d\.Name 'PARTIAL'"
}
Check 'and a PARTIAL domain keeps the findings it DID report' {
    # ⛔ THE LABEL MUST NOT CONTRADICT THE BEHAVIOUR. A domain that exited 30 ran and printed
    # findings -- the 30 is about coverage, not about the output. Skipping to the next domain
    # would discard them while the status line said "it reported what it saw", and what it did
    # find is real. So the 30 branch must NOT `continue` past the row-collection loop.
    $lines = @(Get-Content (Join-Path $repo 'scripts\Invoke-AdmSweep.ps1') |
               Where-Object { $_.TrimStart() -notmatch '^#' })
    $flag = ($lines | Select-String -SimpleMatch '$partialDomain = ($childCode -eq 30)' | Select-Object -First 1).LineNumber
    $add  = ($lines | Select-String -SimpleMatch '[void]$rows.Add($r); $n++' | Select-Object -First 1).LineNumber
    $stat = ($lines | Select-String -SimpleMatch "Add-Status `$d.Name 'PARTIAL' `$n" | Select-Object -First 1).LineNumber
    if (-not ($flag -and $add -and $stat)) { "     flag=$flag add=$add status=$stat" }
    $flag -and $add -and $stat -and $flag -lt $add -and $add -lt $stat
}
Check 'the cross-domain sweep will not call a partially-read domain ok' {
    # ⭐ WORSE THAN THE SINGLE-DOMAIN CASE, NOT BETTER. A collision is found by comparing two
    # holders, so one cut domain out of twenty silently removes every pair with a leg in it --
    # including pairs whose OTHER leg was read perfectly. 'ok' is a claim about COVERAGE, not
    # merely about not throwing.
    $src = Get-Content (Join-Path $repo 'scripts\Invoke-AdmSweep.ps1') -Raw
    ($src -match "Add-Status \`$d\.Name 'PARTIAL'") -and ($src -match 'exit 30') -and
    ($src -match "(?m)^\s+30\s+every domain answered")
}
Check 'and a partial sweep does not outrank a real finding' {
    $lines = @(Get-Content (Join-Path $repo 'scripts\Invoke-AdmSweep.ps1') |
               Where-Object { $_.TrimStart() -notmatch '^#' })
    $ten    = ($lines | Select-String -SimpleMatch 'exit 10' | Select-Object -First 1).LineNumber
    $thirty = ($lines | Select-String -SimpleMatch 'exit 30' | Select-Object -First 1).LineNumber
    $ten -and $thirty -and $ten -lt $thirty
}
Check 'and findings still win the exit code over truncation' {
    # 10 means "act on this". Returning 30 instead would tell the caller the run was inconclusive
    # and cast doubt on duplicates that were genuinely found.
    $lines = @(Get-Content (Join-Path $repo 'scripts\Find-AdDuplicates.ps1'))
    $ten = ($lines | Select-String -SimpleMatch 'exit 10' | Select-Object -First 1).LineNumber
    $thirty = ($lines | Select-String -SimpleMatch 'exit 30' | Select-Object -First 1).LineNumber
    $ten -and $thirty -and $ten -lt $thirty
}

"== the OTHER limit: a multi-valued attribute the directory RENAMED =="
# ⛔ TWO DIFFERENT LIMITS, AND ONLY ONE WAS BEING WATCHED. SizeLimit caps how many ROWS a search
# returns. Past ~1500 VALUES, AD renames the attribute itself -- `member` becomes
# `member;range=0-1499` -- so a plain read finds no `member` property and returns NOTHING. Not a
# short list: an EMPTY one. A 3000-member group read as zero members, and once the truncation
# flag existed it read as zero members with `truncated: false` affirming that. Worse than before
# the field existed, because something was now asserting it.
#
# ⚠ AND THE OBVIOUS GUARD CANNOT WORK. `$members.Count -ge 1500` was written in the privileged
# audit for exactly this, and could never fire: the count is 0, not 1500.
function Row([hashtable]$Props) {
    $o = [pscustomobject]@{}
    foreach ($k in $Props.Keys) { $o | Add-Member -NotePropertyName $k -NotePropertyValue $Props[$k] -Force }
    $o
}
Check 'a plain attribute reads normally and is not marked truncated' {
    $r = Get-AdmRangedProp (Row @{ member = @('a', 'b') }) 'member'
    @($r.Values).Count -eq 2 -and -not $r.Truncated
}
Check 'a RENAMED attribute yields its first window instead of nothing' {
    $r = Get-AdmRangedProp (Row @{ 'member;range=0-1499' = @('a', 'b', 'c') }) 'member'
    @($r.Values).Count -eq 3 -and $r.Truncated
}
Check 'and it raises the module flag, so the CLI envelope sees it' {
    # The two limits share one flag deliberately: a caller should not have to know WHICH kind of
    # truncation happened to know the answer is incomplete.
    Reset-AdmSearchTruncated
    [void](Get-AdmRangedProp (Row @{ 'member;range=0-1499' = @('a') }) 'member')
    Get-AdmSearchTruncated
}
Check 'an absent attribute is empty and NOT truncated' {
    $r = Get-AdmRangedProp (Row @{ name = 'x' }) 'member'
    @($r.Values).Count -eq 0 -and -not $r.Truncated
}
Check 'a null object does not throw' {
    $r = Get-AdmRangedProp $null 'member'
    @($r.Values).Count -eq 0 -and -not $r.Truncated
}
Check 'no caller anywhere reads a large multi-valued attribute by its plain name' {
    # memberOf, member and msDS-PSOAppliesTo are the ones that realistically pass 1500. Reading
    # any of them with Get-AdmRawProp returns EMPTY rather than short, which is why this is a
    # check and not a comment.
    #
    # ⭐ EVERY FILE, NOT A HAND-LISTED FEW. A named list only protects the files somebody
    # remembered to name, and the whole tree is already clean -- so scanning all of it costs
    # nothing today and covers the file nobody thinks about tomorrow. Topology.ps1 is clean by
    # CONSTRUCTION rather than by fix (its link map is built from searches, and gPLink and
    # siteObject are single-valued), which is exactly the kind of property worth pinning before
    # someone "optimises" it into an attribute read.
    $files = @(Get-ChildItem (Join-Path $repo 'ADAdmin') -Recurse -Filter '*.ps1') +
             @(Get-ChildItem (Join-Path $repo 'scripts') -Filter '*.ps1') +
             @(Get-ChildItem (Join-Path $repo 'gui') -Filter '*.ps1')
    # ⛔ A CONTROL THAT CANNOT LEGITIMATELY BE EMPTY. A broken enumeration scans nothing, finds
    # nothing, and reports PASS -- the silent-empty-result shape, inside the guard against it.
    if (@($files).Count -lt 25) { "     enumeration found only $(@($files).Count) file(s)"; return $false }
    $bad = @()
    foreach ($f in $files) {
        $bad += @(Get-Content $f.FullName |
                  Where-Object { $_ -match "Get-AdmRawProp\s+\`$\w+\s+'(member|memberof|msds-psoappliesto)'" } |
                  ForEach-Object { "$($f.Name) :: $($_.Trim())" })
    }
    if ($bad.Count) { $bad | ForEach-Object { "     $_" } }
    $bad.Count -eq 0
}
Check 'the privileged audit no longer uses the guard that can never fire' {
    # `$members.Count -ge 1500` is 0 -ge 1500 on exactly the groups it was meant to catch.
    # ⚠ CODE LINES ONLY. The comment explaining why that guard was wrong necessarily quotes it,
    # and a whole-file -match cannot tell the explanation from the mistake.
    $lines = @(Get-Content (Join-Path $repo 'scripts\Get-AdPrivilegedAccess.ps1') |
               Where-Object { $_.TrimStart() -notmatch '^#' })
    $bad = @($lines | Where-Object { $_ -match '\.Count -ge 1500' })
    if ($bad.Count) { $bad | ForEach-Object { "     $($_.Trim())" } }
    $bad.Count -eq 0 -and @($lines | Where-Object { $_ -match 'Get-AdmRangedProp' }).Count -ge 1
}

"== the CLI's JSON envelope says so, because a warning does not reach a script =="
# ⛔ THE MACHINE-READABLE SURFACE WAS THE LAST ONE STILL SILENT. A cut read announces itself with
# Write-Warning, which is fine for a person at a terminal and USELESS to the caller this envelope
# exists for: a script reading stdout as JSON never sees the warning stream, so it would take
# `data` -- the first N of many -- for the whole domain and act on it. Driven end to end through
# adm.ps1 in a separate process, because that is the thing a script actually runs.
$admPs = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$admPath = Join-Path $repo 'adm.ps1'
function AdmJson { param([string[]]$A)
    $out = & $admPs -NoProfile -ExecutionPolicy Bypass -File $admPath @A -json 2>&1 | Out-String
    # The envelope is the LAST line starting with '{' -- other narration can precede it.
    $line = @($out -split "`r?`n" | Where-Object { $_.TrimStart().StartsWith('{') }) | Select-Object -Last 1
    if (-not $line) { throw "no JSON envelope: $($out -replace '\s+', ' ')" }
    $line | ConvertFrom-Json
}
$env:ADADMIN_PASSPHRASE = 'trunc-suite-pass'   # so the child process can unlock the same store
Check 'the envelope carries a truncated field at all' {
    $j = AdmJson @('user', 'list', '-target', 'corp.example.com', '-limit', '1000')
    $j.PSObject.Properties['truncated'] -and $j.ok
}
Check 'and it is FALSE on a complete read' {
    # ⭐ The half that proves the field means something. A `truncated` that is always true is no
    # more useful than one that is always false.
    (AdmJson @('user', 'list', '-target', 'corp.example.com', '-limit', '1000')).truncated -eq $false
}
Check 'and TRUE when the read was cut' {
    (AdmJson @('user', 'list', '-target', 'corp.example.com', '-limit', '1')).truncated -eq $true
}
Check 'a command that reads no directory reports false, not stale state' {
    (AdmJson @('domain', 'list')).truncated -eq $false
}
Check 'the README documents the envelope the CLI actually emits' {
    # ⛔ A CONTRACT NOBODY RE-RUNS IS A COMMENT. The whole point of `truncated` is that a caller
    # must check it, and a caller only checks fields it has been told about -- so the documented
    # shape drifting from the emitted one silently un-does the fix. Both shapes are compared to
    # what adm.ps1 really returns rather than to what somebody typed.
    # ⚠ BOTH SHAPES, not just the happy one. The failure envelope has DIFFERENT fields -- no
    # `data`, plus `error`, `exitCode` and `diagnosis` -- and documenting only the success case
    # leaves a caller to discover the other half by hitting it in production.
    $readme = Get-Content (Join-Path $repo 'README.md') -Raw
    $ok   = @((AdmJson @('domain', 'list')).PSObject.Properties.Name)
    $fail = @((AdmJson @('user', 'list', '-target')).PSObject.Properties.Name)   # usage error
    $bad = @(@($ok + $fail | Select-Object -Unique) | Where-Object { $readme -notmatch "\`"$_\`"" })
    if ($bad.Count) { $bad | ForEach-Object { "     emitted but undocumented: $_" } }
    # A control that cannot be empty: if either call stopped returning an envelope, this would
    # compare nothing against the README and pass.
    $bad.Count -eq 0 -and $ok.Count -ge 5 -and $fail.Count -ge 4
}
Check 'and the README admits that a usage error carries no diagnosis' {
    # ⛔ THE DOCUMENTED FAILURE SHAPE WAS WRONG WITHIN AN HOUR OF BEING WRITTEN. It showed
    # `diagnosis` as an object, but a usage error -- exitCode 2, a mistyped argument -- has
    # `diagnosis: null`, because nothing went wrong in the environment and there is nothing to
    # diagnose. A caller told to read `diagnosis.title` would dereference null on the commonest
    # failure of all.
    $j = AdmJson @('user', 'list', '-target')
    $readme = Get-Content (Join-Path $repo 'README.md') -Raw
    $j.exitCode -eq 2 -and $null -eq $j.diagnosis -and $readme -match 'diagnosis.{0,4} is .{0,4}null'
}

"== the live suite exists, and stays OUT of the offline runner =="
Check 'the live checks are present' {
    Test-Path (Join-Path $repo 'tests\live\Invoke-AdmLiveTests.ps1')
}
Check 'and Invoke-AdmTests runs NOTHING from tests\live' {
    # ⛔ PUTTING ANY OF THEM IN $suites WOULD MAKE "you are not on the network" INDISTINGUISHABLE
    # FROM "the toolkit is broken" on a target PC, which is the one thing that runner must never
    # do. ⚠ Checked by NAME against every file actually in tests\live rather than against the one
    # file that existed when this was written -- the second live suite arrived within the hour.
    $src = Get-Content (Join-Path $repo 'tests\Invoke-AdmTests.ps1') -Raw
    $m = [regex]::Match($src, '\$suites\s*=\s*@\(([^)]*)\)')
    $listed = @([regex]::Matches($m.Groups[1].Value, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
    $live = @(Get-ChildItem (Join-Path $repo 'tests\live') -Filter '*.ps1' -ErrorAction SilentlyContinue |
              ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) -replace '\.Tests$', '' })
    $leaked = @($live | Where-Object { $listed -contains $_ })
    if ($leaked.Count) { $leaked | ForEach-Object { "     in the offline runner: $_" } }
    $leaked.Count -eq 0 -and ($src -match 'tests\\live\\Invoke-AdmLiveTests\.ps1')
}
Check 'every live suite refuses to be mistaken for an offline one' {
    # ⚠ A live suite dropped into tests\ instead of tests\live\ would be picked up by nothing and
    # run by nobody -- or worse, added to $suites by someone tidying up. Each one says in its own
    # header that it needs a real directory, so the reason travels with the file.
    $bad = @()
    foreach ($f in @(Get-ChildItem (Join-Path $repo 'tests\live') -Filter '*.ps1' -ErrorAction SilentlyContinue)) {
        $src = Get-Content $f.FullName -Raw
        if ($src -notmatch 'NOT (be )?part of Invoke-AdmTests|NOT in `?Invoke-AdmTests|not among them|NOT `?Invoke-AdmTests') {
            $bad += $f.Name
        }
    }
    if ($bad.Count) { $bad | ForEach-Object { "     no 'not part of the offline runner' note: $_" } }
    $bad.Count -eq 0
}
Check 'the live suite refuses to run against the mock provider' {
    # Against the mock it would test nothing while looking green -- worse than not running.
    $src = Get-Content (Join-Path $repo 'tests\live\Invoke-AdmLiveTests.ps1') -Raw
    $src -match "Provider -eq 'mock'" -and $src -match 'throw'
}
Check 'a skip in the live suite cannot be mistaken for a pass' {
    # A domain too small to force truncation proves nothing, and must not report as though it did.
    $src = Get-Content (Join-Path $repo 'tests\live\Invoke-AdmLiveTests.ps1') -Raw
    ($src -match 'function Skip') -and ($src -match 'SKIPPED')
}

"== the refusal explains itself =="
function Diag($text) {
    $ex = New-Object System.Exception($text)
    $er = New-Object System.Management.Automation.ErrorRecord($ex, 'x', 'NotSpecified', $null)
    & (Get-Module ADAdmin) { param($e) Resolve-AdmDiagnosis -ErrorObject $e -Operation 'test' -Target 'corp.example.com' } $er
}
Check 'a truncation refusal diagnoses as READ-TRUNCATED, not the generic size-limit entry' {
    # ⛔ RULE ORDER IS LOAD-BEARING AND FAILS SILENTLY. SIZE-LIMIT-EXCEEDED matches
    # `size limit|admin limit`, which is a SUPERSET of this rule's pattern -- it describes the
    # DIRECTORY hitting its own 1000-object cap, a different event with different fixes. Whichever
    # rule sits first wins, so putting the general one above the specific one makes the specific
    # diagnosis unreachable with nothing anywhere reporting a problem. This is the check that
    # notices.
    $d = Diag 'The subnet list was truncated at the size limit of 50000, so any conclusion drawn from it would be wrong.'
    if ($d.Code -ne 'READ-TRUNCATED') { "     diagnosed as $($d.Code)" }
    $d.Code -eq 'READ-TRUNCATED'
}
Check 'a genuine directory size-limit error still gets the generic entry' {
    $d = Diag 'The size limit for this request was exceeded'
    $d.Code -eq 'SIZE-LIMIT-EXCEEDED'
}
Check 'every refusal message this toolkit throws is matched by the rule' {
    # A message reworded out of the pattern would lose its explanation silently, so the throws
    # themselves are checked against it rather than trusted.
    $pat = 'truncated at (its|the) size limit'
    $src = @('ADAdmin\Public\Bulk.ps1', 'ADAdmin\Public\Topology.ps1') |
             ForEach-Object { Get-Content (Join-Path $repo $_) }
    $throws = @($src | Where-Object { $_ -match 'throw .*truncat' })
    $bad = @($throws | Where-Object { $_ -notmatch $pat })
    if ($bad.Count) { $bad | ForEach-Object { "     unmatched: $($_.Trim())" } }
    $throws.Count -ge 2 -and $bad.Count -eq 0
}

Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
if ($fail) { "FAILED: $fail"; exit 1 } else { "all checks passed"; exit 0 }
