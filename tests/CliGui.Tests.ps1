$repo = Split-Path -Parent $PSScriptRoot   # run from any clone, USB or share
$ErrorActionPreference = 'Continue'
$fail = 0
$adm = (Join-Path $repo 'adm.ps1')
$ps  = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

$work = Join-Path $env:TEMP ("admcli-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$env:ADADMIN_STORE      = Join-Path $work 'adadmin-store.json'
$env:ADADMIN_PASSPHRASE = 'cli-unlock-zzz'
$env:ADADMIN_PROVIDER   = 'mock'

function Run { param([string[]]$A)
    $out = & $ps -NoProfile -ExecutionPolicy Bypass -File $adm @A 2>&1 | Out-String
    [pscustomobject]@{ Out = $out.Trim(); Code = $LASTEXITCODE }
}
function Check($name, [scriptblock]$b) {
    try { if (& $b) { "  PASS  $name" } else { "  FAIL  $name"; $script:fail++ } }
    catch { "  FAIL  $name -- $($_.Exception.Message)"; $script:fail++ }
}

"== cli: help and usage =="
Check 'help exits 0'            { (Run @('help')).Code -eq 0 }
Check 'help mentions exit codes'{ (Run @('help')).Out -match 'EXIT CODES' }
Check 'unknown command = 2'     { (Run @('bogus')).Code -eq 2 }
Check 'a BARE adm prints usage instead of throwing' {
    # ⛔ THE FIRST THING ANYONE TYPES, AND NOTHING COVERED IT. With no remaining arguments $Rest
    # is $null, binding @($null) to a [string[]] parameter collapses it back to $null, and under
    # Set-StrictMode 2.0 $null.Count THROWS -- so `adm` alone died with "The property 'Count'
    # cannot be found on this object" instead of showing the banner. Every other check here
    # invokes adm WITH arguments, which is exactly why it survived.
    $r = Run @()
    if ($r.Code -ne 0) { "     exit $($r.Code): $($r.Out -split "`n" | Select-Object -First 1)" }
    $r.Code -eq 0 -and $r.Out -match 'USAGE' -and $r.Out -notmatch 'cannot be found on this object'
}
Check 'a missing sub-verb is refused BEFORE any passphrase prompt' {
    # ⛔ FIVE COMMAND GROUPS USED TO PROMPT FIRST AND REJECT AFTERWARDS. domain, user, group, ou
    # and object called Confirm-Unlocked at the top of their block, before the sub-verb switch --
    # so `adm domain` with no sub-verb asked a human to type a SECRET for a command that was
    # never going to run, and hung forever with no terminal. store, log and script refused in
    # milliseconds because their Confirm-Unlocked sits inside the individual sub-verbs.
    #
    # ⚠ RUN WITH A BOUNDED WAIT AND WITHOUT -NonInteractive. -NonInteractive would make the
    # prompt throw instead of blocking, so the check would pass even with the guard removed --
    # it would test the wrong thing. The interactive case IS the bug, so the job is given 20
    # seconds and a regression fails here rather than hanging the whole suite.
    $groups = @('store','domain','user','group','computer','ou','object','laps','bitlocker',
                'trust','site','subnet','gpo','pso','deleted','script','log')
    $bad = @()
    foreach ($g in $groups) {
        $j = Start-Job -ScriptBlock {
            param($ps, $adm, $g, $store, $prov)
            $env:ADADMIN_STORE = $store; $env:ADADMIN_PROVIDER = $prov
            # No ADADMIN_PASSPHRASE: a prompt must not be reachable on this path at all.
            & $ps -NoProfile -ExecutionPolicy Bypass -File $adm $g *>$null
            $LASTEXITCODE
        } -ArgumentList $ps, $adm, $g, $env:ADADMIN_STORE, $env:ADADMIN_PROVIDER
        if (Wait-Job $j -Timeout 20) {
            $code = Receive-Job $j
            if ($code -ne 2) { $bad += "$g exited $code" }
        } else {
            $bad += "$g BLOCKED (prompted)"
            Stop-Job $j
        }
        Remove-Job $j -Force
    }
    if ($bad.Count) { $bad | ForEach-Object { "     $_" } }
    $bad.Count -eq 0
}
Check 'an UNKNOWN sub-verb is refused as fast as a missing one' {
    # ⚠ THE FIRST VERSION OF THE GUARD ONLY CHECKED FOR AN EMPTY $Sub, so `adm domain bogus`
    # still reached Confirm-Unlocked and still hung. A typo is far likelier than an omission --
    # it fixed the less common half of the bug.
    $bad = @()
    foreach ($c in @('domain bogus', 'user bogus', 'group bogus', 'ou bogus', 'object bogus',
                     'store bogus', 'log bogus', 'gpo bogus')) {
        $parts = $c -split ' '
        $j = Start-Job -ScriptBlock {
            param($ps, $adm, $a, $b, $store, $prov)
            $env:ADADMIN_STORE = $store; $env:ADADMIN_PROVIDER = $prov
            & $ps -NoProfile -ExecutionPolicy Bypass -File $adm $a $b *>$null
            $LASTEXITCODE
        } -ArgumentList $ps, $adm, $parts[0], $parts[1], $env:ADADMIN_STORE, $env:ADADMIN_PROVIDER
        if (Wait-Job $j -Timeout 20) {
            $code = Receive-Job $j
            if ($code -ne 2) { $bad += "$c exited $code" }
        } else { $bad += "$c BLOCKED (prompted)"; Stop-Job $j }
        Remove-Job $j -Force
    }
    if ($bad.Count) { $bad | ForEach-Object { "     $_" } }
    $bad.Count -eq 0
}
Check 'a missing or valueless option is a USAGE error, not an unrecognised failure' {
    # ⛔ `adm user list -target` -- a flag with no value, one of the commonest typos there is --
    # used to print "Something failed, and this is not a failure the toolkit recognises" and exit
    # 1. Get-RequiredOpt threw, the outer catch handed it to Resolve-AdmDiagnosis, and no catalog
    # rule matches "Missing required option", so it fell through to UNRECOGNISED with the real
    # message buried in the technical detail.
    #
    # ⚠ THE EXIT CODE IS THE HALF THAT MATTERS TO A CALLER: 1 says "error", 2 says "you typed it
    # wrong", and every other usage refusal in this file already says 2.
    $a = Run @('user', 'list', '-target')          # valueless flag
    $b = Run @('user', 'list')                     # absent entirely
    $notes = @()
    if ($a.Code -ne 2) { $notes += "valueless flag exited $($a.Code)" }
    if ($b.Code -ne 2) { $notes += "missing option exited $($b.Code)" }
    if ($a.Out -match 'not a failure the toolkit recognises') { $notes += 'valueless flag still diagnosed as UNRECOGNISED' }
    if ($a.Out -notmatch 'without a value') { $notes += 'the message does not say the value was missing' }
    if ($notes.Count) { $notes | ForEach-Object { "     $_" } }
    $notes.Count -eq 0
}
Check 'the sub-verb table matches the switch arms it guards' {
    # ⛔ THE TABLE IS NOT MAINTAINED BY DISCIPLINE. It is rebuilt here from adm.ps1's OWN AST and
    # compared both ways, because drift is silent and bidirectional:
    #   a verb in the switch but not the table  -> refused before it ever runs
    #   a verb in the table but not the switch  -> falls through to a passphrase prompt again
    # Neither shows up as an error anywhere. This is the same reasoning as pinning the diagnosis
    # rule order and the "no plain read" scan: a rule you cannot check is a rule that decays.
    $t = $null; $e = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($adm, [ref]$t, [ref]$e)
    $switches = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.SwitchStatementAst] }, $true))

    # The declared table, read out of the script rather than retyped here.
    $declared = @{}
    $hash = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] }, $true) |
              Where-Object { "$($_.Extent.Text)" -match "bitlocker\s*=\s*@\('get'\)" })[0]
    foreach ($pair in $hash.KeyValuePairs) {
        $k = ("$($pair.Item1)") -replace "^'|'$", ''
        $declared[$k] = @(("$($pair.Item2)") -split "'" | Where-Object { $_ -match '^[a-z-]+$' })
    }

    # What the dispatch actually accepts. The object and help-desk groups switch on
    # "$Command $Sub", so an arm reads "user list" rather than "list".
    $actual = @{}
    $outer = @($switches | Where-Object { "$($_.Condition)" -match '\$Command' })[0]
    foreach ($clause in $outer.Clauses) {
        $label = "$($clause.Item1)" -replace "^'|'$", ''
        $inner = @($clause.Item2.FindAll({ param($n) $n -is [System.Management.Automation.Language.SwitchStatementAst] }, $true) |
                   Where-Object { "$($_.Condition)" -match '\$Sub' })
        if (-not $inner.Count) { continue }
        foreach ($c in $inner[0].Clauses) {
            $arm = ("$($c.Item1)") -replace "^'|'$", ''
            $words = @($arm -split ' ')
            $cmd = if ($words.Count -gt 1) { $words[0] } else { $label }
            $verb = if ($words.Count -gt 1) { $words[1] } else { $arm }
            if (-not $actual.ContainsKey($cmd)) { $actual[$cmd] = @() }
            $actual[$cmd] += $verb
        }
    }

    $bad = @()
    foreach ($cmd in $actual.Keys) {
        if (-not $declared.ContainsKey($cmd)) { $bad += "$cmd dispatches but is not in the table"; continue }
        foreach ($v in @($actual[$cmd] | Select-Object -Unique)) {
            if ($declared[$cmd] -notcontains $v) { $bad += "$cmd $v dispatches but the table would refuse it" }
        }
        foreach ($v in $declared[$cmd]) {
            if (@($actual[$cmd]) -notcontains $v) { $bad += "$cmd $v is in the table but nothing dispatches it" }
        }
    }
    if ($bad.Count) { $bad | ForEach-Object { "     $_" } }
    $bad.Count -eq 0 -and $declared.Keys.Count -ge 15
}
Check 'the help text is pure ASCII, because 5.1 renders the rest as mojibake' {
    # ⛔ CHECKED ON THE RENDERED OUTPUT, NOT THE SOURCE. These files are BOM-less UTF-8 and
    # Windows PowerShell 5.1 reads them as the system ANSI codepage, so a non-ASCII character in
    # a DISPLAYED string arrives as garbage on the one runtime that matters most. Plain `#`
    # comments are exempt -- they are never rendered -- which is why a source-level scan would
    # be both wrong and annoying. Running the CLI and inspecting what it actually printed is the
    # only honest form of this check, and it is how the last instance was caught: by reading the
    # output, not the file.
    $out = (Run @('help')).Out
    $bad = @([regex]::Matches($out, '[^\x00-\x7F]') | ForEach-Object { $_.Value } | Select-Object -Unique)
    if ($bad.Count) { "     non-ASCII in rendered help: $($bad -join ' ')" }
    $bad.Count -eq 0
}

"== cli: store =="
Check 'init (non-interactive)'  { $r = Run @('store','init','-Name','alice','-NonInteractive'); $r.Code -eq 0 -and (Test-Path $env:ADADMIN_STORE) }
Check 'status as json'          { $j = (Run @('store','status','-Json')).Out | ConvertFrom-Json; $j.ok -eq $true -and $j.data.Exists -eq $true }
Check 'json envelope has ok/command/data' {
    $j = (Run @('store','status','-Json')).Out | ConvertFrom-Json
    ($j.PSObject.Properties.Name -contains 'ok') -and ($j.PSObject.Properties.Name -contains 'command') -and ($j.PSObject.Properties.Name -contains 'data')
}

"== cli: domains =="
Check 'domain add corp'  { (Run @('store','status')).Code -eq 0 -and
                           (Run @('domain','add','-Name','corp','-Dns','corp.example.com','-Netbios','CORP','-Dc','dc01.corp.example.com','-Host','legacy-box','-NonInteractive')).Code -eq 0 }
Check 'domain add child' { (Run @('domain','add','-Name','child','-Dns','child.corp.example.com','-Netbios','CHILD','-NonInteractive')).Code -eq 0 }
Check 'domain add plant' { (Run @('domain','add','-Name','plant','-Dns','plant.local','-Netbios','PLANT','-NonInteractive')).Code -eq 0 }
Check 'domain list json shows 3' { $j = (Run @('domain','list','-Json')).Out | ConvertFrom-Json; @($j.data).Count -eq 3 }

"== cli: resolution, the headline feature =="
Check 'child host resolves to child' {
    $j = (Run @('domain','resolve','-Target','ws1.child.corp.example.com','-Json')).Out | ConvertFrom-Json
    $j.data.Domain -eq 'child' -and $j.data.MatchedOn -eq 'DnsSuffix'
}
Check 'explicit host beats dns' {
    $j = (Run @('domain','resolve','-Target','legacy-box','-Json')).Out | ConvertFrom-Json
    $j.data.Domain -eq 'corp' -and $j.data.MatchedOn -eq 'Hosts'
}
Check 'unknown target = exit 4' { (Run @('domain','resolve','-Target','nope.example.org','-Json')).Code -eq 4 }
Check 'unknown target json has ok:false' {
    $j = (Run @('domain','resolve','-Target','nope.example.org','-Json')).Out | ConvertFrom-Json
    $j.ok -eq $false -and $j.error -match 'No registered domain'
}

"== cli: credentials + objects =="
Check 'set-cred' {
    $env:ADADMIN_CRED_PASSWORD = 'not-a-real-one'
    (Run @('domain','set-cred','-Name','corp','-Tier','read','-User','CORP\svc','-Default','-NonInteractive')).Code -eq 0
}
Check 'user list json' {
    $j = (Run @('user','list','-Target','corp.example.com','-Json')).Out | ConvertFrom-Json
    $j.ok -eq $true -and @($j.data).Count -eq 4
}
Check 'user search filters' {
    $j = (Run @('user','list','-Target','corp.example.com','-Identity','jsmith','-Json')).Out | ConvertFrom-Json
    $j.data.SamAccountName -eq 'jsmith'
}
Check 'locked user visible'  {
    $j = (Run @('user','list','-Target','corp.example.com','-Identity','aokafor','-Json')).Out | ConvertFrom-Json
    $j.data.LockedOut -eq $true
}
Check 'human output is a table' { (Run @('user','list','-Target','corp.example.com')).Out -match 'SamAccountName' }
Check 'missing -Target = usage error' { (Run @('user','list','-Json')).Code -ne 0 }

"== cli: writes honour -WhatIf =="
Check 'whatif does not change state' {
    Run @('user','disable','-Target','corp.example.com','-Identity','jsmith','-WhatIf','-Yes','-NonInteractive') | Out-Null
    $j = (Run @('user','list','-Target','corp.example.com','-Identity','jsmith','-Json')).Out | ConvertFrom-Json
    $j.data.Enabled -eq $true
}

"== gui: xaml loads and every named control resolves =="

# ⛔ FROM HERE ON, THE SAME RULES THE GUI ACTUALLY RUNS UNDER.
#
# The CLI checks above drive adm.ps1 as a subprocess, so this file never needed StrictMode and
# never had it. But Start-AdmGui.ps1 runs under `Set-StrictMode -Version 2.0`, where reading a
# property that does not exist THROWS -- and the GUI functions exercised below are lifted into
# THIS process, so without this line they run in a laxer world than the one they ship into and
# the two crashes this section exists to pin would both pass. Same lesson as running the suites
# on 5.1 rather than only on 7.
Set-StrictMode -Version 2.0
# Get-AdmRawProp is how the GUI reads log fields safely; the handlers below call it.
Import-Module (Join-Path $repo 'ADAdmin\ADAdmin.psd1') -Force

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml
function Load-Window {
    [xml]$x = [System.IO.File]::ReadAllText((Join-Path $repo 'gui\AdmWindow.xaml'), (New-Object System.Text.UTF8Encoding($false)))
    [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $x))
}
$guiAst = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $repo 'gui\Start-AdmGui.ps1'), [ref]$null, [ref]$null)

Check 'xaml parses and EVERY control the code-behind asks for resolves' {
    # ⭐ The list is read from the GUI's own $ui bootstrap rather than copied here. A duplicated
    # list is a list that drifts, and the way it fails is the worst possible one: a control the
    # code wires up but the markup never declared is $null, so the handler silently does nothing
    # and the feature looks present. Derived, this fails the moment the two disagree.
    $w = Load-Window
    $names = @()
    $fe = $guiAst.Find({ param($n)
        $n -is [System.Management.Automation.Language.ForEachStatementAst] -and
        $n.Variable.VariablePath.UserPath -eq 'n' }, $true)
    if ($fe) {
        $names = @([regex]::Matches($fe.Condition.Extent.Text, "'([A-Za-z][A-Za-z0-9_]*)'") |
                   ForEach-Object { $_.Groups[1].Value })
    }
    if ($names.Count -lt 40) { "     only found $($names.Count) names -- the `$ui block was not parsed"; return $false }
    $missing = @($names | Where-Object { $null -eq $w.FindName($_) })
    if ($missing) { "     in the code but NOT in the xaml: $($missing -join ', ')" }
    $missing.Count -eq 0
}
Check 'EVERY $ui.<name> the code touches is actually bound' {
    # ⛔ THE TEST THAT WOULD HAVE CAUGHT TWO SHIPPED CRASHES. $ui is a HASHTABLE, so a key that
    # was never populated returns $null in SILENCE -- Set-StrictMode's property check does not
    # apply to hashtable key access. The null then flows into something that does throw, and
    # because this runs under $ErrorActionPreference = 'Stop', a terminating error inside a WPF
    # handler closes the window with no message at all. `$ui.ScriptRoot` (never a key) is what
    # made the Scripts button quit the application.
    $src = Get-Content (Join-Path $repo 'gui\Start-AdmGui.ps1') -Raw
    # Strip comments first, or the explanation above counts as a usage.
    $code = (($src -split "`n") | ForEach-Object { $_ -replace '#.*$', '' }) -join "`n"
    $used = @([regex]::Matches($code, '\$ui\.([A-Za-z][A-Za-z0-9_]*)') |
              ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    $declared = @()
    $fe2 = $guiAst.Find({ param($n)
        $n -is [System.Management.Automation.Language.ForEachStatementAst] -and
        $n.Variable.VariablePath.UserPath -eq 'n' }, $true)
    if ($fe2) {
        $declared = @([regex]::Matches($fe2.Condition.Extent.Text, "'([A-Za-z][A-Za-z0-9_]*)'") |
                      ForEach-Object { $_.Groups[1].Value })
    }
    $unbound = @($used | Where-Object { $declared -notcontains $_ })
    if ($unbound.Count) { "     `$ui.<name> never bound (null at runtime): $($unbound -join ', ')" }
    $used.Count -gt 40 -and $unbound.Count -eq 0
}
Check 'the window survives a handler error instead of closing' {
    # Individual handlers should catch their own failures; this is the net for when one does not.
    # Without it, any slip in a click handler makes the application vanish.
    $src = Get-Content (Join-Path $repo 'gui\Start-AdmGui.ps1') -Raw
    ($src -match 'add_UnhandledException') -and ($src -match '\$ev\.Handled\s*=\s*\$true')
}
Check 'log fields are read safely, not with bare property access' {
    # A log entry is JSON and carries only the keys that were written; a Windows event has no
    # why/fix/code at all. Bare `$e.title` throws under StrictMode, which is what made clicking
    # an error close the window.
    $src = Get-Content (Join-Path $repo 'gui\Start-AdmGui.ps1') -Raw
    $bad = @([regex]::Matches($src, '\$e\.(title|why|fix|code|technical|severity|tsLocal|operation|machine)\b'))
    if ($bad.Count) { "     bare log-entry property access: $(($bad | ForEach-Object { $_.Value }) -join ', ')" }
    $bad.Count -eq 0
}
Check 'the window can be maximised' {
    $w = Load-Window
    $null -ne $w.FindName('BtnMaximize') -and $null -ne $w.FindName('RootBorder')
}
Check 'maximising is capped to the working area so it cannot cover the taskbar' {
    # A WindowStyle=None + AllowsTransparency window fills the whole monitor otherwise.
    $src = Get-Content (Join-Path $repo 'gui\Start-AdmGui.ps1') -Raw
    ($src -match 'WorkingArea') -and ($src -match 'MaxHeight') -and
    ($src -match 'TransformFromDevice')      # and in DIPs, not device pixels
}
Check 'styles and brushes referenced by code exist' {
    $w = Load-Window
    $need = @('GlassPanel','GlassFillHi','GlassPassword','GlassInput','GhostButton','AccentButton',
              'DangerButton','TabPill','TogglePill','DialogFill','DialogVeil',
              'TextPrimary','TextMuted','TextFaint','Danger','Success','Warn')
    $bad = @($need | Where-Object { $null -eq $w.TryFindResource($_) })
    if ($bad) { "     missing resources: $($bad -join ', ')" }
    $bad.Count -eq 0
}
Check 'no XML comment contains a double hyphen' {
    # `--` is illegal inside an XML comment, and this repo's prose style uses it constantly. The
    # whole window fails to load, so this is caught at once -- but only if someone runs it.
    $t = [System.IO.File]::ReadAllText((Join-Path $repo 'gui\AdmWindow.xaml'))
    $bad = @([regex]::Matches($t, '(?s)<!--(.*?)-->') | Where-Object { $_.Groups[1].Value -match '--' })
    if ($bad.Count) { "     illegal comment: $($bad[0].Value.Substring(0, [Math]::Min(70, $bad[0].Value.Length)))" }
    $bad.Count -eq 0
}

"== gui: the handlers that crashed actually RUN =="
# ⛔ WHY THIS EXISTS. Two crashes shipped because the GUI was verified by loading the XAML and
# resolving control names, which proves a window builds and proves nothing about clicking
# anything. These bind a real window to the GUI's own $ui list, lift the real handlers out of
# the file, and CALL them. Pattern-matching the source would not have caught either bug.
$ModuleRoot = $repo      # Refresh-Scripts resolves scripts\ from this
$guiWin = Load-Window
$fe3 = $guiAst.Find({ param($n)
    $n -is [System.Management.Automation.Language.ForEachStatementAst] -and
    $n.Variable.VariablePath.UserPath -eq 'n' }, $true)
$uiNames = @([regex]::Matches($fe3.Condition.Extent.Text, "'([A-Za-z][A-Za-z0-9_]*)'") | ForEach-Object { $_.Groups[1].Value })
$ui = @{}
foreach ($nm in $uiNames) { $ui[$nm] = $guiWin.FindName($nm) }
$win = $guiWin            # Set-Status and friends reach for $win
foreach ($f in @('Set-Status','Get-ScriptSynopsis','Refresh-Scripts','Show-LogDetail','Show-ContentPane')) {
    $d = $guiAst.Find({ param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $f }.GetNewClosure(), $true)
    if ($d) { Invoke-Expression $d.Extent.Text }
}

Check 'Refresh-Scripts LISTS the scripts instead of closing the window' {
    # `$ui.ScriptRoot` was never a key. $ui is a hashtable, so it returned $null in silence and
    # Split-Path threw -- and a terminating error in a WPF handler closes the application.
    Refresh-Scripts
    $listed = @($ui.ScriptList.ItemsSource)
    if ($listed.Count -eq 0) { '     the scripts folder was not found' }
    $listed.Count -ge 10
}
Check 'Show-LogDetail survives EVERY entry shape the log produces' {
    # Deliberately ragged. A Windows event has no why/fix/code; a plain line has no title. Bare
    # property access on any of those throws under StrictMode, which is what made clicking an
    # error close the window.
    $shapes = @(
        [pscustomobject]@{ tsLocal='t'; severity='error'; title='Bad'; message='m'; operation='bind'
                           target='corp'; machine='PC1'; why='because'; fix=@('a','b'); code='X'
                           technical=[pscustomobject]@{ Codes='0x1'; Raw='raw' } }
        [pscustomobject]@{ message='just a message' }                       # <- the one that crashed
        [pscustomobject]@{ tsLocal='t'; severity='warn'; message='evt'; machine='PC1' }
        [pscustomobject]@{ tsLocal='t'; severity='error'; title='t'; message='m'
                           technical=$null; fix=@(); why=$null }
    )
    foreach ($s in $shapes) {
        $ui.LogList.ItemsSource = @([pscustomobject]@{ When='x'; Headline='y'; Dot='#fff'; Entry=$s })
        $ui.LogList.SelectedIndex = 0
        Show-LogDetail
    }
    $true
}
Check 'a sparse entry really would have thrown on bare access' {
    # Guards the test itself: if this ever stops throwing, the check above proves nothing.
    $sparse = [pscustomobject]@{ message = 'x' }
    $threw = $false
    try { $null = $sparse.title } catch { $threw = $true }
    $threw
}

"== the object detail view =="
foreach ($f in @('New-DetailChip','Add-DetailSection','Add-DetailRow','Show-ObjectDetail',
                 'Hide-ObjectDetail','Get-SelectedIdentity','Show-GuiFailure')) {
    $d = $guiAst.Find({ param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $f }.GetNewClosure(), $true)
    if ($d) { Invoke-Expression $d.Extent.Text }
}
$script:DetailObject = $null

Check 'userAccountControl decodes to named flags' {
    $f = @(ConvertFrom-AdmUac -Value 66048)     # NORMAL_ACCOUNT + DONT_EXPIRE_PASSWORD
    $names = @($f | ForEach-Object { $_.Flag })
    ($names -contains 'NORMAL_ACCOUNT') -and ($names -contains 'DONT_EXPIRE_PASSWORD') -and $names.Count -eq 2
}
Check 'A BIT TABLE KEYED BY INTEGER IS NOT INDEXED POSITIONALLY' {
    # ⛔ The bug this pins. An [ordered] hashtable indexed with an INTEGER does a POSITIONAL
    # lookup, so $h[0x1000000] ran off the end and returned $null -- which then blew up one
    # indirection later as "ContainsKey: Key cannot be null". High bits must still decode.
    $f = @(ConvertFrom-AdmUac -Value 0x01000000)
    @($f | ForEach-Object { $_.Flag }) -contains 'TRUSTED_TO_AUTH_FOR_DELEGATION'
}
Check 'the dangerous flags carry an explanation, not just a name' {
    $f = @(ConvertFrom-AdmUac -Value 0x00080000)   # TRUSTED_FOR_DELEGATION
    $f.Count -eq 1 -and $f[0].Concern -match 'impersonate'
}
Check 'an ordinary flag has no scare text attached' {
    @(ConvertFrom-AdmUac -Value 0x200)[0].Concern -eq $null
}
Check 'groupType decodes despite the SIGN BIT' {
    # SECURITY_ENABLED is 0x80000000, which AD returns as a NEGATIVE 32-bit integer. A naive
    # comparison against 0x80000000 fails on every security group in existence.
    $g = ConvertFrom-AdmGroupType -Value -2147483646
    $g.Scope -eq 'Global' -and $g.Kind -eq 'Security'
}
Check 'a distribution group is not called a security group' {
    (ConvertFrom-AdmGroupType -Value 2).Kind -eq 'Distribution'
}
Check 'the detail renderer fills the panel from a fixture object' {
    $ui.DetailBody.Children.Clear(); $ui.DetailChips.Children.Clear()
    $fake = [pscustomobject]@{
        Domain='corp'; ObjectClass='user'; Name='jsmith'; SamAccountName='jsmith'
        DisplayName='Jordan Smith'; UserPrincipalName='jsmith@corp'; DistinguishedName='CN=jsmith,DC=corp'
        Sid='S-1-5-21-1-2-3-1001'; Description='test'
        Enabled=$true; LockedOut=$false; LockedOutSince=$null; BadPasswordCount=0; BadPasswordTime=$null
        PasswordLastSet=(Get-Date); PasswordPolicy='domain default'; PasswordPolicyDetail=$null
        PasswordNeverExpires=$false; MustChangePassword=$false; PasswordExpiresOn=(Get-Date).AddDays(5); DaysToExpiry=5
        LastLogonTimestamp=(Get-Date); AccountExpires=$null; WhenCreated='x'; WhenChanged='y'
        UacValue=512; UacFlags=@('NORMAL_ACCOUNT'); UacConcerns=@(); AdminCount=$null
        MemberOfDirect=@('CN=Helpdesk,DC=corp'); MemberOfEffective=@('Helpdesk','Tier0-Ops')
        EffectiveNote=$null; PrimaryGroupId=513
        Title='Analyst'; Department=$null; Company=$null; Office=$null; Mail='j@corp'
        Telephone=$null; Mobile=$null; Manager=$null; ManagedBy=$null
        ServicePrincipalNames=@(); AllowedToDelegateTo=@(); SidHistory=@()
    }
    # Render exactly as the handler does, minus the directory read.
    $script:DetailObject = $fake
    Add-DetailSection 'Account'
    Add-DetailRow 'Name' $fake.Name
    Add-DetailRow 'Nothing' $null            # must be omitted, not shown as blank
    $ui.DetailBody.Children.Count -ge 3
}
Check 'AN EMPTY VALUE IS OMITTED, not rendered as a blank row' {
    # A screen of "(none)" teaches people to skim past the rows that do have something in them.
    $ui.DetailBody.Children.Clear()
    Add-DetailRow 'Present' 'yes'
    $withValue = $ui.DetailBody.Children.Count
    Add-DetailRow 'Absent' $null
    Add-DetailRow 'Empty'  ''
    $ui.DetailBody.Children.Count -eq $withValue
}
Check 'NO NON-ASCII IN A DISPLAYED STRING' {
    # ⛔ These files are UTF-8 with NO BOM, and Windows PowerShell 5.1 reads a BOM-less script as
    # the system ANSI codepage -- so a middle dot in a string literal reached the window as "A?".
    # Comments are exempt: they are never rendered.
    #
    # ⚠ IT USED TO SCAN gui\Start-AdmGui.ps1 AND NOTHING ELSE, so a marker character in adm.ps1's
    # -Json help text shipped anyway and reached the console as garbage on 5.1 (2026-08-28). A
    # check scoped to one file protects one file; the rule is about every string a user ever
    # sees. Same hand-listed-scope failure as the no-plain-read check, in a check rather than in
    # the code -- so it now enumerates everything that prints.
    $files = @(Get-ChildItem (Join-Path $repo 'gui') -Filter '*.ps1') +
             @(Get-ChildItem (Join-Path $repo 'scripts') -Filter '*.ps1') +
             @(Get-Item (Join-Path $repo 'adm.ps1'))
    # ⛔ A CONTROL THAT CANNOT LEGITIMATELY BE EMPTY. If the enumeration ever breaks -- a renamed
    # folder, a filter that matches nothing -- this check would scan ZERO files, find zero
    # problems, and report PASS. That is the silent-empty-result shape inside the guard itself,
    # which is the failure it exists to prevent, so the count is asserted rather than assumed.
    if (@($files).Count -lt 10) { "     enumeration found only $(@($files).Count) file(s)"; return $false }
    $bad = @()
    foreach ($f in $files) {
        $i = 0
        foreach ($line in ([System.IO.File]::ReadAllText($f.FullName) -split "`n")) {
            $i++
            if ($line -match '^\s*#') { continue }
            if ([regex]::IsMatch($line, '[^\x00-\x7F]')) { $bad += "$($f.Name):$i" }
        }
    }
    if ($bad.Count) { "     non-ASCII outside comments: $($bad -join ', ')" }
    $bad.Count -eq 0
}

"== the account editor: only what CHANGED is written =="
foreach ($f in @('Get-EditableFields','Get-EditChanges')) {
    $d = $guiAst.Find({ param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $f }.GetNewClosure(), $true)
    if ($d) { Invoke-Expression $d.Extent.Text }
}
function Seed-Edit {
    param([hashtable]$Original, [hashtable]$Now)
    $script:EditOriginal = @{}
    $script:EditControls = @{}
    foreach ($k in $Original.Keys) {
        $script:EditOriginal[$k] = $Original[$k]
        $box = New-Object Windows.Controls.TextBox
        $box.Text = [string]$Now[$k]
        $script:EditControls[$k] = [pscustomobject]@{ Kind = 'text'; Box = $box }
    }
}

Check 'the form is generated from Set-AdmUser''s own parameters' {
    # Not a hand-written list: a parameter added to the cmdlet must appear here with no GUI change.
    $f = @(Get-EditableFields)
    ($f -contains 'Title') -and ($f -contains 'Department') -and ($f -contains 'Manager') -and $f.Count -ge 20
}
Check 'plumbing and the escape hatch are NOT offered as fields' {
    # -Attribute/-Clear belong in the CLI; -Target/-Identity/-Tier are supplied by the panel.
    $f = @(Get-EditableFields)
    @('Target','Identity','Tier','Attribute','Clear','WhatIf','Confirm','UseDnsLookup') |
        ForEach-Object { if ($f -contains $_) { return $false } }
    $true
}
Check 'AN UNTOUCHED FORM SENDS NOTHING' {
    # ⛔ The one that matters. Set-AdmUser treats an empty string as CLEAR, so sending every field
    # on every save would wipe each attribute the user did not happen to fill in.
    Seed-Edit @{ Title='Analyst'; Department='Ops'; Office='' } @{ Title='Analyst'; Department='Ops'; Office='' }
    (Get-EditChanges).Count -eq 0
}
Check 'only the edited field is sent' {
    Seed-Edit @{ Title='Analyst'; Department='Ops' } @{ Title='Engineer'; Department='Ops' }
    $c = Get-EditChanges
    $c.Count -eq 1 -and $c['Title'] -eq 'Engineer'
}
Check 'A CASE-ONLY EDIT IS STILL AN EDIT' {
    # -ne is case-INSENSITIVE in PowerShell, so "jo smith" -> "Jo Smith" would be seen as no
    # change at all and silently discarded.
    Seed-Edit @{ DisplayName='jo smith' } @{ DisplayName='Jo Smith' }
    (Get-EditChanges).Count -eq 1
}
Check 'EMPTYING A FIELD IS DETECTED AS A CLEAR' {
    Seed-Edit @{ Department='Ops' } @{ Department='' }
    $c = Get-EditChanges
    $c.ContainsKey('Department') -and -not $c['Department']
}
Check 'a field that was already empty and stayed empty is not a clear' {
    # Otherwise every blank attribute would be re-cleared on every save, which writes for no reason.
    Seed-Edit @{ Office='' } @{ Office='' }
    (Get-EditChanges).Count -eq 0
}
Check 'the editor re-reads before seeding, rather than trusting a cached object' {
    # Editing against a stale original means a field someone else set reads as unchanged -- or the
    # box shows the old value, gets saved back, and silently reverts their edit.
    $src = Get-Content (Join-Path $repo 'gui\Start-AdmGui.ps1') -Raw
    $m = [regex]::Match($src, '(?s)function Show-EditPanel \{.*?\$ui\.EditBody\.Children\.Clear\(\)')
    $m.Success -and $m.Value -match 'Get-AdmObjectDetail'
}

"== gui: a script runs OFF the ui thread and can be cancelled =="
# ⛔ WHY. The first version called the script inline. Pointed at a real domain,
# Get-MachineIdentity -FromDirectory contacts every computer in turn and the window locked up
# solid, with no way to stop it. WPF cannot repaint while a handler is still running, so the only
# fix is to not run it there. These checks EXECUTE the runner rather than reading the source.
foreach ($f in @('Get-ScriptArguments','Add-ScriptOutput','Stop-ScriptRun','Invoke-SelectedScript',
                 'Update-ErrorChip','New-ParamLabel','Build-ScriptForm','Build-ScriptModes','Get-ScriptInfo',
                 'Get-SelectedScriptName','Set-ScriptOutput','Show-ScriptOutputFor',
                 'Update-ScriptTargetChip','Show-AdmObjectPicker')) {
    $d = $guiAst.Find({ param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $f }.GetNewClosure(), $true)
    if ($d) { Invoke-Expression $d.Extent.Text }
}
$script:ScriptControls = @{}; $script:ScriptInfo = $null; $script:ScriptSet = $null; $script:Runner = $null
$script:ScriptOutputs = @{}
$script:PickerKinds = @{ ComputerName = 'computers'; Only = 'users'; Identity = 'users'
                         Group = 'groups'; RemoveFrom = 'users' }

# The CLI section above already created this store on disk and registered corp in it.
$asyncReady = $false
try {
    $sp = ConvertTo-SecureString $env:ADADMIN_PASSPHRASE -AsPlainText -Force
    Unlock-AdmStore -Passphrase $sp | Out-Null
    $script:SessionPassphrase = $sp.Copy()
    Refresh-Scripts
    $ui.ScriptList.SelectedItem = @($ui.ScriptList.ItemsSource | Where-Object { $_.Name -eq 'Find-StaleComputers' })[0]
    $script:ScriptInfo = Get-ScriptInfo -Path $ui.ScriptList.SelectedItem.Path
    Build-ScriptModes; Build-ScriptForm
    $ui.TargetBox.Text = 'corp.example.com'
    $ui.ScriptWhatIfOff.IsChecked = $true
    $asyncReady = $true
} catch { "     could not set up the async check: $($_.Exception.Message)" }

Check 'starting a script RETURNS AT ONCE instead of blocking the window' {
    if (-not $asyncReady) { return $false }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Invoke-SelectedScript
    $sw.Stop()
    if ($sw.ElapsedMilliseconds -gt 3000) { "     took $($sw.ElapsedMilliseconds) ms -- the ui would freeze" }
    $sw.ElapsedMilliseconds -le 3000 -and $null -ne $script:Runner
}
Check 'the Run button becomes Cancel while it runs' {
    $script:Runner -and [string]$ui.BtnScriptRun.Content -eq 'Cancel'
}
Check 'output and the exit code arrive afterwards, on the dispatcher' {
    if (-not $script:Runner) { return $false }
    $frame = New-Object Windows.Threading.DispatcherFrame
    $deadline = (Get-Date).AddSeconds(90)
    $guard = New-Object Windows.Threading.DispatcherTimer
    $guard.Interval = [timespan]::FromMilliseconds(200)
    $guard.Add_Tick({ if (-not $script:Runner -or (Get-Date) -gt $deadline) { $frame.Continue = $false } }.GetNewClosure())
    $guard.Start()
    [Windows.Threading.Dispatcher]::PushFrame($frame)
    $guard.Stop()
    if ($script:Runner) { '     timed out -- the run never completed'; return $false }
    # exit 10 from Find-StaleComputers, translated into words rather than left as a number.
    ($ui.ScriptOutput.Text -match 'LEGACY-BOX') -and ($ui.StatusText.Text -match 'found something')
}
Check 'CANCEL STOPS IT and restores the button' {
    if (-not $asyncReady) { return $false }
    Invoke-SelectedScript                      # start
    if (-not $script:Runner) { '     second run did not start'; return $false }
    Invoke-SelectedScript                      # click again = cancel
    ($null -eq $script:Runner) -and ([string]$ui.BtnScriptRun.Content -eq 'Run')
}
Check 'OUTPUT IS KEPT PER SCRIPT, not dragged along the list' {
    # One shared pane meant the output shown under one script could have come from another.
    Set-ScriptOutput -For 'Find-StaleComputers' -Text 'RESULT-A'
    Set-ScriptOutput -For 'Get-AdForestStatus'  -Text 'RESULT-B'
    $pick = { param($n) $ui.ScriptList.SelectedItem = @($ui.ScriptList.ItemsSource | Where-Object { $_.Name -eq $n })[0]
              Show-ScriptOutputFor $n; $ui.ScriptOutput.Text }
    $a  = & $pick 'Find-StaleComputers'
    $b  = & $pick 'Get-AdForestStatus'
    $a2 = & $pick 'Find-StaleComputers'
    ($a -eq 'RESULT-A') -and ($b -eq 'RESULT-B') -and ($a2 -eq 'RESULT-A')
}
Check 'a script that has not run says so rather than showing another one''s result' {
    Show-ScriptOutputFor 'RemoveVeeamAgent'
    $ui.ScriptOutput.Text -eq 'Nothing run yet.'
}
Check 'locking the store ends a running script and drops the passphrase' {
    # "Locked" must be true of the work in flight too, not just of the window.
    $script:SessionPassphrase = (ConvertTo-SecureString 'x' -AsPlainText -Force)
    $src = Get-Content (Join-Path $repo 'gui\Start-AdmGui.ps1') -Raw
    ($src -match 'if \(\$script:Runner\) \{ Stop-ScriptRun \}') -and ($src -match 'Clear-SessionPassphrase')
}

"== carrying the domain list to another copy =="
$dioFile = Join-Path $work 'domains-export.json'
Check 'export writes the domain profiles' {
    $r = Export-AdmDomainProfile -Path $dioFile
    (Test-Path -LiteralPath $dioFile) -and $r.Domains -ge 3
}
Check 'NO CREDENTIAL VALUE REACHES THE FILE' {
    # ⛔ The property that makes this file safe to email or hand over. -cmatch, case-SENSITIVE:
    # -match would hit the file's own note, "No credentials are present in this file".
    $t = [System.IO.File]::ReadAllText($dioFile)
    $j = $t | ConvertFrom-Json
    $struct = @($j.domains | Where-Object { $_.PSObject.Properties['Credentials'] })
    if ($struct.Count) { "     a domain carried a Credentials block" }
    (-not ($t -cmatch 'cli-unlock-zzz')) -and $struct.Count -eq 0
}
Check 'tier NAMES are recorded so the far side knows what to set up' {
    $j = [System.IO.File]::ReadAllText($dioFile) | ConvertFrom-Json
    $corp = @($j.domains | Where-Object { $_.Name -eq 'corp' })[0]
    @($corp.CredentialTiers).Count -ge 1
}
Check 'a foreign file is refused rather than guessed at' {
    $bad = Join-Path $work 'not-ours.json'
    [System.IO.File]::WriteAllText($bad, '{"kind":"something-else","domains":[]}')
    $refused = $false
    try { Import-AdmDomainProfile -Path $bad -Confirm:$false | Out-Null }
    catch { $refused = $_.Exception.Message -match 'not a domain profile export' }
    $refused
}
Check 'IMPORT DOES NOT CLOBBER a domain already registered here' {
    # Importing a colleague's file must not quietly repoint one of your forests at their DC.
    $r = Import-AdmDomainProfile -Path $dioFile -Confirm:$false
    @($r.Skipped).Count -ge 3 -and @($r.Added).Count -eq 0
}

"== clearing reviewed problems from the log =="
Check 'clearing ONE entry removes exactly that one from Problems' {
    Write-AdmLog -Message 'clear-probe one' -Severity error -Operation 'probe' | Out-Null
    Write-AdmLog -Message 'clear-probe two' -Severity error -Operation 'probe' | Out-Null
    $before = @(Get-AdmLog -Days 7 -Problems -Last 300)
    if ($before.Count -lt 2) { '     expected two probe problems'; return $false }
    # Passed as-is, not [string]-cast: on 7 this is a [DateTime] and stringifying it here loses
    # the sub-second precision that identifies the entry.
    Set-AdmLogReviewed -Id $before[-1].ts -Confirm:$false | Out-Null
    (@(Get-AdmLog -Days 7 -Problems -Last 300)).Count -eq $before.Count - 1
}
Check 'IT MARKS, IT DOES NOT DELETE' {
    # A log you can delete individual lines out of is worth less than the convenience. The entry
    # keeps its place and still reads back when reviewed ones are included.
    $all = @(Get-AdmLog -Days 7 -Problems -Last 300 -IncludeReviewed)
    @($all | Where-Object { $_.message -eq 'clear-probe two' }).Count -eq 1
}
Check "'reviewed' survives a round trip through the reader" {
    # ⛔ The bug this pins. ConvertTo-AdmLogEntry projects every entry onto $AdmLogFields, so a
    # field missing from that list is silently discarded on READ however correctly it was
    # written -- marking an entry reviewed appeared to do nothing at all.
    $e = @(Get-AdmLog -Days 7 -Problems -Last 300 -IncludeReviewed |
           Where-Object { $_.message -eq 'clear-probe two' })[0]
    [bool](Get-AdmRawProp $e 'reviewed' $false)
}
Check 'clear all empties the problem list' {
    Set-AdmLogReviewed -All -Confirm:$false | Out-Null
    (@(Get-AdmLog -Days 7 -Problems -Last 300)).Count -eq 0
}
Check 'an informational entry was never a problem, so clear all leaves it alone' {
    Write-AdmLog -Message 'just information' -Severity info -Operation 'probe' | Out-Null
    Set-AdmLogReviewed -All -Confirm:$false | Out-Null
    $info = @(Get-AdmLog -Days 7 -Last 300 | Where-Object { $_.message -eq 'just information' })
    $info.Count -eq 1 -and -not (Get-AdmRawProp $info[0] 'reviewed' $false)
}

"== gui: creating the store from the lock screen =="
$fnMatch = $guiAst.Find({ param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Test-SecureStringsMatch' }, $true)
if ($fnMatch) { Invoke-Expression $fnMatch.Extent.Text }
# ConvertTo-SecureString REFUSES an empty string ("Cannot bind argument to parameter 'String'"),
# so the empty case has to be constructed directly.
function Sec {
    param([string]$s)
    if ($s -eq '') { return (New-Object System.Security.SecureString) }
    ConvertTo-SecureString $s -AsPlainText -Force
}

Check 'the confirm-passphrase check exists' { $null -ne $fnMatch }
Check 'identical passphrases match'         { Test-SecureStringsMatch (Sec 'correct horse battery') (Sec 'correct horse battery') }
Check 'A ONE-CHARACTER DIFFERENCE IS CAUGHT' {
    # There is no recovery: the passphrase is the only path to the data key, so a typo confirmed
    # here produces a store nobody can ever open.
    -not (Test-SecureStringsMatch (Sec 'correct horse battery') (Sec 'correct horse bttery'))
}
Check 'CASE MATTERS'                        { -not (Test-SecureStringsMatch (Sec 'Passphrase') (Sec 'passphrase')) }
Check 'differing lengths do not match'      { -not (Test-SecureStringsMatch (Sec 'abc') (Sec 'abcd')) }
Check 'a trailing space is a difference'    { -not (Test-SecureStringsMatch (Sec 'abc') (Sec 'abc ')) }
Check 'two empties match'                   { Test-SecureStringsMatch (Sec '') (Sec '') }
Check 'null is handled, not thrown on'      { -not (Test-SecureStringsMatch $null (Sec 'x')) }
Check 'unicode survives the round trip'     { Test-SecureStringsMatch (Sec 'pässwörd-日本') (Sec 'pässwörd-日本') }

Check 'the lock screen no longer sends people to the CLI' {
    # It used to say "Create one first: adm store init". The first step of a GUI-first toolkit
    # being a CLI step is the gap this closed.
    $src = Get-Content (Join-Path $repo 'gui\Start-AdmGui.ps1') -Raw
    -not ($src -match 'Create one first') -and ($src -match 'Initialize-AdmStore')
}

"== gui: the scripts panel reads every shipped script =="
# Lift the real Get-ScriptInfo out of the GUI so this tests the shipping code, not a copy.
$fn = $guiAst.Find({ param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-ScriptInfo' }, $true)
if ($fn) { Invoke-Expression $fn.Extent.Text }

Check 'Get-ScriptInfo exists in the GUI' { $null -ne $fn }
Check 'every script in scripts\ introspects without throwing' {
    # Including one with NO param() block at all (RemoveVeeamAgent) -- reading .Parameters off a
    # null ParamBlock threw under StrictMode and took the whole panel down.
    $bad = @()
    foreach ($f in (Get-ChildItem (Join-Path $repo 'scripts') -Filter '*.ps1')) {
        try { [void](Get-ScriptInfo -Path $f.FullName) } catch { $bad += "$($f.BaseName): $($_.Exception.Message)" }
    }
    if ($bad.Count) { "     $($bad -join '; ')" }
    $bad.Count -eq 0
}
Check 'parameter SETS are found, so every mode is reachable' {
    $i = Get-ScriptInfo -Path (Join-Path $repo 'scripts\Manage-AdUserAccounts.ps1')
    $i.DefaultSet -eq 'Report' -and
    @('Report','DisableStale','Reset','Create','AddGroup' | Where-Object { $i.Sets -notcontains $_ }).Count -eq 0
}
Check 'a ValidateSet is found, so it renders as buttons not a free-text box' {
    $i = Get-ScriptInfo -Path (Join-Path $repo 'scripts\Find-StaleComputers.ps1')
    $by = @($i.Parameters | Where-Object { $_.Name -eq 'By' })[0]
    $by.ValidateSet.Count -eq 3 -and $by.ValidateSet -contains 'PasswordLastSet'
}
Check 'a String[] ValidateSet is marked for MULTI-select' {
    # -Section takes several values at once; radio buttons would cap it at one and silently
    # remove a feature the CLI has.
    $i = Get-ScriptInfo -Path (Join-Path $repo 'scripts\Get-AdPrivilegedAccess.ps1')
    $s = @($i.Parameters | Where-Object { $_.Name -eq 'Section' })[0]
    $s.ValidateSet.Count -eq 6 -and $s.Type -match '\[\]$'
}
Check 'SecureString parameters are flagged so they get a PasswordBox' {
    $i = Get-ScriptInfo -Path (Join-Path $repo 'scripts\Manage-AdUserAccounts.ps1')
    @($i.Parameters | Where-Object { $_.Name -eq 'NewPassword' })[0].IsSecure
}
Check 'SupportsShouldProcess is detected, so Preview is only offered where it works' {
    (Get-ScriptInfo -Path (Join-Path $repo 'scripts\Find-StaleComputers.ps1')).SupportsWhatIf -and
    -not (Get-ScriptInfo -Path (Join-Path $repo 'scripts\Get-AdPrivilegedAccess.ps1')).SupportsWhatIf
}
Check 'Target and Tier are NOT offered as form fields' {
    # The panel supplies both. Showing them would invite a second, conflicting target.
    $bad = @()
    foreach ($f in (Get-ChildItem (Join-Path $repo 'scripts') -Filter '*.ps1')) {
        $i = Get-ScriptInfo -Path $f.FullName
        if (@($i.Parameters | Where-Object { $_.Name -in @('Target','Tier') }).Count) { $bad += $f.BaseName }
    }
    if ($bad.Count) { "     leaked Target/Tier: $($bad -join ', ')" }
    $bad.Count -eq 0
}
Check 'a MACHINE script is not sent -Target' {
    # Set-UacGoldenPolicy and RemoveVeeamAgent act on a computer and have no notion of a forest.
    # The runner used to pass -Target unconditionally, so both failed with "A parameter cannot be
    # found that matches parameter name 'Target'" before doing anything.
    $uac = Get-ScriptInfo -Path (Join-Path $repo 'scripts\Set-UacGoldenPolicy.ps1')
    $vee = Get-ScriptInfo -Path (Join-Path $repo 'scripts\RemoveVeeamAgent.ps1')
    $dir = Get-ScriptInfo -Path (Join-Path $repo 'scripts\Get-AdPrivilegedAccess.ps1')
    (-not $uac.HasTarget) -and (-not $vee.HasTarget) -and $dir.HasTarget
}
Check 'a machine script CAN be pointed at another system' {
    # "No way to choose which system I am targeting" -- both now take -ComputerName, and because
    # the form is generated from the param block it appears with no change to the GUI.
    foreach ($s in @('Set-UacGoldenPolicy', 'RemoveVeeamAgent')) {
        $i = Get-ScriptInfo -Path (Join-Path $repo "scripts\$s.ps1")
        if (-not (@($i.Parameters | Where-Object { $_.Name -eq 'ComputerName' }).Count)) {
            "     $s has no -ComputerName"; return $false
        }
    }
    $true
}
Check '#requires -RunAsAdministrator is detected before running' {
    # PowerShell refuses to start such a script at all, so the panel says so rather than letting
    # it fail on launch with nothing done.
    (Get-ScriptInfo -Path (Join-Path $repo 'scripts\RemoveVeeamAgent.ps1')).NeedsAdmin -and
    -not (Get-ScriptInfo -Path (Join-Path $repo 'scripts\Get-AdPrivilegedAccess.ps1')).NeedsAdmin
}
Check '-Credential is never rendered as a form field' {
    # A PSCredential cannot be typed into a text box, and a field for one invites a password in
    # plain sight.
    $bad = @()
    foreach ($f in (Get-ChildItem (Join-Path $repo 'scripts') -Filter '*.ps1')) {
        $i = Get-ScriptInfo -Path $f.FullName
        if (@($i.Parameters | Where-Object { $_.Name -eq 'Credential' }).Count) { $bad += $f.BaseName }
    }
    if ($bad.Count) { "     leaked Credential: $($bad -join ', ')" }
    $bad.Count -eq 0
}
Check 'the output pane wraps instead of running off the right edge' {
    # HorizontalScrollBarVisibility must be Disabled, not Auto: with Auto the ScrollViewer offers
    # the TextBlock infinite width, so TextWrapping never takes effect however wide the pane is.
    $x = [System.IO.File]::ReadAllText((Join-Path $repo 'gui\AdmWindow.xaml'))
    $m = [regex]::Match($x, '(?s)<ScrollViewer x:Name="ScriptOutputScroll".*?</ScrollViewer>')
    $m.Success -and ($m.Value -match 'HorizontalScrollBarVisibility="Disabled"') -and
    ($m.Value -match 'TextWrapping="Wrap"')
}
Check 'elevation is offered, and does not silently change which store is opened' {
    # Elevating can land in a different user profile, and the store lives in one. The elevated
    # relaunch is handed the store path explicitly so it opens the same file either way.
    $src = Get-Content (Join-Path $repo 'gui\Start-AdmGui.ps1') -Raw
    ($src -match "Verb\s*=\s*'runas'") -and ($src -match '-StorePath') -and ($src -match 'function Test-AdmElevated')
}
Check 'EVERY shipped script is reachable from the panel' {
    # The panel lists scripts\*.ps1 with no filter, so this pins that nothing is quietly excluded.
    $onDisk = @(Get-ChildItem (Join-Path $repo 'scripts') -Filter '*.ps1' | ForEach-Object { $_.BaseName })
    $onDisk.Count -ge 10 -and ($onDisk -contains 'Get-AdPrivilegedAccess') -and ($onDisk -contains 'Invoke-AdmSweep')
}

Remove-Item -LiteralPath $work -Recurse -Force -EA SilentlyContinue
if ($fail -gt 0) { "`nFAILURES: $fail"; exit 1 } else { "`nall cli/gui checks passed"; exit 0 }
