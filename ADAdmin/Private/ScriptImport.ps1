# ScriptImport.ps1 -- bring an existing PowerShell script into the house style.
#
# WHY THIS IS AST-BASED AND NOT REGEX. A script is code, not text. `Write-Host` inside a string
# literal is not a call; `catch {}` spanning three lines is still empty; an alias only counts
# where a command name is expected. Regex gets all three wrong, and a rewriter that is wrong is
# worse than no rewriter -- it silently changes someone's working script.
#
# ⛔ THE GOVERNING RULE: WRAP, DO NOT REWRITE. Integration happens by generating a wrapper that
# calls the original body inside the toolkit's guard, so the imported logic is untouched and can
# be diffed against its source. Only MECHANICAL, provably-safe edits are applied to the body
# itself; everything else is REPORTED for a human to decide. The original file is never modified.

$script:AdmHouseRules = @(
    @{
        Id = 'IMP-001'; Name = 'No [CmdletBinding()]'; Severity = 'warn'; AutoFix = $true
        Detect = {
            param($ast, $text, $tokens)
            $pb = $ast.ParamBlock
            if (-not $pb) { return @() }
            $has = @($pb.Attributes | Where-Object { $_.TypeName.Name -match 'CmdletBinding' }).Count
            if ($has) { return @() }
            @([pscustomobject]@{ Line = $pb.Extent.StartLineNumber; Detail = 'the param block has no [CmdletBinding()]'; Ast = $pb })
        }
        Problem = 'The script does not declare [CmdletBinding()].'
        Impact  = 'It gets none of the common parameters, so -Verbose, -ErrorAction and -WhatIf do nothing. Anyone who passes them will believe they took effect.'
        Fix     = 'Add [CmdletBinding()] above the param block.'
    }
    @{
        Id = 'IMP-002'; Name = 'Empty catch block'; Severity = 'error'; AutoFix = $true
        Detect = {
            param($ast, $text, $tokens)
            # Not every empty catch is an oversight, and treating them alike makes this rule
            # noise on real scripts. Measured on a 3,371-line production analyser: it flagged
            # four, and three were correct by design -- two of those with a comment inside the
            # catch explaining the decision. A rule that cries wolf three times out of four gets
            # ignored on the fourth, which was the one that mattered.
            #
            # Two exemptions, both meaning "someone decided this":
            #   1. a COMMENT inside the catch -- an author saying so in writing
            #   2. a try block containing nothing but CLEANUP, where failing to clean up is
            #      genuinely uninteresting (Stop-Transcript throws when none is running)
            $cleanup = @('Stop-Transcript', 'Remove-Item', 'Remove-PSDrive', 'Disconnect-VIServer',
                         'Close-Transport', 'Unregister-Event', 'Remove-Module')
            $ignorable = @('Out-Null', 'Write-Verbose', 'Write-Debug')
            $out = @()
            foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CatchClauseAst] }, $true)) {
                if (@($c.Body.Statements).Count -ne 0) { continue }

                $deliberate = $false
                foreach ($t in @($tokens)) {
                    if ($t.Kind -eq [System.Management.Automation.Language.TokenKind]::Comment -and
                        $t.Extent.StartOffset -ge $c.Body.Extent.StartOffset -and
                        $t.Extent.EndOffset -le $c.Body.Extent.EndOffset) { $deliberate = $true; break }
                }

                if (-not $deliberate -and $c.Parent -and $c.Parent.Body) {
                    $names = @($c.Parent.Body.FindAll(
                        { $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) |
                        ForEach-Object { $_.GetCommandName() } |
                        Where-Object { $_ -and ($ignorable -notcontains $_) })
                    if ($names.Count -and -not @($names | Where-Object { $cleanup -notcontains $_ }).Count) {
                        $deliberate = $true
                    }
                }

                if (-not $deliberate) {
                    $out += [pscustomobject]@{ Line = $c.Extent.StartLineNumber; Detail = 'catch block does nothing'; Ast = $c }
                }
            }
            $out
        }
        Problem = 'A catch block swallows the error and does nothing with it.'
        Impact  = 'The script carries on as though the failed step succeeded. This is the single most common cause of "it said it worked but nothing happened", and it leaves no trace to diagnose afterwards.'
        Fix     = 'Record the failure: Write-AdmLog -ErrorRecord $_ -Operation ''<what was being done>''. That diagnoses it and writes it to the shared log.'
    }
    @{
        Id = 'IMP-003'; Name = 'Aliases instead of command names'; Severity = 'warn'; AutoFix = $true
        Detect = {
            param($ast, $text, $tokens)
            $out = @()
            foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                $n = $c.GetCommandName()
                if (-not $n) { continue }
                $a = Get-Alias -Name $n -ErrorAction SilentlyContinue
                if ($a -and $a.ResolvedCommandName) {
                    $out += [pscustomobject]@{
                        Line = $c.Extent.StartLineNumber
                        Detail = "$n -> $($a.ResolvedCommandName)"
                        Ast = $c.CommandElements[0]; Replacement = $a.ResolvedCommandName
                    }
                }
            }
            $out
        }
        Problem = 'The script uses aliases (%, ?, gci, sls) rather than full command names.'
        Impact  = 'Aliases can be redefined, differ between hosts, and are the first thing to break on a constrained or non-English system. They also make the script unreadable to whoever inherits it.'
        Fix     = 'Expand each alias to the command it resolves to.'
    }
    @{
        Id = 'IMP-004'; Name = 'Split-Path -LiteralPath with -Parent'; Severity = 'error'; AutoFix = $true
        Detect = {
            param($ast, $text, $tokens)
            $out = @()
            foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                if ($c.GetCommandName() -ne 'Split-Path') { continue }
                $names = @($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } |
                           ForEach-Object { $_.ParameterName.ToLowerInvariant() })
                if (($names -contains 'literalpath') -and ($names -contains 'parent')) {
                    $out += [pscustomobject]@{ Line = $c.Extent.StartLineNumber; Detail = 'invalid parameter-set combination on 5.1'; Ast = $c }
                }
            }
            $out
        }
        Problem = 'Split-Path is called with both -LiteralPath and -Parent.'
        Impact  = 'That combination is REJECTED by Windows PowerShell 5.1 with "Parameter set cannot be resolved". PowerShell 7 accepts it, so this fails only on the machines the toolkit is actually carried to.'
        Fix     = 'Use [System.IO.Path]::GetDirectoryName($path) instead -- no parameter sets, same result.'
    }
    @{
        Id = 'IMP-005'; Name = 'Plaintext secret in the script'; Severity = 'error'; AutoFix = $false
        Detect = {
            param($ast, $text, $tokens)
            $out = @()
            foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                if ($c.GetCommandName() -ne 'ConvertTo-SecureString') { continue }
                $names = @($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } |
                           ForEach-Object { $_.ParameterName.ToLowerInvariant() })
                $literal = @($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.StringConstantExpressionAst] }).Count -gt 1
                if (($names -contains 'asplaintext') -and $literal) {
                    $out += [pscustomobject]@{ Line = $c.Extent.StartLineNumber; Detail = 'a literal string is being turned into a credential' }
                }
            }
            # assignments whose NAME looks like a secret and whose value is a literal
            foreach ($a in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
                $l = $a.Left.Extent.Text
                if ($l -match '(?i)\$(\w*(password|passwd|pwd|secret|apikey|api_key|token))\b' -and
                    $a.Right.Extent.Text -match '^[''"][^''"$]{4,}[''"]$') {
                    $out += [pscustomobject]@{ Line = $a.Extent.StartLineNumber; Detail = "$l is assigned a literal value" }
                }
            }
            $out
        }
        Problem = 'A password or secret appears literally in the script text.'
        Impact  = 'Anyone who can read the file has the credential -- and it is now in every backup, every copy of the share, and the version history. Rotating it is the only remedy once this has happened.'
        Fix     = 'Take it from the credential store instead: the imported script receives -Target and the right credential is resolved for you. Then ROTATE the exposed credential -- removing it from the file does not un-expose it.'
    }
    @{
        Id = 'IMP-006'; Name = 'Writes without -WhatIf support'; Severity = 'warn'; AutoFix = $false
        Detect = {
            param($ast, $text, $tokens)
            $pb = $ast.ParamBlock
            $supports = $false
            if ($pb) {
                foreach ($at in $pb.Attributes) {
                    if ($at.TypeName.Name -match 'CmdletBinding' -and $at.Extent.Text -match 'SupportsShouldProcess') { $supports = $true }
                }
            }
            if ($supports) { return @() }

            # Functions the script DEFINES ITSELF are not external changes. A local helper named
            # Add-Row or New-Report matches the verb pattern and is nothing but a call into this
            # same file -- asking its author to guard it with ShouldProcess is meaningless.
            $localFunctions = @($ast.FindAll(
                { $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
                ForEach-Object { $_.Name })

            $out = @()
            foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                $n = $c.GetCommandName()
                if (-not $n) { continue }
                # This toolkit's own cmdlets are excluded. Every ADAdmin cmdlet that writes already
                # implements SupportsShouldProcess, so a script calling them inherits -WhatIf
                # properly -- and New-AdmDirectoryEntry, which merely constructs a .NET object,
                # was being reported as a change to the directory.
                if ($n -like '*-Adm*') { continue }
                # Built-ins that match the verb pattern but change nothing outside the process.
                # `Set-StrictMode` was being reported as "this script makes changes" -- which then
                # asks the author to guard a no-op with ShouldProcess.
                if ($n -in @('Set-StrictMode', 'Set-Variable', 'Set-Location', 'Set-Alias', 'Set-PSDebug',
                             'New-Object', 'New-TimeSpan', 'New-Guid', 'New-Variable', 'New-PSSession',
                             'Add-Type', 'Add-Member', 'Clear-Variable', 'Remove-Variable')) { continue }
                if ($localFunctions -contains $n) { continue }
                if ($n -match '^(Set|Remove|New|Disable|Enable|Reset|Add|Clear|Move|Rename)-') {
                    $out += [pscustomobject]@{ Line = $c.Extent.StartLineNumber; Detail = "$n changes something" }
                }
            }
            if ($out.Count) { $out = @($out[0]) }   # one finding, not one per call
            $out
        }
        Problem = 'The script makes changes but does not support -WhatIf.'
        Impact  = 'There is no way to see what it would do before it does it. Against a directory, that means the first time anyone learns what the script touches is after it has touched it.'
        Fix     = 'Declare [CmdletBinding(SupportsShouldProcess)] and guard each change with if ($PSCmdlet.ShouldProcess(...)). The import wrapper adds -WhatIf at the outer level, but it can only stop the whole script, not individual steps.'
    }
    @{
        Id = 'IMP-007'; Name = 'Hard-coded domain or domain controller'; Severity = 'warn'; AutoFix = $false
        Detect = {
            param($ast, $text, $tokens)
            $out = @()
            foreach ($s in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)) {
                $v = $s.Value
                if ($v -match '^(?i)LDAPS?://' -or $v -match '^(?i)(dc\d*|.+)\.(local|corp|internal|lan)$' -or
                    $v -match '^\d{1,3}(\.\d{1,3}){3}$') {
                    $out += [pscustomobject]@{ Line = $s.Extent.StartLineNumber; Detail = "'$v'" }
                }
            }
            $out | Select-Object -First 5
        }
        Problem = 'A domain name, LDAP path or IP address is written into the script.'
        Impact  = 'The script only works against the one environment it was written for. Across untrusted forests that is worse than inconvenient: run it expecting one domain and it silently acts on another, or fails in a way that looks like a credential problem.'
        Fix     = 'Take -Target instead and let the toolkit resolve which domain it means. The import wrapper already provides -Target.'
    }
    @{
        Id = 'IMP-008'; Name = 'RSAT ActiveDirectory cmdlets'; Severity = 'warn'; AutoFix = $false
        Detect = {
            param($ast, $text, $tokens)
            $out = @()
            foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                $n = $c.GetCommandName()
                if (-not $n) { continue }
                # -cmatch, CASE-SENSITIVELY. Case-insensitively, `-AD[A-Z]` also matches `-Adm`,
                # so this rule flagged every one of THIS toolkit's own cmdlets -- Get-AdmUser,
                # Get-AdmRawProp -- as an RSAT dependency. Exactly backwards: those exist so RSAT
                # is not needed. Caught by running the rule over a script written against ADAdmin.
                if ($n -cmatch '^(Get|Set|New|Remove|Unlock|Enable|Disable|Search|Move|Restore)-AD[A-Z]') {
                    $out += [pscustomobject]@{ Line = $c.Extent.StartLineNumber; Detail = $n }
                }
            }
            $out | Select-Object -First 5
        }
        Problem = 'The script depends on Microsoft''s RSAT ActiveDirectory module.'
        Impact  = 'RSAT is usually NOT installed on a target PC, so the script fails at the first cmdlet with "term not recognised". It also does not accept a per-call credential cleanly across untrusted forests, which is the case this toolkit exists for. ⚠ This is FINE and expected if the script is meant to run on a domain controller or a dedicated admin host, where RSAT is present by definition -- nothing here can tell where you intend to run it, so judge this one yourself.'
        Fix     = 'Where an equivalent exists, use the toolkit''s own: Get-AdmUser, Get-AdmGroup, Get-AdmComputer, Unlock-AdmUser, Set-AdmUserEnabled, Reset-AdmUserPassword. They need no RSAT and route to the right forest automatically.'
    }
    @{
        Id = 'IMP-009'; Name = 'Bare throw with a string'; Severity = 'warn'; AutoFix = $false
        Detect = {
            param($ast, $text, $tokens)
            $out = @()
            foreach ($t in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.ThrowStatementAst] }, $true)) {
                if ($t.Pipeline -and $t.Pipeline.Extent.Text -match '^[''"]') {
                    $out += [pscustomobject]@{ Line = $t.Extent.StartLineNumber; Detail = $t.Extent.Text.Substring(0, [Math]::Min(60, $t.Extent.Text.Length)) }
                }
            }
            $out | Select-Object -First 5
        }
        Problem = 'The script throws bare strings.'
        Impact  = 'Nothing recognises them, so they arrive at the operator as raw text with no explanation and no suggested fix, and they cannot be matched by the error catalog.'
        Fix     = 'Keep the throw, but let the wrapper catch it -- imported scripts run inside the guard, so the failure is logged and diagnosed. For a KNOWN failure mode, add an entry to ADAdmin\Private\Diagnostics.ps1 so it is explained properly.'
    }
    @{
        Id = 'IMP-010'; Name = 'Write-Host used for data'; Severity = 'warn'; AutoFix = $false
        Detect = {
            param($ast, $text, $tokens)
            $out = @()
            foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                if ($c.GetCommandName() -eq 'Write-Host') {
                    $out += [pscustomobject]@{ Line = $c.Extent.StartLineNumber; Detail = 'Write-Host' }
                }
            }
            if ($out.Count -gt 3) { $out = @($out[0..2]) }
            $out
        }
        Problem = 'The script prints with Write-Host.'
        Impact  = 'Write-Host output cannot be captured, piped, filtered or turned into JSON, so the script is unusable from another script or by another script. It is fine for narration, and wrong for results.'
        Fix     = 'Emit objects for results and keep Write-Host for narration only. The CLI then renders them as a table for a human, or as JSON with -Json.'
    }
    @{
        # ⛔ REPORT ONLY, deliberately. This was an auto-fix until 2026-08-27, and that was wrong:
        # turning on strict mode CHANGES RUNTIME BEHAVIOUR, so it is not a mechanical edit and it
        # breaks this file's governing rule. Proven on a real script -- a Veeam cleanup tool doing
        # `Where-Object { $_.DisplayName }` over registry keys, most of which have no DisplayName.
        # Silently adding strict mode would have made a working script start erroring on every key.
        # The finding stays, because the advice is still right; applying it is the author's call.
        Id = 'IMP-011'; Name = 'No strict mode'; Severity = 'warn'; AutoFix = $false
        Detect = {
            param($ast, $text, $tokens)
            foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                if ($c.GetCommandName() -eq 'Set-StrictMode') { return @() }
            }
            @([pscustomobject]@{ Line = 1; Detail = 'Set-StrictMode is never called' })
        }
        Problem = 'The script does not enable strict mode.'
        Impact  = 'Typos in variable names and missing properties are silently $null instead of errors. Against a real directory this matters more than usual, because a real object OMITS attributes that are not set -- so a property that exists in testing may not exist in production.'
        Fix     = 'Add Set-StrictMode -Version 2.0 at the top. Expect it to reveal genuine bugs the first time.'
    }
    @{
        Id = 'IMP-012'; Name = '$PSScriptRoot in a param default'; Severity = 'error'; AutoFix = $false
        Detect = {
            param($ast, $text, $tokens)
            $pb = $ast.ParamBlock
            if (-not $pb) { return @() }
            $out = @()
            foreach ($p in $pb.Parameters) {
                if ($p.DefaultValue -and $p.DefaultValue.Extent.Text -match '\$PSScriptRoot') {
                    $out += [pscustomobject]@{ Line = $p.Extent.StartLineNumber; Detail = $p.Name.Extent.Text }
                }
            }
            $out
        }
        Problem = 'A parameter default uses $PSScriptRoot.'
        Impact  = '$PSScriptRoot is EMPTY while parameter defaults are being bound under Windows PowerShell 5.1 with -File. The script fails before its first line runs, usually with a message about an empty string that names the wrong thing.'
        Fix     = 'Leave the parameter empty and resolve it in the body: if (-not $Path) { $Path = Split-Path -Parent $PSScriptRoot }.'
    }
)

function Get-AdmScriptFinding {
    <#
      Parse a script and run every house rule over its AST. Returns findings only -- reads the
      file and changes nothing.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { throw "No script at '$Path'." }
    $text = [System.IO.File]::ReadAllText($Path)

    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)

    $findings = @()
    if ($errors -and $errors.Count) {
        # A script that does not parse cannot be analysed OR converted. Say that plainly rather
        # than reporting a partial result that looks like a clean bill of health.
        foreach ($e in $errors) {
            $findings += [pscustomobject]@{
                Id = 'ADM-IMP-000'; Name = 'The script does not parse'; Severity = 'error'
                Line = $e.Extent.StartLineNumber; Detail = $e.Message; AutoFix = $false
                Problem = 'PowerShell cannot parse this file, so it is not valid PowerShell.'
                Impact  = 'Nothing can be analysed or converted until it parses. The script would fail on its first run too.'
                Fix     = 'Fix the syntax error named above and import again.'
            }
        }
        # Emit, do not comma-wrap. `,@($x)` reaching an [object[]] PARAMETER binds as ONE
        # element containing the array, so the caller's foreach iterates once over the whole
        # collection -- which is how every transform below was skipped with a single, confusing
        # "property Extent not found" against a concatenation of every finding id.
        return $findings
    }

    foreach ($rule in $script:AdmHouseRules) {
        $hits = @()
        try { $hits = @(& $rule.Detect $ast $text $tokens) } catch {
            $findings += [pscustomobject]@{
                Id = "ADM-$($rule.Id)"; Name = $rule.Name; Severity = 'unknown'
                Line = 0; Detail = "the rule itself failed: $($_.Exception.Message)"; AutoFix = $false
                Problem = 'This house rule could not be evaluated.'; Impact = 'This aspect of the script is unchecked -- treat it as unknown, not as clean.'
                Fix = 'Report it; the rule needs fixing.'
            }
            continue
        }
        foreach ($h in $hits) {
            $findings += [pscustomobject]@{
                Id = "ADM-$($rule.Id)"; Name = $rule.Name; Severity = $rule.Severity
                Line = $h.Line; Detail = $h.Detail; AutoFix = [bool]$rule.AutoFix
                Problem = $rule.Problem; Impact = $rule.Impact; Fix = $rule.Fix
                Ast = $(if ($h.PSObject.Properties['Ast']) { $h.Ast } else { $null })
                Replacement = $(if ($h.PSObject.Properties['Replacement']) { $h.Replacement } else { $null })
            }
        }
    }
    $findings
}

function ConvertTo-AdmHouseText {
    <#
      Apply the mechanical, provably-safe rewrites and return the new text plus what was changed.

      ⛔ Edits are applied BACK TO FRONT by character offset. Editing forwards invalidates every
      later offset the AST gave us, and the corruption is silent -- the file still parses, just
      not as the same program.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings)

    $applied = @()
    $edits = @()

    $skipped = @()
    foreach ($f in $Findings) {
        if (-not $f.AutoFix) { continue }
        $hasAst = $false
        try { $hasAst = ($null -ne $f.Ast) } catch { $hasAst = $false }
        if (-not $hasAst) { continue }

        # Each transform is isolated. One that cannot be built must not abandon the other fixes
        # or the whole import -- it becomes a "could not auto-fix" note instead, which is the
        # honest outcome and leaves the finding for a human.
        try {
        switch ($f.Id) {
            'ADM-IMP-001' {
                # Insert the attribute immediately before `param(`, keeping its indentation. A
                # zero-width edit (Start == End) inserts without deleting anything.
                $at = $f.Ast.Extent.StartOffset
                $indent = ' ' * ($f.Ast.Extent.StartColumnNumber - 1)
                $edits += [pscustomobject]@{ Start = $at; End = $at
                                             New = "[CmdletBinding()]`r`n$indent"; Id = $f.Id; Line = $f.Line }
            }
            'ADM-IMP-002' {
                # Fill an empty catch with a logging call, indented to match the catch itself.
                $indent = ' ' * ($f.Ast.Extent.StartColumnNumber + 3)
                $body = "{`n$indent" + 'Write-AdmLog -ErrorRecord $_ -Operation ''imported script''   # added on import' + "`n" + (' ' * ($f.Ast.Extent.StartColumnNumber - 1)) + '}'
                $open = $f.Ast.Body.Extent
                $edits += [pscustomobject]@{ Start = $open.StartOffset; End = $open.EndOffset; New = $body; Id = $f.Id; Line = $f.Line }
            }
            'ADM-IMP-003' {
                $edits += [pscustomobject]@{ Start = $f.Ast.Extent.StartOffset; End = $f.Ast.Extent.EndOffset
                                             New = $f.Replacement; Id = $f.Id; Line = $f.Line }
            }
            'ADM-IMP-004' {
                $c = $f.Ast
                $pathArg = $null
                for ($i = 0; $i -lt $c.CommandElements.Count; $i++) {
                    $e = $c.CommandElements[$i]
                    if ($e -is [System.Management.Automation.Language.CommandParameterAst] -and
                        $e.ParameterName -match '(?i)^literalpath$') {
                        if ($e.Argument) { $pathArg = $e.Argument.Extent.Text }
                        elseif ($i + 1 -lt $c.CommandElements.Count) { $pathArg = $c.CommandElements[$i + 1].Extent.Text }
                    }
                }
                if ($pathArg) {
                    $edits += [pscustomobject]@{ Start = $c.Extent.StartOffset; End = $c.Extent.EndOffset
                                                 New = "[System.IO.Path]::GetDirectoryName($pathArg)"; Id = $f.Id; Line = $f.Line }
                }
            }
        }
        } catch {
            $skipped += [pscustomobject]@{ Id = $f.Id; Line = $f.Line; Reason = $_.Exception.Message }
        }
    }

    $new = $Text
    foreach ($e in ($edits | Sort-Object Start -Descending)) {
        $new = $new.Substring(0, $e.Start) + $e.New + $new.Substring($e.End)
        $applied += [pscustomobject]@{ Id = $e.Id; Line = $e.Line }
    }

    # NO FILE-LEVEL PREAMBLE is prepended here. Strict mode used to be added at this point; see
    # the IMP-011 rule for why that was removed. Edits are confined to the constructs a finding
    # points at -- IMP-001 does insert [CmdletBinding()] directly above the param block, but
    # nothing is added at file scope that would change how the rest of the script behaves.

    # Trailing whitespace and a BOM are not worth a finding, but are worth not shipping.
    $new = ($new -split "\r?\n" | ForEach-Object { $_.TrimEnd() }) -join "`r`n"
    $new = $new.TrimStart([char]0xFEFF)

    [pscustomobject]@{ Text = $new; Applied = @($applied); Skipped = @($skipped) }
}
