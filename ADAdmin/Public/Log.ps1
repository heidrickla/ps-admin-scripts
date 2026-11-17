# Public/Log.ps1 -- the log surface other scripts and the UI use.

function Write-AdmLog {
    <#
    .SYNOPSIS
      Record something in the shared log. For your own scripts as well as the toolkit's.
    .EXAMPLE
      Write-AdmLog -Severity info -Message 'Starting the weekly stale-account sweep'
    .EXAMPLE
      try { ... } catch { Write-AdmLog -ErrorRecord $_ -Operation 'stale-account sweep' -Target corp.example.com }
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('info', 'warn', 'error')][string]$Severity = 'info',
        [string]$Message,
        [string]$Operation,
        [string]$Target,
        [string]$Domain,
        # Pass $_ from a catch block and it is diagnosed automatically -- the plain-English
        # explanation and the suggested fixes are worked out for you.
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    if ($ErrorRecord) {
        $diag = Resolve-AdmDiagnosis -ErrorObject $ErrorRecord -Operation $Operation -Target $Target
        $sev = if ($PSBoundParameters.ContainsKey('Severity')) { $Severity } else { $diag.Severity }
        $msg = if ($Message) { $Message } else { $ErrorRecord.Exception.Message }
        return Write-AdmLogEntry -Severity $sev -Event 'failure' -Message $msg `
                    -Operation $Operation -Target $Target -Domain $Domain -Diagnosis $diag
    }
    Write-AdmLogEntry -Severity $Severity -Event 'note' -Message $Message `
        -Operation $Operation -Target $Target -Domain $Domain
}

function Get-AdmLog {
    <#
    .SYNOPSIS
      Read the log. Defaults to the last 7 days, which is also how long it is kept.
    #>
    [CmdletBinding()]
    param(
        [int]$Days = 7,
        [ValidateSet('all', 'info', 'warn', 'error')][string]$Severity = 'all',
        [int]$Last = 200,
        [switch]$Problems,  # errors and warnings only -- what you want when something broke
        # Reviewed entries are hidden from -Problems by default: once somebody has read a failure
        # and dealt with it, leaving it in the list that means "things needing attention" is how
        # that list stops being read at all. They are never deleted, so an unfiltered read still
        # shows everything that ever happened.
        [switch]$IncludeReviewed
    )
    $sev = if ($Problems) { 'all' } else { $Severity }
    $e = Get-AdmLogEntries -Days $Days -Severity $sev -Last $Last -IncludeRing
    if ($Problems) {
        $e = @($e | Where-Object { $_.severity -in @('error', 'warn') })
        if (-not $IncludeReviewed) {
            $e = @($e | Where-Object { -not (Get-AdmRawProp $_ 'reviewed' $false) })
        }
    }
    $e
}

function Set-AdmLogReviewed {
    <#
    .SYNOPSIS
      Mark log entries as reviewed, so they drop out of the problem list.
    .DESCRIPTION
      ⛔ THIS MARKS, IT DOES NOT DELETE. The entry keeps its place in the file and still appears in
      an unfiltered read; what changes is that it stops counting as something needing attention.
      Deleting individual lines out of a log would make the log worth less than the convenience is
      worth -- and the 7-day rolling cleanup already removes them on its own schedule.

      Matching is on `ts`, which is ISO 8601 to seven decimal places, so it identifies one entry.
    .EXAMPLE
      Set-AdmLogReviewed -Id '2026-08-27T10:14:02.1234567+01:00'
    .EXAMPLE
      Set-AdmLogReviewed -All
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Id')]
    param(
        # ⛔ [object[]], NOT [string[]]. ConvertFrom-Json turns the ISO timestamp into a [DateTime]
        # on PowerShell 7 and leaves it a string on 5.1, so callers hand over whichever their
        # runtime produced. Typing this as [string[]] made PowerShell cast a DateTime at the
        # parameter boundary -- to a culture-formatted "08/27/2026 15:30:05" with the sub-second
        # precision and the offset already gone, before any normalisation could see it. Clearing
        # then matched nothing, and ONLY on 7.
        [Parameter(Mandatory, ParameterSetName = 'Id')][object[]]$Id,
        [Parameter(Mandatory, ParameterSetName = 'All')][switch]$All
    )
    # Normalise the key on both sides. The entry is written with ts = (Get-Date).ToString('o'), a
    # string, and on 5.1 it reads back as one -- but ConvertFrom-Json is not consistent about ISO
    # dates across PowerShell versions, and a [DateTime] on one side compared with `[string]` would
    # give a culture-formatted "27/08/2026 12:34:56" that never matches. Defensive, not a measured
    # failure: the bug that actually broke clearing was `reviewed` missing from $AdmLogFields.
    function ConvertTo-LogId {
        param($Value)
        if ($null -eq $Value) { return '' }
        if ($Value -is [datetime]) { return $Value.ToString('o') }
        $d = [datetime]::MinValue
        if ([datetime]::TryParse([string]$Value, [cultureinfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$d)) { return $d.ToString('o') }
        [string]$Value
    }

    $wanted = @{}
    if ($Id) { foreach ($i in $Id) { $wanted[(ConvertTo-LogId $i)] = $true } }

    $what = if ($All) { 'every problem' } else { "$($wanted.Count) entr(y/ies)" }
    if (-not $PSCmdlet.ShouldProcess($what, 'Mark reviewed')) { return }

    $n = 0

    # The ring first -- it is the copy that cannot fail, and the GUI reads it.
    foreach ($e in @($script:AdmLogRing)) {
        if (-not $All -and -not $wanted.ContainsKey((ConvertTo-LogId (Get-AdmRawProp $e 'ts')))) { continue }
        if ($e.PSObject.Properties['reviewed']) { $e.reviewed = $true }
        else { $e | Add-Member -NotePropertyName 'reviewed' -NotePropertyValue $true -Force }
        $n++
    }

    # Then the files, rewritten line by line. Each line is independent JSON, so a rewrite touches
    # only the lines that matched and cannot corrupt the rest.
    $dir = Get-AdmLogDir
    if ($dir -and (Test-Path -LiteralPath $dir)) {
        foreach ($f in (Get-ChildItem -LiteralPath $dir -Filter 'adadmin-*.jsonl' -EA SilentlyContinue)) {
            try {
                $lines = [System.IO.File]::ReadAllLines($f.FullName)
                $changed = $false
                for ($i = 0; $i -lt $lines.Length; $i++) {
                    if (-not $lines[$i].Trim()) { continue }
                    $o = $null
                    try { $o = $lines[$i] | ConvertFrom-Json } catch { continue }
                    if (Get-AdmRawProp $o 'reviewed' $false) { continue }
                    if (-not $All -and -not $wanted.ContainsKey((ConvertTo-LogId (Get-AdmRawProp $o 'ts')))) { continue }
                    # -All means "everything currently treated as a problem", not literally every
                    # line: an informational entry was never in the list being cleared.
                    if ($All -and (Get-AdmRawProp $o 'severity') -notin @('error', 'warn')) { continue }
                    if ($o.PSObject.Properties['reviewed']) { $o.reviewed = $true }
                    else { $o | Add-Member -NotePropertyName 'reviewed' -NotePropertyValue $true -Force }
                    $lines[$i] = ($o | ConvertTo-Json -Depth 8 -Compress)
                    $changed = $true
                }
                if ($changed) {
                    # Same no-BOM encoding as the writer: a BOM mid-file breaks the line-by-line read.
                    [System.IO.File]::WriteAllLines($f.FullName, $lines, (Get-AdmUtf8Encoding))
                }
            } catch { }
        }
    }
    [pscustomobject]@{ Reviewed = $n; Scope = $(if ($All) { 'all problems' } else { 'selected' }) }
}

function Get-AdmWindowsEvent {
    <#
    .SYNOPSIS
      Recent Windows errors from this machine, in the same shape as the toolkit's own log.
    .DESCRIPTION
      When a script fails for a reason that is really an OS or domain-membership problem, the
      evidence is in the Windows event log rather than anything the script printed. This pulls
      those in so one screen shows both, and normalises them to the toolkit's entry shape so the
      GUI can merge the two sources.

      Empty-result handling: Get-WinEvent
      raises "no matching events" as a TERMINATING error, and the only safe way to tell that apart
      from a real failure is the LOCALE-INVARIANT FullyQualifiedErrorId. Matching the English
      message text misreports every empty read on a non-English machine as an unknown error.

      'Security' is deliberately not offered. It is the audit trail, it needs privileges this
      toolkit does not assume, and reading it is not this tool's job.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('System', 'Application', 'Both')][string]$Log = 'Both',
        [ValidateSet('critical', 'error', 'warning', 'all')][string]$Level = 'error',
        [ValidateRange(1, 500)][int]$MaxEvents = 50,
        [ValidateRange(1, 720)][int]$SinceHours = 168   # 7 days, matching the log retention
    )
    $levels = switch ($Level) {
        'critical' { @(1) }
        'error'    { @(1, 2) }   # Critical + Error is what an operator means by "errors"
        'warning'  { @(3) }
        'all'      { @(1, 2, 3) }
    }
    $logs = if ($Log -eq 'Both') { @('System', 'Application') } else { @($Log) }
    $start = (Get-Date).AddHours(-1 * $SinceHours)
    $out = @()

    foreach ($ln in $logs) {
        try {
            $rows = Get-WinEvent -FilterHashtable @{ LogName = $ln; Level = $levels; StartTime = $start } `
                        -MaxEvents $MaxEvents -ErrorAction Stop
        } catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { continue }   # a valid EMPTY read
            [void](Write-AdmLogEntry -Severity warn -Event 'note' -Operation 'read windows event log' `
                    -Message "Could not read the $ln event log: $($_.Exception.Message)")
            continue
        }
        foreach ($r in $rows) {
            $first = if ($r.Message) { (($r.Message -split "\r?\n")[0]).Trim() } else { '(no message text)' }
            $out += [pscustomobject]@{
                ts        = $r.TimeCreated.ToString('o')
                tsLocal   = $r.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                severity  = if ($r.Level -le 2) { 'error' } else { 'warn' }
                event     = 'windows'
                source    = "windows/$ln"
                message   = $first
                operation = $r.ProviderName
                target    = $r.MachineName
                domain    = $null
                code      = "EventID $($r.Id)"
                title     = "$($r.LevelDisplayName) from $($r.ProviderName)"
                why       = $null
                fix       = @()
                recognised = $null
                machine   = $r.MachineName
                user      = $null
                session   = $script:AdmSessionId
                pid       = $null
                psVersion = $null
                technical = [pscustomobject]@{ Codes = "EventID $($r.Id)"; Raw = $r.Message
                                               Types = $r.ProviderName; SubStatus = $null; Server = $null }
            }
        }
    }
    $out | Sort-Object ts
}

function Get-AdmLogInfo {
    <#
    .SYNOPSIS
      Where the log lives, how much of it there is, and whether writing works at all.
    #>
    [CmdletBinding()]
    param()
    $dir = Get-AdmLogDir
    $files = @()
    if ($dir) { $files = @(Get-ChildItem -LiteralPath $dir -Filter 'adadmin-*.jsonl' -EA SilentlyContinue) }
    [pscustomobject]@{
        Directory     = $dir
        Writable      = [bool]$dir -and -not $script:AdmLogDisabled
        RetentionDays = $script:AdmLogRetention
        Files         = $files.Count
        OldestFile    = if ($files) { ($files | Sort-Object Name | Select-Object -First 1).Name } else { $null }
        TotalKB       = if ($files) { [math]::Round((($files | Measure-Object Length -Sum).Sum) / 1KB, 1) } else { 0 }
        InMemory      = $script:AdmLogRing.Count
        SessionId     = $script:AdmSessionId
    }
}

function Clear-AdmLog {
    <#
    .SYNOPSIS
      Delete log files. Without -All this only enforces the 7-day window, which happens anyway.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([switch]$All)
    $dir = Get-AdmLogDir
    if (-not $dir) { return [pscustomobject]@{ Cleared = 0; Directory = $null } }
    if ($All) {
        if (-not $PSCmdlet.ShouldProcess($dir, 'Delete ALL log files')) { return }
        $n = 0
        foreach ($f in (Get-ChildItem -LiteralPath $dir -Filter 'adadmin-*.jsonl' -EA SilentlyContinue)) {
            try { Remove-Item -LiteralPath $f.FullName -Force -EA Stop; $n++ } catch { }
        }
        $script:AdmLogRing.Clear()
        return [pscustomobject]@{ Cleared = $n; Directory = $dir }
    }
    Invoke-AdmLogPrune -Force
    [pscustomobject]@{ Cleared = 'pruned to the retention window'; Directory = $dir
                       RetentionDays = $script:AdmLogRetention }
}

function Export-AdmLog {
    <#
    .SYNOPSIS
      Write the log out as a plain-text report to hand to someone.
    .DESCRIPTION
      Aimed at a reader who does not write scripts: each problem gets what happened, why, and
      what to do, in that order, with the raw codes last for whoever wants them.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$Days = 7,
        [switch]$ProblemsOnly
    )
    $entries = Get-AdmLog -Days $Days -Last 0
    if ($ProblemsOnly) { $entries = @($entries | Where-Object { $_.severity -in @('error', 'warn') }) }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('ADAdmin activity report')
    [void]$sb.AppendLine("Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine("Covering  : the last $Days day(s)")
    [void]$sb.AppendLine("Entries   : $($entries.Count)")
    [void]$sb.AppendLine(('=' * 78))
    [void]$sb.AppendLine()
    if (-not $entries.Count) { [void]$sb.AppendLine('Nothing recorded in this period.') }

    foreach ($e in $entries) {
        [void]$sb.AppendLine("[$($e.tsLocal)]  $($e.severity.ToUpperInvariant())")
        if ($e.title) { [void]$sb.AppendLine("  What happened : $($e.title)") }
        elseif ($e.message) { [void]$sb.AppendLine("  What happened : $($e.message)") }
        if ($e.operation) { [void]$sb.AppendLine("  While doing   : $($e.operation)") }
        if ($e.target)    { [void]$sb.AppendLine("  Target        : $($e.target)") }
        if ($e.why) {
            [void]$sb.AppendLine("  Why           :")
            foreach ($l in (Split-AdmTextForReport -Text $e.why -Width 62)) { [void]$sb.AppendLine("    $l") }
        }
        if ($e.fix -and @($e.fix).Count) {
            [void]$sb.AppendLine("  What to do    :")
            $i = 1
            foreach ($f in @($e.fix)) {
                foreach ($l in (Split-AdmTextForReport -Text "$i. $f" -Width 62)) { [void]$sb.AppendLine("    $l") }
                $i++
            }
        }
        if ($e.technical -and $e.technical.Raw) {
            [void]$sb.AppendLine("  Technical     : $($e.technical.Codes)")
            # Wrapped like the prose above. A raw server error is routinely 300+ characters, and
            # an unwrapped one turns the report into something nobody scrolls sideways to read.
            foreach ($l in (Split-AdmTextForReport -Text ([string]$e.technical.Raw) -Width 62)) {
                [void]$sb.AppendLine("                  $l")
            }
        }
        [void]$sb.AppendLine("  Recorded on   : $($e.machine) as $($e.user)")
        [void]$sb.AppendLine(('-' * 78))
    }
    Write-AdmFileAtomic -Path $Path -Content $sb.ToString()
    [pscustomobject]@{ Path = $Path; Entries = $entries.Count; Days = $Days }
}

# Wrap prose for the text report. Not cosmetic: an 800-character paragraph on one line is the
# difference between a report someone reads and one they close.
function Split-AdmTextForReport {
    param([string]$Text, [int]$Width = 62)
    $out = @(); $line = ''
    foreach ($w in ($Text -split '\s+')) {
        if (-not $w) { continue }
        if (($line.Length + $w.Length + 1) -gt $Width) { $out += $line; $line = $w }
        else { $line = if ($line) { "$line $w" } else { $w } }
    }
    if ($line) { $out += $line }
    ,$out
}
