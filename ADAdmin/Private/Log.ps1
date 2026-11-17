# Log.ps1 -- the error log the GUI shows and a 7-day rolling cleanup.
#
# ⛔ THE FIRST RULE OF THIS FILE: LOGGING MUST NEVER THROW. Every function here swallows its own
# failures, because a logger that raises replaces the operator's real error with a message about
# logging -- and this repo has already been bitten twice by diagnostic code failing while
# reporting a failure. If the disk is read-only, the entry still reaches the in-memory ring and
# the GUI still shows it; the operator loses history, not the error in front of them.
#
# ROLLING CLEANUP: one file per day, `adadmin-YYYY-MM-DD.jsonl`, and files older than 7 days are
# deleted. Deliberately NOT a single file that gets rewritten -- rewriting the file you are
# appending to is how a log gets truncated on a USB stick that was pulled mid-write.

$script:AdmLogRing      = New-Object System.Collections.ArrayList  # last N entries, always available
$script:AdmLogRingMax   = 500
$script:AdmLogPruned    = $false
$script:AdmLogRetention = 7
$script:AdmSessionId    = [guid]::NewGuid().ToString('N').Substring(0, 8)
$script:AdmLogDirCache  = $null
$script:AdmLogDisabled  = $false   # set only if the destination proves unwritable

function Get-AdmLogDir {
    [OutputType([string])]
    param()
    if ($script:AdmLogDirCache) { return $script:AdmLogDirCache }
    $candidates = @()
    if ($env:ADADMIN_LOG_DIR) { $candidates += $env:ADADMIN_LOG_DIR }
    # Beside the store, so a USB stick carries its own history.
    try {
        $storePath = if ($script:AdmSession) { $script:AdmSession.Path } else { Get-AdmDefaultStorePath }
        $candidates += (Join-Path ([System.IO.Path]::GetDirectoryName($storePath)) 'adadmin-logs')
    } catch { }
    $candidates += (Join-Path $env:LOCALAPPDATA 'ADAdmin\logs')

    foreach ($c in $candidates) {
        if (-not $c) { continue }
        try {
            if (-not (Test-Path -LiteralPath $c)) { New-Item -ItemType Directory -Path $c -Force -ErrorAction Stop | Out-Null }
            # Prove it is writable NOW rather than discovering it at the first error.
            $probe = Join-Path $c ('.w' + [System.IO.Path]::GetRandomFileName())
            [System.IO.File]::WriteAllText($probe, 'x')
            Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
            $script:AdmLogDirCache = $c
            return $c
        } catch { continue }
    }
    $script:AdmLogDisabled = $true
    $null
}

function Get-AdmLogFile {
    param([datetime]$When = (Get-Date))
    $dir = Get-AdmLogDir
    if (-not $dir) { return $null }
    Join-Path $dir ('adadmin-{0:yyyy-MM-dd}.jsonl' -f $When)
}

function Invoke-AdmLogPrune {
    <#
      Delete day-files older than the retention window. Runs once per session, lazily, so it
      costs nothing until something is actually logged.
    #>
    [CmdletBinding()]
    param([int]$Days = $script:AdmLogRetention, [switch]$Force)
    if ($script:AdmLogPruned -and -not $Force) { return }
    $script:AdmLogPruned = $true
    try {
        $dir = Get-AdmLogDir
        if (-not $dir) { return }
        $cutoff = (Get-Date).Date.AddDays(-$Days)
        $removed = 0
        foreach ($f in (Get-ChildItem -LiteralPath $dir -Filter 'adadmin-*.jsonl' -ErrorAction SilentlyContinue)) {
            # Date comes from the FILENAME, not the file's mtime: copying a stick or restoring a
            # backup rewrites mtime and would silently resurrect or destroy the wrong days.
            if ($f.Name -match 'adadmin-(\d{4})-(\d{2})-(\d{2})\.jsonl$') {
                $d = Get-Date -Year $Matches[1] -Month $Matches[2] -Day $Matches[3] -Hour 0 -Minute 0 -Second 0
                if ($d -lt $cutoff) {
                    try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop; $removed++ } catch { }
                }
            }
        }
        if ($removed) { Write-Verbose "ADAdmin log: pruned $removed file(s) older than $Days days." }
    } catch { }   # a failed prune must never stop a write
}

function Write-AdmLogEntry {
    <#
      Append one entry. Returns the entry so a caller can show it; never throws.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('info', 'warn', 'error')][string]$Severity = 'info',
        [string]$Event,
        [string]$Message,
        [string]$Operation,
        [string]$Target,
        [string]$Domain,
        $Diagnosis
    )
    $entry = $null
    try {
        $entry = [pscustomobject]@{
            ts        = (Get-Date).ToString('o')
            tsLocal   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            severity  = $Severity
            event     = $Event
            message   = $Message
            operation = $Operation
            target    = $Target
            domain    = $Domain
            session   = $script:AdmSessionId
            user      = "$env:USERDOMAIN\$env:USERNAME"
            machine   = $env:COMPUTERNAME
            pid       = $PID
            psVersion = $PSVersionTable.PSVersion.ToString()
            code      = if ($Diagnosis) { $Diagnosis.Code } else { $null }
            title     = if ($Diagnosis) { $Diagnosis.Title } else { $null }
            why       = if ($Diagnosis) { $Diagnosis.Why } else { $null }
            fix       = if ($Diagnosis) { @($Diagnosis.Fix) } else { @() }
            recognised = if ($Diagnosis) { [bool]$Diagnosis.Recognised } else { $null }
            technical = if ($Diagnosis) { $Diagnosis.Technical } else { $null }
        }

        # The ring first: it is the copy that cannot fail, and the GUI reads it.
        [void]$script:AdmLogRing.Add($entry)
        while ($script:AdmLogRing.Count -gt $script:AdmLogRingMax) { $script:AdmLogRing.RemoveAt(0) }

        if ($script:AdmLogDisabled) { return $entry }
        Invoke-AdmLogPrune
        $file = Get-AdmLogFile
        if (-not $file) { return $entry }
        $line = ($entry | ConvertTo-Json -Depth 8 -Compress) + "`n"
        # Append with an explicit no-BOM UTF8 stream. AppendAllText would re-open per call; this
        # is the same thing but with the encoding pinned, because a BOM mid-file breaks the
        # line-by-line parse on read.
        [System.IO.File]::AppendAllText($file, $line, (Get-AdmUtf8Encoding))
    } catch {
        $script:AdmLogDisabled = $true   # stop trying; the ring still works
    }
    $entry
}

# Canonical entry shape. Anything read back from disk is projected through this so consumers can
# touch any field without checking. Without it, a hand-edited line, a record written by an older
# build, or a half-written line from a yanked USB stick makes the GUI throw "the property 'code'
# cannot be found" under strict mode -- the log becoming the thing that breaks.
# ⛔ THIS LIST IS THE ENTRY SHAPE. ConvertTo-AdmLogEntry projects every entry onto exactly these
# fields, so a field missing from here is SILENTLY DISCARDED on read no matter how faithfully it
# was written. `reviewed` was written to the file and to the ring correctly and then stripped by
# every read, so marking an entry reviewed appeared to do nothing at all. Anything added to an
# entry has to be added here as well.
$script:AdmLogFields = @('ts','tsLocal','severity','event','message','operation','target','domain',
                         'session','user','machine','pid','psVersion','code','title','why','fix',
                         'recognised','technical','source','reviewed')

function ConvertTo-AdmLogEntry {
    param($Raw)
    $o = [ordered]@{}
    foreach ($f in $script:AdmLogFields) {
        $v = $null
        try { if ($Raw.PSObject.Properties[$f]) { $v = $Raw.$f } } catch { }
        $o[$f] = $v
    }
    if (-not $o['severity']) { $o['severity'] = 'info' }
    if (-not $o['fix']) { $o['fix'] = @() }
    if (-not $o['tsLocal'] -and $o['ts']) {
        try { $o['tsLocal'] = ([datetime]$o['ts']).ToString('yyyy-MM-dd HH:mm:ss') } catch { $o['tsLocal'] = [string]$o['ts'] }
    }
    if (-not $o['source']) { $o['source'] = 'adadmin' }
    [pscustomobject]$o
}

function Get-AdmLogEntries {
    [CmdletBinding()]
    param(
        [int]$Days = $script:AdmLogRetention,
        [ValidateSet('all', 'info', 'warn', 'error')][string]$Severity = 'all',
        [int]$Last = 200,
        [switch]$IncludeRing
    )
    $out = New-Object System.Collections.ArrayList
    try {
        $dir = Get-AdmLogDir
        if ($dir) {
            $cutoff = (Get-Date).Date.AddDays(-$Days)
            $files = Get-ChildItem -LiteralPath $dir -Filter 'adadmin-*.jsonl' -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -match 'adadmin-(\d{4})-(\d{2})-(\d{2})\.jsonl$' -and
                                    (Get-Date -Year $Matches[1] -Month $Matches[2] -Day $Matches[3]) -ge $cutoff } |
                     Sort-Object Name
            foreach ($f in $files) {
                foreach ($line in [System.IO.File]::ReadAllLines($f.FullName, (Get-AdmUtf8Encoding))) {
                    if (-not $line.Trim()) { continue }
                    # A single corrupt line (a half-written record from a yanked stick) must not
                    # take the whole log with it -- and a line missing fields must not either,
                    # hence the normalise.
                    try { [void]$out.Add((ConvertTo-AdmLogEntry -Raw ($line | ConvertFrom-Json))) } catch { }
                }
            }
        }
    } catch { }

    if ($IncludeRing -or $script:AdmLogDisabled) {
        foreach ($e in $script:AdmLogRing) {
            if (-not ($out | Where-Object { $_.ts -eq $e.ts -and $_.message -eq $e.message })) {
                [void]$out.Add((ConvertTo-AdmLogEntry -Raw $e))
            }
        }
    }

    $res = @($out)
    if ($Severity -ne 'all') { $res = @($res | Where-Object { $_.severity -eq $Severity }) }
    $res = @($res | Sort-Object ts)
    if ($Last -gt 0 -and $res.Count -gt $Last) { $res = @($res[($res.Count - $Last)..($res.Count - 1)]) }
    ,$res
}

# The one place a failure is turned into a diagnosis, logged, and re-raised. Public cmdlets wrap
# their real work in this so the behaviour is identical everywhere instead of remembered.
function Invoke-AdmGuarded {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [Parameter(Mandatory)][string]$Operation,
        [string]$Target,
        [string]$Domain
    )
    try {
        & $Action
    } catch {
        $diag = Resolve-AdmDiagnosis -ErrorObject $_ -Operation $Operation -Target $Target
        [void](Write-AdmLogEntry -Severity $diag.Severity -Event 'failure' -Message $_.Exception.Message `
                -Operation $Operation -Target $Target -Domain $Domain -Diagnosis $diag)
        # Re-raise LOUDLY: the plain-English title leads, the original message is kept, and the
        # diagnosis rides along on the exception's Data so the CLI and GUI can render it in full
        # without re-deriving it.
        $msg = "$($diag.Title). $($_.Exception.Message)"
        $err = New-Object System.Exception($msg, $_.Exception)
        $err.Data['AdmDiagnosis'] = $diag
        throw $err
    }
}
