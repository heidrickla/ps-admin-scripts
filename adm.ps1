<#
.SYNOPSIS
  adm -- portable multi-forest Active Directory administration.

.DESCRIPTION
  One entry point for two very different callers:

    A HUMAN gets tables, colour, prompts for the passphrase, and confirmation before writes.
    A SCRIPT gets `-Json` (a stable envelope on stdout), `-NonInteractive` (never blocks on a
    prompt), and exit codes that mean something.

  THE SESSION PROBLEM, stated plainly: there is no daemon, so a decrypted store cannot outlive
  a process. A one-shot command therefore unlocks, acts, and forgets -- which costs a PBKDF2
  derivation each time and is the right shape for a script. A human doing ten things in a row
  should use `adm shell`, which unlocks once. `adm gui` does the same with a window.

.EXAMPLE
  adm store init -Name alice
.EXAMPLE
  adm domain resolve -Target ws1.child.corp.example.com
.EXAMPLE
  $env:ADADMIN_PASSPHRASE = '...'; adm user list -Target corp.example.com -Json
.EXAMPLE
  adm shell
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Command,
    [Parameter(Position = 1)][string]$Sub,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Exit codes are part of the contract a script scripts against. Do not renumber.
$EXIT_OK = 0; $EXIT_ERROR = 1; $EXIT_USAGE = 2; $EXIT_LOCKED = 3
$EXIT_NOTFOUND = 4; $EXIT_AMBIGUOUS = 5

Import-Module (Join-Path $PSScriptRoot 'ADAdmin\ADAdmin.psd1') -Force -ErrorAction Stop

# --- argument parsing -------------------------------------------------------------------------

function Read-AdmArgs {
    param([string[]]$Tokens)
    # ⛔ $Tokens ARRIVES AS $null ON A BARE `adm`, EVEN THOUGH THE CALLER WRITES @($Rest). With no
    # remaining arguments $Rest is $null, and binding @($null) to a [string[]] parameter collapses
    # it back to $null rather than keeping a one-element array. Under Set-StrictMode 2.0
    # $null.Count THROWS -- so running `adm` with no arguments, which is the first thing anyone
    # types, died with "The property 'Count' cannot be found on this object" instead of printing
    # the usage banner. Measured 2026-08-28; every suite invokes adm WITH arguments, which is
    # exactly why nothing caught it.
    #
    # ⚠ The Where-Object is not redundant. If the collapse ever stops happening, @($null) has a
    # Count of ONE, and this would parse a phantom empty token instead of no tokens at all.
    $Tokens = @($Tokens | Where-Object { $null -ne $_ })
    $o = @{}
    $i = 0
    while ($i -lt $Tokens.Count) {
        $t = $Tokens[$i]
        if ($t -match '^-{1,2}(.+)$') {
            $key = $Matches[1].ToLowerInvariant()
            $next = if ($i + 1 -lt $Tokens.Count) { $Tokens[$i + 1] } else { $null }
            if ($null -ne $next -and $next -notmatch '^-{1,2}[A-Za-z]') {
                $o[$key] = $next; $i += 2
            } else { $o[$key] = $true; $i += 1 }   # bare flag
        } else { $i += 1 }
    }
    $o
}

$opt = Read-AdmArgs -Tokens @($Rest)
$AsJson = [bool]($opt['json'])
$NonInteractive = [bool]($opt['noninteractive']) -or [bool]($opt['ni'])

function Opt { param([string]$Name, $Default = $null)
    if ($opt.ContainsKey($Name)) { $opt[$Name] } else { $Default } }

# --- output -----------------------------------------------------------------------------------

function Write-Result {
    param($Data, [string]$Cmd, [string]$Note)
    # ⛔ TRUNCATION HAS TO BE IN THE ENVELOPE, NOT ONLY IN A WARNING. A cut read announces itself
    # with Write-Warning, which is fine for a person and USELESS to the caller this envelope
    # exists for: a script reading stdout as JSON never sees the warning stream. It would take
    # `data` -- the first 200 of 3000 accounts -- for the domain, and act on it. Every other
    # surface in this toolkit learned to say "this is a floor"; the machine-readable one is the
    # last place that should still be silent about it.
    $cut = [bool](Get-AdmSearchTruncated)
    if ($AsJson) {
        # One stable envelope. A script can rely on .ok existing whether or not anything failed.
        [pscustomobject]@{ ok = $true; command = $Cmd; note = $Note; data = $Data; truncated = $cut } |
            ConvertTo-Json -Depth 8 -Compress
    } else {
        if ($Note) { Write-Host $Note -ForegroundColor DarkGray }
        if ($null -ne $Data) { $Data | Format-Table -AutoSize | Out-String -Width 200 | Write-Host }
        if ($cut) {
            Write-Host ('  INCOMPLETE -- the directory holds more than this. Any count, or a name ' +
                        'missing from this list, is not the answer. Narrow the search or raise -Limit.') -ForegroundColor Red
        }
    }
}

function Write-Failure {
    param([string]$Message, [int]$Code, [string]$Cmd, $Diagnosis)
    if ($AsJson) {
        [pscustomobject]@{
            ok = $false; command = $Cmd; error = $Message; exitCode = $Code
            diagnosis = if ($Diagnosis) {
                [pscustomobject]@{ code = $Diagnosis.Code; title = $Diagnosis.Title
                                   why = $Diagnosis.Why; fix = @($Diagnosis.Fix)
                                   recognised = $Diagnosis.Recognised; technical = $Diagnosis.Technical }
            } else { $null }
        } | ConvertTo-Json -Depth 6 -Compress
    } else {
        # FAIL LOUDLY AND IN ENGLISH. The plain-English title leads, then why, then what to do.
        # The raw error is kept last for whoever wants it -- never dropped, never leading.
        Write-Host ''
        if ($Diagnosis) {
            Write-Host "  PROBLEM  $($Diagnosis.Title)" -ForegroundColor Red
            if ($Diagnosis.Why) {
                Write-Host ''
                Write-Host "  Why this happened" -ForegroundColor DarkGray
                foreach ($l in (Format-Wrapped $Diagnosis.Why 74)) { Write-Host "    $l" -ForegroundColor Gray }
            }
            if (@($Diagnosis.Fix).Count) {
                Write-Host ''
                Write-Host "  What to try" -ForegroundColor DarkGray
                $i = 1
                foreach ($f in @($Diagnosis.Fix)) {
                    foreach ($l in (Format-Wrapped "$i. $f" 74)) { Write-Host "    $l" -ForegroundColor White }
                    $i++
                }
            }
            if (-not $Diagnosis.Recognised) {
                Write-Host ''
                Write-Host "  This is not a failure the toolkit recognises -- the raw error is below." -ForegroundColor Yellow
            }
            Write-Host ''
            Write-Host "  Technical detail" -ForegroundColor DarkGray
            foreach ($l in (Format-Wrapped $Message 74)) { Write-Host "    $l" -ForegroundColor DarkGray }
            if ($Diagnosis.Technical -and $Diagnosis.Technical.Codes) {
                Write-Host "    codes: $($Diagnosis.Technical.Codes)" -ForegroundColor DarkGray
            }
            Write-Host ''
            Write-Host "  Recorded in the log. See it with:  adm log list" -ForegroundColor DarkGray
        } else {
            Write-Host "  PROBLEM  $Message" -ForegroundColor Red
        }
        Write-Host ''
    }
    exit $Code
}

# Findings from a script check, grouped so the same problem at ten lines reads as one problem.
function Show-ScriptFindings {
    param($Findings, [string]$Path)
    $f = @($Findings)
    Write-Host ''
    Write-Host "  $([System.IO.Path]::GetFileName($Path))" -ForegroundColor Cyan
    if (-not $f.Count) { Write-Host '  Nothing to change -- this already matches the house style.' -ForegroundColor Green; Write-Host ''; return }

    Write-Host ("  {0} error(s), {1} warning(s); {2} can be fixed automatically" -f
        @($f | Where-Object { $_.Severity -eq 'error' }).Count,
        @($f | Where-Object { $_.Severity -eq 'warn' }).Count,
        @($f | Where-Object { $_.AutoFix }).Count) -ForegroundColor DarkGray

    foreach ($g in ($f | Group-Object Id | Sort-Object { if ($_.Group[0].Severity -eq 'error') { 0 } else { 1 } })) {
        $first = $g.Group[0]
        $lines = (@($g.Group | ForEach-Object { $_.Line }) | Select-Object -Unique) -join ', '
        $col = if ($first.Severity -eq 'error') { 'Red' } else { 'Yellow' }
        Write-Host ''
        Write-Host ("  {0}  {1}   line {2}{3}" -f $first.Id, $first.Name, $lines,
                    $(if ($first.AutoFix) { '   [fixed on import]' } else { '' })) -ForegroundColor $col
        foreach ($l in (Format-Wrapped "PROBLEM  $($first.Problem)" 74)) { Write-Host "    $l" }
        foreach ($l in (Format-Wrapped "IMPACT   $($first.Impact)"  74)) { Write-Host "    $l" -ForegroundColor Gray }
        foreach ($l in (Format-Wrapped "TO FIX   $($first.Fix)"     74)) { Write-Host "    $l" -ForegroundColor Green }
    }
}

function Format-Wrapped {
    param([string]$Text, [int]$Width = 74)
    $out = @(); $line = ''
    foreach ($w in ($Text -split '\s+')) {
        if (-not $w) { continue }
        if (($line.Length + $w.Length + 1) -gt $Width) { $out += $line; $line = $w }
        else { $line = if ($line) { "$line $w" } else { $w } }
    }
    if ($line) { $out += $line }
    ,$out
}

# An error's TEXT decides the exit code, so a script can branch without parsing prose.
function Get-ExitCodeFor {
    param([string]$Message)
    if ($Message -like '*is locked*' -or $Message -like '*auto-locked*') { return $EXIT_LOCKED }
    if ($Message -like '*matches more than one*' -or $Message -like '*more than one object*') { return $EXIT_AMBIGUOUS }
    if ($Message -like '*No registered domain matches*' -or $Message -like '*No domain named*' -or
        $Message -like '*No object matching*' -or $Message -like '*no * credential*') { return $EXIT_NOTFOUND }
    $EXIT_ERROR
}

# --- passphrase -------------------------------------------------------------------------------

function Get-Passphrase {
    param([string]$Purpose = 'Store passphrase')
    # Order is deliberate: an explicit env var beats a prompt, so a script never hangs.
    if ($env:ADADMIN_PASSPHRASE) {
        return (ConvertTo-SecureString $env:ADADMIN_PASSPHRASE -AsPlainText -Force)
    }
    if ($NonInteractive) {
        throw 'No passphrase available. Set ADADMIN_PASSPHRASE, or drop -NonInteractive to be prompted.'
    }
    Read-Host -Prompt $Purpose -AsSecureString
}

function Confirm-Unlocked {
    if ((Get-AdmStoreInfo).Unlocked) { return }
    $p = Get-Passphrase
    $r = Opt 'as'
    if ($r) { Unlock-AdmStore -Passphrase $p -Recipient $r | Out-Null }
    else     { Unlock-AdmStore -Passphrase $p | Out-Null }
}

function Get-RequiredOpt {
    param([string]$Name)
    $v = Opt $Name
    # ⛔ A USAGE MISTAKE IS NOT AN UNRECOGNISED FAILURE. This used to `throw`, which the outer
    # catch handed to Resolve-AdmDiagnosis -- and no catalog rule matches "Missing required
    # option", so `adm user list -target` (a flag with no value, one of the commonest typos there
    # is) printed "Something failed, and this is not a failure the toolkit recognises" and exited
    # 1. The real message survived only in the technical detail underneath.
    #
    # ⚠ Two things were wrong and the exit code is the one that matters to a caller: 1 says
    # "error", 2 says "you typed it wrong", and every other usage refusal in this file already
    # says 2. Routing through Write-Failure gives the plain message and the right code.
    #
    # ⚠ `$v -is [bool]` is the VALUELESS FLAG case: Read-AdmArgs stores a bare `-target` at the
    # end of the line as $true, so without this the value handed on would be the string 'True'.
    if (-not $v -or $v -is [bool]) {
        $why = if ($v -is [bool]) { "-$Name was given without a value" } else { "-$Name is required" }
        Write-Failure -Cmd $cmdName -Code $EXIT_USAGE -Message "$why. Try: adm help"
    }
    [string]$v
}

# --- help --------------------------------------------------------------------------------------

$HELP = @'
adm -- portable multi-forest Active Directory administration

USAGE
  adm <command> <sub> [options]

STORE
  adm store init         -Name <admin>          create the encrypted store
  adm store unlock                              unlock (interactive session only)
  adm store status                              path, admins, provider, lock state
  adm store add-admin    -Name <admin>          give another admin their own passphrase
  adm store remove-admin -Name <admin>          drop an admin's wrap (NOT retroactive revocation)

DOMAIN
  adm domain list
  adm domain add     -Name <n> -Dns <fqdn> [-Netbios <n>] [-Dc <host>] [-Alias <s>] [-Host <s>]
  adm domain remove  -Name <n>
  adm domain resolve -Target <host|fqdn|upn|netbios> [-UseDns]
  adm domain set-cred -Name <n> [-Tier read|write] [-User <u>] [-Default]
  adm domain remove-cred -Name <n> [-Tier read|write]
  adm domain test    -Target <t>

OBJECTS   (-Target picks the domain; the credential follows from it)
  adm user list      -Target <t> [-Identity <s>] [-Tier <t>] [-Limit <n>]
  adm user unlock    -Target <t> -Identity <s>
  adm user enable    -Target <t> -Identity <s>
  adm user disable   -Target <t> -Identity <s>
  adm user reset-password -Target <t> -Identity <s> [-MustChange] [-Generate]
                     -Generate makes a complex password and returns it ONCE; the log records
                     that a reset happened, never the value
  adm user set       -Target <t> -Identity <s> [-Title <s>] [-Department <s>] [-Manager <s>]
                     [-EmailAddress <s>] [-Office <s>] [-Description <s>] [-Company <s>]
                     [-OfficePhone <s>] [-MobilePhone <s>] [-City <s>] [-Country <XX>] ...
                     [-AccountExpires <date>] [-NeverExpires] [-PasswordNeverExpires true|false]
                     [-Clear a,b]        an option with NO value clears that attribute
  adm user import    -Target <t> -Path <csv> [-Mode Create|Update|Upsert] [-DefaultPath <dn>]
                     [-StopOnError] [-Encoding <e>] [-RollbackPath <csv>]
                     validates the WHOLE file before writing anything; -WhatIf returns the plan
                     per row, with the resolved DN and the exact attribute changes (From/To).
                     Columns are the -Set names plus SamAccountName, Password, Path, Enabled.
                     No Password column means one is generated and returned to you once.
                     -RollbackPath records what was applied so a bad import can be undone
  adm group list     -Target <t> [-Identity <s>]
  adm group members  -Target <t> -Identity <s> [-Recursive] [-IncludeGroups]
  adm group new      -Target <t> -Name <s> [-Scope Global|DomainLocal|Universal]
                     [-Category Security|Distribution] [-Path <dn>] [-Description <s>]
  adm group remove   -Target <t> -Identity <s> [-Force]
  adm group add-member    -Target <t> -Group <s> -Identity <s> [-MemberType User|Computer]
  adm group remove-member -Target <t> -Group <s> -Identity <s> [-MemberType User|Computer]
  adm computer list  -Target <t> [-Identity <s>]
  adm computer new   -Target <t> -Name <s> [-Path <dn>] [-Description <s>] [-Location <s>]
                     pre-stage an account so a machine joins into the RIGHT OU -- CN=Computers
                     is a container and no Group Policy can be linked to it
  adm computer set   -Target <t> -Identity <s> [-Description <s>] [-Location <s>] [-ManagedBy <s>]
  adm computer enable / disable -Target <t> -Identity <s>     (a DC is always refused)

ORGANIZATIONAL UNITS AND OBJECT LIFECYCLE
  adm ou list        -Target <t> [-Identity <s>] [-SearchBase <dn>] [-Protection] [-Containers]
                     -Containers also lists CN=Users / CN=Computers / CN=Builtin, which are
                     containers, NOT OUs -- and are where a stock domain keeps its accounts
  adm ou new         -Target <t> -Name <s> [-Path <dn>] [-Description <s>] [-Unprotected]
  adm ou remove      -Target <t> -Identity <s> [-Recurse] [-RemoveProtection]
  adm object move    -Target <t> -Identity <s> -To <dn>   [-Class user|group|computer|ou]
  adm object rename  -Target <t> -Identity <s> -NewName <s>
  adm object remove  -Target <t> -Identity <s> [-RemoveProtection]
  adm object protect / unprotect -Target <t> -Identity <s>
  adm object set     -Target <t> -Identity <s> -Attr name=value[,name=value]

HELP DESK AND FOREST SHAPE   (read-only)
  adm laps get       -Target <t> -Identity <machine>
                     tells "you cannot read it" APART from "no password stored"
  adm bitlocker get  -Target <t> -Identity <machine> [-KeyId <prefix>]
  adm trust list     -Target <t>                       direction, transitivity, SID filtering
  adm site list      -Target <t>                       flags sites with NO subnets
                     zero sites is never right -- every forest has Default-First-Site-Name
  adm subnet list    -Target <t> [-Orphaned]           subnets, and which map to NO site
  adm gpo list       -Target <t> [-Identity <s>] [-Unlinked]   links, and what is linked nowhere
  adm pso list       -Target <t> [-Identity <s>] [-Unlinked]   fine-grained password policies;
                     LOWER precedence wins, and a PSO applying to nobody is dead configuration

RECYCLE BIN
  adm deleted status  -Target <t>            is the bin on? it decides what a restore returns
  adm deleted list    -Target <t> [-Identity <s>] [-Class user|group|computer|ou]
  adm deleted restore -Target <t> -Identity <s> [-To <dn>] [-AcceptTombstone]
                     with the bin OFF a restore returns a stripped object with no group
                     memberships, so it is refused unless you say -AcceptTombstone

BRING IN AN EXISTING SCRIPT   (your original file is never modified)
  adm script check  -Path <file>                    what would change, and why
  adm script import -Path <file> [-Name n] [-Force] convert and install it
  adm script list                                   what is installed; flags a changed source
  adm script run    -Name <n> [-Target <t>]         run it with the toolkit's plumbing
  adm script remove -Name <n>                       uninstall (leaves your original alone)

DIAGNOSE AND FIX
  adm scan    [-Domain <n>] [-Scope machine|store|domain]   check everything; changes nothing
  adm fix     [-Yes] [-AllowMachineChanges] [-WhatIf]       apply fixes, asking before each one
  adm catalog [-Code <code>] [-Severity error|warn]         every failure the toolkit can explain
  adm catalog -Markdown [-Path <file>]                      regenerate the reference table

LOG   (kept 7 days, then deleted automatically)
  adm log list    [-Days n] [-Last n] [-Problems]   what happened, newest last
  adm log show    [-Last n]                         full detail: why, and what to try
  adm log windows [-Level error] [-Hours n]         Windows' OWN errors from this machine
  adm log export  -Path <file> [-Problems]          plain-text report to hand to someone
  adm log info                                      where the log lives, is it writable
  adm log clear   [-All]                            -All wipes it; without, just prunes

SESSION
  adm shell                                     interactive; unlocks once
  adm gui                                       dark-glass window

GLOBAL
  -Json              structured envelope on stdout (for scripts)
                     NOTE: with -WhatIf, PowerShell prints its own "What if:" narration to stdout
                     FIRST. It is written straight to the host and cannot be redirected or
                     suppressed -- 2>, 4>, 5>, 6> and $WhatIfPreference were all measured and
                     none of them catch it. The envelope is always the LAST line, so parse
                     the last line beginning with '{' rather than the whole of stdout.
                     >> CHECK .truncated BEFORE TRUSTING .data. True means the directory holds
                     more than came back, so a count is a FLOOR and a name missing from the
                     list is not proof it does not exist. The human surfaces get a warning on
                     stderr; you are reading stdout and will never see it. Narrow the query or
                     raise -Limit -- do not treat a truncated read as the answer.
  -NonInteractive    never prompt; passphrase must come from ADADMIN_PASSPHRASE
  -Provider adsi|mock    override the directory backend
  -As <admin>        which admin's wrap to try first
  -WhatIf            show the write without performing it
  -Yes               skip confirmation on writes

ENVIRONMENT
  ADADMIN_STORE       path to the store file (default: beside the module)
  ADADMIN_PASSPHRASE  passphrase, for non-interactive use
  ADADMIN_PROVIDER    adsi | mock
  ADADMIN_MOCK_DATA   fixture path for the mock provider

EXIT CODES
  0 ok   1 error   2 usage   3 locked   4 not found   5 ambiguous
'@

# --- dispatch ------------------------------------------------------------------------------------

if (-not $Command -or $Command -in @('help', '-h', '--help', '/?')) {
    if ($AsJson) { [pscustomobject]@{ ok = $true; command = 'help'; data = $HELP } | ConvertTo-Json -Compress }
    else { Write-Host $HELP }
    exit $EXIT_OK
}

$cmdName = "$Command $Sub".Trim()
$provider = Opt 'provider'
if ($provider) { Set-AdmProvider -Name ([string]$provider) | Out-Null }

$whatIf = [bool](Opt 'whatif')
$yes = [bool](Opt 'yes')
# A write is confirmed unless the caller said otherwise. -NonInteractive implies -Yes, because a
# prompt a script cannot answer is just a hang.
$confirmPref = -not ($yes -or $NonInteractive)

# ⛔ ONE RESET, HERE, FOR THE WHOLE INVOCATION. The truncation flag is sticky by design, and this
# process runs exactly one command -- so clearing it once before dispatch and reading it once in
# Write-Result covers every read the command makes, however many searches a cmdlet runs
# internally. Nesting cannot confuse it because there is no nesting: one command, one process.
Reset-AdmSearchTruncated

try {
    # ⛔ REJECT A MISSING SUB-VERB BEFORE ASKING FOR A CREDENTIAL. Several command groups call
    # Confirm-Unlocked at the TOP of their block, before the sub-verb switch -- so `adm domain`,
    # `adm user`, `adm group`, `adm ou` and `adm object` with no sub-verb PROMPTED FOR A
    # PASSPHRASE and only rejected the command afterwards. Two things wrong with that, and the
    # second is the worse one:
    #
    #   * it blocks forever with no terminal. Measured 2026-08-28: five of these hung a headless
    #     run until it was killed, while `store`, `log` and `script` -- whose Confirm-Unlocked
    #     sits inside the individual sub-verbs -- refused in milliseconds
    #   * it asks a HUMAN TO TYPE A SECRET for a command that was never going to run. A typo
    #     should cost a usage message, not a passphrase
    #
    # ⚠ Checked here rather than by moving five Confirm-Unlocked calls, because the ordering is
    # the bug and a guard at the front fixes every group at once -- including any added later.
    # ⚠ AN UNKNOWN SUB-VERB IS THE SAME PATH AS A MISSING ONE. `adm domain bogus` reached
    # Confirm-Unlocked exactly as `adm domain` did, so the first version of this guard -- which
    # only checked for an EMPTY $Sub -- fixed half the bug. A typo is far likelier than an
    # omission, so it fixed the less common half.
    #
    # ⛔ THIS TABLE MUST NOT DRIFT FROM THE SWITCH ARMS BELOW, and it is not maintained by
    # discipline: tests\CliGui.Tests.ps1 rebuilds it from adm.ps1's own AST and fails if the two
    # disagree in either direction. A sub-verb added below and missing here would be refused
    # before it ran; one removed below and left here would fall through to a prompt again.
    $subVerbs = @{
        store     = @('init', 'unlock', 'lock', 'status', 'add-admin', 'remove-admin')
        domain    = @('list', 'add', 'remove', 'remove-cred', 'resolve', 'test', 'set-cred')
        user      = @('list', 'unlock', 'enable', 'disable', 'reset-password', 'set', 'import')
        group     = @('list', 'members', 'new', 'remove', 'add-member', 'remove-member')
        computer  = @('list', 'new', 'set', 'enable', 'disable')
        ou        = @('list', 'new', 'remove')
        object    = @('move', 'rename', 'remove', 'protect', 'unprotect', 'set')
        deleted   = @('list', 'status', 'restore')
        laps      = @('get')
        bitlocker = @('get')
        trust     = @('list')
        site      = @('list')
        subnet    = @('list')
        gpo       = @('list')
        pso       = @('list')
        script    = @('check', 'import', 'list', 'run', 'remove')
        log       = @('list', 'show', 'windows', 'export', 'info', 'clear')
    }
    $cmdLower = $Command.ToLowerInvariant()
    if ($subVerbs.ContainsKey($cmdLower)) {
        $subLower = ([string]$Sub).ToLowerInvariant()
        if ($subVerbs[$cmdLower] -notcontains $subLower) {
            $what = if ($Sub) { "'$Sub'" } else { "''" }
            Write-Failure -Cmd $cmdName -Code $EXIT_USAGE `
                -Message ("Unknown: $Command $what. Try one of: " +
                          "$(($subVerbs[$cmdLower] | Sort-Object) -join ', ') -- or: adm help")
        }
    }

    switch ($Command.ToLowerInvariant()) {

        'store' {
            switch (($Sub | ForEach-Object { $_.ToLowerInvariant() })) {
                'init' {
                    $name = Get-RequiredOpt 'name'
                    $p = Get-Passphrase -Purpose "New passphrase for '$name'"
                    if (-not $NonInteractive) {
                        $again = Read-Host -Prompt 'Confirm passphrase' -AsSecureString
                        $a = [Runtime.InteropServices.Marshal]::PtrToStringUni([Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($p))
                        $b = [Runtime.InteropServices.Marshal]::PtrToStringUni([Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($again))
                        if ($a -ne $b) { throw 'The two passphrases do not match; nothing was created.' }
                    }
                    Write-Result -Cmd $cmdName -Data (Initialize-AdmStore -RecipientName $name -Passphrase $p -Confirm:$false) `
                                 -Note 'Store created. Add the other admins with: adm store add-admin -Name <admin>'
                }
                'unlock' { Confirm-Unlocked; Write-Result -Cmd $cmdName -Data (Get-AdmStoreInfo) -Note 'Unlocked for this process only.' }
                'lock'   { Write-Result -Cmd $cmdName -Data (Lock-AdmStore) }
                'status' { Write-Result -Cmd $cmdName -Data (Get-AdmStoreInfo) }
                'add-admin' {
                    Confirm-Unlocked
                    $name = Get-RequiredOpt 'name'
                    $p = if ($env:ADADMIN_NEW_PASSPHRASE) { ConvertTo-SecureString $env:ADADMIN_NEW_PASSPHRASE -AsPlainText -Force }
                         elseif ($NonInteractive) { throw 'Set ADADMIN_NEW_PASSPHRASE for the new admin when running non-interactively.' }
                         else { Read-Host -Prompt "Passphrase for '$name'" -AsSecureString }
                    Write-Result -Cmd $cmdName -Data (Add-AdmRecipient -Name $name -Passphrase $p -Confirm:$false)
                }
                'remove-admin' {
                    Confirm-Unlocked
                    Write-Result -Cmd $cmdName -Data (Remove-AdmRecipient -Name (Get-RequiredOpt 'name') -Confirm:$confirmPref) `
                                 -Note 'This is not retroactive revocation -- rotate the AD credentials they could read.'
                }
                default { Write-Failure -Cmd $cmdName -Code $EXIT_USAGE -Message "Unknown: store '$Sub'. Try: adm help" }
            }
        }

        'domain' {
            Confirm-Unlocked
            switch (($Sub | ForEach-Object { $_.ToLowerInvariant() })) {
                'list' { Write-Result -Cmd $cmdName -Data (Get-AdmDomain) }
                'add' {
                    $splat = @{
                        Name = Get-RequiredOpt 'name'; DnsDomain = Get-RequiredOpt 'dns'; Confirm = $false
                    }
                    if (Opt 'netbios') { $splat.NetbiosName = [string](Opt 'netbios') }
                    if (Opt 'dc')      { $splat.DomainControllers = ([string](Opt 'dc')) -split ',' }
                    if (Opt 'alias')   { $splat.Aliases = ([string](Opt 'alias')) -split ',' }
                    if (Opt 'host')    { $splat.Hosts = ([string](Opt 'host')) -split ',' }
                    if (Opt 'force')   { $splat.Force = $true }
                    Write-Result -Cmd $cmdName -Data (Register-AdmDomain @splat)
                }
                'remove'  { Write-Result -Cmd $cmdName -Data (Unregister-AdmDomain -Name (Get-RequiredOpt 'name') -Confirm:$confirmPref) }
                'remove-cred' {
                    Write-Result -Cmd $cmdName -Data (Remove-AdmDomainCredential -Domain (Get-RequiredOpt 'name') `
                        -Tier ([string](Opt 'tier' 'read')) -Confirm:$confirmPref)
                }
                'resolve' { Write-Result -Cmd $cmdName -Data (Resolve-AdmDomain -Target (Get-RequiredOpt 'target') -UseDnsLookup:([bool](Opt 'usedns'))) }
                'test'    { Write-Result -Cmd $cmdName -Data (Test-AdmDomain -Target (Get-RequiredOpt 'target') -Tier ([string](Opt 'tier'))) }
                'set-cred' {
                    $name = Get-RequiredOpt 'name'
                    $tier = [string](Opt 'tier' 'read')
                    $user = if (Opt 'user') { [string](Opt 'user') }
                            elseif ($NonInteractive) { throw 'Missing -User.' }
                            else { Read-Host -Prompt "Username for $name/$tier (DOMAIN\user or user@domain)" }
                    $pw = if ($env:ADADMIN_CRED_PASSWORD) { ConvertTo-SecureString $env:ADADMIN_CRED_PASSWORD -AsPlainText -Force }
                          elseif ($NonInteractive) { throw 'Set ADADMIN_CRED_PASSWORD when running non-interactively.' }
                          else { Read-Host -Prompt "Password for $user" -AsSecureString }
                    $cred = New-Object System.Management.Automation.PSCredential($user, $pw)
                    Write-Result -Cmd $cmdName -Data (Set-AdmDomainCredential -Domain $name -Credential $cred -Tier $tier `
                                                        -SetDefault:([bool](Opt 'default')) -Confirm:$false)
                }
                default { Write-Failure -Cmd $cmdName -Code $EXIT_USAGE -Message "Unknown: domain '$Sub'. Try: adm help" }
            }
        }

        { $_ -in @('user', 'group', 'computer', 'ou', 'object') } {
            Confirm-Unlocked
            $target = Get-RequiredOpt 'target'
            $tier = [string](Opt 'tier')
            $identity = [string](Opt 'identity')
            $limit = [int](Opt 'limit' 200)
            $useDns = [bool](Opt 'usedns')

            switch ("$Command $Sub".ToLowerInvariant()) {
                'user list'     { Write-Result -Cmd $cmdName -Data (Get-AdmUser -Target $target -Identity $identity -Tier $tier -Limit $limit -UseDnsLookup:$useDns) }
                'group list'    { Write-Result -Cmd $cmdName -Data (Get-AdmGroup -Target $target -Identity $identity -Tier $tier -Limit $limit -UseDnsLookup:$useDns) }
                'computer list' { Write-Result -Cmd $cmdName -Data (Get-AdmComputer -Target $target -Identity $identity -Tier $tier -Limit $limit -UseDnsLookup:$useDns) }
                'user unlock'   { Write-Result -Cmd $cmdName -Data (Unlock-AdmUser -Target $target -Identity (Get-RequiredOpt 'identity') -Confirm:$confirmPref -WhatIf:$whatIf) }
                'user enable'   { Write-Result -Cmd $cmdName -Data (Set-AdmUserEnabled -Target $target -Identity (Get-RequiredOpt 'identity') -Enabled $true  -Confirm:$confirmPref -WhatIf:$whatIf) }
                'user disable'  { Write-Result -Cmd $cmdName -Data (Set-AdmUserEnabled -Target $target -Identity (Get-RequiredOpt 'identity') -Enabled $false -Confirm:$confirmPref -WhatIf:$whatIf) }
                'user reset-password' {
                    $id = Get-RequiredOpt 'identity'
                    # -Generate makes one that meets default complexity and hands it back ONCE.
                    # It is returned rather than logged: the log records that a reset happened,
                    # never what it was set to.
                    $generated = $null
                    $pw = if ([bool](Opt 'generate')) {
                              $generated = New-AdmRandomPassword
                              ConvertTo-SecureString $generated -AsPlainText -Force
                          }
                          elseif ($env:ADADMIN_NEW_PASSWORD) { ConvertTo-SecureString $env:ADADMIN_NEW_PASSWORD -AsPlainText -Force }
                          elseif ($NonInteractive) { throw 'Set ADADMIN_NEW_PASSWORD, or pass -Generate, when running non-interactively.' }
                          else { Read-Host -Prompt "New password for $id" -AsSecureString }
                    $res = Reset-AdmUserPassword -Target $target -Identity $id -NewPassword $pw `
                               -MustChangeAtNextLogon:([bool](Opt 'mustchange')) -Confirm:$confirmPref -WhatIf:$whatIf
                    if ($generated -and $res) {
                        $res = $res | Select-Object *, @{ n = 'GeneratedPassword'; e = { $generated } }
                    }
                    Write-Result -Cmd $cmdName -Data $res
                }
                # --- editing an existing user ---------------------------------------------------
                # Attribute options are mapped by NAME onto Set-AdmUser's parameters and splatted,
                # rather than each getting its own line here. A bare switch with no value (-office
                # with nothing after it) becomes an empty string, which is how the cmdlet spells
                # "clear this attribute".
                'user set' {
                    $p = @{ Target = $target; Identity = (Get-RequiredOpt 'identity') }
                    $textAttrs = @('displayname', 'givenname', 'surname', 'initials', 'description',
                                   'emailaddress', 'title', 'department', 'company', 'office',
                                   'officephone', 'mobilephone', 'fax', 'streetaddress', 'city',
                                   'state', 'postalcode', 'employeeid', 'employeenumber',
                                   'homedirectory', 'homedrive', 'scriptpath', 'profilepath',
                                   'webpage', 'notes', 'userprincipalname', 'manager', 'country',
                                   'countryname')
                    foreach ($n in $textAttrs) {
                        if ($opt.ContainsKey($n)) {
                            $p[$n] = if ($opt[$n] -is [bool]) { '' } else { [string]$opt[$n] }
                        }
                    }
                    if ($opt.ContainsKey('clear'))        { $p['Clear'] = @([string]$opt['clear'] -split ',' | ForEach-Object { $_.Trim() }) }
                    if ($opt.ContainsKey('neverexpires')) { $p['NeverExpires'] = $true }
                    if ($opt.ContainsKey('accountexpires')) { $p['AccountExpires'] = [datetime]::Parse([string]$opt['accountexpires']) }
                    if ($opt.ContainsKey('passwordneverexpires')) { $p['PasswordNeverExpires'] = [bool]::Parse([string]$opt['passwordneverexpires']) }
                    Write-Result -Cmd $cmdName -Data (Set-AdmUser @p -Confirm:$confirmPref -WhatIf:$whatIf)
                }

                # --- bulk -----------------------------------------------------------------------
                # Run it with -WhatIf first: that returns the PLAN for every row, including why
                # each skipped one is skipped, without touching the directory.
                'user import' {
                    Write-Result -Cmd $cmdName -Data (Import-AdmUserCsv -Target $target -Path (Get-RequiredOpt 'path') `
                        -Mode ([string](Opt 'mode' 'Create')) -DefaultPath ([string](Opt 'defaultpath')) `
                        -Encoding ([string](Opt 'encoding' 'UTF8')) -StopOnError:([bool](Opt 'stoponerror')) `
                        -RollbackPath ([string](Opt 'rollbackpath')) `
                        -Confirm:$confirmPref -WhatIf:$whatIf)
                }

                # --- groups ---------------------------------------------------------------------
                'group members' {
                    Write-Result -Cmd $cmdName -Data (Get-AdmGroupMember -Target $target -Identity (Get-RequiredOpt 'identity') `
                        -Recursive:([bool](Opt 'recursive')) -IncludeGroups:([bool](Opt 'includegroups')) `
                        -Tier $tier -Limit ([int](Opt 'limit' 100000)) -UseDnsLookup:$useDns)
                }
                'group new' {
                    Write-Result -Cmd $cmdName -Data (New-AdmGroup -Target $target -Name (Get-RequiredOpt 'name') `
                        -SamAccountName ([string](Opt 'sam')) -Path ([string](Opt 'path')) `
                        -Description ([string](Opt 'description')) `
                        -Scope ([string](Opt 'scope' 'Global')) -Category ([string](Opt 'category' 'Security')) `
                        -Confirm:$confirmPref -WhatIf:$whatIf)
                }
                'group remove' {
                    Write-Result -Cmd $cmdName -Data (Remove-AdmGroup -Target $target -Identity (Get-RequiredOpt 'identity') `
                        -Force:([bool](Opt 'force')) -Confirm:$confirmPref -WhatIf:$whatIf)
                }
                # -membertype Computer matters: a computer's sAMAccountName ends in '$' and the
                # user-shaped filter finds nothing without it.
                'group add-member' {
                    Write-Result -Cmd $cmdName -Data (Add-AdmGroupMember -Target $target -Group (Get-RequiredOpt 'group') `
                        -Identity (Get-RequiredOpt 'identity') -MemberType ([string](Opt 'membertype' 'User')) `
                        -Confirm:$confirmPref -WhatIf:$whatIf)
                }
                'group remove-member' {
                    Write-Result -Cmd $cmdName -Data (Remove-AdmGroupMember -Target $target -Group (Get-RequiredOpt 'group') `
                        -Identity (Get-RequiredOpt 'identity') -MemberType ([string](Opt 'membertype' 'User')) `
                        -Confirm:$confirmPref -WhatIf:$whatIf)
                }

                # --- computers --------------------------------------------------------------------
                'computer new' {
                    Write-Result -Cmd $cmdName -Data (New-AdmComputer -Target $target -Name (Get-RequiredOpt 'name') `
                        -Path ([string](Opt 'path')) -Description ([string](Opt 'description')) `
                        -Location ([string](Opt 'location')) -DnsHostName ([string](Opt 'dnshostname')) `
                        -Confirm:$confirmPref -WhatIf:$whatIf)
                }
                'computer set' {
                    $p = @{ Target = $target; Identity = (Get-RequiredOpt 'identity') }
                    foreach ($n in @('description', 'location', 'displayname', 'managedby')) {
                        if ($opt.ContainsKey($n)) { $p[$n] = if ($opt[$n] -is [bool]) { '' } else { [string]$opt[$n] } }
                    }
                    Write-Result -Cmd $cmdName -Data (Set-AdmComputer @p -Confirm:$confirmPref -WhatIf:$whatIf)
                }
                'computer disable' {
                    Write-Result -Cmd $cmdName -Data (Set-AdmComputerEnabled -Target $target -Identity (Get-RequiredOpt 'identity') `
                        -Enabled $false -Confirm:$confirmPref -WhatIf:$whatIf)
                }
                'computer enable' {
                    Write-Result -Cmd $cmdName -Data (Set-AdmComputerEnabled -Target $target -Identity (Get-RequiredOpt 'identity') `
                        -Enabled $true -Confirm:$confirmPref -WhatIf:$whatIf)
                }

                # --- organizational units ---------------------------------------------------------
                'ou list' {
                    # -Containers also lists CN=Users, CN=Computers and CN=Builtin, which are NOT
                    # organizational units. Without it a stock domain shows a nearly empty tree,
                    # because that is where the default accounts actually live.
                    Write-Result -Cmd $cmdName -Data (Get-AdmOrganizationalUnit -Target $target -Identity $identity `
                        -SearchBase ([string](Opt 'searchbase')) -IncludeProtection:([bool](Opt 'protection')) `
                        -IncludeContainers:([bool](Opt 'containers')) `
                        -Tier $tier -Limit ([int](Opt 'limit' 20000)) -UseDnsLookup:$useDns)
                }
                'ou new' {
                    # -unprotected is the opt-OUT. Protection is on by default because that is
                    # what the Microsoft tooling does and what every estate assumes has happened.
                    Write-Result -Cmd $cmdName -Data (New-AdmOrganizationalUnit -Target $target -Name (Get-RequiredOpt 'name') `
                        -Path ([string](Opt 'path')) -Description ([string](Opt 'description')) `
                        -ProtectFromAccidentalDeletion (-not [bool](Opt 'unprotected')) `
                        -Confirm:$confirmPref -WhatIf:$whatIf)
                }
                'ou remove' {
                    Write-Result -Cmd $cmdName -Data (Remove-AdmOrganizationalUnit -Target $target -Identity (Get-RequiredOpt 'identity') `
                        -Recurse:([bool](Opt 'recurse')) -RemoveProtection:([bool](Opt 'removeprotection')) `
                        -Confirm:$confirmPref -WhatIf:$whatIf)
                }

                # --- any object ---------------------------------------------------------------------
                'object move' {
                    Write-Result -Cmd $cmdName -Data (Move-AdmObject -Target $target -Identity (Get-RequiredOpt 'identity') `
                        -DestinationPath (Get-RequiredOpt 'to') -Class ([string](Opt 'class' 'any')) `
                        -Confirm:$confirmPref -WhatIf:$whatIf)
                }
                'object rename' {
                    Write-Result -Cmd $cmdName -Data (Rename-AdmObject -Target $target -Identity (Get-RequiredOpt 'identity') `
                        -NewName (Get-RequiredOpt 'newname') -Class ([string](Opt 'class' 'any')) `
                        -Confirm:$confirmPref -WhatIf:$whatIf)
                }
                'object remove' {
                    Write-Result -Cmd $cmdName -Data (Remove-AdmObject -Target $target -Identity (Get-RequiredOpt 'identity') `
                        -Class ([string](Opt 'class' 'any')) -RemoveProtection:([bool](Opt 'removeprotection')) `
                        -Confirm:$confirmPref -WhatIf:$whatIf)
                }
                'object protect' {
                    Write-Result -Cmd $cmdName -Data (Set-AdmObjectProtection -Target $target -Identity (Get-RequiredOpt 'identity') `
                        -Protected $true -Confirm:$confirmPref -WhatIf:$whatIf)
                }
                'object unprotect' {
                    Write-Result -Cmd $cmdName -Data (Set-AdmObjectProtection -Target $target -Identity (Get-RequiredOpt 'identity') `
                        -Protected $false -Confirm:$confirmPref -WhatIf:$whatIf)
                }
                'object set' {
                    # -attr name=value, repeatable via a comma-separated list.
                    $raw = Get-RequiredOpt 'attr'
                    $h = @{}
                    foreach ($pair in @([string]$raw -split ',')) {
                        $kv = $pair -split '=', 2
                        if ($kv.Count -eq 2) { $h[$kv[0].Trim()] = $kv[1] } else { $h[$kv[0].Trim()] = '' }
                    }
                    Write-Result -Cmd $cmdName -Data (Set-AdmObjectAttribute -Target $target -Identity (Get-RequiredOpt 'identity') `
                        -Attribute $h -Class ([string](Opt 'class' 'any')) -Confirm:$confirmPref -WhatIf:$whatIf)
                }

                default { Write-Failure -Cmd $cmdName -Code $EXIT_USAGE -Message "Unknown: $Command '$Sub'. Try: adm help" }
            }
        }

        # --- read-only reports over the forest's shape and its secrets ---------------------------
        # --- the recycle bin ----------------------------------------------------------------------
        'deleted' {
            Confirm-Unlocked
            $target = Get-RequiredOpt 'target'
            $tier = [string](Opt 'tier')
            $useDns = [bool](Opt 'usedns')
            switch (($Sub | ForEach-Object { $_.ToLowerInvariant() })) {
                'list' {
                    Write-Result -Cmd $cmdName -Data (Get-AdmDeletedObject -Target $target `
                        -Identity ([string](Opt 'identity')) -Class ([string](Opt 'class' 'any')) `
                        -Limit ([int](Opt 'limit' 200)) -Tier $tier -UseDnsLookup:$useDns)
                }
                'status' { Write-Result -Cmd $cmdName -Data (Test-AdmRecycleBinEnabled -Target $target -Tier $tier -UseDnsLookup:$useDns) }
                'restore' {
                    Write-Result -Cmd $cmdName -Data (Restore-AdmObject -Target $target `
                        -Identity (Get-RequiredOpt 'identity') -DestinationPath ([string](Opt 'to')) `
                        -Class ([string](Opt 'class' 'any')) -AcceptTombstone:([bool](Opt 'accepttombstone')) `
                        -Confirm:$confirmPref -WhatIf:$whatIf)
                }
                default { Write-Failure -Cmd $cmdName -Code $EXIT_USAGE -Message "Unknown: $Command '$Sub'. Try: adm help" }
            }
        }

        { $_ -in @('laps', 'bitlocker', 'trust', 'site', 'subnet', 'gpo', 'pso') } {
            Confirm-Unlocked
            $target = Get-RequiredOpt 'target'
            $tier = [string](Opt 'tier')
            $useDns = [bool](Opt 'usedns')
            switch ("$Command $Sub".ToLowerInvariant()) {
                'laps get' {
                    Write-Result -Cmd $cmdName -Data (Get-AdmLapsPassword -Target $target `
                        -Identity (Get-RequiredOpt 'identity') -Tier $tier -UseDnsLookup:$useDns)
                }
                'bitlocker get' {
                    Write-Result -Cmd $cmdName -Data (Get-AdmBitLockerRecoveryKey -Target $target `
                        -Identity (Get-RequiredOpt 'identity') -KeyId ([string](Opt 'keyid')) `
                        -Tier $tier -UseDnsLookup:$useDns)
                }
                'trust list' { Write-Result -Cmd $cmdName -Data (Get-AdmTrust -Target $target -Tier $tier -UseDnsLookup:$useDns) }
                'site list'   { Write-Result -Cmd $cmdName -Data (Get-AdmSite -Target $target -Tier $tier -UseDnsLookup:$useDns) }
                'subnet list' {
                    $subs = @(Get-AdmSubnet -Target $target -Tier $tier -UseDnsLookup:$useDns)
                    if ([bool](Opt 'orphaned')) { $subs = @($subs | Where-Object { $_.Orphaned }) }
                    Write-Result -Cmd $cmdName -Data $subs
                }
                'gpo list' {
                    $gpos = @(Get-AdmGpo -Target $target -Identity ([string](Opt 'identity')) -Tier $tier -UseDnsLookup:$useDns)
                    if ([bool](Opt 'unlinked')) { $gpos = @($gpos | Where-Object { $_.Unlinked }) }
                    Write-Result -Cmd $cmdName -Data $gpos
                }
                'pso list' {
                    $psos = @(Get-AdmPasswordSettingsPolicy -Target $target -Identity ([string](Opt 'identity')) -Tier $tier -UseDnsLookup:$useDns)
                    if ([bool](Opt 'unlinked')) { $psos = @($psos | Where-Object { $_.Unlinked }) }
                    Write-Result -Cmd $cmdName -Data $psos
                }
                default { Write-Failure -Cmd $cmdName -Code $EXIT_USAGE -Message "Unknown: $Command '$Sub'. Try: adm help" }
            }
        }

        'script' {
            switch (($Sub | ForEach-Object { $_.ToLowerInvariant() })) {
                'check' {
                    $p = Get-RequiredOpt 'path'
                    $f = @(Test-AdmScript -Path $p)
                    if ($AsJson) { Write-Result -Cmd $cmdName -Data $f; exit $EXIT_OK }
                    Show-ScriptFindings -Findings $f -Path $p
                }
                'import' {
                    # No unlock. Importing writes files and reads no credential -- and a
                    # machine-scoped script (a cleanup tool, an inventory sweep) may never touch a
                    # directory at all. Demanding a store passphrase for it is friction with no
                    # security benefit.
                    $p = Get-RequiredOpt 'path'
                    $r = Import-AdmScript -Path $p -Name ([string](Opt 'name')) `
                            -Force:([bool](Opt 'force')) -AnalyzeOnly:([bool](Opt 'analyze')) -Confirm:$false
                    if ($AsJson) { Write-Result -Cmd $cmdName -Data $r; exit $EXIT_OK }
                    Show-ScriptFindings -Findings @($r.Findings) -Path $r.Source
                    Write-Host ''
                    if (@($r.Applied).Count) {
                        Write-Host "  Fixed automatically ($(@($r.Applied).Count)):" -ForegroundColor Green
                        foreach ($a in @($r.Applied)) { Write-Host "    $($a.Id) at line $($a.Line)" -ForegroundColor Green }
                    }
                    if ($r.PSObject.Properties['Skipped'] -and @($r.Skipped).Count) {
                        Write-Host "  Could not auto-fix:" -ForegroundColor Yellow
                        foreach ($s in @($r.Skipped)) { Write-Host "    $($s.Id) at line $($s.Line): $($s.Reason)" -ForegroundColor Yellow }
                    }
                    Write-Host ''
                    Write-Host "  $($r.Detail)" -ForegroundColor $(if ($r.Installed) { 'Cyan' } else { 'Yellow' })
                    if ($r.Installed) {
                        Write-Host "  Your original file was not modified." -ForegroundColor DarkGray
                    }
                    Write-Host ''
                }
                'list' {
                    $s = @(Get-AdmScript -Name ([string](Opt 'name')))
                    if ($AsJson) { Write-Result -Cmd $cmdName -Data $s; exit $EXIT_OK }
                    if (-not $s.Count) { Write-Host 'Nothing imported yet.  adm script import -Path <file>' -ForegroundColor DarkGray; exit $EXIT_OK }
                    $s | Select-Object Name, Imported, Errors, Warnings, AutoFixed, SourceState |
                        Format-Table -AutoSize | Out-String -Width 160 | Write-Host
                    if (@($s | Where-Object { $_.SourceState -eq 'SOURCE CHANGED' }).Count) {
                        Write-Host '  A source file has changed since it was imported. Re-import it: adm script import -Path <file> -Force' -ForegroundColor Yellow
                    }
                }
                'run' {
                    # Only unlock when a -Target was given: that is the only case that needs a
                    # credential resolved out of the store.
                    if (Opt 'target') { Confirm-Unlocked }
                    Write-Result -Cmd $cmdName -Data (Invoke-AdmScript -Name (Get-RequiredOpt 'name') `
                        -Target ([string](Opt 'target')) -Tier ([string](Opt 'tier')) -Confirm:$false -WhatIf:$whatIf)
                }
                'remove' { Write-Result -Cmd $cmdName -Data (Remove-AdmScript -Name (Get-RequiredOpt 'name') -Confirm:$confirmPref) }
                default  { Write-Failure -Cmd $cmdName -Code $EXIT_USAGE -Message "Unknown: script '$Sub'. Try: adm help" }
            }
        }

        'scan' {
            Confirm-Unlocked
            $findings = @(Invoke-AdmScan -Domain ([string](Opt 'domain')) -Scope ([string](Opt 'scope' 'all')))
            if ($AsJson) { Write-Result -Cmd $cmdName -Data $findings; exit $EXIT_OK }

            $bad = @($findings | Where-Object { $_.Status -in @('fail', 'warn', 'unknown') })
            Write-Host ''
            foreach ($f in $findings) {
                $mark, $col = switch ($f.Status) {
                    'pass'    { ' OK ', 'Green' }
                    'warn'    { 'WARN', 'Yellow' }
                    'fail'    { 'FAIL', 'Red' }
                    default   { ' ?  ', 'DarkGray' }
                }
                Write-Host ("  [{0}]  {1,-13} {2,-52} {3}" -f $mark, $f.Target, $f.Name, $f.Detail) -ForegroundColor $col
            }
            Write-Host ''
            Write-Host ("  {0} checked -- {1} ok, {2} warning, {3} failed, {4} could not be checked" -f
                        $findings.Count,
                        @($findings | Where-Object { $_.Status -eq 'pass' }).Count,
                        @($findings | Where-Object { $_.Status -eq 'warn' }).Count,
                        @($findings | Where-Object { $_.Status -eq 'fail' }).Count,
                        @($findings | Where-Object { $_.Status -eq 'unknown' }).Count) -ForegroundColor DarkGray

            foreach ($f in $bad) {
                Write-Host ''
                Write-Host "  $($f.Id)  $($f.Name)  ($($f.Target))" -ForegroundColor $(if ($f.Status -eq 'fail') { 'Red' } else { 'Yellow' })
                if ($f.Problem) { foreach ($l in (Format-Wrapped "PROBLEM  $($f.Problem)" 74)) { Write-Host "    $l" } }
                if ($f.Impact)  { foreach ($l in (Format-Wrapped "IMPACT   $($f.Impact)"  74)) { Write-Host "    $l" -ForegroundColor Gray } }
                if ($f.CanFix) {
                    foreach ($l in (Format-Wrapped "THE FIX  $($f.FixDescription)" 74)) { Write-Host "    $l" -ForegroundColor Green }
                    Write-Host "    CHANGES  $($f.Changes)$(if ($f.NeedsAdmin) { ' (needs administrator)' })" -ForegroundColor DarkGray
                } else {
                    Write-Host "    FIX      no automatic fix -- this one needs a person to decide" -ForegroundColor DarkGray
                }
            }
            $fixable = @($bad | Where-Object { $_.CanFix }).Count
            Write-Host ''
            if ($fixable) { Write-Host "  $fixable of these can be fixed for you:  adm fix" -ForegroundColor Cyan }
            Write-Host ''
        }

        'fix' {
            Confirm-Unlocked
            $findings = @(Invoke-AdmScan -Domain ([string](Opt 'domain')) -Scope ([string](Opt 'scope' 'all')) -Problems)
            $fixable = @($findings | Where-Object { $_.CanFix })
            if (-not $fixable.Count) {
                Write-Result -Cmd $cmdName -Data @() -Note 'Nothing found that can be fixed automatically. Run: adm scan'
                exit $EXIT_OK
            }
            # -Yes is implied by -NonInteractive: a script cannot answer a prompt, and a fix that
            # silently waits forever is worse than one that is refused.
            $res = $fixable | Invoke-AdmRepair -Yes:([bool]((Opt 'yes') -or $NonInteractive)) `
                        -AllowMachineChanges:([bool](Opt 'allowmachinechanges')) -WhatIf:$whatIf
            Write-Result -Cmd $cmdName -Data @($res)
            if (@($res | Where-Object { $_.Outcome -eq 'skipped' }).Count -and -not $AsJson) {
                Write-Host 'Some fixes change this computer rather than just the toolkit. Re-run with -AllowMachineChanges to permit those.' -ForegroundColor DarkGray
            }
        }

        'catalog' {
            $rows = @(Get-AdmErrorCatalog -Code ([string](Opt 'code')) -Severity ([string](Opt 'severity' 'all')))
            if (Opt 'markdown') {
                $md = Get-AdmErrorCatalog -AsMarkdown
                if (Opt 'path') {
                    # UTF-8 without a BOM: a BOM at the top of a markdown file shows up as a
                    # stray character in every renderer that does not strip it.
                    [System.IO.File]::WriteAllText([string](Opt 'path'), $md, (New-Object System.Text.UTF8Encoding($false)))
                    Write-Result -Cmd $cmdName -Data ([pscustomobject]@{ Path = (Opt 'path'); Entries = $rows.Count })
                }
                else { $md }
            }
            elseif ($AsJson) { Write-Result -Cmd $cmdName -Data $rows }
            elseif (Opt 'code') {
                foreach ($r in $rows) {
                    Write-Host ''
                    Write-Host "  $($r.Code)   [$($r.Severity)]" -ForegroundColor Cyan
                    Write-Host "  $($r.Title)" -ForegroundColor White
                    Write-Host ''
                    foreach ($l in (Format-Wrapped $r.Why 74)) { Write-Host "    $l" -ForegroundColor Gray }
                    Write-Host ''
                    Write-Host '  What to try' -ForegroundColor DarkGray
                    $i = 1; foreach ($f in @($r.Fix)) {
                        foreach ($l in (Format-Wrapped "$i. $f" 72)) { Write-Host "    $l" }
                        $i++
                    }
                    Write-Host ''
                    Write-Host "  fires when: $($r.Signature)" -ForegroundColor DarkGray
                }
                Write-Host ''
            }
            else {
                $rows | Select-Object Code, Category, Severity, Title | Format-Table -AutoSize | Out-String -Width 160 | Write-Host
                Write-Host "  $($rows.Count) recognised failures. Detail on one:  adm catalog -Code <code>" -ForegroundColor DarkGray
            }
        }

        'log' {
            switch (($Sub | ForEach-Object { $_.ToLowerInvariant() })) {
                'list' {
                    $days = [int](Opt 'days' 7)
                    $entries = if (Opt 'problems') { Get-AdmLog -Days $days -Problems -Last ([int](Opt 'last' 50)) }
                               else { Get-AdmLog -Days $days -Last ([int](Opt 'last' 50)) }
                    if ($AsJson) { Write-Result -Cmd $cmdName -Data @($entries) }
                    else {
                        if (-not @($entries).Count) { Write-Host 'Nothing logged in this period.' -ForegroundColor DarkGray }
                        foreach ($e in $entries) {
                            $c = switch ($e.severity) { 'error' { 'Red' } 'warn' { 'Yellow' } default { 'DarkGray' } }
                            Write-Host ("{0}  {1,-5}  {2}" -f $e.tsLocal, $e.severity.ToUpperInvariant(),
                                        $(if ($e.title) { $e.title } else { $e.message })) -ForegroundColor $c
                            if ($e.operation) { Write-Host ("{0}while: {1}" -f (' ' * 28), $e.operation) -ForegroundColor DarkGray }
                        }
                        Write-Host ''
                        Write-Host 'Full detail on one entry:  adm log show -Last 1' -ForegroundColor DarkGray
                    }
                }
                'show' {
                    $n = [int](Opt 'last' 1)
                    $entries = @(Get-AdmLog -Days ([int](Opt 'days' 7)) -Last $n)
                    if ($AsJson) { Write-Result -Cmd $cmdName -Data $entries }
                    else {
                        foreach ($e in $entries) {
                            Write-Host ''
                            Write-Host "  $($e.tsLocal)  [$($e.severity)]" -ForegroundColor Cyan
                            if ($e.title)     { Write-Host "  What happened : $($e.title)" }
                            if ($e.message)   { Write-Host "  Message       : $($e.message)" -ForegroundColor Gray }
                            if ($e.operation) { Write-Host "  While doing   : $($e.operation)" -ForegroundColor Gray }
                            if ($e.target)    { Write-Host "  Target        : $($e.target)" -ForegroundColor Gray }
                            if ($e.why) {
                                Write-Host "  Why           :"
                                foreach ($l in (Format-Wrapped $e.why 62)) { Write-Host "     $l" -ForegroundColor Gray }
                            }
                            if (@($e.fix).Count) {
                                Write-Host "  What to try   :"
                                $i = 1; foreach ($f in @($e.fix)) {
                                    foreach ($l in (Format-Wrapped "$i. $f" 62)) { Write-Host "     $l" -ForegroundColor White }
                                    $i++
                                }
                            }
                            if ($e.technical -and $e.technical.Codes) {
                                Write-Host "  Technical     : $($e.technical.Codes)" -ForegroundColor DarkGray
                            }
                        }
                        Write-Host ''
                    }
                }
                'windows' {
                    $ev = Get-AdmWindowsEvent -Level ([string](Opt 'level' 'error')) `
                            -SinceHours ([int](Opt 'hours' 168)) -MaxEvents ([int](Opt 'last' 50))
                    Write-Result -Cmd $cmdName -Data @($ev | Select-Object tsLocal, severity, source, code, message) `
                                 -Note "$(@($ev).Count) Windows event(s) -- these are the OS's own errors, not the toolkit's"
                }
                'export' {
                    $p = Get-RequiredOpt 'path'
                    Write-Result -Cmd $cmdName -Data (Export-AdmLog -Path $p -Days ([int](Opt 'days' 7)) `
                                    -ProblemsOnly:([bool](Opt 'problems'))) -Note "Written to $p"
                }
                'info'  { Write-Result -Cmd $cmdName -Data (Get-AdmLogInfo) }
                'clear' { Write-Result -Cmd $cmdName -Data (Clear-AdmLog -All:([bool](Opt 'all')) -Confirm:$confirmPref) }
                default { Write-Failure -Cmd $cmdName -Code $EXIT_USAGE -Message "Unknown: log '$Sub'. Try: adm help" }
            }
        }

        'shell' { & (Join-Path $PSScriptRoot 'tools\Start-AdmShell.ps1') -ModuleRoot $PSScriptRoot; exit $EXIT_OK }
        'gui'   { & (Join-Path $PSScriptRoot 'gui\Start-AdmGui.ps1') -ModuleRoot $PSScriptRoot; exit $EXIT_OK }

        default { Write-Failure -Cmd $cmdName -Code $EXIT_USAGE -Message "Unknown command '$Command'. Try: adm help" }
    }
    exit $EXIT_OK
} catch {
    # Invoke-AdmGuarded attaches the diagnosis to the exception, so the CLI renders the same
    # explanation the GUI and the log show, without re-deriving it here. If it is absent (a
    # failure that never reached the module) diagnose it now rather than printing a bare string.
    $diag = $_.Exception.Data['AdmDiagnosis']
    if (-not $diag) {
        try { $diag = & (Get-Module ADAdmin) { param($e, $c) Resolve-AdmDiagnosis -ErrorObject $e -Operation $c } $_ $cmdName } catch { }
    }
    Write-Failure -Cmd $cmdName -Code (Get-ExitCodeFor -Message $_.Exception.Message) `
                  -Message $_.Exception.Message -Diagnosis $diag
}
