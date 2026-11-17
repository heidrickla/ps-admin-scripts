# PowerShell 5.1 traps — symptom lookup

**Every one of these was a real bug in this repo on 2026-08-26**, found by running the suites
under Windows PowerShell 5.1. **Four of the five are accepted by PowerShell 7 and fail only on
5.1** — so testing on 7 alone tests a laxer world than the one the toolkit ships into. The
target is whatever Windows is in front of you, which means 5.1 is the floor, not the fallback.

Run both: `tests\Invoke-AdmTests.ps1 -On both`.

## `A positional parameter cannot be found that accepts argument '<x>'` — on a function you wrote

A parameter named **`-Iv`** collides with the `iv` **alias of `-InformationVariable`**, which
PowerShell adds automatically to every *advanced* function. A function is advanced if it has
`[CmdletBinding()]` **or any `[Parameter()]` attribute** — so `Get-AdmMac` was advanced without
declaring `[CmdletBinding()]`, and the error surfaced at its *caller*, naming the wrong function.

Renamed to `-InitVector`. Watch for the other common-parameter aliases too: `ov`, `ev`, `vb`,
`db`, `ea`, `wa`, `wv`, `cf`.

## `Parameter set cannot be resolved using the specified named parameters` — from `Split-Path`

**`Split-Path -LiteralPath <p> -Parent` is not a valid combination under 5.1.** The two live in
different parameter sets. PowerShell 7 accepts it, so this is invisible if you only test there.

Use `[System.IO.Path]::GetDirectoryName($Path)` — no parameter sets, and it is the right call for
a literal filesystem path anyway.

## `The property 'Name' cannot be found on this object` — from an empty collection

Member enumeration over an **empty** collection throws under `Set-StrictMode -Version 2.0`:

```powershell
$obj.PSObject.Properties.Name          # throws when there are no properties
@($obj.PSObject.Properties | ForEach-Object { $_.Name })   # fine
```

It bit twice, and the second was on an **error path** — the code building the message for
"this domain has no such credential tier" threw while doing so, hiding the real fault. A
diagnostic that fails while reporting a failure is worse than no diagnostic.

## `The property 'Count' cannot be found on this object` — returning a collection from a function

Three ways to get this wrong, and this repo hit two of them in a row:

| you write | caller gets | then |
|---|---|---|
| `return @()` | `$null` (the array unrolls to nothing) | `$null.Count` throws under strict mode |
| `return ,@()` | a **1-element array containing** the empty array | `.Count` is 1, and `[0]` has no properties |
| `Write-Output -NoEnumerate $a` **plus** `@(...)` at the call site | array nested one level deep | same as above |

**FIVE times now, in five disguises** — the fifth in a test helper written *after* this page
already said not to, which is the strongest argument for the blunt rule below. Its symptom there:
`@(f).Count` returned **1 for an empty result**, so three tests asserting "finds nothing" failed
while the code under test was correct.

The fourth was the
worst: a private function returned `,@($findings)` into an `[object[]]` **parameter**, which bound
as one element containing the array — so `foreach ($f in $Findings)` iterated **once, over the
whole collection**. Every transform was skipped with a single baffling "property Extent not found"
against a concatenation of every finding id.

**The rule that would have prevented all four: just emit the collection.** Reach for
`-NoEnumerate` only when a caller assigns the result directly AND must keep an empty array's
`.Count`, and then never wrap that call site in `@()`.

**The three wrong forms:**

- **A PRIVATE function that must preserve an empty array**: `Write-Output -NoEnumerate $array`,
  and do **not** wrap the call site in `@()` — that re-nests it.
- **A PUBLIC cmdlet**: just emit the collection normally and let it enumerate. Callers write
  `@(Get-Thing).Count` and it is correct. `,@($rows)` as a return makes that count `1`, which is
  how `Get-AdmErrorCatalog` briefly reported one empty row instead of 27 entries.

**The second form is the dangerous one.** `Count` was 1, so the "exactly one match" branch ran
and reported a missing `.Domain` — a *resolution* function answering a *property* error, for a
target that simply had no match. The refusal the operator needed never appeared.

## `@($x) | Where-Object` then `.Count` — the wrap must cover the whole pipeline

```powershell
$dcs = @($d.DomainControllers) | Where-Object { $_ }    # WRONG -- scalar when one matches
$dcs = @(@($d.DomainControllers) | Where-Object { $_ }) # right
```

`@()` binds tighter than the pipe, so it wraps the *input* and the pipeline unwraps it again.
A single match comes back as a scalar and `.Count` throws under strict mode — which turned a
health check into "unknown" against a perfectly well-configured domain.

## A function's output IS its return value — including your narration

```powershell
function Try-Mode { "checking..."; $result }   # returns TWO things
$ok = Try-Mode                                  # $ok is an array, always truthy
```

Every uncaptured string becomes part of the return value. A diagnostic script's whole report
vanished into `$ok` this way, and the boolean it was supposed to yield was silently an array.
Narrate with `Write-Host`; return with the pipeline.

## `R` is a built-in alias for `Invoke-History`

Naming a helper `R` in a test harness produced
`Cannot convert 'System.Object[]' to the type 'System.String' required by parameter 'Id'` —
an error about a cmdlet nobody called. Check `Get-Alias` before taking a one-letter name.

## `Cannot bind argument to parameter 'Path' because it is an empty string` — at a `param()` default

**`$PSScriptRoot` is EMPTY while param defaults are being bound** under 5.1 with `-File`. So:

```powershell
param([string]$ModuleRoot = (Split-Path -Parent $PSScriptRoot))   # fails, window never opens
```

Resolve it in the body instead:

```powershell
param([string]$ModuleRoot)
if (-not $ModuleRoot) { $ModuleRoot = Split-Path -Parent $PSScriptRoot }
```

**This one had no visible symptom.** The GUI process started, printed to a console nobody was
reading, and exited — so it looked like a window that "didn't open" rather than a script that
errored. Launching a UI detached hides its stderr; run it in the foreground once when it
misbehaves.

## `The property 'X' cannot be found on this object` — inside a `Where-Object`, from a `switch`

```powershell
$rows | Where-Object {
    switch ($By) {
        'PasswordLastSet' { $_.PasswordAgeDays -ge $threshold }   # <-- throws
    }
}
```

`switch ($By)` **rebinds `$_` to its own input**. Inside those branches `$_` is the string
`'PasswordLastSet'`, not the pipeline row, so `$_.PasswordAgeDays` is looked up on a `String` and
`Set-StrictMode` takes the whole pipeline down. A nested `ForEach-Object` or `Where-Object` does
the same thing.

Capture the row before anything that can rebind it:

```powershell
$rows | Where-Object {
    $row = $_
    switch ($By) { 'PasswordLastSet' { $row.PasswordAgeDays -ge $threshold } }
}
```

The silent variant of this bug is worse: counting severities with
`$sorted | Where-Object { $_.Severity -eq $_ }` inside a `ForEach-Object` compares each finding
against *itself*, produces plausible-looking numbers, and never errors.

## `$script:x++` from a nested function, where `$x` was assigned in a scriptblock

```powershell
Check 'a cycle terminates' {
    $visited = 0
    function Walk($n) { ...; $script:visited++ }     # <-- "cannot be retrieved because it has not been set"
    Walk 'A'; $visited -eq 3
}
```

`$visited` is local to the scriptblock; `$script:visited` names a *script-scope* variable that was
never created. Use a hashtable instead — it is mutated by reference, so the count survives the
scope hop:

```powershell
$state = @{ Visited = 0 }
function Walk($n) { ...; $state.Visited++ }
```

## `$LASTEXITCODE` is sticky, and `try/catch` does not see a child's `exit`

Calling a script with `&` runs it in its own scope, so its `exit 30` ends the child and returns to
the caller — it raises **nothing**, and a `try/catch` around it catches **nothing**.

This matters wherever the child *diagnoses* its own failures rather than throwing, which every
script in `scripts/` deliberately does. `Invoke-AdmSweep` reported two unreachable forests as
`ok` for exactly this reason: they exited 30, no exception surfaced, and a dead domain was
indistinguishable from a healthy one that found nothing.

Read the exit code, and **reset it first** — a script that returns without calling `exit` leaves
the *previous* script's value in place:

```powershell
$global:LASTEXITCODE = 0
$result = & $path @splat
$code = $LASTEXITCODE          # house contract: 0 = clean, 10 = found something, else FAILED
```

## `Set-Content -Encoding UTF8` writes a BOM on 5.1

It emits `EF BB BF`; PowerShell 7's `-Encoding utf8` does not. Regenerating a checked-in file with
it produces a one-byte diff on line 1 that no reviewer expects. Use
`[System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))`,
which is what `Get-AdmUtf8Encoding` exists for.

## `[string]` on a number that came from a HEX literal gives you the literal text

```powershell
function A { [CmdletBinding()] param($Value) "$($Value.GetType().Name)  [string]=$([string]$Value)" }
A -Value 0x200      # Int32  [string]=0x200      <-- not "512"
A -Value 512        # Int32  [string]=512
```

The value really is an `Int32`, and `-eq 512` is true — but PowerShell remembers the **original
token text** of a numeric literal and returns it on string conversion. So the standard idiom

```powershell
[void][int]::TryParse([string]$Value, [ref]$n)      # $n = 0 for a hex argument
```

silently yields **zero**, because `[int]::TryParse` does not accept `"0x200"`. `TryParse` returns
`$false` and the code carries on with whatever `$n` was initialised to.

The damage is silent and shaped like a logic bug: a bit decoder fed `0x200` reported **no flags at
all** rather than erroring, so a `userAccountControl` with several bits set came back empty. It
survived because the directory only ever supplies decimal strings — the hex form appeared first in
a test, and the test looked wrong before the code did.

Convert with PowerShell's own cast instead, which handles every shape that actually turns up — an
`Int32`, the decimal string an LDAP read returns, and a hex literal:

```powershell
function ConvertTo-AdmInt64 {
    param($Value)
    if ($null -eq $Value)   { return 0L }
    if ($Value -is [int64]) { return $Value }
    if ($Value -is [int])   { return [int64]$Value }
    try { [int64]$Value } catch { 0L }
}
```

> Same family as the `switch` and `$_` traps: the failure is not an error, it is a wrong answer
> that looks like a right one.

## A non-ASCII character in a displayed string comes out as mojibake on 5.1

The scripts in this repo are UTF-8 **without a BOM**. Windows PowerShell 5.1 reads a BOM-less
script file as the system **ANSI codepage**, not as UTF-8 — so a `·` in a string literal reaches
the screen as `A·`, and any other non-ASCII character is mangled the same way. PowerShell 7 reads
it as UTF-8 and shows it correctly, so this looks fine right up until someone runs it on 5.1.

It does **not** matter in comments, which is why the `` marks throughout this codebase are
harmless — they are never rendered. The rule is narrow and worth keeping narrow:

> **ASCII only in string literals that a user will see.** Anything in a comment can be whatever
> reads best.

Adding a BOM would also fix it, but every generated file here is deliberately written without one
(`Get-AdmUtf8Encoding`), because a BOM mid-file breaks the line-by-line JSONL log parse.

## Also true here, not yet a bug

- **`Set-StrictMode -Version 2.0` errors on a never-assigned variable**, so every module-scope
  slot is declared before first read.
- **`.Count` on a single object** is unreliable across versions — wrap with `@()` when you mean
  "how many results", which is the *opposite* of the function-return rule above. The difference:
  `@()` around a *pipeline of items* counts them; `@()` around *one emitted array* nests it.
- **`AesGcm` is .NET Core only** — absent on 5.1, which is why the store uses AES-CBC + HMAC.
- **WPF needs STA.** 5.1 is STA; `pwsh` 7 is MTA, so the GUI re-launches itself with `-STA`.
