# Bringing existing scripts in

You have a folder of admin scripts that work. `adm script import` gives them the toolkit's
plumbing — multi-forest targeting, the error catalog, the 7-day log, `-WhatIf` — **without
rewriting their logic**, and tells you plainly what it could not fix for you.

```powershell
adm script check  -Path .\Unlock-StaleUsers.ps1     # what would change, and why
adm script import -Path .\Unlock-StaleUsers.ps1     # convert and install
adm script list                                      # what is installed
adm script run    -Name Unlock-StaleUsers -Target corp.example.com
```

## Your original file is never modified

An import writes three new files and touches nothing else:

| file | what it is |
|---|---|
| `<Name>.body.ps1` | your script, with the mechanical fixes applied and a header saying where it came from |
| `<Name>.ps1` | a generated wrapper — `-Target`, the guard, the log, `-WhatIf` |
| `<Name>.json` | the source path, its SHA-256 at import time, every finding, every fix applied |

They live beside the credential store (or `ADADMIN_SCRIPT_DIR`), so a USB stick carries its
imported scripts with its credentials.

**Edit the source and import again.** `adm script list` compares the source's hash against the
one recorded at import and reports `SOURCE CHANGED` when they differ — an imported copy silently
older than its source is the same class of problem as a stale mirror.

## Wrap, don't rewrite

The imported logic is **called**, not spliced. A tool that merges its own `param()` block into
yours eventually mangles a working script, and PowerShell allows exactly one param block, at the
top. Keeping the body whole means the import is reviewable as a diff against its source and
reversible by deleting three files.

What the wrapper adds, without any edit to your logic:

- **`-Target`** — the domain is resolved through the credential store and exposed to your script
  as `$AdmDomain`, `$AdmCredential`, `$AdmTarget`. No hard-coded server, no credential picking.
- **The guard** — anything your script throws is diagnosed in plain English, written to the log,
  and re-raised with the explanation attached.
- **`-WhatIf`** at the outer level, and start/finish audit entries.

## The analysis is AST-based, not textual

A script is code. `Write-Host` inside a string literal is not a call; a `catch {}` spanning three
lines is still empty; an alias only counts where a command name is expected. Regex gets all three
wrong, and a rewriter that is wrong is worse than none.

## What it fixes, and what it only reports

**Applied automatically** — mechanical and provably safe:

| | |
|---|---|
| `IMP-001` | adds `[CmdletBinding()]` |
| `IMP-002` | fills an empty `catch {}` with a logging call |
| `IMP-003` | expands aliases (`gci`, `?`, `%`) to real command names |
| `IMP-004` | replaces `Split-Path -LiteralPath -Parent`, which **fails on PowerShell 5.1** |

**Reported for a human** — because fixing them means a judgement about what the script is *for*:

| | |
|---|---|
| `IMP-005` | a password or secret written literally in the file |
| `IMP-006` | it makes changes but has no `-WhatIf` |
| `IMP-007` | a hard-coded domain, LDAP path or IP |
| `IMP-008` | depends on RSAT, which a target PC usually lacks |
| `IMP-009` | throws bare strings nothing can recognise |
| `IMP-010` | `Write-Host` used for results, so nothing can capture them |
| `IMP-011` | no strict mode — see below |
| `IMP-012` | `$PSScriptRoot` in a `param()` default — **empty during binding on 5.1** |

Every finding says what is wrong, what it will break, and what to do — the same shape as
`adm scan`.

**`IMP-011` is reported, never applied.** Turning on strict mode CHANGES RUNTIME BEHAVIOUR,
so it is not a mechanical edit. Measured on a real cleanup script that walks the uninstall
registry with `Where-Object { $_.DisplayName }`: most registry keys have no `DisplayName`, and
silently adding strict mode would have made a working script start erroring on every one. The
advice is still right; applying it is the author’s call, not the importer’s.

**`IMP-005` deserves its own note.** Removing a secret from a file does not un-expose it. It is
in every backup, every copy of the share, and the version history. **Rotate it.**

## Guarantees, and what is tested

- The original file is byte-identical afterwards — asserted by hash.
- **The converted body still parses** — asserted with the PowerShell parser. A rewriter that
  produces something that will not run is the one failure mode that matters most.
- The rewrite preserves the original logic — asserted by checking the body still contains it.
- A script that does not parse is **refused**, not half-imported.
- Edits are applied **back to front** by character offset. Editing forwards invalidates every
  later offset the AST gave us, and the corruption is silent — the file still parses, just not
  as the same program.
- One transform that cannot be built is reported as "could not auto-fix" and does not abandon
  the others, or the import.

## After importing

Work through the reported findings in the source, then re-import. The two you should not leave:

1. **`IMP-005`** — rotate the credential and take it from the store instead.
2. **`IMP-007`** — replace the hard-coded domain with `-Target`. Across untrusted forests, a
   script aimed at the wrong domain is worse than one that fails.
