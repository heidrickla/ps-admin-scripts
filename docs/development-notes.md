# Development notes

Build steps, measured constraints and design rules for working on ADAdmin. Failure-specific detail lives in the other documents in this directory: [active-directory-traps.md](active-directory-traps.md) for directory behavior, [powershell-51-traps.md](powershell-51-traps.md) for language traps, [object-lifecycle.md](object-lifecycle.md) for the write paths, [gui-conventions.md](gui-conventions.md) for the interface rules.

## Layout

| Path | Contents |
|---|---|
| `ADAdmin/` | the module: `Public/` cmdlets, `Private/` helpers, `Fixtures/` mock directory |
| `adm.ps1` | the command-line front end |
| `gui/` | the WPF window |
| `scripts/` | stand-alone administration scripts written against the module |
| `tools/` | packaging and shell helpers |
| `tests/` | offline suites; `tests/live/` holds the suites that need a real directory |
| `docs/` | documentation |

## Running the tests

```powershell
tests\Invoke-AdmTests.ps1 -On both
```

The runner enumerates `tests\*.Tests.ps1`, so a new suite is picked up without editing the runner, and it refuses to report if it finds fewer than ten suites. Suites are plain scripts rather than Pester, so they run on a machine with nothing installed. Run them on Windows PowerShell 5.1 as well as PowerShell 7: several faults are accepted by 7 and fail on 5.1.

Offline runs use the mock provider (`ADADMIN_PROVIDER=mock`), which reads `ADAdmin/Fixtures/mock-directory.json`.

## Environment variables

| Variable | Effect |
|---|---|
| `ADADMIN_STORE` | path of the encrypted credential store |
| `ADADMIN_LOG_DIR` | directory for the 7-day log |
| `ADADMIN_SCRIPT_DIR` | directory for imported scripts |
| `ADADMIN_PROVIDER` | `adsi` (default) or `mock` |
| `ADADMIN_PASSPHRASE` | store passphrase for non-interactive runs |
| `ADADMIN_MOCK_DATA` | alternative mock directory file |

The store, the log directory and the imported-script directory are runtime artifacts and are listed in `.gitignore`.

## Adding a failure mode

A new recognized failure goes into the catalog (`ADAdmin/Private/Diagnostics.ps1`) or into a scan check (`ADAdmin/Private/Checks.ps1`), never into a bare `throw` at a call site. Then regenerate the catalog document:

```powershell
adm catalog -Markdown -Path docs\error-catalog.md
```

`tests\Scan.Tests.ps1` fails when `docs/error-catalog.md` differs from the code.

## Design rules

- A check never reports a pass because it could not look. `unknown` is a separate result and is tested for.
- A negative result states what it tested. A failed probe bounds the transport that was used, not the capability. Two probes over the same transport agreeing proves nothing.
- A claim names the identity and host it was measured from.
- A count written into prose is a fact with an expiry date. Name where it is enumerated.
- A check that normalizes its input cannot detect a normalization fault.
- Guards enumerate what exists, and a guard needs a control that cannot legitimately be empty, because an enumeration can succeed at scanning nothing and report a pass. The test runner and the GUI accessibility suite both enumerate rather than hand-list.
- Rules are allow-lists of what promises a behavior (the verbs that promise not to return a value), not deny-lists of what may.
- A caveat the caller cannot receive is not a caveat. `Write-Warning` and `Write-Host` are invisible to a caller reading stdout, so the `-Json` envelope carries `truncated`.
- A fault injected to prove a check must be shown to execute. Appending a `throw` after a suite's own `exit 0` proves nothing.
- Run a negative control in a throwaway clone, never in the working tree.
- Ask "what does nothing ever run?" Bare `adm` and every `adm <group>` with a missing or mistyped verb had no test until this question was asked, and four defects were found that reading the code did not show.

## Measured behavior worth keeping in view

- A search stops silently at its size limit. `$rows.Count -ge $limit` cannot distinguish "exactly the limit exist" from "stopped at the limit", so every search over-fetches one row (`Get-AdmOverfetchLimit`). The truncation flag is sticky across the several searches one cmdlet makes (`Reset-AdmSearchTruncated`, `Get-AdmSearchTruncated`). A size limit of 0 means the server limit and cannot be detected.
- Two different limits share one flag: `SizeLimit` caps rows, and the range limit caps values within one row. A multi-valued attribute past about 1500 values returns nothing, not a truncated list. `Get-AdmRangedAttribute` walks the windows, and `Get-AdmRangedProp` returns the first window plus a `Truncated` indicator.
- A test that forces truncation counts first and derives its limit from the count. `-Limit 1` only truncates a read of two or more objects. Where truncation cannot be forced, the live suite prints `SKIP` and says so.
- An audit is the worst case for truncation, because the finding is the absence of something. An object never examined contributes no finding, so a cut sweep reads as clean. Audits record unchecked coverage instead, and `Find-AdDuplicates` exits `30` when its coverage is incomplete.
- A name-only search of the domain naming context also matches AD-integrated DNS nodes. Constrain every such search with `objectClass`.
- A bit table indexed by an integer in an `[ordered]` hashtable does a positional lookup. Use parallel arrays or an array of hashtables.
- Passing a hex literal such as `0x200` through `[string]` returns the literal text, and `[int]::TryParse` then fails. Cast `[int64]` instead (`ConvertTo-AdmInt64`, `ConvertTo-AdmFlagInt`).
- A forest that did not answer is `FAILED`, never clean. A child script that diagnoses instead of throwing defeats `try/catch`, so callers read `$LASTEXITCODE` (0 clean, 10 findings, anything else failed) and reset it first.
- `-Json` combined with `-WhatIf` writes PowerShell's `What if:` narration to stdout before the envelope. The contract is that the envelope is the last line.

## Test authoring

- A fixture cannot teach what a real directory does: a real directory omits unset attributes, and a fixture written with every field present hides that.
- A test that passes a real `byte[]` cannot catch the SID bug, because directory searches return `Object[]` of `Byte`.
- The live suites are separate from the offline runner on purpose. `tests/live/Invoke-AdmLiveTests.ps1` is read-only by construction and can be pointed at any forest. `tests/live/Verify-AdmWritePaths.ps1` creates and removes a throwaway OU, is marked `export-ignore` in `.gitattributes`, and does not ship in the package.
- Do not create objects to turn a skipped check green. A tick bought that way proves nothing about a real forest.

## Graphical interface

Every control needs `AutomationProperties.Name`. A glyph button and every input are otherwise anonymous to UI Automation, so no automated GUI test can target them. `tests\GuiAccessibility.Tests.ps1` enumerates the XAML controls and fails on an unnamed one.

## Scripts: behavior that is decided

- Stale-computer sweeps judge on `pwdLastSet`, not `lastLogonTimestamp`, because a live member rotates its machine password every 30 days. Domain controllers (`userAccountControl` flag `0x2000`) are excluded, and `Set-AdmComputerEnabled` refuses to disable one. Sweeps disable and never delete.
- `Get-AdPrivilegedAccess` is read-only with no fix mode. It groups by RID rather than name (names are localized), counts nesting only through non-Tier-0 groups, and catches `primaryGroupID=512`, which is invisible to the `member` attribute. It does not read ACLs, so DCSync-style delegation is covered by `Get-AdDelegation`.
- A domain controller enforces SPN uniqueness at write time, so a clean duplicate-SPN scan is expected. Duplicates occur across domains, which is why `Invoke-AdmSweep -CrossDomain` exists.
- A duplicate machine SID does not break domain membership, because the computer account SID is separate. A duplicate `SusClientId` is what makes cloned machines disappear from WSUS, and it is repairable.
- Removing an administrator from the store is not retroactive revocation. Rotate the directory credentials that administrator could read.
- LAPS: an expiration time that is readable with the password absent means no permission, not "not set". `Get-AdmLapsPassword` returns `Available`, `NoPermission`, `Encrypted`, `NotManaged` or `NotDeployed`.
- A new OU is protected from accidental deletion by default, and `Remove-AdmGroup` refuses a group with a RID below 1000.

## UAC baseline profile

`scripts/Set-UacGoldenPolicy.ps1` applies or reports a baseline under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`.

| Value | Baseline | Windows default |
|---|---|---|
| `EnableLUA` | `1` | `1` |
| `ConsentPromptBehaviorAdmin` | `0` | `5` |
| `ConsentPromptBehaviorUser` | `0` | `3` |
| `PromptOnSecureDesktop` | `0` | `1` |

The combination is UAC on with no prompt: the filtered-token model stays in force and an administrator is elevated silently. `EnableLUA` does not take effect until a reboot, so reading it back immediately reports the registry, not the running behavior. `LocalAccountTokenFilterPolicy` is deliberately not set by the script.

## Shell habits

- Backticks inside a double-quoted shell string are command substitution. The command still exits 0, so a green exit proves nothing about the text. Write file content with an editor, or single-quote the payload.
- `Path.write_text` on Windows writes `\r\n`, and `subprocess(..., text=True)` rewrites `\n` to `\r\n`. A remote `sh` then fails on every line. Feed remote scripts as bytes.
- A UTF-8 byte order mark or a trailing CR in a stored secret authenticates as a wrong password and every symptom points at the wrong layer. Write secret values without a BOM and without CRLF.
- `cd X && a && b` anchors only `a` to `X`. Pass the target as an argument for anything that reports state.
- PowerShell variables are case-insensitive, `-notlike` treats its argument as a wildcard, and every non-empty string is `$true`, including the string `"false"`.
