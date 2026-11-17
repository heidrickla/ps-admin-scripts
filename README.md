# ps-admin-scripts (ADAdmin)

A portable PowerShell toolkit for administering several Active Directory forests that have no trusts between them. It runs from a USB stick, an SMB share or a local folder, and installs nothing.

Every action needs the credential of the right domain, and using the wrong one either fails or succeeds against a domain you did not mean to touch. You give ADAdmin a hostname, FQDN, UPN or NetBIOS name, and it works out which registered forest that is and uses that forest's stored credential.

```powershell
adm domain resolve -Target ws1.child.corp.example.com     # -> child (DnsSuffix)
adm user list -Target ws1.child.corp.example.com -Json    # routed to the child forest
adm gui                                                    # dark WPF window
```

## Components

| Component | Description |
|---|---|
| Library | `ADAdmin/`, a PowerShell module of `*-Adm*` cmdlets: `Resolve-AdmDomain`, `Get-AdmUser`, `Set-AdmUser`, `Get-AdmGroupMember` and others |
| CLI | `adm.ps1`: tables and prompts for a person, or `-Json`, `-NonInteractive` and defined exit codes for a script |
| GUI | `adm gui`: a WPF window for the primary interactions |
| Scripts | `scripts/`: stand-alone administration scripts built on the module |
| Tools | `tools/`: packaging (`New-AdmPackage.ps1`) and an interactive shell (`Start-AdmShell.ps1`) |

## Requirements

- Windows with Windows PowerShell 5.1, or PowerShell 7 on Windows. The GUI needs WPF.
- Network access to a domain controller of each forest you manage. RSAT is used when present and is not required.
- Some scripts that change a machine (`Set-UacGoldenPolicy.ps1`, `Set-ComputerDomainMembership.ps1`, `RemoveVeeamAgent.ps1`) need an elevated session.

## Getting started

```powershell
adm store init -Name <you>
adm domain add -Name corp -Dns corp.example.com -Netbios CORP -Dc dc01.corp.example.com
adm domain set-cred -Name corp -Tier read -Default
adm gui
```

Register a domain controller by its FQDN. A TLS certificate names a host, so LDAPS to a bare IP address cannot validate; see [docs/active-directory-traps.md](docs/active-directory-traps.md).

To try it with no directory at all, set `$env:ADADMIN_PROVIDER = 'mock'`. This uses the fixture in `ADAdmin/Fixtures/`, labelled as a fixture wherever it appears.

## Credential store

One encrypted file. Each administrator has their own passphrase: a random data key encrypts the registry once and is wrapped per administrator, so adding or removing someone changes nobody else's secret. Encryption is AES-256-CBC with HMAC-SHA256 (encrypt-then-MAC, verified before decrypt) and PBKDF2-SHA256 at 310,000 iterations. Credentials are tiered (`read` and `write`), so a query credential cannot perform a change. Removing an administrator does not revoke credentials that person could already read; rotate the directory credentials as well.

## The `-Json` envelope

```json
{ "ok": true, "command": "user list", "note": null, "data": [ ... ], "truncated": false }
```

On failure:

```json
{ "ok": false, "command": "user list", "error": "...", "exitCode": 4,
  "diagnosis": { "code": "...", "title": "...", "why": "...", "fix": [ ... ],
                 "recognised": true, "technical": { ... } } }
```

- Parse the last line of stdout that begins with `{`. Under `-WhatIf`, PowerShell writes its own `What if:` narration to stdout first.
- Check `truncated` before trusting `data`. `true` means the directory holds more than was returned, so a count is a lower bound.
- `exitCode` matches the process exit code. `diagnosis` is `null` on a usage error (`exitCode` 2).
- `recognised: false` means the toolkit has no catalog entry for the failure, and `technical.raw` holds the directory's own message.

## Directory administration

```powershell
adm user set   -Target corp.example.com -Identity jsmith -Title 'Senior Engineer' -Manager aokafor
adm user set   -Target corp.example.com -Identity jsmith -Office        # no value clears it
adm ou new     -Target corp.example.com -Name Contractors -Path 'DC=corp,DC=example,DC=com'
adm object move -Target corp.example.com -Identity jsmith -To 'OU=Leavers,DC=corp,DC=example,DC=com'
adm group members -Target corp.example.com -Identity 'Domain Admins' -Recursive
```

- `Get-AdmGroupMember` searches for members instead of reading `member`, because a read of a multi-valued attribute past about 1500 values returns nothing. It also returns primary-group members, who appear in no `member` list. Each row says how it was found.
- Every search asks the directory for one row more than it returns, so a truncated read is detected. A list says it is incomplete, a count says `AT LEAST n`, an audit records unchecked coverage, and a write from a partial view (the CSV import) refuses.
- A new OU is protected from accidental deletion by default. `Remove-AdmOrganizationalUnit` counts the children first and puts the number in the refusal.
- `Remove-AdmGroup` refuses any group with a RID below 1000, with no override, because a recreated built-in group has a new SID.
- Renaming an object does not change `sAMAccountName` or `userPrincipalName`, and the cmdlet says so. A move changes which Group Policy applies, and both DNs are logged.

More: [docs/object-lifecycle.md](docs/object-lifecycle.md).

## Bulk user import

```powershell
adm user import -Target corp.example.com -Path .\joiners.csv -WhatIf     # the plan, per row
adm user import -Target corp.example.com -Path .\joiners.csv -RollbackPath .\undo.csv
```

- The whole file is validated before anything is written: duplicate names, names over 20 characters, missing values and conflicting rows.
- `-WhatIf` returns one object per input row with the action, the resolved DN and the attributes that would change, with `From` and `To`.
- Every row gets its own result, and a failure on one row does not stop the run or read as success.
- `-RollbackPath` records the successful rows only: a delete row per created account and a restore row per changed attribute.
- With no `Password` column, one password is generated per user and returned once. It is not written to the log.

## Help desk

```powershell
adm laps get      -Target corp.example.com -Identity WS1
adm bitlocker get -Target corp.example.com -Identity WS1 -KeyId 3A7F
```

LAPS retrieval distinguishes `Available`, `NoPermission`, `Encrypted`, `NotManaged` and `NotDeployed`, because Active Directory hides an unreadable attribute the same way it hides an unset one. BitLocker retrieval returns every recovery key, newest first, and says when none were returned because none were readable. Secrets are never logged. The fact of each retrieval is.

## Forest topology

```powershell
adm trust list -Target corp.example.com
adm site list   -Target corp.example.com
adm subnet list -Target corp.example.com -Orphaned
adm gpo list   -Target corp.example.com -Unlinked
```

Trusts show direction, transitivity and SID filtering. Sites with no subnets and subnets mapped to no site are flagged. Unlinked GPOs are found by joining `gPLink` back to the policies, and a disabled link is reported separately. This does not compute resultant policy, which is `gpresult` on the target machine.

## Scripts

All scripts in `scripts/` use the module, so they share the credential store, the error catalog, the 7-day log and `-WhatIf`.

| Script | Purpose |
|---|---|
| `Get-AdPrivilegedAccess.ps1` | Tier 0 membership through nesting, delegation, roastable accounts, krbtgt age. Read-only |
| `Get-AdDelegation.ps1` | Dangerous delegations (ACEs) on directory objects |
| `Get-AdLockoutSource.ps1` | Finds the source of an account lockout across all domain controllers |
| `Invoke-AdmSweep.ps1` | Runs a script against every registered forest and merges the results, with cross-domain collisions |
| `Get-AdForestStatus.ps1` | FSMO holders, functional levels, DC reachability and replication over plain LDAP |
| `Manage-AdUserAccounts.ps1` | Locked, expiring and stale accounts; create, group membership, reset, selective disable with CSV export |
| `Find-StaleComputers.ps1` | Computer objects for machines that no longer exist, with selective disable |
| `Set-ComputerDomainMembership.ps1` | Join, leave, rename, computer group membership and time configuration |
| `Find-AdDuplicates.ps1` | Duplicate SPNs (repairable) and duplicate SID history (reported) |
| `Get-MachineIdentity.ps1` | Per-machine cloning fingerprint (machine SID, MachineGuid, SusClientId) and fleet comparison |
| `Set-UacGoldenPolicy.ps1` | Applies or reports a baseline UAC profile |
| `RemoveVeeamAgent.ps1` | Local cleanup of Veeam Agent for Microsoft Windows |

Behavior that is decided:

- Leaving a domain requires a local administrator password, which is set, enabled and proven to authenticate before the machine unjoins.
- Stale-account sweeps refuse a window under 30 days, because `lastLogonTimestamp` replicates lazily, and they exclude `krbtgt`, `Guest` and `Administrator`.
- A domain member takes time from the domain hierarchy. Only a workgroup machine or the PDC emulator gets an explicit peer list, from `-NtpServer`. With no `-NtpServer`, the machine is left on the domain hierarchy.
- A domain controller is never reported as a stale computer and cannot be disabled through the toolkit.
- The privileged-access audit has no fix mode.
- A forest that did not answer is `FAILED`, never clean. `Invoke-AdmSweep` exits `20` on a partial sweep.

## Importing existing scripts

```powershell
adm script check  -Path .\Unlock-StaleUsers.ps1   # what would change, and why
adm script import -Path .\Unlock-StaleUsers.ps1   # convert and install it
adm script run    -Name Unlock-StaleUsers -Target corp.example.com
```

The original file is never modified. The import writes a converted copy and a wrapper that adds `-Target`, the error catalog, the log and `-WhatIf`, plus a manifest with the source hash so a later edit shows as `SOURCE CHANGED`. Analysis is AST-based, and a script that does not parse after conversion is refused. See [docs/script-import.md](docs/script-import.md).

## Diagnose and fix

```powershell
adm scan          # check this machine, the store and every domain; changes nothing
adm fix           # apply what it found, asking before each one
adm catalog       # every failure the toolkit can explain, by code
adm log list      # recent failures in plain English
```

`adm scan` reports what is wrong, what it will break and, where a fix exists, exactly what the fix does. Nothing is applied without a yes, and a fix that changes the computer needs `-AllowMachineChanges`. A check that could not run reports `unknown`, never `pass`. Failures are written to a log kept for 7 days.

## Tests

```powershell
tests\Invoke-AdmTests.ps1 -On both
```

The suites are plain scripts, so they run on a machine with nothing installed. They are offline and use the mock provider. Run them under Windows PowerShell 5.1 as well as PowerShell 7; `-On both` skips 7 when `pwsh` is not on the path.

`tests\live\` holds checks that need a real directory and are run by hand. `Invoke-AdmLiveTests.ps1` is read-only and can be pointed at any forest. `Verify-AdmWritePaths.ps1` creates and removes a throwaway OU, so point it only at a forest you own. It is excluded from the release package.

## Building a package

```powershell
tools\New-AdmPackage.ps1
```

This produces `ADAdmin-<commit>.zip` with a generated `VERSION.txt`. The package is built from `git archive`, so only tracked files are included and uncommitted changes are not.

## Documentation

- [docs/deployment-usb-and-smb.md](docs/deployment-usb-and-smb.md): carrying it, execution policy, Mark of the Web, multi-admin use on shared media
- [docs/object-lifecycle.md](docs/object-lifecycle.md): creating, editing, moving and deleting objects; membership as a search; LAPS and BitLocker retrieval
- [docs/script-import.md](docs/script-import.md): bringing existing scripts in
- [docs/active-directory-traps.md](docs/active-directory-traps.md): directory behavior measured against a real domain controller
- [docs/error-catalog.md](docs/error-catalog.md): every recognized failure, generated from the code
- [docs/powershell-51-traps.md](docs/powershell-51-traps.md): failures that differ between PowerShell 5.1 and 7, by symptom
- [docs/gui-conventions.md](docs/gui-conventions.md): interface rules for the window, the CLI and cmdlet output shapes
- [docs/development-notes.md](docs/development-notes.md): layout, tests, environment variables and design rules

## License

MIT. See [LICENSE](LICENSE).
