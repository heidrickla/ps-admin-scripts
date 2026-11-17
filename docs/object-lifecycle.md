# Object lifecycle, membership, and help-desk retrieval

The everyday half of the toolkit: creating, editing, moving and deleting directory objects,
working out who is really in a group, and getting a LAPS password or a BitLocker key back out.

Added 2026-08-28, and **verified against the lab domain controller the same day** — 35 checks on
the main run and 9 on the restore run, all passing, everything created inside a throwaway OU and
torn down afterwards.

That run found three bugs that the unit suites, all green, could not see:

- **`Set-AdmDaclMask` was called without `[void]`**, so its return value leaked into the caller's
  output. `Test-AdmObjectProtected` returned a two-element array — truthy whatever it holds — so
  *every* object read as protected and every move and unforced delete refused. It also displaced
  the properties on `New-AdmOrganizationalUnit`'s return object.
- **`Restore-AdmObject` could not work at all** through `System.DirectoryServices`. See below.
- **`Set-AdmUser -NeverExpires`** threw on a `[datetime]`-typed internal parameter that, by
  definition, receives no date.

Still unverified, and marked as such in the files rather than quietly claimed: the full-restore
branch with the Recycle Bin **on** (the lab's is off, and enabling it is forest-wide and
irreversible), the LAPS `Available` / `NoPermission` branches (no LAPS deployed there), BitLocker
`Available` (no keys escrowed), and the `InvokeSet` fallback in the `accountExpires` write — the
`Int64` path succeeded, so the fallback never ran.

---

## Why membership is a search, not an attribute read

`Get-AdmGroupMember` never reads the group's `member` attribute to enumerate. Three separate
things go wrong that way and **all three are silent**.

### 1. Range retrieval — the one that returns nothing

A directory returns at most about 1500 values of a multi-valued attribute in one read. Past that
it does **not** return a truncated list. It returns the property under a different name —
`member;range=0-1499` — and a caller that asked for `member` gets **no attribute at all**.

So the obvious implementation reports a 3000-member group as **empty**, and there is no error, no
warning, and nothing in the output to suggest the number is wrong.

A corollary worth stating because it looks like a fix and is not: a check of the form
*"if the member count is >= 1500, warn that it may be truncated"* **can never fire**. Above the
boundary the count is zero, not 1500.

`Get-AdmRangedAttribute` walks the windows properly, asking for `member;range=<n>-*` until the
returned name ends in `-*`. It is used where the declared list genuinely is needed — detecting
foreign members, and counting before a group deletion.

### 2. Primary-group members are in no `member` list

An account whose `primaryGroupID` is the group's RID **is a member of that group** and appears in
the `member` attribute of nothing, anywhere.

This is why:

- `Domain Users` appears to have no members at all — it is almost every account's primary group;
- a privileged group can hold an account invisibly, by setting `primaryGroupID` to 512 rather
  than adding a `member` entry.

`Get-AdmGroupMember` runs a second query on `(primaryGroupID=<rid>)`, derived from the group's own
SID rather than from an assumed RID, and marks those rows `Via = 'primary-group'`. **Expect users
to report these as a bug**; they are the rows every other tool omits.

### 3. Nesting

`member` is one level deep. `-Recursive` uses `LDAP_MATCHING_RULE_IN_CHAIN`
(`1.2.840.113556.1.4.1941`), which walks the chain **server-side** — so a cycle in the nesting
cannot hang the client, and the whole chain costs one query.

### What it cannot do

Members from another domain are reported from the group's own attribute and marked
`Foreign = $true`, carrying **only** a distinguished name. A search bounded by this domain cannot
resolve them, and in this estate there is usually no trust to bind over. `SamAccountName`,
`DisplayName` and `Enabled` are `$null` on those rows by design, not by omission.

---

## Accidental-deletion protection is an ACL, not a flag

"Protect object from accidental deletion" is a pair of **Deny** ACEs for *Everyone* on `Delete`
and `Delete Subtree`. Three consequences:

- A protected object fails deletion with **"Access is denied"** even for a Domain Admin. The
  message is about the wrong thing entirely and sends people to check their rights.
- It blocks a **move** too, because a move is implemented as a delete-and-add of the naming
  attribute. `Move-AdmObject` detects this and says so.
- Clearing it must remove **any** Deny-to-Everyone ACE carrying either bit.
  `RemoveAccessRule` matches on the rights as well, so a partially-set protection — `Delete` but
  not `DeleteTree`, which older tooling produced — survives a naive removal and the delete still
  fails.

`New-AdmOrganizationalUnit` protects by default, matching the Microsoft tooling and what every
estate assumes has happened.

> **Reading a DACL:** pin `Options.SecurityMasks` to `Dacl` before touching `ObjectSecurity`. The
> default mask also requests the SACL, which needs `SeSecurityPrivilege`; without it the read
> throws, and the error reads like a permissions problem *with the object* rather than with the
> mask. `Set-AdmDaclMask` does this.

> **An ACL that could not be read is not an absence of protection.** `Test-AdmObjectProtected`
> raises rather than returning `$false`, because returning `$false` would walk a caller straight
> into a deletion it should have been warned about.

---

## Deleting things

| Refusal | Why it has no override |
|---|---|
| `Remove-AdmObject` on a **domain controller's** computer account | Deleting one removes that DC from the domain. A staleness sweep is *more* likely to select a DC than anything else, because nobody interactively logs on to one and it looks idle by every measure such a sweep uses. |
| `Remove-AdmGroup` on any group with **RID < 1000** | Built-in and well-known groups. Recreating one gives it a **new SID**, so every ACL, GPO reference and local-group nesting that named the old one silently stops matching. The damage surfaces days later as scattered, uncorrelated access failures. |
| `Remove-AdmOrganizationalUnit` on a **non-empty** OU without `-Recurse` | Deleting an OU takes the entire subtree and the directory confirms nothing. The child count is taken first and put **in the refusal**, because "not empty" is not a number anyone can weigh a decision against. |

A group with members needs `-Force`: the membership is the thing being destroyed and it is
recorded nowhere else.

**Recoverability.** A deleted object comes back only if the AD Recycle Bin is enabled in the
forest. Otherwise what remains is a stripped tombstone that cannot usefully be restored.

## Restoring: the one place DirectoryEntry cannot go

Every other operation in this module uses `System.DirectoryServices`. The restore cannot, and it
is worth stating loudly, because the obvious implementations all fail in ways that blame the
wrong thing. Measured against a real tombstone:

| attempt | result |
|---|---|
| Bind a `DirectoryEntry` to `CN=Deleted Objects` as a search base | `FindAll` throws **"There is no such object on the server"** — the container is hidden, and `Tombstone` is a *searcher* property, so the base is bound before the control exists |
| `searcher.Tombstone = $true` → `FindOne()` → `GetDirectoryEntry()` | the entry's bind **silently fails**; reading a property gives *"Cannot index into a null array"*, this repo's own signature for a dead ADSI bind. The SearchResult carries the control, the DirectoryEntry made from it does not |
| `PutEx` on that entry | *"There is no such object on the server"* — thrown from `PutEx` rather than from the bind, so it blames the object |
| **`System.DirectoryServices.Protocols`, `ModifyRequest` + `ShowDeletedControl`** | **`ResultCode: Success`** |

So: **search deleted objects from the domain root** with `Tombstone = $true` and `(isDeleted=TRUE)`,
and **write them through S.DS.Protocols**. The two modifications — deleting `isDeleted` and
replacing `distinguishedName` — must go in one request, because the directory refuses to clear
`isDeleted` without simultaneously being given a live DN to occupy.

Do not "simplify" this back to a `DirectoryEntry`. It looks like an inconsistency in the module,
and it is the only thing that works.

---

## Editing attributes

`Set-AdmUser` touches **only the parameters actually passed**, using `$PSBoundParameters` rather
than a null check — otherwise "leave it alone" and "clear it" are the same call and one of them
is wrong. Passing an empty string clears.

Clearing must use `.Clear()` (or `PutEx(1, …)`), **never** `.Value = ''`. An empty string is a
*value*, not an absence: the attribute stays present, every "is this set?" test that was written
against a real directory's habit of omitting unset attributes now answers wrongly, and nothing
errors.

The write is **atomic** — one `CommitChanges` — so a rejected attribute applies none of them. That
is the right behaviour, but it means the directory names one problem while several may exist, so
the failure message lists every attribute the call was attempting.

Three traps carried in the parameter surface:

- **`-Manager` takes a person, not a DN.** The attribute stores a distinguished name; a
  `sAMAccountName` is resolved first, and resolution refuses on ambiguity. A non-DN written into
  `manager` is accepted by some tooling and then displays as blank everywhere.
- **`-Country` is the two-letter ISO code**, because that is what `c` holds. The readable name
  lives in `co` (`-CountryName`). Setting one without the other is why address blocks come out
  half-populated.
- **Changing `-UserPrincipalName` is not renaming the account.** `sAMAccountName` is separate and
  is what `DOMAIN\user` authentication uses. A duplicate UPN elsewhere in the forest makes the
  directory reject the whole write.

Likewise `Rename-AdmObject` changes the **CN**, not `sAMAccountName`, `userPrincipalName` or
`displayName`. Its RDN prefix is taken from the object's existing DN, so an OU renames as `OU=`
and a user as `CN=` without the caller having to know which.

**UNVERIFIED:** the `accountExpires` **write** path. Reading that attribute is proven here; the
write is `Int64` first with an `InvokeSet('AccountExpirationDate', …)` fallback, from the
documented behaviour of both APIs. Note it is `ToFileTimeUtc()`, not `ToFileTime()` — the local
conversion shifts every expiry by the host's offset, which is invisible in a UTC lab.

---

## LAPS and BitLocker: saying *why* something is missing

**The hard part is not reading the attribute.** Active Directory omits an attribute you are not
allowed to read in *exactly* the same way it omits one that was never set. So the naive
implementation tells someone their machine has no LAPS password when it has one they merely
cannot see — and they go and re-deploy LAPS over a working password.

Both LAPS generations provide a way out. The **expiration-time** attribute is ordinary and
readable by anyone who can read the computer object, while the **password** is guarded by a
separate extended right:

| expiry | password | verdict |
|---|---|---|
| present | present | `Available` |
| present | **absent** | **`NoPermission`** — a password *is* stored; ask for the LAPS read right |
| absent | absent | `NotManaged`, or `NotDeployed` if the schema attribute does not exist at all |

That middle row is the entire point of the cmdlet. The last distinction needs a schema check, or
a forest-wide absence gets reported as a per-machine problem.

Windows LAPS stores a JSON document, `{"n":…,"t":…,"p":…}`, where **`t` is a hex FILETIME** — not
decimal, not ISO. Parsing it as decimal yields a date centuries out, with no error.
`msLAPS-EncryptedPassword` is reported as `Encrypted` rather than pretended over: decryption is
not an LDAP operation.

BitLocker recovery keys are **child objects** of class `msFVE-RecoveryInformation`, not attributes.
A machine that has been re-encrypted, or has more than one protected volume, has several — so all
are returned, newest first. **Match on the key identifier** BitLocker shows on its recovery
screen, not on the date: an identifier belongs to a volume, not to a computer name.

An empty result is ambiguous in the same way as LAPS, and says so rather than implying the keys do
not exist.

**Secrets are never written to the log. The retrieval is** — who asked, for which machine, when.
That record is the audit trail for a credential disclosure and is worth more than the convenience
of omitting it.

---

## Bulk import: partial application is the whole problem

A loop over `Import-Csv` is five lines. What it lacks is the reason this cmdlet is longer.

**A run that fails at row 40 of 200 leaves a state nobody wrote down.** Half the accounts exist,
there is no record of which half, and the operator's obvious next move — re-run the file — either
duplicates work or fails on everything already done. So `Import-AdmUserCsv`:

1. **Validates the entire file before writing anything.** Duplicate `sAMAccountName` within the
   file, names over the 20-character limit (a real AD limit, and the directory's rejection message
   does not mention it), missing values, rows conflicting with `-Mode`. All found while nothing
   has changed. `-StopOnError` refuses the run outright if any row is bad.
2. **Returns one object per input row**, always — including the rows it skipped and why.
3. **Never reports success for rows that failed.** A single row's failure is recorded against that
   row and the run continues; aborting mid-way would create exactly the unrecorded partial state
   the design is meant to prevent.

**The preview is data, not narration.** `-WhatIf` returns the plan as objects: the action, the
resolved `TargetDn`, and `Changes` — each attribute that would move, with `From` and `To`. That is
enough to render the plan, deselect rows, and apply the rest without parsing text. A row whose
values already match reports `no-change`, not an update that would do nothing.

**`-RollbackPath` records what actually applied**: a `delete` row per created account, a `restore`
row per changed attribute carrying its previous value. Only successful rows are written — a
manifest naming failed rows would send someone deleting accounts that were never created.

**Generated passwords use rejection sampling, not modulo.** `byte % 62` biases the first few
characters of the alphabet, because 256 is not a multiple of 62 — a bias that is invisible in any
output you would look at and real in the key space. The generated set also excludes `0 O 1 l I`,
because these get read down a phone and typed by hand.

## PowerShell traps hit while building this

Recorded here because each returned a **plausible wrong value** rather than an error.

**`@( @(a,b) )` containing exactly one inner array is flattened.** Two or more are not. A bit
table written as an array of pairs therefore works at ten entries and throws
`Unable to index into an object of type System.Int32` the day someone trims it to one. Use two
parallel arrays.

**A bare `0x4` in command-argument position arrives as the string `"0x4"`**, and
`[int]::TryParse("0x4")` returns `$false`, leaving the value 0. Any bit decoder called as
`Decode 0x2000` from a script or a test silently reports **no flags**. `ConvertTo-AdmFlagInt`
accepts both forms.

**`,$x.ToArray()` with a caller that writes `@(f)`** yields one element that is itself an array:
an empty result counts as 1, and `-contains` never matches. Just emit the collection.

**`@(a,b,c) | Where-Object {…}` returns a scalar when exactly one value survives**, and `.Count`
on a scalar throws under `Set-StrictMode 2.0`. The `@()` must enclose the whole pipeline.

**`.SYNOPSIS <text>` on one line is silently ignored.** The keyword must stand alone, and a
malformed first directive discards the entire help block — `.DESCRIPTION` included. The symptom
is `Get-Help` returning the generated syntax line as the synopsis and an empty description. This
was true of **all 54 help blocks in the repo** when measured on 2026-08-28.

**A name-only search of the domain naming context also matches AD-integrated DNS nodes.**
`(name=DC01)` returns the computer *and* its `dnsNode` under `CN=MicrosoftDNS,CN=System`, so an
unconstrained resolver refuses every DC-named host as ambiguous. Constrain by `objectClass`.

**`$PSBoundParameters` inside an `Invoke-AdmGuarded -Action { }` block is the wrapper's, not the
cmdlet's.** It holds `Action`, `Operation` and `Target`, so every `ContainsKey('<param>')` is
false and a "touch only what was passed" cmdlet reports that nothing was passed. Capture
`$bound = $PSBoundParameters` *before* the block. This presents as "the cmdlet ignores its
parameters" rather than as a scoping problem, and no unit test can catch it — each function is
correct alone and the fault is in how they nest. It took an end-to-end CLI suite to find.

**`-Json` together with `-WhatIf` puts non-JSON on stdout.** PowerShell's
`What if: Performing the operation ...` narration is written straight to the host, ahead of the
envelope. Measured: none of `2>`, `4>`, `5>`, `6>` or `$WhatIfPreference` suppress or capture it,
and it is on stdout, not stderr. The contract the CLI can actually keep is that **the envelope is
the last line**, so a script should parse the last line beginning with `{`. Asserted both ways in
`tests/LifecycleCli.Tests.ps1` — including a check that the whole of stdout does *not* parse, so
nobody later "fixes" the documentation back to a promise the platform will not keep.
