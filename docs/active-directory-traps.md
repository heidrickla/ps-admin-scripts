# Active Directory traps — measured, not theorised

**Every entry here was hit against a real domain controller** (a lab forest,
Windows Server 2025) on 2026-08-27. They are in the code now; this page exists so the next
person understands *why* the code looks the way it does, and so the same hour is not spent twice.

The theme: **Active Directory reports several completely different problems with the same
message.** "The server is not operational" alone covers unreachable, wrong port, untrusted
certificate, and connecting by IP over TLS. Anything that just forwards that string to an
operator has told them nothing.

## Disposing a failed connection throws again — and replaces the real error

ADSI binds **lazily**: `New-Object DirectoryEntry(...)` connects to nothing. The first property
access connects. So when a bind fails, the object is in a state where even `.Dispose()` retries
the connection and throws — and because that happens in a `finally`, **the new exception replaces
the one you were about to report.**

The operator sees a message about `Dispose` and no mention of the domain controller.

```powershell
try { ... } finally { Close-AdmDirectoryEntry $root }   # swallows; never masks
```

## Forcing the bind by reading a property gives you a PowerShell error, not a directory error

The obvious way to make a lazy bind happen is to read something:

```powershell
$dn = $root.Properties['distinguishedName'].Value      # DON'T
```

On a **failed** bind `.Properties` is a **null collection**, so this raises
`Cannot index into a null array` — a PowerShell error that tells you nothing and matches no
diagnosis rule. Every connection failure lands as "unrecognised".

```powershell
$root.RefreshCache()                                   # DO -- raises the real COMException
```

That one change turned an unrecognised failure into `LDAPS-HANDSHAKE-FAILED` with three concrete
fixes.

## A real directory omits attributes that are not set

The fixture had every field on every object. A real one does not:

- an account that has never been locked has **no `lockoutTime` attribute at all**
- an empty group has **no `member` attribute**
- a computer that has never registered DNS has **no `dNSHostName`**

Under `Set-StrictMode -Version 2.0`, `$raw.lockouttime` on such an object **throws**, and it takes
the whole search with it. The first real query against a lab domain controller died on `Administrator`, an account
that had simply never been locked out.

Treat every attribute as optional — `Get-AdmRawProp` does.

**The general lesson: a fixture cannot teach you what a real system omits.** The mock provider
is genuinely useful, and it could never have found this.

## `SetPassword` needs RPC, and a portable toolkit will not have it

**The most consequential finding of the write-path run.** ADSI's `IADsUser::SetPassword` tries
LDAP-over-TLS first, then falls back to **RPC on 135/445**. On a plain — even *sealed* — LDAP
connection it takes the RPC path, and from a machine outside the target network RPC to a domain
controller is routinely blocked:

```
The RPC server is unavailable. (Exception from HRESULT: 0x800706BA)
```

Nothing in that message mentions passwords, encryption, or the real cause. It reads like the DC
being down.

**Write `unicodePwd` instead.** It is an ordinary LDAP attribute write, needs no RPC, and works
over any encrypted channel — LDAPS on 636, or `Sealing` on 389. The value is the new password
wrapped in double quotes and UTF-16LE encoded:

```powershell
$bytes = [System.Text.Encoding]::Unicode.GetBytes('"' + $plain + '"')
$entry.Properties['unicodePwd'].Value = $bytes
$entry.CommitChanges()
```

**Measured against a lab domain controller over sealed 389:**

| mechanism | result |
|---|---|
| `Invoke('SetPassword')` | **fails** — RPC unavailable |
| `unicodePwd` via `DirectoryEntry` | **works** |
| `unicodePwd` via `S.DS.Protocols ModifyRequest` | works |

Proven properly: after the reset, binding **as that account with the new password** succeeded.
A password change that "returns success" and cannot then authenticate is not a change.

**`pwdLastSet = 0` must be a SEPARATE commit**, after the password one. Setting it in the same
modify as `unicodePwd` is rejected.

**This corrected a wrong explanation in our own code.** The old warning said Active Directory
refuses password changes over an unencrypted channel. The 389 connection is *sealed*, i.e.
encrypted, and the write works fine — what failed was the transport ADSI chose. Being right about
the symptom and wrong about the cause sends the next person to fix the wrong thing.

## A LargeInteger reads back differently depending on how you asked

`lockoutTime`, `pwdLastSet`, `lastLogonTimestamp` and friends are LargeInteger attributes:

- via **`DirectorySearcher`** → a plain **`Int64`**, which casts and compares normally
- via **`DirectoryEntry.Properties[...]`** → a **COM object**, and `[int64]$value` throws
  `Cannot convert the "System.__ComObject" value ... to type "System.Int64"`

Read them through a search. Writing one is worse: assigning an `[int64]` through `DirectoryEntry`
fails with a bare `Unspecified error`, and `lockoutTime` specifically is system-managed — a DC
refuses a direct write to any non-zero value, so a lockout cannot be simulated that way at all.

**This page already said all of that, and it caught us again anyway** — reading the domain
password policy through `DirectoryEntry.Properties['maxPwdAge']`. The failure was silent and
nastier than a crash: `MaxPasswordAgeDays` came back **blank**, and a blank maximum age means
"password expiring soon" quietly matches **nothing at all**. A report that finds no expiring
passwords looks exactly like a healthy domain.

The affected attributes are every duration on the domain object — `maxPwdAge`, `minPwdAge`,
`lockoutDuration`, `lockoutObservationWindow` — plus `pwdLastSet`, `lastLogonTimestamp`,
`accountExpires` and `lockoutTime` on users. **If it is a time or a duration in AD, read it with
a search.** Measured against a lab domain controller: via search, `maxPwdAge` gives 42 days, which is the Windows
default; via `DirectoryEntry`, nothing.

## You cannot manufacture a duplicate SPN to test with — the DC refuses

Adding a service principal name that another object in the **same domain** already holds is
rejected at write time:

```
A constraint violation occurred.
```

Modern domain controllers enforce SPN uniqueness themselves. Useful to know for two reasons:

- **A duplicate-SPN scan finding nothing on a healthy domain is the expected result**, not a
  broken scan. Do not "fix" the scan until you have checked it can see SPNs at all — the lab DC has
  3 SPN-bearing objects carrying 25 SPN values, and the scan reads all of them.
- **The constraint is PER-DOMAIN, not per-forest.** The same SPN on accounts in two different
  domains of one forest is never refused, and Kerberos still breaks. That is the duplicate people
  actually hit, and finding it means scanning each domain and comparing across the results —
  a single-domain scan cannot see it by construction.

The other routes in are replication collisions, objects predating the constraint, restores and
tombstone reanimation, and domains where the check has been relaxed.

## A hardened DC refuses anonymous rootDSE reads — silently

Reading `LDAP://<server>/RootDSE` without credentials is the textbook way to get a DC's own clock
(for Kerberos skew). On a hardened DC it does not fail loudly: the properties simply come back
**empty**, so the check reported "could not read the time" against a DC that answers it fine when
asked *with* a credential.

Bind with the domain's stored credential, and `RefreshCache()` to force it.

## `0x8007203a` means four different things

| what it looks like | what it usually is | how to tell |
|---|---|---|
| the DC is down | it is not | the port probe says the port is **open** |
| wrong port | maybe | probe 389 and 636 separately |
| **certificate not trusted** | **most likely on a non-joined machine** | LDAPS, port open, connecting by name |
| **connecting by IP over TLS** | **certain to fail** | LDAPS, port open, target is an IP address |

A certificate names a **host**, never an address, so LDAPS to `192.0.2.40` can never validate.
The toolkit probes the one relevant port on the failure path and passes the result into the
diagnosis as a hint, which is what separates `SERVER-UNREACHABLE` from `LDAPS-HANDSHAKE-FAILED`.

**Measured on a lab domain controller:** LDAPS/636 open, bind fails; LDAP/389 with signing and sealing binds
immediately and returns `DC=corp,DC=example,DC=com`.

## The forest's DNS is the only thing that knows the forest's names

From a machine outside the forest, the forest name and the names of its hosts all
fail to resolve — the forest DNS lives on the DC itself. This is the normal case for a portable
admin toolkit, not an edge case.

So a domain profile pins a **DC address**, and DNS resolution of a bare hostname is opt-in
(`-UseDnsLookup`) rather than automatic. Asking the local resolver what a name means while
standing in a different forest is a guess wearing an answer's clothes.

## Only a domain controller serves LDAP

Obvious in hindsight, worth stating: on a member server 389/636/3268 are all closed
there while WinRM is open. "The host is up" and "the host serves the directory" are different
questions, and a ping answers neither.

## A SID does not come back as `byte[]`, and the obvious check is false every time

Measured 2026-08-27 against a lab domain controller. Reading `objectSid` through `Invoke-AdmAdsiSearch`:

```
.NET type      : System.Object[]
is [byte[]]    : False
[string] gives : 1 4 0 0 0 0 0 5 21 0 0 0 15 64 75 122 152 58 61 164 44 28 223 120
```

A `DirectorySearcher` property collection hands binary attributes back as a **collection**, and
the module normalises that to `System.Object[]` whose elements happen to be `System.Byte`. So the
natural guard —

```powershell
if ($Raw -is [byte[]]) { (New-Object System.Security.Principal.SecurityIdentifier($Raw,0)).Value }
else { [string]$Raw }        # <-- this branch runs, ALWAYS
```

— never takes the branch it was written for, and the fallback produces the bytes space-joined.
That string is not a SID, is not an error, and does not look obviously wrong at a glance.

**Two independent call sites had written that same check and both were silently broken.**
`Find-AdDuplicates` printed byte soup where a SID belonged in its sIDHistory report — and still
*found* genuine duplicates, because identical bytes give identical soup, so the output was
useless without being wrong. `Get-AdPrivilegedAccess` built `"<soup>-512"` as an LDAP filter,
matched nothing, and **reported Domain Admins as empty**.

The fix is `ConvertTo-AdmSidString`, which is the only supported way to read a SID out of this
module. It does `[byte[]]@($Raw)` — the `@()` then hard cast is what turns `Object[]`-of-`Byte`
into a real `byte[]`, and it is a no-op on something that genuinely is one already.

> **A unit test that passes a real `byte[]` cannot catch this.** The existing SID test did
> exactly that and passed throughout. The test has to construct `Object[]` of `Byte`, which is
> what the directory actually returns.

## Filtering by SID string *does* work — that part was never the problem

`(objectSid=S-1-5-32-544)` returns BUILTIN\Administrators. AD accepts the SDDL string form in an
LDAP filter, so keying well-known groups by RID is sound; only the SID being *built* was wrong.

## Find privileged groups by RID, never by name

`Domain Admins` is `Domänen-Admins` on a German domain and `Admins du domaine` on a French one. A
filter on the English name silently returns nothing and reports the most privileged group in the
forest as empty. Domain-relative RIDs (512 Domain Admins, 519 Enterprise Admins, 518 Schema
Admins, 520 Group Policy Creator Owners) need the domain SID prefix; the BUILTIN ones
(`S-1-5-32-544` and friends) are the same constant in every domain there has ever been.

And because "not found" is indistinguishable from "empty", the groups that exist in *every*
domain — Domain Admins and BUILTIN\Administrators — are checked explicitly: failing to find one
is reported as **unknown**, not as a clean result. Enterprise Admins and Schema Admins are
genuinely absent outside the forest root, so silence there is the right answer.

## `primaryGroupID` membership is invisible to everything that reads `member`

A user whose `primaryGroupID` is 512 **is** a domain admin, with the full rights, and does **not**
appear in the group's `member` attribute — so the Members tab in Active Directory Users and
Computers does not show them, and neither does any recursive walk of `member`. It has to be
queried separately: `(&(objectCategory=person)(primaryGroupID=512))`.

It is a documented privilege-hiding technique. It is also what a careless bulk account creation
produces by accident, which is the more likely way to meet it.

## Membership nesting can contain cycles, and default nesting is not a finding

AD permits A → B → A, so a recursive expansion of `member` needs a seen-set or it never returns.

Separately: Active Directory nests Domain Admins and Enterprise Admins inside
BUILTIN\Administrators **by default, in every domain**. Reporting `Administrators → Domain
Admins → someone` as a serious finding is noise, and noise is how the real finding gets scrolled
past. The rule that separates them is not a hardcoded exception for those two groups — a path
whose intermediate links are *all themselves* Tier 0 groups reveals nothing the inner group's own
walk does not already report. A path through an ordinary group is the one nobody decided on.

Verified on a lab domain controller by building `Domain Admins ← T0-Probe-Outer ← T0-Probe-Inner ← t0probe`,
confirming it was reported critical with the full path, confirming the default nesting stayed
`info`, and deleting all three objects.

## `member` is paged at 1500, and the attribute is RENAMED — a plain read returns nothing

AD returns `member;range=0-1499` for a large group. That is a **different property name**, so
code asking for `member` finds no such property and gets back **nothing** — not a short list, an
empty one.

**The obvious guard therefore cannot work.** `if ($members.Count -ge 1500)` was written in the
privileged-access audit for exactly this case and could never fire: the count is `0`, not `1500`.
A 3000-member privileged group was audited as having **zero** members with that check sitting on
the next line. Any test of the form *"truncated if the count reached the limit"* is dead code
here.

**These are two different limits sharing one flag.** `SizeLimit` caps how many **rows** a
search returns; the range caps how many **values** come back within one row. A search that
returns exactly the one row it asked for is not truncated by the first rule and can still be
missing 1500 values by the second.

`Get-AdmRangedProp` (Objects.ps1) reads the ranged name, returns the **first window** rather than
nothing, reports `Truncated`, and raises the module's search-truncation flag so the `-Json`
envelope and every existing `Get-AdmSearchTruncated` caller see it without knowing which limit
fired. It costs no extra query — the window is already in the result, under the other name.
`Get-AdmRangedAttribute` (Groups.ps1) walks *every* window when the whole set is genuinely needed.

**Say what was tested.** The handling here is proven against *fixtures* carrying both the plain
and the `;range=` property name, and against the code paths that read them — not against a real
group of 1500+ members. The lab has no such group and manufacturing one would mean writing 1500
objects into it. What is measured is that the toolkit reads a ranged property correctly and
reports it; what is taken from documented AD behaviour is the point at which the directory starts
renaming. If you ever run this against a group that large, that is the moment to confirm the
second half.

## A search that hits its size limit returns rows and no complaint

This whole section is one instance of a design rule in [development-notes.md](development-notes.md): "I could not look" must never read as "nothing is wrong". A blind source yields a falsy `[]`, and a truncated probe lies in both directions. Every bug below is that rule applied to a directory. None was found by reading the rule; they surfaced when someone pointed out that production has many subnets. A rule that is written down and not applied is worth nothing, which is the argument for enforcing checks over more prose.


`DirectorySearcher` stops at `SizeLimit` **silently**. You get exactly N objects and nothing
anywhere says there were N+900 more — no exception, no property, no warning. A limit chosen
against a lab is therefore a wrong answer waiting for production.

**The damage is not the missing rows, it is the conclusions DERIVED from them.** Displaying
500 of 3000 rows is a nuisance you can see. These are not:

| computed from a partial read | what somebody does with it |
|---|---|
| "this site has **no subnets**" | goes looking for a different cause of the slow logons |
| "this GPO is **linked nowhere**" | deletes a live policy |
| "this OU contains **40 objects**" | approves the delete; it destroys 4000 |
| "the object is **not in the Recycle Bin**" | concludes it is unrecoverable and stops trying |

All four look exactly like right answers.

**The worst shape is an audit, because there the finding IS the absence.** A delegation sweep,
a duplicate-SPN scan, a stale-computer report and a privileged-access audit all answer largely by
reporting nothing. An object past the size limit is never examined, and an object never examined
contributes no findings — so a truncated audit does not produce a *short* report, it produces a
**clean** one. Worse, a duplicate is found by *comparing two objects*: if either sits past the
limit the pair is never compared, so a real collision is reported as no collision. That is why
`Find-AdDuplicates` grew **exit 30** — `exit 0` is a claim, not a default, and `Invoke-AdmSweep`
reads it. The other three record it as *unchecked coverage* in the section they already have for
what could not be read.

**`$rows.Count -ge $limit` cannot detect this**, and it was what every call site used. It
cannot distinguish *exactly $limit objects exist* from *stopped at $limit*, so it cries
truncation on complete answers and gets disbelieved. Instead **ask the directory for one row
more than you will return** — the arrival of that extra row *is* the signal:

```powershell
Reset-AdmSearchTruncated
$rows = @(Get-AdmGroupMember -Target corp -Identity 'Domain Users')
if (Get-AdmSearchTruncated) { "$($rows.Count) is a FLOOR, not the total" }
```

**The flag is sticky and only the caller clears it.** It has to be: a public cmdlet runs
several searches — `Get-AdmGroupMember` resolves the group, reads members, then reads
primary-group members. If each search cleared the flag on entry, a truncated member read
followed by a one-row SID lookup would report **not truncated**, which is the precise failure the
mechanism exists to prevent. Sticky over-warns; that is the correct direction here.

`SizeLimit = 0` means *the server's own limit applies*, cannot be over-fetched, and so cannot be
detected. Do not pass 0 to a read you intend to draw a conclusion from.

Measured on a lab domain controller 2026-08-28 against a 3-user domain: limit 2 returns 2 rows and reports
truncated, limit 3 returns 3 and reports not truncated, and the rows emitted under truncation are
complete objects rather than stubs. `tests/Truncation.Tests.ps1` holds the same checks on the
mock provider, plus the arithmetic (`0` stays `0`; `[int]::MaxValue` must not wrap to a negative
`SizeLimit`, which `DirectorySearcher` rejects outright). The live half is
`tests/live/Invoke-AdmLiveTests.ps1` — kept out of the offline runner, because a suite needing a
domain controller would make "the toolkit is broken" and "you are not on the network" the same
red line.

**Forcing truncation with a hardcoded `-Limit 1` does not work, and looked like it did.** It
only truncates a read of *two or more* objects, so the trigger depends on what the domain holds
at that moment. The delegation check passed on a lab domain controller only because the domain had an extra
OU alive — a default domain has exactly one (`Domain Controllers`) and, in a small lab, one
domain controller. Count first and derive the limit; where truncation cannot be forced, **skip
loudly**. A lab-sized threshold in the *test* is the same defect as one in the code.

## Reference

- `docs/error-catalog.md` — every recognised failure, generated from the code
- `adm catalog -Code <code>` — one entry, with its fixes
- `adm scan` — checks these conditions before they bite
