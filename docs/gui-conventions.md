# Interface conventions — the rules, and the correction that produced each

Every rule here exists because the toolkit did the opposite and somebody had to say so. They are
written as rules rather than as a changelog because a fix stops one instance and a rule stops the
next one — the commits already record what changed, and none of them stop it happening again.

**Read this before changing `gui/`, `adm.ps1`, or a cmdlet's output shape.** The GUI rules came
first and are below; the CLI and cmdlet rules follow them, and several are the same rule reached
from the opposite end — which is why they share a file rather than disagreeing in two.

Where a rule can be enforced it is, and the enforcing check is named; a convention that lives only
in prose is one nobody reads.

---

## Never block the UI thread

> *"Running Get-MachineIdentity seemed to lock up the app."*

Long work runs on a background runspace with a Cancel that actually stops it. WPF cannot repaint
while a handler is running, so an inline call does not look slow — it looks **hung**, and there is
no way out of it. The first version pumped the dispatcher once before the call so the "running…"
message would paint, which made it worse: it looked responsive and then froze.

A directory operation is never "quick enough". `Get-MachineIdentity -FromDirectory` contacts every
computer in the domain and each machine that is switched off costs a full WinRM timeout.

*Enforced:* `CliGui.Tests.ps1` — "starting a script RETURNS AT ONCE", "CANCEL STOPS IT".

## A handler must not be able to close the window

> *"Clicking the scripts button causes the app to crash… Clicking on an error causes it to crash as well."*

This file runs under `Set-StrictMode -Version 2.0` and `$ErrorActionPreference = 'Stop'`, so any
terminating error inside a WPF event handler propagates to the dispatcher and takes the window
with it — no message, no log line. From the user's side the application simply vanishes.

Two rules follow, and both are needed:

1. **Read every directory or JSON property through `Get-AdmRawProp`, never `$o.attr`.** A log entry
   carries only the keys that were written; a Windows event has no `why`/`fix`/`code` at all.
2. **`Dispatcher.UnhandledException` is handled**, shows the error, logs it, and leaves the window
   open. Handlers should still diagnose their own failures — this is the net for when one does not.

`$ui` is a **hashtable**: a key that was never populated returns `$null` in silence even under
StrictMode. `$ui.ScriptRoot` — a key that never existed — is what made the Scripts button quit.

*Enforced:* "EVERY $ui.\<name\> the code touches is actually bound", "the window survives a handler
error", "log fields are read safely", and a suite that *calls* the handlers rather than reading
their source.

## Exactly one pane visible per cell

> *"the middle pane also has a line going through the buttons at the top"*

That line was the results DataGrid's column-header rule showing **through** the panel on top of it.
`GlassPanel` is 8% white, and opening the log or the scripts pane made the new panel visible
without hiding the one underneath. Stacked translucent panes read as a rendering fault, because
that is what they are.

Everything goes through `Show-ContentPane`, which makes exactly one visible. And anything that
fills a pane must bring it to the front first, or it renders into a hidden one and looks like a
search that returned nothing.

## An empty control must look usable

> *"some of the entry fields look like they are greyed out also instead of active"*

At 9% black with a 15%-white hairline an empty input read as an inert slab — and beside a genuinely
disabled button, which renders at 0.35 opacity, that reading was fair. Empty is the state a field
spends most of its life in, so it is the state to design for.

The generated form labels were `TextFaint`, the dimmest tint in the palette, which made a whole
form of things you are meant to fill in look switched off.

## Selection is carried by colour, not by shape

> *"the ovals over the selected buttons looks weird… make it more like a regular button with selected/unselected colorings"*

`TabPill` was `CornerRadius="999"` with a fully transparent unselected state, so the unselected
options read as bare text and the selected one as an oval floating over them. Every option is a
button at all times now — same radius, padding and border as a normal button — and selection is the
accent treatment the rest of the window already uses for "the one that matters".

## State belongs to the object, not to the pane

> *"Output window should be per script, not follow the scripts as you click on each button."*

One shared buffer meant the output under one script could have come from another. Buffers are keyed
by the script that **produced** the line, so a run keeps filling its own while you click away to
read another — which is the whole point of not blocking.

*Enforced:* "OUTPUT IS KEPT PER SCRIPT, not dragged along the list".

## Offer a picker for anything the directory can enumerate

> *"it's hard to chose a new target unless you know its name… there is some redundancy also where fields in the scripts middle window ask for a computer or username"*

A free-text box for a computer, user or group means already knowing the name, and reads as a second
place to say what you are working on. Those are all names of objects in the forest the target
already names, so the field offers to go and look them up.

The same instinct produced the OU tree: search answers *where is jsmith*, navigation answers *what
is in this OU*, and an admin needs both.

## Say what is hidden

> (from the tree returning 118 system containers)

A filtered view presented as the whole directory is a quiet lie. The tree hides the plumbing under
`CN=System` by default, as ADUC does — and the count says how many were hidden and how to see them.

The same rule covers a failure: **an empty grid must not look like an empty result.** The reason goes
*into the panel*, not only into a status toast, because an empty grid beside an error elsewhere is
indistinguishable from "there is nothing here", and those mean opposite things.

`@($null).Count` is **1**, not 0 — an unset grid renders as one row with every column blank, which
reads as "one item we cannot describe". Null-check before counting. This has bitten three times.

## Before a destructive click, name the loss — not the action

> (from the Recycle Bin work)

"Restore this object?" invites yes. What the operator needs is what will **not** come back: a
tombstone restore returns the object with its original name and SID and no group memberships, and it
looks restored.

- Name the specific fields being **cleared**, and count them.
- Where the outcome is partial, say what the real remedy is (here: an authoritative restore).
- Surface the cmdlet's own `NextSteps` verbatim. A restored account comes back disabled; a toast
  saying "Restored" is true and useless.
- **Disable what cannot work** rather than allowing it and failing: no `ParentAvailable` means there
  is nowhere to put the object back, and that is knowable before the click.

## Generate forms from the source of truth

Both generated forms — the scripts panel and the account editor — are built from the target's own
parameter block via the AST. A hand-written form and a cmdlet drift apart within a release, and the
failure is silent: the GUI simply cannot reach a feature.

**Send only what changed.** `Set-AdmUser` treats an empty string as CLEAR, so a form that posted
every field on every save would wipe every attribute the operator did not fill in. Compare with
`-cne`; PowerShell's `-ne` is case-insensitive, so "jo smith" → "Jo Smith" is not a change to it.

**Re-read before seeding the form.** The diff is only as good as "original" being current: seeded
from a stale copy, a field somebody else just set reads as unchanged, or is silently reverted.

## ASCII only in displayed strings

These files are UTF-8 **without a BOM**, and Windows PowerShell 5.1 reads a BOM-less script as the
system ANSI codepage — so a `·` in a string literal reached the window as `A·`. Comments are exempt;
they are never rendered. Comment-based **help** is not exempt, because `Get-Help` renders it.

*Enforced:* "NO NON-ASCII IN A DISPLAYED STRING".

## Give the window the affordances every window has

> *"There is a minimize and close button, but a maximize button is missing."*

A `WindowStyle=None` window has to provide its own, and half-providing them is worse than a standard
frame. Maximise caps to the **working area of the screen the window is on** (or it covers the
taskbar), converts device pixels to DIPs (or it overshoots on a scaled display), squares the corner
radius (or there are notches of desktop at the edges), and lifts the cap on restore. Double-clicking
the title bar toggles it; dragging a maximised window restores it first.

## Make the first step possible in the window

> *"create the store from the gui"* · *"I would like to be able to export the configured domains"*

The lock screen used to disable its own button and tell you to run `adm store init` in a terminal —
the very first step of a GUI-first toolkit was a CLI step. Anything an operator must do to get
started belongs in the window: create the store, add a domain, store a credential, carry the domain
list to a new version.

Where a GUI action has a security consequence, state it: elevation is **offered**, not forced,
because elevating can land in a different user profile and the credential store lives in one.

---

## CLI and cmdlet conventions

The same practice applied to the other two surfaces. Each rule earned itself on 2026-08-28, and
several are the same rule as one above, arrived at from the opposite end — which is the argument
for one document rather than two.

### An empty result and a failure must not look alike

The sharpest rule of the day, and it cost three separate bugs in three files.

`Test-AdmObjectProtected` returned `@($false, $true)` because a helper's return leaked into it, and
**a two-element array is truthy whatever it holds** — so every object read as protected and every
move and unforced delete refused. `Get-AdmOrganizationalUnit -Identity <dn>` returned zero rows
because a DN was matched as a substring of a name; the caller read that as "no such OU", and for a
protection lookup as "not protected". A caught failure that left a collection unset rendered as one
row with every field empty, because `@($null).Count` is **1**.

*Enforced by:* the static check that helpers returning a value are never called bare
(`Lifecycle.Tests.ps1`), and by the `Truncation` suite.

### Say, per cmdlet, whether nothing is a legitimate answer

Only the cmdlet knows. `Get-AdmSite` returning zero rows is **never** right — every forest has
`Default-First-Site-Name`, so zero means the read failed. `Get-AdmSubnet` returning zero **is** the
answer, and an interesting one: it means site assignment works for nobody. Both now say which, in
their own help, next to the code.

*Correction:* `-IncludeSubnets` returned nothing on a forest with no subnets and read as "no sites".

### A size limit chosen against a lab is a wrong answer waiting for production

A `DirectorySearcher` stops at its `SizeLimit` **without saying so**. The lab has one OU, two GPOs,
a two-member `Domain Users` and zero subnets — so no limit here could ever be shown to be wrong.
Production has many subnets.

The danger is not a short list; it is a **derived** value computed from one. A truncated subnet read
makes `NoSubnets` falsely true. A truncated `gPLink` scan turns a **live** policy into one reported
as `Unlinked` — which is exactly the filter used to decide what is safe to delete.

Where a count or a boolean is derived from a read, either refuse on truncation or report the derived
value as `$null` for unknown. Never both truncate and conclude.

The same rule in the window: the OU delete confirmation says `contains AT LEAST 4000 object(s)`
rather than a number it cannot stand behind, the OU tree's count line says `TRUNCATED — this is NOT
the whole directory` rather than rendering a partial tree that looks complete, and the forest
panel's subnet finding reads *"could not be checked — UNKNOWN, not 'no'"* when `NoSubnets` is
`$null`.

**And the worst case is an audit, because there the finding IS the absence.** A delegation
sweep, a duplicate scan, a stale-computer report, a lockout hunt, a privileged-access audit — all
of them answer largely by reporting nothing. An object past the limit is never examined and so
can never be reported, which means a truncated audit does not read as *short*. It reads as
**clean**. A duplicate is worse still: it is found by *comparing two objects*, so if either half
sits past the limit the pair is never compared and a real collision is reported as none.

So an audit that could not see everything must not exit `0`. `Find-AdDuplicates` grew an
**exit 30** for it — `exit 0` is a claim, not a default, and `Invoke-AdmSweep` maps anything but
`0` or `10` to *did not complete*. The others record it as **unchecked coverage**, in the section
they already have for what could not be read. A finding still outranks it: `10` means *act on
this*, and returning `30` instead would cast doubt on what was genuinely found.

*Enforced by:* over-fetching one past the limit, so the extra row *is* the signal — `$rows.Count -ge
$limit` cannot tell *exactly `$limit` exist* from *stopped at `$limit`*, and only fires where
somebody remembered to write it. `Reset-AdmSearchTruncated` / `Get-AdmSearchTruncated`, **sticky**
so that a cmdlet running several searches cannot erase its own warning with a later one-row lookup.
Refusals are diagnosed as `READ-TRUNCATED` rather than thrown bare, and that rule has to sit
**above** `SIZE-LIMIT-EXCEEDED`, whose pattern is a superset of it — first match wins, so the
general rule placed first makes the specific one silently unreachable.
`tests/Truncation.Tests.ps1` offline, `tests/live/Invoke-AdmLiveTests.ps1` against a real forest.
Every "the warning fired" check has a matching **high-limit** case: proving only that a detector
*fires* cannot tell a working one from one wired to complain every time, and an audit that cries
incomplete on every run is ignored within a week.

**And the trigger limit is measured, never typed** — this rule caught its own test. `-Limit 1`
looks like the maximally aggressive trigger and is not: it only truncates a read of *two or more*
objects, so it passes or fails according to what the domain holds that minute. A delegation check
"passed" on a lab domain controller only because the domain happened to have an extra OU alive; a default
domain has exactly one. The harness now counts first and derives the limit, and where truncation
**cannot** be forced it prints `SKIP` and says so in its closing line. A lab-sized threshold in
the *test* is the same defect as one in the code, and a skip that reads like a pass would be this
very failure mode committed by the thing meant to detect it.

### Never claim a state you could not observe

Active Directory hides an attribute you may not read exactly as it hides one that was never set. So
`Get-AdmLapsPassword` distinguishes `NoPermission` from `NotManaged` from `NotDeployed` by reading
the expiry, which is not access-controlled — rather than reporting "no password" to someone who
would then redeploy LAPS over a working one. `NoSubnets` is `$null`, not `$false`, when the read was
truncated. This is the scan's "unknown is a distinct answer from pass", and the GUI's three-state
**Protection?** button, in a third place.

### Before something destructive, name the loss — not the action

"Delete this OU?" does not convey that everything inside goes with it, so
`Remove-AdmOrganizationalUnit` counts the children **first** and puts the number in the refusal.
`Restore-AdmObject` refuses a tombstone unless told explicitly, because a restore with the Recycle
Bin off returns an object with the right name and SID, no group memberships, and every appearance of
having worked.

### A refusal must say what to do next, in the message

Not in documentation, and not in a code comment. `Move-AdmObject` on a protected object gives the
exact `Set-AdmObjectProtection` command to clear it. `Get-AdmSubnet` on a truncated read says to
raise `-Limit`. A refusal that leaves someone to guess is only half a safety feature.

### Report per-item outcomes; never a batch-level "done"

Partial application is the defining risk of anything batched. `Import-AdmUserCsv` validates the whole
file before writing anything, returns one object per input row including the skipped ones and why,
and never reports success for a row that failed. A run that fails at row 40 of 200 must not look
like a run that succeeded.

### The mock and the real path must emit the identical field set

A narrower mock object throws under `Set-StrictMode` on the **fixture** path only — which is what the
suites and the GUI demo run on, so the failure lands exactly where it is least expected and never
against a real directory.

*Correction:* `Get-AdmOrganizationalUnit`'s mock branch omitted `GpoLinkCount`.

### Exporting a cmdlet is not shipping a feature

`New-AdmComputer`, `Set-AdmComputer` and `Remove-AdmDomainCredential` were all exported, tested, and
reachable from no CLI verb, GUI control or script. The module loaded, the suites passed, and the
capability did not exist for any user.

*Enforced by:* the reachability check — every export must appear in `adm.ps1`, `gui\` or `scripts\`,
or be on an explicit library allow-list that has to be edited in a diff.

### State the contract you can actually keep

`-Json` with `-WhatIf` puts non-JSON on stdout: PowerShell's `What if:` narration is written straight
to the host, and none of `2>`, `4>`, `5>`, `6>` or `$WhatIfPreference` can suppress or capture it.
The honest contract is therefore "the envelope is the **last** line", not "stdout is JSON".

*Enforced by:* a test asserting both that the last line parses **and** that the whole of stdout does
not — so nobody restores the documentation to a promise the platform will not keep.

### A caveat the caller cannot see is not a caveat

**The machine-readable surface was the last one still silent about truncation.** A cut read
announces itself with `Write-Warning`, which is right for a person at a terminal and useless to
the caller the `-Json` envelope exists for: a script reading stdout never sees the warning stream.
It would take `data` — the first 200 of 3000 accounts — for the domain, and act on it. So the
envelope carries `truncated`, and the help says to check it before trusting `data`.

The general form: **whenever a surface gains a caveat, ask which of its consumers can actually
receive it.** A `Write-Host` is invisible to `-Json`; a `Write-Warning` is invisible to anything
reading stdout; a note on a returned object is invisible to a caller that only reads `.Count`.

*Enforced by:* `tests/Truncation.Tests.ps1` driving `adm.ps1` end to end in a child process — the
field must exist, be `true` on a cut read, and `false` on a complete one and on a command that
reads no directory at all. A flag that is always true carries no more information than one that is
always false.

### Secrets are never logged; the fact of retrieval always is

The value of a LAPS password, a BitLocker key or a generated password appears only in the returned
object. That it was retrieved, by whom and for which machine, is always written — that record is the
entire audit trail for a credential disclosure, and it is worth more than the convenience of
omitting it.

## Rules about the checks themselves

These four came out of asking why a check had passed, not from finding a bug. They are recorded
here because they outlast any individual defect, and because each was already violated by guards
that had been green for hours.

### A guard's blind spot is whatever existed when it was written

Four instances in a single day, all correct on the day they were written and all outlived by the
code within weeks:

| guard | scope when written | code by the time it mattered |
|---|---|---|
| comment-based help scan | 5 named files | 18 files; 4 uncovered ones added after |
| non-ASCII displayed-string scan | 1 GUI file | the defect shipped from `adm.ps1` |
| plain multi-valued read scan | a hand-listed set | the set drifted |
| leaked-return scan | 1 named function | any new action verb was invisible |
| `-Json` envelope shape | the success shape only | failures carry `diagnosis: null` |

**Enumerate the directory; never name the inputs.** A hand-maintained list protects the files
somebody remembered. The countermeasure is not vigilance.

### Widening a guard creates the mode where it succeeds at doing nothing

This is the sharp edge, and it is why the previous rule is only half a fix. `Get-Item` on a named
path either works or throws — it cannot scan nothing. An enumeration *can*: a renamed folder or a
filter that stops matching leaves the check running happily over zero files and reporting PASS.

So **enumerating and adding a control that cannot legitimately be empty are one change, not two.**
Every enumerating check here fails if it finds implausibly few inputs.

That is the silent-empty-result shape — the same one that made a truncated subnet read report "this
site has no subnets" — occurring *inside the guard built against it*.

### A guard must be able to fire, and able not to fire

Both halves, and each was violated separately:

- `if ($members.Count -ge 1500)` in the privileged audit **could never fire**: past 1500 the
  attribute is renamed and the count is `0`, not `1500`. Its presence is what stopped anyone
  looking again.
- `Get-AdmGpo`'s truncation refusal **could not be provoked** — the limit was hardcoded at 50000
  and no reachable estate has that many linked containers. Now a parameter, so it is exercisable
  without being workaroundable.
- A guard that always fires carries exactly as much information as one that never does, so every
  refusal needs a **negative control** proving the clean case does *not* refuse.

**And the negative control is itself a guard, so it needs both properties applied to itself.**
A fault injected to prove a check can fail was appended *after* the target suite's own `exit 0` and
never executed — the check honestly reported success, and for a few seconds that read as the
feature being broken. **Presence is not execution.** Verify that the injected fault actually ran
before trusting what the guard said about it.

### Allow-list what promises not to; never deny-list what may

The leaked-return check first excluded `Get-`, `Test-`, `ConvertTo-` — a deny-list of verbs that
may legitimately return. It immediately fired on correct code: `,(Unprotect-AdmBytes …)`, a
deliberate return, because decrypting *is* producing a value.

A deny-list encodes the accidents of what exists today and needs a hole cut for every awkward case.
The rule that holds is the inverse: `Set-`, `Add-`, `Remove-`, `Clear-`, `Write-` **name themselves
as actions**, so a caller writes them bare and anything they return lands silently in that caller's
output.

`Unprotect-` needing no exemption is the evidence the rule is right. **A correct rule has no
awkward cases, only out-of-scope ones.**

