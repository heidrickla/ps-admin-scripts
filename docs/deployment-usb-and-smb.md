# Carrying the toolkit — USB stick and SMB share

Nothing is installed. The tree runs from wherever it sits; only the store location and the
execution policy need thought.

## Layout on the medium

```
E:\                          <- USB root, or \\server\share\adm
  adm.ps1                    <- CLI entry point
  ADAdmin\                   <- the module
  gui\                       <- the window
  tools\                     <- interactive shell
  tests\
  adadmin-store.json         <- the encrypted store, BESIDE the module tree
```

`Get-AdmDefaultStorePath` looks in this order:

1. **`$env:ADADMIN_STORE`** — explicit always wins
2. **one level above the module** — i.e. the USB root in the layout above
3. **`%APPDATA%\ADAdmin\`** — fallback for a read-only medium

So a USB stick carries its own store with no configuration. A **read-only share** does not: set
`ADADMIN_STORE` to somewhere writable, or every write fails with a message saying exactly that.

## Running it

```powershell
E:\adm.ps1 store status
E:\adm.ps1 gui
```

From a share, use the UNC path directly — `$PSScriptRoot` resolves correctly over UNC:

```powershell
\\server\share\adm\adm.ps1 domain list
```

## The two things that actually block a first run

**1. Execution policy.** Scripts from a share or a downloaded stick are untrusted. The toolkit
never asks you to weaken the machine policy; scope the bypass to the invocation:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File E:\adm.ps1 store status
```

**2. Mark of the Web.** Files that arrived via a browser or an untrusted share carry a
`Zone.Identifier` stream and are blocked individually. Clear it once, on the medium:

```powershell
Get-ChildItem E:\ -Recurse -File | Unblock-File
```

A UNC path is in the **Internet zone** by default, which produces the same block even for files
you never downloaded. If a share is a permanent home for this, add the server to Local Intranet
rather than unblocking after every update.

## Multi-admin on shared media

Each admin has their **own passphrase** over a shared data key, so a share works without anyone
learning anyone else's secret:

```powershell
adm store init -Name alice          # first admin creates it
adm store add-admin -Name bob       # bob sets his own passphrase, alice's is unchanged
```

**`remove-admin` is not retroactive revocation.** It stops that passphrase opening *this file
from now on*. Anyone holding an older copy of the store plus their old passphrase can still open
that copy, and anything they already read is already disclosed. **To actually revoke, rotate the
AD credentials the store held.**

**Concurrent writes are last-write-wins.** Two admins editing the registry on one share can
overwrite each other; the file is written atomically so it never *corrupts*, but there is no
merge and no lock. Co-ordinate, or give each admin their own copy.

## Security posture, stated plainly

A single file on removable media holding administrative credentials for multiple forests is a
high-value target. What the design does and does not do:

- **Does:** AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC, verified before decrypt), PBKDF2-SHA256
  at 310k iterations per admin, unique salt and IV per wrap, nothing readable without a
  passphrase, auto-lock after idle, secrets never printed or returned in output objects.
- **Does not:** protect against a keylogger on the target PC, a weak passphrase, or someone
  copying the file and attacking it offline at their leisure. **Passphrase strength is the whole
  control** — the file is assumed to be obtainable.
- **Use credential tiers.** Store a least-privilege `read` account and a separate `write`
  account, and do not let one credential do both. A compromised store is bad; a compromised store
  holding Domain Admin for twenty forests is a different category of bad.

## Directory backend

```powershell
$env:ADADMIN_PROVIDER = 'mock'   # fixture data, for demos and tests
$env:ADADMIN_PROVIDER = 'adsi'   # real directories (default)
```

The mock provider is labelled in the CLI (`provider: mock`), in the GUI chip (amber, not grey),
and in `Test-AdmDomain` output (`status: mock — proves nothing about a real DC`). That labelling
is deliberate: a demo that looks like production is how fixture output gets acted on.
