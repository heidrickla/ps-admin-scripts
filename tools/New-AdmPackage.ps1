<#
.SYNOPSIS
  Build a distributable ADAdmin zip from a commit, with an honest VERSION.txt.

.DESCRIPTION
  Packages the toolkit for a USB stick, a share, or someone else's machine.

  ⛔ IT PACKAGES `git archive HEAD`, NOT THE WORKING DIRECTORY, and that is the point rather
  than an implementation detail. Only TRACKED files can end up in the zip, so a credential
  store, a log directory or a generated copy of an imported script cannot leak into a package
  by accident -- none of them are tracked, so none of them exist as far as git archive is
  concerned. A hand-rolled Copy-Item would ship all three.

  ⚠ THE COROLLARY: UNCOMMITTED CHANGES ARE NOT IN THE PACKAGE. On a dirty tree this builds the
  last commit and says so loudly. That is the safe direction -- a package always corresponds to
  a commit somebody can check out -- but it does mean "I just edited that file" and "that edit
  is in the zip" are different claims. Commit first.

  ⭐ VERSION.txt COUNTS ARE DERIVED, NEVER TYPED. The suite count, the cmdlet count, the error
  catalog size and the script list are all read from the source of truth at build time. The
  previous version of this script carried them as prose and was wrong about two of them within
  a fortnight, which is the ordinary fate of a hand-maintained number.

.EXAMPLE
  tools\New-AdmPackage.ps1
.EXAMPLE
  tools\New-AdmPackage.ps1 -OutputDirectory D:\share -Ref v1.0.0

.NOTES
  EXIT CODES
    0   built (and, with -Verify, the packaged suites passed)
    20  refused -- not a git repository, or the ref does not exist
    21  built, but -Verify FAILED -- the zip exists and does not work
#>
[CmdletBinding()]
param(
    # Where the zip lands. Defaults to the user's temp directory, NOT the repo: a build artefact
    # inside the working tree is one `git add -A` away from being committed.
    [string]$OutputDirectory,
    # Commit, tag or branch to package. HEAD by default.
    [string]$Ref = 'HEAD',
    # ⭐ RUN THE PACKAGE AS A PACKAGE. Extracts the zip that was just built to a fresh directory
    # with NO CLONE PRESENT and runs the offline suites from there.
    #
    # ⛔ THIS IS NOT THE SAME AS RUNNING THE SUITES IN THE REPO, and until 2026-08-28 nobody had
    # ever done it. Every run in this repo's history was from the working tree -- which has a
    # .git directory, a stable path, and whatever happened to be lying around. THREE independent
    # path resolutions have to be right simultaneously for the shipped artefact to work at all:
    # the module finds its root through $PSScriptRoot, each suite finds the repo through
    # Split-Path -Parent $PSScriptRoot, and adm.ps1 locates the module beside itself. None of
    # them had ever been exercised from a path they had not seen.
    [switch]$Verify,
    # ⭐ -Verify RUNS A FAST SUBSET BY DEFAULT, AND THAT IS DELIBERATE. A full pass is ~13 minutes
    # on one runtime and ~26 on both (measured 2026-08-28) -- and a verification step that
    # expensive gets skipped exactly when somebody is in a hurry, which is when it would have
    # caught something. A check people run beats a thorough one they do not.
    #
    # ⚠ THE SUBSET IS NOT AN ARBITRARY SAMPLE. What can only fail from a fresh path is PATH
    # RESOLUTION, and these four exercise all three of them: Module loads the module (its own
    # root), Crypto and Resolution dot-source Private files (each suite finding the repo), and
    # CliGui invokes adm.ps1 (the CLI finding the module beside itself). Every other assertion in
    # the full set is about logic a repo-based run already covers identically.
    [switch]$VerifyFull,
    # Which runtime the -Verify pass uses. 'both' needs pwsh on PATH.
    [ValidateSet('current', 'both')][string]$VerifyOn = 'current',
    [string]$RepoRoot
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Resolved here, not as a param default: $PSScriptRoot is empty during param binding under
# Windows PowerShell 5.1 with -File. See gui\Start-AdmGui.ps1 for the failure it produces.
if (-not $RepoRoot)         { $RepoRoot = Split-Path -Parent $PSScriptRoot }
if (-not $OutputDirectory)  { $OutputDirectory = $env:TEMP }

if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot '.git'))) {
    Write-Error "Not a git repository: $RepoRoot. This packages tracked files only, so it needs one."
    exit 20
}

Push-Location $RepoRoot
try {
    $sha = (& git rev-parse $Ref 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $sha) {
        Write-Error "No such ref '$Ref' in $RepoRoot."
        exit 20
    }
    $sha   = $sha.Trim()
    $short = (& git rev-parse --short $Ref).Trim()
    # `git status --porcelain` prints nothing on a clean tree. @() so an empty result counts 0
    # rather than collapsing to $null.
    $dirty = @(& git status --porcelain).Count -gt 0

    $stage = Join-Path ([System.IO.Path]::GetTempPath()) ("adadmin-pkg-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    try {
        $inner = Join-Path $stage 'inner.zip'
        & git archive --format=zip --prefix=ADAdmin/ $Ref -o $inner
        if ($LASTEXITCODE -ne 0) { throw "git archive failed for $Ref." }

        $expand = Join-Path $stage 'expand'
        Expand-Archive -LiteralPath $inner -DestinationPath $expand -Force
        Remove-Item $inner -Force

        $payload = Join-Path $expand 'ADAdmin'

        # --- derived facts ----------------------------------------------------------------------
        # Read from what was just PACKAGED, not from the working tree, so the numbers describe
        # the zip rather than the machine that built it.

        $suiteNames = @()
        $runner = Join-Path $payload 'tests\Invoke-AdmTests.ps1'
        if (Test-Path -LiteralPath $runner) {
            $m = [regex]::Match((Get-Content -LiteralPath $runner -Raw), '\$suites\s*=\s*@\(([^)]*)\)')
            if ($m.Success) {
                $suiteNames = @([regex]::Matches($m.Groups[1].Value, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
            }
        }

        $cmdletCount = 0
        $manifest = Join-Path $payload 'ADAdmin\ADAdmin.psd1'
        if (Test-Path -LiteralPath $manifest) {
            try { $cmdletCount = @((Import-PowerShellDataFile -LiteralPath $manifest).FunctionsToExport).Count } catch { }
        }

        # The catalog is code, not data, so its size comes from loading the module. Done in a
        # CHILD process: importing a module into the build session leaves it loaded, and a stale
        # in-memory copy is exactly the kind of thing that makes a build non-reproducible.
        $catalogCount = 0
        try {
            $psd1 = $manifest -replace "'", "''"
            $out = & powershell.exe -NoProfile -NonInteractive -Command `
                "Import-Module '$psd1' -Force; (Get-AdmErrorCatalog).Count" 2>$null
            [void][int]::TryParse(([string]$out).Trim(), [ref]$catalogCount)
        } catch { }

        $scriptNames = @()
        $scriptDir = Join-Path $payload 'scripts'
        if (Test-Path -LiteralPath $scriptDir) {
            $scriptNames = @(Get-ChildItem -LiteralPath $scriptDir -Filter '*.ps1' | ForEach-Object { $_.BaseName } | Sort-Object)
        }

        $treeLine = if ($dirty) {
            "$sha  (built from a DIRTY working tree -- uncommitted changes are NOT in this package)"
        } else { $sha }

        $version = @"
ADAdmin -- portable multi-forest Active Directory administration
================================================================
Commit    : $treeLine
Built     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') (Central)
Contents  : $($cmdletCount) exported cmdlets, $($scriptNames.Count) scripts, $($suiteNames.Count) test suites, $($catalogCount) recognised failures

FIRST RUN
---------
1. Unblock the files. Windows marks anything copied from a share or a download as untrusted,
   and PowerShell then refuses to run it:

       Get-ChildItem <this folder> -Recurse -File | Unblock-File

   ADAdmin detects this itself -- 'adm scan' reports it as ADM-SYS-003 and 'adm fix' clears it.

2. Check the machine before anything else. This changes nothing:

       powershell -NoProfile -ExecutionPolicy Bypass -File .\adm.ps1 scan -Scope machine

3. Create a credential store and register a domain:

       .\adm.ps1 store init -Name <your-name>
       .\adm.ps1 domain add -Name corp -Dns corp.example.com -Dc dc01.corp.example.com
       .\adm.ps1 domain set-cred -Name corp -Tier read -Default
       .\adm.ps1 domain test -Target corp.example.com -Deep

4. Try it without touching a directory at all:

       `$env:ADADMIN_PROVIDER = 'mock'
       .\adm.ps1 user list -Target corp.example.com

SCRIPTS IN THIS BUILD
---------------------
$(($scriptNames | ForEach-Object { "  $_" }) -join "`r`n")

Run any of them across EVERY registered forest at once:

       .\scripts\Invoke-AdmSweep.ps1 -Script Get-AdPrivilegedAccess

WHAT IS VERIFIED, AND WHAT IS NOT
---------------------------------
VERIFIED against a real Windows Server 2025 domain controller (forest functional level 7):
  bind, user/group/computer search, account create, enable/disable, unlock,
  password reset (and the new password proven to authenticate), FSMO roles,
  functional levels, domain password policy, group membership, the SPN scan,
  remote machine-identity collection, the stale-computer sweep, and the
  privileged-access audit -- the last of those verified by BUILDING a real nested
  group chain to a privileged group, confirming it was found with the full path,
  and removing it again.
VERIFIED offline: $($suiteNames.Count) test suites, green on Windows PowerShell 5.1 AND PowerShell 7.
  ($($suiteNames -join ', '))

NOT VERIFIED -- treat these as first-run-is-the-test:
  * Your production forests. All directory testing was against ONE lab forest with ONE DC.
    In particular LDAPS was never made to work there (the DC's certificate cannot match an IP
    address), so the LDAPS code path is the least exercised part of the toolkit.
  * Domain JOIN, LEAVE and RENAME in Set-ComputerDomainMembership.ps1. Testing them means
    unjoining a working machine. Run them on a disposable machine first.
  * The GUI has never been seen rendered. It opens with a real window and every control and
    style resolves, but the development environment has no interactive desktop.

KNOWN BEHAVIOUR WORTH READING BEFORE PRODUCTION
-----------------------------------------------
  * Password reset needs an ENCRYPTED channel. LDAPS on 636, or port 389 with sealing, which
    this toolkit always requests. It writes unicodePwd over LDAP and never uses ADSI SetPassword,
    which falls back to RPC and fails from outside the network.
  * Stale-account sweeps refuse a window under 30 days: lastLogonTimestamp replicates lazily and
    can be ~14 days behind, so a shorter window disables people who signed in last week.
    krbtgt, Guest and Administrator are excluded by default.
  * A domain member is configured to sync time from the DOMAIN HIERARCHY, not a manual peer list.
  * Leaving a domain requires a local administrator password, which is set and PROVEN to
    authenticate before the machine unjoins.
  * Find-StaleComputers judges a machine on its MACHINE ACCOUNT PASSWORD AGE, not last logon.
    A live member rotates that password every 30 days and it replicates normally, whereas
    lastLogonTimestamp is lazy and can be ~14 days behind. If your estate has DISABLED machine
    password rotation by policy, that inverts -- use -By LastLogon there. It disables and never
    deletes. DOMAIN CONTROLLERS ARE EXCLUDED AND CANNOT BE DISABLED, with no override: a DC
    looks idle by every measure a staleness sweep uses.
  * Get-AdPrivilegedAccess is READ-ONLY and has no fix mode by design. It does NOT read ACLs on
    the domain head, so rights delegated directly -- DCSync, or write access to an OU -- are not
    covered. A clean report from it is not a clean bill of health.
  * Invoke-AdmSweep treats a forest that did not answer as FAILED, never as clean, and exits 20
    on a partial sweep. Sixteen of twenty forests reporting nothing is not the same as
    twenty reporting nothing.

DOCS
----
  docs\deployment-usb-and-smb.md    carrying it, execution policy, multi-admin, security posture
  docs\active-directory-traps.md    every AD trap here was measured against a real DC
  docs\error-catalog.md             every failure the toolkit can explain, generated from the code
  docs\script-import.md             bringing your existing scripts in
  docs\powershell-51-traps.md       the 5.1-vs-7 failures, by symptom

"@
        # ⚠ NORMALISE THE LINE ENDINGS. The here-string above carries whatever this .ps1 has on
        # disk (LF, since git normalises the repo), while the interpolated -join used CRLF -- so
        # VERSION.txt came out MIXED, and only the script list had CRLF. It is a plain-text file
        # a Windows admin opens by double-clicking, so it is CRLF throughout.
        $version = ($version -split "`r?`n") -join "`r`n"

        # UTF8Encoding($false) = no BOM. Set-Content -Encoding UTF8 emits one on 5.1.
        [System.IO.File]::WriteAllText((Join-Path $payload 'VERSION.txt'), $version,
                                       (New-Object System.Text.UTF8Encoding($false)))

        if (-not (Test-Path -LiteralPath $OutputDirectory)) {
            New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
        }
        $out = Join-Path $OutputDirectory "ADAdmin-$short.zip"
        if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Force }
        Compress-Archive -Path $payload -DestinationPath $out -CompressionLevel Optimal

        if ($dirty) {
            Write-Warning ("The working tree has uncommitted changes. This package contains $short " +
                           'and NOT those changes -- git archive reads the commit, not the disk. ' +
                           'Commit and rebuild if you meant to ship them.')
        }

        # --- run the artefact, if asked ------------------------------------------------------
        $verified = $null
        if ($Verify) {
            # ⛔ EXTRACT THE ZIP, do not reuse $payload. $payload is what went IN; the zip is what
            # comes OUT, and the round trip is the thing a user actually performs. Extracting it
            # to a directory with no clone in sight is the whole point -- nothing here may resolve
            # a path by accidentally finding the repo it was built from.
            $vroot = Join-Path ([System.IO.Path]::GetTempPath()) ("adadmin-verify-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
            try {
                Expand-Archive -LiteralPath $out -DestinationPath $vroot -Force
                $vrunner = Join-Path $vroot 'ADAdmin\tests\Invoke-AdmTests.ps1'
                if (-not (Test-Path -LiteralPath $vrunner)) {
                    # A control that cannot legitimately be absent: the runner is packaged, so a
                    # missing one means the extraction or the layout changed -- and without this
                    # the verification would "pass" by running nothing at all.
                    throw "The packaged tree has no tests\Invoke-AdmTests.ps1 -- nothing was verified."
                }

                # ⚠ A CHILD PROCESS, and not only for cleanliness. The suites import the module,
                # and this session may already have a DIFFERENT copy loaded from the working tree.
                # Running in-process would test the module we already had rather than the one in
                # the zip, which is the exact substitution this check exists to rule out.
                Write-Host "  verifying the packaged artefact at $vroot ..." -ForegroundColor DarkGray
                if ($VerifyFull) {
                    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
                        -File $vrunner -On $VerifyOn
                    $verified = ($LASTEXITCODE -eq 0)
                } else {
                    $subset = @('Module', 'Crypto', 'Resolution', 'CliGui')
                    $vtests = Join-Path $vroot 'ADAdmin\tests'
                    $missing = @($subset | Where-Object { -not (Test-Path -LiteralPath (Join-Path $vtests "$_.Tests.ps1")) })
                    if ($missing.Count) {
                        # ⛔ A control that cannot legitimately be empty. Without it, a rename or a
                        # layout change makes the subset match nothing, run nothing, and PASS --
                        # the silent-empty-result shape inside the verification itself.
                        throw "The packaged tree is missing suite(s): $($missing -join ', '). Nothing was verified."
                    }
                    $verified = $true
                    foreach ($s in $subset) {
                        Write-Host "    $s" -ForegroundColor DarkGray
                        & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
                            -File (Join-Path $vtests "$s.Tests.ps1") | Out-Null
                        if ($LASTEXITCODE -ne 0) {
                            Write-Warning "  packaged suite '$s' FAILED when run from the extracted zip."
                            $verified = $false
                        }
                    }
                }
            } catch {
                $verified = $false
                Write-Warning "Verification could not run: $($_.Exception.Message)"
            } finally {
                Remove-Item -LiteralPath $vroot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        [pscustomobject]@{
            Path     = $out
            Commit   = $short
            SizeKB   = [math]::Round((Get-Item -LiteralPath $out).Length / 1KB)
            Files    = @(Get-ChildItem -LiteralPath $payload -Recurse -File).Count
            Suites   = $suiteNames.Count
            Cmdlets  = $cmdletCount
            Scripts  = $scriptNames.Count
            Catalog  = $catalogCount
            TreeDirty = $dirty
            # $null means it was never asked for -- distinct from $false, which means it was asked
            # for and the packaged artefact did not work.
            Verified = $verified
        }

        if ($Verify -and -not $verified) {
            Write-Warning "The package was BUILT but did not pass its own suites when run from the extracted zip. The file at $out exists and should not be shipped."
            exit 21
        }
    }
    finally { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
}
finally { Pop-Location }

exit 0
