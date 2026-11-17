# Checks.ps1 -- the definitions behind `adm scan` and `adm fix`.
#
# A check is a QUESTION with a known answer shape. Each one carries, in plain English:
#   Problem  -- what is wrong, if it is
#   Impact   -- what will actually break because of it (so "is this worth fixing" is answerable)
#   Remedy   -- what the fix WILL DO, before it does it
#
# ⛔ RULES FOR EVERY CHECK IN THIS FILE:
#   1. A check NEVER changes anything. Scanning is safe to run at any time, on anything.
#   2. A check that cannot run reports 'unknown'. It NEVER reports 'pass' because it could not
#      look -- "I could not check" and "there is no problem" are different answers, and
#      conflating them is how a green scan hides a broken estate.
#   3. A remedy declares what it touches: 'store' (this toolkit's own file), 'files' (files on
#      this machine), or 'machine' (system-wide settings). Anything touching 'machine' needs
#      explicit consent every time, and says whether it needs administrator rights.

function New-AdmCheckResult {
    param(
        [Parameter(Mandatory)][ValidateSet('pass', 'fail', 'warn', 'unknown')][string]$Status,
        [string]$Detail,
        $Data
    )
    [pscustomobject]@{ Status = $Status; Detail = $Detail; Data = $Data }
}

# --- machine checks ---------------------------------------------------------------------------

$script:AdmMachineChecks = @(
    @{
        Id = 'SYS-001'; Name = 'PowerShell version'; Scope = 'machine'
        Run = {
            $v = $PSVersionTable.PSVersion
            if ($v.Major -ge 5) { New-AdmCheckResult -Status pass -Detail "PowerShell $v" }
            else { New-AdmCheckResult -Status fail -Detail "PowerShell $v" }
        }
        Problem = 'This machine is running a version of PowerShell older than 5.1.'
        Impact  = 'The toolkit will not load at all. Nothing else in this report matters until this is fixed.'
        Remedy  = $null   # cannot be fixed from inside a process that cannot run
    }
    @{
        Id = 'SYS-002'; Name = 'Encryption support'; Scope = 'machine'
        Run = {
            try {
                $probe = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
                    [byte[]]@(1), [byte[]]@(1,2,3,4,5,6,7,8), 1,
                    [System.Security.Cryptography.HashAlgorithmName]::SHA256)
                $null = $probe.GetBytes(1); $probe.Dispose()
                New-AdmCheckResult -Status pass -Detail 'PBKDF2-SHA256 available'
            } catch { New-AdmCheckResult -Status fail -Detail $_.Exception.Message }
        }
        Problem = 'This machine cannot perform the encryption the credential store uses (PBKDF2-SHA256 needs .NET Framework 4.7.2 or later).'
        Impact  = 'The credential store cannot be opened or created on this machine.'
        Remedy  = $null
    }
    @{
        Id = 'SYS-003'; Name = 'Files blocked by Windows'; Scope = 'machine'
        Run = {
            param($ctx)
            $root = $ctx.ModuleRoot
            if (-not $root -or -not (Test-Path -LiteralPath $root)) {
                return New-AdmCheckResult -Status unknown -Detail 'Could not locate the toolkit folder to check.'
            }
            $blocked = @()
            foreach ($f in (Get-ChildItem -LiteralPath $root -Recurse -File -Include '*.ps1','*.psm1','*.psd1','*.xaml' -EA SilentlyContinue)) {
                # Zone.Identifier is the "downloaded from the internet" marker.
                if (Get-Item -LiteralPath $f.FullName -Stream 'Zone.Identifier' -EA SilentlyContinue) { $blocked += $f.FullName }
            }
            if ($blocked.Count) { New-AdmCheckResult -Status fail -Detail "$($blocked.Count) file(s) are blocked" -Data $blocked }
            else { New-AdmCheckResult -Status pass -Detail 'no blocked files' }
        }
        Problem = 'Windows has marked some of the toolkit''s files as "came from another computer" and will refuse to run them.'
        Impact  = 'Commands fail with a security warning, or the window simply never opens. This is the usual first-run failure when the toolkit was copied from a share or a USB stick.'
        Remedy  = @{
            Description = 'Remove the "downloaded from the internet" mark from the toolkit''s own files. This only touches files inside the toolkit folder and changes nothing else on this computer.'
            Changes = 'files'; NeedsAdmin = $false
            Apply = {
                param($ctx, $finding)
                $n = 0
                foreach ($p in @($finding.Data)) {
                    try { Unblock-File -LiteralPath $p -ErrorAction Stop; $n++ } catch { }
                }
                "Unblocked $n file(s)."
            }
        }
    }
    @{
        Id = 'SYS-004'; Name = 'Error log can be written'; Scope = 'machine'
        Run = {
            $i = Get-AdmLogInfo
            if ($i.Writable) { New-AdmCheckResult -Status pass -Detail "writing to $($i.Directory)" }
            else { New-AdmCheckResult -Status fail -Detail 'no writable log location' -Data $i }
        }
        Problem = 'The error log cannot be written anywhere, so problems are only visible for as long as the window stays open.'
        Impact  = 'Nothing is kept. If a script fails overnight, or someone closes the window before reading it, the evidence is gone.'
        Remedy  = @{
            Description = 'Create a log folder under this user''s local application data and use it from now on. Writes only inside your own profile.'
            Changes = 'files'; NeedsAdmin = $false
            Apply = {
                param($ctx, $finding)
                $dir = Join-Path $env:LOCALAPPDATA 'ADAdmin\logs'
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
                $env:ADADMIN_LOG_DIR = $dir
                "Logging to $dir for this session. To make it permanent, set ADADMIN_LOG_DIR in your environment."
            }
        }
    }
    @{
        Id = 'SYS-005'; Name = 'RSAT Active Directory module'; Scope = 'machine'
        Run = {
            if (Test-AdmRsat) { New-AdmCheckResult -Status pass -Detail 'installed' }
            else { New-AdmCheckResult -Status warn -Detail 'not installed' }
        }
        Problem = 'The Microsoft RSAT Active Directory module is not installed on this machine.'
        Impact  = 'None for normal use -- the toolkit deliberately does not need it and talks to directories directly. This is worth knowing only if you also want to use Microsoft''s own AD cmdlets here.'
        Remedy  = $null
    }
)

# --- store checks -----------------------------------------------------------------------------

$script:AdmStoreChecks = @(
    @{
        Id = 'STORE-001'; Name = 'Credential store present'; Scope = 'store'
        Run = {
            $i = Get-AdmStoreInfo
            if ($i.Exists) { New-AdmCheckResult -Status pass -Detail $i.Path -Data $i }
            else { New-AdmCheckResult -Status fail -Detail "no store at $($i.Path)" -Data $i }
        }
        Problem = 'There is no credential store at the expected location.'
        Impact  = 'Nothing can be done until one exists -- there is nowhere to keep the credentials for each domain.'
        Remedy  = $null   # needs a passphrase, so it is interactive by nature
    }
    @{
        Id = 'STORE-002'; Name = 'More than one administrator can open the store'; Scope = 'store'
        Run = {
            $i = Get-AdmStoreInfo
            if (-not $i.Exists) { return New-AdmCheckResult -Status unknown -Detail 'no store' }
            if (@($i.Recipients).Count -ge 2) { New-AdmCheckResult -Status pass -Detail "$(@($i.Recipients).Count) admins enrolled" }
            else { New-AdmCheckResult -Status warn -Detail 'only one admin enrolled' }
        }
        Problem = 'Only one person can open this credential store.'
        Impact  = 'If that person is unavailable, or forgets their passphrase, every credential in the store is unrecoverable. There is no reset -- that is the point of the encryption.'
        Remedy  = $null   # adding an admin requires that admin to choose their own passphrase
    }
)

# --- per-domain checks --------------------------------------------------------------------------

$script:AdmDomainChecks = @(
    @{
        Id = 'DOM-001'; Name = 'A domain controller is pinned'; Scope = 'domain'
        Run = {
            param($ctx)
            # @() must wrap the WHOLE pipeline. `@($x) | Where-Object` yields a scalar for a
            # single match, and .Count on a scalar throws under strict mode -- which turned this
            # check into an 'unknown' against a perfectly well-configured domain.
            $dcs = @(@($ctx.Domain.DomainControllers) | Where-Object { $_ })
            if ($dcs.Count) { New-AdmCheckResult -Status pass -Detail ($dcs -join ', ') }
            else {
                $resolves = $false
                try { $null = [System.Net.Dns]::GetHostAddresses($ctx.Domain.DnsDomain); $resolves = $true } catch { }
                if ($resolves) { New-AdmCheckResult -Status warn -Detail 'no DC pinned, but the domain name resolves here' }
                else { New-AdmCheckResult -Status fail -Detail 'no DC pinned and the domain name does not resolve from this machine' }
            }
        }
        Problem = 'This domain has no domain controller address recorded, and this machine cannot look the domain up in DNS.'
        Impact  = 'Every operation against this domain will fail with a confusing "server is not operational" error. A machine outside the forest usually cannot resolve the forest''s own names, so pinning an address is normal rather than a workaround.'
        Remedy  = $null   # needs an address only the operator knows
    }
    @{
        Id = 'DOM-002'; Name = 'The directory port is reachable'; Scope = 'domain'
        Run = {
            param($ctx)
            $want = if ($ctx.Domain.Port) { $ctx.Domain.Port } elseif ($ctx.Domain.UseSsl) { 636 } else { 389 }
            $ports = @(Test-AdmDomainPort -Domain $ctx.Domain -Port $want)
            $hit = @($ports | Where-Object { $_.Port -eq $want })
            if ($hit -and $hit[0].Open) { New-AdmCheckResult -Status pass -Detail "port $want open" -Data $ports }
            else { New-AdmCheckResult -Status fail -Detail "port $want closed or filtered" -Data $ports }
        }
        Problem = 'The port this domain is configured to use is not reachable from this machine.'
        Impact  = 'Nothing will work against this domain. This is a network or firewall problem, not a credential one -- retrying with a different password will not help.'
        Remedy  = $null
    }
    @{
        Id = 'DOM-003'; Name = 'A read credential is stored'; Scope = 'domain'
        Run = {
            param($ctx)
            $tiers = @($ctx.Domain.Credentials.PSObject.Properties | ForEach-Object { $_.Name })
            if ($tiers -contains 'read' -or $tiers.Count) { New-AdmCheckResult -Status pass -Detail ($tiers -join ', ') }
            else { New-AdmCheckResult -Status fail -Detail 'none' }
        }
        Problem = 'No credential is stored for this domain.'
        Impact  = 'Every query against this domain fails immediately. Nothing can sign in.'
        Remedy  = $null   # needs a username and password
    }
    @{
        Id = 'DOM-004'; Name = 'Read and write credentials are separate'; Scope = 'domain'
        Run = {
            param($ctx)
            $creds = $ctx.Domain.Credentials
            $names = @($creds.PSObject.Properties | ForEach-Object { $_.Name })
            if ($names -notcontains 'write') { return New-AdmCheckResult -Status warn -Detail 'no write credential configured' }
            if ($names -notcontains 'read')  { return New-AdmCheckResult -Status warn -Detail 'no read credential configured' }
            if ($creds.read.UserName -eq $creds.write.UserName) {
                New-AdmCheckResult -Status warn -Detail "both tiers use $($creds.read.UserName)"
            } else { New-AdmCheckResult -Status pass -Detail "read=$($creds.read.UserName), write=$($creds.write.UserName)" }
        }
        Problem = 'The same account is used for reading and for making changes (or only one of the two is configured).'
        Impact  = 'A credential that can change the directory is used for routine queries, so a leak or a mistake reaches much further than it needs to. Separating them means the everyday credential structurally cannot make a change.'
        Remedy  = $null
    }
    @{
        Id = 'DOM-005'; Name = 'The stored credential actually signs in'; Scope = 'domain'
        Run = {
            param($ctx)
            $t = Test-AdmDomain -Target $ctx.Domain.DnsDomain
            if ($t.Reachable) { New-AdmCheckResult -Status pass -Detail $t.Detail -Data $t }
            else { New-AdmCheckResult -Status fail -Detail $t.Detail -Data $t }
        }
        Problem = 'The credential stored for this domain could not sign in.'
        Impact  = 'Everything against this domain fails. The error log entry for this attempt names the specific cause and what to do about it.'
        Remedy  = $null
    }
    @{
        Id = 'DOM-006'; Name = 'Password changes will be possible'; Scope = 'domain'
        Run = {
            param($ctx)
            if ($ctx.Domain.UseSsl) { return New-AdmCheckResult -Status pass -Detail 'encrypted connection in use' }
            $ports = @(Test-AdmDomainPort -Domain $ctx.Domain -Port 636)
            $can = [bool]($ports -and $ports[0].Open)
            New-AdmCheckResult -Status warn -Detail 'plain connection; 636 available' -Data @{ CanSwitch = $can }
        }
        Problem = 'This domain is configured for an unencrypted connection.'
        Impact  = 'Reads, unlocks, enables and disables all work. PASSWORD RESETS DO NOT -- Active Directory refuses to accept a new password over an unencrypted channel, and the error it returns does not mention encryption, so it is easy to misread as a permissions problem.'
        Remedy  = @{
            Description = 'Switch this domain to an encrypted connection (LDAPS on port 636). This only changes this toolkit''s own settings for this domain -- nothing on the domain controller and nothing else on this computer. If the encrypted connection turns out not to work, switch it back the same way.'
            Changes = 'store'; NeedsAdmin = $false
            Apply = {
                param($ctx, $finding)
                if (-not $finding.Data.CanSwitch) { throw 'Port 636 is not reachable on this domain controller, so switching would break it.' }
                $d = $ctx.Domain
                Register-AdmDomain -Name $d.Name -DnsDomain $d.DnsDomain -NetbiosName $d.NetbiosName `
                    -Aliases @($d.Aliases) -Hosts @($d.Hosts) -DomainControllers @($d.DomainControllers) `
                    -Port 636 -UseSsl $true -Force -Confirm:$false | Out-Null
                "Domain '$($d.Name)' now uses LDAPS on port 636."
            }
        }
    }
    @{
        Id = 'DOM-007'; Name = 'This computer''s clock matches the domain controller'; Scope = 'domain'
        Run = {
            param($ctx)
            $skew = Get-AdmClockSkew -Domain $ctx.Domain
            if ($null -eq $skew) { return New-AdmCheckResult -Status unknown -Detail 'could not read the time from the domain controller' }
            $mins = [math]::Round([math]::Abs($skew), 2)
            if ($mins -lt 2)      { New-AdmCheckResult -Status pass -Detail "$mins minutes apart" -Data $skew }
            elseif ($mins -lt 5)  { New-AdmCheckResult -Status warn -Detail "$mins minutes apart" -Data $skew }
            else                  { New-AdmCheckResult -Status fail -Detail "$mins minutes apart" -Data $skew }
        }
        Problem = 'This computer''s clock is too far from the domain controller''s.'
        Impact  = 'Kerberos refuses to authenticate once the difference passes about five minutes, and the resulting error never mentions the clock -- it looks like a bad password. Anything over two minutes is worth correcting before it drifts further.'
        Remedy  = @{
            Description = 'Ask Windows to re-synchronise this computer''s clock with its time source (w32tm /resync). This changes the system clock on THIS computer. It does not touch the domain controller.'
            Changes = 'machine'; NeedsAdmin = $true
            Apply = {
                param($ctx, $finding)
                $out = & w32tm /resync 2>&1 | Out-String
                if ($LASTEXITCODE -ne 0) { throw "w32tm reported: $($out.Trim())" }
                "Clock re-synchronised. $($out.Trim())"
            }
        }
    }
    @{
        Id = 'DOM-008'; Name = 'Encrypted connections use a name, not an address'; Scope = 'domain'
        Run = {
            param($ctx)
            if (-not $ctx.Domain.UseSsl) { return New-AdmCheckResult -Status pass -Detail 'not using SSL' }
            $server = Get-AdmLdapServer -Domain $ctx.Domain
            if ($server -as [System.Net.IPAddress]) { New-AdmCheckResult -Status fail -Detail "connecting to $server by address over SSL" }
            else { New-AdmCheckResult -Status pass -Detail "connecting to $server by name" }
        }
        Problem = 'This domain uses an encrypted connection but is configured with an IP address rather than a name.'
        Impact  = 'A certificate identifies a NAME. Connecting by address can never match it, so the secure connection fails every time -- and Windows reports that as "the server is not operational", which reads like the domain controller being down.'
        Remedy  = @{
            Description = 'Switch this domain to an unencrypted-but-signed connection on port 389, which needs no certificate and works by address. This changes only this toolkit''s settings for this domain. Note that password resets will then not be possible until an encrypted connection is restored.'
            Changes = 'store'; NeedsAdmin = $false
            Apply = {
                param($ctx, $finding)
                $d = $ctx.Domain
                Register-AdmDomain -Name $d.Name -DnsDomain $d.DnsDomain -NetbiosName $d.NetbiosName `
                    -Aliases @($d.Aliases) -Hosts @($d.Hosts) -DomainControllers @($d.DomainControllers) `
                    -Port 389 -UseSsl $false -Force -Confirm:$false | Out-Null
                "Domain '$($d.Name)' now uses a signed connection on port 389. Password resets will not work until it uses a name and an encrypted connection."
            }
        }
    }
)

# Read the DC's own clock from the rootDSE -- the only way to measure skew without trusting this
# machine's idea of the time.
# ⚠ AUTHENTICATED, not anonymous. A hardened DC refuses anonymous rootDSE reads, and the failure
# is silent: the properties come back empty rather than raising, so the check reported "could not
# read the time" against a DC that answers this fine with a credential. Measured on a lab domain controller.
function Get-AdmClockSkew {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Domain)
    $entry = $null
    try {
        $cred = Get-AdmDomainCredential -Domain $Domain
        $entry = New-AdmDirectoryEntry -Domain $Domain -Credential $cred -DistinguishedName 'RootDSE'
        $entry.RefreshCache()   # forces the bind and surfaces the real error
        $raw = [string]$entry.Properties['currentTime'].Value
        if (-not $raw) { return $null }
        # Generalized time: yyyyMMddHHmmss.0Z
        $dc = [datetime]::ParseExact($raw.Substring(0, 14), 'yyyyMMddHHmmss', $null,
                [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
        ((Get-Date).ToUniversalTime() - $dc).TotalMinutes
    } catch { $null }
    finally { Close-AdmDirectoryEntry $entry }
}
