# Store.ps1 -- the encrypted-at-rest domain registry, and the unlocked session state.
#
# On disk: one JSON envelope. Recipients hold per-admin wraps of a single data key; the payload
# is everything else, sealed once. Nothing readable without a passphrase, so the file is safe to
# carry on a USB stick or leave on a share -- which is the entire point of the toolkit.

$script:AdmStoreSchema = 1
$script:AdmPayloadAad  = 'adm-payload:v1'

# Session state. Deliberately module-scoped and deliberately clearable: an unlocked store means
# a decrypted data key is in this process, and that should have an end.
$script:AdmSession = $null

function Get-AdmDefaultStorePath {
    <#
      Order matters and is chosen for the carry cases:
        1. ADADMIN_STORE            -- explicit wins, always
        2. beside the module root   -- the USB / share case: module at X:\ADAdmin, store at X:\
        3. %APPDATA%                -- last resort on a read-only medium
    #>
    [OutputType([string])]
    param()
    if ($env:ADADMIN_STORE) { return $env:ADADMIN_STORE }
    if ($script:AdmModuleRoot) {
        # GetDirectoryName, not Split-Path -LiteralPath -Parent -- see Write-AdmFileAtomic.
        $beside = Join-Path ([System.IO.Path]::GetDirectoryName($script:AdmModuleRoot)) 'adadmin-store.json'
        return $beside
    }
    Join-Path $env:APPDATA 'ADAdmin\adadmin-store.json'
}

function New-AdmEmptyData {
    [pscustomobject]@{ domains = @() }
}

function Read-AdmEnvelope {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "No credential store at '$Path'. Create one with Initialize-AdmStore."
    }
    $raw = [System.IO.File]::ReadAllText($Path, (Get-AdmUtf8Encoding))
    try { $env = $raw | ConvertFrom-Json }
    catch { throw "The store at '$Path' is not valid JSON: $($_.Exception.Message)" }

    if ($env.format -ne 'ADAdmin-store') {
        throw "'$Path' is not an ADAdmin store (format='$($env.format)')."
    }
    if ([int]$env.schema -gt $script:AdmStoreSchema) {
        throw ("The store at '$Path' is schema $($env.schema); this build understands " +
               "$($script:AdmStoreSchema). Upgrade the toolkit rather than downgrading the store.")
    }
    $env
}

function Write-AdmEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Envelope
    )
    $Envelope.modified = (Get-Date).ToUniversalTime().ToString('o')
    $json = $Envelope | ConvertTo-Json -Depth 12
    try { Write-AdmFileAtomic -Path $Path -Content $json }
    catch {
        throw ("Could not write the store to '$Path': $($_.Exception.Message). " +
               "If this is a read-only share, point ADADMIN_STORE at a writable location.")
    }
}

function New-AdmEnvelope {
    param([Parameter(Mandatory)]$Recipients, [Parameter(Mandatory)]$Payload)
    [pscustomobject]@{
        format     = 'ADAdmin-store'
        schema     = $script:AdmStoreSchema
        created    = (Get-Date).ToUniversalTime().ToString('o')
        modified   = (Get-Date).ToUniversalTime().ToString('o')
        recipients = @($Recipients)
        payload    = $Payload
    }
}

function Protect-AdmPayload {
    param([Parameter(Mandatory)][byte[]]$DataKey, [Parameter(Mandatory)]$Data)
    $json = $Data | ConvertTo-Json -Depth 12
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    try { Protect-AdmBytes -Key $DataKey -Plaintext $bytes -Aad $script:AdmPayloadAad }
    finally { Clear-AdmBytes -Bytes $bytes }
}

function Unprotect-AdmPayload {
    param([Parameter(Mandatory)][byte[]]$DataKey, [Parameter(Mandatory)]$Payload)
    $bytes = Unprotect-AdmBytes -Key $DataKey -InitVector $Payload.iv -Ciphertext $Payload.ciphertext `
                                -Mac $Payload.mac -Aad $script:AdmPayloadAad
    try {
        $json = [System.Text.Encoding]::UTF8.GetString($bytes)
        $data = $json | ConvertFrom-Json
        # ConvertFrom-Json collapses a one-element array to a scalar; force it back so callers
        # can always treat .domains as a list. This bites exactly when a store has one domain,
        # i.e. on everyone's first day.
        if ($null -eq $data.domains) { $data | Add-Member -NotePropertyName domains -NotePropertyValue @() -Force }
        else { $data.domains = @($data.domains) }
        $data
    } finally { Clear-AdmBytes -Bytes $bytes }
}

# --- session ------------------------------------------------------------------------------

function Set-AdmSession {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Envelope,
        [Parameter(Mandatory)][byte[]]$DataKey,
        [Parameter(Mandatory)]$Data,
        [Parameter(Mandatory)][string]$RecipientName,
        [int]$AutoLockMinutes = 60
    )
    $script:AdmSession = [pscustomobject]@{
        Path            = $Path
        Envelope        = $Envelope
        DataKey         = $DataKey
        Data            = $Data
        RecipientName   = $RecipientName
        UnlockedAt      = Get-Date
        AutoLockMinutes = $AutoLockMinutes
    }
}

function Clear-AdmSession {
    if ($script:AdmSession -and $script:AdmSession.DataKey) {
        Clear-AdmBytes -Bytes $script:AdmSession.DataKey
    }
    $script:AdmSession = $null
}

# Every read and write of store contents goes through here, so the idle timer cannot be
# bypassed by calling a different cmdlet.
function Get-AdmSession {
    [CmdletBinding()]
    param()
    if (-not $script:AdmSession) {
        throw 'The credential store is locked. Run Unlock-AdmStore first.'
    }
    $mins = $script:AdmSession.AutoLockMinutes
    if ($mins -gt 0) {
        $idle = (Get-Date) - $script:AdmSession.UnlockedAt
        if ($idle.TotalMinutes -ge $mins) {
            Clear-AdmSession
            throw "The credential store auto-locked after $mins minutes. Run Unlock-AdmStore again."
        }
    }
    $script:AdmSession
}

function Save-AdmSession {
    [CmdletBinding()]
    param()
    $s = Get-AdmSession
    $s.Envelope.payload = Protect-AdmPayload -DataKey $s.DataKey -Data $s.Data
    Write-AdmEnvelope -Path $s.Path -Envelope $s.Envelope
}

# --- domain records -------------------------------------------------------------------------

function New-AdmDomainRecord {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$DnsDomain,
        [string]$NetbiosName,
        [string[]]$Aliases = @(),
        [string[]]$Hosts = @(),
        [string[]]$DomainControllers = @(),
        [int]$Port = 0,
        [bool]$UseSsl = $true
    )
    if ($Port -le 0) { $Port = if ($UseSsl) { 636 } else { 389 } }
    [pscustomobject]@{
        Name              = $Name
        DnsDomain         = $DnsDomain
        NetbiosName       = $NetbiosName
        Aliases           = @($Aliases)
        Hosts             = @($Hosts)
        DomainControllers = @($DomainControllers)
        Port              = $Port
        UseSsl            = $UseSsl
        # Credential tiering is deliberate: a read credential must not be able to perform a
        # write. One key that can do everything is the thing that turns a leak into an incident.
        Credentials       = [pscustomobject]@{}
        DefaultCredential = 'read'
    }
}

function Get-AdmDomainRecord {
    param([Parameter(Mandatory)][string]$Name)
    $s = Get-AdmSession
    $d = @($s.Data.domains) | Where-Object { $_.Name -eq $Name }
    if (-not $d) { throw "No domain named '$Name' in the store. Registered: $((@($s.Data.domains)|ForEach-Object{$_.Name}) -join ', ')" }
    $d | Select-Object -First 1
}

# Returns a PSCredential built from the named tier, without ever handing back a bare string.
function Get-AdmDomainCredential {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCredential])]
    param(
        [Parameter(Mandatory)]$Domain,
        [string]$Tier
    )
    if (-not $Tier) { $Tier = $Domain.DefaultCredential }
    if (-not $Tier) { $Tier = 'read' }

    $creds = $Domain.Credentials
    $entry = if ($creds) { $creds.PSObject.Properties[$Tier] } else { $null }
    if (-not $entry) {
        # Enumerate explicitly: `.Properties.Name` over an empty collection throws under strict
        # mode, and this line only runs when something has ALREADY gone wrong -- a diagnostic
        # that fails while reporting a failure hides the thing it was written to explain.
        $have = if ($creds) { (@($creds.PSObject.Properties | ForEach-Object { $_.Name })) -join ', ' } else { '' }
        if (-not $have) { $have = '(none)' }
        throw "Domain '$($Domain.Name)' has no '$Tier' credential. Configured tiers: $have."
    }
    $v = $entry.Value
    New-Object System.Management.Automation.PSCredential(
        $v.UserName, (ConvertTo-AdmSecureString -Plain $v.Password))
}
