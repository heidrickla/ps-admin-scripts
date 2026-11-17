# Public/Store.ps1 -- creating, unlocking and sharing the credential store.

function Initialize-AdmStore {
    <#
    .SYNOPSIS
      Create a new encrypted credential store with one initial admin.
    .DESCRIPTION
      Generates a random data key, seals an empty registry with it, and wraps that key for the
      first admin. Add the others with Add-AdmRecipient once unlocked.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string]$Path,
        [Parameter(Mandatory)][string]$RecipientName,
        [Parameter(Mandatory)][System.Security.SecureString]$Passphrase,
        [int]$Iterations = 310000,
        [switch]$Force
    )
    Assert-AdmPlatform
    if (-not $Path) { $Path = Get-AdmDefaultStorePath }
    if ((Test-Path -LiteralPath $Path) -and -not $Force) {
        throw "A store already exists at '$Path'. Use -Force to replace it -- this DESTROYS every credential in it."
    }
    if (-not $PSCmdlet.ShouldProcess($Path, 'Create a new credential store')) { return }

    $dek = New-AdmDataKey
    try {
        $wrap = New-AdmRecipientWrap -Name $RecipientName -Passphrase $Passphrase -DataKey $dek -Iterations $Iterations
        $data = New-AdmEmptyData
        $payload = Protect-AdmPayload -DataKey $dek -Data $data
        $envelope = New-AdmEnvelope -Recipients @($wrap) -Payload $payload
        Write-AdmEnvelope -Path $Path -Envelope $envelope
    } finally { Clear-AdmBytes -Bytes $dek }

    [pscustomobject]@{ Path = $Path; Recipients = @($RecipientName); Domains = 0 }
}

function Unlock-AdmStore {
    <#
    .SYNOPSIS
      Decrypt the store for this session.
    .DESCRIPTION
      Without -Recipient every wrap is tried until one opens, so an admin only needs their own
      passphrase. Naming the recipient skips the others and is noticeably faster.
    #>
    [CmdletBinding()]
    param(
        [string]$Path,
        [Parameter(Mandatory)][System.Security.SecureString]$Passphrase,
        [string]$Recipient,
        [int]$AutoLockMinutes = 60
    )
    Assert-AdmPlatform
    if (-not $Path) { $Path = Get-AdmDefaultStorePath }
    $envelope = Read-AdmEnvelope -Path $Path

    $candidates = @($envelope.recipients)
    if ($Recipient) {
        $candidates = @($candidates | Where-Object { $_.Name -eq $Recipient })
        if (-not $candidates) {
            throw "No recipient named '$Recipient' in '$Path'. Known: $((@($envelope.recipients)|ForEach-Object{$_.Name}) -join ', ')"
        }
    }

    $dek = $null; $who = $null
    foreach ($c in $candidates) {
        try { $dek = Open-AdmRecipientWrap -Recipient $c -Passphrase $Passphrase; $who = $c.Name; break }
        catch [System.Security.Cryptography.CryptographicException] { continue }
    }
    if (-not $dek) {
        throw 'That passphrase does not open this store for any registered admin.'
    }

    $data = Unprotect-AdmPayload -DataKey $dek -Payload $envelope.payload
    Set-AdmSession -Path $Path -Envelope $envelope -DataKey $dek -Data $data `
                   -RecipientName $who -AutoLockMinutes $AutoLockMinutes

    [pscustomobject]@{
        Path = $Path; UnlockedAs = $who; Domains = @($data.domains).Count; AutoLockMinutes = $AutoLockMinutes
    }
}

function Lock-AdmStore {
    <#
    .SYNOPSIS
      Forget the decrypted data key for this session.
    #>
    [CmdletBinding()]
    param()
    Clear-AdmSession
    [pscustomobject]@{ Locked = $true }
}

function Get-AdmStoreInfo {
    <#
    .SYNOPSIS
      Report the store's state without decrypting anything secret.
    #>
    [CmdletBinding()]
    param([string]$Path)
    if (-not $Path) { $Path = if ($script:AdmSession) { $script:AdmSession.Path } else { Get-AdmDefaultStorePath } }
    $exists = Test-Path -LiteralPath $Path
    $recipients = @()
    $schema = $null
    if ($exists) {
        $e = Read-AdmEnvelope -Path $Path
        $schema = $e.schema
        $recipients = @($e.recipients | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; Iterations = $_.Iterations; Created = $_.Created }
        })
    }
    $unlocked = [bool]$script:AdmSession
    [pscustomobject]@{
        Path       = $Path
        Exists     = $exists
        Schema     = $schema
        Recipients = $recipients
        Unlocked   = $unlocked
        UnlockedAs = if ($unlocked) { $script:AdmSession.RecipientName } else { $null }
        IdleMinutes = if ($unlocked) { [math]::Round(((Get-Date) - $script:AdmSession.UnlockedAt).TotalMinutes, 1) } else { $null }
        Domains    = if ($unlocked) { @($script:AdmSession.Data.domains).Count } else { $null }
        Provider   = Get-AdmProviderName
    }
}

function Add-AdmRecipient {
    <#
    .SYNOPSIS
      Give another admin their own passphrase for this store.
    .DESCRIPTION
      Wraps the existing data key for a new admin. The payload is not re-encrypted and nobody
      else's passphrase changes.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][System.Security.SecureString]$Passphrase,
        [int]$Iterations = 310000
    )
    $s = Get-AdmSession
    if (@($s.Envelope.recipients) | Where-Object { $_.Name -eq $Name }) {
        throw "'$Name' is already a recipient of this store."
    }
    if (-not $PSCmdlet.ShouldProcess($Name, 'Add store recipient')) { return }

    $wrap = New-AdmRecipientWrap -Name $Name -Passphrase $Passphrase -DataKey $s.DataKey -Iterations $Iterations
    $s.Envelope.recipients = @($s.Envelope.recipients) + $wrap
    Write-AdmEnvelope -Path $s.Path -Envelope $s.Envelope
    [pscustomobject]@{ Name = $Name; Recipients = @($s.Envelope.recipients | ForEach-Object { $_.Name }) }
}

function Remove-AdmRecipient {
    <#
    .SYNOPSIS
      Drop an admin's ability to unlock FUTURE copies of this store.
    .DESCRIPTION
      ⚠ THIS IS NOT REVOCATION OF WHAT THEY ALREADY SAW. Removing a wrap stops that passphrase
      opening THIS file from now on. Anyone who kept an older copy of the file can still open it
      with their old passphrase, and any credential they already read is already disclosed.
      To actually revoke access, rotate the AD credentials held in the store.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string]$Name)
    $s = Get-AdmSession
    $remaining = @($s.Envelope.recipients | Where-Object { $_.Name -ne $Name })
    if ($remaining.Count -eq @($s.Envelope.recipients).Count) {
        throw "No recipient named '$Name' in this store."
    }
    if ($remaining.Count -eq 0) {
        throw "Refusing to remove the last recipient -- the store would become permanently unopenable."
    }
    if (-not $PSCmdlet.ShouldProcess($Name, 'Remove store recipient')) { return }

    $s.Envelope.recipients = $remaining
    Write-AdmEnvelope -Path $s.Path -Envelope $s.Envelope
    Write-Warning ("'$Name' can no longer open this file. This is NOT revocation: an older copy " +
                   "of the store plus their passphrase still opens, and anything they already " +
                   "read stays disclosed. Rotate the affected AD credentials.")
    [pscustomobject]@{ Removed = $Name; Recipients = @($remaining | ForEach-Object { $_.Name }) }
}
