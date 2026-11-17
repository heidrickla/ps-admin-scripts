# Crypto.ps1 -- envelope encryption for the credential store.
#
# SHAPE: a random 64-byte DATA KEY encrypts the payload once. That data key is then WRAPPED
# once per admin, each wrap guarded by a key derived from that admin's own passphrase. So
# every admin unlocks the same store with a different secret, and an admin can be dropped by
# deleting one wrap -- without re-encrypting the payload or telling anyone else a new
# passphrase.
#
# PRIMITIVES: PBKDF2-SHA256 for derivation, AES-256-CBC for confidentiality, HMAC-SHA256 for
# integrity, composed as ENCRYPT-THEN-MAC and verified before any decrypt. Not AES-GCM:
# System.Security.Cryptography.AesGcm is .NET Core only, and this has to run under Windows
# PowerShell 5.1 on a target PC. Encrypt-then-MAC is the correct construction to reach for
# when an AEAD is unavailable -- it is not a downgrade, but it IS easy to get wrong, so the
# order below (MAC covers version + AAD + IV + ciphertext, and is checked first) is load-bearing.

# OWASP's PBKDF2-SHA256 floor. Stored per-recipient in the file so it can be raised later
# without invalidating existing stores.
$script:AdmDefaultIterations = 310000
$script:AdmKeyBytes = 64   # 32 for AES-256, 32 for HMAC-SHA256

function New-AdmDataKey {
    [OutputType([byte[]])]
    param()
    ,(New-AdmRandomBytes -Count $script:AdmKeyBytes)
}

function Get-AdmDerivedKey {
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][System.Security.SecureString]$Passphrase,
        [Parameter(Mandatory)][byte[]]$Salt,
        [Parameter(Mandatory)][int]$Iterations
    )
    Assert-AdmPlatform
    if ($Iterations -lt 100000) {
        throw "Refusing a PBKDF2 iteration count below 100000 (asked for $Iterations)."
    }
    $plain = ConvertFrom-AdmSecureString -Secure $Passphrase
    $pwBytes = [System.Text.Encoding]::UTF8.GetBytes($plain)
    try {
        $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
            $pwBytes, $Salt, $Iterations,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        try { ,$kdf.GetBytes($script:AdmKeyBytes) } finally { $kdf.Dispose() }
    } finally {
        Clear-AdmBytes -Bytes $pwBytes
        # $plain is an immutable .NET string; it cannot be zeroed. Keeping its lifetime to
        # this function is the only control available.
        $plain = $null
    }
}

function Split-AdmKey {
    param([Parameter(Mandatory)][byte[]]$Key)
    if ($Key.Length -ne $script:AdmKeyBytes) {
        throw "Key must be $($script:AdmKeyBytes) bytes; got $($Key.Length)."
    }
    $enc = New-Object byte[] 32
    $mac = New-Object byte[] 32
    [Array]::Copy($Key, 0, $enc, 0, 32)
    [Array]::Copy($Key, 32, $mac, 0, 32)
    [pscustomobject]@{ Enc = $enc; Mac = $mac }
}

# Seal: AES-256-CBC then HMAC over (aad || iv || ciphertext). $Aad binds the ciphertext to its
# context -- the schema version, and for a wrapped key the recipient id -- so a blob cannot be
# lifted from one slot and replayed into another.
function Protect-AdmBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Key,
        [Parameter(Mandatory)][byte[]]$Plaintext,
        [string]$Aad = ''
    )
    $parts = Split-AdmKey -Key $Key
    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize = 256
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $parts.Enc
        $aes.GenerateIV()
        $iv = $aes.IV
        $enc = $aes.CreateEncryptor()
        try { $cipher = $enc.TransformFinalBlock($Plaintext, 0, $Plaintext.Length) }
        finally { $enc.Dispose() }

        $mac = Get-AdmMac -MacKey $parts.Mac -Aad $Aad -InitVector $iv -Ciphertext $cipher
        [pscustomobject]@{
            Iv         = ConvertTo-AdmBase64 $iv
            Ciphertext = ConvertTo-AdmBase64 $cipher
            Mac        = ConvertTo-AdmBase64 $mac
        }
    } finally {
        $aes.Dispose()
        Clear-AdmBytes -Bytes $parts.Enc
        Clear-AdmBytes -Bytes $parts.Mac
    }
}

# Open: verify the MAC FIRST, then decrypt. Decrypting before authenticating is how padding
# oracles happen; the wrong-passphrase path must be indistinguishable from the tampered path,
# and both must fail before any padding is examined.
function Unprotect-AdmBytes {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][byte[]]$Key,
        [Parameter(Mandatory)][string]$InitVector,
        [Parameter(Mandatory)][string]$Ciphertext,
        [Parameter(Mandatory)][string]$Mac,
        [string]$Aad = ''
    )
    $parts = Split-AdmKey -Key $Key
    try {
        $ivBytes = ConvertFrom-AdmBase64 $InitVector
        $cipherBytes = ConvertFrom-AdmBase64 $Ciphertext
        $expected = ConvertFrom-AdmBase64 $Mac
        $actual = Get-AdmMac -MacKey $parts.Mac -Aad $Aad -InitVector $ivBytes -Ciphertext $cipherBytes

        if (-not (Test-AdmBytesEqual -A $expected -B $actual)) {
            # Deliberately one message for both causes. Telling the caller which one it was
            # would tell an attacker the same thing.
            throw [System.Security.Cryptography.CryptographicException]::new(
                'Authentication failed: wrong passphrase, or the data has been altered.')
        }

        $aes = [System.Security.Cryptography.Aes]::Create()
        try {
            $aes.KeySize = 256
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $aes.Key = $parts.Enc
            $aes.IV = $ivBytes
            $dec = $aes.CreateDecryptor()
            try { ,$dec.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length) }
            finally { $dec.Dispose() }
        } finally { $aes.Dispose() }
    } finally {
        Clear-AdmBytes -Bytes $parts.Enc
        Clear-AdmBytes -Bytes $parts.Mac
    }
}

function Get-AdmMac {
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][byte[]]$MacKey,
        [string]$Aad,
        [Parameter(Mandatory)][byte[]]$InitVector,
        [Parameter(Mandatory)][byte[]]$Ciphertext
    )
    # Length-prefix the AAD so that ("ab","c") and ("a","bc") cannot produce the same MAC
    # input. Concatenating variable-length fields without a delimiter is a canonicalisation
    # bug, and it is silent.
    $aadBytes = [System.Text.Encoding]::UTF8.GetBytes([string]$Aad)
    $lenBytes = [BitConverter]::GetBytes([int]$aadBytes.Length)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256(,$MacKey)
    try {
        $ms = New-Object System.IO.MemoryStream
        try {
            $ms.Write($lenBytes, 0, $lenBytes.Length)
            $ms.Write($aadBytes, 0, $aadBytes.Length)
            $ms.Write($InitVector, 0, $InitVector.Length)
            $ms.Write($Ciphertext, 0, $Ciphertext.Length)
            ,$hmac.ComputeHash($ms.ToArray())
        } finally { $ms.Dispose() }
    } finally { $hmac.Dispose() }
}

# --- recipient wrapping -------------------------------------------------------------------

function New-AdmRecipientWrap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][System.Security.SecureString]$Passphrase,
        [Parameter(Mandatory)][byte[]]$DataKey,
        [int]$Iterations = $script:AdmDefaultIterations
    )
    $id = [guid]::NewGuid().ToString()
    $salt = New-AdmRandomBytes -Count 32
    $kek = Get-AdmDerivedKey -Passphrase $Passphrase -Salt $salt -Iterations $Iterations
    try {
        # The AAD binds the wrap to this recipient id and iteration count, so neither can be
        # swapped or downgraded without failing the MAC.
        $sealed = Protect-AdmBytes -Key $kek -Plaintext $DataKey -Aad "adm-wrap:v1:$id`:$Iterations"
        [pscustomobject]@{
            Id         = $id
            Name       = $Name
            Kdf        = 'PBKDF2-SHA256'
            Iterations = $Iterations
            Salt       = ConvertTo-AdmBase64 $salt
            Iv         = $sealed.Iv
            WrappedKey = $sealed.Ciphertext
            Mac        = $sealed.Mac
            Created    = (Get-Date).ToUniversalTime().ToString('o')
        }
    } finally { Clear-AdmBytes -Bytes $kek }
}

function Open-AdmRecipientWrap {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]$Recipient,
        [Parameter(Mandatory)][System.Security.SecureString]$Passphrase
    )
    $salt = ConvertFrom-AdmBase64 $Recipient.Salt
    $kek = Get-AdmDerivedKey -Passphrase $Passphrase -Salt $salt -Iterations ([int]$Recipient.Iterations)
    try {
        ,(Unprotect-AdmBytes -Key $kek -InitVector $Recipient.Iv -Ciphertext $Recipient.WrappedKey `
            -Mac $Recipient.Mac -Aad "adm-wrap:v1:$($Recipient.Id)`:$($Recipient.Iterations)")
    } finally { Clear-AdmBytes -Bytes $kek }
}
