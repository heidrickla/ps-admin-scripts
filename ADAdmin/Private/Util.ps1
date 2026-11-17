# Util.ps1 -- primitives the rest of the module leans on.
# Nothing here talks to AD or to disk formats; keep it that way so it stays testable.

# The toolkit is carried to machines we cannot probe in advance, so every environmental
# assumption is asserted at runtime with a message that names the fix. Silent degradation is
# the failure mode that matters: a KDF that quietly falls back to SHA-1 still "works".
$script:AdmPlatformChecked = $false

function Assert-AdmPlatform {
    [CmdletBinding()]
    param()
    if ($script:AdmPlatformChecked) { return }

    if ($PSVersionTable.PSVersion.Major -lt 5) {
        throw "ADAdmin requires PowerShell 5.1 or later; this host is $($PSVersionTable.PSVersion)."
    }

    # PBKDF2-SHA256 needs the 4-argument Rfc2898DeriveBytes ctor (.NET Framework 4.7.2+).
    # Server 2016 and Win10 have it. If a target somehow does not, fail here rather than
    # silently deriving with SHA-1 -- the store would still open, with a weaker KDF.
    try {
        $probe = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
            [byte[]]@(1), [byte[]]@(1, 2, 3, 4, 5, 6, 7, 8), 1,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $null = $probe.GetBytes(1)
        $probe.Dispose()
    } catch {
        throw ("This host cannot do PBKDF2-SHA256 (.NET Framework 4.7.2+ required). " +
               "Underlying error: $($_.Exception.Message)")
    }

    $script:AdmPlatformChecked = $true
}

function New-AdmRandomBytes {
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][int]$Count)
    $bytes = New-Object byte[] $Count
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    ,$bytes
}

# Comparison whose duration does not depend on WHERE the first difference is. Used for MAC
# checks; a short-circuiting -eq leaks the matching prefix length by timing.
function Test-AdmBytesEqual {
    [OutputType([bool])]
    param([byte[]]$A, [byte[]]$B)
    if ($null -eq $A -or $null -eq $B) { return $false }
    if ($A.Length -ne $B.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $A.Length; $i++) { $diff = $diff -bor ($A[$i] -bxor $B[$i]) }
    return ($diff -eq 0)
}

# Overwrite key material in place. Best-effort: the CLR may have copied it, but leaving a
# 32-byte AES key sitting in a long-lived module variable is a choice, not a fact of life.
function Clear-AdmBytes {
    param([byte[]]$Bytes)
    if ($null -ne $Bytes) { [Array]::Clear($Bytes, 0, $Bytes.Length) }
}

# SecureString -> plaintext, for the one moment a bind or a KDF needs it. Always call the
# matching free; the BSTR is unmanaged and will not be collected.
function ConvertFrom-AdmSecureString {
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Security.SecureString]$Secure)
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Secure)
    try { [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr) }
}

function ConvertTo-AdmSecureString {
    [OutputType([System.Security.SecureString])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Plain)
    $s = New-Object System.Security.SecureString
    foreach ($c in $Plain.ToCharArray()) { $s.AppendChar($c) }
    $s.MakeReadOnly()
    $s
}

# UTF-8 with NO BOM. A BOM in a stored secret authenticates as a wrong password and every
# symptom points at the wrong layer -- see docs/development-notes.md. Same reasoning for the JSON
# envelope: a BOM there breaks strict parsers on the far side.
function Get-AdmUtf8Encoding {
    New-Object System.Text.UTF8Encoding($false)
}

# Write via a temp file in the SAME directory, then swap. A USB pulled mid-write should cost
# you the new version, never the store you already had.
function Write-AdmFileAtomic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content
    )
    # NOT `Split-Path -LiteralPath -Parent`: those two are in different parameter sets under
    # Windows PowerShell 5.1 and the call fails with "Parameter set cannot be resolved". It is
    # accepted under PowerShell 7, so testing only on 7 hides it completely.
    $dir = [System.IO.Path]::GetDirectoryName($Path)
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $tmp = Join-Path $dir ([System.IO.Path]::GetRandomFileName())
    [System.IO.File]::WriteAllText($tmp, $Content, (Get-AdmUtf8Encoding))
    try {
        if (Test-Path -LiteralPath $Path) {
            # File.Replace is the atomic swap, but it is refused on some removable
            # filesystems; fall back to delete+move, which is the best available there.
            try { [System.IO.File]::Replace($tmp, $Path, $null) }
            catch {
                [System.IO.File]::Delete($Path)
                [System.IO.File]::Move($tmp, $Path)
            }
        } else {
            [System.IO.File]::Move($tmp, $Path)
        }
    } catch {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -EA SilentlyContinue }
        throw
    }
}

function ConvertTo-AdmBase64 {
    [OutputType([string])]
    param([byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes)
}

function ConvertFrom-AdmBase64 {
    [OutputType([byte[]])]
    param([string]$Text)
    ,[Convert]::FromBase64String($Text)
}
