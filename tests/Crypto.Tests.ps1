$repo = Split-Path -Parent $PSScriptRoot   # run from any clone, USB or share
$ErrorActionPreference = 'Stop'
. (Join-Path $repo 'ADAdmin\Private\Util.ps1')
. (Join-Path $repo 'ADAdmin\Private\Crypto.ps1')

$fail = 0
function Check($name, [scriptblock]$body) {
    try {
        $r = & $body
        if ($r) { "  PASS  $name" } else { "  FAIL  $name"; $script:fail++ }
    } catch { "  FAIL  $name -- $($_.Exception.Message)"; $script:fail++ }
}
function ShouldThrow($name, [scriptblock]$body) {
    try { & $body; "  FAIL  $name (no exception)"; $script:fail++ }
    catch { "  PASS  $name (rejected: $($_.Exception.GetType().Name))" }
}

$IT = 100000   # floor allowed by Get-AdmDerivedKey; keeps the suite quick

"== seal / open =="
$key = New-AdmDataKey
$msg = [Text.Encoding]::UTF8.GetBytes('lorem-ipsum-payload-marker-42')
$sealed = Protect-AdmBytes -Key $key -Plaintext $msg -Aad 'ctx'

Check 'round-trips to the same bytes' {
    $out = Unprotect-AdmBytes -Key $key -InitVector $sealed.Iv -Ciphertext $sealed.Ciphertext -Mac $sealed.Mac -Aad 'ctx'
    (Test-AdmBytesEqual -A $out -B $msg)
}
Check 'ciphertext does not contain the plaintext' {
    $c = [Convert]::FromBase64String($sealed.Ciphertext)
    -not ([Text.Encoding]::UTF8.GetString($c)).Contains('marker-42')
}
ShouldThrow 'wrong key is refused' {
    Unprotect-AdmBytes -Key (New-AdmDataKey) -InitVector $sealed.Iv -Ciphertext $sealed.Ciphertext -Mac $sealed.Mac -Aad 'ctx'
}
ShouldThrow 'flipped ciphertext bit is refused' {
    $c = [Convert]::FromBase64String($sealed.Ciphertext); $c[0] = $c[0] -bxor 1
    Unprotect-AdmBytes -Key $key -InitVector $sealed.Iv -Ciphertext ([Convert]::ToBase64String($c)) -Mac $sealed.Mac -Aad 'ctx'
}
ShouldThrow 'flipped IV bit is refused' {
    $v = [Convert]::FromBase64String($sealed.Iv); $v[0] = $v[0] -bxor 1
    Unprotect-AdmBytes -Key $key -InitVector ([Convert]::ToBase64String($v)) -Ciphertext $sealed.Ciphertext -Mac $sealed.Mac -Aad 'ctx'
}
ShouldThrow 'different AAD is refused' {
    Unprotect-AdmBytes -Key $key -InitVector $sealed.Iv -Ciphertext $sealed.Ciphertext -Mac $sealed.Mac -Aad 'other'
}
Check 'AAD length-prefix stops canonicalisation collision' {
    $k = New-AdmDataKey; $p = [Text.Encoding]::UTF8.GetBytes('x')
    $a = Protect-AdmBytes -Key $k -Plaintext $p -Aad 'ab'
    $parts = Split-AdmKey -Key $k
    $m2 = ConvertTo-AdmBase64 (Get-AdmMac -MacKey $parts.Mac -Aad 'a' `
        -InitVector ([Convert]::FromBase64String($a.Iv)) -Ciphertext ([Convert]::FromBase64String($a.Ciphertext)))
    $a.Mac -ne $m2
}

"== multi-recipient wrapping =="
$dek = New-AdmDataKey
$pAlice = ConvertTo-AdmSecureString 'alice-unlock-aaa'
$pBob   = ConvertTo-AdmSecureString 'bob-unlock-bbb'
$pCarol = ConvertTo-AdmSecureString 'carol-unlock-ccc'
$wA = New-AdmRecipientWrap -Name 'alice' -Passphrase $pAlice -DataKey $dek -Iterations $IT
$wB = New-AdmRecipientWrap -Name 'bob'   -Passphrase $pBob   -DataKey $dek -Iterations $IT
$wC = New-AdmRecipientWrap -Name 'carol' -Passphrase $pCarol -DataKey $dek -Iterations $IT

Check 'alice recovers the data key'   { Test-AdmBytesEqual -A (Open-AdmRecipientWrap -Recipient $wA -Passphrase $pAlice) -B $dek }
Check 'bob recovers the same key'     { Test-AdmBytesEqual -A (Open-AdmRecipientWrap -Recipient $wB -Passphrase $pBob)   -B $dek }
Check 'carol recovers the same key'   { Test-AdmBytesEqual -A (Open-AdmRecipientWrap -Recipient $wC -Passphrase $pCarol) -B $dek }
Check 'each wrap is distinct on disk' { ($wA.WrappedKey -ne $wB.WrappedKey) -and ($wB.WrappedKey -ne $wC.WrappedKey) }
Check 'each recipient has its own salt' { ($wA.Salt -ne $wB.Salt) -and ($wB.Salt -ne $wC.Salt) }
ShouldThrow "alice's passphrase does not open bob's wrap" { Open-AdmRecipientWrap -Recipient $wB -Passphrase $pAlice }
ShouldThrow 'empty passphrase is refused'                 { Open-AdmRecipientWrap -Recipient $wA -Passphrase (ConvertTo-AdmSecureString '') }
ShouldThrow 'a wrap replayed under another id is refused' {
    $forged = $wA.PSObject.Copy(); $forged.Id = $wB.Id
    Open-AdmRecipientWrap -Recipient $forged -Passphrase $pAlice
}
ShouldThrow 'downgrading the iteration count is refused' {
    $forged = $wA.PSObject.Copy(); $forged.Iterations = 100001
    Open-AdmRecipientWrap -Recipient $forged -Passphrase $pAlice
}
ShouldThrow 'a weak iteration count is refused outright' {
    Get-AdmDerivedKey -Passphrase $pAlice -Salt (New-AdmRandomBytes -Count 32) -Iterations 1000
}

"== helpers =="
Check 'constant-time compare: equal'     { Test-AdmBytesEqual -A ([byte[]]@(1,2,3)) -B ([byte[]]@(1,2,3)) }
Check 'constant-time compare: differing' { -not (Test-AdmBytesEqual -A ([byte[]]@(1,2,3)) -B ([byte[]]@(1,2,4))) }
Check 'constant-time compare: length'    { -not (Test-AdmBytesEqual -A ([byte[]]@(1,2)) -B ([byte[]]@(1,2,3))) }
Check 'utf8 encoding emits no BOM'       { (Get-AdmUtf8Encoding).GetPreamble().Length -eq 0 }
Check 'securestring round-trips'         { (ConvertFrom-AdmSecureString (ConvertTo-AdmSecureString 'p@ss wor;d')) -eq 'p@ss wor;d' }

if ($fail -gt 0) { "`nFAILURES: $fail"; exit 1 } else { "`nall crypto checks passed"; exit 0 }
