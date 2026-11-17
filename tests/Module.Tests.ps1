$repo = Split-Path -Parent $PSScriptRoot   # run from any clone, USB or share
$ErrorActionPreference = 'Stop'
$fail = 0
function Check($name, [scriptblock]$body) {
    try { $r = & $body
        if ($r) { "  PASS  $name" } else { "  FAIL  $name"; $script:fail++ }
    } catch { "  FAIL  $name -- $($_.Exception.Message)"; $script:fail++ }
}
function ShouldThrow($name, [scriptblock]$body) {
    try { & $body | Out-Null; "  FAIL  $name (no exception)"; $script:fail++ }
    catch { "  PASS  $name (refused)" }
}

$work = Join-Path $env:TEMP ("admtest-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$store = Join-Path $work 'adadmin-store.json'
$env:ADADMIN_STORE = $store

Import-Module (Join-Path $repo 'ADAdmin\ADAdmin.psd1') -Force
"module loaded: $((Get-Module ADAdmin).ExportedFunctions.Count) functions exported"

$pAlice = ConvertTo-SecureString 'alice-unlock-aaa' -AsPlainText -Force
$pBob   = ConvertTo-SecureString 'bob-unlock-bbb'   -AsPlainText -Force
$IT     = 100000

"== store lifecycle =="
Check 'initialize creates the file' {
    $r = Initialize-AdmStore -RecipientName alice -Passphrase $pAlice -Iterations $IT -Confirm:$false
    (Test-Path $store) -and $r.Recipients -contains 'alice'
}
Check 'the file on disk is not readable as plaintext' {
    $raw = Get-Content $store -Raw
    ($raw -notmatch 'corp\.example\.com') -and ($raw -match 'ADAdmin-store')
}
Check 'store file has no BOM' {
    $b = [System.IO.File]::ReadAllBytes($store)
    -not ($b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
}
ShouldThrow 'operations refuse while locked' { Get-AdmDomain }
Check 'unlock as alice'  { (Unlock-AdmStore -Passphrase $pAlice).UnlockedAs -eq 'alice' }
ShouldThrow 'wrong passphrase refused' { Unlock-AdmStore -Passphrase (ConvertTo-SecureString 'nope' -AsPlainText -Force) }
Check 're-unlock after a bad attempt still works' { (Unlock-AdmStore -Passphrase $pAlice).UnlockedAs -eq 'alice' }

"== multi-admin =="
Check 'add bob'            { (Add-AdmRecipient -Name bob -Passphrase $pBob -Iterations $IT -Confirm:$false).Recipients -contains 'bob' }
Check 'bob can unlock'     { (Unlock-AdmStore -Passphrase $pBob).UnlockedAs -eq 'bob' }
Check 'alice still can'    { (Unlock-AdmStore -Passphrase $pAlice).UnlockedAs -eq 'alice' }
ShouldThrow 'duplicate recipient refused' { Add-AdmRecipient -Name bob -Passphrase $pBob -Iterations $IT -Confirm:$false }

"== domain registry =="
Check 'register corp' {
    Register-AdmDomain -Name corp -DnsDomain corp.example.com -NetbiosName CORP `
        -DomainControllers dc01.corp.example.com -Hosts 'legacy-box' -Confirm:$false | Out-Null
    Register-AdmDomain -Name child -DnsDomain child.corp.example.com -NetbiosName CHILD -Confirm:$false | Out-Null
    Register-AdmDomain -Name plant -DnsDomain plant.local -NetbiosName PLANT -Aliases 'plant.internal' -Confirm:$false | Out-Null
    (Get-AdmDomain).Count -eq 3
}
Check 'credentials stored per tier' {
    $c = New-Object System.Management.Automation.PSCredential('CORP\svc-read', (ConvertTo-SecureString 'x' -AsPlainText -Force))
    $w = New-Object System.Management.Automation.PSCredential('CORP\svc-write', (ConvertTo-SecureString 'y' -AsPlainText -Force))
    Set-AdmDomainCredential -Domain corp -Credential $c -Tier read -SetDefault -Confirm:$false | Out-Null
    Set-AdmDomainCredential -Domain corp -Credential $w -Tier write -Confirm:$false | Out-Null
    foreach ($d in 'child','plant') {
        $k = New-Object System.Management.Automation.PSCredential("$d\svc", (ConvertTo-SecureString 'z' -AsPlainText -Force))
        Set-AdmDomainCredential -Domain $d -Credential $k -Tier read -SetDefault -Confirm:$false | Out-Null
        Set-AdmDomainCredential -Domain $d -Credential $k -Tier write -Confirm:$false | Out-Null
    }
    (Get-AdmDomain -Name corp).CredentialTiers.Count -eq 2
}
Check 'Get-AdmDomain never returns a password' {
    ((Get-AdmDomain | ConvertTo-Json -Depth 6) -notmatch 'Password')
}
Check 'credentials survive a re-register (-Force)' {
    Register-AdmDomain -Name corp -DnsDomain corp.example.com -NetbiosName CORP `
        -DomainControllers dc01.corp.example.com -Hosts 'legacy-box' -Force -Confirm:$false | Out-Null
    (Get-AdmDomain -Name corp).CredentialTiers.Count -eq 2
}

"== persistence across a lock =="
Check 'data survives lock + unlock' {
    Lock-AdmStore | Out-Null
    (Unlock-AdmStore -Passphrase $pBob).Domains -eq 3
}

"== resolution through the public cmdlet =="
Check 'fqdn host -> corp'        { (Resolve-AdmDomain -Target ws1.corp.example.com).Domain -eq 'corp' }
Check 'child host -> child'      { (Resolve-AdmDomain -Target ws1.child.corp.example.com).Domain -eq 'child' }
Check 'netbios -> plant'         { (Resolve-AdmDomain -Target PLANT).Domain -eq 'plant' }
Check 'alias -> plant'           { (Resolve-AdmDomain -Target srv.plant.internal).Domain -eq 'plant' }
Check 'explicit host -> corp'    { (Resolve-AdmDomain -Target legacy-box).MatchedOn -eq 'Hosts' }
ShouldThrow 'unknown target refused' { Resolve-AdmDomain -Target nothing.example.org }

"== directory operations via the mock provider =="
Set-AdmProvider -Name mock | Out-Null
Check 'provider reported'        { (Get-AdmStoreInfo).Provider -eq 'mock' }
Check 'users listed'             { (Get-AdmUser -Target corp.example.com).Count -eq 4 }
Check 'user search filters'      { (Get-AdmUser -Target corp.example.com -Identity jsmith).SamAccountName -eq 'jsmith' }
Check 'disabled account seen'    { (Get-AdmUser -Target corp.example.com -Identity rlemieux).Enabled -eq $false }
Check 'locked account seen'      { (Get-AdmUser -Target corp.example.com -Identity aokafor).LockedOut -eq $true }
Check 'target routes to child'   { (Get-AdmUser -Target ws1.child.corp.example.com).SamAccountName -eq 'bchen' }
Check 'groups listed'            { @(Get-AdmGroup -Target plant.local).Count -eq 1 }
Check 'computers listed'         { (Get-AdmComputer -Target corp.example.com).Count -eq 3 }
Check 'test-domain reports mock' { (Test-AdmDomain -Target corp.example.com).Status -eq 'mock' }

"== writes =="
Check 'whatif changes nothing' {
    Unlock-AdmUser -Target corp.example.com -Identity aokafor -WhatIf | Out-Null
    (Get-AdmUser -Target corp.example.com -Identity aokafor).LockedOut -eq $true
}
Check 'unlock clears lockout'    { (Unlock-AdmUser -Target corp.example.com -Identity aokafor -Confirm:$false).LockedOut -eq $false }
Check 'and it is observable'     { (Get-AdmUser -Target corp.example.com -Identity aokafor).LockedOut -eq $false }
Check 'disable an account'       { (Set-AdmUserEnabled -Target corp.example.com -Identity jsmith -Enabled $false -Confirm:$false).Enabled -eq $false }
Check 'and it is observable'     { (Get-AdmUser -Target corp.example.com -Identity jsmith).Enabled -eq $false }
Check 're-enable'                { (Set-AdmUserEnabled -Target corp.example.com -Identity jsmith -Enabled $true -Confirm:$false).Enabled -eq $true }
Check 'password reset returns no secret' {
    $r = Reset-AdmUserPassword -Target corp.example.com -Identity jsmith `
            -NewPassword (ConvertTo-SecureString 'Aa1!aaaaaaaa' -AsPlainText -Force) -MustChangeAtNextLogon -Confirm:$false
    ($r | ConvertTo-Json) -notmatch 'Aa1!'
}

"== account management =="
Check 'password policy is readable'      { (Get-AdmPasswordPolicy -Target corp.example.com).MaxPasswordAgeDays -gt 0 }
Check 'user object exposes expiry fields' {
    $u = Get-AdmUser -Target corp.example.com -Identity jsmith
    ($u.PSObject.Properties['PasswordLastSet']) -and ($u.PSObject.Properties['PasswordNeverExpires']) -and
    ($u.PSObject.Properties['LastLogonTimestamp']) -and ($u.PSObject.Properties['MemberOf'])
}
Check 'a service account with DONT_EXPIRE_PASSWD is detected' {
    # svc-backup has userAccountControl 66048 = 512 + 65536 (DONT_EXPIRE_PASSWD).
    (Get-AdmUser -Target corp.example.com -Identity svc-backup).PasswordNeverExpires -eq $true
}
Check 'and an ordinary account is not'   { (Get-AdmUser -Target corp.example.com -Identity jsmith).PasswordNeverExpires -eq $false }
Check 'create user honours -WhatIf'      { $null -eq (New-AdmUser -Target corp.example.com -SamAccountName nobody `
                                                        -Password (ConvertTo-SecureString 'x' -AsPlainText -Force) -WhatIf) }
Check 'create user returns a result'     { (New-AdmUser -Target corp.example.com -SamAccountName newguy `
                                                -Password (ConvertTo-SecureString 'x' -AsPlainText -Force) -Confirm:$false).Action -eq 'create-user' }
Check 'add group member honours -WhatIf' { $null -eq (Add-AdmGroupMember -Target corp.example.com -Group Helpdesk -Identity jsmith -WhatIf) }
Check 'add group member returns a result'{ (Add-AdmGroupMember -Target corp.example.com -Group Helpdesk -Identity jsmith -Confirm:$false).Result -eq 'added' }
Check 'a FILETIME of 0 is not a date'    {
    $m = Get-Module ADAdmin
    $null -eq (& $m { ConvertFrom-AdmFileTime 0 }) -and $null -eq (& $m { ConvertFrom-AdmFileTime 9223372036854775807 })
}
Check 'and a real FILETIME converts'     {
    $m = Get-Module ADAdmin
    (& $m { param($t) ConvertFrom-AdmFileTime $t } ([datetime]'2024-06-01T12:00:00Z').ToFileTimeUtc()).Year -eq 2024
}

"== credential tiering =="
ShouldThrow 'missing tier is a clear failure' { Get-AdmUser -Target corp.example.com -Tier nonexistent }

"== auto-lock =="
Check 'auto-lock expires the session' {
    Unlock-AdmStore -Passphrase $pAlice -AutoLockMinutes 0 | Out-Null   # 0 = never expire
    Unlock-AdmStore -Passphrase $pAlice -AutoLockMinutes 1 | Out-Null
    # force the clock backwards past the window
    $m = Get-Module ADAdmin
    & $m { $script:AdmSession.UnlockedAt = (Get-Date).AddMinutes(-5) }
    try { Get-AdmDomain | Out-Null; $false } catch { $_.Exception.Message -like '*auto-locked*' }
}

"== recipient removal =="
Check 'remove bob'  {
    Unlock-AdmStore -Passphrase $pAlice | Out-Null
    (Remove-AdmRecipient -Name bob -Confirm:$false -WarningAction SilentlyContinue).Recipients -notcontains 'bob'
}
ShouldThrow "bob can no longer unlock"       { Unlock-AdmStore -Passphrase $pBob }
ShouldThrow 'cannot remove the last admin'   { Unlock-AdmStore -Passphrase $pAlice | Out-Null
                                               Remove-AdmRecipient -Name alice -Confirm:$false }

Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { "`nFAILURES: $fail"; exit 1 } else { "`nall module checks passed"; exit 0 }
