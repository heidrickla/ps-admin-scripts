# Public/Detail.ps1 -- everything about ONE object.
#
# The rest of Objects.ps1 answers "which objects match?". This answers "what IS this one?", which
# is the other half of the daily loop and was missing entirely: you could find an account and act
# on it, but never look at it. A search result is deliberately narrow so a list of 5000 stays
# cheap; this is deliberately wide, because it is fetched for exactly one object at a time.

# ⭐ EVERY userAccountControl BIT, NAMED. A raw UAC value is a number an administrator has to go
# and look up, and the bits that matter most for security -- delegation, pre-authentication,
# PASSWD_NOTREQD -- are precisely the ones nobody remembers. Named here once so every caller
# gets the same vocabulary.
# ⛔ AN ARRAY OF PAIRS, NOT AN [ordered] HASHTABLE KEYED BY THE BIT.
#
# Indexing an OrderedDictionary with an INTEGER is a POSITIONAL lookup, not a key lookup:
# `$ordered[0x2]` returns the third entry's value by position, and a bit like 0x1000000 is far
# past the end so it returns $null in silence. The first live run died on
# "Exception calling ContainsKey with 1 argument(s): Key cannot be null" -- one indirection away
# from the actual mistake. An array of pairs cannot be indexed the wrong way by accident and
# keeps the order.
$script:AdmUacFlags = @(
    @{ Bit = 0x00000002; Name = 'ACCOUNTDISABLE' }
    @{ Bit = 0x00000008; Name = 'HOMEDIR_REQUIRED' }
    @{ Bit = 0x00000010; Name = 'LOCKOUT' }
    @{ Bit = 0x00000020; Name = 'PASSWD_NOTREQD' }
    @{ Bit = 0x00000040; Name = 'PASSWD_CANT_CHANGE' }
    @{ Bit = 0x00000080; Name = 'ENCRYPTED_TEXT_PWD_ALLOWED' }
    @{ Bit = 0x00000100; Name = 'TEMP_DUPLICATE_ACCOUNT' }
    @{ Bit = 0x00000200; Name = 'NORMAL_ACCOUNT' }
    @{ Bit = 0x00000800; Name = 'INTERDOMAIN_TRUST_ACCOUNT' }
    @{ Bit = 0x00001000; Name = 'WORKSTATION_TRUST_ACCOUNT' }
    @{ Bit = 0x00002000; Name = 'SERVER_TRUST_ACCOUNT' }
    @{ Bit = 0x00010000; Name = 'DONT_EXPIRE_PASSWORD' }
    @{ Bit = 0x00020000; Name = 'MNS_LOGON_ACCOUNT' }
    @{ Bit = 0x00040000; Name = 'SMARTCARD_REQUIRED' }
    @{ Bit = 0x00080000; Name = 'TRUSTED_FOR_DELEGATION' }
    @{ Bit = 0x00100000; Name = 'NOT_DELEGATED' }
    @{ Bit = 0x00200000; Name = 'USE_DES_KEY_ONLY' }
    @{ Bit = 0x00400000; Name = 'DONT_REQ_PREAUTH' }
    @{ Bit = 0x00800000; Name = 'PASSWORD_EXPIRED' }
    @{ Bit = 0x01000000; Name = 'TRUSTED_TO_AUTH_FOR_DELEGATION' }
    @{ Bit = 0x04000000; Name = 'PARTIAL_SECRETS_ACCOUNT' }
)

# The handful of bits that are a finding rather than a fact, with why in one line. Shown next to
# the flag so the meaning does not need looking up.
$script:AdmUacConcerns = @{
    'PASSWD_NOTREQD'                 = 'exempt from the minimum password length, including zero'
    'DONT_EXPIRE_PASSWORD'           = 'the password never has to change'
    'TRUSTED_FOR_DELEGATION'         = 'UNCONSTRAINED delegation -- can impersonate anyone who authenticates to it'
    'TRUSTED_TO_AUTH_FOR_DELEGATION' = 'protocol transition -- can act as a user who never turned up'
    'DONT_REQ_PREAUTH'               = 'AS-REP roastable -- crackable material obtainable with no credential'
    'ENCRYPTED_TEXT_PWD_ALLOWED'     = 'reversible encryption: the password is recoverable in clear'
    'USE_DES_KEY_ONLY'               = 'DES only -- broken encryption'
    'SMARTCARD_REQUIRED'             = 'interactive logon requires a smart card'
    'PASSWD_CANT_CHANGE'             = 'the user cannot change their own password'
}

# ⛔ `[string]` ON A NUMBER FROM A HEX LITERAL RETURNS THE LITERAL TEXT, NOT THE DIGITS.
#
#     function A { [CmdletBinding()] param($Value) ... }
#     A -Value 0x200      ->  $Value.GetType() is Int32, but [string]$Value is "0x200"
#
# PowerShell keeps the original token text of a numeric literal and hands it back on string
# conversion. So the usual idiom
#
#     [void][int]::TryParse([string]$Value, [ref]$n)
#
# silently yields ZERO for a hex-literal argument, because [int]::TryParse does not accept "0x200"
# -- and a bit decoder that quietly sees 0 reports NO FLAGS on a value that has several. It was
# invisible until a test passed 0x200 where the directory always passes a decimal string.
#
# Converting with PowerShell's own cast handles all three shapes the directory and callers
# actually produce: an Int32, the decimal string an LDAP read returns, and a hex literal.
function ConvertTo-AdmInt64 {
    [CmdletBinding()]
    param($Value)
    if ($null -eq $Value) { return 0L }
    if ($Value -is [int64]) { return $Value }
    if ($Value -is [int])   { return [int64]$Value }
    try { [int64]$Value } catch { 0L }
}

function ConvertFrom-AdmUac {
    <#
    .SYNOPSIS
      Decode a userAccountControl value into named flags.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Value)
    $n = ConvertTo-AdmInt64 -Value $Value
    $out = New-Object System.Collections.ArrayList
    foreach ($f in $script:AdmUacFlags) {
        if (-not ($n -band $f.Bit)) { continue }
        [void]$out.Add([pscustomobject]@{
            Flag    = $f.Name
            Bit     = ('0x{0:X}' -f $f.Bit)
            Concern = $(if ($script:AdmUacConcerns.ContainsKey($f.Name)) { $script:AdmUacConcerns[$f.Name] } else { $null })
        })
    }
    $out
}

# groupType is a bitmask, and the SIGN matters: SECURITY_ENABLED is 0x80000000, which is negative
# as a 32-bit signed integer -- the value AD actually returns for a security group is negative,
# and a naive [int] comparison against 0x80000000 fails. Parsed as int64 and masked.
function ConvertFrom-AdmGroupType {
    <#
    .SYNOPSIS
      Decode a groupType value into Scope (Global/DomainLocal/Universal) and Kind (Security/Distribution).
    .DESCRIPTION
      SECURITY_ENABLED is 0x80000000, which AD returns as a NEGATIVE 32-bit integer -- so a naive
      comparison against 0x80000000 fails on every security group in existence.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Value)
    # Same reason as ConvertFrom-AdmUac: not via [string], or a hex literal decodes as zero.
    $n = ConvertTo-AdmInt64 -Value $Value
    if ($n -lt 0) { $n = $n -band 0xFFFFFFFFL }   # back to unsigned
    $scope = if ($n -band 0x8) { 'Universal' } elseif ($n -band 0x4) { 'DomainLocal' }
             elseif ($n -band 0x2) { 'Global' } else { 'unknown' }
    $kind = if ($n -band 0x80000000L) { 'Security' } else { 'Distribution' }
    [pscustomobject]@{ Scope = $scope; Kind = $kind; Raw = $Value }
}

$script:AdmDetailProperties = @(
    'samaccountname', 'name', 'displayname', 'userprincipalname', 'distinguishedname',
    'objectclass', 'objectcategory', 'objectsid', 'objectguid', 'useraccountcontrol',
    'lockouttime', 'badpwdcount', 'badpasswordtime', 'mail', 'description', 'title',
    'department', 'company', 'physicaldeliveryofficename', 'telephonenumber', 'mobile',
    'manager', 'managedby', 'whencreated', 'whenchanged', 'lastlogontimestamp', 'pwdlastset',
    'accountexpires', 'memberof', 'member', 'primarygroupid', 'admincount',
    'serviceprincipalname', 'msds-allowedtodelegateto', 'msds-resultantpso',
    'operatingsystem', 'operatingsystemversion', 'dnshostname', 'grouptype',
    'homedirectory', 'profilepath', 'scriptpath', 'sidhistory', 'usercertificate'
)

function Get-AdmObjectDetail {
    <#
    .SYNOPSIS
      Everything about one directory object, decoded.
    .DESCRIPTION
      One object, read wide: named userAccountControl flags, computed password and lockout state,
      the EFFECTIVE group membership including nesting, and the fine-grained password policy that
      actually applies to this account rather than the domain default.

      ⚠ Reports what the DIRECTORY says. Two of these values are known to lie in specific ways and
      are labelled where they appear: lastLogonTimestamp replicates lazily and can be ~14 days
      stale, and badPwdCount is per-DC and not replicated at all, so the value here is one DC's
      opinion -- Get-AdLockoutSource is what asks all of them.
    .EXAMPLE
      Get-AdmObjectDetail -Target corp.example.com -Identity jsmith
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Identity,   # sAMAccountName, name, UPN or full DN
        [string]$Tier,
        # Nested membership needs a second server-side query. Skip it on a slow link.
        [switch]$SkipEffectiveGroups,
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "read object '$Identity'" -Target $Target -Action {

        # The fixture has no query engine, so Get-AdmSearchResult refuses on it by design. Rather
        # than making the whole detail view unavailable in a demo, build the same SHAPE from what
        # the fixture does hold and label it -- the module's standing rule is that mock and real
        # produce the same shape, or the mock stops being a useful test.
        if ((Get-AdmProviderName) -eq 'mock') {
            $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier
            $hit = $null; $kindGuess = 'user'
            foreach ($cls in @('users', 'groups', 'computers')) {
                $found = @(Invoke-AdmMockSearch -Domain $ctx.Domain -ObjectClass $cls -Identity $Identity)
                if ($found.Count) { $hit = $found[0]; $kindGuess = $cls.TrimEnd('s'); break }
            }
            if (-not $hit) { throw "No object matching '$Identity' in $Target." }
            $muac = Get-AdmRawProp $hit 'useraccountcontrol' 0
            $mlock = 0L; [void][int64]::TryParse([string](Get-AdmRawProp $hit 'lockoutTime' 0), [ref]$mlock)
            return [pscustomobject]([ordered]@{
                Domain = $Target; ObjectClass = $kindGuess
                Name = Get-AdmRawProp $hit 'name'
                SamAccountName = Get-AdmRawProp $hit 'samAccountName'
                DisplayName = Get-AdmRawProp $hit 'displayName'
                UserPrincipalName = Get-AdmRawProp $hit 'userPrincipalName'
                DistinguishedName = Get-AdmRawProp $hit 'distinguishedName'
                Sid = $null; Description = Get-AdmRawProp $hit 'description'
                Enabled = -not (Test-AdmUacDisabled -Uac $muac)
                LockedOut = ($mlock -gt 0); LockedOutSince = ConvertFrom-AdmFileTime (Get-AdmRawProp $hit 'lockoutTime')
                BadPasswordCount = $null; BadPasswordTime = $null
                PasswordLastSet = ConvertFrom-AdmFileTime (Get-AdmRawProp $hit 'pwdLastSet')
                PasswordPolicy = 'not modelled by the fixture'; PasswordPolicyDetail = $null
                PasswordNeverExpires = Test-AdmUacPasswordNeverExpires -Uac $muac
                MustChangePassword = $false; PasswordExpiresOn = $null; DaysToExpiry = $null
                LastLogonTimestamp = ConvertFrom-AdmFileTime (Get-AdmRawProp $hit 'lastLogonTimestamp')
                AccountExpires = $null
                WhenCreated = Get-AdmRawProp $hit 'whencreated'; WhenChanged = $null
                UacValue = $muac; UacFlags = @(ConvertFrom-AdmUac -Value $muac | ForEach-Object { $_.Flag })
                UacConcerns = @(ConvertFrom-AdmUac -Value $muac | Where-Object { $_.Concern })
                AdminCount = $null
                MemberOfDirect = @(); MemberOfEffective = @()
                EffectiveNote = 'the fixture does not model group nesting'
                PrimaryGroupId = $null
                Title = $null; Department = $null; Company = $null; Office = $null
                Mail = Get-AdmRawProp $hit 'mail'; Telephone = $null; Mobile = $null
                Manager = $null; ManagedBy = $null
                ServicePrincipalNames = @(); AllowedToDelegateTo = @(); SidHistory = @()
                Members = @(Get-AdmRawProp $hit 'members' @())
                IsMock = $true
            })
        }

        $v = ConvertTo-AdmLdapFilterValue -Value $Identity
        # A DN is matched exactly; anything else is matched against the three names people
        # actually type.
        #
        # ⚠ CONSTRAINED TO SECURITY PRINCIPALS. Searching the domain naming context for
        # `(name=DC01)` alone also matches the AD-INTEGRATED DNS NODE of the same name, which
        # lives under CN=MicrosoftDNS,CN=System in the same partition -- so asking for a domain
        # controller by name came back "matched more than one object" on a perfectly ordinary
        # domain. objectClass=user covers computers too, since computer derives from user.
        $filter = if ($Identity -match '^(CN|OU|DC)=') {
            "(distinguishedName=$v)"
        } else {
            "(&(|(objectClass=user)(objectClass=group)(objectClass=computer))" +
            "(|(sAMAccountName=$v)(userPrincipalName=$v)(name=$v)))"
        }

        # Limit 5, not 2: an ambiguity is worth REPORTING with its candidates rather than just
        # asserting one exists, so the caller can pick a distinguished name.
        $raw = @(Get-AdmSearchResult -Target $Target -Tier $Tier -Filter $filter `
                    -Properties $script:AdmDetailProperties -Limit 5 -UseDnsLookup:$UseDnsLookup)
        if (-not $raw.Count) { throw "No object matching '$Identity' in $Target." }
        if ($raw.Count -gt 1) {
            $cands = @($raw | ForEach-Object { [string](Get-AdmRawProp $_ 'distinguishedname') })
            throw ("'$Identity' matched $($raw.Count) objects. Use one of these distinguished names:`r`n  " +
                   ($cands -join "`r`n  "))
        }
        $o = $raw[0]

        $classes = @(Get-AdmRawProp $o 'objectclass' @())
        $kind = if ($classes -contains 'computer') { 'computer' }
                elseif ($classes -contains 'group') { 'group' }
                elseif ($classes -contains 'user') { 'user' }
                else { 'other' }

        $dn  = [string](Get-AdmRawProp $o 'distinguishedname')
        $uac = Get-AdmRawProp $o 'useraccountcontrol' 0
        $uacFlags = @(ConvertFrom-AdmUac -Value $uac)

        $lockout = 0L
        [void][int64]::TryParse([string](Get-AdmRawProp $o 'lockouttime' 0), [ref]$lockout)

        # --- password state ---------------------------------------------------------------------
        # ⭐ THE PSO IS READ, not just the domain default. msDS-ResultantPSO is computed by the DC
        # and names the fine-grained policy that actually applies to this account -- which is the
        # one thing a domain-wide maxPwdAge cannot tell you, and the reason "expiring soon" reports
        # built on the default policy quietly get the wrong answer for exactly the accounts that
        # have a special policy (usually the privileged ones).
        $psoDn = [string](Get-AdmRawProp $o 'msds-resultantpso')
        $policy = $null; $policySource = 'domain default'
        if ($psoDn) {
            try {
                $pv = ConvertTo-AdmLdapFilterValue -Value $psoDn
                $pso = @(Get-AdmSearchResult -Target $Target -Tier $Tier -Filter "(distinguishedName=$pv)" `
                            -Properties @('name', 'msds-maximumpasswordage', 'msds-minimumpasswordlength',
                                          'msds-lockoutthreshold', 'msds-passwordcomplexityenabled',
                                          'msds-passwordsettingsprecedence') -Limit 2)[0]
                if ($pso) {
                    # Durations are stored as NEGATIVE 100-nanosecond intervals.
                    $maxAgeTicks = 0L
                    [void][int64]::TryParse([string](Get-AdmRawProp $pso 'msds-maximumpasswordage' 0), [ref]$maxAgeTicks)
                    $policy = [pscustomobject]@{
                        Name              = Get-AdmRawProp $pso 'name'
                        MaxPasswordAgeDays = $(if ($maxAgeTicks -ne 0) { [math]::Round([timespan]::FromTicks([math]::Abs($maxAgeTicks)).TotalDays, 1) } else { $null })
                        MinPasswordLength = Get-AdmRawProp $pso 'msds-minimumpasswordlength'
                        LockoutThreshold  = Get-AdmRawProp $pso 'msds-lockoutthreshold'
                        ComplexityEnabled = Get-AdmRawProp $pso 'msds-passwordcomplexityenabled'
                        Precedence        = Get-AdmRawProp $pso 'msds-passwordsettingsprecedence'
                    }
                    $policySource = "fine-grained policy '$($policy.Name)'"
                }
            } catch {
                # A PSO that cannot be read is UNKNOWN, not absent -- saying "domain default" here
                # would be a guess presented as a fact.
                $policySource = 'a fine-grained policy applies but could not be read'
            }
        }

        $maxAgeDays = $null
        if ($policy -and $policy.MaxPasswordAgeDays) { $maxAgeDays = $policy.MaxPasswordAgeDays }
        else {
            try { $maxAgeDays = (Get-AdmPasswordPolicy -Target $Target -Tier $Tier).MaxPasswordAgeDays } catch { }
        }

        $pwdLastSet = ConvertFrom-AdmFileTime (Get-AdmRawProp $o 'pwdlastset')
        $neverExpires = [bool](@($uacFlags | Where-Object { $_.Flag -eq 'DONT_EXPIRE_PASSWORD' }).Count)
        $mustChange = ([string](Get-AdmRawProp $o 'pwdlastset' '1') -eq '0')
        $expiresOn = $null; $daysToExpiry = $null
        if (-not $neverExpires -and -not $mustChange -and $maxAgeDays -and $pwdLastSet) {
            $expiresOn = $pwdLastSet.AddDays($maxAgeDays)
            $daysToExpiry = [math]::Round(($expiresOn - (Get-Date).ToUniversalTime()).TotalDays, 1)
        }

        # --- effective group membership ----------------------------------------------------------
        # ⭐ LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941) walks the nesting SERVER-SIDE, so
        # this is the membership that actually applies rather than the direct memberOf list. The
        # difference is the whole point: nobody is ever added to Domain Admins directly, they are
        # added to a group that is in a group that is in it.
        # ⛔ RANGED. Past ~1500 groups AD renames `memberOf`, and a plain read then reports the
        # account as a member of NOTHING -- which on this panel reads as an unprivileged account.
        $directRanged = Get-AdmRangedProp $o 'memberof'
        $direct = @($directRanged.Values)
        $effective = @()
        $effectiveNote = $null
        if (-not $SkipEffectiveGroups -and $dn) {
            try {
                $dnEsc = $dn -replace '\\', '\5c' -replace '\(', '\28' -replace '\)', '\29' -replace '\*', '\2a'
                # ⛔ THE LIMIT IS A CORRECTNESS PROBLEM HERE, NOT A DISPLAY ONE. A truncated read
                # of this list DROPS GROUPS -- and the whole reason to compute effective membership
                # is to find the privileged one nobody expected. A short list looks like a clean
                # answer. So: a limit far above any real account's membership, and if it is ever
                # reached the result is reported as INCOMPLETE rather than presented as the set.
                $effLimit = 5000
                Reset-AdmSearchTruncated
                $raw = @(Get-AdmSearchResult -Target $Target -Tier $Tier -Limit $effLimit `
                    -Filter "(member:1.2.840.113556.1.4.1941:=$dnEsc)" `
                    -Properties @('samaccountname', 'distinguishedname'))
                $effective = @($raw | ForEach-Object { [string](Get-AdmRawProp $_ 'samaccountname') } |
                               Where-Object { $_ } | Sort-Object)
                if (Get-AdmSearchTruncated) {
                    $effectiveNote = "INCOMPLETE: the nested-membership read stopped at $effLimit groups, so this list may be missing some -- including privileged ones. Treat it as a floor, not the set."
                }
            } catch {
                $effectiveNote = "nested membership could not be resolved: $($_.Exception.Message)"
            }
        }
        # Primary group is a real membership and appears in NEITHER list, by construction.
        $primaryRid = Get-AdmRawProp $o 'primarygroupid'

        $sid = ConvertTo-AdmSidString -Raw (Get-AdmRawProp $o 'objectsid')

        $detail = [ordered]@{
            Domain            = $Target
            ObjectClass       = $kind
            Name              = Get-AdmRawProp $o 'name'
            SamAccountName    = Get-AdmRawProp $o 'samaccountname'
            DisplayName       = Get-AdmRawProp $o 'displayname'
            UserPrincipalName = Get-AdmRawProp $o 'userprincipalname'
            DistinguishedName = $dn
            Sid               = $sid
            Description       = Get-AdmRawProp $o 'description'

            Enabled           = -not (Test-AdmUacDisabled -Uac $uac)
            LockedOut         = ($lockout -gt 0)
            LockedOutSince    = ConvertFrom-AdmFileTime (Get-AdmRawProp $o 'lockouttime')
            # ⚠ ONE DC'S OPINION. badPwdCount is not replicated; the real answer needs every DC.
            BadPasswordCount  = Get-AdmRawProp $o 'badpwdcount'
            BadPasswordTime   = ConvertFrom-AdmFileTime (Get-AdmRawProp $o 'badpasswordtime')

            PasswordLastSet      = $pwdLastSet
            PasswordPolicy       = $policySource
            PasswordPolicyDetail = $policy
            PasswordNeverExpires = $neverExpires
            MustChangePassword   = $mustChange
            PasswordExpiresOn    = $expiresOn
            DaysToExpiry         = $daysToExpiry

            LastLogonTimestamp = ConvertFrom-AdmFileTime (Get-AdmRawProp $o 'lastlogontimestamp')
            AccountExpires     = ConvertFrom-AdmFileTime (Get-AdmRawProp $o 'accountexpires')
            WhenCreated        = Get-AdmRawProp $o 'whencreated'
            WhenChanged        = Get-AdmRawProp $o 'whenchanged'

            UacValue           = $uac
            UacFlags           = @($uacFlags | ForEach-Object { $_.Flag })
            UacConcerns        = @($uacFlags | Where-Object { $_.Concern })
            AdminCount         = Get-AdmRawProp $o 'admincount'

            MemberOfDirect     = @($direct)
            MemberOfEffective  = @($effective)
            EffectiveNote      = $effectiveNote
            PrimaryGroupId     = $primaryRid

            Title       = Get-AdmRawProp $o 'title'
            Department  = Get-AdmRawProp $o 'department'
            Company     = Get-AdmRawProp $o 'company'
            Office      = Get-AdmRawProp $o 'physicaldeliveryofficename'
            Mail        = Get-AdmRawProp $o 'mail'
            Telephone   = Get-AdmRawProp $o 'telephonenumber'
            Mobile      = Get-AdmRawProp $o 'mobile'
            Manager     = Get-AdmRawProp $o 'manager'
            ManagedBy   = Get-AdmRawProp $o 'managedby'

            ServicePrincipalNames = @(Get-AdmRawProp $o 'serviceprincipalname' @())
            AllowedToDelegateTo   = @(Get-AdmRawProp $o 'msds-allowedtodelegateto' @())
            SidHistory            = @(@(Get-AdmRawProp $o 'sidhistory' @()) | ForEach-Object { ConvertTo-AdmSidString -Raw $_ } | Where-Object { $_ })
        }

        if ($kind -eq 'group') {
            $gt = ConvertFrom-AdmGroupType -Value (Get-AdmRawProp $o 'grouptype' 0)
            $detail['GroupScope'] = $gt.Scope
            $detail['GroupKind']  = $gt.Kind

            # ⛔ THE PLAIN `member` READ IS NOT A SHORT LIST PAST 1500 -- IT IS AN EMPTY ONE.
            # AD returns the attribute as `member;range=0-1499`, a DIFFERENT property name, so a
            # request for `member` on a large group yields NOTHING. A count taken from it would
            # report a 4000-member group as empty, and a "truncated if count >= 1500" check can
            # never fire because the count is zero. So membership is counted by SEARCHING for the
            # members instead, which has no range limit.
            $plainRanged = Get-AdmRangedProp $o 'member'
            $plain = @($plainRanged.Values)
            $detail['Members'] = $plain
            $counted = $null; $countTruncated = $false
            try {
                $dnEsc2 = $dn -replace '\\', '\5c' -replace '\(', '\28' -replace '\)', '\29' -replace '\*', '\2a'
                # ⚠ A production group can be very large -- Domain Users is every account in the
                # domain. A limit sized against a lab turns this count into a wrong number that
                # somebody reads as fact, so it is high AND a hit on it is detected.
                $memLimit = 200000
                Reset-AdmSearchTruncated
                $found = @(Get-AdmSearchResult -Target $Target -Tier $Tier -Limit $memLimit `
                                -Filter "(memberOf=$dnEsc2)" -Properties @('distinguishedname'))
                $counted = $found.Count
                $countTruncated = [bool](Get-AdmSearchTruncated)
            } catch { }
            # ⛔ RE-RAISE WHAT THE RESET ABOVE ERASED. Get-AdmRangedProp sets the module flag when
            # the attribute was renamed, and the Reset before the count search then clears it --
            # so without this, a group whose `member` was ranged but whose count search completed
            # would report truncated:false to the CLI envelope. Two different limits share one
            # flag; whichever fired must survive to the caller.
            if ($plainRanged.Truncated) { $script:AdmLastSearchTruncated = $true }
            $detail['MemberCount'] = $counted
            $detail['MembersTruncated'] = $plainRanged.Truncated
            $detail['MemberCountTruncated'] = $countTruncated
            # ⚠ The search finds members whose memberOf points here. It does NOT find accounts whose
            # PRIMARY group this is -- those are members with the same rights and appear in neither
            # `member` nor `memberOf`, by construction.
            $detail['MemberCountNote'] = if ($null -eq $counted) {
                'could not be counted'
            } elseif ($countTruncated) {
                "AT LEAST $counted -- the read stopped at its limit, so this is a floor rather than the total."
            } elseif ($plainRanged.Truncated) {
                "$counted by search. The member attribute was RANGED by the directory, so Members below holds only the first $($plain.Count) -- not a short list by accident, a window. Primary-group members are in neither."
            } elseif ($counted -ne $plain.Count) {
                "$counted by search, $($plain.Count) from the member attribute -- the attribute is paged at 1500 and returns nothing above it. Primary-group members are in neither."
            } else {
                'primary-group members are not included in this count'
            }
        }
        if ($kind -eq 'computer') {
            $detail['DnsHostName']            = Get-AdmRawProp $o 'dnshostname'
            $detail['OperatingSystem']        = Get-AdmRawProp $o 'operatingsystem'
            $detail['OperatingSystemVersion'] = Get-AdmRawProp $o 'operatingsystemversion'
            $detail['IsDomainController']     = [bool]((0 + $uac) -band 0x2000)
        }
        if ($kind -eq 'user') {
            $detail['HomeDirectory'] = Get-AdmRawProp $o 'homedirectory'
            $detail['ProfilePath']   = Get-AdmRawProp $o 'profilepath'
            $detail['ScriptPath']    = Get-AdmRawProp $o 'scriptpath'
        }

        [pscustomobject]$detail
    }
}
