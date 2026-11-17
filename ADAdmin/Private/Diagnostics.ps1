# Diagnostics.ps1 -- turn a directory failure into something a non-scripter can act on.
#
# THE PROBLEM THIS SOLVES. A hardened AD environment does not fail with "permission denied". It
# fails with 0x80090322, or a COMException whose message is "Unknown error (0x80005000)", or an
# empty result set that looks like "no users found". Someone who does not write PowerShell cannot
# get from there to "the DC requires LDAP signing and you connected on 389 in the clear".
#
# So every failure goes through the catalog below and comes out as four things:
#   WHAT happened   -- one sentence, no jargon
#   WHY             -- the actual cause, in plain English
#   FIX             -- concrete, ordered, each one something a person can DO
#   TECHNICAL       -- the raw codes, kept for whoever does want them
#
# ⛔ RULE FOR THIS FILE: never guess. If no rule matches, say so plainly and hand over the raw
# error rather than inventing a plausible cause. A confident wrong diagnosis is worse than
# "unrecognised" -- it sends someone to fix the wrong thing.

# LDAP bind sub-status. The DC returns these inside the extended error text as "data 52e" and
# they are the single most useful field in the whole failure, because they separate "wrong
# password" from "account locked" from "you are not allowed to log on at this hour".
$script:AdmLdapSubStatus = @{
    '525' = @{ t = 'That account does not exist'
               w = 'The directory has no account with that name. Check spelling, and check you are aimed at the right domain -- the same username can exist in one forest and not another.'
               f = @('Run: adm user list -Target <domain> -Identity <partial-name>   to see what does exist',
                     'Confirm the target resolves to the domain you meant: adm domain resolve -Target <target>') }
    '52e' = @{ t = 'Wrong username or password'
               w = 'The credential stored for this domain was rejected. The account exists; the password did not match.'
               f = @('Re-enter the credential: adm domain set-cred -Name <domain> -Tier <read|write>',
                     'Check the username format -- both DOMAIN\user and user@domain.tld work, but the DOMAIN part must be THIS domain',
                     'If the password was recently changed or rotated, the store still holds the old one') }
    '530' = @{ t = 'This account is not allowed to sign in at this time of day'
               w = 'Logon hours are restricted on the account, and right now is outside them. Common on service accounts in hardened environments.'
               f = @('Use a service account without logon-hour restrictions for automation',
                     'Or ask a domain admin to widen the logon hours on this account') }
    '531' = @{ t = 'This account is not allowed to sign in from this computer'
               w = 'The account has a workstation restriction and the machine you are running from is not on its list.'
               f = @('Run the toolkit from an approved administrative workstation',
                     'Or ask a domain admin to add this machine to the account''s allowed workstations') }
    '532' = @{ t = 'The password has expired'
               w = 'The credential is correct but the password is past its expiry date.'
               f = @('Change the password on the account, then update the store: adm domain set-cred -Name <domain> -Tier <tier>',
                     'For service accounts, consider a password that does not expire, or a gMSA') }
    '533' = @{ t = 'The account is disabled'
               w = 'Someone has disabled this account in the directory.'
               f = @('Ask a domain admin to re-enable it, or switch to a different service account') }
    '701' = @{ t = 'The account has expired'
               w = 'The account has an expiry date and it has passed.'
               f = @('Ask a domain admin to extend or clear the account expiry date') }
    '773' = @{ t = 'The password must be changed before this account can be used'
               w = 'The account is flagged "user must change password at next logon", which blocks it from authenticating this way.'
               f = @('Change the password interactively once, then store the new one',
                     'For a service account, clear the "must change at next logon" flag') }
    '775' = @{ t = 'The account is locked out'
               w = 'Too many failed sign-in attempts have locked this account. Note that a stale password in the store can cause this by retrying automatically.'
               f = @('Unlock it: adm user unlock -Target <domain> -Identity <account>',
                     'Then fix the stored password, or it will lock again on the next attempt') }
}

# Signature -> diagnosis. Ordered: the FIRST match wins, so put the specific before the general.
$script:AdmDiagnosisRules = @(
    @{
        Code = 'LDAP-SIGNING-REQUIRED'
        Match = { param($c) $c.AnyCode -match '8009032[12]' -or $c.Text -match 'strong(er)? authentication is required' }
        Severity = 'error'
        Title = 'The domain controller refuses unsigned connections'
        Why = 'This DC is hardened: it requires LDAP signing (and often channel binding), so a plain connection on port 389 is rejected before your credential is even considered. Microsoft has been enabling this by default, so it is increasingly the normal state rather than the exception.'
        Fix = @(
            'Use LDAPS. Re-register the domain with SSL on: adm domain add -Name <n> -Dns <fqdn> -Force   (SSL and port 636 are the default)',
            'If LDAPS is not available, the connection must be signed and sealed -- ADAdmin already requests this on port 389, so a failure here usually means the DC additionally requires channel binding, which needs LDAPS',
            'Confirm 636 is reachable: adm domain test -Target <target>'
        )
    }
    @{
        Code = 'LDAPS-CERT-UNTRUSTED'
        Match = { param($c) $c.AnyCode -match '8009030[eE]|80072030' -and $c.Text -match 'certificate|trust' }
        Severity = 'error'
        Title = 'The domain controller''s certificate is not trusted by this computer'
        Why = 'You connected over LDAPS (port 636) and the DC presented a certificate this machine will not accept -- usually because the issuing CA is not in the local trust store. This is normal on a machine that is not joined to that forest, which is exactly the situation this toolkit is built for.'
        Fix = @(
            'Install the forest''s issuing CA certificate into Local Machine > Trusted Root Certification Authorities on this computer',
            'Or connect on port 389 with signing instead: adm domain add -Name <n> -Dns <fqdn> -UseSsl $false -Force',
            'Do NOT disable certificate validation as a workaround -- that removes the protection LDAPS exists to provide'
        )
    }
    @{
        Code = 'KERBEROS-CLOCK-SKEW'
        Match = { param($c) $c.AnyCode -match '80090324' -or $c.Text -match 'clock.*skew|time difference' }
        Severity = 'error'
        Title = 'This computer''s clock is too far from the domain controller''s'
        Why = 'Kerberos refuses to authenticate when the two clocks differ by more than about five minutes. This is a very common failure on a laptop or a VM that has been suspended, and the error text rarely mentions the clock.'
        Fix = @(
            'Check the difference, then correct this machine''s time',
            'On a domain-joined machine: w32tm /resync',
            'On a standalone machine, set the time zone AND the clock -- a wrong time zone produces exactly this error'
        )
    }
    @{
        Code = 'BIND-BY-IP-NTLM-BLOCKED'
        Match = { param($c) $c.AnyCode -match '8007052[eE]' -and $c.Target -match '^\d{1,3}(\.\d{1,3}){3}$' }
        Severity = 'error'
        Title = 'Signing in by IP address was rejected'
        Why = 'Connecting to a domain controller by IP address forces NTLM, because Kerberos needs a name to look up a ticket. Hardened environments frequently disable NTLM outright, so the same credential that works by hostname fails by IP.'
        Fix = @(
            'Register the domain controller by its FQDN instead of its IP: adm domain add -Name <n> -Dns <fqdn> -Dc dc01.example.com -Force',
            'If this machine cannot resolve that name, add it to C:\Windows\System32\drivers\etc\hosts, or point this machine at the forest''s DNS',
            'Verify with: adm domain test -Target <fqdn>'
        )
    }
    @{
        Code = 'CREDENTIAL-REJECTED'
        Match = { param($c) $c.AnyCode -match '8007052[eE]' -or $c.Text -match 'user name or bad password|invalid credentials' }
        Severity = 'error'
        Title = 'The stored username or password was rejected'
        Why = 'The domain controller answered, but would not accept the credential held for this domain.'
        Fix = @(
            'Re-enter it: adm domain set-cred -Name <domain> -Tier <read|write>',
            'Check the username is qualified for THIS domain -- across untrusted forests, DOMAIN\user from the wrong forest is a different account',
            'If the password was rotated recently, the store still has the old one'
        )
    }
    @{
        Code = 'ACCESS-DENIED'
        Match = { param($c) $c.AnyCode -match '80070005' -or $c.Text -match 'access is denied|insufficient (access )?rights' }
        Severity = 'error'
        Title = 'The account is not allowed to do that'
        Why = 'The credential signed in successfully, but it does not hold the directory rights this operation needs. In a least-privilege environment this is expected for writes: the read account is deliberately unable to change anything.'
        Fix = @(
            'If this was a change (unlock, enable, disable, reset), use the write credential: add -Tier write to the command',
            'Store one if there is not one yet: adm domain set-cred -Name <domain> -Tier write',
            'If the write account is already in use, it needs delegated rights on the target objects -- ask a domain admin to delegate the specific permission (for example "Reset password" on the relevant OU) rather than granting Domain Admin'
        )
    }
    @{
        Code = 'RODC-WRITE-REFUSED'
        Match = { param($c) $c.Text -match 'read.only|RODC|referral' -and $c.Operation -match 'unlock|enable|disable|reset' }
        Severity = 'error'
        Title = 'That domain controller cannot accept changes'
        Why = 'You are talking to a read-only domain controller (RODC), common at branch sites. It will answer queries all day but refuses every write and returns a referral instead.'
        Fix = @(
            'Point this domain at a writable DC: adm domain add -Name <n> -Dns <fqdn> -Dc <writable-dc-fqdn> -Force',
            'Reads can stay on the RODC; only changes need the writable one'
        )
    }
    @{
        Code = 'DC-DISABLE-REFUSED'
        Match = { param($c) $c.Text -match 'is a DOMAIN CONTROLLER' }
        Severity = 'warn'
        Title = 'Refused: that computer account belongs to a domain controller'
        Why = 'The toolkit will not disable a domain controller''s computer account, because doing so takes that DC offline -- authentication, group policy and DNS for everything that depends on it. This refusal exists specifically because a DC looks IDLE to any staleness sweep: nobody interactively logs on to one, so it is the object such a sweep is most likely to select by mistake. This is a guard working, not a fault.'
        Fix = @(
            'If the DC is genuinely gone, this is not the tool for it. An unrecoverable DC must be removed with a metadata cleanup (ntdsutil, or Active Directory Users and Computers, which now does it for you) so its replication and FSMO state goes with it -- disabling the account leaves all of that behind',
            'If the DC is being retired properly, demote it first: dcpromo / Uninstall-ADDSDomainController on the DC itself, which removes the object cleanly',
            'If you were sweeping for stale computers, nothing is wrong -- domain controllers are excluded from those results automatically'
        )
    }
    @{
        Code = 'PASSWORD-RPC-UNAVAILABLE'
        Match = { param($c) $c.AnyCode -match '800706ba' -or $c.Text -match 'RPC server is unavailable' }
        Severity = 'error'
        Title = 'Setting the password fell back to a network protocol this machine cannot reach'
        Why = 'The older Windows way of setting a password (ADSI SetPassword) tries LDAP over TLS first and then falls back to RPC on ports 135 and 445. From a machine that is not inside the target network, RPC to a domain controller is almost always blocked, so it fails with "The RPC server is unavailable" -- an error that mentions neither passwords nor the real cause. ADAdmin does not use that path: it writes the password as an LDAP attribute over the encrypted connection it already has, which needs no RPC.'
        Fix = @(
            'If you are seeing this from ADAdmin itself, the connection is not encrypted -- writing the password attribute requires it. Re-register the domain with SSL: adm domain add -Name <n> -Dns <fqdn> -Force',
            'Confirm the channel: adm domain test -Target <target>',
            'If you are seeing this from your own script, it is calling SetPassword. Use Reset-AdmUserPassword instead, or open 135/445 to the DC -- which is usually not what you want from a portable toolkit'
        )
    }
    @{
        Code = 'PASSWORD-POLICY-REFUSED'
        Match = { param($c) $c.AnyCode -match '80072035' -and $c.Operation -match 'reset|password' }
        Severity = 'error'
        Title = 'The new password was refused by the domain''s password policy'
        Why = 'The directory declined the change ("unwilling to perform"). For a password reset this nearly always means the new password failed complexity, minimum length, or password-history rules -- or the minimum password age has not elapsed since the last change.'
        Fix = @(
            'Use a longer password with mixed case, digits and symbols, and one that has not been used before on this account',
            'Check the domain policy: the default is 7 characters and 24 remembered passwords, but hardened domains commonly require 14 or more',
            'If the password was just changed, minimum password age may block another change for a day'
        )
    }
    @{
        Code = 'PASSWORD-RESET-NEEDS-SECURE-CHANNEL'
        Match = { param($c) $c.Operation -match 'reset|password' -and ($c.AnyCode -match '8007202f|80070005' -or $c.Text -match 'secure|encrypt') }
        Severity = 'error'
        Title = 'Setting a password requires an encrypted connection'
        Why = 'Active Directory refuses to accept a new password over an unencrypted channel. If the connection is plain LDAP on 389 without sealing, the reset is rejected even when the account has every right it needs.'
        Fix = @(
            'Use LDAPS: adm domain add -Name <n> -Dns <fqdn> -Force   (SSL on 636 is the default)',
            'Verify the channel first: adm domain test -Target <target>'
        )
    }
    @{
        Code = 'UNWILLING-TO-PERFORM'
        Match = { param($c) $c.AnyCode -match '80072035' }
        Severity = 'error'
        Title = 'The domain controller declined the request'
        Why = 'The directory understood the request and refused it. This is a policy refusal rather than a permission or connection problem -- something about the operation itself is not allowed here.'
        Fix = @(
            'Check whether the object is protected -- accounts in privileged groups are governed by AdminSDHolder and resist changes',
            'Check whether a domain policy forbids this specific change',
            'The raw server message below usually names the constraint'
        )
    }
    @{
        Code = 'OBJECT-NOT-FOUND'
        Match = { param($c) $c.AnyCode -match '80072030' -or $c.Text -match 'no such object' }
        Severity = 'error'
        Title = 'No object with that name exists in this domain'
        Why = 'The directory answered normally and simply has nothing matching. Very often the name is right but the DOMAIN is wrong -- across untrusted forests the same name lives in several places.'
        Fix = @(
            'Check which domain the target resolved to: adm domain resolve -Target <target>',
            'Search more loosely: adm user list -Target <domain> -Identity <partial-name>'
        )
    }
    @{
        Code = 'LDAPS-HANDSHAKE-FAILED'
        # Ordered BEFORE server-unreachable deliberately: the codes are identical and only the
        # hint separates them.
        Match = { param($c) $c.AnyCode -match '8007203a' -and $c.Hint.UseSsl -and $c.Hint.PortOpen }
        Severity = 'error'
        Title = 'The LDAPS port is open but the secure connection could not be established'
        Why = 'ADSI reports almost every TLS failure as "The server is not operational", which reads like the domain controller being down -- it is not. Port 636 accepted the connection, so the DC is there and listening; the handshake is what failed. On a machine that is not joined to the forest the cause is nearly always that the DC''s certificate is issued by a CA this computer does not trust, or the certificate name does not match the address you connected to (connecting by IP does this every time, because the certificate names the DC, not its address).'
        Fix = @(
            'Connect by the DC''s FQDN rather than its IP -- a certificate never matches an IP address',
            'Install the forest''s issuing CA certificate into Local Machine > Trusted Root Certification Authorities on this computer (adm scan will offer this)',
            'Or use port 389 with signing and sealing, which needs no certificate: adm domain add -Name <n> -Dns <fqdn> -UseSsl $false -Force',
            'Note that password RESETS still require an encrypted channel, so plain 389 will do reads and unlocks but not password changes'
        )
    }
    @{
        Code = 'SERVER-UNREACHABLE'
        Match = { param($c) $c.AnyCode -match '8007203a|80040e37|8007054b' -or $c.Text -match 'server is not operational|cannot contact|no such (host|domain)|actively refused|timed out' }
        Severity = 'error'
        Title = 'Could not reach the domain controller'
        Why = 'Nothing answered on the network. Either the name does not resolve from this machine, the address is wrong, or a firewall is in the way. On a machine that is not joined to the target forest, name resolution is the usual culprit -- the forest''s DNS is the only thing that knows its own names.'
        Fix = @(
            'Register the DC by IP or add it to hosts, rather than relying on this machine''s DNS',
            'Check the ports are open from here -- LDAP is 389, LDAPS is 636',
            'Confirm with: adm domain test -Target <target>'
        )
    }
    @{
        # The one entry here that is the toolkit REFUSING rather than something going wrong. It
        # reads as an error because it stops the operation, so it needs the explanation more than
        # most: otherwise "it just failed" invites raising the limit until the message goes away,
        # which is exactly the wrong reaction.
        Code = 'READ-TRUNCATED'
        Match = { param($c) $c.Text -match 'truncated at (its|the) size limit' }
        Severity = 'error'
        Title = 'The directory returned only part of the answer, so this refused rather than guess'
        Why = 'A search stopped at its size limit. Harmless for a list you are reading, but this operation DERIVES something from the whole set -- whether a policy is linked anywhere, which accounts already exist, how much an OU delete would take with it. Computed from a partial read those come out wrong and look exactly like right answers, so it stops instead.'
        Fix = @(
            'Narrow the operation: a smaller SearchBase, a specific OU, or a filter matching fewer objects',
            'Split the work -- a bulk import per OU rather than one file for the whole domain',
            'Raise -Limit only if you know the real count and it genuinely exceeds the default. The limit is not the problem; answering from a partial read is'
        )
    }
    @{
        # ⛔ MUST STAY BELOW READ-TRUNCATED. The first rule whose Match returns true wins, and
        # this pattern is a SUPERSET of that one -- put it first and the specific diagnosis can
        # never fire, silently, with no error anywhere. Asserted in tests/Truncation.Tests.ps1.
        Code = 'SIZE-LIMIT-EXCEEDED'
        Match = { param($c) $c.Text -match 'size limit|admin limit' }
        Severity = 'warn'
        Title = 'The directory returned only part of the results'
        Why = 'Active Directory caps how many objects one query may return (1000 by default). The results you got are real, but they are not all of them -- which is dangerous to act on, because "not in the list" does not mean "does not exist".'
        Fix = @(
            'Narrow the search with -Identity so fewer objects match',
            'Do not treat this result as a complete inventory'
        )
    }
    @{
        Code = 'STORE-LOCKED'
        Match = { param($c) $c.Text -match 'store is locked|auto-locked' }
        Severity = 'warn'
        Title = 'The credential store is locked'
        Why = 'The store locks itself after a period of inactivity so a decrypted key does not sit in memory indefinitely.'
        Fix = @('Unlock it again: adm store unlock', 'In the window, enter your passphrase on the unlock screen')
    }
    @{
        Code = 'STORE-BAD-PASSPHRASE'
        Match = { param($c) $c.Text -match 'does not open this store|Authentication failed' }
        Severity = 'error'
        Title = 'That passphrase did not open the store'
        Why = 'Your passphrase was tried against every admin''s wrap in the file and none of them opened. Either the passphrase is wrong, or this file is not the store you were enrolled in.'
        Fix = @(
            'Check you are opening the right file -- adm store status shows the path in use',
            'If you were recently added, make sure you are using the passphrase YOU set, not the one that created the store',
            'ADADMIN_STORE overrides the default location and may be pointing somewhere unexpected'
        )
    }
    @{
        Code = 'AMBIGUOUS-TARGET'
        Match = { param($c) $c.Text -match 'matches more than one' }
        Severity = 'warn'
        Title = 'That target could belong to more than one registered domain'
        Why = 'Two domain profiles match it equally well. The toolkit refuses to guess, because binding to the wrong forest is exactly the mistake it exists to prevent.'
        Fix = @(
            'Add the specific host to one profile''s Hosts list so it wins outright',
            'Or give a more specific target -- a full FQDN rather than a short name'
        )
    }
    @{
        Code = 'UNRESOLVED-TARGET'
        Match = { param($c) $c.Text -match 'No registered domain matches' }
        Severity = 'warn'
        Title = 'That target does not belong to any registered domain'
        Why = 'Nothing in the store claims this name. A bare hostname cannot be attributed on its own -- the toolkit will not guess which forest it belongs to.'
        Fix = @(
            'List what is registered: adm domain list',
            'Register the domain: adm domain add -Name <n> -Dns <fqdn> -Dc <dc-fqdn>',
            'Or map this specific host: add it to a profile''s -Host list'
        )
    }
)

function Get-AdmErrorContext {
    <#
      Flatten an ErrorRecord or Exception into the fields the rules match on. Walks the whole
      inner-exception chain: the useful code is almost never on the outermost exception.
    #>
    [CmdletBinding()]
    param($ErrorObject, [string]$Operation, [string]$Target, [hashtable]$Hint)

    $ex = if ($ErrorObject -is [System.Management.Automation.ErrorRecord]) { $ErrorObject.Exception }
          elseif ($ErrorObject -is [Exception]) { $ErrorObject }
          else { $null }

    $texts = @(); $codes = @(); $types = @(); $server = $null
    $cur = $ex
    $depth = 0
    while ($cur -and $depth -lt 8) {
        $texts += $cur.Message
        $types += $cur.GetType().FullName
        # HResult is the reliable numeric identity; format it the way the docs and the web do.
        try { if ($cur.HResult) { $codes += ('0x{0:x8}' -f $cur.HResult) } } catch { }
        # DirectoryServicesCOMException carries the good stuff on extra properties.
        foreach ($p in @('ExtendedError', 'ErrorCode')) {
            try { if ($cur.PSObject.Properties[$p] -and $cur.$p) { $codes += ('0x{0:x8}' -f [int]$cur.$p) } } catch { }
        }
        foreach ($p in @('ExtendedErrorMessage', 'ServerErrorMessage')) {
            try { if ($cur.PSObject.Properties[$p] -and $cur.$p) { $texts += [string]$cur.$p; $server = [string]$cur.$p } } catch { }
        }
        $cur = $cur.InnerException; $depth++
    }
    if ($ErrorObject -is [System.Management.Automation.ErrorRecord]) {
        $texts += $ErrorObject.ToString()
        if ($ErrorObject.FullyQualifiedErrorId) { $texts += $ErrorObject.FullyQualifiedErrorId }
    }

    $allText = ($texts | Where-Object { $_ }) -join ' | '

    # Harvest hex codes out of the TEXT as well as the HResult. A real
    # DirectoryServicesCOMException carries the useful code inside its extended message
    # ("80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 52e"),
    # where no exception property exposes it -- so rules that only looked at HResult would
    # never fire against an actual domain controller.
    foreach ($m in [regex]::Matches($allText, '\b(8[0-9a-fA-F]{7})\b')) {
        $codes += ('0x' + $m.Groups[1].Value.ToLowerInvariant())
    }

    # "data 52e" inside the extended message is the real bind sub-status.
    $sub = $null
    if ($allText -match 'data\s+([0-9a-fA-F]{3})\b') { $sub = $Matches[1].ToLowerInvariant() }

    [pscustomobject]@{
        Text       = $allText
        AnyCode    = (($codes | Select-Object -Unique) -join ' ')
        Types      = (($types | Select-Object -Unique) -join ' ')
        SubStatus  = $sub
        ServerText = $server
        Operation  = [string]$Operation
        Target     = [string]$Target
        # Facts the CALLER knows that the exception cannot carry -- whether SSL was requested,
        # whether the port was proven open. Two identical error codes often mean different
        # things, and this is what tells them apart.
        Hint       = if ($Hint) { [pscustomobject]$Hint } else { [pscustomobject]@{ UseSsl = $false; PortOpen = $false } }
    }
}

function Resolve-AdmDiagnosis {
    <#
      Produce a plain-English diagnosis for a failure. Always returns an object -- an unmatched
      error yields an explicitly UNRECOGNISED diagnosis carrying the raw text, never a guess.
    #>
    [CmdletBinding()]
    param($ErrorObject, [string]$Operation, [string]$Target, [hashtable]$Hint)

    $ctx = Get-AdmErrorContext -ErrorObject $ErrorObject -Operation $Operation -Target $Target -Hint $Hint

    # The bind sub-status is more specific than any generic rule, so it is consulted first.
    if ($ctx.SubStatus -and $script:AdmLdapSubStatus.ContainsKey($ctx.SubStatus)) {
        $s = $script:AdmLdapSubStatus[$ctx.SubStatus]
        return [pscustomobject]@{
            Code = "LDAP-BIND-$($ctx.SubStatus.ToUpperInvariant())"
            Severity = 'error'; Title = $s.t; Why = $s.w; Fix = @($s.f)
            Recognised = $true; Operation = $ctx.Operation; Target = $ctx.Target
            Technical = [pscustomobject]@{ Codes = $ctx.AnyCode; SubStatus = $ctx.SubStatus
                                           Types = $ctx.Types; Server = $ctx.ServerText; Raw = $ctx.Text }
        }
    }

    foreach ($rule in $script:AdmDiagnosisRules) {
        $hit = $false
        try { $hit = [bool](& $rule.Match $ctx) } catch { $hit = $false }
        if ($hit) {
            return [pscustomobject]@{
                Code = $rule.Code; Severity = $rule.Severity; Title = $rule.Title
                Why = $rule.Why; Fix = @($rule.Fix)
                Recognised = $true; Operation = $ctx.Operation; Target = $ctx.Target
                Technical = [pscustomobject]@{ Codes = $ctx.AnyCode; SubStatus = $ctx.SubStatus
                                               Types = $ctx.Types; Server = $ctx.ServerText; Raw = $ctx.Text }
            }
        }
    }

    # No rule matched. Say exactly that -- do not manufacture a cause.
    [pscustomobject]@{
        Code = 'UNRECOGNISED'; Severity = 'error'
        Title = 'Something failed, and this is not a failure the toolkit recognises'
        Why = 'No known cause matches this error. That does not make it mysterious to someone who knows the environment -- the raw message below is the real one, unedited.'
        Fix = @(
            'Read the technical detail below and send it to whoever administers this domain',
            'If this turns out to be a common failure, it is worth adding to the catalog in ADAdmin\Private\Diagnostics.ps1 so the next person gets an explanation'
        )
        Recognised = $false; Operation = $ctx.Operation; Target = $ctx.Target
        Technical = [pscustomobject]@{ Codes = $ctx.AnyCode; SubStatus = $ctx.SubStatus
                                       Types = $ctx.Types; Server = $ctx.ServerText; Raw = $ctx.Text }
    }
}
