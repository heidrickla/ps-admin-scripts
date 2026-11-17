# Error catalog

**Generated from `ADAdmin/Private/Diagnostics.ps1` by `Get-AdmErrorCatalog -AsMarkdown`.**
Do not hand-edit: regenerate it, or the table and the code drift apart.

30 recognised failures. Look one up with `adm catalog -Code <code>`.

| Code | Severity | What it means |
|---|---|---|
| `BIND-BY-IP-NTLM-BLOCKED` | error | Signing in by IP address was rejected |
| `KERBEROS-CLOCK-SKEW` | error | This computer's clock is too far from the domain controller's |
| `LDAPS-CERT-UNTRUSTED` | error | The domain controller's certificate is not trusted by this computer |
| `LDAPS-HANDSHAKE-FAILED` | error | The LDAPS port is open but the secure connection could not be established |
| `LDAP-SIGNING-REQUIRED` | error | The domain controller refuses unsigned connections |
| `RODC-WRITE-REFUSED` | error | That domain controller cannot accept changes |
| `STORE-BAD-PASSPHRASE` | error | That passphrase did not open the store |
| `STORE-LOCKED` | warn | The credential store is locked |
| `ACCESS-DENIED` | error | The account is not allowed to do that |
| `CREDENTIAL-REJECTED` | error | The stored username or password was rejected |
| `DC-DISABLE-REFUSED` | warn | Refused: that computer account belongs to a domain controller |
| `OBJECT-NOT-FOUND` | error | No object with that name exists in this domain |
| `READ-TRUNCATED` | error | The directory returned only part of the answer, so this refused rather than guess |
| `SERVER-UNREACHABLE` | error | Could not reach the domain controller |
| `SIZE-LIMIT-EXCEEDED` | warn | The directory returned only part of the results |
| `UNWILLING-TO-PERFORM` | error | The domain controller declined the request |
| `LDAP-BIND-525` | error | That account does not exist |
| `LDAP-BIND-52E` | error | Wrong username or password |
| `LDAP-BIND-530` | error | This account is not allowed to sign in at this time of day |
| `LDAP-BIND-531` | error | This account is not allowed to sign in from this computer |
| `LDAP-BIND-532` | error | The password has expired |
| `LDAP-BIND-533` | error | The account is disabled |
| `LDAP-BIND-701` | error | The account has expired |
| `LDAP-BIND-773` | error | The password must be changed before this account can be used |
| `LDAP-BIND-775` | error | The account is locked out |
| `PASSWORD-POLICY-REFUSED` | error | The new password was refused by the domain's password policy |
| `PASSWORD-RESET-NEEDS-SECURE-CHANNEL` | error | Setting a password requires an encrypted connection |
| `PASSWORD-RPC-UNAVAILABLE` | error | Setting the password fell back to a network protocol this machine cannot reach |
| `AMBIGUOUS-TARGET` | warn | That target could belong to more than one registered domain |
| `UNRESOLVED-TARGET` | warn | That target does not belong to any registered domain |

## `BIND-BY-IP-NTLM-BLOCKED`

**Signing in by IP address was rejected**

Connecting to a domain controller by IP address forces NTLM, because Kerberos needs a name to look up a ticket. Hardened environments frequently disable NTLM outright, so the same credential that works by hostname fails by IP.

What to try:

- Register the domain controller by its FQDN instead of its IP: adm domain add -Name <n> -Dns <fqdn> -Dc dc01.example.com -Force
- If this machine cannot resolve that name, add it to C:\Windows\System32\drivers\etc\hosts, or point this machine at the forest's DNS
- Verify with: adm domain test -Target <fqdn>

<sub>fires when: `$c.AnyCode -match '8007052[eE]' -and $c.Target -match '^\d{1,3}(\.\d{1,3}){3}$'`</sub>

## `KERBEROS-CLOCK-SKEW`

**This computer's clock is too far from the domain controller's**

Kerberos refuses to authenticate when the two clocks differ by more than about five minutes. This is a very common failure on a laptop or a VM that has been suspended, and the error text rarely mentions the clock.

What to try:

- Check the difference, then correct this machine's time
- On a domain-joined machine: w32tm /resync
- On a standalone machine, set the time zone AND the clock -- a wrong time zone produces exactly this error

<sub>fires when: `$c.AnyCode -match '80090324' -or $c.Text -match 'clock.*skew|time difference'`</sub>

## `LDAPS-CERT-UNTRUSTED`

**The domain controller's certificate is not trusted by this computer**

You connected over LDAPS (port 636) and the DC presented a certificate this machine will not accept -- usually because the issuing CA is not in the local trust store. This is normal on a machine that is not joined to that forest, which is exactly the situation this toolkit is built for.

What to try:

- Install the forest's issuing CA certificate into Local Machine > Trusted Root Certification Authorities on this computer
- Or connect on port 389 with signing instead: adm domain add -Name <n> -Dns <fqdn> -UseSsl $false -Force
- Do NOT disable certificate validation as a workaround -- that removes the protection LDAPS exists to provide

<sub>fires when: `$c.AnyCode -match '8009030[eE]|80072030' -and $c.Text -match 'certificate|trust'`</sub>

## `LDAPS-HANDSHAKE-FAILED`

**The LDAPS port is open but the secure connection could not be established**

ADSI reports almost every TLS failure as "The server is not operational", which reads like the domain controller being down -- it is not. Port 636 accepted the connection, so the DC is there and listening; the handshake is what failed. On a machine that is not joined to the forest the cause is nearly always that the DC's certificate is issued by a CA this computer does not trust, or the certificate name does not match the address you connected to (connecting by IP does this every time, because the certificate names the DC, not its address).

What to try:

- Connect by the DC's FQDN rather than its IP -- a certificate never matches an IP address
- Install the forest's issuing CA certificate into Local Machine > Trusted Root Certification Authorities on this computer (adm scan will offer this)
- Or use port 389 with signing and sealing, which needs no certificate: adm domain add -Name <n> -Dns <fqdn> -UseSsl $false -Force
- Note that password RESETS still require an encrypted channel, so plain 389 will do reads and unlocks but not password changes

<sub>fires when: `$c.AnyCode -match '8007203a' -and $c.Hint.UseSsl -and $c.Hint.PortOpen`</sub>

## `LDAP-SIGNING-REQUIRED`

**The domain controller refuses unsigned connections**

This DC is hardened: it requires LDAP signing (and often channel binding), so a plain connection on port 389 is rejected before your credential is even considered. Microsoft has been enabling this by default, so it is increasingly the normal state rather than the exception.

What to try:

- Use LDAPS. Re-register the domain with SSL on: adm domain add -Name <n> -Dns <fqdn> -Force   (SSL and port 636 are the default)
- If LDAPS is not available, the connection must be signed and sealed -- ADAdmin already requests this on port 389, so a failure here usually means the DC additionally requires channel binding, which needs LDAPS
- Confirm 636 is reachable: adm domain test -Target <target>

<sub>fires when: `$c.AnyCode -match '8009032[12]' -or $c.Text -match 'strong(er)? authentication is required'`</sub>

## `RODC-WRITE-REFUSED`

**That domain controller cannot accept changes**

You are talking to a read-only domain controller (RODC), common at branch sites. It will answer queries all day but refuses every write and returns a referral instead.

What to try:

- Point this domain at a writable DC: adm domain add -Name <n> -Dns <fqdn> -Dc <writable-dc-fqdn> -Force
- Reads can stay on the RODC; only changes need the writable one

<sub>fires when: `$c.Text -match 'read.only|RODC|referral' -and $c.Operation -match 'unlock|enable|disable|reset'`</sub>

## `STORE-BAD-PASSPHRASE`

**That passphrase did not open the store**

Your passphrase was tried against every admin's wrap in the file and none of them opened. Either the passphrase is wrong, or this file is not the store you were enrolled in.

What to try:

- Check you are opening the right file -- adm store status shows the path in use
- If you were recently added, make sure you are using the passphrase YOU set, not the one that created the store
- ADADMIN_STORE overrides the default location and may be pointing somewhere unexpected

<sub>fires when: `$c.Text -match 'does not open this store|Authentication failed'`</sub>

## `STORE-LOCKED`

**The credential store is locked**

The store locks itself after a period of inactivity so a decrypted key does not sit in memory indefinitely.

What to try:

- Unlock it again: adm store unlock
- In the window, enter your passphrase on the unlock screen

<sub>fires when: `$c.Text -match 'store is locked|auto-locked'`</sub>

## `ACCESS-DENIED`

**The account is not allowed to do that**

The credential signed in successfully, but it does not hold the directory rights this operation needs. In a least-privilege environment this is expected for writes: the read account is deliberately unable to change anything.

What to try:

- If this was a change (unlock, enable, disable, reset), use the write credential: add -Tier write to the command
- Store one if there is not one yet: adm domain set-cred -Name <domain> -Tier write
- If the write account is already in use, it needs delegated rights on the target objects -- ask a domain admin to delegate the specific permission (for example "Reset password" on the relevant OU) rather than granting Domain Admin

<sub>fires when: `$c.AnyCode -match '80070005' -or $c.Text -match 'access is denied|insufficient (access )?rights'`</sub>

## `CREDENTIAL-REJECTED`

**The stored username or password was rejected**

The domain controller answered, but would not accept the credential held for this domain.

What to try:

- Re-enter it: adm domain set-cred -Name <domain> -Tier <read|write>
- Check the username is qualified for THIS domain -- across untrusted forests, DOMAIN\user from the wrong forest is a different account
- If the password was rotated recently, the store still has the old one

<sub>fires when: `$c.AnyCode -match '8007052[eE]' -or $c.Text -match 'user name or bad password|invalid credentials'`</sub>

## `DC-DISABLE-REFUSED`

**Refused: that computer account belongs to a domain controller**

The toolkit will not disable a domain controller's computer account, because doing so takes that DC offline -- authentication, group policy and DNS for everything that depends on it. This refusal exists specifically because a DC looks IDLE to any staleness sweep: nobody interactively logs on to one, so it is the object such a sweep is most likely to select by mistake. This is a guard working, not a fault.

What to try:

- If the DC is genuinely gone, this is not the tool for it. An unrecoverable DC must be removed with a metadata cleanup (ntdsutil, or Active Directory Users and Computers, which now does it for you) so its replication and FSMO state goes with it -- disabling the account leaves all of that behind
- If the DC is being retired properly, demote it first: dcpromo / Uninstall-ADDSDomainController on the DC itself, which removes the object cleanly
- If you were sweeping for stale computers, nothing is wrong -- domain controllers are excluded from those results automatically

<sub>fires when: `$c.Text -match 'is a DOMAIN CONTROLLER'`</sub>

## `OBJECT-NOT-FOUND`

**No object with that name exists in this domain**

The directory answered normally and simply has nothing matching. Very often the name is right but the DOMAIN is wrong -- across untrusted forests the same name lives in several places.

What to try:

- Check which domain the target resolved to: adm domain resolve -Target <target>
- Search more loosely: adm user list -Target <domain> -Identity <partial-name>

<sub>fires when: `$c.AnyCode -match '80072030' -or $c.Text -match 'no such object'`</sub>

## `READ-TRUNCATED`

**The directory returned only part of the answer, so this refused rather than guess**

A search stopped at its size limit. Harmless for a list you are reading, but this operation DERIVES something from the whole set -- whether a policy is linked anywhere, which accounts already exist, how much an OU delete would take with it. Computed from a partial read those come out wrong and look exactly like right answers, so it stops instead.

What to try:

- Narrow the operation: a smaller SearchBase, a specific OU, or a filter matching fewer objects
- Split the work -- a bulk import per OU rather than one file for the whole domain
- Raise -Limit only if you know the real count and it genuinely exceeds the default. The limit is not the problem; answering from a partial read is

<sub>fires when: `$c.Text -match 'truncated at (its|the) size limit'`</sub>

## `SERVER-UNREACHABLE`

**Could not reach the domain controller**

Nothing answered on the network. Either the name does not resolve from this machine, the address is wrong, or a firewall is in the way. On a machine that is not joined to the target forest, name resolution is the usual culprit -- the forest's DNS is the only thing that knows its own names.

What to try:

- Register the DC by IP or add it to hosts, rather than relying on this machine's DNS
- Check the ports are open from here -- LDAP is 389, LDAPS is 636
- Confirm with: adm domain test -Target <target>

<sub>fires when: `$c.AnyCode -match '8007203a|80040e37|8007054b' -or $c.Text -match 'server is not operational|cannot contact|no such (host|domain)|actively refused|timed out'`</sub>

## `SIZE-LIMIT-EXCEEDED`

**The directory returned only part of the results**

Active Directory caps how many objects one query may return (1000 by default). The results you got are real, but they are not all of them -- which is dangerous to act on, because "not in the list" does not mean "does not exist".

What to try:

- Narrow the search with -Identity so fewer objects match
- Do not treat this result as a complete inventory

<sub>fires when: `$c.Text -match 'size limit|admin limit'`</sub>

## `UNWILLING-TO-PERFORM`

**The domain controller declined the request**

The directory understood the request and refused it. This is a policy refusal rather than a permission or connection problem -- something about the operation itself is not allowed here.

What to try:

- Check whether the object is protected -- accounts in privileged groups are governed by AdminSDHolder and resist changes
- Check whether a domain policy forbids this specific change
- The raw server message below usually names the constraint

<sub>fires when: `$c.AnyCode -match '80072035'`</sub>

## `LDAP-BIND-525`

**That account does not exist**

The directory has no account with that name. Check spelling, and check you are aimed at the right domain -- the same username can exist in one forest and not another.

What to try:

- Run: adm user list -Target <domain> -Identity <partial-name>   to see what does exist
- Confirm the target resolves to the domain you meant: adm domain resolve -Target <target>

<sub>fires when: `extended error text contains 'data 525'`</sub>

## `LDAP-BIND-52E`

**Wrong username or password**

The credential stored for this domain was rejected. The account exists; the password did not match.

What to try:

- Re-enter the credential: adm domain set-cred -Name <domain> -Tier <read|write>
- Check the username format -- both DOMAIN\user and user@domain.tld work, but the DOMAIN part must be THIS domain
- If the password was recently changed or rotated, the store still holds the old one

<sub>fires when: `extended error text contains 'data 52e'`</sub>

## `LDAP-BIND-530`

**This account is not allowed to sign in at this time of day**

Logon hours are restricted on the account, and right now is outside them. Common on service accounts in hardened environments.

What to try:

- Use a service account without logon-hour restrictions for automation
- Or ask a domain admin to widen the logon hours on this account

<sub>fires when: `extended error text contains 'data 530'`</sub>

## `LDAP-BIND-531`

**This account is not allowed to sign in from this computer**

The account has a workstation restriction and the machine you are running from is not on its list.

What to try:

- Run the toolkit from an approved administrative workstation
- Or ask a domain admin to add this machine to the account's allowed workstations

<sub>fires when: `extended error text contains 'data 531'`</sub>

## `LDAP-BIND-532`

**The password has expired**

The credential is correct but the password is past its expiry date.

What to try:

- Change the password on the account, then update the store: adm domain set-cred -Name <domain> -Tier <tier>
- For service accounts, consider a password that does not expire, or a gMSA

<sub>fires when: `extended error text contains 'data 532'`</sub>

## `LDAP-BIND-533`

**The account is disabled**

Someone has disabled this account in the directory.

What to try:

- Ask a domain admin to re-enable it, or switch to a different service account

<sub>fires when: `extended error text contains 'data 533'`</sub>

## `LDAP-BIND-701`

**The account has expired**

The account has an expiry date and it has passed.

What to try:

- Ask a domain admin to extend or clear the account expiry date

<sub>fires when: `extended error text contains 'data 701'`</sub>

## `LDAP-BIND-773`

**The password must be changed before this account can be used**

The account is flagged "user must change password at next logon", which blocks it from authenticating this way.

What to try:

- Change the password interactively once, then store the new one
- For a service account, clear the "must change at next logon" flag

<sub>fires when: `extended error text contains 'data 773'`</sub>

## `LDAP-BIND-775`

**The account is locked out**

Too many failed sign-in attempts have locked this account. Note that a stale password in the store can cause this by retrying automatically.

What to try:

- Unlock it: adm user unlock -Target <domain> -Identity <account>
- Then fix the stored password, or it will lock again on the next attempt

<sub>fires when: `extended error text contains 'data 775'`</sub>

## `PASSWORD-POLICY-REFUSED`

**The new password was refused by the domain's password policy**

The directory declined the change ("unwilling to perform"). For a password reset this nearly always means the new password failed complexity, minimum length, or password-history rules -- or the minimum password age has not elapsed since the last change.

What to try:

- Use a longer password with mixed case, digits and symbols, and one that has not been used before on this account
- Check the domain policy: the default is 7 characters and 24 remembered passwords, but hardened domains commonly require 14 or more
- If the password was just changed, minimum password age may block another change for a day

<sub>fires when: `$c.AnyCode -match '80072035' -and $c.Operation -match 'reset|password'`</sub>

## `PASSWORD-RESET-NEEDS-SECURE-CHANNEL`

**Setting a password requires an encrypted connection**

Active Directory refuses to accept a new password over an unencrypted channel. If the connection is plain LDAP on 389 without sealing, the reset is rejected even when the account has every right it needs.

What to try:

- Use LDAPS: adm domain add -Name <n> -Dns <fqdn> -Force   (SSL on 636 is the default)
- Verify the channel first: adm domain test -Target <target>

<sub>fires when: `$c.Operation -match 'reset|password' -and ($c.AnyCode -match '8007202f|80070005' -or $c.Text -match 'secure|encrypt')`</sub>

## `PASSWORD-RPC-UNAVAILABLE`

**Setting the password fell back to a network protocol this machine cannot reach**

The older Windows way of setting a password (ADSI SetPassword) tries LDAP over TLS first and then falls back to RPC on ports 135 and 445. From a machine that is not inside the target network, RPC to a domain controller is almost always blocked, so it fails with "The RPC server is unavailable" -- an error that mentions neither passwords nor the real cause. ADAdmin does not use that path: it writes the password as an LDAP attribute over the encrypted connection it already has, which needs no RPC.

What to try:

- If you are seeing this from ADAdmin itself, the connection is not encrypted -- writing the password attribute requires it. Re-register the domain with SSL: adm domain add -Name <n> -Dns <fqdn> -Force
- Confirm the channel: adm domain test -Target <target>
- If you are seeing this from your own script, it is calling SetPassword. Use Reset-AdmUserPassword instead, or open 135/445 to the DC -- which is usually not what you want from a portable toolkit

<sub>fires when: `$c.AnyCode -match '800706ba' -or $c.Text -match 'RPC server is unavailable'`</sub>

## `AMBIGUOUS-TARGET`

**That target could belong to more than one registered domain**

Two domain profiles match it equally well. The toolkit refuses to guess, because binding to the wrong forest is exactly the mistake it exists to prevent.

What to try:

- Add the specific host to one profile's Hosts list so it wins outright
- Or give a more specific target -- a full FQDN rather than a short name

<sub>fires when: `$c.Text -match 'matches more than one'`</sub>

## `UNRESOLVED-TARGET`

**That target does not belong to any registered domain**

Nothing in the store claims this name. A bare hostname cannot be attributed on its own -- the toolkit will not guess which forest it belongs to.

What to try:

- List what is registered: adm domain list
- Register the domain: adm domain add -Name <n> -Dns <fqdn> -Dc <dc-fqdn>
- Or map this specific host: add it to a profile's -Host list

<sub>fires when: `$c.Text -match 'No registered domain matches'`</sub>


