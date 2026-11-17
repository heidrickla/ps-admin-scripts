# Public/Bulk.ps1 -- creating and updating users from a CSV.
#
# This is the job people currently do with a hand-rolled loop, no -WhatIf, and no record of which
# rows actually landed. The loop is the easy part; what makes a bulk run safe is everything around
# it, and that is what this file is.
#
# ⛔ THE DEFINING RISK OF A BULK OPERATION IS PARTIAL APPLICATION. A run that fails at row 40 of
# 200 leaves the directory in a state nobody wrote down, and the operator's next move -- re-run
# the file -- either duplicates work or fails on everything already done. So:
#
#   1. THE WHOLE FILE IS VALIDATED BEFORE ANYTHING IS WRITTEN. Missing columns, duplicate account
#      names within the file, names too long, rows already present in the directory: all found up
#      front, while nothing has changed.
#   2. EVERY ROW GETS ITS OWN RESULT. The return value is one object per input row with what
#      happened to it, so "which ones landed" is never a question you have to reconstruct.
#   3. THE BATCH NEVER REPORTS SUCCESS FOR ROWS THAT FAILED. A summary that says "done" over a
#      partial run is the failure mode this exists to prevent.

# A password that satisfies a default complexity policy without a human choosing it: at least one
# character from each of four classes, the rest drawn from the whole set.
#
# ⚠ REJECTION SAMPLING, not modulo. Taking a random byte % 62 biases the first few characters of
# the alphabet, because 256 is not a multiple of 62 -- a bias that is invisible in any output you
# would look at and real in the key space.
function New-AdmRandomPassword {
    <#
    .SYNOPSIS
      Generate a random password that meets default AD complexity, without modulo bias.
    #>
    [OutputType([string])]
    param([int]$Length = 20)
    $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'      # no I or O
    $lower = 'abcdefghijkmnpqrstuvwxyz'      # no l
    $digit = '23456789'                      # no 0 or 1
    $sym   = '!#%^*_-+=?'
    $all   = $upper + $lower + $digit + $sym

    $pick = {
        param([string]$Set)
        # Largest multiple of the set size that fits in a byte; anything above it is discarded so
        # every character is equally likely.
        $limit = 256 - (256 % $Set.Length)
        while ($true) {
            $b = (New-AdmRandomBytes -Count 1)[0]
            if ($b -lt $limit) { return $Set[$b % $Set.Length] }
        }
    }

    $chars = New-Object System.Collections.ArrayList
    [void]$chars.Add((& $pick $upper))
    [void]$chars.Add((& $pick $lower))
    [void]$chars.Add((& $pick $digit))
    [void]$chars.Add((& $pick $sym))
    for ($i = $chars.Count; $i -lt $Length; $i++) { [void]$chars.Add((& $pick $all)) }

    # Shuffle, or the first four positions always hold the same character classes.
    $arr = $chars.ToArray()
    for ($i = $arr.Count - 1; $i -gt 0; $i--) {
        $limit = 256 - (256 % ($i + 1))
        do { $b = (New-AdmRandomBytes -Count 1)[0] } while ($b -ge $limit)
        $j = $b % ($i + 1)
        $tmp = $arr[$i]; $arr[$i] = $arr[$j]; $arr[$j] = $tmp
    }
    -join $arr
}

function Import-AdmUserCsv {
    <#
    .SYNOPSIS
      Create or update users from a CSV. Validates the whole file first. Writes -- honours -WhatIf.
    .DESCRIPTION
      Column names are the same friendly names Set-AdmUser takes -- Title, Department, Manager,
      EmailAddress and the rest -- plus SamAccountName (required), and optionally Password, Path,
      DisplayName and Enabled. Unknown columns are reported and ignored rather than silently
      dropped, because a misspelled header is otherwise a change that never happens and never
      complains.

      -Mode Create  refuses a row whose account already exists
           Update   refuses a row whose account does not
           Upsert   creates what is missing and updates what is not

      ⛔ NOTHING IS WRITTEN UNTIL THE WHOLE FILE VALIDATES. Duplicate account names within the
      file, names over the 20-character sAMAccountName limit, missing required values and rows
      that conflict with -Mode are all found while the directory is still untouched. With
      -StopOnError the run is refused outright if any row is invalid; without it, the invalid rows
      are skipped and reported and the valid ones proceed.

      ⚠ PASSWORDS. If there is no Password column, one is generated per user and returned in the
      result -- that is the only copy, and it is never written to the log. If there IS a Password
      column then the CSV is a file full of credentials: treat it accordingly and delete it after.

      ⭐ THE PREVIEW IS DATA, NOT NARRATION. -WhatIf returns one object per input row carrying
      Action (create / update / no-change / skip), the resolved TargetDn, and Changes -- the
      specific attributes that would move, each with From and To. That is enough for a caller to
      render the whole plan, let someone deselect rows, and apply the rest, without parsing text.
      A row whose values already match is reported as no-change rather than as an update that
      would do nothing.

      ⭐ -RollbackPath writes a manifest of what was ACTUALLY applied: a delete row per created
      account, and a restore row per changed attribute carrying its previous value. Only
      successful rows go in it -- a manifest naming failed rows would send someone deleting
      accounts that were never created.

      ⚠ ENCODING. On Windows PowerShell 5.1, Import-Csv reads a BOM-less UTF-8 file as the system
      ANSI codepage, which mangles any non-ASCII name silently. This defaults to -Encoding UTF8;
      pass -Encoding if your file is genuinely something else.
    .EXAMPLE
      Import-AdmUserCsv -Target corp.example.com -Path .\joiners.csv -WhatIf
    .EXAMPLE
      Import-AdmUserCsv -Target corp.example.com -Path .\joiners.csv -DefaultPath 'OU=Staff,DC=corp,DC=example,DC=com'
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Create', 'Update', 'Upsert')][string]$Mode = 'Create',
        # Where new accounts go when a row has no Path column. Defaults to the domain's Users
        # container, matching New-AdmUser.
        [string]$DefaultPath,
        [string]$Encoding = 'UTF8',
        # Refuse the whole run if any row is invalid, rather than skipping the bad ones.
        [switch]$StopOnError,
        # Write a manifest of what was ACTUALLY applied, so a bad import can be undone. Bulk
        # create is the one operation here where the mistake is 400 objects rather than one.
        [string]$RollbackPath,
        [string]$Tier = 'write',
        [switch]$UseDnsLookup
    )
    Invoke-AdmGuarded -Operation "import users from '$Path'" -Target $Target -Action {
        if (-not (Test-Path -LiteralPath $Path)) { throw "No such file: '$Path'." }
        $ctx = Get-AdmTargetContext -Target $Target -Tier $Tier -UseDnsLookup:$UseDnsLookup

        $rows = @(Import-Csv -LiteralPath $Path -Encoding $Encoding)
        if (-not $rows.Count) { throw "'$Path' has no data rows." }

        $headers = @($rows[0].PSObject.Properties.Name)
        if ($headers -notcontains 'SamAccountName') {
            throw "'$Path' has no SamAccountName column. Found: $($headers -join ', ')."
        }

        # Known columns are the Set-AdmUser friendly names plus the create-only ones. Anything
        # else is reported once, up front, rather than per row.
        $known = @('SamAccountName', 'Password', 'Path', 'Enabled') + @($script:AdmUserAttributeMap.Keys)
        $unknown = @($headers | Where-Object { $known -notcontains $_ })

        # --- validate the whole file, touching nothing -------------------------------------------
        $seen = @{}
        $plan = New-Object System.Collections.ArrayList
        $rowNum = 1
        foreach ($r in $rows) {
            $rowNum++
            $sam = [string](Get-AdmRawProp $r 'SamAccountName')
            $problem = $null
            if (-not $sam) { $problem = 'SamAccountName is empty' }
            # ⚠ A REAL AD LIMIT, and it is 20 characters -- not 64, and not the length of the
            # display name. A longer value is rejected by the directory with a message about the
            # attribute's syntax, which does not mention the limit.
            elseif ($sam.Length -gt 20) { $problem = "SamAccountName '$sam' is $($sam.Length) characters; the limit is 20" }
            elseif ($seen.ContainsKey($sam.ToLowerInvariant())) { $problem = "duplicate SamAccountName '$sam' -- also on row $($seen[$sam.ToLowerInvariant()])" }
            if ($sam) { $seen[$sam.ToLowerInvariant()] = $rowNum }

            # Every slot exists up front: Set-StrictMode 2.0 treats a reference to a property that
            # was never assigned as an error, so a member added conditionally later would throw on
            # whichever row happened not to get it.
            [void]$plan.Add([pscustomobject]@{
                Row = $rowNum; SamAccountName = $sam; Raw = $r; Problem = $problem
                Exists = $null; Current = $null; TargetDn = $null; Changes = @()
            })
        }

        # ONE query for the whole file, not one per row, and it loads the mapped attributes as
        # well as the names -- so the preview can say what would CHANGE, not merely that a row
        # would be updated. On a 400-row import that is one search instead of eight hundred.
        # ⛔ AND IT REFUSES IF THAT ONE QUERY WAS TRUNCATED. Every row's Action is derived from
        # this map: an account past the limit reads as ABSENT, so the plan says "create" for a
        # user that exists, and in Update mode silently SKIPS a row that should have been
        # changed. A bulk write planned from a partial view of the directory is the worst case of
        # "never both truncate and conclude" -- it writes.
        $existing = @{}
        Reset-AdmSearchTruncated
        $wantProps = @('samaccountname', 'distinguishedname') + @($script:AdmUserAttributeMap.Values)
        if ((Get-AdmProviderName) -eq 'mock') {
            foreach ($u in @(Invoke-AdmMockSearch -Domain $ctx.Domain -ObjectClass 'users' -SizeLimit 5000)) {
                $s = [string](Get-AdmRawProp $u 'samAccountName')
                if ($s) { $existing[$s.ToLowerInvariant()] = $u }
            }
        } else {
            foreach ($u in @(Invoke-AdmAdsiSearch -Domain $ctx.Domain -Credential $ctx.Credential `
                                -Filter '(&(objectCategory=person)(objectClass=user))' `
                                -Properties $wantProps -SizeLimit 100000)) {
                $s = [string](Get-AdmRawProp $u 'samaccountname')
                if ($s) { $existing[$s.ToLowerInvariant()] = $u }
            }
        }
        if (Get-AdmSearchTruncated) {
            throw ("The read of existing accounts was truncated at its size limit, so this import " +
                   "cannot tell which rows already exist. It would report 'create' for accounts " +
                   "that are already there, and in Update mode it would silently skip them. " +
                   "Refusing rather than planning writes from a partial view of the directory.")
        }

        $defaultContainer = if ($DefaultPath) { $DefaultPath }
                            else { "CN=Users,$(ConvertTo-AdmDistinguishedName -DnsDomain $ctx.Domain.DnsDomain)" }

        foreach ($p in $plan) {
            if (-not $p.SamAccountName) { continue }
            $key = $p.SamAccountName.ToLowerInvariant()
            $p.Exists = $existing.ContainsKey($key)
            $p.Current = $(if ($p.Exists) { $existing[$key] } else { $null })

            if (-not $p.Problem) {
                if ($Mode -eq 'Create' -and $p.Exists) { $p.Problem = "'$($p.SamAccountName)' already exists (mode Create)" }
                if ($Mode -eq 'Update' -and -not $p.Exists) { $p.Problem = "'$($p.SamAccountName)' does not exist (mode Update)" }
            }

            # Where the row would land. For an update it is the object's real DN; for a create it
            # is derived, so a wrong -DefaultPath or Path column is visible in the PREVIEW rather
            # than discovered afterwards by finding 400 accounts in the wrong OU.
            if ($p.Exists) {
                $p.TargetDn = [string](Get-AdmRawProp $p.Current 'distinguishedname' (Get-AdmRawProp $p.Current 'distinguishedName'))
            } else {
                $rowPath = [string](Get-AdmRawProp $p.Raw 'Path')
                if (-not $rowPath) { $rowPath = $defaultContainer }
                $p.TargetDn = "CN=$(ConvertTo-AdmRdnEscaped -Value $p.SamAccountName),$rowPath"
            }

            # Per-attribute before/after, so a preview grid can show the actual diff and someone
            # can uncheck the rows they did not mean. A row whose values already match is reported
            # as no-change rather than as an update that does nothing.
            $changes = New-Object System.Collections.ArrayList
            foreach ($friendly in $script:AdmUserAttributeMap.Keys) {
                if ($headers -notcontains $friendly) { continue }
                $new = [string](Get-AdmRawProp $p.Raw $friendly)
                $ldap = $script:AdmUserAttributeMap[$friendly]
                $old = if ($p.Exists) { [string](Get-AdmRawProp $p.Current $ldap) } else { '' }
                if ($old -ne $new) {
                    [void]$changes.Add([pscustomobject]@{ Attribute = $friendly; LdapName = $ldap; From = $old; To = $new })
                }
            }
            $p.Changes = $changes.ToArray()
        }

        $bad = @($plan | Where-Object { $_.Problem })
        if ($bad.Count -and $StopOnError) {
            $detail = ($bad | Select-Object -First 10 | ForEach-Object { "row $($_.Row): $($_.Problem)" }) -join '; '
            throw "$($bad.Count) of $($plan.Count) row(s) are invalid and -StopOnError is set, so nothing was written: $detail"
        }

        $todo = @($plan | Where-Object { -not $_.Problem })
        $verb = "$Mode $($todo.Count) user(s) from $($plan.Count) row(s)"
        if (-not $PSCmdlet.ShouldProcess("$($ctx.Domain.DnsDomain)", $verb)) {
            # -WhatIf still returns the PLAN, which is the useful part: what would happen to every
            # row, including why the skipped ones are skipped.
            return @($plan | ForEach-Object {
                $row = $_
                [pscustomobject]@{
                    Row = $row.Row; SamAccountName = $row.SamAccountName
                    Action = $(if ($row.Problem) { 'skip' }
                               elseif (-not $row.Exists) { 'create' }
                               elseif (@($row.Changes).Count) { 'update' }
                               else { 'no-change' })
                    Status = 'would-run'; Reason = $row.Problem; Password = $null
                    TargetDn = $row.TargetDn
                    Changes = @($row.Changes)
                    ChangeCount = @($row.Changes).Count
                    UnknownColumns = $unknown
                }
            })
        }

        # --- apply, one row at a time, recording each ---------------------------------------------
        $results = New-Object System.Collections.ArrayList
        foreach ($p in $plan) {
            if ($p.Problem) {
                [void]$results.Add([pscustomobject]@{
                    Row = $p.Row; SamAccountName = $p.SamAccountName; Action = 'skip'
                    Status = 'skipped'; Reason = $p.Problem; Password = $null
                    TargetDn = $p.TargetDn; Changes = @($p.Changes); ChangeCount = @($p.Changes).Count
                    UnknownColumns = $unknown })
                continue
            }
            $generated = $null
            try {
                if ($p.Exists) {
                    $set = @{ Target = $Target; Identity = $p.SamAccountName; Tier = $Tier; Confirm = $false }
                    foreach ($friendly in $script:AdmUserAttributeMap.Keys) {
                        if ($headers -contains $friendly) {
                            $v = Get-AdmRawProp $p.Raw $friendly
                            if ($null -ne $v) { $set[$friendly] = [string]$v }
                        }
                    }
                    if ($set.Keys.Count -le 4) { throw "no attribute columns to update" }
                    $null = Set-AdmUser @set
                    $action = 'update'
                } else {
                    $pw = [string](Get-AdmRawProp $p.Raw 'Password')
                    if (-not $pw) { $pw = New-AdmRandomPassword; $generated = $pw }
                    $secure = ConvertTo-AdmSecureString -Plain $pw
                    $rowPath = [string](Get-AdmRawProp $p.Raw 'Path')
                    if (-not $rowPath) { $rowPath = $DefaultPath }
                    $enabledRaw = [string](Get-AdmRawProp $p.Raw 'Enabled')
                    $enabled = if ($enabledRaw) { $enabledRaw -match '^(?i:true|yes|1)$' } else { $true }
                    $null = New-AdmUser -Target $Target -SamAccountName $p.SamAccountName `
                                -DisplayName ([string](Get-AdmRawProp $p.Raw 'DisplayName')) `
                                -Password $secure -Path $rowPath -Enabled $enabled -Tier $Tier -Confirm:$false
                    $action = 'create'
                }
                [void]$results.Add([pscustomobject]@{
                    Row = $p.Row; SamAccountName = $p.SamAccountName; Action = $action
                    Status = 'ok'; Reason = $null; Password = $generated
                    TargetDn = $p.TargetDn; Changes = @($p.Changes); ChangeCount = @($p.Changes).Count
                    UnknownColumns = $unknown })
            } catch {
                # ⛔ ONE ROW'S FAILURE DOES NOT STOP THE RUN, and it is recorded against that row.
                # Aborting here would leave the earlier rows applied and unrecorded, which is the
                # exact partial-application state this cmdlet exists to make visible.
                [void]$results.Add([pscustomobject]@{
                    Row = $p.Row; SamAccountName = $p.SamAccountName
                    Action = $(if ($p.Exists) { 'update' } else { 'create' })
                    Status = 'failed'; Reason = $_.Exception.Message; Password = $null
                    TargetDn = $p.TargetDn; Changes = @($p.Changes); ChangeCount = @($p.Changes).Count
                    UnknownColumns = $unknown })
            }
        }

        # --- rollback manifest -------------------------------------------------------------------
        # Only what actually succeeded goes in it. A manifest listing rows that failed would send
        # someone deleting objects that were never created.
        if ($RollbackPath) {
            $undo = New-Object System.Collections.ArrayList
            foreach ($r in $results) {
                if ($r.Status -ne 'ok') { continue }
                if ($r.Action -eq 'create') {
                    # Undo is a deletion, and the DN is all that is needed for it.
                    [void]$undo.Add([pscustomobject]@{
                        Action = 'delete'; SamAccountName = $r.SamAccountName; TargetDn = $r.TargetDn
                        Attribute = ''; RestoreValue = '' })
                } else {
                    # Undo is putting each attribute back to what it was. An empty RestoreValue
                    # means the attribute was unset before, and '' is how Set-AdmUser spells clear.
                    foreach ($c in @($r.Changes)) {
                        [void]$undo.Add([pscustomobject]@{
                            Action = 'restore'; SamAccountName = $r.SamAccountName; TargetDn = $r.TargetDn
                            Attribute = $c.Attribute; RestoreValue = $c.From })
                    }
                }
            }
            $undo.ToArray() | Export-Csv -LiteralPath $RollbackPath -NoTypeInformation -Encoding $Encoding
        }

        $ok = @($results | Where-Object { $_.Status -eq 'ok' }).Count
        $failed = @($results | Where-Object { $_.Status -eq 'failed' }).Count
        $skipped = @($results | Where-Object { $_.Status -eq 'skipped' }).Count
        # Passwords are never in the log; the counts are.
        [void](Write-AdmLogEntry -Severity $(if ($failed) { 'warn' } else { 'info' }) -Event 'change' `
                -Operation 'import users from CSV' -Target $Target -Domain $ctx.Domain.Name `
                -Message "Imported '$Path' into $($ctx.Domain.DnsDomain): $ok applied, $failed failed, $skipped skipped, of $($plan.Count) row(s)")

        $results.ToArray()
    }
}
