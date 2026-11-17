# Public/Catalog.ps1 -- the error table, as data.
#
# The diagnosis rules are useful when something breaks. This exposes them as a TABLE that can be
# scanned without breaking anything first: a script can list every failure the toolkit knows how
# to explain, look one up by code, and read the fixes -- and the reference doc is generated from
# the same source, so it cannot drift from the code the way a hand-written table does.

function Get-AdmErrorCatalog {
    <#
    .SYNOPSIS
      Every failure the toolkit can recognise, as a table.
    .EXAMPLE
      Get-AdmErrorCatalog | Format-Table Code, Severity, Title
    .EXAMPLE
      Get-AdmErrorCatalog -Code LDAP-BIND-52E
    .EXAMPLE
      Get-AdmErrorCatalog -AsMarkdown | Set-Content docs\error-catalog.md
    #>
    [CmdletBinding()]
    param(
        [string]$Code,
        [ValidateSet('all', 'error', 'warn')][string]$Severity = 'all',
        [switch]$AsMarkdown
    )

    $rows = @()

    # The LDAP bind sub-statuses. These are the codes a domain controller returns inside its
    # extended error text; they are the most specific signal available and are checked first.
    foreach ($k in ($script:AdmLdapSubStatus.Keys | Sort-Object)) {
        $v = $script:AdmLdapSubStatus[$k]
        $rows += [pscustomobject]@{
            Code      = "LDAP-BIND-$($k.ToUpperInvariant())"
            Category  = 'ldap-bind'
            Severity  = 'error'
            Signature = "extended error text contains 'data $k'"
            Title     = $v.t
            Why       = $v.w
            Fix       = @($v.f)
        }
    }

    foreach ($r in $script:AdmDiagnosisRules) {
        $rows += [pscustomobject]@{
            Code      = $r.Code
            Category  = switch -Regex ($r.Code) {
                            '^LDAP|^KERBEROS|^BIND|^RODC' { 'connection' }
                            '^STORE'                      { 'credential-store' }
                            '^AMBIGUOUS|^UNRESOLVED'      { 'resolution' }
                            'PASSWORD'                    { 'password' }
                            default                       { 'directory' }
                        }
            Severity  = $r.Severity
            # The match condition, as written. Not decoration: it tells a reader (or a script)
            # exactly what makes this rule fire, without reading the source.
            Signature = ($r.Match.ToString() -replace '\s+', ' ').Trim() -replace '^param\(\$c\)\s*', ''
            Title     = $r.Title
            Why       = $r.Why
            Fix       = @($r.Fix)
        }
    }

    if ($Code)               { $rows = @($rows | Where-Object { $_.Code -like $Code }) }
    if ($Severity -ne 'all') { $rows = @($rows | Where-Object { $_.Severity -eq $Severity }) }

    # Emit normally, NOT `,@($rows)`: the comma form makes @(Get-AdmErrorCatalog).Count return 1
    # because the caller wraps an already-wrapped array. Public cmdlets enumerate.
    if (-not $AsMarkdown) { return $rows }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('# Error catalog')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('**Generated from `ADAdmin/Private/Diagnostics.ps1` by `Get-AdmErrorCatalog -AsMarkdown`.**')
    [void]$sb.AppendLine('Do not hand-edit: regenerate it, or the table and the code drift apart.')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("$($rows.Count) recognised failures. Look one up with ``adm catalog -Code <code>``.")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('| Code | Severity | What it means |')
    [void]$sb.AppendLine('|---|---|---|')
    foreach ($r in ($rows | Sort-Object Category, Code)) {
        [void]$sb.AppendLine("| ``$($r.Code)`` | $($r.Severity) | $($r.Title) |")
    }
    [void]$sb.AppendLine()
    foreach ($r in ($rows | Sort-Object Category, Code)) {
        [void]$sb.AppendLine("## ``$($r.Code)``")
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("**$($r.Title)**")
        [void]$sb.AppendLine()
        [void]$sb.AppendLine($r.Why)
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('What to try:')
        [void]$sb.AppendLine()
        foreach ($f in @($r.Fix)) { [void]$sb.AppendLine("- $f") }
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("<sub>fires when: ``$($r.Signature)``</sub>")
        [void]$sb.AppendLine()
    }
    $sb.ToString()
}
