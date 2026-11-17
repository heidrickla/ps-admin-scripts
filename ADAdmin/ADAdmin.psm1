# ADAdmin -- portable multi-forest Active Directory administration.
#
# Loads from wherever it sits: a USB stick, an SMB share, or a local folder. Nothing here
# depends on the module's own location being writable, and nothing is installed.

Set-StrictMode -Version 2.0

# $PSScriptRoot resolves correctly under a UNC path, which is how this runs off a share.
$script:AdmModuleRoot = $PSScriptRoot

foreach ($folder in @('Private', 'Public')) {
    $dir = Join-Path $script:AdmModuleRoot $folder
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    # Sorted so load order is identical on every host. An unordered Get-ChildItem is a
    # difference that only shows up on someone else's machine.
    foreach ($file in (Get-ChildItem -LiteralPath $dir -Filter '*.ps1' | Sort-Object Name)) {
        try { . $file.FullName }
        catch { throw "Failed to load $($file.Name): $($_.Exception.Message)" }
    }
}

Export-ModuleMember -Function @(
    # store
    'Initialize-AdmStore', 'Unlock-AdmStore', 'Lock-AdmStore', 'Get-AdmStoreInfo',
    'Add-AdmRecipient', 'Remove-AdmRecipient',
    # domain registry + resolution
    'Register-AdmDomain', 'Unregister-AdmDomain', 'Get-AdmDomain', 'Resolve-AdmDomain',
    'Set-AdmDomainCredential', 'Remove-AdmDomainCredential', 'Export-AdmDomainProfile', 'Import-AdmDomainProfile',
    # directory operations
    'Get-AdmUser', 'Get-AdmGroup', 'Get-AdmComputer', 'Get-AdmObjectDetail', 'Get-AdmRangedProp', 'ConvertFrom-AdmUac', 'ConvertFrom-AdmGroupType',
    'Unlock-AdmUser', 'Set-AdmUserEnabled', 'Set-AdmComputerEnabled', 'Reset-AdmUserPassword',
    'New-AdmUser', 'Add-AdmGroupMember', 'Remove-AdmGroupMember', 'Get-AdmPasswordPolicy', 'Remove-AdmSpn', 'Get-AdmSearchResult',
    'Test-AdmDomain', 'Set-AdmProvider',
    # object lifecycle -- create, move, rename, delete, protect
    'Get-AdmOrganizationalUnit', 'New-AdmOrganizationalUnit', 'Remove-AdmOrganizationalUnit',
    'Move-AdmObject', 'Rename-AdmObject', 'Remove-AdmObject', 'Set-AdmObjectProtection',
    # groups -- lifecycle, and who is actually IN one (range-aware, primary-group aware)
    'Get-AdmGroupMember', 'New-AdmGroup', 'Remove-AdmGroup', 'Get-AdmRangedAttribute',
    # editing an existing object -- the everyday change the module could not make
    'Set-AdmUser', 'Set-AdmObjectAttribute',
    # bulk -- validate the whole file before writing anything, and report every row
    'Import-AdmUserCsv', 'New-AdmRandomPassword',
    # help-desk retrieval -- LAPS and BitLocker, with "cannot read" told apart from "not set"
    'Get-AdmLapsPassword', 'Get-AdmBitLockerRecoveryKey', 'Get-AdmNamingContext', 'Test-AdmSchemaAttribute',
    # forest shape -- trusts, sites and subnets, group policy inventory
    'Get-AdmTrust', 'Get-AdmSite', 'Get-AdmSubnet', 'Get-AdmGpo', 'ConvertFrom-AdmGpLink',
    'ConvertFrom-AdmTrustDirection', 'ConvertFrom-AdmTrustType', 'ConvertFrom-AdmTrustAttributes', 'ConvertFrom-AdmGpoStatus',
    # deleted objects -- and telling a real restore apart from a tombstone
    'Test-AdmRecycleBinEnabled', 'Get-AdmDeletedObject', 'Restore-AdmObject',
    # fine-grained password policies, as objects -- the other half of the resultant PSO
    'Get-AdmPasswordSettingsPolicy', 'ConvertFrom-AdmPsoDuration',
    # computer accounts -- pre-staging a join, and the fields an admin owns
    'New-AdmComputer', 'Set-AdmComputer',
    # the lower-level LDAP API, for the one operation DirectoryEntry cannot perform
    'New-AdmLdapConnection',
    # shared helpers other scripts (and the delegation audit) build on
    'Set-AdmDaclMask', 'ConvertTo-AdmSignedFlag', 'Get-AdmParentDn', 'Get-AdmRdnPrefix', 'ConvertTo-AdmRdnEscaped', 'Resolve-AdmObjectDn', 'Test-AdmObjectProtected',
    # the error log the GUI shows, and that other scripts write to
    'Write-AdmLog', 'Get-AdmLog', 'Get-AdmLogInfo', 'Clear-AdmLog', 'Set-AdmLogReviewed', 'Export-AdmLog', 'Get-AdmWindowsEvent',
    'Get-AdmErrorCatalog', 'Invoke-AdmScan', 'Invoke-AdmRepair',
    'Test-AdmScript', 'Import-AdmScript', 'Get-AdmScript', 'Invoke-AdmScript', 'Remove-AdmScript',
    'Get-AdmTargetContextPublic', 'Invoke-AdmGuardedPublic',
    # the low-level directory API, for scripts written against this module
    'New-AdmDirectoryEntry', 'Close-AdmDirectoryEntry', 'Invoke-AdmAdsiSearch', 'Get-AdmSearchTruncated', 'Reset-AdmSearchTruncated', 'Get-AdmOverfetchLimit', 'Get-AdmRawProp', 'ConvertTo-AdmDistinguishedName', 'ConvertTo-AdmSidString'
)
