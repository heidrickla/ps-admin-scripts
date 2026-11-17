@{
    RootModule        = 'ADAdmin.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'b0d1b6a4-3f2e-4f77-9c1a-6a2f4d8e5c31'
    Author            = 'heidrickla'
    Description       = 'Portable multi-forest Active Directory administration with an encrypted, multi-admin credential store keyed by DNS domain or hostname.'

    # 5.1 is the floor because the toolkit has to run on whatever Windows is in front of you.
    # Everything here also loads under PowerShell 7 on Windows.
    PowerShellVersion = '5.1'

    # Deliberately no RequiredModules. RSAT is used opportunistically when present and must
    # never be a load-time dependency -- a target PC usually does not have it.
    FunctionsToExport = @(
        'Initialize-AdmStore', 'Unlock-AdmStore', 'Lock-AdmStore', 'Get-AdmStoreInfo',
        'Add-AdmRecipient', 'Remove-AdmRecipient',
        'Register-AdmDomain', 'Unregister-AdmDomain', 'Get-AdmDomain', 'Resolve-AdmDomain',
        'Set-AdmDomainCredential', 'Remove-AdmDomainCredential', 'Export-AdmDomainProfile', 'Import-AdmDomainProfile',
        'Get-AdmUser', 'Get-AdmGroup', 'Get-AdmComputer', 'Get-AdmObjectDetail', 'Get-AdmRangedProp', 'ConvertFrom-AdmUac', 'ConvertFrom-AdmGroupType',
        'Unlock-AdmUser', 'Set-AdmUserEnabled', 'Set-AdmComputerEnabled', 'Reset-AdmUserPassword',
        'New-AdmUser', 'Add-AdmGroupMember', 'Remove-AdmGroupMember', 'Get-AdmPasswordPolicy', 'Remove-AdmSpn', 'Get-AdmSearchResult',
        'Test-AdmDomain', 'Set-AdmProvider',
        'Get-AdmOrganizationalUnit', 'New-AdmOrganizationalUnit', 'Remove-AdmOrganizationalUnit',
        'Move-AdmObject', 'Rename-AdmObject', 'Remove-AdmObject', 'Set-AdmObjectProtection',
        'Get-AdmGroupMember', 'New-AdmGroup', 'Remove-AdmGroup', 'Get-AdmRangedAttribute',
        'Set-AdmUser', 'Set-AdmObjectAttribute', 'Import-AdmUserCsv', 'New-AdmRandomPassword',
        'Get-AdmLapsPassword', 'Get-AdmBitLockerRecoveryKey', 'Get-AdmNamingContext', 'Test-AdmSchemaAttribute',
        'Get-AdmTrust', 'Get-AdmSite', 'Get-AdmSubnet', 'Get-AdmGpo', 'ConvertFrom-AdmGpLink',
        'ConvertFrom-AdmTrustDirection', 'ConvertFrom-AdmTrustType', 'ConvertFrom-AdmTrustAttributes', 'ConvertFrom-AdmGpoStatus',
        'Test-AdmRecycleBinEnabled', 'Get-AdmDeletedObject', 'Restore-AdmObject',
        'Get-AdmPasswordSettingsPolicy', 'ConvertFrom-AdmPsoDuration',
        'New-AdmComputer', 'Set-AdmComputer', 'New-AdmLdapConnection',
        'Set-AdmDaclMask', 'ConvertTo-AdmSignedFlag', 'Get-AdmParentDn', 'Get-AdmRdnPrefix', 'ConvertTo-AdmRdnEscaped', 'Resolve-AdmObjectDn', 'Test-AdmObjectProtected',
        'Write-AdmLog', 'Get-AdmLog', 'Get-AdmLogInfo', 'Clear-AdmLog', 'Set-AdmLogReviewed', 'Export-AdmLog', 'Get-AdmWindowsEvent',
        'Get-AdmErrorCatalog', 'Invoke-AdmScan', 'Invoke-AdmRepair',
        'Test-AdmScript', 'Import-AdmScript', 'Get-AdmScript', 'Invoke-AdmScript', 'Remove-AdmScript',
        'Get-AdmTargetContextPublic', 'Invoke-AdmGuardedPublic',
        # the low-level directory API, for scripts written against this module
        'New-AdmDirectoryEntry', 'Close-AdmDirectoryEntry', 'Invoke-AdmAdsiSearch', 'Get-AdmSearchTruncated', 'Reset-AdmSearchTruncated', 'Get-AdmOverfetchLimit', 'Get-AdmRawProp', 'ConvertTo-AdmDistinguishedName', 'ConvertTo-AdmSidString'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('ActiveDirectory', 'Portable', 'MultiForest', 'Credentials')
        }
    }
}
