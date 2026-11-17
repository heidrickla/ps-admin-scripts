<#
.SYNOPSIS
  ADAdmin -- dark glass window over the multi-forest toolkit.

.DESCRIPTION
  WPF, because it is the only UI stack present on every Windows box that can do real
  translucency, rounded geometry and custom chrome. Markup lives in AdmWindow.xaml; this file
  loads it and wires behaviour. No code-behind class exists, so the XAML carries no event
  attributes -- every handler is attached here.
#>
[CmdletBinding()]
param(
    [string]$ModuleRoot,
    # Passed by the elevated relaunch so the new window opens the SAME credential store. UAC can
    # elevate into a different account, and the store lives in a user profile.
    [string]$StorePath,
    [switch]$NoBlur
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# NOT a param default. $PSScriptRoot is EMPTY while param defaults are being bound under Windows
# PowerShell 5.1 with -File, so `Split-Path -Parent $PSScriptRoot` there fails with "Cannot bind
# argument to parameter 'Path' because it is an empty string" -- and the window simply never opens.
if (-not $ModuleRoot) { $ModuleRoot = Split-Path -Parent $PSScriptRoot }
# Set before the module is imported, since that is when the store path is resolved.
if ($StorePath) { $env:ADADMIN_STORE = $StorePath }

# WPF demands a single-threaded apartment. Windows PowerShell 5.1 is STA already; pwsh 7 is
# MTA by default, so re-launch ourselves under -STA rather than failing with an error that
# says nothing about apartments.
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $psArgs = @('-STA', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath,
                '-ModuleRoot', $ModuleRoot)
    if ($StorePath) { $psArgs += @('-StorePath', $StorePath) }
    if ($NoBlur) { $psArgs += '-NoBlur' }
    & $exe @psArgs
    exit $LASTEXITCODE
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml
Import-Module (Join-Path $ModuleRoot 'ADAdmin\ADAdmin.psd1') -Force

# --- elevation ------------------------------------------------------------------------------------
#
# Most of this toolkit does NOT need administrator: querying a directory across forests uses a
# stored credential and cares nothing for local rights. Two of the shipped scripts do, because
# they change the machine itself -- RemoveVeeamAgent declares `#requires -RunAsAdministrator` and
# Set-UacGoldenPolicy writes under HKLM. `#requires` is enforced by PowerShell before the first
# line runs, so an unelevated session cannot even start them.
#
# ⛔ NOT AUTO-ELEVATED ON EVERY LAUNCH, DELIBERATELY. Elevating can land in a DIFFERENT user
# profile when the person running this is not themselves an administrator -- and the credential
# store lives in that profile, so the elevated window would come up with no store, or the wrong
# one. That looks like data loss. Elevation is offered instead, on a button, and the store path is
# passed explicitly to the elevated instance so it opens the same file either way.
function Test-AdmElevated {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { $false }
}

function Start-AdmElevated {
    # -StorePath, so the elevated window opens the SAME store even if UAC switched account.
    $storePath = ''
    try { $storePath = (Get-AdmStoreInfo).Path } catch { }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $argList = @('-STA', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
                 '-ModuleRoot', "`"$ModuleRoot`"")
    if ($storePath) { $argList += @('-StorePath', "`"$storePath`"") }
    if ($NoBlur) { $argList += '-NoBlur' }
    $psi.Arguments = $argList -join ' '
    $psi.Verb = 'runas'          # this is what raises the UAC prompt
    $psi.UseShellExecute = $true
    [System.Diagnostics.Process]::Start($psi) | Out-Null
}

# --- acrylic ------------------------------------------------------------------------------------
# Real backdrop blur is an undocumented user32 entry point. Everything degrades to the gradient
# if it is missing or refuses, which is why the whole thing sits in a try.
if (-not ('AdmBlur' -as [type])) {
    Add-Type -Namespace '' -Name 'AdmBlur' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll")]
internal static extern int SetWindowCompositionAttribute(System.IntPtr hwnd, ref WinCompAttrData data);

[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
internal struct AccentPolicy { public int AccentState; public int AccentFlags; public int GradientColor; public int AnimationId; }

[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
internal struct WinCompAttrData { public int Attribute; public System.IntPtr Data; public int SizeOfData; }

public static void Enable(System.IntPtr hwnd) {
    var accent = new AccentPolicy();
    accent.AccentState = 4;                       // ACCENT_ENABLE_ACRYLICBLURBEHIND
    accent.AccentFlags = 2;
    accent.GradientColor = unchecked((int)0x99101018);   // AABBGGRR tint behind the blur
    int size = System.Runtime.InteropServices.Marshal.SizeOf(accent);
    System.IntPtr ptr = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
    try {
        System.Runtime.InteropServices.Marshal.StructureToPtr(accent, ptr, false);
        var data = new WinCompAttrData { Attribute = 19, Data = ptr, SizeOfData = size };
        SetWindowCompositionAttribute(hwnd, ref data);
    } finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(ptr); }
}
'@
}

# --- load the window ------------------------------------------------------------------------------

$xamlPath = Join-Path $PSScriptRoot 'AdmWindow.xaml'
[xml]$xaml = [System.IO.File]::ReadAllText($xamlPath, (New-Object System.Text.UTF8Encoding($false)))
$reader = New-Object System.Xml.XmlNodeReader $xaml
$win = [Windows.Markup.XamlReader]::Load($reader)

function C { param([string]$Name) $win.FindName($Name) }

$ui = @{}
foreach ($n in @('TitleBar','BtnMinimize','BtnMaximize','BtnClose','RootBorder','ProviderText','AdminText','MainContent',
                 'DomainList','DomainCount','BtnTest','BtnLock','TargetBox','SearchBox','BtnSearch',
                 'BtnAddDomain','BtnEditDomain','DomainOverlay','DomainOverlayTitle','DomName','DomDns',
                 'DomNetbios','DomDcs','DomSslOn','DomSslOff','DomCredNote','DomCredUser','DomCredPass',
                 'DomTierRead','DomTierWrite','DomDefaultYes','DomDefaultNo','DomainError',
                 'BtnDomainSave','BtnDomainCancel','BtnDomainRemove','BtnExportDomains','BtnImportDomains',
                 'BtnScripts','ScriptPanel','ResultPanel','ScriptList','BtnBrowse','TreePanel','OuTree',
                 'BtnBin','BinPanel','BinGrid','BinNotes','BinStateChip','BinStateText',
                 'BtnForest','ForestPanel','ForestGrid','ForestNotes','BtnForestClose',
                 'BtnBulk','BulkPanel','BulkGrid','BulkNotes','BulkFileText','BtnBulkPick','BtnBulkApply','BtnBulkClose',
                 'BulkModeBoth','BulkModeCreate','BulkModeUpdate',
                 'ForestTabTrusts','ForestTabSites','ForestTabGpo','ForestTabPso',
                 'BtnBinRestore','BtnBinRefresh','BtnBinClose',
                 'TreeCountText','TreeSelTitle','TreeSelMeta','TreeGrid','BtnTreeRefresh','BtnTreeClose',
                 'BtnOuNew','BtnOuProtect','BtnOuDelete','BtnObjMove','BtnObjRename','BtnObjDelete',
                 'TreeKindUsers','TreeKindGroups','TreeKindComputers','TreeViewStandard','TreeViewAdvanced','ScriptCountText','ScriptTitle','ScriptMeta',
                 'ScriptSynopsis','ScriptModeRow','ScriptModes','ScriptParams','ScriptOutput',
                 'ScriptOutputScroll','BtnScriptRun','BtnScriptSaveOut','BtnScriptClose',
                 'ScriptWhatIfOn','ScriptWhatIfOff','ScriptTargetChip','ScriptTargetText',
                 'TabUsers','TabGroups','TabComputers','ResolveText','ResultGrid','EmptyText','ResultTruncText',
                 'BtnUnlockUser','BtnEnable','BtnDisable','BtnReset','BtnDetails','LockOverlay','StorePathText',
                 'DetailOverlay','DetailTitle','DetailSubtitle','DetailChips','DetailBody',
                 'BtnDetailUnlock','BtnDetailToggle','BtnDetailReset','BtnDetailMembers','BtnDetailCopy','BtnDetailClose','BtnDetailEdit','BtnDetailSecrets',
                 'EditOverlay','EditTitle','EditError','EditBody','EditChangeCount',
                 'BtnEditPreview','BtnEditCancel','BtnEditSave',
                 'PassBox','PassBox2','LockError','BtnUnlockStore','StatusText','StoreText',
                 'LockTitle','CreateFields','NewAdminName','PassLabel','ConfirmFields','BtnLockMode','LockHint',
                 'ErrorChip','ErrorCountText','BtnLog','LogPanel','LogList','LogTabProblems','LogTabAll','LogTabScan','BtnLogFix',
                 'LogTabWindows','BtnLogExport','BtnLogClose','BtnLogClear','BtnLogClearAll','BtnElevate','LogDetailTitle','LogDetailMeta','LogWhyLabel',
                 'LogDetailWhy','LogFixLabel','LogDetailFix','LogTechLabel','LogDetailTech','LogRetentionText')) {
    $ui[$n] = C $n
}

$script:CurrentDomain = $null
$script:Rows = @()
# Declared before first read: Set-StrictMode 2.0 errors on a never-assigned variable.
$script:EditingDomain = $null
# 'unlock' or 'create'. Same reason: the button handler reads it before Set-LockMode may have run.
$script:LockMode = 'unlock'
# The unlock passphrase, kept ONLY while the store is unlocked so a worker runspace can unlock its
# own module instance. Disposed the moment the store locks or the window closes.
$script:SessionPassphrase = $null

function Clear-SessionPassphrase {
    if ($script:SessionPassphrase) {
        try { $script:SessionPassphrase.Dispose() } catch { }
        $script:SessionPassphrase = $null
    }
}

# --- helpers ---------------------------------------------------------------------------------------

function Set-Status {
    param([string]$Text, [string]$Kind = 'info')
    $ui.StatusText.Text = $Text
    $ui.StatusText.Foreground = switch ($Kind) {
        'error'   { $win.FindResource('Danger') }
        'good'    { $win.FindResource('Success') }
        'warn'    { $win.FindResource('Warn') }
        default   { $win.FindResource('TextFaint') }
    }
}

# A modal overlay built in code so prompts stay on-theme. DispatcherFrame is what makes it
# behave modally without a second Window.
function Show-AdmPrompt {
    param(
        [string]$Title,
        [string]$Message,
        [ValidateSet('confirm', 'password')][string]$Kind = 'confirm',
        [string]$OkText = 'Confirm'
    )
    $root = $win.Content            # the outer Border
    $host_ = $root.Child            # the Grid inside it

    $veil = New-Object Windows.Controls.Grid
    # DialogVeil / DialogFill, not a glass tint: this card floats over the live results grid, and
    # a 13%-white fill lets the table read straight through the prompt.
    $veil.Background = $win.FindResource('DialogVeil')

    $card = New-Object Windows.Controls.Border
    $card.Style = $win.FindResource('GlassPanel')
    $card.Background = $win.FindResource('DialogFill')
    $card.Width = 420; $card.Padding = '26'
    $card.HorizontalAlignment = 'Center'; $card.VerticalAlignment = 'Center'

    $stack = New-Object Windows.Controls.StackPanel
    $t = New-Object Windows.Controls.TextBlock
    $t.Text = $Title; $t.FontSize = 16; $t.FontWeight = 'SemiBold'
    $t.Foreground = $win.FindResource('TextPrimary')
    [void]$stack.Children.Add($t)

    $m = New-Object Windows.Controls.TextBlock
    $m.Text = $Message; $m.FontSize = 12; $m.TextWrapping = 'Wrap'; $m.Margin = '0,10,0,0'
    $m.Foreground = $win.FindResource('TextMuted')
    [void]$stack.Children.Add($m)

    $pw = $null
    if ($Kind -eq 'password') {
        $pw = New-Object Windows.Controls.PasswordBox
        $pw.Style = $win.FindResource('GlassPassword'); $pw.Margin = '0,16,0,0'
        [void]$stack.Children.Add($pw)
    }

    $row = New-Object Windows.Controls.StackPanel
    $row.Orientation = 'Horizontal'; $row.HorizontalAlignment = 'Right'; $row.Margin = '0,20,0,0'
    $cancel = New-Object Windows.Controls.Button
    $cancel.Style = $win.FindResource('GhostButton'); $cancel.Content = 'Cancel'; $cancel.Margin = '0,0,8,0'
    $ok = New-Object Windows.Controls.Button
    $ok.Style = $win.FindResource('DangerButton'); $ok.Content = $OkText
    [void]$row.Children.Add($cancel); [void]$row.Children.Add($ok)
    [void]$stack.Children.Add($row)

    $card.Child = $stack
    [void]$veil.Children.Add($card)
    [void]$host_.Children.Add($veil)
    [Windows.Controls.Grid]::SetRowSpan($veil, 3)

    $frame = New-Object Windows.Threading.DispatcherFrame
    $script:PromptResult = $null
    $ok.Add_Click({ $script:PromptResult = if ($pw) { $pw.SecurePassword } else { $true }; $frame.Continue = $false }.GetNewClosure())
    $cancel.Add_Click({ $script:PromptResult = $null; $frame.Continue = $false }.GetNewClosure())
    if ($pw) { $pw.Focus() } else { $ok.Focus() }
    [Windows.Threading.Dispatcher]::PushFrame($frame)

    [void]$host_.Children.Remove($veil)
    $script:PromptResult
}

# The same modal shape as Show-AdmPrompt, but asking for a line of text. Kept separate rather than
# adding a third -Kind, because the return contract differs: this yields the STRING or $null, and a
# caller that treated an empty string as "confirmed" would act on nothing.
function Show-AdmTextPrompt {
    param([string]$Title, [string]$Message, [string]$Label = 'VALUE', [string]$Default = '')
    $root = $win.Content
    $host_ = $root.Child

    $veil = New-Object Windows.Controls.Grid
    $veil.Background = $win.FindResource('DialogVeil')
    $card = New-Object Windows.Controls.Border
    $card.Style = $win.FindResource('GlassPanel'); $card.Background = $win.FindResource('DialogFill')
    $card.Width = 480; $card.Padding = '26'
    $card.HorizontalAlignment = 'Center'; $card.VerticalAlignment = 'Center'

    $stack = New-Object Windows.Controls.StackPanel
    $t = New-Object Windows.Controls.TextBlock
    $t.Text = $Title; $t.FontSize = 16; $t.FontWeight = 'SemiBold'
    $t.Foreground = $win.FindResource('TextPrimary')
    [void]$stack.Children.Add($t)

    if ($Message) {
        $m = New-Object Windows.Controls.TextBlock
        $m.Text = $Message; $m.FontSize = 12; $m.TextWrapping = 'Wrap'; $m.Margin = '0,10,0,0'
        $m.Foreground = $win.FindResource('TextMuted')
        [void]$stack.Children.Add($m)
    }

    $l = New-Object Windows.Controls.TextBlock
    $l.Text = $Label; $l.FontSize = 10.5; $l.FontWeight = 'SemiBold'; $l.Margin = '2,16,0,5'
    $l.Foreground = $win.FindResource('TextFaint')
    [void]$stack.Children.Add($l)

    $tb = New-Object Windows.Controls.TextBox
    $tb.Style = $win.FindResource('GlassInput'); $tb.Text = $Default
    [void]$stack.Children.Add($tb)

    $row = New-Object Windows.Controls.StackPanel
    $row.Orientation = 'Horizontal'; $row.HorizontalAlignment = 'Right'; $row.Margin = '0,20,0,0'
    $cancel = New-Object Windows.Controls.Button
    $cancel.Style = $win.FindResource('GhostButton'); $cancel.Content = 'Cancel'; $cancel.Margin = '0,0,8,0'
    $ok = New-Object Windows.Controls.Button
    $ok.Style = $win.FindResource('AccentButton'); $ok.Content = 'OK'
    [void]$row.Children.Add($cancel); [void]$row.Children.Add($ok)
    [void]$stack.Children.Add($row)

    $card.Child = $stack
    [void]$veil.Children.Add($card)
    [void]$host_.Children.Add($veil)
    [Windows.Controls.Grid]::SetRowSpan($veil, 3)

    $frame = New-Object Windows.Threading.DispatcherFrame
    $script:TextPromptResult = $null
    # A blank box is a cancel, not an empty answer: every caller here needs a name.
    $ok.Add_Click({ $script:TextPromptResult = $(if ($tb.Text.Trim()) { $tb.Text.Trim() } else { $null }); $frame.Continue = $false }.GetNewClosure())
    $cancel.Add_Click({ $script:TextPromptResult = $null; $frame.Continue = $false }.GetNewClosure())
    $tb.Add_KeyDown({ if ($_.Key -eq 'Return') { $script:TextPromptResult = $(if ($tb.Text.Trim()) { $tb.Text.Trim() } else { $null }); $frame.Continue = $false } }.GetNewClosure())
    $tb.Focus(); $tb.SelectAll()
    [Windows.Threading.Dispatcher]::PushFrame($frame)

    [void]$host_.Children.Remove($veil)
    $script:TextPromptResult
}

function Update-Chips {
    $i = Get-AdmStoreInfo
    $ui.ProviderText.Text = "provider: $($i.Provider)"
    # The mock provider must be impossible to mistake for a real directory. A demo that looks
    # like production is how a fixture result gets acted on.
    $ui.ProviderText.Foreground = if ($i.Provider -eq 'mock') { $win.FindResource('Warn') } else { $win.FindResource('TextMuted') }
    $ui.AdminText.Text = if ($i.Unlocked) { "unlocked as $($i.UnlockedAs)" } else { 'locked' }
    $ui.AdminText.Foreground = if ($i.Unlocked) { $win.FindResource('Success') } else { $win.FindResource('TextMuted') }
    $ui.StoreText.Text = $i.Path
}

function Refresh-Domains {
    $doms = @(Get-AdmDomain)
    $view = foreach ($d in $doms) {
        [pscustomobject]@{
            Name = $d.Name; DnsDomain = $d.DnsDomain
            TierSummary = if ($d.CredentialTiers.Count) { "tiers: $($d.CredentialTiers -join ', ')" } else { 'no credentials stored' }
            Raw = $d
        }
    }
    $ui.DomainList.ItemsSource = @($view)
    # An empty store must say what to do next rather than just "0". This sidebar is the whole
    # entry point, and a count of nothing with no instruction is a dead end.
    $ui.DomainCount.Text = if ($doms.Count) { "$($doms.Count) registered" } else { 'none yet -- add one below' }
    $ui.BtnEditDomain.IsEnabled = [bool]$ui.DomainList.SelectedItem
}

# --- add / edit a domain ---------------------------------------------------------------------------

function Show-DomainEditor {
    param($Domain)   # $null to add

    $editing = $null -ne $Domain
    $ui.DomainOverlayTitle.Text = if ($editing) { "Edit $($Domain.Name)" } else { 'Add a domain' }
    $ui.DomainError.Visibility = 'Collapsed'
    $ui.DomainError.Text = ''

    if ($editing) {
        $ui.DomName.Text     = $Domain.Name
        $ui.DomDns.Text      = $Domain.DnsDomain
        $ui.DomNetbios.Text  = $Domain.NetbiosName
        $ui.DomDcs.Text      = (@($Domain.DomainControllers) -join ', ')
        if ($Domain.UseSsl) { $ui.DomSslOn.IsChecked = $true } else { $ui.DomSslOff.IsChecked = $true }

        # ⛔ The name is the KEY the credentials are filed under, so it is read-only here.
        # Changing it would register a second domain and orphan the first one's credentials --
        # an edit that behaves like a copy. Remove and re-add if a rename is really wanted.
        $ui.DomName.IsReadOnly = $true
        $ui.DomName.Opacity = 0.6
        $ui.BtnDomainRemove.Visibility = 'Visible'

        $tiers = @($Domain.CredentialTiers)
        $ui.DomCredNote.Text = if ($tiers.Count) {
            "Stored tiers: $($tiers -join ', '). Fill these in to add or replace one; leave blank to keep them as they are."
        } else {
            'No credential stored yet -- this domain cannot answer anything until it has one.'
        }
    } else {
        $ui.DomName.Text = ''; $ui.DomDns.Text = ''; $ui.DomNetbios.Text = ''; $ui.DomDcs.Text = ''
        $ui.DomSslOn.IsChecked = $true
        $ui.DomName.IsReadOnly = $false
        $ui.DomName.Opacity = 1.0
        $ui.BtnDomainRemove.Visibility = 'Collapsed'
        $ui.DomCredNote.Text = 'Optional now, but the domain cannot answer anything until it has one.'
    }

    # Never repopulated from the store: it does not hand passwords back, and a box that looks
    # filled would invite saving a value nobody supplied.
    $ui.DomCredUser.Text = ''
    $ui.DomCredPass.Password = ''
    $ui.DomTierRead.IsChecked = $true
    $ui.DomDefaultYes.IsChecked = $true

    $script:EditingDomain = $Domain
    $ui.DomainOverlay.Visibility = 'Visible'
    if ($editing) { $ui.DomDns.Focus() } else { $ui.DomName.Focus() }
}

function Hide-DomainEditor {
    $ui.DomainOverlay.Visibility = 'Collapsed'
    # Clear the password on the way out. Leaving it in a live PasswordBox keeps it in memory for
    # the life of the window for no reason.
    $ui.DomCredPass.Password = ''
    $script:EditingDomain = $null
}

function Set-DomainError {
    param([string]$Text)
    $ui.DomainError.Text = $Text
    $ui.DomainError.Visibility = if ($Text) { 'Visible' } else { 'Collapsed' }
}

function Save-DomainFromEditor {
    $name = $ui.DomName.Text.Trim()
    $dns  = $ui.DomDns.Text.Trim()

    if (-not $name) { Set-DomainError 'A name is required -- it is how you refer to this forest everywhere else.'; return }
    if (-not $dns)  { Set-DomainError 'A DNS domain is required, e.g. corp.example.com.'; return }

    $user = $ui.DomCredUser.Text.Trim()
    $pass = $ui.DomCredPass.SecurePassword
    $wantsCred = [bool]$user -or $pass.Length -gt 0
    if ($wantsCred -and -not $user)          { Set-DomainError 'A password was entered with no username.'; return }
    if ($wantsCred -and $pass.Length -eq 0)  { Set-DomainError "A username was entered with no password."; return }

    $dcs = @($ui.DomDcs.Text -split '[,;\s]+' | Where-Object { $_ })

    try {
        Set-DomainError ''
        # -Force so this is an upsert: editing an existing domain rewrites its profile and KEEPS
        # its stored credentials (Register-AdmDomain is explicit about not discarding them).
        Register-AdmDomain -Name $name -DnsDomain $dns -NetbiosName $ui.DomNetbios.Text.Trim() `
            -DomainControllers $dcs -UseSsl ([bool]$ui.DomSslOn.IsChecked) -Force -Confirm:$false | Out-Null

        if ($wantsCred) {
            $tier = if ($ui.DomTierWrite.IsChecked) { 'write' } else { 'read' }
            $cred = New-Object System.Management.Automation.PSCredential($user, $pass)
            Set-AdmDomainCredential -Domain $name -Credential $cred -Tier $tier `
                -SetDefault:([bool]$ui.DomDefaultYes.IsChecked) -Confirm:$false | Out-Null
            Set-Status "saved $name and stored its $tier credential" 'good'
        } else {
            Set-Status "saved $name -- no credential stored yet, so it cannot be queried" 'warn'
        }

        Hide-DomainEditor
        Refresh-Domains
        Update-ErrorChip
    }
    catch {
        # Stay open with the fields intact. Closing on failure throws away everything typed.
        Set-DomainError $_.Exception.Message
    }
}

function Get-SelectedKind {
    if ($ui.TabGroups.IsChecked) { 'groups' }
    elseif ($ui.TabComputers.IsChecked) { 'computers' }
    else { 'users' }
}

function Update-Resolution {
    $t = $ui.TargetBox.Text
    if (-not $t) { $ui.ResolveText.Text = 'no target resolved'; $ui.ResolveText.Foreground = $win.FindResource('TextMuted'); return }
    try {
        $r = Resolve-AdmDomain -Target $t
        $ui.ResolveText.Text = "$($r.Domain) via $($r.MatchedOn)"
        $ui.ResolveText.Foreground = $win.FindResource('Success')
    } catch {
        # Show the refusal verbatim. This is the one place the operator learns that a target is
        # ambiguous or unknown, and paraphrasing it would lose the remedy the message carries.
        $ui.ResolveText.Text = $_.Exception.Message
        $ui.ResolveText.Foreground = $win.FindResource('Danger')
    }
}

function Invoke-Search {
    $t = $ui.TargetBox.Text
    if (-not $t) { Set-Status 'Enter a target first.' 'warn'; return }
    $q = $ui.SearchBox.Text
    $kind = Get-SelectedKind
    # Bring the results pane back. Now that opening the log or the scripts HIDES it rather than
    # merely covering it, searching from either of those would otherwise fill a pane nobody can
    # see and look like a search that returned nothing.
    Show-ContentPane 'results'
    Set-Status "searching $kind in $t ..."
    try {
        # ⚠ AN EXPLICIT LIMIT, because the cmdlet default is 200 and this is the most-used read in
        # the window. An empty search box matches everything, so on any real domain the default
        # silently showed the first 200 accounts and called it the answer.
        $searchLimit = 20000
        Reset-AdmSearchTruncated
        $rows = switch ($kind) {
            'users'     { @(Get-AdmUser -Target $t -Identity $q -Limit $searchLimit) | Select-Object SamAccountName, DisplayName, UserPrincipalName, Enabled, LockedOut, Mail }
            'groups'    { @(Get-AdmGroup -Target $t -Identity $q -Limit $searchLimit) | Select-Object SamAccountName, Name, @{n='Members';e={ if (Get-AdmRawProp $_ 'MembersTruncated' $false) { "$(@($_.Members).Count)+" } else { [string]@($_.Members).Count } }}, DistinguishedName }
            'computers' { @(Get-AdmComputer -Target $t -Identity $q -Limit $searchLimit) | Select-Object Name, DnsHostName, OperatingSystem, Enabled }
        }
        $cut = [bool](Get-AdmSearchTruncated)
        $script:Rows = @($rows)
        $ui.ResultGrid.ItemsSource = $script:Rows
        $ui.EmptyText.Visibility = if ($script:Rows.Count) { 'Collapsed' } else { 'Visible' }
        $ui.EmptyText.Text = 'Nothing matched.'
        # ⛔ THE CAVEAT HAS TO OUTLIVE THE STATUS BAR, because the data it qualifies does. A status
        # line saying "the first 20000 only" is gone the moment anything else is clicked, while
        # the partial grid stays on screen looking like the whole answer. It goes above the grid,
        # where it cannot be separated from what it is about.
        if ($cut) {
            $ui.ResultTruncText.Text = "INCOMPLETE -- these are the first $($script:Rows.Count) $kind, not all of them. More matched than could be read, so a name missing from this list may still exist. Narrow the search."
            $ui.ResultTruncText.Visibility = 'Visible'
            Set-Status "the first $($script:Rows.Count) $kind ONLY -- more matched than could be read. Narrow the search." 'error'
        } else {
            $ui.ResultTruncText.Visibility = 'Collapsed'
            Set-Status "$($script:Rows.Count) $kind" 'good'
        }
        Update-Resolution
    } catch {
        $ui.ResultGrid.ItemsSource = $null
        $ui.ResultTruncText.Visibility = 'Collapsed'   # else it describes the PREVIOUS search's rows
        $ui.EmptyText.Visibility = 'Visible'
        # The plain-English title where the results would have been, so the empty grid explains
        # itself instead of just looking like "no results".
        $d = $null; try { $d = $_.Exception.Data['AdmDiagnosis'] } catch { }
        $ui.EmptyText.Text = if ($d) { "$($d.Title)`n`nOpen 'Error log' for what to try." }
                             else { $_.Exception.Message }
        Show-GuiFailure $_
    }
}

function Update-ActionButtons {
    $isUser = (Get-SelectedKind) -eq 'users'
    $sel = $ui.ResultGrid.SelectedItem
    $on = [bool]($isUser -and $sel)
    foreach ($b in @($ui.BtnUnlockUser, $ui.BtnEnable, $ui.BtnDisable, $ui.BtnReset)) { $b.IsEnabled = $on }
    # Details works for every class, not just users -- a group's membership and a computer's
    # delegation flags are exactly the things worth looking at.
    $ui.BtnDetails.IsEnabled = [bool]$sel
}

# The name to look an object up by, whichever kind of row is selected. Computers and groups have
# no SamAccountName column in their grid projection, so a single accessor would return blank for
# two of the three tabs.
function Get-SelectedIdentity {
    $sel = $ui.ResultGrid.SelectedItem
    if (-not $sel) { return $null }
    foreach ($p in @('SamAccountName', 'Name', 'DnsHostName')) {
        $v = Get-AdmRawProp $sel $p
        if ($v) { return [string]$v }
    }
    $null
}

# Every GUI failure goes through here: the plain-English title in the status bar, the problem
# counter updated, and the log panel one click away. Silently swallowing an exception into a grey
# status line is how a UI hides the thing the operator needs.
function Show-GuiFailure {
    param($ErrorRecord)
    $d = $null
    try { $d = $ErrorRecord.Exception.Data['AdmDiagnosis'] } catch { }
    $text = if ($d) { $d.Title } else { $ErrorRecord.Exception.Message }
    Set-Status "$text  --  click 'Error log' for what to try" 'error'
    Update-ErrorChip
    if ($ui.LogPanel.Visibility -eq 'Visible') { Refresh-Log }
}

# --- error log ---------------------------------------------------------------------------------------

$script:ScanFindings = @()

function Get-LogView {
    if ($ui.LogTabScan.IsChecked) {
        Set-Status 'scanning this machine, the store and every domain ...'
        $script:ScanFindings = @(Invoke-AdmScan)
        Set-Status ("scan: {0} ok, {1} warning, {2} failed, {3} could not be checked" -f
            @($script:ScanFindings | Where-Object { $_.Status -eq 'pass' }).Count,
            @($script:ScanFindings | Where-Object { $_.Status -eq 'warn' }).Count,
            @($script:ScanFindings | Where-Object { $_.Status -eq 'fail' }).Count,
            @($script:ScanFindings | Where-Object { $_.Status -eq 'unknown' }).Count) 'info'
        # Findings are rendered through the same entry shape as log lines, so one detail pane
        # serves both. Problems first -- a scan is read to find what is wrong.
        $order = @{ fail = 0; warn = 1; unknown = 2; pass = 3 }
        return @($script:ScanFindings | Sort-Object { $order[$_.Status] } | ForEach-Object {
            [pscustomobject]@{
                tsLocal = $_.Id
                severity = switch ($_.Status) { 'fail' { 'error' } 'warn' { 'warn' } 'pass' { 'info' } default { 'warn' } }
                title = $_.Name
                message = $_.Detail
                operation = $_.Target
                target = $_.Target
                why = if ($_.Problem) { "$($_.Problem)`n`n$($_.Impact)" } else { $null }
                fix = if ($_.FixDescription) { @($_.FixDescription) } else { @() }
                code = $_.Id
                technical = $null
                machine = $null
                Finding = $_
            }
        })
    }
    if ($ui.LogTabWindows.IsChecked) { return @(Get-AdmWindowsEvent -Level error -SinceHours 168 -MaxEvents 100) }
    if ($ui.LogTabAll.IsChecked)     { return @(Get-AdmLog -Days 7 -Last 300) }
    @(Get-AdmLog -Days 7 -Problems -Last 300)
}

function Refresh-Log {
    try {
        $rows = @(Get-LogView)
        # Newest first for the log: the thing that just broke is the thing being looked for.
        # A scan is already ordered worst-first and must NOT be reversed, or the passing checks
        # end up at the top and the failures are what needs scrolling to.
        if (-not $ui.LogTabScan.IsChecked) { [array]::Reverse($rows) }
        $view = foreach ($e in $rows) {
            # Same reason as Show-LogDetail: a Windows event and a plain log line do not carry
            # the same keys, and a missing one throws under StrictMode. Here it was swallowed by
            # the catch below, so instead of crashing the list simply came up empty with "Could
            # not read the log" -- a silent failure rather than a loud one.
            $title = Get-AdmRawProp $e 'title'
            $sev   = [string](Get-AdmRawProp $e 'severity' 'info')
            [pscustomobject]@{
                When     = Get-AdmRawProp $e 'tsLocal'
                Headline = if ($title) { [string]$title } else { [string](Get-AdmRawProp $e 'message') }
                Dot      = switch ($sev) { 'error' { '#FB7185' } 'warn' { '#FCD34D' } default { '#6EE7B7' } }
                Entry    = $e
            }
        }
        $ui.LogList.ItemsSource = @($view)
        $info = Get-AdmLogInfo
        $ui.LogRetentionText.Text = if ($info.Writable) {
            "kept $($info.RetentionDays) days - $($info.Files) file(s), $($info.TotalKB) KB - $($info.Directory)"
        } else {
            "NOT BEING SAVED TO DISK - showing this session only. Set ADADMIN_LOG_DIR to somewhere writable."
        }
        $ui.LogRetentionText.Foreground = if ($info.Writable) { $win.FindResource('TextFaint') } else { $win.FindResource('Warn') }
    } catch {
        $ui.LogRetentionText.Text = "Could not read the log: $($_.Exception.Message)"
        $ui.LogRetentionText.Foreground = $win.FindResource('Danger')
    }
}

function Show-LogDetail {
    $sel = $ui.LogList.SelectedItem
    if (-not $sel) { return }
    $e = $sel.Entry

    # ⛔ EVERY FIELD READ THROUGH Get-AdmRawProp, NOT `$e.title`.
    #
    # A log entry is JSON and carries only the keys that were actually written; a Windows event
    # has no `why`, `fix`, `code` or `technical` at all, and a plain log line has no `title`
    # unless the failure was diagnosed. Under Set-StrictMode 2.0 reading a property that is not
    # there THROWS, and an unhandled terminating error inside a WPF handler does not show a
    # message -- it closes the window. Clicking an error crashed the app.
    #
    # The previous version already wrapped `$e.Finding` in a try/catch, so the trap was known for
    # exactly one field and missed for the other nine. This is the same lesson the directory code
    # learned (docs/active-directory-traps.md, "a real directory omits attributes that are not
    # set") -- which is why Get-AdmRawProp already exists and is reused here rather than
    # reinvented.
    function P { param([string]$Name, $Default = $null) Get-AdmRawProp $e $Name $Default }

    $title = P 'title'
    $msg   = P 'message'
    $ui.LogDetailTitle.Text = if ($title) { [string]$title } else { [string]$msg }

    $bits = @()
    foreach ($f in @(@{n='tsLocal'; p=''}, @{n='operation'; p='while: '},
                     @{n='target';  p='target: '}, @{n='machine'; p='on: '})) {
        $v = P $f.n
        if ($v) { $bits += "$($f.p)$v" }
    }
    $ui.LogDetailMeta.Text = ($bits -join '   -   ')

    $why = P 'why'
    $ui.LogDetailWhy.Text = [string]$why
    $ui.LogWhyLabel.Visibility = if ($why) { 'Visible' } else { 'Collapsed' }

    $fixes = @(@(P 'fix' @()) | Where-Object { $_ })
    $n = 1
    $ui.LogDetailFix.ItemsSource = @($fixes | ForEach-Object { "$n. $_"; $n++ })
    $ui.LogFixLabel.Visibility = if ($fixes.Count) { 'Visible' } else { 'Collapsed' }

    $tech = @()
    $code = P 'code'
    if ($code) { $tech += "code: $code" }
    $t = P 'technical'
    if ($t) {
        $codes = Get-AdmRawProp $t 'Codes'
        $raw   = Get-AdmRawProp $t 'Raw'
        if ($codes) { $tech += "codes: $codes" }
        if ($raw)   { $tech += [string]$raw }
    }
    if (-not $tech.Count -and $msg) { $tech += [string]$msg }
    $ui.LogDetailTech.Text = ($tech -join "`r`n")
    $ui.LogTechLabel.Visibility = if ($tech.Count) { 'Visible' } else { 'Collapsed' }

    # "Fix this" appears only for a scan finding that actually has a remedy. A button that is
    # always there and usually does nothing teaches people to ignore it.
    $f = P 'Finding'
    $ui.BtnLogFix.Visibility = if ($f -and (Get-AdmRawProp $f 'CanFix')) { 'Visible' } else { 'Collapsed' }
}

function Update-ErrorChip {
    try {
        $problems = @(Get-AdmLog -Days 7 -Problems -Last 300 | Where-Object { $_.severity -eq 'error' })
        if ($problems.Count) {
            $ui.ErrorCountText.Text = "$($problems.Count) problem$(if ($problems.Count -ne 1) { 's' })"
            $ui.ErrorChip.Visibility = 'Visible'
        } else { $ui.ErrorChip.Visibility = 'Collapsed' }
    } catch { }
}

# The results, the log and the scripts all live in the same grid cell. Exactly one is visible at
# a time: GlassPanel is 8% white, so a panel left visible underneath shows through the one on top
# -- the DataGrid's header rule appeared as a line drawn across the buttons of whatever was in
# front of it.
function Show-ContentPane {
    param([ValidateSet('results', 'log', 'scripts', 'tree', 'bin', 'forest', 'bulk')][string]$Which)
    $ui.ForestPanel.Visibility = if ($Which -eq 'forest')  { 'Visible' } else { 'Collapsed' }
    $ui.BulkPanel.Visibility   = if ($Which -eq 'bulk')    { 'Visible' } else { 'Collapsed' }
    $ui.ResultPanel.Visibility = if ($Which -eq 'results') { 'Visible' } else { 'Collapsed' }
    $ui.LogPanel.Visibility    = if ($Which -eq 'log')     { 'Visible' } else { 'Collapsed' }
    $ui.ScriptPanel.Visibility = if ($Which -eq 'scripts') { 'Visible' } else { 'Collapsed' }
    $ui.TreePanel.Visibility   = if ($Which -eq 'tree')    { 'Visible' } else { 'Collapsed' }
    $ui.BinPanel.Visibility    = if ($Which -eq 'bin')     { 'Visible' } else { 'Collapsed' }
}

function Show-LogPanel {
    param([bool]$Show = $true)
    Show-ContentPane $(if ($Show) { 'log' } else { 'results' })
    if ($Show) { Refresh-Log }
}

# --- scripts -----------------------------------------------------------------------------------

# ⭐ EVERYTHING THE PANEL KNOWS ABOUT A SCRIPT IS READ FROM THE SCRIPT.
#
# The synopsis, every parameter, its type, its ValidateSet, which parameter set it belongs to,
# whether it is mandatory, and whether the script supports -WhatIf all come out of the file's own
# AST. There is deliberately NO table of scripts and their options in this file: a second copy of
# that would drift from the scripts within a release or two, and the failure mode is a GUI that
# silently cannot reach a feature -- which is exactly the gap this panel exists to close. Add a
# parameter to a script and it appears here with no change to the GUI.
function Get-ScriptInfo {
    param([string]$Path)

    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)

    # ⚠ NOT GetReflectionName(): that method does not exist on TypeName under Windows PowerShell
    # 5.1 and throws "does not contain a method named 'GetReflectionName'". .Name is present on
    # both runtimes. The suffix is stripped because [Parameter()] and [ParameterAttribute()] are
    # the same attribute written two ways.
    function Get-AttrName {
        param($Attr)
        $n = [string]$Attr.TypeName.Name
        if ($n.EndsWith('Attribute')) { $n = $n.Substring(0, $n.Length - 9) }
        $n
    }

    $synopsis = ''
    try { $h = $ast.GetHelpContent(); if ($h -and $h.Synopsis) { $synopsis = ($h.Synopsis -replace '\s+', ' ').Trim() } } catch { }

    # SupportsShouldProcess lives on [CmdletBinding()] on the param block.
    $supportsWhatIf = $false
    $defaultSet = $null
    $paramBlock = $ast.ParamBlock
    if ($paramBlock) {
        foreach ($a in @($paramBlock.Attributes)) {
            if ((Get-AttrName $a) -ne 'CmdletBinding') { continue }
            foreach ($na in @($a.NamedArguments)) {
                switch ($na.ArgumentName) {
                    'SupportsShouldProcess' {
                        # `SupportsShouldProcess` with no value is an implicit $true.
                        $supportsWhatIf = if ($na.ExpressionOmitted) { $true } else { [bool]$na.Argument.SafeGetValue() }
                    }
                    'DefaultParameterSetName' { $defaultSet = [string]$na.Argument.SafeGetValue() }
                }
            }
        }
    }

    # Supplied by the panel, or noise. -Target comes from the target box, -Tier from the domain,
    # and the common parameters are not a user-facing feature of the script.
    # -Credential is excluded on purpose: a PSCredential cannot be typed into a text box, and
    # rendering one as a field would invite a password in plain sight. Directory scripts take
    # theirs from the store via -Target; a machine script uses the session's own identity.
    $skip = @('Target', 'Tier', 'Credential', 'Verbose', 'Debug', 'ErrorAction', 'WarningAction',
              'InformationAction', 'ErrorVariable', 'WarningVariable', 'InformationVariable',
              'OutVariable', 'OutBuffer', 'PipelineVariable', 'WhatIf', 'Confirm', 'UseDnsLookup')

    $params = New-Object System.Collections.ArrayList
    # A script can legitimately have no param() block at all -- RemoveVeeamAgent is one. Reading
    # .Parameters off $null throws under StrictMode and took the whole panel down.
    $declared = if ($paramBlock) { @($paramBlock.Parameters) } else { @() }

    # ⛔ NOT EVERY SCRIPT TAKES -Target. The directory ones do; the MACHINE ones -- RemoveVeeamAgent,
    # Set-UacGoldenPolicy -- act on a computer and have no notion of a forest. The runner used to
    # pass -Target unconditionally, so those failed with "A parameter cannot be found that matches
    # parameter name 'Target'" before doing anything at all.
    $names = @($declared | ForEach-Object { $_.Name.VariablePath.UserPath })
    $hasTarget = $names -contains 'Target'
    $hasTier   = $names -contains 'Tier'

    # `#requires -RunAsAdministrator` is not a parameter and is not in the AST's param block; it
    # is a script-level requirement PowerShell enforces before the first line runs. Worth knowing
    # up front so the panel can say so instead of letting it fail on launch.
    $needsAdmin = $false
    try {
        $needsAdmin = [bool]([regex]::IsMatch((Get-Content -LiteralPath $Path -Raw),
                      '(?im)^\s*#requires\b.*-RunAsAdministrator'))
    } catch { }

    foreach ($p in $declared) {
        $name = $p.Name.VariablePath.UserPath
        if ($skip -contains $name) { continue }

        $type = if ($p.StaticType) { $p.StaticType.Name } else { 'Object' }
        $sets = New-Object System.Collections.ArrayList
        $mandatory = $false
        $validate = @()

        foreach ($a in @($p.Attributes)) {
            # Skip the type constraint, e.g. the [string] in [string]$Name -- it lives in the same
            # Attributes collection but is a TypeConstraintAst with no named arguments.
            if ($a -isnot [System.Management.Automation.Language.AttributeAst]) { continue }
            $tn = Get-AttrName $a
            if ($tn -eq 'Parameter') {
                foreach ($na in @($a.NamedArguments)) {
                    if ($na.ArgumentName -eq 'Mandatory') {
                        if ($na.ExpressionOmitted -or [bool]$na.Argument.SafeGetValue()) { $mandatory = $true }
                    }
                    if ($na.ArgumentName -eq 'ParameterSetName') { [void]$sets.Add([string]$na.Argument.SafeGetValue()) }
                }
            }
            elseif ($tn -eq 'ValidateSet') {
                foreach ($pa in @($a.PositionalArguments)) {
                    try { $validate += [string]$pa.SafeGetValue() } catch { }
                }
            }
        }

        [void]$params.Add([pscustomobject]@{
            Name = $name; Type = $type; Mandatory = $mandatory
            Sets = @($sets); ValidateSet = @($validate)
            IsSwitch = ($type -eq 'SwitchParameter')
            IsSecure = ($type -eq 'SecureString')
        })
    }

    # Every named set in the file, default first so the panel opens on the intended mode.
    $allSets = @($params | ForEach-Object { $_.Sets } | Where-Object { $_ } | Select-Object -Unique)
    if ($defaultSet -and $allSets -notcontains $defaultSet) { $allSets = @($defaultSet) + $allSets }
    elseif ($defaultSet) { $allSets = @($defaultSet) + @($allSets | Where-Object { $_ -ne $defaultSet }) }

    [pscustomobject]@{
        Synopsis = $synopsis; SupportsWhatIf = $supportsWhatIf
        Parameters = @($params); Sets = @($allSets); DefaultSet = $defaultSet
        HasTarget = $hasTarget; HasTier = $hasTier; NeedsAdmin = $needsAdmin
    }
}

function Get-ScriptSynopsis {
    param([string]$Path)
    try { (Get-ScriptInfo -Path $Path).Synopsis } catch { '' }
}

# --- the generated form -------------------------------------------------------------------------

$script:ScriptControls = @{}
$script:ScriptInfo = $null
$script:ScriptSet = $null

function New-ParamLabel {
    param([string]$Text, [bool]$Mandatory)
    $t = New-Object Windows.Controls.TextBlock
    # Split the PascalCase before upper-casing, or -PasswordExpiringDays renders as the unreadable
    # run-on PASSWORDEXPIRINGDAYS. The boundary is a lower-to-upper transition, plus the
    # acronym case (IAcceptTheReplicationLag, OUPath) where a run of capitals meets a word.
    $spaced = $Text -creplace '([a-z0-9])([A-Z])', '$1 $2' -creplace '([A-Z]+)([A-Z][a-z])', '$1 $2'
    $t.Text = if ($Mandatory) { "$($spaced.ToUpper())  *" } else { $spaced.ToUpper() }
    $t.FontSize = 10.5; $t.FontWeight = 'SemiBold'; $t.Margin = '2,0,0,4'
    # TextMuted for both, not TextFaint for the optional ones. These label fields you are meant to
    # fill in; at the faint tint the whole generated form read as disabled.
    $t.Foreground = $win.FindResource($(if ($Mandatory) { 'TextPrimary' } else { 'TextMuted' }))
    $t
}

function Build-ScriptForm {
    $ui.ScriptParams.Children.Clear()
    $script:ScriptControls = @{}
    $info = $script:ScriptInfo
    if (-not $info) { return }

    $shown = @($info.Parameters | Where-Object {
        # A parameter with no set declared belongs to every set.
        $_.Sets.Count -eq 0 -or ($script:ScriptSet -and $_.Sets -contains $script:ScriptSet)
    })

    if (-not $shown.Count) {
        $t = New-Object Windows.Controls.TextBlock
        $t.Text = 'No options -- this one just runs against the target.'
        $t.FontSize = 11.5; $t.Foreground = $win.FindResource('TextFaint')
        [void]$ui.ScriptParams.Children.Add($t)
        return
    }

    foreach ($p in $shown) {
        $row = New-Object Windows.Controls.StackPanel
        $row.Margin = '0,0,0,10'
        [void]$row.Children.Add((New-ParamLabel -Text $p.Name -Mandatory $p.Mandatory))

        if ($p.IsSwitch) {
            # A switch is a yes/no, and a pair of buttons says which one is currently in force.
            # A single toggle that looks the same either way is how you run -DisableStale
            # believing you were reporting.
            $sp = New-Object Windows.Controls.StackPanel
            $sp.Orientation = 'Horizontal'
            $on  = New-Object Windows.Controls.RadioButton
            $off = New-Object Windows.Controls.RadioButton
            $on.Style = $win.FindResource('TabPill');  $on.Content = 'On';  $on.GroupName = "sw_$($p.Name)"
            $off.Style = $win.FindResource('TabPill'); $off.Content = 'Off'; $off.GroupName = "sw_$($p.Name)"
            $off.IsChecked = $true
            [void]$sp.Children.Add($on); [void]$sp.Children.Add($off)
            [void]$row.Children.Add($sp)
            $script:ScriptControls[$p.Name] = [pscustomobject]@{ Kind = 'switch'; On = $on; Param = $p }
        }
        elseif ($p.ValidateSet.Count) {
            # A closed set of values is a set of buttons, not a box to mistype into.
            $wp = New-Object Windows.Controls.WrapPanel
            $btns = @()
            # ⭐ A [string[]] with a ValidateSet takes SEVERAL values at once -- the privilege
            # audit's -Section is Membership, Delegation, Roastable, Hygiene, AdminCount, Krbtgt
            # and you are meant to be able to ask for three of them. Radio buttons would cap that
            # at one and quietly remove a feature, so an array gets toggles instead.
            $multi = $p.Type -match '\[\]$'
            foreach ($v in $p.ValidateSet) {
                if ($multi) {
                    $b = New-Object Windows.Controls.Primitives.ToggleButton
                    $b.Style = $win.FindResource('TogglePill')
                } else {
                    $b = New-Object Windows.Controls.RadioButton
                    $b.Style = $win.FindResource('TabPill'); $b.GroupName = "vs_$($p.Name)"
                }
                $b.Content = $v; $b.Tag = $v
                [void]$wp.Children.Add($b); $btns += $b
            }
            # Nothing preselected for an optional one: the script's own default is better than
            # anything guessed here, and picking one would override it silently.
            if ($p.Mandatory -and -not $multi -and $btns.Count) { $btns[0].IsChecked = $true }
            [void]$row.Children.Add($wp)
            $script:ScriptControls[$p.Name] = [pscustomobject]@{ Kind = 'set'; Buttons = $btns; Multi = $multi; Param = $p }
        }
        elseif ($p.IsSecure) {
            $pb = New-Object Windows.Controls.PasswordBox
            $pb.Style = $win.FindResource('GlassPassword')
            [void]$row.Children.Add($pb)
            $script:ScriptControls[$p.Name] = [pscustomobject]@{ Kind = 'secure'; Box = $pb; Param = $p }
        }
        else {
            $tb = New-Object Windows.Controls.TextBox
            $tb.Style = $win.FindResource('GlassInput')
            $tb.ToolTip = "$($p.Type)$(if ($p.Type -match '\[\]$' -or $p.Type -eq 'String[]') { '  --  comma separated' })"

            # A parameter that names an object in the directory gets a Browse, so it can be
            # chosen rather than remembered.
            $kind = $script:PickerKinds[$p.Name]
            if ($kind) {
                $g = New-Object Windows.Controls.Grid
                [void]$g.ColumnDefinitions.Add((New-Object Windows.Controls.ColumnDefinition))
                $c2 = New-Object Windows.Controls.ColumnDefinition
                $c2.Width = 'Auto'
                [void]$g.ColumnDefinitions.Add($c2)
                [void]$g.Children.Add($tb)
                [Windows.Controls.Grid]::SetColumn($tb, 0)

                $browse = New-Object Windows.Controls.Button
                $browse.Style = $win.FindResource('GhostButton')
                $browse.Content = 'Browse'
                $browse.Margin = '8,0,0,0'
                $browse.ToolTip = "List the $kind in the current target and pick from them"
                [Windows.Controls.Grid]::SetColumn($browse, 1)
                [void]$g.Children.Add($browse)

                $browse.Add_Click({
                    $t = $ui.TargetBox.Text.Trim()
                    if (-not $t) { Set-Status 'Set a target first, or pick a domain on the left.' 'warn'; return }
                    $picked = Show-AdmObjectPicker -Kind $kind -Target $t
                    if ($picked) { $tb.Text = (@($picked) -join ', ') }
                }.GetNewClosure())

                [void]$row.Children.Add($g)
            } else {
                [void]$row.Children.Add($tb)
            }
            $script:ScriptControls[$p.Name] = [pscustomobject]@{ Kind = 'text'; Box = $tb; Param = $p }
        }

        [void]$ui.ScriptParams.Children.Add($row)
    }
}

function Build-ScriptModes {
    $ui.ScriptModes.Items.Clear()
    $info = $script:ScriptInfo
    $sets = @($info.Sets)
    if ($sets.Count -lt 2) {
        $ui.ScriptModeRow.Visibility = 'Collapsed'
        $script:ScriptSet = if ($sets.Count) { $sets[0] } else { $null }
        return
    }
    $ui.ScriptModeRow.Visibility = 'Visible'
    foreach ($s in $sets) {
        $rb = New-Object Windows.Controls.RadioButton
        $rb.Style = $win.FindResource('TabPill'); $rb.Content = $s; $rb.GroupName = 'scriptset'; $rb.Tag = $s
        if ($s -eq $info.DefaultSet) { $rb.IsChecked = $true }
        $rb.Add_Checked({ $script:ScriptSet = [string]$this.Tag; Build-ScriptForm }.GetNewClosure())
        [void]$ui.ScriptModes.Items.Add($rb)
    }
    $script:ScriptSet = $info.DefaultSet
}

# Turn the form back into a splat. Empty means "not supplied", so the script's own default wins.
function Get-ScriptArguments {
    $splat = @{}
    foreach ($name in $script:ScriptControls.Keys) {
        $c = $script:ScriptControls[$name]
        switch ($c.Kind) {
            'switch' { if ($c.On.IsChecked) { $splat[$name] = $true } }
            'set'    {
                $sel = @($c.Buttons | Where-Object { $_.IsChecked })
                if (-not $sel.Count) { break }
                $splat[$name] = if ($c.Multi) { @($sel | ForEach-Object { [string]$_.Tag }) } else { [string]$sel[0].Tag }
            }
            'secure' { if ($c.Box.SecurePassword.Length -gt 0) { $splat[$name] = $c.Box.SecurePassword } }
            'text'   {
                $v = $c.Box.Text.Trim()
                if (-not $v) { break }
                # A [string[]] parameter takes a list; splitting here means the user types what
                # they would type in the CLI rather than learning a GUI-specific convention.
                if ($c.Param.Type -match '\[\]$') { $splat[$name] = @($v -split '[,;]\s*' | Where-Object { $_ }) }
                else { $splat[$name] = $v }
            }
        }
    }
    $splat
}

function Refresh-Scripts {
    $items = New-Object System.Collections.ArrayList

    # ⛔ $ModuleRoot, NOT `$ui.ScriptRoot` -- that key never existed. $ui is a HASHTABLE, so a
    # missing key returns $null in silence even under Set-StrictMode 2.0 (the strict property
    # check does not apply to hashtable key access), and `Split-Path -Parent $null` then throws.
    # With $ErrorActionPreference = 'Stop' an unhandled terminating error inside a WPF event
    # handler does not surface as a message -- it takes the whole window down. Clicking Scripts
    # closed the app.
    $shipped = Join-Path $ModuleRoot 'scripts'
    if (Test-Path -LiteralPath $shipped) {
        foreach ($f in (Get-ChildItem -LiteralPath $shipped -Filter '*.ps1' | Sort-Object Name)) {
            [void]$items.Add([pscustomobject]@{
                Name = $f.BaseName; Kind = 'shipped'; Path = $f.FullName
                Synopsis = Get-ScriptSynopsis -Path $f.FullName; Meta = ''
            })
        }
    }

    # Imported: whatever 'adm script import' has installed.
    try {
        foreach ($s in @(Get-AdmScript)) {
            # Drift is worth showing here, not buried in the CLI: a converted copy older than its
            # source is running code the author has already changed.
            $meta = "imported $($s.Imported)"
            if ($s.Drift -and $s.Drift -ne 'current') { $meta += "  --  $($s.Drift)" }
            [void]$items.Add([pscustomobject]@{
                Name = $s.Name; Kind = "imported  ($($s.Drift))"; Path = $null
                Synopsis = ''; Meta = $meta
            })
        }
    } catch { }

    $ui.ScriptList.ItemsSource = @($items)
    $ui.ScriptCountText.Text = "$($items.Count) available"
    $ui.BtnScriptRun.IsEnabled = $false
    $ui.BtnScriptSaveOut.IsEnabled = $false
}

function Update-ScriptTargetChip {
    $t = $ui.TargetBox.Text.Trim()
    # A machine script has no -Target, so saying one applies would be misleading.
    if ($script:ScriptInfo -and -not $script:ScriptInfo.HasTarget) {
        $ui.ScriptTargetText.Text = 'acts on a machine, not a forest'
        $ui.ScriptTargetText.Foreground = $win.FindResource('TextFaint')
    } elseif ($t) {
        $ui.ScriptTargetText.Text = "target: $t"
        $ui.ScriptTargetText.Foreground = $win.FindResource('Success')
    } else {
        $ui.ScriptTargetText.Text = 'no target -- click to set one'
        $ui.ScriptTargetText.Foreground = $win.FindResource('Warn')
    }
}

# --- the directory tree ------------------------------------------------------------------------
#
# Navigation rather than search. Built from ONE call: Get-AdmOrganizationalUnit returns every OU
# with its own DN and its parent's, which is the entire hierarchy without a query per level.
$script:TreeOus = @()

function New-OuNode {
    param($Ou)
    $n = New-Object Windows.Controls.TreeViewItem
    $label = [string]$Ou.Name
    $class = [string](Get-AdmRawProp $Ou 'ObjectClass' 'organizationalUnit')

    # A container is drawn differently from an OU on purpose, not for decoration: most of what
    # you can do to an OU you cannot do to a container -- no rename, no move, and no GPO link.
    # Showing them identically invites someone to try, and to be baffled when it fails.
    $isOu = ($class -eq 'organizationalUnit')
    if (-not $isOu) { $label += "   ($class)" }

    # A protected OU is worth showing as such: it is the reason a delete will fail later with
    # "Access is denied", which reads as a permissions problem and is not one.
    if (Get-AdmRawProp $Ou 'Protected' $false) { $label += '   [protected]' }

    $n.Header = $label
    $n.Tag = $Ou
    $n.Foreground = $win.FindResource($(if ($isOu) { 'TextPrimary' } else { 'TextMuted' }))
    $n
}

function Build-OuTree {
    $target = $ui.TargetBox.Text.Trim()
    if (-not $target) { Set-Status 'Pick a domain on the left first.' 'warn'; return }

    $ui.OuTree.Items.Clear()
    Set-Status "reading the structure of $target ..."
    # ⭐ -IncludeContainers, because CN=Users, CN=Computers and CN=Builtin are objectClass
    # `container` (Builtin is `builtinDomain`), NOT organizationalUnit -- and on a default domain
    # every account still lives in CN=Users. Without them this tree showed one OU and no users at
    # all. Measured on a lab domain controller: 1 OU, 0 users reachable.
    # ⛔ 2000 WAS A LAB NUMBER. A real estate has far more OUs, and a truncated tree looks exactly
    # like a complete one -- you simply do not see the branch you were looking for and conclude it
    # does not exist. High enough that a hit means something is wrong, and a hit is reported.
    $ouLimit = 50000
    Reset-AdmSearchTruncated
    try { $script:TreeOus = @(Get-AdmOrganizationalUnit -Target $target -IncludeContainers -Limit $ouLimit) }
    catch { Show-GuiFailure $_; return }
    $truncated = [bool](Get-AdmSearchTruncated)
    $before = @($script:TreeOus).Count

    # The domain head is the root. It is not an OU, so it is never in the list and has to be
    # synthesised -- but objects live directly in it (CN=Users among them), so it must be
    # selectable or the default containers are unreachable.
    $rootDn = ''
    try { $rootDn = [string](ConvertTo-AdmDistinguishedName -DnsDomain $target) } catch { }
    if (-not $rootDn -and @($script:TreeOus).Count) {
        # Fall back to the shortest parent seen, which is the domain head by construction.
        $rootDn = @($script:TreeOus | ForEach-Object { [string]$_.ParentDn } | Where-Object { $_ } |
                    Sort-Object Length | Select-Object -First 1)
    }
    $root = New-Object Windows.Controls.TreeViewItem
    $root.Header = $target
    $root.Tag = [pscustomobject]@{ Name = $target; DistinguishedName = $rootDn; ParentDn = $null; Description = 'domain root' }
    $root.Foreground = $win.FindResource('Accent')
    $root.IsExpanded = $true

    # ⭐ THE DIRECTORY'S OWN PLUMBING IS HIDDEN BY DEFAULT, as ADUC hides it behind "Advanced
    # Features". Asking for containers gets you CN=System and everything under it -- DNS zones,
    # WinsockServices, ComPartitionSets, and a row of GUID-named containers -- which buried the
    # seven containers an administrator actually works in. Measured on a lab domain controller: the standard view is
    # a readable handful, the advanced view is dozens.
    #
    # The rule is structural rather than a name list, so it does not rot on a domain with
    # different plumbing: an OU is ALWAYS shown at any depth, and a container is shown only when
    # it sits directly under the domain root. That alone removes the whole CN=System subtree,
    # and the named roots below are the ones ADUC also hides at the top level.
    $advanced = [bool]$ui.TreeViewAdvanced.IsChecked
    $noisyRoots = @('System', 'Program Data', 'NTDS Quotas', 'LostAndFound', 'Infrastructure',
                    'TPM Devices', 'Keys', 'Managed Service Accounts')
    $hidden = 0
    if (-not $advanced) {
        $rootLower = $rootDn.ToLowerInvariant()
        $script:TreeOus = @($script:TreeOus | Where-Object {
            $cls = [string](Get-AdmRawProp $_ 'ObjectClass' 'organizationalUnit')
            if ($cls -eq 'organizationalUnit') { return $true }        # an OU always shows
            $parent = [string](Get-AdmRawProp $_ 'ParentDn')
            if ($parent.ToLowerInvariant() -ne $rootLower) { return $false }   # nested plumbing
            $noisyRoots -notcontains [string](Get-AdmRawProp $_ 'Name')
        })
        $hidden = $before - @($script:TreeOus).Count
    }

    # DN -> node, so a child can be hung off its parent in one pass. DNs are compared
    # case-insensitively: AD preserves the case you wrote but does not distinguish by it, so a
    # parent recorded as OU=Staff,DC=... and a child claiming ou=staff,DC=... are the same place.
    $byDn = @{}
    foreach ($o in $script:TreeOus) {
        $dn = [string]$o.DistinguishedName
        if (-not $dn) { continue }
        $byDn[$dn.ToLowerInvariant()] = @{ Ou = $o; Node = (New-OuNode -Ou $o) }
    }

    $orphans = 0
    foreach ($key in $byDn.Keys) {
        $entry = $byDn[$key]
        $parent = [string]$entry.Ou.ParentDn
        $pk = if ($parent) { $parent.ToLowerInvariant() } else { '' }
        if ($pk -and $byDn.ContainsKey($pk)) {
            [void]$byDn[$pk].Node.Items.Add($entry.Node)
        } elseif ($pk -eq $rootDn.ToLowerInvariant() -or -not $pk) {
            [void]$root.Items.Add($entry.Node)
        } else {
            # A parent that is not itself an OU -- an OU nested under a CN container, which is
            # unusual but legal. Hang it off the root rather than dropping it silently.
            [void]$root.Items.Add($entry.Node); $orphans++
        }
    }

    [void]$ui.OuTree.Items.Add($root)
    $ous  = @($script:TreeOus | Where-Object { (Get-AdmRawProp $_ 'ObjectClass' 'organizationalUnit') -eq 'organizationalUnit' }).Count
    $cont = @($script:TreeOus).Count - $ous
    # ⚠ Say how many were hidden. A filtered tree presented as the whole directory is the kind of
    # quiet omission this toolkit refuses everywhere else.
    $ui.TreeCountText.Text = "$ous OU(s), $cont container(s)" +
        $(if ($hidden) { "  ($hidden system container(s) hidden -- switch to Advanced)" } else { '' }) +
        $(if ($truncated) { "  TRUNCATED -- this is NOT the whole directory" } else { '' })
    if ($truncated) {
        Set-Status "TRUNCATED: the read stopped at $ouLimit containers, so branches are missing from this tree." 'error'
    } else {
        Set-Status "$ous OU(s) and $cont container(s) in $target$(if ($hidden) { ", $hidden hidden" })" 'good'
    }
    if ($orphans) {
        Write-Verbose "$orphans OU(s) sit under a non-OU container and were attached to the root."
    }
}

function Get-TreeKind {
    if ($ui.TreeKindGroups.IsChecked) { 'groups' }
    elseif ($ui.TreeKindComputers.IsChecked) { 'computers' }
    else { 'users' }
}

function Show-OuContents {
    $sel = $ui.OuTree.SelectedItem
    if (-not $sel -or -not $sel.Tag) { return }
    $ou = $sel.Tag
    $target = $ui.TargetBox.Text.Trim()
    $dn = [string]$ou.DistinguishedName
    if (-not $dn) { return }

    $ui.TreeSelTitle.Text = [string]$ou.Name
    $bits = @($dn)
    foreach ($f in @('Description', 'ManagedBy', 'WhenCreated')) {
        $v = Get-AdmRawProp $ou $f
        if ($v) { $bits += "$f`: $v" }
    }
    $gp = Get-AdmRawProp $ou 'GpoLinkCount'
    if ($gp) { $bits += "$gp linked GPO(s)" }
    # ⭐ Said out loud, because "why is my policy not applying to the accounts in CN=Users" is a
    # support call that this one field answers. Group Policy links to sites, domains and OUs --
    # never to a container.
    $cls = [string](Get-AdmRawProp $ou 'ObjectClass' '')
    if ($cls -and $cls -ne 'organizationalUnit') {
        $bits += "$cls -- Group Policy CANNOT be linked here"
    }
    if (Get-AdmRawProp $ou 'Protected' $false) { $bits += 'protected from accidental deletion' }
    $ui.TreeSelMeta.Text = ($bits -join '   |   ')

    $kind = Get-TreeKind
    Set-Status "listing $kind directly in $($ou.Name) ..."
    try {
        # ⭐ OneLevel, not Subtree. "What is in this OU" means the objects directly in it -- a
        # subtree listing shows everything underneath and makes a parent OU look like it contains
        # the whole domain, which is exactly the confusion a tree is supposed to remove.
        Reset-AdmSearchTruncated
        $rows = switch ($kind) {
            'groups'    { @(Get-AdmGroup    -Target $target -SearchBase $dn -Scope OneLevel -Limit 50000) |
                            Select-Object SamAccountName, Name, @{n='Members';e={ if (Get-AdmRawProp $_ 'MembersTruncated' $false) { "$(@($_.Members).Count)+" } else { [string]@($_.Members).Count } }}, DistinguishedName }
            'computers' { @(Get-AdmComputer -Target $target -SearchBase $dn -Scope OneLevel -Limit 50000) |
                            Select-Object Name, DnsHostName, OperatingSystem, Enabled, IsDomainController }
            default     { @(Get-AdmUser     -Target $target -SearchBase $dn -Scope OneLevel -Limit 50000) |
                            Select-Object SamAccountName, DisplayName, UserPrincipalName, Enabled, LockedOut }
        }
        $ui.TreeGrid.ItemsSource = @($rows)
        if (Get-AdmSearchTruncated) {
            # Onto TreeSelMeta, which sits above this grid and persists, rather than only into the
            # status bar -- the rows outlive a status line, so the caveat about them has to as well.
            $ui.TreeSelMeta.Text = ($ui.TreeSelMeta.Text + "   |   INCOMPLETE: the first $(@($rows).Count) $kind only, there are more").TrimStart(' ', '|')
            Set-Status "TRUNCATED: the first $(@($rows).Count) $kind in $($ou.Name) only -- there are more." 'error'
        } else {
            Set-Status "$(@($rows).Count) $kind directly in $($ou.Name)" 'good'
        }
    } catch { Show-GuiFailure $_ }
}

function Show-TreePanel {
    param([bool]$Show = $true)
    Show-ContentPane $(if ($Show) { 'tree' } else { 'results' })
    if ($Show -and -not $ui.OuTree.Items.Count) { Build-OuTree }
}

# --- deleted objects ------------------------------------------------------------------------------
#
# ⛔ THE RESTORABILITY IS SHOWN BEFORE THE CLICK, NOT AFTER IT. With the Recycle Bin enabled a
# restore brings the object back whole. Without it, all you can restore is a TOMBSTONE: an object
# with the right name and the right SID and no group memberships at all -- and it looks restored.
# Somebody who cannot tell those apart hands back an account that has quietly lost every
# permission it had, which surfaces days later as scattered access failures.
function Refresh-Bin {
    $target = $ui.TargetBox.Text.Trim()
    if (-not $target) { Set-Status 'Pick a domain on the left first.' 'warn'; return }

    $enabled = $null
    try { $enabled = Test-AdmRecycleBinEnabled -Target $target } catch { }
    $on = [bool](Get-AdmRawProp $enabled 'Enabled' $enabled)
    $ui.BinStateText.Text = if ($on) { 'Recycle Bin ENABLED -- full restore' }
                            else { 'Recycle Bin DISABLED -- tombstone only' }
    $ui.BinStateText.Foreground = $win.FindResource($(if ($on) { 'Success' } else { 'Warn' }))

    Set-Status "reading deleted objects in $target ..."
    # ⛔ CLEARED FIRST. Leaving the previous contents on a failure showed the LAST domain's
    # deleted objects under the new one's name -- and `@($null)` is an array of ONE null, so an
    # unset grid rendered as a single row with every column blank, which read as "one deleted
    # object we cannot describe" rather than "this failed". Same trap as the machine-identity
    # collector.
    $ui.BinGrid.ItemsSource = $null
    $ui.BtnBinRestore.IsEnabled = $false
    try {
        # ⚠ DeletedOn, not Deleted. Binding a grid to a property the object does not have yields
        # a BLANK COLUMN rather than an error, so a wrong name here reads as an empty directory.
        Reset-AdmSearchTruncated
        $rows = @(Get-AdmDeletedObject -Target $target -Limit 20000)
        # ⛔ TRUNCATION MATTERS MORE HERE THAN IN ANY OTHER LIST. Absence from this grid is how
        # somebody concludes an object is unrecoverable and stops looking for it. A short read
        # must never be allowed to say that.
        $binTruncated = [bool](Get-AdmSearchTruncated)
        $ui.BinGrid.ItemsSource = @($rows | Select-Object Name, SamAccountName, ObjectClass,
                                        DeletedOn, Restorable, ParentAvailable, LastKnownParent, DistinguishedName)
        if ($binTruncated) {
            Set-Status "TRUNCATED: more than $($rows.Count) deleted objects. An object missing from this list is NOT proof it is gone." 'error'
            $ui.BinNotes.Text = "This is the first $($rows.Count) deleted objects, not all of them -- the read stopped at its limit. Search for a specific name rather than trusting this list to be complete."
            $ui.BinNotes.Foreground = $win.FindResource('Danger')
        } else {
            Set-Status "$($rows.Count) deleted object(s) in $target" $(if ($rows.Count) { 'warn' } else { 'good' })
        }
        if (-not $rows.Count -and -not $binTruncated) {
            $ui.BinNotes.Text = 'Nothing deleted is still recoverable here. That is either a quiet estate or a window that has already closed: deleted objects are kept only for the deleted-object lifetime, 180 days by default.'
            $ui.BinNotes.Foreground = $win.FindResource('TextMuted')
        }
    } catch {
        # Say what failed IN THE PANEL, not only in a toast. An empty grid with an error elsewhere
        # is indistinguishable from an empty Recycle Bin, and those mean opposite things.
        $ui.BinNotes.Text = "Could not read the deleted objects: $($_.Exception.Message)"
        $ui.BinNotes.Foreground = $win.FindResource('Danger')
        Show-GuiFailure $_
    }
}

function Show-BinSelection {
    $sel = $ui.BinGrid.SelectedItem
    if (-not $sel) { $ui.BtnBinRestore.IsEnabled = $false; return }
    $restorable = [string](Get-AdmRawProp $sel 'Restorable')
    $parent = [string](Get-AdmRawProp $sel 'LastKnownParent')
    # ⛔ NO LAST-KNOWN PARENT MEANS THE PARENT WAS DELETED TOO, and a restore then needs an
    # explicit destination. Disabled rather than allowed-then-failed: the restore would go
    # through the confirmation, touch the directory, and fail for a reason that was knowable
    # before the click.
    $parentOk = [bool](Get-AdmRawProp $sel 'ParentAvailable' $true)
    $ui.BtnBinRestore.IsEnabled = $parentOk

    $bits = @()
    if (-not $parentOk) {
        $bits += 'CANNOT BE RESTORED FROM HERE: the container this object lived in was deleted too, so there is nowhere to put it back. It needs an explicit destination, which the CLI takes as -DestinationPath. Restore the parent first and this becomes possible.'
    }
    if ($restorable -match 'tombstone') {
        $bits += 'TOMBSTONE ONLY. Restoring returns the object with its original name and SID, and WITHOUT its group memberships, most of its attributes, and its password. It will look restored.'
    } else {
        $bits += 'Full restore: attributes and group memberships come back with the object.'
    }
    if ($parent) { $bits += "Goes back to: $parent" }
    else { $bits += 'No last-known parent recorded, so a destination has to be given or the restore will fail.' }
    $bits += 'A restored account comes back DISABLED. That is deliberate; enable it once you have checked it.'
    $ui.BinNotes.Text = ($bits -join '  ')
    $ui.BinNotes.Foreground = $win.FindResource($(if ($restorable -match 'tombstone') { 'Warn' } else { 'TextMuted' }))
}

# --- the shape of the forest ----------------------------------------------------------------------
#
# Four read-only views. Each one carries the FINDING that makes it worth looking at rather than
# just the rows -- a list of sites is unremarkable; a site with no subnets is a fault.
function Refresh-Forest {
    $target = $ui.TargetBox.Text.Trim()
    if (-not $target) { Set-Status 'Pick a domain on the left first.' 'warn'; return }
    $ui.ForestGrid.ItemsSource = $null
    $note = ''

    try {
        if ($ui.ForestTabTrusts.IsChecked) {
            $rows = @(Get-AdmTrust -Target $target)
            $ui.ForestGrid.ItemsSource = @($rows)
            # ⭐ Worth listing even where you believe there are none. Every safety argument this
            # toolkit makes rests on these forests being untrusted, and that is one read to
            # confirm rather than an assumption to carry.
            $note = if (@($rows).Count) {
                "$(@($rows).Count) trust(s). Check direction, transitivity and SID filtering: an inbound transitive trust without SID filtering means the other side can assert any SID, including your Domain Admins."
            } else {
                'No trusts. That is what this toolkit assumes throughout -- every credential is per-forest because nothing can be borrowed across one. Confirmed rather than assumed.'
            }
        }
        elseif ($ui.ForestTabSites.IsChecked) {
            # ⚠ Sites only. The site rows already carry Subnets, SubnetCount and NoSubnets, which
            # is the whole finding here; subnets in their own right are Get-AdmSubnet, and that
            # is a different question -- a subnet with no siteObject belongs to NO site and so
            # appears under none of these rows at all.
            $rows = @(Get-AdmSite -Target $target)
            $ui.ForestGrid.ItemsSource = @($rows)
            # ⚠ THE COMMON FAULT, and invisible unless you look. A client is assigned to a site by
            # matching its IP against subnet objects; an address matching none gets no site and
            # then picks a domain controller more or less at random, which presents as slow logons.
            # ⛔ THREE STATES, NOT TWO. NoSubnets is $null when the subnet read was TRUNCATED --
            # if every subnet could not be seen, it cannot be said that a site has none. Treating
            # null as false would report the fault as absent on exactly the large estates where a
            # truncated read happens, which is backwards. Same shape as the Protection? button.
            # ⛔ AND DO NOT READ THE GLOBAL FLAG AROUND Get-AdmSite. It makes three searches --
            # sites, subnets, servers -- and resets between them because it needs to know WHICH
            # was cut, so the global flag afterwards describes only the last one. The rows carry
            # SubnetsTruncated and ServersTruncated, which are per-read and exact.
            $noSubnet       = @($rows | Where-Object { (Get-AdmRawProp $_ 'NoSubnets') -eq $true })
            $unknownSubnets = @($rows | Where-Object { $null -eq (Get-AdmRawProp $_ 'NoSubnets') })
            # A site with no domain controller is the same class of finding as one with no
            # subnets, and gets the same three states for the same reason: a truncated read must
            # not be allowed to assert that nothing serves a site.
            $noServer       = @($rows | Where-Object { (Get-AdmRawProp $_ 'NoServers') -eq $true })
            $unknownServers = @($rows | Where-Object { $null -eq (Get-AdmRawProp $_ 'NoServers') })
            $serverNote = if ($unknownServers.Count) {
                " $($unknownServers.Count) site(s) could not be checked for domain controllers -- that read was truncated, so UNKNOWN rather than 'none'."
            } elseif ($noServer.Count) {
                " $($noServer.Count) site(s) have NO DOMAIN CONTROLLER: $((@($noServer | ForEach-Object { $_.Name })) -join ', '). Clients assigned there authenticate across a link to somewhere else."
            } else { '' }
            $note = if (-not $rows.Count) {
                'No sites returned. Every forest has at least Default-First-Site-Name, so this is a failed read rather than an empty answer.'
            } elseif ($unknownSubnets.Count) {
                "$($unknownSubnets.Count) site(s) could not be checked for subnets -- the subnet read was truncated, so whether they have any is UNKNOWN, not 'no'. " +
                $(if ($noSubnet.Count) { "$($noSubnet.Count) other site(s) definitely have none." } else { '' }) + $serverNote
            } elseif ($noSubnet.Count) {
                "$($noSubnet.Count) of $($rows.Count) site(s) have NO SUBNETS: $((@($noSubnet | ForEach-Object { $_.Name })) -join ', '). A client whose address matches no subnet is assigned to no site and picks a domain controller at random -- it shows up as slow logons and nothing else." + $serverNote
            } else { "$($rows.Count) site(s), all with subnets." + $serverNote }
        }
        elseif ($ui.ForestTabGpo.IsChecked) {
            $rows = @(Get-AdmGpo -Target $target)
            $ui.ForestGrid.ItemsSource = @($rows)
            $unlinked = @($rows | Where-Object { -not (Get-AdmRawProp $_ 'LinkCount' 0) })
            # ⛔ This is NOT resultant policy. gpresult on the machine is, and implying otherwise
            # would be the more useful-looking lie.
            $note = "$(@($rows).Count) GPO(s), $($unlinked.Count) linked nowhere. An unlinked GPO is indistinguishable from live policy in any list that does not join gPLink back, which is why estates accumulate them and nobody dares delete any. A DISABLED link still counts as a link. " +
                    "This does NOT compute resultant policy -- that is gpresult on the target machine."
        }
        else {
            $rows = @(Get-AdmPasswordSettingsPolicy -Target $target)
            $ui.ForestGrid.ItemsSource = @($rows)
            $unlinked = @($rows | Where-Object { Get-AdmRawProp $_ 'Unlinked' $false })
            # ⭐ The other half of what the detail view shows. That reports the policy that applies
            # to ONE user; this says which policies exist, in what precedence, and which target
            # nobody at all.
            $note = if (@($rows).Count) {
                "$(@($rows).Count) fine-grained policy(ies). Precedence decides which one wins where a user is in scope of several -- LOWER precedence wins. " +
                $(if ($unlinked.Count) { "$($unlinked.Count) apply to NOBODY, which is usually a policy someone believes is in force." } else { '' })
            } else {
                'No fine-grained policies. Every account is therefore under the default domain policy, which is what the account detail view reports.'
            }
        }
        Set-Status "read the forest of $target" 'good'
    } catch {
        $ui.ForestNotes.Text = "Could not read this: $($_.Exception.Message)"
        $ui.ForestNotes.Foreground = $win.FindResource('Danger')
        Show-GuiFailure $_
        return
    }
    $ui.ForestNotes.Text = $note
    $ui.ForestNotes.Foreground = $win.FindResource('TextMuted')
}

# --- bulk import ------------------------------------------------------------------------------------
#
# ⛔ THE PLAN COMES FIRST, ALWAYS. -WhatIf validates the WHOLE file and returns one row per input
# row saying what would happen -- so a bad row at line 400 is found before line 1 is written, and
# a partial import (half the accounts created, no record of where it stopped) cannot occur.
$script:BulkPath = $null
$script:BulkPlan = @()

function Get-BulkMode {
    if ($ui.BulkModeCreate.IsChecked) { 'Create' }
    elseif ($ui.BulkModeUpdate.IsChecked) { 'Update' }
    else { 'CreateOrUpdate' }
}

function Show-BulkPlan {
    $target = $ui.TargetBox.Text.Trim()
    if (-not $target -or -not $script:BulkPath) { return }
    $ui.BulkGrid.ItemsSource = $null
    $ui.BtnBulkApply.IsEnabled = $false
    Set-Status "checking $([System.IO.Path]::GetFileName($script:BulkPath)) ..."
    try {
        # ⚠ NOT -StopOnError. The point of the preview is to show EVERY problem at once; refusing
        # the whole run on the first one gives you a plan you have to fix and re-run to see the
        # rest of. -StopOnError belongs on the apply, where a refusal is the safe outcome.
        $plan = @(Import-AdmUserCsv -Target $target -Path $script:BulkPath -Mode (Get-BulkMode) -WhatIf -Confirm:$false)
        $script:BulkPlan = $plan
        $ui.BulkGrid.ItemsSource = @($plan | Select-Object Row, SamAccountName, Action, Status, ChangeCount, Reason, TargetDn)

        $byAction = @{}
        foreach ($r in $plan) {
            $a = [string](Get-AdmRawProp $r 'Action' 'unknown')
            $byAction[$a] = 1 + [int]$byAction[$a]
        }
        $bad = @($plan | Where-Object { [string](Get-AdmRawProp $_ 'Status') -in @('skipped', 'failed') })
        $unknown = @($plan | ForEach-Object { @(Get-AdmRawProp $_ 'UnknownColumns' @()) } | Where-Object { $_ } | Select-Object -Unique)

        $parts = @(($byAction.Keys | Sort-Object | ForEach-Object { "$_ $($byAction[$_])" }) -join ', ')
        if ($bad.Count)     { $parts += "$($bad.Count) row(s) CANNOT proceed: $((@($bad | ForEach-Object { "row $($_.Row) -- $($_.Reason)" }) | Select-Object -First 3) -join '; ')" }
        if ($unknown.Count) { $parts += "columns the importer does not recognise and will IGNORE: $($unknown -join ', ')" }
        # `no-change` is shown rather than hidden, so the count in the window matches the count in
        # the file. A row whose values already match is not an update that did nothing.
        $parts += 'Nothing has been written. Apply runs the same plan for real.'
        $ui.BulkNotes.Text = ($parts -join '   |   ')
        $ui.BulkNotes.Foreground = $win.FindResource($(if ($bad.Count) { 'Warn' } else { 'TextMuted' }))
        $ui.BtnBulkApply.IsEnabled = [bool]$plan.Count
        Set-Status "$($plan.Count) row(s) planned from $([System.IO.Path]::GetFileName($script:BulkPath))" 'good'
    } catch {
        # ⚠ THE STATE FAILS WITH THE TEXT. Apply is already disabled on entry to Show-BulkPlan and
        # only re-enabled on success, so the button cannot be pressed here -- but $script:BulkPlan
        # was NOT being cleared, leaving the previous plan in a variable the apply handler reads.
        # Nothing reaches it today; it is one careless re-enable away from writing rows from a
        # plan the panel has just said it could not produce. Cleared rather than reasoned about.
        $script:BulkPlan = @()
        $ui.BulkGrid.ItemsSource = $null
        $ui.BtnBulkApply.IsEnabled = $false
        $ui.BulkNotes.Text = "Could not read the plan: $($_.Exception.Message)"
        $ui.BulkNotes.Foreground = $win.FindResource('Danger')
        Show-GuiFailure $_
    }
}

function Show-BulkPanel {
    param([bool]$Show = $true)
    Show-ContentPane $(if ($Show) { 'bulk' } else { 'results' })
}

function Show-ForestPanel {
    param([bool]$Show = $true)
    Show-ContentPane $(if ($Show) { 'forest' } else { 'results' })
    if ($Show) { Refresh-Forest }
}

function Show-BinPanel {
    param([bool]$Show = $true)
    Show-ContentPane $(if ($Show) { 'bin' } else { 'results' })
    if ($Show) { Refresh-Bin }
}

function Show-ScriptPanel {
    param([bool]$Show = $true)
    Show-ContentPane $(if ($Show) { 'scripts' } else { 'results' })
    if ($Show) { Refresh-Scripts; Update-ScriptTargetChip }
}

# ⭐ PICK FROM THE DIRECTORY INSTEAD OF TYPING A NAME.
#
# The generated form asked for a computer or a user as free text, so using it meant already
# knowing the name -- and it read as a second, redundant place to say what you were working on.
# These parameters are all names of objects in the very forest the target already names, so the
# field offers to go and look them up.
$script:PickerKinds = @{
    ComputerName = 'computers'; Only = 'users'; Identity = 'users'
    Group = 'groups'; RemoveFrom = 'users'
}

function Show-AdmObjectPicker {
    param([string]$Kind, [string]$Target)

    $items = @()
    Reset-AdmSearchTruncated
    try {
        $items = switch ($Kind) {
            'computers' { @(Get-AdmComputer -Target $Target -Limit 50000 | ForEach-Object { $_.Name }) }
            'groups'    { @(Get-AdmGroup    -Target $Target -Limit 50000 | ForEach-Object { $_.SamAccountName }) }
            default     { @(Get-AdmUser     -Target $Target -Limit 50000 | ForEach-Object { $_.SamAccountName }) }
        }
    } catch {
        Set-Status "Could not list $Kind in $Target`: $($_.Exception.Message)" 'error'
        return $null
    }
    $pickTruncated = [bool](Get-AdmSearchTruncated)
    $items = @($items | Where-Object { $_ } | Sort-Object)
    if (-not $items.Count) { Set-Status "No $Kind found in $Target." 'warn'; return $null }

    $root = $win.Content; $host_ = $root.Child
    $veil = New-Object Windows.Controls.Grid
    $veil.Background = $win.FindResource('DialogVeil')

    $card = New-Object Windows.Controls.Border
    $card.Style = $win.FindResource('GlassPanel')
    $card.Background = $win.FindResource('DialogFill')
    $card.Width = 460; $card.Padding = '22'
    $card.HorizontalAlignment = 'Center'; $card.VerticalAlignment = 'Center'

    $stack = New-Object Windows.Controls.StackPanel
    $t = New-Object Windows.Controls.TextBlock
    $t.Text = "Choose from $Target"; $t.FontSize = 16; $t.FontWeight = 'SemiBold'
    $t.Foreground = $win.FindResource('TextPrimary')
    [void]$stack.Children.Add($t)

    $sub = New-Object Windows.Controls.TextBlock
    # ⚠ A PICKER THAT SILENTLY OMITS WHAT YOU ARE LOOKING FOR READS AS "no such object", and the
    # person then types the name by hand believing the list was complete. If the read was cut,
    # the subtitle says so instead of quietly presenting a prefix of the directory.
    $sub.Text = if ($pickTruncated) {
        "The first $($items.Count) $Kind ONLY -- the read stopped at its limit. Something missing here may still exist; type the name instead."
    } else { "$($items.Count) $Kind. Tick as many as you need." }
    $sub.FontSize = 11; $sub.Margin = '0,6,0,0'
    $sub.Foreground = $win.FindResource($(if ($pickTruncated) { 'Danger' } else { 'TextFaint' }))
    [void]$stack.Children.Add($sub)

    $filter = New-Object Windows.Controls.TextBox
    $filter.Style = $win.FindResource('GlassInput'); $filter.Margin = '0,14,0,8'
    [void]$stack.Children.Add($filter)

    $list = New-Object Windows.Controls.ListBox
    $list.Height = 260; $list.Background = 'Transparent'; $list.BorderThickness = 0
    $list.SelectionMode = 'Extended'      # several machines is the normal case for a sweep
    $list.ItemsSource = $items
    $list.Foreground = $win.FindResource('TextPrimary')
    [void]$stack.Children.Add($list)

    $filter.Add_TextChanged({
        $q = $filter.Text.Trim()
        $list.ItemsSource = if ($q) { @($items | Where-Object { $_ -like "*$q*" }) } else { $items }
    }.GetNewClosure())

    $row = New-Object Windows.Controls.StackPanel
    $row.Orientation = 'Horizontal'; $row.HorizontalAlignment = 'Right'; $row.Margin = '0,16,0,0'
    $cancel = New-Object Windows.Controls.Button
    $cancel.Style = $win.FindResource('GhostButton'); $cancel.Content = 'Cancel'; $cancel.Margin = '0,0,8,0'
    $ok = New-Object Windows.Controls.Button
    $ok.Style = $win.FindResource('AccentButton'); $ok.Content = 'Use these'
    [void]$row.Children.Add($cancel); [void]$row.Children.Add($ok)
    [void]$stack.Children.Add($row)

    $card.Child = $stack
    [void]$veil.Children.Add($card)
    [void]$host_.Children.Add($veil)
    [Windows.Controls.Grid]::SetRowSpan($veil, 3)

    $frame = New-Object Windows.Threading.DispatcherFrame
    $script:PickerResult = $null
    $ok.Add_Click({ $script:PickerResult = @($list.SelectedItems); $frame.Continue = $false }.GetNewClosure())
    $cancel.Add_Click({ $script:PickerResult = $null; $frame.Continue = $false }.GetNewClosure())
    $list.Add_MouseDoubleClick({ $script:PickerResult = @($list.SelectedItems); $frame.Continue = $false }.GetNewClosure())
    $filter.Focus()
    [Windows.Threading.Dispatcher]::PushFrame($frame)

    [void]$host_.Children.Remove($veil)
    $script:PickerResult
}

# ⛔ SCRIPTS RUN ON A BACKGROUND RUNSPACE, NOT ON THE UI THREAD.
#
# The first version called the script inline and merely pumped the dispatcher once beforehand so
# the "running..." message would paint. That is fine for a lab and wrong for the estate this is
# for: Get-MachineIdentity -FromDirectory contacts every computer in the domain in turn, and each
# machine that is switched off costs a full WinRM timeout. pointing it at a real domain made
# the window locked up -- correctly, from WPF's point of view, because the dispatcher cannot
# repaint while a handler is still running. There was also no way to stop it.
#
# So: a worker runspace, a timer that drains its output into the pane as it arrives, and a Cancel
# button. The window stays live throughout.
#
# ⚠ THE WORKER NEEDS ITS OWN UNLOCK. The decrypted store lives in $script:AdmSession inside the
# module instance, and a new runspace imports a FRESH instance, which is locked. So the GUI keeps
# the unlock passphrase in a SecureString for exactly as long as the store is unlocked, hands it
# to each worker, and clears it the moment the store locks or the window closes. That is not a
# wider exposure than already exists: while unlocked, this process is holding the decrypted data
# key and every credential in memory anyway, for the same window of time.
$script:Runner = $null

function Stop-ScriptRun {
    if (-not $script:Runner) { return }
    $r = $script:Runner
    try { $r.Timer.Stop() } catch { }

    # ⚠ DRAIN BEFORE DISPOSING. Whatever the script had already produced is the most useful thing
    # on the screen after a cancel -- a sweep stopped halfway is still a list of what it found so
    # far. Stopping the timer first and disposing straight away threw that away.
    try {
        foreach ($o in @($r.Out.ReadAll())) {
            $line = ($o | Out-String -Width 200).TrimEnd()
            if ($line -notmatch '^###ADM-EXIT:') { Add-ScriptOutput $line }
        }
        foreach ($w in @($r.PS.Streams.Warning.ReadAll())) { Add-ScriptOutput "WARNING: $($w.Message)" }
        foreach ($e in @($r.PS.Streams.Error.ReadAll()))   { Add-ScriptOutput "ERROR: $($e.Exception.Message)" }
    } catch { }

    # Stop() aborts the running pipeline, and the WSMan CancelTimeout set by the script bounds how
    # long an in-flight remote call takes to let go.
    try { $r.PS.Stop() } catch { }
    try { $r.PS.Dispose() } catch { }
    try { $r.Runspace.Dispose() } catch { }
    $script:Runner = $null

    $ui.BtnScriptRun.Content = 'Run'
    $ui.BtnScriptRun.Style = $win.FindResource('AccentButton')
    $ui.BtnScriptRun.IsEnabled = [bool]$ui.ScriptList.SelectedItem
    # Save applies to whatever is on screen, which is the SELECTED script's buffer -- not
    # necessarily the one that just finished, if the reader clicked away while it ran.
    $ui.BtnScriptSaveOut.IsEnabled = [bool]$script:ScriptOutputs[(Get-SelectedScriptName)]
}

# ⭐ OUTPUT IS KEPT PER SCRIPT, NOT PER PANE. One shared buffer meant clicking down the list
# dragged the last result along with you, so the output under Find-StaleComputers might have come
# from Get-AdPrivilegedAccess. Each script keeps its own, and selecting one shows what THAT script
# last produced.
#
# It is keyed on the script that PRODUCED the line rather than the one currently selected: a run
# started against one script keeps filling its own buffer even after you click away to read
# another, which is the whole point of not blocking the window.
$script:ScriptOutputs = @{}

function Get-SelectedScriptName {
    $sel = $ui.ScriptList.SelectedItem
    if ($sel) { [string]$sel.Name } else { '' }
}

function Set-ScriptOutput {
    param([string]$For, [string]$Text)
    $script:ScriptOutputs[$For] = $Text
    if ((Get-SelectedScriptName) -eq $For) {
        $ui.ScriptOutput.Text = $Text
        try { $ui.ScriptOutputScroll.ScrollToEnd() } catch { }
    }
}

function Add-ScriptOutput {
    param([string]$Text, [string]$For)
    if (-not $Text) { return }
    # Default to whichever script is running; fall back to the selected one for messages raised
    # before a run starts.
    if (-not $For) { $For = if ($script:Runner) { $script:Runner.Name } else { Get-SelectedScriptName } }
    if (-not $For) { return }
    $existing = [string]$script:ScriptOutputs[$For]
    Set-ScriptOutput -For $For -Text (($existing.TrimEnd() + "`r`n" + $Text.TrimEnd()).TrimStart())
}

function Show-ScriptOutputFor {
    param([string]$Name)
    $t = [string]$script:ScriptOutputs[$Name]
    $ui.ScriptOutput.Text = if ($t) { $t } else { 'Nothing run yet.' }
    $ui.BtnScriptSaveOut.IsEnabled = [bool]$t
    try { $ui.ScriptOutputScroll.ScrollToEnd() } catch { }
}

function Invoke-SelectedScript {
    # Second click while a run is in flight means stop.
    if ($script:Runner) {
        Add-ScriptOutput '--- cancelled ---'
        Set-Status "$($script:Runner.Name): cancelled" 'warn'
        Stop-ScriptRun
        return
    }

    $sel = $ui.ScriptList.SelectedItem
    if (-not $sel) { return }

    # A machine script has no -Target, and demanding one would block a script that never wanted it.
    $wantsTarget = (-not $script:ScriptInfo) -or $script:ScriptInfo.HasTarget
    $target = $ui.TargetBox.Text.Trim()
    if ($wantsTarget -and -not $target) {
        Set-ScriptOutput -For $sel.Name -Text "Enter a TARGET first, or pick a domain on the left.`r`n`r`nThis script takes -Target and uses it to work out which forest to act on and which stored credential to use. Without it there is nothing to run against."
        Set-Status 'Enter a target first.' 'warn'
        return
    }

    if ($script:ScriptInfo -and $script:ScriptInfo.NeedsAdmin -and -not (Test-AdmElevated)) {
        Set-ScriptOutput -For $sel.Name -Text ("$($sel.Name) declares '#requires -RunAsAdministrator', and this " +
            "window is not running elevated.`r`n`r`nPowerShell refuses to start the script at all, " +
            "so nothing has happened.`r`n`r`nUse 'Run as administrator' in the title bar to restart " +
            "the window elevated, then try again.")
        Set-Status "$($sel.Name) needs an elevated session" 'warn'
        return
    }
    if (-not $script:SessionPassphrase) {
        Set-ScriptOutput -For $sel.Name -Text "The store has to be unlocked in this window before a script can run.`r`n`r`nLock and unlock again, then retry."
        Set-Status 'No session passphrase -- unlock again.' 'warn'
        return
    }

    $splat = Get-ScriptArguments
    # -WhatIf only where the script declares SupportsShouldProcess. Passing it to a script that
    # does not would be a parameter-binding error, not a safe no-op.
    if ($script:ScriptInfo -and $script:ScriptInfo.SupportsWhatIf -and $ui.ScriptWhatIfOn.IsChecked) {
        $splat['WhatIf'] = $true
    }

    Set-ScriptOutput -For $sel.Name -Text "Running $($sel.Name) against $target ..."
    Set-Status "running $($sel.Name) against $target -- the window stays usable; click Cancel to stop" 'info'
    # Red while running, so the button that was Run is unmistakably a stop.
    $ui.BtnScriptRun.Content = 'Cancel'
    $ui.BtnScriptRun.Style = $win.FindResource('DangerButton')
    $ui.BtnScriptSaveOut.IsEnabled = $false

    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs

    [void]$ps.AddScript({
        param($ModuleRoot, $Passphrase, $Path, $Name, $Kind, $Target, $Splat, $HasTarget)
        # Continue, not Stop: a script that writes a non-terminating error should still finish and
        # report, exactly as it does from the CLI.
        $ErrorActionPreference = 'Continue'
        Import-Module (Join-Path $ModuleRoot 'ADAdmin\ADAdmin.psd1') -Force
        Unlock-AdmStore -Passphrase $Passphrase | Out-Null
        $s = @{}
        foreach ($k in $Splat.Keys) { $s[$k] = $Splat[$k] }
        $global:LASTEXITCODE = 0
        # -Target only where the script declares it; a machine script does not, and passing it
        # fails with "A parameter cannot be found that matches parameter name 'Target'".
        if ($HasTarget) { $s['Target'] = $Target }
        if ($Kind -eq 'shipped') { & $Path -Verbose @s }
        else { Invoke-AdmScript -Name $Name -Target $Target @s }
        # Emitted last and picked out by the collector, so the exit code survives the runspace.
        "###ADM-EXIT:$LASTEXITCODE"
    })
    [void]$ps.AddArgument($ModuleRoot)
    [void]$ps.AddArgument($script:SessionPassphrase)
    [void]$ps.AddArgument($sel.Path)
    [void]$ps.AddArgument($sel.Name)
    [void]$ps.AddArgument($sel.Kind)
    [void]$ps.AddArgument($target)
    [void]$ps.AddArgument($splat)
    [void]$ps.AddArgument($wantsTarget)

    $out = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
    $handle = $ps.BeginInvoke([System.Management.Automation.PSDataCollection[psobject]]::new(), $out)

    # A polling timer rather than the DataAdded events: those fire on the WORKER thread, and
    # touching a WPF control from there throws an invalid-cross-thread exception. The timer runs
    # on the dispatcher, so everything it does is already on the right thread.
    $timer = New-Object Windows.Threading.DispatcherTimer
    $timer.Interval = [timespan]::FromMilliseconds(300)

    $script:Runner = [pscustomobject]@{
        PS = $ps; Runspace = $rs; Handle = $handle; Out = $out; Timer = $timer
        Name = $sel.Name; Code = $null
    }

    $timer.Add_Tick({
        $r = $script:Runner
        if (-not $r) { return }

        # ReadAll drains destructively, so each item is taken exactly once.
        foreach ($o in @($r.Out.ReadAll())) {
            $line = ($o | Out-String -Width 200).TrimEnd()
            if ($line -match '^###ADM-EXIT:(-?\d+)$') { $r.Code = [int]$Matches[1]; continue }
            Add-ScriptOutput $line
        }
        # The caveats that decide whether a result means anything live on the warning stream.
        foreach ($w in @($r.PS.Streams.Warning.ReadAll()))     { Add-ScriptOutput "WARNING: $($w.Message)" }
        foreach ($v in @($r.PS.Streams.Verbose.ReadAll()))     { Add-ScriptOutput "VERBOSE: $($v.Message)" }
        foreach ($e in @($r.PS.Streams.Error.ReadAll()))       { Add-ScriptOutput "ERROR: $($e.Exception.Message)" }
        foreach ($i in @($r.PS.Streams.Information.ReadAll())) { Add-ScriptOutput ([string]$i.MessageData) }

        if (-not $r.Handle.IsCompleted) { return }

        $code = $r.Code
        $name = $r.Name
        try { [void]$r.PS.EndInvoke($r.Handle) } catch { Add-ScriptOutput "ERROR: $($_.Exception.Message)" }
        Stop-ScriptRun

        # The house exit-code contract, spelled out rather than left as a number.
        switch ($code) {
            0       { Set-Status "$name`: nothing found" 'good' }
            10      { Set-Status "$name`: found something -- see the output" 'warn' }
            20      { Set-Status "$name`: a change failed, or the sweep was partial" 'error' }
            30      { Set-Status "$name`: ran, but something could NOT be checked" 'warn' }
            $null   { Set-Status "$name`: finished" 'info' }
            default { Set-Status "$name`: finished (exit $code)" 'info' }
        }
        try { Update-ErrorChip } catch { }
    })
    $timer.Start()
}

# --- object detail ---------------------------------------------------------------------------------
#
# Rendered from code rather than a fixed XAML layout: a user, a group and a computer have
# different interesting fields, and a fixed set of rows would show three blanks for every object.
$script:DetailObject = $null

function New-DetailChip {
    param([string]$Text, [string]$Brush = 'TextMuted')
    $b = New-Object Windows.Controls.Border
    $b.Style = $win.FindResource('Chip'); $b.Margin = '0,0,8,6'
    $t = New-Object Windows.Controls.TextBlock
    $t.Text = $Text; $t.FontSize = 11; $t.Foreground = $win.FindResource($Brush)
    $b.Child = $t
    $b
}

function Add-DetailSection {
    param([string]$Title)
    $t = New-Object Windows.Controls.TextBlock
    $t.Text = $Title.ToUpper(); $t.FontSize = 10.5; $t.FontWeight = 'SemiBold'
    $t.Foreground = $win.FindResource('TextFaint'); $t.Margin = '0,16,0,6'
    [void]$ui.DetailBody.Children.Add($t)
    $line = New-Object Windows.Controls.Border
    $line.Height = 1; $line.Margin = '0,0,0,8'
    $line.Background = $win.FindResource('GlassStroke')
    [void]$ui.DetailBody.Children.Add($line)
}

function Add-DetailRow {
    param([string]$Label, $Value, [string]$Brush = 'TextPrimary', [string]$Note)
    # An empty value is omitted entirely. A screen of "(none)" teaches people to skim past the
    # rows that do have something in them.
    $text = if ($Value -is [array]) { (@($Value) -join ', ') } else { [string]$Value }
    if (-not $text) { return }

    $g = New-Object Windows.Controls.Grid
    $g.Margin = '0,0,0,5'
    $c1 = New-Object Windows.Controls.ColumnDefinition; $c1.Width = '190'
    $c2 = New-Object Windows.Controls.ColumnDefinition
    [void]$g.ColumnDefinitions.Add($c1); [void]$g.ColumnDefinitions.Add($c2)

    $l = New-Object Windows.Controls.TextBlock
    $l.Text = $Label; $l.FontSize = 11.5; $l.Foreground = $win.FindResource('TextFaint')
    $l.VerticalAlignment = 'Top'
    [Windows.Controls.Grid]::SetColumn($l, 0); [void]$g.Children.Add($l)

    $sp = New-Object Windows.Controls.StackPanel
    [Windows.Controls.Grid]::SetColumn($sp, 1)
    $v = New-Object Windows.Controls.TextBlock
    $v.Text = $text; $v.FontSize = 12; $v.TextWrapping = 'Wrap'
    $v.Foreground = $win.FindResource($Brush)
    [void]$sp.Children.Add($v)
    if ($Note) {
        $n = New-Object Windows.Controls.TextBlock
        $n.Text = $Note; $n.FontSize = 10.5; $n.TextWrapping = 'Wrap'; $n.Margin = '0,2,0,0'
        $n.Foreground = $win.FindResource('TextFaint')
        [void]$sp.Children.Add($n)
    }
    [void]$g.Children.Add($sp)
    [void]$ui.DetailBody.Children.Add($g)
}

function Show-ObjectDetail {
    param([string]$Identity)
    $target = $ui.TargetBox.Text.Trim()
    if (-not $target -or -not $Identity) { return }

    Set-Status "reading $Identity ..."
    $d = $null
    try { $d = Get-AdmObjectDetail -Target $target -Identity $Identity }
    catch { Show-GuiFailure $_; return }

    $script:DetailObject = $d
    $ui.DetailBody.Children.Clear()
    $ui.DetailChips.Children.Clear()

    $title = if ($d.DisplayName) { $d.DisplayName } elseif ($d.Name) { $d.Name } else { $d.SamAccountName }
    $ui.DetailTitle.Text = [string]$title
    # ⚠ ASCII ONLY IN A DISPLAYED STRING. These files are UTF-8 WITHOUT a BOM, and Windows
    # PowerShell 5.1 reads a BOM-less script as the system ANSI codepage -- so a middle dot in a
    # string literal reached the window as "A?". It does not matter in comments (they are never
    # rendered), which is why the box-drawing marks elsewhere in this file are harmless.
    $ui.DetailSubtitle.Text = "$($d.ObjectClass)  |  $($d.SamAccountName)  |  $($d.DistinguishedName)"

    # --- chips: the answers you want before reading anything else ---------------------------------
    if ($d.ObjectClass -ne 'group') {
        [void]$ui.DetailChips.Children.Add((New-DetailChip $(if ($d.Enabled) { 'enabled' } else { 'DISABLED' }) `
            $(if ($d.Enabled) { 'Success' } else { 'Danger' })))
        if ($d.LockedOut) { [void]$ui.DetailChips.Children.Add((New-DetailChip 'LOCKED OUT' 'Danger')) }
        if ($d.MustChangePassword) { [void]$ui.DetailChips.Children.Add((New-DetailChip 'must change password' 'Warn')) }
        elseif ($d.PasswordNeverExpires) { [void]$ui.DetailChips.Children.Add((New-DetailChip 'password never expires' 'Warn')) }
        elseif ($null -ne $d.DaysToExpiry) {
            $b = if ($d.DaysToExpiry -lt 0) { 'Danger' } elseif ($d.DaysToExpiry -lt 14) { 'Warn' } else { 'TextMuted' }
            $txt = if ($d.DaysToExpiry -lt 0) { "password EXPIRED $([math]::Abs($d.DaysToExpiry))d ago" }
                   else { "password expires in $($d.DaysToExpiry)d" }
            [void]$ui.DetailChips.Children.Add((New-DetailChip $txt $b))
        }
    }
    if ($d.AdminCount -eq 1) { [void]$ui.DetailChips.Children.Add((New-DetailChip 'adminCount=1' 'Warn')) }
    if (Get-AdmRawProp $d 'IsDomainController' $false) { [void]$ui.DetailChips.Children.Add((New-DetailChip 'DOMAIN CONTROLLER' 'Warn')) }
    if (Get-AdmRawProp $d 'IsMock' $false) { [void]$ui.DetailChips.Children.Add((New-DetailChip 'FIXTURE DATA' 'Warn')) }

    # --- security concerns first, because they are why you would look ------------------------------
    $concerns = @($d.UacConcerns)
    if ($concerns.Count) {
        Add-DetailSection 'Worth knowing'
        foreach ($c in $concerns) { Add-DetailRow $c.Flag $c.Concern 'Warn' }
    }
    if (@($d.ServicePrincipalNames).Count -and $d.ObjectClass -eq 'user') {
        Add-DetailRow 'Kerberoastable' "$(@($d.ServicePrincipalNames).Count) SPN(s) on a user account" 'Warn' `
            'Any authenticated user can request a ticket for this account and crack it offline.'
    }
    if (@($d.AllowedToDelegateTo).Count) { Add-DetailRow 'Delegates to' $d.AllowedToDelegateTo 'Warn' }
    if (@($d.SidHistory).Count) { Add-DetailRow 'SID history' $d.SidHistory 'Warn' }

    Add-DetailSection 'Account'
    Add-DetailRow 'Name' $d.Name
    Add-DetailRow 'Display name' $d.DisplayName
    Add-DetailRow 'User principal name' $d.UserPrincipalName
    Add-DetailRow 'Description' $d.Description
    Add-DetailRow 'SID' $d.Sid
    Add-DetailRow 'Created' $d.WhenCreated
    Add-DetailRow 'Last changed' $d.WhenChanged
    Add-DetailRow 'userAccountControl' "$($d.UacValue)  ($(@($d.UacFlags) -join ', '))"

    if ($d.ObjectClass -eq 'group') {
        Add-DetailSection 'Group'
        Add-DetailRow 'Scope' "$($d.GroupScope) $($d.GroupKind)"

        # ⭐ ENUMERATED BY SEARCH, NOT BY READING `member`. A directory returns at most ~1500
        # values of a multi-valued attribute and NOTHING past that, so reading the attribute
        # reports a large group as empty. This also finds PRIMARY-GROUP members, who are members
        # by primaryGroupID and appear in no member list anywhere -- which is why Domain Users
        # looks empty, and how a privileged group hides an account.
        try {
            # ⚠ 2000 was a lab number. Production groups are far larger -- Domain Users is every
            # account in the domain -- and a truncated membership makes the direct/nested/primary
            # counts below wrong rather than merely short.
            $memberLimit = 100000
            Reset-AdmSearchTruncated
            $members = @(Get-AdmGroupMember -Target $target -Identity $d.SamAccountName -Recursive -IncludeGroups -Limit $memberLimit)
            if (Get-AdmSearchTruncated) {
                Add-DetailRow 'Membership' "TRUNCATED at $memberLimit" 'Danger' `
                    'The read stopped at its limit, so every count below is a floor rather than a total.'
            }
            if ($members.Count) {
                $direct  = @($members | Where-Object { (Get-AdmRawProp $_ 'Via') -eq 'direct' })
                $primary = @($members | Where-Object { (Get-AdmRawProp $_ 'Via') -eq 'primary-group' })
                $nested  = @($members | Where-Object { (Get-AdmRawProp $_ 'Via') -notin @('direct', 'primary-group') })
                $foreign = @($members | Where-Object { Get-AdmRawProp $_ 'Foreign' $false })

                function Show-Names {
                    param($Rows)
                    # ⚠ A FOREIGN row has SamAccountName, DisplayName and Enabled all $null by
                    # design -- another domain, no trust to bind over -- so the DN is all there is.
                    @($Rows | ForEach-Object {
                        $n = Get-AdmRawProp $_ 'SamAccountName'
                        if ($n) { [string]$n } else { [string](Get-AdmRawProp $_ 'DistinguishedName') }
                    })
                }
                Add-DetailRow 'Direct members' "$($direct.Count)" 'TextPrimary' ((Show-Names $direct) -join ', ')
                if ($nested.Count) {
                    Add-DetailRow 'Via nesting' "$($nested.Count)" 'TextPrimary' ((Show-Names $nested) -join ', ')
                }
                if ($primary.Count) {
                    # Called out on its own line rather than folded in: these accounts are members
                    # with the same rights and appear in NO member list, so anyone checking the
                    # Members tab in another tool will not see them and will read this as a bug.
                    Add-DetailRow 'PRIMARY-GROUP members' ((Show-Names $primary) -join ', ') 'Warn' `
                        'Members by primaryGroupID. They are NOT in the group''s member attribute, so no Members tab anywhere shows them.'
                }
                if ($foreign.Count) {
                    Add-DetailRow 'From another domain' "$($foreign.Count)" 'Warn' `
                        'Foreign security principals. There is no trust to resolve them over, so only the distinguished name is available.'
                }
            }
        } catch {
            Add-DetailRow 'Members' 'could not be enumerated' 'Warn' $_.Exception.Message
        }
        $mc = Get-AdmRawProp $d 'MemberCount'
        Add-DetailRow 'Members' $(if ($null -ne $mc) { "$mc" } else { 'could not be counted' }) `
            $(if ($null -eq $mc) { 'Warn' } else { 'TextPrimary' }) `
            ([string](Get-AdmRawProp $d 'MemberCountNote'))
    }
    if ($d.ObjectClass -eq 'computer') {
        Add-DetailSection 'Machine'
        Add-DetailRow 'DNS host name' $d.DnsHostName
        Add-DetailRow 'Operating system' "$($d.OperatingSystem) $($d.OperatingSystemVersion)"
    }

    if ($d.ObjectClass -ne 'group') {
        Add-DetailSection 'Password and sign-in'
        Add-DetailRow 'Password last set' $d.PasswordLastSet
        Add-DetailRow 'Policy in force' $d.PasswordPolicy 'TextPrimary' `
            $(if ($d.PasswordPolicyDetail) {
                "max age $($d.PasswordPolicyDetail.MaxPasswordAgeDays)d, min length $($d.PasswordPolicyDetail.MinPasswordLength), lockout after $($d.PasswordPolicyDetail.LockoutThreshold)"
              } else { 'The domain default. A fine-grained policy would be named here instead.' })
        Add-DetailRow 'Password expires' $d.PasswordExpiresOn
        Add-DetailRow 'Last logon' $d.LastLogonTimestamp 'TextPrimary' `
            'From lastLogonTimestamp, which replicates lazily -- it can be up to ~14 days older than the truth.'
        Add-DetailRow 'Account expires' $d.AccountExpires
        Add-DetailRow 'Bad password count' $d.BadPasswordCount 'TextPrimary' `
            'One domain controller''s count. badPwdCount is not replicated, so the real total needs every DC.'
        Add-DetailRow 'Last bad password' $d.BadPasswordTime
        Add-DetailRow 'Locked out since' $d.LockedOutSince
    }

    # --- groups ------------------------------------------------------------------------------------
    $direct = @($d.MemberOfDirect | ForEach-Object { (($_ -split ',')[0] -replace '^CN=', '') })
    $eff = @($d.MemberOfEffective)
    if ($eff.Count -or $direct.Count) {
        Add-DetailSection 'Group membership'
        if ($eff.Count) {
            # ⭐ The nesting-only groups are called out separately. That set is the one nobody
            # decided on -- somebody was added to an ordinary group that turns out to be inside a
            # privileged one, and no Members tab anywhere shows it.
            $viaNesting = @($eff | Where-Object { $direct -notcontains $_ })
            Add-DetailRow 'Effective' "$($eff.Count) group(s)" 'TextPrimary' ($eff -join ', ')
            if ($viaNesting.Count) {
                Add-DetailRow 'Only via nesting' ($viaNesting -join ', ') 'Warn' `
                    'Reached through another group. These do not appear in this object''s memberOf, and it is not listed in those groups'' Members tab either.'
            }
        } else {
            Add-DetailRow 'Direct' ($direct -join ', ')
        }
        if ($d.EffectiveNote) { Add-DetailRow 'Nesting' $d.EffectiveNote 'Warn' }
        Add-DetailRow 'Primary group RID' $d.PrimaryGroupId 'TextPrimary' `
            $(if ("$($d.PrimaryGroupId)" -and "$($d.PrimaryGroupId)" -ne '513' -and "$($d.PrimaryGroupId)" -ne '515' -and "$($d.PrimaryGroupId)" -ne '516') {
                'NOT the usual Domain Users/Computers/Controllers. A primary group membership is real and appears in NO member list.'
              })
    }

    # ⚠ The @() must wrap the WHOLE pipeline. `@(a,b,c) | Where-Object` yields a SCALAR when
    # exactly one value survives, and .Count on a scalar throws under Set-StrictMode 2.0 --
    # documented in docs\powershell-51-traps.md and hit again right here.
    $contact = @(@($d.Title, $d.Department, $d.Company, $d.Office, $d.Mail, $d.Telephone, $d.Mobile) |
                 Where-Object { $_ })
    if ($contact.Count) {
        Add-DetailSection 'Directory'
        Add-DetailRow 'Title' $d.Title
        Add-DetailRow 'Department' $d.Department
        Add-DetailRow 'Company' $d.Company
        Add-DetailRow 'Office' $d.Office
        Add-DetailRow 'Mail' $d.Mail
        Add-DetailRow 'Telephone' $d.Telephone
        Add-DetailRow 'Mobile' $d.Mobile
        Add-DetailRow 'Manager' $d.Manager
    }

    # Actions apply to user accounts; a group has nothing to unlock or disable.
    $isUser = ($d.ObjectClass -eq 'user')
    $ui.BtnDetailUnlock.IsEnabled = $isUser -and $d.LockedOut
    $ui.BtnDetailReset.IsEnabled  = $isUser
    $ui.BtnDetailToggle.IsEnabled = ($d.ObjectClass -ne 'group')
    # Set-AdmUser edits user attributes only; a group or computer has a different surface.
    $ui.BtnDetailEdit.IsEnabled = $isUser
    # LAPS and BitLocker are properties of a MACHINE.
    $ui.BtnDetailSecrets.IsEnabled = ($d.ObjectClass -eq 'computer')
    $ui.BtnDetailMembers.IsEnabled = ($d.ObjectClass -eq 'group')
    $ui.BtnDetailToggle.Content   = if ($d.Enabled) { 'Disable' } else { 'Enable' }

    $ui.DetailOverlay.Visibility = 'Visible'
    Set-Status "$($d.ObjectClass) $($d.SamAccountName)" 'good'
}

# --- editing an account -------------------------------------------------------------------------
#
# ⭐ THE FORM IS GENERATED FROM Set-AdmUser's OWN PARAMETER BLOCK, the same way the scripts panel
# is generated from each script's. A parameter added to the cmdlet appears here with no change to
# this window, and one that is removed stops being offered -- which is the only way a hand-written
# form and a cmdlet stay in agreement over time.
#
# The value shown in each box is the CURRENT one, read from the object; only boxes whose value
# actually changed are sent. That matters because Set-AdmUser treats an empty string as CLEAR, so
# sending every field on every save would wipe each attribute the user did not happen to fill in.
$script:EditControls = @{}
$script:LastSecret = $null
$script:TextPromptResult = $null
$script:EditOriginal = @{}

# Which detail property supplies the current value for each Set-AdmUser parameter. Only the ones
# that differ in name need listing; the rest match.
$script:EditFieldMap = @{
    EmailAddress = 'Mail'; OfficePhone = 'Telephone'; MobilePhone = 'Mobile'
    Notes = 'Description'
}

function Get-EditableFields {
    $cmd = Get-Command Set-AdmUser -ErrorAction SilentlyContinue
    if (-not $cmd) { return @() }
    # -Attribute/-Clear are the escape hatch for anything not named, and belong in the CLI rather
    # than a form; the rest are plumbing.
    $skip = @('Target', 'Identity', 'Tier', 'UseDnsLookup', 'Attribute', 'Clear',
              'Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction',
              'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable',
              'OutBuffer', 'PipelineVariable', 'WhatIf', 'Confirm', 'ProgressAction')
    @($cmd.Parameters.Keys | Where-Object { $skip -notcontains $_ } | Sort-Object)
}

function Show-EditPanel {
    $d = $script:DetailObject
    if (-not $d -or $d.ObjectClass -ne 'user') { return }

    # ⛔ RE-READ BEFORE SEEDING THE FORM, rather than trusting the object the detail panel is
    # holding. The whole change detection rests on "original" being what is in the directory NOW:
    # if it is stale, a field somebody else set in the meantime reads as unchanged and is left
    # alone -- or worse, the box shows the old value, gets saved back, and silently reverts their
    # edit. Cheap insurance for one extra read on a deliberate click.
    try {
        $fresh = Get-AdmObjectDetail -Target $ui.TargetBox.Text.Trim() -Identity $d.SamAccountName
        if ($fresh) { $d = $fresh; $script:DetailObject = $fresh }
    } catch {
        Set-Status "Could not re-read $($d.SamAccountName); editing against what is on screen." 'warn'
    }

    $ui.EditBody.Children.Clear()
    $script:EditControls = @{}
    $script:EditOriginal = @{}
    $ui.EditError.Visibility = 'Collapsed'
    $ui.EditTitle.Text = "Edit $($d.SamAccountName)"
    $ui.EditChangeCount.Text = ''

    foreach ($p in (Get-EditableFields)) {
        $type = [string](Get-Command Set-AdmUser).Parameters[$p].ParameterType.Name
        $srcName = if ($script:EditFieldMap.ContainsKey($p)) { $script:EditFieldMap[$p] } else { $p }
        $current = [string](Get-AdmRawProp $d $srcName '')

        $row = New-Object Windows.Controls.StackPanel
        $row.Margin = '0,0,0,10'
        [void]$row.Children.Add((New-ParamLabel -Text $p -Mandatory $false))

        if ($type -eq 'SwitchParameter') {
            # A switch here is a state, not an action: show what it IS and let it be changed.
            $sp = New-Object Windows.Controls.StackPanel
            $sp.Orientation = 'Horizontal'
            $on  = New-Object Windows.Controls.RadioButton
            $off = New-Object Windows.Controls.RadioButton
            $on.Style  = $win.FindResource('TabPill'); $on.Content  = 'On';  $on.GroupName  = "ed_$p"
            $off.Style = $win.FindResource('TabPill'); $off.Content = 'Off'; $off.GroupName = "ed_$p"
            # Seeded from the account's current state where the detail view knows it.
            $isOn = switch ($p) {
                'PasswordNeverExpires' { [bool]$d.PasswordNeverExpires }
                'SmartcardLogonRequired' { @($d.UacFlags) -contains 'SMARTCARD_REQUIRED' }
                default { $false }
            }
            if ($isOn) { $on.IsChecked = $true } else { $off.IsChecked = $true }
            [void]$sp.Children.Add($on); [void]$sp.Children.Add($off)
            [void]$row.Children.Add($sp)
            $script:EditControls[$p] = [pscustomobject]@{ Kind = 'switch'; On = $on }
            $script:EditOriginal[$p] = [bool]$isOn
        } else {
            $tb = New-Object Windows.Controls.TextBox
            $tb.Style = $win.FindResource('GlassInput')
            $tb.Text = $current
            [void]$row.Children.Add($tb)
            $script:EditControls[$p] = [pscustomobject]@{ Kind = 'text'; Box = $tb }
            $script:EditOriginal[$p] = $current
        }
        [void]$ui.EditBody.Children.Add($row)
    }

    $ui.EditOverlay.Visibility = 'Visible'
}

function Get-EditChanges {
    $splat = @{}
    foreach ($name in $script:EditControls.Keys) {
        $c = $script:EditControls[$name]
        $orig = $script:EditOriginal[$name]
        if ($c.Kind -eq 'switch') {
            $now = [bool]$c.On.IsChecked
            if ($now -ne [bool]$orig) { $splat[$name] = $now }
        } else {
            $now = $c.Box.Text
            # ⚠ Compared with -cne. -ne is case-INSENSITIVE in PowerShell, so changing a display
            # name from "jo smith" to "Jo Smith" would be seen as no change at all.
            if ($now -cne [string]$orig) { $splat[$name] = $now }
        }
    }
    $splat
}

function Hide-EditPanel {
    $ui.EditOverlay.Visibility = 'Collapsed'
    $script:EditControls = @{}
    $script:EditOriginal = @{}
}

function Hide-ObjectDetail {
    $ui.DetailOverlay.Visibility = 'Collapsed'
    $script:DetailObject = $null
}

function Get-SelectedSam {
    $sel = $ui.ResultGrid.SelectedItem
    if (-not $sel) { throw 'Nothing selected.' }
    $sel.SamAccountName
}

# --- events -----------------------------------------------------------------------------------------

# --- maximise -----------------------------------------------------------------------------------
#
# ⚠ A WindowStyle=None window with AllowsTransparency does NOT respect the taskbar when maximised
# -- it fills the whole monitor and covers it. The fix is to cap MaxWidth/MaxHeight to the working
# area of the screen the window is actually on before maximising, and to lift the cap again on
# restore or the window can never be dragged larger afterwards.
function Set-MaxBounds {
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $h = (New-Object System.Windows.Interop.WindowInteropHelper($win)).Handle
        # FromHandle, not PrimaryScreen: maximising onto the monitor the window is on is the
        # whole point, and a two-monitor desk is the normal case here.
        $wa = [System.Windows.Forms.Screen]::FromHandle($h).WorkingArea

        # WorkingArea is in DEVICE pixels; WPF sizes are in DIPs. On a 150% display those differ
        # by half again, so skipping this conversion overshoots the screen on exactly the laptops
        # this runs on.
        $sx = 1.0; $sy = 1.0
        $src = [System.Windows.PresentationSource]::FromVisual($win)
        if ($src -and $src.CompositionTarget) {
            $sx = $src.CompositionTarget.TransformFromDevice.M11
            $sy = $src.CompositionTarget.TransformFromDevice.M22
        }
        $win.MaxWidth  = $wa.Width  * $sx
        $win.MaxHeight = $wa.Height * $sy
    } catch {
        # Better a maximise that covers the taskbar than one that throws and closes the window.
        Write-Verbose "Could not compute the working area: $($_.Exception.Message)"
    }
}

function Set-MaximizeState {
    param([bool]$Maximized)
    if ($Maximized) {
        Set-MaxBounds
        $win.WindowState = 'Maximized'
        $ui.RootBorder.CornerRadius = New-Object Windows.CornerRadius(0)
    } else {
        $win.WindowState = 'Normal'
        # Lift the cap, or the window stays stuck at the old screen's size.
        $win.MaxWidth  = [double]::PositiveInfinity
        $win.MaxHeight = [double]::PositiveInfinity
        $ui.RootBorder.CornerRadius = New-Object Windows.CornerRadius(14)
    }
    # [char] rather than a `u escape: `u{25A1} is PowerShell 6+ and is a parse error on 5.1.
    $ui.BtnMaximize.Content = if ($Maximized) { [string][char]0x2750 } else { [string][char]0x25A1 }
    $ui.BtnMaximize.ToolTip = if ($Maximized) { 'Restore' } else { 'Maximise' }
}

function Switch-MaximizeState { Set-MaximizeState (-not ($win.WindowState -eq 'Maximized')) }

$ui.BtnMaximize.Add_Click({ Switch-MaximizeState })

$ui.BtnElevate.Add_Click({
    $ok = Show-AdmPrompt -Title 'Restart as administrator?' -OkText 'Restart elevated' `
        -Message ("A second window opens elevated and this one closes. Two of the scripts change " +
                  "the machine itself and PowerShell will not start them otherwise.`n`n" +
                  "The store is unlocked again in the new window, and it is pointed at the same " +
                  "store file explicitly -- if the prompt asks for a different account, its own " +
                  "profile would otherwise have no store in it.")
    if (-not $ok) { return }
    try {
        Start-AdmElevated
        $win.Close()
    } catch {
        # Cancelling the UAC prompt throws; that is a decision, not a fault.
        Set-Status "Not elevated: $($_.Exception.Message)" 'warn'
    }
})

$ui.TitleBar.Add_MouseLeftButtonDown({
    if ($_.ButtonState -ne 'Pressed') { return }
    # Double-click to maximise is what every other window does, and people try it before they
    # look for the button.
    if ($_.ClickCount -eq 2) { Switch-MaximizeState; return }
    # DragMove throws if the window is maximised; restore first so the drag pulls it loose, the
    # way a normal title bar behaves.
    if ($win.WindowState -eq 'Maximized') { Set-MaximizeState $false }
    $win.DragMove()
})
$ui.BtnMinimize.Add_Click({ $win.WindowState = 'Minimized' })
$ui.BtnClose.Add_Click({ $win.Close() })

# The lock screen is either unlocking an existing store or creating a new one. Same card, because
# it is the same moment -- and until now a first-time user was told to go and run a CLI command,
# which for a GUI-first toolkit means the very first step cannot be done in the GUI.
function Set-LockMode {
    param([ValidateSet('unlock', 'create')][string]$Mode, [bool]$Forced = $false)
    $script:LockMode = $Mode
    $creating = $Mode -eq 'create'

    $ui.LockTitle.Text        = if ($creating) { 'Create a credential store' } else { 'Unlock the credential store' }
    $ui.CreateFields.Visibility  = if ($creating) { 'Visible' } else { 'Collapsed' }
    $ui.ConfirmFields.Visibility = if ($creating) { 'Visible' } else { 'Collapsed' }
    $ui.PassLabel.Text        = if ($creating) { 'CHOOSE A PASSPHRASE' } else { 'PASSPHRASE' }
    $ui.BtnUnlockStore.Content = if ($creating) { 'Create store' } else { 'Unlock' }
    $ui.BtnUnlockStore.IsEnabled = $true

    # With no store on disk there is nothing to go back to, so the toggle is hidden rather than
    # offering a mode that cannot work.
    $ui.BtnLockMode.Visibility = if ($Forced) { 'Collapsed' } else { 'Visible' }
    $ui.BtnLockMode.Content = if ($creating) { 'Back to unlocking' } else { 'Create a new store' }

    $ui.LockHint.Text = if ($creating) {
        'A random data key encrypts the registry once and is wrapped with your passphrase; other admins are added afterwards, each with their own. THERE IS NO RECOVERY -- lose the passphrase and the file cannot be opened by anyone.'
    } else {
        'Each admin has their own passphrase. Yours is tried against every wrap in the file.'
    }

    $ui.LockError.Visibility = 'Collapsed'
    $ui.PassBox.Clear(); $ui.PassBox2.Clear()
    if ($creating) { $ui.NewAdminName.Focus() } else { $ui.PassBox.Focus() }
}

# ⚠ Compared by decrypting both into managed strings, briefly, inside this function. There is no
# constant-time need here -- both values were just typed by the same person at the same keyboard,
# so there is no secret to leak to an attacker who can already see the screen. What there IS is a
# store that cannot be opened by anyone if the two differ by one character, because the passphrase
# is the only path to the data key and nothing recovers it. The plaintext is dropped immediately
# and never leaves this scope.
function Test-SecureStringsMatch {
    param([System.Security.SecureString]$A, [System.Security.SecureString]$B)
    if ($null -eq $A -or $null -eq $B) { return $false }
    if ($A.Length -ne $B.Length) { return $false }
    $pa = [IntPtr]::Zero; $pb = [IntPtr]::Zero
    try {
        $pa = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($A)
        $pb = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($B)
        # -ceq: case matters in a passphrase, and -eq in PowerShell does NOT.
        [Runtime.InteropServices.Marshal]::PtrToStringUni($pa) -ceq [Runtime.InteropServices.Marshal]::PtrToStringUni($pb)
    }
    finally {
        # ZeroFreeGlobalAllocUnicode, not FreeHGlobal: it wipes the buffer before releasing it.
        if ($pa -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($pa) }
        if ($pb -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($pb) }
    }
}

function Show-LockError {
    param([string]$Text)
    $ui.LockError.Text = $Text
    $ui.LockError.Visibility = 'Visible'
}

function Enter-UnlockedState {
    param([string]$Message, [System.Security.SecureString]$Passphrase)
    # Held ONLY while the store is unlocked, and only so a worker runspace can unlock its own
    # module instance -- see the comment on the script runner. Copy(), because the PasswordBox's
    # SecureString is disposed when the box is cleared on the next line.
    if ($Passphrase) { $script:SessionPassphrase = $Passphrase.Copy() }
    $ui.PassBox.Clear(); $ui.PassBox2.Clear()
    $ui.LockOverlay.Visibility = 'Collapsed'
    $ui.MainContent.Visibility = 'Visible'
    Update-Chips; Refresh-Domains; Update-ErrorChip
    Set-Status $Message 'good'
}

$ui.BtnLockMode.Add_Click({
    Set-LockMode $(if ($script:LockMode -eq 'create') { 'unlock' } else { 'create' })
})

$ui.BtnUnlockStore.Add_Click({
    $ui.LockError.Visibility = 'Collapsed'

    if ($script:LockMode -eq 'create') {
        try {
            $name = $ui.NewAdminName.Text.Trim()
            if (-not $name) { throw 'Enter a name for this admin -- the store files your passphrase under it.' }
            $sp  = $ui.PassBox.SecurePassword
            $sp2 = $ui.PassBox2.SecurePassword
            if ($sp.Length -eq 0) { throw 'Choose a passphrase.' }
            if (-not (Test-SecureStringsMatch $sp $sp2)) { throw 'The two passphrases do not match.' }

            $info = Get-AdmStoreInfo
            if ($info.Exists) {
                # ⛔ Replacing a store destroys every credential in it and cannot be undone. The
                # confirmation names the path, because the default location is easy to forget.
                $ok = Show-AdmPrompt -Title 'Replace the existing store?' -OkText 'Replace' `
                    -Message ("A store already exists at $($info.Path). Creating a new one DESTROYS every " +
                              "credential in it, for every admin, and cannot be undone.")
                if (-not $ok) { return }
            }

            $r = Initialize-AdmStore -RecipientName $name -Passphrase $sp -Force:([bool]$info.Exists) -Confirm:$false
            Unlock-AdmStore -Passphrase $sp | Out-Null
            Enter-UnlockedState "created the store and unlocked it as $name -- add a domain to begin" -Passphrase $sp
        } catch {
            Show-LockError $_.Exception.Message
            $ui.PassBox.Clear(); $ui.PassBox2.Clear(); $ui.PassBox.Focus()
        }
        return
    }

    try {
        $sp = $ui.PassBox.SecurePassword
        if ($sp.Length -eq 0) { throw 'Enter your passphrase.' }
        $r = Unlock-AdmStore -Passphrase $sp
        Enter-UnlockedState "unlocked as $($r.UnlockedAs) -- auto-lock in $($r.AutoLockMinutes) min" -Passphrase $sp
    } catch {
        Show-LockError $_.Exception.Message
        $ui.PassBox.Clear(); $ui.PassBox.Focus()
    }
})

# Enter submits from any field on the card.
foreach ($box in @($ui.PassBox, $ui.PassBox2, $ui.NewAdminName)) {
    $box.Add_KeyDown({ if ($_.Key -eq 'Return') { $ui.BtnUnlockStore.RaiseEvent(
        (New-Object Windows.RoutedEventArgs([Windows.Controls.Primitives.ButtonBase]::ClickEvent))) } })
}
$ui.PassBox.Add_KeyDown({ if ($_.Key -eq 'Return') { $ui.BtnUnlockStore.RaiseEvent(
    (New-Object Windows.RoutedEventArgs([Windows.Controls.Primitives.ButtonBase]::ClickEvent))) } })

$ui.BtnLock.Add_Click({
    # A running script holds an unlocked store in its own runspace; locking has to end it, or
    # "locked" would be true of this window and false of the work it still has in flight.
    if ($script:Runner) { Stop-ScriptRun }
    Clear-SessionPassphrase
    Lock-AdmStore | Out-Null
    # Close the editor too, and with it the password it may be holding. Leaving it open behind
    # the lock overlay would have a half-typed credential waiting when the store reopens.
    Hide-DomainEditor
    $ui.MainContent.Visibility = 'Collapsed'
    $ui.LockOverlay.Visibility = 'Visible'
    $ui.ResultGrid.ItemsSource = $null
    $ui.ResultTruncText.Visibility = 'Collapsed'   # the rows are gone; the caveat about them must go too
    Update-Chips
    $ui.PassBox.Focus()
})

$ui.DomainList.Add_SelectionChanged({
    $sel = $ui.DomainList.SelectedItem
    $ui.BtnEditDomain.IsEnabled = [bool]$sel
    if (-not $sel) { return }
    $script:CurrentDomain = $sel.Raw
    $ui.TargetBox.Text = $sel.DnsDomain
    Update-Resolution
})

# --- domain editor ---------------------------------------------------------------------------------

$ui.BtnAddDomain.Add_Click({ Show-DomainEditor -Domain $null })

$ui.BtnEditDomain.Add_Click({
    $sel = $ui.DomainList.SelectedItem
    if (-not $sel) { Set-Status 'Select a domain first.' 'warn'; return }
    Show-DomainEditor -Domain $sel.Raw
})

# Double-clicking the row people already click to select is the obvious way in.
$ui.DomainList.Add_MouseDoubleClick({
    $sel = $ui.DomainList.SelectedItem
    if ($sel) { Show-DomainEditor -Domain $sel.Raw }
})

# --- scripts ---------------------------------------------------------------------------------------

$ui.BtnLogClear.Add_Click({
    $sel = $ui.LogList.SelectedItem
    if (-not $sel) { return }
    # No [string] cast: on PowerShell 7 this is a [DateTime], and stringifying it here would throw
    # away the precision that identifies the entry.
    $id = Get-AdmRawProp $sel.Entry 'ts'
    if (-not $id) { Set-Status 'That row has no timestamp to key on.' 'warn'; return }
    Set-AdmLogReviewed -Id $id -Confirm:$false | Out-Null
    Refresh-Log; Update-ErrorChip
    Set-Status 'Marked reviewed. It is still in the file, under Everything.' 'good'
})

$ui.BtnLogClearAll.Add_Click({
    $ok = Show-AdmPrompt -Title 'Clear every problem?' -OkText 'Clear all' `
        -Message ("Marks every error and warning as reviewed, so the Problems list empties and the " +
                  "counter resets.`n`nNothing is deleted -- they stay in the log and under " +
                  "Everything, and the 7-day cleanup removes them on its own schedule.")
    if (-not $ok) { return }
    $r = Set-AdmLogReviewed -All -Confirm:$false
    Refresh-Log; Update-ErrorChip
    Set-Status "Marked $($r.Reviewed) entr(y/ies) reviewed." 'good'
})

# --- OU and object lifecycle, from the tree that shows them ----------------------------------------
#
# ⛔ EVERY DESTRUCTIVE ACTION HERE NAMES WHAT IS LOST, NOT WHAT IS DONE. Deleting an OU takes its
# whole subtree with it and the directory asks nothing first; a rename is not an account rename; a
# move changes which Group Policy applies. Each of those is a surprise the confirmation exists to
# remove.
function Get-TreeSelectedOu {
    $sel = $ui.OuTree.SelectedItem
    if ($sel -and $sel.Tag) { $sel.Tag } else { $null }
}

function Update-TreeButtons {
    $ou = Get-TreeSelectedOu
    $isOu = $ou -and ([string](Get-AdmRawProp $ou 'ObjectClass' 'organizationalUnit') -eq 'organizationalUnit')

    # ⛔ PROTECTION IS FETCHED LAZILY, FOR THE SELECTED OU ONLY. Get-AdmOrganizationalUnit returns
    # Protected = $null unless -IncludeProtection, which costs one extra BIND PER OU -- unacceptable
    # on a domain with hundreds when building the tree. But a null read as $false is worse than
    # slow: the button offers "Protect" on an OU that is already protected, and a delete goes
    # without -RemoveProtection and fails with "Access is denied", which reads as a permissions
    # problem and is not one. So it is read once, on selection, and cached on the node.
    if ($isOu -and $null -eq (Get-AdmRawProp $ou 'Protected')) {
        try {
            # ⚠ QUERIED BY NAME AND FILTERED BY DN, not queried by DN. Get-AdmOrganizationalUnit
            # -Identity does NOT accept a distinguished name -- measured on a lab domain controller, a DN returns
            # ZERO rows while the short name returns the OU. Passing the DN therefore left
            # Protected null forever and the button stuck on "Protection?". Name alone is
            # ambiguous (two OUs may share one under different parents), so the DN filter is what
            # makes this exact.
            $full = @(Get-AdmOrganizationalUnit -Target $ui.TargetBox.Text.Trim() `
                        -Identity ([string]$ou.Name) -IncludeProtection -Limit 100 |
                      Where-Object { [string]$_.DistinguishedName -eq [string]$ou.DistinguishedName })[0]
            if ($full) {
                $p = Get-AdmRawProp $full 'Protected'
                if ($ou.PSObject.Properties['Protected']) { $ou.Protected = $p }
                else { $ou | Add-Member -NotePropertyName 'Protected' -NotePropertyValue $p -Force }
                $sel = $ui.OuTree.SelectedItem
                if ($sel -and $p -and $sel.Header -notmatch 'protected') { $sel.Header = "$($sel.Header)   [protected]" }
            }
        } catch {
            # Unknown, not unprotected. Leaving it null means this runs again next time rather
            # than caching a guess.
            Write-Verbose "Could not read protection on $($ou.Name): $($_.Exception.Message)"
        }
    }
    # A container is not an OU: you cannot create an OU inside CN=Users, rename it or delete it.
    # Offering the buttons and failing afterwards would be worse than not offering them.
    $ui.BtnOuNew.IsEnabled     = [bool]$ou       # a new OU can go under the domain root too
    $ui.BtnOuProtect.IsEnabled = [bool]$isOu
    $ui.BtnOuDelete.IsEnabled  = [bool]$isOu
    if ($isOu) {
        $p = Get-AdmRawProp $ou 'Protected'
        # Three states, not two: protected, not protected, and could-not-tell. The last says so
        # rather than presenting a guess as a fact.
        $ui.BtnOuProtect.Content = if ($null -eq $p) { 'Protection?' } elseif ($p) { 'Unprotect' } else { 'Protect' }
    }
    $row = $ui.TreeGrid.SelectedItem
    foreach ($b in @($ui.BtnObjMove, $ui.BtnObjRename, $ui.BtnObjDelete)) { $b.IsEnabled = [bool]$row }
}

function Get-TreeRowDn {
    $row = $ui.TreeGrid.SelectedItem
    if (-not $row) { return $null }
    [string](Get-AdmRawProp $row 'DistinguishedName')
}

$ui.BtnOuNew.Add_Click({
    $ou = Get-TreeSelectedOu
    if (-not $ou) { return }
    $name = Show-AdmTextPrompt -Title 'New organisational unit' -Label 'NAME' `
        -Message "It will be created inside $($ou.Name).`n`nA new OU is PROTECTED from accidental deletion by default, as the Microsoft tooling does it."
    if (-not $name) { return }
    try {
        New-AdmOrganizationalUnit -Target $ui.TargetBox.Text.Trim() -Name $name `
            -Path ([string]$ou.DistinguishedName) -Confirm:$false | Out-Null
        Set-Status "created OU '$name' in $($ou.Name)" 'good'
        $ui.OuTree.Items.Clear(); Build-OuTree
    } catch { Show-GuiFailure $_ }
})

$ui.BtnOuProtect.Add_Click({
    $ou = Get-TreeSelectedOu
    if (-not $ou) { return }
    $now = [bool](Get-AdmRawProp $ou 'Protected' $false)
    try {
        Set-AdmObjectProtection -Target $ui.TargetBox.Text.Trim() -Identity ([string]$ou.DistinguishedName) `
            -Protected (-not $now) -Confirm:$false | Out-Null
        Set-Status "$($ou.Name) is now $(if ($now) { 'UNPROTECTED -- it can be deleted' } else { 'protected from accidental deletion' })" `
            $(if ($now) { 'warn' } else { 'good' })
        $ui.OuTree.Items.Clear(); Build-OuTree
    } catch { Show-GuiFailure $_ }
})

$ui.BtnOuDelete.Add_Click({
    $ou = Get-TreeSelectedOu
    if (-not $ou) { return }
    $target = $ui.TargetBox.Text.Trim()
    $dn = [string]$ou.DistinguishedName

    # ⭐ COUNT THE CHILDREN FIRST AND PUT THE NUMBER IN THE PROMPT. "Delete this OU?" does not
    # convey that everything inside it goes too, and the directory will not ask.
    # ⛔ THIS NUMBER IS WHAT SOMEONE DECIDES ON, so a truncated read here understates how much a
    # delete destroys -- the worst direction for it to be wrong in. The limit is far above any
    # plausible OU, and a hit on it is reported as "at least N" rather than as N.
    $kidLimit = 100000
    $kids = '?'
    try {
        Reset-AdmSearchTruncated
        $found = @(Get-AdmSearchResult -Target $target -SearchBase $dn -Scope Subtree -Limit $kidLimit `
                    -Filter '(objectClass=*)' -Properties @('distinguishedname'))
        $kids = if (Get-AdmSearchTruncated) { "AT LEAST $($found.Count - 1)" } else { [string]($found.Count - 1) }
    } catch { $kids = 'an unknown number of' }
    $protected = [bool](Get-AdmRawProp $ou 'Protected' $false)

    $msg = "Delete the OU '$($ou.Name)' from $target.`n`nIt contains $kids object(s), and ALL OF THEM " +
           "GO WITH IT. The directory does not ask again."
    if ($protected) { $msg += "`n`nThis OU is PROTECTED from accidental deletion; that protection will be removed to delete it." }
    $ok = Show-AdmPrompt -Title "Delete '$($ou.Name)' and everything in it?" -OkText 'Delete' -Message $msg
    if (-not $ok) { return }

    try {
        Remove-AdmOrganizationalUnit -Target $target -Identity $dn -Recurse -RemoveProtection:$protected -Confirm:$false | Out-Null
        Set-Status "deleted OU $($ou.Name) and $kids object(s)" 'warn'
        $ui.OuTree.Items.Clear(); Build-OuTree
    } catch { Show-GuiFailure $_ }
})

$ui.BtnObjMove.Add_Click({
    $dn = Get-TreeRowDn
    if (-not $dn) { return }
    $dest = Show-AdmTextPrompt -Title 'Move to which container?' -Label 'DESTINATION DISTINGUISHED NAME' `
        -Message "Moving an object changes its distinguished name, and therefore CHANGES WHICH GROUP POLICY APPLIES to it. Both DNs are written to the log.`n`nFrom: $dn"
    if (-not $dest) { return }
    try {
        Move-AdmObject -Target $ui.TargetBox.Text.Trim() -Identity $dn -DestinationPath $dest -Confirm:$false | Out-Null
        Set-Status 'moved' 'good'; Show-OuContents
    } catch { Show-GuiFailure $_ }
})

$ui.BtnObjRename.Add_Click({
    $dn = Get-TreeRowDn
    if (-not $dn) { return }
    $new = Show-AdmTextPrompt -Title 'Rename to what?' -Label 'NEW NAME' `
        -Message "This changes the object's common name only. WARNING: it does NOT change sAMAccountName or userPrincipalName -- the sign-in name stays exactly as it was.`n`n$dn"
    if (-not $new) { return }
    try {
        Rename-AdmObject -Target $ui.TargetBox.Text.Trim() -Identity $dn -NewName $new -Confirm:$false | Out-Null
        Set-Status "renamed to $new -- the sign-in name is unchanged" 'good'; Show-OuContents
    } catch { Show-GuiFailure $_ }
})

$ui.BtnObjDelete.Add_Click({
    $dn = Get-TreeRowDn
    if (-not $dn) { return }
    $ok = Show-AdmPrompt -Title 'Delete this object?' -OkText 'Delete' `
        -Message ("$dn`n`nWith the Recycle Bin disabled this is not reversible in any useful sense: what " +
                  "remains is a tombstone with no group memberships. Check the Deleted objects panel for " +
                  "which this forest can do before relying on being able to undo it.")
    if (-not $ok) { return }
    try {
        Remove-AdmObject -Target $ui.TargetBox.Text.Trim() -Identity $dn -Confirm:$false | Out-Null
        Set-Status 'deleted' 'warn'; Show-OuContents
    } catch { Show-GuiFailure $_ }
})

$ui.BtnBulk.Add_Click({ Show-BulkPanel $true })
$ui.BtnBulkClose.Add_Click({ Show-BulkPanel $false })
foreach ($m in @($ui.BulkModeBoth, $ui.BulkModeCreate, $ui.BulkModeUpdate)) {
    $m.Add_Checked({ if ($script:BulkPath -and $ui.BulkPanel.Visibility -eq 'Visible') { Show-BulkPlan } })
}

$ui.BtnBulkPick.Add_Click({
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Filter = 'CSV (*.csv)|*.csv|All files (*.*)|*.*'
    if (-not $dlg.ShowDialog()) { return }
    $script:BulkPath = $dlg.FileName
    $ui.BulkFileText.Text = [System.IO.Path]::GetFileName($script:BulkPath)
    Show-BulkPlan
})

$ui.BtnBulkApply.Add_Click({
    if (-not $script:BulkPath) { return }
    $target = $ui.TargetBox.Text.Trim()
    $plan = @($script:BulkPlan)
    $creates = @($plan | Where-Object { (Get-AdmRawProp $_ 'Action') -eq 'create' })
    $updates = @($plan | Where-Object { (Get-AdmRawProp $_ 'Action') -eq 'update' })
    $bad     = @($plan | Where-Object { [string](Get-AdmRawProp $_ 'Status') -in @('skipped', 'failed') })

    # ⛔ A ROLLBACK MANIFEST IS WRITTEN BEFORE ANYTHING IS CREATED, and where it went is in the
    # confirmation. Bulk create is the one operation here whose mistake is 400 objects rather than
    # one, and "we can undo it" has to be true before the click, not discovered afterwards.
    $roll = [System.IO.Path]::ChangeExtension($script:BulkPath, $null) +
            "-rollback-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.csv'

    $msg = "Apply to $target from $([System.IO.Path]::GetFileName($script:BulkPath)):`n`n" +
           "  create $($creates.Count) account(s)`n  update $($updates.Count)`n" +
           "  $(@($plan | Where-Object { (Get-AdmRawProp $_ 'Action') -eq 'no-change' }).Count) already match and will not be touched"
    if ($bad.Count) { $msg += "`n  $($bad.Count) CANNOT proceed and will be skipped" }
    $msg += "`n`nA rollback manifest will be written to:`n  $([System.IO.Path]::GetFileName($roll))`n" +
            "It records a delete for each account created and the previous value of each attribute changed."
    if ($creates.Count) {
        $msg += "`n`nWARNING: passwords for created accounts are returned ONCE and are not stored anywhere. Save the result before closing it."
    }

    $ok = Show-AdmPrompt -Title "Apply $($creates.Count + $updates.Count) change(s)?" -OkText 'Apply' -Message $msg
    if (-not $ok) { return }

    Set-Status "importing from $([System.IO.Path]::GetFileName($script:BulkPath)) ..."
    try {
        $res = @(Import-AdmUserCsv -Target $target -Path $script:BulkPath -Mode (Get-BulkMode) `
                    -RollbackPath $roll -Confirm:$false)
        $ui.BulkGrid.ItemsSource = @($res | Select-Object Row, SamAccountName, Action, Status, ChangeCount, Reason, TargetDn)
        $failed = @($res | Where-Object { (Get-AdmRawProp $_ 'Status') -eq 'failed' })
        $okRows = @($res | Where-Object { (Get-AdmRawProp $_ 'Status') -eq 'ok' })

        # ⚠ Per-row outcomes, never a batch-level "done". A partial run reported as success is how
        # somebody discovers three months later that 40 of 400 accounts were never created.
        $ui.BulkNotes.Text = "$($okRows.Count) applied, $($failed.Count) failed. Rollback manifest: $roll" +
            $(if ($failed.Count) { "  FAILED: $((@($failed | ForEach-Object { "row $($_.Row) -- $($_.Reason)" }) | Select-Object -First 4) -join '; ')" } else { '' })
        $ui.BulkNotes.Foreground = $win.FindResource($(if ($failed.Count) { 'Danger' } else { 'Success' }))

        # The generated passwords are the sole copy and exist only in this result. Offered once,
        # to the clipboard, and never written to the log or left in a pane.
        $withPw = @($res | Where-Object { Get-AdmRawProp $_ 'Password' })
        if ($withPw.Count) {
            $body = (@($withPw | ForEach-Object { "$($_.SamAccountName)`t$($_.Password)" }) -join "`r`n")
            $copy = Show-AdmPrompt -Title "$($withPw.Count) generated password(s)" -OkText 'Copy to clipboard' `
                -Message ("These were generated for the accounts just created. They are the ONLY copy -- they are " +
                          "not written to the log and not kept in this window. Copy them now or reset the accounts later.`n`n" +
                          ($withPw | ForEach-Object { $_.SamAccountName }) -join ', ')
            if ($copy) { try { Set-Clipboard -Value $body; Set-Status 'passwords copied to the clipboard' 'warn' } catch { } }
        }
        Set-Status "$($okRows.Count) applied, $($failed.Count) failed" $(if ($failed.Count) { 'error' } else { 'good' })
        Update-ErrorChip
    } catch { Show-GuiFailure $_ }
    $ui.BtnBulkApply.IsEnabled = $false
})

$ui.BtnForest.Add_Click({ Show-ForestPanel $true })
$ui.BtnForestClose.Add_Click({ Show-ForestPanel $false })
foreach ($t in @($ui.ForestTabTrusts, $ui.ForestTabSites, $ui.ForestTabGpo, $ui.ForestTabPso)) {
    $t.Add_Checked({ if ($ui.ForestPanel.Visibility -eq 'Visible') { Refresh-Forest } })
}

$ui.BtnBin.Add_Click({ Show-BinPanel $true })
$ui.BtnBinClose.Add_Click({ Show-BinPanel $false })
$ui.BtnBinRefresh.Add_Click({ Refresh-Bin })
$ui.BinGrid.Add_SelectionChanged({ Show-BinSelection })

$ui.BtnBinRestore.Add_Click({
    $sel = $ui.BinGrid.SelectedItem
    if (-not $sel) { return }
    $target = $ui.TargetBox.Text.Trim()
    $name = [string](Get-AdmRawProp $sel 'Name')
    $dn   = [string](Get-AdmRawProp $sel 'DistinguishedName')
    $restorable = [string](Get-AdmRawProp $sel 'Restorable')
    $tombstone = ($restorable -match 'tombstone')

    # The prompt states the LOSS, not just the action. "Restore this object?" invites yes; naming
    # what will not come back is the only honest way to ask.
    $msg = "Restore '$name' in $target."
    if ($tombstone) {
        $msg += "`n`nTHE RECYCLE BIN IS DISABLED IN THIS FOREST, so only a tombstone can be restored. " +
                "You will get the object back with its original name and SID and WITHOUT its group " +
                "memberships, most of its attributes, and its password. It will look restored.`n`n" +
                "If those memberships matter, an authoritative restore from a system-state backup is " +
                "the option that actually recovers them."
    } else {
        $msg += "`n`nThe Recycle Bin is enabled, so attributes and group memberships come back with it."
    }
    $msg += "`n`nA restored account comes back DISABLED."

    $ok = Show-AdmPrompt -Title $(if ($tombstone) { 'Restore a TOMBSTONE?' } else { 'Restore this object?' }) `
            -OkText 'Restore' -Message $msg
    if (-not $ok) { return }

    try {
        # -AcceptTombstone only where the cmdlet would otherwise refuse, and only after the
        # operator has been told exactly what a tombstone restore does and does not return.
        $r = if ($tombstone) {
            Restore-AdmObject -Target $target -Identity $dn -AcceptTombstone -Confirm:$false
        } else {
            Restore-AdmObject -Target $target -Identity $dn -Confirm:$false
        }
        # NextSteps verbatim: the cmdlet knows what still has to be done and a success toast
        # would throw that away.
        $steps = @(Get-AdmRawProp $r 'NextSteps' @())
        $ui.BinNotes.Text = if ($steps.Count) { "Restored. Still to do:  " + (($steps | ForEach-Object { "- $_" }) -join '   ') }
                            else { "Restored $name." }
        $ui.BinNotes.Foreground = $win.FindResource('Warn')
        Set-Status "restored $name -- read the notes below, it is not finished" 'warn'
        Refresh-Bin
    } catch { Show-GuiFailure $_ }
})

$ui.BtnBrowse.Add_Click({ Show-TreePanel $true })
$ui.BtnTreeClose.Add_Click({ Show-TreePanel $false })
$ui.BtnTreeRefresh.Add_Click({ $ui.OuTree.Items.Clear(); Build-OuTree })
$ui.OuTree.Add_SelectedItemChanged({ Show-OuContents; Update-TreeButtons })
$ui.TreeGrid.Add_SelectionChanged({ Update-TreeButtons })
foreach ($t in @($ui.TreeViewStandard, $ui.TreeViewAdvanced)) { $t.Add_Checked({ $ui.OuTree.Items.Clear(); Build-OuTree }) }
foreach ($t in @($ui.TreeKindUsers, $ui.TreeKindGroups, $ui.TreeKindComputers)) {
    $t.Add_Checked({ if ($ui.OuTree.SelectedItem) { Show-OuContents } })
}
# Double-clicking a row in the browser opens the same detail view as the results grid.
$ui.TreeGrid.Add_MouseDoubleClick({
    $sel = $ui.TreeGrid.SelectedItem
    if (-not $sel) { return }
    foreach ($p in @('SamAccountName', 'Name', 'DnsHostName')) {
        $v = Get-AdmRawProp $sel $p
        if ($v) { Show-ObjectDetail ([string]$v); return }
    }
})

$ui.BtnScripts.Add_Click({ Show-ScriptPanel $true })
$ui.BtnScriptClose.Add_Click({ Show-ScriptPanel $false })

# Clicking the chip takes you to the one field that sets the target, rather than leaving you to
# find it in the bar above.
$ui.ScriptTargetChip.Add_MouseLeftButtonUp({
    $ui.TargetBox.Focus()
    $ui.TargetBox.SelectAll()
    Set-Status 'Type a target, or pick a domain on the left.' 'info'
})
$ui.BtnScriptRun.Add_Click({ Invoke-SelectedScript })

$ui.ScriptList.Add_SelectionChanged({
    $sel = $ui.ScriptList.SelectedItem
    $ui.BtnScriptRun.IsEnabled = [bool]$sel
    if (-not $sel) { return }

    $ui.ScriptTitle.Text = $sel.Name
    $ui.ScriptMeta.Text = $sel.Meta
    $script:ScriptInfo = $null
    $script:ScriptSet = $null

    if ($sel.Path) {
        try { $script:ScriptInfo = Get-ScriptInfo -Path $sel.Path }
        catch { Set-ScriptOutput -For $sel.Name -Text "Could not read this script's parameters: $($_.Exception.Message)" }
    }

    if ($script:ScriptInfo) {
        $ui.ScriptSynopsis.Text = $script:ScriptInfo.Synopsis
        Build-ScriptModes
        Build-ScriptForm
        # Preview is only meaningful where the script honours it. Where it does, it stays the
        # default -- the destructive modes here disable accounts.
        $can = $script:ScriptInfo.SupportsWhatIf
        $ui.ScriptWhatIfOn.IsEnabled = $can
        $ui.ScriptWhatIfOff.IsEnabled = $can
        if ($can) { $ui.ScriptWhatIfOn.IsChecked = $true } else { $ui.ScriptWhatIfOff.IsChecked = $true }
    } else {
        # An imported script is wrapped by the toolkit, so its options are not introspectable
        # from here. Say so rather than showing an empty form that looks like "no options".
        $ui.ScriptSynopsis.Text = 'Imported script. It runs through the toolkit wrapper, which supplies the target, the error catalog and the log.'
        $ui.ScriptModeRow.Visibility = 'Collapsed'
        $ui.ScriptParams.Children.Clear()
        $script:ScriptControls = @{}
        $ui.ScriptWhatIfOn.IsEnabled = $false
        $ui.ScriptWhatIfOff.IsEnabled = $false
        $ui.ScriptWhatIfOff.IsChecked = $true
    }
    # Says whether a target applies to THIS script, so a machine script does not look like it is
    # missing one.
    Update-ScriptTargetChip
    # And show what THIS script last produced, rather than dragging the previous one's result
    # along the list with you.
    Show-ScriptOutputFor (Get-SelectedScriptName)
})

$ui.BtnScriptSaveOut.Add_Click({
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $sel = $ui.ScriptList.SelectedItem
    $dlg.FileName = "$(if ($sel) { $sel.Name } else { 'script' })-output.txt"
    $dlg.Filter = 'Text (*.txt)|*.txt|All files (*.*)|*.*'
    if ($dlg.ShowDialog()) {
        # From the per-script buffer, so what is saved is that script's own output.
        $text = [string]$script:ScriptOutputs[(Get-SelectedScriptName)]
        if (-not $text) { $text = $ui.ScriptOutput.Text }
        [System.IO.File]::WriteAllText($dlg.FileName, $text, (New-Object System.Text.UTF8Encoding($false)))
        Set-Status "saved $($dlg.FileName)" 'good'
    }
})

$ui.BtnExportDomains.Add_Click({
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.FileName = 'adadmin-domains.json'
    $dlg.Filter = 'Domain profiles (*.json)|*.json|All files (*.*)|*.*'
    if (-not $dlg.ShowDialog()) { return }
    try {
        $r = Export-AdmDomainProfile -Path $dlg.FileName
        Set-Status "exported $($r.Domains) domain profile(s) -- no credentials in the file" 'good'
    } catch { Show-GuiFailure $_ }
})

$ui.BtnImportDomains.Add_Click({
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Filter = 'Domain profiles (*.json)|*.json|All files (*.*)|*.*'
    if (-not $dlg.ShowDialog()) { return }
    try {
        $r = Import-AdmDomainProfile -Path $dlg.FileName -Confirm:$false
        Refresh-Domains
        $bits = @()
        if (@($r.Added).Count)    { $bits += "$(@($r.Added).Count) added" }
        if (@($r.Replaced).Count) { $bits += "$(@($r.Replaced).Count) replaced" }
        if (@($r.Skipped).Count)  { $bits += "$(@($r.Skipped).Count) already here, left alone" }
        if (-not $bits.Count) { $bits += 'nothing to import' }
        # Say the credential state out loud: an imported domain resolves and then fails to bind
        # until one is set, and that is confusing if nobody mentioned it.
        Set-Status (($bits -join ', ') + '. Imported domains need a credential before they can be used.') 'warn'
    } catch { Show-GuiFailure $_ }
})

$ui.BtnDomainCancel.Add_Click({ Hide-DomainEditor })
$ui.BtnDomainSave.Add_Click({ Save-DomainFromEditor })

# Enter saves, Escape cancels -- from any field in the panel.
$ui.DomainOverlay.Add_KeyDown({
    if ($_.Key -eq 'Return') { Save-DomainFromEditor; $_.Handled = $true }
    elseif ($_.Key -eq 'Escape') { Hide-DomainEditor; $_.Handled = $true }
})

$ui.BtnDomainRemove.Add_Click({
    $d = $script:EditingDomain
    if (-not $d) { return }
    # Removing a domain destroys its stored credentials with it, which is not obvious from the
    # word "Remove" -- so the prompt says so before anything happens.
    $ok = Show-AdmPrompt -Title "Remove $($d.Name)?" -OkText 'Remove' `
        -Message ("This removes the domain profile AND every credential stored for it. " +
                  "Nothing in $($d.DnsDomain) is changed -- this only forgets how to reach it.")
    if (-not $ok) { return }
    try {
        Unregister-AdmDomain -Name $d.Name -Confirm:$false | Out-Null
        Hide-DomainEditor
        Refresh-Domains
        Set-Status "removed $($d.Name)" 'warn'
    } catch { Set-DomainError $_.Exception.Message }
})

$ui.BtnSearch.Add_Click({ Invoke-Search })
$ui.SearchBox.Add_KeyDown({ if ($_.Key -eq 'Return') { Invoke-Search } })
$ui.TargetBox.Add_KeyDown({ if ($_.Key -eq 'Return') { Invoke-Search } })
$ui.TargetBox.Add_LostFocus({ Update-Resolution })
# Keep the chip in the scripts panel honest as the target changes, wherever it changed from.
$ui.TargetBox.Add_TextChanged({ try { Update-ScriptTargetChip } catch { } })
foreach ($tab in @($ui.TabUsers, $ui.TabGroups, $ui.TabComputers)) {
    $tab.Add_Checked({ Update-ActionButtons; if ($ui.TargetBox.Text) { Invoke-Search } })
}
$ui.ResultGrid.Add_SelectionChanged({ Update-ActionButtons })

# --- object detail ---------------------------------------------------------------------------------

$ui.BtnDetails.Add_Click({ Show-ObjectDetail (Get-SelectedIdentity) })
# Double-click is what people try before looking for a button.
$ui.ResultGrid.Add_MouseDoubleClick({ Show-ObjectDetail (Get-SelectedIdentity) })
$ui.BtnDetailClose.Add_Click({ Hide-ObjectDetail })
$ui.DetailOverlay.Add_KeyDown({ if ($_.Key -eq 'Escape') { Hide-ObjectDetail; $_.Handled = $true } })

$ui.BtnDetailUnlock.Add_Click({
    $d = $script:DetailObject
    if (-not $d) { return }
    try {
        Unlock-AdmUser -Target $ui.TargetBox.Text.Trim() -Identity $d.SamAccountName -Confirm:$false | Out-Null
        Set-Status "unlocked $($d.SamAccountName)" 'good'
        Show-ObjectDetail $d.SamAccountName      # re-read, so the panel shows the new truth
    } catch { Show-GuiFailure $_ }
})

$ui.BtnDetailToggle.Add_Click({
    $d = $script:DetailObject
    if (-not $d) { return }
    $target = $ui.TargetBox.Text.Trim()
    $enable = -not $d.Enabled
    $verb = if ($enable) { 'Enable' } else { 'Disable' }
    if (-not $enable) {
        $ok = Show-AdmPrompt -Title "$verb $($d.SamAccountName)?" -OkText $verb `
            -Message "This disables the account in $target. It can be re-enabled from here."
        if (-not $ok) { return }
    }
    try {
        # A computer goes through the computer cmdlet, which refuses to disable a domain
        # controller -- the guard lives in the module, so this path inherits it.
        if ($d.ObjectClass -eq 'computer') {
            Set-AdmComputerEnabled -Target $target -Identity $d.Name -Enabled $enable -Confirm:$false | Out-Null
        } else {
            Set-AdmUserEnabled -Target $target -Identity $d.SamAccountName -Enabled $enable -Confirm:$false | Out-Null
        }
        Set-Status "$($verb.ToLower())d $($d.SamAccountName)" $(if ($enable) { 'good' } else { 'warn' })
        Show-ObjectDetail $(if ($d.ObjectClass -eq 'computer') { $d.Name } else { $d.SamAccountName })
    } catch { Show-GuiFailure $_ }
})

$ui.BtnDetailReset.Add_Click({
    $d = $script:DetailObject
    if (-not $d) { return }
    $pw = Show-AdmPrompt -Title "Reset the password for $($d.SamAccountName)?" -Kind password -OkText 'Reset' `
        -Message 'The new password is written over the encrypted channel. It is never logged or echoed.'
    if (-not $pw) { return }
    try {
        Reset-AdmUserPassword -Target $ui.TargetBox.Text.Trim() -Identity $d.SamAccountName `
            -NewPassword $pw -Confirm:$false | Out-Null
        Set-Status "password reset for $($d.SamAccountName)" 'good'
        Show-ObjectDetail $d.SamAccountName
    } catch { Show-GuiFailure $_ }
})

$ui.BtnDetailEdit.Add_Click({ Show-EditPanel })
$ui.BtnEditCancel.Add_Click({ Hide-EditPanel })
$ui.EditOverlay.Add_KeyDown({ if ($_.Key -eq 'Escape') { Hide-EditPanel; $_.Handled = $true } })

$ui.BtnEditPreview.Add_Click({
    $d = $script:DetailObject
    if (-not $d) { return }
    $changes = Get-EditChanges
    if (-not $changes.Count) {
        $ui.EditChangeCount.Text = 'nothing changed'
        return
    }
    # -WhatIf, so this says what WOULD happen and writes nothing. The cmdlet's own preview is
    # shown rather than a version of it reconstructed here.
    try {
        $out = Set-AdmUser -Target $ui.TargetBox.Text.Trim() -Identity $d.SamAccountName `
                    @changes -WhatIf -Confirm:$false 4>&1 5>&1 | Out-String
        $ui.EditChangeCount.Text = "$($changes.Count) change(s): $((@($changes.Keys) | Sort-Object) -join ', ')"
        $ui.EditError.Text = $out.Trim()
        $ui.EditError.Foreground = $win.FindResource('TextMuted')
        $ui.EditError.Visibility = 'Visible'
    } catch {
        $ui.EditError.Text = $_.Exception.Message
        $ui.EditError.Foreground = $win.FindResource('Danger')
        $ui.EditError.Visibility = 'Visible'
    }
})

$ui.BtnEditSave.Add_Click({
    $d = $script:DetailObject
    if (-not $d) { return }
    $changes = Get-EditChanges
    if (-not $changes.Count) {
        $ui.EditError.Text = 'Nothing was changed.'
        $ui.EditError.Foreground = $win.FindResource('Warn')
        $ui.EditError.Visibility = 'Visible'
        return
    }
    # Name the fields in the confirmation, and say which are being CLEARED -- emptying a box is a
    # destructive act that looks identical to leaving it alone.
    $cleared = @($changes.Keys | Where-Object { $changes[$_] -is [string] -and -not $changes[$_] })
    $msg = "Write $($changes.Count) change(s) to $($d.SamAccountName) in $($ui.TargetBox.Text.Trim()):`n`n" +
           (($changes.Keys | Sort-Object | ForEach-Object {
                $v = $changes[$_]
                if ($v -is [string] -and -not $v) { "  $_  ->  (cleared)" } else { "  $_  ->  $v" }
            }) -join "`n")
    if ($cleared.Count) { $msg += "`n`n$($cleared.Count) attribute(s) will be CLEARED in the directory." }

    $ok = Show-AdmPrompt -Title 'Save these changes?' -OkText 'Save' -Message $msg
    if (-not $ok) { return }

    try {
        Set-AdmUser -Target $ui.TargetBox.Text.Trim() -Identity $d.SamAccountName @changes -Confirm:$false | Out-Null
        Set-Status "saved $($changes.Count) change(s) to $($d.SamAccountName)" 'good'
        Hide-EditPanel
        Show-ObjectDetail $d.SamAccountName      # re-read, so the panel shows the new truth
    } catch {
        $ui.EditError.Text = $_.Exception.Message
        $ui.EditError.Foreground = $win.FindResource('Danger')
        $ui.EditError.Visibility = 'Visible'
    }
})

# --- recovery secrets -----------------------------------------------------------------------------
#
# ⛔ NOT FETCHED WHEN THE DETAIL VIEW OPENS. Retrieving a machine's local administrator password is
# a credential disclosure, and browsing a list of computers must not perform one per row. It takes a
# deliberate click, the status is shown before anything secret is, and the secret itself goes to the
# clipboard rather than onto a pane that stays on screen behind whatever is opened next.
#
# ⚠ AND "NO PASSWORD" IS NOT THE SAME AS "YOU MAY NOT SEE IT". Active Directory hides an attribute
# you lack rights to read in exactly the same way it hides one that was never set, so the naive
# reading tells someone their machine has no LAPS password when it has one they cannot see -- and
# they go and re-deploy LAPS over a working password. The status distinguishes them; it is shown
# verbatim rather than being reduced to found/not-found.
$ui.BtnDetailMembers.Add_Click({
    $d = $script:DetailObject
    if (-not $d -or $d.ObjectClass -ne 'group') { return }
    $target = $ui.TargetBox.Text.Trim()
    $group = [string]$d.SamAccountName

    # ⭐ ADDING IS A PICK, NOT A TYPE. The member is an object in the same forest the target already
    # names, so the picker lists them rather than asking somebody to remember a sAMAccountName.
    $kind = Show-AdmPrompt -Title "Members of $group" -OkText 'Add a member' `
        -Message ("$group currently has $(Get-AdmRawProp $d 'MemberCount' '?') member(s).`n`n" +
                  "Add: pick an account to put in the group.`nCancel: leave it as it is.`n`n" +
                  "To REMOVE someone, open them and use their own membership list -- removing from " +
                  "here would mean choosing from a list of people who are already members, which is " +
                  "the same click with the opposite meaning and too easy to get backwards.")
    if (-not $kind) { return }

    $picked = Show-AdmObjectPicker -Kind 'users' -Target $target
    if (-not $picked) { return }

    $added = 0; $failed = @()
    foreach ($p in @($picked)) {
        try {
            Add-AdmGroupMember -Target $target -Group $group -Identity ([string]$p) -Confirm:$false | Out-Null
            $added++
        } catch { $failed += "$p ($($_.Exception.Message))" }
    }
    if ($failed.Count) {
        Set-Status "added $added, FAILED $($failed.Count): $($failed[0])" 'error'
    } else {
        # ⚠ Named, not counted. "Added 3 members" does not let anyone check you added the right ones.
        Set-Status "added to $group`: $((@($picked) | ForEach-Object { [string]$_ }) -join ', ')" 'good'
    }
    Show-ObjectDetail $group     # re-read, so the membership shown is the new truth
})

$ui.BtnDetailSecrets.Add_Click({
    $d = $script:DetailObject
    if (-not $d -or $d.ObjectClass -ne 'computer') { return }
    $target = $ui.TargetBox.Text.Trim()
    $name = [string]$d.Name

    $ok = Show-AdmPrompt -Title "Retrieve recovery secrets for $name?" -OkText 'Retrieve' `
        -Message ("This reads the LAPS local administrator password and any BitLocker recovery keys " +
                  "escrowed for $name in $target.`n`nThe secrets are NOT written to the log -- but the " +
                  "fact that you retrieved them IS, deliberately. That record is the audit trail for a " +
                  "credential disclosure.")
    if (-not $ok) { return }

    Set-Status "retrieving recovery secrets for $name ..."
    $lines = New-Object System.Collections.ArrayList
    $secret = $null

    try {
        $laps = Get-AdmLapsPassword -Target $target -Identity $name
        $status = [string](Get-AdmRawProp $laps 'Status')
        [void]$lines.Add("LAPS: $status")
        $detail = [string](Get-AdmRawProp $laps 'Detail')
        if ($detail) { [void]$lines.Add("      $detail") }
        $exp = Get-AdmRawProp $laps 'ExpiresOn'
        if ($exp) { [void]$lines.Add("      expires $exp") }
        $pw = Get-AdmRawProp $laps 'Password'
        if ($pw) {
            $secret = [string]$pw
            [void]$lines.Add("      password retrieved -- use Copy to put it on the clipboard")
        }
    } catch { [void]$lines.Add("LAPS: could not be read -- $($_.Exception.Message)") }

    try {
        $keys = @(Get-AdmBitLockerRecoveryKey -Target $target -Identity $name)
        if ($keys.Count) {
            # ⚠ ALL of them, newest first: a machine that has been re-encrypted or has more than one
            # volume has several, and the KEY IDENTIFIER is what matches the one on screen at the
            # recovery prompt -- not the date.
            [void]$lines.Add("BitLocker: $($keys.Count) recovery key(s)")
            foreach ($k in $keys) {
                [void]$lines.Add("      id $(Get-AdmRawProp $k 'KeyId')   escrowed $(Get-AdmRawProp $k 'WhenCreated')")
            }
            # ⛔ THE CAVEAT HAS TO REACH THIS PANE OR IT MIGHT AS WELL NOT EXIST. The rows carry an
            # Explanation when the read was truncated, and this pane was rendering only KeyId and
            # the date -- so the one thing that explains why none of these keys work would have
            # been dropped on the floor. The sort above is client-side: it orders what came BACK,
            # and cannot recover a newer key the read never fetched.
            $why = @($keys | ForEach-Object { [string](Get-AdmRawProp $_ 'Explanation') } |
                     Where-Object { $_ } | Select-Object -Unique)
            foreach ($w in $why) { [void]$lines.Add("      $w") }
        } else {
            [void]$lines.Add('BitLocker: no recovery objects found. That means either none were escrowed OR you cannot read them -- those are different, and this cannot tell them apart.')
        }
    } catch { [void]$lines.Add("BitLocker: could not be read -- $($_.Exception.Message)") }

    # ⭐ WHOSE CREDENTIAL, AND WHICH MACHINE, ON THE REVEAL ITSELF. The mistake worth preventing is
    # retrieving the right password for the WRONG machine, and a confirmation dialogue does not
    # help with that -- it trains people to click through. Naming both at the moment the secret
    # appears does.
    $who = ''
    try { $who = [string](Get-AdmTargetContextPublic -Target $target -Tier read).Credential.UserName } catch { }
    [void]$lines.Insert(0, "$name  in  $target")
    if ($who) { [void]$lines.Insert(1, "read as $who") }
    [void]$lines.Insert(2, '')

    # ⚠ Said out loud rather than implied. The lab has no LAPS deployed and no BitLocker keys
    # escrowed, so only the not-deployed and no-keys branches have ever run against a real
    # directory. A status this window has never seen produced should not look battle-tested.
    [void]$lines.Add('')
    [void]$lines.Add('Note: the Available and NoPermission statuses are written from documented behaviour and have not been exercised against a real LAPS deployment. Treat an unexpected status as worth checking rather than as fact.')

    $script:LastSecret = $secret
    $body = ($lines -join "`r`n")
    $copy = Show-AdmPrompt -Title "Recovery for $name" -OkText $(if ($secret) { 'Copy password' } else { 'Close' }) `
        -Message $body
    if ($copy -and $secret) {
        try { Set-Clipboard -Value $secret; Set-Status "LAPS password for $name copied to the clipboard" 'warn' }
        catch { Set-Status "could not copy: $($_.Exception.Message)" 'warn' }
    } else {
        Set-Status "read recovery status for $name" 'good'
    }
    # Dropped as soon as the dialogue closes; it is not kept for the life of the window.
    $script:LastSecret = $null
    Update-ErrorChip
})

$ui.BtnDetailCopy.Add_Click({
    $d = $script:DetailObject
    if (-not $d) { return }
    try {
        # Format-List of the whole object: what is on screen is a curated subset, and someone
        # pasting this into a ticket wants everything that was read.
        Set-Clipboard -Value (($d | Format-List | Out-String).Trim())
        Set-Status 'copied to the clipboard' 'good'
    } catch { Set-Status "could not copy: $($_.Exception.Message)" 'warn' }
})

$ui.BtnTest.Add_Click({
    $t = $ui.TargetBox.Text
    if (-not $t) { Set-Status 'Enter a target first.' 'warn'; return }
    Set-Status "binding to $t ..."
    $r = Test-AdmDomain -Target $t
    if ($r.Reachable) { Set-Status "$($r.Status): $($r.Detail)" $(if ($r.Status -eq 'mock') { 'warn' } else { 'good' }) }
    else { Set-Status "$($r.Status): $($r.Detail)" 'error' }
})

$ui.BtnUnlockUser.Add_Click({
    try {
        $sam = Get-SelectedSam
        if (Show-AdmPrompt -Title 'Unlock account' -Message "Clear the lockout on '$sam' in $($ui.TargetBox.Text)?" -OkText 'Unlock') {
            $r = Unlock-AdmUser -Target $ui.TargetBox.Text -Identity $sam -Confirm:$false
            Set-Status "unlocked $($r.SamAccountName)" 'good'; Invoke-Search
        }
    } catch { Show-GuiFailure $_ }
})
$ui.BtnEnable.Add_Click({
    try {
        $sam = Get-SelectedSam
        if (Show-AdmPrompt -Title 'Enable account' -Message "Enable '$sam' in $($ui.TargetBox.Text)?" -OkText 'Enable') {
            $r = Set-AdmUserEnabled -Target $ui.TargetBox.Text -Identity $sam -Enabled $true -Confirm:$false
            Set-Status "enabled $($r.SamAccountName)" 'good'; Invoke-Search
        }
    } catch { Show-GuiFailure $_ }
})
$ui.BtnDisable.Add_Click({
    try {
        $sam = Get-SelectedSam
        if (Show-AdmPrompt -Title 'Disable account' -Message "Disable '$sam' in $($ui.TargetBox.Text)? They will not be able to sign in." -OkText 'Disable') {
            $r = Set-AdmUserEnabled -Target $ui.TargetBox.Text -Identity $sam -Enabled $false -Confirm:$false
            Set-Status "disabled $($r.SamAccountName)" 'warn'; Invoke-Search
        }
    } catch { Show-GuiFailure $_ }
})
$ui.BtnReset.Add_Click({
    try {
        $sam = Get-SelectedSam
        $sp = Show-AdmPrompt -Kind password -Title 'Reset password' `
                -Message "New password for '$sam' in $($ui.TargetBox.Text). It is never displayed or logged." -OkText 'Reset'
        if ($sp) {
            Reset-AdmUserPassword -Target $ui.TargetBox.Text -Identity $sam -NewPassword $sp -MustChangeAtNextLogon -Confirm:$false | Out-Null
            Set-Status "password reset for $sam -- must change at next logon" 'good'
        }
    } catch { Show-GuiFailure $_ }
})

$ui.BtnLog.Add_Click({ Show-LogPanel -Show $true })
$ui.ErrorChip.Add_MouseLeftButtonUp({ Show-LogPanel -Show $true })
$ui.BtnLogClose.Add_Click({ Show-LogPanel -Show $false })
$ui.LogList.Add_SelectionChanged({
    Show-LogDetail
    # Only the toolkit's own entries can be marked: a Windows event belongs to Windows, and a
    # scan finding is recomputed on every scan rather than stored.
    $sel = $ui.LogList.SelectedItem
    $own = $sel -and (Get-AdmRawProp $sel.Entry 'ts') -and -not $ui.LogTabWindows.IsChecked -and -not $ui.LogTabScan.IsChecked
    $ui.BtnLogClear.IsEnabled = [bool]$own
})
foreach ($t in @($ui.LogTabProblems, $ui.LogTabAll, $ui.LogTabWindows, $ui.LogTabScan)) { $t.Add_Checked({ Refresh-Log }) }
$ui.BtnLogFix.Add_Click({
    try {
        $sel = $ui.LogList.SelectedItem
        if (-not $sel -or -not $sel.Entry.Finding) { return }
        $f = $sel.Entry.Finding
        # The confirmation names the problem, the consequence, and exactly what the fix touches.
        $what = switch ($f.Changes) {
            'machine' { 'settings on THIS COMPUTER' }
            'store'   { "this toolkit's own settings only" }
            'files'   { 'files inside the toolkit folder' }
            default   { $f.Changes }
        }
        $msg = "PROBLEM`n$($f.Problem)`n`nIF LEFT ALONE`n$($f.Impact)`n`nTHE FIX WILL`n$($f.FixDescription)`n`nTHIS CHANGES`n$what"
        if ($f.NeedsAdmin) { $msg += "  (needs administrator rights)" }
        if (Show-AdmPrompt -Title $f.Name -Message $msg -OkText 'Apply the fix') {
            $r = @($f | Invoke-AdmRepair -Yes -AllowMachineChanges:([bool]($f.Changes -eq 'machine')))
            if ($r -and $r[0].Outcome -eq 'fixed') { Set-Status "fixed: $($r[0].Detail)" 'good' }
            elseif ($r) { Set-Status "$($r[0].Outcome): $($r[0].Detail)" 'warn' }
            Refresh-Log; Update-ErrorChip
        }
    } catch { Show-GuiFailure $_ }
})
$ui.BtnLogExport.Add_Click({
    try {
        $dlg = New-Object Microsoft.Win32.SaveFileDialog
        $dlg.Filter = 'Text report (*.txt)|*.txt'
        $dlg.FileName = "adadmin-report-$(Get-Date -Format 'yyyy-MM-dd-HHmm').txt"
        if ($dlg.ShowDialog()) {
            $r = Export-AdmLog -Path $dlg.FileName -Days 7
            Set-Status "wrote $($r.Entries) entries to $($dlg.FileName)" 'good'
        }
    } catch { Show-GuiFailure $_ }
})

$win.Add_SourceInitialized({
    if (-not $NoBlur) {
        try { [AdmBlur]::Enable((New-Object Windows.Interop.WindowInteropHelper($win)).Handle) }
        catch { Write-Verbose "acrylic unavailable: $($_.Exception.Message)" }
    }
})

$win.Add_Loaded({
    $i = Get-AdmStoreInfo
    $ui.StorePathText.Text = $i.Path
    Update-Chips

    # The shield only appears when there is something to gain by clicking it.
    if (Test-AdmElevated) {
        $ui.BtnElevate.Visibility = 'Collapsed'
        $ui.AdminText.ToolTip = 'This window is running elevated.'
    } else {
        $ui.BtnElevate.Visibility = 'Visible'
    }
    if (-not $i.Exists) {
        # Straight into create mode, with no way back: there is nothing here to unlock. This used
        # to say "run adm store init first", which made the very first step of a GUI-first
        # toolkit a CLI step.
        Set-LockMode 'create' -Forced $true
        $ui.StorePathText.Text = "It will be created at $($i.Path)"
    } elseif ($i.Unlocked) {
        $ui.LockOverlay.Visibility = 'Collapsed'
        $ui.MainContent.Visibility = 'Visible'
        Refresh-Domains
    } else {
        $ui.PassBox.Focus()
    }
})

# ⛔ THE LAST LINE OF DEFENCE, AND THE REASON IT EXISTS.
#
# This file runs under $ErrorActionPreference = 'Stop', so ANY terminating error inside a WPF
# event handler propagates to the dispatcher and closes the window. There is no message, no log
# line and no stack -- from the user's side the application simply vanishes when they click
# something. Two shipped bugs behaved exactly that way: a hashtable key that never existed
# ($ui.ScriptRoot) took out the Scripts button, and reading an absent property on a JSON log
# entry took out clicking an error.
#
# Individual handlers should still catch their own failures and explain them properly -- that is
# what the error catalog is for. This is what happens when one does not: the error is shown, it
# is written to the 7-day log so it can be read afterwards, and the window STAYS OPEN. A toolkit
# whose stated aim is to fail loudly and clearly must not fail by disappearing.
$win.Dispatcher.add_UnhandledException({
    param($src, $ev)
    $ev.Handled = $true
    $msg = if ($ev.Exception) { $ev.Exception.Message } else { 'unknown error' }
    try {
        Set-Status "Something in the window failed: $msg  --  see the error log" 'error'
    } catch { }
    try {
        Write-AdmLog -Message "GUI handler error: $msg" -Severity error -Operation 'gui' | Out-Null
        Update-ErrorChip
    } catch { }
})

$win.Add_Closed({
    if ($script:Runner) { Stop-ScriptRun }
    Clear-SessionPassphrase
    Lock-AdmStore | Out-Null
})
[void]$win.ShowDialog()
