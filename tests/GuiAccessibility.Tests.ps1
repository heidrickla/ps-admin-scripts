# GuiAccessibility.Tests.ps1 -- every interactive control in the window must expose an accessible
# name, because a control without one is invisible twice over: a screen reader announces its type
# and nothing else, and no UI Automation test can target it except by pixel coordinate.
#
# Measured 2026-08-28 on the live window: the three credential-store inputs came back as
# `Edit ||` and the title bar as `Button |X|`, `Button |[]|`, `Button |-|`. The file contained
# zero AutomationProperties at that point.
#
# The check ENUMERATES every element in the XAML. It does NOT hand-list the control types that
# need a name -- the first pass at this fix did exactly that, listing TextBox/PasswordBox/
# ComboBox/CheckBox/DatePicker/ListView/DataGrid, and silently missed 27 RadioButton, 3 ListBox
# and 2 ItemsControl because they were not on the list. The allow-list below is therefore of
# tags that PROMISE to be presentational; anything not on it must justify itself with a name.
# A control type added to the window in future is unknown to this list and so FAILS LOUDLY,
# which is the whole point -- a list of interactive types would have exempted it in silence.

$repo = Split-Path -Parent $PSScriptRoot
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$script:fail = 0
$xamlPath = Join-Path $repo 'gui\AdmWindow.xaml'

if (-not (Test-Path -LiteralPath $xamlPath)) {
    "  FAIL  gui\AdmWindow.xaml not found -- this suite cannot have looked at anything"
    "`nFAILURES: 1"; exit 1
}

$xml = New-Object System.Xml.XmlDocument
$xml.Load($xamlPath)
$XAML_NS = 'http://schemas.microsoft.com/winfx/2006/xaml'

# Tags that promise to be presentational: layout, resources, brushes, text. Not controls.
$presentational = @(
    'Window','Grid','StackPanel','WrapPanel','DockPanel','Canvas','Border','Separator',
    'TextBlock','Run','Rectangle','Ellipse','Path','Line','Image','Viewbox',
    'ScrollViewer','ContentPresenter','ItemsPresenter','ScrollContentPresenter','AdornerDecorator',
    'RowDefinition','ColumnDefinition','GridSplitter',
    'SolidColorBrush','LinearGradientBrush','RadialGradientBrush','GradientStop','ImageBrush',
    'DropShadowEffect','BlurEffect','ResourceDictionary','Setter','Trigger','DataTrigger',
    'MultiTrigger','Condition','EventTrigger','BeginStoryboard','Storyboard','ColorAnimation',
    'DoubleAnimation','ThicknessAnimation','Style','ControlTemplate','DataTemplate',
    'ScaleTransform','RotateTransform','TranslateTransform','TransformGroup','CornerRadius',
    'ItemsPanelTemplate','VirtualizingStackPanel','UniformGrid'
)

# Subtrees that describe how a control is DRAWN, not instances of controls. A Button inside a
# ControlTemplate is a template part -- naming it is meaningless, and it has no instance identity.
$skipSubtree = @('Style','ControlTemplate','DataTemplate','ResourceDictionary')

$script:examined = 0
$script:named    = 0
$script:missing  = @()
$script:byName   = @{}

function Test-AdmXamlNode {
    param($Node, [string]$Path)

    if ($Node.NodeType -ne [System.Xml.XmlNodeType]::Element) { return }

    $local = $Node.LocalName

    # Property-element syntax: <Grid.RowDefinitions>, <ListBox.ItemTemplate>, <Setter.Value>.
    # A dotted tag is a property container, never a control. Its children still matter, except
    # where the property is a template -- those are covered by $skipSubtree below.
    $isProperty = $local.Contains('.')

    if ($skipSubtree -contains $local) { return }
    if ($isProperty -and ($local -match '\.(ItemTemplate|CellTemplate|HeaderTemplate|ContentTemplate|Resources|Style|Template)$')) { return }

    if (-not $isProperty -and $presentational -notcontains $local) {
        # Anything that is not promised-presentational is treated as a control needing a name.
        $script:examined++

        $auto = $Node.GetAttribute('AutomationProperties.Name')
        $content = $Node.GetAttribute('Content')
        $xName = $Node.GetAttribute('Name', $XAML_NS)
        if (-not $xName) { $xName = "<$local>" }

        # Content counts as a name only when it is real text. A glyph -- an arrow, a shield, a
        # multiplication sign standing in for a close button -- is what a screen reader reads out
        # loud, so it is NOT an accessible name.
        $contentIsText = $content -and ($content -match '[A-Za-z0-9]')

        if ($Node.GetAttribute('Name', $XAML_NS)) { $script:byName[$Node.GetAttribute('Name', $XAML_NS)] = $Node }

        if ($auto) { $script:named++ }
        elseif ($contentIsText) { $script:named++ }
        else { $script:missing += ('{0} ({1}) at {2}' -f $xName, $local, $Path) }
    }

    foreach ($child in $Node.ChildNodes) {
        Test-AdmXamlNode -Node $child -Path ("$Path/" + $Node.LocalName)
    }
}

Test-AdmXamlNode -Node $xml.DocumentElement -Path ''

# A CONTROL THAT CANNOT LEGITIMATELY BE EMPTY. An enumeration can succeed at scanning nothing and
# report PASS -- that is the failure this repo has hit six times. If the walk found no controls,
# the walk is broken, whatever the naming result says.
if ($script:examined -lt 40) {
    "  FAIL  {0,-52} only {1} controls examined -- the XAML walk is broken, not the window" -f 'walk-reached-the-controls', $script:examined
    $script:fail++
} else {
    "  PASS  {0,-52} {1} controls examined" -f 'walk-reached-the-controls', $script:examined
}

if ($script:missing.Count) {
    foreach ($m in $script:missing) {
        "  FAIL  no accessible name: $m"
        $script:fail++
    }
} else {
    "  PASS  {0,-52} all {1} controls expose a name" -f 'accessible-names', $script:named
}

# The glyph title-bar buttons are the specific regression this was written for: their Content is a
# symbol, so they LOOK named to a check that only tests for Content being present.
foreach ($btn in @('BtnClose','BtnMaximize','BtnMinimize','BtnElevate')) {
    $node = if ($script:byName.ContainsKey($btn)) { $script:byName[$btn] } else { $null }
    if (-not $node) {
        "  FAIL  {0,-52} control '{1}' has vanished -- this check now guards nothing" -f 'glyph-buttons', $btn
        $script:fail++
    } elseif (-not $node.GetAttribute('AutomationProperties.Name')) {
        "  FAIL  {0,-52} '{1}' is a glyph button with no AutomationProperties.Name" -f 'glyph-buttons', $btn
        $script:fail++
    }
}
if ($script:fail -eq 0) {
    "  PASS  {0,-52} all 4 glyph title-bar buttons are named" -f 'glyph-buttons'
}

if ($script:fail -gt 0) { "`nFAILURES: $script:fail"; exit 1 } else { "`nall gui accessibility checks passed"; exit 0 }
