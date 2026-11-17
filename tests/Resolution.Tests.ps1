$repo = Split-Path -Parent $PSScriptRoot   # run from any clone, USB or share
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0   # match the module, or the harness tests a laxer world than production
. (Join-Path $repo 'ADAdmin\Private\Resolution.ps1')

$fail = 0
function Expect($target, $expectedName, $expectedOn) {
    try {
        $r = Resolve-AdmDomainProfile -Target $target -Domains $script:Doms
        if ($r.Domain.Name -eq $expectedName -and $r.MatchedOn -eq $expectedOn) {
            "  PASS  {0,-34} -> {1} ({2})" -f $target, $r.Domain.Name, $r.MatchedOn
        } else {
            "  FAIL  {0,-34} -> {1} ({2}); wanted {3} ({4})" -f $target, $r.Domain.Name, $r.MatchedOn, $expectedName, $expectedOn
            $script:fail++
        }
    } catch { "  FAIL  {0,-34} threw: {1}" -f $target, $_.Exception.Message; $script:fail++ }
}
function ExpectThrow($target, $mustContain) {
    try {
        $r = Resolve-AdmDomainProfile -Target $target -Domains $script:Doms
        "  FAIL  {0,-34} resolved to {1}; expected a refusal" -f $target, $r.Domain.Name
        $script:fail++
    } catch {
        if ($_.Exception.Message -like "*$mustContain*") { "  PASS  {0,-34} refused" -f $target }
        else { "  FAIL  {0,-34} refused with the wrong message: {1}" -f $target, $_.Exception.Message; $script:fail++ }
    }
}

$Doms = @(
    [pscustomobject]@{ Name='corp';  DnsDomain='corp.example.com';       NetbiosName='CORP'
                       Aliases=@();  Hosts=@('legacy-box','ws9.plant.local')
                       DomainControllers=@('dc01.corp.example.com','dc02.corp.example.com') }
    [pscustomobject]@{ Name='child'; DnsDomain='child.corp.example.com'; NetbiosName='CHILD'
                       Aliases=@();  Hosts=@(); DomainControllers=@('dc01.child.corp.example.com') }
    [pscustomobject]@{ Name='plant'; DnsDomain='plant.local';            NetbiosName='PLANT'
                       Aliases=@('plant.internal'); Hosts=@(); DomainControllers=@() }
)

"== exact forms =="
Expect 'corp.example.com'                  'corp'  'DnsDomain'
Expect 'dc01.corp.example.com'             'corp'  'DomainController'
Expect 'CORP'                              'corp'  'NetbiosName'
Expect 'corp'                              'corp'  'NetbiosName'
Expect 'plant.internal'                    'plant' 'DnsDomain'

"== forms that need unwrapping =="
Expect 'CORP\alice'                        'corp'  'NetbiosName'
Expect 'alice@corp.example.com'            'corp'  'DnsDomain'
Expect 'ldaps://dc01.corp.example.com:636' 'corp'  'DomainController'
Expect 'ldap://corp.example.com/DC=x'      'corp'  'DnsDomain'
Expect 'corp.example.com.'                 'corp'  'DnsDomain'
Expect 'DC01.CORP.EXAMPLE.COM'             'corp'  'DomainController'
Expect 'corp.example.com:389'              'corp'  'DnsDomain'

"== suffix matching, most specific wins =="
Expect 'ws1.corp.example.com'              'corp'  'DnsSuffix'
Expect 'ws1.child.corp.example.com'        'child' 'DnsSuffix'   # NOT corp -- longest suffix
Expect 'child.corp.example.com'            'child' 'DnsDomain'   # exact beats suffix
Expect 'srv.plant.internal'                'plant' 'DnsSuffix'

"== explicit host mapping outranks DNS =="
Expect 'legacy-box'                        'corp'  'Hosts'
Expect 'ws9.plant.local'                   'corp'  'Hosts'       # in plant's DNS, administered as corp

"== refusals -- never a silent pick =="
ExpectThrow 'unknown.example.org'          'No registered domain matches'
ExpectThrow 'randomhost'                   'bare hostname cannot be attributed'
ExpectThrow '192.0.2.41'                  'IP address cannot be attributed'

"== ambiguity is an error =="
$script:Doms = @(
    [pscustomobject]@{ Name='a'; DnsDomain='shared.example.com'; NetbiosName='A'; Aliases=@(); Hosts=@(); DomainControllers=@() }
    [pscustomobject]@{ Name='b'; DnsDomain='shared.example.com'; NetbiosName='B'; Aliases=@(); Hosts=@(); DomainControllers=@() }
)
ExpectThrow 'host.shared.example.com'      'matches more than one domain'
ExpectThrow 'shared.example.com'           'matches more than one domain'

"== empty registry =="
$script:Doms = @()
ExpectThrow 'anything.example.com'         'No registered domain matches'

"== malformed input =="
try { ConvertTo-AdmNormalizedTarget -Target '   ' ; "  FAIL  blank target accepted"; $fail++ }
catch { "  PASS  blank target refused" }

if ($fail -gt 0) { "`nFAILURES: $fail"; exit 1 } else { "`nall resolution checks passed"; exit 0 }
