# Offline tests for Test-ClientDomains.ps1. No network: DNS, RDAP and TLS are replaced
# with fixtures. Run in Windows PowerShell 5.1 or PowerShell 7:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1
#   pwsh -NoProfile -File ./tests/Run-Tests.ps1
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Test-ClientDomains.ps1'
. $scriptPath

$script:Passed = 0
$script:Failed = 0
function Assert-True {
    param($Condition, [string]$Name)
    if ($Condition) { $script:Passed++ }
    else { $script:Failed++; Write-Host "FAIL: $Name" -ForegroundColor Red }
}
function Assert-Equal {
    param($Expected, $Actual, [string]$Name)
    if ($Expected -eq $Actual) { $script:Passed++ }
    else { $script:Failed++; Write-Host "FAIL: $Name`n      expected: $Expected`n      actual:   $Actual" -ForegroundColor Red }
}
function Get-Levels {
    param($Row, [string]$Area)
    @($Row.Findings | Where-Object { -not $Area -or $_.Area -eq $Area } | ForEach-Object { $_.Level })
}
function Find-Message {
    param($Row, [string]$Pattern)
    @($Row.Findings | Where-Object { $_.Message -match $Pattern }).Count -gt 0
}

# Fakes for DNS, RDAP and TLS (shared with New-SampleReport.ps1)
. (Join-Path $PSScriptRoot 'Fakes.ps1')

Initialize-Http

# ---------------------------------------------------------------- parsing helpers

Assert-Equal 'v=spf1 a -all' (ConvertFrom-TxtData '"v=spf1 a " "-all"') 'TXT: split strings are joined'
Assert-Equal 'say "hi"' (ConvertFrom-TxtData '"say \"hi\""') 'TXT: escaped quotes'
Assert-Equal 'a;b' (ConvertFrom-TxtData '"a\059b"') 'TXT: decimal escapes'
Assert-Equal 'v=spf1 -all' (ConvertFrom-TxtData 'v=spf1 -all') 'TXT: unquoted data passes through'

Assert-Equal 'www.example.com' (ConvertTo-DomainName ' https://WWW.Example.com/path?x=1 ') 'Domain: URL is reduced to host'
Assert-Equal 'example.com' (ConvertTo-DomainName 'Example.COM.') 'Domain: case and trailing dot'
Assert-Equal 'contoso.com' (ConvertTo-DomainName 'admin@contoso.com') 'Domain: email address'
Assert-Equal 'xn--bcher-kva.de' (ConvertTo-DomainName ("b{0}cher.de" -f [char]0x00FC)) 'Domain: IDN to punycode'
Assert-True (Test-DomainName 'contoso.co.uk') 'Domain: valid multi-label'
Assert-True (Test-DomainName 'xn--bcher-kva.de') 'Domain: valid punycode'
Assert-True (-not (Test-DomainName 'not a domain')) 'Domain: spaces rejected'
Assert-True (-not (Test-DomainName 'localhost')) 'Domain: single label rejected'

$h = ConvertTo-HostEntry 'vpn.contoso.com:4443'
Assert-Equal 'vpn.contoso.com' $h.Host 'Host entry: host'
Assert-Equal 4443 $h.Port 'Host entry: port'
Assert-Equal 443 (ConvertTo-HostEntry 'https://remote.contoso.com/RDWeb').Port 'Host entry: default port'

Assert-Equal 'bbc.co.uk' (Get-BaseDomain 'ns1.bbc.co.uk') 'Base domain: co.uk'
Assert-Equal 'host.com' (Get-BaseDomain 'ns1.dns.host.com') 'Base domain: .com'
Assert-Equal 'Microsoft 365' (Get-ProviderName -HostNames @('contoso-com.mail.protection.outlook.com') -Map $script:MailProviders) 'Mail provider: M365'
Assert-Equal 'Microsoft 365' (Get-ProviderName -HostNames @('contoso-com.k-v1.mx.microsoft') -Map $script:MailProviders) 'Mail provider: M365 DNSSEC MX'
Assert-Equal 'Google Workspace' (Get-ProviderName -HostNames @('aspmx.l.google.com', 'alt1.aspmx.l.google.com') -Map $script:MailProviders) 'Mail provider: Google, deduplicated'
Assert-Equal 'mailhost.net' (Get-ProviderName -HostNames @('mx1.mailhost.net') -Map $script:MailProviders) 'Mail provider: unknown shows base domain'
Assert-Equal 'AWS Route 53' (Get-DnsHostName @('ns-1.awsdns-01.org', 'ns-2.awsdns-02.com')) 'DNS host: Route 53'
Assert-Equal 'Cloudflare' (Get-DnsHostName @('ana.ns.cloudflare.com', 'bob.ns.cloudflare.com')) 'DNS host: Cloudflare'

$tags = ConvertFrom-DmarcRecord 'v=DMARC1; p=Quarantine ; pct=50; rua=mailto:a@b.c,mailto:d@e.f'
Assert-Equal 'Quarantine' $tags['p'] 'DMARC: p tag'
Assert-Equal '50' $tags['pct'] 'DMARC: pct tag'
Assert-True ($tags['rua'] -match 'd@e.f') 'DMARC: rua with several addresses'

Assert-Equal 'expires in 1 day' (Format-DaysPhrase 1) 'Days phrase: singular'
Assert-Equal 'expired 3 days ago' (Format-DaysPhrase -3) 'Days phrase: past'
Assert-Equal 'expired' (Format-DaysCell -4224) 'Days cell: expired'
Assert-Equal '1 day' (Format-DaysCell 1) 'Days cell: singular'
Assert-Equal 'bad' (Get-DayClass -3 14 7) 'Day class: negative is critical'
Assert-Equal '-' (Format-DaysCell $null) 'Days cell: unknown'
Assert-Equal 2027 (ConvertTo-UtcDate '2027-02-06T23:15:14Z').Year 'Date: RDAP date parses'
Assert-Equal 23 (ConvertTo-UtcDate '2027-02-06T23:15:14Z').Hour 'Date: RDAP date stays in UTC'

# ---------------------------------------------------------------- SPF lookup counting

Set-Dns 'leaf.test' 'TXT' @('v=spf1 ip4:192.0.2.1 -all')
Set-Dns 'simple.test' 'TXT' @('v=spf1 include:leaf.test mx a:mail.simple.test ip4:192.0.2.2 -all')
$s = Get-SpfAnalysis 'simple.test'
Assert-Equal 3 $s.Lookups 'SPF: include + mx + a = 3'
Assert-Equal '-' $s.All 'SPF: all qualifier'
Assert-Equal 0 $s.Problems.Count 'SPF: no problems'

$includes = (1..11 | ForEach-Object { "include:leaf.test" }) -join ' '
Set-Dns 'many.test' 'TXT' @("v=spf1 $includes ~all")
$s = Get-SpfAnalysis 'many.test'
Assert-Equal 11 $s.Lookups 'SPF: 11 includes counted'

Set-Dns 'nested2.test' 'TXT' @('v=spf1 a mx include:leaf.test ~all')
Set-Dns 'nested1.test' 'TXT' @('v=spf1 include:nested2.test exists:%{i}.spf.example ptr ~all')
Set-Dns 'nested.test' 'TXT' @('v=spf1 include:nested1.test exp=explain.nested.test ~all')
$s = Get-SpfAnalysis 'nested.test'
Assert-Equal 7 $s.Lookups 'SPF: nested includes, exists and ptr count; exp does not'
Assert-True $s.UsesPtr 'SPF: ptr flagged'
Assert-True $s.Macros 'SPF: macros flagged'

Set-Dns 'gone.test' 'TXT' @() -Status 3
Set-Dns 'broken.test' 'TXT' @('v=spf1 include:gone.test -all')
$s = Get-SpfAnalysis 'broken.test'
Assert-True (@($s.Problems | Where-Object { $_ -match 'include:gone.test has no SPF record' }).Count -eq 1) 'SPF: include without SPF record is an error'

Set-Dns 'double.test' 'TXT' @('v=spf1 a -all', 'v=spf1 mx -all')
$s = Get-SpfAnalysis 'double.test'
Assert-Equal 'multiple' $s.Result 'SPF: two records detected'

Set-Dns 'redirect.test' 'TXT' @('v=spf1 redirect=_spf.redirect.test')
Set-Dns '_spf.redirect.test' 'TXT' @('v=spf1 include:leaf.test -all')
$s = Get-SpfAnalysis 'redirect.test'
Assert-Equal 2 $s.Lookups 'SPF: redirect counts and is followed'
Assert-Equal '-' $s.All 'SPF: all comes from the redirect target'

Set-Dns 'redirect-ignored.test' 'TXT' @('v=spf1 a redirect=leaf.test ~all')
$s = Get-SpfAnalysis 'redirect-ignored.test'
Assert-Equal 1 $s.Lookups 'SPF: redirect ignored when all is present'

Set-Dns 'loop1.test' 'TXT' @('v=spf1 include:loop2.test -all')
Set-Dns 'loop2.test' 'TXT' @('v=spf1 include:loop1.test -all')
$s = Get-SpfAnalysis 'loop1.test'
Assert-True (@($s.Problems | Where-Object { $_ -match 'loop' }).Count -ge 1) 'SPF: include loop detected'

Set-Dns 'unknown.test' 'TXT' @('v=spf1 ip4:192.0.2.1 foo:bar -all')
$s = Get-SpfAnalysis 'unknown.test'
Assert-True (@($s.Problems | Where-Object { $_ -match "Unknown term 'foo:bar'" }).Count -eq 1) 'SPF: unknown mechanism is an error'

Set-Dns 'ipv6.test' 'TXT' @('v=spf1 ip6:2001:db8::/32 ip4:192.0.2.0/24 +all')
$s = Get-SpfAnalysis 'ipv6.test'
Assert-Equal 0 $s.Lookups 'SPF: ip4/ip6 do not count'
Assert-Equal '+' $s.All 'SPF: +all detected'

Set-DnsError 'flaky.test' 'TXT'
Set-Dns 'incomplete.test' 'TXT' @('v=spf1 include:flaky.test -all')
$s = Get-SpfAnalysis 'incomplete.test'
Assert-Equal 'flaky.test' ($s.Incomplete -join ',') 'SPF: failed include lookups are reported'

# ---------------------------------------------------------------- whole-domain rules

New-FakeDomain 'healthy.test'
$r = Test-OneDomain -Entry (New-Entry 'healthy.test') -Previous $null
Assert-Equal 'OK' $r.Status 'Healthy domain is OK'
Assert-Equal 'Google Workspace' $r.MailProvider 'Healthy: mail provider'
Assert-Equal 'GoDaddy' $r.DnsHost 'Healthy: DNS host'
Assert-Equal 'OK (1/10 lookups)' $r.SPF 'Healthy: SPF label'
Assert-Equal 'p=reject' $r.DMARC 'Healthy: DMARC label'
Assert-Equal 'google' $r.DKIM 'Healthy: DKIM selector found'
Assert-Equal 0 @(Get-Levels $r | Where-Object { $_ -ne 'Info' }).Count 'Healthy: no warnings'

New-FakeDomain 'expiring.test'
$script:FakeRegistration['expiring.test'] = [pscustomobject]@{ Supported = $true; Found = $true; Expires = [DateTime]::UtcNow.AddDays(5.5); Registrar = 'R'; Statuses = @('client transfer prohibited'); Error = $null }
$r = Test-OneDomain -Entry (New-Entry 'expiring.test') -Previous $null
Assert-Equal 'Critical' $r.Status 'Registration in 5 days is critical'
Assert-True (Find-Message $r 'expires in 5 days') 'Registration message has day count'

New-FakeDomain 'soon.test'
$script:FakeRegistration['soon.test'] = [pscustomobject]@{ Supported = $true; Found = $true; Expires = [DateTime]::UtcNow.AddDays(20.5); Registrar = 'R'; Statuses = @('client transfer prohibited'); Error = $null }
$r = Test-OneDomain -Entry (New-Entry 'soon.test') -Previous $null
Assert-Equal 'Warning' $r.Status 'Registration in 20 days is a warning'

New-FakeDomain 'lapsed.test'
$script:FakeRegistration['lapsed.test'] = [pscustomobject]@{ Supported = $true; Found = $true; Expires = [DateTime]::UtcNow.AddDays(300); Registrar = 'R'; Statuses = @('redemption period', 'client transfer prohibited'); Error = $null }
$r = Test-OneDomain -Entry (New-Entry 'lapsed.test') -Previous $null
Assert-Equal 'Critical' $r.Status 'Redemption period is critical'

New-FakeDomain 'grace.test'
$script:FakeRegistration['grace.test'] = [pscustomobject]@{ Supported = $true; Found = $true; Expires = [DateTime]::UtcNow.AddDays(360); Registrar = 'R'; Statuses = @('auto renew period', 'client transfer prohibited'); Error = $null }
$r = Test-OneDomain -Entry (New-Entry 'grace.test') -Previous $null
Assert-Equal 'Warning' $r.Status 'Auto-renew grace period is a warning the first time'
Assert-Equal 'yes' $r.Snapshot['AutoRenewGrace'] 'Auto-renew grace period is remembered'
$r2 = Test-OneDomain -Entry (New-Entry 'grace.test') -Previous @{ AutoRenewGrace = 'yes' }
Assert-Equal 'OK' $r2.Status 'Auto-renew grace period is only a note after the first alert'
Assert-True (Find-Message $r2 'auto-renew grace period') 'Auto-renew note kept'

New-FakeDomain 'unlocked-example.com'
$script:FakeRegistration['unlocked-example.com'] = [pscustomobject]@{ Supported = $true; Found = $true; Expires = [DateTime]::UtcNow.AddDays(300); Registrar = 'R'; Statuses = @('active'); Error = $null }
$r = Test-OneDomain -Entry (New-Entry 'unlocked-example.com') -Previous $null
Assert-True (Find-Message $r 'transfer lock') 'Missing transfer lock is noted'
Assert-Equal 'OK' $r.Status 'Missing transfer lock alone stays OK'

New-FakeDomain 'nordap.de'
$script:FakeRegistration['nordap.de'] = [pscustomobject]@{ Supported = $false; Found = $null; Expires = $null; Registrar = $null; Statuses = @(); Error = $null }
$r = Test-OneDomain -Entry (New-Entry 'nordap.de') -Previous $null
Assert-Equal 'OK' $r.Status 'TLD without RDAP is only a note'

$script:FakeRegistration['typo.test'] = [pscustomobject]@{ Supported = $true; Found = $false; Expires = $null; Registrar = $null; Statuses = @(); Error = $null }
Set-Dns 'typo.test' 'NS' @() -Status 3
$r = Test-OneDomain -Entry (New-Entry 'typo.test') -Previous $null
Assert-Equal 'Critical' $r.Status 'Unregistered domain is critical'
Assert-True (Find-Message $r 'NXDOMAIN') 'NXDOMAIN reported'

Set-DnsError 'servfail.test' 'NS' -Status 2
$r = Test-OneDomain -Entry (New-Entry 'servfail.test') -Previous $null
Assert-Equal 'Critical' $r.Status 'SERVFAIL is critical'

New-FakeDomain 'cert.test'
$script:FakeCerts['cert.test:443'] = New-FakeCert -HostName 'cert.test' -Days 3
$r = Test-OneDomain -Entry (New-Entry 'cert.test') -Previous $null
Assert-Equal 'Critical' $r.Status 'Website certificate in 3 days is critical'
Assert-Equal 3 $r.WebsiteCertDaysLeft 'Website certificate days'

New-FakeDomain 'certwarn.test'
$script:FakeCerts['certwarn.test:443'] = New-FakeCert -HostName 'certwarn.test' -Days 10
$r = Test-OneDomain -Entry (New-Entry 'certwarn.test') -Previous $null
Assert-Equal 'Warning' $r.Status 'Website certificate in 10 days is a warning'

New-FakeDomain 'shortlived.test'
$script:FakeCerts['shortlived.test:443'] = New-FakeCert -HostName 'shortlived.test' -Days 3 -Lifetime 6
$r = Test-OneDomain -Entry (New-Entry 'shortlived.test') -Previous $null
Assert-Equal 'OK' $r.Status '6-day certificate with 3 days left is normal'
$script:FakeCerts['shortlived.test:443'] = New-FakeCert -HostName 'shortlived.test' -Days -1 -Lifetime 6
$r = Test-OneDomain -Entry (New-Entry 'shortlived.test') -Previous $null
Assert-Equal 'Critical' $r.Status 'Expired 6-day certificate is critical'

New-FakeDomain 'mismatch.test'
$script:FakeCerts['mismatch.test:443'] = New-FakeCert -HostName 'mismatch.test' -Days 80 -Mismatch
$r = Test-OneDomain -Entry (New-Entry 'mismatch.test') -Previous $null
Assert-Equal 'Warning' $r.Status 'Certificate name mismatch is a warning'

New-FakeDomain 'wwwonly.test'
Set-Dns 'wwwonly.test' 'A' @()
Set-Dns 'wwwonly.test' 'AAAA' @()
Set-Dns 'www.wwwonly.test' 'A' @('192.0.2.20')
$r = Test-OneDomain -Entry (New-Entry 'wwwonly.test') -Previous $null
Assert-Equal 'www.wwwonly.test' $r.WebsiteHost 'Falls back to www when the domain has no address'

New-FakeDomain 'apexdown.test'
Set-Dns 'www.apexdown.test' 'A' @('192.0.2.30')
$script:FakeCerts['apexdown.test:443'] = New-FakeCert -HostName 'apexdown.test' -ConnectError 'connection refused'
$r = Test-OneDomain -Entry (New-Entry 'apexdown.test') -Previous $null
Assert-Equal 'www.apexdown.test' $r.WebsiteHost 'Falls back to www when the domain refuses HTTPS'

New-FakeDomain 'extra.test'
$script:FakeCerts['rdg.extra.test:443'] = New-FakeCert -HostName 'rdg.extra.test' -Days -2
$script:FakeCerts['vpn.extra.test:4443'] = New-FakeCert -HostName 'vpn.extra.test' -Port 4443 -ConnectError 'timed out'
$r = Test-OneDomain -Entry (New-Entry 'extra.test' -CertHosts @((ConvertTo-HostEntry 'rdg.extra.test'), (ConvertTo-HostEntry 'vpn.extra.test:4443'))) -Previous $null
Assert-Equal 'Critical' $r.Status 'Expired extra certificate is critical'
Assert-True (Find-Message $r 'rdg.extra.test certificate expired') 'Expired extra certificate message'
Assert-True (Find-Message $r "Couldn't connect to vpn.extra.test:4443") 'Unreachable extra host is reported'
Assert-Equal 2 $r.OtherCerts.Count 'Both extra hosts listed'

New-FakeDomain 'm365.test'
Set-Dns 'm365.test' 'MX' @('0 m365-test.mail.protection.outlook.com')
Set-Dns 'm365.test' 'TXT' @('v=spf1 include:spf.protection.outlook.com -all')
Set-Dns 'spf.protection.outlook.com' 'TXT' @('v=spf1 ip4:40.92.0.0/15 -all')
Set-Dns 'google._domainkey.m365.test' 'TXT' @() -Status 3
$r = Test-OneDomain -Entry (New-Entry 'm365.test') -Previous $null
Assert-Equal 'Microsoft 365' $r.MailProvider 'M365: provider'
Assert-True (Find-Message $r 'no DKIM records at selector1/selector2') 'M365 without DKIM is flagged'
Assert-Equal 'Warning' $r.Status 'M365 without DKIM is a warning'

New-FakeDomain 'm365cname.test'
Set-Dns 'm365cname.test' 'MX' @('0 m365cname-test.mail.protection.outlook.com')
Set-Dns 'google._domainkey.m365cname.test' 'TXT' @() -Status 3
Set-Dns 'selector1._domainkey.m365cname.test' 'TXT' @() -Status 3 -Cnames @('selector1-m365cname-test._domainkey.tenant.onmicrosoft.com')
$r = Test-OneDomain -Entry (New-Entry 'm365cname.test') -Previous $null
Assert-True (Find-Message $r 'CNAMEs exist') 'M365 CNAME without key is flagged'

New-FakeDomain 'm365ok.test'
Set-Dns 'm365ok.test' 'MX' @('0 m365ok-test.mail.protection.outlook.com')
Set-Dns 'google._domainkey.m365ok.test' 'TXT' @() -Status 3
Set-Dns 'selector2._domainkey.m365ok.test' 'TXT' @('v=DKIM1; k=rsa; p=MIGfMA0') -Cnames @('selector2-m365ok-test._domainkey.tenant.onmicrosoft.com')
$r = Test-OneDomain -Entry (New-Entry 'm365ok.test') -Previous $null
Assert-Equal 'selector2' $r.DKIM 'M365 with one active selector is fine'
Assert-Equal 'OK' $r.Status 'M365 with DKIM is OK'

New-FakeDomain 'nodmarc.test'
Set-Dns '_dmarc.nodmarc.test' 'TXT' @() -Status 3
$r = Test-OneDomain -Entry (New-Entry 'nodmarc.test') -Previous $null
Assert-Equal 'Warning' $r.Status 'Mail domain without DMARC is a warning'
Assert-Equal 'Missing' $r.DMARC 'DMARC label: Missing'

New-FakeDomain 'twodmarc.test'
Set-Dns '_dmarc.twodmarc.test' 'TXT' @('v=DMARC1; p=none', 'v=DMARC1; p=reject')
$r = Test-OneDomain -Entry (New-Entry 'twodmarc.test') -Previous $null
Assert-Equal 'Critical' $r.Status 'Two DMARC records is critical'

New-FakeDomain 'monitor.test'
Set-Dns '_dmarc.monitor.test' 'TXT' @('v=DMARC1; p=none')
$r = Test-OneDomain -Entry (New-Entry 'monitor.test') -Previous $null
Assert-Equal 'OK' $r.Status 'p=none is a note, not a warning'
Assert-True (Find-Message $r 'monitoring only') 'p=none note'
Assert-True (Find-Message $r 'no rua=') 'Missing rua note'

New-FakeDomain 'nospf.test'
Set-Dns 'nospf.test' 'TXT' @('google-site-verification=abc')
$r = Test-OneDomain -Entry (New-Entry 'nospf.test') -Previous $null
Assert-Equal 'Warning' $r.Status 'Mail domain without SPF is a warning'

New-FakeDomain 'spf11.test'
Set-Dns 'spf11.test' 'TXT' @("v=spf1 $includes -all")
$r = Test-OneDomain -Entry (New-Entry 'spf11.test') -Previous $null
Assert-Equal 'Critical' $r.Status 'SPF over 10 lookups is critical'
Assert-Equal 'Error (11/10 lookups)' $r.SPF 'SPF over 10 label'

New-FakeDomain 'parked.test'
Set-Dns 'parked.test' 'MX' @()
Set-Dns 'parked.test' 'TXT' @()
Set-Dns '_dmarc.parked.test' 'TXT' @() -Status 3
$r = Test-OneDomain -Entry (New-Entry 'parked.test') -Previous $null
Assert-Equal 'OK' $r.Status 'Parked domain without SPF/DMARC is only a note'
Assert-True (Find-Message $r "doesn't appear to send or receive mail") 'Parked domain advice'
Assert-Equal '-' $r.DKIM 'Parked domain: DKIM not checked'

New-FakeDomain 'lockeddown.test'
Set-Dns 'lockeddown.test' 'MX' @('0 .')
Set-Dns 'lockeddown.test' 'TXT' @('v=spf1 -all')
Set-Dns '_dmarc.lockeddown.test' 'TXT' @('v=DMARC1; p=reject; rua=mailto:x@example.net')
$r = Test-OneDomain -Entry (New-Entry 'lockeddown.test') -Previous $null
Assert-Equal 'No mail (null MX)' $r.MailProvider 'Null MX detected'
Assert-True (-not (Find-Message $r "doesn't appear to send")) 'Locked-down parked domain gets no advice'

$r = Test-OneDomain -Entry ([pscustomobject]@{ Client = ''; Domain = 'not a domain'; Raw = 'not a domain'; CertHosts = @() }) -Previous $null
Assert-Equal 'Warning' $r.Status 'Invalid input is a warning'

# ---------------------------------------------------------------- change detection and state

New-FakeDomain 'changed.test'
$first = Test-OneDomain -Entry (New-Entry 'changed.test') -Previous $null
$previous = @{}
foreach ($k in $first.Snapshot.Keys) { $previous[$k] = $first.Snapshot[$k] }
$previous['_checked'] = '2026-11-01 07:00'
$same = Test-OneDomain -Entry (New-Entry 'changed.test') -Previous $previous
Assert-Equal 0 @(Get-Levels $same 'Change').Count 'No change, no finding'
Set-Dns 'changed.test' 'MX' @('0 changed-test.mail.protection.outlook.com')
Set-Dns 'changed.test' 'NS' @('ana.ns.cloudflare.com', 'bob.ns.cloudflare.com')
$after = Test-OneDomain -Entry (New-Entry 'changed.test') -Previous $previous
Assert-Equal 2 @(Get-Levels $after 'Change').Count 'MX and NS changes found'
Assert-True (Find-Message $after 'MX records changed since the last check \(last check 2026-11-01 07:00\)') 'Change message names the field and date'
Assert-Equal 'Warning' $after.Status 'A change is a warning'

Set-DnsError 'changed.test' 'MX'
$err = Test-OneDomain -Entry (New-Entry 'changed.test') -Previous $previous
Assert-True (-not (Find-Message $err 'MX records changed')) 'A failed lookup is not reported as a change'

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("cdc-test-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $statePath = Join-Path $tmp 'state.json'
    Save-State -Path $statePath -Previous @{ 'changed.test' = $previous } -Results @($err)
    $loaded = Read-State -Path $statePath
    Assert-Equal $previous['MX'] $loaded['changed.test']['MX'] 'State keeps the old value when a lookup failed'
    Assert-Equal 'ana.ns.cloudflare.com, bob.ns.cloudflare.com' $loaded['changed.test']['NS'] 'State stores the new value'

    # ---------------------------------------------------------------- input files
    $csv = Join-Path $tmp 'list.csv'
    Set-Content -LiteralPath $csv -Encoding UTF8 -Value @(
        'client,DOMAIN,CertHosts',
        'Contoso,https://Contoso.com/,remote.contoso.com; vpn.contoso.com:4443',
        'Contoso,contoso.com,remote.contoso.com',
        'Fabrikam,fabrikam.co.uk,',
        ',# commented out,',
        'Blank,,'
    )
    $list = @(Read-DomainList -Path $csv -Names $null)
    Assert-Equal 2 $list.Count 'CSV: duplicates merged, comments and blanks skipped'
    Assert-Equal 'contoso.com' $list[0].Domain 'CSV: domain normalised'
    Assert-Equal 2 @($list[0].CertHosts).Count 'CSV: cert hosts merged without duplicates'
    Assert-Equal 4443 @($list[0].CertHosts)[1].Port 'CSV: cert host port'
    Assert-Equal 'Fabrikam' $list[1].Client 'CSV: header names are case-insensitive'

    $txt = Join-Path $tmp 'list.txt'
    Set-Content -LiteralPath $txt -Value @('# my clients', 'contoso.com', '', 'fabrikam.com  # comment')
    $list = @(Read-DomainList -Path $txt -Names $null)
    Assert-Equal 'contoso.com,fabrikam.com' (($list | ForEach-Object { $_.Domain }) -join ',') 'TXT list with comments'

    $list = @(Read-DomainList -Path $null -Names @('contoso.com, fabrikam.com', 'northwind.com'))
    Assert-Equal 3 $list.Count '-Domain accepts arrays and comma lists'

    $bad = Join-Path $tmp 'bad.csv'
    Set-Content -LiteralPath $bad -Value @('contoso.com', 'fabrikam.com')
    $threw = $false
    try { Read-DomainList -Path $bad -Names $null | Out-Null } catch { $threw = $_.Exception.Message -match 'Domain column' }
    Assert-True $threw 'CSV without header gives a clear error'

    # ---------------------------------------------------------------- report, CSV, webhook, exit code (full run)
    New-FakeDomain 'alpha.test'
    New-FakeDomain 'beta.test'
    $script:FakeRegistration['beta.test'] = [pscustomobject]@{ Supported = $true; Found = $true; Expires = [DateTime]::UtcNow.AddDays(3.5); Registrar = 'Example Registrar'; Statuses = @('client transfer prohibited'); Error = $null }
    $listPath = Join-Path $tmp 'run.csv'
    Set-Content -LiteralPath $listPath -Value @('Client,Domain', '"<script>alert(1)</script> & Co",alpha.test', 'Beta LLC,beta.test')
    $InputFile = $listPath
    $OutputFolder = Join-Path $tmp 'out'
    $run = Invoke-ClientDomainCheck 6> $null
    Assert-Equal 2 $run.ExitCode 'Exit code 2 when something is critical'
    Assert-True (Test-Path -LiteralPath $run.ReportPath) 'HTML report written'
    Assert-True (Test-Path -LiteralPath $run.CsvPath) 'CSV written'
    Assert-True (Test-Path -LiteralPath (Join-Path $OutputFolder 'domain-check-state.json')) 'State file written'
    $html = [IO.File]::ReadAllText($run.ReportPath)
    Assert-True ($html -notmatch '<script>') 'HTML escapes client names'
    Assert-True ($html -match '&lt;script&gt;alert\(1\)&lt;/script&gt; &amp; Co') 'HTML shows the escaped name'
    Assert-True ($html.IndexOf('Beta LLC') -lt $html.IndexOf('All domains')) 'Critical domain is in Needs attention'
    $rows = @(Import-Csv -LiteralPath $run.CsvPath)
    Assert-Equal 'beta.test' $rows[0].Domain 'CSV sorted with critical first'
    Assert-Equal 'Critical' $rows[0].Status 'CSV status column'
    Assert-Equal 0 $script:NetworkCalls.Count 'No unexpected network calls in offline tests'

    $script:FakeRegistration.Remove('beta.test')
    $run = Invoke-ClientDomainCheck 6> $null
    Assert-Equal 0 $run.ExitCode 'Exit code 0 when all clear'
    $html = [IO.File]::ReadAllText($run.ReportPath)
    Assert-True ($html -match 'Nothing needs attention today') 'All-clear message'

    Set-Dns 'beta.test' 'TXT' @('v=spf1 include:_spf.google.com include:sendgrid.net ~all')
    Set-Dns 'sendgrid.net' 'TXT' @('v=spf1 ip4:192.0.2.0/24 ~all')
    $run = Invoke-ClientDomainCheck 6> $null
    Assert-Equal 1 $run.ExitCode 'Exit code 1 for warnings only (SPF change)'

    $teams = New-WebhookPayload -Url 'https://prod-00.westus.logic.azure.com/workflows/x' -Results $run.Results -ReportPath 'C:\r.html' | ConvertFrom-Json
    Assert-Equal 'message' $teams.type 'Teams: message wrapper'
    Assert-Equal 'application/vnd.microsoft.card.adaptive' $teams.attachments[0].contentType 'Teams: adaptive card attachment'
    Assert-Equal 'AdaptiveCard' $teams.attachments[0].content.type 'Teams: card type'
    Assert-True ($teams.attachments[0].content.body[0].text -match '0 critical, 1 warning \(2 domains\)') 'Teams: title counts'
    Assert-True (@($teams.attachments[0].content.body | Where-Object { $_.type -eq 'ColumnSet' }).Count -ge 1) 'Teams: one row per finding'

    $slack = New-WebhookPayload -Url 'https://hooks.slack.com/services/T/B/X' -Results $run.Results -ReportPath 'C:\r.html' | ConvertFrom-Json
    Assert-True ($slack.text -match '^\*Client domain check: 0 critical, 1 warning') 'Slack: title'
    Assert-True ($slack.text -match ':large_yellow_circle: Beta LLC \(beta.test\): SPF record changed') 'Slack: finding line'
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host ("{0} passed, {1} failed  (PowerShell {2} {3})" -f $script:Passed, $script:Failed, $PSVersionTable.PSVersion, $PSVersionTable.PSEdition)
if ($script:Failed -gt 0) { exit 1 }
exit 0
