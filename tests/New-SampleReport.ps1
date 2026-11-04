# Builds the sample report shown in the README from fictional clients (.example domains,
# fixture data, no network). Usage: pwsh ./tests/New-SampleReport.ps1 -Destination ./sample
param([string]$Destination = (Join-Path ([IO.Path]::GetTempPath()) 'cdc-sample'))
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'Test-ClientDomains.ps1')
. (Join-Path $PSScriptRoot 'Fakes.ps1')

function Set-Registration {
    param([string]$Name, [double]$Days, [string]$Registrar = 'Example Registrar', [string[]]$Statuses = @('client transfer prohibited'))
    $script:FakeRegistration[$Name] = [pscustomobject]@{ Supported = $true; Found = $true; Expires = [DateTime]::UtcNow.AddDays($Days); Registrar = $Registrar; Statuses = $Statuses; Error = $null }
}
function Use-Microsoft365 {
    param([string]$Name, [switch]$NoDkim)
    Set-Dns $Name 'MX' @("0 $($Name -replace '\.', '-').mail.protection.outlook.com")
    Set-Dns $Name 'TXT' @('v=spf1 include:spf.protection.outlook.com -all', 'MS=ms12345678')
    Set-Dns "google._domainkey.$Name" 'TXT' @() -Status 3
    if (-not $NoDkim) { Set-Dns "selector1._domainkey.$Name" 'TXT' @('v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3') -Cnames @("selector1-x._domainkey.tenant.onmicrosoft.com") }
}
Set-Dns 'spf.protection.outlook.com' 'TXT' @('v=spf1 ip4:40.92.0.0/15 ip4:40.107.0.0/16 -all')
foreach ($vendor in @('sendgrid.net', 'servers.mcsv.net', 'mail.zendesk.com', 'spf.mandrillapp.com', 'mktomail.com', 'spf.constantcontact.com', '_spf.salesforce.com', 'spf.quickbooks.example', 'spf.dentrix.example')) {
    Set-Dns $vendor 'TXT' @('v=spf1 ip4:192.0.2.0/24 ~all')
}
Set-Dns 'spf.legacyhost.example' 'TXT' @('v=spf1 a mx include:spf.relay.example ~all')
Set-Dns 'spf.relay.example' 'TXT' @('v=spf1 ip4:198.51.100.0/24 ~all')

# Birch & Vale Law: registration about to lapse, Microsoft 365 without DKIM
New-FakeDomain 'birchvale.example'
Use-Microsoft365 'birchvale.example' -NoDkim
Set-Registration 'birchvale.example' 4.4 'GoDaddy.com, LLC'

# Harbor Dental: SPF over the 10-lookup limit, RD Gateway certificate expiring
New-FakeDomain 'harbordental.example'
Use-Microsoft365 'harbordental.example'
Set-Dns 'harbordental.example' 'TXT' @('v=spf1 include:spf.protection.outlook.com include:sendgrid.net include:servers.mcsv.net include:mail.zendesk.com include:spf.mandrillapp.com include:mktomail.com include:spf.constantcontact.com include:_spf.salesforce.com include:spf.dentrix.example include:spf.legacyhost.example -all')
$script:FakeCerts['remote.harbordental.example:443'] = New-FakeCert -HostName 'remote.harbordental.example' -Days 9 -Lifetime 365

# Oakridge Builders: website certificate renewal stuck
New-FakeDomain 'oakridgebuilds.example'
$script:FakeCerts['oakridgebuilds.example:443'] = New-FakeCert -HostName 'oakridgebuilds.example' -Days 5

# Northline Logistics: MX moved since yesterday (Google -> Microsoft 365)
New-FakeDomain 'northline.example'
$northlinePrevious = @{ NS = 'ns1.domaincontrol.com, ns2.domaincontrol.com'; MX = '1 aspmx.l.google.com, 5 alt1.aspmx.l.google.com'; SPF = 'v=spf1 include:_spf.google.com ~all'; DMARC = 'v=DMARC1; p=reject; rua=mailto:dmarc@example.net'; Registrar = 'Tucows Domains Inc.'; _checked = (Get-Date).AddDays(-1).ToString('yyyy-MM-dd 07:00') }
Use-Microsoft365 'northline.example'
Set-Dns 'northline.example' 'TXT' @('v=spf1 include:_spf.google.com ~all')

# Cedar Creek Vet: no DMARC
New-FakeDomain 'cedarcreekvet.example'
Set-Dns '_dmarc.cedarcreekvet.example' 'TXT' @() -Status 3

# Healthy ones
New-FakeDomain 'summitcpa.example'
Set-Dns '_dmarc.summitcpa.example' 'TXT' @('v=DMARC1; p=none; rua=mailto:dmarc@summitcpa.example')
New-FakeDomain 'maplestreet.example'
Set-Dns 'maplestreet.example' 'NS' @('ana.ns.cloudflare.com', 'bob.ns.cloudflare.com')
New-FakeDomain 'pinecrestclinic.example'
Use-Microsoft365 'pinecrestclinic.example'
$script:FakeCerts['vpn.pinecrestclinic.example:4443'] = New-FakeCert -HostName 'vpn.pinecrestclinic.example' -Port 4443 -Days 140 -Lifetime 397
New-FakeDomain 'birchvalelaw.example'
Set-Dns 'birchvalelaw.example' 'MX' @('0 .')
Set-Dns 'birchvalelaw.example' 'TXT' @('v=spf1 -all')

$OutputFolder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Destination)
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
$listPath = Join-Path $OutputFolder 'sample-domains.csv'
Set-Content -LiteralPath $listPath -Value @(
    'Client,Domain,CertHosts',
    'Birch & Vale Law,birchvale.example,',
    'Birch & Vale Law,birchvalelaw.example,',
    'Harbor Dental Group,harbordental.example,remote.harbordental.example',
    'Oakridge Builders,oakridgebuilds.example,',
    'Northline Logistics,northline.example,',
    'Cedar Creek Vet,cedarcreekvet.example,',
    'Summit Accounting,summitcpa.example,',
    'Maple Street Bakery,maplestreet.example,',
    'Pinecrest Clinic,pinecrestclinic.example,vpn.pinecrestclinic.example:4443'
)
$state = [ordered]@{ tool = 'client-domain-check'; version = 1; domains = @{ 'northline.example' = $northlinePrevious } }
[IO.File]::WriteAllText((Join-Path $OutputFolder 'domain-check-state.json'), (ConvertTo-Json -InputObject $state -Depth 5))

# Vary the healthy details so the sample reads like a real client list
$details = @{
    'birchvale.example'       = @(0, 'GoDaddy.com, LLC', 71, "Let's Encrypt")
    'birchvalelaw.example'    = @(212, 'GoDaddy.com, LLC', 58, "Let's Encrypt")
    'harbordental.example'    = @(301, 'Network Solutions, LLC', 233, 'Sectigo Limited')
    'oakridgebuilds.example'  = @(97, 'NameCheap, Inc.', 5, "Let's Encrypt")
    'northline.example'       = @(164, 'Tucows Domains Inc.', 49, 'Google Trust Services')
    'cedarcreekvet.example'   = @(388, 'GoDaddy.com, LLC', 76, 'DigiCert Inc')
    'summitcpa.example'       = @(126, 'Cloudflare, Inc.', 63, 'Google Trust Services')
    'maplestreet.example'     = @(519, 'Cloudflare, Inc.', 81, 'Google Trust Services')
    'pinecrestclinic.example' = @(243, 'Network Solutions, LLC', 302, 'DigiCert Inc')
}
foreach ($name in $details.Keys) {
    $d = $details[$name]
    if ($d[0] -gt 0) { Set-Registration $name ($d[0] + 0.4) $d[1] }
    if (-not $script:FakeCerts.ContainsKey("${name}:443")) { $script:FakeCerts["${name}:443"] = New-FakeCert -HostName $name -Days $d[2] -Issuer $d[3] }
    else { $script:FakeCerts["${name}:443"].Issuer = $d[3] }
}
$script:FakeCerts['remote.harbordental.example:443'].Issuer = 'Sectigo Limited'

$InputFile = $listPath
$run = Invoke-ClientDomainCheck
Write-Host "Sample report: $($run.ReportPath)"
