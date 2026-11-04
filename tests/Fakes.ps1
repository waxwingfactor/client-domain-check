# Test doubles for Test-ClientDomains.ps1: replace DNS, RDAP and TLS lookups with fixtures.
# Dot-source the main script first, then this file.

$script:NetworkCalls = New-Object System.Collections.Generic.List[string]
function Invoke-HttpGet {
    param([string]$Uri, [string]$Accept)
    $script:NetworkCalls.Add($Uri) | Out-Null
    [pscustomobject]@{ StatusCode = 0; Body = $null; Error = 'network disabled in offline tests' }
}

function Set-Dns {
    param([string]$Name, [string]$Type, [string[]]$Records = @(), [int]$Status = 0, [string[]]$Cnames = @())
    $script:DnsCache[("{0}|{1}" -f $Name, $Type).ToLowerInvariant()] = [pscustomobject]@{
        Name = $Name; Type = $Type; Ok = $true; Status = $Status; Records = $Records; Cnames = $Cnames; Error = $null
    }
}
function Set-DnsError {
    param([string]$Name, [string]$Type, [int]$Status = 2)
    $script:DnsCache[("{0}|{1}" -f $Name, $Type).ToLowerInvariant()] = [pscustomobject]@{
        Name = $Name; Type = $Type; Ok = $false; Status = $Status; Records = @(); Cnames = @(); Error = 'DNS lookup returned SERVFAIL'
    }
}

$script:FakeRegistration = @{}
function Get-Registration {
    param([string]$DomainName)
    if ($script:FakeRegistration.ContainsKey($DomainName)) { return $script:FakeRegistration[$DomainName] }
    [pscustomobject]@{ Supported = $true; Found = $true; Expires = [DateTime]::UtcNow.AddDays(200); Registrar = 'Example Registrar'; Statuses = @('client transfer prohibited'); Error = $null }
}

$script:FakeCerts = @{}
function Get-TlsCertificateInfo {
    param([string]$HostName, [int]$Port = 443, [int]$TimeoutMs = 8000)
    $key = "${HostName}:$Port"
    if ($script:FakeCerts.ContainsKey($key)) { return $script:FakeCerts[$key] }
    New-FakeCert -HostName $HostName -Port $Port -Days 60
}
function New-FakeCert {
    param([string]$HostName, [int]$Port = 443, [int]$Days = 60, [int]$Lifetime = 90, [string]$Issuer = 'Test CA', [switch]$Mismatch, [string]$Chain, [string]$ConnectError)
    if ($ConnectError) {
        return [pscustomobject]@{ Host = $HostName; Port = $Port; Connected = $false; Error = $ConnectError; NotAfter = $null; DaysLeft = $null; LifetimeDays = $null; Issuer = $null; Subject = $null; NameMismatch = $false; ChainProblem = $null }
    }
    $notAfter = [DateTime]::UtcNow.AddDays($Days).AddHours(1)
    [pscustomobject]@{ Host = $HostName; Port = $Port; Connected = $true; Error = $null; NotAfter = $notAfter; DaysLeft = (Get-DaysLeft $notAfter); LifetimeDays = $Lifetime; Issuer = $Issuer; Subject = 'other.example'; NameMismatch = [bool]$Mismatch; ChainProblem = $(if ($Chain) { $Chain } else { $null }) }
}

function New-FakeDomain {
    # A healthy Google Workspace domain unless overridden afterwards.
    param([string]$Name)
    Set-Dns $Name 'NS' @('ns1.domaincontrol.com', 'ns2.domaincontrol.com')
    Set-Dns $Name 'A' @('192.0.2.10')
    Set-Dns $Name 'MX' @('1 aspmx.l.google.com', '5 alt1.aspmx.l.google.com')
    Set-Dns $Name 'TXT' @('v=spf1 include:_spf.google.com ~all', 'google-site-verification=abc')
    Set-Dns '_spf.google.com' 'TXT' @('v=spf1 ip4:192.0.2.0/24 ~all')
    Set-Dns "_dmarc.$Name" 'TXT' @('v=DMARC1; p=reject; rua=mailto:dmarc@example.net')
    foreach ($s in $DkimSelectors) { Set-Dns "$s._domainkey.$Name" 'TXT' @() -Status 3 }
    Set-Dns "google._domainkey.$Name" 'TXT' @('v=DKIM1; k=rsa; p=MIIBIjANBgkq')
}
function New-Entry {
    param([string]$Name, [string]$Client = 'Test Client', $CertHosts = @())
    [pscustomobject]@{ Client = $Client; Domain = $Name; Raw = $Name; CertHosts = @($CertHosts) }
}

