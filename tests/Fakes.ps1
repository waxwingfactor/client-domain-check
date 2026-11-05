# Test doubles for Test-ClientDomains.ps1: replace DNS, RDAP and TLS lookups with fixtures.
# Dot-source the main script first, then this file.

$script:NetworkCalls = New-Object System.Collections.Generic.List[string]
$script:FakeHttpCalls = New-Object System.Collections.Generic.List[string]
$script:Posts = New-Object System.Collections.Generic.List[object]

# Fake HTTP responses by host name: a pscustomobject (StatusCode, Body, Error) or a
# scriptblock that receives the URI. By default both DNS-over-HTTPS resolvers answer the
# start-of-run reachability probe, and everything else is "network disabled".
$script:FakeHttp = @{}
function New-DohAnswer {
    param([int]$Status = 0)
    [pscustomobject]@{ StatusCode = 200; Body = ('{"Status":' + $Status + ',"Answer":[{"name":"example.com.","type":1,"TTL":300,"data":"192.0.2.1"}]}'); Error = $null }
}
function Reset-FakeHttp {
    $script:FakeHttp = @{}
    $probe = { param($Uri) if ($Uri -match ('[?&]name=' + [regex]::Escape($script:DohProbeName) + '&')) { New-DohAnswer } else { $null } }
    $script:FakeHttp['cloudflare-dns.com'] = $probe
    $script:FakeHttp['dns.google'] = $probe
    $script:FakeHttpCalls.Clear()
}
Reset-FakeHttp

function Invoke-HttpGet {
    param([string]$Uri, [string]$Accept)
    $hostName = ([Uri]$Uri).Host
    if ($script:FakeHttp.ContainsKey($hostName)) {
        $fake = $script:FakeHttp[$hostName]
        if ($fake -is [scriptblock]) { $fake = & $fake $Uri }
        if ($null -ne $fake) { $script:FakeHttpCalls.Add($Uri) | Out-Null; return $fake }
    }
    $script:NetworkCalls.Add($Uri) | Out-Null
    [pscustomobject]@{ StatusCode = 0; Body = $null; Error = 'network disabled in offline tests' }
}
function Invoke-HttpPostJson {
    param([string]$Uri, [string]$Json)
    $script:Posts.Add([pscustomobject]@{ Uri = $Uri; Json = $Json }) | Out-Null
    [pscustomobject]@{ StatusCode = 200; Body = 'ok'; Error = $null }
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

