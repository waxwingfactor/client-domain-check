<#
.SYNOPSIS
    Daily health check for your clients' domains: expiry, certificates, email
    authentication and DNS changes, in one report.

.DESCRIPTION
    For every domain in your list, this script checks:

      - Domain registration: expiry date, registrar, and risky registry statuses
        (pending delete, redemption, hold, auto-renew grace, transfer in progress).
      - Website certificate: days left, trust and name errors. Checks the domain
        itself, or www. if the domain has no website.
      - Any extra hosts you list, such as RD Gateway, VPN portals or on-prem Exchange.
      - Email: mail provider, SPF (including the 10-lookup limit and broken includes),
        DMARC policy and reporting, and DKIM keys at common selectors.
      - Changes to nameservers, MX, SPF, DMARC or registrar since the last run.

    It writes an HTML report and a CSV, can post a summary to Microsoft Teams or
    Slack, and exits with 0 (all clear), 1 (warnings) or 2 (critical) so an RMM or
    Task Scheduler can alert on it.

    Read-only. It sends DNS queries over HTTPS (Cloudflare by default), queries the
    registries' public RDAP servers, and opens a TLS connection to each website.
    It needs no credentials, modules or admin rights, and runs in Windows
    PowerShell 5.1 and PowerShell 7+.

.PARAMETER InputFile
    A CSV with the columns Client, Domain and (optional) CertHosts, or a text file
    with one domain per line. CertHosts takes extra host names separated by
    semicolons, with an optional port: "remote.contoso.com; vpn.contoso.com:4443".
    Default: domains.csv in the script's folder.

.PARAMETER Domain
    Check these domains instead of reading a file. From cmd.exe, Task Scheduler or an RMM,
    pass them as one quoted, comma-separated value: -Domain "contoso.com,fabrikam.com"

.PARAMETER OutputFolder
    Where the reports and the change-tracking state file go.
    Default: a "reports" folder next to the script.

.PARAMETER WebhookUrl
    Optional Teams (Workflows) or Slack incoming webhook URL. A summary is posted
    only when something needs attention, unless -NotifyAlways is set.

.PARAMETER Open
    Open the HTML report when finished.

.EXAMPLE
    .\Test-ClientDomains.ps1 -Open

.EXAMPLE
    .\Test-ClientDomains.ps1 -Domain contoso.com, fabrikam.com -Open

.EXAMPLE
    .\Test-ClientDomains.ps1 -InputFile C:\ProgramData\DomainCheck\domains.csv `
        -OutputFolder C:\ProgramData\DomainCheck\reports -WebhookUrl $TeamsUrl

.NOTES
    client-domain-check by Waxwing Factory. MIT licensed.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$InputFile,
    [string[]]$Domain,
    [string]$OutputFolder,
    [string]$WebhookUrl,
    [switch]$NotifyAlways,
    [switch]$Open,
    [ValidateSet('Cloudflare', 'Google')]
    [string]$DnsResolver = 'Cloudflare',
    [ValidateRange(1, 365)][int]$DomainWarnDays = 30,
    [ValidateRange(0, 365)][int]$DomainCriticalDays = 7,
    [ValidateRange(1, 365)][int]$CertWarnDays = 14,
    [ValidateRange(0, 365)][int]$CertCriticalDays = 7,
    [string[]]$DkimSelectors = @('selector1', 'selector2', 'google', 'default', 'k1', 's1', 's2'),
    [switch]$PassThru
)

$ScriptVersion = '1.0.0'
$script:DnsCache = @{}
$script:RdapBootstrap = $null
$script:RdapBootstrapError = $null
$script:Http = $null
$script:TlsProtocols = $null

# ---------------------------------------------------------------- helpers

function Get-InnermostMessage {
    param($Exception)
    $e = $Exception
    while ($e.InnerException) { $e = $e.InnerException }
    $msg = [string]$e.Message
    if ($e -is [System.Threading.Tasks.TaskCanceledException] -or $e -is [System.TimeoutException]) { $msg = 'timed out' }
    $msg.Trim()
}

function New-Finding {
    param([ValidateSet('Critical', 'Warning', 'Info')][string]$Level, [string]$Area, [string]$Message)
    [pscustomobject]@{ Level = $Level; Area = $Area; Message = $Message }
}

function Get-LevelRank {
    param([string]$Level)
    switch ($Level) { 'Critical' { 3 } 'Warning' { 2 } 'Info' { 1 } default { 0 } }
}

function Format-Date {
    param($Date)
    if ($null -eq $Date) { return '' }
    $Date.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
}

function Get-DaysLeft {
    param($Date)
    if ($null -eq $Date) { return $null }
    [int][Math]::Floor(($Date - [DateTime]::UtcNow).TotalDays)
}

function Format-DaysCell {
    param($Days)
    if ($null -eq $Days -or '' -eq $Days) { return '-' }
    $Days = [int]$Days   # Windows PowerShell 5.1 can pass "-5" as a string
    if ($Days -lt 0) { return 'expired' }
    if ($Days -eq 1) { return '1 day' }
    "$Days days"
}

function Format-DaysPhrase {
    param([int]$Days)
    if ($Days -lt 0) { return ("expired {0} day{1} ago" -f (-$Days), $(if ($Days -eq -1) { '' } else { 's' })) }
    if ($Days -eq 0) { return 'expires within 24 hours' }
    "expires in $Days day$(if ($Days -eq 1) { '' } else { 's' })"
}

function ConvertTo-UtcDate {
    param($Value)
    if ($null -eq $Value -or '' -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [DateTime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    $parsed = [DateTimeOffset]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal
    if ([DateTimeOffset]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed.UtcDateTime
    }
    $null
}

function Limit-Text {
    param([string]$Text, [int]$Max = 160)
    if ($null -eq $Text) { return '' }
    if ($Text.Length -le $Max) { return $Text }
    $Text.Substring(0, $Max - 3) + '...'
}

function ConvertTo-DomainName {
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    $v = $Value.Trim().ToLowerInvariant()
    $v = $v -replace '^[a-z][a-z0-9+.-]*://', ''
    $v = ($v -split '[/?#]', 2)[0]
    $v = $v -replace '^[^@]*@', ''
    $v = $v -replace ':\d+$', ''
    $v = $v.Trim().TrimEnd('.')
    if ($v -match '[^\x00-\x7F]') {
        try { $v = (New-Object System.Globalization.IdnMapping).GetAscii($v) } catch { }
    }
    $v
}

function Test-DomainName {
    param([string]$Name)
    $Name -match '^(?=.{4,253}$)([a-z0-9_]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$'
}

function ConvertTo-HostEntry {
    param([string]$Value)
    $v = $Value.Trim().ToLowerInvariant() -replace '^[a-z][a-z0-9+.-]*://', ''
    $v = ($v -split '[/?#]', 2)[0]
    $port = 443
    if ($v -match '^(.+):(\d{1,5})$') { $v = $Matches[1]; $port = [int]$Matches[2] }
    $v = $v.TrimEnd('.')
    if (-not $v) { return $null }
    [pscustomobject]@{ Host = $v; Port = $port }
}

# ---------------------------------------------------------------- HTTP

function Initialize-Http {
    if ($PSVersionTable.PSEdition -ne 'Core') {
        # Windows PowerShell 5.1 does not offer TLS 1.2 by default on every system.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $script:TlsProtocols = [System.Security.Authentication.SslProtocols]::Tls12
    }
    else {
        $script:TlsProtocols = [System.Security.Authentication.SslProtocols]::None   # let the OS choose
    }
    Add-Type -AssemblyName System.Net.Http
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(20)
    [void]$client.DefaultRequestHeaders.TryAddWithoutValidation('User-Agent', "client-domain-check/$ScriptVersion (PowerShell)")
    $script:Http = $client
}

function Invoke-HttpGet {
    param([string]$Uri, [string]$Accept = 'application/json')
    $attempt = 0
    while ($true) {
        $attempt++
        $request = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $Uri)
        [void]$request.Headers.TryAddWithoutValidation('Accept', $Accept)
        $result = $null
        $retryAfter = 0
        try {
            $response = $script:Http.SendAsync($request).GetAwaiter().GetResult()
            $code = [int]$response.StatusCode
            $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if (($code -eq 429 -or $code -ge 500) -and $attempt -lt 3) {
                $retryAfter = 2 * $attempt
                if ($response.Headers.RetryAfter -and $response.Headers.RetryAfter.Delta) {
                    $retryAfter = [Math]::Max(1, [Math]::Min(30, [int]$response.Headers.RetryAfter.Delta.Value.TotalSeconds))
                }
            }
            else {
                $result = [pscustomobject]@{ StatusCode = $code; Body = $body; Error = $null }
            }
        }
        catch {
            if ($attempt -lt 3) { $retryAfter = $attempt }
            else { $result = [pscustomobject]@{ StatusCode = 0; Body = $null; Error = (Get-InnermostMessage $_.Exception) } }
        }
        finally { $request.Dispose() }
        if ($result) { return $result }
        Start-Sleep -Seconds $retryAfter
    }
}

function Invoke-HttpPostJson {
    param([string]$Uri, [string]$Json)
    $content = New-Object System.Net.Http.StringContent($Json, [System.Text.Encoding]::UTF8, 'application/json')
    try {
        $response = $script:Http.PostAsync($Uri, $content).GetAwaiter().GetResult()
        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        [pscustomobject]@{ StatusCode = [int]$response.StatusCode; Body = $body; Error = $null }
    }
    catch { [pscustomobject]@{ StatusCode = 0; Body = $null; Error = (Get-InnermostMessage $_.Exception) } }
    finally { $content.Dispose() }
}

# ---------------------------------------------------------------- DNS over HTTPS

function ConvertFrom-TxtData {
    # DoH JSON returns TXT data as one or more quoted strings: "v=spf1 a " "-all"
    param([string]$Data)
    if ($null -eq $Data) { return '' }
    if ($Data -notmatch '^\s*"') { return $Data }
    $sb = New-Object System.Text.StringBuilder
    $inQuote = $false
    $i = 0
    while ($i -lt $Data.Length) {
        $c = $Data[$i]
        if ($inQuote) {
            if ($c -eq [char]'\' -and ($i + 1) -lt $Data.Length) {
                if (($i + 3) -lt $Data.Length -and $Data.Substring($i + 1, 3) -match '^\d{3}$') {
                    [void]$sb.Append([char][int]$Data.Substring($i + 1, 3))
                    $i += 4
                    continue
                }
                [void]$sb.Append($Data[$i + 1])
                $i += 2
                continue
            }
            if ($c -eq [char]'"') { $inQuote = $false }
            else { [void]$sb.Append($c) }
        }
        elseif ($c -eq [char]'"') { $inQuote = $true }
        $i++
    }
    $sb.ToString()
}

function Get-RcodeName {
    param([int]$Code)
    switch ($Code) { 0 { 'NOERROR' } 1 { 'FORMERR' } 2 { 'SERVFAIL' } 3 { 'NXDOMAIN' } 5 { 'REFUSED' } default { "RCODE $Code" } }
}

function Resolve-Doh {
    param(
        [string]$Name,
        [ValidateSet('A', 'AAAA', 'NS', 'CNAME', 'MX', 'TXT')][string]$Type
    )
    $key = ("{0}|{1}" -f $Name, $Type).ToLowerInvariant()
    if ($script:DnsCache.ContainsKey($key)) { return $script:DnsCache[$key] }

    $typeNumber = @{ A = 1; NS = 2; CNAME = 5; MX = 15; TXT = 16; AAAA = 28 }[$Type]
    $escaped = [Uri]::EscapeDataString($Name)
    if ($DnsResolver -eq 'Google') { $uri = "https://dns.google/resolve?name=$escaped&type=$Type" }
    else { $uri = "https://cloudflare-dns.com/dns-query?name=$escaped&type=$Type" }

    $result = [pscustomobject]@{ Name = $Name; Type = $Type; Ok = $false; Status = $null; Records = @(); Cnames = @(); Error = $null }
    for ($try = 1; $try -le 2; $try++) {
        $response = Invoke-HttpGet -Uri $uri -Accept 'application/dns-json'
        if ($response.Error) { $result.Error = "DNS query failed: $($response.Error)"; continue }
        if ($response.StatusCode -ne 200) { $result.Error = "DNS query failed: HTTP $($response.StatusCode)"; continue }
        try { $json = $response.Body | ConvertFrom-Json }
        catch { $result.Error = 'DNS query failed: unreadable response'; continue }
        $result.Status = [int]$json.Status
        if ($result.Status -ne 0 -and $result.Status -ne 3) {
            $result.Error = "DNS lookup returned $(Get-RcodeName $result.Status)"
            continue
        }
        $answers = @()
        if ($json.PSObject.Properties['Answer']) { $answers = @($json.Answer) }
        $records = New-Object System.Collections.Generic.List[string]
        $cnames = New-Object System.Collections.Generic.List[string]
        foreach ($a in $answers) {
            if ($null -eq $a) { continue }
            if ([int]$a.type -eq $typeNumber) {
                if ($Type -eq 'TXT') { $records.Add((ConvertFrom-TxtData ([string]$a.data))) }
                else { $records.Add(([string]$a.data).Trim().TrimEnd('.').ToLowerInvariant()) }
            }
            elseif ([int]$a.type -eq 5) { $cnames.Add(([string]$a.data).Trim().TrimEnd('.').ToLowerInvariant()) }
        }
        $result.Records = $records.ToArray()
        $result.Cnames = $cnames.ToArray()
        $result.Ok = $true
        $result.Error = $null
        break
    }
    $script:DnsCache[$key] = $result
    $result
}

function Test-HasAddress {
    param([string]$Name)
    $a = Resolve-Doh -Name $Name -Type 'A'
    if ($a.Ok -and $a.Records.Count -gt 0) { return $true }
    $aaaa = Resolve-Doh -Name $Name -Type 'AAAA'
    ($aaaa.Ok -and $aaaa.Records.Count -gt 0)
}

# ---------------------------------------------------------------- RDAP (registration)

function Get-RdapBaseUrl {
    param([string]$Tld)
    if ($null -eq $script:RdapBootstrap) {
        $script:RdapBootstrap = @{}
        $response = Invoke-HttpGet -Uri 'https://data.iana.org/rdap/dns.json'
        if ($response.StatusCode -eq 200) {
            $json = $response.Body | ConvertFrom-Json
            foreach ($service in $json.services) {
                $urls = @($service[1])
                $url = @($urls | Where-Object { ([string]$_).StartsWith('https://') }) | Select-Object -First 1
                if (-not $url) { $url = $urls[0] }
                foreach ($t in @($service[0])) { $script:RdapBootstrap[([string]$t).ToLowerInvariant()] = [string]$url }
            }
        }
        else {
            $script:RdapBootstrapError = "Couldn't load the IANA RDAP directory ($(if ($response.Error) { $response.Error } else { 'HTTP ' + $response.StatusCode }))"
        }
    }
    $script:RdapBootstrap[$Tld.ToLowerInvariant()]
}

function Get-VcardName {
    param($Entity)
    if (-not $Entity -or -not $Entity.PSObject.Properties['vcardArray']) { return $null }
    $card = @($Entity.vcardArray)
    if ($card.Count -lt 2) { return $null }
    foreach ($property in @($card[1])) {
        $p = @($property)
        if ($p.Count -ge 4 -and [string]$p[0] -eq 'fn') { return [string]$p[3] }
    }
    $null
}

function Get-Registration {
    param([string]$DomainName)
    $info = [pscustomobject]@{ Supported = $true; Found = $null; Expires = $null; Registrar = $null; Statuses = @(); Error = $null }
    $tld = ($DomainName -split '\.')[-1]
    $base = Get-RdapBaseUrl -Tld $tld
    if (-not $base) {
        if ($script:RdapBootstrapError) { $info.Error = $script:RdapBootstrapError }
        else { $info.Supported = $false }
        return $info
    }
    if (-not $base.EndsWith('/')) { $base += '/' }
    $response = Invoke-HttpGet -Uri ($base + 'domain/' + $DomainName) -Accept 'application/rdap+json, application/json'
    if ($response.StatusCode -eq 404) { $info.Found = $false; return $info }
    if ($response.StatusCode -ne 200) {
        $info.Error = "registry lookup failed ($(if ($response.Error) { $response.Error } else { 'HTTP ' + $response.StatusCode }))"
        return $info
    }
    try { $json = $response.Body | ConvertFrom-Json }
    catch { $info.Error = 'registry returned an unreadable response'; return $info }
    $info.Found = $true
    if ($json.PSObject.Properties['events']) {
        foreach ($event in @($json.events)) {
            if ($event -and [string]$event.eventAction -eq 'expiration') { $info.Expires = ConvertTo-UtcDate $event.eventDate }
        }
    }
    if ($json.PSObject.Properties['status']) {
        $info.Statuses = @(@($json.status) | ForEach-Object { ([string]$_).ToLowerInvariant() })
    }
    if ($json.PSObject.Properties['entities']) {
        foreach ($entity in @($json.entities)) {
            if ($entity -and $entity.PSObject.Properties['roles'] -and (@($entity.roles) -contains 'registrar')) {
                $info.Registrar = Get-VcardName $entity
            }
        }
    }
    $info
}

# ---------------------------------------------------------------- TLS certificates

function Get-TlsCertificateInfo {
    param([string]$HostName, [int]$Port = 443, [int]$TimeoutMs = 8000)
    $info = [pscustomobject]@{
        Host = $HostName; Port = $Port; Connected = $false; Error = $null
        NotAfter = $null; DaysLeft = $null; LifetimeDays = $null; Issuer = $null; Subject = $null
        NameMismatch = $false; ChainProblem = $null
    }
    $tcp = New-Object System.Net.Sockets.TcpClient
    $ssl = $null
    try {
        $connect = $tcp.BeginConnect($HostName, $Port, $null, $null)
        if (-not $connect.AsyncWaitHandle.WaitOne($TimeoutMs)) { throw (New-Object System.TimeoutException('connection timed out')) }
        $tcp.EndConnect($connect)
        $tcp.ReceiveTimeout = $TimeoutMs
        $tcp.SendTimeout = $TimeoutMs

        # Accept any certificate so it can be inspected, but remember what was wrong with it.
        $seen = @{ Errors = [System.Net.Security.SslPolicyErrors]::None; Chain = @() }
        $callback = {
            param($sender, $certificate, $chain, $sslPolicyErrors)
            $seen.Errors = $sslPolicyErrors
            if ($chain) {
                $seen.Chain = @($chain.ChainStatus | ForEach-Object { ([string]$_.StatusInformation).Trim() } | Where-Object { $_ })
            }
            $true
        }.GetNewClosure()
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, ([System.Net.Security.RemoteCertificateValidationCallback]$callback))
        $ssl.AuthenticateAsClient($HostName, $null, $script:TlsProtocols, $false)
        $info.Connected = $true

        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $info.NotAfter = $cert.NotAfter.ToUniversalTime()
        $info.DaysLeft = Get-DaysLeft $info.NotAfter
        $info.LifetimeDays = [int][Math]::Round(($cert.NotAfter - $cert.NotBefore).TotalDays)
        $info.Subject = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        $issuer = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
        if ($cert.Issuer -match '(?:^|,\s*)O="?([^",]+)') { $issuer = $Matches[1].Trim() }
        $info.Issuer = $issuer

        $errors = $seen.Errors
        if (($errors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch) -ne 0) { $info.NameMismatch = $true }
        if (($errors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors) -ne 0) {
            $reasons = @($seen.Chain | Select-Object -Unique)
            if ($reasons.Count -gt 0) { $info.ChainProblem = ($reasons -join '; ') } else { $info.ChainProblem = 'certificate chain is not trusted' }
        }
        $cert.Dispose()
    }
    catch {
        $info.Error = Get-InnermostMessage $_.Exception
    }
    finally {
        if ($ssl) { $ssl.Dispose() }
        $tcp.Close()
    }
    $info
}

function Add-CertificateFindings {
    param($Findings, $Cert, [string]$Area, [string]$Label)
    if (-not $Cert.Connected) { return }
    $days = $Cert.DaysLeft
    $when = Format-Date $Cert.NotAfter
    $criticalDays = $CertCriticalDays
    $warnDays = $CertWarnDays
    if ($Cert.LifetimeDays -and $Cert.LifetimeDays -le 30) {
        # Short-lived certificates (6-day, 30-day) always have few days left; only flag a stalled renewal.
        $criticalDays = 0
        $warnDays = [int][Math]::Floor($Cert.LifetimeDays / 6)
    }
    if ($days -lt 0) {
        $Findings.Add((New-Finding 'Critical' $Area "$Label certificate expired on $when ($((Format-DaysPhrase $days))).")) | Out-Null
    }
    elseif ($days -le $criticalDays) {
        $Findings.Add((New-Finding 'Critical' $Area "$Label certificate $(Format-DaysPhrase $days) ($when). Renewal looks stuck.")) | Out-Null
    }
    elseif ($days -le $warnDays) {
        $Findings.Add((New-Finding 'Warning' $Area "$Label certificate $(Format-DaysPhrase $days) ($when). Check that auto-renewal is working.")) | Out-Null
    }
    if ($Cert.NameMismatch) {
        $Findings.Add((New-Finding 'Warning' $Area "$Label certificate doesn't cover $($Cert.Host) (it's issued to $($Cert.Subject)). Browsers will show a warning.")) | Out-Null
    }
    if ($Cert.ChainProblem -and $days -ge 0) {
        $Findings.Add((New-Finding 'Warning' $Area "$Label certificate isn't trusted: $(Limit-Text $Cert.ChainProblem 140)")) | Out-Null
    }
}

# ---------------------------------------------------------------- email: providers, SPF, DMARC, DKIM

function Get-BaseDomain {
    # Rough registered-domain guess for display only: ns1.bbc.co.uk -> bbc.co.uk, ns1.host.com -> host.com
    param([string]$HostName)
    $labels = @($HostName -split '\.' | Where-Object { $_ })
    if ($labels.Count -lt 2) { return $HostName }
    $take = 2
    if ($labels.Count -ge 3 -and $labels[-1].Length -eq 2 -and @('co', 'com', 'net', 'org', 'gov', 'ac', 'edu', 'ltd', 'plc', 'or', 'ne', 'gv') -contains $labels[-2]) { $take = 3 }
    ($labels[(-$take)..-1] -join '.')
}

function Get-ProviderName {
    param([string[]]$HostNames, [System.Collections.IDictionary]$Map)
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($h in $HostNames) {
        $match = $null
        foreach ($suffix in $Map.Keys) {
            if ($h -eq $suffix -or $h.EndsWith('.' + $suffix)) { $match = $Map[$suffix]; break }
        }
        if (-not $match) { $match = Get-BaseDomain $h }
        if (-not $names.Contains($match)) { $names.Add($match) }
    }
    ($names.ToArray() -join ', ')
}

$script:MailProviders = [ordered]@{
    'mail.protection.outlook.com' = 'Microsoft 365'
    'mx.microsoft'                = 'Microsoft 365'
    'google.com'                  = 'Google Workspace'
    'googlemail.com'              = 'Google Workspace'
    'pphosted.com'                = 'Proofpoint'
    'ppe-hosted.com'              = 'Proofpoint Essentials'
    'mimecast.com'                = 'Mimecast'
    'mimecast.co.za'              = 'Mimecast'
    'barracudanetworks.com'       = 'Barracuda'
    'iphmx.com'                   = 'Cisco Secure Email'
    'messagelabs.com'             = 'Symantec Email Security'
    'hydra.sophos.com'            = 'Sophos Email'
    'secureserver.net'            = 'GoDaddy'
    'zoho.com'                    = 'Zoho Mail'
    'zoho.eu'                     = 'Zoho Mail'
    'emailsrvr.com'               = 'Rackspace'
    'protonmail.ch'               = 'Proton Mail'
    'icloud.com'                  = 'iCloud Mail'
    'mx.cloudflare.net'           = 'Cloudflare Email Routing'
}

$script:DnsProviders = [ordered]@{
    'ns.cloudflare.com'     = 'Cloudflare'
    'domaincontrol.com'     = 'GoDaddy'
    'registrar-servers.com' = 'Namecheap'
    'googledomains.com'     = 'Google Cloud DNS'
    'wixdns.net'            = 'Wix'
}

function Get-DnsHostName {
    param([string[]]$NameServers)
    if (@($NameServers | Where-Object { $_ -match 'awsdns-' }).Count -gt 0) { return 'AWS Route 53' }
    if (@($NameServers | Where-Object { $_ -match '\.azure-dns\.' }).Count -gt 0) { return 'Azure DNS' }
    Get-ProviderName -HostNames $NameServers -Map $script:DnsProviders
}

function Get-SpfRecords {
    param([string[]]$Records)
    @($Records | Where-Object { $_ -match '^\s*v=spf1(\s|$)' })
}

function Invoke-SpfWalk {
    # Counts DNS-querying terms the way RFC 7208 section 4.6.4 limits them,
    # following include: and redirect= into other domains.
    param([string]$DomainName, $Ctx, [string[]]$Path, [bool]$IsPolicyRoot)
    $key = $DomainName.ToLowerInvariant()
    if ($Path -contains $key) { $Ctx.Problems.Add("SPF include loop: $DomainName includes itself") | Out-Null; return 'ok' }
    if ($Path.Count -ge 10) { $Ctx.Problems.Add("SPF includes are nested more than 10 levels deep at $DomainName") | Out-Null; return 'ok' }

    $query = Resolve-Doh -Name $DomainName -Type 'TXT'
    if (-not $query.Ok) { $Ctx.Incomplete.Add($DomainName) | Out-Null; return 'error' }
    $spf = @(Get-SpfRecords $query.Records)
    if ($spf.Count -eq 0) { return 'none' }
    if ($spf.Count -gt 1) {
        $Ctx.Problems.Add("$DomainName publishes $($spf.Count) SPF records. Receivers treat that as an error (permerror); merge them into one.") | Out-Null
        return 'multiple'
    }
    $here = @($Path) + $key
    $terms = @($spf[0].Trim() -split '\s+' | Select-Object -Skip 1 | Where-Object { $_ })
    $redirect = $null
    $hasAll = $false
    foreach ($term in $terms) {
        $qualifier = '+'
        $body = $term
        if ($body -match '^[+\-~?]') { $qualifier = $body.Substring(0, 1); $body = $body.Substring(1) }
        if ($body -match '^([a-z][a-z0-9_.-]*)=(.*)$') {
            if ($Matches[1].ToLowerInvariant() -eq 'redirect') { $redirect = $Matches[2] }
            continue   # exp= and unknown modifiers don't count
        }
        $mechanism = ($body -split '[:/]', 2)[0].ToLowerInvariant()
        $target = $null
        if ($body -match '^[^:]+:([^/]+)') { $target = $Matches[1] }
        switch ($mechanism) {
            'include' {
                $Ctx.Lookups++
                if (-not $target) { $Ctx.Problems.Add("'$term' in $DomainName's SPF has no domain (permerror)") | Out-Null }
                elseif ($target -match '%\{') { $Ctx.Macros = $true }
                else {
                    $r = Invoke-SpfWalk -DomainName $target -Ctx $Ctx -Path $here -IsPolicyRoot $false
                    if ($r -eq 'none') { $Ctx.Problems.Add("include:$target has no SPF record, so SPF fails with an error (permerror) when it is reached. Remove or fix it.") | Out-Null }
                }
            }
            'a' { $Ctx.Lookups++ }
            'mx' { $Ctx.Lookups++ }
            'exists' { $Ctx.Lookups++; if ($target -match '%\{') { $Ctx.Macros = $true } }
            'ptr' { $Ctx.Lookups++; $Ctx.UsesPtr = $true }
            'ip4' { }
            'ip6' { }
            'all' { $hasAll = $true; if ($IsPolicyRoot) { $Ctx.All = $qualifier } }
            default { $Ctx.Problems.Add("Unknown term '$term' in $DomainName's SPF record (permerror)") | Out-Null }
        }
    }
    if ($redirect -and -not $hasAll) {
        $Ctx.Lookups++
        if ($redirect -match '%\{') { $Ctx.Macros = $true }
        else {
            $r = Invoke-SpfWalk -DomainName $redirect -Ctx $Ctx -Path $here -IsPolicyRoot $IsPolicyRoot
            if ($r -eq 'none') { $Ctx.Problems.Add("redirect=$redirect has no SPF record (permerror).") | Out-Null }
        }
    }
    'ok'
}

function Get-SpfAnalysis {
    param([string]$DomainName)
    $ctx = [pscustomobject]@{
        Lookups = 0; All = $null; UsesPtr = $false; Macros = $false
        Problems = (New-Object System.Collections.Generic.List[string])
        Incomplete = (New-Object System.Collections.Generic.List[string])
    }
    $result = Invoke-SpfWalk -DomainName $DomainName -Ctx $ctx -Path @() -IsPolicyRoot $true
    [pscustomobject]@{ Result = $result; Lookups = $ctx.Lookups; All = $ctx.All; UsesPtr = $ctx.UsesPtr; Macros = $ctx.Macros; Problems = $ctx.Problems.ToArray(); Incomplete = $ctx.Incomplete.ToArray() }
}

function ConvertFrom-DmarcRecord {
    param([string]$Record)
    $tags = @{}
    foreach ($part in ($Record -split ';')) {
        if ($part.Trim() -match '^([A-Za-z]+)\s*=\s*(.*)$') { $tags[$Matches[1].ToLowerInvariant()] = $Matches[2].Trim() }
    }
    $tags
}

# ---------------------------------------------------------------- one domain

function Test-OneDomain {
    param($Entry, $Previous)
    $d = $Entry.Domain
    $findings = New-Object System.Collections.Generic.List[object]
    $snapshot = @{}
    $row = [pscustomobject]@{
        Client = $Entry.Client; Domain = $d; Status = 'OK'
        DomainExpires = $null; DomainDaysLeft = $null; Registrar = $null; RegistrationNote = $null; DnsHost = $null
        WebsiteHost = $null; WebsiteCertExpires = $null; WebsiteCertDaysLeft = $null; WebsiteCertIssuer = $null
        OtherCerts = @(); MailProvider = $null; MX = $null; SPF = $null; SpfLookups = $null
        DMARC = $null; DmarcPolicy = $null; DKIM = $null
        Findings = $findings; Snapshot = $snapshot
    }

    if (-not (Test-DomainName $d)) {
        $findings.Add((New-Finding 'Warning' 'Input' "'$($Entry.Raw)' doesn't look like a domain name, so it was skipped.")) | Out-Null
        $row.Status = 'Warning'
        return $row
    }

    # --- DNS: does the domain resolve at all?
    $dnsUsable = $true
    $ns = Resolve-Doh -Name $d -Type 'NS'
    if (-not $ns.Ok) {
        $dnsUsable = $false
        if ($ns.Status -eq 2) {
            $findings.Add((New-Finding 'Critical' 'DNS' 'DNS lookups for this domain fail (SERVFAIL). Its nameservers may be down, or DNSSEC is broken.')) | Out-Null
        }
        else {
            $findings.Add((New-Finding 'Warning' 'DNS' "Couldn't check DNS: $($ns.Error)")) | Out-Null
        }
    }
    elseif ($ns.Status -eq 3) {
        $dnsUsable = $false
        $findings.Add((New-Finding 'Critical' 'DNS' "The domain doesn't exist in DNS (NXDOMAIN). It may have expired or been deleted.")) | Out-Null
    }
    elseif ($ns.Records.Count -gt 0) {
        $nameServers = @($ns.Records | Sort-Object -Unique)
        $row.DnsHost = Get-DnsHostName $nameServers
        $snapshot['NS'] = ($nameServers -join ', ')
    }

    # --- Registration (RDAP)
    $reg = Get-Registration -DomainName $d
    if (-not $reg.Supported) {
        $row.RegistrationNote = 'no RDAP for .' + ($d -split '\.')[-1]
        $findings.Add((New-Finding 'Info' 'Domain' "The .$(($d -split '\.')[-1]) registry doesn't publish registration data over RDAP; check the expiry date at the registrar.")) | Out-Null
    }
    elseif ($reg.Error) {
        $row.RegistrationNote = 'lookup failed'
        $findings.Add((New-Finding 'Warning' 'Domain' "Couldn't check registration: $($reg.Error)")) | Out-Null
    }
    elseif ($reg.Found -eq $false) {
        $row.RegistrationNote = 'not registered'
        $findings.Add((New-Finding 'Critical' 'Domain' 'Not found at the registry: the domain is unregistered or deleted, or the name in your list has a typo.')) | Out-Null
    }
    else {
        $row.Registrar = $reg.Registrar
        if ($reg.Registrar) { $snapshot['Registrar'] = $reg.Registrar }
        if ($reg.Expires) {
            $row.DomainExpires = $reg.Expires
            $days = Get-DaysLeft $reg.Expires
            $row.DomainDaysLeft = $days
            $when = Format-Date $reg.Expires
            if ($days -lt 0) { $findings.Add((New-Finding 'Critical' 'Domain' "Domain registration expired on $when.")) | Out-Null }
            elseif ($days -le $DomainCriticalDays) { $findings.Add((New-Finding 'Critical' 'Domain' "Domain registration $(Format-DaysPhrase $days) ($when). Renew it or confirm auto-renew and the card on file.")) | Out-Null }
            elseif ($days -le $DomainWarnDays) { $findings.Add((New-Finding 'Warning' 'Domain' "Domain registration $(Format-DaysPhrase $days) ($when). Confirm auto-renew and the card on file.")) | Out-Null }
        }
        else {
            $row.RegistrationNote = 'no expiry date published'
            $findings.Add((New-Finding 'Info' 'Domain' "The registry didn't return an expiry date; check it at the registrar.")) | Out-Null
        }
        $statuses = @($reg.Statuses)
        if ($statuses -contains 'pending delete') { $findings.Add((New-Finding 'Critical' 'Domain' 'Registry status is "pending delete": the domain is about to be released.')) | Out-Null }
        if ($statuses -contains 'redemption period') { $findings.Add((New-Finding 'Critical' 'Domain' 'Registry status is "redemption period": the domain has lapsed and must be restored at the registrar.')) | Out-Null }
        if (@($statuses | Where-Object { $_ -match '(client|server) hold' }).Count -gt 0) { $findings.Add((New-Finding 'Critical' 'Domain' 'Registry status includes a hold: the domain is suspended and does not resolve. Contact the registrar.')) | Out-Null }
        if ($statuses -contains 'auto renew period') {
            # Normal after many renewals, so warn the first time it's seen and keep it as a note after that.
            $snapshot['AutoRenewGrace'] = 'yes'
            $level = 'Warning'
            if ($Previous -and $Previous.ContainsKey('AutoRenewGrace') -and $Previous['AutoRenewGrace'] -eq 'yes') { $level = 'Info' }
            $findings.Add((New-Finding $level 'Domain' "Domain is in the registry's auto-renew grace period: its expiry date rolled forward automatically, but if the registrar wasn't paid it can still delete the domain within about 45 days. Confirm the renewal invoice was paid.")) | Out-Null
        }
        else { $snapshot['AutoRenewGrace'] = 'no' }
        if ($statuses -contains 'pending transfer') { $findings.Add((New-Finding 'Warning' 'Domain' 'A registrar transfer is in progress. Make sure it was expected.')) | Out-Null }
        $tld = ($d -split '\.')[-1]
        if ($statuses.Count -gt 0 -and @('com', 'net', 'org', 'info', 'biz', 'us') -contains $tld -and @($statuses | Where-Object { $_ -match 'transfer prohibited' }).Count -eq 0) {
            $findings.Add((New-Finding 'Info' 'Domain' 'No registrar transfer lock is set. Turning it on makes the domain harder to hijack.')) | Out-Null
        }
    }

    if ($dnsUsable) {
        # --- Website certificate (the domain itself, or www.)
        $webHost = $null
        if (Test-HasAddress $d) { $webHost = $d }
        elseif (Test-HasAddress "www.$d") { $webHost = "www.$d" }
        if ($webHost) {
            $cert = Get-TlsCertificateInfo -HostName $webHost
            if (-not $cert.Connected -and $webHost -eq $d -and (Test-HasAddress "www.$d")) {
                $wwwCert = Get-TlsCertificateInfo -HostName "www.$d"
                if ($wwwCert.Connected) {
                    $findings.Add((New-Finding 'Info' 'Website' "https://$d doesn't answer ($($cert.Error)); checked www.$d instead.")) | Out-Null
                    $cert = $wwwCert
                }
            }
            $row.WebsiteHost = $cert.Host
            if ($cert.Connected) {
                $row.WebsiteCertExpires = $cert.NotAfter
                $row.WebsiteCertDaysLeft = $cert.DaysLeft
                $row.WebsiteCertIssuer = $cert.Issuer
                Add-CertificateFindings -Findings $findings -Cert $cert -Area 'Website' -Label "Website ($($cert.Host))"
            }
            else {
                $findings.Add((New-Finding 'Info' 'Website' "No HTTPS answer from $($cert.Host): $($cert.Error)")) | Out-Null
            }
        }
        else {
            $findings.Add((New-Finding 'Info' 'Website' "No website: neither $d nor www.$d has an address record.")) | Out-Null
        }

        # --- Mail: MX
        $mx = Resolve-Doh -Name $d -Type 'MX'
        $receivesMail = $false
        $nullMx = $false
        if (-not $mx.Ok) {
            $findings.Add((New-Finding 'Warning' 'Mail' "Couldn't look up MX records: $($mx.Error)")) | Out-Null
        }
        else {
            $mxEntries = @(foreach ($record in $mx.Records) {
                    $parts = $record -split '\s+', 2
                    $hostName = ''
                    if ($parts.Count -gt 1) { $hostName = $parts[1].Trim().TrimEnd('.') }
                    $preference = 0
                    [void][int]::TryParse($parts[0], [ref]$preference)
                    [pscustomobject]@{ Preference = $preference; Host = $hostName }
                })
            $mxEntries = @($mxEntries | Sort-Object Preference, Host)
            if ($mxEntries.Count -eq 1 -and $mxEntries[0].Host -eq '') {
                $nullMx = $true
                $row.MailProvider = 'No mail (null MX)'
                $row.MX = '0 .'
                $snapshot['MX'] = '0 .'
            }
            elseif ($mxEntries.Count -gt 0) {
                $receivesMail = $true
                $mxHosts = @($mxEntries | ForEach-Object { $_.Host })
                $row.MailProvider = Get-ProviderName -HostNames $mxHosts -Map $script:MailProviders
                $row.MX = (@($mxEntries | ForEach-Object { "$($_.Preference) $($_.Host)" }) -join ', ')
                $snapshot['MX'] = $row.MX
            }
            else {
                $row.MailProvider = 'No MX records'
                $snapshot['MX'] = '(none)'
            }
        }

        # --- SPF
        $apexTxt = Resolve-Doh -Name $d -Type 'TXT'
        $sendsMail = $receivesMail
        if (-not $apexTxt.Ok) {
            $findings.Add((New-Finding 'Warning' 'SPF' "Couldn't look up TXT records: $($apexTxt.Error)")) | Out-Null
            $row.SPF = 'Unknown'
        }
        else {
            $spfRecords = @(Get-SpfRecords $apexTxt.Records)
            if ($spfRecords.Count -eq 0) {
                $row.SPF = 'Missing'
                $snapshot['SPF'] = '(none)'
                if ($receivesMail) { $findings.Add((New-Finding 'Warning' 'SPF' "No SPF record, so receivers can't tell which servers may send this domain's mail.")) | Out-Null }
            }
            else {
                $snapshot['SPF'] = (($spfRecords | ForEach-Object { ($_.Trim() -replace '\s+', ' ') }) -join ' | ')
                if ($spfRecords.Count -eq 1 -and $spfRecords[0].Trim() -notmatch '^v=spf1\s+-all$') { $sendsMail = $true }
                $spf = Get-SpfAnalysis -DomainName $d
                $row.SpfLookups = $spf.Lookups
                $label = "OK ($($spf.Lookups)/10 lookups)"
                foreach ($p in $spf.Problems) { $findings.Add((New-Finding 'Critical' 'SPF' $p)) | Out-Null }
                if ($spf.Problems.Count -gt 0) { $label = 'Error' }
                if ($spf.Lookups -gt 10) {
                    $findings.Add((New-Finding 'Critical' 'SPF' "SPF needs $($spf.Lookups) DNS lookups; the limit is 10, so receivers can fail SPF (permerror) for some of this domain's mail. Remove unused includes or flatten the record.")) | Out-Null
                    $label = "Error ($($spf.Lookups)/10 lookups)"
                }
                elseif ($spf.Lookups -ge 9) {
                    $findings.Add((New-Finding 'Info' 'SPF' "SPF uses $($spf.Lookups) of its 10 DNS lookups. Adding another service's include may break it.")) | Out-Null
                }
                if ($spf.All -eq '+') {
                    $findings.Add((New-Finding 'Critical' 'SPF' 'SPF ends in +all, which lets any server on the internet pass SPF as this domain.')) | Out-Null
                    $label = 'Error (+all)'
                }
                elseif ($spf.Result -eq 'ok' -and ($spf.All -eq '?' -or ($null -eq $spf.All -and $spf.Problems.Count -eq 0))) {
                    $findings.Add((New-Finding 'Info' 'SPF' "SPF ends in ?all or has no 'all', so it doesn't ask receivers to reject other senders.")) | Out-Null
                }
                if ($spf.UsesPtr) { $findings.Add((New-Finding 'Info' 'SPF' "SPF uses the deprecated 'ptr' mechanism, which some receivers ignore.")) | Out-Null }
                if ($spf.Macros) { $findings.Add((New-Finding 'Info' 'SPF' 'SPF uses macros, which this check counts but cannot follow; the lookup count may be higher.')) | Out-Null }
                if ($spf.Incomplete.Count -gt 0) {
                    $findings.Add((New-Finding 'Warning' 'SPF' "Couldn't check every include (DNS lookup failed for $((@($spf.Incomplete) | Select-Object -Unique) -join ', ')); the lookup count may be incomplete.")) | Out-Null
                }
                $row.SPF = $label
            }
        }

        # --- DMARC
        $dmarcQuery = Resolve-Doh -Name "_dmarc.$d" -Type 'TXT'
        if (-not $dmarcQuery.Ok) {
            $findings.Add((New-Finding 'Warning' 'DMARC' "Couldn't look up DMARC: $($dmarcQuery.Error)")) | Out-Null
            $row.DMARC = 'Unknown'
        }
        else {
            $dmarcRecords = @($dmarcQuery.Records | Where-Object { $_ -match '^\s*v\s*=\s*DMARC1\s*(;|$)' })
            if ($dmarcRecords.Count -eq 0) {
                $row.DMARC = 'Missing'
                $snapshot['DMARC'] = '(none)'
                if ($sendsMail) {
                    $findings.Add((New-Finding 'Warning' 'DMARC' "No DMARC record: anyone can spoof this domain and you get no reports. Start with 'v=DMARC1; p=none; rua=mailto:<your reporting address>'.")) | Out-Null
                }
            }
            elseif ($dmarcRecords.Count -gt 1) {
                $row.DMARC = 'Error'
                $snapshot['DMARC'] = ($dmarcRecords -join ' | ')
                $findings.Add((New-Finding 'Critical' 'DMARC' "$($dmarcRecords.Count) DMARC records are published; receivers ignore all of them. Keep one.")) | Out-Null
            }
            else {
                $snapshot['DMARC'] = ($dmarcRecords[0].Trim() -replace '\s+', ' ')
                $tags = ConvertFrom-DmarcRecord $dmarcRecords[0]
                $policy = ''
                if ($tags.ContainsKey('p')) { $policy = $tags['p'].ToLowerInvariant() }
                $row.DmarcPolicy = $policy
                if (@('none', 'quarantine', 'reject') -notcontains $policy) {
                    $row.DMARC = 'Error'
                    $findings.Add((New-Finding 'Warning' 'DMARC' "DMARC record has no valid policy (p=$policy), so receivers may ignore it.")) | Out-Null
                }
                else {
                    $row.DMARC = "p=$policy"
                    if ($tags.ContainsKey('pct') -and $tags['pct'] -ne '100' -and $policy -ne 'none') {
                        $row.DMARC += " (pct=$($tags['pct']))"
                        $findings.Add((New-Finding 'Info' 'DMARC' "DMARC applies its policy to only $($tags['pct'])% of failing mail (pct=$($tags['pct'])).")) | Out-Null
                    }
                    if ($policy -eq 'none') { $findings.Add((New-Finding 'Info' 'DMARC' 'DMARC is monitoring only (p=none): spoofed mail still gets delivered.')) | Out-Null }
                }
                if (-not $tags.ContainsKey('rua')) {
                    $findings.Add((New-Finding 'Info' 'DMARC' 'DMARC has no rua= address, so nobody receives the daily reports.')) | Out-Null
                }
            }
        }

        # --- Parked domains
        if (-not $sendsMail -and $row.SPF -ne 'Unknown' -and $row.DMARC -ne 'Unknown' -and ($row.SPF -eq 'Missing' -or $row.DmarcPolicy -ne 'reject')) {
            $findings.Add((New-Finding 'Info' 'Mail' "Domain doesn't appear to send or receive mail. To stop it being spoofed, publish SPF 'v=spf1 -all' and DMARC 'v=DMARC1; p=reject'.")) | Out-Null
        }

        # --- DKIM (common selectors only; a domain can use any selector name)
        if ($sendsMail -and $DkimSelectors.Count -gt 0) {
            $found = @(); $cnameOnly = @(); $revoked = @(); $failed = 0
            foreach ($selector in $DkimSelectors) {
                $q = Resolve-Doh -Name "$selector._domainkey.$d" -Type 'TXT'
                if (-not $q.Ok) { $failed++; continue }
                $keys = @($q.Records | Where-Object { $_ -match '(^|;)\s*p\s*=' })
                if ($keys.Count -gt 0) {
                    if ($keys[0] -match '(^|;)\s*p\s*=\s*(;|$)') { $revoked += $selector } else { $found += $selector }
                }
                elseif ($q.Cnames.Count -gt 0) { $cnameOnly += $selector }
            }
            if ($found.Count -gt 0) { $row.DKIM = ($found -join ', ') }
            elseif ($failed -gt 0) { $row.DKIM = 'Unknown' }
            else { $row.DKIM = 'Not found' }

            $isM365 = ($row.MailProvider -match 'Microsoft 365')
            $m365Selectors = @($DkimSelectors | Where-Object { $_ -eq 'selector1' -or $_ -eq 'selector2' })
            if ($failed -gt 0) {
                $findings.Add((New-Finding 'Info' 'DKIM' "Couldn't check $failed DKIM selector(s) because DNS lookups failed.")) | Out-Null
            }
            elseif ($isM365 -and $m365Selectors.Count -eq 2 -and -not ($found -contains 'selector1' -or $found -contains 'selector2')) {
                if ($found.Count -gt 0) {
                    $findings.Add((New-Finding 'Info' 'DKIM' "Mail is on Microsoft 365, but its DKIM selectors (selector1/selector2) don't resolve to a key. Another service signs with: $($found -join ', ').")) | Out-Null
                }
                elseif ($cnameOnly.Count -gt 0) {
                    $findings.Add((New-Finding 'Warning' 'DKIM' "Microsoft 365 DKIM CNAMEs exist, but they don't lead to a key, so DKIM signing is probably not enabled. Enable it in the Defender portal (Email authentication settings > DKIM).")) | Out-Null
                }
                else {
                    $findings.Add((New-Finding 'Warning' 'DKIM' 'Microsoft 365 mail with no DKIM records at selector1/selector2: DKIM signing for this domain probably is not set up, so DMARC relies on SPF alone.')) | Out-Null
                }
            }
            elseif ($found.Count -eq 0) {
                $findings.Add((New-Finding 'Info' 'DKIM' "No DKIM key found at the common selectors ($($DkimSelectors -join ', ')). This isn't conclusive: your mail service may use a different selector name.")) | Out-Null
            }
            if ($revoked.Count -gt 0) {
                $findings.Add((New-Finding 'Info' 'DKIM' "DKIM selector(s) $($revoked -join ', ') are published with an empty key (revoked).")) | Out-Null
            }
        }
        elseif (-not $sendsMail) { $row.DKIM = '-' }
    }

    # --- Extra certificates (RD Gateway, VPN, on-prem Exchange...)
    $others = New-Object System.Collections.Generic.List[object]
    foreach ($h in $Entry.CertHosts) {
        $label = $h.Host
        if ($h.Port -ne 443) { $label = "$($h.Host):$($h.Port)" }
        $cert = Get-TlsCertificateInfo -HostName $h.Host -Port $h.Port
        if ($cert.Connected) {
            Add-CertificateFindings -Findings $findings -Cert $cert -Area 'Certificate' -Label $label
            $others.Add([pscustomobject]@{ Label = $label; DaysLeft = $cert.DaysLeft; Expires = $cert.NotAfter; Error = $null; Problem = ($cert.NameMismatch -or $cert.ChainProblem) }) | Out-Null
        }
        else {
            $findings.Add((New-Finding 'Warning' 'Certificate' "Couldn't connect to $label to check its certificate: $($cert.Error)")) | Out-Null
            $others.Add([pscustomobject]@{ Label = $label; DaysLeft = $null; Expires = $null; Error = $cert.Error; Problem = $true }) | Out-Null
        }
    }
    $row.OtherCerts = $others.ToArray()

    # --- Changes since the last run
    if ($Previous) {
        $names = @{ NS = 'Nameservers'; MX = 'MX records'; SPF = 'SPF record'; DMARC = 'DMARC record'; Registrar = 'Registrar' }
        foreach ($field in @('NS', 'Registrar', 'MX', 'SPF', 'DMARC')) {
            if (-not $snapshot.ContainsKey($field) -or -not $Previous.ContainsKey($field)) { continue }
            $old = [string]$Previous[$field]
            $new = [string]$snapshot[$field]
            $same = $old -eq $new
            if ($field -eq 'NS' -or $field -eq 'MX') { $same = $old.ToLowerInvariant() -eq $new.ToLowerInvariant() }
            if (-not $same) {
                $since = ''
                if ($Previous.ContainsKey('_checked')) { $since = " (last check $($Previous['_checked']))" }
                $findings.Add((New-Finding 'Warning' 'Change' "$($names[$field]) changed since the last check$since. Was: $(Limit-Text $old 120) | Now: $(Limit-Text $new 120)")) | Out-Null
            }
        }
    }

    $rank = 0
    foreach ($f in $findings) { $r = Get-LevelRank $f.Level; if ($r -gt $rank) { $rank = $r } }
    if ($rank -ge 3) { $row.Status = 'Critical' } elseif ($rank -eq 2) { $row.Status = 'Warning' } else { $row.Status = 'OK' }
    $row
}

# ---------------------------------------------------------------- input and state

function Read-DomainList {
    param([string]$Path, [string[]]$Names)
    $raw = New-Object System.Collections.Generic.List[object]
    if ($Names) {
        foreach ($n in $Names) { foreach ($part in ($n -split '[,;\s]+')) { if ($part) { $raw.Add([pscustomobject]@{ Client = ''; Domain = $part; CertHosts = '' }) | Out-Null } } }
    }
    else {
        if (-not (Test-Path -LiteralPath $Path)) { throw "Domain list not found: $Path. Create it (see domains.example.csv) or pass -InputFile / -Domain." }
        if ($Path -match '\.csv$') {
            $rows = @(Import-Csv -LiteralPath $Path)
            if ($rows.Count -gt 0) {
                $columns = @($rows[0].PSObject.Properties | ForEach-Object { $_.Name })
                $domainColumn = $columns | Where-Object { $_.Trim() -ieq 'Domain' } | Select-Object -First 1
                $clientColumn = $columns | Where-Object { $_.Trim() -ieq 'Client' } | Select-Object -First 1
                $hostsColumn = $columns | Where-Object { $_.Trim() -ieq 'CertHosts' } | Select-Object -First 1
                if (-not $domainColumn) { throw "$Path needs a header row with a Domain column, for example: Client,Domain,CertHosts" }
                foreach ($r in $rows) {
                    $client = ''; $hosts = ''
                    if ($clientColumn) { $client = [string]$r.$clientColumn }
                    if ($hostsColumn) { $hosts = [string]$r.$hostsColumn }
                    $raw.Add([pscustomobject]@{ Client = $client.Trim(); Domain = [string]$r.$domainColumn; CertHosts = $hosts }) | Out-Null
                }
            }
        }
        else {
            foreach ($line in (Get-Content -LiteralPath $Path)) {
                $t = ($line -replace '#.*$', '').Trim()
                if ($t) { $raw.Add([pscustomobject]@{ Client = ''; Domain = $t; CertHosts = '' }) | Out-Null }
            }
        }
    }

    $byDomain = [ordered]@{}
    foreach ($r in $raw) {
        $original = ([string]$r.Domain).Trim()
        if (-not $original -or $original.StartsWith('#')) { continue }
        $name = ConvertTo-DomainName $original
        $hosts = @(([string]$r.CertHosts -split '[;,\s]+') | Where-Object { $_ } | ForEach-Object { ConvertTo-HostEntry $_ } | Where-Object { $_ })
        if ($byDomain.Contains($name)) {
            $existing = $byDomain[$name]
            foreach ($h in $hosts) {
                if (-not (@($existing.CertHosts | Where-Object { $_.Host -eq $h.Host -and $_.Port -eq $h.Port }).Count)) { $existing.CertHosts += $h }
            }
            if (-not $existing.Client -and $r.Client) { $existing.Client = $r.Client }
            continue
        }
        $byDomain[$name] = [pscustomobject]@{ Client = [string]$r.Client; Domain = $name; Raw = $original; CertHosts = $hosts }
    }
    @($byDomain.Values)
}

function Read-State {
    param([string]$Path)
    $state = @{}
    if (-not (Test-Path -LiteralPath $Path)) { return $state }
    try {
        $json = (Get-Content -LiteralPath $Path -Raw) | ConvertFrom-Json
        if ($json -and $json.PSObject.Properties['domains']) {
            foreach ($p in $json.domains.PSObject.Properties) {
                $entry = @{}
                foreach ($q in $p.Value.PSObject.Properties) { $entry[$q.Name] = [string]$q.Value }
                $state[$p.Name] = $entry
            }
        }
    }
    catch { Write-Warning "Couldn't read the change-tracking file ($Path), so changes aren't compared this run: $($_.Exception.Message)" }
    $state
}

function Save-State {
    param([string]$Path, [hashtable]$Previous, $Results)
    $domains = [ordered]@{}
    $checked = (Get-Date).ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture)
    foreach ($r in $Results) {
        $entry = [ordered]@{}
        # Keep the old value for anything that couldn't be looked up this time.
        if ($Previous.ContainsKey($r.Domain)) { foreach ($k in $Previous[$r.Domain].Keys) { $entry[$k] = $Previous[$r.Domain][$k] } }
        foreach ($k in $r.Snapshot.Keys) { $entry[$k] = $r.Snapshot[$k] }
        $entry['_checked'] = $checked
        $domains[$r.Domain] = $entry
    }
    $doc = [ordered]@{ tool = 'client-domain-check'; version = 1; domains = $domains }
    $json = ConvertTo-Json -InputObject $doc -Depth 5
    $tmp = "$Path.tmp"
    [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}

# ---------------------------------------------------------------- output

function ConvertTo-Html5 {
    param([string]$Text)
    [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Get-DayClass {
    param($Days, [int]$Warn, [int]$Critical)
    if ($null -eq $Days -or '' -eq $Days) { return '' }
    $Days = [int]$Days
    if ($Days -le $Critical) { return 'bad' }
    if ($Days -le $Warn) { return 'warn' }
    ''
}

function New-HtmlReport {
    param($Results, [datetime]$Started, [string]$ResolverName)
    $critical = @($Results | Where-Object { $_.Status -eq 'Critical' }).Count
    $warning = @($Results | Where-Object { $_.Status -eq 'Warning' }).Count
    $ok = @($Results | Where-Object { $_.Status -eq 'OK' }).Count
    $when = $Started.ToString('dddd, MMMM d, yyyy h:mm tt', [Globalization.CultureInfo]::InvariantCulture)

    $css = @'
:root{--navy:#0E1E40;--blue:#0048F0;--red:#C8262C;--amber:#9A5B00;--green:#17704A;--bg:#F5F6FA;--line:#E2E5EE;--muted:#5F6B85}
*{box-sizing:border-box}
body{margin:0;font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--navy);background:var(--bg)}
header{background:var(--navy);color:#fff;padding:22px 28px 20px}
h1{margin:0;font-size:21px;letter-spacing:.01em}
.meta{opacity:.75;font-size:13px;margin-top:3px}
.stats{display:flex;gap:10px;margin-top:16px;flex-wrap:wrap}
.stat{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.14);border-radius:8px;padding:8px 16px;min-width:110px}
.stat b{font-size:22px;display:block;line-height:1.1}
.stat.c b{color:#FF8A8E}.stat.w b{color:#FFC861}.stat.o b{color:#7FE0B0}
main{padding:8px 28px 20px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;margin:24px 0 10px;color:var(--muted)}
.card{background:#fff;border:1px solid var(--line);border-left:4px solid #E3A008;border-radius:8px;padding:11px 16px;margin-bottom:8px;max-width:1100px}
.card.critical{border-left-color:var(--red)}
.card .who{font-weight:600}.card .who span{color:var(--muted);font-weight:400;margin-left:6px}
.card ul{margin:6px 0 0;padding-left:18px}.card li{margin:2px 0}
.lvl{font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;margin-right:6px}
.lvl.Critical{color:var(--red)}.lvl.Warning{color:var(--amber)}.lvl.Info{color:var(--muted)}
.allclear{background:#fff;border:1px solid var(--line);border-left:4px solid var(--green);border-radius:8px;padding:12px 16px;max-width:1100px}
.pill{display:inline-block;font-size:11px;font-weight:700;padding:2px 9px;border-radius:999px;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap}
.pill.Critical{background:#FDE6E7;color:var(--red)}.pill.Warning{background:#FFF1D6;color:var(--amber)}.pill.OK{background:#E1F4EA;color:var(--green)}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px;background:#fff}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top;font-size:13px}
tr:last-child td{border-bottom:0}
th{background:#EEF1F8;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);white-space:nowrap}
td.nowrap{white-space:nowrap}
.bad{color:var(--red);font-weight:600}.warn{color:var(--amber);font-weight:600}.muted{color:var(--muted)}
.sub{display:block;color:var(--muted);font-size:12px}
details summary{cursor:pointer;color:var(--blue)}
details ul{margin:4px 0 0;padding-left:16px}
footer{padding:4px 28px 28px;color:var(--muted);font-size:12px;max-width:1100px}
@media print{header{background:#fff;color:var(--navy);border-bottom:2px solid var(--navy)}.stat{border-color:var(--line)}details{display:block}}
'@

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<!DOCTYPE html>`n<html lang=""en""><head><meta charset=""utf-8""><meta name=""viewport"" content=""width=device-width,initial-scale=1"">")
    [void]$sb.Append("<title>Client domain check - $(ConvertTo-Html5 ($Started.ToString('yyyy-MM-dd')))</title><style>$css</style></head><body>")
    [void]$sb.Append("<header><h1>Client domain check</h1><div class=""meta"">$(ConvertTo-Html5 $when) &middot; $($Results.Count) domain$(if ($Results.Count -ne 1) { 's' })</div>")
    [void]$sb.Append("<div class=""stats""><div class=""stat c""><b>$critical</b>critical</div><div class=""stat w""><b>$warning</b>warning</div><div class=""stat o""><b>$ok</b>OK</div></div></header><main>")

    [void]$sb.Append('<h2>Needs attention</h2>')
    $attention = @($Results | Where-Object { $_.Status -ne 'OK' })
    if ($attention.Count -eq 0) {
        [void]$sb.Append('<div class="allclear">Nothing needs attention today.</div>')
    }
    foreach ($r in $attention) {
        $cls = $r.Status.ToLowerInvariant()
        $who = $r.Domain
        $sub = ''
        if ($r.Client) { $who = $r.Client; $sub = "<span>$(ConvertTo-Html5 $r.Domain)</span>" }
        [void]$sb.Append("<div class=""card $cls""><div class=""who"">$(ConvertTo-Html5 $who)$sub</div><ul>")
        foreach ($f in ($r.Findings | Where-Object { $_.Level -ne 'Info' } | Sort-Object @{ Expression = { Get-LevelRank $_.Level }; Descending = $true })) {
            [void]$sb.Append("<li><span class=""lvl $($f.Level)"">$($f.Level)</span>$(ConvertTo-Html5 $f.Message)</li>")
        }
        [void]$sb.Append('</ul></div>')
    }

    [void]$sb.Append('<h2>All domains</h2><div class="wrap"><table><thead><tr>')
    foreach ($h in @('Client / domain', 'Status', 'Domain expires', 'Website certificate', 'DNS host', 'Mail', 'SPF', 'DMARC', 'DKIM', 'Other certificates', 'Notes')) {
        [void]$sb.Append("<th>$h</th>")
    }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $Results) {
        [void]$sb.Append('<tr>')
        if ($r.Client) { [void]$sb.Append("<td><b>$(ConvertTo-Html5 $r.Client)</b><span class=""sub"">$(ConvertTo-Html5 $r.Domain)</span></td>") }
        else { [void]$sb.Append("<td><b>$(ConvertTo-Html5 $r.Domain)</b></td>") }
        [void]$sb.Append("<td><span class=""pill $($r.Status)"">$($r.Status)</span></td>")

        if ($r.DomainExpires) {
            $c = Get-DayClass $r.DomainDaysLeft $DomainWarnDays $DomainCriticalDays
            [void]$sb.Append("<td class=""nowrap""><span class=""$c"">$(Format-Date $r.DomainExpires)</span><span class=""sub"">$(Format-DaysCell $r.DomainDaysLeft)$(if ($r.Registrar) { ' &middot; ' + (ConvertTo-Html5 (Limit-Text $r.Registrar 28)) })</span></td>")
        }
        else {
            $note = '-'
            if ($r.RegistrationNote) { $note = $r.RegistrationNote }
            $noteClass = 'muted'
            if ($r.RegistrationNote -eq 'not registered') { $noteClass = 'bad' }
            [void]$sb.Append("<td class=""nowrap""><span class=""$noteClass"">$(ConvertTo-Html5 $note)</span>$(if ($r.Registrar) { '<span class=""sub"">' + (ConvertTo-Html5 (Limit-Text $r.Registrar 28)) + '</span>' })</td>")
        }

        if ($r.WebsiteCertExpires) {
            $c = Get-DayClass $r.WebsiteCertDaysLeft $CertWarnDays $CertCriticalDays
            $certProblem = @($r.Findings | Where-Object { $_.Area -eq 'Website' -and $_.Level -ne 'Info' }).Count -gt 0
            if ($certProblem -and -not $c) { $c = 'warn' }
            [void]$sb.Append("<td class=""nowrap""><span class=""$c"">$(Format-DaysCell $r.WebsiteCertDaysLeft)</span><span class=""sub"">$(ConvertTo-Html5 $r.WebsiteHost)$(if ($r.WebsiteCertIssuer) { ' &middot; ' + (ConvertTo-Html5 (Limit-Text $r.WebsiteCertIssuer 24)) })</span></td>")
        }
        else { [void]$sb.Append('<td class="muted">-</td>') }

        [void]$sb.Append("<td>$(if ($r.DnsHost) { ConvertTo-Html5 $r.DnsHost } else { '<span class=""muted"">-</span>' })</td>")
        [void]$sb.Append("<td>$(if ($r.MailProvider) { ConvertTo-Html5 $r.MailProvider } else { '<span class=""muted"">-</span>' })</td>")

        $spfClass = ''
        if ($r.SPF -like 'Error*') { $spfClass = 'bad' } elseif ($r.SPF -eq 'Missing' -and $r.MailProvider -and $r.MailProvider -notmatch '^No ') { $spfClass = 'warn' }
        [void]$sb.Append("<td class=""nowrap""><span class=""$spfClass"">$(ConvertTo-Html5 $(if ($r.SPF) { $r.SPF } else { '-' }))</span></td>")

        $dmarcClass = ''
        if ($r.DMARC -eq 'Error') { $dmarcClass = 'bad' } elseif ($r.DMARC -eq 'Missing' -and @($r.Findings | Where-Object { $_.Area -eq 'DMARC' -and $_.Level -eq 'Warning' }).Count) { $dmarcClass = 'warn' }
        [void]$sb.Append("<td class=""nowrap""><span class=""$dmarcClass"">$(ConvertTo-Html5 $(if ($r.DMARC) { $r.DMARC } else { '-' }))</span></td>")

        $dkimClass = ''
        if (@($r.Findings | Where-Object { $_.Area -eq 'DKIM' -and $_.Level -eq 'Warning' }).Count) { $dkimClass = 'warn' }
        [void]$sb.Append("<td><span class=""$dkimClass"">$(ConvertTo-Html5 $(if ($r.DKIM) { $r.DKIM } else { '-' }))</span></td>")

        if ($r.OtherCerts.Count -gt 0) {
            [void]$sb.Append('<td class="nowrap">')
            foreach ($o in $r.OtherCerts) {
                if ($o.Error) { [void]$sb.Append("<span class=""sub""><span class=""warn"">no answer</span> $(ConvertTo-Html5 $o.Label)</span>") }
                else {
                    $c = Get-DayClass $o.DaysLeft $CertWarnDays $CertCriticalDays
                    if ($o.Problem -and -not $c) { $c = 'warn' }
                    [void]$sb.Append("<span class=""sub""><span class=""$c"">$(Format-DaysCell $o.DaysLeft)</span> $(ConvertTo-Html5 $o.Label)</span>")
                }
            }
            [void]$sb.Append('</td>')
        }
        else { [void]$sb.Append('<td class="muted">-</td>') }

        $notes = @($r.Findings | Where-Object { $_.Level -eq 'Info' })
        if ($notes.Count -gt 0) {
            [void]$sb.Append("<td><details><summary>$($notes.Count) note$(if ($notes.Count -ne 1) { 's' })</summary><ul>")
            foreach ($n in $notes) { [void]$sb.Append("<li>$(ConvertTo-Html5 $n.Message)</li>") }
            [void]$sb.Append('</ul></details></td>')
        }
        else { [void]$sb.Append('<td class="muted">-</td>') }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div></main>')
    [void]$sb.Append("<footer>Read-only checks: DNS over HTTPS ($(ConvertTo-Html5 $ResolverName)), registry RDAP and a TLS handshake with each website. Thresholds: domains warn at $DomainWarnDays days and go critical at $DomainCriticalDays; certificates warn at $CertWarnDays and go critical at $CertCriticalDays. DKIM is checked at common selectors only. Generated by client-domain-check $ScriptVersion, a free tool by Waxwing Factory.</footer>")
    [void]$sb.Append('</body></html>')
    $sb.ToString()
}

function ConvertTo-CsvRows {
    param($Results)
    foreach ($r in $Results) {
        [pscustomobject]@{
            Client              = $r.Client
            Domain              = $r.Domain
            Status              = $r.Status
            DomainExpires       = Format-Date $r.DomainExpires
            DomainDaysLeft      = $r.DomainDaysLeft
            Registrar           = $r.Registrar
            DnsHost             = $r.DnsHost
            WebsiteHost         = $r.WebsiteHost
            WebsiteCertExpires  = Format-Date $r.WebsiteCertExpires
            WebsiteCertDaysLeft = $r.WebsiteCertDaysLeft
            WebsiteCertIssuer   = $r.WebsiteCertIssuer
            OtherCerts          = (@($r.OtherCerts | ForEach-Object { if ($_.Error) { "$($_.Label): no answer" } else { "$($_.Label): $($_.DaysLeft) days" } }) -join '; ')
            MailProvider        = $r.MailProvider
            MX                  = $r.MX
            SPF                 = $r.SPF
            SpfLookups          = $r.SpfLookups
            DMARC               = $r.DMARC
            DKIM                = $r.DKIM
            Findings            = (@($r.Findings | Sort-Object @{ Expression = { Get-LevelRank $_.Level }; Descending = $true } | ForEach-Object { "[$($_.Level)] $($_.Message)" }) -join ' | ')
        }
    }
}

function Get-AttentionLines {
    param($Results, [int]$Max = 25)
    $lines = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Results) {
        foreach ($f in ($r.Findings | Where-Object { $_.Level -ne 'Info' } | Sort-Object @{ Expression = { Get-LevelRank $_.Level }; Descending = $true })) {
            $who = $r.Domain
            if ($r.Client) { $who = "$($r.Client) ($($r.Domain))" }
            $lines.Add([pscustomobject]@{ Level = $f.Level; Who = $who; Message = $f.Message }) | Out-Null
        }
    }
    $sorted = @($lines | Sort-Object @{ Expression = { Get-LevelRank $_.Level }; Descending = $true })
    [pscustomobject]@{ Lines = @($sorted | Select-Object -First $Max); Total = $sorted.Count }
}

function New-WebhookPayload {
    param([string]$Url, $Results, [string]$ReportPath)
    $critical = @($Results | Where-Object { $_.Status -eq 'Critical' }).Count
    $warning = @($Results | Where-Object { $_.Status -eq 'Warning' }).Count
    $title = "Client domain check: $critical critical, $warning warning ($($Results.Count) domains)"
    $attention = Get-AttentionLines -Results $Results -Max 25
    $more = ''
    if ($attention.Total -gt $attention.Lines.Count) { $more = "...and $($attention.Total - $attention.Lines.Count) more in the report." }
    $footer = "Report: $ReportPath (on $([Environment]::MachineName))"

    if ($Url -match '^https://hooks\.slack\.com/') {
        $text = New-Object System.Text.StringBuilder
        [void]$text.Append("*$title*")
        if ($attention.Total -eq 0) { [void]$text.Append("`nNothing needs attention.") }
        foreach ($l in $attention.Lines) {
            $icon = ':large_yellow_circle:'
            if ($l.Level -eq 'Critical') { $icon = ':red_circle:' }
            $safe = ("$($l.Who): $($l.Message)" -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;')
            [void]$text.Append("`n$icon $safe")
        }
        if ($more) { [void]$text.Append("`n$more") }
        [void]$text.Append("`n_$($footer)_")
        return (ConvertTo-Json -InputObject @{ text = $text.ToString() } -Depth 3 -Compress)
    }

    # Microsoft Teams "Workflows" webhook (the replacement for retired Office 365 connectors)
    $body = New-Object System.Collections.Generic.List[object]
    $body.Add([ordered]@{ type = 'TextBlock'; text = $title; weight = 'Bolder'; size = 'Medium'; wrap = $true }) | Out-Null
    if ($attention.Total -eq 0) { $body.Add([ordered]@{ type = 'TextBlock'; text = 'Nothing needs attention.'; wrap = $true }) | Out-Null }
    foreach ($l in $attention.Lines) {
        $color = 'Warning'
        if ($l.Level -eq 'Critical') { $color = 'Attention' }
        $body.Add([ordered]@{
                type = 'ColumnSet'; spacing = 'Small'
                columns = @(
                    [ordered]@{ type = 'Column'; width = 'auto'; items = @([ordered]@{ type = 'TextBlock'; text = $l.Level.ToUpperInvariant(); color = $color; weight = 'Bolder'; size = 'Small' }) },
                    [ordered]@{ type = 'Column'; width = 'stretch'; items = @([ordered]@{ type = 'TextBlock'; text = "**$($l.Who)**: $($l.Message)"; wrap = $true; size = 'Small' }) }
                )
            }) | Out-Null
    }
    if ($more) { $body.Add([ordered]@{ type = 'TextBlock'; text = $more; wrap = $true; isSubtle = $true; size = 'Small' }) | Out-Null }
    $body.Add([ordered]@{ type = 'TextBlock'; text = $footer; wrap = $true; isSubtle = $true; size = 'Small' }) | Out-Null
    $card = [ordered]@{
        type        = 'message'
        attachments = @(
            [ordered]@{
                contentType = 'application/vnd.microsoft.card.adaptive'
                contentUrl  = $null
                content     = [ordered]@{
                    '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
                    type      = 'AdaptiveCard'
                    version   = '1.4'
                    msteams   = @{ width = 'Full' }
                    body      = $body.ToArray()
                }
            }
        )
    }
    ConvertTo-Json -InputObject $card -Depth 12 -Compress
}

# ---------------------------------------------------------------- main

function Invoke-ClientDomainCheck {
    $started = Get-Date
    $base = $PSScriptRoot
    if (-not $base) { $base = (Get-Location).Path }
    $listPath = $InputFile
    if (-not $Domain -and -not $listPath) { $listPath = Join-Path $base 'domains.csv' }
    if ($listPath) { $listPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($listPath) }
    $outDir = $OutputFolder
    if (-not $outDir) { $outDir = Join-Path $base 'reports' }
    $outDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($outDir)

    try { $entries = @(Read-DomainList -Path $listPath -Names $Domain) }
    catch { Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red; return [int]3 }
    if ($entries.Count -eq 0) { Write-Host 'ERROR: the domain list is empty.' -ForegroundColor Red; return [int]3 }
    if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

    Initialize-Http
    $statePath = Join-Path $outDir 'domain-check-state.json'
    $previous = Read-State -Path $statePath

    Write-Host "Checking $($entries.Count) domain$(if ($entries.Count -ne 1) { 's' })..."
    $results = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($entry in $entries) {
        $i++
        Write-Host ("  [{0}/{1}] {2}" -f $i, $entries.Count, $entry.Domain)
        $prev = $null
        if ($previous.ContainsKey($entry.Domain)) { $prev = $previous[$entry.Domain] }
        try { $results.Add((Test-OneDomain -Entry $entry -Previous $prev)) | Out-Null }
        catch {
            $f = New-Object System.Collections.Generic.List[object]
            $f.Add((New-Finding 'Warning' 'Check' "The check failed unexpectedly: $($_.Exception.Message)")) | Out-Null
            $results.Add([pscustomobject]@{ Client = $entry.Client; Domain = $entry.Domain; Status = 'Warning'; DomainExpires = $null; DomainDaysLeft = $null; Registrar = $null; RegistrationNote = $null; DnsHost = $null; WebsiteHost = $null; WebsiteCertExpires = $null; WebsiteCertDaysLeft = $null; WebsiteCertIssuer = $null; OtherCerts = @(); MailProvider = $null; MX = $null; SPF = $null; SpfLookups = $null; DMARC = $null; DmarcPolicy = $null; DKIM = $null; Findings = $f; Snapshot = @{} }) | Out-Null
        }
    }

    $sorted = @($results | Sort-Object @{ Expression = { switch ($_.Status) { 'Critical' { 0 } 'Warning' { 1 } default { 2 } } } }, Client, Domain)
    $stamp = $started.ToString('yyyy-MM-dd-HHmm', [Globalization.CultureInfo]::InvariantCulture)
    $htmlPath = Join-Path $outDir "domain-check-$stamp.html"
    $csvPath = Join-Path $outDir "domain-check-$stamp.csv"
    $html = New-HtmlReport -Results $sorted -Started $started -ResolverName $DnsResolver
    [System.IO.File]::WriteAllText($htmlPath, $html, (New-Object System.Text.UTF8Encoding($false)))
    $csvEncoding = 'UTF8'
    if ($PSVersionTable.PSEdition -eq 'Core') { $csvEncoding = 'utf8BOM' }   # so Excel reads accented names correctly
    ConvertTo-CsvRows -Results $sorted | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding $csvEncoding
    $usable = @($sorted | Where-Object { Test-DomainName $_.Domain })
    Save-State -Path $statePath -Previous $previous -Results $usable

    $critical = @($sorted | Where-Object { $_.Status -eq 'Critical' }).Count
    $warning = @($sorted | Where-Object { $_.Status -eq 'Warning' }).Count
    $ok = $sorted.Count - $critical - $warning
    Write-Host ''
    Write-Host ("{0} critical, {1} warning, {2} OK" -f $critical, $warning, $ok)
    $attention = Get-AttentionLines -Results $sorted -Max 1000
    foreach ($l in $attention.Lines) {
        $color = 'Yellow'
        if ($l.Level -eq 'Critical') { $color = 'Red' }
        Write-Host ("  {0,-8} {1}: {2}" -f $l.Level.ToUpperInvariant(), $l.Who, $l.Message) -ForegroundColor $color
    }
    Write-Host ''
    Write-Host "Report: $htmlPath"
    Write-Host "CSV:    $csvPath"

    if ($WebhookUrl -and (($critical + $warning) -gt 0 -or $NotifyAlways)) {
        $payload = New-WebhookPayload -Url $WebhookUrl -Results $sorted -ReportPath $htmlPath
        $post = Invoke-HttpPostJson -Uri $WebhookUrl -Json $payload
        if ($post.Error -or $post.StatusCode -lt 200 -or $post.StatusCode -ge 300) {
            Write-Warning "Posting to the webhook failed: $(if ($post.Error) { $post.Error } else { 'HTTP ' + $post.StatusCode + ' ' + (Limit-Text $post.Body 200) })"
        }
        else { Write-Host 'Summary posted to the webhook.' }
    }

    if ($Open) { Invoke-Item -LiteralPath $htmlPath }

    $code = 0
    if ($critical -gt 0) { $code = 2 } elseif ($warning -gt 0) { $code = 1 }
    [pscustomobject]@{ ExitCode = $code; Results = $sorted; ReportPath = $htmlPath; CsvPath = $csvPath }
}

# Dot-sourcing (". .\Test-ClientDomains.ps1") only loads the functions, for testing.
if ($MyInvocation.InvocationName -eq '.') { return }

$run = Invoke-ClientDomainCheck
if ($run -is [int]) { exit $run }
if ($PassThru) { $run.Results }
exit $run.ExitCode
