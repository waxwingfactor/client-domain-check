# Live smoke test: runs the script as a separate process against public hosts with known
# properties (badssl.com publishes deliberately broken certificates). Needs internet.
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Live-Tests.ps1
#   pwsh -NoProfile -File ./tests/Live-Tests.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $root 'Test-ClientDomains.ps1'
$out = Join-Path ([IO.Path]::GetTempPath()) ("cdc-live-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $out | Out-Null
$list = Join-Path $out 'domains.csv'
Set-Content -LiteralPath $list -Value @(
    'Client,Domain,CertHosts',
    'Microsoft,microsoft.com,',
    'Example,example.com,',
    'BBC,bbc.co.uk,',
    'TLS test hosts,badssl.com,expired.badssl.com; wrong.host.badssl.com; self-signed.badssl.com',
    'Typo,client-domain-check-nonexistent-zz9.com,'
)

$failed = 0
function Check {
    param([bool]$Condition, [string]$Name)
    if ($Condition) { Write-Host "  ok    $Name" } else { Write-Host "  FAIL  $Name" -ForegroundColor Red; $script:failed++ }
}

$exe = (Get-Process -Id $PID).Path
$arguments = @('-NoProfile', '-File', $scriptPath, '-InputFile', $list, '-OutputFolder', $out)
if ($PSVersionTable.PSEdition -ne 'Core') { $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass') + $arguments[1..($arguments.Count - 1)] }
$started = Get-Date
& $exe @arguments
$exitCode = $LASTEXITCODE
$seconds = [int]((Get-Date) - $started).TotalSeconds
Write-Host ''
Write-Host "Run took $seconds s, exit code $exitCode"

$csv = Get-ChildItem -LiteralPath $out -Filter 'domain-check-*.csv' | Select-Object -First 1
$rows = @{}
foreach ($r in (Import-Csv -LiteralPath $csv.FullName)) { $rows[$r.Domain] = $r }

Check ($exitCode -eq 2) 'exit code is 2 (critical findings present)'
$m = $rows['microsoft.com']
Check ($m.MailProvider -eq 'Microsoft 365') 'microsoft.com: mail provider is Microsoft 365'
Check ($m.DomainExpires -match '^\d{4}-\d{2}-\d{2}$' -and [int]$m.DomainDaysLeft -gt 0) 'microsoft.com: registration expiry from RDAP'
Check ($m.Registrar -match 'MarkMonitor') 'microsoft.com: registrar'
Check ([int]$m.WebsiteCertDaysLeft -gt 0) 'microsoft.com: website certificate read'
Check ($m.SPF -like 'OK*' -and [int]$m.SpfLookups -gt 0) 'microsoft.com: SPF parsed'
Check ($m.DMARC -eq 'p=reject') 'microsoft.com: DMARC reject'
Check ($m.DKIM -match 'selector') 'microsoft.com: DKIM selector found'
Check ($m.DnsHost -eq 'Azure DNS') 'microsoft.com: DNS host'
$e = $rows['example.com']
Check ($e.MailProvider -eq 'No mail (null MX)') 'example.com: null MX'
$b = $rows['bbc.co.uk']
Check ($b.DomainExpires -match '^\d{4}') 'bbc.co.uk: .uk registration via RDAP'
$t = $rows['badssl.com']
Check ($t.Findings -match '\[Critical\] expired\.badssl\.com certificate expired') 'expired.badssl.com: expired certificate is critical'
Check ($t.Findings -match "wrong\.host\.badssl\.com certificate doesn't cover") 'wrong.host.badssl.com: name mismatch'
Check ($t.Findings -match "self-signed\.badssl\.com certificate isn't trusted") 'self-signed.badssl.com: untrusted'
$n = $rows['client-domain-check-nonexistent-zz9.com']
Check ($n.Status -eq 'Critical' -and $n.Findings -match 'Not found at the registry') 'nonexistent domain: critical, not at registry'
Check (Test-Path -LiteralPath (Join-Path $out 'domain-check-state.json')) 'state file written'

if ($env:CDC_KEEP_OUTPUT) { Write-Host "Output kept in $out" } else { Remove-Item -LiteralPath $out -Recurse -Force }
Write-Host ''
Write-Host ("Live test: {0} (PowerShell {1} {2})" -f $(if ($failed) { "$failed FAILED" } else { 'all passed' }), $PSVersionTable.PSVersion, $PSVersionTable.PSEdition)
if ($failed) { exit 1 }
exit 0
