# Times a real run over tests/scale-domains.txt (100 public domains) and reports
# retries and failed lookups, to measure speed and registry rate limits.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Scale-Test.ps1 -Destination .\scale
param([string]$Destination = (Join-Path ([IO.Path]::GetTempPath()) 'cdc-scale'))
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'Test-ClientDomains.ps1')

$OutputFolder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Destination)
$InputFile = Join-Path $PSScriptRoot 'scale-domains.txt'
$watch = [Diagnostics.Stopwatch]::StartNew()
$run = Invoke-ClientDomainCheck
$watch.Stop()
if ($run -is [int]) { Write-Host "The run could not start (exit $run)."; exit 1 }

$results = @($run.Results)
$seconds = [Math]::Round($watch.Elapsed.TotalSeconds)
$dnsFailures = @($results | Where-Object { @($_.Findings | Where-Object { $_.Message -match 'DNS query failed' }).Count -gt 0 })
$rdapFailures = @($results | Where-Object { $_.RegistrationNote -eq 'lookup failed' })
$noRdap = @($results | Where-Object { $_.RegistrationNote -match '^no RDAP' })
$noExpiry = @($results | Where-Object { $_.RegistrationNote -eq 'no expiry date published' })

Write-Host ''
Write-Host '==== Scale test ===='
Write-Host ("PowerShell {0} {1}" -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition)
Write-Host ("Domains: {0}   Time: {1} s ({2:N1} s per domain)" -f $results.Count, $seconds, ($watch.Elapsed.TotalSeconds / [Math]::Max(1, $results.Count)))
Write-Host ("Status: {0} critical, {1} warning, {2} OK" -f @($results | Where-Object Status -eq 'Critical').Count, @($results | Where-Object Status -eq 'Warning').Count, @($results | Where-Object Status -eq 'OK').Count)
Write-Host ("DNS resolver: {0}{1}" -f $script:ActiveResolver, $(if ($script:ResolverNote) { " ($script:ResolverNote)" } else { '' }))
Write-Host ("Domains with a failed DNS query: {0} {1}" -f $dnsFailures.Count, (($dnsFailures | ForEach-Object Domain) -join ', '))
Write-Host ("RDAP lookups failed: {0} {1}" -f $rdapFailures.Count, (($rdapFailures | ForEach-Object Domain) -join ', '))
Write-Host ("TLDs without RDAP: {0} {1}" -f $noRdap.Count, (($noRdap | ForEach-Object Domain) -join ', '))
Write-Host ("RDAP without an expiry date: {0} {1}" -f $noExpiry.Count, (($noExpiry | ForEach-Object Domain) -join ', '))
Write-Host ("HTTP retries: {0}" -f $script:HttpRetryLog.Count)
$script:HttpRetryLog | Group-Object | Sort-Object Count -Descending | ForEach-Object { Write-Host ("  {0,4}  {1}" -f $_.Count, $_.Name) }
"seconds=$seconds" | Out-File -FilePath (Join-Path $OutputFolder 'scale-summary.txt') -Encoding ascii
