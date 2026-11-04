# CI only (needs an elevated Windows session): follows the README's Task Scheduler steps
# exactly, runs the task once and checks that it produced a report.
$ErrorActionPreference = 'Stop'
$dir = 'C:\DomainCheck'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Copy-Item -Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'Test-ClientDomains.ps1') -Destination $dir -Force
Set-Content -Path "$dir\domains.csv" -Value @('Client,Domain,CertHosts', 'Example,example.com,')

# --- README snippet starts
$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\DomainCheck\Test-ClientDomains.ps1"'
$trigger   = New-ScheduledTaskTrigger -Daily -At 7am
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'Client domain check' -Action $action -Trigger $trigger -Principal $principal
# --- README snippet ends

Start-ScheduledTask -TaskName 'Client domain check'
$deadline = (Get-Date).AddMinutes(5)
do {
    Start-Sleep -Seconds 5
    $task = Get-ScheduledTask -TaskName 'Client domain check'
    $info = Get-ScheduledTaskInfo -TaskName 'Client domain check'
} while (($task.State -eq 'Running' -or $info.LastTaskResult -eq 267011) -and (Get-Date) -lt $deadline)

$reports = @(Get-ChildItem -Path "$dir\reports" -Filter 'domain-check-*.html' -ErrorAction SilentlyContinue)
Write-Host "Task state: $($task.State); last result: $($info.LastTaskResult); reports: $($reports.Count)"
Unregister-ScheduledTask -TaskName 'Client domain check' -Confirm:$false
if ($reports.Count -ne 1) { throw 'The scheduled task did not write a report.' }
if (@(0, 1, 2) -notcontains $info.LastTaskResult) { throw "Unexpected task result $($info.LastTaskResult)" }
Write-Host 'Scheduled task test passed.'
