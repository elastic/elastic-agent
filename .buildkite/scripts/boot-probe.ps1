# Boot-time noise probe (Windows).
#
# Started in the background from pre-command.ps1 on freshly-booted CI VMs.
# Captures what the machine is doing during the first ~10 minutes after boot.
# Output lives under C:\boot-probe and is uploaded by pre-exit.ps1.
#
# Self-gates: only runs when the system was booted recently.

$ErrorActionPreference = 'SilentlyContinue'

$Out             = 'C:\boot-probe'
$SampleInterval  = 5
$SampleDuration  = 600     # 10 minutes
$MaxUptimeSecs   = 1800    # skip if older than 30 min

$boot       = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$uptimeSecs = ((Get-Date) - $boot).TotalSeconds
if ($uptimeSecs -gt $MaxUptimeSecs) { exit 0 }

New-Item -ItemType Directory -Force -Path $Out | Out-Null

# --- one-shot snapshot ------------------------------------------------------
@{
    startedAt          = (Get-Date).ToUniversalTime().ToString('o')
    bootedAt           = $boot.ToUniversalTime().ToString('o')
    uptimeAtStartSec   = [int]$uptimeSecs
    os                 = (Get-CimInstance Win32_OperatingSystem).Caption
    buildkitePipeline  = $env:BUILDKITE_PIPELINE_SLUG
    buildkiteStep      = $env:BUILDKITE_STEP_KEY
    buildkiteAgent     = $env:BUILDKITE_AGENT_NAME
    buildkiteJob       = $env:BUILDKITE_JOB_ID
} | ConvertTo-Json | Set-Content "$Out\snapshot.json"

Get-Service |
    Sort-Object Status, Name |
    Select-Object Name, DisplayName, Status, StartType |
    Export-Csv "$Out\services.csv" -NoTypeInformation

Get-ScheduledTask |
    Where-Object State -ne 'Disabled' |
    Select-Object TaskPath, TaskName, State |
    Export-Csv "$Out\tasks.csv" -NoTypeInformation

Get-Process |
    Sort-Object CPU -Descending |
    Select-Object -First 30 Name, Id, CPU, WS, StartTime |
    Export-Csv "$Out\ps-start.csv" -NoTypeInformation

Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $boot } |
    Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message |
    Export-Csv "$Out\system-eventlog.csv" -NoTypeInformation

# --- background continuous sampling -----------------------------------------
$job = Start-Job -Name boot-probe-sampler -ScriptBlock {
    param($Out, $Interval, $Duration)
    $ErrorActionPreference = 'SilentlyContinue'
    $end = (Get-Date).AddSeconds($Duration)
    while ((Get-Date) -lt $end) {
        $ts = (Get-Date).ToUniversalTime().ToString('o')

        $counters = Get-Counter -Counter @(
            '\Processor(_Total)\% Processor Time',
            '\PhysicalDisk(_Total)\% Disk Time',
            '\Memory\Available MBytes',
            '\Network Interface(*)\Bytes Total/sec'
        ) -SampleInterval 1 -MaxSamples 1
        foreach ($s in $counters.CounterSamples) {
            "$ts`t$($s.Path)`t$($s.CookedValue)" | Add-Content "$Out\counters.tsv"
        }

        Get-Process |
            Sort-Object CPU -Descending |
            Select-Object -First 5 |
            ForEach-Object { "$ts`t$($_.Name)`t$($_.CPU)" } |
            Add-Content "$Out\top.tsv"

        Start-Sleep -Seconds $Interval
    }
} -ArgumentList $Out, $SampleInterval, $SampleDuration

# Persist job id so pre-exit can stop it cleanly.
$job.Id | Set-Content "$Out\sampler.jobid"
