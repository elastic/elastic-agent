# Environment probe: characterise the CI execution context so we can diff it
# against a manually-provisioned VM (same image/HW) that does NOT reproduce the
# crash, and find the confounding factor. Deterministic - always produces info,
# never depends on hitting the crash.
$ErrorActionPreference = "Continue"

Write-Host "================ HOST INFO (PowerShell) ================"

Write-Host "`n-- CPU / hypervisor --"
try {
  Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed | Format-List | Out-Host
  $cs = Get-CimInstance Win32_ComputerSystem
  Write-Host ("HypervisorPresent={0}  LogicalProcessors={1}  Manufacturer={2}  Model={3}" -f `
    $cs.HypervisorPresent, $cs.NumberOfLogicalProcessors, $cs.Manufacturer, $cs.Model)
} catch { Write-Host "cpu/hypervisor query failed: $_" }

Write-Host "`n-- Defender status / exclusions --"
try {
  $mp = Get-MpComputerStatus
  Write-Host ("RealTimeProtection={0}  BehaviorMonitor={1}  AMRunningMode={2}" -f `
    $mp.RealTimeProtectionEnabled, $mp.BehaviorMonitorEnabled, $mp.AMRunningMode)
  Write-Host ("ExclusionPath: " + ((Get-MpPreference).ExclusionPath -join ', '))
} catch { Write-Host "defender query failed (maybe not present): $_" }

Write-Host "`n-- filesystem filter drivers (fltmc) --"
try { fltmc filters 2>&1 | Out-Host } catch { Write-Host "fltmc failed: $_" }

Write-Host "`n-- buildkite-agent context --"
Write-Host ("BUILDKITE_AGENT_NAME={0}" -f $env:BUILDKITE_AGENT_NAME)
Write-Host ("BUILDKITE_AGENT_META_DATA / experiments visible in env dump below")
try { & buildkite-agent --version 2>&1 | Out-Host } catch { Write-Host "buildkite-agent --version failed: $_" }

# Run the Go probe two ways so we can see both what the agent hands the job
# (direct) and what a piped child sees (like `go test ... | Tee-Object`).
Write-Host "`n================ GO PROBE (direct: agent's handle to the job) ================"
& go run ./.buildkite/scripts/steps/envprobe 2>&1 | Out-Host

Write-Host "`n================ GO PROBE (piped, like the test pipeline) ================"
& go run ./.buildkite/scripts/steps/envprobe 2>&1 | Tee-Object -FilePath "$env:TEMP\probe-piped.log" | Out-Host

exit 0
